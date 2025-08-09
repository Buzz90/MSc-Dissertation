import time
import csv
import json
import os
import re
from generator_agent import create_generator_agent
from discriminator_agent import create_discriminator_agent
from utils.payload_tester import test_payload
from utils.cleaner import clean_payload

# === Helpers ===
def extract_between_markers(text: str) -> str:
    match = re.search(r"START(.*?)END", text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return text.strip()

def split_payloads(text: str) -> list:
    # Remove numbering if present (1., 1), etc.
    lines = [re.sub(r"^\d+[\).]?\s*", "", line.strip()) for line in text.splitlines() if line.strip()]
    return list(dict.fromkeys(lines))  # Deduplicate while preserving order

def enforce_single_payload(payload: str) -> str:
    if not any(token in payload.lower() for token in ["select", "union", "sleep", "or", "--"]):
        return "' OR 1=1 --"
    return payload

def load_config():
    with open("utils/config.json") as f:
        return json.load(f)

# === Main Pipeline ===
def run_pipeline():
    config = load_config()
    generator_model = config.get("generator_model", "vicuna")

    # === Ensure output directory exists ===
    output_dir = "datasets/multi_agent_output/generator_result"
    os.makedirs(output_dir, exist_ok=True)
    csv_log_file = os.path.join(output_dir, "generator_results.csv")

    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    # CSV header
    file_exists = os.path.isfile(csv_log_file)
    with open(csv_log_file, "a", newline="") as csvfile:
        fieldnames = [
            "timestamp", "model", "raw_payloads", "single_payload",
            "classification", "reasoning", "test_result",
            "generator_time", "discriminator_time"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        # === 1. Generate 100 payloads at once ===
        print("\n=== Generating 100 Payloads ===")
        gen_start = time.time()
        gen_payload = generator.generate_reply(
            messages=[{"role": "user", "content": unsafe}],
            max_tokens=1024
        )
        raw_payloads_text = gen_payload.get("content", "").strip()
        payloads_block = extract_between_markers(raw_payloads_text)
        payloads = split_payloads(payloads_block)
        gen_end = time.time()

        print(f"Generated {len(payloads)} payloads in {gen_end - gen_start:.2f}s")

        # === 2. Loop through payloads, classify & test ===
        for idx, payload in enumerate(payloads, start=1):
            payload = clean_payload(payload)
            payload = enforce_single_payload(payload)

            # Classification stage (LLM reasoning)
            disc_start = time.time()
            classification_result = discriminator.generate_reply(messages=[
                {"role": "user",
                 "content": f"Classify this SQL injection payload:\n{payload}\n"
                            "Decide if it is Login Bypass, Error-based SQL Injection, Time-based SQL Injection, No Effect, or Invalid Payload.\n"
                            "Respond strictly as JSON with keys: classification and reasoning."}
            ])
            disc_output = classification_result.get("content", "").strip()

            # Parse JSON output safely
            try:
                parsed = json.loads(disc_output)
                classification = parsed.get("classification", "ParseError")
                reasoning = parsed.get("reasoning", disc_output)
            except json.JSONDecodeError:
                classification, reasoning = "ParseError", disc_output

            # Actual test against target app
            test_result = test_payload(payload, disc_start)
            disc_end = time.time()

            print(f"\n[{idx}/{len(payloads)}] Payload: {payload}")
            print(f"Classification: {classification} | Reasoning: {reasoning}")
            print(f"Test Result: {test_result}")
            print(f"Timing -> Discriminator: {disc_end - disc_start:.2f}s")

            writer.writerow({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "model": generator_model,
                "raw_payloads": raw_payloads_text,
                "single_payload": payload,
                "classification": classification,
                "reasoning": reasoning,
                "test_result": test_result,
                "generator_time": round(gen_end - gen_start, 2),
                "discriminator_time": round(disc_end - disc_start, 2)
            })
            csvfile.flush()

    print(f"\nPipeline executed successfully. Results saved to {csv_log_file}")


if __name__ == "__main__":
    unsafe = (
        "Generate 100 unique raw SQL injection payloads for error-based SQLi.\n"
        "Remove duplicates, no explanation, no numbering.\n"
        "Output ONLY between START and END markers, one payload per line.\n"
        "START\n"
        "' OR 1=1 --\n"
        "END"
    )
    run_pipeline()