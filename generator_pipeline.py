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

def enforce_single_payload(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "' OR 1=1 --"
    first_payload = lines[0]
    if not any(token in first_payload.lower() for token in ["select", "union", "sleep", "or", "--"]):
        return "' OR 1=1 --"
    return first_payload

def load_config():
    with open("utils/config.json") as f:
        return json.load(f)

# === Main Pipeline ===
def run_pipeline():
    config = load_config()
    generator_model = config.get("generator_model", "vicuna")
    iterations = config.get("iterations", 10)
    csv_log_file = config.get("csv_log_file", "payload_results.csv")

    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    # CSV header
    file_exists = os.path.isfile(csv_log_file)
    with open(csv_log_file, "a", newline="") as csvfile:
        fieldnames = ["timestamp", "model", "raw_payload", "cleaned_payload", "result", "generator_time", "discriminator_time"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        for i in range(iterations):
            print(f"\n=== Iteration {i+1}/{iterations} ===")
            start_time = time.time()

            # Generator Stage
            gen_start = time.time()
            gen_payload = generator.generate_reply(
                messages=[{"role": "user", "content": unsafe}],
                max_tokens=64
            )
            raw_payload = gen_payload.get("content", "").strip()
            payload = extract_between_markers(raw_payload)
            payload = clean_payload(payload)
            payload = enforce_single_payload(payload)
            gen_end = time.time()

            # Discriminator Stage
            disc_start = time.time()
            result = test_payload(payload)
            disc_end = time.time()

            # Log & print
            print(f"[GeneratorAgent] Payload (raw): {raw_payload}")
            print(f"[GeneratorAgent] Payload (cleaned): {payload}")
            print(f"[DiscriminatorAgent] Result: {result}")
            print(f"Timing -> Generator: {gen_end - gen_start:.2f}s, Discriminator: {disc_end - disc_start:.2f}s")

            writer.writerow({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "model": generator_model,
                "raw_payload": raw_payload,
                "cleaned_payload": payload,
                "result": result,
                "generator_time": round(gen_end - gen_start, 2),
                "discriminator_time": round(disc_end - disc_start, 2)
            })
    print(f"\nPipeline executed successfully for {iterations} iterations. Results saved to {csv_log_file}")

if __name__ == "__main__":

    unsafe = (
        "Generate ONE raw SQL injection payload for error-based SQLi.\n"
        "Output ONLY between START and END markers.\n"
        "START\n"
        "' OR 1=1 --\n"
        "END"
    )
    run_pipeline()
