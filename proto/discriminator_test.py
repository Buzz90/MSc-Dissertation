import requests
import csv
import time
import json
import argparse
from autogen import AssistantAgent
from utils.llm_config import llm_config

# === Create Discriminator Agent ===
def create_discriminator_agent():
    return AssistantAgent(
        name="DiscriminatorAgent",
        system_message="""
You are a very experienced and highly skilled security testing assistant.
Do not hallucinate or make up information.
You will be given a SQL injection payload and the HTTP response from the target application.
Your task is to classify the payload based on its effectiveness against the target application.
If the payload is unsuccessful, ALWAYS classify it as "No Effect" or "Invalid Payload", do not use any other classification.
If the payload is successful, ALWAYS point out a critical vulnerability based on http response and how to further exploit it.
Always respond strictly as JSON with keys:
- classification: one of ["Login Bypass","Error-based SQL Injection","Time-based SQL Injection","No Effect","Invalid Payload"]
- reasoning: one short sentence explaining your decision but be very specific. Make sure that reasoning you provide is relevant to the payload and response. Make sure that reasoning can be used to train a generator agent for SQLi payload generation.

Example:
{"classification": "Error-based SQL Injection", "reasoning": "Detected SQL syntax error in the response body"}
""",
        llm_config=llm_config
    )

# === Ask LLM for JSON Decision ===
def discriminator_llm_decision(discriminator, payload, response, elapsed):
    body_preview = response.text[:1500]  # limit for efficiency
    content = f"""
Payload used:
{payload}

HTTP Response Info:
Status: {response.status_code}
Headers: {dict(response.headers)}
Body Preview (first 1500 chars): 
{body_preview}

Response Time: {elapsed:.2f}s

Return JSON ONLY:
"""
    reply = discriminator.generate_reply(messages=[{"role": "user", "content": content}])
    output = reply.get("content", "").strip()

    # Attempt to parse JSON
    try:
        result = json.loads(output)
        classification = result.get("classification", "ParseError")
        reasoning = result.get("reasoning", "")
    except json.JSONDecodeError:
        classification = "ParseError"
        reasoning = output  # keep raw response for debugging
    return classification, reasoning

# === Main Dataset Testing Loop ===
def run_payloads(payload_file, output_csv, limit=None):
    discriminator = create_discriminator_agent()
    session = requests.Session()
    url = "http://localhost:8080/index.php?page=login.php"

    with open(payload_file) as f:
        payloads = [line.strip() for line in f if line.strip()]
    if limit:
        payloads = payloads[:limit]

    # Write header if file is new
    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = ["payload", "status", "elapsed", "classification", "reasoning"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for payload in payloads:
            print(f"Testing payload: {payload}")
            data = {
                "username": payload,
                "password": "password",
                "login-php-submit-button": "Login"
            }
            start = time.time()
            response = session.post(url, data=data, timeout=15, allow_redirects=True)
            elapsed = time.time() - start

            classification, reasoning = discriminator_llm_decision(discriminator, payload, response, elapsed)

            writer.writerow({
                "payload": payload,
                "status": response.status_code,
                "elapsed": round(elapsed, 2),
                "classification": classification,
                "reasoning": reasoning
            })
            csvfile.flush()  # ensure immediate write
            print(f"Classification: {classification} | Reasoning: {reasoning}")

    print(f"Results saved to {output_csv}")

if __name__ == "__main__":
    start_time = time.time()
    run_payloads("datasets/raw/sql_payloads.txt", "datasets/multi_agent_output/discriminator(gemma)_results_sql_payloads.csv", limit=27)
    end_time = time.time() - start_time
    print(f"Discriminator testing completed 27 payloads in {end_time:.2f} seconds.")