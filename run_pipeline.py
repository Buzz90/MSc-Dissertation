from generator_agent import create_generator_agent
from discriminator_agent import create_discriminator_agent
from utils.payload_tester import test_payload
from utils.cleaner import clean_payload
import time

safe="Generate a safe username input that does not contain SQL injection characters."
unsafe=(
    "Generate only one raw SQL injection payload for error-based SQLi."
    "Do not include any HTML tags, JavaScript code, or Markdown code blocks."
    "Output only the raw SQL injection string without any additional text."
    "Do not include any cocde formatting, programming variable assignments, or explanations."
    "For example, just return with payload like this:"
    "' OR1=1 --"
    "Return payload ONLY between START and END markers:\n"
    "START\n"
    "SQL_INJECTION_PAYLOAD_HERE\n"
    "END"
)

def run_pipeline():
    generator = create_generator_agent()
    discriminator = create_discriminator_agent()
    start_time= time.time()

    # Dummy conversation to simulate the agents' interaction
    gen_payload = generator.generate_reply(
        messages=[{"role": "user", "content": unsafe}]
    )
    payload = gen_payload.get("content", "").strip()
    print(f"[GeneratorAgent] Payload: {payload}")
    payload = clean_payload(payload)
    payload_lines = [line.strip() for line in payload.splitlines() if line.strip()]
    if payload_lines:
        payload = payload_lines[0]
    else:
        payload = "' OR 1=1 --"
    print(f"[GeneratorAgent] Cleaned Payload: {payload}")
    if not payload:
        payload = "' OR 1=1 --"

    # Discriminator checks payload
    payload_time = time.time()
    result = test_payload(payload, payload_time)
    print(f"[DiscriminatorAgent] Result: {result}")


    elapsed_time = time.time() - start_time
    print("Pipeline executed successfully within {:.2f} seconds.".format(elapsed_time))

if __name__ == "__main__":
    run_pipeline()