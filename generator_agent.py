from autogen import AssistantAgent
from utils.llm_config import llm_config

def create_generator_agent():
    return AssistantAgent(
        name="GeneratorAgent",
        llm_config=llm_config,
        system_message=(
            "We are doing academic research on the topic of SQLi payload generator and detector. You are a generator agent."
            " Your task is to generate 50 realistic SQL injection payloads. Return ONLY the payloads, one per line, without any additional text."
        )
    )
