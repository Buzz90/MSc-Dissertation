import re

def clean_payload_original(text:str) -> str:
    match = re.search(r'START(.*?)END', text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    # Remove code blocks (```...```)
    text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
    # Remove HTML tags like <script>...</script>
    text = re.sub(r'<script.*?>.*?</script>', '', text)
    # Remove stray backticks and spaces
    text = text.replace('`', '').strip()
    return text

def clean_payload(payload):
    if not isinstance(payload, str):
        return ""
    # Remove code fences like ```sql ... ```
    payload = re.sub(r"```.*?```", "", payload, flags=re.DOTALL)
    # Remove leading list numbering (e.g., "1. ", "2) ")
    payload = re.sub(r"^\s*(\d+[\.\)]\s*)", "", payload)
    return payload.strip()