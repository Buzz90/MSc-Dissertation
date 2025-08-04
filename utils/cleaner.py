import re

def clean_payload(text:str) -> str:
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