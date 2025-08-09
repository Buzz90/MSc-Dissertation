import requests
import time

def test_payload(payload, start_time, url, return_http_response=False, truncate_body=None):
    data = {
        "username": payload,
        "password": "password",
        "login-php-submit-button": "Login"
    }
    try:
        response = requests.post(url, data=data, timeout=30, allow_redirects=True)
    except requests.exceptions.ReadTimeout:
        class DummyResponse:
            status_code = 408
            text = "Read Timeout"
            headers = {}
        response = DummyResponse()

    if return_http_response:
        # Truncate body only if requested
        if truncate_body and hasattr(response, "text") and isinstance(response.text, str):
            response_text = response.text[:truncate_body]
        else:
            response_text = getattr(response, "text", "Read Timeout")
        # Create a new response-like object with truncated text
        class TruncatedResponse:
            status_code = response.status_code
            text = response_text
            headers = getattr(response, "headers", {})
        return TruncatedResponse()
    else:
        return response.status_code