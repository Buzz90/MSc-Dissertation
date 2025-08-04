import requests

def login_mutillidae():
    url = "http://localhost:8080/index.php?page=login.php"
    session = requests.Session()

    # Directly send login form fields
    data = {
        "username": "john",
        "password": "1234",
        "login-php-submit-button": "Login"
    }

    response = session.post(url, data=data, allow_redirects=False)

    # Check redirect location for successful login
    location = response.headers.get("Location", "")
    print(f"[DEBUG] POST status: {response.status_code}")
    print(f"[DEBUG] Redirect location: {location}")

    if "popUpNotificationCode=AU1" in location:
        print("[+] Official login successful")
    else:
        print("[-] Login failed")
        print(response.text[:300])

if __name__ == "__main__":
    login_mutillidae()