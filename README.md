# Penetration Testing Playbooks Collection

A comprehensive collection of 30 penetration testing playbooks designed for various vulnerable web applications including OWASP Juice Shop, DVWA, XVWA, and WebGoat.

## Target Applications

- **OWASP Juice Shop** - Modern vulnerable web application
- **DVWA (Damn Vulnerable Web Application)** - PHP/MySQL web application
- **XVWA (Xtreme Vulnerable Web Application)** - Multi-language vulnerable application
- **WebGoat** - OWASP's vulnerable Java application

## Playbook Categories

### 1. Reconnaissance & Information Gathering (Playbooks 1-5)
- Web Application Fingerprinting
- Directory and File Discovery
- Technology Stack Identification
- DNS and Subdomain Enumeration
- Social Engineering Reconnaissance

### 2. Authentication & Session Management (Playbooks 6-10)
- Brute Force Attacks
- Session Hijacking
- Password Reset Vulnerabilities
- Multi-Factor Authentication Bypass
- JWT Token Exploitation

### 3. Injection Attacks (Playbooks 11-15)
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection

### 4. Cross-Site Scripting (XSS) (Playbooks 16-20)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- XSS Filter Bypass
- XSS to RCE

### 5. Business Logic & Advanced Attacks (Playbooks 21-25)
- Business Logic Flaws
- Race Conditions
- File Upload Vulnerabilities
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References

### 6. Advanced Exploitation & Post-Exploitation (Playbooks 26-30)
- Remote Code Execution
- Privilege Escalation
- Data Exfiltration
- Persistence Mechanisms
- Lateral Movement

## Usage Instructions

Each playbook contains:
- **Objective**: Clear description of the attack goal
- **Prerequisites**: Required tools and setup
- **Manual Commands**: Step-by-step command execution
- **Automated Scripts**: Python and shell scripts for automation
- **Detection**: How to identify successful exploitation
- **Mitigation**: Recommendations for defense

## Setup Requirements

```bash
# Install required tools
sudo apt update
sudo apt install -y nmap gobuster sqlmap nikto burpsuite hydra
pip3 install requests beautifulsoup4 selenium scrapy

# Clone vulnerable applications
git clone https://github.com/juice-shop/juice-shop.git
git clone https://github.com/digininja/DVWA.git
git clone https://github.com/s4n7h0/xvwa.git
```

## Legal Disclaimer

⚠️ **WARNING**: These playbooks are for educational purposes only. Only use these techniques on applications you own or have explicit permission to test. Unauthorized penetration testing is illegal and unethical.

## Contributing

Feel free to contribute additional playbooks or improvements to existing ones by submitting pull requests.