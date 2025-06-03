# Playbook 01: Web Application Fingerprinting

## Objective

Identify the technology stack, frameworks, and components of target web applications to understand potential attack vectors.

## Target Applications

- OWASP Juice Shop (Node.js/Angular)
- DVWA (PHP/MySQL)
- XVWA (PHP/MySQL)
- WebGoat (Java/Spring)

## Prerequisites

- Nmap
- Whatweb
- Wappalyzer
- Burp Suite
- Python 3 with requests library

## Manual Commands

### 1. Basic Service Detection

```bash
# Nmap service detection
nmap -sV -p 80,443,8080,3000 <target_ip>

# Detailed service enumeration
nmap -sC -sV -A -p- <target_ip>
```

### 2. Web Technology Detection

```bash
# Using whatweb
whatweb http://<target_ip>:3000 -v

# Using Nmap scripts
nmap --script http-enum,http-headers,http-methods,http-robots.txt <target_ip>

# Banner grabbing
curl -I http://<target_ip>:3000
```

### 3. Framework Detection

```bash
# Check for common frameworks
curl -s http://<target_ip>:3000 | grep -i "generator\|framework\|version"

# Check robots.txt
curl http://<target_ip>:3000/robots.txt

# Check sitemap
curl http://<target_ip>:3000/sitemap.xml
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Web Application Fingerprinting Script
Targets: Juice Shop, DVWA, XVWA, WebGoat
"""

import requests
import re
import json
from urllib.parse import urljoin

class WebAppFingerprinter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def get_headers(self):
        """Extract server headers"""
        try:
            response = self.session.head(self.target_url, timeout=10)
            return dict(response.headers)
        except Exception as e:
            print(f"Error getting headers: {e}")
            return {}

    def detect_technology(self):
        """Detect web technologies"""
        technologies = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()
            headers = dict(response.headers)

            # Server detection
            server = headers.get('server', '')
            if server:
                technologies.append(f"Server: {server}")

            # Framework detection patterns
            patterns = {
                'Angular': [r'ng-version', r'angular', r'@angular'],
                'React': [r'react', r'reactdom'],
                'Vue.js': [r'vue\.js', r'vuejs'],
                'jQuery': [r'jquery', r'\$\('],
                'Bootstrap': [r'bootstrap'],
                'PHP': [r'\.php', r'phpsessid'],
                'Java': [r'jsessionid', r'struts', r'spring'],
                'Node.js': [r'express', r'node\.js'],
                'ASP.NET': [r'aspnet', r'__viewstate']
            }

            for tech, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, content):
                        technologies.append(tech)
                        break

            return technologies

        except Exception as e:
            print(f"Error detecting technology: {e}")
            return []

    def check_common_files(self):
        """Check for common configuration files"""
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'crossdomain.xml', 'clientaccesspolicy.xml'
        ]

        found_files = []
        for file in common_files:
            url = urljoin(self.target_url, file)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    found_files.append(f"{file} (Size: {len(response.content)} bytes)")
            except:
                continue

        return found_files

    def detect_application_type(self):
        """Detect specific vulnerable application"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()

            if 'juice shop' in content or 'owasp juice shop' in content:
                return "OWASP Juice Shop"
            elif 'damn vulnerable web application' in content or 'dvwa' in content:
                return "DVWA"
            elif 'xvwa' in content or 'xtreme vulnerable' in content:
                return "XVWA"
            elif 'webgoat' in content:
                return "WebGoat"
            else:
                return "Unknown Application"

        except Exception as e:
            print(f"Error detecting application: {e}")
            return "Unknown"

    def fingerprint(self):
        """Main fingerprinting function"""
        print(f"Fingerprinting: {self.target_url}")
        print("=" * 50)

        # Application type
        app_type = self.detect_application_type()
        print(f"Application Type: {app_type}")

        # Headers
        headers = self.get_headers()
        print("\nResponse Headers:")
        for key, value in headers.items():
            print(f"  {key}: {value}")

        # Technologies
        technologies = self.detect_technology()
        print(f"\nDetected Technologies:")
        for tech in technologies:
            print(f"  - {tech}")

        # Common files
        files = self.check_common_files()
        print(f"\nFound Files:")
        for file in files:
            print(f"  - {file}")

        return {
            'application_type': app_type,
            'headers': headers,
            'technologies': technologies,
            'files': files
        }

if __name__ == "__main__":
    targets = [
        "http://10.30.0.237:3000",  # Juice Shop
        "http://10.30.0.235/dvwa",  # DVWA
        "http://10.30.0.237:3001/xvwa",  # XVWA
        "http://10.30.0.237:8080/WebGoat"  # WebGoat
    ]

    for target in targets:
        fingerprinter = WebAppFingerprinter(target)
        result = fingerprinter.fingerprint()
        print("\n" + "="*70 + "\n")
```

## Attack Detection and Monitoring

### Wireshark Detection Signatures

```
# HTTP fingerprinting detection filters
http.request.method == "HEAD" and http.request.uri contains "robots.txt"
http.request.method == "OPTIONS"
http.user_agent contains "whatweb" or http.user_agent contains "nmap"
http.request.uri contains "/sitemap.xml" or http.request.uri contains "/crossdomain.xml"

# Multiple rapid requests pattern
frame.time_delta < 0.1 and http.request.method == "GET"

# Technology enumeration patterns
http.request.uri matches "\\.(php|asp|aspx|jsp|do)$"
http.response.code == 404 and frame.time_delta < 1
```

**Wireshark Analysis Steps:**

1. Capture traffic during reconnaissance phase
2. Filter for HTTP HEAD requests and technology-specific file extensions
3. Look for rapid-fire requests indicating automated scanning
4. Monitor User-Agent strings for reconnaissance tools

### Splunk Detection Queries

```spl
# Web application fingerprinting detection
index=web_logs sourcetype=access_combined
| search (uri_path="/robots.txt" OR uri_path="/sitemap.xml" OR uri_path="crossdomain.xml")
| stats count by src_ip, user_agent
| where count > 5

# Technology enumeration detection
index=web_logs sourcetype=access_combined
| search uri_path="*.php" OR uri_path="*.jsp" OR uri_path="*.asp"
| eval tech_enum=case(
    match(uri_path, "\.php$"), "PHP_scan",
    match(uri_path, "\.jsp$"), "Java_scan",
    match(uri_path, "\.asp$"), "ASP_scan"
)
| stats count by src_ip, tech_enum
| where count > 10

# Automated tool detection by User-Agent
index=web_logs sourcetype=access_combined
| search user_agent="*nmap*" OR user_agent="*whatweb*" OR user_agent="*gobuster*"
| stats count by src_ip, user_agent
| sort -count

# Rapid request pattern detection
index=web_logs sourcetype=access_combined
| bucket _time span=10s
| stats count by _time, src_ip
| where count > 50
| sort -_time
```

### SIEM Alert Rules

```yaml
# ELK Stack Detection Rule
- rule:
    name: "Web Application Fingerprinting"
    condition: >
      (http.request.uri.path in ["/robots.txt", "/sitemap.xml", "/crossdomain.xml"]) or
      (http.user_agent contains ["nmap", "whatweb", "wappalyzer"]) or
      (http.response.status_code == 404 and event.rate > 10/minute)
    severity: medium
    tags: ["reconnaissance", "fingerprinting"]

# QRadar AQL Query
SELECT sourceip, "User-Agent", COUNT(*) as request_count
FROM events
WHERE "User-Agent" ILIKE '%nmap%' OR "User-Agent" ILIKE '%whatweb%'
GROUP BY sourceip, "User-Agent"
HAVING COUNT(*) > 5
LAST 1 HOURS
```

### Security Tools Detection

**Suricata Rules:**

```
alert http any any -> any any (msg:"Web Application Fingerprinting - robots.txt"; flow:established,to_server; http_uri; content:"/robots.txt"; nocase; sid:1001001;)
alert http any any -> any any (msg:"Web Application Fingerprinting - Technology Scan"; flow:established,to_server; http_user_agent; content:"whatweb"; nocase; sid:1001002;)
alert http any any -> any any (msg:"Web Application Fingerprinting - Nmap NSE"; flow:established,to_server; http_user_agent; content:"nmap"; nocase; sid:1001003;)
```

**Snort Rules:**

```
alert tcp any any -> any 80 (msg:"HTTP fingerprinting attempt"; flow:established,to_server; content:"HEAD"; http_method; content:"User-Agent|3A| Mozilla"; http_header; reference:url,attack.mitre.org/T1595; sid:1001004;)
```

### Network Monitoring Indicators

**Key Metrics to Monitor:**

- **Request Rate**: > 10 requests/second to common files
- **404 Error Rate**: High 404 responses in short time window
- **User-Agent Patterns**: Known reconnaissance tool signatures
- **URI Patterns**: Requests to technology-specific files (.php, .jsp, .asp)
- **Response Time Analysis**: Consistent timing may indicate automated tools

**Log Analysis Commands:**

```bash
# Apache/Nginx log analysis for fingerprinting
grep -E "(robots\.txt|sitemap\.xml|\.php|\.jsp|\.asp)" access.log | awk '{print $1}' | sort | uniq -c | sort -nr

# Failed request analysis
grep " 404 " access.log | awk '{print $1, $7}' | sort | uniq -c | sort -nr | head -20

# User-Agent analysis for known tools
grep -E "(nmap|whatweb|wappalyzer|gobuster)" access.log | awk -F'"' '{print $6}' | sort | uniq -c
```

## Detection Methods

### Successful Fingerprinting Indicators:

- Server headers revealed
- Technology stack identified
- Application type determined
- Configuration files discovered

### Common Findings:

- **Juice Shop**: Express.js, Angular, Node.js indicators
- **DVWA**: Apache, PHP, MySQL indicators
- **XVWA**: Apache, PHP indicators
- **WebGoat**: Tomcat, Java indicators

## Mitigation Recommendations

1. **Header Hardening**:

   - Remove or obscure server headers
   - Implement security headers

2. **File Security**:

   - Restrict access to configuration files
   - Remove unnecessary files

3. **Technology Obscuration**:

   - Remove version information
   - Use reverse proxies

4. **Monitoring**:
   - Log reconnaissance attempts
   - Implement rate limiting

## Next Steps

- Use gathered information for targeted attacks
- Proceed to directory enumeration (Playbook 02)
- Plan specific technology-based exploits
