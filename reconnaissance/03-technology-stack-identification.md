# Playbook 03: Technology Stack Identification

## Objective

Perform deep technology stack analysis to identify specific versions, components, and potential vulnerabilities in the target applications.

## Target Applications

- OWASP Juice Shop (Node.js, Express, Angular, SQLite)
- DVWA (Apache, PHP, MySQL)
- XVWA (Apache, PHP, MySQL, Multiple Languages)
- WebGoat (Java, Spring, Tomcat)

## Prerequisites

- Nmap with scripts
- Wappalyzer CLI
- Retire.js
- Custom version detection tools
- Burp Suite Professional
- Python 3 with specialized libraries

## Manual Commands

### 1. HTTP Header Analysis

```bash
# Detailed header analysis
curl -I -X GET http://target:3000
curl -I -X OPTIONS http://target:3000
curl -I -X POST http://target:3000

# Security headers check
curl -I http://target:3000 | grep -E "(Server|X-Powered-By|X-AspNet-Version|X-Generator)"

# Custom headers enumeration
for method in GET POST PUT DELETE OPTIONS TRACE; do
    echo "=== $method ==="
    curl -I -X $method http://target:3000 2>/dev/null | head -20
done
```

### 2. JavaScript Library Detection

```bash
# Download and analyze JavaScript files
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off http://target:3000/

# Check for library versions
grep -r "version\|Version\|VERSION" *.js
grep -r "jquery\|angular\|react\|vue" *.js

# Retire.js for vulnerable libraries
retire --js --outputformat json --outputpath retire_results.json
```

### 3. Framework-Specific Detection

```bash
# Node.js/Express detection
curl -s http://target:3000 | grep -i "express\|node"
nmap --script http-server-header target

# PHP version detection
curl -s http://target/dvwa | grep -i "php"
nmap --script http-php-version target

# Java/Tomcat detection
curl -I http://target:8080/WebGoat | grep -i "tomcat\|java"
nmap --script http-server-header target -p 8080
```

### 4. Database Detection

```bash
# Error-based database detection
curl "http://target/dvwa/vulnerabilities/sqli/?id=1'" --cookie "security=low; PHPSESSID=..."

# Database port scanning
nmap -sV -p 3306,5432,1521,1433 target

# MongoDB detection (for modern apps)
nmap -p 27017 target
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Advanced Technology Stack Identification
Supports: Juice Shop, DVWA, XVWA, WebGoat
"""

import requests
import re
import json
import socket
import subprocess
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import hashlib

class TechnologyStackAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.technologies = {}

    def analyze_headers(self):
        """Analyze HTTP headers for technology indicators"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = dict(response.headers)

            tech_indicators = {
                'server': headers.get('server', ''),
                'x_powered_by': headers.get('x-powered-by', ''),
                'x_generator': headers.get('x-generator', ''),
                'x_aspnet_version': headers.get('x-aspnet-version', ''),
                'set_cookie': headers.get('set-cookie', ''),
                'content_type': headers.get('content-type', '')
            }

            # Analyze indicators
            technologies = {}

            # Server detection
            server = tech_indicators['server'].lower()
            if 'apache' in server:
                technologies['web_server'] = f"Apache {self.extract_version(server, 'apache')}"
            elif 'nginx' in server:
                technologies['web_server'] = f"Nginx {self.extract_version(server, 'nginx')}"
            elif 'iis' in server:
                technologies['web_server'] = f"IIS {self.extract_version(server, 'microsoft-iis')}"

            # Application server detection
            powered_by = tech_indicators['x_powered_by'].lower()
            if 'php' in powered_by:
                technologies['language'] = f"PHP {self.extract_version(powered_by, 'php')}"
            elif 'asp.net' in powered_by:
                technologies['framework'] = f"ASP.NET {self.extract_version(powered_by, 'asp.net')}"

            # Cookie analysis
            cookies = tech_indicators['set_cookie']
            if 'jsessionid' in cookies:
                technologies['session_management'] = 'Java Servlet'
            elif 'phpsessid' in cookies:
                technologies['session_management'] = 'PHP Session'
            elif 'asp.net_sessionid' in cookies:
                technologies['session_management'] = 'ASP.NET Session'

            return technologies

        except Exception as e:
            print(f"Error analyzing headers: {e}")
            return {}

    def extract_version(self, text, technology):
        """Extract version numbers from text"""
        patterns = {
            'apache': r'apache[/\s]([0-9.]+)',
            'nginx': r'nginx[/\s]([0-9.]+)',
            'php': r'php[/\s]([0-9.]+)',
            'microsoft-iis': r'microsoft-iis[/\s]([0-9.]+)',
            'asp.net': r'asp\.net[/\s]([0-9.]+)'
        }

        pattern = patterns.get(technology.lower(), r'([0-9.]+)')
        match = re.search(pattern, text.lower())
        return match.group(1) if match else 'Unknown'

    def analyze_javascript_libraries(self):
        """Analyze JavaScript libraries and frameworks"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all script tags
            scripts = soup.find_all('script')
            libraries = {}

            # Common library patterns
            library_patterns = {
                'jquery': [
                    r'jquery[.-]([0-9.]+)',
                    r'\$\.fn\.jquery\s*=\s*["\']([0-9.]+)["\']'
                ],
                'angular': [
                    r'angular[.-]([0-9.]+)',
                    r'ng-version["\']?\s*[:=]\s*["\']?([0-9.]+)',
                    r'@angular/core["\']?\s*[:=]\s*["\']?\^?([0-9.]+)'
                ],
                'react': [
                    r'react[.-]([0-9.]+)',
                    r'React\.version\s*=\s*["\']([0-9.]+)["\']'
                ],
                'vue': [
                    r'vue[.-]([0-9.]+)',
                    r'Vue\.version\s*=\s*["\']([0-9.]+)["\']'
                ],
                'bootstrap': [
                    r'bootstrap[.-]([0-9.]+)'
                ],
                'express': [
                    r'express[.-]([0-9.]+)',
                    r'"express"\s*:\s*["\'][\^~]?([0-9.]+)["\']'
                ]
            }

            # Analyze inline scripts and external sources
            all_script_content = response.text

            for script in scripts:
                if script.get('src'):
                    # External script
                    src = script['src']
                    all_script_content += f"\n{src}"

                    # Try to fetch external script
                    try:
                        script_url = urljoin(self.target_url, src)
                        script_response = self.session.get(script_url, timeout=5)
                        all_script_content += script_response.text
                    except:
                        pass

                if script.string:
                    all_script_content += script.string

            # Apply patterns
            for library, patterns in library_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, all_script_content, re.IGNORECASE)
                    if match:
                        libraries[library] = match.group(1)
                        break

            return libraries

        except Exception as e:
            print(f"Error analyzing JavaScript: {e}")
            return {}

    def detect_application_framework(self):
        """Detect specific application frameworks"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()

            frameworks = {}

            # Framework detection patterns
            if 'owasp juice shop' in content or 'juice-shop' in content:
                frameworks['application'] = 'OWASP Juice Shop'
                frameworks['description'] = 'Node.js/Express vulnerable application'

                # Try to get version from package info
                try:
                    pkg_response = self.session.get(f"{self.target_url}/package.json")
                    if pkg_response.status_code == 200:
                        pkg_data = pkg_response.json()
                        frameworks['version'] = pkg_data.get('version', 'Unknown')
                except:
                    pass

            elif 'damn vulnerable web application' in content or 'dvwa' in content:
                frameworks['application'] = 'DVWA'
                frameworks['description'] = 'PHP/MySQL vulnerable application'

                # Check for version indicators
                version_match = re.search(r'dvwa[^0-9]*([0-9.]+)', content)
                if version_match:
                    frameworks['version'] = version_match.group(1)

            elif 'xtreme vulnerable web application' in content or 'xvwa' in content:
                frameworks['application'] = 'XVWA'
                frameworks['description'] = 'Multi-language vulnerable application'

            elif 'webgoat' in content:
                frameworks['application'] = 'WebGoat'
                frameworks['description'] = 'Java/Spring vulnerable application'

                # Try to detect Spring version
                if 'spring' in content:
                    spring_match = re.search(r'spring[^0-9]*([0-9.]+)', content)
                    if spring_match:
                        frameworks['spring_version'] = spring_match.group(1)

            return frameworks

        except Exception as e:
            print(f"Error detecting framework: {e}")
            return {}

    def database_detection(self):
        """Detect database technologies"""
        databases = {}

        # Port-based detection
        common_db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1521: 'Oracle',
            1433: 'SQL Server',
            27017: 'MongoDB',
            6379: 'Redis'
        }

        target_host = urlparse(self.target_url).hostname

        for port, db_name in common_db_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_host, port))
            sock.close()

            if result == 0:
                databases[db_name.lower()] = {
                    'port': port,
                    'status': 'Open'
                }

        return databases

    def cms_detection(self):
        """Detect Content Management Systems"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text

            cms_indicators = {}

            # WordPress detection
            if 'wp-content' in content or 'wordpress' in content.lower():
                cms_indicators['wordpress'] = True

                # Try to get version
                wp_version = re.search(r'wp-includes[^"]*ver=([0-9.]+)', content)
                if wp_version:
                    cms_indicators['wordpress_version'] = wp_version.group(1)

            # Drupal detection
            if 'drupal' in content.lower() or '/sites/default/' in content:
                cms_indicators['drupal'] = True

            # Joomla detection
            if 'joomla' in content.lower() or '/components/' in content:
                cms_indicators['joomla'] = True

            return cms_indicators

        except Exception as e:
            print(f"Error detecting CMS: {e}")
            return {}

    def security_headers_analysis(self):
        """Analyze security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = dict(response.headers)

            security_headers = {
                'x-frame-options': headers.get('x-frame-options'),
                'x-xss-protection': headers.get('x-xss-protection'),
                'x-content-type-options': headers.get('x-content-type-options'),
                'strict-transport-security': headers.get('strict-transport-security'),
                'content-security-policy': headers.get('content-security-policy'),
                'x-content-security-policy': headers.get('x-content-security-policy'),
                'referrer-policy': headers.get('referrer-policy')
            }

            # Calculate security score
            score = 0
            total = len(security_headers)

            for header, value in security_headers.items():
                if value:
                    score += 1

            security_headers['security_score'] = f"{score}/{total}"

            return security_headers

        except Exception as e:
            print(f"Error analyzing security headers: {e}")
            return {}

    def comprehensive_analysis(self):
        """Perform comprehensive technology stack analysis"""
        print(f"Analyzing technology stack for: {self.target_url}")
        print("=" * 60)

        results = {
            'url': self.target_url,
            'headers': self.analyze_headers(),
            'javascript_libraries': self.analyze_javascript_libraries(),
            'application_framework': self.detect_application_framework(),
            'databases': self.database_detection(),
            'cms': self.cms_detection(),
            'security_headers': self.security_headers_analysis()
        }

        # Print results
        for category, data in results.items():
            if category == 'url':
                continue

            print(f"\n{category.replace('_', ' ').title()}:")
            if isinstance(data, dict):
                for key, value in data.items():
                    if value:
                        print(f"  {key}: {value}")
            else:
                print(f"  {data}")

        return results

class VulnerabilityScanner:
    """Scan for known vulnerabilities based on detected technologies"""

    def __init__(self, technologies):
        self.technologies = technologies

    def check_vulnerable_libraries(self):
        """Check for known vulnerable JavaScript libraries"""
        vulnerable_libs = {
            'jquery': {
                '1.6.0': ['CVE-2011-4969'],
                '1.7.2': ['CVE-2012-6708'],
                '2.1.4': ['CVE-2015-9251'],
                '3.3.1': ['CVE-2019-11358']
            },
            'angular': {
                '1.5.0': ['CVE-2019-10768'],
                '1.6.0': ['CVE-2018-17057']
            }
        }

        vulnerabilities = []
        js_libs = self.technologies.get('javascript_libraries', {})

        for lib, version in js_libs.items():
            if lib in vulnerable_libs:
                for vuln_version, cves in vulnerable_libs[lib].items():
                    if version and version <= vuln_version:
                        vulnerabilities.extend(cves)

        return vulnerabilities

    def check_application_vulnerabilities(self):
        """Check for application-specific vulnerabilities"""
        app_vulns = []
        framework = self.technologies.get('application_framework', {})

        app_name = framework.get('application', '').lower()

        if 'juice shop' in app_name:
            app_vulns.extend([
                'Intentionally vulnerable (100+ OWASP Top 10 vulnerabilities)',
                'SQL Injection', 'XSS', 'Broken Authentication',
                'Insecure Direct Object References', 'Security Misconfiguration'
            ])
        elif 'dvwa' in app_name:
            app_vulns.extend([
                'Brute Force', 'Command Injection', 'CSRF',
                'File Inclusion', 'File Upload', 'Insecure CAPTCHA',
                'SQL Injection', 'XSS (DOM/Reflected/Stored)', 'Weak Session IDs'
            ])
        elif 'webgoat' in app_name:
            app_vulns.extend([
                'Injection Flaws', 'Broken Authentication',
                'Cross-Site Scripting', 'Insecure Direct Object References',
                'Security Misconfiguration', 'Sensitive Data Exposure'
            ])

        return app_vulns

if __name__ == "__main__":
    targets = [
        "http://localhost:3000",      # Juice Shop
        "http://localhost/dvwa",      # DVWA
        "http://localhost/xvwa",      # XVWA
        "http://localhost:8080/WebGoat"  # WebGoat
    ]

    for target in targets:
        analyzer = TechnologyStackAnalyzer(target)
        results = analyzer.comprehensive_analysis()

        # Vulnerability scanning
        vuln_scanner = VulnerabilityScanner(results)
        js_vulns = vuln_scanner.check_vulnerable_libraries()
        app_vulns = vuln_scanner.check_application_vulnerabilities()

        if js_vulns:
            print(f"\nJavaScript Library Vulnerabilities:")
            for vuln in js_vulns:
                print(f"  - {vuln}")

        if app_vulns:
            print(f"\nApplication Vulnerabilities:")
            for vuln in app_vulns:
                print(f"  - {vuln}")

        print("\n" + "="*80 + "\n")
```

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**Technology Stack Fingerprinting Detection:**

```wireshark
# HTTP technology stack enumeration detection
http.request.method == "HEAD" or http.request.method == "OPTIONS"

# Server header analysis detection
http.response and http.server contains "Apache" or http.server contains "nginx" or http.server contains "IIS"

# JavaScript library reconnaissance
http.request.uri contains ".js" and (http.request.method == "GET" or http.request.method == "HEAD")

# SSL/TLS fingerprinting detection
ssl.handshake.type == 1 or tls.handshake.type == 1

# Service enumeration on database ports
tcp.port in {3306 5432 1521 1433 27017} and tcp.flags.syn == 1

# Error page enumeration for version disclosure
http.response.code >= 400 and http.response.code < 500
```

### Splunk Detection Queries

**Technology Stack Reconnaissance Monitoring:**

```splunk
# HTTP header analysis reconnaissance
index=web_logs sourcetype=access_combined
| search method IN ("HEAD", "OPTIONS")
| stats count by src_ip, dest_ip, uri, user_agent
| where count > 10
| eval priority="medium"

# JavaScript library enumeration detection
index=web_logs sourcetype=access_combined
| search uri="*.js" method IN ("GET", "HEAD")
| stats count dc(uri) as unique_js_files by src_ip
| where count > 20 OR unique_js_files > 15
| eval activity_type="js_library_enumeration"

# Service scanning on database ports
index=network_logs sourcetype=firewall
| search dest_port IN (3306, 5432, 1521, 1433, 27017) action="allow"
| stats count dc(dest_port) as scanned_ports by src_ip
| where scanned_ports >= 3
| eval attack_stage="service_enumeration"

# SSL/TLS fingerprinting detection
index=ssl_logs sourcetype=ssl_handshake
| search ssl_version="*" cipher_suite="*"
| stats count dc(cipher_suite) as cipher_attempts by src_ip, dest_ip
| where cipher_attempts > 5
| eval reconnaissance_type="ssl_fingerprinting"

# Technology stack error harvesting
index=web_logs sourcetype=access_combined
| search status>=400 status<500
| rex field=uri "(?<path>[^?]*)"
| stats count dc(path) as unique_error_paths by src_ip
| where count > 15 AND unique_error_paths > 10
| eval activity="error_page_enumeration"
```

### SIEM Integration

**QRadar AQL Queries:**

```aql
-- HTTP technology enumeration detection
SELECT sourceip, destinationip, "URL", method, count(*) as request_count
FROM events
WHERE category = 'Web Access'
AND method IN ('HEAD', 'OPTIONS')
GROUP BY sourceip, destinationip, "URL", method
HAVING count(*) > 15
LAST 1 HOURS

-- JavaScript library reconnaissance
SELECT sourceip, count(*) as js_requests, count(DISTINCT "URL") as unique_js_files
FROM events
WHERE category = 'Web Access'
AND "URL" LIKE '%.js'
AND method IN ('GET', 'HEAD')
GROUP BY sourceip
HAVING js_requests > 30 OR unique_js_files > 20
LAST 2 HOURS

-- Database service scanning
SELECT sourceip, destinationip, destinationport, count(*) as scan_attempts
FROM events
WHERE category = 'Network Activity'
AND destinationport IN (3306, 5432, 1521, 1433, 27017)
GROUP BY sourceip, destinationip, destinationport
HAVING count(*) > 5
LAST 1 HOURS
```

**Elastic Stack Detection Rules:**

```json
{
  "rule": {
    "name": "Technology Stack Fingerprinting Detection",
    "query": {
      "bool": {
        "should": [
          {
            "bool": {
              "must": [
                { "term": { "http.request.method": "HEAD" } },
                { "range": { "@timestamp": { "gte": "now-1h" } } }
              ]
            }
          },
          {
            "bool": {
              "must": [
                { "wildcard": { "url.path": "*.js" } },
                { "terms": { "http.request.method": ["GET", "HEAD"] } }
              ]
            }
          },
          {
            "bool": {
              "must": [
                {
                  "terms": {
                    "destination.port": [3306, 5432, 1521, 1433, 27017]
                  }
                },
                { "term": { "event.category": "network" } }
              ]
            }
          }
        ]
      }
    },
    "threshold": {
      "field": "source.ip",
      "value": 20
    }
  }
}
```

### Network Security Monitoring

**Suricata Rules:**

```suricata
# HTTP header enumeration detection
alert http any any -> any any (msg:"Technology Stack Fingerprinting - Excessive HEAD/OPTIONS Requests"; flow:established,to_server; http_method; content:"HEAD"; threshold:type both, track by_src, count 15, seconds 300; classtype:web-application-activity; sid:3001001; rev:1;)

alert http any any -> any any (msg:"Technology Stack Fingerprinting - OPTIONS Method Enumeration"; flow:established,to_server; http_method; content:"OPTIONS"; threshold:type both, track by_src, count 10, seconds 300; classtype:web-application-activity; sid:3001002; rev:1;)

# JavaScript library enumeration
alert http any any -> any any (msg:"JavaScript Library Enumeration Detected"; flow:established,to_server; http_uri; content:".js"; threshold:type both, track by_src, count 25, seconds 300; classtype:web-application-activity; sid:3001003; rev:1;)

# Database service scanning
alert tcp any any -> any 3306 (msg:"MySQL Service Scanning Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:3001004; rev:1;)

alert tcp any any -> any 5432 (msg:"PostgreSQL Service Scanning Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:3001005; rev:1;)

alert tcp any any -> any 27017 (msg:"MongoDB Service Scanning Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:3001006; rev:1;)

# SSL/TLS fingerprinting
alert tls any any -> any any (msg:"SSL/TLS Fingerprinting Activity"; threshold:type both, track by_src, count 20, seconds 300; classtype:protocol-command-decode; sid:3001007; rev:1;)
```

**Snort Rules:**

```snort
# Technology enumeration detection
alert tcp any any -> any 80 (msg:"Web Technology Stack Enumeration"; content:"HEAD"; http_method; threshold:type both, track by_src, count 15, seconds 300; classtype:web-application-activity; sid:3001101; rev:1;)

alert tcp any any -> any 443 (msg:"HTTPS Technology Stack Enumeration"; content:"HEAD"; http_method; threshold:type both, track by_src, count 15, seconds 300; classtype:web-application-activity; sid:3001102; rev:1;)

# Error page harvesting
alert tcp any any -> any any (msg:"Error Page Enumeration for Technology Disclosure"; flow:established,from_server; content:"404"; http_stat_code; threshold:type both, track by_src, count 20, seconds 300; classtype:web-application-activity; sid:3001103; rev:1;)
```

### Log Analysis Scripts

**Apache/Nginx Detection Script:**

```bash
#!/bin/bash
# Technology stack fingerprinting detection in web logs

LOG_FILE="/var/log/apache2/access.log"  # or /var/log/nginx/access.log
THRESHOLD=15
TIME_WINDOW=300  # 5 minutes

echo "=== Technology Stack Fingerprinting Detection ==="

# HEAD/OPTIONS method enumeration
echo "[+] Detecting HEAD/OPTIONS enumeration..."
awk -v threshold=$THRESHOLD -v window=$TIME_WINDOW '
BEGIN { current_time = systime() }
{
    if ($6 ~ /HEAD|OPTIONS/) {
        ip = $1
        timestamp = mktime(substr($4,2,19))
        if (current_time - timestamp <= window) {
            head_count[ip]++
        }
    }
}
END {
    for (ip in head_count) {
        if (head_count[ip] >= threshold) {
            print "[!] ALERT: " ip " made " head_count[ip] " HEAD/OPTIONS requests"
        }
    }
}' "$LOG_FILE"

# JavaScript enumeration detection
echo "[+] Detecting JavaScript file enumeration..."
awk -v threshold=20 -v window=$TIME_WINDOW '
BEGIN { current_time = systime() }
{
    if ($7 ~ /\.js(\?|$)/) {
        ip = $1
        timestamp = mktime(substr($4,2,19))
        if (current_time - timestamp <= window) {
            js_requests[ip]++
            unique_js[ip,$7] = 1
        }
    }
}
END {
    for (ip in js_requests) {
        unique_count = 0
        for (combo in unique_js) {
            if (split(combo, parts, SUBSEP) && parts[1] == ip) {
                unique_count++
            }
        }
        if (js_requests[ip] >= threshold || unique_count >= 15) {
            print "[!] ALERT: " ip " enumerated " js_requests[ip] " JS files (" unique_count " unique)"
        }
    }
}' "$LOG_FILE"
```

**PowerShell IIS Analysis:**

```powershell
# IIS technology fingerprinting detection
$LogPath = "C:\inetpub\logs\LogFiles\W3SVC1\"
$TimeThreshold = (Get-Date).AddMinutes(-5)

Get-ChildItem $LogPath -Filter "*.log" | ForEach-Object {
    $LogContent = Get-Content $_.FullName | Where-Object { $_ -notmatch "^#" }

    $LogContent | ForEach-Object {
        $Fields = $_ -split " "
        $DateTime = [DateTime]::Parse("$($Fields[0]) $($Fields[1])")

        if ($DateTime -gt $TimeThreshold) {
            $SourceIP = $Fields[2]
            $Method = $Fields[3]
            $URI = $Fields[4]
            $Status = $Fields[5]

            if ($Method -match "HEAD|OPTIONS") {
                $HeadRequests[$SourceIP]++
            }

            if ($URI -match "\.js$") {
                $JSRequests[$SourceIP]++
            }

            if ($Status -match "^4\d\d$") {
                $ErrorRequests[$SourceIP]++
            }
        }
    }
}

# Generate alerts
$HeadRequests.GetEnumerator() | Where-Object { $_.Value -gt 15 } | ForEach-Object {
    Write-Warning "Technology enumeration detected from $($_.Key): $($_.Value) HEAD/OPTIONS requests"
}

$JSRequests.GetEnumerator() | Where-Object { $_.Value -gt 20 } | ForEach-Object {
    Write-Warning "JavaScript enumeration detected from $($_.Key): $($_.Value) JS file requests"
}
```

### Python Behavioral Analysis

```python
#!/usr/bin/env python3
"""
Technology Stack Fingerprinting Detection Script
Analyzes web server logs for reconnaissance patterns
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse

class TechStackDetector:
    def __init__(self, log_file, time_window=300, head_threshold=15, js_threshold=20):
        self.log_file = log_file
        self.time_window = time_window
        self.head_threshold = head_threshold
        self.js_threshold = js_threshold

        # Pattern matching
        self.log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
        )
        self.js_pattern = re.compile(r'\.js(\?.*)?$')

        # Tracking dictionaries
        self.ip_requests = defaultdict(list)
        self.detection_results = []

    def parse_log_line(self, line):
        """Parse Apache/Nginx log line"""
        match = self.log_pattern.match(line)
        if not match:
            return None

        ip, timestamp_str, method, uri, status, referer, user_agent = match.groups()

        try:
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            return None

        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'uri': uri,
            'status': int(status),
            'user_agent': user_agent
        }

    def analyze_fingerprinting_patterns(self):
        """Analyze logs for technology fingerprinting patterns"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        with open(self.log_file, 'r') as f:
            for line in f:
                parsed = self.parse_log_line(line.strip())
                if not parsed or parsed['timestamp'] < cutoff_time:
                    continue

                self.ip_requests[parsed['ip']].append(parsed)

        self.detect_head_options_enumeration()
        self.detect_javascript_enumeration()
        self.detect_error_harvesting()
        self.detect_user_agent_patterns()

    def detect_head_options_enumeration(self):
        """Detect HEAD/OPTIONS method enumeration"""
        for ip, requests in self.ip_requests.items():
            head_options_count = sum(1 for req in requests
                                   if req['method'] in ['HEAD', 'OPTIONS'])

            if head_options_count >= self.head_threshold:
                self.detection_results.append({
                    'type': 'HTTP Method Enumeration',
                    'ip': ip,
                    'count': head_options_count,
                    'severity': 'medium',
                    'description': f'Excessive HEAD/OPTIONS requests detected'
                })

    def detect_javascript_enumeration(self):
        """Detect JavaScript library enumeration"""
        for ip, requests in self.ip_requests.items():
            js_requests = [req for req in requests if self.js_pattern.search(req['uri'])]
            unique_js_files = len(set(req['uri'] for req in js_requests))

            if len(js_requests) >= self.js_threshold or unique_js_files >= 15:
                self.detection_results.append({
                    'type': 'JavaScript Library Enumeration',
                    'ip': ip,
                    'count': len(js_requests),
                    'unique_files': unique_js_files,
                    'severity': 'medium',
                    'description': f'JavaScript library reconnaissance detected'
                })

    def detect_error_harvesting(self):
        """Detect error page harvesting for technology disclosure"""
        for ip, requests in self.ip_requests.items():
            error_requests = [req for req in requests if 400 <= req['status'] < 500]
            unique_error_uris = len(set(req['uri'] for req in error_requests))

            if len(error_requests) >= 20 and unique_error_uris >= 10:
                self.detection_results.append({
                    'type': 'Error Page Harvesting',
                    'ip': ip,
                    'count': len(error_requests),
                    'unique_pages': unique_error_uris,
                    'severity': 'high',
                    'description': f'Systematic error page enumeration for information disclosure'
                })

    def detect_user_agent_patterns(self):
        """Detect reconnaissance tool user agents"""
        scanner_agents = [
            'curl', 'wget', 'nmap', 'nikto', 'sqlmap', 'dirb', 'dirbuster',
            'gobuster', 'whatweb', 'wpscan', 'masscan', 'zap'
        ]

        for ip, requests in self.ip_requests.items():
            for req in requests:
                for scanner in scanner_agents:
                    if scanner.lower() in req['user_agent'].lower():
                        self.detection_results.append({
                            'type': 'Scanner Tool Detection',
                            'ip': ip,
                            'tool': scanner,
                            'user_agent': req['user_agent'],
                            'severity': 'high',
                            'description': f'Reconnaissance tool detected: {scanner}'
                        })
                        break

    def generate_report(self):
        """Generate detection report"""
        if not self.detection_results:
            print("No technology fingerprinting activity detected.")
            return

        print("=== Technology Stack Fingerprinting Detection Report ===\n")

        severity_counts = Counter(result['severity'] for result in self.detection_results)
        print(f"Total Detections: {len(self.detection_results)}")
        print(f"High Severity: {severity_counts['high']}")
        print(f"Medium Severity: {severity_counts['medium']}")
        print(f"Low Severity: {severity_counts['low']}\n")

        for result in sorted(self.detection_results, key=lambda x: x['severity'], reverse=True):
            print(f"[{result['severity'].upper()}] {result['type']}")
            print(f"  Source IP: {result['ip']}")
            print(f"  Description: {result['description']}")
            if 'count' in result:
                print(f"  Request Count: {result['count']}")
            if 'tool' in result:
                print(f"  Tool: {result['tool']}")
            print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Technology Stack Fingerprinting Detector')
    parser.add_argument('log_file', help='Path to web server log file')
    parser.add_argument('--time-window', type=int, default=300,
                       help='Time window in seconds (default: 300)')
    parser.add_argument('--head-threshold', type=int, default=15,
                       help='HEAD/OPTIONS threshold (default: 15)')
    parser.add_argument('--js-threshold', type=int, default=20,
                       help='JavaScript request threshold (default: 20)')

    args = parser.parse_args()

    detector = TechStackDetector(
        args.log_file,
        args.time_window,
        args.head_threshold,
        args.js_threshold
    )

    try:
        detector.analyze_fingerprinting_patterns()
        detector.generate_report()
    except FileNotFoundError:
        print(f"Error: Log file {args.log_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing logs: {e}")
        sys.exit(1)
```

### Key Detection Metrics

**Quantitative Indicators:**

- **HEAD/OPTIONS Requests**: >15 per 5-minute window per IP
- **JavaScript File Requests**: >20 requests or >15 unique files per IP
- **Database Port Scanning**: >3 different database ports within 1 hour
- **Error Page Enumeration**: >20 4xx errors with >10 unique URIs
- **SSL/TLS Probes**: >20 handshakes per 5-minute window
- **Scanner Tool Detection**: Any request with reconnaissance tool user agents

**Behavioral Patterns:**

- Systematic HTTP method enumeration (HEAD, OPTIONS, TRACE)
- Sequential port scanning on database services
- Bulk downloading of JavaScript/CSS resources
- Error code harvesting across multiple endpoints
- SSL cipher suite enumeration
- Technology-specific URL patterns (/.well-known/, /robots.txt, /sitemap.xml)

**Network Signatures:**

- Multiple HTTP methods against same endpoint
- Rapid port scanning patterns
- SSL/TLS version downgrade attempts
- Non-browser user agent strings
- Sequential URI enumeration patterns

## Detection Methods

### Technology Identification Success Indicators:

- Server headers revealing technology stack
- JavaScript library versions detected
- Database services identified
- Application frameworks recognized

### Version Detection:

- HTTP headers with version information
- JavaScript library version strings
- Error messages revealing versions
- Default pages showing software versions

## Mitigation Recommendations

1. **Header Hardening**:

   - Remove version information from headers
   - Implement custom error pages
   - Use security headers

2. **Library Management**:

   - Keep JavaScript libraries updated
   - Remove unused libraries
   - Use Content Security Policy

3. **Service Hardening**:

   - Change default ports
   - Disable unnecessary services
   - Implement proper access controls

4. **Information Disclosure Prevention**:
   - Remove debug information
   - Customize error messages
   - Hide system information

## Next Steps

- Use identified technologies for targeted attacks
- Check for known vulnerabilities in detected versions
- Proceed to DNS and subdomain enumeration (Playbook 04)
