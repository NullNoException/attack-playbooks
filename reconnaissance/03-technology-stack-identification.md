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

## Shell Script Automation

```bash
#!/bin/bash
# Technology Stack Identification Script

TARGET="$1"
OUTPUT_DIR="tech_analysis"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Technology Stack Analysis for $TARGET"

# Header analysis
echo "[+] Analyzing HTTP headers..."
curl -I "$TARGET" > "$OUTPUT_DIR/headers.txt" 2>/dev/null
curl -I -X OPTIONS "$TARGET" > "$OUTPUT_DIR/options_headers.txt" 2>/dev/null

# JavaScript analysis
echo "[+] Downloading JavaScript files..."
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off "$TARGET" -P "$OUTPUT_DIR/js/" 2>/dev/null

# Library detection
echo "[+] Detecting JavaScript libraries..."
grep -r "jquery\|angular\|react\|vue\|bootstrap" "$OUTPUT_DIR/js/" > "$OUTPUT_DIR/js_libraries.txt" 2>/dev/null

# Server detection
echo "[+] Server detection..."
nmap --script http-server-header,http-title "$TARGET" > "$OUTPUT_DIR/nmap_http.txt"

# SSL/TLS analysis
echo "[+] SSL/TLS analysis..."
nmap --script ssl-enum-ciphers -p 443 "$TARGET" > "$OUTPUT_DIR/ssl_analysis.txt" 2>/dev/null

# Security headers check
echo "[+] Security headers analysis..."
curl -I "$TARGET" | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy)" > "$OUTPUT_DIR/security_headers.txt"

# Database detection
echo "[+] Database detection..."
nmap -sV -p 3306,5432,1521,1433,27017 "$TARGET" > "$OUTPUT_DIR/database_ports.txt"

echo "[+] Analysis complete. Results saved in $OUTPUT_DIR/"
```

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
