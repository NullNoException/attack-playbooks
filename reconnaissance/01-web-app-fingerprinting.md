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
        "http://localhost:3000",  # Juice Shop
        "http://localhost/dvwa",  # DVWA
        "http://localhost/xvwa",  # XVWA
        "http://localhost:8080/WebGoat"  # WebGoat
    ]

    for target in targets:
        fingerprinter = WebAppFingerprinter(target)
        result = fingerprinter.fingerprint()
        print("\n" + "="*70 + "\n")
```

## Shell Script Automation

```bash
#!/bin/bash
# Web Application Fingerprinting Script

TARGET_IP="$1"
OUTPUT_DIR="fingerprint_results"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting Web Application Fingerprinting for $TARGET_IP"

# Port scanning
echo "[+] Port scanning..."
nmap -sV -p 80,443,8080,3000,8443 "$TARGET_IP" > "$OUTPUT_DIR/port_scan.txt"

# Web technology detection
echo "[+] Technology detection..."
whatweb "http://$TARGET_IP" > "$OUTPUT_DIR/whatweb.txt" 2>/dev/null
whatweb "http://$TARGET_IP:3000" >> "$OUTPUT_DIR/whatweb.txt" 2>/dev/null
whatweb "http://$TARGET_IP:8080" >> "$OUTPUT_DIR/whatweb.txt" 2>/dev/null

# HTTP headers
echo "[+] Gathering HTTP headers..."
curl -I "http://$TARGET_IP" > "$OUTPUT_DIR/headers_80.txt" 2>/dev/null
curl -I "http://$TARGET_IP:3000" > "$OUTPUT_DIR/headers_3000.txt" 2>/dev/null
curl -I "http://$TARGET_IP:8080" > "$OUTPUT_DIR/headers_8080.txt" 2>/dev/null

# Common files
echo "[+] Checking common files..."
for file in robots.txt sitemap.xml crossdomain.xml; do
    curl -s "http://$TARGET_IP/$file" -o "$OUTPUT_DIR/$file" 2>/dev/null
    curl -s "http://$TARGET_IP:3000/$file" -o "$OUTPUT_DIR/${file}_3000" 2>/dev/null
    curl -s "http://$TARGET_IP:8080/$file" -o "$OUTPUT_DIR/${file}_8080" 2>/dev/null
done

echo "[+] Results saved in $OUTPUT_DIR/"
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
