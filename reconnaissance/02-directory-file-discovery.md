# Playbook 02: Directory and File Discovery

## Objective

Discover hidden directories, files, and endpoints in web applications to identify potential attack vectors and sensitive information exposure.

## Target Applications

- OWASP Juice Shop (Node.js structure)
- DVWA (PHP application structure)
- XVWA (PHP/multi-language structure)
- WebGoat (Java servlet structure)

## Prerequisites

- Gobuster
- Dirb
- Dirsearch
- Feroxbuster
- Custom wordlists
- Python 3 with requests

## Manual Commands

### 1. Basic Directory Enumeration

```bash
# Using Gobuster
gobuster dir -u http://target:3000 -w /usr/share/wordlists/dirb/common.txt -t 50

# Using Dirb
dirb http://target:3000 /usr/share/wordlists/dirb/common.txt

# Using Dirsearch
python3 dirsearch.py -u http://target:3000 -e php,html,js,txt,xml

# Using Feroxbuster (recursive)
feroxbuster -u http://target:3000 -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt
```

### 2. Technology-Specific Enumeration

```bash
# For PHP applications (DVWA, XVWA)
gobuster dir -u http://target/dvwa -w /usr/share/wordlists/dirb/common.txt -x php,inc,config

# For Java applications (WebGoat)
gobuster dir -u http://target:8080/WebGoat -w /usr/share/wordlists/dirb/common.txt -x jsp,do,action

# For Node.js applications (Juice Shop)
gobuster dir -u http://target:3000 -w /usr/share/wordlists/dirb/common.txt -x js,json,env
```

### 3. API Endpoint Discovery

```bash
# Common API paths
gobuster dir -u http://target:3000 -w api-wordlist.txt -p /api/

# RESTful endpoint patterns
for method in users admin products orders; do
    curl -s "http://target:3000/api/$method" | head -20
done
```

## Custom Wordlists

### Application-Specific Wordlist Creation

```bash
# Create Juice Shop specific wordlist
cat > juice-shop-wordlist.txt << EOF
api
socket.io
rest
ftp
administration
accounting
juice-shop
products
users
orders
basket
complaints
reviews
challenges
score-board
EOF

# Create DVWA specific wordlist
cat > dvwa-wordlist.txt << EOF
dvwa
setup
security
vulnerabilities
instructions
ids_logs
hackable
config
database
login
logout
vulnerabilities
brute_force
command_injection
csrf
file_inclusion
file_upload
insecure_captcha
sql_injection
weak_session_ids
xss_dom
xss_reflected
xss_stored
EOF

# Create WebGoat specific wordlist
cat > webgoat-wordlist.txt << EOF
WebGoat
lessons
attack
service
conf
source
images
css
javascript
META-INF
WEB-INF
classes
lib
EOF
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Advanced Directory and File Discovery Script
Supports: Juice Shop, DVWA, XVWA, WebGoat
"""

import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import argparse

class DirectoryDiscovery:
    def __init__(self, target_url, wordlist_file, extensions=None, threads=20):
        self.target_url = target_url.rstrip('/')
        self.wordlist_file = wordlist_file
        self.extensions = extensions or ['', '.php', '.html', '.js', '.txt', '.xml', '.json']
        self.threads = threads
        self.found_paths = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def load_wordlist(self):
        """Load wordlist from file"""
        try:
            with open(self.wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Wordlist file {self.wordlist_file} not found")
            return []

    def check_path(self, path):
        """Check if a path exists"""
        url = urljoin(self.target_url, path)
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)

            # Consider various status codes as interesting
            if response.status_code in [200, 201, 202, 301, 302, 401, 403]:
                size = len(response.content)
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': size,
                    'redirect': response.headers.get('location', '')
                }
        except:
            pass
        return None

    def generate_paths(self, wordlist):
        """Generate paths with extensions"""
        paths = []
        for word in wordlist:
            for ext in self.extensions:
                paths.append(f"{word}{ext}")
        return paths

    def discover_directories(self):
        """Main discovery function"""
        print(f"Starting directory discovery on {self.target_url}")
        print(f"Using {self.threads} threads")

        wordlist = self.load_wordlist()
        if not wordlist:
            return []

        paths = self.generate_paths(wordlist)
        print(f"Testing {len(paths)} paths...")

        found_results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_path, path): path for path in paths}

            for future in futures:
                result = future.result()
                if result:
                    found_results.append(result)
                    status_color = '\033[92m' if result['status'] == 200 else '\033[93m'
                    print(f"{status_color}[{result['status']}]\033[0m {result['url']} ({result['size']} bytes)")

        return found_results

    def recursive_discovery(self, found_dirs, depth=1, max_depth=2):
        """Recursive directory discovery"""
        if depth > max_depth:
            return []

        additional_findings = []

        for item in found_dirs:
            if item['status'] in [200, 301, 302] and item['url'].endswith('/'):
                print(f"Recursively scanning: {item['url']}")

                # Create new instance for subdirectory
                sub_discovery = DirectoryDiscovery(item['url'], self.wordlist_file, self.extensions, self.threads)
                sub_results = sub_discovery.discover_directories()
                additional_findings.extend(sub_results)

                # Recursive call with increased depth
                additional_findings.extend(
                    self.recursive_discovery(sub_results, depth + 1, max_depth)
                )

        return additional_findings

class ApplicationSpecificDiscovery:
    """Application-specific discovery patterns"""

    @staticmethod
    def juice_shop_discovery(target_url):
        """Juice Shop specific paths"""
        specific_paths = [
            'api/products',
            'api/users',
            'api/orders',
            'api/reviews',
            'api/feedbacks',
            'api/complaints',
            'api/recycles',
            'api/basket-items',
            'api/address-shop',
            'socket.io',
            'ftp',
            'administration',
            'accounting',
            'juice-shop_ctf.key',
            'encryptionkeys',
            '.well-known'
        ]

        discovery = DirectoryDiscovery(target_url, None)
        results = []

        for path in specific_paths:
            result = discovery.check_path(path)
            if result:
                results.append(result)
                print(f"[Juice Shop] Found: {result['url']} [{result['status']}]")

        return results

    @staticmethod
    def dvwa_discovery(target_url):
        """DVWA specific paths"""
        specific_paths = [
            'vulnerabilities/',
            'instructions.php',
            'setup.php',
            'security.php',
            'ids_logs.php',
            'hackable/',
            'hackable/uploads/',
            'hackable/flags/',
            'config/config.inc.php',
            'vulnerabilities/brute_force/',
            'vulnerabilities/command_injection/',
            'vulnerabilities/csrf/',
            'vulnerabilities/file_inclusion/',
            'vulnerabilities/file_upload/',
            'vulnerabilities/sql_injection/',
            'vulnerabilities/xss_dom/',
            'vulnerabilities/xss_reflected/',
            'vulnerabilities/xss_stored/'
        ]

        discovery = DirectoryDiscovery(target_url, None)
        results = []

        for path in specific_paths:
            result = discovery.check_path(path)
            if result:
                results.append(result)
                print(f"[DVWA] Found: {result['url']} [{result['status']}]")

        return results

    @staticmethod
    def webgoat_discovery(target_url):
        """WebGoat specific paths"""
        specific_paths = [
            'service/',
            'lessons/',
            'attack',
            'WebGoat/conf/',
            'WebGoat/plugin_lessons/',
            'WebGoat/lesson_plans/',
            'WebGoat/WEB-INF/',
            'WebGoat/META-INF/',
            'service/lessonmenu.mvc',
            'service/restartlesson.mvc',
            'service/hint.mvc',
            'service/reportcard.mvc'
        ]

        discovery = DirectoryDiscovery(target_url, None)
        results = []

        for path in specific_paths:
            result = discovery.check_path(path)
            if result:
                results.append(result)
                print(f"[WebGoat] Found: {result['url']} [{result['status']}]")

        return results

def create_comprehensive_wordlist():
    """Create a comprehensive wordlist for all applications"""
    wordlist = [
        # Common directories
        'admin', 'administrator', 'administration', 'api', 'app', 'apps',
        'backup', 'backups', 'bin', 'config', 'configs', 'data', 'database',
        'db', 'debug', 'dev', 'docs', 'downloads', 'files', 'images', 'img',
        'includes', 'js', 'css', 'lib', 'libs', 'log', 'logs', 'old', 'private',
        'public', 'src', 'temp', 'tmp', 'test', 'testing', 'uploads', 'user',
        'users', 'web', 'www',

        # Application specific
        'dvwa', 'juice-shop', 'webgoat', 'xvwa',
        'vulnerabilities', 'hackable', 'lessons', 'challenges',
        'socket.io', 'ftp', 'rest', 'service',

        # Common files
        'index', 'home', 'main', 'default', 'login', 'logout', 'register',
        'setup', 'install', 'config', 'readme', 'changelog', 'robots',
        'sitemap', 'crossdomain', 'phpinfo', 'info'
    ]

    return wordlist

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Directory Discovery Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Wordlist file path')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    parser.add_argument('-x', '--extensions', help='File extensions (comma-separated)')
    parser.add_argument('--app-specific', action='store_true', help='Use application-specific discovery')

    args = parser.parse_args()

    if args.app_specific:
        print("Running application-specific discovery...")

        # Detect application type and run specific discovery
        if 'juice' in args.url.lower() or ':3000' in args.url:
            ApplicationSpecificDiscovery.juice_shop_discovery(args.url)
        elif 'dvwa' in args.url.lower():
            ApplicationSpecificDiscovery.dvwa_discovery(args.url)
        elif 'webgoat' in args.url.lower() or ':8080' in args.url:
            ApplicationSpecificDiscovery.webgoat_discovery(args.url)

    # General discovery
    if args.wordlist:
        extensions = args.extensions.split(',') if args.extensions else None
        discovery = DirectoryDiscovery(args.url, args.wordlist, extensions, args.threads)
        results = discovery.discover_directories()

        print(f"\nDiscovery complete. Found {len(results)} interesting paths.")
```

## Attack Detection and Monitoring

### Wireshark Detection Signatures

```
# Directory enumeration detection filters
http.response.code == 404 and frame.time_delta < 0.5
http.request.uri matches "^/[a-zA-Z0-9_-]+/$" and http.response.code in {200, 301, 302, 403}
http.request.method == "GET" and http.request.uri contains "admin" or http.request.uri contains "config"

# Automated directory scanning patterns
(http.response.code == 404 or http.response.code == 403) and frame.time_delta < 0.1
http.user_agent contains "gobuster" or http.user_agent contains "dirb" or http.user_agent contains "dirsearch"

# High-frequency request pattern
tcp.stream and http.request.method == "GET" and frame.time_delta < 0.2
```

**Wireshark Analysis Steps:**

1. Monitor for rapid HTTP GET requests with similar timing patterns
2. Look for 404 error clusters indicating dictionary attacks
3. Filter for requests to common administrative paths
4. Analyze User-Agent strings for known enumeration tools

### Splunk Detection Queries

```spl
# Directory enumeration detection
index=web_logs sourcetype=access_combined
| bucket _time span=10s
| stats count by _time, src_ip, status
| where status=404 AND count > 20
| sort -_time

# Administrative path scanning
index=web_logs sourcetype=access_combined
| search (uri_path="*/admin*" OR uri_path="*/config*" OR uri_path="*/backup*")
| stats count by src_ip, uri_path
| where count > 5
| sort -count

# Tool signature detection
index=web_logs sourcetype=access_combined
| search user_agent="*gobuster*" OR user_agent="*dirb*" OR user_agent="*dirsearch*" OR user_agent="*feroxbuster*"
| stats count by src_ip, user_agent
| sort -count

# Response code analysis for enumeration
index=web_logs sourcetype=access_combined
| bucket _time span=60s
| stats count(eval(status=404)) as not_found, count(eval(status=403)) as forbidden, count(eval(status=200)) as success by _time, src_ip
| where not_found > 50 OR forbidden > 20
| eval enum_score = (not_found * 0.5) + (forbidden * 2) + (success * 3)
| where enum_score > 100
| sort -enum_score
```

### Security Information and Event Management (SIEM)

**QRadar Detection Rules:**

```sql
-- Directory enumeration detection
SELECT sourceip, COUNT(*) as request_count,
       SUM(CASE WHEN httpresponsecode = 404 THEN 1 ELSE 0 END) as not_found_count
FROM events
WHERE devicetype = 'webserver'
  AND httpresponsecode IN (404, 403)
GROUP BY sourceip
HAVING not_found_count > 50
  AND request_count > 100
LAST 5 MINUTES

-- Administrative path probing
SELECT sourceip, url, COUNT(*) as attempts
FROM events
WHERE url ILIKE '%/admin%' OR url ILIKE '%/config%' OR url ILIKE '%/backup%'
GROUP BY sourceip, url
HAVING attempts > 10
LAST 1 HOURS
```

**Elastic Stack (ELK) Detection Rule:**

```yaml
- rule:
    name: 'Directory Enumeration Attack'
    query: |
      (
        (http.response.status_code: 404 OR http.response.status_code: 403) AND
        @timestamp:[now-60s TO now]
      )
    condition: |
      sequence by source.ip
        [any where true] with maxspan=60s
        until [any where count(*) > 50]
    severity: medium
    tags: ['reconnaissance', 'directory_enumeration']
```

### Network Security Monitoring

**Suricata Rules:**

```
alert http any any -> any any (msg:"Directory Enumeration - Gobuster"; flow:established,to_server; http_user_agent; content:"gobuster"; nocase; sid:2001001;)
alert http any any -> any any (msg:"Directory Enumeration - Dirb"; flow:established,to_server; http_user_agent; content:"dirb"; nocase; sid:2001002;)
alert http any any -> any any (msg:"Directory Enumeration - High 404 Rate"; flow:established,to_server; http_stat_code; content:"404"; detection_filter:track by_src, count 50, seconds 60; sid:2001003;)
alert http any any -> any any (msg:"Administrative Path Scanning"; flow:established,to_server; http_uri; content:"/admin"; nocase; threshold:type threshold, track by_src, count 10, seconds 300; sid:2001004;)
```

**Snort Rules:**

```
alert tcp any any -> any 80 (msg:"Potential Directory Enumeration"; flow:established,to_server; content:"GET "; http_method; pcre:"/GET\s+\/[a-zA-Z0-9_-]+\/?\s+HTTP/"; threshold:type threshold, track by_src, count 20, seconds 60; sid:2001005;)
```

### Log Analysis and Correlation

**Apache/Nginx Log Analysis:**

```bash
# Detect high 404 rates
awk '$9 == 404 {print $1}' access.log | sort | uniq -c | sort -nr | head -10

# Find directory enumeration patterns
grep " 404 " access.log | awk '{print $1, $7}' | grep -E "/(admin|config|backup|test|dev)" | sort | uniq -c | sort -nr

# Identify scanning patterns by timing
awk '{print $1, $4}' access.log | sort | awk '
{
    if ($1 == prev_ip) {
        time_diff = systime() - prev_time
        if (time_diff < 1) {
            rapid_requests[$1]++
        }
    }
    prev_ip = $1
    prev_time = systime()
}
END {
    for (ip in rapid_requests) {
        if (rapid_requests[ip] > 50) {
            print ip, rapid_requests[ip]
        }
    }
}'
```

**PowerShell Log Analysis (Windows IIS):**

```powershell
# Parse IIS logs for directory enumeration
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\*.log |
    Where-Object { $_ -match " 404 " } |
    ForEach-Object { ($_ -split " ")[8] } |
    Group-Object |
    Where-Object { $_.Count -gt 50 } |
    Sort-Object Count -Descending

# Detect administrative path scanning
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\*.log |
    Where-Object { $_ -match "(admin|config|backup)" } |
    ForEach-Object { ($_ -split " ")[8] } |
    Group-Object |
    Sort-Object Count -Descending
```

### Behavioral Analysis Indicators

**Key Metrics to Monitor:**

- **Request Rate**: > 20 requests/second from single IP
- **404/403 Ratio**: > 80% error responses
- **Path Patterns**: Sequential dictionary-based paths
- **User-Agent Consistency**: Same User-Agent for multiple requests
- **Response Size Variance**: Small, consistent response sizes for 404s

**Python Detection Script:**

```python
#!/usr/bin/env python3
"""
Directory Enumeration Detection Script
Analyzes web logs for enumeration patterns
"""

import re
from collections import defaultdict, Counter
from datetime import datetime

def analyze_logs(log_file):
    """Analyze web logs for directory enumeration patterns"""

    ip_requests = defaultdict(list)
    ip_404_count = defaultdict(int)
    ip_paths = defaultdict(set)

    with open(log_file, 'r') as f:
        for line in f:
            # Parse common log format
            match = re.match(r'(\S+) .* \[([^\]]+)\] "GET (\S+) .*" (\d+) (\d+)', line)
            if match:
                ip, timestamp, path, status, size = match.groups()

                ip_requests[ip].append({
                    'timestamp': timestamp,
                    'path': path,
                    'status': int(status),
                    'size': int(size) if size != '-' else 0
                })

                if status == '404':
                    ip_404_count[ip] += 1
                    ip_paths[ip].add(path)

    # Detect enumeration patterns
    suspicious_ips = []

    for ip, requests in ip_requests.items():
        # High 404 rate
        if ip_404_count[ip] > 50:
            suspicious_ips.append({
                'ip': ip,
                'reason': 'High 404 count',
                'count': ip_404_count[ip],
                'paths': len(ip_paths[ip])
            })

        # Rapid requests
        if len(requests) > 100:
            # Check timing pattern
            timestamps = [req['timestamp'] for req in requests]
            # Additional timing analysis would go here

            suspicious_ips.append({
                'ip': ip,
                'reason': 'High request volume',
                'count': len(requests),
                'paths': len(ip_paths[ip])
            })

    return suspicious_ips

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detect_enum.py <log_file>")
        sys.exit(1)

    results = analyze_logs(sys.argv[1])

    if results:
        print("Suspicious Directory Enumeration Activity Detected:")
        for result in results:
            print(f"IP: {result['ip']}")
            print(f"Reason: {result['reason']}")
            print(f"Request Count: {result['count']}")
            print(f"Unique Paths: {result['paths']}")
            print("-" * 40)
    else:
        print("No suspicious enumeration activity detected.")
```

## Detection Methods

### Successful Discovery Indicators:

- HTTP 200 responses for valid paths
- HTTP 301/302 redirects indicating existing directories
- HTTP 403 responses showing protected areas
- Large response sizes indicating content

### Application-Specific Findings:

- **Juice Shop**: `/api/*` endpoints, socket.io, administration
- **DVWA**: `/vulnerabilities/*`, hackable directories
- **WebGoat**: `/service/*`, lesson directories
- **XVWA**: Similar to DVWA with additional language-specific paths

## Mitigation Recommendations

1. **Directory Protection**:

   - Implement proper access controls
   - Remove default directories and files

2. **Error Handling**:

   - Configure custom error pages
   - Avoid information disclosure

3. **Web Server Configuration**:

   - Disable directory listings
   - Hide sensitive directories

4. **Monitoring**:
   - Log directory enumeration attempts
   - Implement rate limiting

## Next Steps

- Analyze discovered endpoints for vulnerabilities
- Use found directories for further enumeration
- Proceed to technology stack identification (Playbook 03)
