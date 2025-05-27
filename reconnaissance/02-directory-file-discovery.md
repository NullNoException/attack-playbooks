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

## Shell Script Automation

```bash
#!/bin/bash
# Comprehensive Directory Discovery Script

TARGET="$1"
OUTPUT_DIR="discovery_results"
THREADS=50

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 http://192.168.1.100:3000"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting directory discovery for $TARGET"

# Determine application type
APP_TYPE="unknown"
if [[ "$TARGET" == *":3000"* ]]; then
    APP_TYPE="juice-shop"
elif [[ "$TARGET" == *"dvwa"* ]]; then
    APP_TYPE="dvwa"
elif [[ "$TARGET" == *":8080"* ]] || [[ "$TARGET" == *"webgoat"* ]]; then
    APP_TYPE="webgoat"
fi

echo "[+] Detected application type: $APP_TYPE"

# Common directory discovery
echo "[+] Running common directory discovery..."
gobuster dir -u "$TARGET" -w /usr/share/wordlists/dirb/common.txt -t $THREADS -o "$OUTPUT_DIR/common_dirs.txt"

# Application-specific discovery
case $APP_TYPE in
    "juice-shop")
        echo "[+] Running Juice Shop specific discovery..."
        gobuster dir -u "$TARGET" -w <(echo -e "api\nsocket.io\nftp\nadministration\naccounting") -t $THREADS -o "$OUTPUT_DIR/juiceshop_specific.txt"

        # API endpoints
        for endpoint in products users orders reviews feedbacks complaints; do
            curl -s "$TARGET/api/$endpoint" -o "$OUTPUT_DIR/api_$endpoint.json"
        done
        ;;

    "dvwa")
        echo "[+] Running DVWA specific discovery..."
        gobuster dir -u "$TARGET" -w <(echo -e "vulnerabilities\nhackable\nconfig\nsetup.php\nsecurity.php") -x php -t $THREADS -o "$OUTPUT_DIR/dvwa_specific.txt"
        ;;

    "webgoat")
        echo "[+] Running WebGoat specific discovery..."
        gobuster dir -u "$TARGET" -w <(echo -e "service\nlessons\nattack\nWEB-INF\nMETA-INF") -x mvc,jsp -t $THREADS -o "$OUTPUT_DIR/webgoat_specific.txt"
        ;;
esac

# File discovery with extensions
echo "[+] Running file discovery..."
gobuster dir -u "$TARGET" -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,xml,json,jsp,inc,config -t $THREADS -o "$OUTPUT_DIR/files.txt"

# Backup file discovery
echo "[+] Searching for backup files..."
gobuster dir -u "$TARGET" -w <(echo -e "backup\nbackups\n.bak\n.backup\n.old\n.orig\n.save\n.swp\n.tmp") -t $THREADS -o "$OUTPUT_DIR/backups.txt"

echo "[+] Discovery complete. Results saved in $OUTPUT_DIR/"
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
