# Playbook 04: DNS and Subdomain Enumeration

## Objective

Discover subdomains, DNS records, and infrastructure information to expand the attack surface and identify additional entry points.

## Target Applications

- OWASP Juice Shop (typically localhost or single domain)
- DVWA (may have multiple virtual hosts)
- XVWA (potential subdomain configurations)
- WebGoat (enterprise deployment scenarios)

## Prerequisites

- Subfinder
- Amass
- Gobuster (DNS mode)
- Dnsrecon
- Fierce
- Python 3 with dnspython
- Custom subdomain wordlists

## Manual Commands

### 1. Basic DNS Enumeration

```bash
# DNS record enumeration
dig target.com ANY
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com TXT
dig target.com NS
dig target.com CNAME

# Reverse DNS lookup
dig -x <target_ip>

# DNS zone transfer attempt
dig axfr target.com @ns1.target.com
```

### 2. Subdomain Discovery

```bash
# Using Subfinder
subfinder -d target.com -o subdomains.txt

# Using Amass
amass enum -d target.com -o amass_results.txt

# Using Gobuster (DNS mode)
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Using Dnsrecon
dnsrecon -d target.com -t std,rvl,brt,srv,axfr

# Using Fierce
fierce -dns target.com
```

### 3. Virtual Host Discovery

```bash
# Virtual host enumeration for local testing
gobuster vhost -u http://target-ip -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Host header injection testing
curl -H "Host: admin.target.com" http://target-ip
curl -H "Host: test.target.com" http://target-ip
curl -H "Host: dev.target.com" http://target-ip
```

### 4. DNS Bruteforce

```bash
# Custom subdomain wordlist creation
cat > custom_subdomains.txt << EOF
admin
administrator
api
app
beta
dev
development
test
testing
stage
staging
prod
production
mail
email
www
ftp
ssh
vpn
portal
dashboard
panel
login
secure
private
internal
intranet
extranet
EOF

# Bruteforce with custom wordlist
gobuster dns -d target.com -w custom_subdomains.txt -t 50
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
DNS and Subdomain Enumeration Script
Advanced subdomain discovery for penetration testing
"""

import dns.resolver
import dns.reversename
import dns.zone
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import socket
import subprocess
import json

class DNSEnumerator:
    def __init__(self, domain, wordlist_file=None):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.found_subdomains = set()
        self.dns_records = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def get_dns_records(self):
        """Get various DNS records for the domain"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                self.dns_records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                self.dns_records[record_type] = []

        return self.dns_records

    def reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup"""
        try:
            rev_name = dns.reversename.from_address(ip)
            return str(self.resolver.resolve(rev_name, "PTR")[0])
        except:
            return None

    def zone_transfer_attempt(self):
        """Attempt DNS zone transfer"""
        try:
            # Get NS records first
            ns_records = self.resolver.resolve(self.domain, 'NS')

            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain))
                    return {
                        'success': True,
                        'nameserver': str(ns),
                        'records': [str(name) for name in zone.nodes.keys()]
                    }
                except Exception as e:
                    continue

            return {'success': False, 'error': 'Zone transfer not allowed'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        full_domain = f"{subdomain}.{self.domain}"

        try:
            # Try A record
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]

            # Also check AAAA (IPv6)
            try:
                ipv6_answers = self.resolver.resolve(full_domain, 'AAAA')
                ipv6s = [str(rdata) for rdata in ipv6_answers]
            except:
                ipv6s = []

            return {
                'subdomain': full_domain,
                'ips': ips,
                'ipv6s': ipv6s,
                'exists': True
            }

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            return None

    def load_wordlist(self):
        """Load subdomain wordlist"""
        if self.wordlist_file:
            try:
                with open(self.wordlist_file, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"Wordlist {self.wordlist_file} not found")

        # Default wordlist
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'dev', 'test', 'admin',
            'administrator', 'api', 'app', 'beta', 'stage', 'staging', 'prod', 'production',
            'secure', 'vpn', 'ssh', 'remote', 'portal', 'dashboard', 'panel', 'login',
            'blog', 'shop', 'store', 'cart', 'forum', 'support', 'help', 'docs',
            'mobile', 'm', 'cdn', 'static', 'assets', 'img', 'images', 'video',
            'db', 'database', 'sql', 'mysql', 'oracle', 'postgres', 'mongo',
            'backup', 'old', 'new', 'demo', 'preview', 'lab', 'labs'
        ]

    def bruteforce_subdomains(self, threads=50):
        """Bruteforce subdomains using wordlist"""
        wordlist = self.load_wordlist()
        found_subdomains = []

        print(f"Testing {len(wordlist)} subdomains with {threads} threads...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.check_subdomain, subdomain): subdomain
                      for subdomain in wordlist}

            for future in futures:
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"[+] Found: {result['subdomain']} -> {', '.join(result['ips'])}")

        return found_subdomains

    def certificate_transparency_search(self):
        """Search Certificate Transparency logs for subdomains"""
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                subdomains = set()

                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain.endswith(f".{self.domain}"):
                            subdomains.add(subdomain)

                return list(subdomains)

        except Exception as e:
            print(f"Certificate transparency search failed: {e}")

        return []

    def search_engines_dorking(self):
        """Use search engines to find subdomains"""
        subdomains = []

        # Google dorking (simulated - in practice you'd use proper APIs)
        google_dorks = [
            f"site:{self.domain}",
            f"site:*.{self.domain}",
            f"inurl:{self.domain}",
            f"intitle:{self.domain}"
        ]

        print("Search engine dorking patterns:")
        for dork in google_dorks:
            print(f"  - {dork}")

        return subdomains

    def check_virtual_hosts(self, target_ip, port=80):
        """Check for virtual hosts on target IP"""
        if not target_ip:
            return []

        wordlist = self.load_wordlist()
        virtual_hosts = []

        print(f"Testing virtual hosts on {target_ip}:{port}")

        for subdomain in wordlist[:50]:  # Limit for demo
            try:
                headers = {'Host': f"{subdomain}.{self.domain}"}
                response = requests.get(f"http://{target_ip}:{port}",
                                      headers=headers, timeout=5)

                # Check for different response (indicating virtual host)
                if response.status_code != 404:
                    virtual_hosts.append({
                        'host': f"{subdomain}.{self.domain}",
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    })
                    print(f"[+] Virtual host found: {subdomain}.{self.domain} [{response.status_code}]")

            except:
                continue

        return virtual_hosts

    def comprehensive_enumeration(self):
        """Perform comprehensive DNS enumeration"""
        print(f"Starting DNS enumeration for: {self.domain}")
        print("=" * 50)

        results = {
            'domain': self.domain,
            'dns_records': {},
            'zone_transfer': {},
            'subdomains': [],
            'ct_subdomains': [],
            'virtual_hosts': []
        }

        # DNS records
        print("[+] Getting DNS records...")
        results['dns_records'] = self.get_dns_records()

        # Zone transfer attempt
        print("[+] Attempting zone transfer...")
        results['zone_transfer'] = self.zone_transfer_attempt()

        # Subdomain bruteforce
        print("[+] Bruteforcing subdomains...")
        results['subdomains'] = self.bruteforce_subdomains()

        # Certificate transparency
        print("[+] Searching certificate transparency logs...")
        results['ct_subdomains'] = self.certificate_transparency_search()

        # Search engine dorking
        print("[+] Search engine dorking...")
        self.search_engines_dorking()

        # Virtual host checking (if we have IPs)
        if 'A' in results['dns_records'] and results['dns_records']['A']:
            target_ip = results['dns_records']['A'][0]
            print(f"[+] Checking virtual hosts on {target_ip}...")
            results['virtual_hosts'] = self.check_virtual_hosts(target_ip)

        return results

class LocalNetworkDiscovery:
    """Discovery for local/lab environments"""

    @staticmethod
    def discover_local_hosts(network="192.168.1.0/24"):
        """Discover hosts on local network"""
        print(f"Discovering hosts on {network}")

        try:
            result = subprocess.run(['nmap', '-sn', network],
                                  capture_output=True, text=True)

            hosts = []
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    host = line.split('for ')[1]
                    hosts.append(host)

            return hosts

        except Exception as e:
            print(f"Error discovering local hosts: {e}")
            return []

    @staticmethod
    def scan_common_web_ports(hosts):
        """Scan common web ports on discovered hosts"""
        web_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]
        web_services = []

        for host in hosts:
            print(f"Scanning {host}...")

            for port in web_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)

                try:
                    result = sock.connect_ex((host.strip(), port))
                    if result == 0:
                        web_services.append(f"http://{host}:{port}")
                        print(f"  [+] Found web service: {host}:{port}")
                except:
                    pass
                finally:
                    sock.close()

        return web_services

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='DNS and Subdomain Enumeration')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Subdomain wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--local', action='store_true', help='Local network discovery mode')

    args = parser.parse_args()

    if args.local:
        # Local network discovery for lab environments
        discovery = LocalNetworkDiscovery()
        hosts = discovery.discover_local_hosts()
        web_services = discovery.scan_common_web_ports(hosts)

        print("\nDiscovered web services:")
        for service in web_services:
            print(f"  {service}")
    else:
        # Domain enumeration
        enumerator = DNSEnumerator(args.domain, args.wordlist)
        results = enumerator.comprehensive_enumeration()

        # Print summary
        print("\n" + "="*50)
        print("ENUMERATION SUMMARY")
        print("="*50)

        print(f"Domain: {results['domain']}")
        print(f"Subdomains found: {len(results['subdomains'])}")
        print(f"CT log entries: {len(results['ct_subdomains'])}")
        print(f"Virtual hosts: {len(results['virtual_hosts'])}")

        if results['zone_transfer']['success']:
            print("Zone transfer: SUCCESS")
        else:
            print("Zone transfer: Failed")
```

## Shell Script Automation

```bash
#!/bin/bash
# DNS and Subdomain Enumeration Script

DOMAIN="$1"
OUTPUT_DIR="dns_enum_${DOMAIN}"
THREADS=50

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] DNS and Subdomain Enumeration for $DOMAIN"

# Basic DNS enumeration
echo "[+] Basic DNS records..."
for record in A AAAA MX NS TXT SOA CNAME; do
    dig "$DOMAIN" "$record" > "$OUTPUT_DIR/dns_${record}.txt"
done

# Zone transfer attempt
echo "[+] Attempting zone transfer..."
dig axfr "$DOMAIN" > "$OUTPUT_DIR/zone_transfer.txt"

# Subdomain enumeration with multiple tools
echo "[+] Subdomain enumeration..."

# Subfinder
if command -v subfinder &> /dev/null; then
    subfinder -d "$DOMAIN" -o "$OUTPUT_DIR/subfinder.txt"
fi

# Amass
if command -v amass &> /dev/null; then
    amass enum -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt"
fi

# Gobuster DNS
if command -v gobuster &> /dev/null; then
    gobuster dns -d "$DOMAIN" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o "$OUTPUT_DIR/gobuster.txt"
fi

# Certificate transparency
echo "[+] Certificate transparency search..."
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/crt_sh.txt"

# Combine and deduplicate results
echo "[+] Combining results..."
cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort -u | grep -E "\.$DOMAIN$" > "$OUTPUT_DIR/all_subdomains.txt"

# Verify active subdomains
echo "[+] Verifying active subdomains..."
while read -r subdomain; do
    if host "$subdomain" >/dev/null 2>&1; then
        echo "$subdomain" >> "$OUTPUT_DIR/active_subdomains.txt"
        echo "[+] Active: $subdomain"
    fi
done < "$OUTPUT_DIR/all_subdomains.txt"

# Port scanning on active subdomains
echo "[+] Port scanning active subdomains..."
if [ -f "$OUTPUT_DIR/active_subdomains.txt" ]; then
    nmap -iL "$OUTPUT_DIR/active_subdomains.txt" -p 80,443,8080,8443 -oN "$OUTPUT_DIR/port_scan.txt"
fi

echo "[+] Enumeration complete. Results in $OUTPUT_DIR/"
```

## Detection Methods

### Successful DNS Enumeration Indicators:

- DNS records resolved successfully
- Subdomains discovered and verified
- Zone transfer successful (rare)
- Virtual hosts identified

### Active Subdomain Verification:

- A/AAAA records resolving
- HTTP responses on web ports
- Different content indicating separate services

## Mitigation Recommendations

1. **DNS Security**:

   - Disable zone transfers for unauthorized hosts
   - Use DNS security extensions (DNSSEC)
   - Monitor DNS queries

2. **Subdomain Management**:

   - Remove unused subdomains
   - Implement wildcard certificate monitoring
   - Use private DNS for internal services

3. **Virtual Host Security**:
   - Configure proper virtual host restrictions
   - Implement default deny policies
   - Monitor for unauthorized virtual hosts

## Next Steps

- Use discovered subdomains for further enumeration
- Scan identified services for vulnerabilities
- Proceed to social engineering reconnaissance (Playbook 05)
