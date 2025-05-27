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

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**DNS Enumeration Detection:**

```wireshark
# DNS reconnaissance patterns
dns.qry.type in {1 2 5 6 12 15 16 28} and dns.flags.response == 0

# Bulk DNS queries from single source
ip.src == <attacker_ip> and dns.qry.name and frame.time_delta < 0.1

# Zone transfer attempts
dns.qry.type == 252 or dns.resp.type == 252

# Subdomain enumeration patterns
dns.qry.name matches ".*\.(target\.com)$" and dns.flags.response == 0

# Certificate transparency lookups (external)
http.host contains "crt.sh" or http.host contains "censys.io"

# DNS brute force detection
dns.resp.rcode == 3 and frame.time_delta < 0.5

# Reverse DNS lookups
dns.qry.type == 12 and dns.qry.name matches ".*\.in-addr\.arpa$"

# DNS over HTTPS enumeration
http.request.uri contains "/dns-query" or tls.handshake.extensions_server_name contains "cloudflare-dns.com"
```

### Splunk Detection Queries

**DNS Reconnaissance Monitoring:**

```splunk
# Bulk DNS queries detection
index=dns_logs sourcetype=dns
| bucket _time span=1m
| stats count dc(query) as unique_queries by src_ip, _time
| where count > 100 OR unique_queries > 50
| eval reconnaissance_type="dns_enumeration"

# Subdomain brute forcing detection
index=dns_logs sourcetype=dns
| rex field=query "(?<subdomain>\w+)\.(?<domain>\w+\.\w+)$"
| stats count dc(subdomain) as unique_subdomains by src_ip, domain
| where count > 50 AND unique_subdomains > 30
| eval attack_type="subdomain_bruteforce"

# Zone transfer attempts
index=dns_logs sourcetype=dns
| search query_type="AXFR" OR query_type="IXFR"
| stats count by src_ip, dest_ip, query
| eval severity="high", attack_type="zone_transfer_attempt"

# DNS tunneling detection
index=dns_logs sourcetype=dns
| where len(query) > 100 OR query_type IN ("TXT", "NULL")
| stats count avg(len(query)) as avg_length by src_ip
| where count > 20 OR avg_length > 150
| eval attack_type="dns_tunneling"

# Certificate transparency reconnaissance
index=web_logs sourcetype=access_combined
| search uri="/json*" host IN ("crt.sh", "censys.io", "shodan.io")
| stats count by src_ip, host, uri
| where count > 10
| eval reconnaissance_stage="certificate_transparency"

# Passive DNS enumeration detection
index=dns_logs sourcetype=dns
| search query_type IN ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")
| bucket _time span=5m
| stats count dc(query_type) as query_types dc(query) as unique_queries by src_ip, _time
| where query_types >= 5 AND unique_queries > 20
| eval activity="systematic_dns_reconnaissance"
```

### SIEM Integration

**QRadar AQL Queries:**

```aql
-- DNS enumeration detection
SELECT sourceip, count(*) as query_count, count(DISTINCT "DNS Query Name") as unique_queries
FROM events
WHERE category = 'DNS Query'
AND "DNS Response Code" != 'NOERROR'
GROUP BY sourceip
HAVING query_count > 100 OR unique_queries > 50
LAST 10 MINUTES

-- Zone transfer attempts
SELECT sourceip, destinationip, "DNS Query Name", "DNS Query Type"
FROM events
WHERE category = 'DNS Query'
AND "DNS Query Type" IN ('AXFR', 'IXFR')
LAST 24 HOURS

-- Subdomain enumeration patterns
SELECT sourceip, "DNS Query Name", count(*) as attempts
FROM events
WHERE category = 'DNS Query'
AND "DNS Query Name" MATCHES '.*\.target\.com$'
GROUP BY sourceip, "DNS Query Name"
HAVING attempts > 5
LAST 1 HOURS

-- Certificate transparency abuse
SELECT sourceip, destinationip, url, count(*) as requests
FROM events
WHERE category = 'Web Access'
AND (hostname LIKE '%crt.sh%' OR hostname LIKE '%censys.io%')
GROUP BY sourceip, destinationip, url
HAVING requests > 10
LAST 2 HOURS
```

**Elastic Stack Detection Rules:**

```json
{
  "rule": {
    "name": "DNS Enumeration and Subdomain Discovery",
    "query": {
      "bool": {
        "should": [
          {
            "bool": {
              "must": [
                { "term": { "event.category": "network" } },
                { "term": { "dns.type": "query" } },
                {
                  "terms": {
                    "dns.question.type": [
                      "A",
                      "AAAA",
                      "MX",
                      "NS",
                      "TXT",
                      "SOA",
                      "CNAME"
                    ]
                  }
                }
              ]
            }
          },
          {
            "bool": {
              "must": [
                { "term": { "dns.question.type": "AXFR" } },
                { "term": { "event.category": "network" } }
              ]
            }
          }
        ]
      }
    },
    "threshold": {
      "field": "source.ip",
      "value": 50,
      "cardinality": [
        {
          "field": "dns.question.name",
          "value": 25
        }
      ]
    }
  }
}
```

### Network Security Monitoring

**Suricata Rules:**

```suricata
# DNS enumeration detection
alert dns any any -> any 53 (msg:"DNS Enumeration - Excessive Queries"; dns.query; threshold:type both, track by_src, count 100, seconds 300; classtype:attempted-recon; sid:4001001; rev:1;)

alert dns any any -> any 53 (msg:"DNS Zone Transfer Attempt"; dns.query; content:"|00 FC|"; offset:2; depth:2; classtype:attempted-recon; sid:4001002; rev:1;)

# Subdomain brute force detection
alert dns any any -> any 53 (msg:"Subdomain Brute Force Attack"; dns.query; pcre:"/^[a-z0-9\-]{3,20}\./"; threshold:type both, track by_src, count 50, seconds 300; classtype:attempted-recon; sid:4001003; rev:1;)

# DNS over HTTPS enumeration
alert tls any any -> any 443 (msg:"DNS over HTTPS Enumeration"; tls.sni; content:"cloudflare-dns.com"; classtype:attempted-recon; sid:4001004; rev:1;)

alert tls any any -> any 443 (msg:"DNS over HTTPS Enumeration - Quad9"; tls.sni; content:"dns.quad9.net"; classtype:attempted-recon; sid:4001005; rev:1;)

# Certificate transparency reconnaissance
alert http any any -> any any (msg:"Certificate Transparency Reconnaissance"; http.host; content:"crt.sh"; threshold:type both, track by_src, count 10, seconds 300; classtype:web-application-activity; sid:4001006; rev:1;)

alert http any any -> any any (msg:"Censys API Reconnaissance"; http.host; content:"censys.io"; http.uri; content:"/api/"; threshold:type both, track by_src, count 5, seconds 300; classtype:web-application-activity; sid:4001007; rev:1;)

# Reverse DNS enumeration
alert dns any any -> any 53 (msg:"Reverse DNS Enumeration"; dns.query; content:".in-addr.arpa"; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:4001008; rev:1;)

# DNS tunneling detection
alert dns any any -> any 53 (msg:"Potential DNS Tunneling - Long Query"; dns.query; dsize:>100; classtype:policy-violation; sid:4001009; rev:1;)

alert dns any any -> any 53 (msg:"Potential DNS Tunneling - TXT Records"; dns.query; dns.opcode:0; content:"|00 10|"; offset:2; depth:2; threshold:type both, track by_src, count 10, seconds 60; classtype:policy-violation; sid:4001010; rev:1;)
```

**Snort Rules:**

```snort
# DNS reconnaissance detection
alert udp any any -> any 53 (msg:"DNS Enumeration - Multiple Record Types"; content:"|01 00 00 01|"; offset:2; depth:4; threshold:type both, track by_src, count 50, seconds 300; classtype:attempted-recon; sid:4001101; rev:1;)

alert udp any any -> any 53 (msg:"DNS Zone Transfer Request"; content:"|00 FC|"; offset:2; depth:2; classtype:attempted-recon; sid:4001102; rev:1;)

# Subdomain enumeration
alert udp any any -> any 53 (msg:"Rapid DNS Queries"; content:"|01 00 00 01|"; offset:2; depth:4; threshold:type both, track by_src, count 100, seconds 60; classtype:attempted-recon; sid:4001103; rev:1;)
```

### Log Analysis Scripts

**BIND DNS Server Analysis:**

```bash
#!/bin/bash
# DNS enumeration detection for BIND logs

LOG_FILE="/var/log/named/query.log"
THRESHOLD=50
TIME_WINDOW=300  # 5 minutes
SUBDOMAIN_THRESHOLD=30

echo "=== DNS Enumeration Detection ==="

# Bulk query detection
echo "[+] Detecting bulk DNS queries..."
awk -v threshold=$THRESHOLD -v window=$TIME_WINDOW '
BEGIN {
    current_time = systime()
    # BIND log format: timestamp client query_type query_name response_code
}
{
    # Parse BIND query log
    if (match($0, /([0-9\-]+) ([0-9:]+\.[0-9]+) .*client ([0-9\.]+)#[0-9]+.*query: ([a-zA-Z0-9\.\-]+) IN ([A-Z]+)/, parts)) {
        timestamp_str = parts[1] " " parts[2]
        client_ip = parts[3]
        query_name = parts[4]
        query_type = parts[5]

        # Convert timestamp (simplified)
        query_count[client_ip]++
        unique_queries[client_ip,query_name] = 1

        # Track subdomain patterns
        if (match(query_name, /^([^\.]+)\.(.+)$/, domain_parts)) {
            subdomain = domain_parts[1]
            base_domain = domain_parts[2]
            subdomain_count[client_ip,base_domain]++
        }
    }
}
END {
    print "=== Bulk Query Detection ==="
    for (ip in query_count) {
        if (query_count[ip] >= threshold) {
            unique_count = 0
            for (combo in unique_queries) {
                if (split(combo, parts, SUBSEP) && parts[1] == ip) {
                    unique_count++
                }
            }
            print "[!] ALERT: " ip " made " query_count[ip] " queries (" unique_count " unique)"
        }
    }

    print "\n=== Subdomain Enumeration Detection ==="
    for (combo in subdomain_count) {
        split(combo, parts, SUBSEP)
        ip = parts[1]
        domain = parts[2]
        if (subdomain_count[combo] >= 30) {
            print "[!] ALERT: " ip " enumerated " subdomain_count[combo] " subdomains for " domain
        }
    }
}' "$LOG_FILE"

# Zone transfer attempts
echo "[+] Checking for zone transfer attempts..."
grep -i "AXFR\|IXFR" "$LOG_FILE" | while read -r line; do
    echo "[!] ZONE TRANSFER ATTEMPT: $line"
done

# DNS tunneling detection
echo "[+] Detecting potential DNS tunneling..."
awk '
{
    if (match($0, /client ([0-9\.]+).*query: ([a-zA-Z0-9\.\-]+)/, parts)) {
        client_ip = parts[1]
        query_name = parts[2]

        if (length(query_name) > 100) {
            print "[!] LONG QUERY: " client_ip " -> " query_name
        }

        # Count TXT queries
        if (match($0, /IN TXT/)) {
            txt_count[client_ip]++
        }
    }
}
END {
    print "\n=== DNS Tunneling Detection ==="
    for (ip in txt_count) {
        if (txt_count[ip] > 20) {
            print "[!] POTENTIAL TUNNELING: " ip " made " txt_count[ip] " TXT queries"
        }
    }
}' "$LOG_FILE"
```

**PowerShell DNS Analysis:**

```powershell
# Windows DNS Server log analysis
$DNSLogPath = "C:\Windows\System32\dns\dns.log"
$TimeThreshold = (Get-Date).AddMinutes(-5)

# Parse DNS debug logs
$DNSQueries = @{}
$SubdomainCounts = @{}
$ZoneTransferAttempts = @()

Get-Content $DNSLogPath -Tail 10000 | ForEach-Object {
    if ($_ -match "(\d+/\d+/\d+ \d+:\d+:\d+) .* PACKET .*") {
        # Parse DNS packet logs
        if ($_ -match "UDP ([\d\.]+) .* Q \[0001\] (.+?) \[(.+?)\]") {
            $ClientIP = $Matches[1]
            $QueryName = $Matches[2]
            $QueryType = $Matches[3]

            # Count queries per IP
            if (-not $DNSQueries.ContainsKey($ClientIP)) {
                $DNSQueries[$ClientIP] = @()
            }
            $DNSQueries[$ClientIP] += @{
                'Query' = $QueryName
                'Type' = $QueryType
                'Time' = Get-Date
            }

            # Track subdomain enumeration
            if ($QueryName -match '^([^\.]+)\.(.+)$') {
                $Subdomain = $Matches[1]
                $BaseDomain = $Matches[2]
                $Key = "$ClientIP-$BaseDomain"

                if (-not $SubdomainCounts.ContainsKey($Key)) {
                    $SubdomainCounts[$Key] = 0
                }
                $SubdomainCounts[$Key]++
            }

            # Detect zone transfer attempts
            if ($QueryType -match "AXFR|IXFR") {
                $ZoneTransferAttempts += @{
                    'ClientIP' = $ClientIP
                    'Query' = $QueryName
                    'Type' = $QueryType
                    'Time' = Get-Date
                }
            }
        }
    }
}

# Generate alerts
Write-Host "=== DNS Enumeration Detection Results ===" -ForegroundColor Yellow

$DNSQueries.GetEnumerator() | ForEach-Object {
    $ClientIP = $_.Key
    $Queries = $_.Value

    if ($Queries.Count -gt 50) {
        $UniqueQueries = ($Queries | Select-Object -ExpandProperty Query | Sort-Object -Unique).Count
        Write-Warning "Bulk DNS enumeration from $ClientIP : $($Queries.Count) queries ($UniqueQueries unique)"
    }
}

$SubdomainCounts.GetEnumerator() | ForEach-Object {
    $Key = $_.Key
    $Count = $_.Value

    if ($Count -gt 30) {
        $ClientIP, $Domain = $Key -split '-', 2
        Write-Warning "Subdomain enumeration from $ClientIP against $Domain : $Count subdomains"
    }
}

if ($ZoneTransferAttempts.Count -gt 0) {
    Write-Host "`n=== Zone Transfer Attempts ===" -ForegroundColor Red
    $ZoneTransferAttempts | ForEach-Object {
        Write-Warning "Zone transfer attempt from $($_.ClientIP) for $($_.Query) ($($_.Type))"
    }
}
```

### Python Behavioral Analysis

```python
#!/usr/bin/env python3
"""
DNS Enumeration Detection Script
Analyzes DNS logs for reconnaissance patterns
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse
import socket
import json

class DNSEnumerationDetector:
    def __init__(self, log_file, time_window=300, query_threshold=50, subdomain_threshold=30):
        self.log_file = log_file
        self.time_window = time_window
        self.query_threshold = query_threshold
        self.subdomain_threshold = subdomain_threshold

        # Pattern matching for different DNS log formats
        self.bind_pattern = re.compile(
            r'(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}) .*client ([0-9\.]+)#\d+ .*query: ([a-zA-Z0-9\.\-]+) IN ([A-Z]+)'
        )

        # Detection data structures
        self.client_queries = defaultdict(list)
        self.subdomain_counts = defaultdict(int)
        self.zone_transfers = []
        self.dns_tunneling = []
        self.detection_results = []

    def parse_dns_log(self, line):
        """Parse DNS log line (BIND format)"""
        match = self.bind_pattern.match(line)
        if not match:
            return None

        timestamp_str, client_ip, query_name, query_type = match.groups()

        try:
            timestamp = datetime.strptime(timestamp_str, '%d-%b-%Y %H:%M:%S.%f')
        except ValueError:
            return None

        return {
            'timestamp': timestamp,
            'client_ip': client_ip,
            'query_name': query_name.lower(),
            'query_type': query_type
        }

    def analyze_dns_patterns(self):
        """Analyze DNS logs for enumeration patterns"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        with open(self.log_file, 'r') as f:
            for line in f:
                parsed = self.parse_dns_log(line.strip())
                if not parsed or parsed['timestamp'] < cutoff_time:
                    continue

                self.client_queries[parsed['client_ip']].append(parsed)

                # Track subdomain enumeration
                self.track_subdomain_enumeration(parsed)

                # Detect zone transfers
                self.detect_zone_transfers(parsed)

                # Detect DNS tunneling
                self.detect_dns_tunneling(parsed)

        self.detect_bulk_enumeration()
        self.detect_systematic_reconnaissance()

    def track_subdomain_enumeration(self, query):
        """Track subdomain enumeration patterns"""
        query_name = query['query_name']

        # Extract base domain
        if query_name.count('.') >= 2:
            parts = query_name.split('.')
            if len(parts) >= 3:
                subdomain = parts[0]
                base_domain = '.'.join(parts[1:])
                key = f"{query['client_ip']}:{base_domain}"
                self.subdomain_counts[key] += 1

    def detect_zone_transfers(self, query):
        """Detect zone transfer attempts"""
        if query['query_type'] in ['AXFR', 'IXFR']:
            self.zone_transfers.append(query)
            self.detection_results.append({
                'type': 'Zone Transfer Attempt',
                'client_ip': query['client_ip'],
                'query_name': query['query_name'],
                'query_type': query['query_type'],
                'severity': 'high',
                'description': f'Zone transfer attempt for {query["query_name"]}'
            })

    def detect_dns_tunneling(self, query):
        """Detect potential DNS tunneling"""
        query_name = query['query_name']

        # Long query names
        if len(query_name) > 100:
            self.dns_tunneling.append(query)
            self.detection_results.append({
                'type': 'Potential DNS Tunneling',
                'client_ip': query['client_ip'],
                'query_name': query_name,
                'length': len(query_name),
                'severity': 'medium',
                'description': f'Unusually long DNS query ({len(query_name)} chars)'
            })

        # Excessive TXT queries
        if query['query_type'] == 'TXT':
            key = f"{query['client_ip']}:TXT"
            if key not in self.subdomain_counts:
                self.subdomain_counts[key] = 0
            self.subdomain_counts[key] += 1

    def detect_bulk_enumeration(self):
        """Detect bulk DNS enumeration"""
        for client_ip, queries in self.client_queries.items():
            total_queries = len(queries)
            unique_queries = len(set(q['query_name'] for q in queries))
            query_types = set(q['query_type'] for q in queries)

            if total_queries >= self.query_threshold:
                self.detection_results.append({
                    'type': 'Bulk DNS Enumeration',
                    'client_ip': client_ip,
                    'total_queries': total_queries,
                    'unique_queries': unique_queries,
                    'query_types': list(query_types),
                    'severity': 'high' if total_queries > 200 else 'medium',
                    'description': f'Excessive DNS queries: {total_queries} total, {unique_queries} unique'
                })

    def detect_systematic_reconnaissance(self):
        """Detect systematic subdomain enumeration"""
        for key, count in self.subdomain_counts.items():
            if ':' in key:
                client_ip, domain = key.split(':', 1)

                if domain == 'TXT':  # TXT query analysis
                    if count > 20:
                        self.detection_results.append({
                            'type': 'Excessive TXT Queries',
                            'client_ip': client_ip,
                            'count': count,
                            'severity': 'medium',
                            'description': f'Potential DNS tunneling: {count} TXT queries'
                        })
                elif count >= self.subdomain_threshold:
                    self.detection_results.append({
                        'type': 'Subdomain Enumeration',
                        'client_ip': client_ip,
                        'domain': domain,
                        'subdomain_count': count,
                        'severity': 'high' if count > 100 else 'medium',
                        'description': f'Systematic subdomain enumeration of {domain}'
                    })

    def check_reputation(self, ip):
        """Check IP reputation (placeholder for real reputation services)"""
        # In real implementation, integrate with threat intelligence feeds
        suspicious_ranges = [
            '10.0.0.0/8',    # Private networks doing external enum
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]

        # Simplified check
        for cidr in suspicious_ranges:
            try:
                network = socket.inet_aton(cidr.split('/')[0])
                # Simplified CIDR check
                if ip.startswith(cidr.split('.')[0]):
                    return 'internal_network'
            except:
                pass

        return 'unknown'

    def generate_report(self):
        """Generate detection report"""
        if not self.detection_results:
            print("No DNS enumeration activity detected.")
            return

        print("=== DNS Enumeration Detection Report ===\n")

        severity_counts = Counter(result['severity'] for result in self.detection_results)
        print(f"Total Detections: {len(self.detection_results)}")
        print(f"High Severity: {severity_counts['high']}")
        print(f"Medium Severity: {severity_counts['medium']}")
        print(f"Low Severity: {severity_counts['low']}\n")

        # Group by client IP
        ip_detections = defaultdict(list)
        for result in self.detection_results:
            ip_detections[result['client_ip']].append(result)

        for client_ip, detections in ip_detections.items():
            reputation = self.check_reputation(client_ip)
            print(f"Client IP: {client_ip} (Reputation: {reputation})")
            print("-" * 50)

            for detection in sorted(detections, key=lambda x: x['severity'], reverse=True):
                print(f"  [{detection['severity'].upper()}] {detection['type']}")
                print(f"    Description: {detection['description']}")

                if 'total_queries' in detection:
                    print(f"    Query Details: {detection['total_queries']} total, {detection['unique_queries']} unique")
                if 'subdomain_count' in detection:
                    print(f"    Subdomains Enumerated: {detection['subdomain_count']}")
                if 'query_types' in detection:
                    print(f"    Query Types: {', '.join(detection['query_types'])}")

                print()
            print()

    def export_json(self, output_file):
        """Export results to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'analysis_window': self.time_window,
            'thresholds': {
                'query_threshold': self.query_threshold,
                'subdomain_threshold': self.subdomain_threshold
            },
            'detections': self.detection_results,
            'summary': {
                'total_detections': len(self.detection_results),
                'unique_ips': len(set(r['client_ip'] for r in self.detection_results)),
                'severity_breakdown': dict(Counter(r['severity'] for r in self.detection_results))
            }
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"Report exported to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Enumeration Detection Tool')
    parser.add_argument('log_file', help='Path to DNS log file')
    parser.add_argument('--time-window', type=int, default=300,
                       help='Analysis time window in seconds (default: 300)')
    parser.add_argument('--query-threshold', type=int, default=50,
                       help='Query count threshold (default: 50)')
    parser.add_argument('--subdomain-threshold', type=int, default=30,
                       help='Subdomain enumeration threshold (default: 30)')
    parser.add_argument('--export-json', help='Export results to JSON file')

    args = parser.parse_args()

    detector = DNSEnumerationDetector(
        args.log_file,
        args.time_window,
        args.query_threshold,
        args.subdomain_threshold
    )

    try:
        detector.analyze_dns_patterns()
        detector.generate_report()

        if args.export_json:
            detector.export_json(args.export_json)

    except FileNotFoundError:
        print(f"Error: DNS log file {args.log_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing DNS logs: {e}")
        sys.exit(1)
```

### Key Detection Metrics

**Quantitative Indicators:**

- **Bulk DNS Queries**: >50 queries per 5-minute window per IP
- **Subdomain Enumeration**: >30 subdomain queries for same domain
- **Zone Transfer Attempts**: Any AXFR/IXFR query type
- **DNS Tunneling**: Query length >100 characters or >20 TXT queries
- **Rapid Queries**: <0.1 second intervals between queries
- **Multiple Record Types**: >5 different query types from same IP

**Behavioral Patterns:**

- Sequential subdomain pattern (sub1, sub2, sub3, etc.)
- Dictionary-based subdomain enumeration
- Systematic DNS record type enumeration
- Certificate transparency service abuse
- Reverse DNS enumeration patterns
- DNS over HTTPS/TLS enumeration

**Network Signatures:**

- High-frequency DNS queries from single source
- Non-existent domain (NXDOMAIN) clustering
- Unusual query patterns (long strings, encoded data)
- External reconnaissance service usage
- Multiple authoritative server queries

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
