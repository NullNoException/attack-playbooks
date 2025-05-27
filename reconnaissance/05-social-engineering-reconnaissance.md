# Playbook 05: Social Engineering Reconnaissance

## Objective

Gather information about the organization, users, and potential social engineering vectors through OSINT (Open Source Intelligence) techniques.

## Target Applications Context

- OWASP Juice Shop (fictional company context)
- DVWA (corporate training context)
- XVWA (educational organization context)
- WebGoat (enterprise security context)

## Prerequisites

- theHarvester
- Recon-ng
- Maltego Community Edition
- Social media analysis tools
- Email enumeration tools
- Python 3 with specialized OSINT libraries

## Manual Commands

### 1. Email Harvesting

```bash
# Using theHarvester
theharvester -d target.com -l 500 -b google,bing,yahoo,linkedin

# Email pattern generation
echo "john.doe@target.com
j.doe@target.com
johndoe@target.com
john_doe@target.com
jdoe@target.com" > email_patterns.txt

# Verify emails with SMTP
for email in $(cat email_patterns.txt); do
    echo "VRFY $email" | nc target.com 25
done
```

### 2. Social Media Intelligence

```bash
# LinkedIn enumeration (manual process)
# Search for: site:linkedin.com "target company"
# Extract employee names and positions

# Twitter/X intelligence
# Search for: site:twitter.com "target company"
# Look for employee posts, technology mentions

# GitHub intelligence
# Search for: site:github.com "target company"
# Look for repositories, leaked credentials
```

### 3. Search Engine Dorking

```bash
# Google dorks for information gathering
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com filetype:docx
site:target.com "confidential"
site:target.com "internal use only"
site:target.com inurl:admin
site:target.com inurl:login
site:target.com "index of"

# GitHub dorks
site:github.com "target.com" password
site:github.com "target.com" api_key
site:github.com "target.com" "secret"
```

### 4. Metadata Analysis

```bash
# Download and analyze PDFs/documents
wget -r -A.pdf http://target.com/
exiftool *.pdf | grep -E "(Author|Creator|Producer)"

# Image metadata analysis
exiftool *.jpg *.png | grep -E "(GPS|Camera|Software)"
```

## Automated Python Script

```python
#!/usr/bin/env python3
"""
Social Engineering Reconnaissance Script
OSINT gathering for penetration testing
"""

import requests
import re
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import whois
from email.utils import parseaddr
import dns.resolver

class OSINTGatherer:
    def __init__(self, domain, company_name=None):
        self.domain = domain
        self.company_name = company_name or domain.split('.')[0]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def whois_lookup(self):
        """Perform WHOIS lookup for domain information"""
        try:
            domain_info = whois.whois(self.domain)

            # Extract relevant information
            whois_data = {
                'registrar': getattr(domain_info, 'registrar', 'Unknown'),
                'creation_date': str(getattr(domain_info, 'creation_date', 'Unknown')),
                'expiration_date': str(getattr(domain_info, 'expiration_date', 'Unknown')),
                'name_servers': getattr(domain_info, 'name_servers', []),
                'emails': getattr(domain_info, 'emails', []),
                'organization': getattr(domain_info, 'org', 'Unknown'),
                'country': getattr(domain_info, 'country', 'Unknown')
            }

            return whois_data

        except Exception as e:
            print(f"WHOIS lookup failed: {e}")
            return {}

    def email_enumeration(self):
        """Enumerate potential email addresses"""
        # Common email patterns
        patterns = [
            "{first}.{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}{last}@{domain}",
            "{first}@{domain}",
            "{last}@{domain}",
            "{first_initial}{last}@{domain}",
            "{first}{last_initial}@{domain}"
        ]

        # Common first and last names (would be populated from OSINT)
        common_names = {
            'first': ['john', 'jane', 'admin', 'administrator', 'test', 'user'],
            'last': ['doe', 'smith', 'admin', 'user', 'test']
        }

        email_candidates = []

        for first in common_names['first']:
            for last in common_names['last']:
                for pattern in patterns:
                    email = pattern.format(
                        first=first,
                        last=last,
                        first_initial=first[0],
                        last_initial=last[0],
                        domain=self.domain
                    )
                    email_candidates.append(email)

        return list(set(email_candidates))  # Remove duplicates

    def email_verification(self, email_list):
        """Verify email addresses using various methods"""
        verified_emails = []

        for email in email_list[:20]:  # Limit for demo
            try:
                # Method 1: DNS MX record check
                domain = email.split('@')[1]
                mx_records = dns.resolver.resolve(domain, 'MX')

                if mx_records:
                    # Method 2: SMTP verification (careful with rate limiting)
                    # This is a simplified version - real implementation would be more sophisticated
                    verified_emails.append({
                        'email': email,
                        'method': 'MX_verified',
                        'confidence': 'medium'
                    })

            except:
                continue

        return verified_emails

    def social_media_search(self):
        """Search for social media presence"""
        platforms = {
            'linkedin': f"https://www.linkedin.com/company/{self.company_name}",
            'twitter': f"https://twitter.com/search?q={self.company_name}",
            'facebook': f"https://www.facebook.com/search/top?q={self.company_name}",
            'github': f"https://github.com/search?q={self.company_name}",
            'youtube': f"https://www.youtube.com/results?search_query={self.company_name}"
        }

        social_presence = {}

        for platform, url in platforms.items():
            try:
                # Note: In practice, you'd use proper APIs or more sophisticated scraping
                response = self.session.get(url, timeout=10)

                if response.status_code == 200:
                    social_presence[platform] = {
                        'url': url,
                        'accessible': True,
                        'status_code': response.status_code
                    }
                else:
                    social_presence[platform] = {
                        'url': url,
                        'accessible': False,
                        'status_code': response.status_code
                    }

            except Exception as e:
                social_presence[platform] = {
                    'url': url,
                    'accessible': False,
                    'error': str(e)
                }

        return social_presence

    def search_engine_dorking(self):
        """Generate Google dorks for information gathering"""
        dorks = [
            f'site:{self.domain} filetype:pdf',
            f'site:{self.domain} filetype:xlsx',
            f'site:{self.domain} filetype:docx',
            f'site:{self.domain} "confidential"',
            f'site:{self.domain} "internal use only"',
            f'site:{self.domain} inurl:admin',
            f'site:{self.domain} inurl:login',
            f'site:{self.domain} "index of"',
            f'site:linkedin.com "{self.company_name}"',
            f'site:github.com "{self.domain}"',
            f'site:pastebin.com "{self.domain}"',
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" secret',
        ]

        return dorks

    def technology_footprinting(self):
        """Footprint technologies used by the organization"""
        tech_indicators = {}

        try:
            response = self.session.get(f"http://{self.domain}", timeout=10)
            content = response.text.lower()

            # Technology patterns
            technologies = {
                'cms': {
                    'wordpress': ['wp-content', 'wp-includes'],
                    'drupal': ['drupal', '/sites/default/'],
                    'joomla': ['joomla', '/components/']
                },
                'frameworks': {
                    'angular': ['ng-version', 'angular'],
                    'react': ['react', 'reactdom'],
                    'vue': ['vue.js', 'vuejs'],
                    'jquery': ['jquery']
                },
                'analytics': {
                    'google_analytics': ['google-analytics', 'gtag'],
                    'adobe_analytics': ['adobe analytics', 'omniture']
                }
            }

            for category, tech_dict in technologies.items():
                tech_indicators[category] = {}
                for tech, patterns in tech_dict.items():
                    for pattern in patterns:
                        if pattern in content:
                            tech_indicators[category][tech] = True
                            break
                    else:
                        tech_indicators[category][tech] = False

            return tech_indicators

        except Exception as e:
            print(f"Technology footprinting failed: {e}")
            return {}

    def employee_enumeration(self):
        """Enumerate potential employees (simulated)"""
        # In practice, this would involve LinkedIn scraping, corporate directories, etc.
        # This is a simulated version for educational purposes

        employees = [
            {
                'name': 'John Doe',
                'position': 'IT Administrator',
                'email': 'john.doe@' + self.domain,
                'linkedin': 'https://linkedin.com/in/johndoe',
                'department': 'IT'
            },
            {
                'name': 'Jane Smith',
                'position': 'Security Analyst',
                'email': 'jane.smith@' + self.domain,
                'linkedin': 'https://linkedin.com/in/janesmith',
                'department': 'Security'
            },
            {
                'name': 'Admin User',
                'position': 'System Administrator',
                'email': 'admin@' + self.domain,
                'linkedin': None,
                'department': 'IT'
            }
        ]

        return employees

    def leaked_credentials_search(self):
        """Search for leaked credentials (simulated)"""
        # In practice, this would check databases like:
        # - Have I Been Pwned API
        # - Dehashed
        # - Intelligence X

        potential_breaches = [
            {
                'source': 'Simulated Breach Database',
                'emails_found': ['admin@' + self.domain, 'user@' + self.domain],
                'breach_date': '2023-01-15',
                'compromised_data': ['Email addresses', 'Passwords', 'Names']
            }
        ]

        return potential_breaches

    def comprehensive_osint(self):
        """Perform comprehensive OSINT gathering"""
        print(f"Starting OSINT gathering for: {self.domain}")
        print("=" * 50)

        results = {
            'domain': self.domain,
            'company_name': self.company_name,
            'whois_data': {},
            'email_enumeration': [],
            'verified_emails': [],
            'social_media': {},
            'google_dorks': [],
            'technology_footprint': {},
            'employees': [],
            'leaked_credentials': []
        }

        # WHOIS lookup
        print("[+] WHOIS lookup...")
        results['whois_data'] = self.whois_lookup()

        # Email enumeration
        print("[+] Email enumeration...")
        results['email_enumeration'] = self.email_enumeration()
        results['verified_emails'] = self.email_verification(results['email_enumeration'])

        # Social media search
        print("[+] Social media search...")
        results['social_media'] = self.social_media_search()

        # Google dorks
        print("[+] Generating Google dorks...")
        results['google_dorks'] = self.search_engine_dorking()

        # Technology footprinting
        print("[+] Technology footprinting...")
        results['technology_footprint'] = self.technology_footprinting()

        # Employee enumeration
        print("[+] Employee enumeration...")
        results['employees'] = self.employee_enumeration()

        # Leaked credentials search
        print("[+] Leaked credentials search...")
        results['leaked_credentials'] = self.leaked_credentials_search()

        return results

class SocialEngineeringReportGenerator:
    """Generate social engineering attack vectors report"""

    def __init__(self, osint_data):
        self.data = osint_data

    def generate_attack_vectors(self):
        """Generate potential attack vectors based on gathered intelligence"""
        vectors = []

        # Email-based attacks
        if self.data['verified_emails']:
            vectors.append({
                'type': 'Phishing Campaign',
                'target': 'Verified email addresses',
                'method': 'Targeted spear-phishing emails',
                'success_probability': 'High',
                'payload': 'Credential harvesting, malware delivery'
            })

        # Social media attacks
        active_social = [platform for platform, data in self.data['social_media'].items()
                        if data.get('accessible')]

        if active_social:
            vectors.append({
                'type': 'Social Media Reconnaissance',
                'target': f"Active platforms: {', '.join(active_social)}",
                'method': 'Profile analysis, connection mapping',
                'success_probability': 'Medium',
                'payload': 'Personal information gathering'
            })

        # Employee targeting
        if self.data['employees']:
            vectors.append({
                'type': 'Executive Impersonation',
                'target': 'Identified employees',
                'method': 'CEO fraud, authority impersonation',
                'success_probability': 'Medium',
                'payload': 'Financial fraud, credential harvesting'
            })

        # Technology-based attacks
        tech_footprint = self.data['technology_footprint']
        if any(tech_footprint.values()):
            vectors.append({
                'type': 'Technology-Specific Attacks',
                'target': 'Identified technologies',
                'method': 'Exploit known vulnerabilities',
                'success_probability': 'High',
                'payload': 'System compromise'
            })

        return vectors

    def generate_report(self):
        """Generate comprehensive report"""
        report = {
            'target_info': {
                'domain': self.data['domain'],
                'company': self.data['company_name']
            },
            'intelligence_summary': {
                'emails_found': len(self.data['verified_emails']),
                'employees_identified': len(self.data['employees']),
                'social_platforms': len([p for p, d in self.data['social_media'].items()
                                       if d.get('accessible')]),
                'potential_breaches': len(self.data['leaked_credentials'])
            },
            'attack_vectors': self.generate_attack_vectors(),
            'recommendations': self.generate_recommendations()
        }

        return report

    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            {
                'category': 'Email Security',
                'recommendation': 'Implement SPF, DKIM, and DMARC records',
                'priority': 'High'
            },
            {
                'category': 'Employee Training',
                'recommendation': 'Conduct regular phishing simulation exercises',
                'priority': 'High'
            },
            {
                'category': 'Social Media Policy',
                'recommendation': 'Establish corporate social media guidelines',
                'priority': 'Medium'
            },
            {
                'category': 'Information Disclosure',
                'recommendation': 'Review publicly accessible documents for sensitive information',
                'priority': 'Medium'
            },
            {
                'category': 'Credential Monitoring',
                'recommendation': 'Monitor for leaked credentials in breach databases',
                'priority': 'High'
            }
        ]

        return recommendations

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Social Engineering Reconnaissance')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-c', '--company', help='Company name')
    parser.add_argument('-o', '--output', help='Output file for results')

    args = parser.parse_args()

    # Perform OSINT gathering
    gatherer = OSINTGatherer(args.domain, args.company)
    results = gatherer.comprehensive_osint()

    # Generate report
    report_gen = SocialEngineeringReportGenerator(results)
    report = report_gen.generate_report()

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

    # Print summary
    print("\n" + "="*50)
    print("OSINT SUMMARY")
    print("="*50)
    print(f"Target: {results['domain']}")
    print(f"Emails found: {len(results['verified_emails'])}")
    print(f"Employees identified: {len(results['employees'])}")
    print(f"Social platforms: {len([p for p, d in results['social_media'].items() if d.get('accessible')])}")
    print(f"Attack vectors identified: {len(report['attack_vectors'])}")
```

## Attack Detection and Monitoring

### Wireshark Detection Signatures

**OSINT and Social Engineering Reconnaissance Detection:**

```wireshark
# Email harvesting detection
http.request.uri contains "theharvester" or http.user_agent contains "theHarvester"

# Google dorking patterns
http.request.uri contains "site:" and (http.request.uri contains "filetype:" or http.request.uri contains "inurl:")

# WHOIS lookup detection
dns.qry.name contains "whois" or tcp.dstport == 43

# Social media reconnaissance
http.host contains "linkedin.com" or http.host contains "facebook.com" or http.host contains "twitter.com"
and http.request.uri contains "search"

# GitHub/Pastebin intelligence gathering
http.host contains "github.com" or http.host contains "pastebin.com"
and http.request.uri contains "search"

# Certificate transparency reconnaissance
http.host contains "crt.sh" or http.host contains "censys.io"

# Breach database searches
http.host contains "haveibeenpwned.com" or http.host contains "dehashed.com"

# Automated reconnaissance tools
http.user_agent contains "curl" or http.user_agent contains "wget" or http.user_agent contains "python-requests"
```

### Splunk Detection Queries

**Social Engineering Reconnaissance Monitoring:**

```splunk
# Email harvesting tool detection
index=web_logs sourcetype=access_combined
| search (uri="*theharvester*" OR user_agent="*theHarvester*" OR uri="*hunter.io*")
| stats count by src_ip, uri, user_agent
| eval reconnaissance_type="email_harvesting"

# Google dorking detection
index=web_logs sourcetype=access_combined
| search host="*google.com*" (uri="*site:*" AND (uri="*filetype:*" OR uri="*inurl:*" OR uri="*intitle:*"))
| rex field=uri "q=(?<search_query>[^&]*)"
| stats count by src_ip, search_query
| where count > 5
| eval attack_type="google_dorking"

# Social media intelligence gathering
index=web_logs sourcetype=access_combined
| search (host="*linkedin.com*" OR host="*facebook.com*" OR host="*twitter.com*")
  AND (uri="*search*" OR uri="*company*")
| bucket _time span=1h
| stats count dc(host) as platforms by src_ip, _time
| where count > 10 OR platforms >= 3
| eval activity="social_media_osint"

# WHOIS enumeration detection
index=network_logs sourcetype=firewall
| search dest_port=43 action="allow"
| stats count by src_ip, dest_ip
| where count > 20
| eval reconnaissance_stage="whois_enumeration"

# GitHub/Pastebin reconnaissance
index=web_logs sourcetype=access_combined
| search (host="*github.com*" OR host="*pastebin.com*") uri="*search*"
| rex field=uri "q=(?<search_term>[^&]*)"
| stats count by src_ip, host, search_term
| where count > 10
| eval osint_type="code_repository_search"

# Breach database searches
index=web_logs sourcetype=access_combined
| search host IN ("haveibeenpwned.com", "dehashed.com", "leakcheck.net")
| stats count by src_ip, host, uri
| eval intelligence_gathering="breach_database_search"

# Automated OSINT tool signatures
index=web_logs sourcetype=access_combined
| search user_agent IN ("*recon-ng*", "*theHarvester*", "*maltego*", "*spiderfoot*")
| stats count values(user_agent) as tools by src_ip
| eval automated_osint="true"
```

### SIEM Integration

**QRadar AQL Queries:**

```aql
-- Email harvesting detection
SELECT sourceip, destinationip, "URL", count(*) as requests
FROM events
WHERE category = 'Web Access'
AND ("URL" LIKE '%theharvester%' OR "URL" LIKE '%hunter.io%' OR "User Agent" LIKE '%theHarvester%')
GROUP BY sourceip, destinationip, "URL"
HAVING requests > 5
LAST 2 HOURS

-- Google dorking detection
SELECT sourceip, "URL", count(*) as dork_attempts
FROM events
WHERE category = 'Web Access'
AND hostname = 'www.google.com'
AND ("URL" LIKE '%site:%' AND ("URL" LIKE '%filetype:%' OR "URL" LIKE '%inurl:%'))
GROUP BY sourceip, "URL"
HAVING dork_attempts > 3
LAST 1 HOURS

-- Social media reconnaissance
SELECT sourceip, hostname, count(*) as social_searches
FROM events
WHERE category = 'Web Access'
AND hostname IN ('linkedin.com', 'facebook.com', 'twitter.com')
AND "URL" LIKE '%search%'
GROUP BY sourceip, hostname
HAVING social_searches > 10
LAST 6 HOURS

-- WHOIS enumeration
SELECT sourceip, destinationip, destinationport, count(*) as whois_queries
FROM events
WHERE category = 'Network Activity'
AND destinationport = 43
GROUP BY sourceip, destinationip, destinationport
HAVING whois_queries > 15
LAST 1 HOURS
```

**Elastic Stack Detection Rules:**

```json
{
  "rule": {
    "name": "OSINT and Social Engineering Reconnaissance",
    "query": {
      "bool": {
        "should": [
          {
            "bool": {
              "must": [
                { "term": { "event.category": "web" } },
                { "wildcard": { "url.original": "*theharvester*" } }
              ]
            }
          },
          {
            "bool": {
              "must": [
                { "term": { "url.domain": "google.com" } },
                { "wildcard": { "url.query": "*site:*" } },
                {
                  "bool": {
                    "should": [
                      { "wildcard": { "url.query": "*filetype:*" } },
                      { "wildcard": { "url.query": "*inurl:*" } }
                    ]
                  }
                }
              ]
            }
          },
          {
            "bool": {
              "must": [
                {
                  "terms": {
                    "url.domain": [
                      "linkedin.com",
                      "facebook.com",
                      "twitter.com"
                    ]
                  }
                },
                { "wildcard": { "url.path": "*search*" } }
              ]
            }
          }
        ]
      }
    },
    "threshold": {
      "field": "source.ip",
      "value": 10
    }
  }
}
```

### Network Security Monitoring

**Suricata Rules:**

```suricata
# Email harvesting tool detection
alert http any any -> any any (msg:"Email Harvesting Tool - theHarvester"; http.user_agent; content:"theHarvester"; classtype:attempted-recon; sid:5001001; rev:1;)

alert http any any -> any any (msg:"Email Harvesting Service - Hunter.io"; http.host; content:"hunter.io"; classtype:attempted-recon; sid:5001002; rev:1;)

# Google dorking detection
alert http any any -> any any (msg:"Google Dorking - File Type Search"; http.uri; content:"site:"; content:"filetype:"; distance:0; within:100; classtype:attempted-recon; sid:5001003; rev:1;)

alert http any any -> any any (msg:"Google Dorking - URL Search"; http.uri; content:"site:"; content:"inurl:"; distance:0; within:100; classtype:attempted-recon; sid:5001004; rev:1;)

# Social media reconnaissance
alert http any any -> any any (msg:"LinkedIn Company Reconnaissance"; http.host; content:"linkedin.com"; http.uri; content:"company"; threshold:type both, track by_src, count 10, seconds 300; classtype:attempted-recon; sid:5001005; rev:1;)

alert http any any -> any any (msg:"Social Media Intelligence Gathering"; http.host; content:"facebook.com"; http.uri; content:"search"; threshold:type both, track by_src, count 15, seconds 300; classtype:attempted-recon; sid:5001006; rev:1;)

# WHOIS enumeration
alert tcp any any -> any 43 (msg:"Excessive WHOIS Queries"; threshold:type both, track by_src, count 20, seconds 300; classtype:attempted-recon; sid:5001007; rev:1;)

# GitHub/Pastebin reconnaissance
alert http any any -> any any (msg:"GitHub Code Repository Search"; http.host; content:"github.com"; http.uri; content:"search"; threshold:type both, track by_src, count 10, seconds 300; classtype:attempted-recon; sid:5001008; rev:1;)

alert http any any -> any any (msg:"Pastebin Intelligence Gathering"; http.host; content:"pastebin.com"; http.uri; content:"search"; threshold:type both, track by_src, count 5, seconds 300; classtype:attempted-recon; sid:5001009; rev:1;)

# Automated OSINT tools
alert http any any -> any any (msg:"Automated OSINT Tool - Recon-ng"; http.user_agent; content:"recon-ng"; classtype:attempted-recon; sid:5001010; rev:1;)

alert http any any -> any any (msg:"Automated OSINT Tool - Maltego"; http.user_agent; content:"maltego"; classtype:attempted-recon; sid:5001011; rev:1;)

# Breach database searches
alert http any any -> any any (msg:"Breach Database Search - HaveIBeenPwned"; http.host; content:"haveibeenpwned.com"; threshold:type both, track by_src, count 5, seconds 300; classtype:attempted-recon; sid:5001012; rev:1;)

alert http any any -> any any (msg:"Breach Database Search - Dehashed"; http.host; content:"dehashed.com"; threshold:type both, track by_src, count 3, seconds 300; classtype:attempted-recon; sid:5001013; rev:1;)
```

**Snort Rules:**

```snort
# OSINT reconnaissance detection
alert tcp any any -> any 80 (msg:"OSINT Tool User Agent"; content:"User-Agent:"; http_header; content:"theHarvester"; http_header; classtype:attempted-recon; sid:5001101; rev:1;)

alert tcp any any -> any 443 (msg:"Google Dorking Activity"; content:"Host: www.google.com"; http_header; content:"site:"; http_uri; content:"filetype:"; http_uri; classtype:attempted-recon; sid:5001102; rev:1;)

alert tcp any any -> any 43 (msg:"WHOIS Enumeration"; flow:established,to_server; threshold:type both, track by_src, count 15, seconds 300; classtype:attempted-recon; sid:5001103; rev:1;)
```

### Log Analysis Scripts

**Web Server OSINT Detection:**

```bash
#!/bin/bash
# OSINT reconnaissance detection in web logs

LOG_FILE="/var/log/apache2/access.log"  # or nginx
THRESHOLD=10
TIME_WINDOW=3600  # 1 hour

echo "=== OSINT and Social Engineering Reconnaissance Detection ==="

# Google dorking detection
echo "[+] Detecting Google dorking activity..."
awk -v threshold=5 -v window=$TIME_WINDOW '
BEGIN { current_time = systime() }
{
    if ($7 ~ /google\.com.*site:.*filetype:|google\.com.*site:.*inurl:/) {
        ip = $1
        timestamp = mktime(substr($4,2,19))
        if (current_time - timestamp <= window) {
            dork_count[ip]++
        }
    }
}
END {
    for (ip in dork_count) {
        if (dork_count[ip] >= 3) {
            print "[!] ALERT: " ip " performed " dork_count[ip] " Google dorks"
        }
    }
}' "$LOG_FILE"

# Email harvesting tool detection
echo "[+] Detecting email harvesting tools..."
grep -i "theharvester\|hunter\.io\|clearbit\.com" "$LOG_FILE" | \
awk '{print "[!] EMAIL HARVESTING: " $1 " -> " $7}' | sort -u

# Social media reconnaissance
echo "[+] Detecting social media reconnaissance..."
grep -E "linkedin\.com.*search|facebook\.com.*search|twitter\.com.*search" "$LOG_FILE" | \
awk '{print $1, $7}' | sort | uniq -c | awk '$1 > 10 {print "[!] SOCIAL MEDIA RECON: " $2 " (" $1 " requests)"}'

# OSINT automation tools
echo "[+] Detecting automated OSINT tools..."
grep -iE "recon-ng|maltego|spiderfoot|shodan|censys" "$LOG_FILE" | \
awk '{print "[!] OSINT TOOL: " $1 " -> " $(NF-1)}' | sort -u

# Breach database searches
echo "[+] Detecting breach database searches..."
grep -E "haveibeenpwned\.com|dehashed\.com|leakcheck\.net" "$LOG_FILE" | \
awk '{print "[!] BREACH DB SEARCH: " $1 " -> " $7}' | sort -u

# Certificate transparency searches
echo "[+] Detecting certificate transparency searches..."
grep -E "crt\.sh|censys\.io.*certificates" "$LOG_FILE" | \
awk '{print $1}' | sort | uniq -c | \
awk '$1 > 5 {print "[!] CERT TRANSPARENCY: " $2 " (" $1 " searches)"}'
```

**PowerShell OSINT Detection:**

```powershell
# IIS/Windows OSINT detection
$LogPath = "C:\inetpub\logs\LogFiles\W3SVC1\"
$TimeThreshold = (Get-Date).AddHours(-1)

$OSINTPatterns = @{
    'GoogleDorking' = @('site:', 'filetype:', 'inurl:', 'intitle:')
    'EmailHarvesting' = @('theharvester', 'hunter.io', 'clearbit.com')
    'SocialMedia' = @('linkedin.com/search', 'facebook.com/search', 'twitter.com/search')
    'BreachDatabases' = @('haveibeenpwned.com', 'dehashed.com', 'leakcheck.net')
    'OSINTTools' = @('recon-ng', 'maltego', 'spiderfoot', 'shodan')
}

$DetectionResults = @{}

Get-ChildItem $LogPath -Filter "*.log" | ForEach-Object {
    $LogContent = Get-Content $_.FullName | Where-Object { $_ -notmatch "^#" }

    $LogContent | ForEach-Object {
        $Fields = $_ -split " "
        $DateTime = [DateTime]::Parse("$($Fields[0]) $($Fields[1])")

        if ($DateTime -gt $TimeThreshold) {
            $SourceIP = $Fields[2]
            $URI = $Fields[4]
            $UserAgent = $Fields[9]

            # Check for OSINT patterns
            foreach ($Category in $OSINTPatterns.Keys) {
                foreach ($Pattern in $OSINTPatterns[$Category]) {
                    if ($URI -like "*$Pattern*" -or $UserAgent -like "*$Pattern*") {
                        if (-not $DetectionResults.ContainsKey($SourceIP)) {
                            $DetectionResults[$SourceIP] = @{}
                        }
                        if (-not $DetectionResults[$SourceIP].ContainsKey($Category)) {
                            $DetectionResults[$SourceIP][$Category] = 0
                        }
                        $DetectionResults[$SourceIP][$Category]++
                    }
                }
            }
        }
    }
}

# Generate alerts
Write-Host "=== OSINT Reconnaissance Detection Results ===" -ForegroundColor Yellow

$DetectionResults.GetEnumerator() | ForEach-Object {
    $SourceIP = $_.Key
    $Activities = $_.Value

    Write-Host "`nSource IP: $SourceIP" -ForegroundColor Cyan

    $Activities.GetEnumerator() | ForEach-Object {
        $Activity = $_.Key
        $Count = $_.Value

        $Severity = "Medium"
        if ($Count -gt 20) { $Severity = "High" }
        elseif ($Count -lt 5) { $Severity = "Low" }

        Write-Warning "[$Severity] $Activity : $Count occurrences"
    }
}
```

### Python Behavioral Analysis

```python
#!/usr/bin/env python3
"""
OSINT and Social Engineering Reconnaissance Detection
Analyzes web logs for reconnaissance patterns and automated tools
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse
import json
from urllib.parse import unquote, parse_qs

class OSINTDetector:
    def __init__(self, log_file, time_window=3600):
        self.log_file = log_file
        self.time_window = time_window

        # Pattern definitions
        self.osint_patterns = {
            'google_dorking': [
                r'site:[^\s&]+.*filetype:[^\s&]+',
                r'site:[^\s&]+.*inurl:[^\s&]+',
                r'site:[^\s&]+.*intitle:[^\s&]+',
                r'site:[^\s&]+.*"confidential"',
                r'site:[^\s&]+.*"internal use only"'
            ],
            'email_harvesting': [
                r'theharvester',
                r'hunter\.io',
                r'clearbit\.com',
                r'apollo\.io',
                r'snov\.io'
            ],
            'social_media_recon': [
                r'linkedin\.com.*search',
                r'facebook\.com.*search',
                r'twitter\.com.*search',
                r'instagram\.com.*search'
            ],
            'breach_databases': [
                r'haveibeenpwned\.com',
                r'dehashed\.com',
                r'leakcheck\.net',
                r'breachdirectory\.org'
            ],
            'osint_tools': [
                r'recon-ng',
                r'maltego',
                r'spiderfoot',
                r'shodan',
                r'censys',
                r'theHarvester'
            ],
            'cert_transparency': [
                r'crt\.sh',
                r'censys\.io.*certificates',
                r'certificate-transparency'
            ],
            'github_recon': [
                r'github\.com.*search.*q=',
                r'api\.github\.com.*search'
            ],
            'pastebin_searches': [
                r'pastebin\.com.*search',
                r'paste\.org.*search'
            ]
        }

        # Log parsing pattern
        self.log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
        )

        # Detection results
        self.detections = defaultdict(lambda: defaultdict(list))
        self.ip_activities = defaultdict(lambda: defaultdict(int))

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
            'uri': unquote(uri),
            'status': int(status),
            'referer': referer,
            'user_agent': user_agent
        }

    def analyze_osint_patterns(self):
        """Analyze logs for OSINT reconnaissance patterns"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = self.parse_log_line(line.strip())
                if not parsed or parsed['timestamp'] < cutoff_time:
                    continue

                self.detect_osint_activities(parsed)

        self.generate_alerts()

    def detect_osint_activities(self, entry):
        """Detect OSINT activities in log entry"""
        ip = entry['ip']
        uri = entry['uri']
        user_agent = entry['user_agent']
        combined_text = f"{uri} {user_agent}".lower()

        for category, patterns in self.osint_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    self.detections[ip][category].append({
                        'timestamp': entry['timestamp'],
                        'uri': uri,
                        'user_agent': user_agent,
                        'pattern': pattern
                    })
                    self.ip_activities[ip][category] += 1
                    break

    def detect_google_dorking(self, entry):
        """Specific Google dorking detection"""
        if 'google.com' in entry['uri'].lower():
            # Extract query parameters
            if '?q=' in entry['uri'] or '&q=' in entry['uri']:
                try:
                    query_start = entry['uri'].lower().find('q=') + 2
                    query_end = entry['uri'].find('&', query_start)
                    if query_end == -1:
                        query = entry['uri'][query_start:]
                    else:
                        query = entry['uri'][query_start:query_end]

                    query = unquote(query)

                    # Check for dorking patterns
                    dork_indicators = ['site:', 'filetype:', 'inurl:', 'intitle:', 'intext:']
                    if any(indicator in query for indicator in dork_indicators):
                        self.detections[entry['ip']]['google_dorking'].append({
                            'timestamp': entry['timestamp'],
                            'query': query,
                            'uri': entry['uri']
                        })
                        self.ip_activities[entry['ip']]['google_dorking'] += 1
                except:
                    pass

    def analyze_user_agent_patterns(self):
        """Analyze user agent patterns for automation"""
        automation_indicators = [
            'python-requests', 'curl/', 'wget/', 'urllib', 'httpclient',
            'bot', 'crawler', 'spider', 'scraper'
        ]

        for ip, activities in self.detections.items():
            for category, entries in activities.items():
                for entry in entries:
                    user_agent = entry.get('user_agent', '').lower()
                    for indicator in automation_indicators:
                        if indicator in user_agent:
                            if 'automation_detected' not in self.ip_activities[ip]:
                                self.ip_activities[ip]['automation_detected'] = 0
                            self.ip_activities[ip]['automation_detected'] += 1
                            break

    def generate_alerts(self):
        """Generate detection alerts"""
        self.analyze_user_agent_patterns()

        severity_thresholds = {
            'low': 1,
            'medium': 5,
            'high': 15
        }

        for ip, activities in self.ip_activities.items():
            total_osint_activity = sum(count for category, count in activities.items()
                                     if category != 'automation_detected')

            if total_osint_activity == 0:
                continue

            # Determine severity
            severity = 'low'
            if total_osint_activity >= severity_thresholds['high']:
                severity = 'high'
            elif total_osint_activity >= severity_thresholds['medium']:
                severity = 'medium'

            # Check for automation
            automation_score = activities.get('automation_detected', 0)
            if automation_score > 5:
                severity = 'high'

            print(f"\n[{severity.upper()}] OSINT Reconnaissance Detected")
            print(f"Source IP: {ip}")
            print(f"Total Activities: {total_osint_activity}")

            if automation_score > 0:
                print(f"Automation Score: {automation_score}")

            print("Activity Breakdown:")
            for category, count in activities.items():
                if count > 0 and category != 'automation_detected':
                    print(f"  - {category.replace('_', ' ').title()}: {count}")

            # Show sample activities
            if ip in self.detections:
                print("\nSample Activities:")
                for category, entries in self.detections[ip].items():
                    if entries:
                        sample = entries[0]  # Show first entry as sample
                        if 'query' in sample:
                            print(f"  - {category}: {sample['query']}")
                        else:
                            print(f"  - {category}: {sample['uri'][:100]}...")

    def export_report(self, output_file):
        """Export detailed report to JSON"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_window_seconds': self.time_window,
            'total_ips_detected': len(self.ip_activities),
            'detection_summary': {},
            'detailed_detections': {}
        }

        # Summary statistics
        for ip, activities in self.ip_activities.items():
            for category, count in activities.items():
                if category not in report['detection_summary']:
                    report['detection_summary'][category] = 0
                report['detection_summary'][category] += count

        # Detailed detections
        for ip, activities in self.detections.items():
            report['detailed_detections'][ip] = {}
            for category, entries in activities.items():
                report['detailed_detections'][ip][category] = [
                    {
                        'timestamp': entry['timestamp'].isoformat(),
                        'uri': entry.get('uri', ''),
                        'user_agent': entry.get('user_agent', ''),
                        'pattern': entry.get('pattern', ''),
                        'query': entry.get('query', '')
                    }
                    for entry in entries
                ]

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\nDetailed report saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OSINT Reconnaissance Detection Tool')
    parser.add_argument('log_file', help='Path to web server log file')
    parser.add_argument('--time-window', type=int, default=3600,
                       help='Analysis time window in seconds (default: 3600)')
    parser.add_argument('--export-json', help='Export detailed report to JSON file')

    args = parser.parse_args()

    detector = OSINTDetector(args.log_file, args.time_window)

    try:
        print("=== OSINT and Social Engineering Reconnaissance Detection ===")
        detector.analyze_osint_patterns()

        if args.export_json:
            detector.export_report(args.export_json)

    except FileNotFoundError:
        print(f"Error: Log file {args.log_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing logs: {e}")
        sys.exit(1)
```

### Key Detection Metrics

**Quantitative Indicators:**

- **Google Dorking**: >3 advanced search queries per session
- **Email Harvesting**: Any use of specialized tools or services
- **Social Media Reconnaissance**: >10 search queries across platforms
- **WHOIS Queries**: >15 queries per hour from single IP
- **Breach Database Searches**: >3 queries to credential databases
- **Automation Detection**: Tool signatures in user agents

**Behavioral Patterns:**

- Systematic information gathering across multiple sources
- Sequential searches with increasing specificity
- Use of OSINT automation tools and frameworks
- Cross-platform intelligence correlation
- Time-compressed reconnaissance activities
- Non-human browsing patterns and timing

**Network Signatures:**

- Multiple external reconnaissance service connections
- High-frequency API calls to intelligence services
- Unusual search query patterns and complexity
- Tool-specific HTTP headers and user agents
- Bulk data retrieval patterns

## Detection Methods

### Successful OSINT Indicators:

- Valid email addresses discovered
- Employee information gathered
- Social media profiles identified
- Technology stack revealed
- Leaked credentials found

### Information Quality Assessment:

- **High Confidence**: Verified through multiple sources
- **Medium Confidence**: Single source verification
- **Low Confidence**: Unverified information

## Mitigation Recommendations

1. **Information Disclosure Management**:

   - Review publicly accessible documents
   - Implement data classification policies
   - Regular OSINT audits of own organization

2. **Employee Security Training**:

   - Social media awareness training
   - Phishing simulation exercises
   - Security consciousness programs

3. **Technical Controls**:

   - Email security (SPF, DKIM, DMARC)
   - Web application security headers
   - Monitoring for leaked credentials

4. **Social Media Security**:
   - Corporate social media policies
   - Employee guidelines for online presence
   - Regular monitoring of company mentions

## Next Steps

- Use gathered information for targeted attacks
- Develop phishing campaigns based on OSINT
- Proceed to authentication attacks (Playbook 06)

## Legal and Ethical Considerations

⚠️ **WARNING**: Social engineering reconnaissance must only be performed with proper authorization. Gathering information about individuals without consent may violate privacy laws and ethical guidelines.
