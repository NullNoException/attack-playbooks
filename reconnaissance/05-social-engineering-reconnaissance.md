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

## Shell Script Automation

```bash
#!/bin/bash
# Social Engineering Reconnaissance Script

DOMAIN="$1"
COMPANY="$2"
OUTPUT_DIR="osint_${DOMAIN}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [company_name]"
    echo "Example: $0 example.com 'Example Corp'"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Social Engineering Reconnaissance for $DOMAIN"

# WHOIS lookup
echo "[+] WHOIS lookup..."
whois "$DOMAIN" > "$OUTPUT_DIR/whois.txt"

# Email harvesting with theHarvester
echo "[+] Email harvesting..."
if command -v theharvester &> /dev/null; then
    theharvester -d "$DOMAIN" -l 100 -b google,bing,yahoo > "$OUTPUT_DIR/emails.txt"
fi

# Google dorks (save for manual execution)
echo "[+] Generating Google dorks..."
cat > "$OUTPUT_DIR/google_dorks.txt" << EOF
site:$DOMAIN filetype:pdf
site:$DOMAIN filetype:xlsx
site:$DOMAIN filetype:docx
site:$DOMAIN "confidential"
site:$DOMAIN "internal use only"
site:$DOMAIN inurl:admin
site:$DOMAIN inurl:login
site:$DOMAIN "index of"
site:linkedin.com "$COMPANY"
site:github.com "$DOMAIN"
site:pastebin.com "$DOMAIN"
"$DOMAIN" password
"$DOMAIN" api_key
"$DOMAIN" secret
EOF

# Social media URLs (for manual checking)
echo "[+] Generating social media URLs..."
cat > "$OUTPUT_DIR/social_media_urls.txt" << EOF
LinkedIn: https://www.linkedin.com/company/$COMPANY
Twitter: https://twitter.com/search?q=$COMPANY
Facebook: https://www.facebook.com/search/top?q=$COMPANY
GitHub: https://github.com/search?q=$DOMAIN
YouTube: https://www.youtube.com/results?search_query=$COMPANY
EOF

# Technology detection
echo "[+] Technology detection..."
curl -s "http://$DOMAIN" | grep -i "generator\|framework\|version" > "$OUTPUT_DIR/technology.txt"

# Check for common employee email patterns
echo "[+] Generating email patterns..."
cat > "$OUTPUT_DIR/email_patterns.txt" << EOF
admin@$DOMAIN
administrator@$DOMAIN
info@$DOMAIN
contact@$DOMAIN
support@$DOMAIN
help@$DOMAIN
sales@$DOMAIN
marketing@$DOMAIN
hr@$DOMAIN
it@$DOMAIN
security@$DOMAIN
webmaster@$DOMAIN
EOF

# DNS enumeration for additional info
echo "[+] DNS enumeration..."
dig "$DOMAIN" ANY > "$OUTPUT_DIR/dns_records.txt"

echo "[+] OSINT gathering complete. Review files in $OUTPUT_DIR/"
echo "[+] Manual steps required:"
echo "    1. Execute Google dorks from google_dorks.txt"
echo "    2. Check social media URLs from social_media_urls.txt"
echo "    3. Verify email patterns from email_patterns.txt"
echo "    4. Search for leaked credentials in breach databases"
```

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
