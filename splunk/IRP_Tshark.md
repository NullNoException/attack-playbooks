# Incident Response Plan: Tshark Detection Playbook

## 1. Tshark Detection Commands

### PHP Reverse Shell

```bash
# ARP Reconnaissance
sudo tshark -i eth0 -f "arp" -T fields -e frame.time -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4

# Port Scanning
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e tcp.dstport

# HTTP Upload Activity
sudo tshark -i eth0 -f "host 10.30.0.235 and port 80" -Y "http.request.method == POST" -V

# Reverse Shell Traffic
sudo tshark -i eth0 -f "host 10.30.0.235 and port 4444" -w reverse_shell_capture.pcap

# Analyze Shell Commands
sudo tshark -r reverse_shell_capture.pcap -Y "tcp.port == 4444" -T fields -e tcp.payload | xxd -r -p
```

### Nmap Information Gathering

```bash
# Ping Sweep
sudo tshark -i eth0 -f "icmp" -Y "icmp.type == 8" -T fields -e frame.time -e ip.src -e ip.dst

# TCP Port Scanning
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e tcp.dstport | sort | uniq -c

# OS Fingerprinting
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.window_size_value == 1024 or icmp.type == 13" -V

# Service Version Detection
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1" -T fields -e ip.src -e tcp.dstport -e tcp.seq | head -100

# Script Scanning Activity
sudo tshark -i eth0 -f "host 10.30.0.235 and (port 139 or port 445 or port 22)" -w nmap_scripts.pcap
```

### SQL Injection (Juice Shop)

```bash
# SQL Injection Attempts
sudo tshark -i eth0 -f "host 10.30.0.237 and port 3000" -Y "http" -T fields -e frame.time -e http.request.uri -e http.request.method | grep -E "(SELECT|UNION|'|--)"

# Login Bypass Attempts
sudo tshark -i eth0 -f "host 10.30.0.237 and port 3000" -Y "http.request.uri contains \"/rest/user/login\"" -V

# SQLMap Activity
sudo tshark -i eth0 -f "host 10.30.0.237" -Y "http.user_agent contains \"sqlmap\"" -T fields -e frame.time -e ip.src -e http.user_agent

# Database Queries
sudo tshark -i eth0 -f "host 10.30.0.237" -Y "http contains \"sqlite_master\" or http contains \"information_schema\"" -w sqli_detection.pcap

# Extract HTTP Payloads
sudo tshark -r sqli_detection.pcap -Y "http.request.method == POST" -T fields -e http.file_data | xxd -r -p
```

### XSS Detection

```bash
# XSS Attempts
sudo tshark -i eth0 -f "port 80 or port 443 or port 3000" -Y "http" -T fields -e frame.time -e ip.src -e http.request.uri | grep -E "(<script>|javascript:|onerror|onload)"

# Encoded XSS
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http contains \"%3C\" or http contains \"&#\"" -w xss_encoded.pcap
```

### IDOR Detection

```bash
# ID Parameter Manipulation
sudo tshark -i eth0 -f "port 80 or port 443 or port 3000" -Y "http.request.uri contains \"id=\"" -T fields -e frame.time -e ip.src -e http.request.uri

# Directory Traversal
sudo tshark -i eth0 -Y "http.request.uri contains \"../\" or http.request.uri contains \"..%2F\"" -w idor_traversal.pcap
```

### Phishing Detection

```bash
# Credential Submissions
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.request.method == \"POST\" and http contains \"password\"" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri

# Suspicious DNS Queries
sudo tshark -i eth0 -f "port 53" -Y "dns" -T fields -e frame.time -e ip.src -e dns.qry.name | grep -E "(security|verify|update|account)"
```

### SYN Flood DDoS Detection

```bash
# SYN Flood Activity
sudo tshark -i eth0 -f "tcp[tcpflags] & tcp-syn != 0" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport | head -1000

# SYN Rate Analysis
sudo tshark -i eth0 -f "tcp[tcpflags] & tcp-syn != 0" -T fields -e frame.time | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1)}' | uniq -c
```

### Brute Force Detection

```bash
# Login Attempts
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.request.uri contains \"login\" and http.request.method == \"POST\"" -T fields -e frame.time -e ip.src -e http.host

# SSH Brute Force
sudo tshark -i eth0 -f "port 22" -T fields -e frame.time -e ip.src -e ip.dst | sort | uniq -c | awk '$1 > 10'
```

### Session Hijacking Detection

```bash
# Extract Session Tokens
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.cookie" -T fields -e frame.time -e ip.src -e http.cookie | grep -E "(sessionid|PHPSESSID|JSESSIONID)"

# Monitor Session Activity
sudo tshark -i eth0 -Y "http.set_cookie" -T fields -e frame.time -e ip.src -e ip.dst -e http.set_cookie
```

## 2. Automation Scripts

```bash
#!/bin/bash
# Multi-Attack Detection Script (Tshark)

TARGETS="10.30.0.235 10.30.0.236 10.30.0.237"
INTERFACE="eth0"
LOGDIR="/var/log/multi_attack_detection"
PCAP_DIR="$LOGDIR/pcaps"

mkdir -p $LOGDIR $PCAP_DIR

# ...existing code for detection functions (detect_sqli, detect_xss, detect_idor, detect_brute_force, detect_syn_flood, detect_session_hijacking, capture_evidence)...

# Main execution
echo "[$(date)] Starting Multi-Attack Detection System..."
echo "Monitoring targets: $TARGETS"
echo "Logs will be saved to: $LOGDIR"

detect_sqli
detect_xss
detect_idor
detect_brute_force
detect_syn_flood
detect_session_hijacking
capture_evidence

wait

echo "[$(date)] Detection cycle complete. Check logs in $LOGDIR"

# ...existing code for summary report...
```
