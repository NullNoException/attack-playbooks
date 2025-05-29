# Incident Response Plan - Red Team Attack Detection

## Overview

This document provides step-by-step instructions for detecting and analyzing the red team attacks documented in the Red Team Playbook using Wireshark, Splunk, and tshark. The monitored network includes nodes: 10.30.0.235, 10.30.0.236, 10.30.0.237.

---

## 1. Network Infrastructure Setup

### Network Topology

- **DVWA Target:** 10.30.0.235 (Metasploitable2)
- **Juice Shop Target:** 10.30.0.237
- **Monitoring Node:** 10.30.0.236
- **Attacker:** Kali Linux (various IPs)

### Monitoring Points

- **TAP/SPAN Port:** Configure network switch to mirror traffic to 10.30.0.236
- **Splunk Forwarder:** Install on each target node
- **Network Sensors:** Deploy on critical network segments

---

## 1.5. Wireshark Setup and Configuration Guide

### 1.5.1 Initial Wireshark Configuration

#### Step 1: Network Interface Selection

```bash
# List available interfaces
sudo wireshark -D

# Start Wireshark with specific interface
sudo wireshark -i eth0
```

**Instructions:**

1. Launch Wireshark as root/administrator
2. Go to **Capture → Interfaces**
3. Select the interface connected to the monitored network segment
4. Configure **Capture Options** → **Promiscuous Mode: Enabled**
5. Set **Ring Buffer** to 100MB with 10 files for continuous capture

#### Step 2: Basic Display Filter Syntax

- **AND operator:** `filter1 and filter2`
- **OR operator:** `filter1 or filter2`
- **NOT operator:** `not filter1`
- **Parentheses:** `(filter1 or filter2) and filter3`
- **Field comparison:** `tcp.port == 80`
- **Range matching:** `tcp.port in {80 443 8080}`

#### Step 3: Time-Based Filtering

- **Relative time:** `frame.time_relative >= 10`
- **Absolute time:** `frame.time >= "2024-01-15 10:00:00"`
- **Time delta:** `tcp.time_delta > 1.0`

### 1.5.2 Target-Specific Filter Presets

#### Preset 1: DVWA Target Monitoring (10.30.0.235)

```
host 10.30.0.235 and (tcp or icmp or arp)
```

**Detects:** All network activity to/from DVWA target including reconnaissance, exploitation attempts, and data exfiltration.

#### Preset 2: Juice Shop Target Monitoring (10.30.0.237)

```
host 10.30.0.237 and tcp.port == 3000
```

**Detects:** HTTP/HTTPS traffic to Juice Shop application, SQL injection attempts, authentication bypass, and application-layer attacks.

#### Preset 3: Network Reconnaissance Detection

```
(arp.opcode == 1) or (icmp.type == 8) or (tcp.flags.syn == 1 and tcp.flags.ack == 0)
```

**Detects:** Network discovery activities including ARP scanning, ping sweeps, and port scanning attempts.

#### Preset 4: Malicious Traffic Detection

```
tcp.port in {4444 1234 8080 9999} or http contains "shell" or http contains "cmd"
```

**Detects:** Reverse shell connections, command injection attempts, and backdoor communications.

---

## 1.6 Attack Detection Matrix

### 1.6.1 Wireshark Filter-to-Attack Mapping

| Filter                                                                  | Attack Type            | Detection Purpose                                      |
| ----------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------ |
| `arp.opcode == 1`                                                       | Network Reconnaissance | Detects ARP scanning and network discovery             |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0`                             | Port Scanning          | Identifies TCP SYN scans and stealth scanning          |
| `http.request.method == "POST" and http contains "multipart/form-data"` | File Upload Attack     | Detects malicious file uploads including webshells     |
| `tcp.port == 4444`                                                      | Reverse Shell          | Monitors backdoor connections and command execution    |
| `http contains "'" or http contains "UNION"`                            | SQL Injection          | Identifies SQL injection payloads and database attacks |
| `http.user_agent contains "sqlmap"`                                     | Automated SQL Testing  | Detects SQLMap and other automated testing tools       |
| `icmp.type == 8`                                                        | Network Discovery      | Monitors ping sweeps and host enumeration              |
| `tcp.flags.push == 1 and tcp.len > 0`                                   | Service Enumeration    | Detects banner grabbing and service fingerprinting     |

### 1.6.2 Splunk Query-to-Attack Mapping

| Splunk Query Pattern                                                       | Attack Type            | Detection Logic                                      |
| -------------------------------------------------------------------------- | ---------------------- | ---------------------------------------------------- | ------------- | ------------------------------------------------- |
| `stats dc(dest_port) as unique_ports by src_ip \| where unique_ports > 50` | Port Scanning          | Identifies sources scanning multiple ports           |
| `rex field=uri_query "(?<sqli_indicators>('                                | \"                     | UNION\|SELECT))"`                                    | SQL Injection | Extracts SQL injection patterns from web requests |
| `where match(useragent, "(?i)sqlmap")`                                     | Automated Testing      | Detects automated penetration testing tools          |
| `stats count by src_mac \| where count > 50`                               | ARP Reconnaissance     | Identifies excessive ARP requests from single source |
| `transaction src_ip dest_ip dest_port \| where duration > 60`              | Persistent Connections | Detects long-lived connections indicating backdoors  |

---

## 2. Detection of PHP Reverse Shell Attack

### 2.1 Wireshark Detection Procedures with Detailed Filtering

#### Step 1: Configure Attack-Specific Capture

**Initial Setup Instructions:**

1. Open Wireshark on monitoring node (10.30.0.236)
2. Start capture on network interface
3. Apply broad filter to capture all traffic to DVWA target:
   ```
   host 10.30.0.235
   ```

#### Step 2: Phase-by-Phase Detection Filtering

**Phase 1: Network Discovery (netdiscover)**

**Filter 1A - Basic ARP Traffic:**

```
arp
```

**Filter 1B - Excessive ARP Requests:**

```
arp.opcode == 1
```

**Filter 1C - ARP Requests from Single Source:**

```
arp.opcode == 1 and arp.src.hw_mac == [ATTACKER_MAC]
```

**Analysis Instructions:**

1. Apply Filter 1A and observe ARP request patterns
2. Go to **Statistics → Protocol Hierarchy** to check ARP traffic percentage
3. Use **Statistics → Conversations → Ethernet** to identify top MAC addresses
4. Apply Filter 1B to focus on ARP requests only
5. Look for sequential IP address scanning patterns in **Info** column

**Phase 2: Port Scanning Detection (Nmap)**

**Filter 2A - TCP SYN Scan Detection:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235
```

**Filter 2B - Port Scan from Specific Source:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235 and ip.src == [ATTACKER_IP]
```

**Filter 2C - High Port Scan Detection:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235 and tcp.dstport > 1024
```

**Filter 2D - Rapid Scanning Pattern:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235 and frame.time_delta < 0.01
```

**Analysis Instructions:**

1. Apply Filter 2A and check **Statistics → Endpoints → IPv4**
2. Sort by **Packets** column to identify scanning sources
3. Use **Statistics → I/O Graphs** to visualize scan timing
4. Apply Filter 2B with identified attacker IP
5. Go to **Statistics → Service Response Time → TCP** to analyze response patterns
6. Check for RST responses indicating closed ports

**Phase 3: HTTP File Upload Detection**

**Filter 3A - HTTP POST Requests:**

```
http.request.method == "POST" and ip.dst == 10.30.0.235
```

**Filter 3B - File Upload Detection:**

```
http.request.method == "POST" and ip.dst == 10.30.0.235 and http.content_type contains "multipart/form-data"
```

**Filter 3C - PHP File Upload:**

```
http.request.method == "POST" and ip.dst == 10.30.0.235 and http contains "php"
```

**Filter 3D - Large Upload Detection:**

```
http.request.method == "POST" and ip.dst == 10.30.0.235 and http.content_length > 1000
```

**Analysis Instructions:**

1. Apply Filter 3A to see all POST requests
2. Right-click suspicious POST → **Follow → HTTP Stream**
3. Look for `Content-Disposition: form-data; name="uploaded"` headers
4. Search for PHP reverse shell indicators:
   - `exec()`, `shell_exec()`, `system()`, `passthru()`
   - `fsockopen()`, `socket_create()`
   - `/bin/sh`, `/bin/bash`
5. Export HTTP objects: **File → Export Objects → HTTP**

**Phase 4: Reverse Shell Connection Detection**

**Filter 4A - Reverse Shell Port Traffic:**

```
tcp.port == 4444 and ip.src == 10.30.0.235
```

**Filter 4B - Outbound High Port Connections:**

```
tcp.flags.syn == 1 and ip.src == 10.30.0.235 and tcp.dstport > 1024
```

**Filter 4C - Shell Command Traffic:**

```
tcp.port == 4444 and tcp.len > 0
```

**Filter 4D - Base64 Encoded Commands:**

```
tcp.port == 4444 and tcp.payload contains "echo"
```

**Analysis Instructions:**

1. Apply Filter 4A immediately after file upload
2. Right-click connection → **Follow → TCP Stream**
3. Look for shell prompt indicators (`$`, `#`, `root@`)
4. Check for command execution patterns:
   - `whoami`, `id`, `uname -a`
   - `cat /etc/passwd`
   - `ls -la`
5. Use **Find Packet** (Ctrl+F) to search for specific commands

#### Step 3: Advanced Filtering Techniques

**Multi-Phase Attack Correlation:**

```
(arp.opcode == 1) or (tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235) or (http.request.method == "POST" and ip.dst == 10.30.0.235) or (tcp.port == 4444)
```

**Time-Based Analysis:**

```
host 10.30.0.235 and frame.time >= "2024-01-15 14:00:00" and frame.time <= "2024-01-15 14:30:00"
```

**Attack Chain Visualization:**

1. Apply comprehensive filter above
2. Go to **Statistics → Flow Graph**
3. Select **TCP Flows** and **IPv4 Address**
4. Analyze attack progression timeline

---

## 3. Detection of Nmap Information Gathering Attack

### 3.1 Comprehensive Nmap Detection Filtering

#### Step 1: Initial Scan Phase Detection

**Filter N1A - ICMP Ping Sweep:**

```
icmp.type == 8 and ip.dst_host == 10.30.0.235
```

**Filter N1B - TCP Ping Alternative:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.dstport == 80 and ip.dst == 10.30.0.235
```

**Filter N1C - UDP Ping Detection:**

```
udp and ip.dst == 10.30.0.235 and icmp.type == 3
```

**Analysis Instructions:**

1. Monitor for ICMP echo requests indicating ping sweep
2. Check **Statistics → ICMP** for unusual request patterns
3. Look for immediate ICMP replies or timeouts
4. Use **Statistics → Conversations → IPv4** to identify scanning source

#### Step 2: Port Scanning Techniques Detection

**Filter N2A - TCP Connect Scan:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235
```

**Filter N2B - TCP SYN Stealth Scan:**

```
tcp.flags == 0x02 and ip.dst == 10.30.0.235
```

**Filter N2C - TCP FIN Scan:**

```
tcp.flags.fin == 1 and tcp.flags.syn == 0 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235
```

**Filter N2D - TCP XMAS Scan:**

```
tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1 and ip.dst == 10.30.0.235
```

**Filter N2E - TCP NULL Scan:**

```
tcp.flags == 0x00 and ip.dst == 10.30.0.235
```

**Filter N2F - UDP Scan:**

```
udp and ip.dst == 10.30.0.235
```

**Analysis Instructions:**

1. Apply each filter to identify scan type
2. Monitor **Statistics → TCP Stream Graphs** for scan patterns
3. Check for RST responses indicating closed ports
4. Use **Statistics → Service Response Time** to analyze timing

#### Step 3: Service Version Detection

**Filter N3A - Service Banner Grabbing:**

```
tcp.flags.push == 1 and tcp.len > 0 and ip.dst == 10.30.0.235
```

**Filter N3B - HTTP Version Detection:**

```
http.request.method == "GET" and http.request.uri == "/" and ip.dst == 10.30.0.235
```

**Filter N3C - SSH Version Detection:**

```
tcp.port == 22 and tcp.len > 0 and ip.dst == 10.30.0.235
```

**Filter N3D - FTP Banner Grabbing:**

```
tcp.port == 21 and tcp.len > 0 and ip.dst == 10.30.0.235
```

**Analysis Instructions:**

1. Look for rapid connection-disconnection patterns
2. Check for service banners in TCP streams
3. Monitor for OPTIONS, HEAD requests on HTTP
4. Analyze immediate connection termination after banner grab

#### Step 4: OS Detection Filtering

**Filter N4A - OS Fingerprinting - Window Size:**

```
tcp.window_size_value == 1024 and ip.dst == 10.30.0.235
```

**Filter N4B - OS Fingerprinting - TCP Options:**

```
tcp.options.mss_val < 536 and ip.dst == 10.30.0.235
```

**Filter N4C - ICMP Timestamp Requests:**

```
icmp.type == 13 and ip.dst == 10.30.0.235
```

**Filter N4D - TCP Sequence Analysis:**

```
tcp.flags.syn == 1 and tcp.seq == 0 and ip.dst == 10.30.0.235
```

**Analysis Instructions:**

1. Monitor for unusual TCP window sizes
2. Check TCP options combinations
3. Look for ICMP timestamp and information requests
4. Analyze TCP sequence number patterns

#### Step 5: NSE Script Detection

**Filter N5A - SMB Enumeration:**

```
smb and ip.dst == 10.30.0.235
```

**Filter N5B - SMB2 Protocol:**

```
smb2 and ip.dst == 10.30.0.235
```

**Filter N5C - HTTP Enumeration:**

```
http.request.method in {"OPTIONS" "HEAD" "TRACE"} and ip.dst == 10.30.0.235
```

**Filter N5D - DNS Enumeration:**

```
dns and ip.dst == 10.30.0.235
```

**Analysis Instructions:**

1. Monitor for SMB negotiation packets
2. Check for directory enumeration attempts
3. Look for HTTP OPTIONS requests
4. Analyze DNS reverse lookups

---

## 4. Detection of SQL Injection Attack (OWASP Juice Shop)

### 4.1 HTTP Traffic Analysis and SQL Injection Detection

#### Step 1: Basic HTTP Traffic Monitoring

**Filter S1A - Juice Shop HTTP Traffic:**

```
host 10.30.0.237 and tcp.port == 3000
```

**Filter S1B - HTTP Only:**

```
http and ip.dst == 10.30.0.237
```

**Filter S1C - HTTPS Traffic:**

```
tls and ip.dst == 10.30.0.237 and tcp.port == 3000
```

**Analysis Instructions:**

1. Monitor all HTTP traffic to Juice Shop
2. Check **Statistics → HTTP → Requests** for request patterns
3. Use **Statistics → HTTP → Load Distribution** to identify peaks
4. Monitor response codes in **Info** column

#### Step 2: Authentication Bypass Detection

**Filter S2A - Login Attempts:**

```
http.request.uri contains "/rest/user/login" and http.request.method == "POST"
```

**Filter S2B - SQL Injection in Login:**

```
http.request.uri contains "/rest/user/login" and http contains "'"
```

**Filter S2C - Comment-Based Injection:**

```
http.request.uri contains "/rest/user/login" and http contains "--"
```

**Filter S2D - Union-Based Injection:**

```
http contains "UNION" and ip.dst == 10.30.0.237
```

**Analysis Instructions:**

1. Apply Filter S2A and monitor login frequency
2. Right-click suspicious requests → **Follow → HTTP Stream**
3. Look for SQL injection payloads in request body:
   - `admin@juice-sh.op'--`
   - `' OR 1=1--`
   - `' UNION SELECT`
4. Check response for authentication tokens
5. Monitor for 200 OK responses to malicious payloads

#### Step 3: Database Enumeration Detection

**Filter S3A - Database Keywords:**

```
http contains "SELECT" or http contains "UNION" or http contains "sqlite_master"
```

**Filter S3B - Information Schema Queries:**

```
http contains "information_schema" and ip.dst == 10.30.0.237
```

**Filter S3C - Table Enumeration:**

```
http contains "SHOW TABLES" or http contains "sqlite_master" and ip.dst == 10.30.0.237
```

**Filter S3D - Column Enumeration:**

```
http contains "DESCRIBE" or http contains "PRAGMA table_info" and ip.dst == 10.30.0.237
```

**Analysis Instructions:**

1. Monitor for SQL keywords in HTTP requests
2. Check User-Agent strings for SQLMap signatures
3. Look for database metadata queries
4. Analyze response sizes for data extraction indicators

#### Step 4: SQLMap Automated Tool Detection

**Filter S4A - SQLMap User Agent:**

```
http.user_agent contains "sqlmap"
```

**Filter S4B - Automated Testing Patterns:**

```
http contains "testpayload" or http contains "sqlmap"
```

**Filter S4C - Error-Based Injection:**

```
http.response.code >= 500 and ip.src == 10.30.0.237
```

**Filter S4D - Time-Based Injection:**

```
http and ip.dst == 10.30.0.237 and http.time > 5
```

**Analysis Instructions:**

1. Monitor for SQLMap signatures in requests
2. Check for rapid successive requests with variations
3. Look for error responses containing SQL keywords
4. Analyze response times for time-based injection indicators

#### Step 5: Data Extraction Detection

**Filter S5A - Large HTTP Responses:**

```
http.content_length > 10000 and ip.src == 10.30.0.237
```

**Filter S5B - JSON Data Extraction:**

```
http contains "password" or http contains "email" and ip.src == 10.30.0.237
```

**Filter S5C - Base64 Encoded Data:**

```
http contains "base64" and ip.src == 10.30.0.237
```

**Filter S5D - Hexadecimal Data:**

```
http.response and ip.src == 10.30.0.237 and http contains "0x"
```

**Analysis Instructions:**

1. Monitor for unusually large responses
2. Check for sensitive data in responses
3. Look for encoded data extraction
4. Analyze JSON responses for database dumps

---

## 5. Advanced Wireshark Analysis Techniques

### 5.1 Coloring Rules for Attack Detection

#### Custom Coloring Rules Setup:

1. Go to **View → Coloring Rules**
2. Add new rules with following filters:

**Rule 1 - Port Scanning (Red Background):**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

**Rule 2 - SQL Injection (Orange Background):**

```
http contains "'" or http contains "UNION" or http contains "SELECT"
```

**Rule 3 - Reverse Shell (Purple Background):**

```
tcp.port in {4444 1234 8080 9999}
```

**Rule 4 - ARP Scanning (Yellow Background):**

```
arp.opcode == 1
```

### 5.2 Expert Information Analysis

#### Navigate to Expert Information:

1. Go to **Analyze → Expert Information**
2. Focus on **Warnings** and **Errors** tabs
3. Look for:
   - **TCP Retransmissions** (potential blocking)
   - **TCP RST** (scan responses)
   - **HTTP Response Errors** (injection attempts)

### 5.3 Statistical Analysis

#### Key Statistics for Attack Detection:

**Protocol Hierarchy:**

- **Analyze → Statistics → Protocol Hierarchy**
- Look for unusual protocol distributions

**Conversations Analysis:**

- **Statistics → Conversations → IPv4**
- Sort by packets to identify top talkers

**Endpoints Analysis:**

- **Statistics → Endpoints → IPv4**
- Identify suspicious source/destination patterns

**I/O Graphs:**

- **Statistics → I/O Graphs**
- Visualize attack timing and intensity

### 5.4 Export and Reporting

#### Evidence Collection:

1. **Export Packet Dissections:**

   - **File → Export Packet Dissections → As CSV**

2. **Export HTTP Objects:**

   - **File → Export Objects → HTTP**

3. **Save Filtered Packets:**

   - Apply filter → **File → Export Specified Packets**

4. **Generate Reports:**
   - **Statistics → Summary** for capture overview
   - **Statistics → Resolved Addresses** for IP mapping

---

## 6. Incident Response Procedures

### 6.1 Immediate Response Actions

#### Step 1: Containment

1. **Network Isolation:**

   ```bash
   # Block attacker IP at firewall
   iptables -A INPUT -s <ATTACKER_IP> -j DROP
   iptables -A OUTPUT -d <ATTACKER_IP> -j DROP
   ```

2. **Service Isolation:**
   ```bash
   # Stop affected services
   systemctl stop apache2
   systemctl stop nginx
   ```

#### Step 2: Evidence Collection

**Wireshark Evidence:**

1. Save current packet capture: File → Save As → evidence_YYYYMMDD_HHMMSS.pcapng
2. Export HTTP objects: File → Export Objects → HTTP
3. Export certificate information if HTTPS involved

**Tshark Evidence Collection:**

```bash
# Create evidence directory
mkdir /evidence/$(date +%Y%m%d_%H%M%S)

# Extract specific attack traffic
sudo tshark -r evidence.pcap -Y "host <ATTACKER_IP>" -w /evidence/attacker_traffic.pcap

# Export HTTP conversations
sudo tshark -r evidence.pcap -Y "http" -T pdml > /evidence/http_traffic.xml
```

**Splunk Evidence:**

```spl
# Export search results
index=* src_ip="<ATTACKER_IP>" earliest=-1h
| outputcsv /evidence/splunk_investigation.csv
```

### 6.2 Forensic Analysis

#### Step 1: Timeline Creation

```bash
# Create timeline from packet capture
sudo tshark -r evidence.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri > timeline.csv
```

#### Step 2: Payload Analysis

```bash
# Extract payloads for analysis
sudo tshark -r evidence.pcap -Y "http.request.method == POST" -T fields -e http.file_data | xxd -r -p > payloads.txt
```

#### Step 3: Impact Assessment

1. Identify compromised accounts
2. Check for data exfiltration
3. Assess system integrity
4. Document business impact

### 6.3 Recovery and Lessons Learned

#### Recovery Steps:

1. Patch identified vulnerabilities
2. Update security controls
3. Restore from clean backups
4. Implement additional monitoring

#### Documentation Requirements:

1. Attack timeline
2. Evidence collected
3. Impact assessment
4. Remediation actions
5. Lessons learned

---

## 7. Automation Scripts

### 7.1 Automated Detection Script

```bash
#!/bin/bash
# Red Team Attack Detection Script

TARGETS="10.30.0.235 10.30.0.236 10.30.0.237"
INTERFACE="eth0"
LOGDIR="/var/log/detection"

# Create log directory
mkdir -p $LOGDIR

# Function to detect port scanning
detect_port_scan() {
    echo "[$(date)] Starting port scan detection..."
    sudo tshark -i $INTERFACE -f "tcp[tcpflags] & tcp-syn != 0" -c 1000 -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport | \
    awk '{count[$2]++} END {for (ip in count) if (count[ip] > 50) print "ALERT: Port scan from " ip " (" count[ip] " packets)"}' > $LOGDIR/portscan_$(date +%Y%m%d_%H%M%S).log
}

# Function to detect SQL injection
detect_sqli() {
    echo "[$(date)] Starting SQL injection detection..."
    sudo tshark -i $INTERFACE -f "port 3000 or port 80" -Y "http" -T fields -e frame.time -e ip.src -e http.request.uri | \
    grep -E "('|UNION|SELECT|--|;)" > $LOGDIR/sqli_$(date +%Y%m%d_%H%M%S).log
}

# Function to detect reverse shells
detect_reverse_shell() {
    echo "[$(date)] Starting reverse shell detection..."
    sudo tshark -i $INTERFACE -f "port 4444 or port 1234" -c 10 -w $LOGDIR/reverse_shell_$(date +%Y%m%d_%H%M%S).pcap &
}

# Main execution
echo "[$(date)] Starting Red Team Attack Detection..."
detect_port_scan &
detect_sqli &
detect_reverse_shell &

wait
echo "[$(date)] Detection complete. Check logs in $LOGDIR"
```

### 7.2 Splunk Forwarder Configuration

```conf
# inputs.conf
[monitor:///var/log/detection]
index = security
sourcetype = red_team_detection

[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = 10.30.0.236:9997
```

This comprehensive incident response plan provides detailed detection procedures for all red team attacks using Wireshark, Splunk, and tshark across the specified network nodes.

---

## 8. Detection of Cross-Site Scripting (XSS) Attacks

### 8.1 Wireshark Detection Procedures

#### Step 1: XSS Payload Detection in HTTP Traffic

**Filter X1A - Basic XSS Detection:**

```
http contains "<script>" or http contains "javascript:" or http contains "onerror"
```

**Detects:** Reflected and stored XSS attempts in HTTP requests/responses.

**Filter X1B - Encoded XSS Detection:**

```
http contains "%3Cscript%3E" or http contains "%3C" or http contains "&#"
```

**Detects:** URL-encoded and HTML-encoded XSS payloads.

**Filter X1C - Event Handler XSS:**

```
http contains "onload" or http contains "onclick" or http contains "onmouseover"
```

**Detects:** XSS attacks using HTML event handlers.

**Filter X1D - DOM-based XSS:**

```
http contains "document.write" or http contains "innerHTML" or http contains "location.hash"
```

**Detects:** DOM manipulation attempts indicating DOM-based XSS.

#### Analysis Instructions:

1. Monitor GET/POST parameters for script tags
2. Check for JavaScript execution attempts in form fields
3. Look for cookie theft attempts: `document.cookie`
4. Analyze response headers for Content-Security-Policy bypass attempts

### 8.2 Tshark Detection Commands

#### Command X1: Monitor XSS Attempts

```bash
sudo tshark -i eth0 -f "port 80 or port 443 or port 3000" -Y "http" -T fields -e frame.time -e ip.src -e http.request.uri | grep -E "(<script>|javascript:|onerror|onload)"
```

#### Command X2: Detect Encoded XSS

```bash
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http contains \"%3C\" or http contains \"&#\"" -w xss_encoded.pcap
```

### 8.3 Splunk Detection Queries

#### Query X1: XSS Pattern Detection

```spl
index=web
| rex field=uri_query "(?<xss_indicators>(<script>|javascript:|onerror|onload|alert\(|document\.cookie))"
| where isnotnull(xss_indicators)
| stats count by src_ip xss_indicators uri_path
```

#### Query X2: Cookie Theft Detection

```spl
index=web
| where match(uri_query, "(?i)(document\.cookie|document\.location|window\.location)")
| stats count by src_ip uri_path form_data
```

---

## 9. Detection of Insecure Direct Object Reference (IDOR) Attacks

### 9.1 Wireshark Detection Procedures

#### Step 1: IDOR Pattern Detection

**Filter I1A - Sequential ID Access:**

```
http.request.uri contains "id=" or http.request.uri contains "user=" or http.request.uri contains "file="
```

**Detects:** Direct object reference attempts in URL parameters.

**Filter I1B - Administrative Function Access:**

```
http.request.uri contains "admin" or http.request.uri contains "profile" or http.request.uri contains "account"
```

**Detects:** Attempts to access administrative or user-specific functions.

**Filter I1C - File System Access:**

```
http.request.uri contains "../" or http.request.uri contains "..%2F" or http.request.uri contains "file="
```

**Detects:** Directory traversal and file access attempts.

#### Analysis Instructions:

1. Look for incremental ID manipulation in requests
2. Monitor for access to other users' data
3. Check for privilege escalation attempts
4. Analyze response codes for successful unauthorized access (200 OK)

### 9.2 Tshark Detection Commands

#### Command I1: Monitor ID Parameter Manipulation

```bash
sudo tshark -i eth0 -f "port 80 or port 443 or port 3000" -Y "http.request.uri contains \"id=\"" -T fields -e frame.time -e ip.src -e http.request.uri
```

#### Command I2: Detect Directory Traversal

```bash
sudo tshark -i eth0 -Y "http.request.uri contains \"../\" or http.request.uri contains \"..%2F\"" -w idor_traversal.pcap
```

### 9.3 Splunk Detection Queries

#### Query I1: IDOR Parameter Manipulation

```spl
index=web
| rex field=uri_query "(?<object_refs>(id=|user=|file=|account=)(?<ref_value>\d+))"
| where isnotnull(object_refs)
| eventstats dc(ref_value) as unique_refs by src_ip uri_path
| where unique_refs > 10
| stats count by src_ip uri_path object_refs
```

#### Query I2: Unauthorized Access Detection

```spl
index=web status=200
| where match(uri_path, "(?i)(admin|profile|account|user)")
| where match(uri_query, "(id=|user=)")
| stats dc(uri_query) as unique_access by src_ip
| where unique_access > 5
```

---

## 10. Detection of Phishing Attacks

### 10.1 Wireshark Detection Procedures

#### Step 1: Phishing Infrastructure Detection

**Filter P1A - Suspicious Domain Access:**

```
dns or http.host contains "security" or http.host contains "verify" or http.host contains "update"
```

**Detects:** DNS queries and HTTP requests to domains commonly used in phishing.

**Filter P1B - Credential Harvesting:**

```
http.request.method == "POST" and (http contains "password" or http contains "username" or http contains "login")
```

**Detects:** POST requests containing credentials to potentially malicious sites.

**Filter P1C - Redirect Chains:**

```
http.response.code == 302 or http.response.code == 301
```

**Detects:** HTTP redirects used to obscure phishing destinations.

#### Analysis Instructions:

1. Monitor for suspicious domain registrations
2. Check for SSL certificate anomalies
3. Look for credential submission to non-legitimate domains
4. Analyze referrer headers for phishing email links

### 10.2 Tshark Detection Commands

#### Command P1: Monitor Credential Submissions

```bash
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.request.method == \"POST\" and http contains \"password\"" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

#### Command P2: Detect Suspicious DNS Queries

```bash
sudo tshark -i eth0 -f "port 53" -Y "dns" -T fields -e frame.time -e ip.src -e dns.qry.name | grep -E "(security|verify|update|account)"
```

### 10.3 Splunk Detection Queries

#### Query P1: Phishing Domain Detection

```spl
index=web
| where match(host, "(?i)(security|verify|update|account|confirm)")
| where NOT match(host, "(legitimate-domain\.com|trusted-site\.org)")
| stats count by src_ip host uri_path
```

#### Query P2: Credential Harvesting Detection

```spl
index=web method="POST"
| where match(form_data, "(?i)(password|username|login|email)")
| where NOT match(host, "(legitimate-login-domains)")
| stats count by src_ip host form_data
```

---

## 11. Detection of SYN Flood DDoS Attacks

### 11.1 Wireshark Detection Procedures

#### Step 1: SYN Flood Pattern Detection

**Filter S1A - High Volume SYN Packets:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

**Detects:** TCP SYN packets indicating potential SYN flood attacks.

**Filter S1B - Incomplete Handshakes:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and not tcp.flags.reset == 1
```

**Detects:** SYN packets without corresponding ACK or RST responses.

**Filter S1C - Source IP Analysis:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235
```

**Detects:** SYN packets targeting specific servers for flood analysis.

#### Analysis Instructions:

1. Use Statistics → I/O Graphs to visualize SYN packet rates
2. Check for randomized or spoofed source IPs
3. Monitor TCP conversations for incomplete handshakes
4. Analyze destination port patterns

### 11.2 Tshark Detection Commands

#### Command S1: Monitor SYN Flood Activity

```bash
sudo tshark -i eth0 -f "tcp[tcpflags] & tcp-syn != 0" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport | head -1000
```

#### Command S2: Analyze SYN Rate

```bash
sudo tshark -i eth0 -f "tcp[tcpflags] & tcp-syn != 0" -T fields -e frame.time | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1)}' | uniq -c
```

### 11.3 Splunk Detection Queries

#### Query S1: SYN Flood Detection

```spl
index=network tcp_flags="S"
| bucket _time span=1s
| stats count as syn_count by _time dest_ip
| where syn_count > 100
| sort -syn_count
```

#### Query S2: Source IP Analysis

```spl
index=network tcp_flags="S" dest_ip="10.30.0.235"
| stats count by src_ip
| where count > 50
| sort -count
```

---

## 12. Detection of Brute Force Attacks

### 12.1 Wireshark Detection Procedures

#### Step 1: Authentication Brute Force Detection

**Filter B1A - Multiple Login Attempts:**

```
http.request.uri contains "login" and http.request.method == "POST"
```

**Detects:** Repeated POST requests to login endpoints.

**Filter B1B - SSH Brute Force:**

```
tcp.port == 22 and tcp.flags.syn == 1
```

**Detects:** Multiple SSH connection attempts.

**Filter B1C - FTP Brute Force:**

```
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

**Detects:** FTP authentication attempts.

#### Analysis Instructions:

1. Count login attempts per source IP
2. Monitor for failed authentication responses
3. Check for password spraying patterns
4. Analyze timing between attempts

### 12.2 Tshark Detection Commands

#### Command B1: Monitor Login Attempts

```bash
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.request.uri contains \"login\" and http.request.method == \"POST\"" -T fields -e frame.time -e ip.src -e http.host
```

#### Command B2: SSH Brute Force Detection

```bash
sudo tshark -i eth0 -f "port 22" -T fields -e frame.time -e ip.src -e ip.dst | sort | uniq -c | awk '$1 > 10'
```

### 12.3 Splunk Detection Queries

#### Query B1: HTTP Brute Force Detection

```spl
index=web uri_path contains "login" method="POST"
| stats count as attempts by src_ip
| where attempts > 20
| sort -attempts
```

#### Query B2: SSH Brute Force Detection

```spl
index=network dest_port=22 tcp_flags="S"
| bucket _time span=1m
| stats count as attempts by _time src_ip dest_ip
| where attempts > 10
```

---

## 13. Detection of Session Hijacking Attacks

### 13.1 Wireshark Detection Procedures

#### Step 1: Session Token Analysis

**Filter H1A - Cookie Theft:**

```
http.cookie or http.set_cookie
```

**Detects:** HTTP cookies that could be targets for session hijacking.

**Filter H1B - Session Fixation:**

```
http contains "JSESSIONID" or http contains "PHPSESSID" or http contains "ASP.NET_SessionId"
```

**Detects:** Session identifiers in HTTP traffic.

**Filter H1C - Duplicate Session Usage:**

```
http.cookie contains "sessionid" or http.cookie contains "session"
```

**Detects:** Session cookies being used from multiple sources.

#### Analysis Instructions:

1. Track session tokens across different source IPs
2. Monitor for session token reuse
3. Check for missing HTTPOnly/Secure flags
4. Analyze timing of session usage patterns

### 13.2 Tshark Detection Commands

#### Command H1: Extract Session Tokens

```bash
sudo tshark -i eth0 -f "port 80 or port 443" -Y "http.cookie" -T fields -e frame.time -e ip.src -e http.cookie | grep -E "(sessionid|PHPSESSID|JSESSIONID)"
```

#### Command H2: Monitor Session Activity

```bash
sudo tshark -i eth0 -Y "http.set_cookie" -T fields -e frame.time -e ip.src -e ip.dst -e http.set_cookie
```

### 13.3 Splunk Detection Queries

#### Query H1: Session Hijacking Detection

```spl
index=web
| rex field=cookie "(?&lt;session_token&gt;(PHPSESSID|JSESSIONID|sessionid)=[^;]+)"
| where isnotnull(session_token)
| stats dc(src_ip) as unique_ips, values(src_ip) as source_ips by session_token
| where unique_ips > 1
| sort -unique_ips
```

#### Query H2: Session Anomaly Detection

```spl
index=web
| rex field=cookie "sessionid=(?<session_token>[^;]+)"
| where isnotnull(session_token)
| stats values(src_ip) as source_ips, values(user_agent) as user_agents by session_token
| where mvcount(source_ips) > 1 OR mvcount(user_agents) > 1
```

---

## 14. Comprehensive Attack Detection Dashboard

### 14.1 Enhanced Splunk Dashboard Configuration

#### Multi-Attack Detection Dashboard XML:

```xml
<dashboard>
  <label>Advanced Red Team Attack Detection</label>
  <row>
    <panel>
      <title>Network Reconnaissance</title>
      <chart>
        <search>
          <query>
            index=network (arp OR icmp_type=8 OR tcp_flags="S")
            | timechart span=1m count by attack_type
          </query>
        </search>
      </chart>
    </panel>
    <panel>
      <title>Web Application Attacks</title>
      <table>
        <search>
          <query>
            index=web
            | rex field=uri_query "(?&lt;attack_indicators&gt;('|UNION|SELECT|&lt;script&gt;|javascript:|../|id=))"
            | where isnotnull(attack_indicators)
            | eval attack_type=case(
                match(attack_indicators, "('|UNION|SELECT)"), "SQL Injection",
                match(attack_indicators, "(&lt;script&gt;|javascript:)"), "XSS",
                match(attack_indicators, "(../|id=)"), "IDOR/Path Traversal",
                1=1, "Other"
              )
            | stats count by src_ip attack_type
            | sort -count
          </query>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Brute Force Attempts</title>
      <chart>
        <search>
          <query>
            index=web uri_path contains "login" method="POST"
            | bucket _time span=5m
            | stats count as attempts by _time src_ip
            | where attempts > 5
            | timechart span=5m sum(attempts) by src_ip
          </query>
        </search>
      </chart>
    </panel>
    <panel>
      <title>DDoS/Flood Attacks</title>
      <single>
        <search>
          <query>
            index=network tcp_flags="S"
            | bucket _time span=1s
            | stats count as syn_count by _time
            | where syn_count > 100
            | stats max(syn_count) as peak_syn_rate
          </query>
        </search>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <title>Session Hijacking Indicators</title>
      <table>
        <search>
          <query>
            index=web
            | rex field=cookie "(?&lt;session_token&gt;(PHPSESSID|JSESSIONID|sessionid)=[^;]+)"
            | where isnotnull(session_token)
            | stats dc(src_ip) as unique_ips, values(src_ip) as source_ips by session_token
            | where unique_ips > 1
            | sort -unique_ips
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

### 14.2 Advanced Alert Configuration

#### Alert A1: Multi-Vector Attack Detection

```spl
(index=web AND (match(uri_query, "('|UNION|SELECT|<script>|javascript:)") OR method="POST" AND uri_path contains "login"))
OR (index=network AND tcp_flags="S" AND dest_ip IN ("10.30.0.235", "10.30.0.236", "10.30.0.237"))
| stats count by src_ip attack_vector
| where count > 10
```

#### Alert A2: Advanced Persistent Threat (APT) Indicators

```spl
index=*
| eval apt_score=0
| eval apt_score=if(match(user_agent, "(?i)(sqlmap|nmap|burp)"), apt_score+2, apt_score)
| eval apt_score=if(match(uri_query, "('|UNION|SELECT)"), apt_score+3, apt_score)
| eval apt_score=if(dest_port IN (4444,1234,8080), apt_score+5, apt_score)
| eval apt_score=if(match(uri_query, "(<script>|javascript:)"), apt_score+2, apt_score)
| where apt_score >= 5
| stats sum(apt_score) as total_apt_score by src_ip
| sort -total_apt_score
```

---

## 15. Automated Multi-Attack Detection Script

### 15.1 Comprehensive Detection Script

```bash
#!/bin/bash
# Advanced Red Team Attack Detection Script
# Detects: SQL Injection, XSS, IDOR, Brute Force, SYN Flood, Session Hijacking

TARGETS="10.30.0.235 10.30.0.236 10.30.0.237"
INTERFACE="eth0"
LOGDIR="/var/log/multi_attack_detection"
PCAP_DIR="$LOGDIR/pcaps"

# Create directories
mkdir -p $LOGDIR $PCAP_DIR

# Function to detect SQL Injection
detect_sqli() {
    echo "[$(date)] Detecting SQL Injection attacks..."
    sudo tshark -i $INTERFACE -f "port 80 or port 443 or port 3000" -Y "http" -c 1000 \
    -T fields -e frame.time -e ip.src -e http.request.uri | \
    grep -E "('|UNION|SELECT|--|;)" > $LOGDIR/sqli_$(date +%Y%m%d_%H%M%S).log &
}

# Function to detect XSS
detect_xss() {
    echo "[$(date)] Detecting XSS attacks..."
    sudo tshark -i $INTERFACE -f "port 80 or port 443 or port 3000" -Y "http" -c 1000 \
    -T fields -e frame.time -e ip.src -e http.request.uri | \
    grep -E "(<script>|javascript:|onerror|onload|alert\()" > $LOGDIR/xss_$(date +%Y%m%d_%H%M%S).log &
}

# Function to detect IDOR
detect_idor() {
    echo "[$(date)] Detecting IDOR attacks..."
    sudo tshark -i $INTERFACE -f "port 80 or port 443 or port 3000" -Y "http" -c 1000 \
    -T fields -e frame.time -e ip.src -e http.request.uri | \
    grep -E "(id=|user=|file=|../)" > $LOGDIR/idor_$(date +%Y%m%d_%H%M%S).log &
}

# Function to detect brute force
detect_brute_force() {
    echo "[$(date)] Detecting brute force attacks..."
    sudo tshark -i $INTERFACE -f "port 22 or port 80 or port 443" -c 2000 \
    -T fields -e frame.time -e ip.src -e tcp.dstport | \
    awk '{count[$2":"$3]++} END {for (combo in count) if (count[combo] > 20) print "ALERT: Brute force from " combo " (" count[combo] " attempts)"}' \
    > $LOGDIR/bruteforce_$(date +%Y%m%d_%H%M%S).log &
}

# Function to detect SYN flood
detect_syn_flood() {
    echo "[$(date)] Detecting SYN flood attacks..."
    sudo tshark -i $INTERFACE -f "tcp[tcpflags] & tcp-syn != 0" -c 5000 \
    -T fields -e frame.time -e ip.src -e ip.dst | \
    awk '{count[$3]++} END {for (dst in count) if (count[dst] > 100) print "ALERT: SYN flood to " dst " (" count[dst] " packets)"}' \
    > $LOGDIR/synflood_$(date +%Y%m%d_%H%M%S).log &
}

# Function to detect session hijacking
detect_session_hijacking() {
    echo "[$(date)] Detecting session hijacking..."
    sudo tshark -i $INTERFACE -f "port 80 or port 443" -Y "http.cookie" -c 1000 \
    -T fields -e frame.time -e ip.src -e http.cookie | \
    grep -E "(PHPSESSID|JSESSIONID|sessionid)" > $LOGDIR/sessions_$(date +%Y%m%d_%H%M%S).log &
}

# Function to capture evidence
capture_evidence() {
    echo "[$(date)] Capturing evidence packets..."
    sudo tshark -i $INTERFACE -f "host $TARGETS" -w $PCAP_DIR/evidence_$(date +%Y%m%d_%H%M%S).pcap -c 10000 &
}

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

# Wait for all background processes
wait

echo "[$(date)] Detection cycle complete. Check logs in $LOGDIR"

# Generate summary report
echo "[$(date)] Generating detection summary..."
{
    echo "=== MULTI-ATTACK DETECTION SUMMARY ==="
    echo "Scan completed: $(date)"
    echo ""
    echo "SQL Injection alerts:"
    find $LOGDIR -name "sqli_*.log" -exec wc -l {} \; | awk '{sum+=$1} END {print "Total: " sum " potential incidents"}'
    echo ""
    echo "XSS alerts:"
    find $LOGDIR -name "xss_*.log" -exec wc -l {} \; | awk '{sum+=$1} END {print "Total: " sum " potential incidents"}'
    echo ""
    echo "IDOR alerts:"
    find $LOGDIR -name "idor_*.log" -exec wc -l {} \; | awk '{sum+=$1} END {print "Total: " sum " potential incidents"}'
    echo ""
    echo "Brute Force alerts:"
    find $LOGDIR -name "bruteforce_*.log" -exec cat {} \; | grep "ALERT"
    echo ""
    echo "SYN Flood alerts:"
    find $LOGDIR -name "synflood_*.log" -exec cat {} \; | grep "ALERT"
    echo ""
    echo "Session data captured:"
    find $LOGDIR -name "sessions_*.log" -exec wc -l {} \; | awk '{sum+=$1} END {print "Total: " sum " session records"}'
} > $LOGDIR/summary_$(date +%Y%m%d_%H%M%S).txt

echo "Summary report generated: $LOGDIR/summary_$(date +%Y%m%d_%H%M%S).txt"
```

This enhanced incident response plan now provides comprehensive detection capabilities for all major attack vectors with detailed explanations of what each filter/query detects and how to identify specific attack patterns.
