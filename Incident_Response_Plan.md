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

#### Preset 2: Juice Shop Target Monitoring (10.30.0.237)

```
host 10.30.0.237 and tcp.port == 3000
```

#### Preset 3: Network Reconnaissance Detection

```
(arp.opcode == 1) or (icmp.type == 8) or (tcp.flags.syn == 1 and tcp.flags.ack == 0)
```

#### Preset 4: Malicious Traffic Detection

```
tcp.port in {4444 1234 8080 9999} or http contains "shell" or http contains "cmd"
```

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
    grep -E "('|UNION|SELECT|--)" > $LOGDIR/sqli_$(date +%Y%m%d_%H%M%S).log
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
