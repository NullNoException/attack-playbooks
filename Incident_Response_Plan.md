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

## 2. Detection of PHP Reverse Shell Attack

### 2.1 Wireshark Detection Procedures

#### Step 1: Configure Wireshark Capture

```bash
# Start Wireshark on monitoring node (10.30.0.236)
sudo wireshark
```

**Instructions:**

1. Open Wireshark on the monitoring system
2. Select network interface connected to target network
3. Start packet capture before red team attack begins
4. Apply initial filter: `host 10.30.0.235`

#### Step 2: Detect Reconnaissance Phase

**Filter for netdiscover activity:**

```
arp
```

**Detection Indicators:**

- Multiple ARP requests in short timeframe
- ARP requests for sequential IP addresses
- Source MAC address making excessive ARP queries

**Analysis Steps:**

1. Monitor Statistics → Protocol Hierarchy
2. Look for unusual ARP traffic spikes
3. Examine ARP request patterns in packet list
4. Note source MAC addresses performing reconnaissance

#### Step 3: Detect Port Scanning (Nmap)

**Filter for port scanning:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and host 10.30.0.235
```

**Detection Indicators:**

- Rapid TCP SYN packets to multiple ports
- Sequential port scanning patterns
- RST responses from closed ports
- Stealth scan characteristics (SYN-only packets)

**Analysis Steps:**

1. Apply port scan filter
2. Check packet timing (rapid succession)
3. Examine destination ports being scanned
4. Note scan techniques (TCP Connect vs SYN scan)

#### Step 4: Detect HTTP File Upload

**Filter for HTTP upload activity:**

```
http.request.method == "POST" and host 10.30.0.235
```

**Detection Indicators:**

- POST requests to upload directories
- Content-Type: multipart/form-data
- Large payload sizes
- PHP file extensions in uploads

**Analysis Steps:**

1. Filter for HTTP POST traffic
2. Right-click packet → Follow → HTTP Stream
3. Examine uploaded file content
4. Look for PHP reverse shell signatures:
   - `exec()`, `shell_exec()`, `system()` functions
   - Socket connections (`fsockopen`)
   - `/bin/sh` or `/bin/bash` references

#### Step 5: Detect Reverse Shell Connection

**Filter for reverse shell traffic:**

```
tcp.port == 4444 and host 10.30.0.235
```

**Detection Indicators:**

- Outbound TCP connection from web server
- Connection to unusual high ports (4444, 1234, etc.)
- Shell command traffic in TCP streams
- Base64 encoded commands

**Analysis Steps:**

1. Apply reverse shell port filter
2. Follow TCP stream of suspicious connections
3. Look for shell prompt indicators (`$`, `#`)
4. Examine command execution patterns

### 2.2 Tshark Detection Commands

#### Command 1: Capture and Filter ARP Reconnaissance

```bash
# Run on monitoring node (10.30.0.236)
sudo tshark -i eth0 -f "arp" -T fields -e frame.time -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4
```

#### Command 2: Detect Port Scanning

```bash
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e tcp.dstport
```

#### Command 3: Monitor HTTP Upload Activity

```bash
sudo tshark -i eth0 -f "host 10.30.0.235 and port 80" -Y "http.request.method == POST" -V
```

#### Command 4: Capture Reverse Shell Traffic

```bash
sudo tshark -i eth0 -f "host 10.30.0.235 and port 4444" -w reverse_shell_capture.pcap
```

#### Command 5: Analyze Shell Commands

```bash
sudo tshark -r reverse_shell_capture.pcap -Y "tcp.port == 4444" -T fields -e tcp.payload | xxd -r -p
```

### 2.3 Splunk Detection Queries

#### Query 1: Detect ARP Reconnaissance

```spl
index=network sourcetype=tcpdump arp
| stats count by src_mac
| where count > 50
| sort -count
```

#### Query 2: Identify Port Scanning

```spl
index=network dest_ip="10.30.0.235" tcp_flags="S"
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 100
```

#### Query 3: HTTP File Upload Detection

```spl
index=web host="10.30.0.235" method="POST" uri_path="*upload*"
| rex field=form_data "filename=\"(?<filename>[^\"]+)\""
| where match(filename, "\.php$")
```

#### Query 4: Reverse Shell Connection Detection

```spl
index=network dest_port=4444 src_ip="10.30.0.235"
| transaction src_ip dest_ip dest_port
| where duration > 60
```

---

## 3. Detection of Nmap Information Gathering Attack

### 3.1 Wireshark Detection Procedures

#### Step 1: Basic Nmap Scan Detection

**Filter for comprehensive scanning:**

```
host 10.30.0.235 and (tcp.flags.syn == 1 or icmp)
```

**Detection Indicators:**

- ICMP echo requests (ping sweep)
- TCP SYN packets to multiple ports
- UDP packets to common service ports
- Rapid packet succession patterns

#### Step 2: OS Fingerprinting Detection

**Filter for OS detection attempts:**

```
tcp.window_size_value == 1024 or tcp.options.mss_val < 536 or tcp.urgptr != 0
```

**Detection Indicators:**

- Unusual TCP window sizes
- Specific TCP options combinations
- Crafted packet characteristics
- ICMP timestamp requests

#### Step 3: Service Version Detection

**Filter for version scanning:**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and host 10.30.0.235
```

**Follow-up Analysis:**

1. Examine three-way handshake completion rates
2. Look for immediate connection termination after establishment
3. Check for service banner grabbing attempts

#### Step 4: Script Scanning Detection

**Filter for NSE script activity:**

```
host 10.30.0.235 and (smb or ssh or http or ftp)
```

**Detection Indicators:**

- SMB enumeration packets
- SSH version negotiation attempts
- HTTP OPTIONS/HEAD requests
- FTP banner grabbing

### 3.2 Tshark Detection Commands

#### Command 1: Monitor Ping Sweep

```bash
sudo tshark -i eth0 -f "icmp" -Y "icmp.type == 8" -T fields -e frame.time -e ip.src -e ip.dst
```

#### Command 2: Detect TCP Port Scanning

```bash
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e frame.time -e ip.src -e tcp.dstport | sort | uniq -c
```

#### Command 3: Identify OS Fingerprinting

```bash
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.window_size_value == 1024 or icmp.type == 13" -V
```

#### Command 4: Monitor Service Version Detection

```bash
sudo tshark -i eth0 -f "host 10.30.0.235" -Y "tcp.flags.syn == 1" -T fields -e ip.src -e tcp.dstport -e tcp.seq | head -100
```

#### Command 5: Capture Script Scanning Activity

```bash
sudo tshark -i eth0 -f "host 10.30.0.235 and (port 139 or port 445 or port 22)" -w nmap_scripts.pcap
```

### 3.3 Splunk Detection Queries

#### Query 1: Ping Sweep Detection

```spl
index=network icmp_type=8
| stats dc(dest_ip) as unique_targets by src_ip
| where unique_targets > 10
| sort -unique_targets
```

#### Query 2: Port Scan Identification

```spl
index=network dest_ip="10.30.0.235" tcp_flags="S"
| bucket _time span=1m
| stats dc(dest_port) as ports_per_minute by _time src_ip
| where ports_per_minute > 50
```

#### Query 3: OS Fingerprinting Detection

```spl
index=network dest_ip="10.30.0.235"
| where tcp_window_size=1024 OR tcp_window_size=512 OR tcp_window_size=2048
| stats count by src_ip tcp_window_size
```

#### Query 4: Service Enumeration Detection

```spl
index=network dest_ip="10.30.0.235" (dest_port=139 OR dest_port=445 OR dest_port=22 OR dest_port=21)
| stats count by src_ip dest_port
| where count > 5
```

---

## 4. Detection of SQL Injection Attack (OWASP Juice Shop)

### 4.1 Wireshark Detection Procedures

#### Step 1: HTTP Traffic Analysis

**Filter for Juice Shop HTTP traffic:**

```
host 10.30.0.237 and http
```

**Detection Indicators:**

- POST requests to `/rest/user/login`
- GET requests to `/rest/products/search`
- Unusual HTTP request parameters
- Error responses (500, 400 status codes)

#### Step 2: SQL Injection Payload Detection

**Filter for suspicious HTTP requests:**

```
http contains "'" or http contains "UNION" or http contains "SELECT" or http contains "--"
```

**Detection Indicators:**

- SQL keywords in HTTP parameters
- Single quotes and SQL comments (`--`, `/*`)
- UNION SELECT statements
- Database function names

#### Step 3: SQLMap Detection

**Filter for automated tool signatures:**

```
http.user_agent contains "sqlmap" or http contains "testpayload"
```

**Detection Indicators:**

- SQLMap user agent strings
- Automated testing patterns
- Rapid successive requests
- Error-based injection attempts

#### Step 4: Authentication Bypass Detection

**Filter for login attempts:**

```
http.request.uri contains "/rest/user/login" and http.request.method == "POST"
```

**Analysis Steps:**

1. Right-click → Follow HTTP Stream
2. Examine login request payloads
3. Look for SQL injection patterns in email field
4. Check response for authentication tokens

### 4.2 Tshark Detection Commands

#### Command 1: Monitor SQL Injection Attempts

```bash
sudo tshark -i eth0 -f "host 10.30.0.237 and port 3000" -Y "http" -T fields -e frame.time -e http.request.uri -e http.request.method | grep -E "(SELECT|UNION|'|--)"
```

#### Command 2: Capture Login Bypass Attempts

```bash
sudo tshark -i eth0 -f "host 10.30.0.237 and port 3000" -Y "http.request.uri contains \"/rest/user/login\"" -V
```

#### Command 3: Detect SQLMap Activity

```bash
sudo tshark -i eth0 -f "host 10.30.0.237" -Y "http.user_agent contains \"sqlmap\"" -T fields -e frame.time -e ip.src -e http.user_agent
```

#### Command 4: Monitor Database Queries

```bash
sudo tshark -i eth0 -f "host 10.30.0.237" -Y "http contains \"sqlite_master\" or http contains \"information_schema\"" -w sqli_detection.pcap
```

#### Command 5: Extract HTTP Payloads

```bash
sudo tshark -r sqli_detection.pcap -Y "http.request.method == POST" -T fields -e http.file_data | xxd -r -p
```

### 4.3 Splunk Detection Queries

#### Query 1: SQL Injection Pattern Detection

```spl
index=web host="10.30.0.237"
| rex field=uri_query "(?<sqli_indicators>('|\"|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|\*|;))"
| where isnotnull(sqli_indicators)
| stats count by src_ip sqli_indicators
```

#### Query 2: Authentication Bypass Detection

```spl
index=web host="10.30.0.237" uri_path="/rest/user/login" method="POST"
| rex field=form_data "email=(?<email_input>[^&]+)"
| where match(email_input, "('|--|UNION|SELECT)")
| stats count by src_ip email_input
```

#### Query 3: SQLMap Tool Detection

```spl
index=web host="10.30.0.237"
| where match(useragent, "(?i)sqlmap") OR match(uri_query, "testpayload")
| stats count by src_ip useragent
```

#### Query 4: Database Enumeration Detection

```spl
index=web host="10.30.0.237"
| where match(uri_query, "(?i)(sqlite_master|information_schema|sys\.tables|SHOW\s+TABLES)")
| stats count by src_ip uri_path uri_query
```

#### Query 5: Error-Based SQL Injection

```spl
index=web host="10.30.0.237" status>=400
| where match(response_body, "(?i)(sql|database|syntax|mysql|sqlite|oracle)")
| stats count by src_ip status response_body
```

---

## 5. Comprehensive Detection Dashboard

### 5.1 Splunk Dashboard Configuration

#### Dashboard XML Configuration:

```xml
<dashboard>
  <label>Red Team Attack Detection</label>
  <row>
    <panel>
      <title>Network Reconnaissance</title>
      <single>
        <search>
          <query>
            index=network arp | stats dc(dest_ip) as targets_scanned by src_mac | sort -targets_scanned | head 1
          </query>
        </search>
      </single>
    </panel>
    <panel>
      <title>Port Scanning Activity</title>
      <chart>
        <search>
          <query>
            index=network tcp_flags="S" dest_ip IN (10.30.0.235, 10.30.0.236, 10.30.0.237)
            | timechart span=1m count by dest_ip
          </query>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>SQL Injection Attempts</title>
      <table>
        <search>
          <query>
            index=web (host="10.30.0.237" OR host="10.30.0.235")
            | rex field=uri_query "(?<sqli_pattern>('|UNION|SELECT|--|;))"
            | where isnotnull(sqli_pattern)
            | stats count by src_ip uri_path sqli_pattern
            | sort -count
          </query>
        </search>
      </table>
    </panel>
    <panel>
      <title>Reverse Shell Connections</title>
      <chart>
        <search>
          <query>
            index=network dest_port IN (4444, 1234, 8080) src_ip IN (10.30.0.235, 10.30.0.236, 10.30.0.237)
            | timechart span=5m count by dest_port
          </query>
        </search>
      </chart>
    </panel>
  </row>
</dashboard>
```

### 5.2 Alert Configuration

#### Alert 1: Port Scanning Detection

```spl
index=network tcp_flags="S" dest_ip IN (10.30.0.235, 10.30.0.236, 10.30.0.237)
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 50
```

**Alert Conditions:**

- Trigger: When unique_ports > 50
- Time Window: 5 minutes
- Severity: Medium

#### Alert 2: SQL Injection Detection

```spl
index=web (host="10.30.0.237" OR host="10.30.0.235")
| where match(uri_query, "('|UNION|SELECT|--)")
| stats count by src_ip
| where count > 5
```

**Alert Conditions:**

- Trigger: When count > 5
- Time Window: 1 minute
- Severity: High

#### Alert 3: Reverse Shell Detection

```spl
index=network dest_port IN (4444, 1234, 8080) src_ip IN (10.30.0.235, 10.30.0.236, 10.30.0.237)
| stats count by src_ip dest_ip dest_port
| where count > 0
```

**Alert Conditions:**

- Trigger: Immediate
- Time Window: Real-time
- Severity: Critical

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
