# Incident Response Plan: Wireshark Detection Playbook

## 1. Wireshark Setup and Configuration Guide

### 1.5 Initial Wireshark Configuration

- Launch Wireshark as root/administrator.
- Go to **Capture → Interfaces** and select the interface connected to the monitored network segment.
- Enable **Promiscuous Mode** in Capture Options.
- Set a ring buffer (e.g., 100MB, 10 files) for continuous capture.

#### Basic Display Filter Syntax

- AND: `filter1 and filter2`
- OR: `filter1 or filter2`
- NOT: `not filter1`
- Parentheses: `(filter1 or filter2) and filter3`
- Field comparison: `tcp.port == 80`
- Range: `tcp.port in {80 443 8080}`

#### Time-Based Filtering

- Relative: `frame.time_relative >= 10`
- Absolute: `frame.time >= "2024-01-15 10:00:00"`
- Delta: `tcp.time_delta > 1.0`

### 1.5.2 Target-Specific Filter Presets

- **DVWA Target:**  
  `host 10.30.0.235 and (tcp or icmp or arp)`
- **Juice Shop Target:**  
  `host 10.30.0.237 and tcp.port == 3000`
- **Reconnaissance:**  
  `(arp.opcode == 1) or (icmp.type == 8) or (tcp.flags.syn == 1 and tcp.flags.ack == 0)`
- **Malicious Traffic:**  
  `tcp.port in {4444 1234 8080 9999} or http contains "shell" or http contains "cmd"`

## 2. Wireshark Detection Procedures

### Attack Detection Matrix (Wireshark)

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

### Detection Filters and Analysis Steps

#### PHP Reverse Shell

- **Reconnaissance:**  
  `arp`  
  Look for excessive ARP requests, sequential IPs, and top MACs.
- **Port Scanning:**  
  `tcp.flags.syn == 1 and tcp.flags.ack == 0 and host 10.30.0.235`  
  Check for rapid SYNs, sequential ports, and RSTs.
- **HTTP File Upload:**  
  `http.request.method == "POST" and host 10.30.0.235`  
  Look for POSTs with `multipart/form-data`, large payloads, and `.php` files.
- **Reverse Shell:**  
  `tcp.port == 4444 and host 10.30.0.235`  
  Outbound connections, shell prompts, and command patterns.

#### Nmap Information Gathering

- **Ping Sweep:**  
  `icmp.type == 8 and ip.dst_host == 10.30.0.235`
- **TCP SYN Scan:**  
  `tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 10.30.0.235`
- **OS Fingerprinting:**  
  `tcp.window_size_value == 1024 and ip.dst == 10.30.0.235`
- **Service Enumeration:**  
  `tcp.flags.push == 1 and tcp.len > 0 and ip.dst == 10.30.0.235`

#### SQL Injection (Juice Shop)

- **HTTP Traffic:**  
  `host 10.30.0.237 and http`
- **SQLi Payloads:**  
  `http contains "'" or http contains "UNION" or http contains "SELECT" or http contains "--"`
- **SQLMap:**  
  `http.user_agent contains "sqlmap"`

#### XSS

- **Basic:**  
  `http contains "<script>" or http contains "javascript:" or http contains "onerror"`
- **Encoded:**  
  `http contains "%3Cscript%3E" or http contains "%3C" or http contains "&#"`
- **Event Handler:**  
  `http contains "onload" or http contains "onclick" or http contains "onmouseover"`

#### IDOR

- **ID Parameter:**  
  `http.request.uri contains "id=" or http.request.uri contains "user=" or http.request.uri contains "file="`
- **Directory Traversal:**  
  `http.request.uri contains "../" or http.request.uri contains "..%2F"`

#### Phishing

- **Suspicious Domain:**  
  `dns or http.host contains "security" or http.host contains "verify" or http.host contains "update"`
- **Credential Harvesting:**  
  `http.request.method == "POST" and (http contains "password" or http contains "username" or http contains "login")`

#### SYN Flood

- **SYN Flood:**  
  `tcp.flags.syn == 1 and tcp.flags.ack == 0`
- **Incomplete Handshakes:**  
  `tcp.flags.syn == 1 and tcp.flags.ack == 0 and not tcp.flags.reset == 1`

#### Brute Force

- **Login Attempts:**  
  `http.request.uri contains "login" and http.request.method == "POST"`
- **SSH:**  
  `tcp.port == 22 and tcp.flags.syn == 1`

#### Session Hijacking

- **Cookie Theft:**  
  `http.cookie or http.set_cookie`
- **Session Fixation:**  
  `http contains "JSESSIONID" or http contains "PHPSESSID" or http contains "ASP.NET_SessionId"`

## 3. Advanced Wireshark Analysis Techniques

### Coloring Rules

- **Port Scanning:**  
  `tcp.flags.syn == 1 and tcp.flags.ack == 0`
- **SQL Injection:**  
  `http contains "'" or http contains "UNION" or http contains "SELECT"`
- **Reverse Shell:**  
  `tcp.port in {4444 1234 8080 9999}`
- **ARP Scanning:**  
  `arp.opcode == 1`

### Expert Information

- Go to **Analyze → Expert Information**
- Focus on Warnings/Errors: TCP Retransmissions, RSTs, HTTP Errors

### Statistical Analysis

- **Protocol Hierarchy:**  
  Analyze unusual protocol distributions.
- **Conversations/Endpoints:**  
  Identify top talkers and suspicious patterns.
- **I/O Graphs:**  
  Visualize attack timing and intensity.

### Export and Reporting

- Export packet dissections as CSV.
- Export HTTP objects.
- Save filtered packets.
- Generate reports: Statistics → Summary, Resolved Addresses.
