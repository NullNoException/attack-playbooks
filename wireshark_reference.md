# Wireshark Reference: Detecting Penetration Testing Attack Types

This reference provides step-by-step Wireshark display filters and detection logic for identifying and classifying all major penetration testing (pentesting) attack types. Each section includes example filters and explanations.

---

## 1. Reconnaissance (Information Gathering)

### HTTP Method Enumeration (HEAD/OPTIONS)

```
http.request.method == "HEAD" or http.request.method == "OPTIONS"
```

### Directory/Resource Brute Forcing (404 Errors)

```
http.response.code == 404
```

### User-Agent Reconnaissance Tools

```
http.user_agent contains "nmap" or http.user_agent contains "nikto" or http.user_agent contains "whatweb" or http.user_agent contains "wpscan" or http.user_agent contains "dirb" or http.user_agent contains "gobuster" or http.user_agent contains "sqlmap" or http.user_agent contains "masscan" or http.user_agent contains "curl" or http.user_agent contains "wget"
```

---

## 2. Scanning (Vulnerability/Port Scanning)

### Port Scanning (Multiple Ports)

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Service Enumeration (Database Ports)

```
tcp.port == 3306 or tcp.port == 5432 or tcp.port == 1521 or tcp.port == 1433 or tcp.port == 27017
```

---

## 3. Exploitation (Web, Network, Application)

### SQL Injection Attempts (Common Patterns)

```
http.request.uri contains "' or 1=1" or http.request.uri contains "union select" or http.request.uri contains "--" or http.request.uri contains "%27" or http.request.uri contains "%22"
```

### Cross-Site Scripting (XSS) Attempts

```
http.request.uri contains "<script>" or http.request.uri contains "%3Cscript%3E" or http.request.uri contains "onerror=" or http.request.uri contains "onload=" or http.request.uri contains "alert(" or http.request.uri contains "document.cookie"
```

### Command Injection Attempts

```
http.request.uri contains ";" or http.request.uri contains "&&" or http.request.uri contains "||" or http.request.uri contains "`" or http.request.uri contains "$()"
```

### File Inclusion/Upload Attacks

```
http.request.uri contains ".php?file=" or http.request.uri contains ".php?page=" or http.request.uri contains "/etc/passwd" or http.request.uri contains "/proc/self/environ"
```

---

## 4. Privilege Escalation

_Not directly visible in network traffic unless privilege escalation is performed over the network (e.g., via RDP, SSH, SMB). See Lateral Movement below._

---

## 5. Lateral Movement

### Remote Desktop/SMB/WinRM Connections

```
tcp.port == 3389 or tcp.port == 445 or tcp.port == 5985 or tcp.port == 5986
```

### SSH Lateral Movement

```
tcp.port == 22
```

---

## 6. Persistence

_Persistence is rarely directly visible in network traffic, but repeated connections to management ports (e.g., RDP, SSH) may indicate persistence mechanisms._

---

## 7. Exfiltration

### Large Data Transfers to External IPs

- Sort by highest values in the column `tcp.len` or `frame.len` for outbound connections.
- Filter for large file types:

```
http.request.uri contains ".zip" or http.request.uri contains ".tar" or http.request.uri contains ".gz" or http.request.uri contains ".7z" or http.request.uri contains ".db" or http.request.uri contains ".sql"
```

---

## 8. Cleanup / Covering Tracks

_Log deletion is not directly visible in network traffic unless performed over a remote shell (e.g., SSH, RDP). Monitor for suspicious command execution over these protocols._

---

## 9. Brute Force Attacks

### Web Login Brute Force

```
http.request.uri contains "/login" and http.response.code == 401
```

### SSH Brute Force

```
tcp.port == 22 and (tcp.len > 0)
```

- Look for repeated failed authentication attempts in SSH streams.

---

## 10. Denial of Service (DoS/DDoS)

### High Rate of Requests

- Use Wireshark's "Statistics > Conversations" to identify IPs with high request rates.

### SYN Flood Detection

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

- Look for a high volume of SYN packets without corresponding ACKs.

---

## General Tips

- Use Wireshark's "Follow TCP Stream" to analyze suspicious sessions.
- Use "Statistics > Endpoints" and "Statistics > Protocol Hierarchy" for traffic overview.
- Combine filters for more specific detection (e.g., combine method and port filters).

---

**This file is a living reference. Add new filters as new attack techniques emerge.**
