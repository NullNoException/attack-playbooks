# Splunk Reference: Detecting Penetration Testing Attack Types

This reference provides step-by-step Splunk queries for identifying and classifying all major penetration testing (pentesting) attack types. Each section includes example queries and explanations.

---

## 1. Reconnaissance (Information Gathering)

### HTTP Method Enumeration (HEAD/OPTIONS)

```splunk
index=web_logs sourcetype=access_combined
| search method IN ("HEAD", "OPTIONS")
| stats count by src_ip, dest_ip, uri, http_user_agent
| where count > 10
| eval attack_type="Recon: HTTP Method Enumeration"
```

### Directory/Resource Brute Forcing

```splunk
index=web_logs sourcetype=access_combined
| search http.status=404
| stats count by src_ip, uri
| where count > 20
| eval attack_type="Recon: Directory Brute Force"
```

### User-Agent Reconnaissance Tools

```splunk
index=web_logs sourcetype=access_combined
| regex http_user_agent="(nmap|nikto|whatweb|wpscan|dirb|gobuster|sqlmap|masscan|curl|wget)"
| stats count by src_ip, http_user_agent
| eval attack_type="Recon: Automated Scanner Detected"
```

---

## 2. Scanning (Vulnerability/Port Scanning)

### Port Scanning (Multiple Ports)

```splunk
index=network_logs sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip, dest_ip
| where unique_ports > 10
| eval attack_type="Scanning: Port Scan"
```

### Service Enumeration (Database Ports)

```splunk
index=network_logs sourcetype=firewall
| search dest_port IN (3306, 5432, 1521, 1433, 27017)
| stats count dc(dest_port) as scanned_ports by src_ip
| where scanned_ports >= 3
| eval attack_type="Scanning: Database Service Enumeration"
```

---

## 3. Exploitation (Web, Network, Application)

### SQL Injection Attempts

```splunk
index=web_logs sourcetype=access_combined
| regex uri="(\?|&)id=|select.+from|union.+select|or.1=1|--|%27|%22"
| stats count by src_ip, uri
| where count > 5
| eval attack_type="Exploitation: SQL Injection Attempt"
```

### Cross-Site Scripting (XSS) Attempts

```splunk
index=web_logs sourcetype=access_combined
| regex uri="(<script>|%3Cscript%3E|onerror=|onload=|alert\(|document\.cookie)"
| stats count by src_ip, uri
| where count > 3
| eval attack_type="Exploitation: XSS Attempt"
```

### Command Injection Attempts

```splunk
index=web_logs sourcetype=access_combined
| regex uri="(;|&&|\|\||`|\$\()"
| stats count by src_ip, uri
| where count > 3
| eval attack_type="Exploitation: Command Injection Attempt"
```

### File Inclusion/Upload Attacks

```splunk
index=web_logs sourcetype=access_combined
| regex uri="(\.php\?file=|\.php\?page=|/etc/passwd|/proc/self/environ)"
| stats count by src_ip, uri
| where count > 2
| eval attack_type="Exploitation: File Inclusion/Upload"
```

---

## 4. Privilege Escalation

### Suspicious Privilege Changes (Linux/Unix)

```splunk
index=os_logs sourcetype=auth
| search (command="sudo" OR command="su")
| stats count by user, src_ip, command
| where count > 5
| eval attack_type="Privilege Escalation: Repeated Sudo/Su"
```

### Windows Privilege Escalation

```splunk
index=os_logs sourcetype=WinEventLog:Security
| search EventCode=4672
| stats count by user, src_ip
| where count > 2
| eval attack_type="Privilege Escalation: Special Privileges Assigned"
```

---

## 5. Lateral Movement

### Remote Desktop/SMB/WinRM Connections

```splunk
index=network_logs sourcetype=firewall
| search dest_port IN (3389, 445, 5985, 5986)
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| eval attack_type="Lateral Movement: RDP/SMB/WinRM"
```

### SSH Lateral Movement

```splunk
index=os_logs sourcetype=auth
| search command="ssh"
| stats count by user, src_ip, dest_ip
| where count > 3
| eval attack_type="Lateral Movement: SSH"
```

---

## 6. Persistence

### New Scheduled Tasks or Cron Jobs

```splunk
index=os_logs sourcetype=WinEventLog:Security
| search EventCode=4698
| stats count by user, src_ip, TaskName
| eval attack_type="Persistence: Scheduled Task Created"
```

```splunk
index=os_logs sourcetype=auth
| search command="crontab"
| stats count by user, src_ip
| eval attack_type="Persistence: Cron Job Created"
```

---

## 7. Exfiltration

### Large Data Transfers to External IPs

```splunk
index=network_logs sourcetype=firewall
| search direction="outbound"
| stats sum(bytes) as total_bytes by src_ip, dest_ip
| where total_bytes > 100000000  # >100MB
| eval attack_type="Exfiltration: Large Data Transfer"
```

### Suspicious File Downloads

```splunk
index=web_logs sourcetype=access_combined
| search uri IN ("*.zip", "*.tar", "*.gz", "*.7z", "*.db", "*.sql")
| stats count by src_ip, uri
| where count > 2
| eval attack_type="Exfiltration: Suspicious File Download"
```

---

## 8. Cleanup / Covering Tracks

### Log Deletion Attempts

```splunk
index=os_logs sourcetype=auth
| regex command="(rm\s+/var/log|del\s+C:\\Windows\\System32\\winevt\\Logs)"
| stats count by user, src_ip, command
| eval attack_type="Cleanup: Log Deletion Attempt"
```

### Clearing Windows Event Logs

```splunk
index=os_logs sourcetype=WinEventLog:Security
| search EventCode=1102
| stats count by user, src_ip
| eval attack_type="Cleanup: Windows Event Log Cleared"
```

---

## 9. Brute Force Attacks

### Web Login Brute Force

```splunk
index=web_logs sourcetype=access_combined
| search uri="/login" http.status=401
| stats count by src_ip
| where count > 10
| eval attack_type="Brute Force: Web Login"
```

### SSH Brute Force

```splunk
index=os_logs sourcetype=auth
| search command="ssh" http.status="failed"
| stats count by src_ip
| where count > 10
| eval attack_type="Brute Force: SSH Login"
```

---

## 10. Denial of Service (DoS/DDoS)

### High Rate of Requests

```splunk
index=web_logs sourcetype=access_combined
| stats count by src_ip
| where count > 1000
| eval attack_type="DoS: High Request Rate"
```

### SYN Flood Detection

```splunk
index=network_logs sourcetype=firewall
| search tcp_flags="SYN" direction="inbound"
| stats count by src_ip, dest_ip
| where count > 1000
| eval attack_type="DoS: SYN Flood"
```

---

## Notes

- Adjust thresholds and field names as needed for your environment.
- Use `eval attack_type` to tag and classify detected events.
- Combine queries for dashboards or correlation searches.

---

**This file is a living reference. Add new queries as new attack techniques emerge.**
