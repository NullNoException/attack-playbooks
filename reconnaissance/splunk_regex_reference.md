# Splunk Regex Reference & Useful Stats

This file provides a list of common regex patterns for Splunk, useful stats commands, and a short tutorial on using regex in Splunk searches.

---

## 1. Splunk Regex Patterns

1. **SQL Injection Detection**

   - Regex: `(?:\?|&)id=\d*['"]{0,1}[=\s]+or`
   - Description: Common SQLi payloads

2. **XSS Detection**

   - Regex: `(?:<script|javascript:|onload=|onerror=)`
   - Description: XSS payloads

3. **Command Injection**

   - Regex: `(?:;|\||&&|\$\(|\`)`
   - Description: Command injection metacharacters

4. **File Inclusion**

   - Regex: `(?:\.\.\/|\/etc\/passwd|file=)`
   - Description: LFI/RFI attempts

5. **Directory Brute Force**

   - Regex: `(?:\/admin|\/backup|\/config|\/.git)`
   - Description: Common brute-forced directories

6. **User-Agent Recon Tools**

   - Regex: `(?:nmap|nikto|gobuster|sqlmap|burp|zap)`
   - Description: Reconnaissance tool user-agents

7. **Web Login Paths**

   - Regex: `(?:\/login|\/signin|\/auth)`
   - Description: Login endpoints

8. **File Download Extensions**

   - Regex: `\.(?:zip|tar|gz|7z|db|sql)$`
   - Description: Suspicious file downloads

9. **Windows Event Log Deletion**

   - Regex: `del\s+C:\\Windows\\System32\\winevt\\Logs`
   - Description: Log deletion on Windows

10. **Linux Log Deletion**
    - Regex: `rm\s+(?:-rf\s+)?\/var\/log`
    - Description: Log deletion on Linux

---

## 2. Useful Splunk Stats Commands

| Command Example                                    | Description                            |
| -------------------------------------------------- | -------------------------------------- |
| stats count by src_ip                              | Count events per source IP             |
| stats dc(dest_port) as unique_ports by src_ip      | Count unique destination ports per IP  |
| stats sum(bytes) as total_bytes by src_ip, dest_ip | Total bytes transferred per connection |
| stats count by user, src_ip, command               | Count commands per user and IP         |
| stats count dc(uri) as unique_uris by src_ip       | Unique URIs accessed per IP            |
| stats count by src_ip, uri                         | Count of requests per IP and URI       |
| stats count by user_agent                          | Count by user agent string             |
| stats count by status                              | Count by HTTP status code              |

---

## 3. Short Tutorial: Using Regex in Splunk

### What is Regex in Splunk?

Regex (regular expressions) in Splunk allow you to search for patterns in your data, extract fields, and filter events based on complex criteria.

### Basic Usage

- Use the `regex` command to filter events:
  ```splunk
  ... | regex field="pattern"
  ```
- Use the `rex` command to extract fields:
  ```splunk
  ... | rex field=uri "(?<id>id=\\d+)"
  ```

### Example: Find SQL Injection Attempts

```splunk
index=web_logs sourcetype=access_combined
| regex uri="(\?|&)id=|select.+from|union.+select|or.1=1|--|%27|%22"
```

### Example: Extract Username from Log

```splunk
... | rex "user=(?<username>\\w+)"
```

### Tips

- Use parentheses `()` to group patterns.
- Use `?<>` in `rex` to name extracted fields.
- Use `| regex` to filter, `| rex` to extract.
- Test your regex with Splunk's interactive field extractor or online tools.

---

**Keep this file handy for quick reference when building Splunk searches!**
