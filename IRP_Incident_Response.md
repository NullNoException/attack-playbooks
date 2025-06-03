# Incident Response Plan: Response, Evidence, and Recovery

## 1. Incident Response Procedures

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
