James Shin 1 day ago
Forwarding Splunk

1. Enable Remote Logging on pfSense:

http://192.168.0.1/status_logs_settings.php

Remote Logging Options> Remote Log Servers > <SPLUNK_SERVER_IP>:9997

2. Splunk Forwarder (pfSense):

# look for <INTERFACE> on suricata\_<INTERFACE>

ls /var/log/suricata

/opt/splunkforwarder/etc/system/local/inputs.conf

# <INTERFACE> from suricata above

[monitor:///var/log/suricata/suricata_<INTERFACE>/eve.json]
sourcetype = suricata
disabled = 0

/opt/splunkforwarder/etc/system/local/outputs.conf

[tcpout]
defaultGroup=my_indexers

[tcpout:my_indexers]
server=<SPLUNK_SERVER>\_IP>:9997

Restart Splunk Forwarder:

/opt/splunkforwarder/bin/splunk restart

3. Splunk Server:

/opt/splunk/etc/system/local/inputs.conf

[splunktcp://<SPLUNK_SERVER_IP>:9997]
disabled = 0
sourcetype = suricata
connection_host = none
compressed = true

Restart Splunk Server:

/opt/splunk/bin/splunk restart

---

KALI Key Issue

```bash
# Kali Linux SSH Key Issue
sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
```

---

### listening on pfsens port for wireshark

Install sshpass:
Bash
sudo apt install sshpass

Capture packets from Firewall's DMZ interface and view it on Wireshark on Blue Team's machine:
Bash

# example:

# sshpass -p <PASSWORD> ssh admin@<FIREWALL_IP> -p <PORT> "tcpdump -ni <DMZ_INTERFACE> -U -w -" | wireshark -k -i -

#

# <FIREWALL_IP> = Blue Team's Firewall Interface IP

# <DMZ_INTERFACE> = Firewall's DMZ Interface

#

sshpass -p labadmin ssh admin@192.168.0.1 -p 22 "tcpdump -ni em3 -U -w -" | wireshark -k -i -

---
