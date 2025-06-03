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

```python
import subprocess

def run_cmd(cmd, cwd=None):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result

def ssh_and_run(host, user, password, commands):
    """
    SSH to host and run a list of shell commands using sshpass.
    """
    for cmd in commands:
        ssh_cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{host} \"{cmd}\""
        )
        run_cmd(ssh_cmd)

def configure_pfsense_remote_logging(splunk_server_ip):
    print("Manual step: Go to pfSense web UI at http://192.168.0.1/status_logs_settings.php and set Remote Log Servers to {}:9997".format(splunk_server_ip))

def configure_splunk_forwarder_on_pfsense(interface, splunk_server_ip, pfsense_user, pfsense_pass):
    # pfSense IP is always 192.168.0.1
    pfsense_ip = "192.168.0.1"
    inputs_conf = f"""
[monitor:///var/log/suricata/suricata_{interface}/eve.json]
sourcetype = suricata
disabled = 0
"""
    outputs_conf = f"""
[tcpout]
defaultGroup=my_indexers

[tcpout:my_indexers]
server={splunk_server_ip}:9997
"""
    cmds = [
        f"echo '{inputs_conf}' > /opt/splunkforwarder/etc/system/local/inputs.conf",
        f"echo '{outputs_conf}' > /opt/splunkforwarder/etc/system/local/outputs.conf",
        "/opt/splunkforwarder/bin/splunk restart"
    ]
    ssh_and_run(pfsense_ip, pfsense_user, pfsense_pass, cmds)

def configure_splunk_server(splunk_server_ip, splunk_user, splunk_pass):
    inputs_conf = f"""
[splunktcp://{splunk_server_ip}:9997]
disabled = 0
sourcetype = suricata
connection_host = none
compressed = true
"""
    cmds = [
        f"echo '{inputs_conf}' > /opt/splunk/etc/system/local/inputs.conf",
        "/opt/splunk/bin/splunk restart"
    ]
    ssh_and_run(splunk_server_ip, splunk_user, splunk_pass, cmds)

if __name__ == "__main__":
    # 1. Configure pfSense remote logging (manual)
    configure_pfsense_remote_logging("<SPLUNK_SERVER_IP>")

    # 2. SSH to pfSense (192.168.0.1) and configure Splunk Forwarder
    # configure_splunk_forwarder_on_pfsense("<INTERFACE>", "<SPLUNK_SERVER_IP>", "<PFSENSE_USER>", "<PFSENSE_PASS>")

    # 3. SSH to Splunk Server and configure inputs.conf
    # configure_splunk_server("<SPLUNK_SERVER_IP>", "<SPLUNK_USER>", "<SPLUNK_PASS>")
```
