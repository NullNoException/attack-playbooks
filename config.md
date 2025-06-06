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
    This function should be run from your management/admin machine,
    NOT from pfSense or Splunk themselves.
    """
    for cmd in commands:
        # Use -t to allocate a pseudo-terminal which allows password prompts for sudo
        ssh_cmd = (
            f"sshpass -p '{password}' ssh -t -o StrictHostKeyChecking=no {user}@{host} \"{cmd}\""
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
        f"echo '{inputs_conf}' | tee /opt/splunkforwarder/etc/system/local/inputs.conf > /dev/null",
        f"echo '{outputs_conf}' | tee /opt/splunkforwarder/etc/system/local/outputs.conf > /dev/null",
        "/opt/splunkforwarder/bin/splunk restart"
    ]
    # This SSH command is run from your admin/management machine to pfSense
    ssh_and_run(pfsense_ip, pfsense_user, pfsense_pass, cmds)

def configure_splunk_server(splunk_server_ip, splunk_user, splunk_pass):
    inputs_conf = f"""
[splunktcp://{splunk_server_ip}:9997]
disabled = 0
sourcetype = suricata
connection_host = none
compressed = true
"""
    # These commands avoid using sudo directly
    cmds = [
        f"echo '{inputs_conf}' > /tmp/inputs.conf",
        f"echo '{splunk_pass}' | sudo -S cp /tmp/inputs.conf /opt/splunk/etc/system/local/inputs.conf",
        f"echo '{splunk_pass}' | sudo -S /opt/splunk/bin/splunk restart",
        "rm /tmp/inputs.conf"
    ]
    # This SSH command is run from your admin/management machine to Splunk server
    ssh_and_run(splunk_server_ip, splunk_user, splunk_pass, cmds)

def get_suricata_interface(pfsense_user, pfsense_pass):
    """
    SSH to pfSense and find the Suricata interface name by listing /var/log/suricata.
    Returns the interface string (e.g., 'em3').
    """
    pfsense_ip = "192.168.0.1"
    list_cmd = "ls /var/log/suricata"
    ssh_cmd = (
        f"sshpass -p '{pfsense_pass}' ssh -o StrictHostKeyChecking=no {pfsense_user}@{pfsense_ip} \"{list_cmd}\""
    )
    result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.splitlines():
            if line.startswith("suricata_"):
                # Extract interface name after 'suricata_'
                iface = line.replace("suricata_", "").strip("/")
                print(f"Found Suricata interface: {iface}")
                return iface
    print("No Suricata interface found.")
    return None

def install_sshpass():
    """
    Install sshpass if it's not already installed.
    """
    print("Checking and installing sshpass...")
    # Check if sshpass is already installed
    check_cmd = "which sshpass"
    check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

    if check_result.returncode == 0:
        print("sshpass is already installed.")
        return True

    # Install sshpass
    install_cmd = "sudo apt update && sudo apt install -y sshpass"
    install_result = run_cmd(install_cmd)

    if install_result.returncode == 0:
        print("Successfully installed sshpass.")
        return True
    else:
        print("Failed to install sshpass. Please install it manually.")
        return False

if __name__ == "__main__":
    SPLUNK_SERVER_IP = "<SPLUNK_SERVER_IP>"
    if SPLUNK_SERVER_IP == "<SPLUNK_SERVER_IP>":
        raise ValueError("Please set SPLUNK_SERVER_IP to the actual IP address of your Splunk server.")
    # 0. First install sshpass
    install_sshpass()

    # 1. Configure pfSense remote logging (manual)
    configure_pfsense_remote_logging(SPLUNK_SERVER_IP)

    # 2. Find Suricata interface on pfSense
    interface = get_suricata_interface("admin", "labadmin")

    # 3. SSH to pfSense (192.168.0.1) and configure Splunk Forwarder
    configure_splunk_forwarder_on_pfsense(interface, SPLUNK_SERVER_IP, "admin", "labadmin")

    # 4. SSH to Splunk Server and configure inputs.conf
    configure_splunk_server(SPLUNK_SERVER_IP, "labadmin", "labadmin")
```
