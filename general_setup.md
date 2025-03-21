#General Project Setup and Working Principle 

Here’s a breakdown of the project’s components and key aspects, addressing potential points of confusion:
Purpose
This project creates a tool running on a Raspberry Pi to enforce IoT security policies. It scans connected devices for compliance (e.g., firmware version, encryption), isolates non-compliant devices using iptables, and logs results to AWS CloudWatch, demonstrating security policy enforcement in an IoT network.
Files
policy_enforcement.py: Python script to scan devices, enforce policies, and log to CloudWatch.
setup_network.sh: Bash script to configure iptables for network isolation.
README.md: Documentation with setup instructions and a demo placeholder.
Hardware
Raspberry Pi: E.g., Pi 4, acting as the gateway (running Raspbian OS).
Network: Pi connected to a local network with IoT devices (e.g., another Pi, ESP32, or simulated devices).
Software
Raspbian OS: Operating system for the Pi.
Python 3: Runs policy_enforcement.py with libraries nmap, boto3.
nmap: Network scanning tool to detect devices and their properties.
iptables: Configures firewall rules for isolation.
AWS CloudWatch: Logs compliance and enforcement actions.
Key Features
Policy Check: Scans devices for firmware version (simulated) and encryption status.
Enforcement: Blocks non-compliant devices by IP using iptables.
Logging: Sends compliance reports and actions to CloudWatch.
Placeholders
Replace your-region in policy_enforcement.py with your AWS region (e.g., us-east-1).
Testing Locally
To test this project and generate a demo (e.g., a video for demo.mp4), you’ll set up the Raspberry Pi, configure the network, simulate IoT devices, and run the enforcement script. Here’s a detailed step-by-step process:
Prerequisites
Hardware: Raspberry Pi 4, microSD card, USB power supply, a second device (e.g., another Pi, laptop, or ESP32) to simulate an IoT device.
Software: Raspbian OS, Python 3, AWS account, a video recording tool (e.g., OBS Studio).
Tools: Terminal access (local or SSH), network connectivity.
Step 1: Set Up the Raspberry Pi
Install Raspbian OS:
Download Raspberry Pi OS Lite from raspberrypi.org.
Flash it to a microSD card using Raspberry Pi Imager.
Boot the Pi (default login: pi/raspberry).
Update and Install Dependencies:
Run: sudo apt update && sudo apt upgrade -y.
Install: sudo apt install python3-pip nmap -y.
Install Python libraries: pip3 install python-nmap boto3.
Step 2: Configure the Network
Set Up Pi as Gateway:
Connect the Pi to your router via Ethernet or WiFi.
Find the Pi’s IP: hostname -I (e.g., 192.168.1.100).
Note your subnet (e.g., 192.168.1.0/24).
Simulate IoT Devices:
Use a second device (e.g., laptop or another Pi) on the same network.
Assign a static IP (e.g., 192.168.1.101) via its network settings.
Step 3: Configure iptables
Create setup_network.sh:
On the Pi, create: nano setup_network.sh.
Paste:
bash
#!/bin/bash

# Flush existing rules
sudo iptables -F

# Allow all outbound traffic
sudo iptables -P OUTPUT ACCEPT

# Allow established inbound traffic
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (for management)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Default drop for incoming traffic
sudo iptables -P INPUT DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4

echo "Network baseline configured. Run policy_enforcement.py to isolate non-compliant devices."
Save and make executable: chmod +x setup_network.sh.
Run:
Execute: sudo ./setup_network.sh.
Verify: sudo iptables -L -v (shows SSH allowed, others dropped).
Step 4: Run the Enforcement Script
Create policy_enforcement.py:
On the Pi, create: nano policy_enforcement.py.
Paste:
python
import nmap
import boto3
import subprocess
from datetime import datetime

# AWS CloudWatch setup
cloudwatch = boto3.client('logs', region_name='your-region')
LOG_GROUP = 'IoTSecurityPolicy'
LOG_STREAM = 'EnforcementLogs'

# Network range to scan
NETWORK_RANGE = '192.168.1.0/24'  # Adjust to your subnet

# Security policy
MIN_FIRMWARE_VERSION = '1.2'
REQUIRED_ENCRYPTION = True

def log_to_cloudwatch(message):
    cloudwatch.put_log_events(
        logGroupName=LOG_GROUP,
        logStreamName=LOG_STREAM,
        logEvents=[{
            'timestamp': int(datetime.now().timestamp() * 1000),
            'message': message
        }]
    )

def isolate_device(ip):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    log_to_cloudwatch(f"Isolated non-compliant device: {ip}")

def check_device(ip):
    # Simulate firmware and encryption check (in reality, query device API)
    firmware_version = '1.1' if '101' in ip else '1.3'  # Simulate non-compliance for .101
    encryption_enabled = False if '101' in ip else True

    is_compliant = (firmware_version >= MIN_FIRMWARE_VERSION and encryption_enabled == REQUIRED_ENCRYPTION)
    return {
        'ip': ip,
        'firmware': firmware_version,
        'encryption': encryption_enabled,
        'compliant': is_compliant
    }

# Scan network
nm = nmap.PortScanner()
nm.scan(hosts=NETWORK_RANGE, arguments='-sn')  # Ping scan

for host in nm.all_hosts():
    status = check_device(host)
    log_message = f"Device {host}: Firmware={status['firmware']}, Encryption={status['encryption']}, Compliant={status['compliant']}"
    print(log_message)
    log_to_cloudwatch(log_message)

    if not status['compliant']:
        isolate_device(host)

print("Policy enforcement complete.")
Update NETWORK_RANGE to match your subnet and region_name to your AWS region.
Run:
Execute: python3 policy_enforcement.py.
Expect output like:
Device 192.168.1.100: Firmware=1.3, Encryption=True, Compliant=True
Device 192.168.1.101: Firmware=1.1, Encryption=False, Compliant=False
Isolated non-compliant device: 192.168.1.101
Policy enforcement complete.
Step 5: Test Enforcement
Verify Isolation:
From the simulated device (192.168.1.101), try pinging the Pi: ping 192.168.1.100.
Expect no response (iptables drops traffic).
From a compliant device (e.g., your laptop), ping should succeed.
Check CloudWatch:
In AWS Console, go to CloudWatch > Logs > IoTSecurityPolicy/EnforcementLogs.
Verify logs for compliance checks and isolation actions.
Step 6: Generate the Demo
Record: Use a screen recorder (e.g., OBS Studio) to capture:
Terminal output of policy_enforcement.py.
Failed ping from the isolated device.
CloudWatch logs in the AWS Console.
Save: Export as demo.mp4.
Upload to GitHub: Use “Add file” > “Upload files” in the repository.

General Working Principle
Here’s how the project operates:
Network Setup:
setup_network.sh configures iptables to allow SSH and established traffic, setting a baseline for the Pi as a gateway.

Device Scanning:
policy_enforcement.py uses nmap to discover devices on the subnet (e.g., 192.168.1.0/24).
For each device, it simulates a policy check (firmware version ≥ 1.2, encryption enabled).
Policy Enforcement:
Compliant devices (e.g., Pi itself) are allowed to communicate.
Non-compliant devices (e.g., 192.168.1.101) are blocked by adding an iptables rule to drop their traffic.
Logging:
Compliance status and enforcement actions are logged to CloudWatch (IoTSecurityPolicy/EnforcementLogs).
Flow:
Network Scan → Policy Check → Enforce (iptables) → Log to CloudWatch.

#Troubleshooting Tips
nmap Fails: Ensure it’s installed (sudo apt install nmap) and you have sudo privileges.
No Isolation: Verify iptables rules (sudo iptables -L -v) and device IPs.
CloudWatch Empty: Check AWS region and IAM permissions for CloudWatch Logs.
Network Issues: Confirm all devices are on the same subnet.
