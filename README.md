# IoT Security Policy Enforcement Tool

A Raspberry Pi-based tool to enforce IoT security policies by scanning devices, isolating non-compliant ones with iptables, and logging to AWS CloudWatch.

## Prerequisites
- Raspberry Pi (e.g., 4) with Raspbian OS
- Python 3, `nmap`, `boto3` (`pip3 install python-nmap boto3`)
- `nmap` (`sudo apt install nmap`)
- AWS CloudWatch setup (IAM permissions)

## Setup
1. **Network**: Connect Pi to your local network as a gateway.
2. **Baseline**: Run `sudo ./setup_network.sh`.
3. **Enforcement**: Update `policy_enforcement.py` with your subnet and AWS region, then `python3 policy_enforcement.py`.
4. **Test**: Simulate devices (e.g., set one to IP 192.168.1.101), check isolation and CloudWatch logs.

## Demo
- Scans network, isolates non-compliant devices, logs to CloudWatch.
- [Demo Video](demo.mp4) <!-- Add after testing -->
