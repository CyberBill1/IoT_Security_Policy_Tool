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
