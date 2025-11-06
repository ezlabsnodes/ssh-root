#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Try: sudo $0" >&2
    exit 1
fi

read -p "Enter your SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}
echo "Will protect SSH port: $SSH_PORT"

echo "Running apt update..."
apt-get update > /dev/null 2>&1

install_fail2ban() {
    echo "--- [1/2] Installing Brute-Force Protection (Fail2Ban) ---"
    
    echo "Installing Fail2Ban..."
    apt-get install -y fail2ban > /dev/null
    
    echo "Creating 'jail.local' configuration for SSH on port $SSH_PORT..."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = $SSH_PORT
EOF
    
    systemctl enable fail2ban > /dev/null
    systemctl restart fail2ban
    
    echo "Fail2Ban is now active and protecting SSH."
}

harden_sysctl() {
    echo -e "\n--- [2/2] Applying Kernel Hardening (Sysctl) ---"
    
    echo "Creating sysctl config file 99-ddos-protection.conf..."
    cat > /etc/sysctl.d/99-ddos-protection.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF

    echo "Applying kernel changes..."
    sysctl -p /etc/sysctl.d/99-ddos-protection.conf > /dev/null
    
    echo "Kernel hardening complete."
}

main() {
    echo "Starting VPS Protection Script..."
    
    install_fail2ban
    harden_sysctl
    
    echo -e "\n=== ALL PROTECTIONS ARE NOW ACTIVE ==="
    echo "Your server is now protected by Fail2Ban and Kernel Hardening."
}
main
