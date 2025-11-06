#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Try: sudo $0" >&2
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update > /dev/null 2>&1
apt-get install -y sshpass > /dev/null 2>&1

# Function to create protection script
create_protection_script() {
    cat > "ddos_protection.sh" << 'EOF'
#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Try: sudo $0" >&2
    exit 1
fi

SSH_PORT=$1
SSH_PORT=${SSH_PORT:-22}
echo "Will protect SSH port: $SSH_PORT"

echo "Running apt update..."
apt-get update > /dev/null 2>&1

install_fail2ban() {
    echo "--- [1/2] Installing Brute-Force Protection (Fail2Ban) ---"
    
    echo "Installing Fail2Ban..."
    if command -v apt-get > /dev/null; then
        apt-get install -y fail2ban > /dev/null
    elif command -v yum > /dev/null; then
        yum install -y fail2ban > /dev/null
    elif command -v dnf > /dev/null; then
        dnf install -y fail2ban > /dev/null
    fi
    
    echo "Creating 'jail.local' configuration for SSH on port $SSH_PORT..."
    cat > /etc/fail2ban/jail.local << JAIL_EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
JAIL_EOF
    
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban
    
    echo "Fail2Ban is now active and protecting SSH."
}

harden_sysctl() {
    echo -e "\n--- [2/2] Applying Kernel Hardening (Sysctl) ---"
    
    echo "Creating sysctl config file 99-ddos-protection.conf..."
    cat > /etc/sysctl.d/99-ddos-protection.conf << SYSCTL_EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSCTL_EOF

    echo "Applying kernel changes..."
    sysctl -p /etc/sysctl.d/99-ddos-protection.conf > /dev/null
    
    echo "Kernel hardening complete."
}

main() {
    echo "Starting VPS Protection Script..."
    
    install_fail2ban
    harden_sysctl
    
    echo -e "\n=== ALL PROTECTIONS ARE NOW ACTIVE ==="
    echo "Fail2Ban: Protects against brute force attacks"
    echo "Kernel Hardening: Protects against DDoS attacks"
}

main
EOF

    chmod +x "ddos_protection.sh"
}

# Function to deploy to single VPS
deploy_to_vps() {
    local ip=$1
    local port=$2
    local user=$3
    local password=$4
    
    echo "=========================================="
    echo "Deploying to: $user@$ip:$port"
    echo "=========================================="
    
    # Upload script
    if sshpass -p "$password" scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -P "$port" "ddos_protection.sh" "$user@$ip:/tmp/" 2>/dev/null; then
        echo "✓ Script uploaded successfully"
    else
        echo "✗ Failed to upload script to $ip"
        return 1
    fi
    
    # Execute script
    if sshpass -p "$password" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p "$port" "$user@$ip" "chmod +x /tmp/ddos_protection.sh && sudo /tmp/ddos_protection.sh $port" 2>/dev/null; then
        echo "✓ Protection deployed successfully on $ip"
    else
        echo "✗ Failed to execute script on $ip"
        return 1
    fi
    
    # Cleanup
    sshpass -p "$password" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p "$port" "$user@$ip" "rm -f /tmp/ddos_protection.sh" 2>/dev/null
    
    echo "✓ Completed: $ip"
    echo ""
    return 0
}

# Main function
main() {
    echo "=== VPS DDoS & Brute Force Protection Auto Deployer ==="
    echo ""
    
    # Input jumlah VPS
    read -p "Enter number of VPS: " VPS_COUNT
    
    # Validasi input
    if ! [[ "$VPS_COUNT" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: Please enter a valid number"
        exit 1
    fi
    
    # Input port SSH (sama untuk semua VPS)
    read -p "Enter SSH port for all VPS (default: 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # Input username (sama untuk semua VPS)
    read -p "Enter username for all VPS (default: root): " USERNAME
    USERNAME=${USERNAME:-root}
    
    echo ""
    echo "Will deploy to $VPS_COUNT VPS using:"
    echo "  SSH Port: $SSH_PORT"
    echo "  Username: $USERNAME"
    echo ""
    
    # Array untuk menyimpan data VPS
    declare -a VPS_IPS
    declare -a VPS_PASSWORDS
    
    # Input IP dan password untuk setiap VPS
    for (( i=1; i<=$VPS_COUNT; i++ ))
    do
        echo "--- VPS $i of $VPS_COUNT ---"
        read -p "Enter IP address for VPS $i: " ip
        read -s -p "Enter password for VPS $i: " password
        echo
        
        VPS_IPS[$i]=$ip
        VPS_PASSWORDS[$i]=$password
        echo ""
    done
    
    # Buat script proteksi
    echo "Creating protection script..."
    create_protection_script
    
    # Konfirmasi deployment
    echo ""
    echo "=== SUMMARY ==="
    echo "Ready to deploy protection to $VPS_COUNT VPS:"
    for (( i=1; i<=$VPS_COUNT; i++ ))
    do
        echo "  VPS $i: ${VPS_IPS[$i]}"
    done
    echo ""
    
    read -p "Start deployment? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled."
        exit 0
    fi
    
    echo ""
    echo "Starting deployment..."
    echo ""
    
    # Deploy ke setiap VPS
    success_count=0
    fail_count=0
    
    for (( i=1; i<=$VPS_COUNT; i++ ))
    do
        if deploy_to_vps "${VPS_IPS[$i]}" "$SSH_PORT" "$USERNAME" "${VPS_PASSWORDS[$i]}"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    # Cleanup local script
    rm -f ddos_protection.sh
    
    # Tampilkan hasil
    echo "=== DEPLOYMENT COMPLETED ==="
    echo "Successful: $success_count"
    echo "Failed: $fail_count"
    echo "Total: $VPS_COUNT"
    
    if [ $fail_count -eq 0 ]; then
        echo "✅ All VPS are now protected!"
    else
        echo "⚠ Some VPS failed. Please check the errors above."
    fi
}

# Run main function
main
