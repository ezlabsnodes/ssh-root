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
        apt-get install -y fail2ban > /dev/null 2>&1
    elif command -v yum > /dev/null; then
        yum install -y fail2ban > /dev/null 2>&1
    elif command -v dnf > /dev/null; then
        dnf install -y fail2ban > /dev/null 2>&1
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
    sysctl -p /etc/sysctl.d/99-ddos-protection.conf > /dev/null 2>&1
    
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
    if sshpass -p "$password" scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no -P "$port" "ddos_protection.sh" "$user@$ip:/tmp/" 2>/dev/null; then
        echo "✓ Script uploaded successfully"
    else
        echo "✗ Failed to upload script to $ip"
        return 1
    fi
    
    # Execute script
    echo "Executing protection script on $ip..."
    if sshpass -p "$password" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no -p "$port" "$user@$ip" "chmod +x /tmp/ddos_protection.sh && sudo /tmp/ddos_protection.sh $port" 2>/dev/null; then
        echo "✓ Protection deployed successfully on $ip"
    else
        echo "✗ Failed to execute script on $ip"
        return 1
    fi
    
    # Cleanup
    sshpass -p "$password" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no -p "$port" "$user@$ip" "rm -f /tmp/ddos_protection.sh" 2>/dev/null
    
    echo "✓ Completed: $ip"
    echo ""
    return 0
}

# Main function
main() {
    echo "=== VPS DDoS & Brute Force Protection Auto Deployer ==="
    echo ""
    
    # Otomatis set SSH port ke 22 tanpa konfirmasi
    SSH_PORT=22
    echo "Using SSH port: $SSH_PORT (automatically set)"
    echo ""
    
    echo "Choose input method:"
    echo "1. Enter VPS data manually (format: IP USERNAME PASSWORD)"
    echo "2. Read from file"
    read -p "Choose option (1 or 2): " INPUT_OPTION
    
    declare -a VPS_ENTRIES
    
    if [ "$INPUT_OPTION" = "1" ]; then
        echo ""
        echo "Enter VPS data in format: IP USERNAME PASSWORD"
        echo "One per line. Type 'done' when finished."
        echo ""
        echo "Example:"
        echo "192.168.1.100 root MyPass123"
        echo "10.0.0.50 admin Admin@123"
        echo ""
        echo "Enter VPS data (or 'done' to finish):"
        
        while true; do
            read -r line
            if [ "$line" = "done" ]; then
                break
            fi
            
            # Clean the line
            line=$(echo "$line" | xargs)
            
            # Check if line has at least 3 parts (ip, username, password)
            if [ -n "$line" ]; then
                # Count words in line
                word_count=$(echo "$line" | wc -w)
                if [ $word_count -ge 3 ]; then
                    VPS_ENTRIES+=("$line")
                    echo "Added: $line"
                else
                    echo "Invalid format: $line (should be: IP USERNAME PASSWORD)"
                fi
            fi
        done
    elif [ "$INPUT_OPTION" = "2" ]; then
        read -p "Enter filename containing VPS list: " FILENAME
        if [ ! -f "$FILENAME" ]; then
            echo "File not found: $FILENAME"
            exit 1
        fi
        
        echo "Reading from file: $FILENAME"
        while IFS= read -r line || [ -n "$line" ]; do
            # Clean the line and skip empty/commented lines
            line=$(echo "$line" | sed 's/#.*//' | xargs)
            
            if [ -n "$line" ]; then
                # Count words in line
                word_count=$(echo "$line" | wc -w)
                if [ $word_count -ge 3 ]; then
                    VPS_ENTRIES+=("$line")
                else
                    echo "Warning: Skipping invalid line (not enough fields): $line"
                fi
            fi
        done < "$FILENAME"
        
        echo "Read ${#VPS_ENTRIES[@]} valid entries from file"
    else
        echo "Invalid option"
        exit 1
    fi
    
    # Check if we have any VPS data
    if [ ${#VPS_ENTRIES[@]} -eq 0 ]; then
        echo "Error: No valid VPS data provided"
        exit 1
    fi
    
    echo ""
    echo "=== VPS LIST ==="
    echo "Found ${#VPS_ENTRIES[@]} VPS entries:"
    for i in "${!VPS_ENTRIES[@]}"; do
        # Extract first two fields for display
        ip=$(echo "${VPS_ENTRIES[$i]}" | awk '{print $1}')
        username=$(echo "${VPS_ENTRIES[$i]}" | awk '{print $2}')
        echo "  [$((i+1))] $username@$ip"
    done
    echo ""
    echo "SSH Port: $SSH_PORT"
    echo ""
    
    # Otomatis deploy tanpa konfirmasi
    echo "Starting deployment in 3 seconds..."
    sleep 3
    echo ""
    echo "Starting deployment..."
    echo ""
    
    # Create protection script
    echo "Creating protection script..."
    create_protection_script
    
    # Deploy to each VPS
    success_count=0
    fail_count=0
    
    for entry in "${VPS_ENTRIES[@]}"; do
        # Extract fields from the entry
        ip=$(echo "$entry" | awk '{print $1}')
        username=$(echo "$entry" | awk '{print $2}')
        # Get the rest as password (in case password contains spaces)
        password=$(echo "$entry" | awk '{$1=$2=""; print substr($0,3)}' | xargs)
        
        # Skip if data is incomplete
        if [ -z "$ip" ] || [ -z "$username" ] || [ -z "$password" ]; then
            echo "✗ Skipping invalid entry: $entry"
            ((fail_count++))
            continue
        fi
        
        if deploy_to_vps "$ip" "$SSH_PORT" "$username" "$password"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    # Cleanup local script
    rm -f ddos_protection.sh
    
    # Show results
    echo "=== DEPLOYMENT COMPLETED ==="
    echo "Successful: $success_count"
    echo "Failed: $fail_count"
    echo "Total: ${#VPS_ENTRIES[@]}"
    
    if [ $fail_count -eq 0 ]; then
        echo "✅ All VPS are now protected!"
    else
        echo "⚠ Some VPS failed. Please check the errors above."
    fi
}

# Run main function
main
