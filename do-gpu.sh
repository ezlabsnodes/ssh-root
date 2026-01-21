#!/bin/bash
# complete-root-vps-setup-fixed.sh

############################################
# Fungsi untuk generate SSH key
############################################
generate_ssh_key() {
    echo "Generating public/private rsa key pair..."

    if [ -n "$HOME" ]; then
        SSH_DIR="$HOME/.ssh"
    elif [ -n "$USERPROFILE" ]; then
        SSH_DIR="$USERPROFILE/.ssh"
    else
        SSH_DIR="/root/.ssh"
    fi

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    local generate_new_key=true
    if [ -f "$SSH_DIR/id_rsa" ]; then
        echo "$SSH_DIR/id_rsa already exists."
        read -p "Overwrite (y/n)? " overwrite_choice

        if [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
            echo "Overwriting existing key..."
            rm -f "$SSH_DIR/id_rsa" "$SSH_DIR/id_rsa.pub"
        else
            echo "Using existing key."
            generate_new_key=false
        fi
    fi

    if [ "$generate_new_key" = true ]; then
        ssh-keygen -t rsa -b 4096 -o -a 100 -C "" -f "$SSH_DIR/id_rsa" -N "" -q
        echo "Your identification has been saved in $SSH_DIR/id_rsa"
        echo "Your public key has been saved in $SSH_DIR/id_rsa.pub"
    fi

    echo ""
    echo "=== SSH PUBLIC KEY ==="
    cut -d' ' -f1-2 "$SSH_DIR/id_rsa.pub"
    echo "=== END SSH PUBLIC KEY ==="
    echo ""
}

############################################
# Copy SSH key ke VPS (ROOT)
############################################
copy_ssh_key() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"

    echo "Copying SSH public key to VPS (root)..."
    
    # Clean known_hosts
    if [ -f "$SSH_DIR/known_hosts" ]; then
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "$vps_ip" > /dev/null 2>&1
    fi

    ssh-copy-id -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key.pub" \
        "root@$vps_ip"

    if [ $? -eq 0 ]; then
        echo "SSH key copied successfully."
        return 0
    fi

    echo "Trying alternative SSH key copy method..."
    cat "$ssh_key.pub" | ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key" \
        "root@$vps_ip" \
        "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

    return $?
}

############################################
# Jalankan setup VPS untuk ROOT
############################################
run_complete_vps_setup() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"

    copy_ssh_key "$vps_ip" || return 1

    echo "Setting up VPS..."
    
    # Langsung eksekusi command di VPS (lebih simple)
    ssh -i "$ssh_key" "root@$vps_ip" "
# Update system
apt-get update -y
apt-get upgrade -y

# Install required packages
apt-get install -y openssh-server curl wget nano htop fail2ban ufw

# Generate random password
ROOT_PASS=\$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
echo \"root:\$ROOT_PASS\" | chpasswd

# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configure SSH
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
LoginGraceTime 60
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Restart SSH service (coba berbagai cara)
systemctl restart ssh 2>/dev/null || \
systemctl restart sshd 2>/dev/null || \
service ssh restart 2>/dev/null || \
service sshd restart 2>/dev/null

# Configure fail2ban
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Configure firewall
ufw --force enable
ufw allow 22/tcp
ufw default deny incoming
ufw default allow outgoing

# Get public IP
PUBLIC_IP=\$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print \$1}')

echo ''
echo '========================================'
echo 'VPS SETUP COMPLETE'
echo '========================================'
echo 'IP:       '\$PUBLIC_IP
echo 'User:     root'
echo 'Password: '\$ROOT_PASS
echo 'Port:     22'
echo ''
echo 'Login methods:'
echo '1. SSH Key: ssh -i ~/.ssh/id_rsa root@'\$PUBLIC_IP
echo '2. Password: Use above password in Termius'
echo '========================================'
"
}

############################################
# MAIN
############################################
main() {
    echo "=== COMPLETE VPS SETUP FOR ROOT ==="
    echo ""

    generate_ssh_key

    local vps_ips=("$@")
    if [ ${#vps_ips[@]} -eq 0 ]; then
        read -p "Enter VPS IP (space separated for multiple): " -a vps_ips
    fi

    for ip in "${vps_ips[@]}"; do
        echo ""
        echo "=== SETUP VPS: $ip ==="
        run_complete_vps_setup "$ip"
        
        if [ $? -eq 0 ]; then
            echo "=== SUCCESS: $ip ==="
        else
            echo "=== FAILED: $ip ==="
        fi
        echo ""
    done
}

main "$@"
