#!/bin/bash
# termius-vps-setup.sh - Setup VPS untuk Termius (root password login)

echo "=== VPS SETUP FOR TERMIUS ==="
echo ""

# Generate random password untuk root
ROOT_PASS=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
echo "Generated root password: $ROOT_PASS"
echo ""

# Set password root
echo "Setting root password..."
echo "root:$ROOT_PASS" | chpasswd

# Backup dan edit SSH config
echo "Configuring SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Pastikan setting SSH benar untuk password login
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
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

# Restart SSH
echo "Restarting SSH..."
if systemctl restart sshd 2>/dev/null; then
    echo "SSH restarted successfully"
else
    service ssh restart 2>/dev/null
    echo "SSH restarted using service command"
fi

# Get IP
PUBLIC_IP=$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "========================================"
echo "VPS READY FOR TERMIUS"
echo "========================================"
echo "Host: $PUBLIC_IP"
echo "User: root"
echo "Password: $ROOT_PASS"
echo "Port: 22"
echo ""
echo "Test command:"
echo "ssh root@$PUBLIC_IP"
echo "========================================"
