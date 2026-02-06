#!/bin/bash

############################################
# Generate SSH Key
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
            rm -f "$SSH_DIR/id_rsa" "$SSH_DIR/id_rsa.pub"
        else
            generate_new_key=false
        fi
    fi

    if [ "$generate_new_key" = true ]; then
        ssh-keygen -t rsa -b 4096 -o -a 100 -C "vps-key" -f "$SSH_DIR/id_rsa" -N "" -q
    fi

    echo ""
    echo "=== SSH PUBLIC KEY ==="
    cat "$SSH_DIR/id_rsa.pub"
    echo "======================"
    echo ""
}

############################################
# Clean known_hosts
############################################
clean_known_hosts() {
    local vps_ip="$1"
    if [ -f "$SSH_DIR/known_hosts" ]; then
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "$vps_ip" >/dev/null 2>&1
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "[$vps_ip]:22" >/dev/null 2>&1
    fi
}

############################################
# Copy SSH Key
############################################
copy_ssh_key() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"

    clean_known_hosts "$vps_ip"

    ssh-copy-id -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key.pub" \
        "paperspace@$vps_ip" && return 0

    cat "$ssh_key.pub" | ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key" \
        "paperspace@$vps_ip" \
        "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
}

############################################
# VPS Setup (FAST MODE)
############################################
run_complete_vps_setup() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"

    copy_ssh_key "$vps_ip" || return 1

    local temp_file
    temp_file=$(mktemp)

    cat > "$temp_file" << 'EOFSCRIPT'
#!/bin/bash
set -e

[ "$(id -u)" -ne 0 ] && { echo "Run as root"; exit 1; }

generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' </dev/urandom | head -c 16
}

root_pass=$(generate_password)
echo "root:$root_pass" | chpasswd

usermod -aG sudo paperspace 2>/dev/null || true

cat > /etc/ssh/sshd_config <<EOF
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

systemctl restart ssh || systemctl restart sshd

if command -v fail2ban-server >/dev/null 2>&1; then
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
maxretry = 5
bantime = 1h
EOF
systemctl restart fail2ban
fi

vps_ip=$(hostname -I | awk '{print $1}')

echo "----------------------------------------"
echo "IPv4     : $vps_ip"
echo "User     : root"
echo "Password : $root_pass"
echo "Port     : 22"
echo "----------------------------------------"
EOFSCRIPT

    scp -i "$ssh_key" "$temp_file" "paperspace@$vps_ip:/tmp/vps_setup.sh"
    ssh -i "$ssh_key" "paperspace@$vps_ip" "sudo bash /tmp/vps_setup.sh && rm /tmp/vps_setup.sh"

    rm -f "$temp_file"
}

############################################
# MAIN
############################################
main() {
    echo "=== FAST VPS SETUP (PAPERSPACE) ==="
    echo ""

    generate_ssh_key

    local vps_ips=("$@")
    if [ ${#vps_ips[@]} -eq 0 ]; then
        read -p "Masukkan IP VPS (pisahkan spasi): " -a vps_ips
    fi

    for ip in "${vps_ips[@]}"; do
        echo "=== SETUP VPS: $ip ==="
        run_complete_vps_setup "$ip"
    done
}

main "$@"
