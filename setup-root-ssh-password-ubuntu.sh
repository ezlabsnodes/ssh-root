#!/bin/bash
# complete-vps-setup.sh - Complete VPS Setup Script for Bash (Ubuntu Version)

############################################
# Fungsi untuk generate SSH key (CLEAN)
############################################
generate_ssh_key() {
    echo "Generating public/private rsa key pair..."

    # Determine home directory
    if [ -n "$HOME" ]; then
        SSH_DIR="$HOME/.ssh"
    elif [ -n "$USERPROFILE" ]; then
        SSH_DIR="$USERPROFILE/.ssh"
    else
        SSH_DIR="/root/.ssh"
    fi

    # Create .ssh directory if it doesn't exist
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
        # ⬇⬇⬇ TANPA COMMENT
        ssh-keygen -t rsa -b 4096 -o -a 100 -C "" -f "$SSH_DIR/id_rsa" -N "" -q

        echo "Your identification has been saved in $SSH_DIR/id_rsa"
        echo "Your public key has been saved in $SSH_DIR/id_rsa.pub"
    fi

    echo ""
    echo "=== SSH PUBLIC KEY (Copy content below) ==="
    # ⬇⬇⬇ OUTPUT BERSIH TANPA COMMENT
    cut -d' ' -f1-2 "$SSH_DIR/id_rsa.pub"
    echo "=== END SSH PUBLIC KEY ==="
    echo ""
}

############################################
# Fungsi remove known_hosts
############################################
clean_known_hosts() {
    local vps_ip="$1"

    if [ -f "$SSH_DIR/known_hosts" ]; then
        echo "Cleaning old known_hosts entry for $vps_ip..."
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "$vps_ip" > /dev/null 2>&1
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "[$vps_ip]:22" > /dev/null 2>&1
    fi
}

############################################
# Copy SSH key ke VPS (ubuntu)
############################################
copy_ssh_key() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"

    echo "Copying SSH public key to VPS..."
    clean_known_hosts "$vps_ip"

    ssh-copy-id -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key.pub" \
        "ubuntu@$vps_ip"

    if [ $? -eq 0 ]; then
        echo "SSH key copied successfully."
        return 0
    fi

    echo "Trying alternative SSH key copy method..."
    cat "$ssh_key.pub" | ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -i "$ssh_key" \
        "ubuntu@$vps_ip" \
        "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

    return $?
}

############################################
# Jalankan setup VPS
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

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo)"
    exit 1
fi

generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' </dev/urandom | head -c 16
}

apt update -y >/dev/null 2>&1
apt upgrade -y >/dev/null 2>&1
apt install -y sudo curl openssh-server fail2ban >/dev/null 2>&1

root_pass=$(generate_password)
echo "root:$root_pass" | chpasswd

usermod -aG sudo ubuntu || true

cat > /etc/ssh/sshd_config <<EOF
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

systemctl restart ssh

cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
maxretry = 5
bantime = 1h
EOF

systemctl enable fail2ban
systemctl restart fail2ban

vps_ip=$(curl -4 -s ifconfig.me || hostname -I | awk '{print $1}')

echo "----------------------------------------"
echo "IPv4     : $vps_ip"
echo "User     : root"
echo "Password : $root_pass"
echo "Port     : 22"
echo "----------------------------------------"
EOFSCRIPT

    scp -i "$ssh_key" "$temp_file" "ubuntu@$vps_ip:/tmp/vps_setup.sh"
    ssh -i "$ssh_key" "ubuntu@$vps_ip" "sudo bash /tmp/vps_setup.sh && rm /tmp/vps_setup.sh"

    rm -f "$temp_file"
}

############################################
# MAIN
############################################
main() {
    echo "=== COMPLETE VPS SETUP AUTOMATION FOR UBUNTU ==="
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
