#!/bin/bash
# complete-vps-setup.sh - Complete VPS Setup Script for Bash

# Fungsi untuk generate SSH key
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
    
    # *** MODIFIED: Add interactive y/n prompt ***
    local generate_new_key=true
    if [ -f "$SSH_DIR/id_rsa" ]; then
        echo "$SSH_DIR/id_rsa already exists."
        local overwrite_choice
        # Read user input for overwrite
        read -p "Overwrite (y/n)? " overwrite_choice
        
        if [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
            echo "Overwriting existing key..."
            rm -f "$SSH_DIR/id_rsa" "$SSH_DIR/id_rsa.pub" 2>/dev/null
        else
            echo "Using existing key."
            generate_new_key=false
        fi
    fi
    
    if [ "$generate_new_key" = true ]; then
        # Generate SSH key dengan passphrase kosong secara non-interaktif
        ssh-keygen -t rsa -b 4096 -o -a 100 -C "ez@ezlabsnodes" -f "$SSH_DIR/id_rsa" -N "" -q
        
        echo "Your identification has been saved in $SSH_DIR/id_rsa"
        echo "Your public key has been saved in $SSH_DIR/id_rsa.pub"
    fi
    # *** END MODIFICATION ***
    
    echo ""
    
    # Tampilkan public key untuk dicopy
    echo "=== SSH PUBLIC KEY (Copy content below) ==="
    cat "$SSH_DIR/id_rsa.pub"
    echo "=== END SSH PUBLIC KEY ==="
    echo ""
}

# Fungsi untuk remove known_hosts entry
clean_known_hosts() {
    local vps_ip="$1"
    
    if [ -f "$SSH_DIR/known_hosts" ]; then
        echo "Cleaning old known_hosts entry for $vps_ip..."
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "$vps_ip" > /dev/null 2>&1
        ssh-keygen -f "$SSH_DIR/known_hosts" -R "$vps_ip" -p 22 > /dev/null 2>&1
    fi
}

# Fungsi untuk copy public key ke VPS
copy_ssh_key() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"
    
    echo "Copying SSH public key to VPS..."
    
    # Clean known_hosts first
    clean_known_hosts "$vps_ip"
    
    # Copy public key dengan options untuk handle host key change
    ssh-copy-id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i "$ssh_key.pub" "ubuntu@$vps_ip" > /dev/null 2>&1
    
    # *** MODIFIED: Add return status for retry loop ***
    if [ $? -eq 0 ]; then
        echo "SSH key copied successfully to VPS."
        return 0 # Success
    else
        echo "Trying alternative method to copy SSH key..."
        # Alternative method
        cat "$ssh_key.pub" | ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i "$ssh_key" "ubuntu@$vps_ip" "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo "SSH key setup completed (alternative)."
            return 0 # Success
        else
            echo "Error: Both ssh-copy-id and alternative method failed."
            return 1 # Failure
        fi
    fi
    # *** END MODIFICATION ***
}

# Fungsi untuk menjalankan setup lengkap di VPS
run_complete_vps_setup() {
    local vps_ip="$1"
    local ssh_key="$SSH_DIR/id_rsa"
    
    # Copy SSH key terlebih dahulu
    # *** MODIFIED: Check return status from copy_ssh_key ***
    copy_ssh_key "$vps_ip"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to copy SSH key. Aborting setup for this attempt."
        return 1 # Failure
    fi
    # *** END MODIFICATION ***
    
    # Create setup script file
    local temp_file
    temp_file=$(mktemp)
    
    # *** MODIFIED: Added Fail2Ban function to remote script ***
    cat > "$temp_file" << 'EOFSCRIPT'
#!/bin/bash

# 1. Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Try: sudo $0" >&2
    exit 1
fi

# Function to generate random password
generate_password() {
    local length=${1:-12}
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c "$length"
    echo
}

# Function to update system packages
update_system() {
    echo -e "\n[1/8] Updating system packages..."
    apt update -y > /dev/null 2>&1
    apt upgrade -y > /dev/null 2>&1
    echo "System updated successfully."
}

# Function to set root password
set_root_password() {
    echo -e "\n[2/8] Setting root password..."
    
    # Generate random password
    root_pass=$(generate_password 16)
    
    # Set password using chpasswd
    echo "root:$root_pass" | chpasswd
    
    if [ $? -eq 0 ]; then
        echo "Root password set successfully."
        echo "Generated password: $root_pass"
    else
        echo "Failed to set root password."
        exit 1
    fi
}

# Function to add sudo user to sudo group
add_user_to_sudo() {
    echo -e "\n[3/8] Configuring sudo access..."
    current_user=${SUDO_USER:-$(who am i | awk '{print $1}')}
    
    if [ -n "$current_user" ] && [ "$current_user" != "root" ]; then
        # Check if user exists
        if id "$current_user" &>/dev/null; then
            usermod -aG sudo "$current_user"
            echo "User '$current_user' added to sudo group."
        else
            echo "Warning: User '$current_user' does not exist."
        fi
    else
        echo "Skipped: Could not find a non-root user."
    fi
}

# Function to configure hosts file
configure_hosts() {
    echo -e "\n[4/8] Configuring /etc/hosts..."
    instance_name=$(hostname)
    
    # Backup original hosts file
    cp /etc/hosts /etc/hosts.backup
    
    # Remove existing entry if present and add new one
    sed -i "/$instance_name$/d" /etc/hosts
    echo "127.0.0.1 $instance_name" >> /etc/hosts
    
    echo "Hosts file configured for '$instance_name'."
}

# Function to install OpenSSH Server
install_openssh() {
    echo -e "\n[5/8] Installing OpenSSH server..."
    
    # Check if SSH is already installed
    if command -v ssh >/dev/null 2>&1; then
        echo "OpenSSH is already installed."
    else
        apt install -y openssh-server > /dev/null 2>&1
        echo "OpenSSH server installed successfully."
    fi
}

# Function to configure SSH daemon
configure_ssh() {
    echo -e "\n[6/8] Configuring SSH for root login with password..."
    
    SSH_PORT="22"
    
    # Backup original configuration
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create new SSH configuration
    cat > /etc/ssh/sshd_config << EOL
# Generated by automated setup script
Port $SSH_PORT
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
EOL

    echo "SSH configuration updated."
}

# *** NEW FUNCTION: Install Fail2Ban ***
install_bruteforce_protection() {
    echo -e "\n[7/8] Installing Fail2Ban (Bruteforce Protection)..."
    apt install -y fail2ban > /dev/null 2>&1
    
    # Create a basic local jail config for SSHD
    cat > /etc/fail2ban/jail.local << 'EOF_F2B'
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 5
bantime  = 1h
EOF_F2B
    
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban
    echo "Fail2Ban installed and configured for SSH."
}

# Function to restart SSH service
restart_ssh_service() {
    echo -e "\n[8/8] Restarting SSH service..."
    
    # Enable SSH service to start on boot
    systemctl enable ssh > /dev/null 2>&1
    
    # Restart SSH service
    if systemctl restart ssh; then
        echo "SSH service restarted successfully."
    else
        echo "Warning: Failed to restart SSH service. Trying alternative method..."
        service ssh restart > /dev/null 2>&1 || /etc/init.d/ssh restart > /dev/null 2>&1
    fi
}

# Function to get VPS IP
get_vps_ip() {
    echo -e "\nGetting VPS information..."
    
    # Try multiple methods to get public IP
    if command -v curl >/dev/null 2>&1; then
        vps_ip=$(curl -s -m 5 ifconfig.me) || 
        vps_ip=$(curl -s -m 5 ipinfo.io/ip) || 
        vps_ip=$(curl -s -m 5 icanhazip.com)
    elif command -v wget >/dev/null 2>&1; then
        vps_ip=$(wget -qO- -T 5 ifconfig.me) || 
        vps_ip=$(wget -qO- -T 5 ipinfo.io/ip) || 
        vps_ip=$(wget -qO- -T 5 icanhazip.com)
    fi
    
    # If all methods fail, use local IP
    if [ -z "$vps_ip" ]; then
        vps_ip=$(hostname -I | awk '{print $1}')
        echo "Warning: Could not get public IP, using local IP instead."
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "Installing required dependencies..."
    
    # Update package list first
    apt update -y > /dev/null 2>&1
    
    # Install curl if not present (for IP detection)
    if ! command -v curl >/dev/null 2>&1; then
        apt install -y curl > /dev/null 2>&1
    fi
    
    # Install common utilities
    apt install -y openssl > /dev/null 2>&1
}

# Main execution function
main() {
    echo "=== Automated System Setup for Debian/Ubuntu ==="
    echo "This script will:"
    echo "1. Update system packages"
    echo "2. Set auto-generated root password"
    echo "3. Configure sudo access"
    echo "4. Update hosts file"
    echo "5. Install/configure OpenSSH"
    echo "6. Enable root SSH login"
    echo "7. Install Fail2Ban (Bruteforce Protection)"
    echo "================================================"
    
    # Install dependencies
    install_dependencies
    
    # Execute all functions
    update_system
    set_root_password
    add_user_to_sudo
    configure_hosts
    install_openssh
    configure_ssh
    install_bruteforce_protection
    restart_ssh_service
    get_vps_ip
    
    # Display final information
    echo -e "\n=== SETUP COMPLETE ==="
    echo "Automatic SSH configuration finished."
    echo "----------------------------------------"
    echo "IPv4     : $vps_ip"
    echo "User     : root"
    echo "Password : $root_pass"
    echo "Port     : 22"
    echo "----------------------------------------"
    #echo "IMPORTANT: Save this password securely!"
    #echo "You can now SSH using:"
    #echo "ssh root@$vps_ip"
    #echo "----------------------------------------"
    
    # Also save password to file for backup
    # echo "root@$vps_ip : $root_pass" > /root/ssh_password.txt
    chmod 600 /root/ssh_password.txt
    # echo "Password backup saved to: /root/ssh_password.txt"
    
    # STOP HERE - Tidak melanjutkan ke SSH login
    # echo ""
    # echo "Setup completed. You can now connect manually using the credentials above."
    exit 0
}

# Run main function
main
EOFSCRIPT
    # *** END OF REMOTE SCRIPT ***

    echo "Executing complete VPS setup on remote server..."
    
    # Copy and execute setup script on VPS dengan options untuk handle host key
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 -i "$ssh_key" "$temp_file" "ubuntu@$vps_ip:/tmp/vps_complete_setup.sh" 2>/dev/null
    
    # *** MODIFIED: Check all return codes to return failure status ***
    if [ $? -eq 0 ]; then
        # *** MODIFIED: Capture remote output ***
        local remote_output
        remote_output=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 -i "$ssh_key" "ubuntu@$vps_ip" "sudo chmod +x /tmp/vps_complete_setup.sh && sudo /tmp/vps_complete_setup.sh && sudo rm /tmp/vps_complete_setup.sh" 2>/dev/null)
        local ssh_exit_code=$?
        
        # Print the output for the user
        echo "$remote_output"
        
        if [ $ssh_exit_code -eq 0 ]; then
            echo "VPS setup completed successfully!"
            # Cleanup
            rm -f "$temp_file"
            
            # Echo a special formatted line for main() to capture
            # Ini akan diekstraksi oleh fungsi main()
            local ip_remote=$(echo "$remote_output" | grep 'IPv4' | awk '{print $3}' | tail -n 1)
            local pass_remote=$(echo "$remote_output" | grep 'Password' | awk '{print $3}' | tail -n 1)
            
            # Gunakan IP input sebagai fallback jika deteksi IP remote gagal
            if [ -z "$ip_remote" ]; then
                ip_remote="$vps_ip"
            fi
            
            # Cetak baris data khusus untuk ditangkap oleh main()
            echo "---SETUP_DATA---"
            echo "IP: $ip_remote"
            echo "User: root"
            echo "Password: $pass_remote"
            echo "----------------"
            
            return 0 # Success
        else
            echo "Warning: SSH execution had issues. Setup might be incomplete."
            rm -f "$temp_file"
            return 1 # Failure
        fi
    else
        echo "Error: Could not copy setup script to VPS."
        echo "Please check the VPS IP and network connectivity."
        # Cleanup
        rm -f "$temp_file"
        return 1 # Failure
    fi
    # *** END MODIFICATION ***
}

# Main script
main() {
    echo "=== COMPLETE VPS SETUP AUTOMATION ==="
    echo ""
    
    # Generate SSH key (akan meminta overwrite jika perlu)
    generate_ssh_key
    
    echo "=== VPS Connection & Setup ==="
    
    # *** MODIFIED: Handle multiple IPs from argument or prompt ***
    local vps_ips_to_process=()
    if [ $# -ge 1 ]; then
        # Use all command-line arguments as IPs
        echo "Akan memproses IP dari argumen: $@"
        vps_ips_to_process=("$@")
    else
        # Ask the user to input space-separated IPs
        echo "Masukkan IP VPS (pisahkan dengan spasi, tekan ENTER untuk selesai):"
        read -a vps_ips_to_process
    fi

    if [ ${#vps_ips_to_process[@]} -eq 0 ]; then
        echo "Error: Tidak ada IP VPS yang dimasukkan."
        exit 1
    fi
    
    # Array to store success results
    local setup_results=()
    
    # Loop through each provided IP
    for vps_ip in "${vps_ips_to_process[@]}"; do
        echo ""
        echo "====================================================="
        echo "=== MEMULAI SETUP UNTUK VPS: $vps_ip ==="
        echo "====================================================="
        
        # Clean known_hosts before starting
        clean_known_hosts "$vps_ip"
        
        local setup_successful=false
        local setup_output="" # Variable to capture output
        
        # Start retry loop for this specific IP
        while [ "$setup_successful" = false ]; do
            echo "Attempting to run complete setup on VPS ($vps_ip)..."
            
            # Capture stdout to 'setup_output'
            setup_output=$(run_complete_vps_setup "$vps_ip")
            local exit_code=$?
            
            # Check exit code from run_complete_vps_setup
            if [ $exit_code -eq 0 ]; then
                setup_successful=true
                echo "Setup finished successfully for $vps_ip."
                
                # Parse the output for credentials using the special tags
                local ip_final=$(echo "$setup_output" | grep 'IP:' | awk '{print $2}')
                local user_final=$(echo "$setup_output" | grep 'User:' | awk '{print $2}')
                local pass_final=$(echo "$setup_output" | grep 'Password:' | awk '{print $2}')
                
                # Add to results array
                if [ -n "$ip_final" ] && [ -n "$user_final" ] && [ -n "$pass_final" ]; then
                    setup_results+=("IP: $ip_final | User: $user_final | Password: $pass_final")
                else
                    # Fallback if parsing fails
                    setup_results+=("IP: $vps_ip | User: root | Password: (Gagal parse, cek log di atas)")
                fi
            else
                echo "Setup failed for $vps_ip. Retrying in 10 seconds... (Press Ctrl+C to cancel)"
                sleep 10
                # Clean hosts again in case of key issues
                clean_known_hosts "$vps_ip"
            fi
        done
    done
    
    # *** END MODIFICATION ***
    
    echo ""
    echo "=== RINGKASAN HASIL SETUP ==="
    if [ ${#setup_results[@]} -gt 0 ]; then
        for result in "${setup_results[@]}"; do
            echo "$result"
        done
    else
        echo "Tidak ada setup VPS yang berhasil diselesaikan."
    fi
    echo "=============================="
}

# Jalankan main function
main "$@"
