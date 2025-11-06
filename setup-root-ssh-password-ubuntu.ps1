# complete-vps-setup.ps1 - Complete VPS Setup Script for PowerShell
# Multi-IP, Fail2Ban Protection, Cleaned, IPv4 Fix

# Fungsi untuk generate SSH key
function Generate-SSHKey {
    Write-Host "Generating public/private rsa key pair..." -ForegroundColor Green
    
    # Determine home directory
    $SSH_DIR = Join-Path $HOME ".ssh"
    
    # Create .ssh directory if it doesn't exist
    if (!(Test-Path $SSH_DIR)) {
        New-Item -ItemType Directory -Path $SSH_DIR -Force | Out-Null
    }
    
    # Path file key
    $privateKeyPath = Join-Path $SSH_DIR "id_rsa"
    $publicKeyPath = Join-Path $SSH_DIR "id_rsa.pub"
    
    # *** MODIFIED: Add interactive y/n prompt ***
    $generateNewKey = $true
    if (Test-Path $privateKeyPath) {
        Write-Host "$privateKeyPath already exists." -ForegroundColor Yellow
        $overwriteChoice = Read-Host "Overwrite (y/n)?"
        
        if ($overwriteChoice -match '^[Yy]$') {
            Write-Host "Overwriting existing keys..." -ForegroundColor Yellow
            Remove-Item $privateKeyPath -Force -ErrorAction SilentlyContinue
            Remove-Item $publicKeyPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Using existing key."
            $generateNewKey = $false
        }
    }
    
    if ($generateNewKey) {
        Write-Host "Generating new SSH key..." -ForegroundColor Green
        
        # Gunakan ssh-keygen langsung
        $keygenProcess = Start-Process -FilePath "ssh-keygen" -ArgumentList @("-t", "rsa", "-b", "4096", "-C", "ez@ezlabsnodes", "-f", $privateKeyPath, "-N", '""', "-q") -Wait -PassThru -NoNewWindow
        
        # Tunggu sebentar untuk memastikan file tercreate
        Start-Sleep -Seconds 2
        
        # Verifikasi file created
        if (Test-Path $publicKeyPath) {
            Write-Host "SSH key generated successfully" -ForegroundColor Green
        } else {
            Write-Host "Warning: SSH key generation might have issues" -ForegroundColor Yellow
        }
        
        Write-Host "Your identification has been saved in $privateKeyPath" -ForegroundColor Green
        Write-Host "Your public key has been saved in $publicKeyPath" -ForegroundColor Green
    }
    # *** END MODIFICATION ***
    
    Write-Host ""
    
    # Tampilkan public key untuk dicopy
    Write-Host "=== SSH PUBLIC KEY (Copy content below) ===" -ForegroundColor Cyan
    if (Test-Path $publicKeyPath) {
        try {
            $publicKeyContent = Get-Content $publicKeyPath -ErrorAction Stop
            Write-Host $publicKeyContent -ForegroundColor White
        } catch {
            Write-Host "Error reading public key file: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "ERROR: Public key file not found at $publicKeyPath" -ForegroundColor Red
    }
    Write-Host "=== END SSH PUBLIC KEY ===" -ForegroundColor Cyan
    Write-Host ""
    
    return @{
        SSH_DIR = $SSH_DIR
        PrivateKey = $privateKeyPath
        PublicKey = $publicKeyPath
    }
}

# Fungsi untuk remove known_hosts entry
function Clean-KnownHosts {
    param([string]$VpsIP)
    
    $knownHostsPath = Join-Path $Global:SSH_DIR "known_hosts"
    
    if (Test-Path $knownHostsPath) {
        Write-Host "Cleaning old known_hosts entry for $VpsIP..." -ForegroundColor Yellow
        ssh-keygen -f $knownHostsPath -R $VpsIP 2>&1 | Out-Null
        ssh-keygen -f $knownHostsPath -R "${VpsIP}:22" 2>&1 | Out-Null
    }
}

# Fungsi untuk copy public key ke VPS
function Copy-SSHKey {
    param(
        [string]$VpsIP,
        [string]$SSHKeyPath
    )
    
    Write-Host "Copying SSH public key to VPS..." -ForegroundColor Green
    
    # Clean known_hosts first
    Clean-KnownHosts -VpsIP $VpsIP
    
    $publicKeyPath = "$SSHKeyPath.pub"
    
    if (!(Test-Path $publicKeyPath)) {
        Write-Host "Error: Public key not found at $publicKeyPath" -ForegroundColor Red
        return $false
    }
    
    Write-Host "Attempting to copy SSH key to ubuntu@$VpsIP..." -ForegroundColor Yellow
    
    # Method 1: Using ssh-copy-id (set timeout)
    try {
        # *** MODIFIED: Added ConnectTimeout ***
        # *** PERBAIKAN: Menampilkan output jika terjadi error, agar prompt password terlihat ***
        $process = Start-Process -FilePath "ssh-copy-id" -ArgumentList @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-i", $publicKeyPath, "ubuntu@$VpsIP") -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Host "SSH key copied successfully to VPS." -ForegroundColor Green
            return $true
        } else {
             Write-Host "ssh-copy-id failed with exit code $($process.ExitCode)." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "ssh-copy-id failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Method 2: Manual copy (set timeout)
    Write-Host "Trying alternative method to copy SSH key..." -ForegroundColor Yellow
    
    try {
        $publicKeyContent = Get-Content $publicKeyPath -Raw
        
        # Create temporary file
        $tempFile = [System.IO.Path]::GetTempFileName()
        $publicKeyContent | Out-File -FilePath $tempFile -Encoding ASCII
        
        $command = "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'Key added successfully'"
        
        # *** MODIFIED: Added ConnectTimeout ***
        # *** PERBAIKAN: Menampilkan output jika terjadi error ***
        $process2 = Start-Process -FilePath "ssh" -ArgumentList @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-i", $SSHKeyPath, "ubuntu@$VpsIP", $command) -Wait -PassThru -NoNewWindow -RedirectStandardInput $tempFile
        
        Remove-Item $tempFile -Force
        
        if ($process2.ExitCode -eq 0) {
            Write-Host "SSH key setup completed (alternative)." -ForegroundColor Green
            return $true
        } else {
            Write-Host "Alternative method failed with exit code $($process2.ExitCode)." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Alternative method failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Error: Both SSH key copy methods failed." -ForegroundColor Red
    return $false
}

# Fungsi untuk membuat setup script yang akan dijalankan di VPS
function New-VPSSetupScript {
    # Skrip bash internal (telah dibersihkan dari spasi tidak valid)
    # *** MODIFIED: Added Fail2Ban function + IPv4 Fix ***
    $setupScript = @'
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

# Function to add sudo user to sudo group (Ubuntu specific)
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

# *** MODIFIED FUNCTION: Force IPv4 ***
get_vps_ip() {
    echo -e "\nGetting VPS information (IPv4)..."
    
    # Try multiple methods to get public IP (Forcing IPv4)
    if command -v curl >/dev/null 2>&1; then
        vps_ip=$(curl -4 -s -m 5 ifconfig.me) || 
        vps_ip=$(curl -4 -s -m 5 ipinfo.io/ip) || 
        vps_ip=$(curl -4 -s -m 5 icanhazip.com)
    elif command -v wget >/dev/null 2>&1; then
        vps_ip=$(wget --inet4-only -qO- -T 5 ifconfig.me) || 
        vps_ip=$(wget --inet4-only -qO- -T 5 ipinfo.io/ip) || 
        vps_ip=$(wget --inet4-only -qO- -T 5 icanhazip.com)
    fi
    
    # If all methods fail, use local IP (Forcing IPv4)
    if [ -z "$vps_ip" ]; then
        vps_ip=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d'/' -f1 | head -n1)
        if [ -z "$vps_ip" ]; then
            # Ultimate fallback
            vps_ip=$(hostname -I | awk '{print $1}')
        fi
        echo "Warning: Could not get public IP via external services, using local IP: $vps_ip"
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
    # echo "IMPORTANT: Save this password securely!"
    # echo "You can now SSH using:"
    # echo "ssh root@$vps_ip"
    # echo "----------------------------------------"
    
    # Also save password to file for backup
    # echo "root@$vps_ip : $root_pass" > /root/ssh_password.txt
    # echo "Password backup saved to: /root/ssh_password.txt"
    
    # STOP HERE - Tidak melanjutkan ke SSH login
    # echo ""
    # echo "Setup completed. You can now connect manually using the credentials above."
    exit 0
}

# Run main function
main
'@
    # *** END OF BASH SCRIPT ***
    
    return $setupScript
}

# Fungsi untuk menyimpan script dengan format UNIX
function Save-UnixScript {
    param(
        [string]$Content,
        [string]$FilePath
    )
    
    # Convert to UNIX line endings (LF only)
    $Content = $Content -replace "`r`n", "`n" -replace "`r", "`n"
    
    # Gunakan encoding UTF-8 tanpa BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FilePath, $Content, $utf8NoBom)
}

# Fungsi untuk menjalankan setup lengkap di VPS
function Start-CompleteVPSSetup {
    param(
        [string]$VpsIP,
        [string]$SSHKeyPath
    )
    
    Write-Host "Executing complete VPS setup on remote server..." -ForegroundColor Green
    
    # Create temporary file for setup script
    $tempFile = [System.IO.Path]::GetTempFileName() -replace "\.tmp$", ".sh"
    $setupScript = New-VPSSetupScript
    
    # Save dengan format UNIX
    Save-UnixScript -Content $setupScript -FilePath $tempFile
    
    Write-Host "Setup script created at: $tempFile" -ForegroundColor Yellow
    
    # Copy and execute setup script on VPS
    Write-Host "Copying setup script to VPS..." -ForegroundColor Yellow
    
    $scpArgs = @(
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "ConnectTimeout=30",
        "-i", $SSHKeyPath,
        $tempFile,
        "ubuntu@${VpsIP}:/tmp/vps_complete_setup.sh"
    )
    
    # *** PERBAIKAN: Menampilkan output jika terjadi error ***
    $scpResult = & scp @scpArgs 2>&1
    
    # *** MODIFIED: Capture remote output and return object ***
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Setup script copied successfully." -ForegroundColor Green
        
        # Execute setup script on VPS
        Write-Host "Executing setup script on VPS..." -ForegroundColor Yellow
        
        $sshArgs = @(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=120",
            "-i", $SSHKeyPath,
            "ubuntu@$VpsIP",
            "sudo bash /tmp/vps_complete_setup.sh && sudo rm /tmp/vps_complete_setup.sh" # Cleanup script
        )
        
        Write-Host "Running remote setup (this may take a few minutes)..." -ForegroundColor Cyan
        
        # Jalankan SSH process dan tangkap outputnya
        # *** PERBAIKAN: Menampilkan output jika terjadi error ***
        $remoteOutput = & ssh @sshArgs 2>&1
        $sshExitCode = $LASTEXITCODE
        
        # Tampilkan output ke user
        Write-Host $remoteOutput
        
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        if ($sshExitCode -eq 0) {
            Write-Host "VPS setup completed successfully!" -ForegroundColor Green
            
            # Parse output untuk kredensial
            $ip_remote = ($remoteOutput | Select-String -Pattern "IPv4\s+:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -Last 1
            $pass_remote = ($remoteOutput | Select-String -Pattern "Password\s+:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -Last 1

            if (-not [string]::IsNullOrEmpty($ip_remote) -and -not [string]::IsNullOrEmpty($pass_remote)) {
                 # Kembalikan object dengan kredensial
                 return [PSCustomObject]@{ IP = $ip_remote; User = "root"; Password = $pass_remote }
            } else {
                # Fallback jika parsing gagal
                Write-Host "Warning: Could not parse credentials from output." -ForegroundColor Yellow
                return [PSCustomObject]@{ IP = $VpsIP; User = "root"; Password = "(Gagal parse, cek log)" }
            }
            
        } else {
            Write-Host "SSH process completed with exit code: $sshExitCode" -ForegroundColor Yellow
            return $null # Failure
        }
    } else {
        Write-Host "Error: Could not copy setup script to VPS." -ForegroundColor Red
        Write-Host "SCP Output: $scpResult" -ForegroundColor Red
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        return $null # Failure
    }
    # *** END MODIFICATION ***
}

# Main script
function Main {
    param(
        [string[]]$Args
    )
    
    Write-Host "=== COMPLETE VPS SETUP AUTOMATION ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Check prerequisites
    if (!(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Host "Error: SSH client not found." -ForegroundColor Red
        Write-Host "Install OpenSSH Client via: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Yellow
        exit 1
    }
    
    # Generate SSH key (akan meminta overwrite jika perlu)
    $sshInfo = Generate-SSHKey
    
    Write-Host "=== VPS Connection & Setup ===" -ForegroundColor Cyan
    
    # *** MODIFIED: Get Multiple IPs ***
    $vpsIPsToProcess = @()
    if ($Args.Count -ge 1) {
        Write-Host "Akan memproses IP dari argumen: $($Args -join ', ')" -ForegroundColor Green
        $vpsIPsToProcess = $Args
    } else {
        $ipString = Read-Host "Masukkan IP VPS (pisahkan dengan spasi, tekan ENTER untuk selesai)"
        # Filter input untuk memastikan hanya format IP yang valid
        $vpsIPsToProcess = $ipString -split ' ' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
    }

    if ($vpsIPsToProcess.Count -eq 0) {
        Write-Host "Error: Tidak ada IP VPS yang dimasukkan atau format salah." -ForegroundColor Red
        exit 1
    }
    
    # Set global SSH_DIR
    $Global:SSH_DIR = $sshInfo.SSH_DIR
    
    # Array untuk menyimpan hasil
    $setupResults = @()

    # *** MODIFIED: Loop for each IP ***
    foreach ($vps_ip in $vpsIPsToProcess) {
        Write-Host ""
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host "=== MEMULAI SETUP UNTUK VPS: $vps_ip ===" -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        
        # Clean known_hosts sebelum mulai
        Clean-KnownHosts -VpsIP $vps_ip
        
        # *** MODIFIED: Add retry loop ***
        $setupSuccessful = $false
        while (-not $setupSuccessful) {
            Write-Host "Attempting to run complete setup on VPS ($vps_ip)..." -ForegroundColor Cyan
            
            # 1. Copy Key
            $keyCopied = Copy-SSHKey -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
            
            if ($keyCopied) {
                Write-Host "SSH authentication configured successfully." -ForegroundColor Green
                
                # 2. Run Setup
                $setupResultObject = Start-CompleteVPSSetup -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
                
                if ($setupResultObject -ne $null) {
                    $setupSuccessful = $true
                    Write-Host "Setup finished successfully for $vps_ip." -ForegroundColor Green
                    
                    # Tambahkan hasil ke array
                    $resultString = "IP: $($setupResultObject.IP) | User: $($setupResultObject.User) | Password: $($setupResultObject.Password)"
                    $setupResults += $resultString
                    
                } else {
                    Write-Host "Remote execution (SSH) failed." -ForegroundColor Red
                }
            } else {
                Write-Host "Key copy (ssh-copy-id / scp) failed." -ForegroundColor Red
            }
            
            if (-not $setupSuccessful) {
                Write-Host "Setup failed. Retrying in 10 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                # Clean hosts again
                Clean-KnownHosts -VpsIP $vps_ip
            }
        }
        # *** END MODIFICATION (Retry Loop) ***
    }
    # *** END MODIFICATION (ForEach IP Loop) ***
    
    
    # *** MODIFIED: Print Final Summary ***
    Write-Host ""
    Write-Host "=== RINGKASAN HASIL SETUP ===" -ForegroundColor Cyan
    if ($setupResults.Count -gt 0) {
        $setupResults | ForEach-Object { Write-Host $_ -ForegroundColor White }
    } else {
        Write-Host "Tidak ada setup VPS yang berhasil diselesaikan." -ForegroundColor Yellow
    }
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "SSH Keys location:" -ForegroundColor Cyan
    Write-Host "Private: $($sshInfo.PrivateKey)" -ForegroundColor White
    Write-Host "Public:  $($sshInfo.PublicKey)" -ForegroundColor White
}

# Handle uncaught exceptions
trap {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script terminated unexpectedly." -ForegroundColor Red
    exit 1
}

# Jalankan main function
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main -Args $args
    } catch {
        Write-Host "Fatal error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
