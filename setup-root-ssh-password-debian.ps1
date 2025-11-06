# complete-vps-setup.ps1 - Complete VPS Setup Script for PowerShell
# Fixed version - Multi-IP, CRLF clean, Credential Summary, Fail2Ban Protection

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
        # Generate SSH key dengan passphrase kosong
        Write-Host "Generating new SSH key..." -ForegroundColor Green
        
        # Method 1: Using ssh-keygen dengan full path
        $sshKeygenPath = Get-Command "ssh-keygen" -ErrorAction SilentlyContinue
        if ($sshKeygenPath) {
            $keygenArgs = @(
                "-t", "rsa",
                "-b", "4096", 
                "-C", "ez@ezlabsnodes",
                "-f", $privateKeyPath,
                "-N", '""',
                "-q"
            )
            
            $process = Start-Process -FilePath $sshKeygenPath.Source -ArgumentList $keygenArgs -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0 -and (Test-Path $publicKeyPath)) {
                Write-Host "SSH key generated successfully using ssh-keygen" -ForegroundColor Green
            } else {
                Write-Host "ssh-keygen failed, trying alternative method..." -ForegroundColor Yellow
                Generate-SSHKey-PowerShell -PrivateKeyPath $privateKeyPath -PublicKeyPath $publicKeyPath
            }
        } else {
            Write-Host "ssh-keygen not found, using PowerShell method..." -ForegroundColor Yellow
            Generate-SSHKey-PowerShell -PrivateKeyPath $privateKeyPath -PublicKeyPath $publicKeyPath
        }
        
        Write-Host "Your identification has been saved in $privateKeyPath" -ForegroundColor Green
        Write-Host "Your public key has been saved in $publicKeyPath" -ForegroundColor Green
    }
    # *** END MODIFICATION ***
    
    Write-Host ""
    
    # Tampilkan public key untuk dicopy
    Write-Host "=== SSH PUBLIC KEY (Copy content below) ===" -ForegroundColor Cyan
    if (Test-Path $publicKeyPath) {
        $publicKeyContent = Get-Content $publicKeyPath -Raw
        Write-Host $publicKeyContent.Trim() -ForegroundColor White
    } else {
        Write-Host "ERROR: Public key file not found!" -ForegroundColor Red
        exit 1
    }
    Write-Host "=== END SSH PUBLIC KEY ===" -ForegroundColor Cyan
    Write-Host ""
    
    return @{
        SSH_DIR = $SSH_DIR
        PrivateKey = $privateKeyPath
        PublicKey = $publicKeyPath
    }
}

# Alternative SSH key generation using PowerShell
function Generate-SSHKey-PowerShell {
    param(
        [string]$PrivateKeyPath,
        [string]$PublicKeyPath
    )
    
    try {
        Write-Host "Generating SSH key using PowerShell method..." -ForegroundColor Yellow
        
        # Generate random bytes for key
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(4096)
        
        # Export private key
        $privateKeyBytes = $rsa.ExportCspBlob($true)
        $privateKeyBase64 = [Convert]::ToBase64String($privateKeyBytes)
        
        # Export public key
        $publicKeyBytes = $rsa.ExportCspBlob($false)
        $publicKeyBase64 = [Convert]::ToBase64String($publicKeyBytes)
        
        # Create private key in OpenSSH format
        $privateKeyContent = @"
-----BEGIN RSA PRIVATE KEY-----
$privateKeyBase64
-----END RSA PRIVATE KEY-----
"@
        
        # Create public key in OpenSSH format
        $publicKeyContent = "ssh-rsa $publicKeyBase64 ez@ezlabsnodes"
        
        # Save keys
        $privateKeyContent | Out-File -FilePath $PrivateKeyPath -Encoding ASCII -NoNewline
        $publicKeyContent | Out-File -FilePath $PublicKeyPath -Encoding ASCII -NoNewline
        
        Write-Host "SSH key generated successfully using PowerShell method" -ForegroundColor Green
    } catch {
        Write-Host "Failed to generate SSH key: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Fungsi untuk remove known_hosts entry
function Clean-KnownHosts {
    param([string]$VpsIP)
    
    $knownHostsPath = Join-Path $Global:SSH_DIR "known_hosts"
    
    if (Test-Path $knownHostsPath) {
        Write-Host "Cleaning old known_hosts entry for $VpsIP..." -ForegroundColor Yellow
        & ssh-keygen -f $knownHostsPath -R $VpsIP 2>&1 | Out-Null
        & ssh-keygen -f $knownHostsPath -R "${VpsIP}:22" 2>&1 | Out-Null
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
    
    Write-Host "Attempting to copy SSH key to debian@$VpsIP..." -ForegroundColor Yellow
    
    # Method 1: Direct SSH command to copy key
    Write-Host "Method 1: Manual key copy via SSH..." -ForegroundColor Yellow
    
    $publicKeyContent = Get-Content $publicKeyPath -Raw
    
    # Create a temporary script to handle the key copy
    $copyCommand = @"
set -e
mkdir -p ~/.ssh
echo '$($publicKeyContent.Trim())' >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
echo 'SSH key added successfully'
"@
    
    $tempScript = [System.IO.Path]::GetTempFileName() -replace "\.tmp$", ".sh"
    $copyCommand | Out-File -FilePath $tempScript -Encoding ASCII
    
    try {
        # Copy and execute the setup script
        $scpArgs = @(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", 
            "-o", "ConnectTimeout=30",
            "-i", $SSHKeyPath,
            $tempScript,
            "debian@${VpsIP}:/tmp/copy_key.sh"
        )
        
        $scpProcess = Start-Process -FilePath "scp" -ArgumentList $scpArgs -Wait -PassThru -NoNewWindow
        
        if ($scpProcess.ExitCode -eq 0) {
            $sshArgs = @(
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=30",
                "-i", $SSHKeyPath,
                "debian@$VpsIP",
                "chmod +x /tmp/copy_key.sh && bash /tmp/copy_key.sh && rm /tmp/copy_key.sh"
            )
            
            $sshProcess = Start-Process -FilePath "ssh" -ArgumentList $sshArgs -Wait -PassThru -NoNewWindow
            
            if ($sshProcess.ExitCode -eq 0) {
                Write-Host "SSH key copied successfully to VPS." -ForegroundColor Green
                Remove-Item $tempScript -Force
                return $true
            }
        }
    } catch {
        Write-Host "Method 1 failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    
    # Method 2: Using ssh-copy-id as fallback
    Write-Host "Method 2: Trying ssh-copy-id..." -ForegroundColor Yellow
    
    try {
        $sshCopyArgs = @(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-i", $publicKeyPath,
            "debian@$VpsIP"
        )
        
        $sshCopyProcess = Start-Process -FilePath "ssh-copy-id" -ArgumentList $sshCopyArgs -Wait -PassThru -NoNewWindow
        
        if ($sshCopyProcess.ExitCode -eq 0) {
            Write-Host "SSH key copied successfully using ssh-copy-id." -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "ssh-copy-id also failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "Error: Both SSH key copy methods failed." -ForegroundColor Red
    return $false
}

# Fungsi untuk membuat setup script yang akan dijalankan di VPS (UNIX format)
function New-VPSSetupScript {
    # Script dalam format UNIX (LF line endings only)
    $setupScript = @'
#!/bin/bash
# Using set -e to exit immediately if a command exits with a non-zero status.
set -e

echo "=== Starting Automated System Setup for Debian ==="

# Function to generate random password
generate_password() {
    # Added /dev/urandom for better entropy, pipe to tr to filter chars, head for length
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c 16
    echo
}

# Function to update system packages
update_system() {
    echo "[1/8] Updating system packages..."
    # Redirect output to /dev/null for cleaner execution
    apt-get update -y > /dev/null 2>&1
    apt-get upgrade -y > /dev/null 2>&1
    echo "System updated successfully."
}

# Function to set root password
set_root_password() {
    echo "[2/8] Setting root password..."
    # Store password in a variable. Use local to scope it if preferred, but not strictly needed here.
    ROOT_PASS=$(generate_password)
    echo "root:$ROOT_PASS" | chpasswd
    if [ $? -ne 0 ]; then
        echo "Error: Failed to set root password." >&2
        exit 1
    fi
    echo "Root password set successfully."
    # Echo password here so it gets captured by the log
    echo "Generated password: $ROOT_PASS"
}

# Function to configure debian user
setup_debian_user() {
    echo "[3/8] Configuring debian user..."
    if id "debian" &>/dev/null; then
        usermod -aG sudo debian
        usermod -s /bin/bash debian
        echo "Debian user configured with sudo access."
    else
        echo "Creating debian user..."
        useradd -m -s /bin/bash debian
        local user_pass=$(generate_password)
        echo "debian:$user_pass" | chpasswd
        usermod -aG sudo debian
        echo "Debian user created with password: $user_pass"
    fi
}

# Function to configure hosts file
configure_hosts() {
    echo "[4/8] Configuring /etc/hosts..."
    local hostname=$(hostname)
    # Check if backup already exists
    if [ ! -f /etc/hosts.backup ]; then
        cp /etc/hosts /etc/hosts.backup
    fi
    # Use grep -v to filter out the line, then append the new line
    grep -v "127.0.0.1 $hostname" /etc/hosts > /tmp/hosts.tmp
    echo "127.0.0.1 $hostname" >> /tmp/hosts.tmp
    mv /tmp/hosts.tmp /etc/hosts
    echo "Hosts file configured."
}

# Function to install and configure SSH
setup_ssh() {
    echo "[5/8] Installing and configuring SSH..."
    if ! command -v sshd >/dev/null 2>&1; then
        echo "Installing openssh-server..."
        apt-get install -y openssh-server > /dev/null 2>&1
    fi
    
    # Backup original config
    if [ ! -f /etc/ssh/sshd_config.backup ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    fi
    
    # Create new config using a HEREDOC
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
EOF

    echo "SSH configuration updated."
}

# *** NEW FUNCTION: Install Fail2Ban ***
install_bruteforce_protection() {
    echo "[6/8] Installing Fail2Ban (Bruteforce Protection)..."
    apt-get install -y fail2ban > /dev/null 2>&1
    
    # Create a basic local jail config for SSHD
    cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 5
bantime  = 1h
EOF
    
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban
    echo "Fail2Ban installed and configured for SSH."
}

# Function to restart services
restart_services() {
    echo "[7/8] Restarting SSH service..."
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to restart SSH service." >&2
    else
        echo "SSH service restarted."
    fi
}

# Function to get system info
get_system_info() {
    echo "[8/8] Gathering system information..."
    if ! command -v curl >/dev/null 2>&1; then
        echo "Installing curl..."
        apt-get install -y curl > /dev/null 2>&1
    fi
    # Try multiple IP services with timeouts
    PUBLIC_IP=$(curl -s -m 5 ifconfig.me || curl -s -m 5 ipinfo.io/ip || curl -s -m 5 icanhazip.com)
    
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(hostname -I | awk '{print $1}')
        echo "Could not fetch public IP, using local IP: $PUBLIC_IP"
    fi
}

# Main execution
main() {
    echo "This script will perform the following actions:"
    echo "1. Update system packages"
    echo "2. Set root password"
    echo "3. Configure debian user"
    echo "4. Update hosts file"
    echo "5. Install and configure SSH"
    echo "6. Install Fail2Ban (Bruteforce Protection)"
    echo "7. Restart services"
    echo "8. Get system info"
    echo "=============================================="
    
    # Run all functions
    update_system
    set_root_password
    setup_debian_user
    configure_hosts
    setup_ssh
    install_bruteforce_protection
    restart_services
    get_system_info
    
    # Final summary output
    echo ""
    echo "=== SETUP COMPLETED SUCCESSFULLY ==="
    echo "IPv4 Address: $PUBLIC_IP"
    echo "SSH User: root"
    echo "Root Password: $ROOT_PASS" # This variable is set in set_root_password
    echo "SSH Port: 22"
    echo "================================"
    
    # Save password to file
    echo "Root password: $ROOT_PASS" > /root/password.txt
    chmod 600 /root/password.txt
    echo "Password saved to /root/password.txt"
}

# Run main function and pipe stdout/stderr to a log file
# The 'tee' command will also print it to stdout, which PowerShell will show
main 2>&1 | tee /var/log/vps-setup.log
exit 0
'@
    
    return $setupScript
}

# Fungsi untuk menyimpan script dengan format UNIX (LF only)
function Save-UnixScript {
    param(
        [string]$Content,
        [string]$FilePath
    )
    
    # Convert to UNIX line endings (LF only) dan hapus BOM
    $Content = $Content -replace "`r`n", "`n" -replace "`r", "`n"
    
    # Gun encoding UTF-8 tanpa BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FilePath, $Content, $utf8NoBom)
}

# Fungsi untuk menjalankan setup lengkap di VPS
function Start-CompleteVPSSetup {
    param(
        [string]$VpsIP,
        [string]$SSHKeyPath
    )
    
    Write-Host "Executing complete VPS setup on remote Debian server..." -ForegroundColor Green
    
    # Create temporary file for setup script dengan format UNIX
    $tempFile = [System.IO.Path]::GetTempFileName() -replace "\.tmp$", ".sh"
    $setupScript = New-VPSSetupScript
    
    # Save dengan format UNIX
    Save-UnixScript -Content $setupScript -FilePath $tempFile
    
    Write-Host "Setup script created at: $tempFile" -ForegroundColor Yellow
    
    # Copy setup script ke VPS
    Write-Host "Copying setup script to VPS..." -ForegroundColor Yellow
    
    $scpArgs = @(
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "ConnectTimeout=30",
        "-i", $SSHKeyPath,
        $tempFile,
        "debian@${VpsIP}:/tmp/vps_setup.sh"
    )
    
    $scpResult = & scp @scpArgs 2>&1
    
    # *** MODIFIED: Capture remote output by reading log file ***
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Setup script copied successfully." -ForegroundColor Green
        
        # Execute setup script pada VPS
        Write-Host "Executing setup script on VPS..." -ForegroundColor Yellow
        Write-Host "This may take 3-5 minutes, please wait..." -ForegroundColor Cyan
        
        $sshArgs = @(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=300",
            "-o", "ServerAliveInterval=60",
            "-i", $SSHKeyPath,
            "debian@$VpsIP",
            "sudo bash /tmp/vps_setup.sh"
        )
        
        # Jalankan SSH dan tampilkan output real-time
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "ssh"
        $processInfo.Arguments = $sshArgs
        $processInfo.RedirectStandardOutput = $false # Allow real-time output
        $processInfo.RedirectStandardError = $false # Allow real-time output
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $false
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        Write-Host "Starting remote setup process (output will appear below)..." -ForegroundColor Yellow
        $process.Start() | Out-Null
        $process.WaitForExit() # Wait for the process to finish
        
        $sshExitCode = $process.ExitCode
        
        # Cleanup local script
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        if ($sshExitCode -eq 0) {
            Write-Host "VPS setup script finished execution." -ForegroundColor Green
            Write-Host "Fetching credentials from remote log..." -ForegroundColor Yellow
            
            # Now, fetch the log file to parse credentials
            $sshCatArgs = @(
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=30",
                "-i", $SSHKeyPath,
                "debian@$VpsIP",
                "sudo cat /var/log/vps-setup.log && sudo rm /var/log/vps-setup.log && sudo rm /tmp/vps_setup.sh" # Cat and cleanup
            )
            
            $logContent = & ssh @sshCatArgs 2>&1
            
            # Parse output untuk kredensial
            $ip_remote = ($logContent | Select-String -Pattern "IPv4 Address:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -Last 1
            $pass_remote = ($logContent | Select-String -Pattern "Root Password:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Select-Object -Last 1

            if (-not [string]::IsNullOrEmpty($ip_remote) -and -not [string]::IsNullOrEmpty($pass_remote)) {
                 # Kembalikan object dengan kredensial
                 return [PSCustomObject]@{ IP = $ip_remote; User = "root"; Password = $pass_remote }
            } else {
                # Fallback jika parsing gagal
                Write-Host "Warning: Could not parse credentials from remote log." -ForegroundColor Yellow
                return [PSCustomObject]@{ IP = $VpsIP; User = "root"; Password = "(Gagal parse, cek VPS)" }
            }
            
        } else {
            Write-Host "SSH process completed with exit code: $sshExitCode" -ForegroundColor Red
            return $null # Failure
        }
    } else {
        Write-Host "Error: Failed to copy setup script to VPS." -ForegroundColor Red
        Write-Host "SCP Output: $scpResult" -ForegroundColor Red
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        return $null # Failure
    }
    # *** END MODIFICATION ***
}

# Main script function
function Main {
    param(
        [string[]]$Args
    )
    
    Write-Host "=== COMPLETE VPS SETUP AUTOMATION FOR DEBIAN ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Check prerequisites
    if (!(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Host "Error: SSH client not found." -ForegroundColor Red
        Write-Host "Install OpenSSH Client via: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Yellow
        exit 1
    }
    
    if (!(Get-Command scp -ErrorAction SilentlyContinue)) {
        Write-Host "Error: SCP client not found." -ForegroundColor Red
        Write-Host "Install OpenSSH Client via: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Yellow
        exit 1
    }
    
    # Generate SSH key
    $sshInfo = Generate-SSHKey
    
    Write-Host "=== VPS Connection & Setup ===" -ForegroundColor Cyan
    
    # *** MODIFIED: Get Multiple IPs ***
    $vpsIPsToProcess = @()
    if ($Args.Count -ge 1) {
        Write-Host "Akan memproses IP dari argumen: $($Args -join ', ')" -ForegroundColor Green
        $vpsIPsToProcess = $Args | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
    } else {
        $ipString = Read-Host "Masukkan IP VPS (pisahkan dengan spasi, tekan ENTER untuk selesai)"
        $vpsIPsToProcess = $ipString -split ' ' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
    }

    if ($vpsIPsToProcess.Count -eq 0) {
        Write-Host "Error: Tidak ada IP VPS yang dimasukkan atau format salah." -ForegroundColor Red
        exit 1
    }
    # *** END MODIFICATION ***
    
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
        
        $setupSuccessful = $false
        
        # *** MODIFIED: Added Retry Loop ***
        while (-not $setupSuccessful) {
            # Clean known_hosts
            Clean-KnownHosts -VpsIP $vps_ip
            
            # Copy SSH key
            Write-Host "Setting up SSH key authentication for $vps_ip..." -ForegroundColor Cyan
            $keyCopied = Copy-SSHKey -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
            
            if ($keyCopied) {
                Write-Host "SSH authentication configured successfully." -ForegroundColor Green
                
                # Run complete setup
                Write-Host "Starting complete VPS setup for $vps_ip..." -ForegroundColor Cyan
                $setupResultObject = Start-CompleteVPSSetup -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
                
                if ($setupResultObject -ne $null) {
                    $setupSuccessful = $true
                    Write-Host "Setup finished successfully for $vps_ip." -ForegroundColor Green
                    # Tambahkan hasil ke array
                    $resultString = "IP: $($setupResultObject.IP) | User: $($setupResultObject.User) | Password: $($setupResultObject.Password)"
                    $setupResults += $resultString
                } else {
                    Write-Host "Remote execution (Start-CompleteVPSSetup) failed for $vps_ip." -ForegroundColor Red
                }
            } else {
                Write-Host "SSH key copy (Copy-SSHKey) failed for $vps_ip." -ForegroundColor Red
            }
            
            if (-not $setupSuccessful) {
                Write-Host "Setup failed for $vps_ip. Retrying in 10 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
                Start-Sleep -Seconds 10
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
