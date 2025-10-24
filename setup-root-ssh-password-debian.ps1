# complete-vps-setup.ps1 - Complete VPS Setup Script for PowerShell
# Fixed version - No CRLF issues, better error handling

# Fungsi untuk generate SSH key
function Generate-SSHKey {
    Write-Host "Generating public/private rsa key pair..." -ForegroundColor Green
    
    # Determine home directory
    $SSH_DIR = Join-Path $HOME ".ssh"
    
    # Create .ssh directory if it doesn't exist
    if (!(Test-Path $SSH_DIR)) {
        New-Item -ItemType Directory -Path $SSH_DIR -Force | Out-Null
    }
    
    # Hapus file key yang sudah ada jika ada
    $privateKeyPath = Join-Path $SSH_DIR "id_rsa"
    $publicKeyPath = Join-Path $SSH_DIR "id_rsa.pub"
    
    if (Test-Path $privateKeyPath) {
        Write-Host "$privateKeyPath already exists." -ForegroundColor Yellow
        Write-Host "Overwriting existing keys..." -ForegroundColor Yellow
        Remove-Item $privateKeyPath -Force -ErrorAction SilentlyContinue
        Remove-Item $publicKeyPath -Force -ErrorAction SilentlyContinue
    }
    
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
                "chmod +x /tmp/copy_key.sh && bash /tmp/copy_key.sh"
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
            "-i", $publicKeyPath,
            "debian@$VpsIP"
        )
        
        $sshCopyProcess = Start-Process -FilePath "ssh-copy-id" -ArgumentList $sshCopyArgs -Wait -PassThru -NoNewWindow
        
        if ($sshCopyProcess.ExitCode -eq 0) {
            Write-Host "SSH key copied successfully using ssh-copy-id." -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "ssh-copy-id also failed." -ForegroundColor Yellow
    }
    
    Write-Host "Warning: SSH key copy methods failed, but continuing..." -ForegroundColor Red
    return $false
}

# Fungsi untuk membuat setup script yang akan dijalankan di VPS (UNIX format)
function New-VPSSetupScript {
    # Script dalam format UNIX (LF line endings only)
    $setupScript = @'
#!/bin/bash

set -e

echo "=== Starting Automated System Setup for Debian ==="

# Function to generate random password
generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c 16
    echo
}

# Function to update system packages
update_system() {
    echo "[1/7] Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
    echo "System updated successfully."
}

# Function to set root password
set_root_password() {
    echo "[2/7] Setting root password..."
    ROOT_PASS=$(generate_password)
    echo "root:$ROOT_PASS" | chpasswd
    echo "Root password set successfully."
    echo "Generated password: $ROOT_PASS"
}

# Function to configure debian user
setup_debian_user() {
    echo "[3/7] Configuring debian user..."
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
    echo "[4/7] Configuring /etc/hosts..."
    local hostname=$(hostname)
    cp /etc/hosts /etc/hosts.backup
    sed -i "/$hostname$/d" /etc/hosts
    echo "127.0.0.1 $hostname" >> /etc/hosts
    echo "Hosts file configured."
}

# Function to install and configure SSH
setup_ssh() {
    echo "[5/7] Installing and configuring SSH..."
    if ! command -v ssh >/dev/null 2>&1; then
        apt-get install -y openssh-server
    fi
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create new config
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

# Function to restart services
restart_services() {
    echo "[6/7] Restarting SSH service..."
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
    echo "SSH service restarted."
}

# Function to get system info
get_system_info() {
    echo "[7/7] Gathering system information..."
    if command -v curl >/dev/null 2>&1; then
        PUBLIC_IP=$(curl -s -m 5 ifconfig.me || curl -s -m 5 ipinfo.io/ip || curl -s -m 5 icanhazip.com)
    else
        apt-get install -y curl
        PUBLIC_IP=$(curl -s -m 5 ifconfig.me || curl -s -m 5 ipinfo.io/ip || curl -s -m 5 icanhazip.com)
    fi
    
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(hostname -I | awk '{print $1}')
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
    echo "6. Restart services"
    echo "=============================================="
    
    update_system
    set_root_password
    setup_debian_user
    configure_hosts
    setup_ssh
    restart_services
    get_system_info
    
    echo ""
    echo "=== SETUP COMPLETED SUCCESSFULLY ==="
    echo "IPv4 Address: $PUBLIC_IP"
    echo "SSH User: root"
    echo "Root Password: $ROOT_PASS"
    echo "SSH Port: 22"
    # echo ""
    # echo "You can now connect using:"
    # echo "ssh root@$PUBLIC_IP"
    # echo ""
    # echo "=== IMPORTANT ==="
    # echo "Save the root password shown above!"
    echo "================================"
    
    # Save password to file
    # echo "Root password: $ROOT_PASS" > /root/password.txt
    # chmod 600 /root/password.txt
    # echo "Password saved to /root/password.txt"
}

# Run main function and handle errors
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
    Write-Host "Script size: $((Get-Item $tempFile).Length) bytes" -ForegroundColor Gray
    
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
    
    Write-Host "Executing: scp [args] $tempFile debian@${VpsIP}:/tmp/vps_setup.sh" -ForegroundColor Gray
    
    $scpResult = & scp @scpArgs 2>&1
    
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
        
        Write-Host "Executing: ssh [args] debian@$VpsIP 'sudo bash /tmp/vps_setup.sh'" -ForegroundColor Gray
        
        # Jalankan SSH dan tampilkan output real-time
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "ssh"
        $processInfo.Arguments = $sshArgs
        $processInfo.RedirectStandardOutput = $false
        $processInfo.RedirectStandardError = $false
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $false
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        Write-Host "Starting remote setup process..." -ForegroundColor Yellow
        $process.Start() | Out-Null
        
        # Tunggu proses selesai dengan timeout
        $timeout = 600 # 10 minutes
        $startTime = Get-Date
        
        while (!$process.HasExited) {
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -gt $timeout) {
                Write-Host "Timeout reached, killing process..." -ForegroundColor Red
                $process.Kill()
                break
            }
            Start-Sleep -Seconds 5
            Write-Host "Still running... ($([math]::Round($elapsed.TotalSeconds)) seconds)" -ForegroundColor Gray
        }
        
        if ($process.ExitCode -eq 0) {
            Write-Host "VPS setup completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "SSH process completed with exit code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Error: Failed to copy setup script to VPS." -ForegroundColor Red
        Write-Host "SCP Output: $scpResult" -ForegroundColor Red
    }
    
    # Cleanup
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

# Main script function
function Main {
    param(
        [string[]]$Args
    )
    
    Write-Host "=== COMPLETE VPS SETUP AUTOMATION FOR DEBIAN ===" -ForegroundColor Cyan
    Write-Host "Fixed Version - No CRLF Issues" -ForegroundColor Green
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
    
    # Get VPS IP
    if ($Args.Count -ge 1 -and $Args[0] -match '^\d+\.\d+\.\d+\.\d+$') {
        $vps_ip = $Args[0]
        Write-Host "Using VPS IP: $vps_ip" -ForegroundColor Green
    } else {
        do {
            $vps_ip = Read-Host "Masukkan IP VPS"
            if ($vps_ip -notmatch '^\d+\.\d+\.\d+\.\d+$') {
                Write-Host "Invalid IP format. Please enter a valid IP address." -ForegroundColor Red
            }
        } while ($vps_ip -notmatch '^\d+\.\d+\.\d+\.\d+$')
    }
    
    # Set global SSH_DIR
    $Global:SSH_DIR = $sshInfo.SSH_DIR
    
    # Clean known_hosts
    Clean-KnownHosts -VpsIP $vps_ip
    
    # Copy SSH key
    Write-Host "Setting up SSH key authentication..." -ForegroundColor Cyan
    $keyCopied = Copy-SSHKey -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
    
    if ($keyCopied) {
        Write-Host "SSH authentication configured successfully." -ForegroundColor Green
    } else {
        Write-Host "SSH authentication may have issues, but continuing..." -ForegroundColor Yellow
    }
    
    # Run complete setup
    Write-Host "Starting complete VPS setup..." -ForegroundColor Cyan
    Start-CompleteVPSSetup -VpsIP $vps_ip -SSHKeyPath $sshInfo.PrivateKey
    
    # Write-Host ""
    # Write-Host "=== SETUP PROCESS COMPLETED ===" -ForegroundColor Green
    # Write-Host "Check the output above for root password and connection details." -ForegroundColor White
    # Write-Host "Connect using: ssh root@$vps_ip" -ForegroundColor Yellow
    # Write-Host ""
    # Write-Host "SSH Keys location:" -ForegroundColor Cyan
    # Write-Host "Private: $($sshInfo.PrivateKey)" -ForegroundColor White
    # Write-Host "Public:  $($sshInfo.PublicKey)" -ForegroundColor White
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
