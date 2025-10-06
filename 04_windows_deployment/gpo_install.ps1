# Zabbix Agent GPO Installation Script
# Deploy via Group Policy - Computer Startup Script
# Place installer and this script in SYSVOL

param(
    [string]$ZabbixServer = "192.168.1.100",
    [string]$InstallerPath = "\\domain.local\SYSVOL\domain.local\scripts\zabbix_agent.msi",
    [string]$PSKFile = "\\domain.local\SYSVOL\domain.local\scripts\zabbix_agentd.psk",
    [switch]$EnablePSK
)

# Log file
$LogPath = "C:\Windows\Temp\zabbix_gpo_install.log"

function Write-InstallLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogPath -Value "[$timestamp] $Message"
}

Write-InstallLog "=== Zabbix Agent GPO Installation Started ==="
Write-InstallLog "Computer: $env:COMPUTERNAME"
Write-InstallLog "User: $env:USERNAME"
Write-InstallLog "Zabbix Server: $ZabbixServer"

# Check if already installed
$installed = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "Zabbix Agent*" }

if ($installed) {
    Write-InstallLog "Zabbix Agent already installed (Version: $($installed.Version))"

    # Check if service is running
    $service = Get-Service "Zabbix Agent" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Write-InstallLog "Starting Zabbix Agent service..."
        Start-Service "Zabbix Agent"
    }

    Write-InstallLog "Installation check completed. Exiting."
    exit 0
}

Write-InstallLog "Zabbix Agent not installed. Proceeding with installation..."

# Check installer exists
if (!(Test-Path $InstallerPath)) {
    Write-InstallLog "ERROR: Installer not found at $InstallerPath"
    exit 1
}

# Copy installer locally
$localInstaller = "C:\Windows\Temp\zabbix_agent.msi"
Write-InstallLog "Copying installer to local temp..."

try {
    Copy-Item -Path $InstallerPath -Destination $localInstaller -Force
    Write-InstallLog "Installer copied successfully"
} catch {
    Write-InstallLog "ERROR: Failed to copy installer - $($_.Exception.Message)"
    exit 1
}

# Prepare installation parameters
$installArgs = @(
    "/i `"$localInstaller`""
    "/qn"
    "/norestart"
    "SERVER=$ZabbixServer"
    "SERVERACTIVE=$ZabbixServer"
    "HOSTNAME=$env:COMPUTERNAME"
    "ENABLEPATH=1"
    "LOGTYPE=file"
)

# Handle PSK encryption
if ($EnablePSK -and (Test-Path $PSKFile)) {
    Write-InstallLog "PSK encryption enabled"

    # Create Zabbix data directory
    $zabbixDataDir = "C:\ProgramData\zabbix"
    if (!(Test-Path $zabbixDataDir)) {
        New-Item -ItemType Directory -Path $zabbixDataDir -Force | Out-Null
    }

    # Copy PSK file
    $localPSKFile = Join-Path $zabbixDataDir "zabbix_agentd.psk"
    Copy-Item -Path $PSKFile -Destination $localPSKFile -Force

    $installArgs += "TLSCONNECT=psk"
    $installArgs += "TLSACCEPT=psk"
    $installArgs += "TLSPSKIDENTITY=PSK-$env:COMPUTERNAME"
    $installArgs += "TLSPSKFILE=`"$localPSKFile`""

    Write-InstallLog "PSK file copied to $localPSKFile"
}

# Install
Write-InstallLog "Starting installation..."
$installCommand = "msiexec.exe $($installArgs -join ' ')"
Write-InstallLog "Command: $installCommand"

try {
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList ($installArgs -join ' ') -Wait -PassThru -NoNewWindow
    $exitCode = $process.ExitCode

    Write-InstallLog "Installation completed with exit code: $exitCode"

    if ($exitCode -eq 0) {
        Write-InstallLog "SUCCESS: Zabbix Agent installed successfully"

        # Verify service
        Start-Sleep -Seconds 5
        $service = Get-Service "Zabbix Agent" -ErrorAction SilentlyContinue

        if ($service) {
            Write-InstallLog "Service status: $($service.Status)"

            if ($service.Status -ne "Running") {
                Write-InstallLog "Starting service..."
                Start-Service "Zabbix Agent"
            }

            # Set to automatic startup
            Set-Service "Zabbix Agent" -StartupType Automatic
            Write-InstallLog "Service configured for automatic startup"
        }

        # Cleanup
        Remove-Item $localInstaller -Force -ErrorAction SilentlyContinue
        Write-InstallLog "Temporary files cleaned up"

    } else {
        Write-InstallLog "ERROR: Installation failed with exit code $exitCode"
    }

} catch {
    Write-InstallLog "ERROR: Installation exception - $($_.Exception.Message)"
    exit 1
}

Write-InstallLog "=== Zabbix Agent GPO Installation Completed ==="