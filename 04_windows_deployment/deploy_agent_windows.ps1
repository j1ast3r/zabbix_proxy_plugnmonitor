# Zabbix Agent Mass Deployment Script for Windows
# Plug & Monitor - Windows Agent Installer
# Supports: Windows 10, 11, Server 2016+

<#
.SYNOPSIS
    Mass deploy Zabbix Agent to Windows computers
.DESCRIPTION
    Installs Zabbix Agent on multiple Windows hosts using WinRM or PsExec
.PARAMETER HostList
    Path to file with list of hosts (one per line)
.PARAMETER Hosts
    Array of hostnames/IPs
.PARAMETER ZabbixServer
    Zabbix Server or Proxy IP
.PARAMETER Method
    Deployment method: WinRM or PsExec
.EXAMPLE
    .\deploy_agent_windows.ps1 -HostList hosts.txt -ZabbixServer 192.168.1.100
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$HostList,

    [Parameter(Mandatory=$false)]
    [string[]]$Hosts,

    [Parameter(Mandatory=$true)]
    [string]$ZabbixServer,

    [Parameter(Mandatory=$false)]
    [ValidateSet('WinRM','PsExec')]
    [string]$Method = 'WinRM',

    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [string]$InstallerPath = ".\zabbix_agent-7.0-windows-amd64-openssl.msi",

    [Parameter(Mandatory=$false)]
    [switch]$EnablePSK,

    [Parameter(Mandatory=$false)]
    [int]$Threads = 5
)

# Configuration
$AgentPort = 10050
$LogFile = "deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$PSKDir = ".\psk_keys"
$ConfigTemplate = ".\config\zabbix_agentd.conf.template"

# Colors
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage

    switch($Level) {
        "ERROR" { Write-ColorOutput $logMessage "Red" }
        "SUCCESS" { Write-ColorOutput $logMessage "Green" }
        "WARNING" { Write-ColorOutput $logMessage "Yellow" }
        default { Write-ColorOutput $logMessage "White" }
    }
}

# Generate PSK key
function New-PSKKey {
    param([string]$Hostname)

    $pskKey = -join ((1..64) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
    $pskIdentity = "PSK-$Hostname"

    # Save to file
    if (!(Test-Path $PSKDir)) {
        New-Item -ItemType Directory -Path $PSKDir -Force | Out-Null
    }

    $keyFile = Join-Path $PSKDir "$Hostname.psk"
    @{
        "hostname" = $Hostname
        "identity" = $pskIdentity
        "key" = $pskKey
    } | ConvertTo-Json | Out-File -FilePath $keyFile -Encoding UTF8

    return @{
        Identity = $pskIdentity
        Key = $pskKey
    }
}

# Check if host is online
function Test-HostOnline {
    param([string]$Hostname)

    $ping = Test-Connection -ComputerName $Hostname -Count 1 -Quiet -ErrorAction SilentlyContinue
    return $ping
}

# Test WinRM connectivity
function Test-WinRMConnection {
    param([string]$Hostname, [PSCredential]$Cred)

    try {
        $session = New-PSSession -ComputerName $Hostname -Credential $Cred -ErrorAction Stop
        Remove-PSSession $session
        return $true
    } catch {
        return $false
    }
}

# Install agent via WinRM
function Install-AgentWinRM {
    param(
        [string]$Hostname,
        [PSCredential]$Cred,
        [string]$ServerIP,
        [hashtable]$PSKInfo
    )

    try {
        Write-Log "[$Hostname] Connecting via WinRM..." "INFO"

        $session = New-PSSession -ComputerName $Hostname -Credential $Cred -ErrorAction Stop

        # Copy installer
        Write-Log "[$Hostname] Copying installer..." "INFO"
        $remoteInstaller = "C:\Windows\Temp\zabbix_agent.msi"
        Copy-Item -Path $InstallerPath -Destination $remoteInstaller -ToSession $session

        # Copy PSK key if enabled
        $remotePSKFile = ""
        if ($EnablePSK -and $PSKInfo) {
            $localPSKFile = [System.IO.Path]::GetTempFileName()
            $PSKInfo.Key | Out-File -FilePath $localPSKFile -Encoding ASCII -NoNewline

            $remotePSKFile = "C:\ProgramData\zabbix\zabbix_agentd.psk"

            Invoke-Command -Session $session -ScriptBlock {
                if (!(Test-Path "C:\ProgramData\zabbix")) {
                    New-Item -ItemType Directory -Path "C:\ProgramData\zabbix" -Force | Out-Null
                }
            }

            Copy-Item -Path $localPSKFile -Destination $remotePSKFile -ToSession $session
            Remove-Item $localPSKFile
        }

        # Install agent
        Write-Log "[$Hostname] Installing Zabbix Agent..." "INFO"

        $installParams = @(
            "/i `"$remoteInstaller`""
            "/qn"
            "/norestart"
            "SERVER=$ServerIP"
            "SERVERACTIVE=$ServerIP"
            "HOSTNAME=$Hostname"
            "ENABLEPATH=1"
            "LOGTYPE=file"
            "LOGFILE=`"C:\Program Files\Zabbix Agent\zabbix_agentd.log`""
        )

        if ($EnablePSK -and $PSKInfo) {
            $installParams += "TLSCONNECT=psk"
            $installParams += "TLSACCEPT=psk"
            $installParams += "TLSPSKIDENTITY=$($PSKInfo.Identity)"
            $installParams += "TLSPSKFILE=`"$remotePSKFile`""
        }

        $installCmd = "msiexec.exe $($installParams -join ' ')"

        $result = Invoke-Command -Session $session -ScriptBlock {
            param($cmd)
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -PassThru -NoNewWindow
            return $process.ExitCode
        } -ArgumentList $installCmd

        if ($result -eq 0) {
            Write-Log "[$Hostname] Agent installed successfully" "SUCCESS"

            # Start service
            Invoke-Command -Session $session -ScriptBlock {
                Start-Service "Zabbix Agent"
                Set-Service "Zabbix Agent" -StartupType Automatic
            }

            Write-Log "[$Hostname] Service started" "SUCCESS"

            # Cleanup
            Invoke-Command -Session $session -ScriptBlock {
                param($installer)
                Remove-Item $installer -Force -ErrorAction SilentlyContinue
            } -ArgumentList $remoteInstaller

            Remove-PSSession $session
            return $true

        } else {
            Write-Log "[$Hostname] Installation failed with exit code: $result" "ERROR"
            Remove-PSSession $session
            return $false
        }

    } catch {
        Write-Log "[$Hostname] Error: $($_.Exception.Message)" "ERROR"
        if ($session) { Remove-PSSession $session }
        return $false
    }
}

# Install agent via PsExec
function Install-AgentPsExec {
    param(
        [string]$Hostname,
        [string]$ServerIP,
        [PSCredential]$Cred
    )

    Write-Log "[$Hostname] PsExec method not fully implemented in this version" "WARNING"
    Write-Log "[$Hostname] Please use WinRM method or implement PsExec logic" "WARNING"
    return $false
}

# Main deployment function
function Deploy-Agent {
    param([string]$Hostname)

    Write-Log "[$Hostname] Starting deployment..." "INFO"

    # Check if online
    if (!(Test-HostOnline -Hostname $Hostname)) {
        Write-Log "[$Hostname] Host is offline" "ERROR"
        return @{
            Hostname = $Hostname
            Status = "Failed"
            Reason = "Host offline"
        }
    }

    # Generate PSK if enabled
    $pskInfo = $null
    if ($EnablePSK) {
        $pskInfo = New-PSKKey -Hostname $Hostname
        Write-Log "[$Hostname] Generated PSK: $($pskInfo.Identity)" "INFO"
    }

    # Deploy based on method
    $success = $false

    if ($Method -eq 'WinRM') {
        if (Test-WinRMConnection -Hostname $Hostname -Cred $Credential) {
            $success = Install-AgentWinRM -Hostname $Hostname -Cred $Credential -ServerIP $ZabbixServer -PSKInfo $pskInfo
        } else {
            Write-Log "[$Hostname] WinRM connection failed" "ERROR"
        }
    } elseif ($Method -eq 'PsExec') {
        $success = Install-AgentPsExec -Hostname $Hostname -ServerIP $ZabbixServer -Cred $Credential
    }

    return @{
        Hostname = $Hostname
        Status = if($success) {"Success"} else {"Failed"}
        PSKIdentity = if($pskInfo) {$pskInfo.Identity} else {""}
    }
}

# Main script execution
Write-ColorOutput "`n=== Zabbix Agent Mass Deployment ===" "Cyan"
Write-ColorOutput "Plug & Monitor - Windows Deployment Tool`n" "Cyan"

# Check prerequisites
if (!(Test-Path $InstallerPath)) {
    Write-Log "Installer not found: $InstallerPath" "ERROR"
    Write-Log "Download from: https://www.zabbix.com/download_agents" "ERROR"
    exit 1
}

# Get credentials if not provided
if (!$Credential) {
    Write-ColorOutput "Enter admin credentials for target computers:" "Yellow"
    $Credential = Get-Credential
}

# Get host list
$targetHosts = @()

if ($HostList -and (Test-Path $HostList)) {
    $targetHosts = Get-Content $HostList | Where-Object { $_ -match '\S' }
    Write-Log "Loaded $($targetHosts.Count) hosts from file" "INFO"
} elseif ($Hosts) {
    $targetHosts = $Hosts
    Write-Log "Using $($targetHosts.Count) hosts from parameter" "INFO"
} else {
    Write-Log "No hosts specified. Use -HostList or -Hosts parameter" "ERROR"
    exit 1
}

Write-Log "Zabbix Server: $ZabbixServer" "INFO"
Write-Log "Deployment method: $Method" "INFO"
Write-Log "PSK Encryption: $(if($EnablePSK){'Enabled'}else{'Disabled'})" "INFO"
Write-Log "Parallel threads: $Threads" "INFO"
Write-ColorOutput "`nStarting deployment...`n" "Green"

# Deploy to all hosts
$results = @()
$jobs = @()

foreach ($host in $targetHosts) {
    # Wait if too many jobs running
    while ((Get-Job -State Running).Count -ge $Threads) {
        Start-Sleep -Seconds 2
    }

    # Start deployment job
    $job = Start-Job -ScriptBlock ${function:Deploy-Agent} -ArgumentList $host
    $jobs += $job
}

# Wait for all jobs to complete
Write-Log "`nWaiting for all deployments to complete..." "INFO"
$jobs | Wait-Job | Out-Null

# Collect results
foreach ($job in $jobs) {
    $result = Receive-Job -Job $job
    $results += $result
    Remove-Job -Job $job
}

# Summary
Write-ColorOutput "`n=== Deployment Summary ===" "Cyan"
$successCount = ($results | Where-Object {$_.Status -eq "Success"}).Count
$failedCount = ($results | Where-Object {$_.Status -eq "Failed"}).Count

Write-Log "Total hosts: $($results.Count)" "INFO"
Write-Log "Successful: $successCount" "SUCCESS"
Write-Log "Failed: $failedCount" "ERROR"

# Detailed results
Write-ColorOutput "`nDetailed Results:" "Yellow"
$results | Format-Table -AutoSize

# Export results
$resultsFile = "deployment_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $resultsFile -NoTypeInformation
Write-Log "`nResults exported to: $resultsFile" "INFO"
Write-Log "Log file: $LogFile" "INFO"

if ($EnablePSK) {
    Write-Log "PSK keys saved to: $PSKDir" "INFO"
}

Write-ColorOutput "`nDeployment completed!`n" "Green"