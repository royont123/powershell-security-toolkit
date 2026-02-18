<#
.SYNOPSIS
    System Health and Security Checker for Windows
.DESCRIPTION
    Performs automated security and health checks including Windows Update status,
    firewall configuration, antivirus status, running services, and disk space monitoring.
.NOTES
    Author: royont123
    Requires: PowerShell 5.1+, Administrator privileges recommended
.EXAMPLE
    .\System-Health-Checker.ps1
#>

#Requires -Version 5.1

# Color coding function
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Status # "Good", "Warning", "Error", "Info"
    )
    
    switch ($Status) {
        "Good"    { Write-Host "✓ $Message" -ForegroundColor Green }
        "Warning" { Write-Host "⚠ $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "✗ $Message" -ForegroundColor Red }
        "Info"    { Write-Host "ℹ $Message" -ForegroundColor Cyan }
        default   { Write-Host $Message }
    }
}

# Banner
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   System Health & Security Checker" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput "Not running as Administrator - some checks may be limited" "Warning"
} else {
    Write-ColorOutput "Running with Administrator privileges" "Good"
}

Write-Host "`n--- Windows Update Status ---" -ForegroundColor Yellow

try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
    
    $PendingUpdates = $SearchResult.Updates.Count
    
    if ($PendingUpdates -eq 0) {
        Write-ColorOutput "No pending Windows updates" "Good"
    } else {
        Write-ColorOutput "$PendingUpdates pending Windows update(s) found" "Warning"
    }
} catch {
    Write-ColorOutput "Unable to check Windows Update status: $($_.Exception.Message)" "Error"
}

Write-Host "`n--- Firewall Status ---" -ForegroundColor Yellow

try {
    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
    
    foreach ($Profile in $FirewallProfiles) {
        if ($Profile.Enabled -eq $true) {
            Write-ColorOutput "$($Profile.Name) Profile: Enabled" "Good"
        } else {
            Write-ColorOutput "$($Profile.Name) Profile: Disabled" "Error"
        }
    }
} catch {
    Write-ColorOutput "Unable to check firewall status: $($_.Exception.Message)" "Error"
}

Write-Host "`n--- Antivirus Status ---" -ForegroundColor Yellow

try {
    # Windows Defender status
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
    
    if ($DefenderStatus.AntivirusEnabled) {
        Write-ColorOutput "Windows Defender: Enabled" "Good"
        
        # Check signature age
        $SignatureAge = (Get-Date) - $DefenderStatus.AntivirusSignatureLastUpdated
        if ($SignatureAge.Days -eq 0) {
            Write-ColorOutput "Virus definitions: Up to date (Updated today)" "Good"
        } elseif ($SignatureAge.Days -le 2) {
            Write-ColorOutput "Virus definitions: $($SignatureAge.Days) day(s) old" "Good"
        } else {
            Write-ColorOutput "Virus definitions: $($SignatureAge.Days) day(s) old - Update recommended" "Warning"
        }
        
        if ($DefenderStatus.RealTimeProtectionEnabled) {
            Write-ColorOutput "Real-time protection: Enabled" "Good"
        } else {
            Write-ColorOutput "Real-time protection: Disabled" "Error"
        }
    } else {
        Write-ColorOutput "Windows Defender: Disabled" "Warning"
    }
} catch {
    Write-ColorOutput "Unable to check Windows Defender status: $($_.Exception.Message)" "Error"
}

Write-Host "`n--- Critical Services Status ---" -ForegroundColor Yellow

$CriticalServices = @(
    "Windows Defender Antivirus Service",
    "Windows Update",
    "Windows Firewall",
    "Security Center"
)

foreach ($ServiceName in $CriticalServices) {
    try {
        $Service = Get-Service -DisplayName "*$ServiceName*" -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($Service) {
            if ($Service.Status -eq "Running") {
                Write-ColorOutput "$($Service.DisplayName): Running" "Good"
            } else {
                Write-ColorOutput "$($Service.DisplayName): $($Service.Status)" "Warning"
            }
        }
    } catch {
        Write-ColorOutput "Unable to check $ServiceName" "Error"
    }
}

Write-Host "`n--- Disk Space Status ---" -ForegroundColor Yellow

try {
    $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
    
    foreach ($Drive in $Drives) {
        $PercentFree = [math]::Round(($Drive.Free / ($Drive.Used + $Drive.Free)) * 100, 2)
        $FreeGB = [math]::Round($Drive.Free / 1GB, 2)
        
        if ($PercentFree -gt 20) {
            Write-ColorOutput "Drive $($Drive.Name): ${FreeGB}GB free (${PercentFree}%)" "Good"
        } elseif ($PercentFree -gt 10) {
            Write-ColorOutput "Drive $($Drive.Name): ${FreeGB}GB free (${PercentFree}%)" "Warning"
        } else {
            Write-ColorOutput "Drive $($Drive.Name): ${FreeGB}GB free (${PercentFree}%) - Low disk space!" "Error"
        }
    }
} catch {
    Write-ColorOutput "Unable to check disk space: $($_.Exception.Message)" "Error"
}

Write-Host "`n--- System Information ---" -ForegroundColor Yellow

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
    
    Write-ColorOutput "Computer Name: $($Computer.Name)" "Info"
    Write-ColorOutput "OS: $($OS.Caption) $($OS.Version)" "Info"
    Write-ColorOutput "Last Boot: $($OS.LastBootUpTime)" "Info"
    
    $Uptime = (Get-Date) - $OS.LastBootUpTime
    Write-ColorOutput "Uptime: $($Uptime.Days) days, $($Uptime.Hours) hours" "Info"
} catch {
    Write-ColorOutput "Unable to retrieve system information: $($_.Exception.Message)" "Error"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "         Health Check Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Summary
Write-Host "Scan completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
