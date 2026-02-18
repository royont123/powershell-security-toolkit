<#
.SYNOPSIS
    Windows Event Log Analyzer for Security Events
.DESCRIPTION
    Analyzes Windows Event Logs for security-relevant events including failed logins,
    account lockouts, and security audit failures. Useful for incident response and forensics.
.PARAMETER Days
    Number of days to look back in logs (default: 1)
.PARAMETER ExportPath
    Optional path to export results to CSV file
.NOTES
    Author: royont123
    Requires: PowerShell 5.1+, Administrator privileges recommended
.EXAMPLE
    .\Log-Analyzer.ps1
.EXAMPLE
    .\Log-Analyzer.ps1 -Days 7
.EXAMPLE
    .\Log-Analyzer.ps1 -Days 3 -ExportPath "C:\Reports\security-events.csv"
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory=$false)]
    [int]$Days = 1,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ""
)

# Color coding function
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Status
    )
    
    switch ($Status) {
        "Good"    { Write-Host "✓ $Message" -ForegroundColor Green }
        "Warning" { Write-Host "⚠ $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "✗ $Message" -ForegroundColor Red }
        "Info"    { Write-Host "ℹ $Message" -ForegroundColor Cyan }
        "Header"  { Write-Host $Message -ForegroundColor Yellow }
        default   { Write-Host $Message }
    }
}

# Banner
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     Windows Event Log Analyzer" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput "Warning: Not running as Administrator - some events may not be accessible" "Warning"
} else {
    Write-ColorOutput "Running with Administrator privileges" "Good"
}

# Calculate time range
$StartTime = (Get-Date).AddDays(-$Days)
Write-ColorOutput "Analyzing events from $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to now ($Days day(s))" "Info"
Write-Host ""

# Initialize results array
$AllEvents = @()

# Event IDs to monitor
$EventIDsToCheck = @{
    4625 = "Failed Login Attempt"
    4740 = "Account Lockout"
    4648 = "Logon with Explicit Credentials"
    4672 = "Special Privileges Assigned to New Logon"
    4720 = "User Account Created"
    4726 = "User Account Deleted"
    4732 = "Member Added to Security-Enabled Local Group"
    4733 = "Member Removed from Security-Enabled Local Group"
    1102 = "Audit Log Cleared"
}

Write-ColorOutput "--- Searching Security Event Log ---" "Header"

foreach ($EventID in $EventIDsToCheck.Keys) {
    try {
        Write-Host "Checking for Event ID $EventID ($($EventIDsToCheck[$EventID]))..." -NoNewline
        
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $EventID
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
        
        if ($Events) {
            $EventCount = ($Events | Measure-Object).Count
            Write-Host " Found $EventCount" -ForegroundColor Yellow
            
            foreach ($Event in $Events) {
                $AllEvents += [PSCustomObject]@{
                    TimeCreated = $Event.TimeCreated
                    EventID = $Event.Id
                    EventType = $EventIDsToCheck[$Event.Id]
                    Message = $Event.Message.Split("`n")[0]
                    MachineName = $Event.MachineName
                    UserID = $Event.UserId
                }
            }
        } else {
            Write-Host " None found" -ForegroundColor Green
        }
    } catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-ColorOutput "--- Analysis Summary ---" "Header"

if ($AllEvents.Count -eq 0) {
    Write-ColorOutput "No suspicious security events found in the specified time range" "Good"
} else {
    Write-ColorOutput "Total security events found: $($AllEvents.Count)" "Warning"
    Write-Host ""
    
    # Group by event type
    $EventsByType = $AllEvents | Group-Object EventType | Sort-Object Count -Descending
    
    Write-ColorOutput "Breakdown by Event Type:" "Info"
    foreach ($Group in $EventsByType) {
        Write-Host "  • $($Group.Name): $($Group.Count)" -ForegroundColor Cyan
    }
    
    Write-Host ""
    
    # Show most recent events
    Write-ColorOutput "Most Recent Events (Top 10):" "Info"
    $AllEvents | Sort-Object TimeCreated -Descending | Select-Object -First 10 | Format-Table TimeCreated, EventType, MachineName -AutoSize
    
    # Failed login analysis
    $FailedLogins = $AllEvents | Where-Object { $_.EventID -eq 4625 }
    if ($FailedLogins) {
        Write-ColorOutput "`n⚠ Failed Login Analysis:" "Warning"
        Write-Host "  Total failed login attempts: $($FailedLogins.Count)" -ForegroundColor Yellow
        
        # Group by time to detect patterns
        $FailedByHour = $FailedLogins | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:00') } | Sort-Object Count -Descending | Select-Object -First 5
        
        if ($FailedByHour) {
            Write-Host "`n  Peak failed login hours:" -ForegroundColor Yellow
            foreach ($Hour in $FailedByHour) {
                Write-Host "    • $($Hour.Name): $($Hour.Count) attempts" -ForegroundColor Cyan
            }
        }
    }
    
    # Account lockout analysis
    $Lockouts = $AllEvents | Where-Object { $_.EventID -eq 4740 }
    if ($Lockouts) {
        Write-ColorOutput "`n⚠ Account Lockouts Detected:" "Error"
        Write-Host "  Total lockouts: $($Lockouts.Count)" -ForegroundColor Red
        $Lockouts | Format-Table TimeCreated, MachineName -AutoSize
    }
    
    # Audit log cleared
    $LogCleared = $AllEvents | Where-Object { $_.EventID -eq 1102 }
    if ($LogCleared) {
        Write-ColorOutput "`n✗ CRITICAL: Audit Log Cleared!" "Error"
        $LogCleared | Format-Table TimeCreated, MachineName -AutoSize
    }
    
    # Export to CSV if requested
    if ($ExportPath -ne "") {
        try {
            $AllEvents | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-ColorOutput "`nResults exported to: $ExportPath" "Good"
        } catch {
            Write-ColorOutput "`nFailed to export results: $($_.Exception.Message)" "Error"
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "         Analysis Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Scan completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Recommendations
if ($AllEvents.Count -gt 0) {
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    Write-Host "  • Review events marked as warnings or errors" -ForegroundColor White
    Write-Host "  • Investigate patterns in failed login attempts" -ForegroundColor White
    Write-Host "  • Verify any account changes are authorized" -ForegroundColor White
    Write-Host "  • Consider enabling additional auditing if needed" -ForegroundColor White
}
