<#
.SYNOPSIS
    System Information Reporter
.DESCRIPTION
    Generates comprehensive system information reports including hardware specs,
    OS details, network configuration, disk usage, and installed software.
.PARAMETER Format
    Output format: "Text" or "HTML" (default: Text)
.PARAMETER OutputPath
    Path to save the report. If not specified, displays to console.
.NOTES
    Author: royont123
    Requires: PowerShell 5.1+, Administrator privileges recommended for complete data
.EXAMPLE
    .\System-Info-Reporter.ps1
.EXAMPLE
    .\System-Info-Reporter.ps1 -Format HTML -OutputPath "C:\Reports\system-report.html"
.EXAMPLE
    .\System-Info-Reporter.ps1 -OutputPath "C:\Reports\system-info.txt"
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Text", "HTML")]
    [string]$Format = "Text",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ""
)

# Color coding function
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Banner
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     System Information Reporter" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput "⚠ Not running as Administrator - some information may be limited" "Yellow"
} else {
    Write-ColorOutput "✓ Running with Administrator privileges" "Green"
}

Write-Host "`nGathering system information..." -ForegroundColor Cyan
Write-Host ""

# Initialize report content
$ReportContent = @()
$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to add section to report
function Add-ReportSection {
    param(
        [string]$Title,
        [string]$Content
    )
    
    if ($Format -eq "HTML") {
        $script:ReportContent += "<h2>$Title</h2>"
        $script:ReportContent += "<pre>$Content</pre>"
    } else {
        $script:ReportContent += "`n========================================`n"
        $script:ReportContent += "$Title`n"
        $script:ReportContent += "========================================`n"
        $script:ReportContent += "$Content`n"
    }
}

# 1. COMPUTER INFORMATION
Write-Host "[1/7] Collecting computer information..." -ForegroundColor Yellow

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $BIOS = Get-CimInstance -ClassName Win32_BIOS
    
    $ComputerInfo = @"
Computer Name: $($ComputerSystem.Name)
Domain: $($ComputerSystem.Domain)
Manufacturer: $($ComputerSystem.Manufacturer)
Model: $($ComputerSystem.Model)
System Type: $($ComputerSystem.SystemType)
BIOS Version: $($BIOS.SMBIOSBIOSVersion)
BIOS Manufacturer: $($BIOS.Manufacturer)
Serial Number: $($BIOS.SerialNumber)
"@
    
    Add-ReportSection "Computer Information" $ComputerInfo
    Write-ColorOutput "  ✓ Computer information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting computer information: $($_.Exception.Message)" "Red"
}

# 2. OPERATING SYSTEM
Write-Host "[2/7] Collecting operating system information..." -ForegroundColor Yellow

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $Uptime = (Get-Date) - $OS.LastBootUpTime
    
    $OSInfo = @"
Operating System: $($OS.Caption)
Version: $($OS.Version)
Build Number: $($OS.BuildNumber)
Architecture: $($OS.OSArchitecture)
Install Date: $($OS.InstallDate)
Last Boot: $($OS.LastBootUpTime)
Uptime: $($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes
System Drive: $($OS.SystemDrive)
Windows Directory: $($OS.WindowsDirectory)
"@
    
    Add-ReportSection "Operating System" $OSInfo
    Write-ColorOutput "  ✓ Operating system information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting OS information: $($_.Exception.Message)" "Red"
}

# 3. PROCESSOR INFORMATION
Write-Host "[3/7] Collecting processor information..." -ForegroundColor Yellow

try {
    $Processors = Get-CimInstance -ClassName Win32_Processor
    $ProcessorInfo = ""
    
    $ProcessorCount = 0
    foreach ($Processor in $Processors) {
        $ProcessorCount++
        $ProcessorInfo += "Processor #" + $ProcessorCount + ":`n"
        $ProcessorInfo += "  Name: " + $Processor.Name + "`n"
        $ProcessorInfo += "  Manufacturer: " + $Processor.Manufacturer + "`n"
        $ProcessorInfo += "  Cores: " + $Processor.NumberOfCores + "`n"
        $ProcessorInfo += "  Logical Processors: " + $Processor.NumberOfLogicalProcessors + "`n"
        $ProcessorInfo += "  Max Clock Speed: " + $Processor.MaxClockSpeed + " MHz`n"
        $ProcessorInfo += "  Current Load: " + $Processor.LoadPercentage + "%`n`n"
    }
    
    Add-ReportSection "Processor Information" $ProcessorInfo
    Write-ColorOutput "  ✓ Processor information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting processor information: $($_.Exception.Message)" "Red"
}

# 4. MEMORY INFORMATION
Write-Host "[4/7] Collecting memory information..." -ForegroundColor Yellow

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
    $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
    $UsedMemoryGB = [math]::Round($TotalMemoryGB - $FreeMemoryGB, 2)
    $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 2)
    
    $MemoryInfo = @"
Total Physical Memory: $TotalMemoryGB GB
Used Memory: $UsedMemoryGB GB
Free Memory: $FreeMemoryGB GB
Memory Usage: $MemoryUsagePercent%
"@
    
    Add-ReportSection "Memory Information" $MemoryInfo
    Write-ColorOutput "  ✓ Memory information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting memory information: $($_.Exception.Message)" "Red"
}

# 5. DISK INFORMATION
Write-Host "[5/7] Collecting disk information..." -ForegroundColor Yellow

try {
    $Disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $DiskInfo = ""
    
    foreach ($Disk in $Disks) {
        $SizeGB = [math]::Round($Disk.Size / 1GB, 2)
        $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
        $UsedGB = [math]::Round($SizeGB - $FreeGB, 2)
        $PercentFree = [math]::Round(($FreeGB / $SizeGB) * 100, 2)
        
        $DiskInfo += @"
Drive $($Disk.DeviceID)
  Volume Name: $($Disk.VolumeName)
  File System: $($Disk.FileSystem)
  Total Size: $SizeGB GB
  Used Space: $UsedGB GB
  Free Space: $FreeGB GB
  Percent Free: $PercentFree%

"@
    }
    
    Add-ReportSection "Disk Information" $DiskInfo
    Write-ColorOutput "  ✓ Disk information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting disk information: $($_.Exception.Message)" "Red"
}

# 6. NETWORK INFORMATION
Write-Host "[6/7] Collecting network information..." -ForegroundColor Yellow

try {
    $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    $NetworkInfo = ""
    
    foreach ($Adapter in $NetworkAdapters) {
        $NetworkInfo += @"
Adapter: $($Adapter.Description)
  MAC Address: $($Adapter.MACAddress)
  IP Address: $($Adapter.IPAddress -join ', ')
  Subnet Mask: $($Adapter.IPSubnet -join ', ')
  Default Gateway: $($Adapter.DefaultIPGateway -join ', ')
  DNS Servers: $($Adapter.DNSServerSearchOrder -join ', ')
  DHCP Enabled: $($Adapter.DHCPEnabled)

"@
    }
    
    Add-ReportSection "Network Information" $NetworkInfo
    Write-ColorOutput "  ✓ Network information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting network information: $($_.Exception.Message)" "Red"
}

# 7. INSTALLED SOFTWARE (Top 20)
Write-Host "[7/7] Collecting installed software (this may take a moment)..." -ForegroundColor Yellow

try {
    $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                Where-Object { $_.DisplayName -ne $null } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                Sort-Object DisplayName |
                Select-Object -First 20
    
    $SoftwareInfo = $Software | ForEach-Object {
        "$($_.DisplayName) - Version: $($_.DisplayVersion) (Publisher: $($_.Publisher))"
    } | Out-String
    
    Add-ReportSection "Installed Software (Top 20)" $SoftwareInfo
    Write-ColorOutput "  ✓ Software information collected" "Green"
} catch {
    Write-ColorOutput "  ✗ Error collecting software information: $($_.Exception.Message)" "Red"
}

# Build final report
Write-Host "`nGenerating report..." -ForegroundColor Cyan

if ($Format -eq "HTML") {
    $HTMLHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Information Report - $env:COMPUTERNAME</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; background-color: #ecf0f1; padding: 10px; border-left: 4px solid #3498db; }
        pre { background-color: white; padding: 15px; border: 1px solid #ddd; border-radius: 4px; overflow-x: auto; }
        .header { background-color: #3498db; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }
        .footer { margin-top: 30px; padding: 10px; background-color: #ecf0f1; border-radius: 4px; text-align: center; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Information Report</h1>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>Report Generated: $ReportDate</p>
    </div>
"@
    
    $HTMLFooter = @"
    <div class="footer">
        <p>Report generated by PowerShell Security Toolkit | Author: royont123</p>
    </div>
</body>
</html>
"@
    
    $FinalReport = $HTMLHeader + ($ReportContent -join "`n") + $HTMLFooter
} else {
    $TextHeader = @"
========================================
    SYSTEM INFORMATION REPORT
========================================
Computer: $env:COMPUTERNAME
Report Generated: $ReportDate
========================================
"@
    
    $FinalReport = $TextHeader + ($ReportContent -join "`n")
}

# Output or save report
if ($OutputPath -ne "") {
    try {
        $FinalReport | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-ColorOutput "`n✓ Report saved to: $OutputPath" "Green"
        
        if ($Format -eq "HTML") {
            Write-ColorOutput "  You can open this file in a web browser" "Cyan"
        }
    } catch {
        Write-ColorOutput "`n✗ Error saving report: $($_.Exception.Message)" "Red"
        Write-Host "`nDisplaying report to console instead:`n"
        Write-Host $FinalReport
    }
} else {
    Write-Host "`n$FinalReport"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "      Report Generation Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
