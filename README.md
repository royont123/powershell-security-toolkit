# powershell-security-toolkit
A collection of PowerShell scripts for security monitoring, log analysis, and system reporting
# 🛡️ PowerShell Security Toolkit

A collection of PowerShell scripts designed for security monitoring, log analysis, and system reporting. Built to help IT professionals and security analysts automate routine security checks and investigate potential issues.

## 📋 Overview

This toolkit contains three core scripts that every IT/cybersecurity professional can use:

1. **System Health & Security Checker** - Monitors system security posture
2. **Log Analyzer** - Investigates Windows Event Logs for security events
3. **System Information Reporter** - Generates comprehensive system reports

## 🚀 Scripts

### 1. System-Health-Checker.ps1
Performs automated security and health checks on Windows systems.

**Features:**
- ✅ Windows Update status
- ✅ Firewall configuration check
- ✅ Antivirus status verification
- ✅ Running services audit
- ✅ Disk space monitoring
- ✅ Color-coded output for easy reading

**Usage:**
```powershell
.\scripts\System-Health-Checker.ps1
```

### 2. Log-Analyzer.ps1
Analyzes Windows Event Logs for security-relevant events and suspicious activities.

**Features:**
- 🔍 Failed login attempt detection
- 🔍 Account lockout events
- 🔍 Security audit failures
- 🔍 Custom time range filtering
- 🔍 Export results to CSV
- 🔍 Summary statistics

**Usage:**
```powershell
# Analyze last 24 hours
.\scripts\Log-Analyzer.ps1

# Analyze last 7 days
.\scripts\Log-Analyzer.ps1 -Days 7

# Export to CSV
.\scripts\Log-Analyzer.ps1 -ExportPath "C:\Reports\security-events.csv"
```

### 3. System-Info-Reporter.ps1
Generates detailed system information reports for documentation and troubleshooting.

**Features:**
- 💻 Hardware specifications
- 💻 Operating system details
- 💻 Network configuration
- 💻 Disk usage statistics
- 💻 Installed software list
- 💻 HTML or text report output

**Usage:**
```powershell
# Generate text report
.\scripts\System-Info-Reporter.ps1

# Generate HTML report
.\scripts\System-Info-Reporter.ps1 -Format HTML -OutputPath "C:\Reports\system-report.html"
```

## 📦 Installation

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges (for some checks)

### Setup
1. Clone or download this repository:
```powershell
git clone https://github.com/royont123/powershell-security-toolkit.git
cd powershell-security-toolkit
```

2. Set execution policy (if needed):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. Run any script:
```powershell
.\scripts\System-Health-Checker.ps1
```

## 🔒 Security Considerations

- These scripts require appropriate permissions to access system logs and configurations
- Some features require Administrator privileges
- Review scripts before running in production environments
- Log Analyzer may process sensitive security data - handle output files appropriately

## 🎯 Use Cases

**For IT Administrators:**
- Daily system health monitoring
- Pre-maintenance baseline reporting
- Quick security posture checks

**For Security Analysts:**
- Initial incident response data gathering
- Failed login pattern analysis
- Security event correlation

**For Learning:**
- Understanding Windows Event Logs
- PowerShell automation techniques
- Security monitoring fundamentals

## 🛠️ Technologies Used

- PowerShell 5.1+
- Windows Management Instrumentation (WMI)
- Windows Event Log API
- .NET Framework classes

## 📚 Learning Resources

These scripts were built while learning:
- PowerShell scripting and automation
- Windows security fundamentals
- Cyber forensics techniques
- System administration

## 🤝 Contributing

This is a learning project, but suggestions and improvements are welcome! Feel free to:
- Open an issue for bugs or feature requests
- Submit pull requests with improvements
- Share how you've used or modified these scripts

## 📝 License

MIT License - Feel free to use and modify for your own purposes.

## 👤 Author

**royont123**
- Aspiring cybersecurity professional
- Focus: Cyber forensics and security operations
- Learning: PowerShell, Python, Kali Linux, Digital Forensics

---

**⚠️ Disclaimer:** These tools are for legitimate security monitoring and system administration only. Always ensure you have proper authorization before running security scripts on any system.
