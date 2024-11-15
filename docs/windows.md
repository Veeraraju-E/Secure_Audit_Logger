## Quick Start Guide

### For Windows Users:

1. Open PowerShell as Administrator and clone the repository:

```powershell
git clone https://github.com/yourusername/Secure_Audit_Logger.git
cd Secure_Audit_Logger
```

2. Install dependencies using Chocolatey:

```powershell
# Install Chocolatey if not already installed
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install required packages
choco install -y mingw make
```

3. Build the project:

```powershell
make windows
```

4. Run the audit:

```powershell
.\scripts\run_audit.ps1 -OSType windows
```
