# Secure_Audit_Logger

A comprehensive security auditing tool designed to assess, monitor, and enforce system security policies across multiple operating systems (macOS, Windows, and Linux/Ubuntu).

## Overview

This security-focused project provides automated testing and monitoring of critical system components:

- Detailed logging of system activities and security events (e.g., file access, process creation, network connections)
- OS-level background monitoring
- Tamper-resistant logging mechanisms
- Comprehensive security policy enforcement
- Actionable remediation steps for failed checks

## Features

### 1. Network Configuration

- IPv6 configuration validation
- Wireless interface security
- Packet redirect controls
- IP forwarding settings
- Source-routed packet handling
- ICMP redirect management
- Suspicious packet logging
- Bogus ICMP response handling

### 2. Logging and Auditing

#### System Logging

- Auditd service installation and configuration
- Rsyslog setup and management
- Journald compression and storage settings
- Log rotation and retention policies

#### Event Monitoring

- Date and time modification events
- User/group information changes
- Network environment modifications
- MAC policy alterations
- Login/logout events
- Session initiation tracking
- Permission modifications
- File access attempts
- System mount operations
- File deletion events

#### Administrative Monitoring

- Sudoers configuration changes
- Administrative command execution
- Kernel module operations
- Audit configuration immutability

### 3. Access, Authentication, and Authorization

- File permission validation
- Cron daemon configuration
- At command access control
- Sudo installation and setup
- User privilege management
- Password policies
- Account lockout settings

## Installation & Usage

### Prerequisites

#### Ubuntu 22.04

```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y build-essential gcc make
```

#### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required packages
brew install gcc make
```

#### Windows

```powershell
# Install Chocolatey if not already installed
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install required packages
choco install -y mingw make
```

### Building and Running

You can find more OS-Specific details in docs/[os].md
Here are some general instructions

1. Clone the repository:

```bash
git clone https://github.com/yourusername/Secure_Audit_Logger.git
cd Secure_Audit_Logger
```

2. Build for your operating system:

For Ubuntu:

```bash
make linux
```

For macOS:

```bash
make macos
```

For Windows (in PowerShell):

```powershell
make windows
```

3. Run the security audit:

For Ubuntu:

```bash
sudo ./scripts/run_audit.sh
```

For macOS:

```bash
sudo ./scripts/run_audit.sh
```

For Windows (Run PowerShell as Administrator):

```powershell
.\scripts\run_audit.ps1 -OSType windows
```

4. View results:

For Linux/macOS:

```bash
# View full results
cat audit_results/audit_YYYYMMDD_HHMMSS.log

# View only failed tests
grep -A 1 "\[FAIL\]" audit_results/audit_YYYYMMDD_HHMMSS.log
```

For Windows:

```powershell
# View full results
Get-Content audit_results\audit_YYYYMMDD_HHMMSS.log

# View only failed tests
Select-String -Pattern "\[FAIL\]" -Context 0,1 audit_results\audit_YYYYMMDD_HHMMSS.log
```

## Test Results

The tool provides detailed output for each test, including:

- Test description and importance
- Pass/Fail status
- Specific remediation steps for failed tests
- Commands to implement fixes
- Configuration file locations and required changes

### Example Output

```
Test: 4.1.1.1 Ensure auditd is installed (Automated)
[PASS] auditd is installed

Test: 4.1.1.2 Ensure auditd service is enabled (Automated)
[FAIL] auditd service is not enabled
Action: Run 'sudo systemctl enable auditd'

### Remediation
- For failed tests, the tool provides specific commands and configuration changes needed
- All remediation steps are logged in the audit report
- Review the changes before implementing them
- Some changes may require system restart


Test: 4.1.2.1 Ensure audit log storage size is configured (Automated)
[PASS] Audit log storage size is properly configured
```

## Operating System Support

- Linux (Ubuntu 22.04 LTS)
- macOS (coming soon)
- Windows (coming soon)

## Project Structure

```
Secure_Audit_Logger/
├── audit_results/               # Results of tests
├── bin/                         # Compiled binaries
├── docs/                        # Helper Docs
├── src/
│   ├── linux_ubuntu_22_04/      # Ubuntu-specific tests
│   │   ├── network_config.c     # Network security tests
│   │   ├── logging_auditing.c   # Logging system tests
│   │   └── access_control.c     # Access control tests
│   ├── macos/                   # macOS-specific tests
│   │   ├── network_config.c
│   │   ├── logging_auditing.c
│   │   └── access_control.c
│   ├── windows/                 # Windows-specific tests
│       ├── network_config.c
│       ├── logging_auditing.c
│       └── access_control.c
└── scripts/
    ├── run_audit.sh            # Linux/macOS audit script
    └── run_audit.ps1           # Windows audit script
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

- All tests should be run with appropriate permissions
- Some tests may require root/administrator access
- Always review suggested changes before implementation
- Backup critical files before making modifications
- Test changes in a non-production environment first

## Acknowledgments

- CIS Benchmarks for security guidelines
- Linux Audit System documentation
- System logging best practices
