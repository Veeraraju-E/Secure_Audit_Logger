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

## Usage

1. Clone the repository:

```bash
git clone https://github.com/yourusername/Secure_Audit_Logger.git

```

3. Run the security audit based on your OS

## Test Results

The tool provides detailed output for each test, including:

- Test description and importance
- Pass/Fail status
- Specific remediation steps for failed tests
- Commands to implement fixes
- Configuration file locations and required changes

## Operating System Support

- Linux (Ubuntu 22.04 LTS)
- macOS (coming soon)
- Windows (coming soon)

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
