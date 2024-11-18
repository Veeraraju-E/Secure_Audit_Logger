---
layout: default
title: Secure Audit Logger
css: styles.css
---

# Secure Audit Logger

A comprehensive security auditing tool designed to assess, monitor, and enforce system security policies across multiple operating systems (macOS, Windows, and Linux/Ubuntu).

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

## Operating System Support

- Linux (Ubuntu 22.04 LTS)
- macOS (coming soon)
- Windows (coming soon)

## Test Considerations

The tool provides detailed output for each test, including:

- Test description and importance
- Pass/Fail status
- Specific remediation steps for failed tests
- Commands to implement fixes
- Configuration file locations and required changes

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Project Members

- [Veeraraju Elluru](https://github.com/Veeraraju-E) - Project Maintainer + Contributor (Ubuntu)
- [Pujit Jha](https://github.com/pujit-jha) - Contributor (macOS)
- [Sai Vighnesh](https://github.com/viggu3sd) - Contributor (Windows)
- [Malothu Suresh](https://github.com/malothusuresh) - Contributor (Windows)

## Acknowledgments

- CIS Benchmarks for security guidelines
- Linux Audit System documentation
- System logging best practices
