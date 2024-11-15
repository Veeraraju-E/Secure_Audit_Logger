#!/bin/bash

# Create necessary directories
mkdir -p audit_results

# Set proper permissions
chmod 750 audit_results

# Configure audit environment
if [ -f /etc/audit/auditd.conf ]; then
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
fi