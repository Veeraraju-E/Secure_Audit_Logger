#!/bin/bash

# Check OS type
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS_TYPE="linux"
else
    echo "Unsupported OS"
    exit 1
fi

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root/sudo"
    exit 1
fi

# Create results directory
mkdir -p audit_results

# Run audit
timestamp=$(date +%Y%m%d_%H%M%S)
output_file="audit_results/audit_${timestamp}.log"

# Start logging
{
    echo "Starting $OS_TYPE security audit..."
    echo "==================================="

    log_section() {
        local section_name="$1"
        local command="$2"

        echo "" 
        echo "=== $section_name ==="
        echo "-----------------------------------"
        $command
        echo "-----------------------------------"
        echo "Finished $section_name"
    }

    # Run binaries and log the outputs
    if [[ "$OS_TYPE" == "linux" ]]; then
        log_section "Network Configuration Audit" "../bin/network_config"
        log_section "Logging and Auditing Audit" "../bin/logging_auditing"
        log_section "Access Control Audit" "../bin/access_auth"
    elif [[ "$OS_TYPE" == "macos" ]]; then
        log_section "Network Configuration Audit" "../bin/network_config"
        log_section "Logging and Auditing Audit" "../bin/logging_auditing"
        log_section "Access Control Audit" "../bin/access_auth"
    fi

    echo ""
    echo "==================================="
    echo "Audit completed. Results saved to $output_file"
} >> "$output_file" 2>&1
