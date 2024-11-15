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

echo "Starting $OS_TYPE security audit..." | tee "$output_file"
./bin/network_config | tee -a "$output_file"
./bin/logging_auditing | tee -a "$output_file"
./bin/access_control | tee -a "$output_file"