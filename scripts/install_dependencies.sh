#!/bin/bash

install_ubuntu_deps() {
    apt-get update
    apt-get install -y \
        build-essential \
        auditd \
        rsyslog \
        gcc \
        make
}

install_macos_deps() {
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install required packages
    brew install \
        gcc \
        make \
        audit \
        osquery
}

install_windows_deps() {
    # Check if Chocolatey is installed
    if ! command -v choco &> /dev/null; then
        echo "Installing Chocolatey..."
        powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
    }
    
    # Install required packages
    choco install -y `
        mingw `
        make `
        windows-sdk `
        windows-audit-tools
}

# Detect OS and install dependencies
case "$(uname -s)" in
    Linux*)
        install_ubuntu_deps
        ;;
    Darwin*)
        install_macos_deps
        ;;
    CYGWIN*|MINGW*|MSYS*)
        install_windows_deps
        ;;
    *)
        echo "Unsupported OS"
        exit 1
        ;;
esac