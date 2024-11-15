## Quick Start Guide

### For macOS Users:

1. Clone and enter the repository:

```bash
git clone https://github.com/yourusername/Secure_Audit_Logger.git
cd Secure_Audit_Logger
```

2. Install dependencies using Homebrew:

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required packages
brew install gcc make
```

3. Build the project:

```bash
make macos
```

4. Run the audit:

```bash
sudo ./scripts/run_audit.sh
```
