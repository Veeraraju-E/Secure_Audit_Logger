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
brew install mysql-client
brew install openssl
brew install curl
brew install mailutils
```

3. Build the project:

```bash
make macos
```

4. Run the audit:

```bash
gcc -o MacExec <name_of_file>.c -I/opt/homebrew/Cellar/mysql/9.0.1_6/include -L/opt/homebrew/Cellar/mysql/9.0.1_6/lib -lmysqlclient -lpthread -I/opt/homebrew/opt/curl/include -L/opt/homebrew/opt/curl/lib -lcurl -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#To be executed for each file
```
