## Quick Start Guide

### For Ubuntu 22.04 Users:

1. Clone and enter the repository:

```bash
git clone https://github.com/yourusername/Secure_Audit_Logger.git
cd Secure_Audit_Logger
```

2. Install required dependencies:

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc make
```

3. Build the project:

```bash
make linux
```

4. Run the audit:

```bash
sudo ./scripts/run_audit.sh
```

5. View the results:

```bash
# View latest audit results (replace with actual timestamp)
cat audit_results/audit_YYYYMMDD_HHMMSS.log

# Or view only failed tests
grep -A 1 "\[FAIL\]" audit_results/audit_YYYYMMDD_HHMMSS.log
```
