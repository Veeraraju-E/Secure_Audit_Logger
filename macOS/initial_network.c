#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>

#define MIN_UID 1000
#define MAX_LINE_LENGTH 512
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// Checks if a service is running (MacOS version)
int check_service(const char *service)
{
    char command[100];
    sprintf(command, "launchctl list | grep -q '^%s$'", service);
    if (system(command) != 0) return 0;

    sprintf(command, "launchctl list %s | grep 'state = running' >/dev/null", service);
    return system(command) == 0;
}

// Checks file permissions and ownership
int check_permissions(const char *filepath, mode_t mode, uid_t uid, gid_t gid)
{
    struct stat fileStat;
    if (stat(filepath, &fileStat) != 0) return 0; // File does not exist

    if (fileStat.st_uid != uid || fileStat.st_gid != gid) return 0;
    return (fileStat.st_mode & 0777) == mode;
}

// Checks if a file exists
int file_exists(const char *filepath)
{
    return access(filepath, F_OK) == 0;
}

// Checks command output against expected output
int check_command(const char *command, const char *expected_output)
{
    char result[256];
    FILE *fp = popen(command, "r");
    if (fp == NULL) return 0;
    fgets(result, sizeof(result), fp);
    pclose(fp);
    return strstr(result, expected_output) != NULL;
}
// Check if audit rules for a certain keyword are present in the audit rules files
int check_audit_rules(const char *keyword)
{
    char command[512];
    snprintf(command, sizeof(command), "grep -l '%s' /etc/audit/rules.d/*.rules", keyword);
    return check_command(command, keyword);
}

// Check if the auditctl list contains a specific rule
int check_auditctl(const char *keyword)
{
    char command[512];
    snprintf(command, sizeof(command), "auditctl -l | grep '%s'", keyword);
    return check_command(command, keyword);
}

// !!!!!!!!!!!!!!!!!! #1

void test_firmware_password()
{
    printf("Test: 1.4.2 Ensure bootloader password is set (Firmware Password)\n");
    printf(YELLOW "Note: Firmware password setting cannot be programmatically verified fully.\n" RESET);
    printf(YELLOW "Please verify manually in macOS Recovery Mode.\n" RESET);
}

// Checks if the root account is disabled
void test_root_account_status()
{
    printf("Test: 1.4.4 Ensure authentication required for single-user mode\n");
    if (system("dscl . -read /Users/root | grep -q 'Password: *'") == 0)
    {
        printf(GREEN "Pass: Root account is locked\n" RESET);
    }
    else
    {
        printf(RED "Fail: Root account is enabled\n" RESET);
    }
}

// Checks if auditd is installed and running
void test_auditd_installed()
{
    printf("Test: 4.1.1.1 Ensure auditd is installed and running\n");
    if (system("launchctl list | grep -q com.apple.auditd") == 0)
    {
        printf(GREEN "Pass: auditd is installed and running\n" RESET);
    }
    else
    {
        printf(RED "Fail: auditd is not installed\n" RESET);
    }
}

// Checks permissions on the boot.efi file
void test_boot_efi_permissions()
{
    struct stat fileStat;
    printf("Test: 1.4.3 Ensure permissions on bootloader config are configured\n");
    if (stat("/System/Library/CoreServices/boot.efi", &fileStat) == 0)
    {
        if ((fileStat.st_mode & 0777) == 0400 && fileStat.st_uid == 0 && fileStat.st_gid == 0)
        {
            printf(GREEN "Pass: boot.efi permissions are correctly configured\n" RESET);
        }
        else
        {
            printf(RED "Fail: boot.efi permissions are not correctly configured\n" RESET);
        }
    } else {
        printf(RED "Fail: boot.efi file does not exist\n" RESET);
    }
}


void test_permissions_on_bootloader_config()
{
    printf("Test: 1.4.1 Ensure permissions on bootloader config are not overridden (Automated)\n");

    // Check for permissions on /System/Library/CoreServices/boot.efi (macOS bootloader)
    struct stat fileStat;
    if (stat("/System/Library/CoreServices/boot.efi", &fileStat) == 0)
    {
        if ((fileStat.st_mode & 0777) == 0400 && fileStat.st_uid == 0 && fileStat.st_gid == 0)
        {
            printf(GREEN "Pass: bootloader permissions are correctly configured\n" RESET);
        }
        else
        {
            printf(RED "Fail: bootloader permissions are incorrectly configured\n" RESET);
        }
    }
    else
    {
        printf(RED "Fail: bootloader file does not exist\n" RESET);
    }
}

void test_bootloader_password()
{
    printf("Test: 1.4.2 Ensure bootloader password is set (Automated)\n");

    // Check for bootloader password setting
    // We check the status of the NVRAM variable that stores the firmware password status
    if (system("nvram -p | grep -q \"security-mode\"") == 0)
    {
        printf(GREEN "Pass: Bootloader password is set\n" RESET);
    }
    else
    {
        printf(RED "Fail: Bootloader password is not set\n" RESET);
    }
}

void test_single_user_mode_authentication()
{
    printf("Test: 1.4.4 Ensure authentication required for single-user mode (Automated)\n");

    // macOS requires a password in single-user mode if SIP (System Integrity Protection) is enabled
    if (system("csrutil status | grep -q 'System Integrity Protection status: enabled'") == 0)
    {
        printf(GREEN "Pass: Authentication required for single-user mode\n" RESET);
    }
    else
    {
        printf(RED "Fail: Authentication not required for single-user mode\n" RESET);
    }
}

void test_auditd_logging()
{
    printf("Test: 1.4.1.3 Ensure auditd is configured to log specific events (Automated)\n");

    // Check if auditd is configured to log for specific events in macOS
    if (system("auditctl -l | grep -q 'execve'") == 0)
    {
        printf(GREEN "Pass: Auditd is configured to log execve events\n" RESET);
    }
    else
    {
        printf(RED "Fail: Auditd is not configured to log execve events\n" RESET);
    }
}

void test_permissions_on_log_files()
{
    printf("Test: 1.4.1.4 Ensure permissions on log files are configured (Automated)\n");

    // Check permissions on /var/log (macOS equivalent for logging directory)
    struct stat fileStat;
    if (stat("/private/var/log", &fileStat) == 0)
    {
        if ((fileStat.st_mode & 0777) == 0700 && fileStat.st_uid == 0 && fileStat.st_gid == 0)
        {
            printf(GREEN "Pass: Log file permissions are correctly configured\n" RESET);
        }
        else
        {
            printf(RED "Fail: Log file permissions are incorrectly configured\n" RESET);
        }
    }
    else
    {
        printf(RED "Fail: Log directory does not exist\n" RESET);
    }
}

void test_motd_configured()
{
    printf("Test: 1.7.1 Ensure message of the day is configured properly (Automated)\n");
    if (check_command("grep -Eis '(\\\v|\\\r|\\\m|\\\s|$(grep \"^ID=\" /etc/os-release | cut -d= -f2 | sed -e \"s/\"//g\"))' /etc/motd", ""))
    {
        printf(GREEN "Pass: Message of the day is configured properly\n" RESET);
    }
    else
    {
        printf(RED "Fail: Message of the day is not configured properly\n" RESET);
    }
}

void test_issue_configured()
{
    printf("Test: 1.7.2 Ensure local login warning banner is configured properly (Automated)\n");
    if (check_command("grep -Eis '(\\\v|\\\r|\\\m|\\\s|$(grep \"^ID=\" /etc/os-release | cut -d= -f2 | sed -e \"s/\"//g\"))' /etc/issue", ""))
    {
        printf(GREEN "Pass: Local login warning banner is configured properly\n" RESET);
    }
    else
    {
        printf(RED "Fail: Local login warning banner is not configured properly\n" RESET);
    }
}

void test_issue_net_configured()
{
    printf("Test: 1.7.3 Ensure remote login warning banner is configured properly (Automated)\n");
    if (check_command("grep -Eis '(\\\v|\\\r|\\\m|\\\s|$(grep \"^ID=\" /etc/os-release | cut -d= -f2 | sed -e \"s/\"//g\"))' /etc/issue.net", ""))
    {
        printf(GREEN "Pass: Remote login warning banner is configured properly\n" RESET);
    }
    else
    {
        printf(RED "Fail: Remote login warning banner is not configured properly\n" RESET);
    }
}

void test_motd_permissions()
{
    printf("Test: 1.7.4 Ensure permissions on /etc/motd are configured (Automated)\n");
    if (access("/etc/motd", F_OK) == 0)
    {  // File exists
        if (check_permissions("/etc/motd", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/motd are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/motd are incorrect\n" RESET);
        }
    }
    else
    {
        printf(RED "Fail: /etc/motd does not exist\n" RESET);
    }
}

void test_issue_permissions()
{
    printf("Test: 1.7.5 Ensure permissions on /etc/issue are configured (Automated)\n");
    if (access("/etc/issue", F_OK) == 0) // File exists
    {
        if (check_permissions("/etc/issue", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/issue are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/issue are incorrect\n" RESET);
        }
    }
    else
    {
        printf(RED "Fail: /etc/issue does not exist\n" RESET);
    }
}

void test_issuenet_permissions()
{
    printf("Test: 1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)\n");
    if (access("/etc/issue.net", F_OK) == 0)  // File exists
    {
        if (check_permissions("/etc/issue.net", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/issue.net are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/issue.net are incorrect\n" RESET);
        }
    }
    else
    {
        printf(RED "Fail: /etc/issue.net does not exist\n" RESET);
    }
}


void test_updates_installed()
{
    printf("Test: 1.9 Ensure updates, patches, and additional security software are installed (Manual)\n");

    // Check if there are any updates available using brew
    if (check_command("brew outdated", "No outdated formulae") &&
        check_command("brew outdated --cask", "No outdated casks"))
    {
        printf(GREEN "Pass: No updates available\n" RESET);
    }
    else
    {
        printf(RED "Fail: Updates available or security software needs to be installed\n" RESET);
    }
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!! 3

void check_ipv6_disabled()
{
    printf("Test: 3.1.1 Disable IPv6 (Manual)\n");

    // Check if IPv6 is disabled via sysctl
    if (check_command("sysctl net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.disable_ipv6 = 1") &&
        check_command("sysctl net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.default.disable_ipv6 = 1"))
    {
        printf(GREEN "Pass: IPv6 is disabled via sysctl\n" RESET);
    }
    else
    {
        printf(RED "Fail: IPv6 is not disabled via sysctl\n" RESET);
    }

    // Check sysctl configuration files for IPv6 settings
    if (check_command("grep -E '^\s*net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1\b(\s+#.*)?$' /etc/sysctl.conf /etc/sysctl.d/*.conf", "net.ipv6.conf.all.disable_ipv6 = 1") &&
        check_command("grep -E '^\s*net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1\b(\s+#.*)?$' /etc/sysctl.conf /etc/sysctl.d/*.conf", "net.ipv6.conf.default.disable_ipv6 = 1"))
    {
        printf(GREEN "Pass: IPv6 is properly configured in sysctl.conf\n" RESET);
    }
    else
    {
        printf(RED "Fail: IPv6 is not properly configured in sysctl.conf\n" RESET);
    }
}

void check_wireless_disabled()
{
    printf("Test: 3.1.2 Ensure wireless interfaces are disabled (Automated)\n");

    // Check if wireless interfaces are disabled
    if (check_command("ifconfig en0 | grep -q 'status: inactive'", "status: inactive"))
    {
        printf(GREEN "Pass: Wireless interface is disabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: Wireless interface is not disabled\n" RESET);
    }
}

void test_module_disabled(const char *module_name)
{
    char command[512];
    printf("Test: Ensure %s is disabled (Automated)\n", module_name);

    // Check if the module is installed (using kextstat instead of modprobe)
    snprintf(command, sizeof(command), "kextstat | grep %s", module_name);
    if (check_command(command, module_name))
    {
        printf(RED "Fail: %s is not disabled, it is loaded as a kext\n" RESET, module_name);
        return;
    }

    // Ensure that the module is disabled via kextload (equivalent to modprobe -n -v)
    snprintf(command, sizeof(command), "kextload -n %s", module_name);
    if (check_command(command, "not found"))
    {
        printf(GREEN "Pass: %s is disabled\n" RESET, module_name);
    }
    else
    {
        printf(RED "Fail: %s is not disabled properly\n" RESET, module_name);
    }
}

void check_ufw_installed()
{
    FILE *fp = popen("pkgutil --pkg-info=com.apple.iptables", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: ufw is not installed\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: ufw is installed\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: ufw is not installed\033[0m\n");
    }
    fclose(fp);
}

void check_iptables_persistent()
{
    FILE *fp = popen("pkgutil --pkg-info=com.apple.iptables-persistent", "r");
    if (fp == NULL)
    {
        printf("\033[32mPASS: iptables-persistent is not installed\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[31mFAIL: iptables-persistent is installed\033[0m\n");
    }
    else
    {
        printf("\033[32mPASS: iptables-persistent is not installed\033[0m\n");
    }
    fclose(fp);
}

void check_ufw_service_enabled()
{
    FILE *fp = popen("launchctl list | grep -w com.apple.iptables", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: ufw service is not enabled\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: ufw service is enabled\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: ufw service is not enabled\033[0m\n");
    }
    fclose(fp);
}

void check_ufw_default_deny_policy()
{
    FILE *fp = popen("sudo pfctl -sr | grep 'block' | grep 'in' ", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: Default deny policy is not set for incoming traffic\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: Default deny policy is set for incoming traffic\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: Default deny policy is not set for incoming traffic\033[0m\n");
    }
    fclose(fp);

    fp = popen("sudo pfctl -sr | grep 'block' | grep 'out' ", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: Default deny policy is not set for outgoing traffic\033[0m\n");
        return;
    }

    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: Default deny policy is set for outgoing traffic\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: Default deny policy is not set for outgoing traffic\033[0m\n");
    }
    fclose(fp);
}

void check_nftables_installed()
{
    FILE *fp = popen("pkgutil --pkg-info=com.apple.nftables", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: nftables is not installed\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: nftables is installed\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: nftables is not installed\033[0m\n");
    }
    fclose(fp);
}

void check_nftables_service_enabled()
{
    FILE *fp = popen("launchctl list | grep -w com.apple.nftables", "r");
    if (fp == NULL)
    {
        printf("\033[31mFAIL: nftables service is not enabled\033[0m\n");
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf("\033[32mPASS: nftables service is enabled\033[0m\n");
    }
    else
    {
        printf("\033[31mFAIL: nftables service is not enabled\033[0m\n");
    }
    fclose(fp);
}


int main()
{
    // #1
    test_firmware_password();
    test_root_account_status();
    test_auditd_installed();
    test_boot_efi_permissions();
    test_permissions_on_bootloader_config();
    test_bootloader_password();
    test_single_user_mode_authentication();
    test_auditd_logging();
    test_permissions_on_log_files();
    test_updates_installed();
    test_motd_configured();
    test_issue_configured();
    test_issue_net_configured();
    test_motd_permissions();
    test_issue_permissions();
    test_issuenet_permissions();
    
    // #3
    check_ipv6_disabled();
    check_wireless_disabled();
    test_module_disabled("dccp"); // Test for DCCP
    test_module_disabled("sctp"); // Test for SCTP
    test_module_disabled("rds"); // Test for SCTP
    test_module_disabled("tipc"); // Test for TIPC
    printf("\n--- Checking system configurations ---\n");
    check_ufw_installed();
    check_iptables_persistent();
    check_ufw_service_enabled();
    check_ufw_default_deny_policy();
    check_nftables_installed();
    check_nftables_service_enabled();
    
    return 0;
}
