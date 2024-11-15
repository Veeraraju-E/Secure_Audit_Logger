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
#include <fcntl.h>
//#include <fstream>

FILE *results_file;
#define printf(fmt, ...)                        \
    do                                          \
    {                                           \
        fprintf(stdout, fmt, ##__VA_ARGS__);    \
        if (results_file)                       \
            fprintf(results_file, fmt, ##__VA_ARGS__); \
    } while (0)

// Function to log failure details to suggestions.txt
void log_failure(const char *test_case, const char *purpose, const char *implications, const char *suggestion)
{
    FILE *file = fopen("suggestions.txt", "a");
    if (file != NULL)
    {
        fprintf(file, "Test Case: %s\n", test_case);
        fprintf(file, "Purpose: %s\n", purpose);
        fprintf(file, "Implications: %s\n", implications);
        fprintf(file, "Suggestion: %s\n\n", suggestion);
        fclose(file);
    }
}

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
        log_failure(
            "1.4.4 Ensure authentication required for single-user mode",
            "To disable the root account and require authentication for single-user mode",
            "If enabled, unauthorized users can access single-user mode, posing a security risk.",
            "Disable the root account by using 'sudo passwd -l root' or equivalent command."
        );
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
        log_failure(
            "4.1.1.1 Ensure auditd is installed and running",
            "To ensure auditd is installed and actively monitoring system activity",
            "Without auditd, system activities are not logged, reducing system security and audit capabilities.",
            "Install and start auditd using 'launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist'."
        );
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
            log_failure(
                "1.4.3 Ensure permissions on bootloader config are configured",
                "To secure the bootloader by configuring permissions on boot.efi",
                "Incorrect permissions on boot.efi can allow unauthorized modification, compromising boot security.",
                "Set permissions on boot.efi to 400 and ensure root owns the file."
            );
        }
    }
    else
    {
        printf(RED "Fail: boot.efi file does not exist\n" RESET);
        log_failure(
            "1.4.3 Ensure permissions on bootloader config are configured",
            "To ensure the boot.efi file exists and has correct permissions",
            "If boot.efi is missing, the boot process might be vulnerable to attacks.",
            "Verify the file path or reinstall the system to restore boot.efi."
        );
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
            log_failure(
                "1.4.1 Ensure permissions on bootloader config are not overridden",
                "To ensure only root has access to modify the bootloader config",
                "Incorrect permissions allow unauthorized access to the bootloader config, posing a security risk.",
                "Set permissions to 400 on /System/Library/CoreServices/boot.efi, with root as owner."
            );
        }
    }
    else
    {
        printf(RED "Fail: bootloader file does not exist\n" RESET);
        log_failure(
            "1.4.1 Ensure permissions on bootloader config are not overridden",
            "To verify the existence and secure permissions of the bootloader file",
            "Missing bootloader file can prevent secure boot and may indicate a compromised system.",
            "Check if the file path is correct, or consider reinstalling the OS if missing."
        );
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
        log_failure(
            "1.4.2 Ensure bootloader password is set",
            "To protect the bootloader by setting a bootloader password",
            "Without a bootloader password, unauthorized users may access or modify the boot process.",
            "Set a bootloader password via macOS Recovery Mode."
        );
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
        log_failure(
            "1.4.4 Ensure authentication required for single-user mode",
            "To ensure authentication for single-user mode by enabling SIP",
            "Without SIP enabled, unauthorized access to single-user mode could compromise the system.",
            "Enable SIP by booting into Recovery Mode and using 'csrutil enable' command."
        );
    }
}

void test_auditd_logging()
{
    printf("Test: 1.4.1.3 Ensure auditd is configured to log specific events (Automated)\n");

    // Check if auditd is configured to log execve events in macOS
    if (system("grep -q 'execve' /etc/security/audit_control") == 0)
    {
        printf(GREEN "Pass: Auditd is configured to log execve events\n" RESET);
    }
    else
    {
        printf(RED "Fail: Auditd is not configured to log execve events\n" RESET);
        log_failure(
            "1.4.1.3 Ensure auditd is configured to log specific events",
            "To ensure auditd is logging execve events to track execution of processes",
            "Without logging execve events, unauthorized or suspicious process executions may go unnoticed.",
            "Add 'execve' to the flags in /etc/security/audit_control and restart the audit daemon using 'sudo audit -s'."
        );
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
            log_failure(
                "1.4.1.4 Ensure permissions on log files are configured",
                "To secure the log directory by setting appropriate permissions",
                "Improper permissions on log files can allow unauthorized access, compromising log integrity.",
                "Set the permissions on /private/var/log to 700, with root as the owner and group."
            );
        }
    }
    else
    {
        printf(RED "Fail: Log directory does not exist\n" RESET);
        log_failure(
            "1.4.1.4 Ensure permissions on log files are configured",
            "To verify the existence and secure permissions of the log directory",
            "A missing log directory can prevent logging, making it difficult to audit events.",
            "Ensure /private/var/log exists or recreate the directory with appropriate permissions."
        );
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
        log_failure(
            "1.7.1 Ensure message of the day is configured properly",
            "To display important information to users upon login",
            "Without a properly configured MOTD, users may miss important system messages.",
            "Edit /etc/motd to include necessary information or notifications for users."
        );
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
        log_failure(
            "1.7.2 Ensure local login warning banner is configured properly",
            "To display a security warning banner before local login",
            "A missing or incorrect login warning banner may reduce user awareness of login policies.",
            "Edit /etc/issue to include a warning message for local logins."
        );
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
        log_failure(
            "1.7.3 Ensure remote login warning banner is configured properly",
            "To display a security warning banner before remote logins",
            "Without a remote login warning banner, users may miss important security notices.",
            "Edit /etc/issue.net to include a warning message for remote logins."
        );
    }
}

void test_motd_permissions()
{
    printf("Test: 1.7.4 Ensure permissions on /etc/motd are configured (Automated)\n");
    if (access("/etc/motd", F_OK) == 0)
    {
        if (check_permissions("/etc/motd", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/motd are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/motd are incorrect\n" RESET);
            log_failure(
                "1.7.4 Ensure permissions on /etc/motd are configured",
                "To secure the message of the day file with appropriate permissions",
                "Incorrect permissions on /etc/motd may allow unauthorized modification of displayed messages.",
                "Set the permissions on /etc/motd to 644, with root as the owner and group."
            );
        }
    }
    else
    {
        printf(RED "Fail: /etc/motd does not exist\n" RESET);
        log_failure(
            "1.7.4 Ensure permissions on /etc/motd are configured",
            "To ensure the existence and secure permissions of the MOTD file",
            "A missing /etc/motd file means the MOTD is not displayed.",
            "Create /etc/motd or restore it with permissions set to 644."
        );
    }
}

void test_issue_permissions()
{
    printf("Test: 1.7.5 Ensure permissions on /etc/issue are configured (Automated)\n");
    if (access("/etc/issue", F_OK) == 0)
    {
        if (check_permissions("/etc/issue", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/issue are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/issue are incorrect\n" RESET);
            log_failure(
                "1.7.5 Ensure permissions on /etc/issue are configured",
                "To secure the local login warning banner with appropriate permissions",
                "Incorrect permissions on /etc/issue may allow unauthorized modification.",
                "Set permissions on /etc/issue to 644, with root as the owner and group."
            );
        }
    }
    else
    {
        printf(RED "Fail: /etc/issue does not exist\n" RESET);
        log_failure(
            "1.7.5 Ensure permissions on /etc/issue are configured",
            "To verify the existence and secure permissions of the local login warning banner",
            "A missing /etc/issue file prevents displaying the local login warning.",
            "Create /etc/issue or restore it with permissions set to 644."
        );
    }
}

void test_issuenet_permissions()
{
    printf("Test: 1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)\n");
    if (access("/etc/issue.net", F_OK) == 0)
    {
        if (check_permissions("/etc/issue.net", 0644, 0, 0))
        {
            printf(GREEN "Pass: Permissions on /etc/issue.net are configured correctly\n" RESET);
        }
        else
        {
            printf(RED "Fail: Permissions on /etc/issue.net are incorrect\n" RESET);
            log_failure(
                "1.7.6 Ensure permissions on /etc/issue.net are configured",
                "To secure the remote login warning banner with appropriate permissions",
                "Incorrect permissions on /etc/issue.net may allow unauthorized modification.",
                "Set permissions on /etc/issue.net to 644, with root as the owner and group."
            );
        }
    }
    else
    {
        printf(RED "Fail: /etc/issue.net does not exist\n" RESET);
        log_failure(
            "1.7.6 Ensure permissions on /etc/issue.net are configured",
            "To verify the existence and secure permissions of the remote login warning banner",
            "A missing /etc/issue.net file prevents displaying the remote login warning.",
            "Create /etc/issue.net or restore it with permissions set to 644."
        );
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
        log_failure(
            "1.9 Ensure updates, patches, and additional security software are installed",
            "To ensure that all software is up to date with the latest patches",
            "Outdated software may contain vulnerabilities that could compromise system security.",
            "Run 'brew update' and 'brew upgrade' to install available updates."
        );
    }
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!! 3

void check_ipv6_disabled()
{
    printf("Test: 3.1.1 Disable IPv6 (Manual)\n");

    // Check if IPv6 is disabled for all network services
    if (check_command("networksetup -listallnetworkservices | grep -v '*' | xargs -I {} networksetup -getinfo {} | grep -q 'IPv6: Off'", "IPv6: Off"))
    {
        printf(GREEN "Pass: IPv6 is disabled on all network services\n" RESET);
    }
    else
    {
        printf(RED "Fail: IPv6 is not disabled on all network services\n" RESET);
        log_failure(
            "3.1.1 Disable IPv6",
            "To enhance security by disabling IPv6 when it's not required",
            "If IPv6 is enabled, it may be vulnerable to certain attacks if not properly configured.",
            "Disable IPv6 on all network interfaces using the command:\n"
            "'networksetup -setv6off <networkservice>' for each service listed in 'networksetup -listallnetworkservices'."
        );
    }
}

void check_wireless_disabled()
{
    printf("Test: 3.1.2 Ensure wireless interfaces are disabled (Automated)\n");

    if (check_command("ifconfig en0 | grep -q 'status: inactive'", "status: inactive"))
    {
        printf(GREEN "Pass: Wireless interface is disabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: Wireless interface is not disabled\n" RESET);
        log_failure(
            "3.1.2 Ensure wireless interfaces are disabled",
            "To prevent unauthorized access via wireless networks",
            "If wireless interfaces are enabled, they may be exploited if not secured properly.",
            "Disable wireless interfaces by turning off Wi-Fi or configuring the interface as inactive."
        );
    }
}

void test_module_disabled(const char *module_name)
{
    char command[512];
    printf("Test: Ensure %s is disabled (Automated)\n", module_name);

    // Check if the module is loaded as a kernel extension
    snprintf(command, sizeof(command), "kextstat | grep -i %s", module_name);
    if (check_command(command, module_name))
    {
        printf(RED "Fail: %s is loaded as a kernel extension\n" RESET, module_name);
        log_failure(
            "Ensure module is disabled",
            "To prevent loading of unwanted modules for security",
            "Loaded modules may present security risks if not required by the system.",
            "Unload the module by disabling it in the kernel extensions configuration or removing it from /Library/Extensions."
        );
        return;
    }

    // Verify the module is not present in available kernel extensions
    snprintf(command, sizeof(command), "kmutil showloaded 2>/dev/null | grep -i %s", module_name);
    if (!check_command(command, module_name))
    {
        printf(GREEN "Pass: %s is not loaded\n" RESET, module_name);
    }
    else
    {
        printf(RED "Fail: %s is still available as a kernel extension\n" RESET, module_name);
        log_failure(
            "Ensure module is disabled",
            "To ensure the module is not inadvertently loaded in the future",
            "Kernel extensions that are not properly removed may still load during boot or manually.",
            "Remove the module file from /Library/Extensions or /System/Library/Extensions and update the kext cache."
        );
    }
}

void check_ufw_installed()
{
    printf("Test: Ensure a firewall is configured (Automated)\n");

    // Check if macOS Application Firewall is enabled
    FILE *fp = popen("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: Unable to determine firewall state\n" RESET);
        log_failure(
            "Ensure a firewall is configured",
            "To protect the system from unauthorized network access",
            "Without a configured firewall, the system is vulnerable to external attacks.",
            "Enable the macOS built-in firewall: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'."
        );
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL && strstr(output, "enabled"))
    {
        printf(GREEN "Pass: macOS built-in firewall is enabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: macOS built-in firewall is disabled\n" RESET);
        log_failure(
            "Ensure a firewall is configured",
            "To ensure network security and block unauthorized access",
            "A disabled firewall exposes the system to potential network threats.",
            "Enable the macOS built-in firewall using: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'."
        );
    }
    pclose(fp);
}

void check_iptables_persistent()
{
    printf("Test: Ensure unauthorized persistent pf rules are not present (Automated)\n");

    // Check if the pf configuration file exists
    FILE *fp = fopen("/etc/pf.conf", "r");
    if (fp == NULL)
    {
        printf(GREEN "Pass: No pf rules configured (pf.conf does not exist)\n" RESET);
        return;
    }
    fclose(fp);

    // Verify if pf.conf contains any unauthorized rules
    if (system("grep -q -E 'block|pass' /etc/pf.conf") == 0)
    {
        printf(RED "Fail: pf.conf contains rules; check for unauthorized configurations\n" RESET);
        log_failure(
            "Ensure unauthorized persistent pf rules are not present",
            "To verify that no unintended rules are being persistently applied to the firewall",
            "Unauthorized rules may compromise system security by allowing unwanted network traffic.",
            "Review and clean up /etc/pf.conf to ensure only intended rules are present."
        );
    }
    else
    {
        printf(GREEN "Pass: No unauthorized persistent pf rules found\n" RESET);
    }
}

void check_ufw_service_enabled()
{
    FILE *fp = popen("launchctl list | grep -w com.apple.iptables", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: ufw service is not enabled\n" RESET);
        log_failure(
            "Ensure ufw service is enabled",
            "To ensure the firewall service is actively managing traffic",
            "Without an active ufw service, firewall rules may not be enforced, leaving the system vulnerable.",
            "Enable the ufw service using 'launchctl load /Library/LaunchDaemons/com.apple.iptables.plist'."
        );
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf(GREEN "Pass: ufw service is enabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: ufw service is not enabled\n" RESET);
        log_failure(
            "Ensure ufw service is enabled",
            "To ensure the firewall service is active",
            "Inactive ufw service results in no protection by the firewall.",
            "Enable ufw service by loading the associated launch agent."
        );
    }
    fclose(fp);
}

void check_ufw_default_deny_policy()
{
    FILE *fp = popen("sudo pfctl -sr | grep 'block' | grep 'in' ", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: Default deny policy is not set for incoming traffic\n" RESET);
        log_failure(
            "Ensure default deny policy is set for incoming traffic",
            "To block all incoming traffic by default, only allowing essential connections",
            "Without a default deny policy, unwanted or malicious incoming traffic may bypass the firewall.",
            "Ensure the pfctl rules set a default deny for incoming traffic by verifying the pf configuration."
        );
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf(GREEN "Pass: Default deny policy is set for incoming traffic\n" RESET);
    }
    else
    {
        printf(RED "Fail: Default deny policy is not set for incoming traffic\n" RESET);
        log_failure(
            "Ensure default deny policy is set for incoming traffic",
            "To restrict all incoming traffic unless explicitly allowed",
            "Failing to block unwanted traffic increases system vulnerability to attacks.",
            "Check pf rules and make sure 'block in' is set for incoming traffic."
        );
    }
    fclose(fp);

    fp = popen("sudo pfctl -sr | grep 'block' | grep 'out' ", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: Default deny policy is not set for outgoing traffic\n" RESET);
        log_failure(
            "Ensure default deny policy is set for outgoing traffic",
            "To block all outgoing traffic by default, allowing only specific essential outbound connections",
            "Outgoing traffic should be blocked to prevent unauthorized data leakage.",
            "Verify pf rules to ensure 'block out' is configured for outgoing traffic."
        );
        return;
    }

    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf(GREEN "Pass: Default deny policy is set for outgoing traffic\n" RESET);
    }
    else
    {
        printf(RED "Fail: Default deny policy is not set for outgoing traffic\n" RESET);
        log_failure(
            "Ensure default deny policy is set for outgoing traffic",
            "To prevent unauthorized data from leaving the system",
            "Failing to block outgoing traffic could lead to data leakage or connections to malicious sites.",
            "Check pf rules to confirm that 'block out' is set for outgoing traffic."
        );
    }
    fclose(fp);
}

void check_nftables_installed()
{
    FILE *fp = popen("pkgutil --pkg-info=com.apple.nftables", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: nftables is not installed\n" RESET);
        log_failure(
            "Ensure nftables is installed",
            "To provide a modern and secure firewall configuration",
            "Without nftables, the system may lack essential packet filtering features.",
            "Install nftables by using the appropriate package manager for your distribution."
        );
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf(GREEN "Pass: nftables is installed\n" RESET);
    }
    else
    {
        printf(RED "Fail: nftables is not installed\n" RESET);
        log_failure(
            "Ensure nftables is installed",
            "To use modern firewall management",
            "Without nftables, the system may be vulnerable due to lack of packet filtering functionality.",
            "Install nftables using 'brew install nftables' or the package manager of your OS."
        );
    }
    fclose(fp);
}

void check_nftables_service_enabled()
{
    FILE *fp = popen("launchctl list | grep -w com.apple.nftables", "r");
    if (fp == NULL)
    {
        printf(RED "Fail: nftables service is not enabled\n" RESET);
        log_failure(
            "Ensure nftables service is enabled",
            "To ensure that nftables is actively filtering traffic on the system",
            "Without an active nftables service, the firewall rules won't be enforced, leaving the system exposed.",
            "Enable nftables by loading the service using 'launchctl load /Library/LaunchDaemons/com.apple.nftables.plist'."
        );
        return;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        printf(GREEN "Pass: nftables service is enabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: nftables service is not enabled\n" RESET);
        log_failure(
            "Ensure nftables service is enabled",
            "To make sure nftables is running to protect the system",
            "Inactive nftables service means firewall protection isn't actively filtering traffic.",
            "Enable nftables by loading the associated launch agent to ensure firewall rules are enforced."
        );
    }
    fclose(fp);
}



int main()
{
    results_file = fopen("log.txt", "w");
    if (results_file == NULL)
    {
        fprintf(stderr, "Error: Unable to open results.txt for writing\n");
        return 1;
    }
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
    
    fclose(results_file);
    printf("Execution completed");
    return 0;
}
