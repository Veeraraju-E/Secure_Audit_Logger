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
#define RESET "\033[0m"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

// Function to log failure details to suggestions.txt
void log_failure(const char *test_case, const char *purpose, const char *implications, const char *suggestion)
{
    FILE *file = fopen("suggestions2.txt", "a");
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

//#4_Tests
// 4.1 - Configure System Accounting
void test_auditd_installed()
{
    printf("Test: 4.1.1.1 Ensure audit is installed (Automated)\n");
    if (check_command("which audit", "/usr/sbin/audit") || check_command("which audit", "/usr/bin/audit"))
    {
        printf(GREEN "Pass: audit is installed\n" RESET);
    }
    else
    {
        printf(RED "Fail: audit is not installed\n" RESET);
        log_failure(
            "Ensure audit is installed",
            "To provide system auditing capabilities for tracking user actions and security events",
            "Without auditing tools, it is impossible to track and analyze critical security events.",
            "Install the audit package using the appropriate package manager for your system."
        );
    }
}

void test_auditd_service_enabled()
{
    printf("Test: 4.1.1.2 Ensure audit service is enabled (Automated)\n");
    if (check_command("sudo systemctl is-enabled auditd", "enabled"))
    {
        printf(GREEN "Pass: audit service is enabled\n" RESET);
    }
    else
    {
        printf(RED "Fail: audit service is not enabled\n" RESET);
        log_failure(
            "Ensure audit service is enabled",
            "To ensure that auditing is actively collecting system logs and events",
            "Without the audit service enabled, auditing will not be performed and security events will be missed.",
            "Enable the auditd service using 'systemctl enable auditd'."
        );
    }
}

void test_auditd_enabled_at_boot()
{
    printf("Test: 4.1.1.3 Ensure auditing for processes that start prior to audit is enabled (Automated)\n");
    if (!check_command("grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit=1\"", ""))
    {
        printf(GREEN "Pass: audit is enabled at boot\n" RESET);
    }
    else
    {
        printf(RED "Fail: audit is not enabled at boot\n" RESET);
        log_failure(
            "Ensure auditing for processes that start prior to audit is enabled",
            "To ensure system processes are audited from the boot process onwards",
            "Without audit enabled at boot, early system processes will not be logged, potentially missing security events.",
            "Edit the GRUB configuration to include the 'audit=1' parameter and update the boot loader."
        );
    }
}

void test_audit_log_not_deleted()
{
    printf("Test: 4.1.2.2 Ensure audit logs are not automatically deleted (Automated)\n");
    if (check_command("grep max_log_file_action /etc/security/audit_control", "keep_logs"))
    {
        printf(GREEN "Pass: audit logs are configured to not be deleted\n" RESET);
    }
    else
    {
        printf(RED "[IMP] Fail: audit logs may be automatically deleted\n" RESET);
        log_failure(
            "Ensure audit logs are not automatically deleted",
            "To preserve audit logs for security auditing and compliance",
            "If audit logs are deleted, crucial evidence of system activity and potential incidents will be lost.",
            "Ensure that the 'max_log_file_action' setting in '/etc/security/audit_control' is set to 'keep_logs'."
        );
    }
}

void test_audit_logs_on_full()
{
    printf("Test: 4.1.2.3 Ensure system is disabled when audit logs are full (Automated)\n");
    int pass = 1;
    pass &= check_command("grep space_left_action /etc/security/audit_control", "email");
    pass &= check_command("grep action_mail_acct /etc/security/audit_control", "root");
    pass &= check_command("grep admin_space_left_action /etc/security/audit_control", "halt");

    if (pass)
    {
        printf(GREEN "Pass: System is configured to disable on full audit logs\n" RESET);
    }
    else
    {
        printf(RED "Fail: System is not configured correctly for full audit logs\n" RESET);
        log_failure(
            "Ensure system is disabled when audit logs are full",
            "To prevent the system from continuing operations without logging when audit logs are full",
            "Allowing the system to continue without available audit logs can leave the system blind to security events.",
            "Configure 'space_left_action' to 'email', 'action_mail_acct' to 'root', and 'admin_space_left_action' to 'halt' in '/etc/security/audit_control'."
        );
    }
}

// Ensures events that modify date and time information are collected
void test_time_change_events_collected()
{
    printf("Test: 4.1.3 Ensure events that modify date and time information are collected (Automated)\n");
    int pass = 1;

    // Check if audit rules for time-change are configured in audit rules directory for macOS
    pass &= check_command("grep time-change /etc/security/audit_control", "-w /etc/localtime -p wa -k time-change");

    // Check if time-change events are being logged (using system time modification commands)
    pass &= check_command("grep time-change /etc/security/audit_control", "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change");
    pass &= check_command("grep time-change /etc/security/audit_control", "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change");
    pass &= check_command("grep time-change /etc/security/audit_control", "-a always,exit -F arch=b64 -S clock_settime -k time-change");
    pass &= check_command("grep time-change /etc/security/audit_control", "-a always,exit -F arch=b32 -S clock_settime -k time-change");

    // Ensure that localtime file modifications are being logged for changes in date/time
    pass &= check_command("grep /etc/localtime /etc/security/audit_control", "audit /etc/localtime");

    if (pass)
    {
        printf(GREEN "Pass: Date and time modification events are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Date and time modification events are not fully collected\n" RESET);
        log_failure(
            "Ensure events that modify date and time information are collected",
            "To track system time modifications that could impact logging and security policies",
            "Failure to track time-change events could allow an attacker to cover their tracks by changing timestamps.",
            "Ensure the audit control file includes time-change related audit rules such as '-w /etc/localtime' and '-a always,exit -F arch=b64 -S clock_settime'."
        );
    }
}

// Ensures events that modify user/group information are collected
void test_user_group_info_events()
{
    printf("Test: 4.1.4 Ensure events that modify user/group information are collected (Automated)\n");
    if (check_command("grep identity /etc/security/audit_control", "-w /etc/group -p wa -k identity") ||
        check_command("grep identity /etc/security/audit_control", "-w /etc/passwd -p wa -k identity") ||
        check_command("grep identity /etc/security/audit_control", "-w /etc/gshadow -p wa -k identity") ||
        check_command("grep identity /etc/security/audit_control", "-w /etc/shadow -p wa -k identity") ||
        check_command("grep identity /etc/security/audit_control", "-w /etc/security/opasswd -p wa -k identity"))
    {
        printf(GREEN "Pass: Events that modify user/group information are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Events that modify user/group information are not collected\n" RESET);
        log_failure(
            "Ensure events that modify user/group information are collected",
            "To track changes to user and group information for security and compliance purposes",
            "Failure to log modifications to user and group information can lead to unauthorized privilege escalation or account manipulation.",
            "Ensure audit rules include '-w /etc/group -p wa' and similar for other user/group related files like '/etc/passwd' and '/etc/shadow'."
        );
    }
}

// Ensures events that modify the system's network environment are collected
void test_network_environment_events()
{
    printf("Test: 4.1.5 Ensure events that modify the system's network environment are collected (Automated)\n");
    if (check_command("grep system-locale /etc/security/audit_control", "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale") ||
        check_command("grep system-locale /etc/security/audit_control", "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale") ||
        check_command("grep system-locale /etc/security/audit_control", "-w /etc/issue -p wa -k system-locale") ||
        check_command("grep system-locale /etc/security/audit_control", "-w /etc/issue.net -p wa -k system-locale") ||
        check_command("grep system-locale /etc/security/audit_control", "-w /etc/hosts -p wa -k system-locale") ||
        check_command("grep system-locale /etc/security/audit_control", "-w /etc/network -p wa -k system-locale"))
    {
        printf(GREEN "Pass: Events that modify the network environment are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Events that modify the network environment are not collected\n" RESET);
        log_failure(
            "Ensure events that modify the system's network environment are collected",
            "To track changes to network configuration that may affect system security or availability",
            "Failure to log network environment modifications may allow attackers to modify network settings without detection.",
            "Ensure audit rules are configured to monitor critical network files such as '/etc/hosts' and system commands like 'sethostname'."
        );
    }
}

// Ensures events that modify the system's Mandatory Access Controls are collected
void test_mac_policy_events()
{
    printf("Test: 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)\n");
    if (check_command("grep MAC-policy /etc/security/audit_control", "-w /etc/apparmor/ -p wa -k MAC-policy") ||
        check_command("grep MAC-policy /etc/security/audit_control", "-w /etc/apparmor.d/ -p wa -k MAC-policy"))
    {
        printf(GREEN "Pass: Events that modify MAC policies are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Events that modify MAC policies are not collected\n" RESET);
        log_failure(
            "Ensure events that modify the system's Mandatory Access Controls are collected",
            "To monitor changes in security policies that could affect the entire system's security posture",
            "Failure to log changes to Mandatory Access Control policies could allow unauthorized modifications to security settings.",
            "Ensure that audit rules include monitoring directories like '/etc/apparmor/' for changes and actions."
        );
    }
}

// Ensures login and logout events are collected
void test_login_logout_events()
{
    printf("Test: 4.1.7 Ensure login and logout events are collected (Automated)\n");
    if (check_command("grep logins /etc/security/audit_control", "-w /var/log/faillog -p wa -k logins") ||
        check_command("grep logins /etc/security/audit_control", "-w /var/log/lastlog -p wa -k logins") ||
        check_command("grep logins /etc/security/audit_control", "-w /var/log/tallylog -p wa -k logins"))
    {
        printf(GREEN "Pass: Login and logout events are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Login and logout events are not collected\n" RESET);
        log_failure(
            "Ensure login and logout events are collected",
            "To ensure that user login and logout activities are logged for auditing purposes",
            "Failure to log login and logout events may allow unauthorized access to go undetected.",
            "Ensure audit rules are configured for important log files such as '/var/log/lastlog' and '/var/log/faillog'."
        );
    }
}

// Ensures session initiation information is collected
void test_session_initiation_events()
{
    printf("Test: 4.1.8 Ensure session initiation information is collected (Automated)\n");
    if (check_command("grep -E '(session|logins)' /etc/security/audit_control", "-w /var/run/utmp -p wa -k session") ||
        check_command("grep -E '(session|logins)' /etc/security/audit_control", "-w /var/log/wtmp -p wa -k logins") ||
        check_command("grep -E '(session|logins)' /etc/security/audit_control", "-w /var/log/btmp -p wa -k logins"))
    {
        printf(GREEN "Pass: Session initiation information is collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Session initiation information is not collected\n" RESET);
        log_failure(
            "Ensure session initiation information is collected",
            "To track session initiation events, such as when a user logs into the system",
            "Failure to collect session initiation data may allow unauthorized access to go unnoticed.",
            "Ensure audit rules are set to monitor session-related logs like '/var/log/wtmp' and '/var/run/utmp'."
        );
    }
}

// Ensures discretionary access control permission modification events are collected
void test_permission_modification_events()
{
    printf("Test: 4.1.9 Ensure discretionary access control permission modification events are collected (Automated)\n");

    int pass = 1;

    pass &= check_command("grep perm_mod /etc/security/audit_control", "");

    // Check for 64-bit and 32-bit architectures for permission modification events
    char cmd_64[512];
    char cmd_32[512];

    snprintf(cmd_64, sizeof(cmd_64), "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=%d -F auid!=4294967295 -k perm_mod", MIN_UID);
    snprintf(cmd_32, sizeof(cmd_32), "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=%d -F auid!=4294967295 -k perm_mod", MIN_UID);

    pass &= check_command("auditctl -l | grep perm_mod", cmd_64);
    pass &= check_command("auditctl -l | grep perm_mod", cmd_32);

    if (pass)
    {
        printf(GREEN "Pass: Permission modification events are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Permission modification events are not fully collected\n" RESET);
        log_failure(
            "Ensure discretionary access control permission modification events are collected",
            "To monitor changes in file permissions that could impact system security",
            "Failure to log permission changes could allow unauthorized access or privilege escalation.",
            "Ensure audit rules are configured to log 'chmod' and 'fchmod' system calls, including for both 32-bit and 64-bit architectures."
        );
    }
}

// Ensures unsuccessful unauthorized file access attempts are collected
// Ensures unsuccessful unauthorized file access attempts are collected
void test_unsuccessful_file_access_attempts()
{
    printf("Test: 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)\n");

    int pass = 1;

    char cmd_acces_b64[512];
    char cmd_acces_b32[512];

    snprintf(cmd_acces_b64, sizeof(cmd_acces_b64), "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=%d -F auid!=4294967295 -k access", MIN_UID);
    snprintf(cmd_acces_b32, sizeof(cmd_acces_b32), "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=%d -F auid!=4294967295 -k access", MIN_UID);

    pass &= check_command("auditctl -l | grep access", cmd_acces_b64);
    pass &= check_command("auditctl -l | grep access", cmd_acces_b32);

    if (pass)
    {
        printf(GREEN "Pass: Unauthorized file access attempts are collected\n" RESET);
    }
    else
    {
        printf(RED "[IMP] Fail: Unauthorized file access attempts are not fully collected\n" RESET);
        log_failure(
            "Ensure unsuccessful unauthorized file access attempts are collected",
            "To track unauthorized access attempts on files and maintain system security",
            "Failure to collect unsuccessful access attempts may allow attackers to attempt unauthorized access without detection.",
            "Ensure the audit rules include monitoring for system calls such as 'creat', 'open', and 'truncate' with 'exit=-EACCES'."
        );
    }
}

// Ensures successful file system mounts are collected
void test_mounts_collection()
{
    printf("4.1.12 - Ensure successful file system mounts are collected\n");
    if (check_audit_rules("mounts") == 0 && check_auditctl("mounts") == 0)
    {
        printf(GREEN "Pass: Successful file system mounts are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Unable to collect successful system mounts\n" RESET);
        log_failure(
            "Ensure successful file system mounts are collected",
            "To track system mounts, ensuring they are legitimate and authorized",
            "Failure to track mount events could lead to unauthorized file systems being mounted without detection.",
            "Ensure audit rules are configured to collect file system mount events using 'mount' and similar system calls."
        );
    }
}

// Ensures file deletion events by users are collected
void test_file_deletion_collection()
{
    printf("4.1.13 - Ensure file deletion events by users are collected\n");
    if (check_audit_rules("delete") == 0 && check_auditctl("delete") == 0)
    {
        printf(GREEN "Pass: File deletion user events are collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Unable to collect file deletion events by users.\n" RESET);
        log_failure(
            "Ensure file deletion events by users are collected",
            "To monitor unauthorized or suspicious file deletions that could impact data integrity",
            "Failure to log file deletions may result in critical files being deleted without detection.",
            "Ensure audit rules monitor file deletion activities, such as those involving 'unlink' and 'rm'."
        );
    }
}

// Ensures changes to system administration scope (sudoers) are collected
void test_sudoers_scope_collection()
{
    printf("4.1.14 - Ensure changes to system administration scope (sudoers) are collected\n");
    if (check_audit_rules("scope") == 0 && check_auditctl("scope") == 0)
    {
        printf(GREEN "Pass: Changes to sudoers collected\n" RESET);
    }
    else
    {
        printf(RED "[IMP] Fail: Unable to collect changes to the sudoers\n" RESET);
        log_failure(
            "Ensure changes to system administration scope (sudoers) are collected",
            "To track modifications to sudoers files, which can alter system administrator privileges",
            "Failure to track sudoers changes could allow unauthorized privilege escalation.",
            "Ensure audit rules monitor changes to files like '/etc/sudoers' and 'sudoers.d'."
        );
    }
}

// Ensures system administrator command executions (sudo) are collected
void test_sudo_command_execution_collection()
{
    printf("4.1.15 - Ensure system administrator command executions (sudo) are collected\n");
    if (check_audit_rules("actions") == 0 && check_auditctl("actions") == 0)
    {
        printf(GREEN "Pass: System admin command executions collected\n" RESET);
    }
    else
    {
        printf(RED "[IMP] Fail: Unable to collect system admin command executions\n" RESET);
        log_failure(
            "Ensure system administrator command executions (sudo) are collected",
            "To monitor privileged command execution, especially sudo",
            "Failure to track sudo executions could allow attackers to perform administrative tasks without detection.",
            "Ensure audit rules are set up to track 'sudo' command executions and related system calls."
        );
    }
}

// Ensures kernel module loading and unloading is collected
void test_kernel_module_loading_collection()
{
    printf("4.1.16 - Ensure kernel module loading and unloading is collected\n");
    if (check_audit_rules("modules") == 0 && check_auditctl("modules") == 0)
    {
        printf(GREEN "Pass: Kernel module load and unload successfully collected\n" RESET);
    }
    else
    {
        printf(RED "Fail: Unable to collect kernel module load and unload\n" RESET);
        log_failure(
            "Ensure kernel module loading and unloading is collected",
            "To track loading and unloading of kernel modules, which could affect system security",
            "Failure to log kernel module changes may allow attackers to load malicious modules undetected.",
            "Ensure audit rules are configured to track 'insmod', 'rmmod', and similar kernel module operations."
        );
    }
}

//// Logs failed tests to suggestions.txt
//void log_failure(const char *test_name, const char *purpose, const char *implication, const char *suggestion)
//{
//    FILE *file = fopen("suggestions.txt", "a");
//    if (file != NULL)
//    {
//        fprintf(file, "Test: %s\n", test_name);
//        fprintf(file, "Purpose: %s\n", purpose);
//        fprintf(file, "Implication of Failure: %s\n", implication);
//        fprintf(file, "Suggestion: %s\n\n", suggestion);
//        fclose(file);
//    }
//    else
//    {
//        printf("Error: Could not open suggestions.txt for writing.\n");
//    }
//}

// #5_Tests
// Ensures cron daemon is enabled and running
void test_cron_enabled_and_running()
{
    printf("Test: 5.1.1 Ensure cron daemon is enabled and running\n");
    if (check_command("launchctl list | grep cron", "com.vix.cron") &&
        check_command("launchctl list com.vix.cron | grep 'state = running'", "state = running"))
    {
        printf(GREEN "Pass: cron daemon is enabled and running\n" RESET);
    }
    else
    {
        printf(RED "Fail: cron daemon is not enabled or running\n" RESET);
        log_failure(
            "Ensure cron daemon is enabled and running",
            "To ensure the cron daemon is active for scheduling tasks",
            "Failure to run cron daemon can prevent scheduled tasks from being executed.",
            "Check if the cron service is active using 'launchctl list' and ensure 'state = running'."
        );
    }
}

// Ensures permissions on /etc/crontab are configured
void test_crontab_permissions()
{
    printf("Test: 5.1.2 Ensure permissions on /etc/crontab are configured\n");
    if (check_permissions("/etc/crontab", 0700, 0, 0))
    {
        printf(GREEN "Pass: /etc/crontab permissions are correct\n" RESET);
    }
    else
    {
        printf(RED "Fail: /etc/crontab permissions are incorrect\n" RESET);
        log_failure(
            "Ensure permissions on /etc/crontab are configured",
            "To secure the crontab configuration from unauthorized modifications",
            "Incorrect permissions can allow unauthorized users to alter scheduled tasks.",
            "Ensure '/etc/crontab' permissions are set to 0700 with ownership by root."
        );
    }
}

// Ensures permissions on cron directories
void test_cron_directories_permissions(const char *directory, const char *test_name)
{
    printf("Test: %s Ensure permissions on %s are configured\n", test_name, directory);
    if (check_permissions(directory, 0700, 0, 0))
    {
        printf(GREEN "Pass: %s permissions are correct\n" RESET, directory);
    }
    else
    {
        printf(RED "Fail: %s permissions are incorrect\n" RESET, directory);
        log_failure(
            "Ensure permissions on cron directories are configured",
            "To secure cron directories that contain scripts run at regular intervals",
            "Improper permissions may allow unauthorized modifications to cron jobs.",
            "Ensure cron directories like '/etc/cron.hourly', '/etc/cron.daily', etc. have 0700 permissions."
        );
    }
}

// Ensures cron is restricted to authorized users
void test_cron_restricted_to_authorized_users()
{
    printf("Test: 5.1.8 Ensure cron is restricted to authorized users\n");
    if (!access("/etc/cron.deny", F_OK) && check_permissions("/etc/cron.allow", 0640, 0, 0))
    {
        printf(GREEN "Pass: cron is restricted to authorized users\n" RESET);
    }
    else
    {
        printf(RED "Fail: cron is not restricted to authorized users\n" RESET);
        log_failure(
            "Ensure cron is restricted to authorized users",
            "To ensure that only authorized users can schedule cron jobs",
            "Failure to restrict cron access could allow unauthorized users to schedule tasks.",
            "Ensure '/etc/cron.allow' has correct permissions and '/etc/cron.deny' is absent or empty."
        );
    }
}

// !!!!!!!!!!!!!!!!!!!!!!!!5.2
// Ensures sudo is installed
void test_sudo_installed()
{
    printf("Test: 5.2.1 Ensure sudo is installed\n");
    if (check_command("dpkg -s sudo", "Status: install ok installed") ||
        check_command("dpkg -s sudo-ldap", "Status: install ok installed"))
    {
        printf(GREEN "Pass: sudo is installed\n" RESET);
    }
    else
    {
        printf(RED "Fail: sudo is not installed\n" RESET);
        log_failure(
            "Ensure sudo is installed",
            "To allow controlled access to superuser privileges",
            "Without sudo, users may lack the ability to perform administrative tasks securely.",
            "Ensure that 'sudo' or 'sudo-ldap' is installed via package management."
        );
    }
}

// Ensures sudo log file exists
void test_sudo_log_file_exists()
{
    printf("Test: 5.2.3 Ensure sudo log file exists\n");
    if (check_command("grep -Ei '^[[:space:]]*Defaults[[:space:]]+logfile=\\S+' /etc/sudoers /etc/sudoers.d/*", "Defaults"))
    {
        printf(GREEN "Pass: sudo log file is configured\n" RESET);
    }
    else
    {
        printf(RED "Fail: sudo log file is not configured\n" RESET);
        log_failure(
            "Ensure sudo log file exists",
            "To track usage of sudo commands for auditing and security analysis",
            "Failure to log sudo usage may hinder tracking of administrative actions on the system.",
            "Ensure the sudoers configuration includes 'Defaults logfile=<path>' to specify the log file."
        );
    }
}

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!5.4
//Ensures password creation requirements are configured
void test_password_creation_requirements()
{
    printf("Test: 5.4.1 Ensure password creation requirements are configured\n");

    char command[128];
    snprintf(command, sizeof(command), "grep '^\s*minlen\s*' /etc/security/pwquality.conf");
    char minlen_output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(minlen_output, sizeof(minlen_output), fp) != NULL)
    {
        int minlen = atoi(strchr(minlen_output, '=') + 1); // Extract number after "minlen = "
        pclose(fp);
        snprintf(command, sizeof(command), "grep '^\s*minclass\s*' /etc/security/pwquality.conf");
        fp = popen(command, "r");
        if (fp != NULL && fgets(minlen_output, sizeof(minlen_output), fp) != NULL)
        {
            int pwquality = atoi(strchr(minlen_output, '=') + 1); // Extract number after "minclass = "
            pclose(fp);
            if (minlen >= 14 && pwquality >= 4 &&
                check_command("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "dcredit = -1") &&
                check_command("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "ucredit = -1") &&
                check_command("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "lcredit = -1") &&
                check_command("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "ocredit = -1") &&
                check_command("grep -E '^\s*password\s+(requisite|required)\s+pam_pwquality.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password", "retry=[1-3]"))
            {
                printf(GREEN "Pass: Password creation requirements are configured correctly\n" RESET);
            }
            else
            {
                printf(RED "Fail: Password creation requirements are not configured correctly\n" RESET);
                log_failure(
                    "Ensure password creation requirements are configured",
                    "To enforce secure password creation policies, such as length and complexity",
                    "Failure to set these requirements can lead to weak passwords being used, which could compromise system security.",
                    "Ensure '/etc/security/pwquality.conf' is configured with minlen >= 14, minclass >= 4, and appropriate credit settings."
                );
            }
        }
    }
}

// Ensures lockout for failed password attempts is configured
void test_lockout_for_failed_password_attempts()
{
    printf("Test: 5.4.2 Ensure lockout for failed password attempts is configured\n");
    if (check_command("grep \"pam_tally2\" /etc/pam.d/common-auth", "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900") &&
        check_command("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account requisite pam_deny.so") &&
        check_command("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account required pam_tally2.so"))
    {
        printf(GREEN "Pass: Lockout for failed password attempts is configured\n" RESET);
    }
    else
    {
        printf(RED "Fail: Lockout for failed password attempts is not configured\n" RESET);
        log_failure(
            "Ensure lockout for failed password attempts is configured",
            "To protect the system from brute-force attacks by locking out users after multiple failed login attempts",
            "Failure to configure lockout for failed attempts could allow attackers to repeatedly try passwords.",
            "Ensure '/etc/pam.d/common-auth' and '/etc/pam.d/common-account' include the correct pam_tally2 and pam_deny configurations."
        );
    }
}

// Ensures password reuse is limited
void test_password_reuse_limited()
{
    printf("Test: 5.4.3 Ensure password reuse is limited\n");
    if (check_command("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "password required pam_pwhistory.so") &&
        check_command("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "remember=5"))
    {
        printf(GREEN "Pass: Password reuse is limited\n" RESET);
    }
    else
    {
        printf(RED "Fail: Password reuse is not limited\n" RESET);
        log_failure(
            "Ensure password reuse is limited",
            "To prevent users from reusing old passwords too frequently",
            "Failure to limit password reuse could lead to the re-use of easily guessed passwords, compromising system security.",
            "Ensure '/etc/pam.d/common-password' includes 'remember=5' in the pam_pwhistory.so configuration."
        );
    }
}

// Ensures password hashing algorithm is SHA-512
void test_password_hashing_algorithm_sha512()
{
    printf("Test: 5.4.4 Ensure password hashing algorithm is SHA-512\n");
    if (check_command("grep -E '^\s*password\s+(\S+\s+)+pam_unix.so\s+(\S+\s+)*sha512\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password", "sha512"))
    {
        printf(GREEN "Pass: Password hashing algorithm is SHA-512\n" RESET);
    }
    else
    {
        printf(RED "Fail: Password hashing algorithm is not SHA-512\n" RESET);
        log_failure(
            "Ensure password hashing algorithm is SHA-512",
            "To ensure that password hashes are strong and secure using SHA-512",
            "Failure to use SHA-512 could result in weaker password hashes, making passwords easier to crack.",
            "Ensure '/etc/pam.d/common-password' is configured with 'sha512' for the pam_unix.so module."
        );
    }
}

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!5.5
//Ensures minimum days between password changes is configured
void test_minimum_days_between_password_changes()
{
    printf("Test: 5.5.1.1 Ensure minimum days between password changes is configured\n");

    char command[128];
    snprintf(command, sizeof(command), "grep PASS_MIN_DAYS /etc/login.defs | grep --invert-match \"#\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL)
    {
        int mindays = atoi(strchr(output, '=') + 1); // Extract the number after "PASS_MIN_DAYS"
        fclose(fp);

        if (mindays > 0)
        {
            snprintf(command, sizeof(command), "awk -F : '(/^[^:]+:[^!*]/ && $4 < 1){print $1 \" \" $4}' /etc/shadow");
            fp = popen(command, "r");
            if (fp != NULL && fgets(output, sizeof(output), fp) == NULL)
            {
                printf("\033[1;32mPass: Minimum days between password changes is configured\n\033[0m");
            }
            else
            {
                printf("\033[1;31mFail: Minimum days between password changes is not configured\n\033[0m");
                log_failure("Test: 5.5.1.1 Ensure minimum days between password changes is configured", "Checks whether the system enforces a minimum number of days between password changes.", "Fail: Minimum days between password changes is not configured", "This may leave the system vulnerable to rapid password changes.");
            }
            fclose(fp);
        }
        else
        {
            printf("\033[1;31mFail: Minimum days between password changes is not configured\n\033[0m");
            log_failure("Test: 5.5.1.1 Ensure minimum days between password changes is configured", "Checks whether the system enforces a minimum number of days between password changes.", "Fail: Minimum days between password changes is not configured", "This may leave the system vulnerable to rapid password changes.");
        }
    }
}

// Ensures password expiration is 365 days or less
void test_password_expiration()
{
    printf("Test: 5.5.1.2 Ensure password expiration is 365 days or less\n");

    char command[128];
    snprintf(command, sizeof(command), "grep PASS_MAX_DAYS /etc/login.defs | grep --invert-match \"#\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL)
    {
        int maxdays = atoi(strchr(output, '=') + 1); // Extract the number after "PASS_MAX_DAYS"
        fclose(fp);

        if (maxdays < 366)
        {
            snprintf(command, sizeof(command), "awk -F: '(/^[^:]+:[^!*]/ && ($5>365||$5~/([0-1]|-1)/)){print $1 \" \" $5}' /etc/shadow");
            fp = popen(command, "r");
            if (fp != NULL && fgets(output, sizeof(output), fp) == NULL)
            {
                printf("\033[1;32mPass: Password expiration is 365 days or less\n\033[0m");
            }
            else
            {
                printf("\033[1;31mFail: Password expiration is not configured correctly\n\033[0m");
                log_failure("Test: 5.5.1.2 Ensure password expiration is 365 days or less", "Ensures that the system enforces a password expiration policy of no more than 365 days.", "Fail: Password expiration is not configured correctly", "The system could allow long-lived passwords, potentially exposing the system to security risks.");
            }
            fclose(fp);
        }
        else
        {
            printf("\033[1;31mFail: Password expiration exceeds 365 days\n\033[0m");
            log_failure("Test: 5.5.1.2 Ensure password expiration is 365 days or less", "Ensures that the system enforces a password expiration policy of no more than 365 days.", "Fail: Password expiration exceeds 365 days", "The system could allow long-lived passwords, potentially exposing the system to security risks.");
        }
    }
}

// Ensures password expiration warning days is 7 or more
void test_password_expiration_warning()
{
    printf("Test: 5.5.1.3 Ensure password expiration warning days is 7 or more\n");

    char command[128];
    snprintf(command, sizeof(command), "grep PASS_WARN_AGE /etc/login.defs | grep --invert-match \"#\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL)
    {
        int warnage = atoi(strchr(output, '=') + 1); // Extract the number after "PASS_WARN_AGE"
        fclose(fp);

        if (warnage > 6)
        {
            snprintf(command, sizeof(command), "awk -F: '(/^[^:]+:[^!*]/ && $6<7){print $1 \" \" $6}' /etc/shadow");
            fp = popen(command, "r");
            if (fp != NULL && fgets(output, sizeof(output), fp) == NULL)
            {
                printf("\033[1;32mPass: Password expiration warning days is 7 or more\n\033[0m");
            }
            else
            {
                printf("\033[1;31mFail: Password expiration warning days is less than 7\n\033[0m");
                log_failure("Test: 5.5.1.3 Ensure password expiration warning days is 7 or more", "It checks the PASS_WARN_AGE setting in /etc/login.defs to ensure it is greater than 6 (i.e., 7 or more days).", "Fail: Password expiration warning days is less than 7", "This may lead to users being unaware of impending password expiration.");
            }
            fclose(fp);
        }
        else
        {
            printf("\033[1;31mFail: Password expiration warning days is less than 7\n\033[0m");
            log_failure("Test: 5.5.1.3 Ensure password expiration warning days is 7 or more", "It checks the PASS_WARN_AGE setting in /etc/login.defs to ensure it is greater than 6 (i.e., 7 or more days).", "Fail: Password expiration warning days is less than 7", "This may lead to users being unaware of impending password expiration.");
        }
    }
}

// Ensures inactive password lock is 30 days or less
void test_inactive_password_lock()
{
    printf("Test: 5.5.1.4 Ensure inactive password lock is 30 days or less\n");

    char command[128];
    snprintf(command, sizeof(command), "useradd -D | grep INACTIVE");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL)
    {
        int inactive = atoi(strchr(output, '=') + 1); // Extract the number after "INACTIVE"
        fclose(fp);

        if (inactive != -1 && inactive < 31)
        {
            snprintf(command, sizeof(command), "awk -F: '(/^[^:]+:[^!*]/ && ($7~/(-1)/ || $7>30)){print $1 \" \" $7}' /etc/shadow");
            fp = popen(command, "r");
            if (fp != NULL && fgets(output, sizeof(output), fp) == NULL)
            {
                printf("\033[1;32mPass: Inactive password lock is 30 days or less\n\033[0m");
            }
            else
            {
                printf("\033[1;31mFail: Inactive password lock exceeds 30 days\n\033[0m");
                log_failure("Test: 5.5.1.4 Ensure inactive password lock is 30 days or less", "Retrieves the INACTIVE setting from useradd -D and ensures it is less than 31 days.", "Fail: Inactive password lock exceeds 30 days", "The system may allow accounts to be locked for too long, which could be a security risk.");
            }
            fclose(fp);
        }
        else
        {
            printf("\033[1;31mFail: Inactive password lock exceeds 30 days or is not configured\n\033[0m");
            log_failure("Test: 5.5.1.4 Ensure inactive password lock is 30 days or less", "Retrieves the INACTIVE setting from useradd -D and ensures it is less than 31 days.", "Fail: Inactive password lock exceeds 30 days or is not configured", "The system may allow accounts to be locked for too long, which could be a security risk.");
        }
    }
}

// Ensures all users last password change date is in the past
void test_users_last_password_change()
{
    printf("Test: 5.5.1.5 Ensure all users last password change date is in the past\n");

    char output[128];
    char command[128];
    snprintf(command, sizeof(command), "awk -F: '{print $1}' /etc/shadow | while read -r usr; do [[ $(date --date=\"$(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\" +%%s) > $(date +%%s) ]] && echo \"$usr last password change was: $(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\"; done");
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) == NULL)
    {
        printf("\033[1;32mPass: All users' last password change date is in the past\n\033[0m");
    }
    else
    {
        printf("\033[1;31mFail: Some users' last password change date is in the future\n\033[0m");
        log_failure("Test: 5.5.1.5 Ensure all users last password change date is in the past", "It retrieves the last password change date for all users from /etc/shadow using the chage command and checks if any user has a future date for their password change.", "Fail: Some users' last password change date is in the future", "Having a future password change date may indicate misconfiguration or a vulnerability.");
    }
    fclose(fp);
}

// Ensures system accounts are secured
void test_system_accounts_secured()
{
    printf("Test: 5.5.2 Ensure system accounts are secured\n");

    if (check_command("awk -F: '$1!~/(root|sync|shutdown|halt|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)' && $7!~/((\\/usr)?\\/sbin\\/nologin)/ && $7!~/(\\/bin)?\\/false/ {print}' /etc/passwd", "") &&
        check_command("awk -F: '($1!~/(root|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'", ""))
    {
        printf("\033[1;32mPass: System accounts are secured\n\033[0m");
    }
    else
    {
        printf("\033[1;31mFail: System accounts are not secured\n\033[0m");
        log_failure("Test: 5.5.2 Ensure system accounts are secured", "Ensures that no system accounts have invalid shell settings.", "Fail: System accounts are not secured", "Exposed or misconfigured system accounts could lead to unauthorized access.");
    }
}

int main()
{
    // // 5.1.1 Ensure cron daemon is enabled and running
    // if (check_service("cron"))
    //     printf("5.1.1 Cron service is enabled and running.\n");
    // else
    //     printf("5.1.1 Cron service is NOT enabled or running.\n");
    
    // // 5.1.2 Ensure permissions on /etc/crontab
    // if (check_permissions("/etc/crontab", 0700, 0, 0))
    //     printf("5.1.2 /etc/crontab permissions are correct.\n");
    // else
    //     printf("5.1.2 /etc/crontab permissions are NOT correct.\n");
    
    // // 5.1.3 to 5.1.7 Check permissions for cron directories
    // const char *cron_dirs[] = {
    //     "/etc/cron.hourly", "/etc/cron.daily",
    //     "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"
    // };
    // for (int i = 0; i < 5; ++i) {
    //     if (check_permissions(cron_dirs[i], 0700, 0, 0))
    //         printf("Permissions for %s are correct.\n", cron_dirs[i]);
    //     else
    //         printf("Permissions for %s are NOT correct.\n", cron_dirs[i]);
    // }
    
    // // 5.1.8 Ensure cron is restricted to authorized users
    // if (!file_exists("/etc/cron.deny") && check_permissions("/etc/cron.allow", 0640, 0, 0))
    //     printf("5.1.8 Cron is restricted to authorized users.\n");
    // else
    //     printf("5.1.8 Cron is NOT restricted to authorized users.\n");
    
    // // 5.1.9 Ensure at is restricted to authorized users
    // if (!file_exists("/etc/at.deny") && check_permissions("/etc/at.allow", 0640, 0, 0))
    //     printf("5.1.9 At is restricted to authorized users.\n");
    // else
    //     printf("5.1.9 At is NOT restricted to authorized users.\n");
    
    //4.1
    test_auditd_installed(); // Checks if auditd is installed on the system
    test_auditd_service_enabled(); // Ensures that the auditd service is enabled
    test_auditd_enabled_at_boot(); // Verifies if auditd is enabled at boot for process auditing
    test_audit_log_not_deleted(); // Ensures audit logs are not automatically deleted
    test_audit_logs_on_full(); // Ensures proper action is taken when audit logs are full
    test_time_change_events_collected();
    test_user_group_info_events(); // Test user/group information collection
    test_network_environment_events(); // Test network environment modification collection
    test_mac_policy_events(); // Test MAC policy modification collection
    test_login_logout_events(); // Test login and logout events collection
    test_session_initiation_events(); // Test session initiation information collection
    test_permission_modification_events(); // Test discretionary access control permission modification events collection
    test_unsuccessful_file_access_attempts(); // Test unsuccessful unauthorized file access attempts collection
    test_mounts_collection(); // Test successful file system mounts collection
    test_file_deletion_collection(); // Test file deletion events by users collection
    test_sudoers_scope_collection(); // Test changes to sudoers scope collection
    test_sudo_command_execution_collection(); // Test system administrator command executions collection
    test_kernel_module_loading_collection(); // Test kernel module loading and unloading collection
    
    //5.1
    test_cron_enabled_and_running();
    test_crontab_permissions();
    test_cron_directories_permissions("/etc/cron.hourly", "5.1.3");
    test_cron_directories_permissions("/etc/cron.daily", "5.1.4");
    test_cron_directories_permissions("/etc/cron.weekly", "5.1.5");
    test_cron_directories_permissions("/etc/cron.monthly", "5.1.6");
    test_cron_directories_permissions("/etc/cron.d", "5.1.7");
    test_cron_restricted_to_authorized_users();
    
    //5.2
    test_sudo_installed();
    test_sudo_log_file_exists();
    
    //5.4
    test_password_creation_requirements();
    test_lockout_for_failed_password_attempts();
    test_password_reuse_limited();
    test_password_hashing_algorithm_sha512();
    
    //5.5
    test_minimum_days_between_password_changes();
    test_password_expiration();
    test_password_expiration_warning();
    test_inactive_password_lock();
    test_users_last_password_change();
    test_system_accounts_secured();
    
    return 0;
}
