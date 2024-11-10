#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_UID 1000
#define MAX_LINE_LENGTH 512
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define RESET "\033[0m"

int check_audit_rules(const char *pattern);
int check_auditctl(const char *pattern);

int check_command(const char *command, const char *expected_output) {
    char buffer[256];
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        perror("popen failed");
        return -1;
    }

    int status = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        if (strstr(buffer, expected_output)) {
            status = 1;  // Expected output found
            break;
        }
    }

    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        return 0;  // Command failed
    }

    return status;
}

// 4.1 - Configure System Accounting
void test_auditd_installed() {
    printf("Test: 4.1.1.1 Ensure auditd is installed (Automated)\n");
    if (check_command("dpkg -s auditd audispd-plugins", "Status: install ok installed")) {
        printf(GREEN "Pass: auditd is installed\n" RESET);
    } else {
        printf(RED "Fail: auditd is not installed\n" RESET);
    }
}

void test_auditd_service_enabled() {
    printf("Test: 4.1.1.2 Ensure auditd service is enabled (Automated)\n");
    if (check_command("systemctl is-enabled auditd", "enabled")) {
        printf(GREEN "Pass: auditd service is enabled\n" RESET);
    } else {
        printf(RED "Fail: auditd service is not enabled\n" RESET);
    }
}

void test_auditd_enabled_at_boot() {
    printf("Test: 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)\n");
    if (!check_command("grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit=1\"", "")) {
        printf(GREEN "Pass: auditd is enabled at boot\n" RESET);
    } else {
        printf(RED "Fail: auditd is not enabled at boot\n" RESET);
    }
}

void test_audit_log_not_deleted() {
    printf("Test: 4.1.2.2 Ensure audit logs are not automatically deleted (Automated)\n");
    if (check_command("grep max_log_file_action /etc/audit/auditd.conf", "max_log_file_action = keep_logs")) {
        printf(GREEN "Pass: audit logs are configured to not be deleted\n" RESET);
    } else {
        printf(RED "Fail: audit logs may be automatically deleted\n" RESET);
    }
}

void test_audit_logs_on_full() {
    printf("Test: 4.1.2.3 Ensure system is disabled when audit logs are full (Automated)\n");
    int pass = 1;
    pass &= check_command("grep space_left_action /etc/audit/auditd.conf", "space_left_action = email");
    pass &= check_command("grep action_mail_acct /etc/audit/auditd.conf", "action_mail_acct = root");
    pass &= check_command("grep admin_space_left_action /etc/audit/auditd.conf", "admin_space_left_action = halt");

    if (pass) {
        printf(GREEN "Pass: System is configured to disable on full audit logs\n" RESET);
    } else {
        printf(RED "Fail: System is not configured correctly for full audit logs\n" RESET);
    }
}

void test_time_change_events_collected() {
    printf("Test: 4.1.3 Ensure events that modify date and time information are collected (Automated)\n");
    int pass = 1;
    
    pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change");
    pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change");
    pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
        "-a always,exit -F arch=b64 -S clock_settime -k time-change");
    pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
        "-a always,exit -F arch=b32 -S clock_settime -k time-change");
    pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
        "-w /etc/localtime -p wa -k time-change");

    if (pass) {
        printf(GREEN "Pass: Date and time modification events are collected\n" RESET);
    } else {
        printf(RED "Fail: Date and time modification events are not fully collected\n" RESET);
    }
}

void test_user_group_info_events() {
    printf("Test: 4.1.4 Ensure events that modify user/group information are collected (Automated)\n");
    if (check_command("grep identity /etc/audit/rules.d/*.rules", "-w /etc/group -p wa -k identity") ||
        check_command("grep identity /etc/audit/rules.d/*.rules", "-w /etc/passwd -p wa -k identity") ||
        check_command("grep identity /etc/audit/rules.d/*.rules", "-w /etc/gshadow -p wa -k identity") ||
        check_command("grep identity /etc/audit/rules.d/*.rules", "-w /etc/shadow -p wa -k identity") ||
        check_command("grep identity /etc/audit/rules.d/*.rules", "-w /etc/security/opasswd -p wa -k identity")) {
        printf(GREEN "Pass: Events that modify user/group information are collected\n" RESET);
    } else {
        printf(RED "Fail: Events that modify user/group information are not collected\n" RESET);
    }
}

void test_network_environment_events() {
    printf("Test: 4.1.5 Ensure events that modify the system's network environment are collected (Automated)\n");
    if (check_command("grep system-locale /etc/audit/rules.d/*.rules", "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale") ||
        check_command("grep system-locale /etc/audit/rules.d/*.rules", "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale") ||
        check_command("grep system-locale /etc/audit/rules.d/*.rules", "-w /etc/issue -p wa -k system-locale") ||
        check_command("grep system-locale /etc/audit/rules.d/*.rules", "-w /etc/issue.net -p wa -k system-locale") ||
        check_command("grep system-locale /etc/audit/rules.d/*.rules", "-w /etc/hosts -p wa -k system-locale") ||
        check_command("grep system-locale /etc/audit/rules.d/*.rules", "-w /etc/network -p wa -k system-locale")) {
        printf(GREEN "Pass: Events that modify the network environment are collected\n" RESET);
    } else {
        printf(RED "Fail: Events that modify the network environment are not collected\n" RESET);
    }
}

void test_mac_policy_events() {
    printf("Test: 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)\n");
    if (check_command("grep MAC-policy /etc/audit/rules.d/*.rules", "-w /etc/apparmor/ -p wa -k MAC-policy") ||
        check_command("grep MAC-policy /etc/audit/rules.d/*.rules", "-w /etc/apparmor.d/ -p wa -k MAC-policy")) {
        printf(GREEN "Pass: Events that modify MAC policies are collected\n" RESET);
    } else {
        printf(RED "Fail: Events that modify MAC policies are not collected\n" RESET);
    }
}

void test_login_logout_events() {
    printf("Test: 4.1.7 Ensure login and logout events are collected (Automated)\n");
    if (check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/faillog -p wa -k logins") ||
        check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/lastlog -p wa -k logins") ||
        check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/tallylog -p wa -k logins")) {
        printf(GREEN "Pass: Login and logout events are collected\n" RESET);
    } else {
        printf(RED "Fail: Login and logout events are not collected\n" RESET);
    }
}

void test_session_initiation_events() {
    printf("Test: 4.1.8 Ensure session initiation information is collected (Automated)\n");
    if (check_command("grep -E '(session|logins)' /etc/audit/rules.d/*.rules", "-w /var/run/utmp -p wa -k session") ||
        check_command("grep -E '(session|logins)' /etc/audit/rules.d/*.rules", "-w /var/log/wtmp -p wa -k logins") ||
        check_command("grep -E '(session|logins)' /etc/audit/rules.d/*.rules", "-w /var/log/btmp -p wa -k logins")) {
        printf(GREEN "Pass: Session initiation information is collected\n" RESET);
    } else {
        printf(RED "Fail: Session initiation information is not collected\n" RESET);
    }
}

void test_permission_modification_events() {
    printf("Test: 4.1.9 Ensure discretionary access control permission modification events are collected (Automated)\n");
    
    int pass = 1;

    pass &= check_command("grep perm_mod /etc/audit/rules.d/*.rules", "");
    
    // Check for 64-bit and 32-bit architectures for permission modification events
    char cmd_64[512];
    char cmd_32[512];

    snprintf(cmd_64, sizeof(cmd_64), "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=%d -F auid!=4294967295 -k perm_mod", MIN_UID);
    snprintf(cmd_32, sizeof(cmd_32), "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=%d -F auid!=4294967295 -k perm_mod", MIN_UID);

    pass &= check_command("auditctl -l | grep perm_mod", cmd_64);
    pass &= check_command("auditctl -l | grep perm_mod", cmd_32);

    if (pass) {
        printf(GREEN "Pass: Permission modification events are collected\n" RESET);
    } else {
        printf(RED "Fail: Permission modification events are not fully collected\n" RESET);
    }
}

void test_unsuccessful_file_access_attempts() {
    printf("Test: 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)\n");

    int pass = 1;

    char cmd_acces_b64[512];
    char cmd_acces_b32[512];

    snprintf(cmd_acces_b64, sizeof(cmd_acces_b64), "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=%d -F auid!=4294967295 -k access", MIN_UID);
    snprintf(cmd_acces_b32, sizeof(cmd_acces_b32), "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=%d -F auid!=4294967295 -k access", MIN_UID);

    pass &= check_command("auditctl -l | grep access", cmd_acces_b64);
    pass &= check_command("auditctl -l | grep access", cmd_acces_b32);

    if (pass) {
        printf(GREEN "Pass: Unauthorized file access attempts are collected\n" RESET);
    } else {
        printf(RED "Fail: Unauthorized file access attempts are not fully collected\n" RESET);
    }
}

void test_mounts_collection() {
    printf("4.1.12 - Ensure successful file system mounts are collected\n");
    if (check_audit_rules("mounts") == 0 && check_auditctl("mounts") == 0) {
        printf(GREEN "Pass: Succesful file system mounts are collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect succesful system mounts\n" RESET);
    }
}

void test_file_deletion_collection() {
    printf("4.1.13 - Ensure file deletion events by users are collected\n");
    if (check_audit_rules("delete") == 0 && check_auditctl("delete") == 0) {
        printf(GREEN "Pass: File deletion user events are collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect file deletion events by users.\n" RESET);
    }
}

void test_sudoers_scope_collection() {
    printf("4.1.14 - Ensure changes to system administration scope (sudoers) are collected\n");
    if (check_audit_rules("scope") == 0 && check_auditctl("scope") == 0) {
        printf(GREEN "Pass: Changes to sudoers collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect chnages to the sudoers\n" RESET);
    }
}

void test_sudo_command_execution_collection() {
    printf("4.1.15 - Ensure system administrator command executions (sudo) are collected\n");
    if (check_audit_rules("actions") == 0 && check_auditctl("actions") == 0) {
        printf(GREEN "Pass: System admin command executions collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect system admin command executions\n" RESET);
    }
}

void test_kernel_module_loading_collection() {
    printf("4.1.16 - Ensure kernel module loading and unloading is collected\n");
    if (check_audit_rules("modules") == 0 && check_auditctl("modules") == 0) {
        printf(GREEN "Pass: Kernel module load and unload successfuly collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect kernel module load and unload\n" RESET);
    }
}

int check_audit_rules(const char *pattern) {
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "grep %s /etc/audit/rules.d/*.rules > /dev/null 2>&1", pattern);
    int status = system(command);
    return status;
}

int check_auditctl(const char *pattern) {
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "auditctl -l | grep %s > /dev/null 2>&1", pattern);
    int status = system(command);
    return status;
}

void test_audit_immutable_configuration() {
    printf("4.1.17 - Ensure the audit configuration is immutable\n");
    
    // Check the last line of the audit rules
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "grep \"^\\s*[^#]\" /etc/audit/audit.rules | tail -1");
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to execute command\n");
        return;
    }

    char output[MAX_LINE_LENGTH];
    if (fgets(output, sizeof(output), fp) != NULL) {
        // Remove the newline character if present
        output[strcspn(output, "\n")] = 0;

        // Check if the last line matches the expected "-e 2" string
        if (strcmp(output, "-e 2") == 0) {
            printf(GREEN "Pass: Audit configuration is immutable\n" RESET);
        } else {
            printf(RED "Fail: Audit configuration is mutable.\n" RESET);
        }
    } else {
        printf(RED "Fail: Audit configuration is mutable\n" RESET);
    }

    fclose(fp);
}


// 4.2 - Configure Logging
void test_rsyslog_installed() {
    printf("Test: 4.2.1.1 Ensure rsyslog is installed (Automated)\n");
    if (check_command("dpkg -s rsyslog", "Status: install ok installed")) {
        printf(GREEN "Pass: rsyslog is installed\n" RESET);
    } else {
        printf(RED "Fail: rsyslog is not installed\n" RESET);
    }
}

void test_rsyslog_service_enabled() {
    printf("Test: 4.2.1.2 Ensure rsyslog Service is enabled (Automated)\n");
    if (check_command("systemctl is-enabled rsyslog", "enabled")) {
        printf(GREEN "Pass: rsyslog service is enabled\n" RESET);
    } else {
        printf(RED "Fail: rsyslog service is not enabled\n" RESET);
    }
}

void test_rsyslog_default_permissions() {
    printf("Test: 4.2.1.4 Ensure rsyslog default file permissions configured (Automated)\n");
    if (check_command("grep ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf", "0640") ||
        check_command("grep ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf", "0600") ||
        check_command("grep ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf", "0440") ||
        check_command("grep ^\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf", "0400")) {
        printf(GREEN "Pass: rsyslog file permissions are configured correctly\n" RESET);
    } else {
        printf(RED "Fail: rsyslog file permissions are not configured correctly\n" RESET);
    }
}

void test_journald_forward_to_rsyslog() {
    printf("Test: 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Automated)\n");
    if (check_command("grep -e \"^\\s*ForwardToSyslog\" /etc/systemd/journald.conf", "ForwardToSyslog=yes") &&
        !check_command("grep -e \"^\\s*ForwardToSyslog\" /etc/systemd/journald.conf", "#ForwardToSyslog=yes")) {
        printf(GREEN "Pass: journald is configured to send logs to rsyslog\n" RESET);
    } else {
        printf(RED "Fail: journald is not configured to send logs to rsyslog\n" RESET);
    }
}

void test_journald_compression() {
    printf("Test: 4.2.2.2 Ensure journald is configured to compress large log files (Automated)\n");
    if (check_command("grep -e \"^\\s*Compress\" /etc/systemd/journald.conf", "Compress=yes") &&
        !check_command("grep -e \"^\\s*Compress\" /etc/systemd/journald.conf", "#Compress=yes")) {
        printf(GREEN "Pass: journald compression is enabled\n" RESET);
    } else {
        printf(RED "Fail: journald compression is not enabled\n" RESET);
    }
}

void test_journald_persistent_storage() {
    printf("Test: 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Automated)\n");
    if (check_command("grep -e \"^\\s*Storage\" /etc/systemd/journald.conf", "Storage=persistent") &&
        !check_command("grep -e \"^\\s*Storage\" /etc/systemd/journald.conf", "#Storage=persistent")) {
        printf(GREEN "Pass: journald is configured to use persistent storage\n" RESET);
    } else {
        printf(RED "Fail: journald is not configured to use persistent storage\n" RESET);
    }
}

void skip_test(const char *test_name) {
    printf("Test: %s\n", test_name);
    printf(BLUE "Skip: This audit has to be done manually\n" RESET);
}

//----------------------------------------------------------------------------------------------------------------------------------
//Added by Pujit, to be rechecked after running

//Checks if a service is enabled and running
int check_service(const char *service) 
{
    char command[100];
    sprintf(command, "systemctl is-enabled %s 2>/dev/null", service);
    if (system(command) != 0) return 0;

    sprintf(command, "systemctl status %s | grep 'Active: active (running)' >/dev/null", service);
    return system(command) == 0;
}

//Checks file permissions and ownership
int check_permissions(const char *filepath, mode_t mode, uid_t uid, gid_t gid) 
{
    struct stat fileStat;
    if (stat(filepath, &fileStat) != 0) return 0; // File does not exist

    if (fileStat.st_uid != uid || fileStat.st_gid != gid) return 0;
    return (fileStat.st_mode & 0777) == mode;
}

//Checks if file exists
int file_exists(const char *filepath) 
{
    return access(filepath, F_OK) == 0;
}

int check_command(const char *command, const char *expected_output) 
{
    char result[256];
    FILE *fp = popen(command, "r");
    if (fp == NULL) return 0;
    fgets(result, sizeof(result), fp);
    pclose(fp);
    return strstr(result, expected_output) != NULL;
}

int check_permissions(const char *filepath, mode_t mode, uid_t uid, gid_t gid) 
{
    struct stat fileStat;
    if (stat(filepath, &fileStat) != 0) return 0;
    if (fileStat.st_uid != uid || fileStat.st_gid != gid) return 0;
    return (fileStat.st_mode & 0777) == mode;
}

// Tests
void test_cron_enabled_and_running() //The cron daemon schedules and executes tasks at specified times. This test ensures that cron is active and will continue to run scheduled jobs.
{
    printf("Test: 5.1.1 Ensure cron daemon is enabled and running\n");
    if (check_command("systemctl is-enabled cron", "enabled") && check_command("systemctl status cron | grep 'Active: active (running)'", "active (running)")) 
    {
        printf("\033[1;32mPass: cron daemon is enabled and running\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: cron daemon is not enabled or running\033[0m\n");
    }
}

void test_crontab_permissions() //The crontab file contains system-wide scheduled tasks. Restricting its permissions prevents unauthorized users from modifying scheduled jobs.
{
    printf("Test: 5.1.2 Ensure permissions on /etc/crontab are configured\n");
    if (check_permissions("/etc/crontab", 0700, 0, 0)) 
    {
        printf("\033[1;32mPass: /etc/crontab permissions are correct\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: /etc/crontab permissions are incorrect\033[0m\n");
    }
}

//Checks permissions on various cron directories: /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, and /etc/cron.d.
void test_cron_directories_permissions(const char *directory, const char *test_name) //These directories contain scripts that are run by cron at regular intervals (hourly, daily, weekly, monthly, or as specified). Securing their permissions helps protect scheduled tasks.
{
    printf("Test: %s Ensure permissions on %s are configured\n", test_name, directory);
    if (check_permissions(directory, 0700, 0, 0)) 
    {
        printf("\033[1;32mPass: %s permissions are correct\033[0m\n", directory);
    } 
    else 
    {
        printf("\033[1;31mFail: %s permissions are incorrect\033[0m\n", directory);
    }
}

//Ensures that cron jobs are restricted to authorized users only.
void test_cron_restricted_to_authorized_users() //Prevents unauthorized users from scheduling cron jobs, which could lead to security risks or unauthorized system modifications.
{
    printf("Test: 5.1.8 Ensure cron is restricted to authorized users\n");
    if (!access("/etc/cron.deny", F_OK) &&
        check_permissions("/etc/cron.allow", 0640, 0, 0)) 
    {
        printf("\033[1;32mPass: cron is restricted to authorized users\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: cron is not restricted to authorized users\033[0m\n");
    }
}

//Ensures that access to the at command (used for scheduling one-time jobs) is restricted to authorized users.
void test_at_restricted_to_authorized_users() //Limits the ability to schedule jobs with at, preventing unauthorized users from running scheduled commands, which could impact security.
{
    printf("Test: 5.1.9 Ensure at is restricted to authorized users\n");
    if (!access("/etc/at.deny", F_OK) && check_permissions("/etc/at.allow", 0640, 0, 0)) 
    {
        printf("\033[1;32mPass: at is restricted to authorized users\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: at is not restricted to authorized users\033[0m\n");
    }
}

int check_command_5_2(const char *command) 
{
    int status;
    status = system(command);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

//Ensures sudo is installed
void test_sudo_installed() //The sudo command is essential for managing access to elevated privileges. Ensuring sudo is installed confirms that users can be given controlled access to superuser privileges when necessary.
{
    printf("Test: 5.2.1 Ensure sudo is installed\n");
    if (check_command_5_2("dpkg -s sudo") || check_command_5_2("dpkg -s sudo-ldap")) 
    {
        printf("\033[1;32mPass: sudo is installed\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: sudo is not installed\033[0m\n");
    }
}

//Ensures sudo commands use pty
void test_sudo_commands_use_pty() //Running sudo commands in a pseudo-terminal adds security by providing better command logging and accountability. A pseudo-terminal can log sudo usage more reliably, especially in scenarios involving remote or script-based access.
{
    printf("Test: 5.2.2 Ensure sudo commands use pty\n");
    if (check_command_5_2("grep -Ei '^[[:space:]]*Defaults[[:space:]]+([^#]+,[[:space:]]*)?use_pty(,[[:space:]]+\\S+[[:space:]]*)*(\\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*")) 
    {
        printf("\033[1;32mPass: sudo commands use pty\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: sudo commands do not use pty\033[0m\n");
    }
}

//Ensures sudo log file exists
void test_sudo_log_file_exists() //Logging sudo command usage is crucial for auditing and tracking actions performed with elevated privileges. Setting a specific logfile for sudo helps administrators monitor privileged commands, track changes, and investigate security incidents.
{
    printf("Test: 5.2.3 Ensure sudo log file exists\n");
    if (check_command_5_2("grep -Ei '^[[:space:]]*Defaults[[:space:]]+logfile=\\S+' /etc/sudoers /etc/sudoers.d/*")) 
    {
        printf("\033[1;32mPass: sudo log file is configured\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: sudo log file is not configured\033[0m\n");
    }
}

int check_command_5_4(const char *command, const char *expected_output) 
{
    char buffer[128];
    FILE *fp = popen(command, "r");
    if (fp == NULL) 
    {
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) 
    {
        if (strstr(buffer, expected_output) != NULL) 
        {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

//Ensures password creation requirements are configured
void test_password_creation_requirements() //Verifies that password creation requirements such as minimum length (minlen) and the number of required character classes (minclass) are set to secure values (e.g., minlen >= 14 and minclass >= 4). 
{
    printf("Test: 5.4.1 Ensure password creation requirements are configured\n");

    char command[128];
    snprintf(command, sizeof(command), "grep '^\s*minlen\s*' /etc/security/pwquality.conf");
    char minlen_output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(minlen_output, sizeof(minlen_output), fp) != NULL) 
    {
        int minlen = atoi(strchr(minlen_output, '=') + 1); // Extract number after "minlen = "
        fclose(fp);
        snprintf(command, sizeof(command), "grep '^\s*minclass\s*' /etc/security/pwquality.conf");
        fp = popen(command, "r");
        if (fp != NULL && fgets(minlen_output, sizeof(minlen_output), fp) != NULL) 
        {
            int pwquality = atoi(strchr(minlen_output, '=') + 1); // Extract number after "minclass = "
            fclose(fp);
            if (minlen < 14 || pwquality < 4) 
            {
                if (check_command_5_4("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "dcredit = -1") &&
                    check_command_5_4("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "ucredit = -1") &&
                    check_command_5_4("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "lcredit = -1") &&
                    check_command_5_4("grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf", "ocredit = -1") &&
                    check_command_5_4("grep -E '^\s*password\s+(requisite|required)\s+pam_pwquality.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password", "retry=[1-3]")) {
                    printf("\033[1;32mPass: Password creation requirements are configured correctly\033[0m\n");
                } 
                else 
                {
                    printf("\033[1;31mFail: Password creation requirements are not configured correctly\033[0m\n");
                }
            } 
            else 
            {
                printf("\033[1;32mPass: Password creation requirements are configured correctly\033[0m\n");
            }
        }
    }
}

//Ensures lockout for failed password attempts is configured
void test_lockout_for_failed_password_attempts() //Ensures that failed password attempts are logged, and lockout is configured using pam_tally2 and pam_deny. It verifies that failed login attempts will be denied after 5 unsuccessful attempts and the account will be locked for 900 seconds.
{
    printf("Test: 5.4.2 Ensure lockout for failed password attempts is configured\n");
    if (check_command_5_4("grep \"pam_tally2\" /etc/pam.d/common-auth", "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900") &&
        check_command_5_4("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account requisite pam_deny.so") &&
        check_command_5_4("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account required pam_tally2.so")) 
    {
        printf("\033[1;32mPass: Lockout for failed password attempts is configured\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: Lockout for failed password attempts is not configured\033[0m\n");
    }
}

//Ensures password reuse is limited
void test_password_reuse_limited() //Verifies that password reuse is limited by checking if the pam_pwhistory.so module is configured with the remember parameter to prevent users from reusing the same password within the last 5 changes.
{
    printf("Test: 5.4.3 Ensure password reuse is limited\n");
    if (check_command_5_4("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "password required pam_pwhistory.so") &&
        check_command_5_4("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "remember=5")) 
    {
        printf("\033[1;32mPass: Password reuse is limited\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: Password reuse is not limited\033[0m\n");
    }
}

//Ensures password hashing algorithm is SHA-512
void test_password_hashing_algorithm_sha512() //Ensures that the system uses the SHA-512 algorithm for hashing passwords by checking the /etc/pam.d/common-password configuration file.
{
    printf("Test: 5.4.4 Ensure password hashing algorithm is SHA-512\n");
    if (check_command_5_4("grep -E '^\s*password\s+(\S+\s+)+pam_unix.so\s+(\S+\s+)*sha512\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password", "sha512")) 
    {
        printf("\033[1;32mPass: Password hashing algorithm is SHA-512\033[0m\n");
    } 
    else 
    {
        printf("\033[1;31mFail: Password hashing algorithm is not SHA-512\033[0m\n");
    }
}

int check_command_5_5(const char *command, const char *expected_output) 
{
    char buffer[128];
    FILE *fp = popen(command, "r");
    if (fp == NULL) 
    {
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) 
    {
        if (strstr(buffer, expected_output) != NULL) 
        {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

//Ensures minimum days between password changes is configured
void test_minimum_days_between_password_changes() //Checks whether the system enforces a minimum number of days between password changes. The configuration for this is found in /etc/login.defs under the PASS_MIN_DAYS setting.
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
            }
            fclose(fp);
        } 
        else 
        {
            printf("\033[1;31mFail: Minimum days between password changes is not configured\n\033[0m");
        }
    }
}

//Ensures password expiration is 365 days or less
void test_password_expiration() //Ensures that the system enforces a password expiration policy of no more than 365 days.
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
            }
            fclose(fp);
        } 
        else 
        {
            printf("\033[1;31mFail: Password expiration exceeds 365 days\n\033[0m");
        }
    }
}

//Ensures password expiration warning days is 7 or more
void test_password_expiration_warning() //It checks the PASS_WARN_AGE setting in /etc/login.defs to ensure it is greater than 6 (i.e., 7 or more days).
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
            }
            fclose(fp);
        } 
        else 
        {
            printf("\033[1;31mFail: Password expiration warning days is less than 7\n\033[0m");
        }
    }
}

//Ensures inactive password lock is 30 days or less
void test_inactive_password_lock() //Retrieves the INACTIVE setting from useradd -D and ensures it is less than 31 days.
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
            }
            fclose(fp);
        } 
        else 
        {
            printf("\033[1;31mFail: Inactive password lock exceeds 30 days or is not configured\n\033[0m");
        }
    }
}

//Ensures all users last password change date is in the past
void test_users_last_password_change() //It retrieves the last password change date for all users from /etc/shadow using the chage command and checks if any user has a future date for their password change.
{
    printf("Test: 5.5.1.5 Ensure all users last password change date is in the past\n");

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
    }
    fclose(fp);
}

//Ensures system accounts are secured
void test_system_accounts_secured() //Ensures that no system accounts have invalid shell settings (e.g., /usr/sbin/nologin or /bin/false).
{
    printf("Test: 5.5.2 Ensure system accounts are secured\n");

    if (check_command_5_5("awk -F: '$1!~/(root|sync|shutdown|halt|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)' && $7!~/((\\/usr)?\\/sbin\\/nologin)/ && $7!~/(\\/bin)?\\/false/ {print}' /etc/passwd", "") &&
        check_command_5_5("awk -F: '($1!~/(root|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'", "")) 
    {
        printf("\033[1;32mPass: System accounts are secured\n\033[0m");
    } 
    else 
    {
        printf("\033[1;31mFail: System accounts are not secured\n\033[0m");
    }
}

//Ensures default group for the root account is GID 0
void test_default_group_for_root() //Checks the /etc/passwd file to ensure that the root account's group ID is 0.
{
    printf("Test: 5.5.3 Ensure default group for the root account is GID 0\n");

    if (check_command_5_5("grep \"^root:\" /etc/passwd | cut -f4 -d:", "0")) 
    {
        printf("\033[1;32mPass: Default group for root is GID 0\n\033[0m");
    } 
    else 
    {
        printf("\033[1;31mFail: Default group for root is not GID 0\n\033[0m");
    }
}

//Ensures default user umask is 027 or more restrictive
void test_default_user_umask() //Runs two checks: one to confirm that the umask is set and another to ensure it’s not set to a less restrictive value.
{
    printf("Test: 5.5.4 Ensure default user umask is 027 or more restrictive\n");

    if (check_command_5_5("check_default_umask", "Default user umask is set") && check_command_5_5("check_for_less_restrictive_umask", "")) 
    {
        printf("\033[1;32mPass: Default user umask is 027 or more restrictive\n\033[0m");
    } 
    else 
    {
        printf("\033[1;31mFail: Default user umask is not 027 or more restrictive\n\033[0m");
    }
}

//Ensures default user shell timeout is 900 seconds or less
void test_default_user_shell_timeout() //Checks the shell timeout settings (specifically the TMOUT variable) to ensure it’s properly configured to meet this requirement.
{
    printf("Test: 5.5.5 Ensure default user shell timeout is 900 seconds or less\n");

    if (check_command_5_5("check_timeout_settings", "PASSED")) 
    {
        printf("\033[1;32mPass: Default user shell timeout is 900 seconds or less\n\033[0m");
    } 
    else 
    {
        printf("\033[1;31mFail: Default user shell timeout exceeds 900 seconds\n\033[0m");
    }
}

//Ensures root login is restricted to system console (Manual)
void test_root_login_restricted() //This test is marked as skip because it requires manual inspection of system settings that can’t be easily automated.
{
    printf("Test: 5.6 Ensure root login is restricted to system console\n");
    printf("\033[1;33mThis audit has to be done manually\033[0m\n");
}

// Test: Ensure access to the su command is restricted
void test_access_to_su_command() //It checks for the pam_wheel.so module in /etc/pam.d/su to ensure that the wheel group is used to restrict su access.
{
    printf("Test: 5.7 Ensure access to the su command is restricted\n");

    char command[128];
    snprintf(command, sizeof(command), "grep pam_wheel.so /etc/pam.d/su");
    if (check_command_5_5(command, "auth required pam_wheel.so use_uid group=")) 
    {
        printf("\033[1;32mPass: Access to the su command is restricted\n\033[0m");
    } 
    else 
    {
        printf("\033[1;31mFail: Access to the su command is not restricted\n\033[0m");
    }
}
//Pujit's additions end here
//----------------------------------------------------------------------------------------------------------------------------------

int main() 
{
    // 4.1 - Configure System Accounting
    test_auditd_installed();    // 4.1.1.1
    test_auditd_service_enabled();  // 4.1.1.2
    test_auditd_enabled_at_boot();  // 4.1.1.3
    skip_test("4.1.1.4 Ensure audit_backlog_limit is sufficient (Manual)"); // 4.1.1.4
    skip_test("4.1.2.1 Ensure audit log storage size is configured (Manual)");  // 4.1.2.1
    test_audit_log_not_deleted();   // 4.1.2.2
    test_audit_logs_on_full();  // 4.1.2.3
    test_time_change_events_collected();    // 4.1.3
    test_user_group_info_events();  // 4.1.4
    test_network_environment_events();  // 4.1.5
    test_mac_policy_events();   // 4.1.6
    test_login_logout_events(); // 4.1.7
    test_session_initiation_events();   // 4.1.8
    test_permission_modification_events();  // 4.1.9
    test_unsuccessful_file_access_attempts();   // 4.1.10
    skip_test("4.1.11 Ensure use of privileged commands is collected (Manual)");    // 4.1.11
    test_mounts_collection();   // 4.1.12
    test_file_deletion_collection();    // 4.1.13
    test_sudoers_scope_collection();    // 4.1.14
    test_sudo_command_execution_collection();   // 4.1.15
    test_kernel_module_loading_collection();    // 4.1.16
    test_audit_immutable_configuration();   // 4.1.17

    // 4.2 - Configure Logging
    test_rsyslog_installed();
    test_rsyslog_service_enabled();
    skip_test("4.2.1.3 Ensure logging is configured (Manual)");
    test_rsyslog_default_permissions();
    skip_test("4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Manual)");
    skip_test("4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts (Manual)");
    test_journald_forward_to_rsyslog();
    test_journald_compression();
    test_journald_persistent_storage();
    skip_test("4.2.3 Ensure permissions on all logfiles are configured (Manual)");


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

    //5.1
    test_cron_enabled_and_running();
    test_crontab_permissions();
    test_cron_directories_permissions("/etc/cron.hourly", "5.1.3");
    test_cron_directories_permissions("/etc/cron.daily", "5.1.4");
    test_cron_directories_permissions("/etc/cron.weekly", "5.1.5");
    test_cron_directories_permissions("/etc/cron.monthly", "5.1.6");
    test_cron_directories_permissions("/etc/cron.d", "5.1.7");
    test_cron_restricted_to_authorized_users();
    test_at_restricted_to_authorized_users();

    //5.2
    test_sudo_installed();
    test_sudo_commands_use_pty();
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
    test_default_group_for_root();
    test_default_user_umask();
    test_default_user_shell_timeout();
    test_root_login_restricted();
    test_access_to_su_command();
    return 0;
}
