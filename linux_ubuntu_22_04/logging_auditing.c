#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIN_UID 1000
#define MAX_LINE_LENGTH 512
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define RESET "\033[0m"
int AUDITD_INSTALLED = 0;

int check_audit_rules(const char *pattern);
int check_auditctl(const char *pattern);

int check_command(const char *command, const char *expected_output) {
    char buffer[256];
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        perror("Unable to run test as popen failed");
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
        AUDITD_INSTALLED = 1;
    } else {
        printf(RED "Fail: auditd is not installed\n" RESET);
        printf("Action: Run 'sudo apt install auditd audispd-plugins'\n");
        AUDITD_INSTALLED = 0;
    }
}

void test_auditd_service_enabled() {
    printf("Test: 4.1.1.2 Ensure auditd service is enabled (Automated)\n");
    if (check_command("systemctl is-enabled auditd", "enabled")) {
        printf(GREEN "Pass: auditd service is enabled\n" RESET);
    } else {
        if (AUDITD_INSTALLED) printf(RED "Fail: auditd service is not enabled\n" RESET);
        else printf(BLUE "auditd is not installed\n" RESET);
        printf("Action: Run 'sudo systemctl enable auditd'\n");

    }
}

void test_auditd_enabled_at_boot() {
    printf("Test: 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)\n");
    if (!check_command("grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"audit=1\"", "")) {
        printf(GREEN "Pass: auditd is enabled at boot\n" RESET);
    } else {
        if (AUDITD_INSTALLED) printf(RED "Fail: auditd is not enabled at boot\n" RESET);
        else printf(BLUE "auditd is not installed\n" RESET);
        printf("Action: Run 'sudo apt install auditd audispd-plugins'\n");

    }
}

void test_audit_log_not_deleted() {
    printf("Test: 4.1.2.2 Ensure audit logs are not automatically deleted (Automated)\n");
    if (check_command("grep max_log_file_action /etc/audit/auditd.conf", "max_log_file_action = keep_logs")) {
        printf(GREEN "Pass: audit logs are configured to not be deleted\n" RESET);
    } else {
        printf(RED "Fail: audit logs may be automatically deleted\n" RESET);
        printf("Action: Edit /etc/audit/auditd.conf and set 'max_log_file_action = keep_logs'\n");

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
        printf("Action: Edit /etc/audit/auditd.conf and ensure:\n");
        printf("  - space_left_action = email\n");
        printf("  - action_mail_acct = root\n");
        printf("  - admin_space_left_action = halt\n");
    }
}

// void test_time_change_events_collected() {
//     printf("Test: 4.1.3 Ensure events that modify date and time information are collected (Automated)\n");
//     int pass = 1;
    
//     pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
//         "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change");
//     pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
//         "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change");
//     pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
//         "-a always,exit -F arch=b64 -S clock_settime -k time-change");
//     pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
//         "-a always,exit -F arch=b32 -S clock_settime -k time-change");
//     pass &= check_command("grep time-change /etc/audit/rules.d/*.rules",
//         "-w /etc/localtime -p wa -k time-change");

//     if (pass) {
//         printf(GREEN "Pass: Date and time modification events are collected\n" RESET);
//     } else {
//         printf(RED "Fail: Date and time modification events are not fully collected\n" RESET);
//     }
// }

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
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -w /etc/group -p wa -k identity\n");
        printf("  -w /etc/passwd -p wa -k identity\n");
        printf("  -w /etc/gshadow -p wa -k identity\n");
        printf("  -w /etc/shadow -p wa -k identity\n");
        printf("  -w /etc/security/opasswd -p wa -k identity\n");
        printf("Then run 'sudo augenrules --load'\n\n");

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
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n");
        printf("  -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale\n");
        printf("  -w /etc/issue -p wa -k system-locale\n");
        printf("  -w /etc/issue.net -p wa -k system-locale\n");
        printf("  -w /etc/hosts -p wa -k system-locale\n");
        printf("  -w /etc/network -p wa -k system-locale\n");
        printf("Then run 'sudo augenrules --load'\n\n");
    }
}

// void test_mac_policy_events() {
//     printf("Test: 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)\n");
//     if (check_command("grep MAC-policy /etc/audit/rules.d/*.rules", "-w /etc/apparmor/ -p wa -k MAC-policy") ||
//         check_command("grep MAC-policy /etc/audit/rules.d/*.rules", "-w /etc/apparmor.d/ -p wa -k MAC-policy")) {
//         printf(GREEN "Pass: Events that modify MAC policies are collected\n" RESET);
//     } else {
//         printf(RED "Fail: Events that modify MAC policies are not collected\n" RESET);
//     }
// }

void test_login_logout_events() {
    printf("Test: 4.1.7 Ensure login and logout events are collected (Automated)\n");
    if (check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/faillog -p wa -k logins") ||
        check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/lastlog -p wa -k logins") ||
        check_command("grep logins /etc/audit/rules.d/*.rules", "-w /var/log/tallylog -p wa -k logins")) {
        printf(GREEN "Pass: Login and logout events are collected\n" RESET);
    } else {
        printf(RED "Fail: Login and logout events are not collected\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -w /var/log/faillog -p wa -k logins\n");
        printf("  -w /var/log/lastlog -p wa -k logins\n");
        printf("  -w /var/log/tallylog -p wa -k logins\n");
        printf("Then run 'sudo augenrules --load'\n");

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
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -w /var/run/utmp -p wa -k session\n");
        printf("  -w /var/log/wtmp -p wa -k logins\n");
        printf("  -w /var/log/btmp -p wa -k logins\n");
        printf("Then run 'sudo augenrules --load'\n");
 
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
        printf(RED "Fail: Permission modification events are not fully collected\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n");
        printf("  -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n");
        printf("Then run 'sudo augenrules --load'\n");

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
        printf(RED "[IMP] Fail: Unauthorized file access attempts are not fully collected\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n");
        printf("  -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n");
        printf("Then run 'sudo augenrules --load'\n");

    }
}

void test_mounts_collection() {
    printf("4.1.12 - Ensure successful file system mounts are collected\n");
    if (check_audit_rules("mounts") == 0 && check_auditctl("mounts") == 0) {
        printf(GREEN "Pass: Succesful file system mounts are collected\n" RESET);
    } else {
        printf(RED "Fail: Unable to collect succesful system mounts\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n");
        printf("  -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n");
        printf("Then run 'sudo augenrules --load'\n");

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
        printf(RED "[IMP] Fail: Unable to collect changes to the sudoers\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -w /etc/sudoers -p wa -k scope\n");
        printf("  -w /etc/sudoers.d/ -p wa -k scope\n");
        printf("Then run 'sudo augenrules --load'\n");

    }
}

void test_sudo_command_execution_collection() {
    printf("4.1.15 - Ensure system administrator command executions (sudo) are collected\n");
    if (check_audit_rules("actions") == 0 && check_auditctl("actions") == 0) {
        printf(GREEN "Pass: System admin command executions collected\n" RESET);
    } else {
        printf(RED "[IMP] Fail: Unable to collect system admin command executions\n" RESET);
        printf("Action: Add the following lines to /etc/audit/rules.d/audit.rules:\n");
        printf("  -a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions\n");
        printf("  -a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions\n");
        printf("Then run 'sudo augenrules --load'\n");

    }
}

// void test_kernel_module_loading_collection() {
//     printf("4.1.16 - Ensure kernel module loading and unloading is collected\n");
//     if (check_audit_rules("modules") == 0 && check_auditctl("modules") == 0) {
//         printf(GREEN "Pass: Kernel module load and unload successfuly collected\n" RESET);
//     } else {
//         printf(RED "Fail: Unable to collect kernel module load and unload\n" RESET);
//     }
// }

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
        output[strcspn(output, "\n")] = 0;

        // expected output "-e 2" string
        if (strcmp(output, "-e 2") == 0) {
            printf(GREEN "Pass: Audit configuration is immutable\n" RESET);
        } else {
            printf(RED "[IMP] Fail: Audit configuration is mutable.\n" RESET);
        }
    } else {
        printf(RED "[IMP] Fail: Audit configuration is mutable\n" RESET);
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
        printf("Action: Run 'sudo apt install rsyslog'\n");
    }
}

void test_rsyslog_service_enabled() {
    printf("Test: 4.2.1.2 Ensure rsyslog Service is enabled (Automated)\n");
    if (check_command("systemctl is-enabled rsyslog", "enabled")) {
        printf(GREEN "Pass: rsyslog service is enabled\n" RESET);
    } else {
        printf(RED "Fail: rsyslog service is not enabled\n" RESET);
        printf("Action: Run 'sudo systemctl enable rsyslog'\n");
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
        printf("Action: Edit /etc/systemd/journald.conf and set 'Compress=yes'\n");
        printf("Then run 'sudo systemctl restart systemd-journald'\n");
    }
}

// void test_journald_forward_to_rsyslog() {
//     printf("Test: 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Automated)\n");
//     if (check_command("grep -e \"^\\s*ForwardToSyslog\" /etc/systemd/journald.conf", "ForwardToSyslog=yes") &&
//         !check_command("grep -e \"^\\s*ForwardToSyslog\" /etc/systemd/journald.conf", "#ForwardToSyslog=yes")) {
//         printf(GREEN "Pass: journald is configured to send logs to rsyslog\n" RESET);
//     } else {
//         printf(RED "Fail: journald is not configured to send logs to rsyslog\n" RESET);
//     }
// }

// void test_journald_compression() {
//     printf("Test: 4.2.2.2 Ensure journald is configured to compress large log files (Automated)\n");
//     if (check_command("grep -e \"^\\s*Compress\" /etc/systemd/journald.conf", "Compress=yes") &&
//         !check_command("grep -e \"^\\s*Compress\" /etc/systemd/journald.conf", "#Compress=yes")) {
//         printf(GREEN "Pass: journald compression is enabled\n" RESET);
//     } else {
//         printf(RED "Fail: journald compression is not enabled\n" RESET);
//     }
// }

// void test_journald_persistent_storage() {
//     printf("Test: 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Automated)\n");
//     if (check_command("grep -e \"^\\s*Storage\" /etc/systemd/journald.conf", "Storage=persistent") &&
//         !check_command("grep -e \"^\\s*Storage\" /etc/systemd/journald.conf", "#Storage=persistent")) {
//         printf(GREEN "Pass: journald is configured to use persistent storage\n" RESET);
//     } else {
//         printf(RED "Fail: journald is not configured to use persistent storage\n" RESET);
//     }
// }

void skip_test(const char *test_name) {
    printf("Test: %s\n", test_name);
    printf(BLUE "Skip: This audit has to be done manually\n" RESET);
}

int main() {
    // 4.1 - Configure System Accounting
    test_auditd_installed();    // 4.1.1.1
    sleep(1);
    test_auditd_service_enabled();  // 4.1.1.2
    sleep(1);
    test_auditd_enabled_at_boot();  // 4.1.1.3
    sleep(1);
    skip_test("4.1.1.4 Ensure audit_backlog_limit is sufficient (Manual)"); // 4.1.1.4
    sleep(1);
    skip_test("4.1.2.1 Ensure audit log storage size is configured (Manual)");  // 4.1.2.1
    sleep(1);
    test_audit_log_not_deleted();   // 4.1.2.2
    sleep(1);
    test_audit_logs_on_full();  // 4.1.2.3
    sleep(1);
    // test_time_change_events_collected();    // 4.1.3
    test_user_group_info_events();  // 4.1.4
    sleep(1);
    test_network_environment_events();  // 4.1.5
    sleep(1);
    // test_mac_policy_events();   // 4.1.6
    test_login_logout_events(); // 4.1.7
    sleep(1);
    test_session_initiation_events();   // 4.1.8
    sleep(1);
    test_permission_modification_events();  // 4.1.9
    sleep(1);
    test_unsuccessful_file_access_attempts();   // 4.1.10
    sleep(1);
    skip_test("4.1.11 Ensure use of privileged commands is collected (Manual)");    // 4.1.11
    sleep(1);
    test_mounts_collection();   // 4.1.12
    sleep(1);
    test_file_deletion_collection();    // 4.1.13
    sleep(1);
    test_sudoers_scope_collection();    // 4.1.14
    sleep(1);
    test_sudo_command_execution_collection();   // 4.1.15
    sleep(1);
    // test_kernel_module_loading_collection();    // 4.1.16
    test_audit_immutable_configuration();   // 4.1.17
    sleep(2);

    // 4.2 - Configure Logging
    test_rsyslog_installed();
    sleep(1);
    test_rsyslog_service_enabled();
    sleep(1);
    skip_test("4.2.1.3 Ensure logging is configured (Manual)");
    sleep(1);
    test_rsyslog_default_permissions();
    sleep(1);
    skip_test("4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Manual)");
    sleep(1);
    skip_test("4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts (Manual)");
    sleep(1);
    // test_journald_forward_to_rsyslog();
    // test_journald_compression();
    // test_journald_persistent_storage();
    skip_test("4.2.3 Ensure permissions on all logfiles are configured (Manual)");

    return 0;
}
