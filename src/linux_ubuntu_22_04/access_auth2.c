#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <src/common/colors.h>

#define MIN_UID 1000
#define MAX_LINE_LENGTH 512

int check_command(const char *command, const char *expected_output)
{
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

//----------------------------------------------------------------------------------------------------------------------------------
//Added by Pujit, to be rechecked after running
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

// Tests
void test_cron_enabled_and_running() //The cron daemon schedules and executes tasks at specified times. This test ensures that cron is active and will continue to run scheduled jobs.
{
    printf("Test: 5.1.1 Ensure cron daemon is enabled and running (Automated)\n");
    if (check_command("systemctl is-enabled cron", "enabled") && check_command("systemctl status cron | grep 'Active: active (running)'", "active (running)")) 
    {
        printf(GREEN "Pass: cron daemon is enabled and running\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: cron daemon is not enabled or running\n" RESET);
    }
}

void test_crontab_permissions() //The crontab file contains system-wide scheduled tasks. Restricting its permissions prevents unauthorized users from modifying scheduled jobs.
{
    printf("Test: 5.1.2 Ensure permissions on /etc/crontab are configured (Automated)\n");
    if (check_permissions("/etc/crontab", 0700, 0, 0)) 
    {
        printf(GREEN "Pass: /etc/crontab permissions are correct\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: /etc/crontab permissions are incorrect\n" RESET);
    }
}

//Checks permissions on various cron directories: /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, and /etc/cron.d.
void test_cron_directories_permissions(const char *directory, const char *test_name) //These directories contain scripts that are run by cron at regular intervals (hourly, daily, weekly, monthly, or as specified). Securing their permissions helps protect scheduled tasks.
{
    printf("Test: %s Ensure permissions on %s are configured (Automated)\n", test_name, directory);
    if (check_permissions(directory, 0700, 0, 0)) 
    {
        printf(GREEN "Pass: %s permissions are correct\n" RESET, directory);
    } 
    else 
    {
        printf(RED "Fail: %s permissions are incorrect\n" RESET, directory);
    }
}

//Ensures that cron jobs are restricted to authorized users only.
void test_cron_restricted_to_authorized_users() //Prevents unauthorized users from scheduling cron jobs, which could lead to security risks or unauthorized system modifications.
{
    printf("Test: 5.1.8 Ensure cron is restricted to authorized users (Automated)\n");
    if (!access("/etc/cron.deny", F_OK) &&
        check_permissions("/etc/cron.allow", 0640, 0, 0)) 
    {
        printf(GREEN "Pass: cron is restricted to authorized users\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: cron is not restricted to authorized users\n" RESET);
    }
}

//Ensures that access to the at command (used for scheduling one-time jobs) is restricted to authorized users.
void test_at_restricted_to_authorized_users() //Limits the ability to schedule jobs with at, preventing unauthorized users from running scheduled commands, which could impact security.
{
    printf("Test: 5.1.9 Ensure at is restricted to authorized users (Automated)\n");
    if (!access("/etc/at.deny", F_OK) && check_permissions("/etc/at.allow", 0640, 0, 0)) 
    {
        printf(GREEN "Pass: at is restricted to authorized users\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: at is not restricted to authorized users\n" RESET);
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
    printf("Test: 5.2.1 Ensure sudo is installed (Automated)\n");
    if (check_command_5_2("dpkg -s sudo") || check_command_5_2("dpkg -s sudo-ldap")) 
    {
        printf(GREEN "Pass: sudo is installed\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: sudo is not installed\n" RESET);
    }
}

//Ensures sudo commands use pty
void test_sudo_commands_use_pty() //Running sudo commands in a pseudo-terminal adds security by providing better command logging and accountability. A pseudo-terminal can log sudo usage more reliably, especially in scenarios involving remote or script-based access.
{
    printf("Test: 5.2.2 Ensure sudo commands use pty (Automated)\n");
    if (check_command_5_2("grep -Ei '^[[:space:]]*Defaults[[:space:]]+([^#]+,[[:space:]]*)?use_pty(,[[:space:]]+\\S+[[:space:]]*)*(\\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*")) 
    {
        printf(GREEN "Pass: sudo commands use pty\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: sudo commands do not use pty\n" RESET);
    }
}

//Ensures sudo log file exists
void test_sudo_log_file_exists() //Logging sudo command usage is crucial for auditing and tracking actions performed with elevated privileges. Setting a specific logfile for sudo helps administrators monitor privileged commands, track changes, and investigate security incidents.
{
    printf("Test: 5.2.3 Ensure sudo log file exists (Automated)\n");
    if (check_command_5_2("grep -Ei '^[[:space:]]*Defaults[[:space:]]+logfile=\\S+' /etc/sudoers /etc/sudoers.d/*")) 
    {
        printf(GREEN "Pass: sudo log file is configured\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: sudo log file is not configured\n" RESET);
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
    printf("Test: 5.4.1 Ensure password creation requirements are configured (Automated)\n");

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
                    printf(GREEN "Pass: Password creation requirements are configured correctly\n" RESET);
                } 
                else 
                {
                    printf(RED "Fail: Password creation requirements are not configured correctly\n" RESET);
                }
            } 
            else 
            {
                printf(GREEN "Pass: Password creation requirements are configured correctly\n" RESET);
            }
        }
    }
}

//Ensures lockout for failed password attempts is configured
void test_lockout_for_failed_password_attempts() //Ensures that failed password attempts are logged, and lockout is configured using pam_tally2 and pam_deny. It verifies that failed login attempts will be denied after 5 unsuccessful attempts and the account will be locked for 900 seconds.
{
    printf("Test: 5.4.2 Ensure lockout for failed password attempts is configured (Automated)\n");
    if (check_command_5_4("grep \"pam_tally2\" /etc/pam.d/common-auth", "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900") &&
        check_command_5_4("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account requisite pam_deny.so") &&
        check_command_5_4("grep -E \"pam_(tally2|deny)\\.so\" /etc/pam.d/common-account", "account required pam_tally2.so")) 
    {
        printf(GREEN "Pass: Lockout for failed password attempts is configured\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Lockout for failed password attempts is not configured\n" RESET);
    }
}

//Ensures password reuse is limited
void test_password_reuse_limited() //Verifies that password reuse is limited by checking if the pam_pwhistory.so module is configured with the remember parameter to prevent users from reusing the same password within the last 5 changes.
{
    printf("Test: 5.4.3 Ensure password reuse is limited (Automated)\n");
    if (check_command_5_4("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "password required pam_pwhistory.so") &&
        check_command_5_4("grep -E '^password\\s+required\\s+pam_pwhistory.so' /etc/pam.d/common-password", "remember=5")) 
    {
        printf(GREEN "Pass: Password reuse is limited\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Password reuse is not limited\n" RESET);
    }
}

//Ensures password hashing algorithm is SHA-512
void test_password_hashing_algorithm_sha512() //Ensures that the system uses the SHA-512 algorithm for hashing passwords by checking the /etc/pam.d/common-password configuration file.
{
    printf("Test: 5.4.4 Ensure password hashing algorithm is SHA-512 (Automated)\n");
    if (check_command_5_4("grep -E '^\s*password\s+(\S+\s+)+pam_unix.so\s+(\S+\s+)*sha512\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password", "sha512")) 
    {
        printf(GREEN "Pass: Password hashing algorithm is SHA-512\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Password hashing algorithm is not SHA-512\n" RESET);
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
    printf("Test: 5.5.1.1 Ensure minimum days between password changes is configured (Automated)\n");

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
                printf(GREEN "Pass: Minimum days between password changes is configured\n" RESET);
            } 
            else 
            {
                printf(RED "Fail: Minimum days between password changes is not configured\n" RESET);
            }
            fclose(fp);
        } 
        else 
        {
            printf(RED "Fail: Minimum days between password changes is not configured\n" RESET);
        }
    }
}

//Ensures password expiration is 365 days or less
void test_password_expiration() //Ensures that the system enforces a password expiration policy of no more than 365 days.
{
    printf("Test: 5.5.1.2 Ensure password expiration is 365 days or less (Automated)\n");

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
                printf(GREEN "Pass: Password expiration is 365 days or less\n" RESET);
            } 
            else 
            {
                printf(RED "Fail: Password expiration is not configured correctly\n" RESET);
            }
            fclose(fp);
        } 
        else 
        {
            printf(RED "Fail: Password expiration exceeds 365 days\n" RESET);
        }
    }
}

//Ensures password expiration warning days is 7 or more
void test_password_expiration_warning() //It checks the PASS_WARN_AGE setting in /etc/login.defs to ensure it is greater than 6 (i.e., 7 or more days).
{
    printf("Test: 5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)\n");

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
                printf(GREEN "Pass: Password expiration warning days is 7 or more\n" RESET);
            } 
            else 
            {
                printf(RED "Fail: Password expiration warning days is less than 7\n" RESET);
            }
            fclose(fp);
        } 
        else 
        {
            printf(RED "Fail: Password expiration warning days is less than 7\n" RESET);
        }
    }
}

//Ensures inactive password lock is 30 days or less
void test_inactive_password_lock() //Retrieves the INACTIVE setting from useradd -D and ensures it is less than 31 days.
{
    printf("Test: 5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)\n");

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
                printf(GREEN "Pass: Inactive password lock is 30 days or less\n" RESET);
            } 
            else 
            {
                printf(RED "Fail: Inactive password lock exceeds 30 days\n" RESET);
            }
            fclose(fp);
        } 
        else 
        {
            printf(RED "Fail: Inactive password lock exceeds 30 days or is not configured\n" RESET);
        }
    }
}

//Ensures all users last password change date is in the past
void test_users_last_password_change() //It retrieves the last password change date for all users from /etc/shadow using the chage command and checks if any user has a future date for their password change.
{
    printf("Test: 5.5.1.5 Ensure all users last password change date is in the past (Automated)\n");
    char output[128];
    char command[128];
    snprintf(command, sizeof(command), "awk -F: '{print $1}' /etc/shadow | while read -r usr; do [[ $(date --date=\"$(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\" +%%s) > $(date +%%s) ]] && echo \"$usr last password change was: $(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\"; done");
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) == NULL) 
    {
        printf(GREEN "Pass: All users' last password change date is in the past\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Some users' last password change date is in the future\n" RESET);
    }
    fclose(fp);
}

//Ensures system accounts are secured
void test_system_accounts_secured() //Ensures that no system accounts have invalid shell settings (e.g., /usr/sbin/nologin or /bin/false).
{
    printf("Test: 5.5.2 Ensure system accounts are secured (Automated)\n");

    if (check_command_5_5("awk -F: '$1!~/(root|sync|shutdown|halt|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)' && $7!~/((\\/usr)?\\/sbin\\/nologin)/ && $7!~/(\\/bin)?\\/false/ {print}' /etc/passwd", "") &&
        check_command_5_5("awk -F: '($1!~/(root|^\\+)/ && $3<'$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}'", "")) 
    {
        printf(GREEN "Pass: System accounts are secured\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: System accounts are not secured\n" RESET);
    }
}

//Ensures default group for the root account is GID 0
void test_default_group_for_root() //Checks the /etc/passwd file to ensure that the root account's group ID is 0.
{
    printf("Test: 5.5.3 Ensure default group for the root account is GID 0 (Automated)\n");

    if (check_command_5_5("grep \"^root:\" /etc/passwd | cut -f4 -d:", "0")) 
    {
        printf(GREEN "Pass: Default group for root is GID 0\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Default group for root is not GID 0\n" RESET);
    }
}

//Ensures default user umask is 027 or more restrictive
void test_default_user_umask() //Runs two checks: one to confirm that the umask is set and another to ensure it’s not set to a less restrictive value.
{
    printf("Test: 5.5.4 Ensure default user umask is 027 or more restrictive (Automated)\n");

    if (check_command_5_5("check_default_umask", "Default user umask is set") && check_command_5_5("check_for_less_restrictive_umask", "")) 
    {
        printf(GREEN "Pass: Default user umask is 027 or more restrictive\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Default user umask is not 027 or more restrictive\n" RESET);
    }
}

//Ensures default user shell timeout is 900 seconds or less
void test_default_user_shell_timeout() //Checks the shell timeout settings (specifically the TMOUT variable) to ensure it’s properly configured to meet this requirement.
{
    printf("Test: 5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)\n");

    if (check_command_5_5("check_timeout_settings", "PASSED")) 
    {
        printf(GREEN "Pass: Default user shell timeout is 900 seconds or less\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Default user shell timeout exceeds 900 seconds\n" RESET);
    }
}

//Ensures root login is restricted to system console (Manual)
void test_root_login_restricted() //This test is marked as skip because it requires manual inspection of system settings that can’t be easily automated.
{
    printf("Test: 5.6 Ensure root login is restricted to system console (Manual)\n");
    printf(BLUE "This audit has to be done manually\n" RESET);
}

// Test: Ensure access to the su command is restricted
void test_access_to_su_command() //It checks for the pam_wheel.so module in /etc/pam.d/su to ensure that the wheel group is used to restrict su access.
{
    printf("Test: 5.7 Ensure access to the su command is restricted (Automated)\n");

    char command[128];
    snprintf(command, sizeof(command), "grep pam_wheel.so /etc/pam.d/su");
    if (check_command_5_5(command, "auth required pam_wheel.so use_uid group=")) 
    {
        printf(GREEN "Pass: Access to the su command is restricted\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Access to the su command is not restricted\n" RESET);
    }
}



int check_command_5_3(const char *command, const char *expected_output) {
    char buffer[128];
    FILE *fp;
    int status = 0;

    // Open the command for reading.
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run command: %s\n", command);
        return 0;
    }

    // Read the output line by line and compare with expected_output.
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, expected_output) != NULL) {
            status = 1;  // Match found.
            break;
        }
    }

    // Close the file pointer.
    fclose(fp);

    return status;
}

void test_permissions_on_etc_ssh_sshd_config() {
    printf("Test: 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)\n");
    if (check_command_5_3("stat /etc/ssh/sshd_config", "Uid: ( 0/ root) Gid: ( 0/ root) Access: (0640/-rw-r-----)")) {
        printf(GREEN "Pass: Permissions on /etc/ssh/sshd_config are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/ssh/sshd_config are not correctly configured\n" RESET);
    }
}

void test_permissions_on_ssh_private_host_key_files() {
    printf("Test: 5.3.2 Ensure permissions on SSH private host key files are configured (Automated)\n");
    if (check_command_5_3("find /etc/ssh -type f -name 'ssh_host_*_key' -exec stat {} \\;", "Uid: ( 0/ root) Gid: ( 0/ root) Access: (0600/-rw-------)")) {
        printf(GREEN "Pass: Permissions on SSH private host key files are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on SSH private host key files are not correctly configured\n" RESET);
    }
}

void test_permissions_on_ssh_public_host_key_files() {
    printf("Test: 5.3.3 Ensure permissions on SSH public host key files are configured (Automated)\n");
    if (check_command_5_3("find /etc/ssh -type f -name 'ssh_host_*_key.pub' -exec stat {} \\;", "Uid: ( 0/ root) Gid: ( 0/ root) Access: (0644/-rw-r--r--)")) {
        printf(GREEN "Pass: Permissions on SSH public host key files are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on SSH public host key files are not correctly configured\n" RESET);
    }
}

void test_ssh_access_is_limited() {
    printf("Test: 5.3.4 Ensure SSH access is limited (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep -Ei '^\s*(allow|deny)(users|groups)\\s+\\S+'", "allowusers")) {
        printf(GREEN "Pass: SSH access is correctly limited\n" RESET);
    } else {
        printf(RED "Fail: SSH access is not correctly limited\n" RESET);
    }
}

void test_ssh_loglevel_is_appropriate() {
    printf("Test: 5.3.5 Ensure SSH LogLevel is appropriate (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep loglevel", "LogLevel VERBOSE") ||
        check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep loglevel", "loglevel INFO")) {
        printf(GREEN "Pass: SSH LogLevel is correctly configured\n" RESET);
    } else {
        printf(RED "Fail: SSH LogLevel is not correctly configured\n" RESET);
    }
}

void test_ssh_x11_forwarding_disabled() {
    printf("Test: 5.3.6 Ensure SSH X11 forwarding is disabled (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep -i x11forwarding", "x11forwarding no")) {
        printf(GREEN "Pass: SSH X11 forwarding is correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: SSH X11 forwarding is not correctly disabled\n" RESET);
    }
}

void test_ssh_max_auth_tries_configured() {
    printf("Test: 5.3.7 Ensure SSH MaxAuthTries is configured (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep maxauthtries", "MaxAuthTries 3")) {
        printf(GREEN "Pass: SSH MaxAuthTries is correctly configured\n" RESET);
    } else {
        printf(RED "Fail: SSH MaxAuthTries is not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_gshadow() {
    printf("Test: 5.3.8 Ensure permissions on /etc/gshadow are configured (Automated)\n");
    if (check_command_5_3("stat /etc/gshadow", "Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ shadow)")) {
        printf(GREEN "Pass: Permissions on /etc/gshadow are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/gshadow are not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_shadow() {
    printf("Test: 5.3.9 Ensure permissions on /etc/shadow are configured (Automated)\n");
    if (check_command_5_3("stat /etc/shadow", "Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ shadow)")) {
        printf(GREEN "Pass: Permissions on /etc/shadow are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/shadow are not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_passwd() {
    printf("Test: 5.3.10 Ensure permissions on /etc/passwd are configured (Automated)\n");
    if (check_command_5_3("stat /etc/passwd", "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)")) {
        printf(GREEN "Pass: Permissions on /etc/passwd are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/passwd are not correctly configured\n" RESET);
    }
}

void test_etc_passwd_is_immutable() {
    printf("Test: 5.3.11 Ensure /etc/passwd is immutable (Automated)\n");
    if (check_command_5_3("lsattr /etc/passwd", "i")) {
        printf(GREEN "Pass: /etc/passwd is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/passwd is not correctly immutable\n" RESET);
    }
}

void test_etc_shadow_is_immutable() {
    printf("Test: 5.3.12 Ensure /etc/shadow is immutable (Automated)\n");
    if (check_command_5_3("lsattr /etc/shadow", "i")) {
        printf(GREEN "Pass: /etc/shadow is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/shadow is not correctly immutable\n" RESET);
    }
}

void test_etc_group_is_immutable() {
    printf("Test: 5.3.13 Ensure /etc/group is immutable (Automated)\n");
    if (check_command_5_3("lsattr /etc/group", "i")) {
        printf(GREEN "Pass: /etc/group is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/group is not correctly immutable\n" RESET);
    }
}

void test_etc_gshadow_is_immutable() {
    printf("Test: 5.3.14 Ensure /etc/gshadow is immutable (Automated)\n");
    if (check_command_5_3("lsattr /etc/gshadow", "i")) {
        printf(GREEN "Pass: /etc/gshadow is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/gshadow is not correctly immutable\n" RESET);
    }
}

void test_rhosts_files_disabled() {
    printf("Test: 5.3.15 Ensure .rhosts files are disabled (Automated)\n");
    if (check_command_5_3("grep -i '^*.*rhosts' /etc/ssh/sshd_config", "")) {
        printf(GREEN "Pass: .rhosts files are correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: .rhosts files are not correctly disabled\n" RESET);
    }
}

void test_ssh_root_login_disabled() {
    printf("Test: 5.3.16 Ensure SSH root login is disabled (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep permitrootlogin", "PermitRootLogin no")) {
        printf(GREEN "Pass: SSH root login is correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: SSH root login is not correctly disabled\n" RESET);
    }
}

void test_ssh_protocol_is_2() {
    printf("Test: 5.3.17 Ensure SSH protocol is set to 2 (Automated)\n");
    if (check_command_5_3("sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep protocol", "Protocol 2")) {
        printf(GREEN "Pass: SSH protocol is correctly set to 2\n" RESET);
    } else {
        printf(RED "Fail: SSH protocol is not correctly set to 2\n" RESET);
    }
}

void test_etc_ssh_disabled() {
    printf("Test: 5.3.18 Ensure SSH is disabled if not needed (Automated)\n");
    if (check_command_5_3("systemctl is-enabled ssh", "disabled")) {
        printf(GREEN "Pass: SSH is correctly disabled if not needed\n" RESET);
    } else {
        printf(RED "Fail: SSH is not correctly disabled if not needed\n" RESET);
    }
}
//Pujit's additions end here
//----------------------------------------------------------------------------------------------------------------------------------

int main() 
{
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

    //5.3
    test_permissions_on_etc_ssh_sshd_config();
    test_permissions_on_ssh_private_host_key_files();
    test_permissions_on_ssh_public_host_key_files();
    test_ssh_access_is_limited();
    test_ssh_loglevel_is_appropriate();
    test_ssh_x11_forwarding_disabled();
    test_ssh_max_auth_tries_configured();
    test_permissions_on_etc_gshadow();
    test_permissions_on_etc_shadow();
    test_permissions_on_etc_passwd();
    test_etc_passwd_is_immutable();
    test_etc_shadow_is_immutable();
    test_etc_group_is_immutable();
    test_etc_gshadow_is_immutable();
    test_rhosts_files_disabled();
    test_ssh_root_login_disabled();
    test_ssh_protocol_is_2();
    test_etc_ssh_disabled();
    
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
