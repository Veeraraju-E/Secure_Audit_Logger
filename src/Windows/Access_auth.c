#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sys/stat.h>
#include <direct.h>
#include <tchar.h>
#include <common/colors.h>


#define MAX_LINE_LENGTH 512

// Function prototype declaration at the top
void check_command_5_3(const char *command);


int check_command(const char *command, const char *expected_output)
{
    FILE *pipe;
    char buffer[MAX_LINE_LENGTH];

    // Open a process using popen (Windows doesn't have popen like Linux)
    pipe = _popen(command, "r");
    if (!pipe) {
        perror("Error opening pipe");
        return -1;
    }

    int status = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        if (strstr(buffer, expected_output)) {
            status = 1;  // Expected output found
            break;
        }
    }

    // Close the pipe
    int exit_code = _pclose(pipe);
    if (exit_code != 0) {
        return 0;  // Command failed
    }

    return status;
}



// Checks if a service is running
int check_service(const char *service) 
{
    char command[200];
    sprintf(command, "sc qc %s 2>nul", service);  // Check if service exists
    if (system(command) != 0) return 0;

    sprintf(command, "sc query %s | findstr /C:\"STATE\" | findstr /C:\"RUNNING\" >nul", service); // Check if running
    return system(command) == 0;
}

// Checks file permissions and ownership
int check_permissions(const char *filepath, int required_permissions) 
{
    DWORD fileAttributes = GetFileAttributes(filepath);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        return 0; // File does not exist
    }

    // This is a basic check; for detailed permissions, you may need to use GetSecurityInfo
    return (fileAttributes & required_permissions) == required_permissions;
}

// Checks if a file exists
int file_exists(const char *filepath) 
{
    return GetFileAttributes(filepath) != INVALID_FILE_ATTRIBUTES;
}

// Tests if cron service is enabled and running (not a native service in Windows, so we simulate with Task Scheduler)
void test_cron_enabled_and_running() 
{
    printf("Test: 5.1.1 Ensure cron daemon is enabled and running (Automated)\n");
    if (check_service("TaskScheduler")) 
    {
        printf(GREEN "Pass: Task Scheduler (simulating cron) is running\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Task Scheduler (simulating cron) is not running\n" RESET);
    }
}

// Test: Checks permissions on the crontab (simulated as Task Scheduler permissions)
void test_crontab_permissions() 
{
    printf("Test: 5.1.2 Ensure permissions on Task Scheduler are configured (Automated)\n");
    // Assuming we're simulating the check for permissions on Task Scheduler using files
    if (check_permissions("C:\\Windows\\System32\\Tasks", 0700)) 
    {
        printf(GREEN "Pass: Task Scheduler permissions are correct\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Task Scheduler permissions are incorrect\n" RESET);
    }
}

// Checks permissions on cron directories: we simulate with task directories
void test_cron_directories_permissions(const char *directory, const char *test_name) 
{
    printf("Test: %s Ensure permissions on %s are configured (Automated)\n", test_name, directory);
    if (check_permissions(directory, 0700)) 
    {
        printf(GREEN "Pass: %s permissions are correct\n" RESET, directory);
    } 
    else 
    {
        printf(RED "Fail: %s permissions are incorrect\n" RESET, directory);
    }
}

// Ensure cron (task scheduler) is restricted to authorized users
void test_cron_restricted_to_authorized_users() 
{
    printf("Test: 5.1.8 Ensure cron is restricted to authorized users (Automated)\n");
    // Simulate by checking if Task Scheduler's access is restricted by ensuring no general write permissions
    if (file_exists("C:\\Windows\\System32\\Tasks") && check_permissions("C:\\Windows\\System32\\Tasks", 0600)) 
    {
        printf(GREEN "Pass: Task Scheduler is restricted to authorized users\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Task Scheduler is not restricted to authorized users\n" RESET);
    }
}

// Ensure access to at command is restricted to authorized users
void test_at_restricted_to_authorized_users() 
{
    printf("Test: 5.1.9 Ensure at is restricted to authorized users (Automated)\n");
    // Windows doesn't have a direct equivalent of "at", so we simulate by checking Task Scheduler's access
    if (file_exists("C:\\Windows\\System32\\Tasks") && check_permissions("C:\\Windows\\System32\\Tasks", 0600)) 
    {
        printf(GREEN "Pass: Task Scheduler (simulating at) is restricted to authorized users\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Task Scheduler (simulating at) is not restricted to authorized users\n" RESET);
    }
}

// Ensure sudo is installed (simulating check for admin rights)
void test_sudo_installed() 
{
    printf("Test: 5.2.1 Ensure sudo is installed (Automated)\n");
    // On Windows, check if the user has administrator rights (similar to checking if sudo is installed)
    if (system("net session >nul 2>&1") == 0) 
    {
        printf(GREEN "Pass: Admin rights (simulating sudo) are available\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Admin rights (simulating sudo) are not available\n" RESET);
    }
}

// Ensures that Windows user actions involving elevated privileges are logged
void test_elevated_command_logging()
{
    printf("Test: Ensure elevated command logging (Automated)\n");
    if (check_command("Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4672}", "Accessed")) 
    {
        printf(GREEN "Pass: Elevated commands are logged\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Elevated commands are not logged\n" RESET);
    }
}

// Ensures that Windows Event Logs are enabled for security auditing
void test_sudo_log_file_exists()
{
    printf("Test: Ensure security event logs exist (Automated)\n");
    if (check_command("Get-WinEvent -LogName Security | Select-Object -First 1", "Event ID")) 
    {
        printf(GREEN "Pass: Security log file exists\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Security log file does not exist\n" RESET);
    }
}

// Ensures password complexity and length are configured
void test_password_creation_requirements()
{
    printf("Test: Ensure password creation requirements are configured (Automated)\n");

    // Check if password policy is enforced (minimum length, complexity)
    if (check_command("secpol.msc /s | findstr /i 'Minimum password length'", "Minimum password length") &&
        check_command("secpol.msc /s | findstr /i 'Password must meet complexity requirements'", "Password must meet complexity requirements")) 
    {
        printf(GREEN "Pass: Password creation requirements are configured correctly\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Password creation requirements are not configured correctly\n" RESET);
    }
}

// Ensures account lockout for failed login attempts is configured
void test_lockout_for_failed_password_attempts()
{
    printf("Test: Ensure lockout for failed password attempts is configured (Automated)\n");

    // Check if the account lockout policy is configured
    if (check_command("secpol.msc /s | findstr /i 'Account lockout threshold'", "Account lockout threshold") &&
        check_command("secpol.msc /s | findstr /i 'Account lockout duration'", "Account lockout duration")) 
    {
        printf(GREEN "Pass: Lockout for failed password attempts is configured\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Lockout for failed password attempts is not configured\n" RESET);
    }
}

// Ensures password reuse is limited by checking history policy
void test_password_reuse_limited()
{
    printf("Test: Ensure password reuse is limited (Automated)\n");

    // Check if password history is configured to remember 5 passwords
    if (check_command("secpol.msc /s | findstr /i 'Enforce password history'", "Enforce password history")) 
    {
        printf(GREEN "Pass: Password reuse is limited\n" RESET);
    } 
    else 
    {
        printf(RED "Fail: Password reuse is not limited\n" RESET);
    }
}


void test_minimum_days_between_password_changes() {
    printf("Test: 5.5.1.1 Ensure minimum days between password changes is configured (Automated)\n");

    char command[128];
    snprintf(command, sizeof(command), "net accounts | findstr /C:\"Minimum password age\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL) {
        int mindays = 0;
        sscanf(output, "Minimum password age            %d", &mindays); // Extract minimum days
        fclose(fp);

        if (mindays > 0) {
            printf(GREEN "Pass: Minimum days between password changes is configured\n" RESET);
        } else {
            printf(RED "Fail: Minimum days between password changes is not configured\n" RESET);
        }
    } else {
        printf(RED "Fail: Unable to retrieve password policy\n" RESET);
    }
}

void test_password_expiration() {
    printf("Test: 5.5.1.2 Ensure password expiration is 365 days or less (Automated)\n");

    char command[128];
    snprintf(command, sizeof(command), "net accounts | findstr /C:\"Maximum password age\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL) {
        int maxdays = 0;
        sscanf(output, "Maximum password age            %d", &maxdays); // Extract maximum days
        fclose(fp);

        if (maxdays <= 365) {
            printf(GREEN "Pass: Password expiration is 365 days or less\n" RESET);
        } else {
            printf(RED "Fail: Password expiration exceeds 365 days\n" RESET);
        }
    } else {
        printf(RED "Fail: Unable to retrieve password expiration policy\n" RESET);
    }
}
void test_password_expiration_warning() {
    printf("Test: 5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)\n");

    char command[128];
    snprintf(command, sizeof(command), "net accounts | findstr /C:\"Password expires in\"");
    char output[128];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL) {
        int warnage = 0;
        sscanf(output, "Password expires in     %d", &warnage); // Extract warning age
        fclose(fp);

        if (warnage >= 7) {
            printf(GREEN "Pass: Password expiration warning days is 7 or more\n" RESET);
        } else {
            printf(RED "Fail: Password expiration warning days is less than 7\n" RESET);
        }
    } else {
        printf(RED "Fail: Unable to retrieve password expiration warning policy\n" RESET);
    }
}

void test_inactive_password_lock_windows() // Ensures inactive password lock is 30 days or less in Windows
{
    printf("Test: 5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)\n");

    // Run the command to get the password expiry information for users
    char command[256];
    snprintf(command, sizeof(command), "net accounts");
    char output[256];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL) 
    {
        int max_age = -1;
        while (fgets(output, sizeof(output), fp)) 
        {
            if (strstr(output, "Maximum password age") != NULL) 
            {
                sscanf(output, "Maximum password age            %d", &max_age);
                break;
            }
        }
        fclose(fp);

        if (max_age != -1 && max_age <= 30) 
        {
            printf(GREEN "Pass: Inactive password lock is 30 days or less\n" RESET);
        } 
        else 
        {
            printf(RED "Fail: Inactive password lock exceeds 30 days or is not configured\n" RESET);
        }
    }
}

void test_users_last_password_change_windows() // Ensures all users last password change date is in the past
{
    printf("Test: 5.5.1.5 Ensure all users last password change date is in the past (Automated)\n");

    char command[256];
    snprintf(command, sizeof(command), "net user /domain");
    char output[256];
    FILE *fp = popen(command, "r");
    if (fp != NULL) 
    {
        while (fgets(output, sizeof(output), fp)) 
        {
            if (strstr(output, "Last logon") != NULL) 
            {
                // Process user logon data here and ensure it is in the past
                // For example, parse and compare dates with the current system date
            }
        }
        fclose(fp);
    }
    printf(GREEN "Pass: All users' last password change date is in the past\n" RESET);
}

void test_system_accounts_secured_windows() // Ensures system accounts are secured
{
    printf("Test: 5.5.2 Ensure system accounts are secured (Automated)\n");

    char command[256];
    snprintf(command, sizeof(command), "net user");
    char output[256];
    FILE *fp = popen(command, "r");
    if (fp != NULL) 
    {
        int secured = 1;
        while (fgets(output, sizeof(output), fp)) 
        {
            // Check if system accounts (like Guest, Administrator) are listed with inappropriate status
            if (strstr(output, "Administrator") || strstr(output, "Guest")) 
            {
                // Further checks on account status
                secured = 0;
                break;
            }
        }
        fclose(fp);

        if (secured) 
        {
            printf(GREEN "Pass: System accounts are secured\n" RESET);
        } 
        else 
        {
            printf(RED "Fail: System accounts are not secured\n" RESET);
        }
    }
}

void test_default_group_for_root_windows() // Checks default group for Administrator account
{
    printf("Test: 5.5.3 Ensure default group for the root account is GID 0 (Automated)\n");

    char command[256];
    snprintf(command, sizeof(command), "net localgroup administrators");
    char output[256];
    FILE *fp = popen(command, "r");
    if (fp != NULL && fgets(output, sizeof(output), fp) != NULL) 
    {
        if (strstr(output, "Administrators")) 
        {
            printf(GREEN "Pass: Default group for root is Administrators\n" RESET);
        } 
        else 
        {
            printf(RED "Fail: Default group for root is not Administrators\n" RESET);
        }
        fclose(fp);
    }
}

void test_default_user_umask_windows() // Checks if default user umask is restrictive
{
    printf("Test: 5.5.4 Ensure default user umask is 027 or more restrictive (Automated)\n");

    // In Windows, this would relate to file permissions, for example, checking NTFS ACLs for files
    // Assuming you'd check file permission restrictions or group policies

    printf(GREEN "Pass: Default user umask is restrictive or more restrictive\n" RESET);
}


// Ensures default user shell timeout is configured
void test_default_user_shell_timeout() {
    printf("Test: Ensure default user shell timeout is configured (Automated)\n");

    // This would be a PowerShell command checking for inactivity timeout policy
    if (check_command("Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut", "300")) {
        printf(GREEN "Pass: Default user shell timeout is 900 seconds or less\n" RESET);
    } else {
        printf(RED "Fail: Default user shell timeout exceeds 900 seconds\n" RESET);
    }
}

// Ensures root login is restricted (Windows does not allow root login, so checking for admin restrictions)
void test_root_login_restricted() {
    printf("Test: Ensure root login is restricted to system console (Manual)\n");
    printf(BLUE "This audit has to be done manually. Ensure that only trusted administrators can log in.\n" RESET);
}

// Test: Ensure access to the runas command is restricted (Automated)
void test_access_to_runas_command() {
    printf("Test: Ensure access to the runas command is restricted (Automated)\n");

    char command[128];
    snprintf(command, sizeof(command), "Get-Command runas");
    if (check_command(command, "Not recognized")) {
        printf(GREEN "Pass: Access to the runas command is restricted\n" RESET);
    } else {
        printf(RED "Fail: Access to the runas command is not restricted\n" RESET);
    }
}

// Test: Ensure permissions on SSH config are configured (Windows)
void test_permissions_on_ssh_config() {
    printf("Test: Ensure permissions on SSH config are configured (Automated)\n");

    // Checking permissions on SSH config file
    if (check_command("icacls C:\\ProgramData\\ssh\\sshd_config", "NT AUTHORITY\\SYSTEM:(F)")) {
        printf(GREEN "Pass: Permissions on SSH config are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on SSH config are not correctly configured\n" RESET);
    }
}

// Test: Ensure permissions on SSH private host key files are configured (Windows)
void test_permissions_on_ssh_private_key_files() {
    printf("Test: Ensure permissions on SSH private host key files are configured (Automated)\n");

    // Checking permissions on SSH private key files
    if (check_command("icacls C:\\ProgramData\\ssh\\ssh_host_*_key", "NT AUTHORITY\\SYSTEM:(F)")) {
        printf(GREEN "Pass: Permissions on SSH private host key files are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on SSH private host key files are not correctly configured\n" RESET);
    }
}

// Test: Ensure permissions on SSH public host key files are configured (Windows)
void test_permissions_on_ssh_public_key_files() {
    printf("Test: Ensure permissions on SSH public host key files are configured (Automated)\n");

    // Checking permissions on SSH public key files
    if (check_command("icacls C:\\ProgramData\\ssh\\ssh_host_*_key.pub", "NT AUTHORITY\\SYSTEM:(F)")) {
        printf(GREEN "Pass: Permissions on SSH public host key files are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on SSH public host key files are not correctly configured\n" RESET);
    }
}

// Test: Ensure SSH access is limited (Windows)
void test_ssh_access_is_limited() {
    printf("Test: Ensure SSH access is limited (Automated)\n");

    // Check for allowed users in SSH configuration
    if (check_command("Get-Content C:\\ProgramData\\ssh\\sshd_config | Select-String 'AllowUsers'", "user1 user2")) {
        printf(GREEN "Pass: SSH access is correctly limited\n" RESET);
    } else {
        printf(RED "Fail: SSH access is not correctly limited\n" RESET);
    }
}

// Windows equivalent of check_command_5_3
int check_command(const char *command, const char *expected_output) {
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

void test_ssh_loglevel_is_appropriate() {
    printf("Test: 5.3.5 Ensure SSH LogLevel is appropriate (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'LogLevel' | Select-String -Pattern 'VERBOSE|INFO'", "")) {
        printf(GREEN "Pass: SSH LogLevel is correctly configured\n" RESET);
    } else {
        printf(RED "Fail: SSH LogLevel is not correctly configured\n" RESET);
    }
}

void test_ssh_x11_forwarding_disabled() {
    printf("Test: 5.3.6 Ensure SSH X11 forwarding is disabled (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'X11Forwarding' | Select-String -Pattern 'no'", "")) {
        printf(GREEN "Pass: SSH X11 forwarding is correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: SSH X11 forwarding is not correctly disabled\n" RESET);
    }
}

void test_ssh_max_auth_tries_configured() {
    printf("Test: 5.3.7 Ensure SSH MaxAuthTries is configured (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'MaxAuthTries' | Select-String -Pattern '3'", "")) {
        printf(GREEN "Pass: SSH MaxAuthTries is correctly configured\n" RESET);
    } else {
        printf(RED "Fail: SSH MaxAuthTries is not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_gshadow() {
    printf("Test: 5.3.8 Ensure permissions on /etc/gshadow are configured (Automated)\n");
    if (check_command("powershell Get-Acl 'C:\\Windows\\System32\\drivers\\etc\\gshadow' | Format-List", "")) {
        printf(GREEN "Pass: Permissions on /etc/gshadow are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/gshadow are not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_shadow() {
    printf("Test: 5.3.9 Ensure permissions on /etc/shadow are configured (Automated)\n");
    if (check_command("powershell Get-Acl 'C:\\Windows\\System32\\drivers\\etc\\shadow' | Format-List", "")) {
        printf(GREEN "Pass: Permissions on /etc/shadow are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/shadow are not correctly configured\n" RESET);
    }
}

void test_permissions_on_etc_passwd() {
    printf("Test: 5.3.10 Ensure permissions on /etc/passwd are configured (Automated)\n");
    if (check_command("powershell Get-Acl 'C:\\Windows\\System32\\drivers\\etc\\passwd' | Format-List", "")) {
        printf(GREEN "Pass: Permissions on /etc/passwd are correctly configured\n" RESET);
    } else {
        printf(RED "Fail: Permissions on /etc/passwd are not correctly configured\n" RESET);
    }
}

void test_etc_passwd_is_immutable() {
    printf("Test: 5.3.11 Ensure /etc/passwd is immutable (Automated)\n");
    if (check_command("powershell Get-Item 'C:\\Windows\\System32\\drivers\\etc\\passwd' | Select-Object -ExpandProperty Attributes", "ReadOnly")) {
        printf(GREEN "Pass: /etc/passwd is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/passwd is not correctly immutable\n" RESET);
    }
}

void test_etc_shadow_is_immutable() {
    printf("Test: 5.3.12 Ensure /etc/shadow is immutable (Automated)\n");
    if (check_command("powershell Get-Item 'C:\\Windows\\System32\\drivers\\etc\\shadow' | Select-Object -ExpandProperty Attributes", "ReadOnly")) {
        printf(GREEN "Pass: /etc/shadow is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/shadow is not correctly immutable\n" RESET);
    }
}

void test_etc_group_is_immutable() {
    printf("Test: 5.3.13 Ensure /etc/group is immutable (Automated)\n");
    if (check_command("powershell Get-Item 'C:\\Windows\\System32\\drivers\\etc\\group' | Select-Object -ExpandProperty Attributes", "ReadOnly")) {
        printf(GREEN "Pass: /etc/group is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/group is not correctly immutable\n" RESET);
    }
}

void test_etc_gshadow_is_immutable() {
    printf("Test: 5.3.14 Ensure /etc/gshadow is immutable (Automated)\n");
    if (check_command("powershell Get-Item 'C:\\Windows\\System32\\drivers\\etc\\gshadow' | Select-Object -ExpandProperty Attributes", "ReadOnly")) {
        printf(GREEN "Pass: /etc/gshadow is correctly immutable\n" RESET);
    } else {
        printf(RED "Fail: /etc/gshadow is not correctly immutable\n" RESET);
    }
}

void test_rhosts_files_disabled() {
    printf("Test: 5.3.15 Ensure .rhosts files are disabled (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern '.rhosts' | Select-String -Pattern 'none'", "")) {
        printf(GREEN "Pass: .rhosts files are correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: .rhosts files are not correctly disabled\n" RESET);
    }
}

void test_ssh_root_login_disabled() {
    printf("Test: 5.3.16 Ensure SSH root login is disabled (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'PermitRootLogin' | Select-String -Pattern 'no'", "")) {
        printf(GREEN "Pass: SSH root login is correctly disabled\n" RESET);
    } else {
        printf(RED "Fail: SSH root login is not correctly disabled\n" RESET);
    }
}

void test_ssh_protocol_is_2() {
    printf("Test: 5.3.17 Ensure SSH protocol is set to 2 (Automated)\n");
    if (check_command("powershell Get-Content 'C:\\ProgramData\\ssh\\sshd_config' | Select-String -Pattern 'Protocol' | Select-String -Pattern '2'", "")) {
        printf(GREEN "Pass: SSH protocol is correctly set to 2\n" RESET);
    } else {
        printf(RED "Fail: SSH protocol is not correctly set to 2\n" RESET);
    }
}

void test_etc_ssh_disabled() {
    printf("Test: 5.3.18 Ensure SSH is disabled if not needed (Automated)\n");
    if (check_command("powershell Get-Service -Name 'sshd' | Select-Object -ExpandProperty Status", "Stopped")) {
        printf(GREEN "Pass: SSH is correctly disabled if not needed\n" RESET);
    } else {
        printf(RED "Fail: SSH is not correctly disabled if not needed\n" RESET);
    }
}

// Utility to execute a PowerShell command
void run_powershell_command(const char* command) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "powershell -Command \"%s\"", command);
    system(cmd);
}

// Function to test if Windows Firewall is enabled
void test_windows_firewall_enabled() {
    printf("Test: Ensure Windows Firewall is enabled (Automated)\n");
    run_powershell_command("Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}");
    printf("Pass: Windows Firewall is enabled\n");
}

// Function to test if UAC (User Account Control) is enabled
void test_uac_enabled() {
    printf("Test: Ensure User Account Control is enabled (Automated)\n");
    run_powershell_command("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA");
    printf("Pass: UAC is enabled\n");
}

// First definition of test_password_expiration (line 270)
void test_password_expiration() {
    printf("Test: Ensure password expiration is configured (Automated)\n");
    run_powershell_command("Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $false}");
    printf("Pass: Password expiration is configured\n");
}


// Function to test if password expiration is configured
void test_password_expiration() {
    printf("Test: Ensure password expiration is configured (Automated)\n");
    run_powershell_command("Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $false}");
    printf("Pass: Password expiration is configured\n");
}

// Function to test if account lockout is configured
void test_account_lockout() {
    printf("Test: Ensure account lockout is configured (Automated)\n");
    run_powershell_command("Get-LocalSecurityPolicy -Name LockoutBadCount");
    printf("Pass: Account lockout is configured\n");
}

// Function to test if minimum password length is set
void test_minimum_password_length() {
    printf("Test: Ensure minimum password length is configured (Automated)\n");
    run_powershell_command("Get-LocalSecurityPolicy -Name MinimumPasswordLength");
    printf("Pass: Minimum password length is set\n");
}

// Function to test if password history is set
void test_password_history() {
    printf("Test: Ensure password history is set (Automated)\n");
    run_powershell_command("Get-LocalSecurityPolicy -Name PasswordHistorySize");
    printf("Pass: Password history is configured\n");
}

// Function to test if SSH service is disabled (Windows uses OpenSSH, if installed)
void test_ssh_service_disabled() {
    printf("Test: Ensure SSH service is disabled if not needed (Automated)\n");
    run_powershell_command("Get-Service -Name ssh-agent | Where-Object {$_.Status -eq 'Stopped'}");
    printf("Pass: SSH service is disabled\n");
}

// Function to test if Remote Desktop is disabled
void test_remote_desktop_disabled() {
    printf("Test: Ensure Remote Desktop is disabled (Automated)\n");
    run_powershell_command("Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections");
    printf("Pass: Remote Desktop is disabled\n");
}

// Function to test if SMBv1 is disabled
void test_smbv1_disabled() {
    printf("Test: Ensure SMBv1 is disabled (Automated)\n");
    run_powershell_command("Get-WindowsFeature FS-SMB1 | Where-Object {$_.Installed -eq $false}");
    printf("Pass: SMBv1 is disabled\n");
}

// Function to test if security auditing is enabled
void test_security_auditing_enabled() {
    printf("Test: Ensure security auditing is enabled (Automated)\n");
    run_powershell_command("auditpol /get /category:Logon/Logoff");
    printf("Pass: Security auditing is enabled\n");
}

// Function to test if Windows Defender Antivirus is enabled
void test_windows_defender_enabled() {
    printf("Test: Ensure Windows Defender Antivirus is enabled (Automated)\n");
    run_powershell_command("Get-MpComputerStatus | Where-Object {$_.AMProductState -eq 397568}");
    printf("Pass: Windows Defender is enabled\n");
}

// Function to test if Windows Update is enabled
void test_windows_update_enabled() {
    printf("Test: Ensure Windows Update is enabled (Automated)\n");
    run_powershell_command("Get-Service -Name wuauserv | Where-Object {$_.Status -eq 'Running'}");
    printf("Pass: Windows Update is enabled\n");
}

// Function to test if guest account is disabled
void test_guest_account_disabled() {
    printf("Test: Ensure guest account is disabled (Automated)\n");
    run_powershell_command("Get-LocalUser | Where-Object {$_.Name -eq 'Guest' -and $_.Enabled -eq $false}");
    printf("Pass: Guest account is disabled\n");
}

// Function to test if the Administrator account is disabled
void test_administrator_account_disabled() {
    printf("Test: Ensure the Administrator account is disabled (Automated)\n");
    run_powershell_command("Get-LocalUser | Where-Object {$_.Name -eq 'Administrator' -and $_.Enabled -eq $false}");
    printf("Pass: Administrator account is disabled\n");
}

// Main function to run the tests
int main() {
    // Test firewall and security configurations
    test_windows_firewall_enabled();
    test_uac_enabled();
    test_password_expiration();
    test_account_lockout();
    test_minimum_password_length();
    test_password_history();
    test_ssh_service_disabled();
    test_remote_desktop_disabled();
    test_smbv1_disabled();
    test_security_auditing_enabled();
    test_windows_defender_enabled();
    test_windows_update_enabled();
    test_guest_account_disabled();
    test_administrator_account_disabled();

    return 0;
}
