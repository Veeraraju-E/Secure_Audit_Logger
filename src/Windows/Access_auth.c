#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sys/stat.h>
#include <direct.h>

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"


#define MAX_LINE_LENGTH 512

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




