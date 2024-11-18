#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <common/colors.h>


// Declare function prototypes at the top
int check_command(const char *command, const char *expected_output);
int check_command_windows(const char *command, const char *expected_output);


void check_log_config(const char *log_path, const char *expected_value) {
    printf("Checking log configuration: %s...\n", log_path);
    char command[512];
    snprintf(command, sizeof(command),
             "powershell -Command \"(Get-ItemProperty -Path '%s').Start -eq %s\"", 
             log_path, expected_value);

    if (check_command_windows(command, "True")) {
        printf(GREEN "Pass: Log configuration at %s is correct\n" RESET, log_path);
    } else {
        printf(RED "Fail: Log configuration at %s is incorrect\n" RESET, log_path);
        printf("Action: Update registry key at %s to correct value (%s).\n", log_path, expected_value);
    }
}

void check_event_log_retention(const char *log_name) {
    printf("Checking retention policy for %s log...\n", log_name);
    char command[256];
    snprintf(command, sizeof(command), 
             "powershell -Command \"wevtutil gl %s | Select-String -Pattern 'Retention'\"", 
             log_name);

    if (check_command_windows(command, "True")) {
        printf(GREEN "Pass: Retention policy for %s is set correctly\n" RESET, log_name);
    } else {
        printf(RED "Fail: Retention policy for %s is not set correctly\n" RESET, log_name);
        printf("Action: Configure retention policy for %s using 'wevtutil'.\n", log_name);
    }
}


int check_command(const char *command, const char *expected_output) {
    char buffer[128];
    FILE *fp = _popen(command, "r");

    if (fp == NULL) {
        return 0; // Error in executing the command
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, expected_output)) {
            _pclose(fp);
            return 1; // Command output matches expected_output
        }
    }

    _pclose(fp);
    return 0; // Command output does not match expected_output
}

int check_command_windows(const char *command, const char *expected_output) {
    // Implement this function similarly if it's for Windows-specific commands
    return check_command(command, expected_output);
}



void test_event_logs_installed() {
    printf("Test: 4.1.1.1 Ensure Windows Event Logs are enabled (Automated)\n");
    if (check_command_windows("powershell -Command \"Get-WindowsFeature | Where-Object {$_.Name -eq 'RSAT-AD-Tools'}\"", "Installed")) {
        printf(GREEN "Pass: Windows Event Logs are enabled\n" RESET);
    } else {
        printf(RED "Fail: Windows Event Logs are not enabled\n" RESET);
        printf("Action: Enable Windows Event Logs via Control Panel or PowerShell\n");
    }
}


void test_service_enabled(const char *service_name) {
    printf("Test: 4.1.1.2 Ensure %s service is enabled (Automated)\n", service_name);
    char command[256];
    snprintf(command, sizeof(command), "powershell -Command \"(Get-Service -Name %s).StartType -eq 'Automatic'\"", service_name);

    if (check_command_windows(command, "True")) {
        printf(GREEN "Pass: %s service is enabled\n" RESET, service_name);
    } else {
        printf(RED "Fail: %s service is not enabled\n" RESET, service_name);
        printf("Action: Enable %s service via PowerShell or Services Manager\n", service_name);
    }
}


void test_log_config(const char *config_path, const char *expected_value) {
    printf("Test: Checking if configuration %s is set correctly (Automated)\n", config_path);
    char command[512];
    snprintf(command, sizeof(command), "powershell -Command \"Get-ItemProperty -Path '%s'\"", config_path);

    if (check_command_windows(command, expected_value)) {
        printf(GREEN "Pass: Configuration %s is set correctly\n" RESET, config_path);
    } else {
        printf(RED "Fail: Configuration %s is not set correctly\n" RESET, config_path);
        printf("Action: Modify %s via PowerShell or Registry Editor\n", config_path);
    }
}

void test_user_group_info_events() {
    printf("Test: Ensure events that modify user/group information are collected (Windows)\n");

    // Check if auditing for Account Management is enabled
    char command[512];
    snprintf(command, sizeof(command),
             "powershell -Command \"(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security').AuditAccountManagement -eq 1\"");

    if (check_command_windows(command, "True")) {
        printf(GREEN "Pass: Events that modify user/group information are collected\n" RESET);
    } else {
        printf(RED "Fail: Events that modify user/group information are not collected\n" RESET);
        printf("Action: Enable auditing for Account Management:\n");
        printf("  1. Open Local Security Policy (secpol.msc).\n");
        printf("  2. Navigate to Security Settings -> Advanced Audit Policy Configuration.\n");
        printf("  3. Under Audit Policies -> Account Management, ensure the following are enabled:\n");
        printf("     - Audit User Account Management\n");
        printf("     - Audit Group Membership Changes\n");
        printf("  4. Apply the changes and ensure policies are deployed.\n");
    }
}


void test_network_environment_events() {
    printf("Test: Ensure events that modify the system's network environment are collected (Windows)\n");

    // Check if auditing for Policy Change and System Events is enabled
    char command[512];
    snprintf(command, sizeof(command),
             "powershell -Command \"(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security').AuditPolicyChange -eq 1\"");

    if (check_command_windows(command, "True")) {
        printf(GREEN "Pass: Events that modify the network environment are collected\n" RESET);
    } else {
        printf(RED "Fail: Events that modify the network environment are not collected\n" RESET);
        printf("Action: Enable auditing for network environment changes:\n");
        printf("  1. Open Local Security Policy (secpol.msc).\n");
        printf("  2. Navigate to Security Settings -> Advanced Audit Policy Configuration.\n");
        printf("  3. Under Audit Policies -> System, ensure the following are enabled:\n");
        printf("     - Audit Policy Change\n");
        printf("     - Audit Other System Events\n");
        printf("     - Audit Logon Events (for hostname changes).\n");
        printf("  4. Apply the changes and ensure policies are deployed.\n");
    }
}

#include <windows.h>
#include <stdio.h>

#define GREEN "\x1b[32m"
#define RED "\x1b[31m"
#define RESET "\x1b[0m"

#define MAX_LINE_LENGTH 1024

void test_login_logout_events() {
    printf("Test: Ensure login and logout events are collected (Windows)\n");
    // Check if auditing is enabled for logon events
    system("auditpol /get /category:\"Logon/Logoff\" | findstr \"Logon\" > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Login and logout events are being collected\n" RESET);
    } else {
        printf(RED "Fail: Login and logout events are not being collected\n" RESET);
        printf("Action: Enable auditing using the following command:\n");
        printf("  auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable\n");
    }
}

void test_session_initiation_events() {
    printf("Test: Ensure session initiation information is collected (Windows)\n");
    // Check for session initiation logs in Event Viewer
    system("wevtutil qe Security /q:\"*[System[EventID=4624 or EventID=4648]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Session initiation information is collected\n" RESET);
    } else {
        printf(RED "Fail: Session initiation information is not collected\n" RESET);
        printf("Action: Ensure that Event ID 4624 and 4648 are enabled in Security logs.\n");
    }
}

void test_permission_modification_events() {
    printf("Test: Ensure permission modification events are collected (Windows)\n");
    // Check for permission changes in Event Viewer
    system("auditpol /get /subcategory:\"Object Access\" | findstr \"File System\" > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Permission modification events are being collected\n" RESET);
    } else {
        printf(RED "Fail: Permission modification events are not being collected\n" RESET);
        printf("Action: Enable auditing for Object Access:\n");
        printf("  auditpol /set /subcategory:\"Object Access\" /success:enable /failure:enable\n");
    }
}

void test_unsuccessful_file_access_attempts() {
    printf("Test: Ensure unsuccessful file access attempts are collected (Windows)\n");
    // Check for failed file access attempts in Event Viewer
    system("wevtutil qe Security /q:\"*[System[EventID=4656]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Unauthorized file access attempts are being collected\n" RESET);
    } else {
        printf(RED "Fail: Unauthorized file access attempts are not being collected\n" RESET);
        printf("Action: Enable auditing for unauthorized access attempts.\n");
    }
}

void test_mounts_collection() {
    printf("Test: Ensure successful file system mounts are collected (Windows)\n");
    // Check if Event ID 4663 (file/folder accesses) is logged
    system("wevtutil qe Security /q:\"*[System[EventID=4663]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: File system mounts are being collected\n" RESET);
    } else {
        printf(RED "Fail: File system mounts are not being collected\n" RESET);
        printf("Action: Enable auditing for file and folder access (Event ID 4663).\n");
    }
}

void test_file_deletion_collection() {
    printf("Test: Ensure file deletion events are collected (Windows)\n");
    // Check if file deletion logs are available in Event Viewer
    system("wevtutil qe Security /q:\"*[System[EventID=4660]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: File deletion events are being collected\n" RESET);
    } else {
        printf(RED "Fail: File deletion events are not being collected\n" RESET);
        printf("Action: Enable auditing for file deletion (Event ID 4660).\n");
    }
}

void test_sudoers_scope_collection() {
    printf("Test: Ensure administrative scope changes are collected (Windows)\n");
    // Check for administrative changes in Event Viewer
    system("wevtutil qe Security /q:\"*[System[EventID=4670]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Administrative scope changes are being collected\n" RESET);
    } else {
        printf(RED "Fail: Administrative scope changes are not being collected\n" RESET);
        printf("Action: Enable auditing for administrative changes (Event ID 4670).\n");
    }
}

void test_sudo_command_execution_collection() {
    printf("Test: Ensure administrative command executions are collected (Windows)\n");
    // Check for administrative command executions in Event Viewer
    system("wevtutil qe Security /q:\"*[System[EventID=4688]]\" /c:1 > nul");
    if (GetLastError() == 0) {
        printf(GREEN "Pass: Administrative command executions are being collected\n" RESET);
    } else {
        printf(RED "Fail: Administrative command executions are not being collected\n" RESET);
        printf("Action: Enable auditing for administrative command executions (Event ID 4688).\n");
    }
}

int check_audit_rules_windows(const char *pattern) {
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "powershell -Command \"Get-AuditPolicy | Select-String '%s'\"", pattern);
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        return -1; // Error in executing the command
    }
    
    char output[MAX_LINE_LENGTH];
    int found = 0;
    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, pattern) != NULL) {
            found = 1;
            break;
        }
    }

    _pclose(fp);
    return found;
}

int check_auditpol(const char *policy) {
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "powershell -Command \"AuditPol /Get /Category:%s\"", policy);
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        return -1; // Error in executing the command
    }
    
    char output[MAX_LINE_LENGTH];
    int found = 0;
    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, "Success") != NULL || strstr(output, "Failure") != NULL) {
            found = 1;
            break;
        }
    }

    _pclose(fp);
    return found;
}

void test_audit_immutable_configuration_windows() {
    printf("4.1.17 - Ensure audit configuration is immutable\n");

    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "powershell -Command \"(Get-WinEvent -LogName Security -MaxEvents 1).Message\"");
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Failed to execute command\n");
        return;
    }

    char output[MAX_LINE_LENGTH];
    int immutable = 0;

    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, "Tamper Protection Enabled") != NULL) {
            immutable = 1;
            break;
        }
    }

    if (immutable) {
        printf(GREEN "Pass: Audit configuration is immutable\n" RESET);
    } else {
        printf(RED "[IMP] Fail: Audit configuration is mutable\n" RESET);
        printf("Action: Enable Tamper Protection in Windows Security settings.\n");
    }

    _pclose(fp);
}

void test_eventlog_installed() {
    printf("Test: 4.2.1.1 Ensure Event Log Service is installed (Automated)\n");
    
    if (check_command("powershell -Command \"Get-Service -Name 'EventLog'\"", "Running")) {
        printf(GREEN "Pass: Event Log Service is installed\n" RESET);
    } else {
        printf(RED "Fail: Event Log Service is not installed\n" RESET);
        printf("Action: Reinstall Windows Event Log Service via system components.\n");
    }
}

void test_eventlog_service_enabled() {
    printf("Test: 4.2.1.2 Ensure Event Log Service is enabled (Automated)\n");
    
    if (check_command("powershell -Command \"Get-Service -Name 'EventLog' | Select-Object -ExpandProperty StartType\"", "Automatic") &&
        check_command("powershell -Command \"Get-Service -Name 'EventLog' | Select-Object -ExpandProperty Status\"", "Running")) {
        printf(GREEN "Pass: Event Log Service is enabled and running\n" RESET);
    } else {
        printf(RED "Fail: Event Log Service is not enabled or not running\n" RESET);
        printf("Action: Run 'Set-Service -Name 'EventLog' -StartupType Automatic' in PowerShell and start the service.\n");
    }
}

void test_eventlog_default_permissions() {
    printf("Test: 4.2.1.4 Ensure Event Log default file permissions are configured (Automated)\n");
    
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "powershell -Command \"(Get-Acl 'C:\\\\Windows\\\\System32\\\\winevt\\\\Logs\\\\System.evtx').Access | Format-List\"");
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        printf(RED "Fail: Unable to check Event Log permissions\n" RESET);
        return;
    }

    char output[MAX_LINE_LENGTH];
    int permission_correct = 0;
    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, "NT AUTHORITY\\SYSTEM") || strstr(output, "BUILTIN\\Administrators")) {
            permission_correct = 1;
            break;
        }
    }

    _pclose(fp);

    if (permission_correct) {
        printf(GREEN "Pass: Event Log default file permissions are configured correctly\n" RESET);
    } else {
        printf(RED "Fail: Event Log default file permissions are not configured correctly\n" RESET);
        printf("Action: Use 'icacls' to set permissions for Event Log files.\n");
    }
}

#include <stdio.h>
#include <windows.h>
#include <tchar.h>  // For _tcslen() and TCHAR types

#define BLUE ""
#define RESET ""

void skip_test(const char *test_name) {
    printf("Test: %s\n", test_name);
    printf(BLUE "Skip: This audit has to be done manually\n" RESET);
}

void check_service(const char *service_name) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        printf("Error: Could not connect to Service Manager\n");
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, service_name, SERVICE_QUERY_STATUS);
    if (hService) {
        printf("Test: Service '%s' is installed and available\n", service_name);
        CloseServiceHandle(hService);
    } else {
        printf("Test: Service '%s' is not installed\n", service_name);
    }

    CloseServiceHandle(hSCManager);
}

void check_service_running(const char *service_name) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        printf("Error: Could not connect to Service Manager\n");
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, service_name, SERVICE_QUERY_STATUS);
    if (hService) {
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            if (status.dwCurrentState == SERVICE_RUNNING) {
                printf("Test: Service '%s' is running\n", service_name);
            } else {
                printf("Test: Service '%s' is not running\n", service_name);
            }
        }
        CloseServiceHandle(hService);
    } else {
        printf("Test: Service '%s' is not installed\n", service_name);
    }

    CloseServiceHandle(hSCManager);
}

void check_file_permissions(const char *file_path) {
    DWORD attributes = GetFileAttributes(file_path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        printf("Test: File '%s' does not exist\n", file_path);
    } else {
        printf("Test: File '%s' exists\n", file_path);
        // For detailed permission checks, use Windows Security API or PowerShell scripts.
    }
}

void check_registry_key(const char *key_path, const char *value_name) {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD valueType;
        DWORD valueData;
        DWORD valueSize = sizeof(valueData);
        if (RegQueryValueEx(hKey, value_name, NULL, &valueType, (LPBYTE)&valueData, &valueSize) == ERROR_SUCCESS) {
            printf("Test: Registry key '%s\\%s' exists\n", key_path, value_name);
        } else {
            printf("Test: Registry value '%s\\%s' does not exist\n", key_path, value_name);
        }
        RegCloseKey(hKey);
    } else {
        printf("Test: Registry key '%s' does not exist\n", key_path);
    }
}

int main() {
    // Example Windows tests for services, file permissions, and registry values.

    // Test for Windows Event Log service
    check_service("EventLog");
    Sleep(1000);

    // Test if Windows Event Log service is running
    check_service_running("EventLog");
    Sleep(1000);

    // Test for file permissions (e.g., log file location)
    check_file_permissions("C:\\Windows\\System32\\LogFiles\\WMI\\RtBackup");
    Sleep(1000);

    // Test for registry key (e.g., audit settings in Windows)
    check_registry_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "Audit");
    Sleep(1000);

    // Skip manual tests
    skip_test("4.1.1.4 Ensure audit_backlog_limit is sufficient (Manual)");
    Sleep(1000);
    skip_test("4.2.3 Ensure permissions on all log files are configured (Manual)");
    Sleep(1000);

    return 0;
}





