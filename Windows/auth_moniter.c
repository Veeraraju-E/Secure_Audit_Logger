#include <stdio.h>
#include <string.h>
#include <windows.h>

void log_event(const char *message) {
    // Logs messages to a file for auditing purposes
    FILE *logFile = fopen("auth_audit_log.txt", "a");
    if (logFile) {
        fprintf(logFile, "%s\n", message);
        fclose(logFile);
    }
}

int check_authorization(const char *username, const char *password) {
    // Predefined credentials for access
    const char *validUsername = "admin";
    const char *validPassword = "password123";

    if (strcmp(username, validUsername) == 0 && strcmp(password, validPassword) == 0) {
        log_event("Authorization succeeded for user.");
        return 1;
    } else {
        log_event("Authorization failed for user.");
        return 0;
    }
}

HANDLE secure_file_open(const char *filePath, const char *username, const char *password) {
    if (check_authorization(username, password)) {
        log_event("Attempting to open file with valid credentials.");

        HANDLE fileHandle = CreateFile(
            filePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (fileHandle == INVALID_HANDLE_VALUE) {
            log_event("Failed to open file.");
        } else {
            log_event("File opened successfully.");
        }
        return fileHandle;
    } else {
        log_event("File open denied due to invalid credentials.");
        return INVALID_HANDLE_VALUE;
    }
}

void secure_file_close(HANDLE fileHandle) {
    if (fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle);
        log_event("File closed.");
    }
}

int main() {
    const char *filePath = "secure_data.txt";

    // Simulate user input for authorization
    char username[50];
    char password[50];

    printf("Enter username: ");
    scanf("%49s", username);

    printf("Enter password: ");
    scanf("%49s", password);

    // Attempt to open file with given credentials
    HANDLE fileHandle = secure_file_open(filePath, username, password);

    // If access granted, close the file
    if (fileHandle != INVALID_HANDLE_VALUE) {
        // Perform any operations on the file as needed (this example only opens/closes)
        secure_file_close(fileHandle);
    }

    return 0;
}
