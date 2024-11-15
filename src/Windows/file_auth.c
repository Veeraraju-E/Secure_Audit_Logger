#include <windows.h>
#include <stdio.h>

void log_event(const char *message) {
    // A simple function to log messages to a file or console
    FILE *logFile = fopen("audit_log.txt", "a");
    if (logFile) {
        fprintf(logFile, "%s\n", message);
        fclose(logFile);
    }
}

HANDLE audited_create_file(const char *filePath, DWORD accessMode, DWORD creationDisposition) {
    HANDLE fileHandle = CreateFile(
        filePath,
        accessMode,
        0,
        NULL,
        creationDisposition,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (fileHandle == INVALID_HANDLE_VALUE) {
        log_event("Failed to open file");
    } else {
        char logMessage[256];
        sprintf(logMessage, "File opened: %s", filePath);
        log_event(logMessage);
    }
    return fileHandle;
}

DWORD audited_read_file(HANDLE fileHandle, void *buffer, DWORD numberOfBytesToRead) {
    DWORD bytesRead;
    BOOL success = ReadFile(fileHandle, buffer, numberOfBytesToRead, &bytesRead, NULL);
    
    if (success) {
        log_event("File read operation succeeded");
    } else {
        log_event("File read operation failed");
    }
    return bytesRead;
}

void audited_close_file(HANDLE fileHandle) {
    CloseHandle(fileHandle);
    log_event("File closed");
}

int main() {
    // Example of file operations
    HANDLE fileHandle = audited_create_file("test.txt", GENERIC_WRITE, CREATE_ALWAYS);
    if (fileHandle != INVALID_HANDLE_VALUE) {
        const char *data = "Logging file access!";
        DWORD bytesWritten;
        WriteFile(fileHandle, data, strlen(data), &bytesWritten, NULL);
        audited_close_file(fileHandle);
    }

    return 0;
}
