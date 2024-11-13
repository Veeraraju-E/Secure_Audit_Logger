#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib") // Link with Winsock library

// Function to initialize Winsock
int initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    return 0;
}

// Function to log network events to a file
void log_event(const char* event_message) {
    FILE *log_file = fopen("network_log.txt", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", event_message);
        fclose(log_file);
    } else {
        printf("Failed to open log file\n");
    }
}

// Function to monitor network connections
void monitor_network() {
    SOCKET sock;
    struct sockaddr_in server_addr;

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed with error %ld\n", WSAGetLastError());
        log_event("Socket creation failed");
        return;
    }

    // Log socket creation event
    log_event("New socket created for network connection");

    // Set up server address (localhost, port 9090 for this example)
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(9090);

    // Attempt to connect (for monitoring)
    int connect_result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (connect_result == SOCKET_ERROR) {
        printf("Connection failed with error %d\n", WSAGetLastError());
        log_event("Connection attempt failed");
    } else {
        printf("Connected to server\n");
        log_event("Successfully connected to server on port 9090");
    }

    // Close the socket after monitoring
    closesocket(sock);
    log_event("Socket closed after connection attempt");
}

// Main function
int main() {
    // Initialize Winsock
    if (initialize_winsock() != 0) {
        return 1; // Exit if Winsock initialization fails
    }

    // Monitor network activity
    monitor_network();

    // Clean up Winsock
    WSACleanup();

    return 0;
}
