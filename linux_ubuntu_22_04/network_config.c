#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define RESET "\033[0m"

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

// Helper to check IPv6 Configuration
void check_ipv6_status() {
    printf("Checking IPv6 configuration:\n");

    // Check if IPv6 is disabled in grub and sysctl configuration files
    int is_ipv6_disabled_grub = check_command("grep -L \"ipv6.disable=1\" /boot/grub/grub.cfg", "");
    int is_ipv6_disabled_sysctl = check_command("sysctl net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.disable_ipv6 = 1") &&
                                  check_command("sysctl net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.default.disable_ipv6 = 1");

    if (is_ipv6_disabled_grub && is_ipv6_disabled_sysctl) {
        printf(GREEN "Pass: IPv6 is disabled in grub and sysctl configuration\n" RESET);
    } else {
        printf(RED "Fail: IPv6 is not fully disabled\n" RESET);
    }
}

// 3.1 - Unused network protocols
void test_disable_ipv6() {
    printf("Test: 3.1.1 Disable IPv6 (Automated)\n");
    int is_ipv6_disabled = check_command("grep \"^\\s*linux\" /boot/grub/grub.cfg | grep -v \"ipv6.disable=1\"", "");

    if (is_ipv6_disabled) {
        printf(BLUE "IPv6 is not disabled in GRUB. Proceeding with sysctl checks.\n" RESET);

        if (check_command("sysctl net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.disable_ipv6 = 1") &&
            check_command("sysctl net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.default.disable_ipv6 = 1") &&
            check_command("grep -E \"^\\s*net\\.ipv6\\.conf\\.(all|default)\\.disable_ipv6\\s*=\\s*1\\b\" /etc/sysctl.conf /etc/sysctl.d/*.conf", "net.ipv6.conf.all.disable_ipv6 = 1") &&
            check_command("grep -E \"^\\s*net\\.ipv6\\.conf\\.(all|default)\\.disable_ipv6\\s*=\\s*1\\b\" /etc/sysctl.conf /etc/sysctl.d/*.conf", "net.ipv6.conf.default.disable_ipv6 = 1")) {
            printf(GREEN "Pass: Done with sysctl checks. IPv6 is disabled\n" RESET);
        } else {
            printf(RED "Fail: IPv6 is not fully disabled\n" RESET);
            printf("Action: To disable IPv6:\n");
            printf("1. Edit /etc/default/grub and add 'ipv6.disable=1' to GRUB_CMDLINE_LINUX\n");
            printf("2. Run 'sudo update-grub'\n");
            printf("3. Edit /etc/sysctl.conf and add:\n");
            printf("   net.ipv6.conf.all.disable_ipv6 = 1\n");
            printf("   net.ipv6.conf.default.disable_ipv6 = 1\n");
            printf("4. Run 'sudo sysctl -p'\n");
            printf("5. Reboot the system\n");
        }
    } else {
        printf(GREEN "Pass: IPv6 is disabled in GRUB\n" RESET);
    }
}

void test_disable_wireless_interfaces() {
    printf("Test: 3.1.2 Ensure wireless interfaces are disabled (Automated)\n");

    // Check if nmcli is available and check radio status
    if (system("command -v nmcli >/dev/null 2>&1") == 0) {
        if (check_command("nmcli radio all", "disabled")) {
            printf(GREEN "Pass: Wireless interfaces are disabled\n" RESET);
        } else {
            printf(RED "Fail: Wireless interfaces are enabled\n" RESET);
        }
    } else {
        // Check manually if there are any wireless interfaces
        if (system("find /sys/class/net/*/ -type d -name wireless >/dev/null 2>&1") == 0) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename \"$(readlink -f \"$driverdir\"/device/driver/module)\"; done | sort -u");
            FILE *fp = popen(cmd, "r");
            if (!fp) {
                perror("popen failed");
                return;
            }

            char module_name[128];
            int all_disabled = 1;
            while (fgets(module_name, sizeof(module_name), fp) != NULL) {
                module_name[strcspn(module_name, "\n")] = 0;  // Remove newline
                char disable_check_cmd[512];
                snprintf(disable_check_cmd, sizeof(disable_check_cmd), "grep -Eq \"^\\s*install\\s+%s\\s+/bin/(true|false)\" /etc/modprobe.d/*.conf", module_name);
                if (system(disable_check_cmd) != 0) {
                    printf(RED "Fail: %s is not disabled\n" RESET, module_name);
                    all_disabled = 0;
                }
            }
            pclose(fp);
            if (all_disabled) {
                printf(GREEN "Pass: Wireless interfaces are not enabled\n" RESET);
            } else {
                printf(RED "Fail: Some wireless interfaces are enabled\n" RESET);
                printf("Action: To disable wireless interfaces:\n");
                printf("1. Run 'nmcli radio all off' to immediately disable wireless\n");
                printf("2. For permanent disable, create /etc/modprobe.d/disable-wireless.conf with:\n");
                printf("   install iwlwifi /bin/false\n");
                printf("   install wl /bin/false\n");
                printf("3. Run 'sudo systemctl mask wireless.service'\n");
            }
        } else {
            printf(GREEN "Pass: No wireless interfaces detected\n" RESET);
            printf("Action: Edit /etc/sysctl.conf and add:\n");
            printf("  net.ipv4.conf.all.send_redirects = 0\n");
            printf("  net.ipv4.conf.default.send_redirects = 0\n");
            printf("Then run 'sudo sysctl -p'\n");
        }
    }
}

// 3.2 - Host Network Parameters
void test_packet_redirect_sending_disabled() {
    printf("Test: 3.2.1 Ensure packet redirect sending is disabled (Automated)\n");

    // Check sysctl settings
    if (check_command("sysctl net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.send_redirects = 0") &&
        check_command("sysctl net.ipv4.conf.default.send_redirects", "net.ipv4.conf.default.send_redirects = 0")) {
        printf(GREEN "Pass: Packet redirect sending is disabled\n" RESET);
    } else {
        printf(RED "Fail: Packet redirect sending is not disabled\n" RESET);
    }

    // Check configuration files for proper settings
    if (check_command("grep \"net\\.ipv4\\.conf\\.all\\.send_redirects = 0\" /etc/sysctl.conf /etc/sysctl.d/*", "net.ipv4.conf.all.send_redirects = 0") &&
        check_command("grep \"net\\.ipv4\\.conf\\.default\\.send_redirects = 0\" /etc/sysctl.conf /etc/sysctl.d/*", "net.ipv4.conf.default.send_redirects = 0")) {
        printf(GREEN "Pass: Configuration files correctly set packet redirect sending to disabled\n" RESET);
    } else {
        printf(RED "Fail: Configuration files do not correctly set packet redirect sending\n" RESET);
    }
}

void test_ip_forwarding_disabled() {
    printf("Test: 3.2.2 Ensure IP forwarding is disabled (Automated)\n");

    // Check IPv4 forwarding
    if (check_command("sysctl net.ipv4.ip_forward", "net.ipv4.ip_forward = 0")) {
        printf(GREEN "Pass: IPv4 forwarding is disabled\n" RESET);
    } else {
        printf(RED "Fail: IPv4 forwarding is not disabled\n" RESET);
        printf("Action: Edit /etc/sysctl.conf and add:\n");
        printf("  net.ipv4.ip_forward = 0\n");
        printf("Then run 'sudo sysctl -p'\n");

    }

    // Check configuration files for IPv4 forwarding settings
    if (!check_command("grep -E -s \"^\\s*net\\.ipv4\\.ip_forward\\s*=\\s*1\" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf", "net.ipv4.ip_forward = 1")) {
        printf(GREEN "Pass: Configuration files correctly set IPv4 forwarding to disabled\n" RESET);
    } else {
        printf(RED "Fail: Configuration files have incorrect IPv4 forwarding settings\n" RESET);
    }

    // Check if IPv6 is enabled and check forwarding setting
    if (check_command("sysctl net.ipv6.conf.all.forwarding", "net.ipv6.conf.all.forwarding = 0")) {
        printf(GREEN "Pass: IPv6 forwarding is disabled\n" RESET);
    } else {
        printf(RED "Fail: IPv6 forwarding is not disabled\n" RESET);
        printf("Action: Edit /etc/sysctl.conf and add:\n");
        printf("  net.ipv6.conf.all.forwarding = 0\n");
        printf("Then run 'sudo sysctl -p'\n");
    }

    // Check configuration files for IPv6 forwarding settings
    if (!check_command("grep -E -s \"^\\s*net\\.ipv6\\.conf\\.all\\.forwarding\\s*=\\s*1\" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf", "net.ipv6.conf.all.forwarding = 1")) {
        printf(GREEN "Pass: Configuration files correctly set IPv6 forwarding to disabled\n" RESET);
    } else {
        printf(RED "Fail: Configuration files have incorrect IPv6 forwarding settings\n" RESET);
    }
}

// 3.3 Network Parameters between Host and Router
void test_source_routed_packets() {
    printf("Test 3.3.1: Ensure source-routed packets are not accepted (Automated)\n");

    // Check IPv4 source-routing settings
    if (check_command("sysctl net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_source_route = 0") &&
        check_command("sysctl net.ipv4.conf.default.accept_source_route", "net.ipv4.conf.default.accept_source_route = 0")) {
        printf(GREEN "Pass: IPv4 source-routed packets are not accepted\n" RESET);
    } else {
        printf(RED "Fail: IPv4 source-routed packets acceptance is not disabled\n" RESET);
        printf("Action: Edit /etc/sysctl.conf and add:\n");
        printf("  net.ipv4.conf.all.accept_source_route = 0\n");
        printf("  net.ipv4.conf.default.accept_source_route = 0\n");
        printf("  net.ipv6.conf.all.accept_source_route = 0\n");
        printf("  net.ipv6.conf.default.accept_source_route = 0\n");
        printf("Then run 'sudo sysctl -p'\n");

    }

    // Check if IPv6 is enabled
    // check_ipv6_status();
    if (check_command("sysctl net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.all.accept_source_route = 0") &&
        check_command("sysctl net.ipv6.conf.default.accept_source_route", "net.ipv6.conf.default.accept_source_route = 0")) {
        printf(GREEN "Pass: IPv6 source-routed packets are not accepted\n" RESET);
    } else {
        printf(RED "Fail: IPv6 source-routed packets acceptance is not disabled\n" RESET);
    }
}

int is_ipv6_enabled() {
    return !check_command("sysctl net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.disable_ipv6 = 1") &&
           !check_command("sysctl net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.default.disable_ipv6 = 1");
}

void test_icmp_redirects() {
    printf("Test 3.3.2: Ensure ICMP redirects are not accepted (Automated)\n");

    // Check IPv4 ICMP redirect settings
    if (check_command("sysctl net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.accept_redirects = 0") &&
        check_command("sysctl net.ipv4.conf.default.accept_redirects", "net.ipv4.conf.default.accept_redirects = 0")) {
        printf(GREEN "Pass: IPv4 ICMP redirects are not accepted\n" RESET);
    } else {
        printf(RED "Fail: IPv4 ICMP redirects acceptance is not disabled\n" RESET);
        printf("Action: Edit /etc/sysctl.conf and add:\n");
        printf("  net.ipv4.conf.all.accept_redirects = 0\n");
        printf("  net.ipv4.conf.default.accept_redirects = 0\n");
        printf("  net.ipv6.conf.all.accept_redirects = 0\n");
        printf("  net.ipv6.conf.default.accept_redirects = 0\n");
        printf("Then run 'sudo sysctl -p'\n");
    }

    // Check if IPv6 is enabled
    // check_ipv6_status();
    if (check_command("sysctl net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.all.accept_redirects = 0") &&
        check_command("sysctl net.ipv6.conf.default.accept_redirects", "net.ipv6.conf.default.accept_redirects = 0")) {
        printf(GREEN "Pass: IPv6 ICMP redirects are not accepted\n" RESET);
    } else {
        printf(RED "Fail: IPv6 ICMP redirects acceptance is not disabled\n" RESET);
    }
}

void test_suspicious_packet_logging() {
    printf("Test 3.3.3: Ensure suspicious packets are logged (Automated)\n");

    // Check if suspicious packets are logged in IPv4
    if (check_command("sysctl net.ipv4.conf.all.log_martians", "net.ipv4.conf.all.log_martians = 1") &&
        check_command("sysctl net.ipv4.conf.default.log_martians", "net.ipv4.conf.default.log_martians = 1")) {
        printf(GREEN "Pass: Suspicious packets logging is enabled for IPv4\n" RESET);
    } else {
        printf(RED "Fail: Suspicious packets logging is not enabled for IPv4\n" RESET);
        printf("Action: Edit /etc/sysctl.conf and add:\n");
        printf("  net.ipv4.conf.all.log_martians = 1\n");
        printf("  net.ipv4.conf.default.log_martians = 1\n");
        printf("Then run 'sudo sysctl -p'\n");
    }
}

void test_bogus_icmp_ignore() {
    printf("Test 3.3.4: Ensure bogus ICMP responses are ignored (Automated)\n");

    // Check if bogus ICMP responses are ignored
    if (check_command("sysctl net.ipv4.icmp_ignore_bogus_error_responses", "net.ipv4.icmp_ignore_bogus_error_responses = 1")) {
        printf(GREEN "Pass: Bogus ICMP responses are ignored\n" RESET);
    } else {
        printf(RED "Fail: Bogus ICMP responses are not ignored\n" RESET);
   }
}
int main() {

    // 3.1 - Disable unused network protocols
    test_disable_ipv6();	// 3.1.1
    sleep(1);
    test_disable_wireless_interfaces();  // 3.1.2
    sleep(1);

    // 3.2 - Host Network Params
    test_packet_redirect_sending_disabled(); // 3.2.1
    sleep(1);
    test_ip_forwarding_disabled();           // 3.2.2
    sleep(1);

    // 3.3 - Host and Router Params
    // check_ipv6_status();			// 3.3.1
    test_source_routed_packets();		// 3.3.2
    sleep(1);
    test_icmp_redirects();			// 3.3.3
    sleep(1);
    test_suspicious_packet_logging();		// 3.3.4
    sleep(1);
    test_bogus_icmp_ignore();			// 3.3.5
    return 0;
}
