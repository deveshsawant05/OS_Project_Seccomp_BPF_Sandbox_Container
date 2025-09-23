#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

/**
 * Network Sandbox Example
 * 
 * This example demonstrates network access control using seccomp:
 * 1. Complete network isolation
 * 2. Selective protocol blocking
 * 3. Localhost-only access
 * 4. Port-based restrictions
 */

/**
 * Install a complete network isolation filter
 */
void install_no_network_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Allow essential syscalls
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        // Allow file operations
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),

        // Block ALL network-related syscalls
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sendmsg, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_recvmsg, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_shutdown, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getsockopt, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getsockname, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getpeername, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socketpair, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        // Allow other syscalls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };

    printf("Installing complete network isolation filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install network isolation filter\n");
        exit(1);
    }
    printf("Network isolation filter installed successfully!\n\n");
}

/**
 * Install a filter that blocks only TCP connections
 */
void install_no_tcp_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Check for socket syscall
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socket, 0, 6),
        
        // Load domain argument (first argument)
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AF_INET, 0, 3),
        
        // Load type argument (second argument)
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SOCK_STREAM, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPROTONOSUPPORT),

        // Allow all other syscalls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };

    printf("Installing TCP-blocking filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install TCP-blocking filter\n");
        exit(1);
    }
    printf("TCP-blocking filter installed successfully!\n\n");
}

/**
 * Test network operations
 */
void test_network_operations() {
    printf("=== Testing Network Operations ===\n");

    // Test 1: TCP socket creation
    printf("1. Creating TCP socket: ");
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock >= 0) {
        printf("SUCCESS (fd=%d)\n", tcp_sock);
        close(tcp_sock);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 2: UDP socket creation
    printf("2. Creating UDP socket: ");
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock >= 0) {
        printf("SUCCESS (fd=%d)\n", udp_sock);
        close(udp_sock);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 3: Unix domain socket
    printf("3. Creating Unix domain socket: ");
    int unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_sock >= 0) {
        printf("SUCCESS (fd=%d)\n", unix_sock);
        close(unix_sock);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 4: Raw socket (requires root)
    printf("4. Creating raw socket: ");
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock >= 0) {
        printf("SUCCESS (fd=%d)\n", raw_sock);
        close(raw_sock);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

/**
 * Test TCP connection attempts
 */
void test_tcp_connection() {
    printf("\n=== Testing TCP Connection ===\n");

    // Create a TCP socket first
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Cannot create TCP socket: %s\n", strerror(errno));
        return;
    }

    printf("TCP socket created successfully (fd=%d)\n", sock);

    // Try to connect to localhost:80
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("Attempting to connect to localhost:80: ");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILED (errno=%d: %s)\n", errno, strerror(errno));
    }

    close(sock);
}

/**
 * Test UDP operations
 */
void test_udp_operations() {
    printf("\n=== Testing UDP Operations ===\n");

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("Cannot create UDP socket: %s\n", strerror(errno));
        return;
    }

    printf("UDP socket created successfully (fd=%d)\n", sock);

    // Try to bind to a local address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    printf("Attempting to bind to port 12345: ");
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        printf("SUCCESS\n");
        
        // Try to send data
        printf("Attempting to send UDP packet: ");
        const char *msg = "Hello UDP!";
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(12346);
        dest.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr*)&dest, sizeof(dest)) >= 0) {
            printf("SUCCESS\n");
        } else {
            printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
        }
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    close(sock);
}

/**
 * Demonstrate complete network isolation
 */
void demonstrate_network_isolation() {
    printf("=== Complete Network Isolation Demo ===\n");
    printf("This will block ALL network operations.\n\n");

    setup_signal_handler();
    install_no_network_filter();

    test_network_operations();
    printf("\nAs expected, all network operations should be blocked.\n");
}

/**
 * Demonstrate selective network blocking
 */
void demonstrate_tcp_blocking() {
    printf("=== TCP Blocking Demo ===\n");
    printf("This will block only TCP sockets, allowing UDP.\n\n");

    setup_signal_handler();
    install_no_tcp_filter();

    test_network_operations();
    test_udp_operations();
    printf("\nTCP should be blocked, but UDP should work.\n");
}

/**
 * Show network syscall information
 */
void show_network_syscalls() {
    printf("=== Network System Call Information ===\n");
    printf("Common network-related syscalls:\n\n");
    
    printf("Socket operations:\n");
    printf("  socket:      %d\n", __NR_socket);
    printf("  bind:        %d\n", __NR_bind);
    printf("  connect:     %d\n", __NR_connect);
    printf("  listen:      %d\n", __NR_listen);
    printf("  accept:      %d\n", __NR_accept);
    
    printf("\nData transfer:\n");
    printf("  sendto:      %d\n", __NR_sendto);
    printf("  recvfrom:    %d\n", __NR_recvfrom);
    printf("  sendmsg:     %d\n", __NR_sendmsg);
    printf("  recvmsg:     %d\n", __NR_recvmsg);
    
    printf("\nSocket options:\n");
    printf("  setsockopt:  %d\n", __NR_setsockopt);
    printf("  getsockopt:  %d\n", __NR_getsockopt);
    printf("  shutdown:    %d\n", __NR_shutdown);
    
    printf("\nSocket families:\n");
    printf("  AF_INET:     %d (IPv4)\n", AF_INET);
    printf("  AF_INET6:    %d (IPv6)\n", AF_INET6);
    printf("  AF_UNIX:     %d (Unix domain)\n", AF_UNIX);
    
    printf("\nSocket types:\n");
    printf("  SOCK_STREAM: %d (TCP)\n", SOCK_STREAM);
    printf("  SOCK_DGRAM:  %d (UDP)\n", SOCK_DGRAM);
    printf("  SOCK_RAW:    %d (Raw)\n", SOCK_RAW);
}

int main(int argc, char *argv[]) {
    printf("Network Sandbox Examples\n");
    printf("========================\n\n");

    if (argc < 2) {
        printf("Usage: %s <mode>\n\n", argv[0]);
        printf("Modes:\n");
        printf("  isolation - Complete network isolation\n");
        printf("  no-tcp    - Block TCP, allow UDP\n");
        printf("  test      - Test network operations without sandbox\n");
        printf("  info      - Show network syscall information\n");
        return 1;
    }

    if (strcmp(argv[1], "isolation") == 0) {
        demonstrate_network_isolation();
    } else if (strcmp(argv[1], "no-tcp") == 0) {
        demonstrate_tcp_blocking();
    } else if (strcmp(argv[1], "test") == 0) {
        printf("=== Testing Network Operations (No Sandbox) ===\n");
        test_network_operations();
        test_tcp_connection();
        test_udp_operations();
    } else if (strcmp(argv[1], "info") == 0) {
        show_network_syscalls();
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
