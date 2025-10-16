#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * Advanced Seccomp Filter Example
 * 
 * This program demonstrates advanced seccomp-bpf filtering with:
 * 1. Conditional filtering based on syscall arguments
 * 2. Different return actions (ERRNO, TRAP, KILL)
 * 3. Logging of syscall attempts
 * 4. Complex filter chains
 */

/**
 * Create a filter that allows read-only file operations
 */
void install_readonly_filter() {
    struct sock_filter filter[] = {
        // Validate architecture
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

        // Always allow these essential syscalls
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_munmap, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

        // Check for open syscall - we'll inspect its flags
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 6),
        
        // Load flags argument (second argument)
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        
        // Check if O_WRONLY or O_RDWR flags are set
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),  // Allow read-only
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),  // Deny write access

        // Check for openat syscall
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 6),
        
        // Load flags argument (third argument for openat)
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[2])),
        
        // Check access mode
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),  // Allow read-only
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),  // Deny write access

        // Block dangerous syscalls with logging
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_LOG | SECCOMP_RET_KILL_PROCESS),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_LOG | SECCOMP_RET_KILL_PROCESS),

        // Return EPERM for other syscalls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    printf("Installing read-only file access filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install seccomp filter\n");
        exit(1);
    }
    printf("Read-only filter installed successfully!\n\n");
}

/**
 * Create a network sandbox filter
 */
void install_network_sandbox_filter() {
    struct sock_filter filter[] = {
        // Validate architecture
        VALIDATE_ARCHITECTURE,

        // Load syscall number
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

        // Block network-related syscalls
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

        // Allow other syscalls with EPERM for unknown ones
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    printf("Installing network sandbox filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install seccomp filter\n");
        exit(1);
    }
    printf("Network sandbox filter installed successfully!\n\n");
}

void test_readonly_operations() {
    printf("=== Testing Read-Only Operations ===\n");

    // Test 1: Read from existing file
    printf("1. Attempting to read from /etc/passwd: ");
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        printf("SUCCESS (fd=%d)\n", fd);
        char buffer[100];
        ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("   Read %zd bytes: %.50s...\n", bytes, buffer);
        }
        close(fd);
    } else {
        perror("   FAILED");
    }

    // Test 2: Try to open file for writing (should fail)
    printf("2. Attempting to open file for writing: ");
    fd = open("/tmp/test_write.txt", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        printf("ERROR: Write access was allowed! (fd=%d)\n", fd);
        close(fd);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 3: Try to open file for read-write (should fail)
    printf("3. Attempting to open file for read-write: ");
    fd = open("/tmp/test_rw.txt", O_RDWR | O_CREAT, 0644);
    if (fd >= 0) {
        printf("ERROR: Read-write access was allowed! (fd=%d)\n", fd);
        close(fd);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

void test_network_operations() {
    printf("\n=== Testing Network Operations ===\n");

    // Test 1: Try to create a socket (should fail)
    printf("1. Attempting to create socket: ");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("ERROR: Socket creation was allowed! (fd=%d)\n", sock);
        close(sock);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 2: Basic I/O operations (should work)
    printf("2. Testing basic I/O: ");
    printf("SUCCESS\n");

    // Test 3: Memory operations (should work)
    printf("3. Testing memory allocation: ");
    void *ptr = malloc(1024);
    if (ptr) {
        printf("SUCCESS\n");
        free(ptr);
    } else {
        printf("FAILED\n");
    }
}

int main(int argc, char *argv[]) {
    printf("Advanced Seccomp Filter Example\n");
    printf("===============================\n\n");

    // Setup signal handler
    setup_signal_handler();

    if (argc > 1 && strcmp(argv[1], "--readonly") == 0) {
        install_readonly_filter();
        test_readonly_operations();
    } else if (argc > 1 && strcmp(argv[1], "--network") == 0) {
        install_network_sandbox_filter();
        test_network_operations();
    } else {
        printf("Usage: %s [--readonly|--network]\n", argv[0]);
        printf("\nOptions:\n");
        printf("  --readonly  : Install read-only file access filter\n");
        printf("  --network   : Install network access blocking filter\n\n");
        
        printf("Example filters available:\n");
        printf("1. Read-only filter: Allows only read access to files\n");
        printf("2. Network sandbox: Blocks all network operations\n");
        
        return 1;
    }

    printf("\nAdvanced seccomp filtering demonstration completed!\n");
    return 0;
}
