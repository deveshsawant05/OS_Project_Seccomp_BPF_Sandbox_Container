#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * Practical Sandbox Example
 * 
 * This program demonstrates a practical sandbox implementation that:
 * 1. Creates isolated environments for untrusted code
 * 2. Implements different security levels
 * 3. Provides safe execution of external programs
 * 4. Monitors and logs security violations
 */

typedef enum {
    SANDBOX_STRICT,     // Only basic I/O allowed
    SANDBOX_LIMITED,    // Limited file access
    SANDBOX_NETWORK,    // No network access
    SANDBOX_CUSTOM      // Custom filter
} sandbox_level_t;

/**
 * Create a strict sandbox filter
 */
void create_strict_sandbox() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Allow only essential syscalls
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(rt_sigreturn),

        // Allow minimal memory management
        ALLOW_SYSCALL(brk),

        // Deny everything else
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
    };

    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install strict sandbox filter\n");
        exit(1);
    }
}

/**
 * Create a limited sandbox filter
 */
void create_limited_sandbox() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Allow file operations
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(lseek),

        // Allow memory management
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(mprotect),

        // Allow process control
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(rt_sigreturn),

        // Allow stat operations
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),

        // Block dangerous syscalls
        DENY_SYSCALL(execve),
        DENY_SYSCALL(execveat),
        DENY_SYSCALL(fork),
        DENY_SYSCALL(vfork),
        DENY_SYSCALL(clone),

        // Block network syscalls
        DENY_SYSCALL(socket),
        DENY_SYSCALL(connect),
        DENY_SYSCALL(bind),
        DENY_SYSCALL(listen),
        DENY_SYSCALL(accept),

        // Allow other syscalls with EPERM
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install limited sandbox filter\n");
        exit(1);
    }
}

/**
 * Create a no-network sandbox filter
 */
void create_no_network_sandbox() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Block all network-related syscalls
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

        // Allow all other syscalls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };

    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install no-network sandbox filter\n");
        exit(1);
    }
}

/**
 * Execute code in a sandbox
 */
int execute_in_sandbox(sandbox_level_t level, void (*user_code)(void)) {
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process - apply sandbox and execute code
        printf("Child process (%d): Applying sandbox level %d\n", getpid(), level);
        
        // Setup signal handler
        setup_signal_handler();
        
        // Apply appropriate sandbox filter
        switch (level) {
            case SANDBOX_STRICT:
                printf("Applying STRICT sandbox...\n");
                create_strict_sandbox();
                break;
            case SANDBOX_LIMITED:
                printf("Applying LIMITED sandbox...\n");
                create_limited_sandbox();
                break;
            case SANDBOX_NETWORK:
                printf("Applying NO-NETWORK sandbox...\n");
                create_no_network_sandbox();
                break;
            default:
                printf("Unknown sandbox level!\n");
                exit(1);
        }
        
        printf("Sandbox applied. Executing user code...\n");
        
        // Execute user code
        user_code();
        
        printf("User code completed successfully.\n");
        exit(0);
    } else {
        // Parent process - wait for child
        int status;
        printf("Parent process (%d): Waiting for child (%d)\n", getpid(), pid);
        
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        
        if (WIFEXITED(status)) {
            printf("Child exited with status: %d\n", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            printf("Child terminated by signal: %d\n", WTERMSIG(status));
            return -1;
        }
    }
    
    return 0;
}

// Test functions for different scenarios

void test_basic_io() {
    printf("=== Test: Basic I/O Operations ===\n");
    printf("This test performs basic input/output operations.\n");
    
    // This should work in all sandbox levels
    printf("Writing to stdout: SUCCESS\n");
    
    // Try to read from stdin (this should work)
    printf("Basic I/O test completed.\n");
}

void test_file_operations() {
    printf("=== Test: File Operations ===\n");
    printf("This test attempts various file operations.\n");
    
    // Try to create and write to a file
    int fd = open("/tmp/sandbox_test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        printf("File creation: SUCCESS\n");
        write(fd, "Hello from sandbox!\n", 20);
        close(fd);
        
        // Try to read it back
        fd = open("/tmp/sandbox_test.txt", O_RDONLY);
        if (fd >= 0) {
            char buffer[100];
            ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("File read: SUCCESS - %s", buffer);
            }
            close(fd);
        }
    } else {
        printf("File creation: BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

void test_network_operations() {
    printf("=== Test: Network Operations ===\n");
    printf("This test attempts to create network connections.\n");
    
    // Try to create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("Socket creation: SUCCESS (this should be blocked in network sandbox)\n");
        close(sock);
    } else {
        printf("Socket creation: BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

void test_dangerous_operations() {
    printf("=== Test: Dangerous Operations ===\n");
    printf("This test attempts potentially dangerous operations.\n");
    
    // Try to execute another program
    printf("Attempting execve (should be blocked)...\n");
    execve("/bin/echo", (char*[]){"echo", "Hello from execve", NULL}, NULL);
    
    // This line should not be reached if execve is blocked
    printf("ERROR: execve was not blocked!\n");
}

void interactive_sandbox_shell() {
    printf("=== Interactive Sandbox Shell ===\n");
    printf("Available commands: read, write, exit\n");
    printf("Type 'exit' to quit.\n\n");
    
    char command[256];
    
    while (1) {
        printf("sandbox> ");
        fflush(stdout);
        
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "read") == 0) {
            printf("Reading from /etc/passwd:\n");
            int fd = open("/etc/passwd", O_RDONLY);
            if (fd >= 0) {
                char buffer[200];
                ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    printf("%.100s...\n", buffer);
                }
                close(fd);
            } else {
                printf("Read blocked: %s\n", strerror(errno));
            }
        } else if (strcmp(command, "write") == 0) {
            printf("Writing to /tmp/sandbox_output.txt:\n");
            int fd = open("/tmp/sandbox_output.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                write(fd, "Hello from sandbox shell!\n", 27);
                close(fd);
                printf("Write successful!\n");
            } else {
                printf("Write blocked: %s\n", strerror(errno));
            }
        } else {
            printf("Unknown command: %s\n", command);
        }
    }
    
    printf("Exiting sandbox shell.\n");
}

int main(int argc, char *argv[]) {
    printf("Practical Seccomp Sandbox Example\n");
    printf("=================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <test_type> [sandbox_level]\n\n", argv[0]);
        printf("Test types:\n");
        printf("  basic     - Basic I/O operations\n");
        printf("  file      - File operations\n");
        printf("  network   - Network operations\n");
        printf("  dangerous - Dangerous operations\n");
        printf("  shell     - Interactive sandbox shell\n\n");
        printf("Sandbox levels:\n");
        printf("  0 - STRICT (only basic I/O)\n");
        printf("  1 - LIMITED (limited file access)\n");
        printf("  2 - NO_NETWORK (no network access)\n");
        return 1;
    }

    sandbox_level_t level = SANDBOX_LIMITED;
    if (argc >= 3) {
        level = (sandbox_level_t)atoi(argv[2]);
    }

    printf("Selected sandbox level: %d\n", level);
    printf("Starting sandbox test...\n\n");

    void (*test_function)(void) = NULL;

    if (strcmp(argv[1], "basic") == 0) {
        test_function = test_basic_io;
    } else if (strcmp(argv[1], "file") == 0) {
        test_function = test_file_operations;
    } else if (strcmp(argv[1], "network") == 0) {
        test_function = test_network_operations;
    } else if (strcmp(argv[1], "dangerous") == 0) {
        test_function = test_dangerous_operations;
    } else if (strcmp(argv[1], "shell") == 0) {
        test_function = interactive_sandbox_shell;
    } else {
        printf("Unknown test type: %s\n", argv[1]);
        return 1;
    }

    int result = execute_in_sandbox(level, test_function);
    
    printf("\nSandbox execution completed with result: %d\n", result);
    return result;
}
