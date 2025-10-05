#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>

/**
 * Simple Syscall Tester
 * 
 * This program helps you test if specific syscalls are allowed or blocked.
 * Usage: ./test_syscall <filter_type> <syscall_name>
 */

void print_usage() {
    printf("Usage: ./test_syscall <filter_type> <syscall_name>\n\n");
    printf("Filter types:\n");
    printf("  basic       - Basic filter (minimal syscalls)\n");
    printf("  file        - File operations filter\n");
    printf("  network     - Network blocking filter\n");
    printf("  none        - No filter (test without seccomp)\n\n");
    printf("Syscall tests:\n");
    printf("  read        - Test read syscall\n");
    printf("  write       - Test write syscall\n");
    printf("  open        - Test open syscall\n");
    printf("  socket      - Test socket syscall\n");
    printf("  fork        - Test fork syscall\n");
    printf("  execve      - Test execve syscall\n");
    printf("  unlink      - Test unlink syscall\n");
    printf("  time        - Test time syscall\n\n");
    printf("Example: ./test_syscall basic open\n");
}

void install_basic_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0]));
}

void install_file_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unlink, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };
    install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0]));
}

void install_network_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0]));
}

void test_read() {
    char buf[10];
    printf("Testing read syscall...\n");
    int fd = 0; // stdin
    ssize_t result = read(fd, buf, 0);
    if (result >= 0) {
        printf("✓ READ: SUCCESS - Syscall allowed\n");
    } else {
        printf("✗ READ: FAILED - %s\n", strerror(errno));
    }
}

void test_write() {
    printf("Testing write syscall...\n");
    ssize_t result = write(1, "", 0);
    if (result >= 0) {
        printf("✓ WRITE: SUCCESS - Syscall allowed\n");
    } else {
        printf("✗ WRITE: FAILED - %s\n", strerror(errno));
    }
}

void test_open() {
    printf("Testing open syscall...\n");
    int fd = open("/tmp/test_seccomp.txt", O_RDONLY | O_CREAT, 0644);
    if (fd >= 0) {
        printf("✓ OPEN: SUCCESS - Syscall allowed\n");
        close(fd);
    } else {
        printf("✗ OPEN: BLOCKED - %s\n", strerror(errno));
    }
}

void test_socket() {
    printf("Testing socket syscall...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("✓ SOCKET: SUCCESS - Syscall allowed\n");
        close(sock);
    } else {
        printf("✗ SOCKET: BLOCKED - %s\n", strerror(errno));
    }
}

void test_fork() {
    printf("Testing fork syscall...\n");
    pid_t pid = fork();
    if (pid == 0) {
        // Child
        printf("✓ FORK: SUCCESS - Syscall allowed (child process)\n");
        exit(0);
    } else if (pid > 0) {
        // Parent
        wait(NULL);
        printf("✓ FORK: SUCCESS - Syscall allowed (parent process)\n");
    } else {
        printf("✗ FORK: BLOCKED - %s\n", strerror(errno));
    }
}

void test_unlink() {
    printf("Testing unlink syscall...\n");
    // Create a temp file first
    int fd = open("/tmp/test_unlink.txt", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    
    int result = unlink("/tmp/test_unlink.txt");
    if (result == 0) {
        printf("✓ UNLINK: SUCCESS - Syscall allowed\n");
    } else {
        printf("✗ UNLINK: BLOCKED - %s\n", strerror(errno));
    }
}

void test_time() {
    printf("Testing time syscall...\n");
    time_t t = time(NULL);
    if (t != (time_t)-1) {
        printf("✓ TIME: SUCCESS - Syscall allowed\n");
    } else {
        printf("✗ TIME: BLOCKED - %s\n", strerror(errno));
    }
}

void test_execve() {
    printf("Testing execve syscall...\n");
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};
    
    pid_t pid = fork();
    if (pid == 0) {
        execve("/bin/true", argv, envp);
        // If we get here, execve failed
        printf("✗ EXECVE: BLOCKED - %s\n", strerror(errno));
        exit(1);
    } else if (pid > 0) {
        int status;
        wait(&status);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("✓ EXECVE: SUCCESS - Syscall allowed\n");
        } else {
            printf("✗ EXECVE: BLOCKED or child crashed\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    char *filter_type = argv[1];
    char *syscall_name = argv[2];

    printf("=== Syscall Tester ===\n");
    printf("Filter: %s\n", filter_type);
    printf("Testing: %s\n\n", syscall_name);

    // Setup signal handler
    setup_signal_handler();

    // Install filter
    if (strcmp(filter_type, "basic") == 0) {
        printf("Installing basic filter...\n");
        install_basic_filter();
    } else if (strcmp(filter_type, "file") == 0) {
        printf("Installing file filter...\n");
        install_file_filter();
    } else if (strcmp(filter_type, "network") == 0) {
        printf("Installing network filter...\n");
        install_network_filter();
    } else if (strcmp(filter_type, "none") == 0) {
        printf("No filter installed (testing without seccomp)\n");
    } else {
        printf("Unknown filter type: %s\n", filter_type);
        return 1;
    }

    printf("Filter installed successfully!\n\n");

    // Test syscall
    if (strcmp(syscall_name, "read") == 0) {
        test_read();
    } else if (strcmp(syscall_name, "write") == 0) {
        test_write();
    } else if (strcmp(syscall_name, "open") == 0) {
        test_open();
    } else if (strcmp(syscall_name, "socket") == 0) {
        test_socket();
    } else if (strcmp(syscall_name, "fork") == 0) {
        test_fork();
    } else if (strcmp(syscall_name, "unlink") == 0) {
        test_unlink();
    } else if (strcmp(syscall_name, "time") == 0) {
        test_time();
    } else if (strcmp(syscall_name, "execve") == 0) {
        test_execve();
    } else {
        printf("Unknown syscall test: %s\n", syscall_name);
        return 1;
    }

    printf("\nTest completed successfully!\n");
    return 0;
}
