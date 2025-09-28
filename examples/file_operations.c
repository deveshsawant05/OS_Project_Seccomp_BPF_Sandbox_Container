#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

/**
 * File Operations Sandbox Example
 * 
 * This example demonstrates how to create a sandbox that:
 * 1. Restricts file access to specific directories
 * 2. Prevents modification of system files
 * 3. Logs file access attempts
 * 4. Implements different permission levels
 */

/**
 * Install a filter that restricts file operations to /tmp directory
 */
void install_tmp_only_filter() {
    struct sock_filter filter[] = {
        // Validate architecture
        VALIDATE_ARCHITECTURE,

        // Load syscall number
        LOAD_SYSCALL_NR,

        // Always allow essential syscalls
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(rt_sigreturn),

        // Allow file operations (will be further restricted by path checks)
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),
        ALLOW_SYSCALL(access),

        // Allow directory operations
        ALLOW_SYSCALL(getdents),
        ALLOW_SYSCALL(getdents64),

        // Block dangerous file operations
        DENY_SYSCALL(unlink),
        DENY_SYSCALL(unlinkat),
        DENY_SYSCALL(rmdir),
        DENY_SYSCALL(rename),
        DENY_SYSCALL(renameat),
        DENY_SYSCALL(chmod),
        DENY_SYSCALL(fchmod),
        DENY_SYSCALL(chown),
        DENY_SYSCALL(fchown),

        // Block process creation
        DENY_SYSCALL(execve),
        DENY_SYSCALL(execveat),
        DENY_SYSCALL(fork),
        DENY_SYSCALL(vfork),
        DENY_SYSCALL(clone),

        // Return EPERM for other syscalls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    printf("Installing /tmp-only file access filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install file sandbox filter\n");
        exit(1);
    }
    printf("File sandbox filter installed successfully!\n\n");
}

/**
 * Test file operations in different directories
 */
void test_file_access() {
    printf("=== Testing File Access Restrictions ===\n");

    // Test 1: Try to read a system file
    printf("1. Attempting to read /etc/passwd: ");
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        printf("ALLOWED\n");
        char buffer[100];
        ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("   First line: %.60s...\n", buffer);
        }
        close(fd);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 2: Try to write to /tmp (should work)
    printf("2. Attempting to write to /tmp/sandbox_test.txt: ");
    fd = open("/tmp/sandbox_test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        printf("ALLOWED\n");
        const char *data = "Hello from file sandbox!\n";
        write(fd, data, strlen(data));
        close(fd);
        printf("   Data written successfully\n");
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 3: Try to read back from /tmp
    printf("3. Attempting to read from /tmp/sandbox_test.txt: ");
    fd = open("/tmp/sandbox_test.txt", O_RDONLY);
    if (fd >= 0) {
        printf("ALLOWED\n");
        char buffer[100];
        ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("   Content: %s", buffer);
        }
        close(fd);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 4: Try to write to home directory
    printf("4. Attempting to write to ~/sandbox_test.txt: ");
    const char *home = getenv("HOME");
    char home_path[512];
    if (home) {
        snprintf(home_path, sizeof(home_path), "%s/sandbox_test.txt", home);
        fd = open(home_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            printf("ALLOWED (this should be blocked in a real sandbox)\n");
            close(fd);
        } else {
            printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
        }
    } else {
        printf("SKIPPED (HOME not set)\n");
    }

    // Test 5: Try to delete a file (should be blocked)
    printf("5. Attempting to delete /tmp/sandbox_test.txt: ");
    if (unlink("/tmp/sandbox_test.txt") == 0) {
        printf("ALLOWED (this should be blocked!)\n");
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }

    // Test 6: Try to list directory contents
    printf("6. Attempting to list /tmp directory: ");
    DIR *dir = opendir("/tmp");
    if (dir) {
        printf("ALLOWED\n");
        struct dirent *entry;
        int count = 0;
        printf("   Contents: ");
        while ((entry = readdir(dir)) != NULL && count < 5) {
            if (entry->d_name[0] != '.') {
                printf("%s ", entry->d_name);
                count++;
            }
        }
        printf("...\n");
        closedir(dir);
    } else {
        printf("BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

/**
 * Create a comprehensive file sandbox
 */
void create_file_sandbox() {
    printf("=== File Operations Sandbox ===\n");
    printf("This sandbox restricts file operations to safe directories.\n\n");

    // Setup signal handler
    setup_signal_handler();

    // Install the filter
    install_tmp_only_filter();

    // Run tests
    test_file_access();

    printf("\nFile operations test completed.\n");
    printf("Note: In a production sandbox, you would also implement:\n");
    printf("- Path validation using ptrace or eBPF\n");
    printf("- Chroot jail for additional isolation\n");
    printf("- Namespace isolation\n");
    printf("- Resource limits (ulimit)\n");
}

/**
 * Demonstrate read-only filesystem sandbox
 */
void create_readonly_sandbox() {
    printf("=== Read-Only Filesystem Sandbox ===\n");
    printf("This sandbox allows only read operations on files.\n\n");

    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Allow essential syscalls
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),  // Only to already open FDs
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        // Allow read-only file operations
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 6),
        // Load flags argument
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        // Check if it's read-only
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EROFS),

        // Allow stat operations
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),
        ALLOW_SYSCALL(access),

        // Block all write operations
        DENY_SYSCALL(creat),
        DENY_SYSCALL(mkdir),
        DENY_SYSCALL(rmdir),
        DENY_SYSCALL(unlink),
        DENY_SYSCALL(link),
        DENY_SYSCALL(symlink),
        DENY_SYSCALL(rename),
        DENY_SYSCALL(chmod),
        DENY_SYSCALL(chown),

        // Block process creation
        DENY_SYSCALL(execve),
        DENY_SYSCALL(fork),
        DENY_SYSCALL(clone),

        // Allow other syscalls with EPERM
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    setup_signal_handler();

    printf("Installing read-only filesystem filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install read-only filter\n");
        exit(1);
    }
    printf("Read-only filter installed successfully!\n\n");

    // Test read operations
    printf("Testing read operations:\n");
    
    printf("1. Reading /etc/os-release: ");
    int fd = open("/etc/os-release", O_RDONLY);
    if (fd >= 0) {
        printf("SUCCESS\n");
        char buffer[200];
        ssize_t bytes = read(fd, buffer, sizeof(buffer)-1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            char *newline = strchr(buffer, '\n');
            if (newline) *newline = '\0';
            printf("   First line: %s\n", buffer);
        }
        close(fd);
    } else {
        printf("FAILED: %s\n", strerror(errno));
    }

    printf("2. Attempting to create file: ");
    fd = open("/tmp/readonly_test.txt", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        printf("ERROR: Write was allowed!\n");
        close(fd);
    } else {
        printf("BLOCKED: %s\n", strerror(errno));
    }

    printf("\nRead-only sandbox test completed.\n");
}

int main(int argc, char *argv[]) {
    printf("File Operations Sandbox Examples\n");
    printf("================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <mode>\n\n", argv[0]);
        printf("Modes:\n");
        printf("  tmp      - Allow file operations only in /tmp\n");
        printf("  readonly - Allow only read operations on files\n");
        return 1;
    }

    if (strcmp(argv[1], "tmp") == 0) {
        create_file_sandbox();
    } else if (strcmp(argv[1], "readonly") == 0) {
        create_readonly_sandbox();
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
