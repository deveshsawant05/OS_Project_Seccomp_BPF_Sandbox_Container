#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Define __NR_waitpid if not available on 64-bit systems */
#ifndef __NR_waitpid
#define __NR_waitpid __NR_wait4
#endif

/**
 * Shell Sandbox Example
 * 
 * This example demonstrates creating a sandboxed shell environment:
 * 1. Limited command execution
 * 2. File system restrictions  
 * 3. Process isolation
 * 4. Resource monitoring
 */

/**
 * Install shell sandbox filter
 */
void install_shell_sandbox_filter() {
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,

        // Allow basic process operations
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),

        // Allow memory management
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(mprotect),

        // Allow file operations (read-only)
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 6),
        // Load flags argument
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        // Check if read-only
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),

        // Allow stat operations
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),
        ALLOW_SYSCALL(access),

        // Allow directory operations
        ALLOW_SYSCALL(getdents),
        ALLOW_SYSCALL(getdents64),
        ALLOW_SYSCALL(getcwd),
        ALLOW_SYSCALL(chdir),

        // Allow limited process creation (for safe commands)
        ALLOW_SYSCALL(fork),
        ALLOW_SYSCALL(vfork),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(execve),
        ALLOW_SYSCALL(wait4),
        ALLOW_SYSCALL(waitpid),

        // Allow signal handling
        ALLOW_SYSCALL(rt_sigaction),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(rt_sigreturn),

        // Allow time operations
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),

        // Allow user/group info
        ALLOW_SYSCALL(getuid),
        ALLOW_SYSCALL(getgid),
        ALLOW_SYSCALL(geteuid),
        ALLOW_SYSCALL(getegid),
        ALLOW_SYSCALL(getpid),
        ALLOW_SYSCALL(getppid),

        // Block dangerous operations
        DENY_SYSCALL(unlink),
        DENY_SYSCALL(rmdir),
        DENY_SYSCALL(rename),
        DENY_SYSCALL(chmod),
        DENY_SYSCALL(chown),
        DENY_SYSCALL(mount),
        DENY_SYSCALL(umount2),
        DENY_SYSCALL(reboot),
        DENY_SYSCALL(swapon),
        DENY_SYSCALL(swapoff),

        // Block network operations
        DENY_SYSCALL(socket),
        DENY_SYSCALL(connect),
        DENY_SYSCALL(bind),

        // Block ptrace and debugging
        DENY_SYSCALL(ptrace),

        // Allow other syscalls with EPERM
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };

    printf("Installing shell sandbox filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install shell sandbox filter\n");
        exit(1);
    }
    printf("Shell sandbox filter installed successfully!\n\n");
}

/**
 * Safe command whitelist
 */
const char *safe_commands[] = {
    "ls", "cat", "echo", "pwd", "whoami", "id", "date", "uptime",
    "ps", "uname", "head", "tail", "wc", "grep", "sort", "uniq",
    "which", "type", "help", "history", NULL
};

/**
 * Check if a command is in the safe list
 */
int is_safe_command(const char *command) {
    for (int i = 0; safe_commands[i] != NULL; i++) {
        if (strcmp(command, safe_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Execute a command safely
 */
int execute_safe_command(const char *command, char *args[]) {
    if (!is_safe_command(command)) {
        printf("Command '%s' is not allowed in sandbox\n", command);
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // Child process - execute command
        char command_path[256];
        
        // Try common paths
        const char *paths[] = {"/bin/", "/usr/bin/", "/usr/local/bin/", NULL};
        for (int i = 0; paths[i] != NULL; i++) {
            snprintf(command_path, sizeof(command_path), "%s%s", paths[i], command);
            if (access(command_path, X_OK) == 0) {
                execv(command_path, args);
                perror("execv");
                exit(1);
            }
        }
        
        printf("Command '%s' not found\n", command);
        exit(1);
    } else {
        // Parent process - wait for child
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        return WEXITSTATUS(status);
    }
}

/**
 * Parse command line input
 */
int parse_command(char *input, char *args[], int max_args) {
    int argc = 0;
    char *token = strtok(input, " \t\n");
    
    while (token != NULL && argc < max_args - 1) {
        args[argc++] = token;
        token = strtok(NULL, " \t\n");
    }
    
    args[argc] = NULL;
    return argc;
}

/**
 * Display help information
 */
void show_help() {
    printf("\nSandboxed Shell Help\n");
    printf("===================\n\n");
    printf("This is a restricted shell environment. Only safe commands are allowed.\n\n");
    printf("Available commands:\n");
    for (int i = 0; safe_commands[i] != NULL; i++) {
        printf("  %s", safe_commands[i]);
        if ((i + 1) % 6 == 0) printf("\n");
    }
    printf("\n\nBuilt-in commands:\n");
    printf("  help     - Show this help\n");
    printf("  exit     - Exit the shell\n");
    printf("  cd <dir> - Change directory\n");
    printf("  pwd      - Show current directory\n");
    printf("  info     - Show sandbox information\n");
    printf("\nSecurity restrictions:\n");
    printf("  - No file modification allowed\n");
    printf("  - No network access\n");
    printf("  - Limited command set\n");
    printf("  - No dangerous operations\n\n");
}

/**
 * Show sandbox information
 */
void show_sandbox_info() {
    printf("\nSandbox Information\n");
    printf("==================\n");
    printf("Process ID: %d\n", getpid());
    printf("Parent PID: %d\n", getppid());
    printf("User ID: %d\n", getuid());
    printf("Group ID: %d\n", getgid());
    
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("Working Directory: %s\n", cwd);
    }
    
    printf("Sandbox Features:\n");
    printf("  - Read-only file system access\n");
    printf("  - No network connectivity\n");
    printf("  - Limited command execution\n");
    printf("  - Process isolation\n");
    printf("  - Seccomp filtering active\n\n");
}

/**
 * Interactive shell loop
 */
void run_shell() {
    char input[256];
    char *args[32];
    
    printf("Welcome to the Sandboxed Shell!\n");
    printf("Type 'help' for available commands or 'exit' to quit.\n\n");
    
    while (1) {
        printf("sandbox$ ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break;
        }
        
        // Remove leading/trailing whitespace
        char *start = input;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '\n' || *start == '\0') continue;
        
        int argc = parse_command(start, args, 32);
        if (argc == 0) continue;
        
        // Handle built-in commands
        if (strcmp(args[0], "exit") == 0) {
            printf("Exiting sandboxed shell.\n");
            break;
        } else if (strcmp(args[0], "help") == 0) {
            show_help();
        } else if (strcmp(args[0], "info") == 0) {
            show_sandbox_info();
        } else if (strcmp(args[0], "cd") == 0) {
            if (argc > 1) {
                if (chdir(args[1]) != 0) {
                    perror("cd");
                }
            } else {
                printf("Usage: cd <directory>\n");
            }
        } else if (strcmp(args[0], "pwd") == 0) {
            char cwd[256];
            if (getcwd(cwd, sizeof(cwd))) {
                printf("%s\n", cwd);
            } else {
                perror("pwd");
            }
        } else {
            // Try to execute external command
            execute_safe_command(args[0], args);
        }
    }
}

/**
 * Test shell sandbox restrictions
 */
void test_shell_restrictions() {
    printf("=== Testing Shell Sandbox Restrictions ===\n");

    // Test 1: Try to create a file
    printf("1. Attempting to create file: ");
    int fd = open("/tmp/shell_test.txt", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        printf("FAILED - File creation was allowed!\n");
        close(fd);
    } else {
        printf("SUCCESS - File creation blocked (%s)\n", strerror(errno));
    }

    // Test 2: Try to read a file
    printf("2. Attempting to read /etc/passwd: ");
    fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        printf("SUCCESS - Read access allowed\n");
        close(fd);
    } else {
        printf("FAILED - Read access blocked (%s)\n", strerror(errno));
    }

    // Test 3: Try to delete a file
    printf("3. Attempting to delete file: ");
    if (unlink("/tmp/nonexistent.txt") == 0) {
        printf("FAILED - Deletion was allowed!\n");
    } else {
        printf("SUCCESS - Deletion blocked (%s)\n", strerror(errno));
    }

    // Test 4: Try to create network socket
    printf("4. Attempting to create socket: ");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("FAILED - Socket creation was allowed!\n");
        close(sock);
    } else {
        printf("SUCCESS - Socket creation blocked (%s)\n", strerror(errno));
    }

    printf("\nRestriction tests completed.\n\n");
}

int main(int argc, char *argv[]) {
    printf("Shell Sandbox Example\n");
    printf("====================\n\n");

    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        printf("Running sandbox restriction tests...\n\n");
        setup_signal_handler();
        install_shell_sandbox_filter();
        test_shell_restrictions();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [--test|--help]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --test   Run restriction tests\n");
        printf("  --help   Show this help\n");
        printf("\nDefault: Start interactive sandboxed shell\n");
        return 0;
    }

    // Setup signal handler
    setup_signal_handler();

    // Install sandbox filter
    install_shell_sandbox_filter();

    // Test restrictions first
    test_shell_restrictions();

    // Run interactive shell
    run_shell();

    return 0;
}
