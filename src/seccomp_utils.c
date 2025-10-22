#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <string.h>
#include <time.h>

/* Define SYS_SECCOMP if not available */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

/* Global flag for logging */
static int logging_enabled = 1;

/**
 * Install a seccomp filter
 */
int install_seccomp_filter(struct sock_filter *filter, unsigned int filter_len) {
    struct sock_fprog prog = {
        .len = filter_len,
        .filter = filter,
    };

    // Set no new privileges to allow seccomp without being root
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return SECCOMP_ERROR;
    }

    // Install the filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        perror("prctl(PR_SET_SECCOMP)");
        return SECCOMP_ERROR;
    }

    return SECCOMP_SUCCESS;
}

/**
 * Print information about a system call
 */
void print_syscall_info(int syscall_nr) {
    const char *syscall_names[] = {
        [0] = "read", [1] = "write", [2] = "open", [3] = "close",
        [4] = "stat", [5] = "fstat", [6] = "lstat", [7] = "poll",
        [8] = "lseek", [9] = "mmap", [10] = "mprotect", [11] = "munmap",
        [12] = "brk", [13] = "rt_sigaction", [14] = "rt_sigprocmask",
        [15] = "rt_sigreturn", [16] = "ioctl", [17] = "pread64",
        [18] = "pwrite64", [19] = "readv", [20] = "writev",
        [60] = "exit", [231] = "exit_group"
    };

    if (syscall_nr >= 0 && syscall_nr < (int)(sizeof(syscall_names)/sizeof(char*)) && 
        syscall_names[syscall_nr]) {
        printf("System call: %s (%d)\n", syscall_names[syscall_nr], syscall_nr);
    } else {
        printf("System call: unknown (%d)\n", syscall_nr);
    }
}

/**
 * Signal handler for seccomp violations
 */
void seccomp_violation_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;  /* Mark as intentionally unused */
    
    if (sig == SIGSYS) {
        printf("\n=== SECCOMP VIOLATION DETECTED ===\n");
        printf("Signal: SIGSYS\n");
        printf("PID: %d\n", getpid());
        
        if (info && info->si_code == SYS_SECCOMP) {
            printf("Blocked syscall number: %d\n", info->si_syscall);
            print_syscall_info(info->si_syscall);
        }
        
        printf("Process will be terminated.\n");
        printf("=====================================\n");
        
        // Log the violation if logging is enabled
        if (logging_enabled && info) {
            log_syscall_attempt(info->si_syscall, "BLOCKED");
        }
        
        exit(1);
    }
}

/**
 * Setup signal handler for seccomp violations
 */
void setup_signal_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_sigaction = seccomp_violation_handler;
    sa.sa_flags = SA_SIGINFO;
    
    if (sigaction(SIGSYS, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
}

/**
 * Enable basic seccomp mode (only allows exit, sigreturn, read, write)
 */
int enable_basic_seccomp(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return SECCOMP_ERROR;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == -1) {
        perror("prctl(PR_SET_SECCOMP)");
        return SECCOMP_ERROR;
    }

    return SECCOMP_SUCCESS;
}

/**
 * Create a whitelist filter (only allow specified syscalls)
 */
int create_whitelist_filter(int *allowed_syscalls, int count) {
    // Calculate filter size: architecture check + syscall checks + deny all
    int filter_size = 3 + (count * 2) + 1;
    struct sock_filter *filter = malloc(filter_size * sizeof(struct sock_filter));
    
    if (!filter) {
        perror("malloc");
        return SECCOMP_ERROR;
    }

    int idx = 0;

    // Validate architecture
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch));
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS);

    // Load syscall number
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr));

    // Allow specified syscalls
    for (int i = 0; i < count; i++) {
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, allowed_syscalls[i], 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);
    }

    // Deny all other syscalls
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS);

    int result = install_seccomp_filter(filter, idx);
    free(filter);
    return result;
}

/**
 * Create a blacklist filter (deny specified syscalls, allow others)
 */
int create_blacklist_filter(int *denied_syscalls, int count) {
    // Calculate filter size: architecture check + syscall checks + allow all
    int filter_size = 3 + (count * 2) + 1;
    struct sock_filter *filter = malloc(filter_size * sizeof(struct sock_filter));
    
    if (!filter) {
        perror("malloc");
        return SECCOMP_ERROR;
    }

    int idx = 0;

    // Validate architecture
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch));
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS);

    // Load syscall number
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr));

    // Deny specified syscalls
    for (int i = 0; i < count; i++) {
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, denied_syscalls[i], 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS);
    }

    // Allow all other syscalls
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);

    int result = install_seccomp_filter(filter, idx);
    free(filter);
    return result;
}

/**
 * Log syscall attempts
 */
void log_syscall_attempt(int syscall_nr, const char *syscall_name) {
    if (!logging_enabled) return;
    
    FILE *log_file = fopen("/tmp/seccomp_log.txt", "a");
    if (log_file) {
        fprintf(log_file, "PID %d: %s syscall %d at %ld\n", 
                getpid(), syscall_name, syscall_nr, (long)time(NULL));
        fclose(log_file);
    }
}
