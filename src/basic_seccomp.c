#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

/**
 * Basic Seccomp Example
 * 
 * This program demonstrates basic seccomp functionality by:
 * 1. Setting up signal handlers
 * 2. Installing a simple filter
 * 3. Attempting various system calls to show filtering in action
 */

void demonstrate_basic_filtering() {
    printf("=== Basic Seccomp Filter Demo ===\n");
    printf("This program will install a basic seccomp filter and test it.\n\n");

    // Setup signal handler for violations
    setup_signal_handler();

    // Create a simple filter that only allows specific syscalls
    struct sock_filter filter[] = {
        // Validate architecture
        VALIDATE_ARCHITECTURE,

        // Load syscall number
        LOAD_SYSCALL_NR,

        // Allow exit
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),

        // Allow basic I/O
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),

        // Allow memory management
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        // Allow time-related calls
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),

        // Deny everything else
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
    };

    printf("Installing seccomp filter...\n");
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        fprintf(stderr, "Failed to install seccomp filter\n");
        exit(1);
    }

    printf("Seccomp filter installed successfully!\n\n");

    // Test allowed operations
    printf("Testing allowed operations:\n");
    
    printf("1. Writing to stdout (should work): ");
    printf("SUCCESS!\n");

    printf("2. Getting current time (should work): ");
    time_t current_time = time(NULL);
    printf("Current time: %ld\n", current_time);

    printf("3. Memory allocation with brk (should work): ");
    void *old_brk = sbrk(0);
    if (brk((char*)old_brk + 4096) == 0) {
        printf("SUCCESS!\n");
        brk(old_brk); // Reset
    } else {
        printf("FAILED!\n");
    }

    // Test forbidden operations
    printf("\nTesting forbidden operations:\n");
    printf("4. Attempting to open a file (should be blocked)...\n");
    
    // This should trigger seccomp and kill the process
    int fd = open("/tmp/test.txt", O_CREAT | O_WRONLY, 0644);
    
    // This line should never be reached
    printf("ERROR: open() was not blocked!\n");
    if (fd >= 0) close(fd);
}

void show_syscall_info() {
    printf("\n=== System Call Information ===\n");
    printf("Common syscall numbers on this architecture:\n");
    
    printf("read: %d\n", __NR_read);
    printf("write: %d\n", __NR_write);
    printf("open: %d\n", __NR_open);
    printf("close: %d\n", __NR_close);
    printf("exit: %d\n", __NR_exit);
    printf("exit_group: %d\n", __NR_exit_group);
    printf("brk: %d\n", __NR_brk);
    printf("mmap: %d\n", __NR_mmap);
    
    #ifdef AUDIT_ARCH_X86_64
    printf("Architecture: x86_64\n");
    #elif defined(AUDIT_ARCH_I386)
    printf("Architecture: i386\n");
    #elif defined(AUDIT_ARCH_ARM)
    printf("Architecture: ARM\n");
    #else
    printf("Architecture: Other\n");
    #endif
}

int main(int argc, char *argv[]) {
    printf("Basic Seccomp Sandbox Filter Example\n");
    printf("=====================================\n\n");

    if (argc > 1 && strcmp(argv[1], "--info") == 0) {
        show_syscall_info();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--strict") == 0) {
        printf("Enabling strict seccomp mode (only allows exit, sigreturn, read, write)...\n");
        
        // Print something before enabling strict mode
        printf("This message is printed before enabling strict mode.\n");
        
        if (enable_basic_seccomp() != 0) {
            fprintf(stderr, "Failed to enable strict seccomp mode\n");
            return 1;
        }
        
        // After strict mode, only read/write to already open FDs is allowed
        printf("Strict seccomp mode enabled. Only basic I/O allowed now.\n");
        
        // Try to allocate memory (should fail in strict mode)
        printf("Attempting malloc (should cause termination)...\n");
        void *ptr = malloc(100);  // This will trigger seccomp violation
        printf("ERROR: malloc was allowed in strict mode!\n");
        free(ptr);
        return 0;
    }

    // Run the filtering demonstration
    demonstrate_basic_filtering();

    printf("Program completed successfully!\n");
    return 0;
}
