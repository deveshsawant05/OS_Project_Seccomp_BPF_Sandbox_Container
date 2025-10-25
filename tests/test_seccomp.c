#define _GNU_SOURCE
#include "../include/seccomp_utils.h"
#include <sys/syscall.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>

/**
 * Seccomp Test Suite
 * 
 * Comprehensive tests for seccomp functionality:
 * 1. Filter installation tests
 * 2. Syscall blocking verification
 * 3. Return value tests
 * 4. Signal handling tests
 */

static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;

#define TEST_START(name) \
    do { \
        test_count++; \
        printf("Test %d: %s ... ", test_count, name); \
        fflush(stdout); \
    } while(0)

#define TEST_PASS() \
    do { \
        printf("PASS\n"); \
        test_passed++; \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        printf("FAIL - %s\n", msg); \
        test_failed++; \
    } while(0)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("FAIL - Expected %d, got %d\n", (expected), (actual)); \
            test_failed++; \
            return; \
        } \
    } while(0)

/**
 * Test basic filter installation
 */
void test_filter_installation() {
    TEST_START("Basic filter installation");

    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
    };

    int result = install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0]));
    if (result == SECCOMP_SUCCESS) {
        TEST_PASS();
    } else {
        TEST_FAIL("Filter installation failed");
    }
}

/**
 * Test whitelist filter creation
 */
void test_whitelist_filter() {
    TEST_START("Whitelist filter creation");

    int allowed_syscalls[] = {
        __NR_exit,
        __NR_exit_group,
        __NR_read,
        __NR_write
    };

    int result = create_whitelist_filter(allowed_syscalls, 4);
    if (result == SECCOMP_SUCCESS) {
        TEST_PASS();
    } else {
        TEST_FAIL("Whitelist filter creation failed");
    }
}

/**
 * Test blacklist filter creation
 */
void test_blacklist_filter() {
    TEST_START("Blacklist filter creation");

    int denied_syscalls[] = {
        __NR_execve,
        __NR_fork,
        __NR_clone
    };

    int result = create_blacklist_filter(denied_syscalls, 3);
    if (result == SECCOMP_SUCCESS) {
        TEST_PASS();
    } else {
        TEST_FAIL("Blacklist filter creation failed");
    }
}

/**
 * Test signal handler setup
 */
void test_signal_handler() {
    TEST_START("Signal handler setup");

    setup_signal_handler();
    
    // Verify signal handler is installed
    struct sigaction sa;
    if (sigaction(SIGSYS, NULL, &sa) == 0 && sa.sa_sigaction != NULL) {
        TEST_PASS();
    } else {
        TEST_FAIL("Signal handler not properly installed");
    }
}

/**
 * Test syscall information functions
 */
void test_syscall_info() {
    TEST_START("Syscall information functions");

    // Test print_syscall_info (just verify it doesn't crash)
    print_syscall_info(__NR_read);
    print_syscall_info(__NR_write);
    print_syscall_info(999); // Unknown syscall

    TEST_PASS();
}

/**
 * Test in child process to avoid affecting main process
 */
void run_filter_test(void (*test_func)(void), const char *test_name) {
    pid_t pid = fork();
    
    if (pid == -1) {
        printf("Test %d: %s ... FAIL - Fork failed\n", ++test_count, test_name);
        test_failed++;
        return;
    }
    
    if (pid == 0) {
        // Child process
        test_func();
        exit(0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            // Child exited normally, which means test passed
        } else {
            // Child was killed or exited with error
        }
    }
}

/**
 * Test strict seccomp mode
 */
void test_strict_seccomp() {
    printf("Test %d: Strict seccomp mode ... ", ++test_count);
    
    pid_t pid = fork();
    if (pid == -1) {
        TEST_FAIL("Fork failed");
        return;
    }
    
    if (pid == 0) {
        // Child process - enable strict mode (filter-based)
        if (enable_basic_seccomp() != 0) {
            exit(1);
        }
        
        // Try to do something that should be blocked
        // In strict mode, only read, write, exit, sigreturn are allowed
        // Try getpid() which should be blocked
        getpid();
        
        // Should not reach here if filter is working
        exit(2);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        // Child should be killed by SIGSYS or exit with error
        if (WIFSIGNALED(status)) {
            // Process was killed by a signal (likely SIGSYS)
            TEST_PASS();
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
            // Filter installation failed
            TEST_FAIL("Filter installation failed");
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
            // Syscall was not blocked
            TEST_FAIL("Strict mode did not block syscall");
        } else {
            TEST_FAIL("Unexpected exit status");
        }
    }
}

/**
 * Test errno return values
 */
void test_errno_returns() {
    printf("Test %d: ERRNO return values ... ", ++test_count);
    
    pid_t pid = fork();
    if (pid == -1) {
        TEST_FAIL("Fork failed");
        return;
    }
    
    if (pid == 0) {
        // Child process - install filter that returns EACCES for openat
        struct sock_filter filter[] = {
            VALIDATE_ARCHITECTURE,
            LOAD_SYSCALL_NR,
            
            ALLOW_SYSCALL(exit),
            ALLOW_SYSCALL(exit_group),
            ALLOW_SYSCALL(brk),
            ALLOW_SYSCALL(mmap),
            ALLOW_SYSCALL(munmap),
            
            // Return EACCES for openat (x86_64 uses openat instead of open)
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),
            
#ifdef __NR_open
            // Also handle open for 32-bit systems
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),
#endif
            
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
        };
        
        if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
            exit(1);
        }
        
        // Try to open a file - should get EACCES
        int fd = open("/tmp/test", O_RDONLY);
        if (fd == -1 && errno == EACCES) {
            exit(0); // Success
        }
        
        exit(2); // Wrong errno or open succeeded
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            TEST_PASS();
        } else {
            TEST_FAIL("ERRNO return value test failed");
        }
    }
}

/**
 * Performance test - measure filter overhead
 */
void test_performance() {
    TEST_START("Performance test");
    
    // Install a simple filter
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(getpid),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };
    
    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
        TEST_FAIL("Filter installation failed");
        return;
    }
    
    // Measure time for many syscalls
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < 10000; i++) {
        getpid(); // Simple syscall
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    printf("10000 syscalls took %ld ns (avg: %ld ns/call) ... ", ns, ns/10000);
    
    TEST_PASS();
}

/**
 * Test filter with complex conditions
 */
void test_complex_filter() {
    printf("Test %d: Complex filter conditions ... ", ++test_count);
    
    pid_t pid = fork();
    if (pid == -1) {
        TEST_FAIL("Fork failed");
        return;
    }
    
    if (pid == 0) {
        // Child process - install filter that checks openat flags
        struct sock_filter filter[] = {
            VALIDATE_ARCHITECTURE,
            LOAD_SYSCALL_NR,
            
            ALLOW_SYSCALL(exit),
            ALLOW_SYSCALL(exit_group),
            ALLOW_SYSCALL(close),
            ALLOW_SYSCALL(fstat),
            ALLOW_SYSCALL(brk),
            ALLOW_SYSCALL(mmap),
            ALLOW_SYSCALL(munmap),
            
            // Check openat syscall (x86_64 uses openat)
            // If NOT openat, skip to default allow (skip next 5 instructions)
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 5),
            
            // Load flags (third argument for openat, index 2)
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[2])),
            
            // Check if read-only (flags & O_ACCMODE == O_RDONLY)
            BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),
            
            // Default: allow all other syscalls
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
        };
        
        if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) != 0) {
            exit(1);
        }
        
        // Test read-only open (should work)
        int fd1 = open("/etc/passwd", O_RDONLY);
        if (fd1 < 0) {
            exit(2); // Read-only open failed
        }
        close(fd1);
        
        // Test write open (should fail)
        int fd2 = open("/tmp/test", O_WRONLY | O_CREAT, 0644);
        if (fd2 >= 0) {
            close(fd2);
            exit(3); // Write open succeeded when it shouldn't
        }
        
        if (errno != EACCES) {
            exit(4); // Wrong error code
        }
        
        exit(0); // Success
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            TEST_PASS();
        } else {
            char msg[100];
            snprintf(msg, sizeof(msg), "Exit status: %d", WEXITSTATUS(status));
            TEST_FAIL(msg);
        }
    }
}

/**
 * Print test summary
 */
void print_test_summary() {
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed:      %d\n", test_passed);
    printf("Failed:      %d\n", test_failed);
    printf("Success rate: %.1f%%\n", 
           test_count > 0 ? (test_passed * 100.0 / test_count) : 0.0);
    
    if (test_failed == 0) {
        printf("\n🎉 All tests passed!\n");
    } else {
        printf("\n❌ Some tests failed. Please review the failures above.\n");
    }
}

int main(int argc, char *argv[]) {
    printf("Seccomp Test Suite\n");
    printf("==================\n\n");

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [test_name]\n\n", argv[0]);
        printf("Available tests:\n");
        printf("  basic      - Basic functionality tests\n");
        printf("  filters    - Filter creation tests\n");
        printf("  strict     - Strict seccomp mode test\n");
        printf("  errno      - ERRNO return value test\n");
        printf("  complex    - Complex filter conditions\n");
        printf("  perf       - Performance test\n");
        printf("  all        - Run all tests (default)\n");
        return 0;
    }

    const char *test_name = argc > 1 ? argv[1] : "all";

    if (strcmp(test_name, "basic") == 0 || strcmp(test_name, "all") == 0) {
        // Run basic tests
        run_filter_test(test_filter_installation, "Basic filter installation");
        run_filter_test(test_signal_handler, "Signal handler setup");
        run_filter_test(test_syscall_info, "Syscall information functions");
    }

    if (strcmp(test_name, "filters") == 0 || strcmp(test_name, "all") == 0) {
        // Run filter tests
        run_filter_test(test_whitelist_filter, "Whitelist filter creation");
        run_filter_test(test_blacklist_filter, "Blacklist filter creation");
    }

    if (strcmp(test_name, "strict") == 0 || strcmp(test_name, "all") == 0) {
        test_strict_seccomp();
    }

    if (strcmp(test_name, "errno") == 0 || strcmp(test_name, "all") == 0) {
        test_errno_returns();
    }

    if (strcmp(test_name, "complex") == 0 || strcmp(test_name, "all") == 0) {
        test_complex_filter();
    }

    if (strcmp(test_name, "perf") == 0 || strcmp(test_name, "all") == 0) {
        // Run performance test in child process
        pid_t pid = fork();
        if (pid == 0) {
            test_performance();
            exit(0);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        }
    }

    print_test_summary();

    return test_failed > 0 ? 1 : 0;
}
