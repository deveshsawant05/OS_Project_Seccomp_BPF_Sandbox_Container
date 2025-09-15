# Seccomp Programming Guide

## Introduction

Seccomp (secure computing mode) is a Linux kernel security feature that allows filtering of system calls. This guide covers the practical implementation and usage of seccomp filters for creating secure sandboxed environments.

## Table of Contents

1. [Basic Concepts](#basic-concepts)
2. [Seccomp Modes](#seccomp-modes)
3. [BPF Filters](#bpf-filters)
4. [Implementation Guide](#implementation-guide)
5. [Best Practices](#best-practices)
6. [Common Patterns](#common-patterns)
7. [Troubleshooting](#troubleshooting)

## Basic Concepts

### What is Seccomp?

Seccomp is a kernel feature that allows a process to transition into a restricted state where it can only make a limited set of system calls. It's commonly used for sandboxing untrusted code.

### Key Features

- **System call filtering**: Control which syscalls a process can make
- **Minimal overhead**: Efficient BPF-based filtering
- **Inheritance**: Child processes inherit seccomp restrictions
- **One-way transition**: Once enabled, seccomp cannot be disabled

## Seccomp Modes

### 1. Strict Mode (SECCOMP_MODE_STRICT)

The original seccomp mode that allows only four system calls:
- `read()` (from already-open file descriptors)
- `write()` (to already-open file descriptors)
- `exit()`
- `sigreturn()`

```c
#include <sys/prctl.h>
#include <linux/seccomp.h>

// Enable strict mode
if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == -1) {
    perror("prctl");
    exit(1);
}
```

### 2. Filter Mode (SECCOMP_MODE_FILTER)

Advanced mode using BPF (Berkeley Packet Filter) programs to define custom filtering rules.

```c
struct sock_filter filter[] = {
    // Filter program goes here
};

struct sock_fprog prog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter,
};

if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("prctl");
    exit(1);
}
```

## BPF Filters

### Filter Structure

BPF filters examine the `seccomp_data` structure:

```c
struct seccomp_data {
    int nr;                 // System call number
    __u32 arch;            // Architecture identifier
    __u64 instruction_pointer;
    __u64 args[6];         // System call arguments
};
```

### Basic Filter Template

```c
struct sock_filter filter[] = {
    // 1. Validate architecture
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

    // 2. Load system call number
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    // 3. Check specific system calls
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    // 4. Default action
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
};
```

### Return Values

- `SECCOMP_RET_ALLOW`: Allow the system call
- `SECCOMP_RET_ERRNO`: Return an errno value
- `SECCOMP_RET_TRAP`: Send SIGSYS signal
- `SECCOMP_RET_KILL_THREAD`: Kill the calling thread
- `SECCOMP_RET_KILL_PROCESS`: Kill the entire process
- `SECCOMP_RET_LOG`: Log the syscall and allow it

## Implementation Guide

### Step 1: Setup

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>

// Disable new privileges to allow seccomp without root
if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl");
    exit(1);
}
```

### Step 2: Create Filter

```c
struct sock_filter filter[] = {
    // Architecture validation
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

    // Load syscall number
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    // Allow essential syscalls
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    // Deny everything else
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
};
```

### Step 3: Install Filter

```c
struct sock_fprog prog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter,
};

if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("prctl");
    exit(1);
}
```

### Step 4: Handle Violations

```c
#include <signal.h>

void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    printf("Blocked syscall: %d\n", info->si_syscall);
    exit(1);
}

// Install signal handler
struct sigaction sa;
sa.sa_sigaction = sigsys_handler;
sa.sa_flags = SA_SIGINFO;
sigaction(SIGSYS, &sa, NULL);
```

## Best Practices

### 1. Always Validate Architecture

```c
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
```

### 2. Use Whitelist Approach

Deny by default, allow specific syscalls:

```c
// Allow specific syscalls
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_allowed_syscall, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

// Deny everything else
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)
```

### 3. Handle Dependencies

Some syscalls depend on others. For example, `printf()` might need:
- `write()` for output
- `brk()` or `mmap()` for memory allocation
- `fstat()` to check file descriptors

### 4. Test Thoroughly

```c
// Test in child process to avoid crashing main program
pid_t pid = fork();
if (pid == 0) {
    // Child: install filter and test
    install_filter();
    test_operations();
    exit(0);
} else {
    // Parent: wait for results
    wait(&status);
}
```

## Common Patterns

### 1. Read-Only File Access

```c
// Check open() flags
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 6),
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),
```

### 2. Network Isolation

```c
// Block all network syscalls
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socket, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),

BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_connect, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | ENETDOWN),
```

### 3. Process Isolation

```c
// Block process creation
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fork, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM),

BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM),
```

## Advanced Techniques

### 1. Argument Inspection

```c
// Check if writing to stdout/stderr only
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 4),
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[0])),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, STDOUT_FILENO, 1, 0),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, STDERR_FILENO, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
```

### 2. Conditional Filtering

```c
// Allow mmap() only for reading
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 6),
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[2])),
BPF_STMT(BPF_ALU+BPF_AND+BPF_K, PROT_WRITE),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EACCES),
```

### 3. Multiple Filter Layers

```c
// Install multiple filters for different policies
install_base_filter();      // Basic restrictions
install_network_filter();   // Network isolation
install_file_filter();      // File access control
```

## Troubleshooting

### Common Issues

1. **Filter not working**: Check architecture validation
2. **Process killed unexpectedly**: Enable signal handler for debugging
3. **EPERM errors**: Ensure `PR_SET_NO_NEW_PRIVS` is set
4. **Missing syscalls**: Use `strace` to identify required syscalls

### Debugging Tips

```c
// Use SECCOMP_RET_TRAP for debugging
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),

// Signal handler will show blocked syscalls
void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    printf("DEBUG: Blocked syscall %d\n", info->si_syscall);
    // Don't exit, continue for debugging
}
```

### Testing Framework

```c
void test_syscall(int syscall_nr, const char *name) {
    pid_t pid = fork();
    if (pid == 0) {
        install_filter();
        // Test the syscall
        syscall(syscall_nr);
        exit(0);
    } else {
        int status;
        wait(&status);
        if (WIFSIGNALED(status)) {
            printf("%s: BLOCKED\n", name);
        } else {
            printf("%s: ALLOWED\n", name);
        }
    }
}
```

## Performance Considerations

- BPF filters are very fast (minimal overhead)
- Complex filters may have slight impact
- Use simple jumps when possible
- Avoid deep filter chains

## Security Considerations

- Always validate architecture
- Use whitelist approach (deny by default)
- Consider syscall dependencies
- Test with real workloads
- Monitor for bypass attempts

## Further Reading

- [Linux kernel seccomp documentation](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
- [libseccomp library](https://github.com/seccomp/libseccomp)
- [Seccomp in practice](https://blog.lizzie.io/linux-containers-in-500-lines.html)
- [BPF documentation](https://www.kernel.org/doc/Documentation/networking/filter.txt)
