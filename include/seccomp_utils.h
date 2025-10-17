#ifndef SECCOMP_UTILS_H
#define SECCOMP_UTILS_H

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

/* Architecture-specific definitions */
#if defined(__x86_64__)
#define ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define ARCH_NR AUDIT_ARCH_I386
#elif defined(__arm__)
#define ARCH_NR AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#define ARCH_NR AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture"
#endif

/* Seccomp return values */
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_KILL_THREAD  0x00000000U
#define SECCOMP_RET_TRAP         0x00030000U
#define SECCOMP_RET_ERRNO        0x00050000U
#define SECCOMP_RET_TRACE        0x7ff00000U
#define SECCOMP_RET_LOG          0x7ffc0000U
#define SECCOMP_RET_ALLOW        0x7fff0000U

/* BPF macros for easier filter creation */
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

/* Utility macros for common operations */
#define VALIDATE_ARCHITECTURE \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)

#define LOAD_SYSCALL_NR \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr))

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define DENY_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS)

/* Function declarations */
int install_seccomp_filter(struct sock_filter *filter, unsigned int filter_len);
void print_syscall_info(int syscall_nr);
void setup_signal_handler(void);
void seccomp_violation_handler(int sig, siginfo_t *info, void *ucontext);
int enable_basic_seccomp(void);
int create_whitelist_filter(int *allowed_syscalls, int count);
int create_blacklist_filter(int *denied_syscalls, int count);
void log_syscall_attempt(int syscall_nr, const char *syscall_name);

/* Common syscall numbers for reference */
#define SYSCALL_EXIT       60
#define SYSCALL_EXIT_GROUP 231
#define SYSCALL_READ       0
#define SYSCALL_WRITE      1
#define SYSCALL_OPEN       2
#define SYSCALL_CLOSE      3
#define SYSCALL_MMAP       9
#define SYSCALL_MUNMAP     11
#define SYSCALL_BRK        12

/* Error codes */
#define SECCOMP_SUCCESS    0
#define SECCOMP_ERROR     -1
#define SECCOMP_EINVAL    -2
#define SECCOMP_ENOSYS    -3

#endif /* SECCOMP_UTILS_H */
