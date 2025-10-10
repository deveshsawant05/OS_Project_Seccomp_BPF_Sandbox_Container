# System Call Reference

This document provides a comprehensive reference of Linux system calls commonly used in seccomp filtering.

## System Call Categories

### Process Management
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `fork` | 57 | Create child process | High - Process creation |
| `vfork` | 58 | Create child process (shared memory) | High - Process creation |
| `clone` | 56 | Create child process/thread | High - Process creation |
| `execve` | 59 | Execute program | Critical - Code execution |
| `execveat` | 322 | Execute program (extended) | Critical - Code execution |
| `exit` | 60 | Terminate process | Low - Safe termination |
| `exit_group` | 231 | Terminate process group | Low - Safe termination |
| `wait4` | 61 | Wait for process | Medium - Process control |
| `waitpid` | - | Wait for specific process | Medium - Process control |
| `getpid` | 39 | Get process ID | Low - Information only |
| `getppid` | 110 | Get parent process ID | Low - Information only |

### File Operations
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `open` | 2 | Open file | Medium - File access |
| `openat` | 257 | Open file (relative to directory) | Medium - File access |
| `close` | 3 | Close file descriptor | Low - Resource cleanup |
| `read` | 0 | Read from file descriptor | Low - Data input |
| `write` | 1 | Write to file descriptor | Medium - Data output |
| `pread64` | 17 | Positional read | Low - Data input |
| `pwrite64` | 18 | Positional write | Medium - Data output |
| `lseek` | 8 | Change file position | Low - File navigation |
| `stat` | 4 | Get file status | Low - Information only |
| `fstat` | 5 | Get file status (by fd) | Low - Information only |
| `lstat` | 6 | Get symlink status | Low - Information only |
| `access` | 21 | Check file accessibility | Low - Information only |
| `faccessat` | 269 | Check file accessibility (extended) | Low - Information only |
| `unlink` | 87 | Delete file | High - File destruction |
| `unlinkat` | 263 | Delete file (extended) | High - File destruction |
| `rename` | 82 | Rename file | High - File modification |
| `renameat` | 264 | Rename file (extended) | High - File modification |
| `chmod` | 90 | Change file permissions | High - Permission change |
| `fchmod` | 91 | Change file permissions (by fd) | High - Permission change |
| `chown` | 92 | Change file ownership | High - Ownership change |
| `fchown` | 93 | Change file ownership (by fd) | High - Ownership change |

### Directory Operations
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `mkdir` | 83 | Create directory | Medium - Filesystem modification |
| `rmdir` | 84 | Remove directory | High - Filesystem modification |
| `getcwd` | 79 | Get current directory | Low - Information only |
| `chdir` | 80 | Change current directory | Medium - Process state |
| `getdents` | 78 | Get directory entries | Low - Information only |
| `getdents64` | 217 | Get directory entries (64-bit) | Low - Information only |

### Memory Management
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `brk` | 12 | Change heap size | Medium - Memory allocation |
| `mmap` | 9 | Map memory | Medium - Memory allocation |
| `munmap` | 11 | Unmap memory | Low - Memory cleanup |
| `mprotect` | 10 | Change memory protection | High - Memory security |
| `madvise` | 28 | Memory usage advice | Low - Performance hint |
| `mlock` | 149 | Lock memory pages | Medium - Memory control |
| `munlock` | 150 | Unlock memory pages | Medium - Memory control |

### Network Operations
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `socket` | 41 | Create socket | High - Network access |
| `bind` | 49 | Bind socket to address | High - Network server |
| `connect` | 42 | Connect to remote address | High - Network client |
| `listen` | 50 | Listen for connections | High - Network server |
| `accept` | 43 | Accept connection | High - Network server |
| `accept4` | 288 | Accept connection (extended) | High - Network server |
| `sendto` | 44 | Send data | High - Network communication |
| `recvfrom` | 45 | Receive data | High - Network communication |
| `sendmsg` | 46 | Send message | High - Network communication |
| `recvmsg` | 47 | Receive message | High - Network communication |
| `shutdown` | 48 | Shutdown socket | Medium - Network cleanup |
| `setsockopt` | 54 | Set socket options | Medium - Network configuration |
| `getsockopt` | 55 | Get socket options | Low - Information only |
| `getsockname` | 51 | Get socket name | Low - Information only |
| `getpeername` | 52 | Get peer name | Low - Information only |

### Signal Handling
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `rt_sigaction` | 13 | Set signal handler | Medium - Signal control |
| `rt_sigprocmask` | 14 | Change signal mask | Medium - Signal control |
| `rt_sigreturn` | 15 | Return from signal handler | Low - Signal cleanup |
| `rt_sigpending` | 127 | Get pending signals | Low - Information only |
| `rt_sigsuspend` | 130 | Wait for signal | Medium - Process control |
| `kill` | 62 | Send signal to process | High - Process control |
| `tkill` | 200 | Send signal to thread | High - Thread control |
| `tgkill` | 234 | Send signal to thread group | High - Process control |

### Time Operations
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `time` | 201 | Get current time | Low - Information only |
| `gettimeofday` | 96 | Get time of day | Low - Information only |
| `clock_gettime` | 228 | Get clock time | Low - Information only |
| `clock_settime` | 227 | Set clock time | High - System modification |
| `nanosleep` | 35 | Sleep for specified time | Low - Process control |
| `alarm` | 37 | Set alarm | Medium - Timer control |

### System Information
| Syscall | Number (x86_64) | Description | Security Risk |
|---------|-----------------|-------------|---------------|
| `uname` | 63 | Get system information | Low - Information only |
| `getuid` | 102 | Get user ID | Low - Information only |
| `getgid` | 104 | Get group ID | Low - Information only |
| `geteuid` | 107 | Get effective user ID | Low - Information only |
| `getegid` | 108 | Get effective group ID | Low - Information only |
| `setuid` | 105 | Set user ID | Critical - Privilege escalation |
| `setgid` | 106 | Set group ID | Critical - Privilege escalation |
| `seteuid` | 107 | Set effective user ID | Critical - Privilege escalation |
| `setegid` | 108 | Set effective group ID | Critical - Privilege escalation |

### Dangerous System Calls
| Syscall | Number (x86_64) | Description | Why Dangerous |
|---------|-----------------|-------------|---------------|
| `ptrace` | 101 | Process tracing | Can debug/modify other processes |
| `mount` | 165 | Mount filesystem | Can modify filesystem namespace |
| `umount2` | 166 | Unmount filesystem | Can modify filesystem namespace |
| `reboot` | 169 | Restart system | System-wide impact |
| `swapon` | 167 | Enable swap | System resource modification |
| `swapoff` | 168 | Disable swap | System resource modification |
| `ioctl` | 16 | Device I/O control | Direct hardware access |
| `create_module` | 174 | Create kernel module | Kernel code execution |
| `delete_module` | 176 | Delete kernel module | Kernel modification |
| `quotactl` | 179 | Quota control | Filesystem limits |

## Architecture-Specific Considerations

### x86_64
- Uses `AUDIT_ARCH_X86_64` (0xc000003e)
- 64-bit arguments
- Some syscalls differ from 32-bit

### i386
- Uses `AUDIT_ARCH_I386` (0x40000003)
- 32-bit arguments
- Different syscall numbers

### ARM64
- Uses `AUDIT_ARCH_AARCH64` (0xc00000b7)
- 64-bit arguments
- ARM-specific syscalls

## Common Seccomp Patterns

### Essential Syscalls (Minimal Set)
```c
int essential_syscalls[] = {
    __NR_read,
    __NR_write,
    __NR_exit,
    __NR_exit_group,
    __NR_rt_sigreturn
};
```

### Basic Application Set
```c
int basic_syscalls[] = {
    __NR_read, __NR_write, __NR_close,
    __NR_exit, __NR_exit_group,
    __NR_brk, __NR_mmap, __NR_munmap,
    __NR_open, __NR_openat,
    __NR_stat, __NR_fstat, __NR_lstat
};
```

### Network-Enabled Application
```c
int network_syscalls[] = {
    // Basic syscalls...
    __NR_socket, __NR_connect, __NR_bind,
    __NR_listen, __NR_accept, __NR_accept4,
    __NR_sendto, __NR_recvfrom,
    __NR_sendmsg, __NR_recvmsg,
    __NR_shutdown, __NR_setsockopt, __NR_getsockopt
};
```

### Dangerous Syscalls to Always Block
```c
int dangerous_syscalls[] = {
    __NR_execve, __NR_execveat,        // Code execution
    __NR_ptrace,                       // Process debugging
    __NR_mount, __NR_umount2,          // Filesystem mounting
    __NR_reboot,                       // System control
    __NR_setuid, __NR_setgid,          // Privilege escalation
    __NR_create_module, __NR_delete_module, // Kernel modules
    __NR_ioctl                         // Device control (context-dependent)
};
```

## Syscall Dependencies

### Standard Library Functions
| Function | Required Syscalls |
|----------|-------------------|
| `printf()` | `write`, `brk`/`mmap` (for buffering) |
| `malloc()` | `brk`, `mmap`, `munmap` |
| `fopen()` | `open`/`openat`, `stat`/`fstat` |
| `system()` | `fork`, `execve`, `wait4` |
| `gethostbyname()` | `socket`, `connect`, `sendto`, `recvfrom` |

### Complex Operations
- **File copying**: `open`, `read`, `write`, `close`, `stat`, `fstat`
- **Directory listing**: `opendir`, `getdents64`, `close`
- **Process creation**: `fork`/`clone`, `execve`, potentially `wait4`
- **Network communication**: `socket`, `connect`/`bind`, `send`/`recv`, `close`

## Troubleshooting Guide

### Finding Missing Syscalls
Use `strace` to identify syscalls used by your application:
```bash
strace -c ./your_program
strace -e trace=file ./your_program
strace -e trace=network ./your_program
```

### Common Missing Syscalls
- **Memory allocation**: `brk`, `mmap`, `munmap`
- **File operations**: `stat`, `fstat`, `access`
- **Dynamic linking**: `open`, `read`, `close`, `mmap` (for shared libraries)
- **Signal handling**: `rt_sigaction`, `rt_sigprocmask`

### Architecture Validation
Always include architecture validation in filters:
```c
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
```

## References

- [Linux System Call Table](https://filippo.io/linux-syscall-table/)
- [Linux man-pages project](https://man7.org/linux/man-pages/)
- [Seccomp BPF documentation](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
- [Architecture-specific syscall tables](https://github.com/torvalds/linux/tree/master/arch)
