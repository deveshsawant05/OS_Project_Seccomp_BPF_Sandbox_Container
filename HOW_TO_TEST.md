# How to Test Syscalls

## Quick Testing Guide

### 1. Build Everything

```bash
docker-compose up -d
docker exec -it seccomp-sandbox /bin/bash
make all
```

### 2. Test Individual Syscalls

Use the new `test_syscall` program:

```bash
./bin/test_syscall <filter> <syscall>
```

**Examples:**

```bash
# Test if 'open' is allowed with basic filter
./bin/test_syscall basic open
# Result: ✗ OPEN: BLOCKED (process killed)

# Test if 'write' is allowed with basic filter
./bin/test_syscall basic write
# Result: ✓ WRITE: SUCCESS

# Test if 'socket' is blocked with network filter
./bin/test_syscall network socket
# Result: ✗ SOCKET: BLOCKED - Network is down

# Test without any filter
./bin/test_syscall none open
# Result: ✓ OPEN: SUCCESS
```

### 3. Available Filters

- **`basic`** - Minimal syscalls (read, write, exit, memory ops)
- **`file`** - File operations allowed, dangerous ones blocked
- **`network`** - All network syscalls blocked
- **`none`** - No filter (all syscalls allowed)

### 4. Available Syscall Tests

- `read` - Read from file descriptor
- `write` - Write to file descriptor
- `open` - Open file
- `socket` - Create network socket
- `fork` - Fork process
- `unlink` - Delete file
- `time` - Get current time
- `execve` - Execute program

### 5. Understanding Results

| Symbol | Meaning | What Happened |
|--------|---------|---------------|
| ✓ SUCCESS | Syscall allowed | Filter permits this syscall |
| ✗ BLOCKED | Syscall blocked | Filter returned error (EPERM/ENETDOWN) |
| (crash) | Process killed | Filter killed process (SECCOMP_RET_KILL) |

### 6. See All Allowed/Blocked Syscalls

Check the JSON file:

```bash
cat syscall_filters.json
```

This shows exactly which syscalls are allowed/blocked for each filter.

## Quick Examples

```bash
# Test basic filter - should block 'open'
./bin/test_syscall basic open

# Test basic filter - should allow 'write'  
./bin/test_syscall basic write

# Test network filter - should block 'socket'
./bin/test_syscall network socket

# Test file filter - should allow 'open'
./bin/test_syscall file open

# Test file filter - should block 'unlink'
./bin/test_syscall file unlink
```

## Run Full Test Suite

```bash
./bin/test_seccomp
```

This runs all comprehensive tests.

## Manual Testing

You can also manually test by running the example programs:

```bash
# Will crash when trying blocked syscalls
./bin/basic_seccomp

# Shows file operations being blocked
./bin/file_operations

# Shows network operations being blocked
./bin/network_sandbox
```

## Test Results Explained

**If program crashes with "Bad system call":**
- ✓ This is GOOD! The filter is working correctly.
- The syscall was blocked and process was killed.

**If you see an error message like "Permission denied":**
- ✓ This is GOOD! The filter returned an error instead of killing.
- The syscall was blocked gracefully.

**If the operation succeeds:**
- ✓ The syscall is allowed by the filter.
