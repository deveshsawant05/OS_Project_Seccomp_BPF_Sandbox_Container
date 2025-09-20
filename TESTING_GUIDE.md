# Testing Guide

## Quick Start

### 1. Build & Enter Container

```powershell
docker-compose up -d
docker exec -it seccomp-sandbox /bin/bash
make all
```

### 2. Test Individual Syscalls (NEW!)

```bash
# Test if a specific syscall is allowed/blocked
./bin/test_syscall <filter> <syscall>
```

**Examples:**
```bash
./bin/test_syscall basic open      # ✗ BLOCKED (killed)
./bin/test_syscall basic write     # ✓ ALLOWED
./bin/test_syscall network socket  # ✗ BLOCKED (ENETDOWN)
./bin/test_syscall file unlink     # ✗ BLOCKED (EPERM)
./bin/test_syscall none socket     # ✓ ALLOWED (no filter)
```

**Available Filters:** `basic`, `file`, `network`, `none`

**Available Syscalls:** `read`, `write`, `open`, `socket`, `fork`, `unlink`, `time`, `execve`

### 3. Run Full Test Suite

```bash
./bin/test_seccomp
```

### 4. Check Syscall Mappings

```bash
cat syscall_filters.json
```

Shows exactly which syscalls are allowed/blocked for each filter.

---

## Run Example Programs

```bash
./bin/basic_seccomp        # Basic filter demo (will crash on blocked syscalls)
./bin/file_operations      # File restrictions demo
./bin/network_sandbox      # Network blocking demo  
./bin/shell_sandbox        # Shell sandbox demo
```

**Expected:** Programs crash or show errors = Filter working! ✓

---

## Understanding Results

| Result | Meaning | Status |
|--------|---------|--------|
| ✓ SUCCESS | Syscall allowed | Good |
| ✗ BLOCKED | Syscall blocked with error | Good - Filter working |
| Process killed | Syscall blocked, process terminated | Good - Filter working |
| "Bad system call" | SECCOMP_RET_KILL triggered | Good - Filter working |
| "Permission denied" | SECCOMP_RET_ERRNO | Good - Filter working |

---

## Why Programs Crash

Seccomp **kills** the process when it tries a blocked syscall. **This is normal behavior!**

```
Installing filter...
Trying blocked syscall...
Bad system call (core dumped)  ← Filter working correctly!
```

---

## Advanced Testing

### Run Specific Test Types

```bash
./bin/test_seccomp basic    # Basic functionality tests
./bin/test_seccomp filters  # Filter tests
./bin/test_seccomp strict   # Strict mode tests
./bin/test_seccomp perf     # Performance tests
```

### Debug with strace

See all syscalls a program makes:

```bash
strace ./bin/basic_seccomp
```

---

## Files

- **`syscall_filters.json`** - Complete list of allowed/blocked syscalls per filter
- **`HOW_TO_TEST.md`** - Detailed testing instructions
- **`./bin/test_syscall`** - NEW! Test individual syscalls

---

## Quick Reference

```bash
# Test individual syscall
./bin/test_syscall basic open

# Run all tests
./bin/test_seccomp

# Check filter config
cat syscall_filters.json

# Debug
strace ./bin/basic_seccomp
```

---

**Simple testing, clear results!** ✓
