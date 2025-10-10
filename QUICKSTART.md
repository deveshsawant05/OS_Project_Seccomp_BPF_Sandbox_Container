# Seccomp Sandbox - Quick Start

## What is This?

A Linux security project using **seccomp** to control what programs can do by filtering system calls.

---

## How to Run (3 Steps)

### 1. Build
```powershell
docker-compose build
```

### 2. Start
```powershell
docker-compose up -d
```

### 3. Enter
```powershell
docker exec -it seccomp-sandbox /bin/bash
```

Inside container, build the project:
```bash
make all
```

---

## Run Examples

```bash
# Basic example
./bin/basic_seccomp

# File operations
./bin/file_operations

# Network sandbox  
./bin/network_sandbox

# Shell sandbox
./bin/shell_sandbox
```

---

## Run Tests

```bash
./bin/test_seccomp
```

---

## Expected Behavior

- **Programs crash** = GOOD! Seccomp blocked dangerous syscalls ✓
- **"Permission denied"** = Filter working ✓
- **"Bad system call"** = Filter working ✓

This is EXPECTED BEHAVIOR!

---

## Stop Container

```bash
exit                    # Exit container
```
```powershell
docker-compose down     # Stop container
```

---

## Complete Documentation

- **`DOCKER_SETUP.md`** - Detailed Docker setup
- **`TESTING_GUIDE.md`** - How to test
- **`docs/seccomp_guide.md`** - Seccomp theory

---

## Quick Reference

| Command | Action |
|---------|--------|
| `docker-compose build` | Build container |
| `docker-compose up -d` | Start container |
| `docker exec -it seccomp-sandbox /bin/bash` | Enter container |
| `make all` | Build programs |
| `./bin/test_seccomp` | Run tests |
| `docker-compose down` | Stop container |

---

## Project Structure

```
src/         - Main programs
examples/    - Example sandboxes
tests/       - Test suite
bin/         - Compiled programs
docs/        - Documentation
```

---

**That's it! Simple 3-step setup.** 🎉
