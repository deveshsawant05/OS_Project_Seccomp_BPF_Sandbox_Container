# Docker Setup Guide

## Prerequisites

- Docker Desktop installed on Windows
- WSL2 enabled (for Docker Desktop)

## Setup Steps

### 1. Build the Docker Container

Open PowerShell in the project directory and run:

```powershell
docker-compose build
```

### 2. Start the Container

```powershell
docker-compose up -d
```

### 3. Enter the Container

```powershell
docker exec -it seccomp-sandbox /bin/bash
```

Now you're inside the container and can run the programs!

## Running the Examples

Inside the container, run any of these:

```bash
# Basic seccomp demo
./bin/basic_seccomp

# Advanced filter demo
./bin/seccomp_filter

# Sandbox example
./bin/sandbox_example

# File operations example
./bin/file_operations

# Network sandbox example
./bin/network_sandbox

# Shell sandbox example
./bin/shell_sandbox
```

## Testing

### Run All Tests

```bash
./bin/test_seccomp
```

### Run Specific Tests

```bash
# Test basic functionality
./bin/test_seccomp basic

# Test filters
./bin/test_seccomp filters

# Test strict mode
./bin/test_seccomp strict

# Performance tests
./bin/test_seccomp perf
```

## Stop the Container

Exit the container (type `exit`) and then:

```powershell
docker-compose down
```

## Rebuild After Changes

If you modify the code:

```powershell
docker-compose down
docker-compose build
docker-compose up -d
```

## Quick Commands Reference

```powershell
# Build
docker-compose build

# Start container
docker-compose up -d

# Enter container
docker exec -it seccomp-sandbox /bin/bash

# Stop container
docker-compose down

# View logs
docker-compose logs

# Rebuild everything
docker-compose down; docker-compose build; docker-compose up -d
```

## Troubleshooting

**Container won't start?**
- Make sure Docker Desktop is running
- Check if port is already in use

**Programs crash immediately?**
- This is expected! Seccomp kills the process when blocked syscalls are used
- Check the output messages to see which syscalls were blocked

**Build fails?**
- Make sure all source files are present
- Try: `docker-compose build --no-cache`
