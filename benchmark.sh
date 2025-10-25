#!/bin/bash
# Benchmark script for seccomp filter performance

echo "==================================="
echo "Seccomp Filter Performance Benchmark"
echo "==================================="
echo ""

cd / || exit

# Rebuild to ensure latest version
echo "Building project..."
make clean > /dev/null 2>&1
make all > /dev/null 2>&1
echo "Build complete."
echo ""

# Test 1: Basic execution time
echo "Test 1: Basic execution timing (10 runs)"
echo "----------------------------------------"
total=0
for i in {1..10}; do
    result=$( { time ./bin/seccomp_filter --readonly 2>&1; } 2>&1 | grep real | awk '{print $2}' )
    echo "Run $i: $result"
done
echo ""

# Test 2: Compare with and without seccomp (if possible)
echo "Test 2: Syscall performance comparison"
echo "----------------------------------------"
echo "With seccomp filter:"
time ./bin/test_syscall 2>&1
echo ""

# Test 3: Different sandbox modes
echo "Test 3: Different sandbox modes"
echo "----------------------------------------"
echo "Read-only mode:"
time ./bin/seccomp_filter --readonly 2>&1
echo ""
echo "Network blocking mode:"
time ./bin/seccomp_filter --network 2>&1
echo ""

# Test 4: Check if perf is available
if command -v perf &> /dev/null; then
    echo "Test 4: Detailed performance analysis with perf"
    echo "------------------------------------------------"
    perf stat -e cycles,instructions,cache-references,cache-misses ./bin/seccomp_filter --readonly 2>&1
    echo ""
fi

echo "==================================="
echo "Benchmark Complete"
echo "==================================="
