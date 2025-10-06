# Seccomp Sandbox Filter Project Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -g
INCLUDES = -Iinclude
LIBS = -lrt

# Directories
SRC_DIR = src
EXAMPLES_DIR = examples
TESTS_DIR = tests
BIN_DIR = bin
OBJ_DIR = obj

# Source files
UTILS_SRC = $(SRC_DIR)/seccomp_utils.c
MAIN_SOURCES = $(SRC_DIR)/basic_seccomp.c $(SRC_DIR)/seccomp_filter.c $(SRC_DIR)/sandbox_example.c
EXAMPLE_SOURCES = $(wildcard $(EXAMPLES_DIR)/*.c)
TEST_SOURCES = $(wildcard $(TESTS_DIR)/*.c)

# Object files
UTILS_OBJ = $(OBJ_DIR)/seccomp_utils.o
MAIN_OBJS = $(MAIN_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
EXAMPLE_OBJS = $(EXAMPLE_SOURCES:$(EXAMPLES_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_OBJS = $(TEST_SOURCES:$(TESTS_DIR)/%.c=$(OBJ_DIR)/%.o)

# Executables
MAIN_BINS = $(MAIN_SOURCES:$(SRC_DIR)/%.c=$(BIN_DIR)/%)
EXAMPLE_BINS = $(EXAMPLE_SOURCES:$(EXAMPLES_DIR)/%.c=$(BIN_DIR)/%)
TEST_BINS = $(TEST_SOURCES:$(TESTS_DIR)/%.c=$(BIN_DIR)/%)

# Default target
all: directories $(MAIN_BINS) $(EXAMPLE_BINS) $(TEST_BINS)

# Create directories
directories:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

# Utility object file (shared by all programs)
$(UTILS_OBJ): $(UTILS_SRC) include/seccomp_utils.h | directories
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Main program object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c include/seccomp_utils.h | directories
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Example object files
$(OBJ_DIR)/%.o: $(EXAMPLES_DIR)/%.c include/seccomp_utils.h | directories
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Test object files
$(OBJ_DIR)/%.o: $(TESTS_DIR)/%.c include/seccomp_utils.h | directories
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Main executables
$(BIN_DIR)/%: $(OBJ_DIR)/%.o $(UTILS_OBJ) | directories
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Example executables
$(BIN_DIR)/file_operations: $(OBJ_DIR)/file_operations.o $(UTILS_OBJ) | directories
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(BIN_DIR)/network_sandbox: $(OBJ_DIR)/network_sandbox.o $(UTILS_OBJ) | directories
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(BIN_DIR)/shell_sandbox: $(OBJ_DIR)/shell_sandbox.o $(UTILS_OBJ) | directories
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Test executables
$(BIN_DIR)/test_seccomp: $(OBJ_DIR)/test_seccomp.o $(UTILS_OBJ) | directories
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Individual targets
basic: $(BIN_DIR)/basic_seccomp
filter: $(BIN_DIR)/seccomp_filter
sandbox: $(BIN_DIR)/sandbox_example
examples: $(EXAMPLE_BINS)
tests: $(TEST_BINS)

# Run tests
test: $(BIN_DIR)/test_seccomp
	@echo "Running seccomp tests..."
	@./$(BIN_DIR)/test_seccomp

# Run specific test suites
test-basic: $(BIN_DIR)/test_seccomp
	@./$(BIN_DIR)/test_seccomp basic

test-filters: $(BIN_DIR)/test_seccomp
	@./$(BIN_DIR)/test_seccomp filters

test-strict: $(BIN_DIR)/test_seccomp
	@./$(BIN_DIR)/test_seccomp strict

test-perf: $(BIN_DIR)/test_seccomp
	@./$(BIN_DIR)/test_seccomp perf

# Demonstration targets
demo-basic: $(BIN_DIR)/basic_seccomp
	@echo "=== Basic Seccomp Demo ==="
	@./$(BIN_DIR)/basic_seccomp

demo-strict: $(BIN_DIR)/basic_seccomp
	@echo "=== Strict Seccomp Demo ==="
	@./$(BIN_DIR)/basic_seccomp --strict

demo-readonly: $(BIN_DIR)/seccomp_filter
	@echo "=== Read-Only Filter Demo ==="
	@./$(BIN_DIR)/seccomp_filter --readonly

demo-network: $(BIN_DIR)/seccomp_filter
	@echo "=== Network Sandbox Demo ==="
	@./$(BIN_DIR)/seccomp_filter --network

demo-file-sandbox: $(BIN_DIR)/file_operations
	@echo "=== File Operations Sandbox Demo ==="
	@./$(BIN_DIR)/file_operations tmp

demo-network-isolation: $(BIN_DIR)/network_sandbox
	@echo "=== Network Isolation Demo ==="
	@./$(BIN_DIR)/network_sandbox isolation

demo-shell: $(BIN_DIR)/shell_sandbox
	@echo "=== Shell Sandbox Demo ==="
	@./$(BIN_DIR)/shell_sandbox --test

# Run all demos
demo: demo-basic demo-readonly demo-file-sandbox demo-network-isolation

# Install (copy to /usr/local/bin - requires sudo)
install: all
	@echo "Installing to /usr/local/bin (requires sudo)..."
	sudo cp $(BIN_DIR)/* /usr/local/bin/
	@echo "Installation complete."

# Uninstall
uninstall:
	@echo "Removing from /usr/local/bin (requires sudo)..."
	sudo rm -f /usr/local/bin/basic_seccomp
	sudo rm -f /usr/local/bin/seccomp_filter
	sudo rm -f /usr/local/bin/sandbox_example
	sudo rm -f /usr/local/bin/file_operations
	sudo rm -f /usr/local/bin/network_sandbox
	sudo rm -f /usr/local/bin/shell_sandbox
	sudo rm -f /usr/local/bin/test_seccomp
	@echo "Uninstall complete."

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

# Clean and rebuild
rebuild: clean all

# Check for required tools and libraries
check-deps:
	@echo "Checking dependencies..."
	@which gcc > /dev/null || (echo "ERROR: gcc not found" && exit 1)
	@echo "✓ gcc found"
	@echo "✓ All dependencies satisfied"
	@echo "Note: This project requires Linux kernel 3.5+ for seccomp-bpf support"

# Show help
help:
	@echo "Seccomp Sandbox Filter Project"
	@echo "==============================="
	@echo ""
	@echo "Build targets:"
	@echo "  all        - Build all programs (default)"
	@echo "  basic      - Build basic seccomp example"
	@echo "  filter     - Build advanced filter example"
	@echo "  sandbox    - Build sandbox example"
	@echo "  examples   - Build all examples"
	@echo "  tests      - Build test suite"
	@echo ""
	@echo "Test targets:"
	@echo "  test       - Run all tests"
	@echo "  test-basic - Run basic functionality tests"
	@echo "  test-filters - Run filter creation tests"
	@echo "  test-strict - Run strict seccomp tests"
	@echo "  test-perf  - Run performance tests"
	@echo ""
	@echo "Demo targets:"
	@echo "  demo       - Run all demonstrations"
	@echo "  demo-basic - Basic seccomp demonstration"
	@echo "  demo-strict - Strict mode demonstration"
	@echo "  demo-readonly - Read-only filter demonstration"
	@echo "  demo-network - Network sandbox demonstration"
	@echo "  demo-file-sandbox - File operations sandbox"
	@echo "  demo-network-isolation - Network isolation demo"
	@echo "  demo-shell - Shell sandbox demonstration"
	@echo ""
	@echo "Utility targets:"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  uninstall  - Remove from /usr/local/bin"
	@echo "  clean      - Remove build artifacts"
	@echo "  rebuild    - Clean and rebuild"
	@echo "  check-deps - Check for required dependencies"
	@echo "  help       - Show this help"

# Show project information
info:
	@echo "Seccomp Sandbox Filter Project"
	@echo "==============================="
	@echo "Version: 1.0"
	@echo "Description: Comprehensive seccomp filtering examples and utilities"
	@echo "Author: OS Project"
	@echo ""
	@echo "Programs:"
	@echo "  basic_seccomp    - Basic seccomp functionality demonstration"
	@echo "  seccomp_filter   - Advanced BPF-based filtering examples"
	@echo "  sandbox_example  - Practical sandbox implementations"
	@echo "  file_operations  - File access restriction examples"
	@echo "  network_sandbox  - Network access control examples"
	@echo "  shell_sandbox    - Sandboxed shell environment"
	@echo "  test_seccomp     - Comprehensive test suite"
	@echo ""
	@echo "Build system: GNU Make"
	@echo "Required: Linux kernel 3.5+, GCC"

.PHONY: all directories basic filter sandbox examples tests test demo install uninstall clean rebuild check-deps help info
.PHONY: test-basic test-filters test-strict test-perf
.PHONY: demo-basic demo-strict demo-readonly demo-network demo-file-sandbox demo-network-isolation demo-shell
