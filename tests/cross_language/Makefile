# Makefile for C FFI tests
# Builds cachekit-core Rust library and links C test harness

# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LIB_EXT = so
    LIB_PREFIX = lib
    RPATH_FLAG = -Wl,-rpath,../../target/release
endif
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
    LIB_PREFIX = lib
    RPATH_FLAG = -Wl,-rpath,@loader_path/../../target/release
endif

# Paths
REPO_ROOT = ../..
TARGET_DIR = $(REPO_ROOT)/target/release
LIB_NAME = $(LIB_PREFIX)cachekit_core.$(LIB_EXT)
LIB_PATH = $(TARGET_DIR)/$(LIB_NAME)
INCLUDE_DIR = $(REPO_ROOT)/include

# Compiler settings
CC = cc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -I$(INCLUDE_DIR)
LDFLAGS = -L$(TARGET_DIR) -lcachekit_core $(RPATH_FLAG)

# Targets
TEST_BIN = test_c

.PHONY: all build-lib test clean help

all: test

help:
	@echo "CacheKit C FFI Test Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make test        - Build library, compile tests, and run (default)"
	@echo "  make build-lib   - Build cachekit-core Rust library with FFI"
	@echo "  make clean       - Remove compiled test binary"
	@echo ""
	@echo "Platform: $(UNAME_S)"
	@echo "Library: $(LIB_NAME)"

build-lib:
	@echo "Building cachekit-core with FFI and encryption features..."
	cd $(REPO_ROOT) && cargo build --release --features ffi,encryption
	@echo "Built: $(LIB_PATH)"

$(TEST_BIN): build-lib test_c.c
	@echo "Compiling C test harness..."
	$(CC) $(CFLAGS) -o $(TEST_BIN) test_c.c $(LDFLAGS)
	@echo "Compiled: $(TEST_BIN)"

test: $(TEST_BIN)
	@echo ""
	@echo "Running C FFI tests..."
	@echo ""
	./$(TEST_BIN)

clean:
	rm -f $(TEST_BIN)
	@echo "Cleaned test binary"
