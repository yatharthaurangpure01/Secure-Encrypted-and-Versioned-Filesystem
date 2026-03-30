# ============================================================
# Makefile for SecFS - Secure Encrypted and Versioned Filesystem
# ============================================================
#
# Build targets:
#   make          - Build the SecFS filesystem binary
#   make debug    - Build with debug symbols and verbose logging
#   make clean    - Remove compiled binaries
#   make dirs     - Create mountpoint and storage directories
#   make mount    - Build and mount the filesystem (foreground)
#   make umount   - Unmount the filesystem
#   make test     - Run the automated test suite
#   make help     - Show this help message
#
# Dependencies:
#   - gcc (GNU C Compiler)
#   - libfuse3-dev (FUSE 3 development headers)
#   - libssl-dev (OpenSSL development headers)
#   - pkg-config (build configuration tool)
# ============================================================

# Compiler and flags
CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -std=c11 -g
CFLAGS  += $(shell pkg-config fuse3 --cflags)
LDFLAGS  = $(shell pkg-config fuse3 --libs) -lcrypto -lpthread

# Source files (all .c files in src/)
SRC_DIR  = src
SOURCES  = $(SRC_DIR)/main.c \
           $(SRC_DIR)/fuse_ops.c \
           $(SRC_DIR)/encryption.c \
           $(SRC_DIR)/logging.c \
           $(SRC_DIR)/versioning.c

# Output binary
TARGET   = secfs

# Directories
MOUNT_DIR   = mountpoint
STORAGE_DIR = storage
VERSIONS_DIR = $(STORAGE_DIR)/.versions

# ============================================================
# Build Targets
# ============================================================

# Default target: build the filesystem binary
all: $(TARGET)
	@echo ""
	@echo "╔══════════════════════════════════════════════════╗"
	@echo "║  Build successful! Run './secfs -f mountpoint'  ║"
	@echo "╚══════════════════════════════════════════════════╝"

# Link all object files into the final binary
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build with debug logging enabled
debug: CFLAGS += -DDEBUG
debug: $(TARGET)
	@echo "[DEBUG] Built with verbose debug logging enabled"

# ============================================================
# Directory Management
# ============================================================

# Create required directories
dirs:
	@mkdir -p $(MOUNT_DIR)
	@mkdir -p $(STORAGE_DIR)
	@mkdir -p $(VERSIONS_DIR)
	@echo "[✓] Directories created:"
	@echo "    Mount point: $(MOUNT_DIR)/"
	@echo "    Storage:     $(STORAGE_DIR)/"
	@echo "    Versions:    $(VERSIONS_DIR)/"

# ============================================================
# Mount/Unmount Shortcuts
# ============================================================

# Build, create directories, and mount in foreground mode
mount: all dirs
	@echo "[*] Mounting SecFS at $(MOUNT_DIR)/ (foreground mode)..."
	@echo "[*] Press Ctrl+C to unmount and exit"
	@echo ""
	./$(TARGET) -f $(MOUNT_DIR)

# Mount as a background daemon
mount-daemon: all dirs
	@echo "[*] Mounting SecFS at $(MOUNT_DIR)/ (daemon mode)..."
	./$(TARGET) $(MOUNT_DIR)
	@echo "[✓] SecFS mounted. Use 'make umount' to unmount."

# Unmount the filesystem
umount:
	fusermount -u $(MOUNT_DIR) 2>/dev/null || true
	@echo "[✓] Filesystem unmounted"

# ============================================================
# Testing
# ============================================================

# Run the automated test suite
test: all dirs
	@echo "[*] Running test suite..."
	@chmod +x test.sh
	./test.sh

# ============================================================
# Cleanup
# ============================================================

# Remove compiled binary
clean:
	rm -f $(TARGET)
	@echo "[✓] Cleaned build artifacts"

# Full cleanup: remove binary, logs, storage, and mountpoint
distclean: umount clean
	rm -rf $(STORAGE_DIR) $(MOUNT_DIR) logs.txt
	@echo "[✓] Full cleanup complete (storage, logs, mountpoint removed)"

# ============================================================
# Help
# ============================================================

help:
	@echo ""
	@echo "SecFS - Secure Encrypted and Versioned Filesystem"
	@echo "================================================="
	@echo ""
	@echo "Build targets:"
	@echo "  make          - Build the SecFS binary"
	@echo "  make debug    - Build with debug logging"
	@echo "  make clean    - Remove compiled binary"
	@echo "  make distclean- Remove everything (binary, storage, logs)"
	@echo ""
	@echo "Run targets:"
	@echo "  make dirs     - Create required directories"
	@echo "  make mount    - Build and mount (foreground)"
	@echo "  make mount-daemon - Build and mount (background)"
	@echo "  make umount   - Unmount the filesystem"
	@echo "  make test     - Run automated tests"
	@echo ""
	@echo "Prerequisites:"
	@echo "  sudo apt install libfuse3-dev libssl-dev pkg-config gcc"
	@echo ""

.PHONY: all debug clean distclean dirs mount mount-daemon umount test help
