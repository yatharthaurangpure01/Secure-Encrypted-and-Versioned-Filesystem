# SecFS — Secure Encrypted and Versioned Filesystem

A custom FUSE-based filesystem written in C that provides **transparent AES-256-CBC encryption**, **automatic file versioning**, and **comprehensive operation logging**. Built with `libfuse3` and `OpenSSL` for Linux.

> **Suitable for a Final Year Systems Programming Project**

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
  - [How FUSE Works](#how-fuse-works)
  - [Module Architecture](#module-architecture)
  - [Encrypted File Format](#encrypted-file-format)
  - [Data Flow](#data-flow)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Usage](#usage)
  - [Mounting the Filesystem](#mounting-the-filesystem)
  - [Using the Filesystem](#using-the-filesystem)
  - [Unmounting](#unmounting)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Module Details](#module-details)
  - [Encryption Module](#encryption-module)
  - [Logging Module](#logging-module)
  - [Versioning Module](#versioning-module)
  - [FUSE Operations Module](#fuse-operations-module)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| **Transparent Encryption** | AES-256-CBC encryption using OpenSSL. Files are automatically encrypted on write and decrypted on read — invisible to the user. |
| **PBKDF2 Key Derivation** | Encryption key is derived from a passphrase using PBKDF2-HMAC-SHA256 with 10,000 iterations. |
| **Random IV Per File** | Each file write generates a unique random IV, ensuring identical files produce different ciphertext. |
| **Automatic Versioning** | When a file is modified, the previous version is automatically saved as `filename.v1`, `filename.v2`, etc. |
| **Operation Logging** | Every operation (read, write, create, delete, rename) is logged with a timestamp to `logs.txt`. |
| **Thread-Safe** | All shared resources (log file, encryption) are protected by mutexes for FUSE's multi-threaded mode. |
| **Multi-Directory Support** | Full support for creating, listing, and removing subdirectories. |
| **Hidden Versions** | The `.versions` directory is hidden from the mounted filesystem view. |
| **Modular Design** | Clean separation into encryption, logging, versioning, and FUSE operation modules. |

---

## Architecture

### How FUSE Works

FUSE (Filesystem in Userspace) allows implementing filesystems as user-space programs rather than kernel modules. This is safer, easier to develop, and doesn't require kernel recompilation.

```
┌──────────────────────────────────────────────────────────┐
│                    USER SPACE                            │
│                                                          │
│  ┌─────────────┐    System     ┌──────────────────────┐  │
│  │ User App    │    Calls      │ SecFS Daemon         │  │
│  │ (ls, cat,   │───────┐      │ (this program)       │  │
│  │  echo, rm)  │       │      │                      │  │
│  └─────────────┘       │      │  ┌────────────────┐  │  │
│                        │      │  │ Encryption     │  │  │
│                        │      │  │ (AES-256-CBC)  │  │  │
│                        │      │  ├────────────────┤  │  │
│                        │      │  │ Versioning     │  │  │
│                        │      │  │ (.versions/)   │  │  │
│                        │      │  ├────────────────┤  │  │
│                        │      │  │ Logging        │  │  │
│                        │      │  │ (logs.txt)     │  │  │
│                        │      │  └────────┬───────┘  │  │
│                        │      │           │          │  │
│                        │      │     ┌─────▼─────┐   │  │
│                        │      │     │ libfuse3  │   │  │
│                        │      │     └─────┬─────┘   │  │
│                        │      └───────────┼──────────┘  │
│                        │                  │              │
│ ═══════════════════════╪══════════════════╪══════════════│
│                        │     /dev/fuse    │              │
│                    KERNEL SPACE           │              │
│                        │                  │              │
│                  ┌─────▼──────┐    ┌──────▼─────┐       │
│                  │ Linux VFS  │    │ FUSE Kernel │       │
│                  │ (Virtual   │───▶│ Module      │       │
│                  │ File       │    │ (fuse.ko)   │       │
│                  │ Switch)    │    └─────────────┘       │
│                  └────────────┘                          │
└──────────────────────────────────────────────────────────┘
```

**Flow of a `cat mountpoint/hello.txt` command:**

1. `cat` calls `read()` system call
2. Linux VFS checks: "which filesystem handles `/mountpoint`?" → FUSE
3. FUSE kernel module serializes the request and sends it to `/dev/fuse`
4. `libfuse` in our daemon receives the request and calls `secfs_read()`
5. `secfs_read()`:
   - Reads encrypted data from `storage/hello.txt`
   - Calls `decrypt_data()` to get the plaintext
   - Logs the READ operation to `logs.txt`
   - Returns plaintext to the user
6. Response flows back: `secfs_read` → `libfuse` → FUSE kernel → VFS → `cat`

### Module Architecture

```
┌─────────────────────────────────────────────────┐
│                    main.c                        │
│            (Entry point, initialization)         │
│                       │                          │
│              ┌────────▼────────┐                 │
│              │   fuse_ops.c    │                 │
│              │ (FUSE callbacks)│                 │
│              └──┬─────┬─────┬─┘                 │
│                 │     │     │                    │
│    ┌────────────▼┐  ┌▼─────▼────────┐           │
│    │encryption.c │  │ versioning.c  │           │
│    │(AES-256-CBC)│  │ (.versions/)  │           │
│    └─────────────┘  └──────────────┘            │
│                 │                                │
│         ┌───────▼───────┐                        │
│         │  logging.c    │                        │
│         │ (logs.txt)    │                        │
│         └───────────────┘                        │
│                                                  │
│  ┌──────────┐  ┌──────────┐                      │
│  │ config.h │  │ common.h │  (Shared headers)    │
│  └──────────┘  └──────────┘                      │
└─────────────────────────────────────────────────┘
```

### Encrypted File Format

Each file stored in `storage/` uses this binary format:

```
┌────────────────┬─────────────────┬──────────────────────────┐
│ IV (16 bytes)  │ Size (4 bytes)  │ AES-256-CBC Ciphertext   │
│ Random per     │ Original file   │ PKCS#7 padded            │
│ write          │ size (uint32)   │                          │
└────────────────┴─────────────────┴──────────────────────────┘
```

- **IV**: A cryptographically random 16-byte Initialization Vector, unique for each write
- **Size**: The original plaintext size as a `uint32_t` (so we know exact decrypted length)
- **Ciphertext**: The AES-256-CBC encrypted data with PKCS#7 padding

### Data Flow

#### Write Operation
```
User data (plaintext)
    │
    ▼
┌─────────────────────┐
│ Create version       │  → storage/.versions/file.txt.v1
│ backup (if exists)   │
└─────────┬───────────┘
          │
    ┌─────▼───────────┐
    │ Generate random  │
    │ IV (16 bytes)    │
    └─────┬───────────┘
          │
    ┌─────▼───────────┐
    │ AES-256-CBC      │
    │ Encrypt          │  Key = PBKDF2(passphrase)
    └─────┬───────────┘
          │
    ┌─────▼───────────┐
    │ Write to storage │  → storage/file.txt
    │ [IV][size][data] │
    └─────┬───────────┘
          │
    ┌─────▼───────────┐
    │ Log operation    │  → logs.txt
    └─────────────────┘
```

#### Read Operation
```
storage/file.txt
    │
    ▼
┌─────────────────────┐
│ Read encrypted file  │  [IV][size][ciphertext]
└─────────┬───────────┘
          │
    ┌─────▼───────────┐
    │ Extract IV and   │
    │ original size    │
    └─────┬───────────┘
          │
    ┌─────▼───────────┐
    │ AES-256-CBC      │
    │ Decrypt          │  Key = PBKDF2(passphrase)
    └─────┬───────────┘
          │
    ┌─────▼───────────┐
    │ Log operation    │  → logs.txt
    └─────┬───────────┘
          │
          ▼
    Plaintext returned to user
```

---

## Prerequisites

Install the required packages on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install gcc make pkg-config libfuse3-dev libssl-dev fuse3
```

Verify FUSE is available:

```bash
pkg-config --modversion fuse3    # Should show 3.x.x
ls /dev/fuse                      # Should exist
```

---

## Building

### Standard Build
```bash
make
```

### Debug Build (verbose logging to stderr)
```bash
make debug
```

### Clean Build Artifacts
```bash
make clean
```

---

## Usage

### Mounting the Filesystem

**Foreground mode** (recommended for development/debugging):
```bash
# Create directories and mount
make mount

# Or manually:
mkdir -p mountpoint storage storage/.versions
./secfs -f mountpoint
```

**Background (daemon) mode**:
```bash
make mount-daemon

# Or manually:
./secfs mountpoint
```

### Using the Filesystem

Once mounted, use the filesystem like any normal directory:

```bash
# Create a file
echo "Hello, SecFS!" > mountpoint/hello.txt

# Read a file (automatically decrypted)
cat mountpoint/hello.txt
# Output: Hello, SecFS!

# Verify encryption (raw storage is encrypted)
xxd storage/hello.txt | head
# Output: Binary/encrypted data

# Modify a file (creates a version backup)
echo "Updated content" > mountpoint/hello.txt

# Check version history
ls storage/.versions/
# Output: hello.txt.v1

# Create directories
mkdir mountpoint/documents
echo "Report content" > mountpoint/documents/report.txt

# List files
ls -la mountpoint/

# Rename a file
mv mountpoint/hello.txt mountpoint/greeting.txt

# Delete a file
rm mountpoint/greeting.txt

# View operation log
cat logs.txt
```

### Unmounting

```bash
make umount

# Or manually:
fusermount -u mountpoint
```

---

## Testing

Run the automated test suite:

```bash
make test
```

The test suite verifies:
1. ✅ File creation and writing
2. ✅ File reading with transparent decryption
3. ✅ Encryption verification (raw storage check)
4. ✅ Automatic versioning on file modification
5. ✅ Reading modified file content
6. ✅ Multiple file creation
7. ✅ Subdirectory operations
8. ✅ File rename operations
9. ✅ File deletion
10. ✅ `.versions` directory hidden from mount
11. ✅ Operation logging with timestamps
12. ✅ Large file encryption/decryption

---

## Project Structure

```
FUSE-based filesystem/
├── src/
│   ├── main.c              # Entry point, subsystem initialization
│   ├── fuse_ops.c           # FUSE callback implementations (12 operations)
│   ├── fuse_ops.h           # FUSE operations header
│   ├── encryption.c         # AES-256-CBC encryption with PBKDF2
│   ├── encryption.h         # Encryption function declarations
│   ├── logging.c            # Thread-safe timestamped logging
│   ├── logging.h            # Logging function declarations
│   ├── versioning.c         # Automatic file version management
│   ├── versioning.h         # Versioning function declarations
│   ├── common.h             # Shared includes, macros, utilities
│   └── config.h             # Configuration constants
├── Makefile                 # Build system with multiple targets
├── test.sh                  # Automated test suite (12 tests)
├── README.md                # This documentation
├── mountpoint/              # FUSE mount directory (created at runtime)
├── storage/                 # Encrypted file storage (created at runtime)
│   └── .versions/           # Version history (hidden from mount)
└── logs.txt                 # Operation log (created at runtime)
```

---

## Module Details

### Encryption Module (`encryption.c`)

| Function | Description |
|----------|-------------|
| `encryption_init(passphrase)` | Derives AES-256 key from passphrase using PBKDF2-HMAC-SHA256 |
| `encryption_cleanup()` | Securely zeros key material from memory |
| `encrypt_data(in, in_len, out, out_len)` | Encrypts data with random IV, outputs `[IV][size][ciphertext]` |
| `decrypt_data(in, in_len, out, out_len)` | Decrypts data by reading IV from header |
| `get_encrypted_size(plain_len)` | Calculates output buffer size needed for encryption |

**Key derivation**: `PBKDF2(passphrase, salt, 10000, HMAC-SHA256) → 256-bit key`

### Logging Module (`logging.c`)

| Function | Description |
|----------|-------------|
| `logging_init()` | Opens log file, initializes mutex |
| `logging_cleanup()` | Closes log file, destroys mutex |
| `log_operation(op, path)` | Thread-safe timestamped log entry |

**Log format**: `[2026-03-30 11:42:12] WRITE      /documents/report.txt`

### Versioning Module (`versioning.c`)

| Function | Description |
|----------|-------------|
| `versioning_init()` | Creates `.versions` directory |
| `create_version_backup(real_path, virt_path)` | Copies current file to `.versions/file.txt.vN` |
| `get_next_version_number(basename)` | Scans `.versions/` for highest existing version |

**Path flattening**: `storage/docs/report.txt` → `.versions/docs__report.txt.v1`

### FUSE Operations Module (`fuse_ops.c`)

| Operation | POSIX Equivalent | Description |
|-----------|-----------------|-------------|
| `secfs_getattr` | `stat()` | Get file attributes (reports decrypted size) |
| `secfs_readdir` | `readdir()` | List directory (hides `.versions`) |
| `secfs_open` | `open()` | Validate file exists |
| `secfs_read` | `read()` | Read + decrypt file data |
| `secfs_write` | `write()` | Version + encrypt + write file data |
| `secfs_create` | `creat()` | Create new file |
| `secfs_unlink` | `unlink()` | Delete file (versions preserved) |
| `secfs_rename` | `rename()` | Rename/move file |
| `secfs_mkdir` | `mkdir()` | Create directory |
| `secfs_rmdir` | `rmdir()` | Remove directory |
| `secfs_truncate` | `truncate()` | Truncate file (with versioning) |
| `secfs_utimens` | `utimensat()` | Update timestamps |

---

## Security Considerations

| Aspect | Implementation | Production Recommendation |
|--------|---------------|--------------------------|
| **Key Derivation** | PBKDF2-HMAC-SHA256, 10K iterations | Use 100K+ iterations, Argon2id preferred |
| **Key Storage** | Derived at runtime, zeroed on exit | Use hardware security module (HSM) |
| **IV Generation** | `RAND_bytes()` per write (CSPRNG) | ✅ Already strong |
| **Passphrase** | Default hardcoded in `config.h` | User-supplied at mount time |
| **Salt** | Static in `config.h` | Random per-filesystem, stored in metadata |
| **Padding** | PKCS#7 via OpenSSL EVP | ✅ Standard and correct |
| **Integrity** | None (CBC mode) | Add HMAC or use AES-GCM for AEAD |
| **Memory** | Key in process memory | Use `mlock()` to prevent swapping |

---

## License

This project is developed as an academic/educational project.
Free to use and modify for educational purposes.

---

*Built with ❤️ using FUSE3 + OpenSSL on Linux*
