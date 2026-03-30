/*
 * config.h - Configuration constants for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * This header defines all configurable parameters for the filesystem
 * including storage paths, encryption settings, and logging configuration.
 */

#ifndef SECFS_CONFIG_H
#define SECFS_CONFIG_H

/* ============================================================
 * Directory Paths
 * ============================================================ */

/* Base directory where encrypted files are stored on disk */
#define STORAGE_DIR     "./storage"

/* Directory where file versions are stored (hidden from mount) */
#define VERSIONS_DIR    "./storage/.versions"

/* Default mount point directory */
#define MOUNT_DIR       "./mountpoint"

/* Log file path */
#define LOG_FILE        "./logs.txt"

/* ============================================================
 * Encryption Settings (AES-256-CBC via OpenSSL EVP)
 * ============================================================ */

/* Default passphrase for PBKDF2 key derivation (demo only!)
 * In production, this should be supplied by the user at mount time */
#define DEFAULT_PASSPHRASE  "SecFS-Default-Passphrase-2026"

/* Salt for PBKDF2 key derivation (should be random in production) */
#define PBKDF2_SALT         "SecFS-Salt-v1"

/* Number of PBKDF2 iterations (higher = more secure but slower) */
#define PBKDF2_ITERATIONS   10000

/* AES-256 requires a 32-byte (256-bit) key */
#define AES_KEY_SIZE        32

/* AES-CBC uses a 16-byte (128-bit) IV */
#define AES_IV_SIZE         16

/* AES block size in bytes */
#define AES_BLOCK_SIZE      16

/* ============================================================
 * File Format Constants
 * ============================================================
 * 
 * Encrypted file format on disk:
 * [16 bytes IV][4 bytes original_size][encrypted_data...]
 * 
 * - IV: Random initialization vector (unique per file write)
 * - original_size: uint32_t storing the plaintext length
 * - encrypted_data: AES-256-CBC encrypted content with PKCS#7 padding
 */
#define ENCRYPTED_HEADER_SIZE   (AES_IV_SIZE + sizeof(uint32_t))

/* ============================================================
 * Limits
 * ============================================================ */

/* Maximum path length for internal buffers */
#define MAX_PATH_LEN    4096

/* Maximum log message length */
#define MAX_LOG_LEN     1024

/* Maximum number of versions to keep per file (0 = unlimited) */
#define MAX_VERSIONS    0

#endif /* SECFS_CONFIG_H */
