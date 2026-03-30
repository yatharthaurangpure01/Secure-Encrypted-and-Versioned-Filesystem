/*
 * main.c - Entry point for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * This is the main entry point for the SecFS filesystem daemon.
 * It initializes all subsystems (encryption, logging, versioning),
 * creates the necessary directories, and starts the FUSE event loop.
 * 
 * Usage:
 *   ./secfs [FUSE options] <mountpoint>
 *   ./secfs -f mountpoint          # Run in foreground (for debugging)
 *   ./secfs mountpoint             # Run as daemon (background)
 *   ./secfs -o allow_other mountpoint  # Allow other users to access
 * 
 * The filesystem mounts at the specified mountpoint and stores
 * encrypted files in the ./storage directory.
 * 
 * Architecture:
 * 
 *   ┌──────────────────┐
 *   │   User Programs   │  (ls, cat, echo, cp, mv, rm, etc.)
 *   │   (user space)    │
 *   └────────┬─────────┘
 *            │ system calls (open, read, write, stat, ...)
 *   ┌────────▼─────────┐
 *   │   Linux VFS       │  Virtual Filesystem Switch
 *   │   (kernel space)  │  Routes calls to the right filesystem
 *   └────────┬─────────┘
 *            │
 *   ┌────────▼─────────┐
 *   │   FUSE Kernel     │  FUSE kernel module (fuse.ko)
 *   │   Module          │  Forwards requests to user space via /dev/fuse
 *   │   (kernel space)  │
 *   └────────┬─────────┘
 *            │ /dev/fuse device
 *   ┌────────▼─────────┐
 *   │   libfuse         │  User-space FUSE library
 *   │   (user space)    │  Deserializes requests, calls our callbacks
 *   └────────┬─────────┘
 *            │ function calls
 *   ┌────────▼─────────┐
 *   │   SecFS           │  Our filesystem implementation
 *   │   (this program)  │  Encryption + Versioning + Logging
 *   └────────┬─────────┘
 *            │ regular file I/O
 *   ┌────────▼─────────┐
 *   │   ./storage/      │  Real files on disk (encrypted)
 *   │   (ext4, etc.)    │
 *   └──────────────────┘
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include "common.h"
#include "fuse_ops.h"
#include "encryption.h"
#include "logging.h"
#include "versioning.h"

/*
 * initialize_subsystems - Start all SecFS modules
 * 
 * Initializes encryption (with PBKDF2 key derivation), logging,
 * and versioning subsystems. Creates necessary directories.
 * 
 * Returns:
 *   0 on success, -1 on error
 */
static int initialize_subsystems(void)
{
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║          SecFS - Secure Encrypted Filesystem        ║\n");
    printf("║     Encrypted • Versioned • Logged • FUSE-based     ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    /* Step 1: Create required directories */
    printf("[*] Creating directories...\n");
    if (ensure_directory_exists(STORAGE_DIR) != 0) {
        fprintf(stderr, "ERROR: Failed to create storage directory\n");
        return -1;
    }
    if (ensure_directory_exists(VERSIONS_DIR) != 0) {
        fprintf(stderr, "ERROR: Failed to create versions directory\n");
        return -1;
    }
    printf("    ✓ Storage directory: %s\n", STORAGE_DIR);
    printf("    ✓ Versions directory: %s\n", VERSIONS_DIR);

    /* Step 2: Initialize encryption with PBKDF2 key derivation */
    printf("[*] Initializing encryption (AES-256-CBC + PBKDF2)...\n");
    if (encryption_init(DEFAULT_PASSPHRASE) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize encryption\n");
        return -1;
    }
    printf("    ✓ Key derived from passphrase using PBKDF2-HMAC-SHA256\n");
    printf("    ✓ Iterations: %d\n", PBKDF2_ITERATIONS);

    /* Step 3: Initialize logging */
    printf("[*] Initializing logging...\n");
    if (logging_init() != 0) {
        fprintf(stderr, "ERROR: Failed to initialize logging\n");
        encryption_cleanup();
        return -1;
    }
    printf("    ✓ Log file: %s\n", LOG_FILE);

    /* Step 4: Initialize versioning */
    printf("[*] Initializing versioning...\n");
    if (versioning_init() != 0) {
        fprintf(stderr, "ERROR: Failed to initialize versioning\n");
        logging_cleanup();
        encryption_cleanup();
        return -1;
    }
    printf("    ✓ Automatic file versioning enabled\n");

    printf("\n[✓] All subsystems initialized successfully!\n");
    printf("[*] Mounting filesystem...\n\n");

    return 0;
}

/*
 * cleanup_subsystems - Shut down all SecFS modules
 * 
 * Called when the filesystem is unmounted.
 * Cleans up resources in reverse initialization order.
 */
static void cleanup_subsystems(void)
{
    printf("\n[*] Shutting down SecFS...\n");
    logging_cleanup();
    encryption_cleanup();
    printf("[✓] Cleanup complete.\n");
}

/*
 * main - Entry point
 * 
 * Parses command-line arguments and starts the FUSE filesystem.
 * 
 * FUSE handles most command-line parsing internally. We just
 * need to initialize our subsystems and pass the operations
 * structure to fuse_main().
 * 
 * fuse_main() enters the FUSE event loop and does not return
 * until the filesystem is unmounted (via fusermount -u or umount).
 */
int main(int argc, char *argv[])
{
    /* Initialize all subsystems before starting FUSE */
    if (initialize_subsystems() != 0) {
        fprintf(stderr, "Failed to initialize SecFS subsystems\n");
        return 1;
    }

    /*
     * Start the FUSE filesystem.
     * 
     * fuse_main() does the following:
     * 1. Parses FUSE-specific command-line options (-f, -d, -o, etc.)
     * 2. Mounts the filesystem at the specified mountpoint
     * 3. Enters the event loop (blocking)
     * 4. When unmounted, returns the exit status
     * 
     * The last parameter (NULL) is for private data that would be
     * accessible via fuse_get_context()->private_data in our callbacks.
     */
    int ret = fuse_main(argc, argv, get_fuse_operations(), NULL);

    /* Clean up when the filesystem is unmounted */
    cleanup_subsystems();

    return ret;
}
