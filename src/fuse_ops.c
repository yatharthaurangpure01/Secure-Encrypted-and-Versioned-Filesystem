/*
 * fuse_ops.c - FUSE operations module implementation for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * This is the core module that implements all filesystem operations.
 * Each function is a callback registered with libfuse. When a user
 * application makes a system call (open, read, write, etc.) on a file
 * in the mounted filesystem, the Linux kernel routes the call through
 * the FUSE kernel module, which then invokes the corresponding callback
 * function here in user space.
 * 
 * Data flow for a READ operation:
 *   1. User calls: cat mountpoint/hello.txt
 *   2. Kernel VFS -> FUSE kernel module -> libfuse -> secfs_read()
 *   3. secfs_read() reads encrypted file from storage/hello.txt
 *   4. Decrypts the data using the encryption module
 *   5. Returns plaintext to the user
 * 
 * Data flow for a WRITE operation:
 *   1. User calls: echo "Hello" > mountpoint/hello.txt
 *   2. Kernel VFS -> FUSE kernel module -> libfuse -> secfs_write()
 *   3. secfs_write() creates a version backup of existing file
 *   4. Encrypts the new data using the encryption module
 *   5. Writes ciphertext to storage/hello.txt
 *   6. Logs the operation
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include "fuse_ops.h"
#include "common.h"
#include "encryption.h"
#include "logging.h"
#include "versioning.h"

/* ============================================================
 * Static FUSE Operations Structure
 * ============================================================ */

static const struct fuse_operations secfs_operations = {
    .getattr    = secfs_getattr,
    .readdir    = secfs_readdir,
    .open       = secfs_open,
    .read       = secfs_read,
    .write      = secfs_write,
    .create     = secfs_create,
    .unlink     = secfs_unlink,
    .rename     = secfs_rename,
    .mkdir      = secfs_mkdir,
    .rmdir      = secfs_rmdir,
    .truncate   = secfs_truncate,
    .utimens    = secfs_utimens,
};

const struct fuse_operations *get_fuse_operations(void)
{
    return &secfs_operations;
}

/* ============================================================
 * FUSE Callback Implementations
 * ============================================================ */

/*
 * secfs_getattr - Get file attributes (equivalent of stat())
 * 
 * This is the most frequently called FUSE operation. The kernel
 * calls it for almost every file operation to check permissions,
 * determine file type, and get file size.
 * 
 * For regular files, we need to report the DECRYPTED file size
 * (not the encrypted size on disk), because user applications
 * expect the reported size to match the data they'll read back.
 * We read the original size from the encrypted file header.
 */
int secfs_getattr(const char *path, struct stat *stbuf,
                  struct fuse_file_info *fi)
{
    (void)fi;  /* Unused parameter */

    memset(stbuf, 0, sizeof(struct stat));

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("getattr: %s -> %s", path, real_path);

    /*
     * Use lstat (not stat) to avoid following symbolic links.
     * This gives us the actual file metadata from the storage directory.
     */
    int res = lstat(real_path, stbuf);
    if (res == -1) {
        return -errno;
    }

    /*
     * For regular files, adjust the reported size to reflect the
     * decrypted (original) size rather than the encrypted size on disk.
     * 
     * The encrypted file format stores the original size in a header:
     * [16-byte IV][4-byte original_size][encrypted_data]
     */
    if (S_ISREG(stbuf->st_mode) && stbuf->st_size > 0) {
        FILE *f = fopen(real_path, "rb");
        if (f) {
            /* Skip past the IV to read the original size */
            unsigned char iv_skip[AES_IV_SIZE];
            uint32_t orig_size;
            if (fread(iv_skip, 1, AES_IV_SIZE, f) == AES_IV_SIZE &&
                fread(&orig_size, sizeof(uint32_t), 1, f) == 1) {
                stbuf->st_size = orig_size;
            }
            fclose(f);
        }
    }

    return 0;
}

/*
 * secfs_readdir - List directory contents
 * 
 * Called when a user runs 'ls' or iterates over directory contents.
 * The filler() function is provided by libfuse to add entries to
 * the directory listing.
 * 
 * Important: We hide the .versions directory from user listings
 * to maintain transparency. Users should not see or interact with
 * version history directly through the filesystem.
 */
int secfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi,
                  enum fuse_readdir_flags flags)
{
    (void)offset;   /* Unused - we always read the full directory */
    (void)fi;       /* Unused */
    (void)flags;    /* Unused */

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("readdir: %s -> %s", path, real_path);

    DIR *dp = opendir(real_path);
    if (!dp) {
        return -errno;
    }

    /*
     * Every directory must contain '.' (self) and '..' (parent).
     * filler() returns 0 on success, 1 if the buffer is full.
     */
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        /* Skip . and .. (we already added them above) */
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        /*
         * Hide the .versions directory from the root listing.
         * This directory is only used internally for version management
         * and should not be visible to users of the mounted filesystem.
         */
        if (strcmp(path, "/") == 0 && strcmp(de->d_name, ".versions") == 0) {
            SECFS_DEBUG("Hiding .versions directory from listing");
            continue;
        }

        /* Add this entry to the directory listing */
        if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
            SECFS_ERROR("filler buffer full while listing %s", path);
            break;
        }
    }

    closedir(dp);
    log_operation("READDIR", path);
    return 0;
}

/*
 * secfs_open - Open a file
 * 
 * Validates that the file exists in storage. We don't need to
 * do anything special here since we read/write files in the
 * read() and write() callbacks.
 */
int secfs_open(const char *path, struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("open: %s -> %s (flags: 0x%x)", path, real_path, fi->flags);

    /* Check if the file exists and is accessible */
    int res = access(real_path, F_OK);
    if (res == -1) {
        return -errno;
    }

    log_operation("OPEN", path);
    return 0;
}

/*
 * secfs_read - Read and decrypt file data
 * 
 * This is where transparent decryption happens:
 * 1. Read the entire encrypted file from storage
 * 2. Decrypt it to get the original plaintext
 * 3. Return the requested portion (offset + size) to the user
 * 
 * The user never sees the encrypted data — they get clean plaintext
 * as if the file were stored normally.
 */
int secfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("read: %s (size: %zu, offset: %ld)", path, size, offset);

    /* Open the encrypted file from storage */
    FILE *f = fopen(real_path, "rb");
    if (!f) {
        return -errno;
    }

    /* Get the encrypted file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(f);
        return 0;  /* Empty file, nothing to read */
    }

    /* Read the entire encrypted file into memory */
    unsigned char *encrypted_data = malloc(file_size);
    if (!encrypted_data) {
        fclose(f);
        return -ENOMEM;
    }

    size_t bytes_read = fread(encrypted_data, 1, file_size, f);
    fclose(f);

    if ((long)bytes_read != file_size) {
        SECFS_ERROR("Failed to read complete file: %s", real_path);
        free(encrypted_data);
        return -EIO;
    }

    /*
     * Decrypt the data.
     * Allocate enough space for the decrypted output.
     * The decrypted data will be at most file_size bytes
     * (actually less due to header and padding).
     */
    unsigned char *decrypted_data = malloc(file_size);
    if (!decrypted_data) {
        free(encrypted_data);
        return -ENOMEM;
    }

    size_t decrypted_len = 0;
    if (decrypt_data(encrypted_data, bytes_read,
                     decrypted_data, &decrypted_len) != 0) {
        SECFS_ERROR("Decryption failed for: %s", real_path);
        free(encrypted_data);
        free(decrypted_data);
        return -EIO;
    }

    free(encrypted_data);

    /*
     * Handle offset and size.
     * The user may request a portion of the file (e.g., reading
     * in chunks or seeking to a specific position).
     */
    int result = 0;
    if ((size_t)offset < decrypted_len) {
        /* Calculate how much data we can actually return */
        size_t available = decrypted_len - offset;
        if (size > available) {
            size = available;
        }
        memcpy(buf, decrypted_data + offset, size);
        result = size;
    }

    free(decrypted_data);
    log_operation("READ", path);
    return result;
}

/*
 * secfs_write - Encrypt and write file data
 * 
 * This is where transparent encryption happens:
 * 1. If the file already exists, create a version backup
 * 2. If writing at an offset, read and decrypt existing content first
 * 3. Merge the new data at the specified offset
 * 4. Encrypt the complete file content
 * 5. Write the encrypted data to storage
 * 
 * The user just writes normal plaintext — encryption is invisible.
 */
int secfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("write: %s (size: %zu, offset: %ld)", path, size, offset);

    /*
     * Step 1: Create a version backup of the existing file
     * 
     * This preserves the previous version before we overwrite.
     * create_version_backup() handles the case where the file
     * doesn't exist yet (returns 1, which we ignore).
     */
    create_version_backup(real_path, path);

    /*
     * Step 2: Read existing content if we're writing at an offset
     * 
     * For writes at offset > 0, we need to preserve the existing
     * content before the offset. This requires:
     *   a. Reading the encrypted file
     *   b. Decrypting it
     *   c. Merging the new data at the offset
     *   d. Re-encrypting the entire file
     */
    unsigned char *existing_data = NULL;
    size_t existing_len = 0;

    struct stat st;
    if (stat(real_path, &st) == 0 && st.st_size > 0) {
        FILE *f = fopen(real_path, "rb");
        if (f) {
            unsigned char *enc_buf = malloc(st.st_size);
            if (enc_buf) {
                size_t enc_read = fread(enc_buf, 1, st.st_size, f);
                if (enc_read > 0) {
                    existing_data = malloc(st.st_size);
                    if (existing_data) {
                        if (decrypt_data(enc_buf, enc_read,
                                        existing_data, &existing_len) != 0) {
                            /* Decryption failed - treat as new file */
                            free(existing_data);
                            existing_data = NULL;
                            existing_len = 0;
                        }
                    }
                }
                free(enc_buf);
            }
            fclose(f);
        }
    }

    /*
     * Step 3: Merge existing data with new data
     * 
     * Calculate the total size needed: max of existing content
     * and the end of the new write (offset + size).
     */
    size_t total_len = existing_len;
    if ((size_t)offset + size > total_len) {
        total_len = (size_t)offset + size;
    }

    unsigned char *merged_data = calloc(1, total_len);
    if (!merged_data) {
        free(existing_data);
        return -ENOMEM;
    }

    /* Copy existing data first (if any) */
    if (existing_data && existing_len > 0) {
        memcpy(merged_data, existing_data, existing_len);
    }
    free(existing_data);

    /* Write new data at the specified offset */
    memcpy(merged_data + offset, buf, size);

    /*
     * Step 4: Encrypt the merged content
     */
    size_t enc_size = get_encrypted_size(total_len);
    unsigned char *encrypted = malloc(enc_size);
    if (!encrypted) {
        free(merged_data);
        return -ENOMEM;
    }

    size_t encrypted_len = 0;
    if (encrypt_data(merged_data, total_len, encrypted, &encrypted_len) != 0) {
        SECFS_ERROR("Encryption failed for: %s", real_path);
        free(merged_data);
        free(encrypted);
        return -EIO;
    }
    free(merged_data);

    /*
     * Step 5: Write encrypted data to storage
     * 
     * We always write the entire file (not just the changed portion)
     * because the entire file needs to be re-encrypted when any
     * part changes (AES-CBC mode chains blocks together).
     */
    FILE *f = fopen(real_path, "wb");
    if (!f) {
        free(encrypted);
        return -errno;
    }

    size_t written = fwrite(encrypted, 1, encrypted_len, f);
    fclose(f);
    free(encrypted);

    if (written != encrypted_len) {
        SECFS_ERROR("Failed to write complete encrypted file: %s", real_path);
        return -EIO;
    }

    log_operation("WRITE", path);

    /* Return the number of bytes the user wanted to write (not crypto size) */
    return size;
}

/*
 * secfs_create - Create a new file
 * 
 * Called when a new file is created. We create the file in storage
 * with the specified permissions.
 */
int secfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("create: %s -> %s (mode: %o)", path, real_path, mode);

    /*
     * Create the file using open() with O_CREAT | O_WRONLY | O_TRUNC.
     * This creates a new file or truncates an existing one.
     */
    int fd = open(real_path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd == -1) {
        return -errno;
    }
    close(fd);

    log_operation("CREATE", path);
    return 0;
}

/*
 * secfs_unlink - Delete a file
 * 
 * Removes the file from storage. Version history in .versions/
 * is preserved (old versions are NOT deleted when the current
 * file is deleted, allowing potential recovery).
 */
int secfs_unlink(const char *path)
{
    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("unlink: %s -> %s", path, real_path);

    int res = unlink(real_path);
    if (res == -1) {
        return -errno;
    }

    log_operation("DELETE", path);
    return 0;
}

/*
 * secfs_rename - Rename or move a file
 * 
 * Maps both source and destination paths to storage and
 * performs the rename operation.
 */
int secfs_rename(const char *from, const char *to, unsigned int flags)
{
    (void)flags;

    char real_from[MAX_PATH_LEN];
    char real_to[MAX_PATH_LEN];

    if (get_real_path(real_from, from, sizeof(real_from)) != 0 ||
        get_real_path(real_to, to, sizeof(real_to)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("rename: %s -> %s", from, to);

    int res = rename(real_from, real_to);
    if (res == -1) {
        return -errno;
    }

    /* Log with both source and destination */
    char log_msg[MAX_PATH_LEN];
    snprintf(log_msg, sizeof(log_msg), "%s -> %s", from, to);
    log_operation("RENAME", log_msg);
    return 0;
}

/*
 * secfs_mkdir - Create a directory
 * 
 * Creates the directory in storage with the specified permissions.
 */
int secfs_mkdir(const char *path, mode_t mode)
{
    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("mkdir: %s -> %s (mode: %o)", path, real_path, mode);

    int res = mkdir(real_path, mode);
    if (res == -1) {
        return -errno;
    }

    log_operation("MKDIR", path);
    return 0;
}

/*
 * secfs_rmdir - Remove a directory
 * 
 * Removes the directory from storage. Only succeeds if the
 * directory is empty (standard POSIX behavior).
 */
int secfs_rmdir(const char *path)
{
    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("rmdir: %s -> %s", path, real_path);

    int res = rmdir(real_path);
    if (res == -1) {
        return -errno;
    }

    log_operation("RMDIR", path);
    return 0;
}

/*
 * secfs_truncate - Truncate a file to a specified length
 * 
 * Called when a file is opened with O_TRUNC or when truncate()
 * is called. Creates a version backup before truncating.
 * 
 * For the encrypted filesystem, truncating to size 0 simply
 * truncates the storage file. Truncating to other sizes requires
 * read-decrypt-truncate-encrypt cycle.
 */
int secfs_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("truncate: %s to %ld bytes", path, size);

    /* Create a version backup before truncating */
    create_version_backup(real_path, path);

    if (size == 0) {
        /*
         * Truncating to zero: just truncate the raw storage file.
         * No encryption needed for an empty file.
         */
        int res = truncate(real_path, 0);
        if (res == -1) {
            return -errno;
        }
    } else {
        /*
         * Truncating to non-zero size: we need to:
         * 1. Read and decrypt existing content
         * 2. Truncate/extend the plaintext
         * 3. Re-encrypt and write back
         */
        struct stat st;
        unsigned char *plaintext = NULL;
        size_t plain_len = 0;

        if (stat(real_path, &st) == 0 && st.st_size > 0) {
            /* Read and decrypt existing file */
            FILE *f = fopen(real_path, "rb");
            if (f) {
                unsigned char *enc_data = malloc(st.st_size);
                if (enc_data) {
                    size_t enc_read = fread(enc_data, 1, st.st_size, f);
                    if (enc_read > 0) {
                        plaintext = malloc(st.st_size);
                        if (plaintext) {
                            if (decrypt_data(enc_data, enc_read,
                                           plaintext, &plain_len) != 0) {
                                free(plaintext);
                                plaintext = NULL;
                                plain_len = 0;
                            }
                        }
                    }
                    free(enc_data);
                }
                fclose(f);
            }
        }

        /* Create the truncated/extended plaintext */
        unsigned char *new_plain = calloc(1, (size_t)size);
        if (!new_plain) {
            free(plaintext);
            return -ENOMEM;
        }

        /* Copy existing data up to the new size */
        if (plaintext && plain_len > 0) {
            size_t copy_len = plain_len < (size_t)size ? plain_len : (size_t)size;
            memcpy(new_plain, plaintext, copy_len);
        }
        free(plaintext);

        /* Encrypt the truncated content */
        size_t enc_size = get_encrypted_size((size_t)size);
        unsigned char *encrypted = malloc(enc_size);
        if (!encrypted) {
            free(new_plain);
            return -ENOMEM;
        }

        size_t encrypted_len = 0;
        if (encrypt_data(new_plain, (size_t)size,
                        encrypted, &encrypted_len) != 0) {
            free(new_plain);
            free(encrypted);
            return -EIO;
        }
        free(new_plain);

        /* Write encrypted data back */
        FILE *f = fopen(real_path, "wb");
        if (!f) {
            free(encrypted);
            return -errno;
        }
        fwrite(encrypted, 1, encrypted_len, f);
        fclose(f);
        free(encrypted);
    }

    log_operation("TRUNCATE", path);
    return 0;
}

/*
 * secfs_utimens - Update file timestamps
 * 
 * Called when file access and modification times are updated.
 * Uses utimensat() to set the timestamps on the storage file.
 */
int secfs_utimens(const char *path, const struct timespec ts[2],
                  struct fuse_file_info *fi)
{
    (void)fi;

    char real_path[MAX_PATH_LEN];
    if (get_real_path(real_path, path, sizeof(real_path)) != 0) {
        return -ENAMETOOLONG;
    }

    SECFS_DEBUG("utimens: %s", path);

    /*
     * utimensat() with AT_FDCWD uses the path relative to the
     * current working directory. The 0 flag means follow symlinks.
     */
    int res = utimensat(AT_FDCWD, real_path, ts, 0);
    if (res == -1) {
        return -errno;
    }

    return 0;
}
