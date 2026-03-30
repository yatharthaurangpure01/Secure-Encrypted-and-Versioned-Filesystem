/*
 * versioning.c - Versioning module implementation for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Implements automatic file versioning. When a file is about to be
 * modified (write or truncate), the current version is copied to
 * the .versions directory with an incrementing version suffix.
 * 
 * Version files are stored as encrypted data (they are direct copies
 * of the encrypted storage file), so they can only be decrypted
 * through the filesystem.
 * 
 * Directory structure example:
 *   storage/
 *   ├── hello.txt              (current version, encrypted)
 *   ├── docs/
 *   │   └── report.txt         (current version, encrypted)
 *   └── .versions/
 *       ├── hello.txt.v1       (first previous version)
 *       ├── hello.txt.v2       (second previous version)
 *       └── docs__report.txt.v1 (subdirectory file version)
 */

#include "versioning.h"
#include "common.h"
#include "logging.h"

/* ============================================================
 * Public API Implementation
 * ============================================================ */

int versioning_init(void)
{
    /* Create the .versions directory inside storage */
    if (ensure_directory_exists(VERSIONS_DIR) != 0) {
        SECFS_ERROR("Failed to create versions directory: %s", VERSIONS_DIR);
        return -1;
    }

    SECFS_DEBUG("Versioning initialized, versions stored in '%s'", VERSIONS_DIR);
    return 0;
}

int get_next_version_number(const char *basename)
{
    DIR *dir;
    struct dirent *entry;
    int max_version = 0;

    dir = opendir(VERSIONS_DIR);
    if (!dir) {
        SECFS_DEBUG("Cannot open versions directory, starting at v1");
        return 1;
    }

    /*
     * Scan all files in .versions/ to find the highest existing
     * version number for this basename.
     * 
     * We look for files matching the pattern: basename.vN
     * and track the maximum N found.
     */
    size_t basename_len = strlen(basename);
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.' && 
            (entry->d_name[1] == '\0' || 
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        /*
         * Check if this entry starts with our basename followed by ".v"
         * Example: for basename "hello.txt", match "hello.txt.v1", "hello.txt.v2"
         */
        if (strncmp(entry->d_name, basename, basename_len) == 0 &&
            entry->d_name[basename_len] == '.' &&
            entry->d_name[basename_len + 1] == 'v') {
            
            /* Extract version number */
            int version = atoi(entry->d_name + basename_len + 2);
            if (version > max_version) {
                max_version = version;
            }
        }
    }

    closedir(dir);

    /* Return next available version number */
    return max_version + 1;
}

int create_version_backup(const char *real_path, const char *virt_path)
{
    struct stat st;

    /*
     * Check if the source file exists.
     * If it doesn't exist, there's nothing to back up (this is a new file).
     */
    if (stat(real_path, &st) == -1) {
        SECFS_DEBUG("No existing file to version: %s", real_path);
        return 1;  /* Not an error, just nothing to backup */
    }

    /* Don't version empty files or directories */
    if (st.st_size == 0 || S_ISDIR(st.st_mode)) {
        SECFS_DEBUG("Skipping version for empty file or directory: %s", real_path);
        return 0;
    }

    /*
     * Extract the filename from the real path and prepare the
     * version filename.
     * 
     * For files in subdirectories, we flatten the path by replacing
     * '/' with '__' to create a flat namespace in .versions/
     * 
     * Examples:
     *   ./storage/hello.txt       -> basename: hello.txt
     *   ./storage/docs/report.txt -> basename: docs__report.txt
     */
    const char *rel_path = real_path + strlen(STORAGE_DIR);
    if (*rel_path == '/') rel_path++;  /* Skip leading slash */

    /* Create a flattened version of the relative path */
    char flat_name[MAX_PATH_LEN];
    strncpy(flat_name, rel_path, sizeof(flat_name) - 1);
    flat_name[sizeof(flat_name) - 1] = '\0';

    /* Replace path separators with double underscores */
    for (char *p = flat_name; *p; p++) {
        if (*p == '/') {
            /*
             * We need to insert an extra '_' character.
             * Shift remaining string right by 1 to make room.
             */
            size_t remaining = strlen(p + 1);
            if (p - flat_name + 2 + remaining < MAX_PATH_LEN - 1) {
                memmove(p + 2, p + 1, remaining + 1);
                p[0] = '_';
                p[1] = '_';
                p++;  /* Skip past the second underscore */
            }
        }
    }

    /* Get the next version number */
    int version = get_next_version_number(flat_name);

    /* Build the version file path */
    char version_path[MAX_PATH_LEN];
    snprintf(version_path, sizeof(version_path), "%s/%s.v%d",
             VERSIONS_DIR, flat_name, version);

    SECFS_DEBUG("Creating version backup: %s -> %s", real_path, version_path);

    /*
     * Copy the file byte-by-byte.
     * 
     * We copy the raw encrypted data from storage, so the version
     * file is also encrypted. This means versions can only be read
     * through the filesystem, maintaining security.
     */
    FILE *src = fopen(real_path, "rb");
    if (!src) {
        SECFS_ERROR("Failed to open source for versioning: %s (%s)",
                   real_path, strerror(errno));
        return -1;
    }

    FILE *dst = fopen(version_path, "wb");
    if (!dst) {
        SECFS_ERROR("Failed to create version file: %s (%s)",
                   version_path, strerror(errno));
        fclose(src);
        return -1;
    }

    /* Copy data in chunks */
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dst) != bytes_read) {
            SECFS_ERROR("Failed to write version file: %s (%s)",
                       version_path, strerror(errno));
            fclose(src);
            fclose(dst);
            return -1;
        }
    }

    fclose(src);
    fclose(dst);

    SECFS_DEBUG("Version backup created: %s (v%d)", flat_name, version);

    /* Log the versioning operation */
    char log_msg[MAX_PATH_LEN];
    snprintf(log_msg, sizeof(log_msg), "%s (v%d)", virt_path, version);
    log_operation("VERSION", log_msg);

    return 0;
}
