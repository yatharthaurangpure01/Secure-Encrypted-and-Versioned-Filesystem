/*
 * common.h - Shared includes and utility functions for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * This header provides common includes, macros, and utility function
 * declarations used across all modules of the filesystem.
 */

#ifndef SECFS_COMMON_H
#define SECFS_COMMON_H

/* ============================================================
 * Standard Library Includes
 * ============================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>

/* ============================================================
 * Project Includes
 * ============================================================ */
#include "config.h"

/* ============================================================
 * Utility Macros
 * ============================================================ */

/* Debug logging macro - prints to stderr when DEBUG is defined */
#ifdef DEBUG
    #define SECFS_DEBUG(fmt, ...) \
        fprintf(stderr, "[SECFS DEBUG] %s:%d: " fmt "\n", \
                __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define SECFS_DEBUG(fmt, ...) ((void)0)
#endif

/* Error logging macro - always prints to stderr */
#define SECFS_ERROR(fmt, ...) \
    fprintf(stderr, "[SECFS ERROR] %s:%d: " fmt "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__)

/* ============================================================
 * Utility Functions
 * ============================================================ */

/*
 * get_real_path - Translate a virtual FUSE path to a real storage path
 * 
 * Maps virtual path "/foo/bar.txt" to "storage/foo/bar.txt"
 * 
 * Parameters:
 *   real_path   - Output buffer for the translated path
 *   path        - Virtual path from FUSE (starts with '/')
 *   buf_size    - Size of the output buffer
 * 
 * Returns:
 *   0 on success, -1 if the path would overflow the buffer
 */
static inline int get_real_path(char *real_path, const char *path, size_t buf_size)
{
    int ret = snprintf(real_path, buf_size, "%s%s", STORAGE_DIR, path);
    if (ret < 0 || (size_t)ret >= buf_size) {
        SECFS_ERROR("Path too long: %s", path);
        return -1;
    }
    return 0;
}

/*
 * ensure_directory_exists - Create a directory if it doesn't exist
 * 
 * Creates the directory with permissions 0755.
 * Does not create parent directories (not recursive).
 * 
 * Parameters:
 *   path - Path to the directory to create
 * 
 * Returns:
 *   0 on success (or if directory already exists), -1 on error
 */
static inline int ensure_directory_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0755) == -1) {
            SECFS_ERROR("Failed to create directory: %s (%s)", 
                       path, strerror(errno));
            return -1;
        }
        SECFS_DEBUG("Created directory: %s", path);
    }
    return 0;
}

#endif /* SECFS_COMMON_H */
