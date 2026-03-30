/*
 * versioning.h - Versioning module header for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Provides automatic file versioning. When a file is modified,
 * the previous version is saved in the .versions directory
 * with an incrementing version number.
 * 
 * Version naming: filename.ext.v1, filename.ext.v2, ...
 * Storage: storage/.versions/
 */

#ifndef SECFS_VERSIONING_H
#define SECFS_VERSIONING_H

/*
 * versioning_init - Initialize the versioning subsystem
 * 
 * Creates the .versions directory if it doesn't exist.
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int versioning_init(void);

/*
 * create_version_backup - Save a backup of the current file version
 * 
 * Copies the existing file (at real_path in storage) to
 * storage/.versions/filename.ext.vN where N is auto-incremented.
 * 
 * This should be called BEFORE the file is overwritten with new content.
 * 
 * For files in subdirectories, the path separator '/' is replaced
 * with '__' to create a flat namespace in .versions/.
 * Example: storage/docs/report.txt -> .versions/docs__report.txt.v1
 * 
 * Parameters:
 *   real_path   - Full real path to the file in storage (e.g., "./storage/test.txt")
 *   virt_path   - Virtual FUSE path (e.g., "/test.txt") for logging
 * 
 * Returns:
 *   0 on success, -1 on error, 1 if source file doesn't exist (no backup needed)
 */
int create_version_backup(const char *real_path, const char *virt_path);

/*
 * get_next_version_number - Get the next available version number for a file
 * 
 * Scans the .versions directory to find the highest existing version
 * number for the given filename and returns the next one.
 * 
 * Parameters:
 *   basename - The base filename to check versions for
 * 
 * Returns:
 *   The next version number (starting from 1)
 */
int get_next_version_number(const char *basename);

#endif /* SECFS_VERSIONING_H */
