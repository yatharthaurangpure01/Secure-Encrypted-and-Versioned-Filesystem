/*
 * fuse_ops.h - FUSE operations module header for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Declares all FUSE callback functions that implement the
 * virtual filesystem operations. These callbacks are registered
 * with libfuse and called by the FUSE kernel module when
 * user applications perform file operations on the mount point.
 */

#ifndef SECFS_FUSE_OPS_H
#define SECFS_FUSE_OPS_H

#define FUSE_USE_VERSION 31
#include <fuse.h>

/*
 * secfs_getattr - Get file/directory attributes
 * 
 * Called when the system needs metadata about a file (stat, ls, etc.)
 * Maps the virtual path to storage and returns the stat information.
 * For encrypted files, reports the decrypted (original) file size.
 */
int secfs_getattr(const char *path, struct stat *stbuf,
                  struct fuse_file_info *fi);

/*
 * secfs_readdir - List directory contents
 * 
 * Called when a user lists a directory (ls command).
 * Reads the corresponding directory in storage and returns entries.
 * Filters out the .versions directory from the root listing.
 */
int secfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi,
                  enum fuse_readdir_flags flags);

/*
 * secfs_open - Open a file
 * 
 * Called when a file is opened for reading or writing.
 * Validates the file exists in storage.
 */
int secfs_open(const char *path, struct fuse_file_info *fi);

/*
 * secfs_read - Read file data
 * 
 * Called when a user reads file contents (cat, read syscall).
 * Reads the encrypted data from storage, decrypts it, and
 * returns the plaintext to the user.
 */
int secfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi);

/*
 * secfs_write - Write file data
 * 
 * Called when a user writes to a file (echo >, write syscall).
 * Creates a version backup of the existing file, then encrypts
 * the new data and writes it to storage.
 */
int secfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi);

/*
 * secfs_create - Create a new file
 * 
 * Called when a new file is created (touch, open with O_CREAT).
 * Creates the file in storage and logs the operation.
 */
int secfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);

/*
 * secfs_unlink - Delete a file
 * 
 * Called when a file is deleted (rm command, unlink syscall).
 * Removes the file from storage and logs the operation.
 */
int secfs_unlink(const char *path);

/*
 * secfs_rename - Rename/move a file
 * 
 * Called when a file is renamed or moved (mv command).
 * Renames the file in storage and logs the operation.
 */
int secfs_rename(const char *from, const char *to, unsigned int flags);

/*
 * secfs_mkdir - Create a directory
 * 
 * Called when a directory is created (mkdir command).
 * Creates the directory in storage.
 */
int secfs_mkdir(const char *path, mode_t mode);

/*
 * secfs_rmdir - Remove a directory
 * 
 * Called when a directory is removed (rmdir command).
 * Removes the directory from storage.
 */
int secfs_rmdir(const char *path);

/*
 * secfs_truncate - Truncate a file to a specified size
 * 
 * Called when a file is truncated (opening with O_TRUNC, truncate syscall).
 * Creates a version backup before truncating.
 */
int secfs_truncate(const char *path, off_t size, struct fuse_file_info *fi);

/*
 * secfs_utimens - Update file access and modification times
 * 
 * Called when file timestamps are modified (touch command, utime syscall).
 */
int secfs_utimens(const char *path, const struct timespec ts[2],
                  struct fuse_file_info *fi);

/*
 * get_fuse_operations - Get the populated fuse_operations struct
 * 
 * Returns a pointer to the static fuse_operations structure
 * with all callbacks registered.
 */
const struct fuse_operations *get_fuse_operations(void);

#endif /* SECFS_FUSE_OPS_H */
