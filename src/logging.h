/*
 * logging.h - Logging module header for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Provides thread-safe, timestamped operation logging to logs.txt.
 * Every filesystem operation (read, write, create, delete, rename)
 * is recorded with a timestamp and file path.
 */

#ifndef SECFS_LOGGING_H
#define SECFS_LOGGING_H

/*
 * logging_init - Initialize the logging subsystem
 * 
 * Opens the log file and initializes the mutex lock.
 * Must be called once before any log_operation calls.
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int logging_init(void);

/*
 * logging_cleanup - Clean up the logging subsystem
 * 
 * Closes the log file and destroys the mutex lock.
 */
void logging_cleanup(void);

/*
 * log_operation - Log a filesystem operation
 * 
 * Thread-safe function that writes a timestamped log entry.
 * Format: [YYYY-MM-DD HH:MM:SS] OPERATION /path/to/file
 * 
 * Parameters:
 *   operation - Name of the operation (e.g., "READ", "WRITE", "CREATE")
 *   path      - Virtual path of the file being operated on
 */
void log_operation(const char *operation, const char *path);

#endif /* SECFS_LOGGING_H */
