/*
 * logging.c - Logging module implementation for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Implements thread-safe filesystem operation logging.
 * 
 * Since FUSE operates in multi-threaded mode by default (via fuse_main),
 * multiple filesystem operations can happen concurrently. A pthread mutex
 * ensures that log entries are written atomically and don't interleave.
 * 
 * Log format: [YYYY-MM-DD HH:MM:SS] OPERATION /path/to/file
 * Example:    [2026-03-30 11:42:12] WRITE /documents/report.txt
 */

#include "logging.h"
#include "common.h"

/* ============================================================
 * Module State
 * ============================================================ */

/* File pointer for the log file */
static FILE *log_fp = NULL;

/* Mutex for thread-safe logging */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================
 * Public API Implementation
 * ============================================================ */

int logging_init(void)
{
    /*
     * Open log file in append mode.
     * "a" mode ensures:
     *   - File is created if it doesn't exist
     *   - New entries are always appended (even if another process writes)
     *   - Previous log entries are preserved across filesystem restarts
     */
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        SECFS_ERROR("Failed to open log file '%s': %s", LOG_FILE, strerror(errno));
        return -1;
    }

    /* Initialize the mutex for thread safety */
    if (pthread_mutex_init(&log_mutex, NULL) != 0) {
        SECFS_ERROR("Failed to initialize log mutex");
        fclose(log_fp);
        log_fp = NULL;
        return -1;
    }

    SECFS_DEBUG("Logging initialized, writing to '%s'", LOG_FILE);

    /* Write a startup marker to the log */
    log_operation("MOUNT", "/");

    return 0;
}

void logging_cleanup(void)
{
    if (log_fp) {
        /* Log the unmount event before closing */
        log_operation("UNMOUNT", "/");

        fclose(log_fp);
        log_fp = NULL;
    }

    pthread_mutex_destroy(&log_mutex);
    SECFS_DEBUG("Logging cleaned up");
}

void log_operation(const char *operation, const char *path)
{
    if (!log_fp) {
        /* Logging not initialized; silently skip */
        return;
    }

    /*
     * Lock the mutex to prevent concurrent log writes from
     * interleaving. This is necessary because FUSE can call
     * our callbacks from multiple threads simultaneously.
     */
    pthread_mutex_lock(&log_mutex);

    /*
     * Get the current timestamp.
     * 
     * time()     - returns seconds since epoch
     * localtime() - converts to local time struct
     * strftime() - formats as human-readable string
     */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /*
     * Write the log entry in the format:
     * [2026-03-30 11:42:12] WRITE /documents/report.txt
     */
    fprintf(log_fp, "[%s] %-10s %s\n", timestamp, operation, path);

    /*
     * Flush the log file immediately.
     * 
     * Without fflush, log entries might be buffered and lost
     * if the filesystem crashes or is killed. For a filesystem,
     * reliable logging is critical for debugging and auditing.
     */
    fflush(log_fp);

    pthread_mutex_unlock(&log_mutex);
}
