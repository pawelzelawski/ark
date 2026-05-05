#ifndef CHEVRON_H
#define CHEVRON_H

/*
 * chevron.h - libchevron public API
 *
 * Crash-safe atomic file replacement for Linux and OpenBSD.
 *
 * Single-shot:
 *   chevron_write(path, buf, len, durability, mode, err)
 *
 * Streaming:
 *   chevron_handle_t h = CHEVRON_HANDLE_INIT;
 *   chevron_open(&h, path, durability, mode, err)
 *   chevron_write_chunk(&h, buf, len, err)  [x N]
 *   chevron_commit(&h, err)
 *
 *   or on error:
 *   chevron_abort(&h)
 *
 * See ARCHITECTURE.md for the full internal design.
 */

#include <limits.h>    /* NAME_MAX, PATH_MAX */
#include <sys/stat.h>  /* mode_t, struct stat */
#include <sys/types.h> /* uid_t, gid_t */

/*
 * NAME_MAX may require _POSIX_C_SOURCE on some platforms when using strict
 * C11. Provide a safe fallback so the header remains self-contained when
 * syntax-checked without feature test macros.
 */
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

/*
 * CHEVRON_MODE_DEFAULT - pass as mode to request the safe default (0600)
 * for new files. Allows mode 0000 to be expressed explicitly as (mode_t)0.
 *
 * NOTE: CHEVRON_MODE_DEFAULT is (mode_t)-1, not 0. mode 0000 is a valid
 *       caller-specified value. Do not treat 0 as the default sentinel.
 */
#define CHEVRON_MODE_DEFAULT ((mode_t) - 1)

/*
 * CHEVRON_HANDLE_INIT - required initial state for chevron_handle_t.
 * Always use this, never zero-initialise: _fd == 0 and _dirfd == 0
 * are valid live file descriptor values.
 */
#define CHEVRON_HANDLE_INIT {._fd = -1, ._dirfd = -1}

/*
 * chevron_durability_t - caller-selectable durability level.
 *
 * CHEVRON_FULL  - fsync file and parent directory; data and directory entry
 *                 are durable after crash.
 * CHEVRON_FILE  - fsync file only; data is durable; directory entry
 *                 durability depends on a higher-level mechanism.
 * CHEVRON_NONE  - atomic rename only; not durable across crash.
 */
typedef enum {
	CHEVRON_FULL = 0,
	CHEVRON_FILE = 1,
	CHEVRON_NONE = 2,
} chevron_durability_t;

/*
 * chevron_err_t - class of failure.
 */
typedef enum {
	CHEVRON_ERR_NONE       = 0,
	CHEVRON_ERR_INVALID    = 1,
	CHEVRON_ERR_OPEN       = 2,
	CHEVRON_ERR_WRITE      = 3,
	CHEVRON_ERR_FSYNC      = 4,
	CHEVRON_ERR_CLOSE      = 5,
	CHEVRON_ERR_RENAME     = 6,
	CHEVRON_ERR_PERMISSION = 7,
} chevron_err_t;

/*
 * chevron_op_t - specific operation that failed.
 */
typedef enum {
	CHEVRON_OP_NONE        = 0,
	CHEVRON_OP_VALIDATE    = 1,
	CHEVRON_OP_OPEN_DIR    = 2,
	CHEVRON_OP_OPEN_TMP    = 3,
	CHEVRON_OP_STAT_TARGET = 4,
	CHEVRON_OP_WRITE       = 5,
	CHEVRON_OP_FCHOWN      = 6,
	CHEVRON_OP_FCHMOD      = 7,
	CHEVRON_OP_FSYNC_FILE  = 8,
	CHEVRON_OP_CLOSE_TMP   = 9,
	CHEVRON_OP_RENAME      = 10,
	CHEVRON_OP_FSYNC_DIR   = 11,
	CHEVRON_OP_UNLINK_TMP  = 12,
} chevron_op_t;

/*
 * chevron_error_t - detailed error information.
 *
 * err         - class of failure; CHEVRON_ERR_NONE on success.
 * errno_value - value of errno at the point of failure; 0 on success.
 * op          - operation that failed; CHEVRON_OP_NONE on success.
 *
 * May be passed as NULL to any function; if NULL, error detail is discarded.
 */
typedef struct {
	chevron_err_t err;
	int           errno_value;
	chevron_op_t  op;
} chevron_error_t;

/*
 * chevron_handle_t - streaming write handle.
 *
 * Stack-allocatable transparent struct. All fields are internal to the
 * library and must not be accessed directly by callers.
 *
 * Initialise with CHEVRON_HANDLE_INIT before first use and before reuse
 * after commit or abort.
 */
typedef struct {
	int                  _fd;    /* temp file fd; -1 when inactive */
	int                  _dirfd; /* parent dir fd; -1 when inactive */
	char                 _tmp_name[NAME_MAX + 1]; /* temp file basename */
	char                 _target_name[NAME_MAX + 1]; /* target basename */
	chevron_durability_t _durability;
	mode_t               _mode;
	uid_t                _uid; /* (uid_t)-1 = no preservation */
	gid_t                _gid; /* (gid_t)-1 = no preservation */
} chevron_handle_t;

/*
 * chevron_write - single-shot atomic file replacement.
 *
 * Writes buf (len bytes) to path atomically. If path exists, permissions
 * and ownership are preserved. If path does not exist, mode is applied
 * (or CHEVRON_MODE_DEFAULT for 0600).
 *
 * durability controls whether fsync is performed on the file and/or the
 * parent directory. See chevron_durability_t.
 *
 * err may be NULL. Returns 0 on success, -1 on failure.
 */
int chevron_write(const char *path, const void *buf, size_t len,
                  chevron_durability_t durability, mode_t mode,
                  chevron_error_t *err);

/*
 * chevron_open - begin a streaming atomic file replacement.
 *
 * Validates arguments, opens the parent directory, inspects the existing
 * target, and creates the temporary file. On success, handle holds live
 * file descriptors and is in the active state.
 *
 * handle must be initialised with CHEVRON_HANDLE_INIT and must be inactive
 * (_fd == -1) before calling. err may be NULL.
 *
 * Returns 0 on success, -1 on failure.
 */
int chevron_open(chevron_handle_t *handle, const char *path,
                 chevron_durability_t durability, mode_t mode,
                 chevron_error_t *err);

/*
 * chevron_write_chunk - write a chunk of data to the streaming handle.
 *
 * Appends buf (len bytes) to the temporary file. May be called multiple
 * times between chevron_open and chevron_commit.
 *
 * On failure, the temporary file is cleaned up and the handle is set to
 * the inactive state. Calling chevron_abort() afterward is safe (no-op).
 *
 * handle->_fd == -1 returns CHEVRON_ERR_INVALID immediately.
 * err may be NULL. Returns 0 on success, -1 on failure.
 */
int chevron_write_chunk(chevron_handle_t *handle, const void *buf, size_t len,
                        chevron_error_t *err);

/*
 * chevron_commit - finalise a streaming write with atomic replacement.
 *
 * Applies fchown and fchmod, fsyncs the temporary file (if durability
 * requires), closes the temporary file, performs renameat, and fsyncs
 * the parent directory (if CHEVRON_FULL).
 *
 * On return (success or failure), the handle is set to the inactive state.
 * Reinitialise with CHEVRON_HANDLE_INIT before reuse.
 *
 * Failure before renameat: target path is unchanged; temp file is cleaned up.
 * Failure after renameat (dir fsync, CHEVRON_FULL): returns -1; new file
 * may already be visible. What failed is directory entry durability.
 *
 * handle->_fd == -1 returns CHEVRON_ERR_INVALID immediately.
 * err may be NULL. Returns 0 on success, -1 on failure.
 */
int chevron_commit(chevron_handle_t *handle, chevron_error_t *err);

/*
 * chevron_abort - cancel a streaming write and clean up.
 *
 * Unlinks the temporary file and closes all file descriptors. Sets the
 * handle to the inactive state.
 *
 * If handle->_fd == -1 (inactive), returns immediately without side effects.
 * Safe to call after chevron_write_chunk failure or after chevron_commit.
 */
void chevron_abort(chevron_handle_t *handle);

#endif /* CHEVRON_H */
