/*
 * chevron.c - libchevron core implementation
 *
 * Single-shot and streaming atomic file replacement.
 * See ARCHITECTURE.md §2 for the complete operation sequence.
 * See ARCHITECTURE.md §3 for platform path details.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/chevron.h"
#include "chevron_internal.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/*
 * chevron_mkostemp_cloexec - portable mkostemp(O_CLOEXEC) equivalent.
 *
 * mkostemp is a GNU extension. Keep libchevron buildable with only POSIX/XSI
 * feature macros by using mkstemp followed immediately by FD_CLOEXEC.
 */
static int
chevron_mkostemp_cloexec(char *template, int flags)
{
	int fd;
	int fdflags;
	int saved_errno;

	if ((flags & ~O_CLOEXEC) != 0) {
		errno = EINVAL;
		return -1;
	}

	fd = mkstemp(template);
	if (fd == -1)
		return -1;

	fdflags = fcntl(fd, F_GETFD);
	if (fdflags == -1 ||
	    fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) == -1) {
		saved_errno = errno;
		(void)close(fd);
		(void)unlink(template);
		errno = saved_errno;
		return -1;
	}

	return fd;
}

/*
 * chevron_fail - populate err and return -1.
 */
static inline int chevron_fail(chevron_error_t *err, chevron_err_t e,
                               chevron_op_t op, int errno_value)
{
	if (err != NULL) {
		err->err         = e;
		err->op          = op;
		err->errno_value = errno_value;
	}
	return -1;
}

/*
 * chevron_ok - populate err with success values and return 0.
 */
static inline int __attribute__((unused)) chevron_ok(chevron_error_t *err)
{
	if (err != NULL) {
		err->err         = CHEVRON_ERR_NONE;
		err->op          = CHEVRON_OP_NONE;
		err->errno_value = 0;
	}
	return 0;
}

/*
 * split_path - split path into parent directory and basename components.
 *
 * Handles:
 *   - No directory component (basename only): parent is "."
 *   - Root-level path ("/foo"):               parent is "/"
 *   - Trailing slashes:                        stripped before splitting
 *
 * See ARCHITECTURE.md §2 step 2.
 */
static void split_path(const char *path, char *parent_out, char *basename_out)
{
	char        tmp[PATH_MAX];
	const char *last_slash;
	size_t      len;
	size_t      blen;

	len = strlen(path);

	/*
	 * NOTE: PATH_MAX includes the NUL terminator; path has already been
	 * validated as < PATH_MAX chars. The memcpy is safe.
	 */
	memcpy(tmp, path, len + 1);

	/*
	 * Strip trailing slashes. A validated path will not have them,
	 * but handle defensively. Stop at len == 1 to preserve the root "/".
	 */
	while (len > 1 && tmp[len - 1] == '/') {
		tmp[--len] = '\0';
	}

	last_slash = strrchr(tmp, '/');

	if (last_slash == NULL) {
		/* No directory component - parent is ".". */
		parent_out[0] = '.';
		parent_out[1] = '\0';
		memcpy(basename_out, tmp, len + 1);
	} else if (last_slash == tmp) {
		/*
		 * Path is "/<name>" - parent is the root "/".
		 * last_slash + 1 points to the basename.
		 */
		parent_out[0] = '/';
		parent_out[1] = '\0';
		blen          = strlen(last_slash + 1);
		memcpy(basename_out, last_slash + 1, blen + 1);
	} else {
		/*
		 * General case: "/a/b/name" - parent is everything
		 * up to (but not including) the last slash.
		 */
		len = (size_t)(last_slash - tmp);
		memcpy(parent_out, tmp, len);
		parent_out[len] = '\0';
		blen            = strlen(last_slash + 1);
		memcpy(basename_out, last_slash + 1, blen + 1);
	}
}

/*
 * open_parent_dir - open the parent directory for dirfd-anchored operations.
 * See ARCHITECTURE.md §2 step 3 and §1.3.
 */
static int open_parent_dir(const char *parent, int *dirfd_out,
                           chevron_error_t *err)
{
	int fd;

	do {
		fd =
		    CHEVRON_OPEN(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	} while (fd == -1 && errno == EINTR);

	if (fd == -1) {
		if (errno == ENAMETOOLONG)
			return chevron_fail(err, CHEVRON_ERR_INVALID,
			                    CHEVRON_OP_VALIDATE, errno);
		return chevron_fail(err, CHEVRON_ERR_OPEN, CHEVRON_OP_OPEN_DIR,
		                    errno);
	}

	*dirfd_out = fd;
	return 0;
}

/*
 * inspect_target - inspect the existing target and populate handle fields.
 *
 * Inspects the path entry itself (AT_SYMLINK_NOFOLLOW), not a symlink target.
 * See ARCHITECTURE.md §5 and §2 step 4.
 *
 * Outcomes:
 *   ENOENT  - target absent: set _uid/_gid sentinels; apply caller mode or
 *             CHEVRON_MODE_DEFAULT (0600). Return 0.
 *   S_ISDIR - fail: CHEVRON_ERR_PERMISSION / CHEVRON_OP_STAT_TARGET.
 *   S_ISLNK - skip preservation: set _uid/_gid sentinels; apply caller mode
 *             or CHEVRON_MODE_DEFAULT (0600). Return 0.
 *             See ARCHITECTURE.md §8.3 - renameat replaces the symlink.
 *   regular - preserve: store st.st_mode, st.st_uid, st.st_gid in handle.
 *             Caller-specified mode is ignored; the existing mode is used.
 *   other   - any other fstatat error: CHEVRON_ERR_OPEN /
 *             CHEVRON_OP_STAT_TARGET.
 *
 * NOTE: CHEVRON_MODE_DEFAULT is (mode_t)-1, not 0. mode 0000 is a valid
 *       caller-specified value and must not be treated as the default sentinel.
 *       See ARCHITECTURE.md §5.3.
 *
 * See ARCHITECTURE.md §5 and §2 step 4.
 */
static int inspect_target(int dirfd, const char *basename, chevron_handle_t *h,
                          chevron_error_t *err)
{
	struct stat st;
	int         rc;

	do {
		rc = CHEVRON_FSTATAT(dirfd, basename, &st, AT_SYMLINK_NOFOLLOW);
	} while (rc != 0 && errno == EINTR);

	if (rc != 0) {
		if (errno == ENOENT) {
			/*
			 * Target absent: set uid/gid sentinels so fchown is
			 * skipped. Apply caller mode or safe default.
			 * See ARCHITECTURE.md §5.2 and §4.4.
			 */
			h->_uid = (uid_t)-1;
			h->_gid = (gid_t)-1;
			if (h->_mode == CHEVRON_MODE_DEFAULT)
				h->_mode = 0600;
			return 0;
		}
		if (errno == ENAMETOOLONG)
			return chevron_fail(err, CHEVRON_ERR_INVALID,
			                    CHEVRON_OP_VALIDATE, errno);
		return chevron_fail(err, CHEVRON_ERR_OPEN,
		                    CHEVRON_OP_STAT_TARGET, errno);
	}

	if (S_ISDIR(st.st_mode))
		return chevron_fail(err, CHEVRON_ERR_PERMISSION,
		                    CHEVRON_OP_STAT_TARGET, 0);

	if (S_ISLNK(st.st_mode)) {
		/*
		 * Target is a symlink: renameat will replace the symlink
		 * itself, not its target. Skip ownership preservation;
		 * apply caller mode or safe default.
		 * See ARCHITECTURE.md §8.3.
		 */
		h->_uid = (uid_t)-1;
		h->_gid = (gid_t)-1;
		if (h->_mode == CHEVRON_MODE_DEFAULT)
			h->_mode = 0600;
		return 0;
	}

	/*
	 * Regular file: preserve existing mode, uid, and gid.
	 * Caller-specified mode is overridden by the target's mode.
	 * See ARCHITECTURE.md §5.1.
	 */
	h->_mode = st.st_mode;
	h->_uid  = st.st_uid;
	h->_gid  = st.st_gid;
	return 0;
}

/*
 * create_tmp_mkostemp - create a named temporary file in the parent directory.
 * See ARCHITECTURE.md §3.2.
 */
static int create_tmp_mkostemp(const char *parent, int *fd_out,
                               char *tmp_name_out, chevron_error_t *err)
{
	static const char prefix[] = ".chevron_XXXXXX";
	char              template[PATH_MAX];
	size_t            pfx_off;
	int               fd;
	int               n;

	/*
	 * Build the full template. pfx_off is the byte offset of the prefix
	 * inside template - used to rebuild the XXXXXX suffix on EINTR retry
	 * and to extract the basename after mkostemp succeeds.
	 */
	n = snprintf(template, sizeof(template), "%s/%s", parent, prefix);
	if (n < 0 || (size_t)n >= sizeof(template))
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, ENAMETOOLONG);

	pfx_off = strlen(parent) + 1; /* skip "parent/" */

	for (;;) {
		/*
		 * NOTE: mkostemp mutates the template buffer. Restore the
		 * XXXXXX suffix before each call so retries use a fresh
		 * template. On the first call this is a no-op.
		 * See ARCHITECTURE.md §3.2.
		 */
		memcpy(template + pfx_off, prefix, sizeof(prefix));

		fd = CHEVRON_MKOSTEMP(template, O_CLOEXEC);
		if (fd != -1)
			break;
		if (errno != EINTR) {
			if (errno == ENAMETOOLONG)
				return chevron_fail(err, CHEVRON_ERR_INVALID,
				                    CHEVRON_OP_VALIDATE, errno);
			return chevron_fail(err, CHEVRON_ERR_OPEN,
			                    CHEVRON_OP_OPEN_TMP, errno);
		}
	}

	/*
	 * template now holds the full path of the created temp file.
	 * Copy the basename into tmp_name_out - the openat-safe relative name
	 * used with renameat and unlinkat anchored to the parent dirfd.
	 *
	 * The basename is always sizeof(prefix) - 1 bytes long (mkostemp
	 * replaces XXXXXX in-place, keeping the total length constant).
	 */
	memcpy(tmp_name_out, template + pfx_off, sizeof(prefix));
	*fd_out = fd;
	return 0;
}

/*
 * write_loop - write all bytes in buf to fd, handling short writes and EINTR.
 *
 * On EINTR the call is retried immediately.
 * On any other error: fatal with CHEVRON_ERR_WRITE / CHEVRON_OP_WRITE.
 * See ARCHITECTURE.md §2 step 6.
 */
static int write_loop(int fd, const void *buf, size_t len, chevron_error_t *err)
{
	const uint8_t *p = buf;
	ssize_t        n;

	while (len > 0) {
		n = CHEVRON_WRITE(fd, p, MIN(len, (size_t)SSIZE_MAX));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return chevron_fail(err, CHEVRON_ERR_WRITE,
			                    CHEVRON_OP_WRITE, errno);
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * apply_ownership - apply uid/gid to the temporary file fd.
 *
 * Skipped entirely when uid == (uid_t)-1 (sentinel: target absent or symlink;
 * new file inherits the process's effective uid/gid).
 * See ARCHITECTURE.md §5.2 and §4.4.
 *
 * EPERM is non-fatal: the process may lack the privilege to change ownership,
 * but the caller may still want the write to succeed. Any other error is fatal.
 * See ARCHITECTURE.md §5.1 step 2.
 *
 * SAFETY: fchown before fchmod. fchown clears setuid/setgid bits on Linux.
 * Running fchmod after ensures those bits survive. Order must not be changed.
 * See ARCHITECTURE.md §5.1.
 */
static int apply_ownership(int fd, uid_t uid, gid_t gid, chevron_error_t *err)
{
	int rc;

	/* Sentinel: no ownership to preserve; skip fchown entirely. */
	if (uid == (uid_t)-1)
		return 0;

	do {
		rc = CHEVRON_FCHOWN(fd, uid, gid);
	} while (rc != 0 && errno == EINTR);

	if (rc != 0) {
		/*
		 * EPERM: non-fatal. The process lacks privilege to change
		 * ownership. Proceed; the file will be owned by the process.
		 * See ARCHITECTURE.md §5.1 step 2.
		 */
		if (errno == EPERM)
			return 0;
		return chevron_fail(err, CHEVRON_ERR_OPEN, CHEVRON_OP_FCHOWN,
		                    errno);
	}

	return 0;
}

/*
 * apply_mode - apply mode to the temporary file fd.
 *
 * Any error is fatal. Must be called after apply_ownership.
 * See ARCHITECTURE.md §5.1 step 3.
 */
static int apply_mode(int fd, mode_t mode, chevron_error_t *err)
{
	int rc;

	do {
		rc = CHEVRON_FCHMOD(fd, mode);
	} while (rc != 0 && errno == EINTR);

	if (rc != 0)
		return chevron_fail(err, CHEVRON_ERR_OPEN, CHEVRON_OP_FCHMOD,
		                    errno);

	return 0;
}

/*
 * do_fsync - fsync fd, retrying on EINTR.
 *
 * See ARCHITECTURE.md §2 steps 9 and 13.
 */
static int do_fsync(int fd, chevron_op_t op, chevron_error_t *err)
{
	int rc;

	do {
		rc = CHEVRON_FSYNC(fd);
	} while (rc != 0 && errno == EINTR);

	if (rc != 0)
		return chevron_fail(err, CHEVRON_ERR_FSYNC, op, errno);

	return 0;
}

/*
 * close_tmp - close the temporary file fd before renameat.
 *
 * Any error on close is fatal: close() surfaces delayed writeback errors
 * that fsync() may not have caught. Aborting before renameat is the
 * correct response.
 * See ARCHITECTURE.md §2 step 10.
 *
 * SAFETY: do not retry close() on EINTR. On Linux the fd is closed
 * regardless of whether close() returns EINTR. Retrying would operate on
 * an already-closed fd.
 */
static int close_tmp(int fd, chevron_error_t *err)
{
	if (CHEVRON_CLOSE(fd) != 0)
		return chevron_fail(err, CHEVRON_ERR_CLOSE,
		                    CHEVRON_OP_CLOSE_TMP, errno);

	return 0;
}

/*
 * do_renameat - atomically replace target with temp file.
 * See ARCHITECTURE.md §2 step 12 and §1.3.
 */
static int do_renameat(int dirfd, const char *tmp_name, const char *target_name,
                       chevron_error_t *err)
{
	int rc;

	do {
		rc = CHEVRON_RENAMEAT(dirfd, tmp_name, dirfd, target_name);
	} while (rc != 0 && errno == EINTR);

	if (rc != 0)
		return chevron_fail(err, CHEVRON_ERR_RENAME, CHEVRON_OP_RENAME,
		                    errno);

	return 0;
}

/*
 * cleanup_tmp - best-effort cleanup of the temporary file on pre-rename
 * failure.
 *
 * Attempts CHEVRON_CLOSE(tmp_fd) if tmp_fd != -1.
 * Attempts CHEVRON_UNLINKAT(dirfd, tmp_name, 0) if dirfd != -1.
 * Attempts CHEVRON_CLOSE(dirfd) if dirfd != -1.
 * All are best-effort: return values are ignored.
 *
 * SAFETY: this function must never touch chevron_error_t. The primary
 * error has already been captured by the caller before jumping to cleanup.
 * Overwriting err here would lose the original failure.
 * See ARCHITECTURE.md §2.
 *
 * SAFETY: CHEVRON_UNLINKAT, not unlink(). Cleanup must be anchored to the
 * opened parent dirfd to avoid operating on a different directory if the
 * namespace changes. See ARCHITECTURE.md §1.3.
 */
static void cleanup_tmp(int tmp_fd, int dirfd, const char *tmp_name)
{
	if (tmp_fd != -1)
		(void)CHEVRON_CLOSE(tmp_fd);

	if (dirfd != -1 && tmp_name != NULL && tmp_name[0] != '\0')
		(void)CHEVRON_UNLINKAT(dirfd, tmp_name, 0);

	if (dirfd != -1)
		(void)CHEVRON_CLOSE(dirfd);
}

/*
 * chevron_validate_args - validate public API arguments.
 *
 * See ARCHITECTURE.md §7.3.
 */
static int chevron_validate_args(const char *path, const void *buf, size_t len,
                                 chevron_durability_t durability,
                                 chevron_error_t     *err)
{
	const char *p;
	const char *last_slash;
	const char *base;
	size_t      base_len;

	if (path == NULL || path[0] == '\0')
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	if (strlen(path) >= PATH_MAX)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	/*
	 * Verify the path has a non-empty basename component.
	 * Find the last slash; everything after it is the basename.
	 * If no slash, the whole path is the basename.
	 * A trailing slash means the basename is empty - reject it.
	 */
	last_slash = NULL;
	for (p = path; *p != '\0'; p++) {
		if (*p == '/')
			last_slash = p;
	}
	if (last_slash != NULL && last_slash[1] == '\0')
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	base     = (last_slash == NULL) ? path : (last_slash + 1);
	base_len = strlen(base);
	if (base_len == 0 || base_len > NAME_MAX)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	if (buf == NULL && len > 0)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	if (durability != CHEVRON_FULL && durability != CHEVRON_FILE &&
	    durability != CHEVRON_NONE)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	return 0;
}

#if defined(__linux__) && defined(O_TMPFILE)
/*
 * try_open_otmpfile - probe for O_TMPFILE support and open a temp inode.
 *
 * No EINTR retry: EINTR from the probe is treated as a fallback trigger.
 * See ARCHITECTURE.md §3.1 - runtime detection strategy.
 *
 * NOTE: O_RDWR is required with O_TMPFILE; O_WRONLY alone produces EINVAL
 * on some kernels. See ARCHITECTURE.md §3.1.
 */
static int try_open_otmpfile(const char *parent, int *fd_out)
{
	int fd;

#ifdef CHEVRON_TEST
	/*
	 * Test-only escape hatch: when chevron_fault.force_no_otmpfile is
	 * set, behave as if the kernel does not support O_TMPFILE. errno is
	 * set to EOPNOTSUPP for parity with a real soft-fail.
	 */
	if (chevron_fault.force_no_otmpfile) {
		errno = EOPNOTSUPP;
		return 0;
	}
#endif

	fd = CHEVRON_OPEN(parent, O_RDWR | O_TMPFILE | O_CLOEXEC, 0600);
	if (fd == -1) {
		if (errno == EOPNOTSUPP || errno == EINVAL || errno == EISDIR ||
		    errno == EINTR)
			return 0;
		return -1;
	}

	*fd_out = fd;
	return 1;
}

/*
 * create_tmp_otmpfile - production-path O_TMPFILE creation with EINTR retry.
 *
 * Wraps try_open_otmpfile() to add the EINTR-retry policy required by the
 * committed (non-probe) creation path: EINTR is retried, not treated as a
 * fallback trigger. Soft fallback errnos (EOPNOTSUPP, EINVAL, EISDIR) still
 * cause a return of 0 so the caller can switch to the mkostemp path.
 * See ARCHITECTURE.md §3.1.
 */
static int create_tmp_otmpfile(const char *parent, int *fd_out,
                               chevron_error_t *err)
{
	int rc;

	for (;;) {
		rc = try_open_otmpfile(parent, fd_out);
		if (rc == 1)
			return 1;
		if (rc == -1)
			return chevron_fail(err, CHEVRON_ERR_OPEN,
			                    CHEVRON_OP_OPEN_TMP, errno);
		/*
		 * rc == 0: soft failure. EINTR means the syscall was
		 * interrupted - retry. EOPNOTSUPP / EINVAL / EISDIR mean the
		 * kernel/filesystem does not support O_TMPFILE - return 0 so
		 * the caller falls back to mkostemp.
		 */
		if (errno == EINTR)
			continue;
		return 0;
	}
}

/*
 * generate_tmp_name - generate an unpredictable basename for the linkat
 * temp entry on the O_TMPFILE path.
 */
static void generate_tmp_name(const chevron_handle_t *h, char *out,
                              unsigned int attempt)
{
	static const char    charset[] = "abcdefghijklmnopqrstuvwxyz"
	                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	                                 "0123456789";
	static const char    prefix[]  = ".chevron_";
	static uint64_t      nonce     = UINT64_C(0x7f4a7c159e3779b9);
	uint64_t             seed;
	size_t               i;
	size_t               plen;
	const unsigned char *p;

	plen = sizeof(prefix) - 1; /* exclude NUL */

	/*
	 * Mix handle-local state, ASLR-influenced pointer values, and a
	 * per-process nonce so the generated name is not trivially predictable.
	 */
	nonce += UINT64_C(0x9e3779b97f4a7c15);
	seed = nonce ^ (uint64_t)attempt;
	seed ^= (uint64_t)(uintptr_t)h;
	seed ^= (uint64_t)(uintptr_t)out << 7;
	seed ^= (uint64_t)(uintptr_t)&attempt << 13;
	p = (const unsigned char *)h->_target_name;
	while (*p != '\0') {
		seed ^= (uint64_t)*p++;
		seed *= UINT64_C(0x100000001b3);
	}
	seed ^= (uint64_t)(unsigned int)(h->_fd + 1);
	seed ^= (uint64_t)(unsigned int)(h->_dirfd + 1) << 17;
	seed ^= (uint64_t)h->_mode << 32;
	seed ^= (uint64_t)(unsigned int)h->_uid << 9;
	seed ^= (uint64_t)(unsigned int)h->_gid << 23;
	seed ^= (uint64_t)(unsigned int)h->_durability << 41;
	if (seed == 0)
		seed = UINT64_C(0x9e3779b97f4a7c15);

	memcpy(out, prefix, plen);
	for (i = 0; i < 6; i++) {
		/* xorshift64* step; deterministic, no syscall dependency. */
		seed ^= seed >> 12;
		seed ^= seed << 25;
		seed ^= seed >> 27;
		seed *= UINT64_C(2685821657736338717);
		out[plen + i] = charset[seed % (sizeof(charset) - 1)];
	}
	out[plen + 6] = '\0';
}

/*
 * commit_linkat_otmpfile - link the unnamed O_TMPFILE inode to a temporary
 * name in the parent directory.
 *
 * Generates an unpredictable basename, then issues
 *   CHEVRON_LINKAT(tmpfd, "", dirfd, tmp_name, AT_EMPTY_PATH)
 * with EINTR retry. On success, the inode now has a directory entry under
 * tmp_name - copied into h->_tmp_name so post-rename / failure cleanup
 * paths can address it via dirfd.
 *
 * SAFETY: h->_tmp_name is only populated AFTER linkat succeeds. If linkat
 * fails, h->_tmp_name remains empty and cleanup_tmp will not attempt
 * unlinkat on a non-existent entry.
 *
 * NOTE: linkat(tmpfd, "", dirfd, tmp_name, AT_EMPTY_PATH) requires
 *       AT_EMPTY_PATH. Standard linkat without this flag will fail.
 *       See ARCHITECTURE.md §3.1.
 *
 * EOPNOTSUPP from linkat is fatal. See ARCHITECTURE.md §3.1.
 * Reported as CHEVRON_ERR_OPEN / CHEVRON_OP_OPEN_TMP.
 */
static int commit_linkat_otmpfile(chevron_handle_t *h, chevron_error_t *err)
{
	char         tmp_name[NAME_MAX + 1];
	int          rc;
	unsigned int attempt;

	for (attempt = 0; attempt < 32; attempt++) {
		generate_tmp_name(h, tmp_name, attempt);

		do {
			rc = CHEVRON_LINKAT(h->_fd, "", h->_dirfd, tmp_name,
			                    AT_EMPTY_PATH);
		} while (rc != 0 && errno == EINTR);

		if (rc == 0)
			break;
		if (errno != EEXIST)
			return chevron_fail(err, CHEVRON_ERR_OPEN,
			                    CHEVRON_OP_OPEN_TMP, errno);
	}

	if (rc != 0)
		return chevron_fail(err, CHEVRON_ERR_OPEN, CHEVRON_OP_OPEN_TMP,
		                    EEXIST);

	/*
	 * linkat succeeded - directory entry now exists. Commit the name to
	 * the handle so cleanup paths can remove it via unlinkat.
	 */
	memcpy(h->_tmp_name, tmp_name, strlen(tmp_name) + 1);
	return 0;
}
#endif /* defined(__linux__) && defined(O_TMPFILE) */

/*
 * chevron_do_open - open the parent directory, inspect the target, and
 * create the temporary file.
 *
 * SAFETY: h->_tmp_name is explicitly cleared to '\0' at entry so that
 * cleanup_tmp never attempts unlinkat with an uninitialised name if the
 * open phase fails before temp creation. See ARCHITECTURE.md §2.
 *
 * See ARCHITECTURE.md §2, §3.1, §3.2, §4.2.
 */
static int chevron_do_open(chevron_handle_t *h, const char *path,
                           chevron_durability_t durability, mode_t mode,
                           chevron_error_t *err)
{
	char parent[PATH_MAX];
	int  rc;
#if defined(__linux__) && defined(O_TMPFILE)
	int using_otmpfile = 0;
#endif

	h->_durability  = durability;
	h->_mode        = mode;
	h->_tmp_name[0] = '\0';

	/* Step 2: split path. See ARCHITECTURE.md §2 step 2. */
	split_path(path, parent, h->_target_name);

	/* Step 3: open parent directory. See ARCHITECTURE.md §2 step 3. */
	rc = open_parent_dir(parent, &h->_dirfd, err);
	if (rc != 0)
		goto cleanup;

	/* Step 4: inspect existing target. See ARCHITECTURE.md §2 step 4. */
	rc = inspect_target(h->_dirfd, h->_target_name, h, err);
	if (rc != 0)
		goto cleanup;

#if defined(__linux__) && defined(O_TMPFILE)
	/*
	 * Step 5a: try the O_TMPFILE path with EINTR retry.
	 *
	 * create_tmp_otmpfile returns:
	 *   1  - O_TMPFILE inode opened; h->_fd holds the unnamed-inode fd.
	 *   0  - kernel/filesystem does not support O_TMPFILE; fall through.
	 *  -1  - hard error; err already populated.
	 *
	 * See ARCHITECTURE.md §3.1 and §3.3.
	 */
	rc = create_tmp_otmpfile(parent, &h->_fd, err);
	if (rc == -1)
		goto cleanup;
	if (rc == 1)
		using_otmpfile = 1;
#endif /* defined(__linux__) && defined(O_TMPFILE) */

#if defined(__linux__) && defined(O_TMPFILE)
	if (!using_otmpfile)
#endif
	{
		/* Step 5b: create named temporary file. See ARCHITECTURE.md
		 * §3.2. */
		rc = create_tmp_mkostemp(parent, &h->_fd, h->_tmp_name, err);
		if (rc != 0)
			goto cleanup;
	}

	return 0;

cleanup:
	/*
	 * SAFETY: primary error already captured before this goto.
	 * cleanup_tmp must not touch err.
	 */
	cleanup_tmp(h->_fd, h->_dirfd, h->_tmp_name);
	h->_fd    = -1;
	h->_dirfd = -1;
	return -1;
}

/*
 * chevron_do_write - write data to the open temporary file.
 *
 * Calls write_loop() handling short writes and EINTR.
 * Calling chevron_abort() after failure is safe - inactive-handle guard fires.
 * See ARCHITECTURE.md §2 step 6.
 */
static int chevron_do_write(chevron_handle_t *h, const void *buf, size_t len,
                            chevron_error_t *err)
{
	if (write_loop(h->_fd, buf, len, err) != 0) {
		/* SAFETY: cleanup_tmp must not touch err. */
		cleanup_tmp(h->_fd, h->_dirfd, h->_tmp_name);
		h->_fd    = -1;
		h->_dirfd = -1;
		return -1;
	}
	return 0;
}

/*
 * chevron_do_commit - apply permissions, fsync, close, rename, dir fsync.
 *
 * O_TMPFILE path detection: h->_tmp_name[0] == '\0' inside the
 * __linux__ && O_TMPFILE guard signals the O_TMPFILE path. The mkostemp
 * path always populates h->_tmp_name in chevron_do_open; the O_TMPFILE
 * path leaves it empty until linkat succeeds here.
 * See ARCHITECTURE.md §3.1 - linkat must precede close.
 *
 * SAFETY: h->_fd and h->_dirfd are set to -1 together on every exit path.
 *
 * SAFETY: fchown before fchmod. fchown clears setuid/setgid bits on Linux;
 * fchmod after restores them. Order must not be changed.
 * See ARCHITECTURE.md §5.1.
 *
 * SAFETY: h->_tmp_name is empty on the O_TMPFILE path unless linkat (step
 * 11a) succeeded. cleanup_tmp checks tmp_name[0] != '\0' before unlinkat,
 * so the unnamed-inode case is handled by closing the fd alone.
 *
 * See ARCHITECTURE.md §2.
 */
static int chevron_do_commit(chevron_handle_t *h, chevron_error_t *err)
{
	int rc;

	/*
	 * Steps 7-8: apply fchown then fchmod.
	 * SAFETY: fchown before fchmod always. See ARCHITECTURE.md §5.1.
	 */
	rc = apply_ownership(h->_fd, h->_uid, h->_gid, err);
	if (rc != 0)
		goto cleanup;

	rc = apply_mode(h->_fd, h->_mode, err);
	if (rc != 0)
		goto cleanup;

	/*
	 * Step 9: fsync temporary file (skipped for CHEVRON_NONE).
	 * See ARCHITECTURE.md §6.
	 */
	if (h->_durability != CHEVRON_NONE) {
		rc = do_fsync(h->_fd, CHEVRON_OP_FSYNC_FILE, err);
		if (rc != 0)
			goto cleanup;
	}

#if defined(__linux__) && defined(O_TMPFILE)
	/*
	 * Step 11a (O_TMPFILE only): link the unnamed inode to a fresh
	 * temporary name in the parent directory.
	 *
	 * Detected via h->_tmp_name[0] == '\0': create_tmp_mkostemp always
	 * populates h->_tmp_name; create_tmp_otmpfile leaves it empty until
	 * linkat succeeds. This check is safe inside the __linux__ && O_TMPFILE
	 * guard because on non-Linux platforms this block is compiled out.
	 *
	 * linkat MUST precede close - closing first would release the inode
	 * (EBADF on the subsequent linkat).
	 * See ARCHITECTURE.md §2 step 10/11a and §3.1.
	 *
	 * EOPNOTSUPP from linkat is fatal: the unnamed inode cannot be
	 * salvaged via fallback. See ARCHITECTURE.md §3.1.
	 */
	if (h->_tmp_name[0] == '\0') {
		rc = commit_linkat_otmpfile(h, err);
		if (rc != 0)
			goto cleanup;
	}
#endif /* defined(__linux__) && defined(O_TMPFILE) */

	/*
	 * Step 10: close temporary file.
	 * SAFETY: fatal before renameat; no EINTR retry. close() surfaces
	 * delayed writeback errors. See ARCHITECTURE.md §2 step 10.
	 *
	 * On the O_TMPFILE path, the directory entry created by step 11a
	 * already exists - if close fails, cleanup_tmp will unlinkat that
	 * entry (h->_tmp_name is now populated).
	 */
	rc     = close_tmp(h->_fd, err);
	h->_fd = -1;
	if (rc != 0)
		goto cleanup;

	/*
	 * Step 12: atomic replacement.
	 * -- atomic replacement boundary --
	 * See ARCHITECTURE.md §2 step 12.
	 */
	rc = do_renameat(h->_dirfd, h->_tmp_name, h->_target_name, err);
	if (rc != 0)
		goto cleanup;

	/*
	 * Step 13: fsync parent directory (CHEVRON_FULL only).
	 * On failure after successful renameat: new file may already be
	 * visible. What failed is directory entry durability only.
	 * See ARCHITECTURE.md §6 and §2 step 13.
	 */
	if (h->_durability == CHEVRON_FULL) {
		rc = do_fsync(h->_dirfd, CHEVRON_OP_FSYNC_DIR, err);
		if (rc != 0)
			goto post_rename_fail;
	}

	/*
	 * Step 14: close dirfd. Best-effort; does not affect success/failure
	 * after step 13 has completed. See ARCHITECTURE.md §2 step 14.
	 */
	(void)CHEVRON_CLOSE(h->_dirfd);

	/* SAFETY: both _fd and _dirfd set to -1 together on success. */
	h->_fd    = -1;
	h->_dirfd = -1;
	return chevron_ok(err);

post_rename_fail:
	/*
	 * renameat succeeded; the new file may already be visible at the
	 * target path. Cleanup of the target is not attempted - that would
	 * remove the just-written data. What failed is directory entry
	 * durability only. See ARCHITECTURE.md §2 and §6.
	 */
	(void)CHEVRON_CLOSE(h->_dirfd);

	/* SAFETY: both _fd and _dirfd set to -1 together. */
	h->_fd    = -1;
	h->_dirfd = -1;
	return -1;

cleanup:
	/*
	 * Pre-rename failure: clean up the temporary file. The primary error
	 * is already captured in err. cleanup_tmp must not touch err.
	 *
	 * On the O_TMPFILE path, h->_tmp_name is empty unless linkat (step
	 * 11a) succeeded. cleanup_tmp checks tmp_name[0] != '\0' before
	 * unlinkat, so the unnamed-inode case is handled by closing the fd
	 * alone.
	 */
	cleanup_tmp(h->_fd, h->_dirfd, h->_tmp_name);

	/* SAFETY: both _fd and _dirfd set to -1 together. */
	h->_fd    = -1;
	h->_dirfd = -1;
	return -1;
}

/*
 * chevron_open - begin a streaming atomic file replacement.
 *
 * Validates arguments, opens the parent directory, inspects the existing
 * target, and creates the temporary file. On success, handle->_fd and
 * handle->_dirfd hold live file descriptors and the handle is in the active
 * state. On failure, both are set to -1.
 *
 * Relative paths are resolved against the process cwd at the time this
 * function is called. All subsequent operations are dirfd-anchored to the
 * opened parent directory and are unaffected by subsequent chdir().
 * See ARCHITECTURE.md §9.
 *
 * err may be NULL. Returns 0 on success, -1 on failure.
 * See ARCHITECTURE.md §4.2.
 */
int chevron_open(chevron_handle_t *handle, const char *path,
                 chevron_durability_t durability, mode_t mode,
                 chevron_error_t *err)
{
	if (handle == NULL)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	/*
	 * Guard: canonical inactive state is _fd == -1 and _dirfd == -1.
	 * See ARCHITECTURE.md §4.2.
	 */
	if (handle->_fd != -1 || handle->_dirfd != -1) {
		handle->_fd    = -1;
		handle->_dirfd = -1;
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);
	}

	/*
	 * Validate path and durability. buf/len are not applicable for open;
	 * pass NULL/0 which satisfies the buf==NULL && len>0 check.
	 */
	if (chevron_validate_args(path, NULL, 0, durability, err) != 0) {
		handle->_fd    = -1;
		handle->_dirfd = -1;
		return -1;
	}

	return chevron_do_open(handle, path, durability, mode, err);
}

/*
 * chevron_write_chunk - write a chunk of data to the streaming handle.
 *
 * Appends buf (len bytes) to the temporary file. May be called multiple
 * times between chevron_open and chevron_commit.
 *
 * Guard: handle->_fd == -1 returns CHEVRON_ERR_INVALID immediately.
 * See ARCHITECTURE.md §4.2.
 *
 * On failure: cleanup_tmp is called; both _fd and _dirfd are set to -1.
 * Calling chevron_abort() afterward is safe and is a no-op (guard fires).
 *
 * err may be NULL. Returns 0 on success, -1 on failure.
 */
int chevron_write_chunk(chevron_handle_t *handle, const void *buf, size_t len,
                        chevron_error_t *err)
{
	if (handle == NULL || handle->_fd == -1)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	if (buf == NULL && len > 0)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	if (write_loop(handle->_fd, buf, len, err) != 0) {
		/* SAFETY: cleanup_tmp must not touch err. */
		cleanup_tmp(handle->_fd, handle->_dirfd, handle->_tmp_name);
		handle->_fd    = -1;
		handle->_dirfd = -1;
		return -1;
	}
	return 0;
}

/*
 * chevron_commit - finalise a streaming write with atomic replacement.
 *
 * Guard: handle->_fd == -1 returns CHEVRON_ERR_INVALID immediately.
 *
 * On return (success or failure), both _fd and _dirfd are set to -1 by
 * chevron_do_commit. See ARCHITECTURE.md §4.2.
 *
 * err may be NULL. Returns 0 on success, -1 on failure.
 */
int chevron_commit(chevron_handle_t *handle, chevron_error_t *err)
{
	if (handle == NULL || handle->_fd == -1)
		return chevron_fail(err, CHEVRON_ERR_INVALID,
		                    CHEVRON_OP_VALIDATE, 0);

	/*
	 * chevron_do_commit executes steps 7-14 and always sets both _fd and
	 * _dirfd to -1 on return (success or failure).
	 * See ARCHITECTURE.md §2 and §4.2.
	 */
	return chevron_do_commit(handle, err);
}

/*
 * chevron_abort - cancel a streaming write and clean up.
 *
 * Unlinks the temporary file and closes all file descriptors. Sets both
 * _fd and _dirfd to -1.
 *
 * Guard: if _fd == -1 (inactive handle), returns immediately without any
 * side effects. This makes chevron_abort safe to call after a failed
 * chevron_write_chunk, after chevron_commit, or multiple times.
 * See ARCHITECTURE.md §4.2.
 *
 * Void: no error is reported. Cleanup failures are silently ignored; the
 * temporary file may remain as an orphan in this case.
 * See ARCHITECTURE.md §10.
 */
void chevron_abort(chevron_handle_t *handle)
{
	if (handle == NULL)
		return;

	/* Inactive-handle guard. See ARCHITECTURE.md §4.2. */
	if (handle->_fd == -1)
		return;

	/* SAFETY: cleanup_tmp never touches chevron_error_t. */
	cleanup_tmp(handle->_fd, handle->_dirfd, handle->_tmp_name);

	/*
	 * SAFETY: both _fd and _dirfd set to -1 together so a subsequent
	 * chevron_abort() is a no-op.
	 */
	handle->_fd    = -1;
	handle->_dirfd = -1;
}

/*
 * chevron_write - single-shot atomic file replacement.
 *
 * Validates arguments, initialises a stack-allocated handle, and delegates
 * to the three-phase internal sequence:
 *   chevron_do_open   - steps 2-5b (path split, dir open, tmp creation)
 *   chevron_do_write  - step 6     (write loop)
 *   chevron_do_commit - steps 7-14 (permissions, fsync, close, rename)
 *
 * The handle is never exposed to the caller.
 *
 * path       - target path; must be non-NULL, non-empty, with non-empty
 *              basename, strlen < PATH_MAX
 * buf        - data to write; may be NULL only when len == 0
 * len        - number of bytes to write
 * durability - CHEVRON_FULL, CHEVRON_FILE, or CHEVRON_NONE
 * mode       - file mode for new files; CHEVRON_MODE_DEFAULT for 0600;
 *              existing file's mode is always preserved regardless of this
 * err        - populated on failure; may be NULL
 *
 * Returns 0 on success, -1 on failure.
 * See ARCHITECTURE.md §2 and §6.
 */
int chevron_write(const char *path, const void *buf, size_t len,
                  chevron_durability_t durability, mode_t mode,
                  chevron_error_t *err)
{
	chevron_handle_t h = CHEVRON_HANDLE_INIT;

	if (chevron_validate_args(path, buf, len, durability, err) != 0)
		return -1;

	if (chevron_do_open(&h, path, durability, mode, err) != 0)
		return -1;

	if (chevron_do_write(&h, buf, len, err) != 0)
		return -1;

	return chevron_do_commit(&h, err);
}
