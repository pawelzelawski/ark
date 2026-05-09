/*
 * ark_stubs.c — ARK_TEST syscall wrappers with fault injection.
 *
 * Each stub increments its call counter, optionally fails on configured Nth
 * invocation, and otherwise forwards to the real libc syscall.
 */

#include <errno.h>
#include <stdarg.h>

#include "ark_internal.h"

ark_fault_t ark_fault;

static int fault_should_fail(int which, int call_n)
{
	/* Disabled unless selector matches and a positive fail call is
	 * configured. */
	if (ark_fault.which != which)
		return (0);
	if (ark_fault.fail_on_call_n <= 0)
		return (0);
	return (call_n == ark_fault.fail_on_call_n);
}

void fault_reset(void)
{
	ark_fault = (ark_fault_t){0};
}

void fault_inject(int which, int fail_on_call_n, int errno_value)
{
	fault_reset();
	ark_fault.which = which;
	ark_fault.fail_on_call_n = fail_on_call_n;
	ark_fault.errno_value = errno_value;
}

ssize_t ark_stub_read(int fd, void *buf, size_t count)
{
	ark_fault.read_calls++;
	if (fault_should_fail(ARK_FAULT_READ, ark_fault.read_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (read(fd, buf, count));
}

ssize_t ark_stub_write(int fd, const void *buf, size_t count)
{
	ark_fault.write_calls++;
	if (fault_should_fail(ARK_FAULT_WRITE, ark_fault.write_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (write(fd, buf, count));
}

int ark_stub_open(const char *path, int flags, ...)
{
	mode_t mode;
	va_list ap;

	ark_fault.open_calls++;
	if (fault_should_fail(ARK_FAULT_OPEN, ark_fault.open_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	if ((flags & O_CREAT) == 0)
		return (open(path, flags));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (open(path, flags, mode));
}

int ark_stub_close(int fd)
{
	ark_fault.close_calls++;
	if (fault_should_fail(ARK_FAULT_CLOSE, ark_fault.close_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (close(fd));
}

int ark_stub_lstat(const char *path, struct stat *sb)
{
	ark_fault.lstat_calls++;
	if (fault_should_fail(ARK_FAULT_LSTAT, ark_fault.lstat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (lstat(path, sb));
}

int ark_stub_unlink(const char *path)
{
	ark_fault.unlink_calls++;
	if (fault_should_fail(ARK_FAULT_UNLINK, ark_fault.unlink_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (unlink(path));
}

int ark_stub_rmdir(const char *path)
{
	ark_fault.rmdir_calls++;
	if (fault_should_fail(ARK_FAULT_RMDIR, ark_fault.rmdir_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (rmdir(path));
}

int ark_stub_link(const char *oldpath, const char *newpath)
{
	ark_fault.link_calls++;
	if (fault_should_fail(ARK_FAULT_LINK, ark_fault.link_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (link(oldpath, newpath));
}

int ark_stub_mkdir(const char *path, mode_t mode)
{
	ark_fault.mkdir_calls++;
	if (fault_should_fail(ARK_FAULT_MKDIR, ark_fault.mkdir_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (mkdir(path, mode));
}

int ark_stub_lchown(const char *path, uid_t owner, gid_t group)
{
	ark_fault.lchown_calls++;
	if (fault_should_fail(ARK_FAULT_LCHOWN, ark_fault.lchown_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (lchown(path, owner, group));
}

int ark_stub_chmod(const char *path, mode_t mode)
{
	ark_fault.chmod_calls++;
	if (fault_should_fail(ARK_FAULT_CHMOD, ark_fault.chmod_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (chmod(path, mode));
}

int ark_stub_utimensat(int fd, const char *path, const struct timespec times[2],
                       int flags)
{
	ark_fault.utimensat_calls++;
	if (fault_should_fail(ARK_FAULT_UTIMENSAT, ark_fault.utimensat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (utimensat(fd, path, times, flags));
}

DIR *ark_stub_opendir(const char *path)
{
	ark_fault.opendir_calls++;
	if (fault_should_fail(ARK_FAULT_OPENDIR, ark_fault.opendir_calls)) {
		errno = ark_fault.errno_value;
		return (NULL);
	}
	return (opendir(path));
}

struct dirent *ark_stub_readdir(DIR *dirp)
{
	ark_fault.readdir_calls++;
	if (fault_should_fail(ARK_FAULT_READDIR, ark_fault.readdir_calls)) {
		errno = ark_fault.errno_value;
		return (NULL);
	}
	return (readdir(dirp));
}

int ark_stub_closedir(DIR *dirp)
{
	ark_fault.closedir_calls++;
	if (fault_should_fail(ARK_FAULT_CLOSEDIR, ark_fault.closedir_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (closedir(dirp));
}

char *ark_stub_realpath(const char *path, char *resolved_path)
{
	ark_fault.realpath_calls++;
	if (fault_should_fail(ARK_FAULT_REALPATH, ark_fault.realpath_calls)) {
		errno = ark_fault.errno_value;
		return (NULL);
	}
	return (realpath(path, resolved_path));
}

/* ark_stub_readlink - Fault-injectable wrapper for symlink traversal reads. */
ssize_t ark_stub_readlink(const char *path, char *buf, size_t bufsiz)
{
	ark_fault.readlink_calls++;
	if (fault_should_fail(ARK_FAULT_READLINK, ark_fault.readlink_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (readlink(path, buf, bufsiz));
}
