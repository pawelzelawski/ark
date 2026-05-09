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

int ark_stub_openat(int fd, const char *path, int flags, ...)
{
	mode_t mode;
	va_list ap;

	ark_fault.openat_calls++;
	if (fault_should_fail(ARK_FAULT_OPENAT, ark_fault.openat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	if ((flags & O_CREAT) == 0)
		return (openat(fd, path, flags));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (openat(fd, path, flags, mode));
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

off_t ark_stub_lseek(int fd, off_t offset, int whence)
{
	ark_fault.lseek_calls++;
	if (fault_should_fail(ARK_FAULT_LSEEK, ark_fault.lseek_calls)) {
		errno = ark_fault.errno_value;
		return ((off_t)-1);
	}
	return (lseek(fd, offset, whence));
}

int ark_stub_fstat(int fd, struct stat *sb)
{
	ark_fault.fstat_calls++;
	if (fault_should_fail(ARK_FAULT_FSTAT, ark_fault.fstat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fstat(fd, sb));
}

int ark_stub_fstatat(int fd, const char *path, struct stat *sb, int flags)
{
	ark_fault.fstatat_calls++;
	if (fault_should_fail(ARK_FAULT_FSTATAT, ark_fault.fstatat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fstatat(fd, path, sb, flags));
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

int ark_stub_unlinkat(int fd, const char *path, int flags)
{
	ark_fault.unlinkat_calls++;
	if (fault_should_fail(ARK_FAULT_UNLINKAT, ark_fault.unlinkat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (unlinkat(fd, path, flags));
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

int ark_stub_linkat(int oldfd, const char *oldpath, int newfd,
                    const char *newpath, int flags)
{
	ark_fault.linkat_calls++;
	if (fault_should_fail(ARK_FAULT_LINKAT, ark_fault.linkat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (linkat(oldfd, oldpath, newfd, newpath, flags));
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

int ark_stub_mkdirat(int fd, const char *path, mode_t mode)
{
	ark_fault.mkdirat_calls++;
	if (fault_should_fail(ARK_FAULT_MKDIRAT, ark_fault.mkdirat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (mkdirat(fd, path, mode));
}

int ark_stub_symlinkat(const char *target, int fd, const char *linkpath)
{
	ark_fault.symlinkat_calls++;
	if (fault_should_fail(ARK_FAULT_SYMLINKAT, ark_fault.symlinkat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (symlinkat(target, fd, linkpath));
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

int ark_stub_fchown(int fd, uid_t owner, gid_t group)
{
	ark_fault.fchown_calls++;
	if (fault_should_fail(ARK_FAULT_FCHOWN, ark_fault.fchown_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fchown(fd, owner, group));
}

int ark_stub_fchownat(int fd, const char *path, uid_t owner, gid_t group,
                      int flags)
{
	ark_fault.fchownat_calls++;
	if (fault_should_fail(ARK_FAULT_FCHOWNAT, ark_fault.fchownat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fchownat(fd, path, owner, group, flags));
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

int ark_stub_fchmod(int fd, mode_t mode)
{
	ark_fault.fchmod_calls++;
	if (fault_should_fail(ARK_FAULT_FCHMOD, ark_fault.fchmod_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fchmod(fd, mode));
}

int ark_stub_fchmodat(int fd, const char *path, mode_t mode, int flags)
{
	ark_fault.fchmodat_calls++;
	if (fault_should_fail(ARK_FAULT_FCHMODAT, ark_fault.fchmodat_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (fchmodat(fd, path, mode, flags));
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

int ark_stub_futimens(int fd, const struct timespec times[2])
{
	ark_fault.futimens_calls++;
	if (fault_should_fail(ARK_FAULT_FUTIMENS, ark_fault.futimens_calls)) {
		errno = ark_fault.errno_value;
		return (-1);
	}
	return (futimens(fd, times));
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
