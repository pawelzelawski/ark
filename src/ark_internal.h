#ifndef ARK_INTERNAL_H
#define ARK_INTERNAL_H

/*
 * ark_internal.h — shared internal types and syscall wrapper macros.
 *
 * Not part of the public API. Source files use ARK_* wrappers so test
 * builds can inject syscall failures through ARK_TEST stubs.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Syscall wrappers for fault injection in ARK_TEST builds. */
#ifdef ARK_TEST

enum ark_fault_which {
	ARK_FAULT_NONE = 0,
	ARK_FAULT_READ,
	ARK_FAULT_WRITE,
	ARK_FAULT_OPEN,
	ARK_FAULT_CLOSE,
	ARK_FAULT_FSTAT,
	ARK_FAULT_LSTAT,
	ARK_FAULT_UNLINK,
	ARK_FAULT_RMDIR,
	ARK_FAULT_LINK,
	ARK_FAULT_MKDIR,
	ARK_FAULT_LCHOWN,
	ARK_FAULT_CHMOD,
	ARK_FAULT_UTIMENSAT,
	ARK_FAULT_OPENDIR,
	ARK_FAULT_READDIR,
	ARK_FAULT_CLOSEDIR,
	ARK_FAULT_REALPATH,
	ARK_FAULT_READLINK,
};

typedef struct ark_fault {
	int which;
	int fail_on_call_n;
	int errno_value;
	int read_calls;
	int write_calls;
	int open_calls;
	int close_calls;
	int fstat_calls;
	int lstat_calls;
	int unlink_calls;
	int rmdir_calls;
	int link_calls;
	int mkdir_calls;
	int lchown_calls;
	int chmod_calls;
	int utimensat_calls;
	int opendir_calls;
	int readdir_calls;
	int closedir_calls;
	int realpath_calls;
	int readlink_calls;
} ark_fault_t;

extern ark_fault_t ark_fault;

void fault_reset(void);
void fault_inject(int which, int fail_on_call_n, int errno_value);

ssize_t ark_stub_read(int fd, void *buf, size_t count);
ssize_t ark_stub_write(int fd, const void *buf, size_t count);
int ark_stub_open(const char *path, int flags, ...);
int ark_stub_close(int fd);
int ark_stub_fstat(int fd, struct stat *sb);
int ark_stub_lstat(const char *path, struct stat *sb);
int ark_stub_unlink(const char *path);
int ark_stub_rmdir(const char *path);
int ark_stub_link(const char *oldpath, const char *newpath);
int ark_stub_mkdir(const char *path, mode_t mode);
int ark_stub_lchown(const char *path, uid_t owner, gid_t group);
int ark_stub_chmod(const char *path, mode_t mode);
int ark_stub_utimensat(int fd, const char *path, const struct timespec times[2],
                       int flags);
DIR *ark_stub_opendir(const char *path);
struct dirent *ark_stub_readdir(DIR *dirp);
int ark_stub_closedir(DIR *dirp);
char *ark_stub_realpath(const char *path, char *resolved_path);
ssize_t ark_stub_readlink(const char *path, char *buf, size_t bufsiz);

#define ARK_READ ark_stub_read
#define ARK_WRITE ark_stub_write
#define ARK_OPEN ark_stub_open
#define ARK_CLOSE ark_stub_close
#define ARK_FSTAT ark_stub_fstat
#define ARK_LSTAT ark_stub_lstat
#define ARK_UNLINK ark_stub_unlink
#define ARK_RMDIR ark_stub_rmdir
#define ARK_LINK ark_stub_link
#define ARK_MKDIR ark_stub_mkdir
#define ARK_LCHOWN ark_stub_lchown
#define ARK_CHMOD ark_stub_chmod
#define ARK_UTIMENSAT ark_stub_utimensat
#define ARK_OPENDIR ark_stub_opendir
#define ARK_READDIR ark_stub_readdir
#define ARK_CLOSEDIR ark_stub_closedir
#define ARK_REALPATH ark_stub_realpath
#define ARK_READLINK ark_stub_readlink

#else

#define ARK_READ read
#define ARK_WRITE write
#define ARK_OPEN open
#define ARK_CLOSE close
#define ARK_FSTAT fstat
#define ARK_LSTAT lstat
#define ARK_UNLINK unlink
#define ARK_RMDIR rmdir
#define ARK_LINK link
#define ARK_MKDIR mkdir
#define ARK_LCHOWN lchown
#define ARK_CHMOD chmod
#define ARK_UTIMENSAT utimensat
#define ARK_OPENDIR opendir
#define ARK_READDIR readdir
#define ARK_CLOSEDIR closedir
#define ARK_REALPATH realpath
#define ARK_READLINK readlink

#endif

#endif /* ARK_INTERNAL_H */
