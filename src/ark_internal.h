#ifndef ARK_INTERNAL_H
#define ARK_INTERNAL_H

/*
 * ark_internal.h - shared internal types and syscall wrapper macros.
 *
 * Not part of the public API. Source files use ARK_* wrappers so test
 * builds can inject syscall failures through ARK_TEST stubs.
 */

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
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
	ARK_FAULT_OPENAT,
	ARK_FAULT_CLOSE,
	ARK_FAULT_LSEEK,
	ARK_FAULT_FSTAT,
	ARK_FAULT_FSTATAT,
	ARK_FAULT_LSTAT,
	ARK_FAULT_UNLINK,
	ARK_FAULT_UNLINKAT,
	ARK_FAULT_RMDIR,
	ARK_FAULT_LINK,
	ARK_FAULT_LINKAT,
	ARK_FAULT_MKDIR,
	ARK_FAULT_MKDIRAT,
	ARK_FAULT_SYMLINKAT,
	ARK_FAULT_LCHOWN,
	ARK_FAULT_FCHOWN,
	ARK_FAULT_FCHOWNAT,
	ARK_FAULT_CHMOD,
	ARK_FAULT_FCHMOD,
	ARK_FAULT_FCHMODAT,
	ARK_FAULT_UTIMENSAT,
	ARK_FAULT_FUTIMENS,
	ARK_FAULT_OPENDIR,
	ARK_FAULT_READDIR,
	ARK_FAULT_CLOSEDIR,
	ARK_FAULT_REALPATH,
	ARK_FAULT_READLINK,
	ARK_FAULT_PTHREAD_CREATE,
	ARK_FAULT_PTHREAD_MUTEX_INIT,
	ARK_FAULT_PTHREAD_COND_INIT,
};

typedef struct ark_fault {
	int which;
	int fail_on_call_n;
	int errno_value;
	int read_calls;
	int write_calls;
	int open_calls;
	int openat_calls;
	int close_calls;
	int lseek_calls;
	int fstat_calls;
	int fstatat_calls;
	int lstat_calls;
	int unlink_calls;
	int unlinkat_calls;
	int rmdir_calls;
	int link_calls;
	int linkat_calls;
	int mkdir_calls;
	int mkdirat_calls;
	int symlinkat_calls;
	int lchown_calls;
	int fchown_calls;
	int fchownat_calls;
	int chmod_calls;
	int fchmod_calls;
	int fchmodat_calls;
	int utimensat_calls;
	int futimens_calls;
	int opendir_calls;
	int readdir_calls;
	int closedir_calls;
	int realpath_calls;
	int readlink_calls;
	int pthread_create_calls;
	int pthread_mutex_init_calls;
	int pthread_cond_init_calls;
	/*
	 * Worker-start handshake for pool startup tests. Worker threads read
	 * and write these fields, so access them only with __atomic builtins.
	 * cond_wait_delay_ms > 0 makes the first ARK_PTHREAD_COND_WAIT set
	 * cond_wait_entered and sleep before waiting, and makes an injected
	 * ARK_PTHREAD_CREATE failure wait for cond_wait_entered first.
	 */
	int cond_wait_delay_ms;
	int cond_wait_entered;
} ark_fault_t;

extern ark_fault_t ark_fault;

void fault_reset(void);
void fault_inject(int which, int fail_on_call_n, int errno_value);

ssize_t ark_stub_read(int fd, void *buf, size_t count);
ssize_t ark_stub_write(int fd, const void *buf, size_t count);
int ark_stub_open(const char *path, int flags, ...);
int ark_stub_openat(int fd, const char *path, int flags, ...);
int ark_stub_close(int fd);
off_t ark_stub_lseek(int fd, off_t offset, int whence);
int ark_stub_fstat(int fd, struct stat *sb);
int ark_stub_fstatat(int fd, const char *path, struct stat *sb, int flags);
int ark_stub_lstat(const char *path, struct stat *sb);
int ark_stub_unlink(const char *path);
int ark_stub_unlinkat(int fd, const char *path, int flags);
int ark_stub_rmdir(const char *path);
int ark_stub_link(const char *oldpath, const char *newpath);
int ark_stub_linkat(int oldfd, const char *oldpath, int newfd,
                    const char *newpath, int flags);
int ark_stub_mkdir(const char *path, mode_t mode);
int ark_stub_mkdirat(int fd, const char *path, mode_t mode);
int ark_stub_symlinkat(const char *target, int fd, const char *linkpath);
int ark_stub_lchown(const char *path, uid_t owner, gid_t group);
int ark_stub_fchown(int fd, uid_t owner, gid_t group);
int ark_stub_fchownat(int fd, const char *path, uid_t owner, gid_t group,
                      int flags);
int ark_stub_chmod(const char *path, mode_t mode);
int ark_stub_fchmod(int fd, mode_t mode);
int ark_stub_fchmodat(int fd, const char *path, mode_t mode, int flags);
int ark_stub_utimensat(int fd, const char *path, const struct timespec times[2],
                       int flags);
int ark_stub_futimens(int fd, const struct timespec times[2]);
DIR *ark_stub_opendir(const char *path);
struct dirent *ark_stub_readdir(DIR *dirp);
int ark_stub_closedir(DIR *dirp);
char *ark_stub_realpath(const char *path, char *resolved_path);
ssize_t ark_stub_readlink(const char *path, char *buf, size_t bufsiz);
int ark_stub_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                            void *(*start)(void *), void *arg);
int ark_stub_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int ark_stub_pthread_mutex_init(pthread_mutex_t *mutex,
                                const pthread_mutexattr_t *attr);
int ark_stub_pthread_cond_init(pthread_cond_t *cond,
                               const pthread_condattr_t *attr);

#define ARK_READ ark_stub_read
#define ARK_WRITE ark_stub_write
#define ARK_OPEN ark_stub_open
#define ARK_OPENAT ark_stub_openat
#define ARK_CLOSE ark_stub_close
#define ARK_LSEEK ark_stub_lseek
#define ARK_FSTAT ark_stub_fstat
#define ARK_FSTATAT ark_stub_fstatat
#define ARK_LSTAT ark_stub_lstat
#define ARK_UNLINK ark_stub_unlink
#define ARK_UNLINKAT ark_stub_unlinkat
#define ARK_RMDIR ark_stub_rmdir
#define ARK_LINK ark_stub_link
#define ARK_LINKAT ark_stub_linkat
#define ARK_MKDIR ark_stub_mkdir
#define ARK_MKDIRAT ark_stub_mkdirat
#define ARK_SYMLINKAT ark_stub_symlinkat
#define ARK_LCHOWN ark_stub_lchown
#define ARK_FCHOWN ark_stub_fchown
#define ARK_FCHOWNAT ark_stub_fchownat
#define ARK_CHMOD ark_stub_chmod
#define ARK_FCHMOD ark_stub_fchmod
#define ARK_FCHMODAT ark_stub_fchmodat
#define ARK_UTIMENSAT ark_stub_utimensat
#define ARK_FUTIMENS ark_stub_futimens
#define ARK_OPENDIR ark_stub_opendir
#define ARK_READDIR ark_stub_readdir
#define ARK_CLOSEDIR ark_stub_closedir
#define ARK_REALPATH ark_stub_realpath
#define ARK_READLINK ark_stub_readlink
#define ARK_PTHREAD_CREATE ark_stub_pthread_create
#define ARK_PTHREAD_COND_WAIT ark_stub_pthread_cond_wait
#define ARK_PTHREAD_MUTEX_INIT ark_stub_pthread_mutex_init
#define ARK_PTHREAD_COND_INIT ark_stub_pthread_cond_init

#else

#define ARK_READ read
#define ARK_WRITE write
#define ARK_OPEN open
#define ARK_OPENAT openat
#define ARK_CLOSE close
#define ARK_LSEEK lseek
#define ARK_FSTAT fstat
#define ARK_FSTATAT fstatat
#define ARK_LSTAT lstat
#define ARK_UNLINK unlink
#define ARK_UNLINKAT unlinkat
#define ARK_RMDIR rmdir
#define ARK_LINK link
#define ARK_LINKAT linkat
#define ARK_MKDIR mkdir
#define ARK_MKDIRAT mkdirat
#define ARK_SYMLINKAT symlinkat
#define ARK_LCHOWN lchown
#define ARK_FCHOWN fchown
#define ARK_FCHOWNAT fchownat
#define ARK_CHMOD chmod
#define ARK_FCHMOD fchmod
#define ARK_FCHMODAT fchmodat
#define ARK_UTIMENSAT utimensat
#define ARK_FUTIMENS futimens
#define ARK_OPENDIR opendir
#define ARK_READDIR readdir
#define ARK_CLOSEDIR closedir
#define ARK_REALPATH realpath
#define ARK_READLINK readlink
#define ARK_PTHREAD_CREATE pthread_create
#define ARK_PTHREAD_COND_WAIT pthread_cond_wait
#define ARK_PTHREAD_MUTEX_INIT pthread_mutex_init
#define ARK_PTHREAD_COND_INIT pthread_cond_init

#endif

#endif /* ARK_INTERNAL_H */
