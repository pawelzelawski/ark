#ifndef ARK_INTERNAL_H
#define ARK_INTERNAL_H

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef ARK_TEST
/* Placeholder: ARK_TEST stub declarations are added in Phase 1.3. */
#else
#define ARK_READ		read
#define ARK_WRITE		write
#define ARK_OPEN		open
#define ARK_CLOSE		close
#define ARK_LSTAT		lstat
#define ARK_UNLINK		unlink
#define ARK_RMDIR		rmdir
#define ARK_LINK		link
#define ARK_MKDIR		mkdir
#define ARK_LCHOWN		lchown
#define ARK_CHMOD		chmod
#define ARK_UTIMENSAT	utimensat
#define ARK_OPENDIR		opendir
#define ARK_READDIR		readdir
#define ARK_CLOSEDIR	closedir
#define ARK_REALPATH	realpath
#endif

#endif /* ARK_INTERNAL_H */

