#ifndef CHEVRON_INTERNAL_H
#define CHEVRON_INTERNAL_H

/*
 * chevron_internal.h - internal types, function declarations, and
 * syscall wrapper macro definitions.
 *
 * Not part of the public API. Never included by embedders.
 * See ARCHITECTURE.md for design rationale.
 * See TESTING.md §2.3 for fault injection infrastructure details.
 */

#include "../include/chevron.h"

/*
 * Syscall wrapper macros for fault injection.
 *
 * In production builds: each macro expands directly to the real syscall name
 * with zero overhead.
 *
 * In test builds (-DCHEVRON_TEST): each macro expands to a stub function
 * defined in tests/chevron_stubs.c. Stubs check the fault injection state
 * struct (chevron_fault) and either return an injected error or call the
 * real syscall.
 */
#ifndef CHEVRON_TEST
#define CHEVRON_OPEN open
#define CHEVRON_LINKAT linkat
#define CHEVRON_MKOSTEMP chevron_mkostemp_cloexec
#define CHEVRON_WRITE write
#define CHEVRON_FSYNC fsync
#define CHEVRON_CLOSE close
#define CHEVRON_FSTATAT fstatat
#define CHEVRON_FCHMOD fchmod
#define CHEVRON_FCHOWN fchown
#define CHEVRON_RENAMEAT renameat
#define CHEVRON_UNLINKAT unlinkat
#else /* CHEVRON_TEST */

/*
 * In test builds, each CHEVRON_* macro expands to a stub function.
 * Stub functions are defined in tests/chevron_stubs.c.
 *
 * Syscall identifiers - used in chevron_fault_t.which_syscall to select
 * which stub should inject a fault.
 */
typedef enum {
	CHEVRON_SYSCALL_NONE     = 0,
	CHEVRON_SYSCALL_OPEN     = 1,
	CHEVRON_SYSCALL_LINKAT   = 2,
	CHEVRON_SYSCALL_MKOSTEMP = 3,
	CHEVRON_SYSCALL_WRITE    = 4,
	CHEVRON_SYSCALL_FSYNC    = 5,
	CHEVRON_SYSCALL_CLOSE    = 6,
	CHEVRON_SYSCALL_FSTATAT  = 7,
	CHEVRON_SYSCALL_FCHMOD   = 8,
	CHEVRON_SYSCALL_FCHOWN   = 9,
	CHEVRON_SYSCALL_RENAMEAT = 10,
	CHEVRON_SYSCALL_UNLINKAT = 11,
} chevron_syscall_id_t;

/*
 * chevron_fault_t - fault injection control struct.
 *
 * which_syscall   - which syscall to fault (CHEVRON_SYSCALL_NONE = no fault).
 * fail_on_call_n  - fault on the Nth call to which_syscall (1-based).
 * errno_value     - errno to set when injecting a fault.
 *
 * Per-syscall call counters track how many times each stub has been called.
 * Tests reset the struct before each scenario.
 */
typedef struct {
	chevron_syscall_id_t which_syscall;
	int                  fail_on_call_n;
	int                  errno_value;
	size_t               write_max_bytes;

	/*
	 * Test-only knob: when non-zero, try_open_otmpfile() returns 0
	 * unconditionally (as if the kernel did not support O_TMPFILE on
	 * this filesystem), forcing the mkostemp fallback path.
	 */
	int force_no_otmpfile;

	/*
	 * Secondary fault knob for unlinkat: when non-zero, every call to
	 * CHEVRON_UNLINKAT returns -1 with unlinkat_always_errno, regardless
	 * of which_syscall. Used to verify that cleanup failure does not
	 * overwrite the primary error (CHEVRON_OP_UNLINK_TMP invariant).
	 * See ARCHITECTURE.md §2 error precedence.
	 */
	int unlinkat_always_fail;
	int unlinkat_always_errno;

	/* per-syscall call counters */
	int n_open;
	int n_linkat;
	int n_mkostemp;
	int n_write;
	int n_fsync;
	int n_close;
	int n_fstatat;
	int n_fchmod;
	int n_fchown;
	int n_renameat;
	int n_unlinkat;
} chevron_fault_t;

/* Global fault injection state - defined in tests/chevron_stubs.c */
extern chevron_fault_t chevron_fault;

/* Stub function declarations */
int     chevron_stub_open(const char *path, int flags, ...);
int     chevron_stub_linkat(int olddirfd, const char *oldpath, int newdirfd,
                            const char *newpath, int flags);
int     chevron_stub_mkostemp(char *tmpl, int flags);
ssize_t chevron_stub_write(int fd, const void *buf, size_t count);
int     chevron_stub_fsync(int fd);
int     chevron_stub_close(int fd);
int chevron_stub_fstatat(int dirfd, const char *pathname, struct stat *statbuf,
                         int flags);
int chevron_stub_fchmod(int fd, mode_t mode);
int chevron_stub_fchown(int fd, uid_t owner, gid_t group);
int chevron_stub_renameat(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath);
int chevron_stub_unlinkat(int dirfd, const char *pathname, int flags);

#define CHEVRON_OPEN chevron_stub_open
#define CHEVRON_LINKAT chevron_stub_linkat
#define CHEVRON_MKOSTEMP chevron_stub_mkostemp
#define CHEVRON_WRITE chevron_stub_write
#define CHEVRON_FSYNC chevron_stub_fsync
#define CHEVRON_CLOSE chevron_stub_close
#define CHEVRON_FSTATAT chevron_stub_fstatat
#define CHEVRON_FCHMOD chevron_stub_fchmod
#define CHEVRON_FCHOWN chevron_stub_fchown
#define CHEVRON_RENAMEAT chevron_stub_renameat
#define CHEVRON_UNLINKAT chevron_stub_unlinkat

#endif /* CHEVRON_TEST */

#endif /* CHEVRON_INTERNAL_H */
