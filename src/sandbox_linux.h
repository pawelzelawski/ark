#ifndef ARK_SANDBOX_LINUX_H
#define ARK_SANDBOX_LINUX_H

/*
 * sandbox_linux.h - Linux seccomp-bpf system call filter per subcommand.
 *
 * Internal to ark, not a library component. main.c installs the filter
 * after Landlock and after the worker pool has started:
 *
 *   if (ark_seccomp_apply(ARK_SECCOMP_LIST) != 0) ... fail
 *
 * The allowlists mirror the OpenBSD pledge promises of each subcommand.
 * See ARCHITECTURE.md section 10.4 for the policy, the promise groups and
 * how the lists are derived.
 */

/*
 * Exit status of a process stopped by the filter: a system call outside
 * the subcommand's allowlist was attempted. See ARCHITECTURE.md §10.4.
 */
#define ARK_SECCOMP_EXIT_BLOCKED 70

typedef enum {
	ARK_SECCOMP_CREATE = 0,
	ARK_SECCOMP_EXTRACT,
	ARK_SECCOMP_LIST,
	ARK_SECCOMP_VERIFY,
	ARK_SECCOMP_GENERATE_READER,
} ark_seccomp_profile_t;

/*
 * ark_seccomp_apply - install the subcommand's filter on every thread.
 *
 * Installs a SIGSYS handler that reports a blocked call on stderr and
 * exits with ARK_SECCOMP_EXIT_BLOCKED, sets PR_SET_NO_NEW_PRIVS, then
 * installs the filter with SECCOMP_FILTER_FLAG_TSYNC so threads that
 * already exist (the worker pool) are filtered too. Irreversible.
 *
 * Returns 0 on success, otherwise an errno value: EINVAL for an unknown
 * profile, E2BIG if the program does not fit (a bug), EAGAIN if a thread
 * could not be synchronised, or the errno of sigaction, prctl or
 * seccomp (ENOSYS when the kernel or valgrind lacks seccomp).
 */
int ark_seccomp_apply(ark_seccomp_profile_t profile);

#endif /* ARK_SANDBOX_LINUX_H */
