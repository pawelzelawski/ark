/*
 * sandbox_linux.c - Linux seccomp-bpf system call filter per subcommand.
 *
 * Builds one classic BPF program per subcommand from promise groups that
 * mirror the subcommand's OpenBSD pledge string (stdio, rpath, wpath, cpath,
 * fattr, pthread) and installs it on every thread of the process. Landlock
 * restricts paths, this filter restricts system calls; together they are
 * the Linux counterpart of unveil + pledge. A call outside the allowlist
 * raises SIGSYS; the handler reports the call number and exits with
 * ARK_SECCOMP_EXIT_BLOCKED. See ARCHITECTURE.md section 10.4.
 *
 * Supported: x86-64 and arm64 (the Linux architectures in the quality
 * gates). Any other architecture stops the build, so a port gets a filter
 * that was derived and tested for it rather than none.
 */

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include <asm/ioctls.h>
#include <asm/termbits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "sandbox_linux.h"

extern long syscall(long, ...);

#if defined(__x86_64__)
#define ARK_SECCOMP_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARK_SECCOMP_ARCH AUDIT_ARCH_AARCH64
#else
#error                                                                         \
    "ark: the seccomp filter supports Linux on x86-64 and arm64 only (ARCHITECTURE.md section 10.4)"
#endif

/* Promise groups, named after the OpenBSD pledge promises they mirror. */
enum {
	G_STDIO = 1U << 0,
	G_RPATH = 1U << 1,
	G_WPATH = 1U << 2,
	G_CPATH = 1U << 3,
	G_FATTR = 1U << 4,
	G_PTHREAD = 1U << 5,
	/* Sanitizer and valgrind builds only (ARK_SECCOMP_SANITIZER). */
	G_SANITIZER = 1U << 6,
};

/* What a matching rule does. Every check ends in a return. */
typedef enum {
	CHECK_ALLOW = 0,
	CHECK_EACCES,      /* fail with EACCES, process goes on */
	CHECK_EPERM,       /* fail with EPERM, process goes on */
	CHECK_NO_EXEC,     /* args[2] (prot) without PROT_EXEC */
	CHECK_OPEN_RDONLY, /* args[2] (flags) opens for reading only */
	CHECK_TTY_QUERY,   /* args[1] (request) is TCGETS or TCGETS2 */
	CHECK_CONNECTED,   /* args[4] (dest addr) is NULL: connected socket */
} ark_seccomp_check_t;

typedef struct {
	int nr;
	unsigned groups;
	ark_seccomp_check_t check;
} ark_seccomp_rule_t;

/*
 * Rules in match order: for each call number only the first rule whose
 * group the profile holds is emitted, so broader rules come first (wpath's
 * unrestricted openat before rpath's read-only one). Frequent calls come
 * early: the program is a linear list of comparisons.
 *
 * Derived with strace from every subcommand's normal and error paths
 * (glibc, x86-64) and widened to the equivalent calls another glibc or
 * arm64 makes for the same operation. See ARCHITECTURE.md §10.4.
 *
 * NOTE: the __x86_64__ blocks hold the old path-based calls that arm64
 * does not have (glibc on arm64 uses the *at forms). clone3, rseq, statx
 * and renameat are in every kernel header set that has linux/landlock.h
 * (Linux 5.13+), which ark requires; only fchmodat2 (6.6) is optional.
 */
static const ark_seccomp_rule_t g_rules[] = {
#ifdef ARK_SECCOMP_SANITIZER
    /* ASan/UBSan runtime: startup, reports, symbolizer fallback. */
    {SYS_gettid, G_SANITIZER, CHECK_ALLOW},
    {SYS_sched_getaffinity, G_SANITIZER, CHECK_ALLOW},
    {SYS_sigaltstack, G_SANITIZER, CHECK_ALLOW},
    {SYS_sched_yield, G_SANITIZER, CHECK_ALLOW},
    {SYS_readlinkat, G_SANITIZER, CHECK_ALLOW},
    {SYS_prctl, G_SANITIZER, CHECK_ALLOW},
    {SYS_tgkill, G_SANITIZER, CHECK_ALLOW},
    {SYS_rt_sigaction, G_SANITIZER, CHECK_ALLOW},
    {SYS_getrlimit, G_SANITIZER, CHECK_ALLOW},
    {SYS_prlimit64, G_SANITIZER, CHECK_ALLOW},
    {SYS_nanosleep, G_SANITIZER, CHECK_ALLOW},
    {SYS_clock_nanosleep, G_SANITIZER, CHECK_ALLOW},
    {SYS_getrusage, G_SANITIZER, CHECK_ALLOW},
    {SYS_uname, G_SANITIZER, CHECK_ALLOW},
    {SYS_getppid, G_SANITIZER, CHECK_ALLOW},
    {SYS_getdents64, G_SANITIZER, CHECK_ALLOW},
#ifdef __x86_64__
    {SYS_readlink, G_SANITIZER, CHECK_ALLOW},
    {SYS_open, G_SANITIZER, CHECK_ALLOW},
#endif
    /* Process creation fails: the runtimes fall back (no symbolizer). */
    {SYS_pipe2, G_SANITIZER, CHECK_EPERM},
    {SYS_clone, G_SANITIZER, CHECK_EPERM},
    {SYS_execve, G_SANITIZER, CHECK_EPERM},
    {SYS_wait4, G_SANITIZER, CHECK_EPERM},
    {SYS_clone3, G_SANITIZER, CHECK_EPERM},
#ifdef __x86_64__
    {SYS_pipe, G_SANITIZER, CHECK_EPERM},
    {SYS_fork, G_SANITIZER, CHECK_EPERM},
    {SYS_vfork, G_SANITIZER, CHECK_EPERM},
#endif
#endif
    /* stdio: I/O on open descriptors, memory, time, exit. */
    {SYS_futex, G_STDIO, CHECK_ALLOW},
    {SYS_pread64, G_STDIO, CHECK_ALLOW},
    {SYS_read, G_STDIO, CHECK_ALLOW},
    {SYS_write, G_STDIO, CHECK_ALLOW},
    {SYS_close, G_STDIO, CHECK_ALLOW},
    {SYS_lseek, G_STDIO, CHECK_ALLOW},
    {SYS_fstat, G_STDIO, CHECK_ALLOW},
    {SYS_readv, G_STDIO, CHECK_ALLOW},
    {SYS_writev, G_STDIO, CHECK_ALLOW},
    {SYS_brk, G_STDIO, CHECK_ALLOW},
    {SYS_mmap, G_STDIO, CHECK_NO_EXEC},
    {SYS_mprotect, G_STDIO, CHECK_NO_EXEC},
    {SYS_munmap, G_STDIO, CHECK_ALLOW},
    {SYS_mremap, G_STDIO, CHECK_ALLOW},
    {SYS_madvise, G_STDIO, CHECK_ALLOW},
    {SYS_geteuid, G_STDIO, CHECK_ALLOW},
    {SYS_getuid, G_STDIO, CHECK_ALLOW},
    {SYS_getegid, G_STDIO, CHECK_ALLOW},
    {SYS_getgid, G_STDIO, CHECK_ALLOW},
    {SYS_getpid, G_STDIO, CHECK_ALLOW},
    {SYS_getrandom, G_STDIO, CHECK_ALLOW},
    {SYS_clock_gettime, G_STDIO, CHECK_ALLOW},
    {SYS_gettimeofday, G_STDIO, CHECK_ALLOW},
    {SYS_rt_sigprocmask, G_STDIO, CHECK_ALLOW},
    {SYS_rt_sigreturn, G_STDIO, CHECK_ALLOW},
    {SYS_exit_group, G_STDIO, CHECK_ALLOW},
    {SYS_ioctl, G_STDIO, CHECK_TTY_QUERY},
    /* syslog: send on the socket openlog(LOG_NDELAY) connected; no new
     * socket, no reconnect (the message is lost, stderr still has it). */
    {SYS_sendto, G_STDIO, CHECK_CONNECTED},
    {SYS_socket, G_STDIO, CHECK_EACCES},
    {SYS_connect, G_STDIO, CHECK_EACCES},
    /* wpath + cpath: opening for writing and creating. */
    {SYS_openat, G_WPATH | G_CPATH, CHECK_ALLOW},
    /* rpath: opening for reading, metadata, directory listing. */
    {SYS_openat, G_RPATH, CHECK_OPEN_RDONLY},
    {SYS_newfstatat, G_RPATH, CHECK_ALLOW},
    {SYS_getdents64, G_RPATH, CHECK_ALLOW},
    {SYS_readlinkat, G_RPATH, CHECK_ALLOW},
    {SYS_statx, G_RPATH, CHECK_ALLOW},
#ifdef __x86_64__
    {SYS_readlink, G_RPATH, CHECK_ALLOW},
#endif
    /* wpath: writing to files. */
    {SYS_fsync, G_WPATH, CHECK_ALLOW},
    {SYS_fdatasync, G_WPATH, CHECK_ALLOW},
    {SYS_ftruncate, G_WPATH, CHECK_ALLOW},
    {SYS_pwrite64, G_WPATH, CHECK_ALLOW},
    /* cpath: creating and removing names. */
    {SYS_mkdirat, G_CPATH, CHECK_ALLOW},
    {SYS_unlinkat, G_CPATH, CHECK_ALLOW},
    {SYS_symlinkat, G_CPATH, CHECK_ALLOW},
    {SYS_linkat, G_CPATH, CHECK_ALLOW},
    {SYS_renameat2, G_CPATH, CHECK_ALLOW},
    {SYS_renameat, G_CPATH, CHECK_ALLOW},
#ifdef __x86_64__
    {SYS_mkdir, G_CPATH, CHECK_ALLOW},
    {SYS_unlink, G_CPATH, CHECK_ALLOW},
    {SYS_rmdir, G_CPATH, CHECK_ALLOW},
    {SYS_link, G_CPATH, CHECK_ALLOW},
    {SYS_symlink, G_CPATH, CHECK_ALLOW},
    {SYS_rename, G_CPATH, CHECK_ALLOW},
#endif
    /* fattr: ownership, mode, times. */
    {SYS_utimensat, G_FATTR, CHECK_ALLOW},
    {SYS_fchmod, G_FATTR, CHECK_ALLOW},
    {SYS_fchmodat, G_FATTR, CHECK_ALLOW},
    {SYS_fchown, G_FATTR, CHECK_ALLOW},
    {SYS_fchownat, G_FATTR, CHECK_ALLOW},
#ifdef SYS_fchmodat2
    {SYS_fchmodat2, G_FATTR, CHECK_ALLOW},
#endif
#ifdef __x86_64__
    {SYS_lchown, G_FATTR, CHECK_ALLOW},
    {SYS_chmod, G_FATTR, CHECK_ALLOW},
#endif
    /* pthread: the running pool (it is started before the filter, so no
     * clone/clone3: threads are never created afterwards). */
    {SYS_exit, G_PTHREAD, CHECK_ALLOW},
    {SYS_sched_yield, G_PTHREAD, CHECK_ALLOW},
    {SYS_set_robust_list, G_PTHREAD, CHECK_ALLOW},
    {SYS_rseq, G_PTHREAD, CHECK_ALLOW},
};

/* Profiles: the same promises as the OpenBSD pledge strings (§10.4). */
static unsigned profile_groups(ark_seccomp_profile_t profile)
{
	unsigned extra = 0;

#ifdef ARK_SECCOMP_SANITIZER
	extra = G_SANITIZER;
#endif
	switch (profile) {
	case ARK_SECCOMP_CREATE:
	case ARK_SECCOMP_EXTRACT:
		return extra | G_STDIO | G_RPATH | G_WPATH | G_CPATH | G_FATTR |
		       G_PTHREAD;
	case ARK_SECCOMP_LIST:
		return extra | G_STDIO | G_RPATH;
	case ARK_SECCOMP_VERIFY:
		return extra | G_STDIO | G_RPATH | G_PTHREAD;
	case ARK_SECCOMP_GENERATE_READER:
		return extra | G_STDIO | G_RPATH | G_WPATH | G_CPATH | G_FATTR;
	default:
		return 0;
	}
}

#define ARK_SECCOMP_MAX_INSNS 512U
/* x32 system calls carry this bit in the number (x86-64 only). */
#define ARK_SECCOMP_X32_BIT 0x40000000U

#define ARG_LO(n)                                                              \
	((uint32_t)(offsetof(struct seccomp_data, args) +                      \
	            (size_t)(n) * sizeof(uint64_t)))
#define ARG_HI(n) (ARG_LO(n) + 4U)

typedef struct {
	struct sock_filter *insns;
	size_t len;
	size_t cap;
	int overflow;
} ark_bpf_t;

static void emit(ark_bpf_t *p, uint16_t code, uint8_t jt, uint8_t jf,
                 uint32_t k)
{
	if (p->len >= p->cap) {
		p->overflow = 1;
		return;
	}
	p->insns[p->len].code = code;
	p->insns[p->len].jt = jt;
	p->insns[p->len].jf = jf;
	p->insns[p->len].k = k;
	p->len++;
}

static void emit_ret(ark_bpf_t *p, uint32_t action)
{
	emit(p, BPF_RET | BPF_K, 0, 0, action);
}

static void emit_load(ark_bpf_t *p, uint32_t offset)
{
	emit(p, BPF_LD | BPF_W | BPF_ABS, 0, 0, offset);
}

/* Instructions check_emit produces for check (all end in a return). */
static uint8_t check_len(ark_seccomp_check_t check)
{
	switch (check) {
	case CHECK_NO_EXEC:
	case CHECK_OPEN_RDONLY:
		return 4;
	case CHECK_TTY_QUERY:
		return 5;
	case CHECK_CONNECTED:
		return 6;
	default:
		return 1;
	}
}

/*
 * NOTE: the argument checks read the low 32-bit word of the argument (both
 * supported architectures are little-endian): prot, flags and the ioctl
 * request are 32-bit values to the kernel. The destination address of
 * sendto is a pointer, so both words are compared.
 */
static void check_emit(ark_bpf_t *p, ark_seccomp_check_t check)
{
	switch (check) {
	case CHECK_EACCES:
		emit_ret(p, SECCOMP_RET_ERRNO | (uint32_t)EACCES);
		break;
	case CHECK_EPERM:
		emit_ret(p, SECCOMP_RET_ERRNO | (uint32_t)EPERM);
		break;
	case CHECK_NO_EXEC:
		emit_load(p, ARG_LO(2));
		emit(p, BPF_JMP | BPF_JSET | BPF_K, 0, 1, (uint32_t)PROT_EXEC);
		emit_ret(p, SECCOMP_RET_TRAP);
		emit_ret(p, SECCOMP_RET_ALLOW);
		break;
	case CHECK_OPEN_RDONLY:
		emit_load(p, ARG_LO(2));
		emit(p, BPF_JMP | BPF_JSET | BPF_K, 0, 1,
		     (uint32_t)(O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND));
		emit_ret(p, SECCOMP_RET_TRAP);
		emit_ret(p, SECCOMP_RET_ALLOW);
		break;
	case CHECK_TTY_QUERY:
		emit_load(p, ARG_LO(1));
		emit(p, BPF_JMP | BPF_JEQ | BPF_K, 2, 0, (uint32_t)TCGETS);
		emit(p, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, (uint32_t)TCGETS2);
		emit_ret(p, SECCOMP_RET_TRAP);
		emit_ret(p, SECCOMP_RET_ALLOW);
		break;
	case CHECK_CONNECTED:
		emit_load(p, ARG_LO(4));
		emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0);
		emit_load(p, ARG_HI(4));
		emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
		emit_ret(p, SECCOMP_RET_ALLOW);
		emit_ret(p, SECCOMP_RET_TRAP);
		break;
	default:
		emit_ret(p, SECCOMP_RET_ALLOW);
		break;
	}
}

static int rule_emitted_before(size_t idx, unsigned groups)
{
	size_t i;

	for (i = 0; i < idx; i++) {
		if (g_rules[i].nr == g_rules[idx].nr &&
		    (g_rules[i].groups & groups) != 0)
			return 1;
	}
	return 0;
}

/*
 * build_program - emit the filter for groups into p.
 *
 * Layout: architecture check (anything but the build's own architecture is
 * killed: i386 compat calls on x86-64 included), x32 numbers killed, then
 * one comparison per allowed call, each followed by its check; anything
 * else traps (SIGSYS, reported by the handler).
 */
static void build_program(ark_bpf_t *p, unsigned groups)
{
	size_t i;

	emit_load(p, (uint32_t)offsetof(struct seccomp_data, arch));
	emit(p, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, ARK_SECCOMP_ARCH);
	emit_ret(p, SECCOMP_RET_KILL_PROCESS);
	emit_load(p, (uint32_t)offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
	emit(p, BPF_JMP | BPF_JGE | BPF_K, 0, 1, ARK_SECCOMP_X32_BIT);
	emit_ret(p, SECCOMP_RET_KILL_PROCESS);
#endif
	for (i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); i++) {
		if ((g_rules[i].groups & groups) == 0 ||
		    rule_emitted_before(i, groups))
			continue;
		emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0,
		     check_len(g_rules[i].check), (uint32_t)g_rules[i].nr);
		check_emit(p, g_rules[i].check);
	}
	emit_ret(p, SECCOMP_RET_TRAP);
}

static atomic_flag g_sigsys_reported = ATOMIC_FLAG_INIT;

/*
 * on_sigsys - report a blocked call and exit.
 *
 * SAFETY: async-signal-safe only: atomic_flag, write(2), _exit(2). Raw
 * write, not ARK_WRITE: the fault-injection stub is not signal-safe, and
 * this path must never be faked. rt_sigaction is in no release allowlist,
 * so the handler cannot be replaced once the filter is on.
 */
/* The signature is sigaction's sa_sigaction: info cannot be const. */
/* cppcheck-suppress constParameterCallback */
static void on_sigsys(int sig, siginfo_t *info, void *uctx)
{
	static const char head[] = "ark: system call ";
	static const char tail[] =
	    " blocked by the seccomp sandbox; please report this as a bug\n";
	char msg[sizeof(head) + 12 + sizeof(tail)];
	char digits[12];
	size_t len;
	size_t n;
	size_t i;
	unsigned nr;

	(void)sig;
	(void)uctx;
	if (atomic_flag_test_and_set(&g_sigsys_reported))
		_exit(ARK_SECCOMP_EXIT_BLOCKED);
	nr = info->si_syscall < 0 ? 0U : (unsigned)info->si_syscall;
	n = 0;
	do {
		digits[n++] = (char)('0' + nr % 10U);
		nr /= 10U;
	} while (nr != 0U && n < sizeof(digits));
	len = 0;
	for (i = 0; i + 1 < sizeof(head); i++)
		msg[len++] = head[i];
	while (n > 0)
		msg[len++] = digits[--n];
	for (i = 0; i + 1 < sizeof(tail); i++)
		msg[len++] = tail[i];
	(void)write(STDERR_FILENO, msg, len);
	_exit(ARK_SECCOMP_EXIT_BLOCKED);
}

int ark_seccomp_apply(ark_seccomp_profile_t profile)
{
	struct sock_filter insns[ARK_SECCOMP_MAX_INSNS];
	ark_bpf_t p = {insns, 0, ARK_SECCOMP_MAX_INSNS, 0};
	struct sock_fprog prog;
	struct sigaction sa = {0};
	unsigned groups;
	long rc;

	groups = profile_groups(profile);
	if (groups == 0)
		return EINVAL;
	build_program(&p, groups);
	if (p.overflow)
		return E2BIG;

	sa.sa_sigaction = on_sigsys;
	sa.sa_flags = SA_SIGINFO;
	(void)sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSYS, &sa, NULL) != 0)
		return errno;

	/* SAFETY: NO_NEW_PRIVS is required for an unprivileged filter; it is
	 * already set when Landlock ran first (ARCHITECTURE.md §10.4). */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return errno;

	prog.len = (unsigned short)p.len;
	prog.filter = insns;
	/*
	 * SAFETY: TSYNC applies the filter to every thread of the process, so
	 * the worker pool started before this call is filtered too. A positive
	 * result is the id of a thread that could not be synchronised.
	 */
	rc = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
	             SECCOMP_FILTER_FLAG_TSYNC, &prog);
	if (rc < 0)
		return errno;
	if (rc > 0)
		return EAGAIN;
	return 0;
}

#else

/* Not Linux: nothing to build (OpenBSD uses pledge, see main.c). */
typedef int ark_sandbox_linux_unused_t;

#endif /* __linux__ */
