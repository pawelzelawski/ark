/*
 * test_seccomp.c - Linux seccomp-bpf filter tests (ARCHITECTURE.md §10.4).
 *
 * Each in-process test forks a child that installs one subcommand's filter
 * through ark_seccomp_apply and then makes allowed and forbidden calls; the
 * parent checks the child's exit status and stderr. The child's filter never
 * reaches the test harness. One test runs the production binary and reads
 * /proc while it waits on a FIFO archive, which shows that every ark thread
 * is filtered.
 *
 * Skipped (pass with a note) where the filter cannot run: not Linux, and the
 * TSan and valgrind test builds (ARK_TEST_NO_SECCOMP; TESTING.md). The
 * integration tests run every subcommand under the filter on Linux.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) && !defined(ARK_TEST_NO_SECCOMP)
#define ARK_SECCOMP_TESTS 1
#include <dirent.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "sandbox_linux.h"

extern long syscall(long, ...);
#endif

int test_seccomp_profiles_install(void);
int test_seccomp_blocks_unlisted_call(void);
int test_seccomp_read_only_profiles(void);
int test_seccomp_no_exec_memory_or_ioctl(void);
int test_seccomp_covers_running_threads(void);
int test_seccomp_foreign_abi_killed(void);
int test_seccomp_cli_threads_filtered(void);

#ifdef ARK_SECCOMP_TESTS

static const ark_seccomp_profile_t g_profiles[] = {
    ARK_SECCOMP_CREATE, ARK_SECCOMP_EXTRACT,         ARK_SECCOMP_LIST,
    ARK_SECCOMP_VERIFY, ARK_SECCOMP_GENERATE_READER,
};
#define PROFILE_COUNT (sizeof(g_profiles) / sizeof(g_profiles[0]))

/* Child exit status when ark_seccomp_apply itself failed. */
#define CHILD_APPLY_FAILED 90

typedef int (*child_body_t)(ark_seccomp_profile_t);

typedef struct {
	int exited;
	int code;
	int signaled;
	int sig;
	char err[512];
} child_result_t;

/*
 * run_child - fork, install profile's filter in the child, run body there.
 *
 * The child's stderr goes to a pipe the parent collects (the SIGSYS report).
 * Returns 0 when the child was reaped, -1 on a harness failure.
 */
static int run_child(ark_seccomp_profile_t profile, child_body_t body,
                     child_result_t *res)
{
	int fds[2];
	pid_t pid;
	int status;
	size_t used;
	ssize_t n;

	memset(res, 0, sizeof(*res));
	if (pipe(fds) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		return -1;
	}
	if (pid == 0) {
		(void)close(fds[0]);
		if (dup2(fds[1], STDERR_FILENO) < 0)
			_exit(CHILD_APPLY_FAILED + 1);
		(void)close(fds[1]);
		if (ark_seccomp_apply(profile) != 0)
			_exit(CHILD_APPLY_FAILED);
		_exit(body(profile));
	}
	(void)close(fds[1]);
	used = 0;
	for (;;) {
		n = read(fds[0], res->err + used, sizeof(res->err) - 1 - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
		if (used == sizeof(res->err) - 1)
			break;
	}
	res->err[used] = '\0';
	(void)close(fds[0]);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	res->exited = WIFEXITED(status);
	res->code = res->exited ? WEXITSTATUS(status) : -1;
	res->signaled = WIFSIGNALED(status);
	res->sig = res->signaled ? WTERMSIG(status) : 0;
	return 0;
}

/* The child was stopped by the filter's SIGSYS handler with its report. */
static int blocked(const child_result_t *res)
{
	return res->exited && res->code == ARK_SECCOMP_EXIT_BLOCKED &&
	       strstr(res->err, "blocked by the seccomp sandbox") != NULL;
}

/* Allowed calls: /proc status, getpid, isatty, socket fails (EACCES). */
static int body_allowed(ark_seccomp_profile_t profile)
{
	char buf[4096];
	ssize_t n;
	int fd;
	int s;

	(void)profile;
	fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n <= 0)
		return 2;
	buf[n] = '\0';
	if (strstr(buf, "Seccomp:\t2") == NULL)
		return 3;
	if (getpid() <= 0)
		return 4;
	(void)isatty(STDIN_FILENO);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s >= 0 || errno != EACCES)
		return 5;
	return 0;
}

static int body_ptrace(ark_seccomp_profile_t profile)
{
	(void)profile;
	(void)syscall(SYS_ptrace, 0L, 0L, 0L, 0L);
	return 1;
}

static int body_open_write(ark_seccomp_profile_t profile)
{
	int fd;

	(void)profile;
	fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	(void)close(fd);
	return 0;
}

static int body_open_read(ark_seccomp_profile_t profile)
{
	int fd;

	(void)profile;
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	(void)close(fd);
	return 0;
}

static int body_mmap_exec(ark_seccomp_profile_t profile)
{
	(void)profile;
	(void)mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, -1, 0);
	return 1;
}

static int body_ioctl_other(ark_seccomp_profile_t profile)
{
	int pending;

	(void)profile;
	(void)ioctl(STDIN_FILENO, FIONREAD, &pending);
	return 1;
}

#ifdef __x86_64__
static int body_x32(ark_seccomp_profile_t profile)
{
	(void)profile;
	(void)syscall(0x40000000L | (long)SYS_getpid);
	return 1;
}
#endif

static pthread_mutex_t g_thread_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_thread_cv = PTHREAD_COND_INITIALIZER;
static int g_thread_go;

/*
 * NOTE: the thread makes a harmless unlisted call (getsid). An unfiltered
 * thread's ptrace(PTRACE_TRACEME) would succeed and leave a traced thread
 * that waitpid without __WALL never reaps (the test would hang, not fail).
 */
static void *thread_unlisted(void *arg)
{
	(void)arg;
	(void)pthread_mutex_lock(&g_thread_mu);
	while (!g_thread_go)
		(void)pthread_cond_wait(&g_thread_cv, &g_thread_mu);
	(void)pthread_mutex_unlock(&g_thread_mu);
	(void)syscall(SYS_getsid, 0L);
	return NULL;
}

#endif /* ARK_SECCOMP_TESTS */

/* Every profile installs; allowed calls work; socket fails with EACCES. */
int test_seccomp_profiles_install(void)
{
#ifdef ARK_SECCOMP_TESTS
	child_result_t res;
	size_t i;

	for (i = 0; i < PROFILE_COUNT; i++) {
		if (run_child(g_profiles[i], body_allowed, &res) != 0 ||
		    !res.exited || res.code != 0)
			return -1;
	}
	if (run_child((ark_seccomp_profile_t)99, body_allowed, &res) != 0 ||
	    !res.exited || res.code != CHILD_APPLY_FAILED)
		return -1;
	return 0;
#else
	printf("seccomp tests skipped (no seccomp in this build)\n");
	return 0;
#endif
}

/* A call outside every allowlist is reported and exits with status 70. */
int test_seccomp_blocks_unlisted_call(void)
{
#ifdef ARK_SECCOMP_TESTS
	child_result_t res;
	size_t i;

	for (i = 0; i < PROFILE_COUNT; i++) {
		if (run_child(g_profiles[i], body_ptrace, &res) != 0 ||
		    !blocked(&res))
			return -1;
	}
	return 0;
#else
	return 0;
#endif
}

/* list and verify (pledge stdio rpath) may open files for reading only. */
int test_seccomp_read_only_profiles(void)
{
#ifdef ARK_SECCOMP_TESTS
	child_result_t res;
	size_t i;
	int read_only;

	for (i = 0; i < PROFILE_COUNT; i++) {
		read_only = g_profiles[i] == ARK_SECCOMP_LIST ||
		            g_profiles[i] == ARK_SECCOMP_VERIFY;
		if (run_child(g_profiles[i], body_open_read, &res) != 0 ||
		    !res.exited || res.code != 0)
			return -1;
		if (run_child(g_profiles[i], body_open_write, &res) != 0)
			return -1;
		if (read_only && !blocked(&res))
			return -1;
		if (!read_only && (!res.exited || res.code != 0))
			return -1;
	}
	return 0;
#else
	return 0;
#endif
}

/* No executable mappings; ioctl only for the terminal query of isatty. */
int test_seccomp_no_exec_memory_or_ioctl(void)
{
#ifdef ARK_SECCOMP_TESTS
	child_result_t res;
	size_t i;

	for (i = 0; i < PROFILE_COUNT; i++) {
		if (run_child(g_profiles[i], body_mmap_exec, &res) != 0 ||
		    !blocked(&res))
			return -1;
		if (run_child(g_profiles[i], body_ioctl_other, &res) != 0 ||
		    !blocked(&res))
			return -1;
	}
	return 0;
#else
	return 0;
#endif
}

/*
 * A thread started before the filter (like ark's worker pool) is filtered
 * too (SECCOMP_FILTER_FLAG_TSYNC).
 */
int test_seccomp_covers_running_threads(void)
{
#ifdef ARK_SECCOMP_TESTS
	int fds[2];
	pid_t pid;
	int status;
	char buf[512];
	ssize_t n;
	size_t used;

	if (pipe(fds) != 0)
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		pthread_t t;

		(void)close(fds[0]);
		(void)dup2(fds[1], STDERR_FILENO);
		(void)close(fds[1]);
		if (pthread_create(&t, NULL, thread_unlisted, NULL) != 0)
			_exit(91);
		if (ark_seccomp_apply(ARK_SECCOMP_VERIFY) != 0)
			_exit(CHILD_APPLY_FAILED);
		(void)pthread_mutex_lock(&g_thread_mu);
		g_thread_go = 1;
		(void)pthread_cond_broadcast(&g_thread_cv);
		(void)pthread_mutex_unlock(&g_thread_mu);
		(void)pthread_join(t, NULL);
		_exit(1);
	}
	(void)close(fds[1]);
	used = 0;
	while (used < sizeof(buf) - 1) {
		n = read(fds[0], buf + used, sizeof(buf) - 1 - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
	}
	buf[used] = '\0';
	(void)close(fds[0]);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (!WIFEXITED(status) ||
	    WEXITSTATUS(status) != ARK_SECCOMP_EXIT_BLOCKED ||
	    strstr(buf, "blocked by the seccomp sandbox") == NULL)
		return -1;
	return 0;
#else
	return 0;
#endif
}

/*
 * x32 system call numbers on x86-64 kill the process outright (no report:
 * ark never makes them). arm64 has no second ABI to try from C.
 */
int test_seccomp_foreign_abi_killed(void)
{
#if defined(ARK_SECCOMP_TESTS) && defined(__x86_64__)
	child_result_t res;

	if (run_child(ARK_SECCOMP_LIST, body_x32, &res) != 0 || !res.signaled ||
	    res.sig != SIGSYS)
		return -1;
	return 0;
#else
	return 0;
#endif
}

#ifdef ARK_SECCOMP_TESTS
/*
 * thread_status_seccomp - count ark's threads and those in seccomp mode 2.
 * Returns 0 when /proc/<pid>/task could be read.
 */
static int thread_status_seccomp(pid_t pid, int *threads, int *filtered)
{
	char path[64];
	char file[sizeof(path) + sizeof(((struct dirent *)0)->d_name) + 8];
	char buf[4096];
	DIR *dir;
	struct dirent *de;
	ssize_t n;
	int fd;

	*threads = 0;
	*filtered = 0;
	(void)snprintf(path, sizeof(path), "/proc/%ld/task", (long)pid);
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		(void)snprintf(file, sizeof(file), "%s/%s/status", path,
		               de->d_name);
		fd = open(file, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		(void)close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		(*threads)++;
		if (strstr(buf, "Seccomp:\t2") != NULL)
			(*filtered)++;
	}
	(void)closedir(dir);
	return 0;
}

/*
 * cli_probe - run ./build/ark <cmd> on a FIFO archive and check its threads.
 *
 * ark blocks opening the FIFO after its sandbox is in place; the parent
 * polls /proc until at least min_threads threads exist and all of them are
 * filtered, then unblocks ark, which fails on the FIFO (seek: exit 2).
 */
static int cli_probe(const char *dir, const char *cmd, int min_threads)
{
	char fifo[256];
	char out[256];
	pid_t pid;
	int status;
	int threads;
	int filtered;
	int tries;
	int ok;
	int fd;

	(void)snprintf(fifo, sizeof(fifo), "%s/%s.ark", dir, cmd);
	(void)snprintf(out, sizeof(out), "%s/out", dir);
	if (mkfifo(fifo, 0600) != 0)
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		char *argv[6];
		int nfd;

		(void)setenv("ASAN_OPTIONS", "detect_leaks=0", 1);
		nfd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (nfd >= 0) {
			(void)dup2(nfd, STDOUT_FILENO);
			(void)dup2(nfd, STDERR_FILENO);
		}
		argv[0] = "./build/ark";
		argv[1] = (char *)cmd;
		if (strcmp(cmd, "extract") == 0) {
			argv[2] = "--output";
			argv[3] = out;
			argv[4] = fifo;
			argv[5] = NULL;
		} else {
			argv[2] = fifo;
			argv[3] = NULL;
		}
		execv(argv[0], argv);
		_exit(127);
	}
	ok = 0;
	for (tries = 0; tries < 500; tries++) {
		struct timespec ts = {0, 10000000L};

		if (thread_status_seccomp(pid, &threads, &filtered) == 0 &&
		    threads >= min_threads && filtered == threads) {
			ok = 1;
			break;
		}
		(void)nanosleep(&ts, NULL);
	}
	/*
	 * Unblock ark: it cannot seek on the FIFO (I/O error, exit 2).
	 * O_NONBLOCK fails (ENXIO) instead of hanging when ark is not waiting
	 * in open; then ark is stopped.
	 */
	fd = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0)
		(void)close(fd);
	else
		(void)kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	(void)unlink(fifo);
	if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 2)
		return -1;
	return 0;
}
#endif

/*
 * The production binary is filtered: list (no pool) and verify/extract
 * (main thread + workers, all filtered) while they wait on a FIFO archive.
 */
int test_seccomp_cli_threads_filtered(void)
{
#ifdef ARK_SECCOMP_TESTS
	char dir[] = "/tmp/ark_seccomp_XXXXXX";
	char out[256];
	int rc;

	if (mkdtemp(dir) == NULL)
		return -1;
	(void)snprintf(out, sizeof(out), "%s/out", dir);
	if (mkdir(out, 0700) != 0) {
		(void)rmdir(dir);
		return -1;
	}
	rc = cli_probe(dir, "list", 1);
	if (rc == 0)
		rc = cli_probe(dir, "verify", 2);
	if (rc == 0)
		rc = cli_probe(dir, "extract", 2);
	(void)rmdir(out);
	(void)rmdir(dir);
	return rc;
#else
	return 0;
#endif
}
