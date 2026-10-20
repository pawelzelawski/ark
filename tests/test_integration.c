/*
 * test_integration.c - End-to-end CLI integration tests for Phase 7.1.
 *
 * Exercises the production ark binary against real temporary files as required
 * by TESTING.md section 8. Each subcommand runs in a child process so the
 * process-wide sandbox state from ARCHITECTURE.md sections 6.3 and 10.4 cannot
 * leak into the test harness.
 */
#include "archive.h"
#include "blake3.h"
#include "deflate.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
static const char g_ark_bin[] = "./build/ark";
/*
 * path_join - Join dir/name into dst as "dir/name".
 */
static int path_join(char *dst, size_t dst_sz, const char *dir,
                     const char *name)
{
	int n;
	n = snprintf(dst, dst_sz, "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= dst_sz)
		return -1;
	return 0;
}
/*
 * make_temp_root - Create one owned temporary directory for a test.
 *
 * OWNERSHIP: caller removes the returned directory with remove_tree().
 */
static int make_temp_root(char *dst, size_t dst_sz)
{
	int n;
	n = snprintf(dst, dst_sz, "/tmp/ark-integration.XXXXXX");
	if (n < 0 || (size_t)n >= dst_sz)
		return -1;
	if (mkdtemp(dst) == NULL)
		return -1;
	return 0;
}
/*
 * remove_tree - Recursively remove a test-created file tree.
 *
 * SAFETY: callers pass only mkdtemp-owned integration roots or paths below
 * those roots. This helper must never be used on repository or system paths.
 */
static int remove_tree(const char *path)
{
	const struct dirent *de;
	struct stat st;
	DIR *dir;
	char child[PATH_MAX];
	int rc;
	if (lstat(path, &st) != 0)
		return errno == ENOENT ? 0 : -1;
	if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
		return unlink(path);
	dir = opendir(path);
	if (dir == NULL)
		return -1;
	rc = 0;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		if (path_join(child, sizeof(child), path, de->d_name) != 0 ||
		    remove_tree(child) != 0)
			rc = -1;
	}
	if (closedir(dir) != 0)
		rc = -1;
	if (rmdir(path) != 0)
		rc = -1;
	return rc;
}
/*
 * write_full_fd - Write all bytes to fd unless a hard write error occurs.
 */
static int write_full_fd(int fd, const uint8_t *buf, size_t len)
{
	while (len > 0U) {
		ssize_t n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}
/*
 * write_text_file - Create a small text fixture file.
 */
static int write_text_file(const char *path, const char *text)
{
	int fd;
	int rc;
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	rc = write_full_fd(fd, (const uint8_t *)text, strlen(text));
	if (close(fd) != 0)
		rc = -1;
	return rc;
}
/*
 * write_pattern_file - Create deterministic binary fixture data.
 */
static int write_pattern_file(const char *path, size_t total, uint32_t seed)
{
	uint8_t block[4096];
	size_t i;
	size_t rem;
	int fd;
	int rc;
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	rem = total;
	rc = 0;
	while (rem > 0U) {
		size_t chunk;
		chunk = rem < sizeof(block) ? rem : sizeof(block);
		for (i = 0U; i < chunk; i++) {
			seed = seed * 1664525U + 1013904223U;
			block[i] = (uint8_t)(seed >> 24);
		}
		if (write_full_fd(fd, block, chunk) != 0) {
			rc = -1;
			break;
		}
		rem -= chunk;
	}
	if (close(fd) != 0)
		rc = -1;
	return rc;
}
/*
 * read_file_bytes - Read one complete file into memory.
 *
 * OWNERSHIP: on success *out is owned by the caller and must be freed.
 */
/* Archive builders defined in test_archive.c. */
size_t test_archive_one_chunk(uint8_t *, size_t, const uint8_t *, size_t,
                              uint64_t, size_t *);
size_t test_archive_one_chunk_at(uint8_t *, size_t, const char *,
                                 const uint8_t *, size_t, uint64_t, size_t *);
/* Defined in test_deflate.c. */
ssize_t test_deflate_compress(const uint8_t *, size_t, uint8_t *, size_t, int);

/* Write len bytes to a new file at path. Returns 0 on success, -1 on error. */
static int write_bytes_file(const char *path, const uint8_t *buf, size_t len)
{
	int fd;
	int rc;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd == -1)
		return -1;
	rc = write_full_fd(fd, buf, len);
	if (close(fd) != 0)
		rc = -1;
	return rc;
}

static int read_file_bytes(const char *path, uint8_t **out, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	size_t off;
	int fd;
	*out = NULL;
	*out_len = 0U;
	if (stat(path, &st) != 0 || st.st_size < 0)
		return -1;
	buf = malloc((size_t)st.st_size == 0U ? 1U : (size_t)st.st_size);
	if (buf == NULL)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	off = 0U;
	while (off < (size_t)st.st_size) {
		ssize_t n;
		n = read(fd, buf + off, (size_t)st.st_size - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			(void)close(fd);
			free(buf);
			return -1;
		}
		if (n == 0) {
			(void)close(fd);
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}
	if (close(fd) != 0) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = (size_t)st.st_size;
	return 0;
}
/*
 * files_equal - Compare two regular files byte-for-byte.
 */
static int files_equal(const char *a_path, const char *b_path)
{
	uint8_t *a;
	uint8_t *b;
	size_t a_len;
	size_t b_len;
	int ok;
	a = NULL;
	b = NULL;
	if (read_file_bytes(a_path, &a, &a_len) != 0)
		return 0;
	if (read_file_bytes(b_path, &b, &b_len) != 0) {
		free(a);
		return 0;
	}
	ok = a_len == b_len && memcmp(a, b, a_len) == 0;
	free(b);
	free(a);
	return ok;
}
static int compare_tree(const char *, const char *);
/*
 * compare_dir_entries - Compare all entries below two directories.
 */
static int compare_dir_entries(const char *a_path, const char *b_path)
{
	const struct dirent *de;
	DIR *dir;
	char a_child[PATH_MAX];
	char b_child[PATH_MAX];
	size_t a_count;
	size_t b_count;
	dir = opendir(a_path);
	if (dir == NULL)
		return -1;
	a_count = 0U;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		a_count++;
		if (path_join(a_child, sizeof(a_child), a_path, de->d_name) !=
		        0 ||
		    path_join(b_child, sizeof(b_child), b_path, de->d_name) !=
		        0 ||
		    compare_tree(a_child, b_child) != 0) {
			(void)closedir(dir);
			return -1;
		}
	}
	if (closedir(dir) != 0)
		return -1;
	dir = opendir(b_path);
	if (dir == NULL)
		return -1;
	b_count = 0U;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0)
			b_count++;
	}
	if (closedir(dir) != 0)
		return -1;
	return a_count == b_count ? 0 : -1;
}
/*
 * compare_tree - Compare regular files, directories, and symlinks.
 */
static int compare_tree(const char *a_path, const char *b_path)
{
	struct stat a_st;
	struct stat b_st;
	if (lstat(a_path, &a_st) != 0 || lstat(b_path, &b_st) != 0)
		return -1;
	if ((a_st.st_mode & S_IFMT) != (b_st.st_mode & S_IFMT))
		return -1;
	if (S_ISREG(a_st.st_mode))
		return files_equal(a_path, b_path) ? 0 : -1;
	if (S_ISDIR(a_st.st_mode))
		return compare_dir_entries(a_path, b_path);
	if (S_ISLNK(a_st.st_mode)) {
		char a_link[PATH_MAX];
		char b_link[PATH_MAX];
		ssize_t a_len;
		ssize_t b_len;

		a_len = readlink(a_path, a_link, sizeof(a_link) - 1U);
		b_len = readlink(b_path, b_link, sizeof(b_link) - 1U);
		if (a_len < 0 || b_len < 0 || a_len != b_len)
			return -1;
		a_link[a_len] = '\0';
		b_link[b_len] = '\0';
		return strcmp(a_link, b_link) == 0 ? 0 : -1;
	}
	return -1;
}
/*
 * run_program_limited - Fork, optionally redirect, and exec one test command;
 * a nonzero data_limit sets the child's RLIMIT_DATA (bytes) first.
 *
 * SAFETY: ark subcommands are executed in child processes so pledge/Landlock
 * restrictions are discarded when that child exits. See ARCHITECTURE.md
 * sections 6.3 and 10.4.
 */
static int run_program_limited(char *const argv[], const char *cwd,
                               const char *stdout_path, const char *stderr_path,
                               rlim_t data_limit)
{
	pid_t pid;
	int status;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int fd;
		/*
		 * NOTE: production Landlock intentionally blocks /proc.
		 * LeakSanitizer needs /proc at process exit, so disable leak
		 * detection only in the sandboxed child; the test harness
		 * itself remains sanitised.
		 */
		(void)setenv("ASAN_OPTIONS", "detect_leaks=0", 1);
		(void)setenv("LSAN_OPTIONS", "detect_leaks=0", 1);
		if (cwd != NULL && chdir(cwd) != 0)
			_exit(126);
		fd = open("/dev/null", O_RDONLY);
		if (fd >= 0) {
			(void)dup2(fd, STDIN_FILENO);
			(void)close(fd);
		}
		fd = open(stdout_path == NULL ? "/dev/null" : stdout_path,
		          O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if (fd >= 0) {
			(void)dup2(fd, STDOUT_FILENO);
			(void)close(fd);
		}
		if (stderr_path != NULL) {
			fd = open(stderr_path, O_CREAT | O_TRUNC | O_WRONLY,
			          0600);
			if (fd >= 0) {
				(void)dup2(fd, STDERR_FILENO);
				(void)close(fd);
			}
		}
		/*
		 * RLIMIT_DATA covers malloc'd memory on Linux and OpenBSD. It
		 * is set last: until exec the child is still the (sanitized)
		 * test process, whose own allocations would exceed a small
		 * limit.
		 */
		if (data_limit != 0) {
			struct rlimit rl;

			rl.rlim_cur = data_limit;
			rl.rlim_max = data_limit;
			if (setrlimit(RLIMIT_DATA, &rl) != 0)
				_exit(125);
		}
		execvp(argv[0], argv);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}
/*
 * run_program - Run argv in cwd (NULL = unchanged) with stdout/stderr
 * redirected; returns the exit status, or -1.
 */
static int run_program(char *const argv[], const char *cwd,
                       const char *stdout_path, const char *stderr_path)
{
	return run_program_limited(argv, cwd, stdout_path, stderr_path, 0);
}
/*
 * run_ark - Execute the production CLI and require an expected exit code.
 */
static int run_ark(char *const argv[], int expected, const char *stdout_path,
                   const char *stderr_path)
{
	int rc;
	rc = run_program(argv, NULL, stdout_path, stderr_path);
	return rc == expected ? 0 : -1;
}
/*
 * create_archive - Run ark create for one source path.
 *
 * ARCHITECTURE.md section 12.2 defines the CLI surface exercised here.
 */
static int create_archive(const char *archive, const char *source,
                          const char *hash)
{
	char *argv_default[] = {(char *)g_ark_bin, "create", (char *)archive,
	                        (char *)source, NULL};
	if (hash != NULL) {
		char *argv_hash[] = {
		    (char *)g_ark_bin, "create",       "--hash", (char *)hash,
		    (char *)archive,   (char *)source, NULL};

		return run_ark(argv_hash, 0, NULL, NULL);
	}
	return run_ark(argv_default, 0, NULL, NULL);
}
/*
 * verify_archive - Run ark verify for a complete archive.
 */
static int verify_archive(const char *archive)
{
	char *argv[] = {(char *)g_ark_bin, "verify", (char *)archive, NULL};
	return run_ark(argv, 0, NULL, NULL);
}
/*
 * extract_archive - Run ark extract into an existing output directory.
 */
static int extract_archive(const char *archive, const char *out_dir,
                           int overwrite)
{
	char *argv_overwrite[] = {
	    (char *)g_ark_bin, "extract",       "--output", (char *)out_dir,
	    "--overwrite",     (char *)archive, NULL};
	char *argv[] = {(char *)g_ark_bin, "extract",       "--output",
	                (char *)out_dir,   (char *)archive, NULL};
	return run_ark(overwrite ? argv_overwrite : argv, 0, NULL, NULL);
}
/*
 * flip_archive_byte - Toggle one archive byte after bounds checking.
 */
static int flip_archive_byte(const char *path, off_t off)
{
	uint8_t byte;
	struct stat st;
	int fd;
	if (stat(path, &st) != 0 || off < 0 || off >= st.st_size)
		return -1;
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (lseek(fd, off, SEEK_SET) == (off_t)-1 || read(fd, &byte, 1U) != 1) {
		(void)close(fd);
		return -1;
	}
	byte ^= 0x80U;
	if (lseek(fd, off, SEEK_SET) == (off_t)-1 ||
	    write_full_fd(fd, &byte, 1U) != 0) {
		(void)close(fd);
		return -1;
	}
	return close(fd);
}
/*
 * le64_at - Decode one little-endian u64 from archive bytes.
 */
static uint64_t le64_at(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}
/*
 * flip_index_byte - Corrupt the hash-covered index block.
 *
 * ARCHITECTURE.md section 8.2 requires ark verify to reject this as an index
 * hash failure before parsing the damaged entry bytes.
 */
static int flip_index_byte(const char *archive)
{
	uint8_t *buf;
	size_t len;
	uint64_t index_offset;
	uint64_t index_size;
	int rc;
	if (read_file_bytes(archive, &buf, &len) != 0)
		return -1;
	if (len < 64U) {
		free(buf);
		return -1;
	}
	index_offset = le64_at(buf + len - 64U);
	index_size = le64_at(buf + len - 56U);
	if (index_size == 0U || index_offset >= len ||
	    index_offset + index_size > len - 64U) {
		free(buf);
		return -1;
	}
	rc = flip_archive_byte(archive, (off_t)index_offset);
	free(buf);
	return rc;
}
/*
 * set_file_mtime - Set atime/mtime to the same second value.
 */
static int set_file_mtime(const char *path, time_t sec)
{
	struct timespec ts[2];
	ts[0].tv_sec = sec;
	ts[0].tv_nsec = 123456789L;
	ts[1] = ts[0];
	return utimensat(AT_FDCWD, path, ts, 0);
}
/*
 * make_basic_tree - Create a deterministic mixed regular-file tree.
 */
static int make_basic_tree(const char *src)
{
	char a[PATH_MAX];
	char sub[PATH_MAX];
	char b[PATH_MAX];
	char c[PATH_MAX];
	if (mkdir(src, 0700) != 0)
		return -1;
	if (path_join(a, sizeof(a), src, "alpha.txt") != 0 ||
	    path_join(sub, sizeof(sub), src, "sub") != 0 ||
	    path_join(b, sizeof(b), sub, "beta.bin") != 0 ||
	    path_join(c, sizeof(c), sub, "gamma.txt") != 0)
		return -1;
	if (mkdir(sub, 0700) != 0)
		return -1;
	if (write_text_file(a, "alpha\n") != 0)
		return -1;
	if (write_pattern_file(b, 8192U, 7U) != 0)
		return -1;
	return write_text_file(c, "gamma\n");
}
/*
 * make_member_type_tree - Create regular, directory, symlink, and hardlink.
 *
 * ARCHITECTURE.md sections 13.2 and 13.3 define the hardlink and symlink
 * member semantics verified by the corresponding integration test.
 */
static int make_member_type_tree(const char *src)
{
	char dir[PATH_MAX];
	char original[PATH_MAX];
	char hard[PATH_MAX];
	char sym[PATH_MAX];
	if (mkdir(src, 0700) != 0)
		return -1;
	if (path_join(dir, sizeof(dir), src, "dir") != 0 ||
	    path_join(original, sizeof(original), dir, "original.txt") != 0 ||
	    path_join(hard, sizeof(hard), src, "hard.txt") != 0 ||
	    path_join(sym, sizeof(sym), src, "sym.txt") != 0)
		return -1;
	if (mkdir(dir, 0700) != 0)
		return -1;
	if (write_text_file(original, "member types\n") != 0)
		return -1;
	if (link(original, hard) != 0)
		return -1;
	return symlink("dir/original.txt", sym);
}
/*
 * make_large_tree - Create the 1000-file mixed-size integration fixture.
 */
static int make_large_tree(const char *src)
{
	char dir[PATH_MAX];
	char file[PATH_MAX];
	char name[64];
	int i;
	if (mkdir(src, 0700) != 0)
		return -1;
	for (i = 0; i < 10; i++) {
		(void)snprintf(name, sizeof(name), "group%02d", i);
		if (path_join(dir, sizeof(dir), src, name) != 0 ||
		    mkdir(dir, 0700) != 0)
			return -1;
	}
	for (i = 0; i < 1000; i++) {
		size_t size;
		(void)snprintf(name, sizeof(name), "group%02d/file%04d.bin",
		               i % 10, i);
		if (path_join(file, sizeof(file), src, name) != 0)
			return -1;
		size = (size_t)((i * 37) % 16384);
		if ((i % 17) == 0)
			size = 65536U + (size_t)(i % 4096);
		if (write_pattern_file(file, size, (uint32_t)i + 1U) != 0)
			return -1;
	}
	return 0;
}
int test_integration_single_file(void)
{
	char root[PATH_MAX];
	char src[PATH_MAX];
	char out[PATH_MAX];
	char archive[PATH_MAX];
	char extracted[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "one.txt") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "one.ark") != 0 ||
	    path_join(extracted, sizeof(extracted), out, "one.txt") != 0)
		goto cleanup;
	if (write_text_file(src, "single file\n") != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    verify_archive(archive) != 0)
		goto cleanup;
	if (extract_archive(archive, out, 0) != 0)
		goto cleanup;
	rc = files_equal(src, extracted) ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_directory_tree(void)
{
	char root[PATH_MAX];
	char src[PATH_MAX];
	char out[PATH_MAX];
	char archive[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "tree.ark") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    verify_archive(archive) != 0)
		goto cleanup;
	if (extract_archive(archive, out, 0) != 0)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_all_member_types(void)
{
	struct stat a_st;
	struct stat b_st;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char original[PATH_MAX], hard[PATH_MAX], sym[PATH_MAX],
	    linkbuf[PATH_MAX];
	ssize_t linklen;
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "members.ark") != 0 ||
	    path_join(original, sizeof(original), out, "dir/original.txt") !=
	        0 ||
	    path_join(hard, sizeof(hard), out, "hard.txt") != 0 ||
	    path_join(sym, sizeof(sym), out, "sym.txt") != 0)
		goto cleanup;
	if (make_member_type_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	linklen = readlink(sym, linkbuf, sizeof(linkbuf) - 1U);
	if (linklen < 0)
		goto cleanup;
	linkbuf[linklen] = '\0';
	if (strcmp(linkbuf, "dir/original.txt") != 0)
		goto cleanup;
	if (stat(original, &a_st) != 0 || stat(hard, &b_st) != 0)
		goto cleanup;
	if (a_st.st_ino != b_st.st_ino || a_st.st_dev != b_st.st_dev)
		goto cleanup;
	rc = files_equal(original, hard) ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_empty_file(void)
{
	struct stat st;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char empty[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "empty.ark") != 0 ||
	    path_join(empty, sizeof(empty), out, "empty") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (path_join(empty, sizeof(empty), src, "empty") != 0 ||
	    write_text_file(empty, "") != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	if (path_join(empty, sizeof(empty), out, "empty") != 0)
		goto cleanup;
	rc = stat(empty, &st) == 0 && st.st_size == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_round_trip_blake3(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "blake3.ark") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, "blake3") != 0 ||
	    verify_archive(archive) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_round_trip_sha256(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "sha256.ark") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, "sha256") != 0 ||
	    verify_archive(archive) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_mtime_preserved(void)
{
	struct stat st;
	time_t mtime;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char file[PATH_MAX];
	int rc;
	mtime = (time_t)1700000000;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "mtime.ark") != 0 ||
	    path_join(file, sizeof(file), src, "mtime.txt") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0 ||
	    write_text_file(file, "mtime\n") != 0 ||
	    set_file_mtime(file, mtime) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	if (path_join(file, sizeof(file), out, "mtime.txt") != 0)
		goto cleanup;
	rc = stat(file, &st) == 0 && st.st_mtime == mtime ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_mtime_pre_epoch(void)
{
	struct stat st;
	time_t mtime;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char file[PATH_MAX];
	int rc;
	mtime = (time_t)-123456789;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "pre.ark") != 0 ||
	    path_join(file, sizeof(file), src, "pre.txt") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0 ||
	    write_text_file(file, "pre epoch\n") != 0 ||
	    set_file_mtime(file, mtime) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	if (path_join(file, sizeof(file), out, "pre.txt") != 0)
		goto cleanup;
	rc = stat(file, &st) == 0 && st.st_mtime == mtime ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_verify_detects_corruption(void)
{
	char root[PATH_MAX], src[PATH_MAX], archive[PATH_MAX],
	    err_path[PATH_MAX];
	char file[PATH_MAX];
	char *argv[] = {(char *)g_ark_bin, "verify", archive, NULL};
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "bad-member.ark") != 0 ||
	    path_join(err_path, sizeof(err_path), root, "verify.err") != 0 ||
	    path_join(file, sizeof(file), src, "data.bin") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 ||
	    write_pattern_file(file, 65536U, 123U) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0)
		goto cleanup;
	/* ARCHITECTURE.md section 8.2: member data hash covers body bytes. */
	if (flip_archive_byte(archive, 24) != 0)
		goto cleanup;
	if (run_ark(argv, 4, NULL, err_path) != 0)
		goto cleanup;
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_verify_detects_index_corruption(void)
{
	char root[PATH_MAX], src[PATH_MAX], archive[PATH_MAX],
	    err_path[PATH_MAX];
	char *argv[] = {(char *)g_ark_bin, "verify", archive, NULL};
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "bad-index.ark") != 0 ||
	    path_join(err_path, sizeof(err_path), root, "verify.err") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 ||
	    create_archive(archive, src, NULL) != 0)
		goto cleanup;
	if (flip_index_byte(archive) != 0)
		goto cleanup;
	if (run_ark(argv, 4, NULL, err_path) != 0)
		goto cleanup;
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_overwrite(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char src_file[PATH_MAX], out_file[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "overwrite.ark") != 0 ||
	    path_join(src_file, sizeof(src_file), src, "same.txt") != 0 ||
	    path_join(out_file, sizeof(out_file), out, "same.txt") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (write_text_file(src_file, "new\n") != 0 ||
	    write_text_file(out_file, "old stale tail\n") != 0)
		goto cleanup;
	/* ARCHITECTURE.md section 14.2 defines --overwrite replacement. */
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 1) != 0)
		goto cleanup;
	rc = files_equal(src_file, out_file) ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_overwrite_symlink(void)
{
	struct stat st;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char src_file[PATH_MAX], out_file[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "overwrite-sym.ark") !=
	        0 ||
	    path_join(src_file, sizeof(src_file), src, "victim") != 0 ||
	    path_join(out_file, sizeof(out_file), out, "victim") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (write_text_file(src_file, "regular replacement\n") != 0 ||
	    symlink("dangling-target", out_file) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0 ||
	    extract_archive(archive, out, 1) != 0)
		goto cleanup;
	rc = lstat(out_file, &st) == 0 && S_ISREG(st.st_mode) &&
	             files_equal(src_file, out_file)
	         ? 0
	         : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_selective_member(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char b[PATH_MAX], a_out[PATH_MAX], b_out[PATH_MAX], c_out[PATH_MAX];
	char *argv[] = {(char *)g_ark_bin, "extract", "--output", out,
	                "--member",        "b.txt",   archive,    NULL};
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "selective.ark") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (path_join(b, sizeof(b), src, "a.txt") != 0 ||
	    write_text_file(b, "a\n") != 0 ||
	    path_join(b, sizeof(b), src, "b.txt") != 0 ||
	    write_text_file(b, "b\n") != 0 ||
	    path_join(b, sizeof(b), src, "c.txt") != 0 ||
	    write_text_file(b, "c\n") != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0)
		goto cleanup;
	/* ARCHITECTURE.md section 14.4 permits selective leaf extraction. */
	if (run_ark(argv, 0, NULL, NULL) != 0)
		goto cleanup;
	if (path_join(a_out, sizeof(a_out), out, "a.txt") != 0 ||
	    path_join(b_out, sizeof(b_out), out, "b.txt") != 0 ||
	    path_join(c_out, sizeof(c_out), out, "c.txt") != 0)
		goto cleanup;
	rc = access(b_out, F_OK) == 0 && access(a_out, F_OK) != 0 &&
	             access(c_out, F_OK) != 0
	         ? 0
	         : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_list(void)
{
	uint8_t *out_bytes;
	size_t out_len;
	char root[PATH_MAX], src[PATH_MAX], archive[PATH_MAX],
	    list_out[PATH_MAX];
	char *argv[] = {(char *)g_ark_bin, "list", archive, NULL};
	int rc;
	out_bytes = NULL;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "list.ark") != 0 ||
	    path_join(list_out, sizeof(list_out), root, "list.out") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 ||
	    create_archive(archive, src, NULL) != 0)
		goto cleanup;
	if (run_ark(argv, 0, list_out, NULL) != 0)
		goto cleanup;
	if (read_file_bytes(list_out, &out_bytes, &out_len) != 0)
		goto cleanup;
	(void)out_len;
	rc = strstr((const char *)out_bytes, "alpha.txt") != NULL &&
	             strstr((const char *)out_bytes, "sub/beta.bin") != NULL &&
	             strstr((const char *)out_bytes, "sub/gamma.txt") != NULL
	         ? 0
	         : 1;
cleanup:
	free(out_bytes);
	(void)remove_tree(root);
	return rc;
}
int test_integration_generate_reader(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recovery_c[PATH_MAX], recover_bin[PATH_MAX];
	char *gen_argv[] = {(char *)g_ark_bin, "generate-reader", recovery_c,
	                    NULL};
	char *cc_argv[] = {"cc", "-O2", recovery_c, "-o", recover_bin, NULL};
	char *recover_argv[] = {recover_bin, archive, NULL};
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "recover-out") != 0 ||
	    path_join(archive, sizeof(archive), root, "reader.ark") != 0 ||
	    path_join(recovery_c, sizeof(recovery_c), root, "recovery.c") !=
	        0 ||
	    path_join(recover_bin, sizeof(recover_bin), root, "recover") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0)
		goto cleanup;
	/* ARCHITECTURE.md section 15.2 requires valid C11 recovery output. */
	if (run_ark(gen_argv, 0, NULL, NULL) != 0)
		goto cleanup;
	if (run_program(cc_argv, NULL, NULL, NULL) != 0)
		goto cleanup;
	if (run_program(recover_argv, out, NULL, NULL) != 0)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
/*
 * test_integration_generate_reader_rejects_legacy_258 - The generated reader
 * applies the decoder's RFC 1951 rule: a chunk coding length 258 as code
 * 284 + extra 31 (pre-v1.1.0 encoders) fails recovery, while the same
 * archive with 284 + 30 (length 257) recovers. Archives are hand-built with
 * valid hashes, so only the length rule differs. See ARCHITECTURE.md 7.4.
 */
int test_integration_generate_reader_rejects_legacy_258(void)
{
	/* Fixed block 'A', code 284 + extra 31 or 30, distance 1, EOB. */
	static const uint8_t legacy[] = {0x73, 0x1c, 0xf9, 0x00, 0x00};
	static const uint8_t valid[] = {0x73, 0x1c, 0xf1, 0x00, 0x00};
	char root[PATH_MAX], out_bad[PATH_MAX], out_ok[PATH_MAX];
	char bad_ark[PATH_MAX], ok_ark[PATH_MAX], member[PATH_MAX];
	char recovery_c[PATH_MAX], recover_bin[PATH_MAX];
	char *gen_argv[] = {(char *)g_ark_bin, "generate-reader", recovery_c,
	                    NULL};
	char *cc_argv[] = {"cc", "-O2", recovery_c, "-o", recover_bin, NULL};
	char *bad_argv[] = {recover_bin, bad_ark, NULL};
	char *ok_argv[] = {recover_bin, ok_ark, NULL};
	uint8_t buf[512];
	uint8_t *got;
	size_t got_len;
	size_t index_len;
	size_t len;
	size_t i;
	int rc;

	got = NULL;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(out_bad, sizeof(out_bad), root, "out-bad") != 0 ||
	    path_join(out_ok, sizeof(out_ok), root, "out-ok") != 0 ||
	    path_join(bad_ark, sizeof(bad_ark), root, "legacy.ark") != 0 ||
	    path_join(ok_ark, sizeof(ok_ark), root, "valid.ark") != 0 ||
	    path_join(member, sizeof(member), out_ok, "a") != 0 ||
	    path_join(recovery_c, sizeof(recovery_c), root, "recovery.c") !=
	        0 ||
	    path_join(recover_bin, sizeof(recover_bin), root, "recover") != 0)
		goto cleanup;
	if (mkdir(out_bad, 0700) != 0 || mkdir(out_ok, 0700) != 0)
		goto cleanup;
	len = test_archive_one_chunk(buf, sizeof(buf), legacy, sizeof(legacy),
	                             259U, &index_len);
	if (len == 0U || write_bytes_file(bad_ark, buf, len) != 0)
		goto cleanup;
	len = test_archive_one_chunk(buf, sizeof(buf), valid, sizeof(valid),
	                             258U, &index_len);
	if (len == 0U || write_bytes_file(ok_ark, buf, len) != 0)
		goto cleanup;
	if (run_ark(gen_argv, 0, NULL, NULL) != 0 ||
	    run_program(cc_argv, NULL, NULL, NULL) != 0)
		goto cleanup;
	if (run_program(bad_argv, out_bad, "/dev/null", "/dev/null") == 0)
		goto cleanup;
	if (run_program(ok_argv, out_ok, "/dev/null", "/dev/null") != 0 ||
	    read_file_bytes(member, &got, &got_len) != 0 || got_len != 258U)
		goto cleanup;
	for (i = 0; i < got_len; i++) {
		if (got[i] != 'A')
			goto cleanup;
	}
	rc = 0;
cleanup:
	free(got);
	(void)remove_tree(root);
	return rc;
}
/*
 * test_integration_generate_reader_strict_c11 - The generated reader builds
 * as strict C11 with every warning an error, using each available compiler
 * (cc is required; clang and gcc when installed), and each build recovers
 * the source tree. Guards the feature-test macro in recovery_template.c.
 * See ARCHITECTURE.md section 15.2.
 */
int test_integration_generate_reader_strict_c11(void)
{
	static const char *const compilers[] = {"cc", "clang", "gcc"};
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recovery_c[PATH_MAX], recover_bin[PATH_MAX];
	char *gen_argv[] = {(char *)g_ark_bin, "generate-reader", recovery_c,
	                    NULL};
	char *recover_argv[] = {recover_bin, archive, NULL};
	size_t i;
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "reader.ark") != 0 ||
	    path_join(recovery_c, sizeof(recovery_c), root, "recovery.c") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0 ||
	    create_archive(archive, src, NULL) != 0 ||
	    run_ark(gen_argv, 0, NULL, NULL) != 0)
		goto cleanup;
	for (i = 0U; i < sizeof(compilers) / sizeof(compilers[0]); i++) {
		char *probe_argv[] = {(char *)compilers[i], "--version", NULL};
		char *cc_argv[] = {(char *)compilers[i],
		                   "-std=c11",
		                   "-Wall",
		                   "-Wextra",
		                   "-Wpedantic",
		                   "-Werror",
		                   "-O2",
		                   recovery_c,
		                   "-o",
		                   recover_bin,
		                   NULL};
		char name[32];

		if (run_program(probe_argv, NULL, NULL, "/dev/null") != 0) {
			if (i == 0U)
				goto cleanup;
			continue;
		}
		(void)snprintf(name, sizeof(name), "recover-%s", compilers[i]);
		if (path_join(recover_bin, sizeof(recover_bin), root, name) !=
		    0)
			goto cleanup;
		(void)snprintf(name, sizeof(name), "out-%s", compilers[i]);
		if (path_join(out, sizeof(out), root, name) != 0 ||
		    mkdir(out, 0700) != 0)
			goto cleanup;
		if (run_program(cc_argv, NULL, NULL, NULL) != 0)
			goto cleanup;
		if (run_program(recover_argv, out, NULL, NULL) != 0 ||
		    compare_tree(src, out) != 0)
			goto cleanup;
	}
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
/*
 * test_integration_generate_reader_no_follow - The recovery reader must not
 * write through a symlink that already exists at a regular-file member path
 * (non-empty and empty file paths). Recovery fails instead and the symlink
 * target is left unchanged. See ARCHITECTURE.md sections 14.2 and 15.2.
 */
int test_integration_generate_reader_no_follow(void)
{
	static const char *const members[] = {"data.txt", "empty.txt"};
	char root[PATH_MAX], src[PATH_MAX], archive[PATH_MAX];
	char recovery_c[PATH_MAX], recover_bin[PATH_MAX];
	char victim[PATH_MAX], victim_ref[PATH_MAX];
	char out[PATH_MAX], file[PATH_MAX], link_path[PATH_MAX];
	char *gen_argv[] = {(char *)g_ark_bin, "generate-reader", recovery_c,
	                    NULL};
	char *cc_argv[] = {"cc", "-O2", recovery_c, "-o", recover_bin, NULL};
	char *recover_argv[] = {recover_bin, archive, NULL};
	size_t i;
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "reader.ark") != 0 ||
	    path_join(recovery_c, sizeof(recovery_c), root, "recovery.c") !=
	        0 ||
	    path_join(recover_bin, sizeof(recover_bin), root, "recover") != 0 ||
	    path_join(victim, sizeof(victim), root, "victim.txt") != 0 ||
	    path_join(victim_ref, sizeof(victim_ref), root, "victim.ref") != 0)
		goto cleanup;
	if (mkdir(src, 0700) != 0 || write_text_file(victim, "victim\n") != 0 ||
	    write_text_file(victim_ref, "victim\n") != 0)
		goto cleanup;
	if (path_join(file, sizeof(file), src, "data.txt") != 0 ||
	    write_text_file(file, "recovered data\n") != 0 ||
	    path_join(file, sizeof(file), src, "empty.txt") != 0 ||
	    write_text_file(file, "") != 0)
		goto cleanup;
	if (create_archive(archive, src, NULL) != 0)
		goto cleanup;
	if (run_ark(gen_argv, 0, NULL, NULL) != 0)
		goto cleanup;
	if (run_program(cc_argv, NULL, NULL, NULL) != 0)
		goto cleanup;
	for (i = 0U; i < sizeof(members) / sizeof(members[0]); i++) {
		char name[32];

		(void)snprintf(name, sizeof(name), "out%zu", i);
		if (path_join(out, sizeof(out), root, name) != 0 ||
		    mkdir(out, 0700) != 0 ||
		    path_join(link_path, sizeof(link_path), out, members[i]) !=
		        0 ||
		    symlink(victim, link_path) != 0)
			goto cleanup;
		if (run_program(recover_argv, out, NULL, "/dev/null") == 0)
			goto cleanup;
		if (!files_equal(victim, victim_ref))
			goto cleanup;
	}
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
/*
 * build_reader - Generate the recovery reader into root/recovery.c and build
 * it as root/recover with cc -O2. recover_bin receives the binary path.
 */
static int build_reader(const char *root, char *recover_bin, size_t cap)
{
	char recovery_c[PATH_MAX];
	char *gen_argv[] = {(char *)g_ark_bin, "generate-reader", recovery_c,
	                    NULL};
	char *cc_argv[] = {"cc", "-O2", recovery_c, "-o", recover_bin, NULL};

	if (path_join(recovery_c, sizeof(recovery_c), root, "recovery.c") !=
	        0 ||
	    path_join(recover_bin, cap, root, "recover") != 0)
		return -1;
	if (run_ark(gen_argv, 0, NULL, NULL) != 0 ||
	    run_program(cc_argv, NULL, NULL, NULL) != 0)
		return -1;
	return 0;
}
/*
 * dir_is_empty - Return 1 when path is a directory with no entries.
 */
static int dir_is_empty(const char *path)
{
	DIR *d;
	const struct dirent *e;
	int empty;

	d = opendir(path);
	if (d == NULL)
		return 0;
	empty = 1;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
			empty = 0;
	}
	(void)closedir(d);
	return empty;
}
/*
 * test_integration_generate_reader_no_follow_parent - The recovery reader
 * never follows a symlink in a parent component of a member path, and never
 * creates parents itself. A hand-built archive holding only "d/f" (no "d"
 * member) is rejected before any write (exit 2), whether "d" in the
 * destination is a symlink to another directory, which stays empty, or
 * missing. An ark-built tree fails when its "sub" directory already exists
 * as a symlink. See ARCHITECTURE.md sections 8.3 (check 9) and 15.2.
 */
int test_integration_generate_reader_no_follow_parent(void)
{
	/* Fixed block: 'A', then length 257 at distance 1, EOB. */
	static const uint8_t stream[] = {0x73, 0x1c, 0xf1, 0x00, 0x00};
	char root[PATH_MAX], victim[PATH_MAX], archive[PATH_MAX];
	char tree_ark[PATH_MAX], src[PATH_MAX], out[PATH_MAX];
	char path[PATH_MAX], recover_bin[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	char *tree_argv[] = {recover_bin, tree_ark, NULL};
	uint8_t buf[512];
	size_t index_len;
	size_t len;
	int rc;

	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(victim, sizeof(victim), root, "victim") != 0 ||
	    path_join(archive, sizeof(archive), root, "parent.ark") != 0 ||
	    path_join(tree_ark, sizeof(tree_ark), root, "tree.ark") != 0 ||
	    path_join(src, sizeof(src), root, "src") != 0 ||
	    mkdir(victim, 0700) != 0)
		goto cleanup;
	len = test_archive_one_chunk_at(buf, sizeof(buf), "d/f", stream,
	                                sizeof(stream), 258U, &index_len);
	if (len == 0U || write_bytes_file(archive, buf, len) != 0 ||
	    make_basic_tree(src) != 0 ||
	    create_archive(tree_ark, src, NULL) != 0)
		goto cleanup;
	if (build_reader(root, recover_bin, sizeof(recover_bin)) != 0)
		goto cleanup;

	/* "d" is a symlink to victim: rejected, victim stays empty. */
	if (path_join(out, sizeof(out), root, "out-link") != 0 ||
	    mkdir(out, 0700) != 0 ||
	    path_join(path, sizeof(path), out, "d") != 0 ||
	    symlink(victim, path) != 0)
		goto cleanup;
	if (run_program(recover_argv, out, "/dev/null", "/dev/null") != 2 ||
	    !dir_is_empty(victim))
		goto cleanup;

	/* No "d": still rejected, nothing created. */
	if (path_join(out, sizeof(out), root, "out-new") != 0 ||
	    mkdir(out, 0700) != 0 ||
	    run_program(recover_argv, out, "/dev/null", "/dev/null") != 2 ||
	    !dir_is_empty(out))
		goto cleanup;

	/* ark-built tree, "sub" exists as a symlink to victim: fails. */
	if (path_join(out, sizeof(out), root, "out-tree") != 0 ||
	    mkdir(out, 0700) != 0 ||
	    path_join(path, sizeof(path), out, "sub") != 0 ||
	    symlink(victim, path) != 0)
		goto cleanup;
	if (run_program(tree_argv, out, "/dev/null", "/dev/null") != 1 ||
	    !dir_is_empty(victim))
		goto cleanup;
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
/*
 * test_integration_generate_reader_member_types - The recovery reader
 * restores every member type: a directory, a regular file inside it, a
 * hardlink to that file (the link target is a path in a subdirectory) and a
 * symlink. See ARCHITECTURE.md sections 13.2, 13.3 and 15.2.
 */
int test_integration_generate_reader_member_types(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recover_bin[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	struct stat st_a;
	struct stat st_b;
	int rc;

	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "types.ark") != 0 ||
	    make_member_type_tree(src) != 0 || mkdir(out, 0700) != 0 ||
	    create_archive(archive, src, NULL) != 0 ||
	    build_reader(root, recover_bin, sizeof(recover_bin)) != 0 ||
	    run_program(recover_argv, out, NULL, NULL) != 0)
		goto cleanup;
	if (path_join(a, sizeof(a), out, "dir/original.txt") != 0 ||
	    path_join(b, sizeof(b), out, "hard.txt") != 0 ||
	    stat(a, &st_a) != 0 || stat(b, &st_b) != 0 ||
	    st_a.st_ino != st_b.st_ino || st_a.st_dev != st_b.st_dev)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
/*
 * test_integration_generate_reader_bounded_memory - The recovery reader reads
 * the archive in pieces, so a 40 MiB archive (incompressible data, stored
 * chunks) recovers with its data size limited to 32 MiB, which the old
 * whole-file read could not. See ARCHITECTURE.md section 15.2.
 */
int test_integration_generate_reader_bounded_memory(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char file[PATH_MAX], recover_bin[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	struct stat st;
	uint8_t *block;
	uint32_t x;
	size_t i;
	int fd;
	int rc;

	block = NULL;
	fd = -1;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "big.ark") != 0 ||
	    path_join(file, sizeof(file), src, "random.bin") != 0 ||
	    mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	/* 40 x 1 MiB of xorshift bytes, each MiB differing in its first word.
	 */
	block = (uint8_t *)malloc(1048576U);
	if (block == NULL)
		goto cleanup;
	x = 0x2545f491U;
	for (i = 0; i < 1048576U; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		block[i] = (uint8_t)x;
	}
	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd == -1)
		goto cleanup;
	for (i = 0; i < 40U; i++) {
		block[0] = (uint8_t)i;
		if (write(fd, block, 1048576U) != 1048576)
			goto cleanup;
	}
	if (close(fd) != 0) {
		fd = -1;
		goto cleanup;
	}
	fd = -1;
	if (create_archive(archive, src, NULL) != 0 ||
	    stat(archive, &st) != 0 || st.st_size < 40 * 1048576)
		goto cleanup;
	if (build_reader(root, recover_bin, sizeof(recover_bin)) != 0 ||
	    run_program_limited(recover_argv, out, NULL, NULL,
	                        (rlim_t)32 * 1048576) != 0)
		goto cleanup;
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	if (fd != -1)
		(void)close(fd);
	free(block);
	(void)remove_tree(root);
	return rc;
}
/*
 * Hand-built archives for the recovery reader's index checks: entries as in
 * ARCHITECTURE.md section 5.2, with explicit path and link lengths so a
 * case can hold NUL bytes or invalid UTF-8.
 */
#define RD_MAX_ENTRIES 12U
typedef struct {
	uint8_t type;
	uint32_t mode;
	uint64_t mtime;
	uint64_t size_original;
	uint64_t size_compressed;
	uint64_t data_offset;
	uint8_t hash[32];
	const char *path;
	size_t path_len;
	const char *link;
	size_t link_len;
	uint32_t chunk_count;
	uint32_t chunk_sizes[2];
} rd_entry_t;
typedef struct {
	rd_entry_t e[RD_MAX_ENTRIES];
	uint32_t n;
	uint32_t member_count; /* footer value; n unless a case changes it */
	int extra_index_byte;
	uint8_t body[256];
	size_t body_len;
} rd_archive_t;

static void rd_put16(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}
static void rd_put32(uint8_t *p, uint64_t v)
{
	rd_put16(p, v);
	rd_put16(p + 2, v >> 16);
}
static void rd_put64(uint8_t *p, uint64_t v)
{
	rd_put32(p, v);
	rd_put32(p + 4, v >> 32);
}

/*
 * rd_build - Serialize a: header (BLAKE3), body, index, footer with the
 * index hash. Returns the archive length and the index offset/length, or 0
 * when buf is too small.
 */
static size_t rd_build(const rd_archive_t *a, uint8_t *buf, size_t cap,
                       size_t *index_off, size_t *index_len)
{
	size_t off;
	uint32_t i;

	if (a->body_len > sizeof(a->body) || cap < 16U + a->body_len + 64U)
		return 0U;
	memset(buf, 0, 16U);
	memcpy(buf, "ark!\n\x01\x00\x00\x01\x01", 10U);
	memcpy(buf + 16U, a->body, a->body_len);
	off = 16U + a->body_len;
	*index_off = off;
	for (i = 0U; i < a->n; i++) {
		const rd_entry_t *e;
		uint32_t j;

		e = &a->e[i];
		if (cap - off <
		    64U + 79U + e->path_len + 2U + e->link_len + 4U + 8U + 1U)
			return 0U;
		buf[off] = e->type;
		rd_put32(buf + off + 1U, e->mode);
		rd_put32(buf + off + 5U, 1000U);
		rd_put32(buf + off + 9U, 1000U);
		rd_put64(buf + off + 13U, e->mtime);
		rd_put64(buf + off + 21U, e->size_original);
		rd_put64(buf + off + 29U, e->size_compressed);
		rd_put64(buf + off + 37U, e->data_offset);
		memcpy(buf + off + 45U, e->hash, 32U);
		rd_put16(buf + off + 77U, e->path_len);
		off += 79U;
		memcpy(buf + off, e->path, e->path_len);
		off += e->path_len;
		if (e->type == 0x03U || e->type == 0x04U) {
			rd_put16(buf + off, e->link_len);
			memcpy(buf + off + 2U, e->link, e->link_len);
			off += 2U + e->link_len;
		}
		rd_put32(buf + off, e->chunk_count);
		off += 4U;
		for (j = 0U; j < e->chunk_count && j < 2U; j++) {
			rd_put32(buf + off, e->chunk_sizes[j]);
			off += 4U;
		}
	}
	if (a->extra_index_byte)
		buf[off++] = 0U;
	*index_len = off - *index_off;
	memset(buf + off, 0, 64U);
	rd_put64(buf + off, *index_off);
	rd_put64(buf + off + 8U, *index_len);
	ark_blake3(buf + *index_off, *index_len, buf + off + 16U);
	rd_put32(buf + off + 48U, a->member_count);
	rd_put32(buf + off + 52U, 0x4b52410aU);
	return off + 64U;
}

static void rd_set(rd_entry_t *e, uint8_t type, const char *path,
                   const char *link)
{
	static const uint8_t none = 0U;

	memset(e, 0, sizeof(*e));
	e->type = type;
	e->mode = type == 0x02U ? 0755U : 0644U;
	e->mtime = UINT64_C(1700000000000000000);
	e->path = path;
	e->path_len = strlen(path);
	e->link = link;
	e->link_len = link != NULL ? strlen(link) : 0U;
	ark_blake3(&none, 0U, e->hash);
}

/* Add a regular member holding text as one Deflate chunk. */
static int rd_add_file(rd_archive_t *a, rd_entry_t *e, const char *path,
                       const char *text)
{
	ssize_t clen;
	size_t len;

	len = strlen(text);
	rd_set(e, 0x01U, path, NULL);
	clen = test_deflate_compress(
	    (const uint8_t *)text, len, a->body + a->body_len,
	    sizeof(a->body) - a->body_len, ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0)
		return -1;
	e->size_original = len;
	e->size_compressed = (uint64_t)clen;
	e->data_offset = 16U + a->body_len;
	e->chunk_count = 1U;
	e->chunk_sizes[0] = (uint32_t)clen;
	ark_blake3(a->body + a->body_len, (size_t)clen, e->hash);
	a->body_len += (size_t)clen;
	return 0;
}

/*
 * rd_base - Every member type and both symlink-target forms ark accepts:
 *   0 d/  1 d/f  2 d/sub/  3 d/sub/g  4 e (empty)  5 h -> d/f (hardlink)
 *   6 s -> d/f  7 d/dot -> .  (symlinks)
 */
static int rd_base(rd_archive_t *a)
{
	memset(a, 0, sizeof(*a));
	rd_set(&a->e[0], 0x02U, "d", NULL);
	if (rd_add_file(a, &a->e[1], "d/f", "recovery differential\n") != 0)
		return -1;
	rd_set(&a->e[2], 0x02U, "d/sub", NULL);
	if (rd_add_file(a, &a->e[3], "d/sub/g", "second member, gggggggg\n") !=
	    0)
		return -1;
	rd_set(&a->e[4], 0x01U, "e", NULL);
	rd_set(&a->e[5], 0x04U, "h", "d/f");
	rd_set(&a->e[6], 0x03U, "s", "d/f");
	rd_set(&a->e[7], 0x03U, "d/dot", ".");
	a->n = 8U;
	a->member_count = 8U;
	return 0;
}

static void rd_set_path(rd_entry_t *e, const char *path, size_t len)
{
	e->path = path;
	e->path_len = len;
}
static void rd_set_link(rd_entry_t *e, const char *link, size_t len)
{
	e->link = link;
	e->link_len = len;
}

/*
 * rd_hide_byte - Insert one zero byte into the body at body offset at and
 * move the data of every member behind it, so the byte belongs to no
 * member: hidden bytes that checks 13 and 15 must find.
 */
static void rd_hide_byte(rd_archive_t *a, size_t at)
{
	uint32_t i;

	if (a->body_len >= sizeof(a->body) || at > a->body_len)
		return;
	memmove(a->body + at + 1U, a->body + at, a->body_len - at);
	a->body[at] = 0U;
	a->body_len++;
	for (i = 0U; i < a->n; i++) {
		if (a->e[i].chunk_count > 0U && a->e[i].data_offset >= 16U + at)
			a->e[i].data_offset++;
	}
}

/*
 * rd_mutate - Apply structured case k to the base archive. Returns 1 when
 * ark must accept the index, 0 when it must reject it, -1 past the last
 * case. The numbers in comments are ARCHITECTURE.md section 8.3 checks.
 */
static int rd_mutate(rd_archive_t *a, int k)
{
	static char long_path[1025];
	rd_entry_t t;

	memset(long_path, 'x', sizeof(long_path) - 1U);
	long_path[sizeof(long_path) - 1U] = '\0';
	switch (k) {
	case 0: /* base archive */
		return 1;
	case 1: /* 6: empty components are valid in a symlink target */
		rd_set_link(&a->e[6], "d//f", 4U);
		return 1;
	case 2:
		rd_set_link(&a->e[6], "./d/f/", 6U);
		return 1;
	case 3:
		rd_set_link(&a->e[6], "d/../f", 6U);
		return 0;
	case 4:
		rd_set_link(&a->e[6], "/etc", 4U);
		return 0;
	case 5:
		rd_set_link(&a->e[6], "d\0f", 3U);
		return 0;
	case 6:
		rd_set_link(&a->e[6], "\xc0\xaf", 2U);
		return 0;
	case 7: /* 3: member path grammar */
		rd_set_path(&a->e[4], "e\0x", 3U);
		return 0;
	case 8:
		rd_set_path(&a->e[4], "e\xed\xa0\x80", 4U);
		return 0;
	case 9:
		rd_set_path(&a->e[4], "/e", 2U);
		return 0;
	case 10:
		rd_set_path(&a->e[4], "d/../e", 6U);
		return 0;
	case 11:
		rd_set_path(&a->e[4], "d/./e", 5U);
		return 0;
	case 12:
		rd_set_path(&a->e[4], "d//e", 4U);
		return 0;
	case 13:
		rd_set_path(&a->e[4], "d/", 2U);
		return 0;
	case 14:
		rd_set_path(&a->e[4], ".", 1U);
		return 0;
	case 15: /* 5: 1023 bytes is the limit */
		rd_set_path(&a->e[4], long_path, 1023U);
		return 1;
	case 16:
		rd_set_path(&a->e[4], long_path, 1024U);
		return 0;
	case 17: /* 8 */
		rd_set_path(&a->e[4], "d/f", 3U);
		return 0;
	case 18: /* 9: missing, non-directory and later parents */
		rd_set_path(&a->e[3], "x/g", 3U);
		return 0;
	case 19:
		rd_set_path(&a->e[3], "d/f/g", 5U);
		return 0;
	case 20:
		t = a->e[2];
		a->e[2] = a->e[3];
		a->e[3] = t;
		return 0;
	case 21: /* 7 and 14: hardlink targets */
		rd_set_link(&a->e[5], "d/sub/g", 7U);
		return 1;
	case 22:
		rd_set_link(&a->e[5], "zz", 2U);
		return 0;
	case 23:
		rd_set_link(&a->e[5], "d", 1U);
		return 0;
	case 24:
		rd_set_link(&a->e[5], "d/dot", 5U);
		return 0;
	case 25:
		rd_set_link(&a->e[5], "./d/f", 5U);
		return 0;
	case 26:
		t = a->e[5];
		a->e[5] = a->e[6];
		a->e[6] = t;
		rd_set_link(&a->e[6], "s", 1U);
		return 0;
	case 27: /* member types and zero-data size fields */
		a->e[4].type = 0x05U;
		return 0;
	case 28:
		a->e[4].type = 0x00U;
		return 0;
	case 29:
		a->e[0].size_original = 1U;
		return 0;
	case 30:
		a->e[6].data_offset = 16U;
		return 0;
	case 31:
		a->e[4].chunk_count = 1U;
		a->e[4].chunk_sizes[0] = 1U;
		return 0;
	case 32: /* chunk count from size */
		a->e[1].chunk_count = 2U;
		a->e[1].chunk_sizes[0] = a->e[1].chunk_sizes[0] - 1U;
		a->e[1].chunk_sizes[1] = 1U;
		return 0;
	case 33: /* 11 */
		a->e[1].size_compressed++;
		return 0;
	case 34: /* 12, 13, 15: body layout */
		a->e[1].data_offset = 15U;
		return 0;
	case 35:
		a->e[3].data_offset = a->e[1].data_offset;
		return 0;
	case 36: /* bodies swapped: valid layout, data fails later */
		a->e[3].data_offset = 16U;
		a->e[1].data_offset = 16U + a->e[3].size_compressed;
		return 1;
	case 37:
		a->e[3].size_compressed--;
		a->e[3].chunk_sizes[0]--;
		return 0;
	case 38: /* 16 */
		a->e[0].hash[0] ^= 1U;
		return 0;
	case 39:
		a->e[4].hash[31] ^= 0x80U;
		return 0;
	case 40: /* footer count and index length */
		a->member_count = 9U;
		return 0;
	case 41:
		a->member_count = 7U;
		return 0;
	case 42:
		a->member_count = 0xffffffffU;
		return 0;
	case 43:
		a->extra_index_byte = 1;
		return 0;
	case 44: /* no members: the body becomes hidden bytes */
		a->n = 0U;
		a->member_count = 0U;
		return 0;
	case 45: /* metadata only */
		a->e[1].mode = 0777U;
		a->e[3].mtime = 0U;
		return 1;
	case 46: /* parent turned into an empty file */
		a->e[2].type = 0x01U;
		return 0;
	case 47: /* a NUL would cut the hardlink target to "d/f" */
		rd_set_link(&a->e[5], "d/f\0x", 5U);
		return 0;
	case 48: /* 7: hardlink before its regular-file target */
		t = a->e[4];
		a->e[4] = a->e[5];
		a->e[5] = t;
		rd_set_link(&a->e[4], "e", 1U);
		return 0;
	case 49: /* 15: hidden byte before the first body, after the last */
		rd_hide_byte(a, 0U);
		return 0;
	case 50:
		rd_hide_byte(a, (size_t)a->e[1].size_compressed);
		return 0;
	case 51:
		rd_hide_byte(a, a->body_len);
		return 0;
	default:
		return -1;
	}
}

/*
 * rd_make_writable - Give every directory below path (path included) mode
 * 0700, so remove_tree can empty directories whose restored mode is
 * read-only. Symlinks are not followed.
 */
static void rd_make_writable(const char *path)
{
	const struct dirent *de;
	struct stat st;
	char child[PATH_MAX];
	DIR *dir;

	if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
	    chmod(path, 0700) != 0)
		return;
	dir = opendir(path);
	if (dir == NULL)
		return;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0 &&
		    path_join(child, sizeof(child), path, de->d_name) == 0)
			rd_make_writable(child);
	}
	(void)closedir(dir);
}

/*
 * rd_check_case - Run one archive through ark_read_index (with the header
 * and footer calls before it) and through the recovery reader in a new
 * directory under root. The reader must exit 2 exactly when ark rejects,
 * and then leave the directory empty. *ark_ok receives ark's verdict and
 * *rec_rc the reader's exit status.
 */
static int rd_check_case(const char *root, const char *recover_bin,
                         const uint8_t *buf, size_t len, size_t index_off,
                         size_t index_len, int *ark_ok, int *rec_rc)
{
	ark_read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	char archive[PATH_MAX], out[PATH_MAX];
	char *argv[] = {(char *)recover_bin, archive, NULL};
	int rc;

	memset(&storage, 0, sizeof(storage));
	ctx = (ark_read_ctx_t *)(void *)storage.bytes;
	*ark_ok = ark_read_header(ctx, buf, 16U, &err) == 0 &&
	          ark_read_init(ctx, buf + len - 64U, 64U, &err) == 0 &&
	          ark_read_index(ctx, buf + index_off, index_len, &err) == 0;
	if (*ark_ok)
		ark_read_free(ctx);
	if (path_join(archive, sizeof(archive), root, "case.ark") != 0 ||
	    path_join(out, sizeof(out), root, "case-out") != 0 ||
	    write_bytes_file(archive, buf, len) != 0 || mkdir(out, 0700) != 0)
		return -1;
	*rec_rc = run_program(argv, out, "/dev/null", "/dev/null");
	rc = 0;
	if ((*rec_rc == 2) == (*ark_ok != 0) ||
	    (*rec_rc == 2 && !dir_is_empty(out)) || *rec_rc < 0 || *rec_rc > 2)
		rc = -1;
	rd_make_writable(out);
	if (remove_tree(out) != 0)
		rc = -1;
	return rc;
}

/*
 * test_integration_generate_reader_index_differential - The recovery reader
 * accepts exactly the indexes ark_read_index accepts, and rejects the
 * others before writing anything (exit 2). Structured cases cover each
 * ARCHITECTURE.md section 8.3 check with its expected verdict (the base
 * archive must also recover completely); then every index byte of the base
 * archive is flipped once (masks 0x01, 0x80, 0x04 in turn), with the index
 * hash recomputed so that only the checks after check 2 decide. See
 * ARCHITECTURE.md section 15.2.
 */
int test_integration_generate_reader_index_differential(void)
{
	static const uint8_t masks[3] = {0x01U, 0x80U, 0x04U};
	rd_archive_t a;
	char root[PATH_MAX], recover_bin[PATH_MAX];
	uint8_t base[4096];
	uint8_t buf[4096];
	size_t base_len;
	size_t index_off;
	size_t index_len;
	size_t p;
	unsigned int counts[3];
	int ark_ok;
	int rec_rc;
	int expect;
	int k;
	int rc;

	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	/* Reader outcomes: recovered, failed while extracting, rejected. */
	memset(counts, 0, sizeof(counts));
	if (build_reader(root, recover_bin, sizeof(recover_bin)) != 0)
		goto cleanup;
	for (k = 0;; k++) {
		size_t len;

		if (rd_base(&a) != 0)
			goto cleanup;
		expect = rd_mutate(&a, k);
		if (expect < 0)
			break;
		len = rd_build(&a, buf, sizeof(buf), &index_off, &index_len);
		if (len == 0U ||
		    rd_check_case(root, recover_bin, buf, len, index_off,
		                  index_len, &ark_ok, &rec_rc) != 0 ||
		    ark_ok != expect || (k == 0 && rec_rc != 0)) {
			fprintf(stderr, "  index case %d: ark %d, reader %d\n",
			        k, ark_ok, rec_rc);
			goto cleanup;
		}
		counts[rec_rc]++;
	}
	if (rd_base(&a) != 0)
		goto cleanup;
	base_len = rd_build(&a, base, sizeof(base), &index_off, &index_len);
	if (base_len == 0U)
		goto cleanup;
	for (p = 0U; p < index_len; p++) {
		memcpy(buf, base, base_len);
		buf[index_off + p] ^= masks[p % 3U];
		ark_blake3(buf + index_off, index_len,
		           buf + base_len - 64U + 16U);
		if (rd_check_case(root, recover_bin, buf, base_len, index_off,
		                  index_len, &ark_ok, &rec_rc) != 0) {
			fprintf(
			    stderr,
			    "  index byte %zu ^ 0x%02x: ark %d, reader %d\n", p,
			    masks[p % 3U], ark_ok, rec_rc);
			goto cleanup;
		}
		counts[rec_rc]++;
	}
	printf("recovery index cases: %u recovered, %u failed in extraction, "
	       "%u rejected (ark agrees on all)\n",
	       counts[0], counts[1], counts[2]);
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}

/*
 * test_integration_generate_reader_refuses_existing - Like ark without
 * --overwrite, the recovery reader refuses an object already at a member
 * path (a regular file in place of a file, a hardlink or a symlink member)
 * and leaves it unchanged; an existing directory is reused for a directory
 * member. See ARCHITECTURE.md section 15.2.
 */
int test_integration_generate_reader_refuses_existing(void)
{
	static const char *const taken[] = {"dir/original.txt", "hard.txt",
	                                    "sym.txt"};
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recover_bin[PATH_MAX], path[PATH_MAX], dir[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	uint8_t *got;
	size_t got_len;
	size_t i;
	int rc;

	got = NULL;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(archive, sizeof(archive), root, "types.ark") != 0 ||
	    make_member_type_tree(src) != 0 ||
	    create_archive(archive, src, NULL) != 0 ||
	    build_reader(root, recover_bin, sizeof(recover_bin)) != 0)
		goto cleanup;
	for (i = 0U; i < sizeof(taken) / sizeof(taken[0]); i++) {
		char name[32];

		(void)snprintf(name, sizeof(name), "out%zu", i);
		if (path_join(out, sizeof(out), root, name) != 0 ||
		    mkdir(out, 0700) != 0 ||
		    path_join(dir, sizeof(dir), out, "dir") != 0 ||
		    mkdir(dir, 0700) != 0 ||
		    path_join(path, sizeof(path), out, taken[i]) != 0 ||
		    write_text_file(path, "keep\n") != 0)
			goto cleanup;
		if (run_program(recover_argv, out, "/dev/null", "/dev/null") !=
		        1 ||
		    read_file_bytes(path, &got, &got_len) != 0 ||
		    got_len != 5U || memcmp(got, "keep\n", 5U) != 0)
			goto cleanup;
		free(got);
		got = NULL;
	}
	/* Only "dir" exists, as a directory: reused, recovery succeeds. */
	if (path_join(out, sizeof(out), root, "out-dir") != 0 ||
	    mkdir(out, 0700) != 0 ||
	    path_join(dir, sizeof(dir), out, "dir") != 0 ||
	    mkdir(dir, 0700) != 0 ||
	    run_program(recover_argv, out, NULL, NULL) != 0 ||
	    compare_tree(src, out) != 0)
		goto cleanup;
	rc = 0;
cleanup:
	free(got);
	(void)remove_tree(root);
	return rc;
}

/* rd_mode_mtime - 0 when path (not followed) has mode bits and mtime. */
static int rd_mode_mtime(const char *dir, const char *name, mode_t mode,
                         time_t mtime)
{
	char path[PATH_MAX];
	struct stat st;

	if (path_join(path, sizeof(path), dir, name) != 0 ||
	    lstat(path, &st) != 0 || st.st_mtime != mtime)
		return -1;
	if (!S_ISLNK(st.st_mode) && (st.st_mode & 0777) != mode)
		return -1;
	return 0;
}

/*
 * test_integration_generate_reader_metadata - The recovery reader restores
 * mode (0777 bits) and mtime as ark does: files and directories, including
 * a read-only directory whose file is written before its mode is set, and
 * the mtime of a symlink itself; directory metadata goes in reverse index
 * order, so a hand-built directory without its search bit still gets its
 * subdirectory's metadata restored first. See ARCHITECTURE.md sections 14.5
 * and 15.2.
 */
int test_integration_generate_reader_metadata(void)
{
	static const struct {
		const char *name;
		mode_t mode;
		time_t mtime;
	} want[] = {
	    {"run.sh", 0750, 1000000000}, {"d/f", 0604, 1100000000},
	    {"ro/f", 0444, 1200000000},   {"d", 0751, 1300000000},
	    {"ro", 0555, 1400000000},     {"l", 0, 1500000000},
	};
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recover_bin[PATH_MAX], path[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	struct timespec times[2];
	rd_archive_t hand;
	uint8_t buf[1024];
	size_t index_off;
	size_t index_len;
	size_t len;
	size_t i;
	int rc;

	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "meta.ark") != 0 ||
	    mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	if (path_join(path, sizeof(path), src, "d") != 0 ||
	    mkdir(path, 0700) != 0 ||
	    path_join(path, sizeof(path), src, "ro") != 0 ||
	    mkdir(path, 0700) != 0 ||
	    path_join(path, sizeof(path), src, "run.sh") != 0 ||
	    write_text_file(path, "#!/bin/sh\n") != 0 ||
	    path_join(path, sizeof(path), src, "d/f") != 0 ||
	    write_text_file(path, "data\n") != 0 ||
	    path_join(path, sizeof(path), src, "ro/f") != 0 ||
	    write_text_file(path, "read only\n") != 0 ||
	    path_join(path, sizeof(path), src, "l") != 0 ||
	    symlink("run.sh", path) != 0)
		goto cleanup;
	/* Files first, then directories, so no later write moves an mtime. */
	for (i = 0U; i < sizeof(want) / sizeof(want[0]); i++) {
		if (path_join(path, sizeof(path), src, want[i].name) != 0)
			goto cleanup;
		if (want[i].mode != 0 && chmod(path, want[i].mode) != 0)
			goto cleanup;
		times[0].tv_sec = want[i].mtime;
		times[0].tv_nsec = 0;
		times[1] = times[0];
		if (utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) != 0)
			goto cleanup;
	}
	if (create_archive(archive, src, NULL) != 0 ||
	    build_reader(root, recover_bin, sizeof(recover_bin)) != 0 ||
	    run_program(recover_argv, out, NULL, NULL) != 0)
		goto cleanup;
	for (i = 0U; i < sizeof(want) / sizeof(want[0]); i++) {
		if (rd_mode_mtime(out, want[i].name, want[i].mode,
		                  want[i].mtime) != 0)
			goto cleanup;
	}
	if (compare_tree(src, out) != 0)
		goto cleanup;

	/*
	 * Hand-built (ark cannot read such a source tree): directory "p"
	 * without its search bit (0600) holding directory "p/c" (0750). Only
	 * the reverse order restores c, before p loses its search bit.
	 */
	memset(&hand, 0, sizeof(hand));
	rd_set(&hand.e[0], 0x02U, "p", NULL);
	hand.e[0].mode = 0600U;
	rd_set(&hand.e[1], 0x02U, "p/c", NULL);
	hand.e[1].mode = 0750U;
	hand.e[1].mtime = UINT64_C(1600000000000000000);
	hand.n = 2U;
	hand.member_count = 2U;
	len = rd_build(&hand, buf, sizeof(buf), &index_off, &index_len);
	if (len == 0U || write_bytes_file(archive, buf, len) != 0 ||
	    path_join(out, sizeof(out), root, "out-hand") != 0 ||
	    mkdir(out, 0700) != 0 ||
	    run_program(recover_argv, out, NULL, NULL) != 0 ||
	    rd_mode_mtime(out, "p", 0600, 1700000000) != 0 ||
	    path_join(path, sizeof(path), out, "p") != 0 ||
	    chmod(path, 0700) != 0 ||
	    rd_mode_mtime(out, "p/c", 0750, 1600000000) != 0)
		goto cleanup;
	rc = 0;
cleanup:
	/* Writable again so remove_tree can empty read-only directories. */
	rd_make_writable(root);
	(void)remove_tree(root);
	return rc;
}

/*
 * test_integration_generate_reader_keeps_verified - A damaged member stops
 * the recovery with exit 1: the member before it stays, complete and
 * verified, and the damaged member's file is removed. Here the last body
 * byte (b.txt's data) is flipped, so b.txt fails its hash check. See
 * ARCHITECTURE.md section 15.2.
 */
int test_integration_generate_reader_keeps_verified(void)
{
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recover_bin[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	uint8_t *bytes;
	size_t len;
	struct stat st;
	int rc;

	bytes = NULL;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "two.ark") != 0 ||
	    mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0 ||
	    path_join(a, sizeof(a), src, "a.txt") != 0 ||
	    write_text_file(a, "first member\n") != 0 ||
	    path_join(b, sizeof(b), src, "b.txt") != 0 ||
	    write_text_file(b, "second member\n") != 0 ||
	    create_archive(archive, src, NULL) != 0 ||
	    read_file_bytes(archive, &bytes, &len) != 0 || len < 80U)
		goto cleanup;
	if (flip_archive_byte(archive, (off_t)le64_at(bytes + len - 64U) - 1) !=
	        0 ||
	    build_reader(root, recover_bin, sizeof(recover_bin)) != 0 ||
	    run_program(recover_argv, out, "/dev/null", "/dev/null") != 1)
		goto cleanup;
	if (path_join(b, sizeof(b), out, "a.txt") != 0 || !files_equal(a, b) ||
	    path_join(b, sizeof(b), out, "b.txt") != 0 || lstat(b, &st) == 0 ||
	    errno != ENOENT)
		goto cleanup;
	rc = 0;
cleanup:
	free(bytes);
	(void)remove_tree(root);
	return rc;
}

/*
 * test_integration_generate_reader_trailing_bytes - As in ark (C07), a chunk
 * must be exactly one Deflate stream: the same archive member with one byte
 * after the final block (covered by the chunk size and both hashes) fails
 * recovery and leaves no file, and recovers without that byte. See
 * ARCHITECTURE.md sections 6.2 and 15.2.
 */
int test_integration_generate_reader_trailing_bytes(void)
{
	static const uint8_t text[] = {'a', 'b', 'c'};
	char root[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	char recover_bin[PATH_MAX];
	char *recover_argv[] = {recover_bin, archive, NULL};
	uint8_t comp[64];
	uint8_t buf[512];
	ssize_t clen;
	size_t index_len;
	size_t len;
	int extra;
	int rc;

	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	clen =
	    test_deflate_compress(text, sizeof(text), comp, sizeof(comp) - 1U,
	                          ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0 ||
	    path_join(archive, sizeof(archive), root, "pad.ark") != 0 ||
	    build_reader(root, recover_bin, sizeof(recover_bin)) != 0)
		goto cleanup;
	comp[clen] = 0U;
	for (extra = 1; extra >= 0; extra--) {
		int want;

		len = test_archive_one_chunk(buf, sizeof(buf), comp,
		                             (size_t)clen + (size_t)extra,
		                             sizeof(text), &index_len);
		want = extra ? 1 : 0;
		if (len == 0U || write_bytes_file(archive, buf, len) != 0 ||
		    path_join(out, sizeof(out), root,
		              extra ? "out-pad" : "out-ok") != 0 ||
		    mkdir(out, 0700) != 0 ||
		    run_program(recover_argv, out, "/dev/null", "/dev/null") !=
		        want ||
		    dir_is_empty(out) != extra)
			goto cleanup;
	}
	rc = 0;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_deterministic(void)
{
	char root[PATH_MAX], src[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(a, sizeof(a), root, "a.ark") != 0 ||
	    path_join(b, sizeof(b), root, "b.ark") != 0)
		goto cleanup;
	if (make_basic_tree(src) != 0)
		goto cleanup;
	/* ARCHITECTURE.md section 13.1 requires same-binary determinism. */
	if (create_archive(a, src, NULL) != 0 ||
	    create_archive(b, src, NULL) != 0)
		goto cleanup;
	rc = files_equal(a, b) ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
int test_integration_large_archive(void)
{
	struct timespec start;
	struct timespec end;
	uint64_t elapsed_ms;
	time_t elapsed_sec;
	long elapsed_nsec;
	char root[PATH_MAX], src[PATH_MAX], out[PATH_MAX], archive[PATH_MAX];
	int rc;
	if (make_temp_root(root, sizeof(root)) != 0)
		return 1;
	rc = 1;
	if (path_join(src, sizeof(src), root, "src") != 0 ||
	    path_join(out, sizeof(out), root, "out") != 0 ||
	    path_join(archive, sizeof(archive), root, "large.ark") != 0)
		goto cleanup;
	if (make_large_tree(src) != 0 || mkdir(out, 0700) != 0)
		goto cleanup;
	(void)clock_gettime(CLOCK_MONOTONIC, &start);
	if (create_archive(archive, src, NULL) != 0 ||
	    verify_archive(archive) != 0 ||
	    extract_archive(archive, out, 0) != 0)
		goto cleanup;
	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed_sec = end.tv_sec - start.tv_sec;
	elapsed_nsec = end.tv_nsec - start.tv_nsec;
	if (elapsed_nsec < 0) {
		elapsed_sec--;
		elapsed_nsec += 1000000000L;
	}
	elapsed_ms = (uint64_t)elapsed_sec * 1000ULL +
	             (uint64_t)elapsed_nsec / 1000000ULL;
	(void)fprintf(stderr, "integration large archive: %llu ms\n",
	              (unsigned long long)elapsed_ms);
	rc = compare_tree(src, out) == 0 ? 0 : 1;
cleanup:
	(void)remove_tree(root);
	return rc;
}
