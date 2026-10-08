/*
 * test_integration.c - End-to-end CLI integration tests for Phase 7.1.
 *
 * Exercises the production ark binary against real temporary files as required
 * by TESTING.md section 8. Each subcommand runs in a child process so the
 * process-wide sandbox state from ARCHITECTURE.md sections 6.3 and 10.4 cannot
 * leak into the test harness.
 */
#include "deflate.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
 * run_program - Fork, optionally redirect, and exec one test command.
 *
 * SAFETY: ark subcommands are executed in child processes so pledge/Landlock
 * restrictions are discarded when that child exits. See ARCHITECTURE.md
 * sections 6.3 and 10.4.
 */
static int run_program(char *const argv[], const char *cwd,
                       const char *stdout_path, const char *stderr_path)
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
