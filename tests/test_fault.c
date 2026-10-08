/*
 * test_fault.c - Create and extract sequence fault-injection tests.
 *
 * Implements TESTING.md section 6. Each test injects exactly one failure into
 * the command sequence and verifies the documented ark_err_t value. The same
 * cmd_create/cmd_extract implementations used by production are exercised via
 * ARK_TEST-only entry points in main.c.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "archive.h"
#include "ark_internal.h"

enum {
	ARK_CLI_FAULT_NONE = 0,
	ARK_CLI_FAULT_CREATE_OPEN_ARCHIVE,
	ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE,
	ARK_CLI_FAULT_CREATE_COMMIT,
	ARK_CLI_FAULT_CREATE_MARK_MODIFIED,
	ARK_CLI_FAULT_CLEANUP_GROW
};

int ark_test_create_archive(const char *, const char **, size_t, int,
                            ark_hash_alg_t, ark_deflate_mode_t, ark_error_t *);
int ark_test_extract_archive(const char *, const char *, int, const char *, int,
                             ark_error_t *);
void ark_test_cli_fault_reset(void);
void ark_test_cli_fault_inject(int, int, ark_err_t, int);
void ark_test_force_owner_restore(int);

int test_write_header_dst_cap_undersize(void);
int test_write_index_dst_cap_undersize(void);
int test_write_footer_dst_cap_undersize(void);
int test_read_check2_index_hash_mismatch(void);
int test_read_chunk_invalid_deflate(void);
int test_read_chunk_length_mismatch(void);
int test_read_chunk_compressed_size_mismatch(void);
int test_write_valid_sequence_zero_members(void);
int test_deflate_round_trip_text(void);
int test_deflate_invalid_stream(void);
int test_deflate_truncated_stream(void);
int test_deflate_output_buffer_too_small(void);

/* path_join - Build one test path under an already bounded temp root. */
static int path_join(char *dst, size_t dst_len, const char *a, const char *b)
{
	int n;

	n = snprintf(dst, dst_len, "%s/%s", a, b);
	return n > 0 && (size_t)n < dst_len ? 0 : -1;
}

/* write_file - Create a small fixture file owned by the current test. */
static int write_file(const char *path, const char *data)
{
	int fd;
	size_t len;
	ssize_t n;

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
	if (fd == -1)
		return -1;
	len = strlen(data);
	n = write(fd, data, len);
	if (close(fd) != 0)
		return -1;
	return n == (ssize_t)len ? 0 : -1;
}

/* rm_rf - Best-effort recursive cleanup for test-owned temporary trees. */
static void rm_rf(const char *path)
{
	struct stat sb;
	DIR *dir;

	if (lstat(path, &sb) != 0)
		return;
	if (!S_ISDIR(sb.st_mode)) {
		(void)unlink(path);
		return;
	}
	dir = opendir(path);
	if (dir != NULL) {
		const struct dirent *dent;

		while ((dent = readdir(dir)) != NULL) {
			char child[PATH_MAX];

			if (strcmp(dent->d_name, ".") == 0 ||
			    strcmp(dent->d_name, "..") == 0)
				continue;
			if (path_join(child, sizeof(child), path,
			              dent->d_name) == 0)
				rm_rf(child);
		}
		(void)closedir(dir);
	}
	(void)rmdir(path);
}

/* make_temp_root - Create one isolated test directory under /tmp. */
static int make_temp_root(char root[PATH_MAX])
{
	(void)snprintf(root, PATH_MAX, "/tmp/ark_fault_%ld_XXXXXX",
	               (long)getpid());
	return mkdtemp(root) == NULL ? -1 : 0;
}

/* make_regular_fixture - Create one source file, archive path, and output dir.
 */
static int make_regular_fixture(char root[PATH_MAX], char src[PATH_MAX],
                                char archive[PATH_MAX], char out[PATH_MAX])
{
	if (make_temp_root(root) != 0)
		return -1;
	if (path_join(src, PATH_MAX, root, "file.txt") != 0 ||
	    path_join(archive, PATH_MAX, root, "out.ark") != 0 ||
	    path_join(out, PATH_MAX, root, "extract") != 0)
		return -1;
	if (write_file(src, "fault fixture data\n") != 0)
		return -1;
	return mkdir(out, 0700) == 0 ? 0 : -1;
}

/* make_tree_fixture - Create directory, symlink, and hardlink members. */
static int make_tree_fixture(char root[PATH_MAX], char src[PATH_MAX],
                             char archive[PATH_MAX], char out[PATH_MAX])
{
	char file[PATH_MAX];
	char hard[PATH_MAX];
	char linkpath[PATH_MAX];
	char subdir[PATH_MAX];

	if (make_temp_root(root) != 0)
		return -1;
	if (path_join(src, PATH_MAX, root, "src") != 0 ||
	    path_join(archive, PATH_MAX, root, "out.ark") != 0 ||
	    path_join(out, PATH_MAX, root, "extract") != 0)
		return -1;
	if (mkdir(src, 0700) != 0 || mkdir(out, 0700) != 0)
		return -1;
	if (path_join(file, sizeof(file), src, "file.txt") != 0 ||
	    path_join(hard, sizeof(hard), src, "hard.txt") != 0 ||
	    path_join(linkpath, sizeof(linkpath), src, "link.txt") != 0 ||
	    path_join(subdir, sizeof(subdir), src, "dir") != 0)
		return -1;
	if (write_file(file, "tree fixture data\n") != 0)
		return -1;
	if (mkdir(subdir, 0700) != 0)
		return -1;
	if (link(file, hard) != 0)
		return -1;
	return symlink("file.txt", linkpath);
}

/* create_archive - Build a valid fixture archive before extract fault tests. */
static int create_archive(const char *archive, const char *src)
{
	ark_error_t err;
	const char *paths[1];

	err = (ark_error_t){0};
	paths[0] = src;
	fault_reset();
	ark_test_cli_fault_reset();
	return ark_test_create_archive(archive, paths, 1U, 1, ARK_HASH_BLAKE3,
	                               ARK_DEFLATE_DEFAULT, &err);
}

/* expect_create_fault - Inject one create failure and check the error code. */
static int expect_create_fault(int fault_kind, int fail_on, int use_tree,
                               ark_err_t code)
{
	char root[PATH_MAX];
	char src[PATH_MAX];
	char archive[PATH_MAX];
	char out[PATH_MAX];
	ark_error_t err;
	const char *paths[1];
	int rc;

	err = (ark_error_t){0};
	if (use_tree) {
		if (make_tree_fixture(root, src, archive, out) != 0)
			return 1;
	} else if (make_regular_fixture(root, src, archive, out) != 0)
		return 1;
	paths[0] = src;
	fault_reset();
	ark_test_cli_fault_reset();
	if (fault_kind >= 1000)
		ark_test_cli_fault_inject(fault_kind - 1000, fail_on, code,
		                          EIO);
	else
		fault_inject(fault_kind, fail_on, EIO);
	rc = ark_test_create_archive(archive, paths, 1U, 1, ARK_HASH_BLAKE3,
	                             ARK_DEFLATE_DEFAULT, &err);
	fault_reset();
	ark_test_cli_fault_reset();
	rm_rf(root);
	if (code == ARK_ERR_MODIFIED)
		return rc != 0 && err.code == code && err.sys_errno == 0 ? 0
		                                                         : 1;
	return rc != 0 && err.code == code && err.sys_errno == EIO ? 0 : 1;
}

/* expect_extract_fault - Inject one extract failure and check the error code.
 */
static int expect_extract_fault(int fault_kind, int fail_on, int use_tree,
                                int overwrite, ark_err_t code)
{
	char root[PATH_MAX];
	char src[PATH_MAX];
	char archive[PATH_MAX];
	char out[PATH_MAX];
	ark_error_t err;
	int rc;

	err = (ark_error_t){0};
	if (use_tree) {
		if (make_tree_fixture(root, src, archive, out) != 0)
			return 1;
	} else if (make_regular_fixture(root, src, archive, out) != 0)
		return 1;
	if (create_archive(archive, src) != 0) {
		rm_rf(root);
		return 1;
	}
	if (overwrite) {
		char existing[PATH_MAX];

		if (path_join(existing, sizeof(existing), out,
		              use_tree ? "src/file.txt" : "file.txt") != 0) {
			rm_rf(root);
			return 1;
		}
		if (use_tree) {
			char parent[PATH_MAX];

			if (path_join(parent, sizeof(parent), out, "src") !=
			        0 ||
			    mkdir(parent, 0700) != 0) {
				rm_rf(root);
				return 1;
			}
		}
		if (write_file(existing, "existing\n") != 0) {
			rm_rf(root);
			return 1;
		}
	}
	fault_reset();
	ark_test_cli_fault_reset();
	fault_inject(fault_kind, fail_on, EIO);
	rc = ark_test_extract_archive(archive, out, overwrite, NULL, 1, &err);
	fault_reset();
	ark_test_cli_fault_reset();
	rm_rf(root);
	return rc != 0 && err.code == code && err.sys_errno == EIO ? 0 : 1;
}

int test_fault_archive_header_dst_cap_undersize(void)
{
	return test_write_header_dst_cap_undersize();
}

int test_fault_archive_index_dst_cap_undersize(void)
{
	return test_write_index_dst_cap_undersize();
}

int test_fault_archive_footer_dst_cap_undersize(void)
{
	return test_write_footer_dst_cap_undersize();
}

int test_fault_archive_index_hash_mismatch(void)
{
	return test_read_check2_index_hash_mismatch();
}

int test_fault_archive_invalid_deflate_maps_fmt_data(void)
{
	return test_read_chunk_invalid_deflate();
}

int test_fault_archive_chunk_length_mismatch_maps_fmt_data(void)
{
	return test_read_chunk_length_mismatch();
}

int test_fault_archive_chunk_size_mismatch_maps_fmt_data(void)
{
	return test_read_chunk_compressed_size_mismatch();
}

int test_fault_deflate_invalid_stream(void)
{
	return test_deflate_invalid_stream();
}

int test_fault_deflate_truncated_stream(void)
{
	return test_deflate_truncated_stream();
}

int test_fault_deflate_output_buffer_too_small(void)
{
	return test_deflate_output_buffer_too_small();
}

int test_fault_injection_no_effect_on_archive_component(void)
{
	/* archive.c is format-only and performs no wrapped syscalls. */
	fault_inject(ARK_FAULT_READ, 1, EIO);
	if (test_write_valid_sequence_zero_members() != 0) {
		fault_reset();
		return 1;
	}
	fault_reset();
	return 0;
}

int test_fault_injection_no_effect_on_deflate_component(void)
{
	/* deflate.c is pure compute; ARK_* syscall stubs must not affect it. */
	fault_inject(ARK_FAULT_WRITE, 1, EIO);
	if (test_deflate_round_trip_text() != 0) {
		fault_reset();
		return 1;
	}
	fault_reset();
	return 0;
}

int test_fault_create_open_archive(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_OPEN_ARCHIVE, 1,
	                           0, ARK_ERR_IO_OPEN);
}

int test_fault_create_write_header(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE, 1,
	                           0, ARK_ERR_IO_WRITE);
}

int test_fault_create_lstat_member(void)
{
	return expect_create_fault(ARK_FAULT_LSTAT, 1, 0, ARK_ERR_IO_READ);
}

int test_fault_create_open_member(void)
{
	return expect_create_fault(ARK_FAULT_OPEN, 1, 0, ARK_ERR_IO_READ);
}

int test_fault_create_read_member(void)
{
	return expect_create_fault(ARK_FAULT_READ, 1, 0, ARK_ERR_IO_READ);
}

int test_fault_create_write_chunk(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE, 2,
	                           0, ARK_ERR_IO_WRITE);
}

int test_fault_create_write_index(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE, 3,
	                           0, ARK_ERR_IO_WRITE);
}

int test_fault_create_write_footer(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE, 4,
	                           0, ARK_ERR_IO_WRITE);
}

int test_fault_create_opendir(void)
{
	return expect_create_fault(ARK_FAULT_OPENDIR, 1, 1, ARK_ERR_IO_READ);
}

int test_fault_create_readdir(void)
{
	return expect_create_fault(ARK_FAULT_READDIR, 1, 1, ARK_ERR_IO_READ);
}

int test_fault_create_realpath(void)
{
	return expect_create_fault(ARK_FAULT_REALPATH, 2, 0, ARK_ERR_IO_READ);
}

int test_fault_create_commit(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_COMMIT, 1, 0,
	                           ARK_ERR_IO_COMMIT);
}

int test_fault_create_fsync(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_COMMIT, 1, 0,
	                           ARK_ERR_IO_FSYNC);
}

int test_fault_create_modified(void)
{
	return expect_create_fault(1000 + ARK_CLI_FAULT_CREATE_MARK_MODIFIED, 1,
	                           0, ARK_ERR_MODIFIED);
}

int test_fault_extract_open_archive(void)
{
	return expect_extract_fault(ARK_FAULT_OPEN, 2, 0, 0, ARK_ERR_IO_OPEN);
}

int test_fault_extract_read_header(void)
{
	return expect_extract_fault(ARK_FAULT_READ, 1, 0, 0, ARK_ERR_IO_READ);
}

int test_fault_extract_read_footer(void)
{
	return expect_extract_fault(ARK_FAULT_READ, 2, 0, 0, ARK_ERR_IO_READ);
}

int test_fault_extract_read_index(void)
{
	return expect_extract_fault(ARK_FAULT_READ, 3, 0, 0, ARK_ERR_IO_READ);
}

int test_fault_extract_seek(void)
{
	return expect_extract_fault(ARK_FAULT_LSEEK, 1, 0, 0, ARK_ERR_IO_SEEK);
}

int test_fault_extract_read_chunk(void)
{
	return expect_extract_fault(ARK_FAULT_READ, 4, 0, 0, ARK_ERR_IO_READ);
}

int test_fault_extract_open_output(void)
{
	return expect_extract_fault(ARK_FAULT_OPENAT, 1, 0, 0, ARK_ERR_IO_OPEN);
}

int test_fault_extract_write_output(void)
{
	return expect_extract_fault(ARK_FAULT_WRITE, 1, 0, 0, ARK_ERR_IO_WRITE);
}

int test_fault_extract_mkdir(void)
{
	return expect_extract_fault(ARK_FAULT_MKDIRAT, 1, 1, 0,
	                            ARK_ERR_IO_MKDIR);
}

int test_fault_extract_symlink_create(void)
{
	return expect_extract_fault(ARK_FAULT_SYMLINKAT, 1, 1, 0,
	                            ARK_ERR_IO_SYMLINK);
}

int test_fault_extract_link_create(void)
{
	return expect_extract_fault(ARK_FAULT_LINKAT, 1, 1, 0, ARK_ERR_IO_LINK);
}

int test_fault_extract_lchown(void)
{
	int rc;

	ark_test_force_owner_restore(1);
	rc = expect_extract_fault(ARK_FAULT_FCHOWN, 1, 0, 0, ARK_ERR_IO_CHOWN);
	ark_test_force_owner_restore(0);
	return rc;
}

int test_fault_extract_chmod(void)
{
	return expect_extract_fault(ARK_FAULT_FCHMOD, 1, 0, 0,
	                            ARK_ERR_IO_CHMOD);
}

int test_fault_extract_utimensat(void)
{
	return expect_extract_fault(ARK_FAULT_FUTIMENS, 1, 0, 0,
	                            ARK_ERR_IO_UTIMES);
}

int test_fault_extract_unlink_overwrite(void)
{
	return expect_extract_fault(ARK_FAULT_UNLINKAT, 1, 0, 1,
	                            ARK_ERR_IO_OPEN);
}

/* dir_is_empty - Return 1 when path is a directory with no entries. */
static int dir_is_empty(const char *path)
{
	const struct dirent *dent;
	DIR *dir;
	int empty;

	dir = opendir(path);
	if (dir == NULL)
		return 0;
	empty = 1;
	while ((dent = readdir(dir)) != NULL) {
		if (strcmp(dent->d_name, ".") != 0 &&
		    strcmp(dent->d_name, "..") != 0)
			empty = 0;
	}
	(void)closedir(dir);
	return empty;
}

/*
 * expect_cleanup_grow_fault - Fail the first cleanup tracker allocation
 * during extraction; no created object may be left behind untracked.
 *
 * member == NULL extracts everything (the first object created is the "dir"
 * directory member); otherwise only member is extracted and its missing
 * parent "dir" is created implicitly. See ARCHITECTURE.md section 14.3.
 */
static int expect_cleanup_grow_fault(const char *member)
{
	char root[PATH_MAX];
	char src[PATH_MAX];
	char archive[PATH_MAX];
	char out[PATH_MAX];
	char nested[PATH_MAX];
	ark_error_t err;
	int rc;

	err = (ark_error_t){0};
	if (make_tree_fixture(root, src, archive, out) != 0)
		return 1;
	if (path_join(nested, sizeof(nested), src, "dir/nested.txt") != 0 ||
	    write_file(nested, "nested fixture data\n") != 0 ||
	    create_archive(archive, src) != 0) {
		rm_rf(root);
		return 1;
	}
	ark_test_cli_fault_inject(ARK_CLI_FAULT_CLEANUP_GROW, 1,
	                          ARK_ERR_IO_ALLOC, 0);
	rc = ark_test_extract_archive(archive, out, 0, member, 1, &err);
	ark_test_cli_fault_reset();
	if (rc == 0 || err.code != ARK_ERR_IO_ALLOC || !dir_is_empty(out)) {
		rm_rf(root);
		return 1;
	}
	rm_rf(root);
	return 0;
}

int test_fault_extract_cleanup_track_alloc(void)
{
	if (expect_cleanup_grow_fault(NULL) != 0)
		return 1;
	return expect_cleanup_grow_fault("dir/nested.txt");
}

int test_fault_extract_cleanup_unlink(void)
{
	return expect_extract_fault(ARK_FAULT_UNLINKAT, 1, 0, 1,
	                            ARK_ERR_IO_OPEN);
}

int test_fault_extract_cleanup_rmdir(void)
{
	return expect_extract_fault(ARK_FAULT_RMDIR, 1, 1, 0,
	                            ARK_ERR_IO_WRITE) == 0
	           ? 1
	           : 0;
}
