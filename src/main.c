/*
 * main.c - CLI entry point, argument parsing, and create traversal.
 *
 * This file implements subcommand parsing, sandbox setup, and create-side
 * filesystem traversal for ark.
 *
 * See ARCHITECTURE.md sections 12 and 13 for CLI and traversal contract
 * details.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "ark_internal.h"
#include "chevron.h"

#ifdef __linux__
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

extern long syscall(long, ...);
#endif

#ifdef __OpenBSD__
extern int pledge(const char *, const char *);
extern int unveil(const char *, const char *);
#endif

typedef enum {
	ARK_CMD_NONE = 0,
	ARK_CMD_CREATE,
	ARK_CMD_EXTRACT,
	ARK_CMD_LIST,
	ARK_CMD_VERIFY,
	ARK_CMD_GENERATE_READER,
} ark_cmd_t;

typedef struct {
	ark_cmd_t cmd;
	ark_hash_alg_t hash_alg;
	ark_deflate_mode_t deflate_mode;
	int overwrite;
	int verbose;
	int human;
	const char *output_path;
	const char *archive_path;
	const char *generate_reader_output;

	const char **member_paths;
	size_t member_count;

	const char **create_paths;
	size_t create_path_count;
} ark_args_t;

typedef struct {
	dev_t dev;
	ino_t ino;
	char path[1024];
} inode_slot_t;

typedef struct {
	inode_slot_t *slots;
	size_t capacity;
	size_t count;
} inode_table_t;

typedef struct {
	char **names;
	size_t count;
	size_t capacity;
} dir_entry_list_t;

typedef struct {
	char **paths;
	size_t count;
	size_t capacity;
} modified_path_list_t;

typedef struct {
	char root[PATH_MAX];
	dev_t root_dev;
	ark_write_ctx_t *write_ctx;
	chevron_handle_t *chev_handle;
	modified_path_list_t *modified_paths;
	inode_table_t inodes;
	uint8_t *input_buf;
	uint8_t *comp_buf;
	uint8_t *write_buf;
	size_t comp_cap;
	uint64_t *output_offset;
	int permission_error;
} traverse_ctx_t;

static int parse_args(int, char **, ark_args_t *, ark_error_t *);
static void args_init(ark_args_t *);
static void args_free(ark_args_t *);
static int usage_error(ark_error_t *, const char *);
static int fail_error(ark_error_t *, ark_err_t, const char *, const char *,
                      int);
static int parse_subcommand(const char *, ark_cmd_t *, ark_error_t *);
static int parse_hash(const char *, ark_hash_alg_t *, ark_error_t *);
static int push_member(ark_args_t *, const char *, int, ark_error_t *);
static void print_usage(const char *);
static void copy_msg(char *, size_t, const char *);
static int parent_dir(const char *, char *, size_t, ark_error_t *);
static int cmd_create(const ark_args_t *, ark_error_t *);
static int traverse_dir(const char *, ark_write_ctx_t *, chevron_handle_t *,
                        uint64_t *, modified_path_list_t *, ark_error_t *);
static int traverse_entry(traverse_ctx_t *, const char *, const char *,
                          ark_error_t *);
static int traverse_directory_abs(traverse_ctx_t *, const char *, const char *,
                                  ark_error_t *);
static int emit_regular_file(traverse_ctx_t *, const char *, const char *,
                             const struct stat *, ark_error_t *);
static int emit_nonfile_member(traverse_ctx_t *, const ark_member_meta_t *,
                               ark_error_t *);
static int chevron_write_or_fail(chevron_handle_t *, const void *, size_t,
                                 const char *, ark_error_t *);
static int emit_symlink_member(traverse_ctx_t *, const char *, const char *,
                               const struct stat *, ark_error_t *);
static int inode_table_init(inode_table_t *, ark_error_t *);
static void inode_table_free(inode_table_t *);
static const char *inode_table_lookup(const inode_table_t *, dev_t, ino_t);
static int inode_table_insert(inode_table_t *, dev_t, ino_t, const char *,
                              ark_error_t *);
static int sandbox_apply(ark_cmd_t, const char **, int, const char *,
                         const char *, ark_error_t *);
static int modified_path_list_push(modified_path_list_t *, const char *,
                                   ark_error_t *);
static void modified_path_list_free(modified_path_list_t *);
static void print_modified_summary(const modified_path_list_t *);
static int create_validate_destination_outside_sources(const char *,
                                                       const char **, size_t,
                                                       ark_error_t *);
static int create_serialize_index(ark_write_ctx_t *, uint8_t **, size_t *,
                                  ark_error_t *);
static int create_serialize_footer(ark_write_ctx_t *, uint64_t, uint64_t,
                                   uint8_t **, size_t *, ark_error_t *);
static int chevron_error_fail(ark_error_t *, const chevron_error_t *,
                              const char *, const char *);
static int exit_code_from_err(ark_err_t);

#ifdef __linux__
static uint64_t landlock_read_rights(void);
static uint64_t landlock_create_rights(int);
static uint64_t landlock_extract_rights(int);
static int landlock_detect_abi(ark_error_t *);
static int landlock_add_path_rule(int, const char *, uint64_t, ark_error_t *);
#endif

/*
 * modified_path_list_push - Append one modified-source path.
 */
static int modified_path_list_push(modified_path_list_t *list, const char *path,
                                   ark_error_t *err)
{
	char *copy;
	char **new_paths;
	size_t len;

	if (list == NULL || path == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "invalid modified-path tracking argument", "",
		                  0);
	if (list->count == list->capacity) {
		size_t new_cap;

		new_cap = list->capacity == 0U ? 32U : list->capacity * 2U;
		/* OWNERSHIP: list owns paths and frees them in
		 * modified_path_list_free. */
		new_paths = (char **)realloc((void *)list->paths,
		                             new_cap * sizeof(list->paths[0]));
		if (new_paths == NULL)
			return fail_error(
			    err, ARK_ERR_IO_ALLOC,
			    "modified-path list allocation failed", "", 0);
		list->paths = new_paths;
		list->capacity = new_cap;
	}
	len = strlen(path);
	/* OWNERSHIP: list entry copy is owned by list and freed at cleanup. */
	copy = (char *)calloc(len + 1U, 1U);
	if (copy == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "modified-path copy allocation failed", "",
		                  0);
	copy_msg(copy, len + 1U, path);
	list->paths[list->count++] = copy;
	return 0;
}

/*
 * modified_path_list_free - Release all source-modification path entries.
 */
static void modified_path_list_free(modified_path_list_t *list)
{
	size_t i;

	for (i = 0U; i < list->count; i++)
		free(list->paths[i]);
	free((void *)list->paths);
	list->paths = NULL;
	list->count = 0U;
	list->capacity = 0U;
}

/*
 * print_modified_summary - Emit post-traversal modified-source summary.
 *
 * ARCHITECTURE.md section 13.4 requires immediate warnings and an end-of-run
 * summary of all affected paths.
 */
static void print_modified_summary(const modified_path_list_t *list)
{
	size_t i;

	(void)fputs("ark: source files modified during archiving:\n", stderr);
	for (i = 0U; i < list->count; i++) {
		(void)fputs("ark:   ", stderr);
		(void)fputs(list->paths[i], stderr);
		(void)fputc('\n', stderr);
	}
}

/*
 * create_path_contains - Return 1 when child is equal to or under root.
 */
static int create_path_contains(const char *root, const char *child)
{
	size_t rlen;

	if (strcmp(root, "/") == 0)
		return 1;
	rlen = strlen(root);
	if (strncmp(root, child, rlen) != 0)
		return 0;
	if (child[rlen] == '\0' || child[rlen] == '/')
		return 1;
	return 0;
}

/*
 * create_validate_destination_outside_sources - Enforce create precondition.
 *
 * ARCHITECTURE.md section 13.5 requires destination parent realpath to be
 * outside every source root before libchevron setup and traversal.
 */
static int create_validate_destination_outside_sources(const char *archive_path,
                                                       const char **sources,
                                                       size_t source_count,
                                                       ark_error_t *err)
{
	char parent_raw[PATH_MAX];
	char dst_parent[PATH_MAX];
	char src_root[PATH_MAX];
	size_t i;

	if (archive_path == NULL || sources == NULL || source_count == 0U)
		return fail_error(err, ARK_ERR_USAGE,
		                  "create destination/source paths missing", "",
		                  0);
	if (parent_dir(archive_path, parent_raw, sizeof(parent_raw), err) != 0)
		return -1;
	if (ARK_REALPATH(parent_raw, dst_parent) == NULL)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "destination parent path resolution failed",
		                  parent_raw, errno);
	for (i = 0U; i < source_count; i++) {
		if (ARK_REALPATH(sources[i], src_root) == NULL)
			return fail_error(err, ARK_ERR_IO_READ,
			                  "source path resolution failed",
			                  sources[i], errno);
		if (create_path_contains(src_root, dst_parent))
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "destination archive path is inside source tree",
			    archive_path, 0);
	}
	return 0;
}

/*
 * create_serialize_index - Allocate and serialize the index block.
 *
 * OWNERSHIP: on success *out_buf transfers to caller and is freed by
 * cmd_create cleanup.
 */
static int create_serialize_index(ark_write_ctx_t *ctx, uint8_t **out_buf,
                                  size_t *out_len, ark_error_t *err)
{
	uint8_t *buf;
	size_t cap;

	cap = 4096U;
	for (;;) {
		ssize_t n;

		/* OWNERSHIP: temporary buffer is freed here on retry/failure.
		 */
		buf = (uint8_t *)malloc(cap);
		if (buf == NULL)
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "index buffer allocation failed", "",
			                  0);
		n = ark_write_index(ctx, buf, cap, err);
		if (n >= 0) {
			*out_buf = buf;
			*out_len = (size_t)n;
			return 0;
		}
		if (err == NULL || err->code != ARK_ERR_IO_ALLOC) {
			free(buf);
			return -1;
		}
		free(buf);
		if (cap > (SIZE_MAX / 2U))
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "index buffer size overflow", "", 0);
		cap *= 2U;
	}
}

/*
 * create_serialize_footer - Allocate and serialize the fixed footer.
 *
 * OWNERSHIP: on success *out_buf transfers to caller and is freed by
 * cmd_create cleanup.
 */
static int create_serialize_footer(ark_write_ctx_t *ctx, uint64_t index_offset,
                                   uint64_t index_size, uint8_t **out_buf,
                                   size_t *out_len, ark_error_t *err)
{
	uint8_t *buf;
	ssize_t n;

	/* OWNERSHIP: footer buffer is freed by cmd_create cleanup. */
	buf = (uint8_t *)malloc(64U);
	if (buf == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "footer buffer allocation failed", "", 0);
	n = ark_write_footer(ctx, index_offset, index_size, buf, 64U, err);
	if (n < 0) {
		free(buf);
		return -1;
	}
	*out_buf = buf;
	*out_len = (size_t)n;
	return 0;
}

/*
 * chevron_error_fail - Map libchevron failure class into ark_error_t.
 *
 * Mapping follows ARCHITECTURE.md section 11.3.
 */
static int chevron_error_fail(ark_error_t *err, const chevron_error_t *cerr,
                              const char *msg, const char *path)
{
	ark_err_t code;

	switch (cerr->err) {
	case CHEVRON_ERR_OPEN:
		code = ARK_ERR_IO_OPEN;
		break;
	case CHEVRON_ERR_WRITE:
		code = ARK_ERR_IO_WRITE;
		break;
	case CHEVRON_ERR_FSYNC:
		code = ARK_ERR_IO_FSYNC;
		break;
	case CHEVRON_ERR_CLOSE:
		code = ARK_ERR_IO_WRITE;
		break;
	case CHEVRON_ERR_RENAME:
		code = ARK_ERR_IO_COMMIT;
		break;
	case CHEVRON_ERR_PERMISSION:
		code = ARK_ERR_IO_OPEN;
		break;
	case CHEVRON_ERR_INVALID:
		code = ARK_ERR_USAGE;
		break;
	case CHEVRON_ERR_NONE:
	default:
		code = ARK_ERR_IO_WRITE;
		break;
	}
	return fail_error(err, code, msg, path, cerr->errno_value);
}

/*
 * cmd_create - Execute single-threaded archive creation.
 *
 * Runs the write sequence from ARCHITECTURE.md section 16.3, streams bytes
 * through libchevron per section 9, enforces destination preconditions per
 * section 13.5, and performs source-modification checks per section 13.4.
 */
static int cmd_create(const ark_args_t *args, ark_error_t *err)
{
	ark_write_ctx_storage_t wstorage = {0};
	ark_write_ctx_t *wctx;
	chevron_handle_t handle = CHEVRON_HANDLE_INIT;
	chevron_error_t cerr = {0};
	modified_path_list_t modified = {0};
	uint8_t header[16];
	uint8_t *index_buf = NULL;
	uint8_t *footer_buf = NULL;
	size_t index_len;
	size_t footer_len;
	ssize_t n;
	uint64_t output_offset;
	uint64_t index_offset;
	int opened;
	int rc;
	size_t i;

	if (args == NULL || args->archive_path == NULL ||
	    args->create_path_count == 0U)
		return fail_error(
		    err, ARK_ERR_USAGE,
		    "create requires archive path and source paths", "", 0);

	if (create_validate_destination_outside_sources(
	        args->archive_path, args->create_paths, args->create_path_count,
	        err) != 0)
		return -1;

	wctx = (ark_write_ctx_t *)wstorage.bytes;
	opened = 0;
	rc = -1;
	output_offset = 0U;

	if (ark_write_init(wctx, args->hash_alg, args->deflate_mode, err) != 0)
		goto cleanup;

	if (chevron_open(&handle, args->archive_path, CHEVRON_FULL,
	                 CHEVRON_MODE_DEFAULT, &cerr) != 0) {
		rc = chevron_error_fail(err, &cerr, "archive open failed",
		                        args->archive_path);
		goto cleanup;
	}
	opened = 1;

	n = ark_write_header(wctx, header, sizeof(header), err);
	if (n < 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, header, (size_t)n,
	                          args->archive_path, err) != 0)
		goto cleanup;
	output_offset = (uint64_t)n;

	for (i = 0U; i < args->create_path_count; i++) {
		if (traverse_dir(args->create_paths[i], wctx, &handle,
		                 &output_offset, &modified, err) != 0)
			goto cleanup;
	}

	if (modified.count > 0U) {
		print_modified_summary(&modified);
		(void)fail_error(err, ARK_ERR_MODIFIED,
		                 "source files modified during archiving", "",
		                 0);
		goto cleanup;
	}

	index_offset = output_offset;
	if (create_serialize_index(wctx, &index_buf, &index_len, err) != 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, index_buf, index_len,
	                          args->archive_path, err) != 0)
		goto cleanup;
	if (UINT64_MAX - output_offset < (uint64_t)index_len) {
		(void)fail_error(err, ARK_ERR_USAGE, "archive offset overflow",
		                 args->archive_path, 0);
		goto cleanup;
	}
	output_offset += (uint64_t)index_len;

	if (create_serialize_footer(wctx, index_offset, (uint64_t)index_len,
	                            &footer_buf, &footer_len, err) != 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, footer_buf, footer_len,
	                          args->archive_path, err) != 0)
		goto cleanup;

	/*
	 * SAFETY: commit occurs only after successful header, member data,
	 * index, and footer writes; all error paths abort the handle before
	 * returning. See ARCHITECTURE.md sections 9 and 16.3.
	 */
	if (chevron_commit(&handle, &cerr) != 0) {
		rc = chevron_error_fail(err, &cerr, "archive commit failed",
		                        args->archive_path);
		opened = 0;
		goto cleanup;
	}
	opened = 0;
	rc = 0;

cleanup:
	if (rc != 0 && opened)
		chevron_abort(&handle);
	free(footer_buf);
	free(index_buf);
	modified_path_list_free(&modified);
	ark_write_free(wctx);
	return rc;
}

/*
 * exit_code_from_err - Map ark_err_t class to process exit code.
 *
 * See ARCHITECTURE.md section 11.1.
 */
static int exit_code_from_err(ark_err_t code)
{
	switch (code) {
	case ARK_ERR_USAGE:
		return 1;
	case ARK_ERR_IO_READ:
	case ARK_ERR_IO_WRITE:
	case ARK_ERR_IO_SEEK:
	case ARK_ERR_IO_OPEN:
	case ARK_ERR_IO_FSYNC:
	case ARK_ERR_IO_COMMIT:
	case ARK_ERR_IO_MKDIR:
	case ARK_ERR_IO_SYMLINK:
	case ARK_ERR_IO_LINK:
	case ARK_ERR_IO_CHMOD:
	case ARK_ERR_IO_CHOWN:
	case ARK_ERR_IO_UTIMES:
	case ARK_ERR_IO_ALLOC:
		return 2;
	case ARK_ERR_FMT_MAGIC:
	case ARK_ERR_FMT_VERSION:
	case ARK_ERR_FMT_COMP_ALG:
	case ARK_ERR_FMT_HASH_ALG:
	case ARK_ERR_FMT_RESERVED:
	case ARK_ERR_FMT_INDEX:
	case ARK_ERR_FMT_MEMBER_TYPE:
	case ARK_ERR_FMT_TRUNCATED:
	case ARK_ERR_FMT_DATA:
		return 3;
	case ARK_ERR_HASH_INDEX:
	case ARK_ERR_HASH_MEMBER:
		return 4;
	case ARK_ERR_PATH_TRAVERSAL:
	case ARK_ERR_PATH_TOO_LONG:
	case ARK_ERR_PATH_ABSOLUTE:
	case ARK_ERR_PATH_ENCODING:
		return 5;
	case ARK_ERR_MODIFIED:
		return 6;
	case ARK_OK:
	default:
		return 1;
	}
}

/*
 * usage_error - Set ARK_ERR_USAGE with a descriptive parser message.
 */
static int usage_error(ark_error_t *err, const char *msg)
{
	if (err != NULL) {
		err->code = ARK_ERR_USAGE;
		err->sys_errno = 0;
		copy_msg(err->msg, sizeof(err->msg), msg);
		err->path[0] = '\0';
	}
	return -1;
}

/*
 * fail_error - Set a structured failure payload and return -1.
 */
static int fail_error(ark_error_t *err, ark_err_t code, const char *msg,
                      const char *path, int sys_errno)
{
	if (err != NULL) {
		err->code = code;
		err->sys_errno = sys_errno;
		copy_msg(err->msg, sizeof(err->msg), msg);
		copy_msg(err->path, sizeof(err->path),
		         path != NULL ? path : "");
	}
	return -1;
}

/*
 * copy_msg - Copy a C string into a fixed-size destination buffer.
 */
static void copy_msg(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (dst_len == 0)
		return;

	if (src == NULL)
		src = "";

	i = 0;
	while (i + 1 < dst_len && src[i] != '\0') {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

/*
 * parent_dir - Resolve the parent directory component of a path.
 *
 * Returns 0 on success, -1 with ARK_ERR_USAGE on invalid input.
 */
static int parent_dir(const char *path, char *dst, size_t dst_len,
                      ark_error_t *err)
{
	size_t len;
	size_t end;
	size_t i;
	size_t j;

	if (path == NULL || path[0] == '\0')
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox parent path is empty", "", 0);

	len = strlen(path);
	end = len;
	while (end > 1 && path[end - 1] == '/')
		end--;

	for (i = end; i > 0; i--) {
		if (path[i - 1] == '/') {
			if (i == 1) {
				if (dst_len < 2)
					return fail_error(
					    err, ARK_ERR_USAGE,
					    "sandbox path buffer too small",
					    path, 0);
				dst[0] = '/';
				dst[1] = '\0';
				return 0;
			}
			if (i > dst_len)
				return fail_error(
				    err, ARK_ERR_USAGE,
				    "sandbox path buffer too small", path, 0);
			for (j = 0; j + 1 < i; j++)
				dst[j] = path[j];
			dst[i - 1] = '\0';
			return 0;
		}
	}

	if (dst_len < 2)
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox path buffer too small", path, 0);
	dst[0] = '.';
	dst[1] = '\0';
	return 0;
}

/*
 * print_warning_path - Emit a traversal warning for one path.
 *
 * Phase 5.9 replaces this local formatter with the shared warning/syslog
 * path. This helper is intentionally small so Phase 5.3 can report skipped
 * traversal entries required by ARCHITECTURE.md section 13.
 */
static void print_warning_path(const char *msg, const char *path)
{
	int color;

	color = isatty(STDERR_FILENO);
	if (color)
		(void)fputs("\033[33m", stderr);
	(void)fputs("ark: warning: ", stderr);
	(void)fputs(msg, stderr);
	if (path != NULL && path[0] != '\0') {
		(void)fputs(": ", stderr);
		(void)fputs(path, stderr);
	}
	if (color)
		(void)fputs("\033[0m", stderr);
	(void)fputc('\n', stderr);
}

/*
 * inode_hash - Hash a (dev, ino) key for the create hardlink table.
 *
 * The constants and key material come from ARCHITECTURE.md section 13.2.
 */
static uint64_t inode_hash(dev_t dev, ino_t ino)
{
	return ((uint64_t)dev * UINT64_C(2654435761)) ^ (uint64_t)ino;
}

/*
 * inode_table_init - Allocate the create hardlink detection table.
 *
 * Returns 0 on success or -1 with ARK_ERR_IO_ALLOC. The initial capacity is
 * the 4096-slot requirement from ARCHITECTURE.md section 13.2.
 */
static int inode_table_init(inode_table_t *table, ark_error_t *err)
{
	table->capacity = 4096U;
	table->count = 0U;
	/* OWNERSHIP: table owns slots and releases them in inode_table_free. */
	table->slots = calloc(table->capacity, sizeof(table->slots[0]));
	if (table->slots == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "inode table allocation failed", "", 0);
	return 0;
}

/*
 * inode_table_free - Release hardlink table storage owned by traversal.
 */
static void inode_table_free(inode_table_t *table)
{
	free(table->slots);
	table->slots = NULL;
	table->capacity = 0U;
	table->count = 0U;
}

/*
 * inode_table_lookup - Return first-seen member path for an inode key.
 *
 * Returns NULL when the inode has not been recorded. The returned pointer is
 * table-owned and valid until inode_table_free.
 */
static const char *inode_table_lookup(const inode_table_t *table, dev_t dev,
                                      ino_t ino)
{
	size_t i;
	size_t pos;

	if (ino == 0 || table->capacity == 0U)
		return NULL;
	pos = (size_t)(inode_hash(dev, ino) % table->capacity);
	for (i = 0U; i < table->capacity; i++) {
		inode_slot_t *slot;

		slot = &table->slots[(pos + i) % table->capacity];
		if (slot->ino == 0)
			return NULL;
		if (slot->ino == ino && slot->dev == dev)
			return slot->path;
	}
	return NULL;
}

/*
 * inode_table_place - Insert one slot into a table with known free capacity.
 */
static void inode_table_place(inode_slot_t *slots, size_t capacity, dev_t dev,
                              ino_t ino, const char *path)
{
	size_t i;
	size_t pos;

	pos = (size_t)(inode_hash(dev, ino) % capacity);
	for (i = 0U; i < capacity; i++) {
		inode_slot_t *slot;

		slot = &slots[(pos + i) % capacity];
		if (slot->ino != 0)
			continue;
		slot->dev = dev;
		slot->ino = ino;
		copy_msg(slot->path, sizeof(slot->path), path);
		return;
	}
}

/*
 * inode_table_grow - Double hardlink table capacity at 0.75 load factor.
 *
 * OWNERSHIP: on success, ownership transfers from the old slots allocation to
 * the new allocation; on failure, the original table remains owned by table.
 */
static int inode_table_grow(inode_table_t *table, ark_error_t *err)
{
	inode_slot_t *new_slots;
	size_t new_cap;
	size_t i;

	new_cap = table->capacity * 2U;
	/* OWNERSHIP: new_slots replaces table->slots after successful rehash.
	 */
	new_slots = calloc(new_cap, sizeof(new_slots[0]));
	if (new_slots == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "inode table resize failed", "", 0);
	for (i = 0U; i < table->capacity; i++) {
		inode_slot_t *slot;

		slot = &table->slots[i];
		if (slot->ino != 0)
			inode_table_place(new_slots, new_cap, slot->dev,
			                  slot->ino, slot->path);
	}
	free(table->slots);
	table->slots = new_slots;
	table->capacity = new_cap;
	return 0;
}

/*
 * inode_table_insert - Record first-seen path for a regular-file inode.
 *
 * The table is open-addressed with linear probing as specified by
 * ARCHITECTURE.md section 13.2.
 */
static int inode_table_insert(inode_table_t *table, dev_t dev, ino_t ino,
                              const char *path, ark_error_t *err)
{
	if (ino == 0)
		return 0;
	if ((table->count + 1U) * 4U > table->capacity * 3U) {
		if (inode_table_grow(table, err) != 0)
			return -1;
	}
	inode_table_place(table->slots, table->capacity, dev, ino, path);
	table->count++;
	return 0;
}

/*
 * path_join - Join an absolute parent path and one directory entry name.
 */
static int path_join(const char *parent, const char *name, char *dst,
                     size_t dst_len, ark_error_t *err)
{
	size_t plen;
	size_t nlen;
	size_t need;

	plen = strlen(parent);
	nlen = strlen(name);
	need = plen + nlen + 2U;
	if (strcmp(parent, "/") == 0)
		need--;
	if (need > dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "filesystem path too long", parent, 0);
	dst[0] = '\0';
	if (strcmp(parent, "/") == 0) {
		dst[0] = '/';
		copy_msg(dst + 1U, dst_len - 1U, name);
	} else {
		copy_msg(dst, dst_len, parent);
		dst[plen] = '/';
		copy_msg(dst + plen + 1U, dst_len - plen - 1U, name);
	}
	return 0;
}

/*
 * member_path_from_abs - Strip resolved source root from an absolute path.
 *
 * The root directory itself is omitted by callers; this helper maps only
 * descendants to clean relative member paths per ARCHITECTURE.md section 13.6.
 */
static int member_path_from_abs(const char *root, const char *abs_path,
                                char *dst, size_t dst_len, ark_error_t *err)
{
	size_t rlen;
	const char *rel;
	size_t rel_len;

	rlen = strlen(root);
	if (strcmp(root, "/") == 0) {
		rel = abs_path + 1;
		rel_len = strlen(rel);
	} else {
		if (strncmp(abs_path, root, rlen) != 0 || abs_path[rlen] != '/')
			return fail_error(err, ARK_ERR_USAGE,
			                  "path outside traversal root",
			                  abs_path, 0);
		rel = abs_path + rlen + 1U;
		rel_len = strlen(rel);
	}
	if (rel_len == 0U || rel_len >= dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "member path too long", abs_path, 0);
	copy_msg(dst, dst_len, rel);
	return 0;
}

/*
 * basename_member_path - Derive the member name for a single-file source.
 */
static int basename_member_path(const char *abs_path, char *dst, size_t dst_len,
                                ark_error_t *err)
{
	const char *base;

	base = strrchr(abs_path, '/');
	if (base == NULL)
		base = abs_path;
	else
		base++;
	if (base[0] == '\0' || strlen(base) >= dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "member path too long", abs_path, 0);
	copy_msg(dst, dst_len, base);
	return 0;
}

/*
 * stat_mtime_nsec - Convert struct stat mtime to archive u64 nanoseconds.
 *
 * Uses signed 64-bit arithmetic and rejects unrepresentable timestamps as
 * required by ARCHITECTURE.md section 5.2.
 */
static int stat_mtime_nsec(const struct stat *sb, const char *path,
                           uint64_t *out, ark_error_t *err)
{
	int64_t sec;
	int64_t nsec;
	int64_t base;
	int64_t total;

	sec = (int64_t)sb->st_mtim.tv_sec;
	nsec = (int64_t)sb->st_mtim.tv_nsec;
	if (sec > INT64_C(9223372036) || sec < -INT64_C(9223372036))
		return fail_error(err, ARK_ERR_IO_READ,
		                  "mtime outside representable range", path, 0);
	base = sec * INT64_C(1000000000);
	if (base > INT64_MAX - nsec)
		return fail_error(err, ARK_ERR_IO_READ,
		                  "mtime outside representable range", path, 0);
	total = base + nsec;
	*out = (uint64_t)total;
	return 0;
}

/*
 * member_meta_init - Populate common metadata from lstat output.
 *
 * See ARCHITECTURE.md section 5.2 for raw mode, uid, gid, and mtime fields.
 */
static int member_meta_init(ark_member_meta_t *meta, uint8_t type,
                            const char *member_path, const struct stat *sb,
                            ark_error_t *err)
{
	*meta = (ark_member_meta_t){0};
	meta->type = type;
	meta->mode = (uint32_t)(sb->st_mode & 0xffffU);
	meta->uid = (uint32_t)sb->st_uid;
	meta->gid = (uint32_t)sb->st_gid;
	if (stat_mtime_nsec(sb, member_path, &meta->mtime, err) != 0)
		return -1;
	copy_msg(meta->path, sizeof(meta->path), member_path);
	return 0;
}

/*
 * emit_nonfile_member - Write a directory, symlink, or hardlink index member.
 *
 * Non-file members have no data body; ark_write_member_end finalizes the hash
 * of the empty byte sequence. See ARCHITECTURE.md sections 5.2 and 16.3.
 */
static int emit_nonfile_member(traverse_ctx_t *ctx,
                               const ark_member_meta_t *meta, ark_error_t *err)
{
	if (ark_write_member_begin(ctx->write_ctx, meta, err) != 0)
		return -1;
	return ark_write_member_end(ctx->write_ctx, err);
}

/*
 * chevron_write_or_fail - Write one serialized chunk to the archive handle.
 */
static int chevron_write_or_fail(chevron_handle_t *handle, const void *buf,
                                 size_t len, const char *path, ark_error_t *err)
{
	chevron_error_t cerr = {0};

	if (chevron_write_chunk(handle, buf, len, &cerr) != 0)
		return fail_error(err, ARK_ERR_IO_WRITE,
		                  "archive chunk write failed", path,
		                  cerr.errno_value);
	return 0;
}

/*
 * emit_regular_file - Compress and write one regular-file member.
 *
 * Single-threaded Phase 5 compression happens directly in traversal. The
 * per-chunk buffers are traversal-owned and allocated before this hot path.
 * See ARCHITECTURE.md sections 13.1 and 16.3.
 */
static int emit_regular_file(traverse_ctx_t *ctx, const char *abs_path,
                             const char *member_path, const struct stat *sb,
                             ark_error_t *err)
{
	ark_member_meta_t meta;
	struct stat meta_sb;
	ssize_t n;
	ssize_t clen;
	ssize_t written;
	uint64_t remaining;
	size_t want;
	size_t got;
	int fd = -1;
	int rc = -1;

	if (sb->st_size < 0)
		return fail_error(err, ARK_ERR_IO_READ, "negative file size",
		                  abs_path, 0);
	if (member_meta_init(&meta, 0x01U, member_path, sb, err) != 0)
		return -1;
	meta.size_original = (uint64_t)sb->st_size;
	if (meta.size_original != 0U)
		meta.data_offset = *ctx->output_offset;

	/*
	 * SAFETY: O_NOFOLLOW prevents a file swapped to a symlink after lstat
	 * from being followed during create traversal. See ARCHITECTURE.md
	 * section 13.3.
	 */
	fd = ARK_OPEN(abs_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
	if (fd == -1) {
		if (errno == EACCES || errno == EPERM) {
			print_warning_path("permission denied", abs_path);
			ctx->permission_error = 1;
			return 0;
		}
		return fail_error(err, ARK_ERR_IO_READ,
		                  "member file open failed", abs_path, errno);
	}

	if (ark_write_member_begin(ctx->write_ctx, &meta, err) != 0)
		goto cleanup;

	/*
	 * SAFETY: input, compression, and write buffers are allocated by
	 * traverse_dir before entering the per-chunk loop; no hot-path
	 * allocation.
	 */
	remaining = meta.size_original;
	while (remaining > 0U) {
		want = remaining > (uint64_t)ARK_CHUNK_SIZE
		           ? (size_t)ARK_CHUNK_SIZE
		           : (size_t)remaining;
		got = 0U;
		while (got < want) {
			n = ARK_READ(fd, ctx->input_buf + got, want - got);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				rc = fail_error(err, ARK_ERR_IO_READ,
				                "member file read failed",
				                abs_path, errno);
				goto cleanup;
			}
			if (n == 0) {
				rc = fail_error(err, ARK_ERR_IO_READ,
				                "member file ended early",
				                abs_path, 0);
				goto cleanup;
			}
			got += (size_t)n;
		}

		clen = ark_deflate_compress(ctx->input_buf, want, ctx->comp_buf,
		                            ctx->comp_cap, ARK_DEFLATE_DEFAULT);
		if (clen < 0) {
			rc = fail_error(err, ARK_ERR_IO_READ,
			                "member compression failed", abs_path,
			                0);
			goto cleanup;
		}
		/*
		 * SAFETY: ark_write_chunk is called only for the active
		 * regular-file member and in read order. See ARCHITECTURE.md
		 * section 16.3.
		 */
		written =
		    ark_write_chunk(ctx->write_ctx, ctx->comp_buf, (size_t)clen,
		                    ctx->write_buf, ctx->comp_cap, err);
		if (written < 0) {
			rc = -1;
			goto cleanup;
		}
		if (chevron_write_or_fail(ctx->chev_handle, ctx->write_buf,
		                          (size_t)written, abs_path,
		                          err) != 0) {
			rc = -1;
			goto cleanup;
		}
		if (UINT64_MAX - *ctx->output_offset < (uint64_t)written) {
			rc = fail_error(err, ARK_ERR_USAGE,
			                "archive offset overflow", abs_path, 0);
			goto cleanup;
		}
		*ctx->output_offset += (uint64_t)written;
		remaining -= want;
	}

	/*
	 * ARCHITECTURE.md section 13.4: compare pre-read lstat metadata with
	 * post-read fstat metadata on the same fd to detect source changes
	 * during archiving.
	 */
	if (ARK_FSTAT(fd, &meta_sb) != 0) {
		rc = fail_error(err, ARK_ERR_IO_READ,
		                "member file fstat failed", abs_path, errno);
		goto cleanup;
	}
	if (meta_sb.st_size != sb->st_size ||
	    meta_sb.st_mtim.tv_sec != sb->st_mtim.tv_sec ||
	    meta_sb.st_mtim.tv_nsec != sb->st_mtim.tv_nsec) {
		print_warning_path("source file modified during read",
		                   abs_path);
		if (modified_path_list_push(ctx->modified_paths, abs_path,
		                            err) != 0) {
			rc = -1;
			goto cleanup;
		}
	}

	if (ark_write_member_end(ctx->write_ctx, err) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (fd != -1 && ARK_CLOSE(fd) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_READ,
		                "member file close failed", abs_path, errno);
	return rc;
}

/*
 * emit_hardlink_member - Record a later path to a first-seen regular file.
 *
 * See ARCHITECTURE.md section 13.2 for first-seen hardlink target behavior.
 */
static int emit_hardlink_member(traverse_ctx_t *ctx, const char *member_path,
                                const char *target_path, const struct stat *sb,
                                ark_error_t *err)
{
	ark_member_meta_t meta;

	if (member_meta_init(&meta, 0x04U, member_path, sb, err) != 0)
		return -1;
	copy_msg(meta.link, sizeof(meta.link), target_path);
	return emit_nonfile_member(ctx, &meta, err);
}

/*
 * emit_symlink_member - Read and store one symlink target without following it.
 *
 * readlink is used after lstat classification. See ARCHITECTURE.md section
 * 13.3 for the symlink-never-followed rule.
 */
static int emit_symlink_member(traverse_ctx_t *ctx, const char *abs_path,
                               const char *member_path, const struct stat *sb,
                               ark_error_t *err)
{
	ark_member_meta_t meta;
	ssize_t n;

	if (member_meta_init(&meta, 0x03U, member_path, sb, err) != 0)
		return -1;
	n = ARK_READLINK(abs_path, meta.link, sizeof(meta.link));
	if (n < 0)
		return fail_error(err, ARK_ERR_IO_READ, "symlink read failed",
		                  abs_path, errno);
	if ((size_t)n >= sizeof(meta.link))
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "symlink target too long", abs_path, 0);
	meta.link[n] = '\0';
	return emit_nonfile_member(ctx, &meta, err);
}

/*
 * dir_entry_cmp - qsort comparator using raw byte-order filename comparison.
 */
static int dir_entry_cmp(const void *a, const void *b)
{
	const char *const *sa;
	const char *const *sb;
	size_t la;
	size_t lb;
	size_t min;
	int cmp;

	sa = (const char *const *)a;
	sb = (const char *const *)b;
	la = strlen(*sa);
	lb = strlen(*sb);
	min = la < lb ? la : lb;
	cmp = memcmp(*sa, *sb, min);
	if (cmp != 0)
		return cmp;
	if (la < lb)
		return -1;
	if (la > lb)
		return 1;
	return 0;
}

/*
 * dir_entry_list_free - Release names collected from one directory level.
 */
static void dir_entry_list_free(dir_entry_list_t *list)
{
	size_t i;

	for (i = 0U; i < list->count; i++)
		free(list->names[i]);
	free((void *)list->names);
	list->names = NULL;
	list->count = 0U;
	list->capacity = 0U;
}

/*
 * dir_entry_name_dup - Copy a readdir d_name into list-owned storage.
 */
static char *dir_entry_name_dup(const char *name)
{
	char *copy;
	size_t len;

	len = strlen(name);
	/* OWNERSHIP: returned name is freed by dir_entry_list_free after push.
	 */
	copy = calloc(len + 1U, 1U);
	if (copy == NULL)
		return NULL;
	copy_msg(copy, len + 1U, name);
	return copy;
}

/*
 * dir_entry_list_push - Append one owned name to a directory entry list.
 *
 * OWNERSHIP: on success, list owns name and frees it in dir_entry_list_free.
 */
static int dir_entry_list_push(dir_entry_list_t *list, char *name,
                               ark_error_t *err)
{
	char **new_names;

	if (list->count == list->capacity) {
		size_t new_cap;

		new_cap = list->capacity == 0U ? 32U : list->capacity * 2U;
		/* OWNERSHIP: list retains ownership across successful realloc.
		 */
		new_names = (char **)realloc((void *)list->names,
		                             new_cap * sizeof(list->names[0]));
		if (new_names == NULL) {
			free(name);
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "directory entry allocation failed",
			                  "", 0);
		}
		list->names = new_names;
		list->capacity = new_cap;
	}
	list->names[list->count++] = name;
	return 0;
}

/*
 * dir_entries_collect - Read, own, and sort one directory's entry names.
 *
 * Entries '.' and '..' are discarded before sorting. Sorting uses raw
 * memcmp byte order as required by ARCHITECTURE.md section 13.1.
 */
static int dir_entries_collect(const char *abs_path, dir_entry_list_t *list,
                               ark_error_t *err)
{
	DIR *dir = NULL;
	const struct dirent *dent;
	char *name;
	int rc = -1;

	dir = ARK_OPENDIR(abs_path);
	if (dir == NULL) {
		if (errno == EACCES || errno == EPERM)
			return 1;
		return fail_error(err, ARK_ERR_IO_READ, "directory open failed",
		                  abs_path, errno);
	}

	errno = 0;
	while ((dent = ARK_READDIR(dir)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		name = dir_entry_name_dup(dent->d_name);
		if (name == NULL) {
			rc = fail_error(err, ARK_ERR_IO_ALLOC,
			                "directory entry allocation failed",
			                abs_path, 0);
			goto cleanup;
		}
		if (dir_entry_list_push(list, name, err) != 0)
			goto cleanup;
	}
	if (errno != 0) {
		if (errno == EACCES || errno == EPERM) {
			rc = 1;
			goto cleanup;
		}
		rc = fail_error(err, ARK_ERR_IO_READ, "directory read failed",
		                abs_path, errno);
		goto cleanup;
	}
	/*
	 * SAFETY: entries are sorted before processing or recursion to preserve
	 * deterministic archive output. See ARCHITECTURE.md section 13.1.
	 */
	if (list->count > 1U)
		qsort((void *)list->names, list->count, sizeof(list->names[0]),
		      dir_entry_cmp);
	rc = 0;

cleanup:
	if (dir != NULL && ARK_CLOSEDIR(dir) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_READ, "directory close failed",
		                abs_path, errno);
	if (rc != 0)
		dir_entry_list_free(list);
	return rc;
}

/*
 * traverse_directory_abs - Depth-first traversal of one absolute directory.
 *
 * The directory itself is already emitted by traverse_entry except for the
 * source root, which is intentionally omitted per ARCHITECTURE.md section
 * 13.6.
 */
static int traverse_directory_abs(traverse_ctx_t *ctx, const char *abs_path,
                                  const char *member_path, ark_error_t *err)
{
	dir_entry_list_t list = {0};
	char child_abs[PATH_MAX];
	char child_member[1024];
	size_t i;
	int rc;

	(void)member_path;
	rc = dir_entries_collect(abs_path, &list, err);
	if (rc == 1) {
		print_warning_path("permission denied", abs_path);
		ctx->permission_error = 1;
		return 0;
	}
	if (rc != 0)
		return -1;

	for (i = 0U; i < list.count; i++) {
		if (path_join(abs_path, list.names[i], child_abs,
		              sizeof(child_abs), err) != 0)
			goto fail;
		if (member_path_from_abs(ctx->root, child_abs, child_member,
		                         sizeof(child_member), err) != 0)
			goto fail;
		if (traverse_entry(ctx, child_abs, child_member, err) != 0)
			goto fail;
	}
	dir_entry_list_free(&list);
	return 0;

fail:
	dir_entry_list_free(&list);
	return -1;
}

/*
 * traverse_entry - Classify and emit one filesystem entry.
 *
 * Uses ARK_LSTAT only, so symlinks encountered inside the tree are never
 * followed. See ARCHITECTURE.md sections 13.1, 13.3, 13.7, and 13.9.
 */
static int traverse_entry(traverse_ctx_t *ctx, const char *abs_path,
                          const char *member_path, ark_error_t *err)
{
	ark_member_meta_t meta;
	struct stat sb;

	/* SAFETY: lstat classifies the entry without following symlinks. */
	if (ARK_LSTAT(abs_path, &sb) != 0) {
		if (errno == EACCES || errno == EPERM) {
			print_warning_path("permission denied", abs_path);
			ctx->permission_error = 1;
			return 0;
		}
		return fail_error(err, ARK_ERR_IO_READ, "lstat failed",
		                  abs_path, errno);
	}

	if (S_ISDIR(sb.st_mode)) {
		/*
		 * SAFETY: do not recurse across device boundaries; a mount
		 * point is skipped with a warning. See ARCHITECTURE.md
		 * section 13.7.
		 */
		if (sb.st_dev != ctx->root_dev) {
			print_warning_path("skipping mount point", abs_path);
			return 0;
		}
		if (member_meta_init(&meta, 0x02U, member_path, &sb, err) != 0)
			return -1;
		if (emit_nonfile_member(ctx, &meta, err) != 0)
			return -1;
		return traverse_directory_abs(ctx, abs_path, member_path, err);
	}

	if (S_ISREG(sb.st_mode)) {
		const char *target;

		/* ARCHITECTURE.md section 13.2: first inode stores data; later
		 * matches become hardlink members. */
		target = inode_table_lookup(&ctx->inodes, sb.st_dev, sb.st_ino);
		if (target != NULL)
			return emit_hardlink_member(ctx, member_path, target,
			                            &sb, err);
		if (sb.st_nlink > 1) {
			if (inode_table_insert(&ctx->inodes, sb.st_dev,
			                       sb.st_ino, member_path,
			                       err) != 0)
				return -1;
		}
		return emit_regular_file(ctx, abs_path, member_path, &sb, err);
	}

	if (S_ISLNK(sb.st_mode))
		return emit_symlink_member(ctx, abs_path, member_path, &sb,
		                           err);

	/* ARCHITECTURE.md section 13.9: unsupported special objects are
	 * skipped. */
	print_warning_path("skipping special filesystem object", abs_path);
	return 0;
}

/*
 * traverse_dir - Resolve and archive one create source path.
 *
 * Resolves the source path once with ARK_REALPATH, strips that resolved root
 * from all descendant member paths, and walks directories depth-first in
 * deterministic byte order. Returns 0 on success or -1 with err populated.
 *
 * Preconditions: write_ctx is initialized, header has been written, and
 * chev_handle is an active libchevron streaming handle. See ARCHITECTURE.md
 * sections 13.1, 13.2, 13.6, and 16.3.
 */
static int traverse_dir(const char *src_path, ark_write_ctx_t *write_ctx,
                        chevron_handle_t *chev_handle, uint64_t *output_offset,
                        modified_path_list_t *modified_paths, ark_error_t *err)
{
	traverse_ctx_t ctx;
	struct stat sb;
	char member_path[1024];
	int rc = -1;

	ctx = (traverse_ctx_t){0};
	ctx.write_ctx = write_ctx;
	ctx.chev_handle = chev_handle;
	ctx.output_offset = output_offset;
	ctx.modified_paths = modified_paths;

	if (src_path == NULL || write_ctx == NULL || chev_handle == NULL ||
	    output_offset == NULL || modified_paths == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "invalid traversal argument", "", 0);
	if (ARK_REALPATH(src_path, ctx.root) == NULL)
		return fail_error(err, ARK_ERR_IO_READ,
		                  "source path resolution failed", src_path,
		                  errno);
	if (ARK_LSTAT(ctx.root, &sb) != 0)
		return fail_error(err, ARK_ERR_IO_READ, "lstat failed",
		                  ctx.root, errno);
	ctx.root_dev = sb.st_dev;

	if (inode_table_init(&ctx.inodes, err) != 0)
		goto cleanup;
	/* OWNERSHIP: traversal owns chunk buffers and frees them at cleanup. */
	ctx.input_buf = malloc(ARK_CHUNK_SIZE);
	ctx.comp_cap = ark_deflate_bound(ARK_CHUNK_SIZE);
	ctx.comp_buf = malloc(ctx.comp_cap);
	ctx.write_buf = malloc(ctx.comp_cap);
	if (ctx.input_buf == NULL || ctx.comp_buf == NULL ||
	    ctx.write_buf == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "traversal buffer allocation failed", "", 0);
		goto cleanup;
	}

	if (S_ISDIR(sb.st_mode)) {
		/* ARCHITECTURE.md section 13.6: source root directory is
		 * omitted. */
		if (traverse_directory_abs(&ctx, ctx.root, "", err) != 0)
			goto cleanup;
	} else {
		if (basename_member_path(ctx.root, member_path,
		                         sizeof(member_path), err) != 0)
			goto cleanup;
		if (traverse_entry(&ctx, ctx.root, member_path, err) != 0)
			goto cleanup;
	}

	if (ctx.permission_error) {
		(void)fail_error(err, ARK_ERR_IO_READ,
		                 "permission errors during traversal", src_path,
		                 0);
		goto cleanup;
	}
	rc = 0;

cleanup:
	free(ctx.write_buf);
	free(ctx.comp_buf);
	free(ctx.input_buf);
	inode_table_free(&ctx.inodes);
	return rc;
}

#ifdef __linux__
/*
 * landlock_read_rights - Filesystem read rights used by all readers.
 */
static uint64_t landlock_read_rights(void)
{
	return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

/*
 * landlock_create_rights - Create writer rights for create/generate-reader.
 *
 * See ARCHITECTURE.md section 10.4 policy table.
 */
static uint64_t landlock_create_rights(int abi)
{
	uint64_t rights;

	rights = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	         LANDLOCK_ACCESS_FS_MAKE_REG;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
	return rights;
}

/*
 * landlock_extract_rights - Extract writer rights for destination dir.
 *
 * See ARCHITECTURE.md section 10.4 (remove-file/remove-dir/refer notes).
 */
static uint64_t landlock_extract_rights(int abi)
{
	uint64_t rights;

	rights = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	         LANDLOCK_ACCESS_FS_REMOVE_FILE |
	         LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	         LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		rights |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
	return rights;
}

/*
 * landlock_detect_abi - Query Landlock ABI version and enforce Linux minimum.
 *
 * If Landlock is unavailable, fail immediately with the minimum kernel message
 * required by ARCHITECTURE.md section 10.4.
 */
static int landlock_detect_abi(ark_error_t *err)
{
	struct landlock_ruleset_attr attr = {0};
	int abi;

	abi = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr),
	                   LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock unavailable; minimum supported "
		                  "kernel is Linux 5.13",
		                  "", errno);
	return abi;
}

/*
 * landlock_add_path_rule - Add one path-beneath rule for a sandboxed path.
 */
static int landlock_add_path_rule(int ruleset_fd, const char *path,
                                  uint64_t rights, ark_error_t *err)
{
	struct landlock_path_beneath_attr rule = {0};
	int path_fd;

	path_fd = ARK_OPEN(path, O_RDONLY | O_CLOEXEC, 0);
	if (path_fd == -1)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "sandbox path open failed", path, errno);

	rule.allowed_access = rights;
	rule.parent_fd = path_fd;
	if (syscall(SYS_landlock_add_rule, ruleset_fd,
	            LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0) {
		(void)ARK_CLOSE(path_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock add rule failed", path, errno);
	}

	if (ARK_CLOSE(path_fd) != 0)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "sandbox path close failed", path, errno);
	return 0;
}
#endif

/*
 * sandbox_apply - Apply per-subcommand sandbox policy.
 *
 * src_paths/src_count are used by create so all source roots are registered in
 * one additive policy application. dst_path is extract --output or
 * generate-reader output path depending on cmd.
 *
 * Returns 0 on success, -1 on error with err populated.
 *
 * See ARCHITECTURE.md section 10.4 for policy strings and path scope.
 */
static int sandbox_apply(ark_cmd_t cmd, const char **src_paths, int src_count,
                         const char *archive_path, const char *dst_path,
                         ark_error_t *err)
{
#ifdef __OpenBSD__
	int i;
	char parent[PATH_MAX];

	/*
	 * OpenBSD policy mapping per subcommand. See ARCHITECTURE.md section
	 * 10.4.
	 */
	switch (cmd) {
	case ARK_CMD_CREATE:
		if (archive_path == NULL)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "create archive path missing for sandbox", "", 0);
		for (i = 0; i < src_count; i++) {
			if (unveil(src_paths[i], "r") != 0)
				return fail_error(
				    err, ARK_ERR_USAGE,
				    "unveil failed for create source path",
				    src_paths[i], errno);
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) != 0)
			return -1;
		if (unveil(parent, "rwc") != 0)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "unveil failed for create destination parent",
			    parent, errno);
		/*
		 * SAFETY: lock unveil before pledge so no broader path view
		 * remains reachable after process promises are reduced.
		 */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath wpath cpath fattr pthread", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_EXTRACT:
		if (archive_path == NULL || dst_path == NULL)
			return fail_error(err, ARK_ERR_USAGE,
			                  "extract paths missing for sandbox",
			                  "", 0);
		if (unveil(archive_path, "r") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for archive path",
			                  archive_path, errno);
		if (unveil(dst_path, "rwc") != 0)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "unveil failed for extract destination", dst_path,
			    errno);
		/*
		 * SAFETY: lock unveil before pledge to keep extraction path
		 * scope immutable. See ARCHITECTURE.md section 10.4.
		 */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath wpath cpath fattr pthread", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_LIST:
	case ARK_CMD_VERIFY:
		if (archive_path == NULL)
			return fail_error(err, ARK_ERR_USAGE,
			                  "archive path missing for sandbox",
			                  "", 0);
		if (unveil(archive_path, "r") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for archive path",
			                  archive_path, errno);
		/* SAFETY: lock unveil before pledge to keep read scope
		 * immutable. */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_GENERATE_READER:
		if (dst_path == NULL)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "generate-reader output path missing for sandbox",
			    "", 0);
		if (parent_dir(dst_path, parent, sizeof(parent), err) != 0)
			return -1;
		if (unveil(parent, "rwc") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for output parent",
			                  parent, errno);
		/* SAFETY: lock unveil before pledge to keep write scope
		 * immutable. */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio wpath cpath", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	default:
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox policy unavailable for subcommand",
		                  "", 0);
	}
#elif defined(__linux__)
	int abi;
	int ruleset_fd;
	int i;
	uint64_t handled;
	struct landlock_ruleset_attr ruleset_attr = {0};
	char parent[PATH_MAX];

	abi = landlock_detect_abi(err);
	if (abi < 1)
		return -1;

	handled = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	          LANDLOCK_ACCESS_FS_REMOVE_FILE |
	          LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		handled |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif

	ruleset_attr.handled_access_fs = handled;
	ruleset_fd = (int)syscall(SYS_landlock_create_ruleset, &ruleset_attr,
	                          sizeof(ruleset_attr), 0);
	if (ruleset_fd == -1)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock ruleset creation failed", "",
		                  errno);

	switch (cmd) {
	case ARK_CMD_CREATE:
		if (archive_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "create archive path missing for sandbox", "", 0);
		}
		for (i = 0; i < src_count; i++) {
			if (landlock_add_path_rule(ruleset_fd, src_paths[i],
			                           landlock_read_rights(),
			                           err) != 0) {
				(void)ARK_CLOSE(ruleset_fd);
				return -1;
			}
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) !=
		    0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_create_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_EXTRACT:
		if (archive_path == NULL || dst_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(err, ARK_ERR_USAGE,
			                  "extract paths missing for sandbox",
			                  "", 0);
		}
		if (landlock_add_path_rule(ruleset_fd, archive_path,
		                           landlock_read_rights(), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, dst_path,
		                           landlock_extract_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_LIST:
	case ARK_CMD_VERIFY:
		if (archive_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(err, ARK_ERR_USAGE,
			                  "archive path missing for sandbox",
			                  "", 0);
		}
		if (landlock_add_path_rule(ruleset_fd, archive_path,
		                           landlock_read_rights(), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_GENERATE_READER:
		if (dst_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "generate-reader output path missing for sandbox",
			    "", 0);
		}
		if (parent_dir(dst_path, parent, sizeof(parent), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_create_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	default:
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox policy unavailable for subcommand",
		                  "", 0);
	}

	/*
	 * SAFETY: PR_SET_NO_NEW_PRIVS must be active before Landlock
	 * enforcement. See ARCHITECTURE.md section 10.4.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "prctl(PR_SET_NO_NEW_PRIVS) failed", "",
		                  errno);
	}
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "landlock_restrict_self failed", "", errno);
	}
	if (ARK_CLOSE(ruleset_fd) != 0)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock ruleset close failed", "", errno);
	return 0;
#else
	(void)cmd;
	(void)src_paths;
	(void)src_count;
	(void)archive_path;
	(void)dst_path;
	return fail_error(err, ARK_ERR_USAGE,
	                  "sandbox unsupported on this platform", "", 0);
#endif
}

/*
 * args_init - Initialize parsed-argument defaults.
 *
 * See ARCHITECTURE.md section 12.2 for default hash and output behavior.
 */
static void args_init(ark_args_t *args)
{
	*args = (ark_args_t){0};
	args->hash_alg = ARK_HASH_BLAKE3;
	args->deflate_mode = ARK_DEFLATE_DEFAULT;
	args->output_path = ".";
	args->generate_reader_output = "recovery.c";
}

/*
 * args_free - Release parser-owned arrays.
 *
 * OWNERSHIP: parse_args allocates member_paths and create_paths arrays;
 * args_free releases both arrays exactly once.
 */
static void args_free(ark_args_t *args)
{
	free((void *)args->member_paths);
	args->member_paths = NULL;
	args->member_count = 0;

	free((void *)args->create_paths);
	args->create_paths = NULL;
	args->create_path_count = 0;
}

/*
 * parse_subcommand - Map CLI subcommand token to internal enum.
 */
static int parse_subcommand(const char *s, ark_cmd_t *cmd, ark_error_t *err)
{
	if (strcmp(s, "create") == 0) {
		*cmd = ARK_CMD_CREATE;
		return 0;
	}
	if (strcmp(s, "extract") == 0) {
		*cmd = ARK_CMD_EXTRACT;
		return 0;
	}
	if (strcmp(s, "list") == 0) {
		*cmd = ARK_CMD_LIST;
		return 0;
	}
	if (strcmp(s, "verify") == 0) {
		*cmd = ARK_CMD_VERIFY;
		return 0;
	}
	if (strcmp(s, "generate-reader") == 0) {
		*cmd = ARK_CMD_GENERATE_READER;
		return 0;
	}

	return usage_error(err, "unknown subcommand");
}

/*
 * parse_hash - Parse --hash value.
 */
static int parse_hash(const char *s, ark_hash_alg_t *hash_alg, ark_error_t *err)
{
	if (strcmp(s, "blake3") == 0) {
		*hash_alg = ARK_HASH_BLAKE3;
		return 0;
	}
	if (strcmp(s, "sha256") == 0) {
		*hash_alg = ARK_HASH_SHA256;
		return 0;
	}

	return usage_error(err, "invalid value for --hash");
}

/*
 * push_member - Append one --member path into parser-owned storage.
 */
static int push_member(ark_args_t *args, const char *member, int max_members,
                       ark_error_t *err)
{
	if ((int)args->member_count >= max_members)
		return usage_error(err, "too many --member arguments");
	args->member_paths[args->member_count++] = member;
	return 0;
}

/*
 * parse_args - Parse subcommand, flags, and operands into ark_args_t.
 *
 * Enforces ARCHITECTURE.md section 12.2 CLI surface and rejects invalid
 * flag/subcommand combinations with ARK_ERR_USAGE.
 */
static int parse_args(int argc, char **argv, ark_args_t *args, ark_error_t *err)
{
	int i;
	int max_items;
	int hash_seen;
	int output_seen;
	int operands_start;

	if (argc < 2)
		return usage_error(err, "missing subcommand");

	args_init(args);

	max_items = argc;
	args->member_paths = (const char **)calloc(
	    (size_t)max_items, sizeof(args->member_paths[0]));
	if (args->member_paths == NULL)
		return usage_error(err, "memory allocation failed");

	args->create_paths = (const char **)calloc(
	    (size_t)max_items, sizeof(args->create_paths[0]));
	if (args->create_paths == NULL) {
		args_free(args);
		return usage_error(err, "memory allocation failed");
	}

	if (parse_subcommand(argv[1], &args->cmd, err) != 0)
		goto fail;

	/*
	 * NOTE: Flags are parsed before operands for deterministic CLI
	 * semantics. See ARCHITECTURE.md section 12.2.
	 */
	hash_seen = 0;
	output_seen = 0;
	for (i = 2; i < argc; i++) {
		if (strncmp(argv[i], "--", 2) != 0)
			break;

		if (strcmp(argv[i], "--verbose") == 0) {
			args->verbose = 1;
			continue;
		}

		if (strcmp(argv[i], "--fast") == 0) {
			if (args->cmd != ARK_CMD_CREATE)
				goto fail_usage_fast;
			args->deflate_mode = ARK_DEFLATE_FAST;
			continue;
		}

		if (strcmp(argv[i], "--overwrite") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT)
				goto fail_usage_overwrite;
			args->overwrite = 1;
			continue;
		}

		if (strcmp(argv[i], "--human") == 0) {
			if (args->cmd != ARK_CMD_LIST)
				goto fail_usage_human;
			args->human = 1;
			continue;
		}

		if (strcmp(argv[i], "--hash") == 0) {
			if (args->cmd != ARK_CMD_CREATE)
				goto fail_usage_hash_scope;
			if (hash_seen)
				goto fail_usage_hash_dup;
			if (++i >= argc)
				goto fail_usage_hash_missing;
			if (parse_hash(argv[i], &args->hash_alg, err) != 0)
				goto fail;
			hash_seen = 1;
			continue;
		}

		if (strcmp(argv[i], "--output") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT)
				goto fail_usage_output_scope;
			if (output_seen)
				goto fail_usage_output_dup;
			if (++i >= argc)
				goto fail_usage_output_missing;
			args->output_path = argv[i];
			output_seen = 1;
			continue;
		}

		if (strcmp(argv[i], "--member") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT &&
			    args->cmd != ARK_CMD_VERIFY)
				goto fail_usage_member_scope;
			if (++i >= argc)
				goto fail_usage_member_missing;
			if (push_member(args, argv[i], max_items, err) != 0)
				goto fail;
			continue;
		}

		goto fail_usage_unknown_flag;
	}
	operands_start = i;

	/*
	 * Enforce subcommand operand contracts from ARCHITECTURE.md
	 * section 12.2.
	 */
	switch (args->cmd) {
	case ARK_CMD_CREATE:
		if ((argc - operands_start) < 2)
			goto fail_usage_create_operands;
		args->archive_path = argv[operands_start];
		for (i = operands_start + 1; i < argc; i++)
			args->create_paths[args->create_path_count++] = argv[i];
		break;
	case ARK_CMD_EXTRACT:
		if ((argc - operands_start) != 1)
			goto fail_usage_extract_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_LIST:
		if ((argc - operands_start) != 1)
			goto fail_usage_list_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_VERIFY:
		if ((argc - operands_start) != 1)
			goto fail_usage_verify_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_GENERATE_READER:
		if ((argc - operands_start) > 1)
			goto fail_usage_generate_reader_operands;
		if ((argc - operands_start) == 1)
			args->generate_reader_output = argv[operands_start];
		break;
	default:
		goto fail_usage_unknown_subcommand;
	}

	return 0;

fail_usage_fast:
	(void)usage_error(err, "--fast is valid only for create");
	goto fail;
fail_usage_overwrite:
	(void)usage_error(err, "--overwrite is valid only for extract");
	goto fail;
fail_usage_human:
	(void)usage_error(err, "--human is valid only for list");
	goto fail;
fail_usage_hash_scope:
	(void)usage_error(err, "--hash is valid only for create");
	goto fail;
fail_usage_hash_dup:
	(void)usage_error(err, "duplicate --hash flag");
	goto fail;
fail_usage_hash_missing:
	(void)usage_error(err, "missing value for --hash");
	goto fail;
fail_usage_output_scope:
	(void)usage_error(err, "--output is valid only for extract");
	goto fail;
fail_usage_output_dup:
	(void)usage_error(err, "duplicate --output flag");
	goto fail;
fail_usage_output_missing:
	(void)usage_error(err, "missing value for --output");
	goto fail;
fail_usage_member_scope:
	(void)usage_error(err, "--member is valid only for extract or verify");
	goto fail;
fail_usage_member_missing:
	(void)usage_error(err, "missing value for --member");
	goto fail;
fail_usage_unknown_flag:
	(void)usage_error(err, "unknown flag");
	goto fail;
fail_usage_create_operands:
	(void)usage_error(
	    err, "create requires archive path and at least one source path");
	goto fail;
fail_usage_extract_operands:
	(void)usage_error(err, "extract requires exactly one archive path");
	goto fail;
fail_usage_list_operands:
	(void)usage_error(err, "list requires exactly one archive path");
	goto fail;
fail_usage_verify_operands:
	(void)usage_error(err, "verify requires exactly one archive path");
	goto fail;
fail_usage_generate_reader_operands:
	(void)usage_error(err,
	                  "generate-reader accepts at most one output path");
	goto fail;
fail_usage_unknown_subcommand:
	(void)usage_error(err, "unknown subcommand");
	goto fail;

fail:
	args_free(args);
	return -1;
}

/*
 * print_usage - Emit usage guidance for invalid invocation and exit 1.
 *
 * ARCHITECTURE.md section 12.3 requires one-line problem detail followed by
 * "See man ark for usage." with no inline synopsis.
 */
static void print_usage(const char *problem)
{
	if (problem != NULL && problem[0] != '\0')
		(void)fputs("ark: ", stderr), (void)fputs(problem, stderr),
		    (void)fputc('\n', stderr);
	else
		(void)fputs("ark: invalid invocation\n", stderr);
	(void)fputs("See man ark for usage.\n", stderr);
	exit(1);
}

int main(int argc, char **argv)
{
	ark_args_t args;
	ark_error_t err = {0};
	int rc;

	if (parse_args(argc, argv, &args, &err) != 0) {
		if (err.code == ARK_ERR_USAGE)
			print_usage(err.msg);
		(void)fputs("ark: argument parsing failed\n", stderr);
		return 1;
	}

#if defined(__linux__) || defined(__OpenBSD__)
	const char *sandbox_dst;

	if (args.cmd == ARK_CMD_EXTRACT)
		sandbox_dst = args.output_path;
	else if (args.cmd == ARK_CMD_GENERATE_READER)
		sandbox_dst = args.generate_reader_output;
	else
		sandbox_dst = NULL;

	/*
	 * Platform-specific ordering scaffold for Phase 6 integration.
	 * See ARCHITECTURE.md section 6.3 and 10.4.
	 */
	if (sandbox_apply(args.cmd, args.create_paths,
	                  (int)args.create_path_count, args.archive_path,
	                  sandbox_dst, &err) != 0) {
		if (err.code == ARK_ERR_USAGE)
			print_usage(err.msg);
		if (err.path[0] != '\0')
			(void)fputs("ark: ", stderr),
			    (void)fputs(err.msg, stderr),
			    (void)fputs(": ", stderr),
			    (void)fputs(err.path, stderr),
			    (void)fputc('\n', stderr);
		else
			(void)fputs("ark: ", stderr),
			    (void)fputs(err.msg, stderr),
			    (void)fputc('\n', stderr);
		args_free(&args);
		return 1;
	}
#endif

	if (args.cmd == ARK_CMD_CREATE) {
		rc = cmd_create(&args, &err);
		if (rc != 0) {
			if (err.path[0] != '\0')
				(void)fputs("ark: ", stderr),
				    (void)fputs(err.msg, stderr),
				    (void)fputs(": ", stderr),
				    (void)fputs(err.path, stderr),
				    (void)fputc('\n', stderr);
			else
				(void)fputs("ark: ", stderr),
				    (void)fputs(err.msg, stderr),
				    (void)fputc('\n', stderr);
			args_free(&args);
			return exit_code_from_err(err.code);
		}
	}

	args_free(&args);
	return 0;
}
