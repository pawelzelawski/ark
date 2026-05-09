/*
 * main.c - CLI entry point and argument parsing.
 *
 * This file implements subcommand and flag parsing for ark.
 *
 * See ARCHITECTURE.md section 12 for CLI contract details.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "ark_internal.h"

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
static int sandbox_apply(ark_cmd_t, const char **, int, const char *,
                         const char *, ark_error_t *);

#ifdef __linux__
static uint64_t landlock_read_rights(void);
static uint64_t landlock_create_rights(int);
static uint64_t landlock_extract_rights(int);
static int landlock_detect_abi(ark_error_t *);
static int landlock_add_path_rule(int, const char *, uint64_t, ark_error_t *);
#endif

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

	args_free(&args);
	return 0;
}
