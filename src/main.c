/*
 * main.c - CLI entry point and argument parsing.
 *
 * This file implements subcommand and flag parsing for ark.
 *
 * See ARCHITECTURE.md section 12 for CLI contract details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"

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
static int parse_subcommand(const char *, ark_cmd_t *, ark_error_t *);
static int parse_hash(const char *, ark_hash_alg_t *, ark_error_t *);
static int push_member(ark_args_t *, const char *, int, ark_error_t *);
static void print_usage(const char *);
static void copy_msg(char *, size_t, const char *);

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

	args_free(&args);
	return 0;
}
