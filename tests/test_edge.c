/*
 * test_edge.c - Component-level edge and adversarial format tests.
 *
 * These tests stay at the archive/deflate layer for Phase 5.10 and avoid
 * main.c extraction integration behaviour, which is validated in Phase 7.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "archive.h"

typedef ark_write_ctx_storage_t write_ctx_storage_t;

int test_write_valid_sequence_zero_members(void);
int test_write_valid_sequence_one_member(void);
int test_write_empty_file_chunk_count_zero(void);
int test_read_empty_file_chunk_count_zero(void);
int test_read_member_count_too_large(void);
int test_read_check11_data_offset_low(void);
int test_read_check11_data_range_exceeds_body(void);
int test_read_check12_overlapping_ranges(void);
int test_read_check13_hardlink_targets_dir(void);
int test_read_check6_hardlink_forward_reference(void);
int test_read_check7_duplicate_path(void);
int test_read_check3_path_absolute(void);
int test_read_check3_path_dotdot(void);
int test_read_check4_path_too_long(void);
int test_read_check5_link_dotdot(void);
int test_read_check5_link_too_long(void);
int test_read_check10_size_mismatch(void);
int test_read_check2_index_hash_mismatch(void);
int test_read_verify_hash_mismatch(void);

static ark_write_ctx_t *ctx_from_storage(write_ctx_storage_t *storage)
{
	/* Context storage is opaque; tests provide zeroed backing bytes. */
	(void)storage->align;
	memset(storage, 0, sizeof(*storage));
	return (ark_write_ctx_t *)(void *)storage->bytes;
}

static void meta_init(ark_member_meta_t *meta, const char *path)
{
	/* Minimal regular-file metadata baseline used by writer edge checks. */
	memset(meta, 0, sizeof(*meta));
	meta->type = 0x01U;
	meta->mode = 0644U;
	meta->uid = 1000U;
	meta->gid = 1000U;
	meta->mtime = 1U;
	(void)strncpy(meta->path, path, sizeof(meta->path) - 1);
}

int test_edge_empty_archive(void)
{
	return test_write_valid_sequence_zero_members();
}

int test_edge_single_member(void)
{
	return test_write_valid_sequence_one_member();
}

int test_edge_max_path_length(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	char path[1024];
	size_t i;

	/* ARCHITECTURE.md §5.2/§8.3: member paths up to 1023 bytes are valid.
	 */
	for (i = 0; i < 1023; i++)
		path[i] = 'a';
	path[1023] = '\0';

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, path);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	ark_write_free(ctx);
	return 0;
}

int test_edge_path_one_over_max(void)
{
	/* ARCHITECTURE.md §8.3 check 5: paths over 1023 bytes are rejected. */
	return test_read_check4_path_too_long();
}

int test_edge_empty_file(void)
{
	if (test_write_empty_file_chunk_count_zero() != 0)
		return 1;
	return test_read_empty_file_chunk_count_zero();
}

int test_adv_forged_member_count(void)
{
	return test_read_member_count_too_large();
}

int test_adv_data_offset_in_header(void)
{
	return test_read_check11_data_offset_low();
}

int test_adv_data_range_past_index(void)
{
	return test_read_check11_data_range_exceeds_body();
}

int test_adv_overlapping_data_ranges(void)
{
	return test_read_check12_overlapping_ranges();
}

int test_adv_hardlink_to_dir(void)
{
	return test_read_check13_hardlink_targets_dir();
}

int test_adv_hardlink_forward_ref(void)
{
	return test_read_check6_hardlink_forward_reference();
}

int test_adv_duplicate_paths(void)
{
	return test_read_check7_duplicate_path();
}

int test_adv_path_traversal_abs(void)
{
	return test_read_check3_path_absolute();
}

int test_adv_path_traversal_dotdot(void)
{
	return test_read_check3_path_dotdot();
}

int test_adv_link_target_dotdot(void)
{
	return test_read_check5_link_dotdot();
}

int test_adv_link_target_too_long(void)
{
	return test_read_check5_link_too_long();
}

int test_adv_chunk_count_mismatch(void)
{
	return test_read_check10_size_mismatch();
}

int test_adv_nonzero_chunk_count_empty_file(void)
{
	return test_read_check10_size_mismatch();
}

int test_adv_corrupt_index_hash(void)
{
	return test_read_check2_index_hash_mismatch();
}

int test_adv_corrupt_member_data(void)
{
	return test_read_verify_hash_mismatch();
}
