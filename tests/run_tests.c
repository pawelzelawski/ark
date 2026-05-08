#include <stddef.h>
#include <stdio.h>

typedef int (*test_fn_t)(void);

typedef struct {
	const char *name;
	test_fn_t fn;
} test_case_t;

int test_write_valid_sequence_zero_members(void);
int test_write_valid_sequence_one_member(void);
int test_write_valid_sequence_multi_member(void);
int test_write_chunk_outside_member(void);
int test_write_member_begin_while_active(void);
int test_write_member_end_outside_member(void);
int test_write_index_before_member_end(void);
int test_write_footer_before_index(void);
int test_write_chunk_non_regular_member(void);
int test_write_free_any_state(void);
int test_write_header_dst_cap_undersize(void);
int test_write_footer_dst_cap_undersize(void);
int test_write_index_dst_cap_undersize(void);
int test_write_header_magic(void);
int test_write_header_version(void);
int test_write_header_flags_zero(void);
int test_write_header_comp_alg(void);
int test_write_header_hash_alg(void);
int test_write_header_reserved_zero(void);
int test_write_footer_magic_confirm(void);
int test_write_footer_index_offset(void);
int test_write_index_little_endian(void);
int test_write_empty_file_chunk_count_zero(void);
int test_write_member_hash_non_file_types(void);
int test_write_index_hash_matches_footer(void);
int test_write_member_hash_matches_compressed_bytes(void);
int test_blake3_vectors_all(void);
int test_blake3_empty(void);
int test_blake3_single_chunk(void);
int test_blake3_multi_chunk(void);
int test_blake3_large(void);
int test_blake3_output_fixed_32(void);
int test_blake3_single_shot_matches_streaming(void);
int test_blake3_independent_contexts(void);
int test_blake3_incremental_updates(void);
int test_deflate_round_trip_text(void);
int test_deflate_round_trip_binary(void);
int test_deflate_round_trip_empty(void);
int test_deflate_round_trip_single_byte(void);
int test_deflate_round_trip_exact_chunk(void);
int test_deflate_round_trip_sub_chunk(void);
int test_deflate_incompressible_within_bound(void);
int test_deflate_bound_non_zero(void);
int test_deflate_stored_block_valid(void);
int test_deflate_invalid_stream(void);
int test_deflate_truncated_stream(void);
int test_deflate_output_buffer_too_small(void);
int test_deflate_output_buffer_exact(void);
int test_edge_stub(void);
int test_extract_stub(void);
int test_fault_stub(void);
int test_integration_stub(void);
int test_thread_stub(void);

int test_sha256_empty(void);
int test_sha256_abc(void);
int test_sha256_448_bits(void);
int test_sha256_one_block(void);
int test_sha256_exact_block(void);
int test_sha256_block_boundary(void);
int test_sha256_two_blocks(void);
int test_sha256_multiblock(void);
int test_sha256_single_shot_matches_streaming(void);
int test_sha256_output_length(void);
int test_sha256_independent_contexts(void);

static const test_case_t g_tests[] = {
    {"test_sha256_empty", test_sha256_empty},
    {"test_sha256_abc", test_sha256_abc},
    {"test_sha256_448_bits", test_sha256_448_bits},
    {"test_sha256_one_block", test_sha256_one_block},
    {"test_sha256_exact_block", test_sha256_exact_block},
    {"test_sha256_block_boundary", test_sha256_block_boundary},
    {"test_sha256_two_blocks", test_sha256_two_blocks},
    {"test_sha256_multiblock", test_sha256_multiblock},
    {"test_sha256_single_shot_matches_streaming",
     test_sha256_single_shot_matches_streaming},
    {"test_sha256_output_length", test_sha256_output_length},
    {"test_sha256_independent_contexts", test_sha256_independent_contexts},
    {"test_blake3_vectors_all", test_blake3_vectors_all},
    {"test_blake3_empty", test_blake3_empty},
    {"test_blake3_single_chunk", test_blake3_single_chunk},
    {"test_blake3_multi_chunk", test_blake3_multi_chunk},
    {"test_blake3_large", test_blake3_large},
    {"test_blake3_output_fixed_32", test_blake3_output_fixed_32},
    {"test_blake3_single_shot_matches_streaming",
     test_blake3_single_shot_matches_streaming},
    {"test_blake3_independent_contexts", test_blake3_independent_contexts},
    {"test_blake3_incremental_updates", test_blake3_incremental_updates},
    {"test_deflate_round_trip_text", test_deflate_round_trip_text},
    {"test_deflate_round_trip_binary", test_deflate_round_trip_binary},
    {"test_deflate_round_trip_empty", test_deflate_round_trip_empty},
    {"test_deflate_round_trip_single_byte",
     test_deflate_round_trip_single_byte},
    {"test_deflate_round_trip_exact_chunk",
     test_deflate_round_trip_exact_chunk},
    {"test_deflate_round_trip_sub_chunk", test_deflate_round_trip_sub_chunk},
    {"test_deflate_incompressible_within_bound",
     test_deflate_incompressible_within_bound},
    {"test_deflate_bound_non_zero", test_deflate_bound_non_zero},
    {"test_deflate_stored_block_valid", test_deflate_stored_block_valid},
    {"test_deflate_invalid_stream", test_deflate_invalid_stream},
    {"test_deflate_truncated_stream", test_deflate_truncated_stream},
    {"test_deflate_output_buffer_too_small",
     test_deflate_output_buffer_too_small},
    {"test_deflate_output_buffer_exact", test_deflate_output_buffer_exact},
    {"test_write_valid_sequence_zero_members",
     test_write_valid_sequence_zero_members},
    {"test_write_valid_sequence_one_member",
     test_write_valid_sequence_one_member},
    {"test_write_valid_sequence_multi_member",
     test_write_valid_sequence_multi_member},
    {"test_write_chunk_outside_member", test_write_chunk_outside_member},
    {"test_write_member_begin_while_active",
     test_write_member_begin_while_active},
    {"test_write_member_end_outside_member",
     test_write_member_end_outside_member},
    {"test_write_index_before_member_end", test_write_index_before_member_end},
    {"test_write_footer_before_index", test_write_footer_before_index},
    {"test_write_chunk_non_regular_member",
     test_write_chunk_non_regular_member},
    {"test_write_free_any_state", test_write_free_any_state},
    {"test_write_header_dst_cap_undersize",
     test_write_header_dst_cap_undersize},
    {"test_write_footer_dst_cap_undersize",
     test_write_footer_dst_cap_undersize},
    {"test_write_index_dst_cap_undersize", test_write_index_dst_cap_undersize},
    {"test_write_header_magic", test_write_header_magic},
    {"test_write_header_version", test_write_header_version},
    {"test_write_header_flags_zero", test_write_header_flags_zero},
    {"test_write_header_comp_alg", test_write_header_comp_alg},
    {"test_write_header_hash_alg", test_write_header_hash_alg},
    {"test_write_header_reserved_zero", test_write_header_reserved_zero},
    {"test_write_footer_magic_confirm", test_write_footer_magic_confirm},
    {"test_write_footer_index_offset", test_write_footer_index_offset},
    {"test_write_index_little_endian", test_write_index_little_endian},
    {"test_write_empty_file_chunk_count_zero",
     test_write_empty_file_chunk_count_zero},
    {"test_write_member_hash_non_file_types",
     test_write_member_hash_non_file_types},
    {"test_write_index_hash_matches_footer",
     test_write_index_hash_matches_footer},
    {"test_write_member_hash_matches_compressed_bytes",
     test_write_member_hash_matches_compressed_bytes},
    {"test_thread_stub", test_thread_stub},
    {"test_extract_stub", test_extract_stub},
    {"test_fault_stub", test_fault_stub},
    {"test_edge_stub", test_edge_stub},
    {"test_integration_stub", test_integration_stub},
};

int main(void)
{
	size_t i;
	size_t passed;
	size_t total;

	passed = 0;
	total = sizeof(g_tests) / sizeof(g_tests[0]);
	for (i = 0; i < total; i++) {
		if (g_tests[i].fn() == 0) {
			passed++;
			continue;
		}
		fprintf(stderr, "FAIL: %s\n", g_tests[i].name);
	}
	printf("%zu/%zu tests passed\n", passed, total);
	return passed == total ? 0 : 1;
}
