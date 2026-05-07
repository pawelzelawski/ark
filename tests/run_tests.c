#include <stddef.h>
#include <stdio.h>

typedef int (*test_fn_t)(void);

typedef struct {
	const char *name;
	test_fn_t fn;
} test_case_t;

int test_archive_stub(void);
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
    {"test_archive_stub", test_archive_stub},
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
