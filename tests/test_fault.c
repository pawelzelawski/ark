/*
 * test_fault.c - Component-level fault-path tests.
 *
 * Scope for Phase 5.10 is limited to pure component APIs compiled in the test
 * binary: archive.c and deflate.c. CLI/main.c extraction behaviour is covered
 * later by integration tests in Phase 7.
 */

#include <errno.h>

#include "ark_internal.h"

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
