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
int test_write_member_begin_invalid_type(void);
int test_write_member_begin_rejects_bad_path(void);
int test_write_member_begin_rejects_bad_link(void);
int test_write_member_begin_rejects_chunk_sizes(void);
int test_write_size_compressed_owned_by_context(void);
int test_read_header_bad_magic(void);
int test_read_header_bad_version(void);
int test_read_header_unknown_comp_alg(void);
int test_read_header_unknown_hash_alg(void);
int test_read_header_nonzero_flags(void);
int test_read_header_nonzero_reserved(void);
int test_read_header_before_init(void);
int test_read_header_truncated(void);
int test_read_check1_bad_footer_magic(void);
int test_read_check2_index_hash_mismatch(void);
int test_read_check3_path_absolute(void);
int test_read_check3_path_dotdot(void);
int test_read_check3_path_empty_component_fmt(void);
int test_read_check3_path_invalid_utf8(void);
int test_read_index_unknown_member_type(void);
int test_read_check4_path_too_long(void);
int test_read_check5_link_absolute(void);
int test_read_check5_link_dotdot(void);
int test_read_check5_link_too_long(void);
int test_read_check6_hardlink_missing_target(void);
int test_read_check6_hardlink_forward_reference(void);
int test_read_check7_duplicate_path(void);
int test_read_check8_missing_ancestor(void);
int test_read_check9_present_ancestor_non_directory(void);
int test_read_check10_size_mismatch(void);
int test_read_check11_data_offset_low(void);
int test_read_check11_data_range_exceeds_body(void);
int test_read_check12_overlapping_ranges(void);
int test_read_check13_hardlink_targets_dir(void);
int test_read_check13_hardlink_targets_symlink(void);
int test_read_check14_structural_gap(void);
int test_read_check15_zero_data_hash_mismatch(void);
int test_read_check16_zero_data_hash_mismatch(void);
int test_read_member_count_too_large(void);
int test_read_regular_size_overflow_rejected(void);
int test_read_verify_hash_match(void);
int test_read_verify_hash_mismatch(void);
int test_read_verify_out_of_order_chunk(void);
int test_read_chunk_invalid_deflate(void);
int test_read_chunk_length_mismatch(void);
int test_read_chunk_compressed_size_mismatch(void);
int test_read_empty_file_chunk_count_zero(void);
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
int test_deflate_default_emits_dynamic_block(void);
int test_deflate_fast_emits_fixed_block(void);
int test_deflate_invalid_stream(void);
int test_deflate_truncated_stream(void);
int test_deflate_output_buffer_too_small(void);
int test_deflate_output_buffer_exact(void);
int test_edge_empty_archive(void);
int test_edge_single_member(void);
int test_edge_max_path_length(void);
int test_edge_path_one_over_max(void);
int test_edge_empty_file(void);
int test_adv_forged_member_count(void);
int test_adv_data_offset_in_header(void);
int test_adv_data_range_past_index(void);
int test_adv_overlapping_data_ranges(void);
int test_adv_hardlink_to_dir(void);
int test_adv_hardlink_forward_ref(void);
int test_adv_duplicate_paths(void);
int test_adv_path_traversal_abs(void);
int test_adv_path_traversal_dotdot(void);
int test_adv_link_target_dotdot(void);
int test_adv_link_target_too_long(void);
int test_adv_chunk_count_mismatch(void);
int test_adv_nonzero_chunk_count_empty_file(void);
int test_adv_corrupt_index_hash(void);
int test_adv_corrupt_member_data(void);
int test_extract_stub(void);
int test_fault_archive_header_dst_cap_undersize(void);
int test_fault_archive_index_dst_cap_undersize(void);
int test_fault_archive_footer_dst_cap_undersize(void);
int test_fault_archive_index_hash_mismatch(void);
int test_fault_archive_invalid_deflate_maps_fmt_data(void);
int test_fault_archive_chunk_length_mismatch_maps_fmt_data(void);
int test_fault_archive_chunk_size_mismatch_maps_fmt_data(void);
int test_fault_deflate_invalid_stream(void);
int test_fault_deflate_truncated_stream(void);
int test_fault_deflate_output_buffer_too_small(void);
int test_fault_injection_no_effect_on_archive_component(void);
int test_fault_injection_no_effect_on_deflate_component(void);
int test_fault_create_open_archive(void);
int test_fault_create_write_header(void);
int test_fault_create_lstat_member(void);
int test_fault_create_open_member(void);
int test_fault_create_read_member(void);
int test_fault_create_write_chunk(void);
int test_fault_create_write_index(void);
int test_fault_create_write_footer(void);
int test_fault_create_opendir(void);
int test_fault_create_readdir(void);
int test_fault_create_realpath(void);
int test_fault_create_commit(void);
int test_fault_create_fsync(void);
int test_fault_create_modified(void);
int test_fault_extract_open_archive(void);
int test_fault_extract_read_header(void);
int test_fault_extract_read_footer(void);
int test_fault_extract_read_index(void);
int test_fault_extract_seek(void);
int test_fault_extract_read_chunk(void);
int test_fault_extract_open_output(void);
int test_fault_extract_write_output(void);
int test_fault_extract_mkdir(void);
int test_fault_extract_symlink_create(void);
int test_fault_extract_link_create(void);
int test_fault_extract_lchown(void);
int test_fault_extract_chmod(void);
int test_fault_extract_utimensat(void);
int test_fault_extract_unlink_overwrite(void);
int test_fault_extract_cleanup_track_alloc(void);
int test_fault_extract_cleanup_unlink(void);
int test_fault_extract_cleanup_rmdir(void);
int test_integration_single_file(void);
int test_integration_directory_tree(void);
int test_integration_all_member_types(void);
int test_integration_empty_file(void);
int test_integration_round_trip_blake3(void);
int test_integration_round_trip_sha256(void);
int test_integration_mtime_preserved(void);
int test_integration_mtime_pre_epoch(void);
int test_integration_verify_detects_corruption(void);
int test_integration_verify_detects_index_corruption(void);
int test_integration_overwrite(void);
int test_integration_overwrite_symlink(void);
int test_integration_selective_member(void);
int test_integration_list(void);
int test_integration_generate_reader(void);
int test_integration_generate_reader_no_follow(void);
int test_integration_deterministic(void);
int test_integration_large_archive(void);
int test_ring_normal_produce_consume(void);
int test_ring_out_of_order_completion(void);
int test_ring_abort_sentinel_written(void);
int test_ring_io_thread_unblocks_on_abort(void);
int test_ring_abort_does_not_block(void);
int test_worker_error_stores_first(void);
int test_worker_error_subsequent_discarded(void);
int test_worker_error_then_sentinel(void);
int test_worker_error_published_complete(void);
int test_io_thread_reads_worker_error(void);
int test_worker_error_triggers_cancel(void);
int test_cancel_workers_exit_cleanly(void);
int test_cancel_join_completes(void);
int test_pool_init_create_failure_wakes_workers(void);
int test_pool_init_create_failure_cleans_up(void);
int test_ring_init_sync_failure_cleans_up(void);
int test_pool_init_sync_failure_cleans_up(void);
int test_quiescence_sequence_order(void);
int test_no_resource_leak_on_cancel(void);
int test_no_cleanup_race(void);
int test_create_deterministic_single_worker(void);
int test_create_deterministic_multi_worker_matches_single(void);

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
    {"test_deflate_default_emits_dynamic_block",
     test_deflate_default_emits_dynamic_block},
    {"test_deflate_fast_emits_fixed_block",
     test_deflate_fast_emits_fixed_block},
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
    {"test_write_member_begin_invalid_type",
     test_write_member_begin_invalid_type},
    {"test_write_member_begin_rejects_bad_path",
     test_write_member_begin_rejects_bad_path},
    {"test_write_member_begin_rejects_bad_link",
     test_write_member_begin_rejects_bad_link},
    {"test_write_member_begin_rejects_chunk_sizes",
     test_write_member_begin_rejects_chunk_sizes},
    {"test_write_size_compressed_owned_by_context",
     test_write_size_compressed_owned_by_context},
    {"test_read_header_bad_magic", test_read_header_bad_magic},
    {"test_read_header_bad_version", test_read_header_bad_version},
    {"test_read_header_unknown_comp_alg", test_read_header_unknown_comp_alg},
    {"test_read_header_unknown_hash_alg", test_read_header_unknown_hash_alg},
    {"test_read_header_nonzero_flags", test_read_header_nonzero_flags},
    {"test_read_header_nonzero_reserved", test_read_header_nonzero_reserved},
    {"test_read_header_before_init", test_read_header_before_init},
    {"test_read_header_truncated", test_read_header_truncated},
    {"test_read_check1_bad_footer_magic", test_read_check1_bad_footer_magic},
    {"test_read_check2_index_hash_mismatch",
     test_read_check2_index_hash_mismatch},
    {"test_read_check3_path_absolute", test_read_check3_path_absolute},
    {"test_read_check3_path_dotdot", test_read_check3_path_dotdot},
    {"test_read_check3_path_empty_component_fmt",
     test_read_check3_path_empty_component_fmt},
    {"test_read_check3_path_invalid_utf8", test_read_check3_path_invalid_utf8},
    {"test_read_index_unknown_member_type",
     test_read_index_unknown_member_type},
    {"test_read_check4_path_too_long", test_read_check4_path_too_long},
    {"test_read_check5_link_absolute", test_read_check5_link_absolute},
    {"test_read_check5_link_dotdot", test_read_check5_link_dotdot},
    {"test_read_check5_link_too_long", test_read_check5_link_too_long},
    {"test_read_check6_hardlink_missing_target",
     test_read_check6_hardlink_missing_target},
    {"test_read_check6_hardlink_forward_reference",
     test_read_check6_hardlink_forward_reference},
    {"test_read_check7_duplicate_path", test_read_check7_duplicate_path},
    {"test_read_check8_missing_ancestor", test_read_check8_missing_ancestor},
    {"test_read_check9_present_ancestor_non_directory",
     test_read_check9_present_ancestor_non_directory},
    {"test_read_check10_size_mismatch", test_read_check10_size_mismatch},
    {"test_read_check11_data_offset_low", test_read_check11_data_offset_low},
    {"test_read_check11_data_range_exceeds_body",
     test_read_check11_data_range_exceeds_body},
    {"test_read_check12_overlapping_ranges",
     test_read_check12_overlapping_ranges},
    {"test_read_check13_hardlink_targets_dir",
     test_read_check13_hardlink_targets_dir},
    {"test_read_check13_hardlink_targets_symlink",
     test_read_check13_hardlink_targets_symlink},
    {"test_read_check14_structural_gap", test_read_check14_structural_gap},
    {"test_read_check15_zero_data_hash_mismatch",
     test_read_check15_zero_data_hash_mismatch},
    {"test_read_check16_zero_data_hash_mismatch",
     test_read_check16_zero_data_hash_mismatch},
    {"test_read_member_count_too_large", test_read_member_count_too_large},
    {"test_read_regular_size_overflow_rejected",
     test_read_regular_size_overflow_rejected},
    {"test_read_verify_hash_match", test_read_verify_hash_match},
    {"test_read_verify_hash_mismatch", test_read_verify_hash_mismatch},
    {"test_read_verify_out_of_order_chunk",
     test_read_verify_out_of_order_chunk},
    {"test_read_chunk_invalid_deflate", test_read_chunk_invalid_deflate},
    {"test_read_chunk_length_mismatch", test_read_chunk_length_mismatch},
    {"test_read_chunk_compressed_size_mismatch",
     test_read_chunk_compressed_size_mismatch},
    {"test_read_empty_file_chunk_count_zero",
     test_read_empty_file_chunk_count_zero},
    {"test_fault_archive_header_dst_cap_undersize",
     test_fault_archive_header_dst_cap_undersize},
    {"test_fault_archive_index_dst_cap_undersize",
     test_fault_archive_index_dst_cap_undersize},
    {"test_fault_archive_footer_dst_cap_undersize",
     test_fault_archive_footer_dst_cap_undersize},
    {"test_fault_archive_index_hash_mismatch",
     test_fault_archive_index_hash_mismatch},
    {"test_fault_archive_invalid_deflate_maps_fmt_data",
     test_fault_archive_invalid_deflate_maps_fmt_data},
    {"test_fault_archive_chunk_length_mismatch_maps_fmt_data",
     test_fault_archive_chunk_length_mismatch_maps_fmt_data},
    {"test_fault_archive_chunk_size_mismatch_maps_fmt_data",
     test_fault_archive_chunk_size_mismatch_maps_fmt_data},
    {"test_fault_deflate_invalid_stream", test_fault_deflate_invalid_stream},
    {"test_fault_deflate_truncated_stream",
     test_fault_deflate_truncated_stream},
    {"test_fault_deflate_output_buffer_too_small",
     test_fault_deflate_output_buffer_too_small},
    {"test_fault_injection_no_effect_on_archive_component",
     test_fault_injection_no_effect_on_archive_component},
    {"test_fault_injection_no_effect_on_deflate_component",
     test_fault_injection_no_effect_on_deflate_component},
    {"test_fault_create_open_archive", test_fault_create_open_archive},
    {"test_fault_create_write_header", test_fault_create_write_header},
    {"test_fault_create_lstat_member", test_fault_create_lstat_member},
    {"test_fault_create_open_member", test_fault_create_open_member},
    {"test_fault_create_read_member", test_fault_create_read_member},
    {"test_fault_create_write_chunk", test_fault_create_write_chunk},
    {"test_fault_create_write_index", test_fault_create_write_index},
    {"test_fault_create_write_footer", test_fault_create_write_footer},
    {"test_fault_create_opendir", test_fault_create_opendir},
    {"test_fault_create_readdir", test_fault_create_readdir},
    {"test_fault_create_realpath", test_fault_create_realpath},
    {"test_fault_create_commit", test_fault_create_commit},
    {"test_fault_create_fsync", test_fault_create_fsync},
    {"test_fault_create_modified", test_fault_create_modified},
    {"test_fault_extract_open_archive", test_fault_extract_open_archive},
    {"test_fault_extract_read_header", test_fault_extract_read_header},
    {"test_fault_extract_read_footer", test_fault_extract_read_footer},
    {"test_fault_extract_read_index", test_fault_extract_read_index},
    {"test_fault_extract_seek", test_fault_extract_seek},
    {"test_fault_extract_read_chunk", test_fault_extract_read_chunk},
    {"test_fault_extract_open_output", test_fault_extract_open_output},
    {"test_fault_extract_write_output", test_fault_extract_write_output},
    {"test_fault_extract_mkdir", test_fault_extract_mkdir},
    {"test_fault_extract_symlink_create", test_fault_extract_symlink_create},
    {"test_fault_extract_link_create", test_fault_extract_link_create},
    {"test_fault_extract_lchown", test_fault_extract_lchown},
    {"test_fault_extract_chmod", test_fault_extract_chmod},
    {"test_fault_extract_utimensat", test_fault_extract_utimensat},
    {"test_fault_extract_unlink_overwrite",
     test_fault_extract_unlink_overwrite},
    {"test_fault_extract_cleanup_track_alloc",
     test_fault_extract_cleanup_track_alloc},
    {"test_fault_extract_cleanup_unlink", test_fault_extract_cleanup_unlink},
    {"test_fault_extract_cleanup_rmdir", test_fault_extract_cleanup_rmdir},
    {"test_edge_empty_archive", test_edge_empty_archive},
    {"test_edge_single_member", test_edge_single_member},
    {"test_edge_max_path_length", test_edge_max_path_length},
    {"test_edge_path_one_over_max", test_edge_path_one_over_max},
    {"test_edge_empty_file", test_edge_empty_file},
    {"test_adv_forged_member_count", test_adv_forged_member_count},
    {"test_adv_data_offset_in_header", test_adv_data_offset_in_header},
    {"test_adv_data_range_past_index", test_adv_data_range_past_index},
    {"test_adv_overlapping_data_ranges", test_adv_overlapping_data_ranges},
    {"test_adv_hardlink_to_dir", test_adv_hardlink_to_dir},
    {"test_adv_hardlink_forward_ref", test_adv_hardlink_forward_ref},
    {"test_adv_duplicate_paths", test_adv_duplicate_paths},
    {"test_adv_path_traversal_abs", test_adv_path_traversal_abs},
    {"test_adv_path_traversal_dotdot", test_adv_path_traversal_dotdot},
    {"test_adv_link_target_dotdot", test_adv_link_target_dotdot},
    {"test_adv_link_target_too_long", test_adv_link_target_too_long},
    {"test_adv_chunk_count_mismatch", test_adv_chunk_count_mismatch},
    {"test_adv_nonzero_chunk_count_empty_file",
     test_adv_nonzero_chunk_count_empty_file},
    {"test_adv_corrupt_index_hash", test_adv_corrupt_index_hash},
    {"test_adv_corrupt_member_data", test_adv_corrupt_member_data},
    {"test_ring_normal_produce_consume", test_ring_normal_produce_consume},
    {"test_ring_out_of_order_completion", test_ring_out_of_order_completion},
    {"test_ring_abort_sentinel_written", test_ring_abort_sentinel_written},
    {"test_ring_io_thread_unblocks_on_abort",
     test_ring_io_thread_unblocks_on_abort},
    {"test_ring_abort_does_not_block", test_ring_abort_does_not_block},
    {"test_worker_error_stores_first", test_worker_error_stores_first},
    {"test_worker_error_subsequent_discarded",
     test_worker_error_subsequent_discarded},
    {"test_worker_error_then_sentinel", test_worker_error_then_sentinel},
    {"test_worker_error_published_complete",
     test_worker_error_published_complete},
    {"test_io_thread_reads_worker_error", test_io_thread_reads_worker_error},
    {"test_worker_error_triggers_cancel", test_worker_error_triggers_cancel},
    {"test_cancel_workers_exit_cleanly", test_cancel_workers_exit_cleanly},
    {"test_cancel_join_completes", test_cancel_join_completes},
    {"test_pool_init_create_failure_wakes_workers",
     test_pool_init_create_failure_wakes_workers},
    {"test_pool_init_create_failure_cleans_up",
     test_pool_init_create_failure_cleans_up},
    {"test_ring_init_sync_failure_cleans_up",
     test_ring_init_sync_failure_cleans_up},
    {"test_pool_init_sync_failure_cleans_up",
     test_pool_init_sync_failure_cleans_up},
    {"test_quiescence_sequence_order", test_quiescence_sequence_order},
    {"test_no_resource_leak_on_cancel", test_no_resource_leak_on_cancel},
    {"test_no_cleanup_race", test_no_cleanup_race},
    {"test_create_deterministic_single_worker",
     test_create_deterministic_single_worker},
    {"test_create_deterministic_multi_worker_matches_single",
     test_create_deterministic_multi_worker_matches_single},
    {"test_extract_stub", test_extract_stub},
    {"test_integration_single_file", test_integration_single_file},
    {"test_integration_directory_tree", test_integration_directory_tree},
    {"test_integration_all_member_types", test_integration_all_member_types},
    {"test_integration_empty_file", test_integration_empty_file},
    {"test_integration_round_trip_blake3", test_integration_round_trip_blake3},
    {"test_integration_round_trip_sha256", test_integration_round_trip_sha256},
    {"test_integration_mtime_preserved", test_integration_mtime_preserved},
    {"test_integration_mtime_pre_epoch", test_integration_mtime_pre_epoch},
    {"test_integration_verify_detects_corruption",
     test_integration_verify_detects_corruption},
    {"test_integration_verify_detects_index_corruption",
     test_integration_verify_detects_index_corruption},
    {"test_integration_overwrite", test_integration_overwrite},
    {"test_integration_overwrite_symlink", test_integration_overwrite_symlink},
    {"test_integration_selective_member", test_integration_selective_member},
    {"test_integration_list", test_integration_list},
    {"test_integration_generate_reader", test_integration_generate_reader},
    {"test_integration_generate_reader_no_follow",
     test_integration_generate_reader_no_follow},
    {"test_integration_deterministic", test_integration_deterministic},
    {"test_integration_large_archive", test_integration_large_archive},
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
