# Testing Strategy

## 1. Overview

Testing operates at four levels:

| Level | What | When | Tools |
|---|---|---|---|
| Component unit | Individual component APIs in isolation | During each phase, before moving on | Plain C, Valgrind, ASan/UBSan |
| Thread | Thread pool, ring buffer, cancellation, error propagation | Phase introducing parallelism | Same test binary, TSan required |
| Edge case | Boundary conditions, adversarial inputs, malformed archives | During component phases | Same test binary |
| Integration | End-to-end create → verify → extract pipelines | Final phase | Same test binary |

The rule is simple: **a phase is not done until its tests pass cleanly on
Linux with Valgrind and ASan/UBSan**. Tests must also pass on OpenBSD before
the phase is declared complete. Do not accumulate untested code.

**TSan is required at phase boundaries** for any phase that introduces or
modifies concurrent data structures. TSan and ASan are mutually exclusive;
TSan runs as a separate `make test-tsan` target.

**No external test framework.** Plain C programs with a minimal assertion
macro. Every test function returns 0 on success and non-zero on failure.
The test binary exits with code 0 if all tests pass and 1 if any fail.

---

## 2. Test Harness

### 2.1 Structure

```
tests/
├── run_tests.c           # binary entry point; calls all test suites in order
├── ark_stubs.c           # fault injection stubs (compiled with -DARK_TEST only)
├── test_sha256.c         # SHA-256 implementation against NIST test vectors
├── test_blake3.c         # BLAKE3 implementation against official test vectors
├── test_deflate.c        # Deflate compress/decompress correctness and bounds
├── test_archive.c        # archive.h API: write path, read path, error model
├── test_thread.c         # thread pool, ring buffer, cancellation, error propagation
├── test_extract.c        # extraction correctness, metadata, cleanup, --overwrite
├── test_fault.c          # fault injection at each sequence step
├── test_edge.c           # boundary conditions and adversarial inputs
└── test_integration.c    # end-to-end create → verify → extract pipelines
```

`make test` builds all test files with `-DARK_TEST` against all source files
and runs the binary.

### 2.2 Test Assertion Macro

```c
/*
 * CHECK(name, expr) - assert expr is true; record pass or fail.
 * name is a string literal identifying the test case.
 */
#define CHECK(name, expr) do {                                          \
	int _r = (expr) ? 0 : 1;                                       \
	if (_r == 0) { tests_passed++; }                                \
	else { fprintf(stderr, "FAIL: %s\n", (name)); tests_failed++; }\
} while (0)
```

Each test function returns 0 on success, non-zero on failure. The runner
in `run_tests.c` calls each function, accumulates pass/fail counts, and
prints a summary. Exit code 0 means all tests passed.

### 2.3 Fault Injection Infrastructure

Fault injection uses compile-time substitution. All source files in `src/`
use `ARK_*` wrapper macros for every syscall. In test builds (`-DARK_TEST`)
the macros resolve to stub functions in `tests/ark_stubs.c`.

The fault injection state struct:

```c
typedef struct {
	int  which;           /* ARK_STUB_READ, ARK_STUB_WRITE, etc. */
	int  fail_on_call_n;  /* fail on the nth call to this syscall */
	int  errno_value;     /* errno to inject */
	/* per-syscall call counters */
	int  read_calls;
	int  write_calls;
	int  open_calls;
	int  close_calls;
	int  lstat_calls;
	int  unlink_calls;
	int  rmdir_calls;
	int  link_calls;
	int  mkdir_calls;
	int  lchown_calls;
	int  chmod_calls;
	int  utimensat_calls;
	int  opendir_calls;
	int  readdir_calls;
	int  closedir_calls;
	int  realpath_calls;
} ark_fault_t;

extern ark_fault_t ark_fault;
```

Each fault injection test:
1. Sets `ark_fault.which`, `ark_fault.fail_on_call_n`, `ark_fault.errno_value`
2. Calls the function under test
3. Verifies the returned error code matches the expected `ark_err_t`
4. Verifies filesystem state: no partial files, no leaked descriptors
5. Resets `ark_fault` to zero before the next test

Test helper:
```c
static void
fault_reset(void)
{
	memset(&ark_fault, 0, sizeof(ark_fault));
}

static void
fault_inject(int which, int on_call_n, int errno_value)
{
	fault_reset();
	ark_fault.which          = which;
	ark_fault.fail_on_call_n = on_call_n;
	ark_fault.errno_value    = errno_value;
}
```

Thread-pool start-up uses the same mechanism for pthread calls:
`ARK_PTHREAD_CREATE`, `ARK_PTHREAD_MUTEX_INIT` and `ARK_PTHREAD_COND_INIT`
are fault-injectable (`ARK_FAULT_PTHREAD_CREATE`,
`ARK_FAULT_PTHREAD_MUTEX_INIT`, `ARK_FAULT_PTHREAD_COND_INIT`), and
`ARK_PTHREAD_COND_WAIT` has a test-only handshake
(`ark_fault.cond_wait_delay_ms`, `ark_fault.cond_wait_entered`) that holds a
started worker in its wait window while a later `pthread_create` fails.
Worker threads touch these two fields only through atomics. Test loops that
wait for other threads call `sched_yield()` instead of spinning: Valgrind
runs one guest thread at a time.

Command sequence points that are not syscalls use `ark_test_cli_fault_inject`
in `src/main.c` (for example `ARK_CLI_FAULT_CLEANUP_GROW`, which fails the
extraction cleanup-tracker allocation). Deflate encoder internals are reached
through stateless `ark_deflate_test_*` accessors compiled only with
`-DARK_TEST`.

---

## 3. Component Unit Test Catalogue

### 3.1 SHA-256 (`test_sha256.c`)

Tests validate the implementation against NIST FIPS 180-4 test vectors.
All vectors must pass before the component is accepted.

| Test case | What is verified |
|---|---|
| `test_sha256_empty` | Empty input; expected NIST vector for zero bytes |
| `test_sha256_one_block` | 55-byte input; fits in one block without padding extension |
| `test_sha256_exact_block` | 64-byte input; exactly one block |
| `test_sha256_block_boundary` | 55 bytes + 1 byte in separate update call; same digest as 56-byte single call |
| `test_sha256_two_blocks` | 65-byte input; crosses block boundary |
| `test_sha256_multiblock` | 1KB input; multi-block correctness |
| `test_sha256_abc` | NIST vector: input "abc" |
| `test_sha256_448_bits` | NIST vector: 448-bit message |
| `test_sha256_single_shot_matches_streaming` | Single-shot and streaming produce identical digest for same input |
| `test_sha256_output_length` | Output is exactly 32 bytes |
| `test_sha256_independent_contexts` | Two contexts fed different data produce different digests |

### 3.2 BLAKE3 (`test_blake3.c`)

Tests validate the implementation against the official BLAKE3 test vectors
published in the reference repository. The test vectors cover input lengths
0 through 2^n for progressively larger n. All vectors must pass.

| Test case | What is verified |
|---|---|
| `test_blake3_vectors_all` | All official test vectors; loop over vector table |
| `test_blake3_empty` | Zero-byte input; matches official vector |
| `test_blake3_single_chunk` | 1024-byte input (one BLAKE3 chunk) |
| `test_blake3_multi_chunk` | 1025-byte input (crosses chunk boundary) |
| `test_blake3_large` | 32KB input; multi-chunk tree structure |
| `test_blake3_output_fixed_32` | Output is exactly 32 bytes regardless of input size |
| `test_blake3_single_shot_matches_streaming` | Identical digest from both API paths |
| `test_blake3_independent_contexts` | Two contexts produce different digests for different inputs |
| `test_blake3_incremental_updates` | 1-byte updates produce same digest as single update |

### 3.3 Deflate (`test_deflate.c`)

`ark_deflate_compress` and `ark_deflate_decompress` have no `ark_error_t *`
parameter. Both return -1 on failure with no error code. `ARK_ERR_FMT_DATA`
is synthesized by `ark_read_chunk` in `archive.c` after
`ark_deflate_decompress` returns -1. Deflate unit tests check only for -1
returns. `ARK_ERR_FMT_DATA` is verified via `ark_read_chunk` in
`test_archive.c` (§3.5).

| Test case | What is verified |
|---|---|
| `test_deflate_round_trip_text` | Compress then decompress; byte-for-byte identity |
| `test_deflate_round_trip_binary` | Binary input (all byte values); round-trip identity |
| `test_deflate_round_trip_empty` | Zero-byte input; round-trip; decompressed length 0 |
| `test_deflate_round_trip_single_byte` | One-byte input; round-trip identity |
| `test_deflate_round_trip_exact_chunk` | Exactly 1MB input; round-trip identity |
| `test_deflate_round_trip_sub_chunk` | 512KB input; round-trip identity |
| `test_deflate_incompressible_within_bound` | Incompressible input; compressed size <= `ark_deflate_bound(src_len)` |
| `test_deflate_bound_non_zero` | `ark_deflate_bound(n) > n` for all tested n |
| `test_deflate_stored_block_valid` | Incompressible chunk stored as Deflate stored block; decompresses correctly |
| `test_deflate_default_emits_dynamic_block` | Default mode emits a dynamic-Huffman block for compressible input |
| `test_deflate_fast_emits_fixed_block` | Fast mode emits a fixed-Huffman block for compressible input |
| `test_deflate_invalid_stream` | Corrupt compressed bytes fed to decompress; returns -1 |
| `test_deflate_truncated_stream` | Compressed bytes truncated; returns -1 |
| `test_deflate_output_buffer_too_small` | Correct compressed stream but insufficient output capacity; returns -1 |
| `test_deflate_output_buffer_exact` | Output buffer exactly the right size; no overflow |
| `test_deflate_length_symbol_mapping` | Length symbol and extra bits at code boundaries; 258 maps to code 285 with no extra bits; 2 and 259 rejected |
| `test_deflate_zero_run_uses_code_285` | 1MB of zeros compresses below 2KB (default) and 8KB (fast); round-trip identity |
| `test_deflate_round_trip_all_match_lengths` | Runs of every match length 3..260; round-trip identity in default and fast mode |
| `test_deflate_limit_lengths_fibonacci` | Fibonacci frequencies (17..30 symbols) limited to 15 bits; all used symbols coded; Kraft sum exactly 1 |
| `test_deflate_limit_lengths_small_alphabets` | Distance (30, 15 bits) and code-length (19, 7 bits) alphabets complete; single used symbol gets one 1-bit code; no used symbol gives symbol 0 a 1-bit code |
| `test_deflate_cl_code_always_complete` | Code-length plan with only one used symbol is completed with a second 1-bit code |
| `test_deflate_header_cost_matches_emitted` | Costed dynamic header size equals the emitted bits for dense and sparse code lengths |
| `test_deflate_small_input_not_stored` | 128-byte text input compresses to a smaller dynamic block, not a stored block |
| `test_deflate_fixed_then_stored` | Fixed block followed by a stored block decodes correctly (bit reader gives back read-ahead bytes) |
| `test_deflate_accepts_legacy_length_258` | Length 258 written as code 284 + extra 31 (older ark encoders) still decodes |
| `test_deflate_rejects_incomplete_trees` | Incomplete code-length code, incomplete literal/length code and oversubscribed code-length code; returns -1 |
| `test_deflate_accepts_allowed_incomplete_trees` | Distance code with no codes, and with a single 1-bit code, decode correctly (zlib-compatible exceptions) |
| `test_deflate_round_trip_periodic` | Periodic input with periods 1..17 (overlapping matches around the 8-byte copy threshold); round-trip identity |

### 3.4 Archive Write Path (`test_archive.c`)

**State machine:**

| Test case | What is verified |
|---|---|
| `test_write_valid_sequence_zero_members` | Full sequence with zero members; completes without error |
| `test_write_valid_sequence_one_member` | Full sequence with one regular file member |
| `test_write_valid_sequence_multi_member` | Full sequence with regular, directory, symlink, hardlink members |
| `test_write_chunk_outside_member` | `ark_write_chunk` called before `ark_write_member_begin`; `ARK_ERR_USAGE` |
| `test_write_member_begin_while_active` | `ark_write_member_begin` called while member active; `ARK_ERR_USAGE` |
| `test_write_member_end_outside_member` | `ark_write_member_end` called in IDLE state; `ARK_ERR_USAGE` |
| `test_write_index_before_member_end` | `ark_write_index` called with active member; `ARK_ERR_USAGE` |
| `test_write_footer_before_index` | `ark_write_footer` called before `ark_write_index`; `ARK_ERR_USAGE` |
| `test_write_chunk_non_regular_member` | `ark_write_chunk` called for directory member; `ARK_ERR_USAGE` |
| `test_write_free_any_state` | `ark_write_free` valid in all states; no crash |
| `test_write_header_dst_cap_undersize` | `dst_cap < 16`; returns -1, `ARK_ERR_IO_ALLOC` |
| `test_write_footer_dst_cap_undersize` | `dst_cap < 64`; returns -1, `ARK_ERR_IO_ALLOC` |
| `test_write_index_dst_cap_undersize` | `dst_cap` too small for serialised index; -1, `ARK_ERR_IO_ALLOC` |

**Byte layout correctness:**

| Test case | What is verified |
|---|---|
| `test_write_header_magic` | Bytes 0-4 are `ark!\n` |
| `test_write_header_version` | ver_major=1, ver_minor=0 at correct offsets |
| `test_write_header_flags_zero` | flags byte is 0x00 |
| `test_write_header_comp_alg` | comp_alg byte matches ARK_HASH_BLAKE3 or ARK_HASH_SHA256 |
| `test_write_header_reserved_zero` | Bytes 10-15 are all zero |
| `test_write_footer_magic_confirm` | magic_confirm matches reversed header magic |
| `test_write_footer_index_offset` | index_offset correctly reflects body size |
| `test_write_index_little_endian` | All multi-byte fields in index are little-endian |
| `test_write_empty_file_chunk_count_zero` | Regular file with size_original=0; chunk_count=0 in index |
| `test_write_member_hash_non_file_types` | Directories, symlinks, hardlinks: hash of empty byte sequence |
| `test_write_member_begin_invalid_type` | Writer rejects unknown member type with `ARK_ERR_USAGE` |
| `test_write_member_begin_rejects_bad_path` | Writer rejects canonical path grammar violation |
| `test_write_member_begin_rejects_bad_link` | Writer rejects unsafe link target |
| `test_write_member_begin_rejects_chunk_sizes` | Writer rejects non-NULL `chunk_sizes` on write path |
| `test_write_size_compressed_owned_by_context` | Writer ignores caller `size_compressed` and records compressed byte total |

### 3.5 Archive Read Path (`test_archive.c`)

**Header validation:**

| Test case | What is verified |
|---|---|
| `test_read_header_bad_magic` | Wrong magic bytes; `ARK_ERR_FMT_MAGIC` |
| `test_read_header_bad_version` | ver_major != 1; `ARK_ERR_FMT_VERSION` |
| `test_read_header_unknown_comp_alg` | comp_alg = 0xFF; `ARK_ERR_FMT_COMP_ALG` |
| `test_read_header_unknown_hash_alg` | hash_alg = 0xFF; `ARK_ERR_FMT_HASH_ALG` |
| `test_read_header_nonzero_flags` | flags = 0x01; `ARK_ERR_FMT_RESERVED` |
| `test_read_header_nonzero_reserved` | Any reserved byte non-zero; `ARK_ERR_FMT_RESERVED` |
| `test_read_header_before_init` | `ark_read_init` called without prior `ark_read_header`; `ARK_ERR_USAGE` |

**Index validation (§8.3 checks, each tested individually):**

| Test case | §8.3 check | What is verified |
|---|---|---|
| `test_read_check1_bad_footer_magic` | Check 1 | `ARK_ERR_FMT_MAGIC` before index read |
| `test_read_check2_index_hash_mismatch` | Check 2 | One byte of index flipped; `ARK_ERR_HASH_INDEX` |
| `test_read_check3_path_absolute` | Check 3 | Member path starts with `/`; `ARK_ERR_PATH_ABSOLUTE` |
| `test_read_check3_path_dotdot` | Check 3 | Member path contains `..`; `ARK_ERR_PATH_TRAVERSAL` |
| `test_read_check3_path_empty_component_fmt` | Check 3 | Member path has an empty component; `ARK_ERR_FMT_INDEX` |
| `test_read_check4_path_too_long` | Check 5 | Member path length exceeds 1023 bytes; `ARK_ERR_PATH_TOO_LONG` |
| `test_read_check5_link_too_long` | Check 6 | Link target > 1023 bytes; `ARK_ERR_FMT_INDEX` |
| `test_read_check5_link_dotdot` | Check 6 | Link target contains `..`; `ARK_ERR_PATH_TRAVERSAL` |
| `test_read_check6_hardlink_missing_target` | Check 7 | Hardlink names non-existent member; `ARK_ERR_FMT_INDEX` |
| `test_read_check6_hardlink_forward_reference` | Check 7 | Hardlink target appears after hardlink; `ARK_ERR_FMT_INDEX` |
| `test_read_check7_duplicate_path` | Check 8 | Two members with identical paths; `ARK_ERR_FMT_INDEX` |
| `test_read_check8_missing_ancestor` | Check 9 | Leaf member path with no parent directory member; `ARK_ERR_FMT_INDEX` |
| `test_read_check9_present_ancestor_non_directory` | Check 10 | Present ancestor is not an earlier directory; `ARK_ERR_FMT_INDEX` |
| `test_read_check10_size_mismatch` | Check 11 | `size_compressed` != sum of `chunk_sizes`; `ARK_ERR_FMT_INDEX` |
| `test_read_check11_data_offset_low` | Check 12 | `data_offset < 16`; `ARK_ERR_FMT_INDEX` |
| `test_read_check11_data_range_exceeds_body` | Check 12 | `data_offset + size_compressed > index_offset`; `ARK_ERR_FMT_INDEX` |
| `test_read_check12_overlapping_ranges` | Check 13 | Two members with overlapping data ranges; `ARK_ERR_FMT_INDEX` |
| `test_read_check13_hardlink_targets_dir` | Check 14 | Hardlink target is a directory; `ARK_ERR_FMT_INDEX` |
| `test_read_check13_hardlink_targets_symlink` | Check 14 | Hardlink target is a symlink; `ARK_ERR_FMT_INDEX` |
| `test_read_check14_structural_gap` | Check 15 | Body ranges are not contiguous to the index; `ARK_ERR_FMT_INDEX` |
| `test_read_check15_zero_data_hash_mismatch` | Check 16 | Directory hash is not empty-input digest; `ARK_ERR_HASH_MEMBER` |
| `test_read_check16_zero_data_hash_mismatch` | Check 16 | Empty regular-file hash is not empty-input digest; `ARK_ERR_HASH_MEMBER` |
| `test_read_regular_size_overflow_rejected` | Overflow-safe arithmetic | Huge `size_original` cannot overflow chunk-count calculation; `ARK_ERR_FMT_INDEX` |

**Pre-allocation bound:**

| Test case | What is verified |
|---|---|
| `test_read_member_count_too_large` | `member_count > index_size / 84`; `ARK_ERR_FMT_INDEX` before allocation |

**Per-member verification:**

| Test case | What is verified |
|---|---|
| `test_read_verify_hash_match` | All chunks fed in order; `ark_read_verify_member_final` returns 0 |
| `test_read_verify_hash_mismatch` | One byte of compressed data flipped; `ARK_ERR_HASH_MEMBER` |
| `test_read_verify_out_of_order_chunk` | Chunk fed at wrong sequence number; `ARK_ERR_FMT_INDEX` immediately |
| `test_read_chunk_invalid_deflate` | Compressed bytes are not a valid Deflate stream; `ARK_ERR_FMT_DATA` |
| `test_read_chunk_length_mismatch` | Decompressed size does not match expected chunk size; `ARK_ERR_FMT_DATA` |
| `test_read_chunk_compressed_size_mismatch` | Supplied compressed byte count does not match index chunk size; `ARK_ERR_FMT_DATA` |
| `test_read_empty_file_chunk_count_zero` | Regular file with chunk_count=0; `ark_read_member_meta` reports correctly |

---

## 4. Thread Test Catalogue (`test_thread.c`)

**TSan is required** when running this test file. All tests in this file
must pass `make test-tsan` on Linux before the threading phase is declared
complete.

### 4.1 Ring Buffer

| Test case | What is verified |
|---|---|
| `test_ring_normal_produce_consume` | Worker writes slot; I/O thread reads slot in order; contents correct |
| `test_ring_out_of_order_completion` | Workers complete out of order; I/O thread receives all in sequence order |
| `test_ring_abort_sentinel_written` | Worker writes abort sentinel; slot state is ARK_RING_ABORT |
| `test_ring_io_thread_unblocks_on_abort` | I/O thread waiting for slot N; worker writes abort sentinel at N; I/O thread unblocks immediately |
| `test_ring_abort_does_not_block` | Abort sentinel written to any slot; no deadlock |

### 4.2 Worker Error Propagation

| Test case | What is verified |
|---|---|
| `test_worker_error_stores_first` | First worker error stored in shared atomic struct |
| `test_worker_error_subsequent_discarded` | Second worker error does not overwrite first |
| `test_worker_error_then_sentinel` | Error struct populated before abort sentinel is written |
| `test_io_thread_reads_worker_error` | I/O thread detects abort sentinel; reads error struct; correct error code |
| `test_worker_error_triggers_cancel` | I/O thread sets cancellation flag after reading worker error |
| `test_worker_error_published_complete` | Concurrent first-error stores while the I/O side polls; any visible error is one writer's complete payload |

### 4.3 Cancellation and Quiescence

| Test case | What is verified |
|---|---|
| `test_cancel_workers_exit_cleanly` | Cancellation flag set; all workers exit loop without processing further chunks |
| `test_cancel_join_completes` | `pthread_join` completes for all workers after cancellation |
| `test_quiescence_sequence_order` | Cancel flag set, workers joined, fd closed, cleanup runs; in that order |
| `test_no_resource_leak_on_cancel` | After cancel and join: no leaked fds, no leaked memory |
| `test_no_cleanup_race` | No filesystem operation in cleanup races an active worker |

### 4.4 Pool and Ring Start-up Failures

| Test case | What is verified |
|---|---|
| `test_pool_init_create_failure_wakes_workers` | `pthread_create` fails while a started worker is in its wait window; `pool_init` returns `ARK_ERR_IO_ALLOC` without hanging in `pthread_join` |
| `test_pool_init_create_failure_cleans_up` | `pthread_create` fails at the first and a later worker; `ARK_ERR_IO_ALLOC`; no leak |
| `test_ring_init_sync_failure_cleans_up` | Ring mutex or condition initialisation fails; `ARK_ERR_IO_ALLOC`; slot payloads freed |
| `test_pool_init_sync_failure_cleans_up` | Each pool and ring mutex/condition initialisation fails in turn; `ARK_ERR_IO_ALLOC`; no leak |

---

## 5. Extraction Test Catalogue (`test_extract.c`)

### 5.1 Member Type Extraction

| Test case | What is verified |
|---|---|
| `test_extract_regular_file` | File created; contents correct; mode applied |
| `test_extract_empty_regular_file` | chunk_count=0; empty file created at path |
| `test_extract_directory` | Directory created; mode applied |
| `test_extract_symlink` | Symlink created with correct target; `readlink` confirms |
| `test_extract_hardlink` | Hardlink created; same inode as target member |

### 5.2 Metadata Restoration

| Test case | What is verified |
|---|---|
| `test_meta_mode_applied_regular` | Permission bits applied via chmod; setuid/setgid bits stripped |
| `test_meta_mode_stripped_setuid` | Stored mode has setuid bit; extracted file does not |
| `test_meta_lchown_regular` | lchown used for regular files; ownership correct (root only) |
| `test_meta_mtime_regular` | mtime restored via utimensat; matches stored value |
| `test_meta_mtime_pre_epoch` | Pre-epoch mtime stored and restored; tv_nsec normalisation applied |
| `test_meta_symlink_chmod_skipped` | No chmod called for symlink member |
| `test_meta_symlink_lchown` | lchown used for symlink (not chown); modifies symlink inode |
| `test_meta_symlink_utimensat_nofollow` | `utimensat` called with `AT_SYMLINK_NOFOLLOW` for symlinks |
| `test_meta_hardlink_no_metadata_ops` | No metadata operations performed for hardlink members |

### 5.3 Overwrite Handling

| Test case | What is verified |
|---|---|
| `test_overwrite_existing_regular` | Existing regular file unlinked before open; new content correct |
| `test_overwrite_no_stale_bytes` | Existing file longer than extracted content; no tail bytes after overwrite |
| `test_overwrite_existing_symlink` | Symlink unlinked; regular file created in its place |
| `test_overwrite_o_nofollow_defence` | Symlink created between unlink and open; open returns ELOOP; `ARK_ERR_IO_OPEN` |
| `test_overwrite_nonexistent_target` | No prior file; O_CREAT creates new file correctly |

### 5.4 Cleanup

| Test case | What is verified |
|---|---|
| `test_cleanup_hash_mismatch_removes_all` | Hash mismatch mid-extraction; all previously created objects removed |
| `test_cleanup_io_error_removes_all` | I/O error mid-extraction; all previously created objects removed |
| `test_cleanup_implicit_dirs_removed` | Implicit dirs from --member extraction included in cleanup |
| `test_cleanup_best_effort_continues` | One cleanup failure; remaining objects still removed |
| `test_cleanup_original_error_preserved` | Cleanup failure does not overwrite original error code |

### 5.5 Selective Extraction

| Test case | What is verified |
|---|---|
| `test_selective_member_present` | Requested member extracted; other members absent |
| `test_selective_implicit_dirs_created` | Parent dirs not in member set created implicitly with mode 0700 |
| `test_selective_member_absent` | Requested member not in archive; `ARK_ERR_FMT_INDEX` |

---

## 6. Fault Injection Catalogue (`test_fault.c`)

Every `ARK_*` wrapped syscall is failed at each point in the create and
extract sequences. Each test verifies:
- The correct `ark_err_t` error code is returned
- `ark_error_t` is populated with the injected errno
- No resource leak (open fds, allocated memory, partial files)
- No partial archive or partial extraction left on the filesystem

### 6.1 Create Sequence Faults

| Test case | Injected failure | Expected error |
|---|---|---|
| `test_fault_create_open_archive` | `ARK_OPEN` fails on archive file open | `ARK_ERR_IO_OPEN` |
| `test_fault_create_write_header` | `ARK_WRITE` fails on header write | `ARK_ERR_IO_WRITE` |
| `test_fault_create_lstat_member` | `ARK_LSTAT` fails during traversal | `ARK_ERR_IO_READ` |
| `test_fault_create_open_member` | `ARK_OPEN` fails on member file open | `ARK_ERR_IO_READ` |
| `test_fault_create_read_member` | `ARK_READ` fails reading member data | `ARK_ERR_IO_READ` |
| `test_fault_create_write_chunk` | `ARK_WRITE` fails writing compressed chunk | `ARK_ERR_IO_WRITE` |
| `test_fault_create_write_index` | `ARK_WRITE` fails writing index block | `ARK_ERR_IO_WRITE` |
| `test_fault_create_write_footer` | `ARK_WRITE` fails writing footer | `ARK_ERR_IO_WRITE` |
| `test_fault_create_opendir` | `ARK_OPENDIR` fails on source directory | `ARK_ERR_IO_READ` |
| `test_fault_create_readdir` | `ARK_READDIR` fails during traversal | `ARK_ERR_IO_READ` |
| `test_fault_create_realpath` | `ARK_REALPATH` fails on source path | `ARK_ERR_IO_READ` |

### 6.2 Extract Sequence Faults

| Test case | Injected failure | Expected error |
|---|---|---|
| `test_fault_extract_open_archive` | `ARK_OPEN` fails on archive open | `ARK_ERR_IO_OPEN` |
| `test_fault_extract_read_header` | `ARK_READ` fails reading header | `ARK_ERR_IO_READ` |
| `test_fault_extract_read_footer` | `ARK_READ` fails reading footer | `ARK_ERR_IO_READ` |
| `test_fault_extract_read_index` | `ARK_READ` fails reading index block | `ARK_ERR_IO_READ` |
| `test_fault_extract_read_chunk` | `ARK_READ` fails reading compressed chunk | `ARK_ERR_IO_READ` |
| `test_fault_extract_open_output` | `ARK_OPEN` fails creating output file | `ARK_ERR_IO_OPEN` |
| `test_fault_extract_write_output` | `ARK_WRITE` fails writing decompressed data | `ARK_ERR_IO_WRITE` |
| `test_fault_extract_mkdir` | `ARK_MKDIR` fails creating directory member | `ARK_ERR_IO_MKDIR` |
| `test_fault_extract_symlink_create` | `symlink()` fails creating symlink | `ARK_ERR_IO_SYMLINK` |
| `test_fault_extract_link_create` | `ARK_LINK` fails creating hardlink | `ARK_ERR_IO_LINK` |
| `test_fault_extract_lchown` | `ARK_LCHOWN` fails (non-root); non-fatal warning | warning only |
| `test_fault_extract_chmod` | `ARK_CHMOD` fails | `ARK_ERR_IO_CHMOD` |
| `test_fault_extract_utimensat` | `ARK_UTIMENSAT` fails | `ARK_ERR_IO_UTIMES` |
| `test_fault_extract_unlink_overwrite` | `ARK_UNLINK` fails in --overwrite path | `ARK_ERR_IO_OPEN` |
| `test_fault_extract_cleanup_track_alloc` | Cleanup tracker allocation fails (full extraction and implicit parent in selective extraction); nothing created is left behind | `ARK_ERR_IO_ALLOC` |
| `test_fault_extract_cleanup_unlink` | `ARK_UNLINK` fails during cleanup; continues | best-effort only |
| `test_fault_extract_cleanup_rmdir` | `ARK_RMDIR` fails during cleanup; continues | best-effort only |

---

## 7. Edge Case Catalogue (`test_edge.c`)

### 7.1 Archive Size Boundaries

| Test case | What is verified |
|---|---|
| `test_edge_empty_archive` | Archive with zero members; creates, verifies, extracts cleanly |
| `test_edge_single_member` | Archive with exactly one member |
| `test_edge_max_path_length` | Member path exactly 1023 bytes; accepted |
| `test_edge_path_one_over_max` | Member path 1024 bytes; `ARK_ERR_PATH_TOO_LONG` at creation |
| `test_edge_path_at_local_path_max` | On OpenBSD: path exactly PATH_MAX-1 bytes; accepted (OpenBSD PATH_MAX=1024) |

### 7.2 File Size Boundaries

| Test case | What is verified |
|---|---|
| `test_edge_empty_file` | Regular file with size=0; chunk_count=0; round-trip correct |
| `test_edge_single_byte_file` | One-byte file; compressed and extracted correctly |
| `test_edge_exact_one_chunk` | File exactly 1MB (1048576 bytes); one chunk; round-trip correct |
| `test_edge_one_chunk_plus_one` | File 1048577 bytes; two chunks, second chunk = 1 byte; round-trip correct |
| `test_edge_exact_two_chunks` | File exactly 2MB; two full chunks; round-trip correct |

### 7.3 Adversarial Index Inputs

Each test constructs a crafted binary archive that passes the format
signature check but contains a specific malformation.

| Test case | Malformation | Expected error |
|---|---|---|
| `test_adv_forged_member_count` | `member_count = UINT32_MAX`; `index_size = 200` | `ARK_ERR_FMT_INDEX` (pre-allocation bound) |
| `test_adv_data_offset_in_header` | `data_offset = 0` (inside fixed header) | `ARK_ERR_FMT_INDEX` |
| `test_adv_data_range_past_index` | `data_offset + size_compressed > index_offset` | `ARK_ERR_FMT_INDEX` |
| `test_adv_overlapping_data_ranges` | Two members with identical data_offset | `ARK_ERR_FMT_INDEX` |
| `test_adv_hardlink_to_dir` | Hardlink target is a directory member | `ARK_ERR_FMT_INDEX` |
| `test_adv_hardlink_forward_ref` | Hardlink target appears after hardlink entry | `ARK_ERR_FMT_INDEX` |
| `test_adv_duplicate_paths` | Two members with path `a/b/c` | `ARK_ERR_FMT_INDEX` |
| `test_adv_path_traversal_abs` | Member path `/etc/passwd` | `ARK_ERR_PATH_TRAVERSAL` |
| `test_adv_path_traversal_dotdot` | Member path `../../etc/passwd` | `ARK_ERR_PATH_TRAVERSAL` |
| `test_adv_link_target_dotdot` | Symlink target `../../etc/passwd` | `ARK_ERR_FMT_INDEX` |
| `test_adv_link_target_too_long` | Symlink target 1024 bytes | `ARK_ERR_FMT_INDEX` |
| `test_adv_chunk_count_mismatch` | chunk_count=5 but size_original implies 1 | `ARK_ERR_FMT_INDEX` |
| `test_adv_nonzero_chunk_count_empty_file` | size_original=0 but chunk_count=1 | `ARK_ERR_FMT_INDEX` |
| `test_adv_corrupt_index_hash` | One byte of index block flipped after writing | `ARK_ERR_HASH_INDEX` |
| `test_adv_corrupt_member_data` | One byte of compressed chunk flipped | `ARK_ERR_HASH_MEMBER` |

### 7.4 Timestamp Edge Cases

| Test case | What is verified |
|---|---|
| `test_mtime_zero` | mtime = 0 (Unix epoch); stored and restored correctly |
| `test_mtime_pre_epoch` | mtime before 1970; stored as u64 two's complement; tv_nsec normalisation applied on restore |
| `test_mtime_pre_epoch_fractional` | Pre-epoch mtime with non-zero nanoseconds; normalisation produces valid tv_nsec >= 0 |
| `test_mtime_far_future` | mtime in year 2500; stored and restored correctly |

---

## 8. Integration Test Catalogue (`test_integration.c`)

Integration tests exercise the full pipeline without fault injection.
All tests run on real files in a temporary directory cleaned up after each
test. These tests are the final gate before a phase is declared complete.

| Test case | What is verified |
|---|---|
| `test_integration_single_file` | Create archive from one file; verify; extract; byte-identical |
| `test_integration_directory_tree` | Create from directory with subdirectories; extract; full tree matches |
| `test_integration_all_member_types` | Archive with regular, directory, symlink, hardlink; extract; all types correct |
| `test_integration_empty_file` | Archive containing empty regular file; extract; empty file present |
| `test_integration_round_trip_blake3` | BLAKE3 hash algorithm; create and verify; no hash errors |
| `test_integration_round_trip_sha256` | SHA-256 hash algorithm; create and verify; no hash errors |
| `test_integration_mtime_preserved` | mtime of extracted members matches original source mtime |
| `test_integration_mtime_pre_epoch` | Source file with pre-epoch mtime; survives round-trip |
| `test_integration_verify_detects_corruption` | Flip one byte in member data; verify reports `ARK_ERR_HASH_MEMBER` |
| `test_integration_verify_detects_index_corruption` | Flip one byte in index; verify reports `ARK_ERR_HASH_INDEX` |
| `test_integration_overwrite` | Extract to directory with existing files; --overwrite; new contents correct |
| `test_integration_overwrite_symlink` | Existing symlink at target path; --overwrite; symlink replaced by file |
| `test_integration_selective_member` | Archive with three members; --member extracts only one |
| `test_integration_list` | list subcommand; output includes all member paths, sizes, types |
| `test_integration_generate_reader` | generate-reader output is valid C11; compiles with `cc -O2`; runs against test archive |
| `test_integration_generate_reader_no_follow` | Recovery reader refuses to write through a pre-existing symlink at a regular-file member path (empty and non-empty); symlink target unchanged |
| `test_integration_deterministic` | Same source content archived twice; archives are bit-identical |
| `test_integration_large_archive` | Archive containing 1000 files of mixed sizes; create, verify, extract; all clean |

---

## 9. Platform Testing

| Platform | Architecture | Required |
|---|---|---|
| Linux | x86_64 | Yes - primary development platform |
| Linux | ARM64 | Yes - before release |
| OpenBSD | x86_64 | Yes - before release |
| OpenBSD | ARM64 | Yes - before release |

All tests must pass on all platforms before any phase is declared complete.
Platform-conditional test code is not permitted - the same test binary runs
unmodified on Linux and OpenBSD.

**Sandboxing tests:** The sandboxing policy (`pledge`/`unveil` on OpenBSD,
Landlock on Linux) is exercised by the integration tests. Each subcommand
test verifies the sandbox does not interfere with legitimate operations.
Sandbox policy is applied in each integration test as it would be in
production.

OpenBSD-specific note: `generate-reader` uses libchevron atomic commit flow,
which performs metadata operations (`fchmod`/`fchown`) and read-only parent
directory access during commit/open; the pledge profile for
`ARK_CMD_GENERATE_READER` therefore requires `rpath` and `fattr` in addition
to `stdio wpath cpath`.

**Landlock ABI version detection:** The integration tests on Linux verify
correct behaviour on the host kernel's Landlock ABI version. No specific
kernel version is required for the test environment beyond the hard minimum
of Linux 5.13.

---

## 10. Sanitiser and Tool Matrix

| Check | Tool | Platform | When |
|---|---|---|---|
| Memory errors, leaks | Valgrind | Linux | After each phase; before release |
| Memory errors, undefined behaviour | ASan/UBSan | Linux | Every `make test` (dev build) |
| Data races | TSan | Linux (Clang only) | At thread phase boundary; before release |
| Static analysis | clang-tidy | Linux, OpenBSD | Before release |
| Static analysis | cppcheck | Linux, OpenBSD | Before release |
| Code formatting | clang-format | Both | Before every commit |

Unlike libchevron, ark uses `malloc`/`free`. Valgrind is therefore
substantively useful for detecting heap errors and leaks, not only for
validating the test harness. All tests must pass Valgrind clean with
`--leak-check=full --show-leak-kinds=all --track-origins=yes`.

TSan is primarily useful for verifying the thread pool, ring buffer, shared
cancellation flag, and shared error struct. Run TSan after the parallelism
phase and after any subsequent change to concurrent data structures.

---

## 11. Coverage Tracking

Track coverage manually. Update after each phase. A cell is marked done
only when the test passes cleanly with Valgrind and ASan on Linux.

### Component Coverage

| Test file | Written | Valgrind clean | ASan clean | OpenBSD |
|---|---|---|---|---|
| `test_sha256.c` | ✓ | ✓ | ✓ | ✓ |
| `test_blake3.c` | ✓ | ✓ | ✓ | ✓ |
| `test_deflate.c` | ✓ | ✓ | ✓ | ✓ |
| `test_archive.c` | ✓ | ✓ | ✓ | ✓ |
| `test_thread.c` | ✓ | ✓ | ✓ (TSan) | ✓ |
| `test_extract.c` | ✓ | ✓ | ✓ | ✓ |
| `test_fault.c` | ✓ | ✓ | ✓ | ✓ |
| `test_edge.c` | ✓ | ✓ | ✓ | ✓ |
| `test_integration.c` | ✓ | ✓ | ✓ | ✓ |

### Key Correctness Cases

| Test case | File | Reference |
|---|---|---|
| SHA-256 NIST vectors all pass | `test_sha256.c` | ARCHITECTURE.md §8.4 |
| BLAKE3 official vectors all pass | `test_blake3.c` | ARCHITECTURE.md §8.4 |
| Deflate round-trip: byte-for-byte identity | `test_deflate.c` | ARCHITECTURE.md §7 |
| All sixteen §8.3 checks individually reject crafted malformed archive | `test_archive.c` | ARCHITECTURE.md §8.3 |
| member_count pre-allocation bound enforced before allocation | `test_archive.c` | ARCHITECTURE.md §5.1 |
| Write state machine: all invalid transitions return ARK_ERR_USAGE | `test_archive.c` | ARCHITECTURE.md §16.3 |
| Out-of-order chunk update: ARK_ERR_FMT_INDEX immediate | `test_archive.c` | ARCHITECTURE.md §16.4 |
| Ring buffer abort sentinel unblocks I/O thread | `test_thread.c` | ARCHITECTURE.md §6.3 |
| Worker error stored before sentinel; I/O thread reads it | `test_thread.c` | ARCHITECTURE.md §6.3 |
| Quiescence before cleanup: join completes, then filesystem ops | `test_thread.c` | ARCHITECTURE.md §14.3 |
| lchown before chmod on all metadata restoration paths | `test_extract.c` | ARCHITECTURE.md §14.5 |
| chmod skipped for symlink members | `test_extract.c` | ARCHITECTURE.md §14.5 |
| utimensat with AT_SYMLINK_NOFOLLOW for symlinks | `test_extract.c` | ARCHITECTURE.md §14.5 |
| --overwrite unlinks before open; no stale tail bytes | `test_extract.c` | ARCHITECTURE.md §14.2 |
| Implicitly created dirs included in cleanup | `test_extract.c` | ARCHITECTURE.md §14.4 |
| Pre-epoch mtime: tv_nsec normalised to >= 0 | `test_extract.c` | ARCHITECTURE.md §5.2 |
| Empty file: chunk_count=0 accepted; empty file extracted | `test_edge.c` | ARCHITECTURE.md §5.2 |
| Non-file member types: hash of empty byte sequence | `test_archive.c` | ARCHITECTURE.md §5.2 |
| data_offset + size_compressed bound checked | `test_edge.c` | ARCHITECTURE.md §8.3 |
| hardlink target type validated: only 0x01 accepted | `test_edge.c` | ARCHITECTURE.md §8.3 |
| Deterministic archives: identical source produces identical output | `test_integration.c` | ARCHITECTURE.md §13.1 |
| generate-reader output compiles and runs correctly | `test_integration.c` | ARCHITECTURE.md §15 |
| Every create sequence step tested with forced failure | `test_fault.c` | ARCHITECTURE.md §16.3 |
| Every extract sequence step tested with forced failure | `test_fault.c` | ARCHITECTURE.md §14 |

### Quality Milestone Gate

Milestones are defined in DEVELOPMENT.md. Each milestone is confirmed
by one or more specific test cases.

| Milestone | Confirmed by |
|---|---|
| Hash components: NIST/official vectors pass | `test_sha256.c`, `test_blake3.c` full catalogue |
| Deflate: round-trip correct; bound holds | `test_deflate.c` full catalogue |
| Archive format: all format validation checks implemented | `test_archive.c` §8.3 catalogue |
| Archive format: write state machine enforced | `test_archive.c` state machine catalogue |
| Thread pool: no deadlock on worker error | `test_thread.c ring_io_thread_unblocks_on_abort` |
| Thread pool: TSan clean | `make test-tsan` full test suite |
| Extraction: all sixteen §8.3 checks reject crafted inputs | `test_archive.c` §8.3 per-check tests |
| Extraction: cleanup removes all objects on any fatal error | `test_extract.c` cleanup catalogue |
| Extraction: metadata restored correctly per member type | `test_extract.c` metadata catalogue |
| Edge cases: adversarial index inputs all rejected | `test_edge.c` adversarial catalogue |
| Integration: full round-trip byte-identical | `test_integration_single_file` |
| Integration: deterministic output | `test_integration_deterministic` |
| Integration: generate-reader functional | `test_integration_generate_reader` |
| Valgrind clean on Linux | `make valgrind` full test suite |
| ASan/UBSan clean on Linux | `make dev` full test suite |
| All tests pass on OpenBSD | Full test suite on OpenBSD |

---

## 12. Cross-Reference

| Topic | Reference |
|---|---|
| Test harness structure and CHECK macro | TECH_STACK.md §6 |
| Fault injection infrastructure | TECH_STACK.md §6.2 |
| Per-phase test tasks | DEVELOPMENT.md (each phase) |
| Format binary layout | ARCHITECTURE.md §3, §4, §5 |
| Hash component APIs | ARCHITECTURE.md §8.4 |
| Deflate component API | ARCHITECTURE.md §7 |
| Pre-extraction validation (sixteen checks) | ARCHITECTURE.md §8.3 |
| Threading model and cancellation | ARCHITECTURE.md §6.3 |
| Ring buffer abort sentinel | ARCHITECTURE.md §6.3 |
| Worker error propagation | ARCHITECTURE.md §6.3 |
| Thread quiescence before cleanup | ARCHITECTURE.md §14.3 |
| Extraction cleanup policy | ARCHITECTURE.md §14.3 |
| Metadata restoration per member type | ARCHITECTURE.md §14.5 |
| --overwrite sequence | ARCHITECTURE.md §14.2 |
| Write context state machine | ARCHITECTURE.md §16.3 |
| Read context call sequence | ARCHITECTURE.md §16.4 |
| Recovery reader | ARCHITECTURE.md §15 |
| Known limitations | ARCHITECTURE.md §17 |
| SAFETY comment convention | CODING_STANDARDS.md §7.3 |
| Syscall wrapper macro discipline | CODING_STANDARDS.md §4.1 |
| Threading discipline | CODING_STANDARDS.md §5 |
