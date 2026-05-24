# Development Plan

## Status Overview

**Last Updated:** 2026-05-24
**Current Phase:** Phase 8 - Hardening and release (not started)
**Next Task:** Phase 8.1 - Static analysis

### Phase Summary

| Phase | Name | Status | Tests | Notes |
|---|---|---|---|---|
| 1 | Foundation | DONE | 1.1-1.4 complete | Build system, test harness, skeleton, fault injection infrastructure |
| 2 | Cryptographic components | DONE | 2.1-2.4 complete | sha256, blake3 against official test vectors |
| 3 | Deflate component | DONE | 3.1-3.4 complete | Compress, decompress, bound; round-trip correctness |
| 4 | Archive format | DONE | 4.1-4.5 complete | archive.h types, write path, read path, and §8.3 validation coverage |
| 5 | CLI: core operations | DONE | 5.1-5.10 complete | Single-threaded create/extract/list/verify/generate-reader; sandboxing |
| 6 | Thread pool | DONE | 6.1-6.7 complete | Ring buffer, workers, cancellation, error propagation; TSan required; parallel correctness confirmed |
| 7 | Test suite completion | DONE | 7.1-7.3 complete | Integration tests complete; coverage verification and OpenBSD run complete |
| 8 | Hardening and release | NOT STARTED | - | Valgrind, TSan final, static analysis, README |

### Quality Milestones

| ID | Milestone | Status |
|---|---|---|
| M1 | Build system works on Linux x86_64 | DONE |
| M2 | Build system works on OpenBSD | DONE |
| M3 | SHA-256 NIST vectors all pass | DONE |
| M4 | BLAKE3 official vectors all pass | DONE |
| M5 | Deflate round-trip: byte-for-byte identity on all test inputs | DONE |
| M6 | Deflate bound: ark_deflate_bound holds for all inputs including incompressible | DONE |
| M7 | Archive format: all sixteen §8.3 checks individually reject crafted malformed archives | DONE |
| M8 | Archive format: write state machine enforced; all invalid transitions return ARK_ERR_USAGE | DONE |
| M9 | Single-threaded create produces valid, verifiable archive | DONE |
| M10 | Single-threaded extract round-trip: extracted content byte-identical to source | DONE |
| M11 | Sandboxing: all subcommands operate correctly under pledge/unveil on OpenBSD | DONE |
| M12 | Sandboxing: all subcommands operate correctly under Landlock on Linux 5.13+ | DONE |
| M13 | Thread pool: no deadlock on worker error (ring buffer abort sentinel unblocks I/O thread) | DONE |
| M14 | Thread pool: TSan clean | DONE |
| M15 | Parallel create: output bit-identical to single-threaded create on same input | DONE |
| M16 | Fault injection: every create sequence step covered with forced failure | DONE |
| M17 | Fault injection: every extract sequence step covered with forced failure | DONE |
| M18 | All sixteen §8.3 adversarial index inputs rejected before any filesystem side effect | DONE |
| M19 | Pre-epoch mtime: stored and restored; tv_nsec normalised to [0, 999999999] | DONE |
| M20 | Empty file: chunk_count=0 accepted; empty file extracted correctly | DONE |
| M21 | Non-file member types: hash of empty byte sequence stored and verified | DONE |
| M22 | --overwrite: existing target unlinked before open; no stale tail bytes | DONE |
| M23 | Cleanup: all filesystem objects removed after any fatal extraction error, including implicitly created dirs | DONE |
| M24 | generate-reader: output is valid C11 that compiles with `cc -O2` and extracts correctly (Phase 7 integration) | DONE |
| M25 | Deterministic archives: identical source content archived twice produces bit-identical archives (Phase 7 integration) | DONE |
| M26 | Valgrind clean on Linux x86_64 and ARM64 | NOT STARTED |
| M27 | ASan/UBSan clean on Linux | NOT STARTED |
| M28 | TSan clean on Linux (final sweep) | NOT STARTED |
| M29 | clang-tidy zero warnings on Linux and OpenBSD | NOT STARTED |
| M30 | cppcheck zero warnings on Linux and OpenBSD | NOT STARTED |
| M31 | clang-format clean | NOT STARTED |
| M32 | All tests pass on OpenBSD x86_64 | DONE |
| M33 | All tests pass on OpenBSD ARM64 | NOT STARTED |
| M34 | Deflate optimisation pass is format-preserving and deterministic (same input, same binary, identical output) | NOT STARTED |
| M35 | Deflate optimisation pass improves compression ratio on the reference benchmark dataset | NOT STARTED |
| M36 | Deflate optimisation pass improves create throughput or stays within an explicitly accepted regression threshold while improving ratio | NOT STARTED |

---

## Development Principles

Before starting any phase, read and follow these documents:

- **CODING_STANDARDS.md** - KNF style, error handling, memory and fd
  discipline, syscall wrapper discipline, threading discipline, context
  state machine rules, pre-commit checklist. Every function written must
  comply.
- **ARCHITECTURE.md** - The specification. Every implementation decision
  must match what is documented there. If there is a conflict, ARCHITECTURE.md
  wins - raise it before deviating.
- **TECH_STACK.md** - Compiler flags, build system, platform requirements,
  system library usage, sanitiser integration.
- **TESTING.md** - Test catalogue and quality milestone gate definitions.
  Do not write a test that is not in the catalogue without first adding it
  to TESTING.md.

**Bottom-up approach.** Each phase builds on the previous. Do not start a
phase until the prior phase is complete and all its tests pass cleanly with
Valgrind and ASan/UBSan on Linux. No exceptions.

**Test as you go.** Write tests for each component as it is implemented.
A component without passing tests is not done, regardless of whether the
implementation compiles.

**Wrapper macros always.** All syscall invocations in `src/` use the `ARK_*`
wrapper macros from `ark_internal.h`. Never invoke raw syscall names directly.
Verify before each commit:
```sh
grep -n "\bread\b\|\bwrite\b\|\bopen\b\|\blstat\b\|\bunlink\b\|\blchown\b\|\butimensat\b" src/*.c
```
This must produce no matches outside of comments and string literals.

**goto cleanup always.** Multi-step resource acquisition uses `goto cleanup`.
One cleanup label per function, reachable from all failure paths. See
CODING_STANDARDS.md §3.1.

**lchown before chmod always.** These two operations must appear in this
order on every metadata restoration path. On Linux, `lchown` clears setuid
and setgid bits; `chmod` after restores them. Code review must verify this
order actively. See CODING_STANDARDS.md §4.4.

**malloc is permitted but disciplined.** Every `malloc` has exactly one
matched `free` on all paths. No allocation inside the per-chunk hot path.
Ownership documented at the allocation site. Verify after each phase:
```sh
grep -n "malloc\|calloc\|realloc" src/archive.c
```
This must produce no matches inside `ark_write_chunk` or `ark_read_chunk`.

**Phase ordering rationale.** Phases 2 and 3 build the pure-C components
with no I/O or platform dependencies first. Phase 4 builds the format layer
on top of those components, keeping all platform-specific code out of
`archive.c`. Phase 5 builds the CLI and platform-specific code (sandboxing,
traversal) using the validated format layer. Phase 6 adds parallelism to an
already-correct single-threaded implementation. Phases cannot be reordered.

---

## Phase 1 - Foundation

**Goal:** Repository structure is in place. Build system works on Linux on
both architectures. Test harness compiles and runs. All skeleton headers and
source files are present with correct include structure. Fault injection
infrastructure is defined and verified. Code compiles clean with zero warnings.

**Reference documents:**
- TECH_STACK.md §4 - compiler flags and build targets
- TECH_STACK.md §5 - Makefile structure and platform detection
- TECH_STACK.md §6 - test harness structure
- CODING_STANDARDS.md §1.2 - file organisation and include order
- REPOSITORY_STRUCTURE.md §1 - top-level directory layout
- REPOSITORY_STRUCTURE.md §2 - src/ file annotations

### Tasks

**1.1 - Repository skeleton** ✓ DONE
- [x] Create directory structure: `src/`, `vendor/`, `tests/`, `man/`
- [x] Create `vendor/libchevron/` and populate with the pinned libchevron
  commit; create `vendor/libchevron/COMMIT` containing the full commit SHA-1
- [x] Create `src/sha256.h`, `src/sha256.c`, `src/blake3.h`, `src/blake3.c`,
  `src/deflate.h`, `src/deflate.c`, `src/archive.h`, `src/archive.c`,
  `src/main.c`, `src/recovery_template.c` as empty skeletons with include
  guards, correct includes, and no implementation
- [x] Create `src/ark_internal.h` with include guards and `ARK_*` wrapper
  macro definitions (production path - direct syscall names); the
  `#ifdef ARK_TEST` stub block is a placeholder at this stage
- [x] Create `tests/run_tests.c` stub: `main()` that prints `0/0 tests passed`
  and exits 0
- [x] Create `tests/ark_stubs.c` stub: empty file, compiled only with
  `-DARK_TEST`
- [x] Create stub test files: `tests/test_sha256.c`, `tests/test_blake3.c`,
  `tests/test_deflate.c`, `tests/test_archive.c`, `tests/test_thread.c`,
  `tests/test_extract.c`, `tests/test_fault.c`, `tests/test_edge.c`,
  `tests/test_integration.c` - each defines one empty test function
  returning 0 and registers it in `run_tests.c`
- [x] Create `.clang-format` (KNF-based, consistent with ecosystem)
- [x] Create `.clang-tidy` configuration

**1.2 - Build system** ✓ DONE
- [x] Create top-level `Makefile` with all targets per TECH_STACK.md §5.1:
  `dev`, `release`, `test`, `test-tsan`, `valgrind`, `lint`, `format`,
  `clean`, `install`
- [x] Platform detection via `OS != uname -s`; all flag sets per
  TECH_STACK.md §4.3; `-DARK_TEST` defined in test builds
- [x] `-lpthread` linked on Linux; omitted on OpenBSD
- [x] Add the recovery template embedding rule to the Makefile:
  `build/recovery_template_data.h` generated from `src/recovery_template.c`
  via a portable awk one-liner; `src/main.c` includes this generated header
  (the include is a forward declaration at this stage)
- [x] Verify `make dev` compiles with zero warnings on Linux x86_64
- [x] Verify `make release` compiles with zero warnings on Linux x86_64
- [x] Verify `make test` compiles and runs with `0/0 tests passed`
- [x] Quality milestone M1 confirmed

**1.3 - Fault injection infrastructure** ✓ DONE
- [x] Define all `ARK_*` wrapper macros in `ark_internal.h`:
  `ARK_READ`, `ARK_WRITE`, `ARK_OPEN`, `ARK_CLOSE`, `ARK_LSTAT`,
  `ARK_UNLINK`, `ARK_RMDIR`, `ARK_LINK`, `ARK_MKDIR`, `ARK_LCHOWN`,
  `ARK_CHMOD`, `ARK_UTIMENSAT`, `ARK_OPENDIR`, `ARK_READDIR`,
  `ARK_CLOSEDIR`, `ARK_REALPATH`
- [x] In production builds: each macro expands to the real syscall name
- [x] Define `ark_fault_t` struct in `ark_internal.h` under `#ifdef ARK_TEST`:
  `which` (int enum), `fail_on_call_n` (int), `errno_value` (int), and
  call counters per syscall (one int per `ARK_*` macro)
- [x] Declare `extern ark_fault_t ark_fault` in test builds
- [x] In test builds: each macro expands to a stub function that increments
  its call counter, checks whether this is the `n`th call to fail, and
  either injects `errno_value` and returns -1 (or NULL for pointer-returning
  syscalls) or calls the real syscall
- [x] Implement stubs in `tests/ark_stubs.c`; define `ark_fault_t ark_fault`
- [x] Implement `fault_reset()` and `fault_inject()` helpers in
  `tests/ark_stubs.c`
- [x] Verify: `make test` compiles with `-DARK_TEST` and the stubs link

**1.4 - OpenBSD build verification** ✓ DONE
- [x] Verify `make dev` compiles with zero warnings on OpenBSD
- [x] Verify `make test` compiles and runs on OpenBSD
- [x] Quality milestone M2 confirmed

### Phase 1 Completion Criteria

- [x] All targets in the Makefile work on Linux
- [x] All targets (excluding `make valgrind` and `make test-tsan`) work on
  OpenBSD
- [x] `make test` exits 0 (stub tests, no real tests yet)
- [x] Zero warnings on both platforms
- [x] Quality milestones M1, M2 confirmed

---

## Phase 2 - Cryptographic Components

**Goal:** `sha256.c` and `blake3.c` are fully implemented and validated
against their respective official test vectors on both platforms. Both
components are self-contained and have no dependencies beyond libc.

**Prerequisite:** Phase 1 complete.

**Reference documents:**
- ARCHITECTURE.md §8.4 - hash component API contracts
- TESTING.md §3.1 - SHA-256 test catalogue
- TESTING.md §3.2 - BLAKE3 test catalogue

### Tasks

**2.1 - SHA-256 implementation** ✓ DONE
- [x] Define `ark_sha256_ctx_t` struct in `sha256.h`: internal state fields
  per FIPS 180-4 (eight 32-bit state words, message schedule buffer, byte
  count)
- [x] Implement `ark_sha256_init`, `ark_sha256_update`, `ark_sha256_final`
  in `sha256.c` per FIPS 180-4; no platform intrinsics, pure portable C
- [x] Implement `ark_sha256` single-shot wrapper
- [x] Verify `sha256.h` is self-contained:
  `cc -std=c11 -fsyntax-only src/sha256.h`

**2.2 - SHA-256 tests** ✓ DONE
- [x] Implement `test_sha256_empty`: NIST vector for zero bytes
- [x] Implement `test_sha256_abc`: NIST vector for "abc"
- [x] Implement `test_sha256_448_bits`: NIST vector for 448-bit message
- [x] Implement `test_sha256_one_block`: 55-byte input
- [x] Implement `test_sha256_exact_block`: 64-byte input
- [x] Implement `test_sha256_block_boundary`: 56-byte input split across two
  `ark_sha256_update` calls
- [x] Implement `test_sha256_two_blocks`: 65-byte input
- [x] Implement `test_sha256_multiblock`: 1KB input
- [x] Implement `test_sha256_single_shot_matches_streaming`
- [x] Implement `test_sha256_output_length`
- [x] Implement `test_sha256_independent_contexts`
- [x] All SHA-256 tests pass; Valgrind clean; ASan clean
- [x] Quality milestone M3 confirmed

**2.3 - BLAKE3 implementation** ✓ DONE
- [x] Define `ark_blake3_ctx_t` struct in `blake3.h`; internal state per the
  BLAKE3 specification (chaining values, input buffer, block state, chunk
  counter, stack)
- [x] Implement `ark_blake3_init`, `ark_blake3_update`, `ark_blake3_final`
  in `blake3.c`; sequential mode only; output fixed to 32 bytes
- [x] Implement `ark_blake3` single-shot wrapper
- [x] Verify `blake3.h` is self-contained:
  `cc -std=c11 -fsyntax-only src/blake3.h`

**2.4 - BLAKE3 tests** ✓ DONE
- [x] Obtain official BLAKE3 test vectors from the reference repository
- [x] Implement `test_blake3_vectors_all`: loop over all official vectors
- [x] Implement `test_blake3_empty`, `test_blake3_single_chunk`,
  `test_blake3_multi_chunk`, `test_blake3_large`
- [x] Implement `test_blake3_output_fixed_32`
- [x] Implement `test_blake3_single_shot_matches_streaming`
- [x] Implement `test_blake3_independent_contexts`
- [x] Implement `test_blake3_incremental_updates`
- [x] All BLAKE3 tests pass; Valgrind clean; ASan clean
- [x] Quality milestone M4 confirmed

### Phase 2 Completion Criteria

- [x] All SHA-256 tests pass on Linux and OpenBSD
- [x] All BLAKE3 tests pass on Linux and OpenBSD
- [x] Valgrind clean; ASan/UBSan clean on Linux
- [x] Quality milestones M3, M4 confirmed

---

## Phase 3 - Deflate Component

**Goal:** `deflate.c` is fully implemented. Compress and decompress are
correct. `ark_deflate_bound` holds for all inputs including incompressible
data. Round-trip produces byte-for-byte identical output.

**Prerequisite:** Phase 2 complete.

**Reference documents:**
- ARCHITECTURE.md §7 - Deflate design decisions and compressor requirements
- ARCHITECTURE.md §7.2 - compressor quality requirements
- TESTING.md §3.3 - Deflate test catalogue

### Tasks

**3.1 - Deflate API definition** ✓ DONE
- [x] Define public API in `deflate.h`:
  `ark_deflate_compress(src, src_len, dst, dst_cap, mode)` → `ssize_t`;
  `ark_deflate_decompress(src, src_len, dst, dst_cap)` → `ssize_t`;
  `ark_deflate_bound(src_len)` → `size_t`
- [x] Document: `ark_deflate_compress` receives at most `ARK_CHUNK_SIZE`
  (1048576) bytes; `ark_deflate_decompress` returns -1 on invalid stream
  or output buffer overflow; `archive.c` maps -1 to `ARK_ERR_FMT_DATA`
- [x] Expose `ARK_CHUNK_SIZE` as a named constant in `deflate.h`
- [x] Verify `deflate.h` is self-contained

**3.2 - Deflate compressor** ✓ DONE
- [x] Implement `ark_deflate_bound`: returns an upper bound on compressed
  output size for a given input size; must hold for all inputs including
  incompressible (stored block framing overhead)
- [x] Implement `ark_deflate_compress`: RFC 1951 Deflate compressor with
  hash-chain match finding and lazy matching; handles incompressible content
  via stored blocks (fallback when compressed size >= input size);
  deterministic: same input always produces same output

**3.3 - Deflate decompressor** ✓ DONE
- [x] Implement `ark_deflate_decompress`: strict RFC 1951 Deflate
  decompressor; supports stored, fixed-Huffman, and dynamic-Huffman blocks;
  validates all block headers and back-references; returns -1 on any invalid
  stream or output buffer overflow

**3.4 - Deflate tests** ✓ DONE
- [x] Implement `test_deflate_round_trip_text`
- [x] Implement `test_deflate_round_trip_binary`
- [x] Implement `test_deflate_round_trip_empty`
- [x] Implement `test_deflate_round_trip_single_byte`
- [x] Implement `test_deflate_round_trip_exact_chunk`
- [x] Implement `test_deflate_round_trip_sub_chunk`
- [x] Implement `test_deflate_incompressible_within_bound`
- [x] Implement `test_deflate_bound_non_zero`
- [x] Implement `test_deflate_stored_block_valid`
- [x] Implement `test_deflate_default_emits_dynamic_block`
- [x] Implement `test_deflate_fast_emits_fixed_block`
- [x] Implement `test_deflate_invalid_stream`
- [x] Implement `test_deflate_truncated_stream`
- [x] Implement `test_deflate_output_buffer_too_small`
- [x] Implement `test_deflate_output_buffer_exact`
- [x] All deflate tests pass; Valgrind clean; ASan clean
- [x] Quality milestones M5, M6 confirmed

### Phase 3 Completion Criteria

- [x] All deflate tests pass on Linux and OpenBSD
- [x] Valgrind clean; ASan/UBSan clean on Linux
- [x] Quality milestones M5, M6 confirmed

---

## Phase 4 - Archive Format

**Goal:** `archive.c` is fully implemented. Write path produces correct
binary output per the format spec. Read path validates all sixteen §8.3
checks before touching the filesystem. All write state machine transitions
enforced. Per-member and index hash verification correct.

**Prerequisite:** Phase 3 complete.

**Reference documents:**
- ARCHITECTURE.md §3-§6 - format binary layout
- ARCHITECTURE.md §8.3 - sixteen pre-extraction validation checks
- ARCHITECTURE.md §16.3 - write path API and state machine
- ARCHITECTURE.md §16.4 - read path API and call sequence
- TESTING.md §3.4 - archive write path test catalogue
- TESTING.md §3.5 - archive read path test catalogue

### Tasks

**4.1 - archive.h public types** ✓ DONE
- [x] Define `ark_err_t` enum: all error codes per ARCHITECTURE.md §11.3
- [x] Define `ark_error_t` struct: `code`, `sys_errno`, `msg[256]`,
  `path[1024]`
- [x] Define `ark_hash_alg_t`, `ark_deflate_mode_t` enums
- [x] Define `ark_member_meta_t` struct: all fields per §5.2; `chunk_sizes`
  is a `uint32_t *` (NULL on write path, populated on read path)
- [x] Define `ark_write_ctx_t` and `ark_read_ctx_t` as opaque structs
- [x] Declare all public write and read path functions
- [x] Verify `archive.h` is self-contained

**4.2 - Write path implementation** ✓ DONE
- [x] Implement `ark_write_init`: initialise context, record `hash_alg` and
  `mode`; set state to READY
- [x] Implement `ark_write_header`: serialise 16-byte fixed header per §3;
  all fields little-endian; dst_cap < 16 → `ARK_ERR_IO_ALLOC`; set state
  to IDLE
- [x] Implement `ark_write_member_begin`: validate state is IDLE; record
  member metadata; initialise per-member hash context; set state to MEMBER
- [x] Implement `ark_write_chunk`: validate state is MEMBER; validate member
  type is 0x01; update per-member hash over `src` bytes; record chunk size;
  copy `src` to `dst`; return bytes copied
- [x] Implement `ark_write_member_end`: validate state is MEMBER; finalise
  per-member hash; record hash and chunk table into context; set state to IDLE
- [x] Implement `ark_write_index`: validate state is IDLE; serialise all
  member entries in index format per §5; compute and store index hash;
  dst_cap check → `ARK_ERR_IO_ALLOC`; set state to INDEXED
- [x] Implement `ark_write_footer`: validate state is INDEXED; serialise
  64-byte footer per §4; retrieve index hash from context; dst_cap < 64 →
  `ARK_ERR_IO_ALLOC`; set state to DONE
- [x] Implement `ark_write_free`: release all context-owned memory regardless
  of state
- [x] Verify all state machine transitions: every invalid transition returns
  -1 with `ARK_ERR_USAGE`

**4.3 - Write path tests** ✓ DONE
- [x] Implement all state machine tests per TESTING.md §3.4
- [x] Implement all byte layout correctness tests
- [x] Implement hash correctness tests: write archive, read back, verify
  index hash and per-member hashes match expected values
- [x] Implement empty member type tests: directory, symlink, hardlink hash
  equals hash of empty byte sequence

**4.4 - Read path implementation** ✓ DONE
- [x] Implement `ark_read_header`: validate state is UNINIT; parse and
  validate all header fields per §3; populate `comp_alg`, `hash_alg`,
  `ver_major`, `ver_minor` into context; set state to HEADER_DONE
- [x] Implement `ark_read_init`: validate state is HEADER_DONE; parse and
  validate footer per §4; populate `index_offset`, `index_size`,
  `member_count`, `index_hash` into context; set state to FOOTER_DONE
- [x] Implement `ark_read_index`: validate state is FOOTER_DONE; apply
  member_count pre-allocation bound (`member_count > index_size / 84` →
  `ARK_ERR_FMT_INDEX`); verify index hash before parsing; implement all
  sixteen §8.3 checks in order; allocate and populate member entry array;
  verify bytes consumed equals `index_size`; set state to INDEX_DONE
- [x] Implement all sixteen §8.3 checks explicitly; each check is a distinct
  validation step with its specific error code; see ARCHITECTURE.md §8.3
- [x] Implement `ark_read_member_meta`: validate state is INDEX_DONE; return
  pointer to entry at position `pos`; NULL if out of range
- [x] Implement `ark_read_chunk`: validate expected decompressed length; call
  `ark_deflate_decompress`; return `ARK_ERR_FMT_DATA` on invalid stream or
  length mismatch
- [x] Implement `ark_read_verify_member_begin`: reset per-member hash context
  and expected chunk index counter to 0
- [x] Implement `ark_read_verify_member_update`: validate chunk index is the
  expected next in sequence (`ARK_ERR_FMT_INDEX` on out-of-order); feed
  compressed bytes into hash context; increment expected chunk index
- [x] Implement `ark_read_verify_member_final`: compare computed hash against
  `meta->hash`; return `ARK_ERR_HASH_MEMBER` on mismatch
- [x] Implement `ark_read_free`: release all context-owned memory

**4.5 - Read path tests** ✓ DONE
- [x] Implement all header validation tests per TESTING.md §3.5
- [x] Implement all sixteen §8.3 per-check tests: each test crafts a binary
  archive that passes all prior checks and fails exactly at check N
- [x] Implement `test_read_member_count_too_large`
- [x] Implement all per-member verification tests
- [x] All archive tests pass; Valgrind clean; ASan clean
- [x] Quality milestones M7, M8 confirmed

### Phase 4 Completion Criteria

- [x] All archive unit tests pass on Linux and OpenBSD
- [x] All sixteen §8.3 checks individually verified by crafted malformed
  archive tests
- [x] Write state machine enforced: all invalid transitions tested
- [x] Per-member hash mismatch detected and reported correctly
- [x] Out-of-order chunk update returns `ARK_ERR_FMT_INDEX` immediately
- [x] Valgrind clean; ASan/UBSan clean on Linux
- [x] Quality milestones M7, M8, M20 (hash of empty byte sequence), M21
  (empty file chunk_count=0) confirmed

---

## Phase 5 - CLI: Core Operations

**Goal:** All five subcommands are implemented without a thread pool.
Single-threaded create and extract are correct and produce valid archives.
Sandboxing is applied correctly on both platforms. The full single-threaded
pipeline passes end-to-end tests.

**Prerequisite:** Phase 4 complete.

**Reference documents:**
- ARCHITECTURE.md §9 - crash safety via libchevron
- ARCHITECTURE.md §10.4 - sandboxing policies per subcommand
- ARCHITECTURE.md §13 - traversal, path stripping, special file handling
- ARCHITECTURE.md §14 - extraction model
- ARCHITECTURE.md §14.2 - overwrite handling
- ARCHITECTURE.md §14.3 - cleanup on fatal error
- ARCHITECTURE.md §14.4 - selective extraction
- ARCHITECTURE.md §14.5 - metadata restoration per member type
- ARCHITECTURE.md §15 - generate-reader
- TESTING.md §5 - extraction test catalogue
- TESTING.md §6 - fault injection catalogue

### Tasks

**5.1 - Argument parsing** ✓ DONE
- [x] Implement `parse_args` in `main.c`: parse subcommand, flags, and
  operands; validate required arguments; populate an `ark_args_t` struct;
  return `ARK_ERR_USAGE` with a descriptive message on invalid invocation
- [x] Subcommands: `create`, `extract`, `list`, `verify`, `generate-reader`
- [x] Flags: `--hash` (blake3 | sha256), `--overwrite`, `--member`,
  `--output`, `--fast`, `--verbose`, `--human`; flag interactions validated
- [x] `print_usage()` emits one-line invocation error detail to stderr,
  followed by `See man ark for usage.`, and exits 1

**5.2 - Sandbox application** ✓ DONE
- [x] Implement `sandbox_apply(subcommand, src_paths, src_count, archive_path, dst_path)` in `main.c`
- [x] On OpenBSD: call `pledge` and `unveil` with the correct strings and
  paths per ARCHITECTURE.md §10.4; `pledge` failure is fatal
- [x] On Linux: create Landlock ruleset with the correct access rights per
  §10.4; add rules for src and dst paths; apply ruleset via
  `landlock_restrict_self`; on kernel < 5.13 or Landlock unavailable: fail
  immediately with a clear error identifying the minimum kernel requirement
- [x] Sandbox is applied after argument parsing and libchevron handle
  initialisation, before the main operation; thread pool is initialised
  before sandbox is applied (Phase 6 task, but the call site is reserved)
- [x] Verify pledge/unveil strings match ARCHITECTURE.md §10.4 exactly:
  `pthread` promise present for create and extract

**5.3 - Filesystem traversal (create)** ✓ DONE
- [x] Implement `traverse_dir(src_path, write_ctx, chev_handle, err)` in
  `main.c`: depth-first traversal; entries sorted by `memcmp` byte order at
  each level per §13.1; stops at mount point boundaries per §13.6; skips
  special filesystem objects with a warning per §13.8; aborts on permission
  errors per §13.7
- [x] Implement `traverse_entry`: handles regular files, directories,
  symlinks, hardlinks; uses `ARK_LSTAT`, never follows symlinks
- [x] Path stripping per §13.5: resolve source via `ARK_REALPATH` once before
  traversal; strip prefix from all member paths
- [x] Inode deduplication table per §13.2: detect hardlink relationships;
  initial capacity 4096 slots, 0.75 load factor, double on resize; table
  freed after traversal
- [x] In single-threaded Phase 5: call `ark_deflate_compress` directly in
  `traverse_entry` for regular file chunks; call `ark_write_chunk` with the
  compressed result; no ring buffer, no worker threads yet

**5.4 - Create subcommand** ✓ DONE
- [x] Implement `cmd_create`: parse source paths and output path; initialise
  libchevron handle with `CHEVRON_FULL` durability; call `ark_write_init`,
  `ark_write_header`; run traversal; call `ark_write_index`,
  `ark_write_footer`; call `chevron_commit` on success or `chevron_abort`
  on any error; serialise index and footer into a malloc'd buffer before
  passing to `chevron_write_chunk`
- [x] Source modification detection per §13.4: record `st_mtime` of each
  regular file before opening; verify it has not changed after reading;
  `ARK_ERR_MODIFIED` on mismatch
- [x] Multiple source arguments: each argument is a separate archive root;
  traversed in order

**5.5 - Extract subcommand** ✓ DONE
- [x] Implement `cmd_extract`: open archive; call `ark_read_header`,
  `ark_read_init`, `ark_read_index`; apply pre-extraction validation (§8.3
  checks are implemented in `ark_read_index`; §14.2 conflict pre-flight
  check is main.c responsibility); apply sandbox; extract each member in
  index order
- [x] Implement extraction cleanup tracker: `cleanup_track` records each
  filesystem object immediately after creation; `cleanup_created` removes
  all tracked objects on fatal error; tracker allocated as a dynamic list
  grown by doubling
- [x] Implement extraction of each member type per §14: regular files,
  directories, symlinks, hardlinks
- [x] Implement metadata restoration per §14.5: per-member-type rules;
  `lchown` before `chmod`; `chmod` skipped for symlinks; `utimensat` with
  `AT_SYMLINK_NOFOLLOW` for symlinks
- [x] Implement `--overwrite` per §14.2: `lstat` target; if exists: `unlink`;
  open with `O_CREAT|O_WRONLY|O_NOFOLLOW`; `ELOOP` → `ARK_ERR_IO_OPEN`
- [x] Per-member hash verification: `ark_read_verify_member_begin`,
  `ark_read_verify_member_update` (called with compressed bytes before
  passing to `ark_read_chunk`), `ark_read_verify_member_final`
- [x] In single-threaded Phase 5: process one chunk at a time in the main
  loop; no parallelism

**5.6 - List subcommand** ✓ DONE
- [x] Implement `cmd_list`: open and validate archive via read path; iterate
  members; call `print_member` for each; output columns: type, size, mode,
  mtime, path
- [x] `--member` flag: print only the specified member; `ARK_ERR_FMT_INDEX`
  if not found

**5.7 - Verify subcommand** ✓ DONE
- [x] Implement `cmd_verify`: open and validate archive via read path; for
  each regular member: decompress all chunks into a temporary per-chunk
  buffer and feed compressed bytes into the verification hash; call
  `ark_read_verify_member_final`; report any hash mismatch immediately

**5.8 - generate-reader subcommand** ✓ DONE
- [x] Implement `src/recovery_template.c`: standalone recovery reader per
  ARCHITECTURE.md §15; footer parsing, index parsing and hash verification,
  member extraction to current directory; byte-by-byte little-endian field
  reads; no platform dependencies beyond libc; no host-endian struct casts
- [x] Implement `cmd_generate_reader`: write the embedded
  `recovery_template[]` byte array to the specified output path; use
  libchevron for the write; apply sandbox with write-only policy for output
  path

**5.9 - Output formatting** ✓ DONE
- [x] Implement `print_error`: format `ark_error_t` to stderr with ANSI
  colour when `isatty(STDERR_FILENO)` is true; red for errors
- [x] Implement `print_warning`: yellow warning line to stderr with terminal
  detection
- [x] Implement `print_member`: one formatted row for list output
- [x] All messages to syslog via `openlog`/`syslog`/`closelog` in addition
  to stderr

**5.10 - Extraction and fault tests** ✓ DONE
- [x] Keep strict component-layer scope for this task: core API test build only
  (`archive.c`, `deflate.c`, `blake3.c`, `sha256.c`), no `main.c` test harness
  changes
- [x] Expand format-layer read-path/adversarial coverage in `test_archive.c`
  / `test_edge.c` for §8.3 validation and index edge cases
- [x] Implement component-level fault-path tests in `test_fault.c` against
  archive/deflate public interfaces and ARK_TEST fault-injection boundaries
- [x] Linux mandatory validation gate and OpenBSD validation commands passed
  for the agreed 5.10 scope

### Phase 5 Completion Criteria

- [x] All five subcommands work correctly end-to-end (single-threaded)
- [x] Sandboxing applied correctly on both platforms; no sandbox interference
  with legitimate operations
- [x] All extraction and fault tests pass on Linux
- [x] All tests pass on OpenBSD
- [x] Valgrind clean; ASan/UBSan clean on Linux
- [x] Quality milestones M9, M10, M11, M12, M19, M22, M23 confirmed

---

## Phase 6 - Thread Pool

**Goal:** The single-threaded compression and decompression loops are
replaced with a parallel worker pool using the ring buffer model. The
parallel create output is bit-identical to the single-threaded create.
TSan clean on Linux.

**Prerequisite:** Phase 5 complete with all tests passing.

**Reference documents:**
- ARCHITECTURE.md §6.3 - parallelism model, threading model, cancellation,
  worker error propagation
- ARCHITECTURE.md §14.3 - thread quiescence before cleanup
- CODING_STANDARDS.md §5 - threading discipline
- TESTING.md §4 - thread test catalogue

### Tasks

**6.1 - Ring buffer** ✓ DONE
- [x] Implement `ring_buf_t` struct: fixed-size array of slots; each slot
  holds: sequence number, compressed data pointer, compressed length, abort
  flag, worker error; a mutex and condition variable for synchronisation
- [x] Implement `ring_buf_init(n_slots)`: allocate ring buffer with `n_slots`
  (one per worker thread)
- [x] Implement `ring_buf_write(ring, seq, data, len, err)`: worker path;
  write compressed result to slot `seq % n_slots`; signal I/O thread
- [x] Implement `ring_buf_abort(ring, seq, err)`: worker error path; write
  abort flag and error to slot; signal I/O thread; see ARCHITECTURE.md §6.3
- [x] Implement `ring_buf_read(ring, seq)`: I/O thread path; block until
  slot `seq % n_slots` is ready; return slot data or abort flag
- [x] Implement `ring_buf_free(ring)`: release ring buffer and all slot
  memory
- [x] Verify: I/O thread unblocks when abort sentinel is written to the
  awaited slot

**6.2 - Shared error state** ✓ DONE
- [x] Implement `ark_shared_err_t`: atomic flag (`_Atomic int`) indicating
  an error has been recorded; `ark_error_t` for the first worker error
- [x] Implement `error_store_once`: compare-and-swap write; only first
  worker error is stored; subsequent calls are no-ops

**6.3 - Worker threads** ✓ DONE
- [x] Implement `worker_compress(arg)`: receive chunk from queue; call
  `ark_deflate_compress`; on success: call `ring_buf_write`; on failure:
  call `error_store_once` then `ring_buf_abort`; check cancellation flag
  between chunks
- [x] Implement `worker_decompress(arg)`: same pattern for the extract path
- [x] Implement `pool_init(n_workers)`: allocate thread pool; create
  `n_workers` pthreads; each thread waits on a work queue
- [x] Implement `pool_submit(pool, chunk)`: enqueue a chunk for compression
  or decompression; block if queue is full
- [x] Implement `pool_shutdown(pool)`: set cancellation flag; join all
  workers; free pool

**6.4 - I/O thread integration** ✓ DONE
- [x] In `cmd_create`: replace single-threaded compression loop with:
  submit chunk to pool; drain ring buffer in sequence order; call
  `ark_write_chunk` with each delivered compressed result; on abort
  sentinel: read shared error, proceed to cancel + join + cleanup
- [x] In `cmd_extract`: same pattern for decompression
- [x] Number of worker threads: default `nproc` on Linux,
  `sysctl hw.ncpu` on OpenBSD; capped at a reasonable maximum (e.g. 16);
  not user-configurable

**6.5 - Thread quiescence on error** ✓ DONE
- [x] On any fatal error in `cmd_create` or `cmd_extract`: apply the five-
  step quiescence sequence per ARCHITECTURE.md §14.3:
  (1) set cancellation flag,
  (2) stop submitting new work,
  (3) join all workers,
  (4) close current output fd,
  (5) run cleanup
- [x] Verify: no filesystem cleanup races an active worker
- [x] Verify: `pthread_join` completes for all workers before any cleanup
  filesystem operation

**6.6 - Thread pool tests** ✓ DONE
- [x] Implement all ring buffer tests per TESTING.md §4.1
- [x] Implement all worker error propagation tests per TESTING.md §4.2
- [x] Implement all cancellation and quiescence tests per TESTING.md §4.3
- [x] All thread tests pass
- [x] `make test-tsan` passes: zero data races
- [x] Quality milestones M13, M14 confirmed

**6.7 - Parallel correctness**
- [x] Verify parallel create output is bit-identical to single-threaded
  create: run both on same input; compare archives byte-by-byte
- [x] Quality milestone M15 confirmed

### Phase 6 Completion Criteria

- [x] All thread pool tests pass
- [x] `make test-tsan` passes on Linux
- [x] Parallel and single-threaded create produce identical archives
- [x] All Phase 5 tests still pass after threading integration
- [x] Valgrind clean; ASan/UBSan clean on Linux
- [x] Quality milestones M13, M14, M15 confirmed

---

### Post-Phase 6 Follow-up - Deflate Optimisation Backlog

**Goal:** After Phase 6 threading is stable, improve Deflate ratio and CPU
cost without changing archive format, API, or determinism guarantees.

**Prerequisite:** Phase 6 complete.

**Reference documents:**
- ARCHITECTURE.md §6.2 - fixed 1MB independent chunk streams (must remain)
- ARCHITECTURE.md §7.2 - compressor quality targets
- ARCHITECTURE.md §13.1 - determinism scope
- ARCHITECTURE.md §15.3 - decompressor boundary required for recovery amalgamation

#### Tasks

**P6F.1 - Baseline freeze** ✓ DONE
- [x] Capture baseline benchmark on a fixed dataset: source size, archive
  size, create wall/user/sys time, verify wall/user/sys time

**P6F.2 - O1 fixed decode table caching (decompress path)** ✓ DONE
- [x] Prebuild and reuse fixed-Huffman decode tables instead of rebuilding
  per block
- [x] Verify no decompression output regressions on existing tests

**P6F.3 - O2 reset-cost reduction in match finder (compress path)** ✓ DONE
- [x] Replace full hash-chain table clears with a deterministic cheaper
  reset strategy (e.g. generation stamping)
- [x] Verify deterministic output unchanged for identical input and mode

**P6F.4 - O3 remove repeated parse passes for chosen dynamic block** ✓ DONE
- [x] Refactor default-mode block pipeline to avoid redundant full
  parse_block passes for the selected block
- [x] Keep block-boundary selection deterministic

**P6F.5 - O4 length-limited Huffman builder** ✓ DONE
- [x] Replace rank-based heuristic code-length assignment with a proper
  Deflate-compliant length-limited builder for lit/dist trees
- [x] Enforce Deflate max code-length constraints and preserve RFC 1951 validity

---

## Phase 7 - Test Suite Completion

**Goal:** Integration tests are complete and passing on both platforms.
All quality milestones for correctness are confirmed. Coverage tracking
in TESTING.md §11 is fully populated.

**Prerequisite:** Phase 6 complete.

**Reference documents:**
- TESTING.md §8 - integration test catalogue
- TESTING.md §11 - coverage tracking and quality milestone gate

### Tasks

**7.1 - Integration tests** ✓ DONE
- [x] Implement all integration tests per TESTING.md §8
- [x] `test_integration_generate_reader`: verify output compiles with
  `cc -O2 recovery.c -o recover && ./recover archive.ark`; extracted
  content matches source
- [x] `test_integration_deterministic`: archive same source twice; compare
  archives byte-by-byte; must be identical
- [x] `test_integration_large_archive`: 1000 files of mixed sizes; create,
  verify, extract; all clean; measures wall time for regression reference

**7.2 - Coverage verification** ✓ DONE
- [x] Verify every `ark_err_t` value appears in at least one test that
  triggers it under correct conditions
- [x] Verify every create sequence step has a fault injection test
- [x] Verify every extract sequence step has a fault injection test
- [x] Verify all sixteen §8.3 checks are individually tested with crafted
  archives
- [x] Populate TESTING.md §11 coverage tracking table; all cells marked done

**7.3 - OpenBSD test run** ✓ DONE
- [x] All tests pass on OpenBSD x86_64
- [x] Quality milestones M32 confirmed

### Phase 7 Completion Criteria

- [x] All integration tests pass on Linux and OpenBSD
- [x] Coverage tracking table fully populated
- [x] All correctness quality milestones confirmed
- [x] Quality milestones M24, M25, M32 confirmed

---

## Phase 8 - Hardening and Release

**Goal:** All quality milestones are confirmed. Static analysis, Valgrind,
TSan final sweep, and clang-format all pass clean. README is written.
Documentation is complete and accurate.

**Prerequisite:** Phase 7 complete with all tests passing on both platforms.

### Tasks

**8.1 - Static analysis**
- [ ] `make lint`: `clang-tidy` zero warnings on Linux
- [ ] `make lint`: `clang-tidy` zero warnings on OpenBSD
- [ ] `make lint`: `cppcheck` zero warnings on Linux
- [ ] `make lint`: `cppcheck` zero warnings on OpenBSD
- [ ] Resolve all findings before proceeding
- [ ] Quality milestones M29, M30 confirmed

**8.2 - Final Valgrind sweep**
- [ ] `make valgrind` clean on Linux x86_64
- [ ] `make valgrind` clean on Linux ARM64
- [ ] Quality milestone M26 confirmed

**8.3 - Final TSan sweep**
- [ ] `make test-tsan` passes on Linux x86_64
- [ ] `make test-tsan` passes on Linux ARM64
- [ ] Quality milestone M28 confirmed

**8.4 - Final sanitiser sweep**
- [ ] ASan/UBSan clean on Linux x86_64 and ARM64
- [ ] Quality milestone M27 confirmed

**8.5 - Code formatting**
- [ ] `make format` produces no diff
- [ ] Quality milestone M31 confirmed

**8.6 - OpenBSD ARM64 test run**
- [ ] All tests pass on OpenBSD ARM64
- [ ] Quality milestone M33 confirmed

**8.7 - README.md**
- [ ] Write `README.md`: what ark does, installation, minimum requirements
  (Linux 5.13+, OpenBSD 6.4+), quickstart examples for each subcommand,
  format overview, known limitations summary (pointing to ARCHITECTURE.md
  §17), build requirements

**8.8 - Final pre-release checklist**
- [ ] All quality milestones M1 through M33 confirmed
- [ ] No `FIXME` without explanation
- [ ] All public function doc comments complete and accurate
- [ ] ARCHITECTURE.md cross-reference comments present on every non-trivial
  sequence step in `src/main.c` and `src/archive.c`
- [ ] `SAFETY:` comments present on every safety-critical invariant
- [ ] `man/ark.1` reviewed; examples accurate; known limitations section
  matches ARCHITECTURE.md §17

### Phase 8 Completion Criteria

- [ ] All quality milestones M1 through M33 confirmed
- [ ] `make lint` zero warnings on all four platform/architecture combinations
- [ ] `make test-tsan` passes on Linux x86_64 and ARM64
- [ ] `make valgrind` clean on Linux x86_64 and ARM64
- [ ] `make format` produces no diff
- [ ] README.md complete
- [ ] Man page complete and accurate
