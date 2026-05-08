# Repository Structure

## 1. Top-Level Layout

```
ark/
├── Makefile                    # Build orchestration: dev, release, test, lint, install
├── .clang-format               # Code formatting rules (KNF-based)
├── .clang-tidy                 # Static analysis configuration
├── README.md                   # User-facing introduction, installation, quickstart
├── PROJECT.md                  # Overview, goals, scope, design philosophy
├── ARCHITECTURE.md             # Full architecture — format spec, component design,
│                               #   API contracts, security model, error model,
│                               #   threading model, known limitations
├── TECH_STACK.md               # Build system, compiler flags, system libraries,
│                               #   platform requirements, development tools
├── CODING_STANDARDS.md         # C style, error handling, memory and fd discipline,
│                               #   syscall wrapper discipline, threading discipline,
│                               #   context state machine rules, pre-commit checklist
├── REPOSITORY_STRUCTURE.md     # This file
├── DEVELOPMENT.md              # Phased implementation plan, milestones, task breakdown
├── TESTING.md                  # Test strategy, fault injection, test catalogue
├── man/                        # Manual page
├── src/                        # All source files
├── vendor/                     # Vendored dependencies (libchevron only)
└── tests/                      # Test suite
```

The sole build output is `build/ark`. No library is installed. `make install`
installs exactly two artefacts: the `ark` binary into `$(BINDIR)` and
`man/ark.1` into `$(MANDIR)/man1/`.

---

## 2. src/ — Source Files

ark is decomposed into five components, each a self-contained two-file unit
(public header + implementation), plus one internal shared header and the
application entry point.

```
src/
│
│   — Cryptographic hash components —
│
├── sha256.h            # SHA-256 public API.
│                       #
│                       # Types:
│                       #   ark_sha256_ctx_t   — opaque streaming context
│                       #
│                       # Functions:
│                       #   ark_sha256_init()   — initialise context
│                       #   ark_sha256_update() — feed data
│                       #   ark_sha256_final()  — produce 32-byte digest
│                       #   ark_sha256()        — single-shot convenience
│                       #
│                       # Self-contained: depends only on <stddef.h> and
│                       #   <stdint.h>. Copyable to other projects without
│                       #   modification. See ARCHITECTURE.md §8.4.
│
├── sha256.c            # SHA-256 implementation per FIPS 180-4.
│                       # Validated against NIST test vectors.
│                       # No dependencies beyond sha256.h and libc.
│
├── blake3.h            # BLAKE3 public API.
│                       #
│                       # Types:
│                       #   ark_blake3_ctx_t   — opaque streaming context
│                       #
│                       # Functions:
│                       #   ark_blake3_init()   — initialise context
│                       #   ark_blake3_update() — feed data
│                       #   ark_blake3_final()  — produce 32-byte digest
│                       #   ark_blake3()        — single-shot convenience
│                       #
│                       # Output length is fixed at 32 bytes. Variable-length
│                       #   output is not exposed. Tree parallelism is not
│                       #   exposed. Sequential mode only.
│                       #   See ARCHITECTURE.md §8.4.
│
├── blake3.c            # BLAKE3 implementation per the BLAKE3 specification.
│                       # Validated against the official BLAKE3 test vectors.
│                       # No dependencies beyond blake3.h and libc.
│
│   — Compression component —
│
├── deflate.h           # Deflate compress/decompress public API.
│                       #
│                       # Functions:
│                       #   ark_deflate_compress()  — compress one chunk
│                       #   ark_deflate_decompress()— decompress one chunk
│                       #   ark_deflate_bound()     — maximum compressed
│                       #     output size for a given input size; used by
│                       #     main.c to size output buffers
│                       #
│                       # No I/O, no allocation. Caller owns all buffers.
│                       # Caller is responsible for providing output buffers
│                       #   at least ark_deflate_bound(src_len) bytes.
│                       # Implements RFC 1951. See ARCHITECTURE.md §7.
│
├── deflate.c           # Deflate implementation.
│                       # Compressor targets near-optimal parsing with
│                       #   aggressive block boundary decisions.
│                       #   See ARCHITECTURE.md §7.2.
│                       # Decompressor is a strict RFC 1951 implementation.
│                       # No dependencies beyond deflate.h and libc.
│
│   — Archive format component —
│
├── archive.h           # Archive read and write public API.
│                       #
│                       # Types:
│                       #   ark_write_ctx_t    — write context
│                       #   ark_read_ctx_t     — read context
│                       #   ark_member_meta_t  — member metadata
│                       #   ark_error_t        — error detail struct
│                       #   ark_err_t          — error code enum
│                       #   ark_hash_alg_t     — BLAKE3 or SHA-256
│                       #   ark_deflate_mode_t — compressor quality
│                       #
│                       # Write path:
│                       #   ark_write_init()         — initialise context
│                       #   ark_write_header()        — serialise header
│                       #   ark_write_member_begin()  — begin member
│                       #   ark_write_chunk()         — record pre-compressed chunk
│                       #   ark_write_member_end()    — finalise member
│                       #   ark_write_index()         — serialise index
│                       #   ark_write_footer()        — serialise footer
│                       #   ark_write_free()          — release context
│                       #
│                       # Read path:
│                       #   ark_read_header()                 — parse and validate header
│                       #   ark_read_init()                   — parse and validate footer
│                       #   ark_read_index()                  — verify and parse index
│                       #   ark_read_member_meta()            — access member metadata
│                       #   ark_read_chunk()                  — decompress one chunk
│                       #   ark_read_verify_member_begin()    — begin per-member hash
│                       #   ark_read_verify_member_update()   — feed compressed chunk
│                       #   ark_read_verify_member_final()    — verify hash
│                       #   ark_read_free()                   — release context
│                       #
│                       # No I/O, no threading, no allocation beyond context
│                       #   lifetime. See ARCHITECTURE.md §16.
│
├── archive.c           # Archive format implementation.
│                       # Implements all write-path and read-path functions.
│                       # Enforces the §16.3 write context state machine.
│                       # Index serialisation and parsing.
│                       # Per-member and index hash verification.
│                       # Format validation per §8.3.
│
│   — Recovery reader template —
│
├── recovery_template.c # Source template for the generate-reader subcommand.
│                       #
│                       # A valid, standalone C11 source file that compiles
│                       #   with any C11 compiler. Produced as output by
│                       #   `ark generate-reader`. Not compiled into the ark
│                       #   binary directly; embedded as a byte array via
│                       #   the Makefile build step (see §6).
│                       #
│                       # Implements: footer parsing, index parsing and
│                       #   hash verification, member extraction to stdout.
│                       # Uses only libc. No platform dependencies.
│                       # Byte-by-byte little-endian field reads throughout
│                       #   (no host-endian struct casts). Compilable on any
│                       #   host byte order. See ARCHITECTURE.md §15.
│
│   — Internal shared header —
│
├── ark_internal.h      # Shared internal definitions.
│                       # Not part of any component's public API.
│                       # Included by all .c files in src/.
│                       #
│                       # Contains:
│                       #   ARK_* syscall wrapper macros for fault injection.
│                       #   In production builds: macros expand to real
│                       #     syscall names with zero overhead.
│                       #   In test builds (-DARK_TEST): macros expand to
│                       #     stub functions in tests/ark_stubs.c.
│                       #
│                       # Wrapped syscalls:
│                       #   ARK_READ        → read
│                       #   ARK_WRITE       → write
│                       #   ARK_OPEN        → open
│                       #   ARK_CLOSE       → close
│                       #   ARK_LSTAT       → lstat
│                       #   ARK_UNLINK      → unlink
│                       #   ARK_RMDIR       → rmdir
│                       #   ARK_LINK        → link
│                       #   ARK_MKDIR       → mkdir
│                       #   ARK_LCHOWN      → lchown
│                       #   ARK_CHMOD       → chmod
│                       #   ARK_UTIMENSAT   → utimensat
│                       #   ARK_OPENDIR     → opendir
│                       #   ARK_READDIR     → readdir
│                       #   ARK_CLOSEDIR    → closedir
│                       #   ARK_REALPATH    → realpath
│
│   — Application entry point —
│
└── main.c              # CLI entry point and application logic.
                        #
                        # Subcommand dispatch:
                        #   cmd_create()          — traverse, compress, write archive
                        #   cmd_extract()         — validate index, extract members
                        #   cmd_list()            — read index, print member table
                        #   cmd_verify()          — read index, verify all member hashes
                        #   cmd_generate_reader() — write recovery_template.c to output
                        #
                        # Argument parsing:
                        #   parse_args()          — validate flags and operands
                        #
                        # Thread pool (create and extract):
                        #   pool_init()           — allocate worker pool
                        #   pool_submit()         — submit chunk to worker queue
                        #   pool_shutdown()       — cancel flag, join, free
                        #   worker_compress()     — worker thread: compress one chunk
                        #   worker_decompress()   — worker thread: decompress one chunk
                        #
                        # Filesystem traversal (create):
                        #   traverse_dir()        — depth-first directory walk
                        #   traverse_entry()      — process one directory entry
                        #
                        # Ring buffer:
                        #   ring_buf_init()       — initialise fixed-size ring buffer
                        #   ring_buf_write()      — worker: write compressed result
                        #   ring_buf_abort()      — worker: write abort sentinel
                        #   ring_buf_read()       — I/O thread: read next slot in order
                        #   ring_buf_free()       — release ring buffer
                        #
                        # Extraction cleanup tracker:
                        #   cleanup_track()       — register created filesystem object
                        #   cleanup_created()     — remove all tracked objects
                        #
                        # Sandboxing:
                        #   sandbox_apply()       — apply pledge/unveil or Landlock
                        #                           policy for the current subcommand
                        #
                        # Output formatting:
                        #   print_error()         — format and emit ark_error_t to stderr
                        #   print_warning()       — yellow warning line to stderr
                        #   print_member()        — one member row for list subcommand
                        #
                        # main.c is the only file that calls pledge/unveil (OpenBSD)
                        # and Landlock/seccomp-bpf (Linux). No sandboxing code
                        # exists in any other source file.
```

---

## 3. vendor/ — Vendored Dependencies

```
vendor/
│
└── libchevron/             # Pinned commit of libchevron.
    │                       # Author's own library, ISC license.
    │                       # Provides crash-safe archive write via
    │                       #   chevron_open / chevron_write_chunk /
    │                       #   chevron_commit. Used exclusively by main.c
    │                       #   in the create subcommand.
    │                       # See ARCHITECTURE.md §9.
    │
    ├── include/
    │   └── chevron.h       # libchevron public API. Only header included
    │                       #   by ark source. See libchevron/ARCHITECTURE.md
    │                       #   for its internal design.
    │
    └── src/
        ├── chevron_internal.h  # libchevron internal header. Not included
        │                       #   by ark source.
        └── chevron.c           # libchevron implementation.
```

The vendored libchevron is pinned to a specific commit hash recorded in
`vendor/libchevron/COMMIT` (a single-line file containing the full SHA-1).
Updating libchevron requires updating this file and verifying that the full
test suite passes on both platforms with the new version.

libchevron source files are compiled directly into the `ark` binary alongside
ark's own source files. There is no separate libchevron.a build step.

---

## 4. tests/ — Test Suite

```
tests/
│
├── run_tests.c             # Test binary entry point.
│                           # Calls all test suite functions in order.
│                           # Accumulates pass/fail counts.
│                           # Exits 0 on all-pass, 1 on any failure.
│
├── ark_stubs.c             # Fault injection stubs.
│                           # Compiled only with -DARK_TEST.
│                           # Provides ARK_* stub functions that the wrapper
│                           #   macros in ark_internal.h resolve to in test
│                           #   builds. Controlled by a test state struct
│                           #   that specifies which syscall to fail, on
│                           #   which call count, and which errno to inject.
│                           #   See TESTING.md §2.3.
│
├── test_sha256.c           # SHA-256 correctness tests.
│                           # NIST FIPS 180-4 test vectors: empty input,
│                           #   one-block, multi-block, byte-boundary inputs.
│                           # Streaming and single-shot API paths.
│                           # See TESTING.md §3.1.
│
├── test_blake3.c           # BLAKE3 correctness tests.
│                           # Official BLAKE3 test vectors from the reference
│                           #   repository. All vector lengths covered.
│                           # Streaming and single-shot API paths.
│                           # See TESTING.md §3.2.
│
├── test_deflate.c          # Deflate compress/decompress tests.
│                           # Round-trip: compress then decompress, verify
│                           #   byte-for-byte identity.
│                           # Incompressible input: output no larger than
│                           #   ark_deflate_bound(src_len).
│                           # Empty input, single-byte input, exact chunk
│                           #   boundary, sub-chunk sizes.
│                           # Invalid compressed stream: ARK_ERR_FMT_DATA.
│                           # Length mismatch: ARK_ERR_FMT_DATA.
│                           # See TESTING.md §3.3.
│
├── test_archive.c          # archive.h API unit tests.
│                           # Write path: state machine valid transitions,
│                           #   all invalid transitions return ARK_ERR_USAGE,
│                           #   header/footer serialisation correctness,
│                           #   index serialisation and hash correctness,
│                           #   empty archive (zero members), single member,
│                           #   multi-member, all member types.
│                           # Read path: header validation (bad magic, bad
│                           #   version, unknown alg), footer validation,
│                           #   index hash verification, member_count pre-
│                           #   allocation bound, sixteen §8.3 checks each
│                           #   individually, per-member hash verification,
│                           #   out-of-order chunk update detection.
│                           # See TESTING.md §3.4.
│
├── test_thread.c           # Thread pool and ring buffer tests.
│                           # Ring buffer: normal produce/consume,
│                           #   abort sentinel written and detected,
│                           #   I/O thread unblocks on abort sentinel.
│                           # Worker error propagation: worker writes sentinel,
│                           #   shared error struct populated, I/O thread
│                           #   reads error and proceeds to cancel+join.
│                           # Cancellation: flag set, workers exit cleanly,
│                           #   join completes, no resource leak.
│                           # TSan required at phase boundary.
│                           # See TESTING.md §3.5.
│
├── test_extract.c          # Extraction correctness tests.
│                           # Path validation: all sixteen §8.3 checks,
│                           #   each tested with a crafted index that
│                           #   fails exactly that check.
│                           # Member types: regular file, directory, symlink,
│                           #   hardlink extraction and metadata restoration.
│                           # Symlink safety: lchown, AT_SYMLINK_NOFOLLOW,
│                           #   chmod skipped for symlinks.
│                           # --overwrite: existing regular file, existing
│                           #   symlink (unlinked before open), O_NOFOLLOW
│                           #   defence, stale tail bytes absent.
│                           # Cleanup tracker: all objects removed on fatal
│                           #   error, implicitly created dirs included.
│                           # See TESTING.md §3.6.
│
├── test_fault.c            # Fault injection at each sequence step.
│                           # Every ARK_* wrapped syscall is failed at each
│                           #   point in the create and extract sequences.
│                           # Verifies: correct error code returned, no
│                           #   resource leak (fd, memory, created files),
│                           #   error struct populated correctly.
│                           # Covers all components via stubs in ark_stubs.c.
│                           # See TESTING.md §4.
│
├── test_edge.c             # Boundary conditions and adversarial inputs.
│                           # Archive edge cases: empty archive, one-member
│                           #   archive, maximum path length (1023 bytes),
│                           #   path exactly at PATH_MAX on OpenBSD.
│                           # Member edge cases: empty regular file
│                           #   (chunk_count=0), file exactly 1MB,
│                           #   file exactly 2MB, single-byte file.
│                           # Adversarial index: forged member_count, bad
│                           #   data_offset, overlapping ranges, forward-
│                           #   referencing hardlink, hardlink to directory,
│                           #   duplicate paths, missing ancestor directory.
│                           # Pre-epoch mtime: stored and restored correctly.
│                           # See TESTING.md §5.
│
└── test_integration.c      # End-to-end integration tests.
                            # No fault injection. Exercises the full create
                            #   → extract → verify pipeline on real archives.
                            # Tests: single regular file, directory tree,
                            #   mixed member types, hardlinks and symlinks,
                            #   round-trip hash identity, --overwrite,
                            #   selective extraction via --member,
                            #   generate-reader output compiles and runs.
                            # See TESTING.md §6.
```

See TESTING.md for the complete test catalogue, fault injection infrastructure
design, platform test matrix, and quality milestone gates.

---

## 5. man/ — Manual Page

```
man/
│
└── ark.1           # UNIX manual page (troff/mdoc format).
                    # Installed to $(MANDIR)/man1/ by make install.
                    # Covers: synopsis, description, subcommands and their
                    #   flags, exit codes, format overview, known limitations
                    #   (including --overwrite non-atomicity and index memory
                    #   pressure), examples, and a note on the minimum Linux
                    #   kernel version (5.13).
```

---

## 6. Top-Level Files

### Makefile

Single top-level Makefile. No per-directory Makefiles. Compatible with GNU
make (Linux) and BSD make (OpenBSD). Uses `!=` for shell assignment.

```sh
make              # same as make dev
make dev          # debug build with ASan/UBSan (Linux), runs tests
make release      # optimised binary (build/ark)
make test         # compile and run tests (dev flags, -DARK_TEST)
make test-tsan    # TSan build and test run (Linux/Clang only)
make valgrind     # run tests under Valgrind (Linux only, no sanitisers)
make lint         # clang-tidy + cppcheck on src/
make format       # clang-format -i on all source and test files
make clean        # remove build artefacts
make install      # install ark binary and man page to PREFIX
```

Platform detected via `OS != uname -s`. `-DARK_TEST` is defined in
`make test`, `make dev`, `make valgrind`, and `make test-tsan` so that
fault injection stubs are always active during development.

**Recovery template embedding.** `src/recovery_template.c` is embedded into
the ark binary as a byte array. The Makefile generates
`build/recovery_template_data.h` at build time using a portable awk one-liner
that wraps the file content as a `static const unsigned char` array. This
header is included by `main.c` only. The awk step requires no tools beyond
what is present on any POSIX system.

```makefile
build/recovery_template_data.h: src/recovery_template.c
	awk 'BEGIN { print "static const unsigned char recovery_template[] = {" }
	     { for (i=1; i<=length($0); i++) printf "0x%02x,", ord(substr($0,i,1))
	       printf "0x0a," }
	     END { print "0x00 };" }' $< > $@
```

`make install` installs exactly two artefacts:
```sh
$(BINDIR)/ark
$(MANDIR)/man1/ark.1
```

Default install prefix is `/usr/local`. Override: `PREFIX=/path make install`.

### .clang-format

KNF-based formatting rules, consistent with all projects in this ecosystem:

```yaml
BasedOnStyle: LLVM
IndentWidth: 8
UseTab: ForIndentation
BreakBeforeBraces: Linux
ColumnLimit: 80
AllowShortFunctionsOnASingleLine: None
AllowShortIfStatementsOnASingleLine: Never
```

### .clang-tidy

Static analysis configuration:

```yaml
Checks: >
  clang-analyzer-*,
  cert-*,
  bugprone-*,
  performance-*,
  portability-*,
  -cert-err33-c,
  -bugprone-easily-swappable-parameters
```

---

## 7. Function-to-File Mapping

| Function | File | Notes |
|---|---|---|
| `ark_sha256_init` | `src/sha256.c` | Public |
| `ark_sha256_update` | `src/sha256.c` | Public |
| `ark_sha256_final` | `src/sha256.c` | Public |
| `ark_sha256` | `src/sha256.c` | Public; single-shot wrapper |
| `ark_blake3_init` | `src/blake3.c` | Public |
| `ark_blake3_update` | `src/blake3.c` | Public |
| `ark_blake3_final` | `src/blake3.c` | Public |
| `ark_blake3` | `src/blake3.c` | Public; single-shot wrapper |
| `ark_deflate_compress` | `src/deflate.c` | Public; called by worker threads |
| `ark_deflate_decompress` | `src/deflate.c` | Public; called by worker threads |
| `ark_deflate_bound` | `src/deflate.c` | Public; output buffer sizing |
| `ark_write_init` | `src/archive.c` | Public |
| `ark_write_header` | `src/archive.c` | Public |
| `ark_write_member_begin` | `src/archive.c` | Public |
| `ark_write_chunk` | `src/archive.c` | Public; I/O thread only |
| `ark_write_member_end` | `src/archive.c` | Public |
| `ark_write_index` | `src/archive.c` | Public |
| `ark_write_footer` | `src/archive.c` | Public |
| `ark_write_free` | `src/archive.c` | Public |
| `ark_read_header` | `src/archive.c` | Public |
| `ark_read_init` | `src/archive.c` | Public |
| `ark_read_index` | `src/archive.c` | Public |
| `ark_read_member_meta` | `src/archive.c` | Public |
| `ark_read_chunk` | `src/archive.c` | Public |
| `ark_read_verify_member_begin` | `src/archive.c` | Public |
| `ark_read_verify_member_update` | `src/archive.c` | Public |
| `ark_read_verify_member_final` | `src/archive.c` | Public |
| `ark_read_free` | `src/archive.c` | Public |
| `main` | `src/main.c` | Entry point |
| `parse_args` | `src/main.c` | Internal |
| `cmd_create` | `src/main.c` | Internal; create subcommand |
| `cmd_extract` | `src/main.c` | Internal; extract subcommand |
| `cmd_list` | `src/main.c` | Internal; list subcommand |
| `cmd_verify` | `src/main.c` | Internal; verify subcommand |
| `cmd_generate_reader` | `src/main.c` | Internal; generate-reader subcommand |
| `pool_init` | `src/main.c` | Internal; thread pool setup |
| `pool_submit` | `src/main.c` | Internal; enqueue chunk for worker |
| `pool_shutdown` | `src/main.c` | Internal; cancel, join, free |
| `worker_compress` | `src/main.c` | Internal; compression worker thread |
| `worker_decompress` | `src/main.c` | Internal; decompression worker thread |
| `ring_buf_init` | `src/main.c` | Internal; ring buffer setup |
| `ring_buf_write` | `src/main.c` | Internal; worker writes result slot |
| `ring_buf_abort` | `src/main.c` | Internal; worker writes abort sentinel |
| `ring_buf_read` | `src/main.c` | Internal; I/O thread reads next slot |
| `ring_buf_free` | `src/main.c` | Internal; release ring buffer |
| `traverse_dir` | `src/main.c` | Internal; depth-first directory walk |
| `traverse_entry` | `src/main.c` | Internal; process one directory entry |
| `cleanup_track` | `src/main.c` | Internal; register created object |
| `cleanup_created` | `src/main.c` | Internal; remove all tracked objects |
| `sandbox_apply` | `src/main.c` | Internal; pledge/Landlock per subcommand |
| `print_error` | `src/main.c` | Internal; format ark_error_t to stderr |
| `print_warning` | `src/main.c` | Internal; yellow warning to stderr |
| `print_member` | `src/main.c` | Internal; one row for list subcommand |
| All `ARK_*` stubs | `tests/ark_stubs.c` | Test only; fault injection |

---

## 8. Naming Conventions

**Component public API:** `ark_` prefix for all functions. `ARK_` prefix for
all macros, enum values, and constants. Defined in component public headers.

**Internal functions in main.c:** No `ark_` prefix. Descriptive verb-noun
names. All declared `static`. The `ark_` prefix is reserved for the component
public APIs.

**Internal wrapper macros:** `ARK_` prefix in `ark_internal.h`. Resolve to
real syscalls in production builds and to stubs in test builds.

| Namespace | Scope | Example |
|---|---|---|
| `ark_` (functions) | Component public API | `ark_write_chunk()`, `ark_read_index()` |
| `ARK_` (macros/enums) | Public constants | `ARK_CHUNK_SIZE`, `ARK_ERR_IO_READ`, `ARK_HASH_BLAKE3` |
| `ARK_` (macros) | Internal syscall wrappers | `ARK_READ`, `ARK_LSTAT`, `ARK_UTIMENSAT` |
| Verb-noun (static) | main.c internals | `traverse_dir()`, `ring_buf_abort()`, `cleanup_track()` |
| `cmd_` (static) | Subcommand handlers | `cmd_create()`, `cmd_extract()` |
| `worker_` (static) | Thread pool workers | `worker_compress()`, `worker_decompress()` |
