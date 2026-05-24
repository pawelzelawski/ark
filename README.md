# ark

`ark` is a crash-safe archive and compression tool for Linux and OpenBSD. It
creates and reads `.ark` files: a purpose-built binary archive format with
integrated Deflate compression, per-member integrity verification, an index
hash, and atomic crash-safe writes through vendored `libchevron`.

`ark` is a command-line tool, not a library, and it does not read or write
`tar`, `zip`, or other existing archive formats.

## What ark does

`ark` stores an ordered set of archive members:

- regular files
- directories
- symbolic links
- hardlinks

For each member, `ark` stores metadata including mode, uid, gid, mtime, size,
data offsets, chunk sizes, and a cryptographic hash. Member data is split into
fixed 1MB chunks. Each chunk is compressed independently with Deflate, enabling
parallel compression during archive creation and parallel decompression during
extraction.

On extraction, `ark` verifies the archive index before touching the filesystem.
This prevents extraction from starting when the archive index is malformed or
corrupt.

## Supported platforms

Both Linux and OpenBSD are first-class supported platforms.

| Platform | Minimum version | Reason |
|---|---:|---|
| Linux | kernel 5.13 | Landlock filesystem sandboxing |
| OpenBSD | 6.4 | `unveil(2)` sandboxing |

Linux 5.13 is a hard minimum. If Landlock is unavailable at runtime, `ark`
fails immediately instead of running without sandboxing. OpenBSD uses
`pledge(2)` and `unveil(2)`.

Supported architectures are x86_64 and ARM64. The implementation is portable
C11 with no architecture-specific assembly, SIMD, or intrinsics.

## Dependencies

Runtime dependencies:

- Linux: libc, libpthread, Linux kernel 5.13+
- OpenBSD: libc, OpenBSD 6.4+

The repository is self-contained. `libchevron` is vendored at a pinned commit,
and the SHA-256, BLAKE3, and Deflate implementations are built directly into
the `ark` binary.

Build requirements:

- `make`
- a C11 compiler
- Clang 14.0 or newer as the primary compiler
- GCC 11.0 or newer as a Linux-only secondary compiler

Development and validation tools:

- Valgrind on Linux for memory checking
- cppcheck for static analysis
- clang-tidy and clang-format from the Clang toolchain

## Building

Build the development binary:

```sh
make dev
```

Build the optimized release binary:

```sh
make release
```

The `ark` binary is written to:

```sh
build/ark
```

Run the test suite:

```sh
make test
```

Run the Linux validation targets:

```sh
make valgrind
make test-tsan
make lint
make format
```

`make valgrind` and `make test-tsan` are Linux-only targets. OpenBSD validates
correctness with the standard build and test suite because OpenBSD clang does
not ship the sanitizer runtimes and Valgrind is not available there.

## Installing

Install the binary and manual page:

```sh
make install
```

The default installation prefix is `/usr/local`. Override it with `PREFIX`:

```sh
make install PREFIX="$HOME/.local"
```

`make install` installs:

- `$(BINDIR)/ark`
- `$(MANDIR)/man1/ark.1`

## Quickstart

### Create an archive

Create an archive from a file or directory:

```sh
ark create archive.ark path
```

Use SHA-256 instead of the default BLAKE3 hash:

```sh
ark create --hash sha256 archive.ark path
```

Use faster Deflate parsing with a lower compression ratio:

```sh
ark create --fast archive.ark path
```

Print each member path as it is added:

```sh
ark create --verbose archive.ark path
```

### List archive contents

List archive members:

```sh
ark list archive.ark
```

List with full metadata:

```sh
ark list --verbose archive.ark
```

Print sizes in human-readable form with verbose output:

```sh
ark list --verbose --human archive.ark
```

`ark list` reads and verifies only the index. Member data is not decompressed.

### Extract an archive

Extract into the current directory:

```sh
ark extract archive.ark
```

Extract into a specific directory:

```sh
ark extract --output restored archive.ark
```

Extract one member:

```sh
ark extract --member path/in/archive archive.ark
```

Overwrite existing extraction targets:

```sh
ark extract --overwrite archive.ark
```

Without `--overwrite`, `ark` checks for conflicts before touching the
filesystem and aborts if any extraction target already exists.

### Verify an archive

Verify all regular-file member data and hashes:

```sh
ark verify archive.ark
```

Verify selected members:

```sh
ark verify --member path/in/archive archive.ark
```

Print each verified member:

```sh
ark verify --verbose archive.ark
```

### Generate a recovery reader

Generate a standalone C11 recovery reader:

```sh
ark generate-reader recovery.c
```

If no output path is supplied, `ark generate-reader` writes `recovery.c` in the
current directory:

```sh
ark generate-reader
```

The generated source contains a Deflate decompressor, BLAKE3 and SHA-256
implementations, archive read logic, and a minimal extraction program for the
v1 archive format.

Example compilation:

```sh
cc -O2 recovery.c -o recover
```

## Format overview

An `.ark` file has four top-level regions. See `ARCHITECTURE.md` section 2,
"Format Overview", for the complete format overview.

```text
[Fixed header]       16 bytes, always at byte offset 0
[Member data]        N compressed member blocks, sequential
[Index]              Variable length, all member metadata
[Footer]             64 bytes, always at file_size - 64
```

The footer stores the byte offset of the index. A reader locates the index by
reading the footer at `file_size - 64`, validating the footer magic, then
seeking to `index_offset`.

The index contains one entry per member and is verified as a whole before any
member metadata is accessed or any filesystem operation is performed. All
multi-byte integer fields in the fixed header, index entries, and footer are
little-endian.

Member data is written between the fixed header and the index. Regular-file
content is split into fixed 1MB chunks, and each chunk is compressed as an
independent Deflate stream. Compressed chunk sizes are stored in the member's
index entry.

## Sandboxing

Sandboxing is mandatory and platform-specific. See `ARCHITECTURE.md` section
10.4, "Sandboxing", for the full policy table.

- Linux uses Landlock and seccomp-bpf.
- OpenBSD uses `pledge(2)` and `unveil(2)`.
- `create` and `extract` use worker threads and require pthread support.
- `list` and `verify` require read access to the archive only.
- `generate-reader` requires write/create access to the output parent
  directory.

There is no unsandboxed fallback path for supported platforms.

## Known limitations

The complete list of confirmed design limitations is maintained in
`ARCHITECTURE.md` section 17, "Known Limitations". Highlights include:

- `--overwrite` is not rollback-safe. If extraction fails after replacing a
  pre-existing file, the original file contents are lost.
- The recovery reader covers the v1 format only.
- The archive index is loaded entirely into memory during reads.
- The writer buffers index metadata in memory until all member data has been
  written.
- Compression is always enabled; there is no store-only mode.
- ACLs, SELinux contexts, and extended attributes are not preserved.
- Paths are limited to 1023 bytes.
- Concurrent writes to the same target path are not coordinated by `ark`.
- Local POSIX filesystem behavior is required; network filesystem guarantees
  are outside the project scope.
- Numeric uid/gid values are restored on a best-effort basis and are not
  portable across systems.
- Existing archives cannot be appended to or updated in place.
- A crash can leave an orphaned libchevron temporary file in the target parent
  directory, but not a partial archive at the target path.
- The chunk size is fixed at 1MB for v1 archives.
- On Linux 5.13 through 5.18, extraction of archives containing hardlinks is
  rejected before filesystem side effects because hardlink extraction requires
  Landlock ABI v2, available from Linux 5.19.
- Cleanup failure after an extraction error may leave residual extracted
  content, with warnings reported to stderr.
- `ark generate-reader` writes a separate companion source file; users are
  responsible for keeping it alongside long-term archives.

## Documentation

- `ARCHITECTURE.md` - complete format, API, security, error, threading, and
  limitations specification
- `TECH_STACK.md` - compiler, build, platform, and tool requirements
- `TESTING.md` - test strategy and validation catalogue
- `CODING_STANDARDS.md` - source style and implementation rules
- `DEVELOPMENT.md` - phased development plan and quality milestones
- `man/ark.1` - command-line reference

## License

ISC License. See `LICENSE`.
