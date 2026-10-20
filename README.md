# ark

`ark` is a crash-safe archive and compression tool for Linux and OpenBSD. It
creates `.ark` files with integrated Deflate compression, per-member hashes, an
index hash, sandboxed operations, and atomic writes via vendored
[libchevron](https://github.com/pawelzelawski/libchevron).

`ark` is a command-line tool, not a library, and it does not read or write
`tar`, `zip`, or other existing archive formats.

## Features

- Single `.ark` archive format with built-in Deflate compression
- Per-member and index integrity verification
- Parallel create and extract using fixed 1MB chunks; create keeps chunks of
  several files in flight, so trees of small files compress in parallel too
- Crash-safe archive writes via vendored
  [libchevron](https://github.com/pawelzelawski/libchevron)
- Mandatory sandboxing: Landlock/seccomp-bpf on Linux, `pledge(2)` and
  `unveil(2)` on OpenBSD
- Standalone recovery reader generation for long-term archive recovery

## Requirements

- Linux 5.13+ or OpenBSD 6.4+
- x86_64 or ARM64
- C11 compiler
- `make`
- No external runtime dependencies beyond libc/pthread
- Vendored [libchevron](https://github.com/pawelzelawski/libchevron)

Linux 5.13 is a hard minimum because Landlock sandboxing is mandatory. On Linux
5.13 through 5.18, extracting archives containing hardlinks is rejected before
filesystem side effects because hardlink extraction requires Landlock ABI v2,
available from Linux 5.19.

## Build

```sh
make release
```

The binary is written to:

```sh
build/ark
```

Install the binary and manual page:

```sh
make install
```

The default prefix is `/usr/local`. Override it with:

```sh
make install PREFIX="$HOME/.local"
```

Run the test suite:

```sh
make test
```

## Quickstart

Create an archive:

```sh
ark create archive.ark path
```

The default compression (Deflate level 6) favours small archives.
`--fast` uses level 1 instead: creating is roughly two to three times
faster, but the archive is about a tenth larger and somewhat slower to
extract. The archive format is the same either way.

```sh
ark create --fast archive.ark path
```

List archive contents:

```sh
ark list archive.ark
```

Verify archive integrity:

```sh
ark verify archive.ark
```

Extract into a directory:

```sh
ark extract --output restored archive.ark
```

Generate a standalone recovery reader:

```sh
ark generate-reader recovery.c
cc -O2 recovery.c -o recover
```

## Recovery reader

`ark generate-reader` writes a self-contained C11 source file that can extract
v1 `.ark` archives without requiring `ark` itself. The intended preservation
workflow is to keep both files together:

```text
archive.ark
recovery.c
```

If this repository disappears, or if `ark` is not installed many years later,
anyone with a C11 compiler on a POSIX system (POSIX.1-2008) can build the
recovery reader and extract the archive:

```sh
cc -O2 recovery.c -o recover
mkdir out && cd out && ../recover ../archive.ark
```

The generated file opens with a description of the whole format, enough to
recover the data by hand, and includes a Deflate decompressor, BLAKE3 and
SHA-256 implementations, archive read logic, and an extraction program. It
checks the archive exactly as `ark` does before writing anything (exit
status 2 if the archive is rejected), extracts into the current directory
without replacing existing files or following a symbolic link in a member's
path, restores mode and mtime, and needs memory for the archive index plus
about 2 MiB, whatever the archive size. If a member is damaged, recovery
stops there and keeps the members already recovered. See `ARCHITECTURE.md`
section 15 for the full recovery model.

## Format overview

```text
[Fixed header]       16 bytes
[Member data]        Deflate-compressed 1MB chunks
[Index]              Member metadata, offsets, chunk sizes, hashes
[Footer]             64 bytes, contains index location and hash
```

All multi-byte fields are little-endian. The index is verified before
extraction touches the filesystem. See `ARCHITECTURE.md` for the full format
specification.

## Important limitations

- Not compatible with tar, zip, or other archive formats
- No encryption
- No ACL, SELinux context, or extended attribute preservation
- `--overwrite` is not rollback-safe
- Index metadata is buffered in memory
- Compression is always enabled; there is no store-only mode
- Recovery readers are separate companion files and must be kept with archives

See `ARCHITECTURE.md` section 17 for the complete limitations list.

## Documentation

- [`man/ark.1`](man/ark.1) - command reference
- [`ARCHITECTURE.md`](ARCHITECTURE.md) - format and implementation specification
- [`TECH_STACK.md`](TECH_STACK.md) - build and platform requirements
- [`TESTING.md`](TESTING.md) - validation strategy
- [`DEVELOPMENT.md`](DEVELOPMENT.md) - implementation history and milestones
- [libchevron](https://github.com/pawelzelawski/libchevron) - vendored
  crash-safe write library used by `ark`

## License

[`ISC License`](LICENSE)
