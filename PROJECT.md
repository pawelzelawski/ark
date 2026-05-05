# ark

A crash-safe archive and compression tool for Linux and OpenBSD.

ark implements a purpose-built archive format with integrated Deflate
compression, per-member and per-index integrity verification, and atomic
crash-safe writes. It is a single self-contained binary with zero external
dependencies beyond libc and vendored libchevron.

---

## The Problem

Existing archive formats carry the constraints of the hardware and use cases
that existed when they were designed. tar was designed for sequential magnetic
tape: no index, no random access, weak checksums, ambiguous filename encoding,
and multiple incompatible dialects. gzip is a separate tool applied after
archiving, producing two-extension artifacts (.tar.gz) that reflect the two
separate concerns. Neither was designed with multi-core hardware, SSD random
access, or century-scale durability simultaneously in mind.

In practice every project that needs reliable archiving either accepts these
limitations or reaches for complex tools (7z, libarchive) that carry large
codebases with third-party dependencies and format complexity that resists
auditing.

ark fills a specific gap: a clean-slate 2026 archive format and tool designed
for Linux and OpenBSD, with integrated compression, strong integrity, crash-safe
atomic writes, and a codebase small enough to audit and trust completely.

---

## Design Philosophy

**One format, one tool, one extension.** Compression is integral to the ark
format, not a separate step. Unlike tar+gzip, there is no separation of
archiving and compression concerns. The result is a single `.ark` file produced
by a single `ark` command. Two-extension artifacts and two-step workflows are
eliminated by design.

**Correctness is a format property.** Every member carries a cryptographic
hash. The index carries a cryptographic hash. Corruption is detected before any
data is extracted. Partial extraction due to corruption is not possible - the
reader validates the index completely before touching the filesystem.

**Longevity by simplicity.** The format spec fits in a single document. The
compression algorithm (Deflate, RFC 1951) is public domain and reimplementable
from spec. The hash algorithms (BLAKE3, SHA-256) are well-specified and
independently implementable. The entire codebase is small enough to be read
and understood by a single engineer in a day. The source code of the reader is
intended to be included inside archives for maximum recovery longevity.

**Zero external dependencies.** libc and POSIX only, plus vendored libchevron
(author's own library, same license, same standards). No third-party libraries.
No build system beyond make. A future person who can compile C can build ark
from a single repository clone with no network access.

**Auditability by component separation.** The internal implementation is
decomposed into independent components with clean APIs: hash layer, compression
layer, archive format layer, CLI and I/O layer. Each component is a separate
source file with a separate header. Each can be read, tested, and reasoned
about independently. Each could be extracted for reuse in another project
without modification.

**Multi-core aware by design.** Member data is split into fixed-size
independent chunks. Each chunk is compressed and hashed independently. This
enables parallel compression on archive creation and parallel decompression
on extraction, utilising all available CPU cores for large archives.

**Atomic crash safety.** The archive writer uses libchevron's streaming
interface. The target `.ark` file either exists complete and verified or does
not exist. A partial write caused by process crash or power loss never leaves
a corrupt file at the target path.

**Precise error reporting.** Every failure produces a specific, actionable
error. Errors with non-obvious causes include a human-friendly explanation
alongside the technical detail.

---

## What ark Does

ark creates, lists, and extracts `.ark` archives. An archive contains an
ordered set of members - regular files, directories, symbolic links, and
hardlinks - with their metadata (mode, uid, gid, mtime) and content preserved.

**On creation:** ark traverses the source filesystem tree, splits each
member's content into 1MB chunks, compresses each chunk independently using
Deflate, computes a cryptographic hash of each compressed member, writes all
member data sequentially, writes the index (metadata for all members including
chunk sizes, data offsets, and hashes), writes the index hash to the footer,
and commits the complete archive atomically via libchevron.

**On extraction:** ark reads the footer to locate the index, verifies the
index hash, validates all member paths against the local platform's PATH_MAX
before touching the filesystem, then extracts members to the target directory.
If any validation fails, extraction is aborted before creating a single file
or directory.

**On listing:** ark reads and verifies the index and prints member metadata
without decompressing any member data.

---

## What ark Does Not Do

- Does not support Windows (not a target platform)
- Does not support network filesystem guarantees (local POSIX only)
- Does not preserve ACLs, SELinux contexts, or extended attributes - mode,
  uid, and gid only
- Does not perform multi-archive spanning
- Does not support encryption (integrity only, not confidentiality)
- Does not support incremental or differential archives
- Does not support append to an existing archive
- Does not interoperate with tar, zip, or any other archive format
- Does not resume after a crash - the archive either exists complete or
  does not exist

---

## Dependency Model

| Dependency | Kind | Rationale |
|---|---|---|
| libc (POSIX.1-2008) | System | Only unavoidable dependency |
| libchevron | Vendored (author's own) | Crash-safe atomic write; same license, same standards |

The project description states "zero external dependencies". libchevron is
vendored at a pinned commit inside the ark repository. No system library
search, no pkg-config, no version negotiation. The repository is entirely
self-contained.

---

## Component Structure

```
sha256.c / sha256.h       SHA-256 hash - pure algorithm, no I/O, no allocation
blake3.c / blake3.h       BLAKE3 hash - pure algorithm, no I/O, no allocation
deflate.c / deflate.h     Deflate compress + decompress - pure algorithm, no I/O
archive.c / archive.h     Format read/write - calls hash and deflate layers
main.c                    CLI, filesystem traversal, platform I/O, libchevron use
vendor/libchevron/        Vendored libchevron at pinned commit
```

Each component has a single responsibility. Lower components know nothing
about higher components. The hash and deflate components are extractable for
reuse in other projects without modification.

---

## Target Platforms

| Platform | Architecture | Status |
|---|---|---|
| Linux | x86_64 | First-class |
| Linux | ARM64 | First-class |
| OpenBSD | amd64 | First-class |
| OpenBSD | arm64 | First-class |

Linux and OpenBSD are equally first-class. No feature, behaviour, or error
path is permitted to work correctly on one platform and incorrectly on the
other.

---

## Current Status

Design phase complete. Implementation not yet started.

| Area | Status |
|---|---|
| Project overview and philosophy | COMPLETE |
| Archive format - fixed header | COMPLETE |
| Archive format - footer | COMPLETE |
| Archive format - index structure | COMPLETE |
| Archive format - member data layout | COMPLETE |
| Deflate implementation scope | COMPLETE |
| Hash layer API | COMPLETE |
| Archive read/write API | COMPLETE |
| Writer behaviour (traversal, hardlinks, symlinks) | COMPLETE |
| Reader behaviour (validation, error model) | COMPLETE |
| CLI interface | COMPLETE |
| Self-describing recovery story | COMPLETE |
| Security model (sandboxing, privilege) | COMPLETE |
| Error model | COMPLETE |
| Threading model | COMPLETE |
| Tech stack and build system | COMPLETE |
| Coding standards | COMPLETE |
| Development plan (phased) | COMPLETE |
| Testing strategy | COMPLETE |
| Repository structure | COMPLETE |

---

## License

ISC License.
