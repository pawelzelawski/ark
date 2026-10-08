# Architecture

## Status Note

This document is a design-phase snapshot. Sections marked DECIDED are locked.
Sections marked IN PROGRESS contain confirmed partial decisions with open items
noted explicitly. Sections marked NOT STARTED are placeholders for decisions
not yet reached. Nothing is implemented.

Sections §1 through §16 are fully decided and locked. §17 (Known Limitations)
is a living record of confirmed design decisions, not defects. Twelve external
AI audit rounds have been completed and all findings incorporated.

Remaining work before implementation: tech stack and build system, coding
standards, development plan (phased), testing strategy, repository structure.

---

## 1. Project Overview

### 1.1 What ark Is

ark is a command-line tool, not a library. It produces and consumes `.ark`
files: a purpose-built binary archive format with integrated Deflate
compression and cryptographic integrity verification.

The internal implementation is decomposed into library-quality components with
clean APIs. These components are extractable for reuse. The tool is the
primary deliverable; reusable components are a structural consequence of the
design discipline, not a separate goal.

### 1.2 What ark Is Not

ark is not a general-purpose compression library. It is not a tar replacement
in the sense of format interoperability - it does not read or write tar, zip,
or any other existing format. It is not a streaming pipe tool in the tar sense.
It is not a library with a public C API.

### 1.3 Design Goals (Priority Order)

1. **Correctness.** Every failure mode handled. Every error detected before
   filesystem side effects where possible. No silent data corruption. Partial
   extraction is prevented on any fatal error; cleanup after extraction is
   best-effort and cleanup failures are reported as warnings (see §14.3 and
   §17).

2. **Longevity.** Format specifiable in a single document. Algorithm
   implementations reproducible from public specs. Codebase auditable by one
   engineer in one day.

3. **Zero external dependencies.** libc + vendored libchevron (author's own).
   One repository clone, one make invocation.

4. **Auditability.** Component separation with clean APIs. One responsibility
   per source file. No hidden behaviour.

5. **Crash safety.** Archive target either exists complete and verified or
   does not exist. libchevron streaming interface used for all writes.

6. **Multi-core utilisation.** Fixed-size independent chunks enable parallel
   compression on creation and parallel decompression on extraction. A 50GB
   archive must not be limited to one CPU core.

### 1.4 Rejected Alternatives

**Using tar + gzip.** Carries 1979 tape-drive design constraints: no index,
no random access, weak checksums, multiple incompatible dialects, ambiguous
filename encoding. Not addressable without a new format.

**Using zstd for compression.** Better compression ratio than Deflate. Rejected
because a correct compressor implementation requires 8,000-15,000 lines of C
versus ~2,000-2,500 lines for Deflate with competitive match-finding. Deflate
is specified in RFC 1951 (public domain). The ratio difference (Deflate gives
~10-15% larger archives than zstd on text) is accepted in exchange for a fully
self-contained, auditable implementation. zstd is also available as a system
library on all target platforms but taking a system library dependency conflicts
with the zero-external-dependencies goal.

**Using LZMA1 for compression.** Evaluated during design phase via independent
research. LZMA1 sits between Deflate and zstd in ratio but has no RFC-grade
formal specification, implementation size estimates varied from 2,500 to 8,000
lines across sources indicating high uncertainty, and the chunking model used
by ark reduces LZMA1's primary advantage (large dictionary / long-distance
matching) to approximately 3-8% gain on mixed content over a well-implemented
Deflate compressor. The comp_alg field in the fixed header reserves space for
a future LZMA1 identifier if a standalone RFC-quality LZMA1 specification and
implementation is produced as a separate project.

**Using LZ4 for compression.** Simpler implementation (~600 lines) but
~25-35% larger archives than Deflate on text content. The ratio gap is too
significant for an archival tool. Deflate sits meaningfully closer to zstd
than to LZ4 in compression ratio.

**Using SHA-256 only.** SHA-256 is the conservative NIST-standard choice.
BLAKE3 is the modern high-performance choice. Both are supported as a
user-selectable option at archive creation time. BLAKE3 is the default.
Dual-hash (storing both per member) was considered and rejected: doubles the
hash field size per index entry, doubles hash computation on every read/write,
and adds format complexity. Single hash per archive selected by the user is
sufficient.

**Separate compression and archive layers (tar model).** Rejected. Integrated
compression enables per-member chunk offsets stored in the index, giving
random member access without full decompression. Two separate tools with two
extensions is an inferior user experience.

**Optional compression (store mode).** Rejected. Deflate handles
incompressible content gracefully via stored blocks internally - the overhead
is a few bytes of framing per chunk. A `--no-compress` flag would add a code
path in both reader and writer requiring testing and documentation permanently.
Compression is always on. This is a documented design decision.

**Whole-archive hash.** Considered and rejected. Per-member hashes plus
index hash provide end-to-end verification already. A whole-archive hash
would require either a two-pass write or a seek-back-and-patch after writing
the footer, working against libchevron's streaming model. No additional
integrity benefit justifies the complexity.

**Variable chunk size.** Fixed 1MB chunks were chosen over configurable chunk
size. A configurable chunk size adds a per-archive parameter to store, adds
reader complexity, and provides no meaningful benefit for the general case.
The fixed size is a documented format constant.

---

## 2. Format Overview

### 2.1 Structure

```
[Fixed header]       16 bytes, always at byte offset 0
[Member data]        N compressed member blocks, sequential
[Index]              Variable length, all member metadata
[Footer]             64 bytes, always at file_size - 64
```

The footer contains the byte offset of the index. A reader locates the index
by seeking to `file_size - 64`, reading the footer, verifying the footer magic,
then seeking to `index_offset`.

The index contains one entry per member. All entries are read into memory in
one operation and the index hash is verified before any member metadata is
accessed or any filesystem operation is performed.

Member data blocks are written sequentially between the fixed header and the
index. Each block contains the Deflate-compressed content of one member,
split into fixed-size 1MB chunks. Each chunk is compressed independently.
Chunk compressed sizes are recorded in the index entry for each member.

### 2.2 Byte Order

**Little-endian throughout.** All multi-byte integer fields in the fixed
header, index entries, and footer are little-endian. This is a hard format
invariant with no per-field exceptions.

---

## 3. Fixed Header

**DECIDED. No open items.**

Size: 16 bytes. Always at byte offset 0. Human-readable ASCII magic at bytes
0-4 ensures the archive is identifiable with `xxd`, `vim`, or any hex viewer
without format-specific tooling.

```
Offset  Size  Type  Name          Value / Meaning
------  ----  ----  ----          ---------------
0       1     u8    magic[0]      0x61 'a'
1       1     u8    magic[1]      0x72 'r'
2       1     u8    magic[2]      0x6B 'k'
3       1     u8    magic[3]      0x21 '!'
4       1     u8    magic[4]      0x0A '\n'
5       1     u8    ver_major     0x01 (current)
6       1     u8    ver_minor     0x00 (current)
7       1     u8    flags         0x00 reserved, must be zero
8       1     u8    comp_alg      0x01 = Deflate (only valid value in v1)
9       1     u8    hash_alg      0x01 = BLAKE3 (default)
                                  0x02 = SHA-256
10      6     u8[]  reserved      0x00 x6, must be zero
```

**comp_alg field rationale.** Although 0x01 (Deflate) is the only valid value
in format version 1, the field is retained because the compression layer is
implemented as a separate pluggable component (deflate.c with a clean API).
Future format versions may introduce additional compression algorithm
identifiers without requiring a major version bump. A reader encountering an
unknown comp_alg value must reject the archive with a specific error identifying
the unknown algorithm value, not a generic format error.

**hash_alg field.** One hash algorithm applies to the entire archive - all
per-member hashes and the index hash use the algorithm specified in this field.
The algorithm is chosen at archive creation time. BLAKE3 (0x01) is the default.
SHA-256 (0x02) is available for contexts where NIST compliance is required.

**Version compatibility.** A reader must check ver_major first. If ver_major
differs from the reader's supported version, reject with a clear error before
reading any other field. ver_minor differences within the same ver_major are
backwards compatible by definition.

---

## 4. Footer

**DECIDED. No open items.**

Size: 64 bytes. Always at `file_size - 64`. Fixed size means a reader can
locate the footer by a single seek without scanning.

```
Offset  Size  Type   Name            Value / Meaning
------  ----  ----   ----            ---------------
0       8     u64    index_offset    byte offset from file start to index start
8       8     u64    index_size      byte count of the index block
16      32    u8[]   index_hash      hash of the entire index block
                                     (BLAKE3 or SHA-256 per header hash_alg)
48      4     u32    member_count    total number of members in the archive
52      4     u32    magic_confirm   0x4B52410A fixed confirmation value
56      8     u8[]   reserved        0x00 x8, must be zero
```

**magic_confirm rationale.** A reader that finds valid magic at byte 0 and
valid magic_confirm at `file_size - 12` has high confidence it is reading a
real ark archive before performing any index I/O. A truncated or corrupt file
is detected at this step.

**index_hash verification.** The reader must verify index_hash before parsing
any index entry or performing any filesystem operation. A corrupt index is
detected before any side effects occur.

**Post-verification member_count use.** member_count is used after index_hash
verification to allocate the correct number of index entry structures before
parsing. It must not be used before hash verification.

---

## 5. Index

**DECIDED. No open items.**

### 5.1 Location and Loading

The index immediately precedes the footer. Its byte offset from the start of
the file is given by `index_offset` in the footer. Its total size in bytes is
given by `index_size` in the footer.

**Pre-allocation footer bounds checks.** Before allocating any buffer or
seeking to `index_offset`, the reader must validate the footer fields
using checked arithmetic. These checks require `file_size`, which is
known to `main.c` but is not passed to `ark_read_init()` (see §16.4).
Therefore these checks are explicitly assigned to `main.c` and must be
performed before calling `ark_read_init()`:

1. `file_size >= 80`: minimum valid ark file is 16-byte header + 0-byte
   body + 0-byte index + 64-byte footer. A shorter file is
   `ARK_ERR_FMT_TRUNCATED`.
2. `index_offset >= 16`: the index cannot overlap the fixed header.
   A value below 16 is `ARK_ERR_FMT_INDEX`.
3. `index_size > 0` or `index_offset == 16` for a zero-member archive.
4. `index_offset + index_size` does not overflow u64. Overflow is
   `ARK_ERR_FMT_INDEX`.
5. `index_offset + index_size == file_size - 64`. A mismatch is
   `ARK_ERR_FMT_INDEX`.

`main.c` reads `file_size` via `fstat()` on the open archive fd before
reading the footer. These five checks are performed after reading the
raw footer bytes and extracting `index_offset` and `index_size` from
them, but before calling `ark_read_init()`. `ark_read_init()` receives
a pre-validated footer and does not re-perform these checks.

Only after all five checks pass does `main.c` allocate `index_size`
bytes and seek to `index_offset` to read the index block, then pass
the index buffer to `ark_read_index()`. These checks are redundant with
§8.3 check 15, which re-verifies structural layout after parsing the
index, but they must occur earlier in `main.c` to prevent malformed
footer values from causing unbounded allocation or invalid seeks.

The reader loads the entire index block into memory in one read operation,
verifies its hash against `index_hash` in the footer, then parses it
in-memory. The index is never parsed partially or incrementally.

Before allocating the member entry array, the reader must verify that
`member_count` is plausible given `index_size`. The fixed metadata block
is 79 bytes and already includes `path_len` (u16) at offset 77. The
minimum syntactically valid index entry is therefore 84 bytes: 79 bytes
of fixed metadata block (includes path_len), 1 byte of path data, and
4 bytes of `chunk_count`. If `member_count > index_size / 84`, the reader
must reject with `ARK_ERR_FMT_INDEX` before any allocation. This bounds
allocation to a size proportional to the actual index data rather than
trusting the unhashed `member_count` field in the footer.

After parsing all `member_count` entries, the reader must verify that the
total number of bytes consumed equals `index_size`. A mismatch indicates
either a malformed `member_count` or trailing garbage in the index block
and is rejected as a format error (`ARK_ERR_FMT_INDEX`).

### 5.2 Entry Structure

The index is a sequence of `member_count` entries with no padding between
entries. Each entry consists of a fixed-width metadata block followed by
variable-length fields.

**Fixed metadata block - 79 bytes, always present:**

```
Offset  Size  Type    Name
------  ----  ----    ----
0       1     u8      type
1       4     u32     mode
5       4     u32     uid
9       4     u32     gid
13      8     u64     mtime
21      8     u64     size_original
29      8     u64     size_compressed
37      8     u64     data_offset
45      32    u8[32]  hash
77      2     u16     path_len
```

Fields are packed with no alignment padding. All multi-byte fields are
little-endian. Parsing uses explicit `memcpy` into typed local variables
followed by `le32toh` / `le64toh` conversion. No pointer casting.

**type field values:**

| Value | Meaning |
|---|---|
| 0x01 | Regular file |
| 0x02 | Directory |
| 0x03 | Symbolic link |
| 0x04 | Hardlink |

**Field values by member type:**

| Field | Regular file | Directory | Symlink | Hardlink |
|---|---|---|---|---|
| size_original | file size in bytes | 0 | 0 | 0 |
| size_compressed | total compressed size | 0 | 0 | 0 |
| data_offset | byte offset of member data | 0 | 0 | 0 |
| chunk_count | 0 when size_original == 0; >= 1 otherwise | 0 | 0 | 0 |

Writers must set size_original, size_compressed, data_offset, and
chunk_count to zero for directories, symlinks, and hardlinks. Readers
must reject non-zero values for these fields on those member types as a
format error (`ARK_ERR_FMT_INDEX`).

**Empty regular files.** A regular file with `size_original == 0` is valid.
The writer stores `chunk_count = 0`, `size_compressed = 0`, and
`data_offset = 0` (no data block is written). The reader must accept
`chunk_count == 0` for a regular file when `size_original == 0` and
create an empty file at the extraction path. A regular file with
`size_original == 0` and `chunk_count != 0` is a format error
(`ARK_ERR_FMT_INDEX`).

**Variable-length fields following the fixed block:**

```
[path_len bytes]     UTF-8 encoded relative path, not null-terminated
[u16 link_len]       present only for type=0x03 and type=0x04
[link_len bytes]     UTF-8 link target, present only for type=0x03 and type=0x04
[u32 chunk_count]    number of compressed chunks for this member
[chunk_count x u32]  compressed size of each chunk in bytes
```

**mode field:** stores the POSIX file permission and type bits as defined
in POSIX.1-2008 `<sys/stat.h>`. The stored value is the raw `st_mode`
field from `stat()`, masked to the low 16 bits. Writers store
`(uint32_t)(st.st_mode & 0xFFFF)`. On extraction, the reader applies
`chmod()` using only the permission bits (mask `0777`). The reader must
never apply setuid (`S_ISUID`, bit 04000), setgid (`S_ISGID`, bit 02000),
or sticky (`S_ISVTX`, bit 01000) bits from the archive; these bits are
silently stripped on extraction regardless of the extracting user's
privilege level. This prevents a malicious archive from creating setuid
binaries. The file type bits in `mode` are informational only and are
ignored by the reader on extraction. The canonical member type is
determined solely by the `type` field. A mismatch between the file type
bits in `mode` and the `type` field is not a format error; the reader
silently uses the `type` field and ignores the `mode` type bits.

**mtime field:** nanoseconds since the Unix epoch (1970-01-01 00:00:00 UTC),
stored as a u64. Writers populate this using signed 64-bit arithmetic:
`(int64_t)st_mtim.tv_sec * INT64_C(1000000000) + (int64_t)st_mtim.tv_nsec`,
then cast the result to `uint64_t`. This preserves pre-epoch timestamps
(negative tv_sec) correctly via two's complement representation. Readers
restore mtime via `utimensat`, converting back using signed arithmetic:
cast the stored u64 to `int64_t`, then divide by 1,000,000,000 to obtain
`tv_sec` and take the remainder for `tv_nsec`. In C11, division and modulo
of negative values truncate toward zero, so pre-epoch timestamps produce a
negative `tv_nsec` when the stored value is not an exact multiple of
1,000,000,000. POSIX requires `tv_nsec` to be in the range
[0, 999,999,999]. Readers must apply the following normalisation after
conversion: `if (tv_nsec < 0) { tv_sec--; tv_nsec += 1000000000; }`.
Nanosecond precision is consistent with ext4, xfs, and OpenBSD UFS2.

**Representable mtime range.** The signed 64-bit nanosecond intermediate
value must not overflow. The representable range of source timestamps is
therefore approximately 1677-09-21 to 2262-04-11 UTC (the range of signed
64-bit nanoseconds: -2^63 to 2^63-1). Before computing the formula, the
writer must check that the multiplication will not overflow:
- If `tv_sec > 9223372036` or `tv_sec < -9223372036`, the timestamp is
  outside the representable range
- Adding `tv_nsec` (max 999,999,999) after multiplication can also cause
  overflow at the extreme: check that
  `(int64_t)tv_sec * INT64_C(1000000000)` does not overflow before adding
  `tv_nsec`

If a source file's mtime is outside the representable range, the writer
must abort with `ARK_ERR_IO_READ` and a message identifying the path and
the out-of-range timestamp value. Silent clamping or wrapping is not
permitted. This is a rare condition in practice; the bounds cover all
timestamps from the 17th century to the 23rd century.

**Path field semantics:**
- Stores the full relative path as it will appear on extraction
  (e.g. `libchevron/src/main.c`, not an absolute path)
- UTF-8 encoding required; invalid UTF-8 is rejected by the writer and
  reader (`ARK_ERR_PATH_ENCODING`)
- Paths are stored as received from the OS without Unicode normalisation.
  NFC, NFD, and other normalisation forms are not applied. Cross-platform
  path identity for paths containing non-ASCII characters is not guaranteed.
- Path separator is `/` on all platforms

**Canonical path grammar.** Both writer and reader enforce the following
grammar on every member path. A path that violates any rule is rejected:
- Non-empty: a zero-length path is `ARK_ERR_FMT_INDEX` on read,
  `ARK_ERR_USAGE` on write
- No NUL bytes (0x00); presence is `ARK_ERR_FMT_INDEX` on read,
  `ARK_ERR_USAGE` on write. The reader must check the raw bytes before
  constructing any C string, as NUL inside a path truncates silently
  and bypasses duplicate detection
- No leading slash: paths must not begin with `/`
- No trailing slash: paths must not end with `/`
- No empty components: consecutive slashes (`a//b`) are forbidden
- No `.` components: a path component consisting solely of `.` is
  forbidden (`a/./b` is rejected)
- No `..` components: already required; restated here for completeness
- Maximum path length is 1023 bytes (OpenBSD PATH_MAX - 1), enforced by
  the writer regardless of creating platform
- Duplicate detection is performed on the canonical path exactly as stored
  after the above rules are enforced; no further normalisation is applied

All checks are applied before the path is stored as a C string in any
context. Violation on read produces `ARK_ERR_FMT_INDEX` except where a
more specific code is defined above.

- The reader must bounds-check path_len against remaining index bytes
  before reading path data; a path_len that would read past the end of
  the index block is a format error (`ARK_ERR_FMT_INDEX`)

**No separate filename field.** The filename is the final component of the
path, derivable by the reader as everything after the last `/`. Storing it
redundantly would waste space and create a consistency obligation.

**Link field semantics:**
- For type=0x03 (symlink): contains the symlink target exactly as
  `readlink()` returns it. `link_len` must be >= 1; an empty symlink
  target (`link_len == 0`) is `ARK_ERR_FMT_INDEX`. The writer must
  reject targets containing NUL bytes. The writer must reject targets
  that are absolute paths (beginning with `/`) or contain `..` components,
  as these can create symlinks pointing outside the extraction directory.
  The reader must apply the same validation checks on extraction.
- For type=0x04 (hardlink): contains the relative path of the target member
  already present in the archive. `link_len` must be >= 1; an empty
  hardlink target path (`link_len == 0`) is `ARK_ERR_FMT_INDEX`. The
  hardlink target path must satisfy the full canonical member-path grammar
  defined in §5.2 with the same per-violation error codes: non-empty,
  no NUL, no leading slash (`ARK_ERR_PATH_ABSOLUTE`), no trailing slash
  (`ARK_ERR_FMT_INDEX`), no empty components (`ARK_ERR_FMT_INDEX`), no
  `.` components (`ARK_ERR_FMT_INDEX`), no `..` components
  (`ARK_ERR_PATH_TRAVERSAL`), valid UTF-8 (`ARK_ERR_PATH_ENCODING`),
  maximum 1023 bytes (`ARK_ERR_FMT_INDEX`). The reader must verify the
  target member exists in the index before calling `link()`; a missing
  target is a format error (`ARK_ERR_FMT_INDEX`).
- For type=0x01 and type=0x02: link field is absent; chunk_count follows
  immediately after the path field
- The reader must bounds-check link_len against remaining index bytes
  before reading link data, identical to the path_len check

**Chunk table:**
- chunk_count is u32; maximum ~4 billion chunks per member (effectively
  unlimited for any realistic archive)
- Each chunk size entry is u32; maximum 4GB per chunk (far exceeds the
  1MB uncompressed input size)
- The last chunk of a member may be smaller than 1MB if
  `size_original mod 1MB != 0`; its compressed size is stored normally
- Chunk offsets within the archive are not stored explicitly; the reader
  derives them by accumulating compressed sizes from `data_offset`
- Directories have chunk_count=0 and no chunk size entries
- The reader must validate that chunk_count equals
  `ceil(size_original / 1048576)` for regular files with `size_original > 0`.
  A chunk_count that does not match this formula is a format error
  (`ARK_ERR_FMT_INDEX`). This check must occur before any chunk table
  entries are read to prevent out-of-bounds allocation.

**hash field for non-file member types.** The hash field is present in
every index entry regardless of member type. For directories, symlinks,
and hardlinks, which have no compressed data, the writer computes the
hash of the empty byte sequence (zero bytes of input fed to
`ark_blake3_final` or `ark_sha256_final` immediately after `init`) and
stores the result. The reader verifies the hash field against this same
empty-input digest for these member types. This keeps verification uniform
across all member types with no special cases in the reader.

---

## 6. Member Data Layout

**DECIDED. No open items.**

### 6.1 Archive Body Structure

Member data occupies the bytes between the fixed header and the index.
The archive body contains pure compressed bytes with no inline framing,
no per-chunk headers, and no padding between chunks or members. The index
is the sole source of structural metadata.

### 6.2 Chunking Model

Each member's content is split into fixed-size 1MB chunks before compression.
Each chunk is compressed independently as a complete Deflate stream. The last
chunk of a member contains the remaining bytes and may be smaller than 1MB.

**Chunk size: 1MB (1,048,576 bytes) uncompressed.**

Rationale: 1MB is a natural power-of-two boundary, fits comfortably in
L2/L3 cache on all target hardware, provides fine enough granularity for
parallel compression across many cores on large archives, and keeps per-chunk
overhead negligible relative to chunk size.

### 6.3 Parallelism Model

Independent chunk compression is the primary mechanism for multi-core
utilisation. The writer compresses chunks in parallel using a
producer-consumer model: one thread traverses the filesystem and feeds
raw chunks, a pool of worker threads compress independently using
`ark_deflate_compress` directly, output is collected and written
sequentially by the I/O thread. The reader decompresses chunks in
parallel using the same model.

**Compression threading model.** Worker threads call `ark_deflate_compress`
directly from `deflate.h`. Each worker operates on independent input and
output buffers with no shared state. Compressed results are placed into
a fixed-size ring buffer indexed by chunk sequence number. The I/O thread
drains the ring buffer in sequence order, calling `ark_write_chunk` with
the pre-compressed bytes for each chunk in order. `ark_write_chunk` is
called only from the I/O thread and only in chunk order; it is never
called from worker threads. This model keeps all shared context mutation
inside the single I/O thread and keeps parallelism entirely within
`main.c`.

**Decompression threading model (extract).** The extract path is symmetric
with the create path. Worker threads call `ark_deflate_decompress` directly
from `deflate.h`. Workers never call `ark_read_chunk`. `ark_read_ctx_t` is
not thread-safe and is never accessed from worker threads; it is used only
by the I/O thread for index and metadata access. Each worker receives a
compressed chunk buffer and an output buffer; it calls `ark_deflate_decompress`
and writes the result and the decompressed byte count to its ring buffer slot.
The I/O thread drains the ring buffer in sequence order and performs the
decompressed-length validation: for each non-final chunk, the decompressed
length must equal 1,048,576 bytes; for the final chunk it must equal
`size_original mod 1,048,576` (or 1,048,576 if `size_original` is an exact
multiple). A length mismatch or a failed `ark_deflate_decompress` call (return
-1) causes the I/O thread to set `ARK_ERR_FMT_DATA` in the shared error struct,
set the cancellation flag, join all workers, and proceed to cleanup. The I/O
thread owns all `ARK_ERR_FMT_DATA` generation for decompression; worker threads
signal failure only by writing an abort sentinel to their ring buffer slot.

**Output ordering.** Compressed chunks are always written to the archive
in input order regardless of completion order. Worker threads write
completed chunks into the ring buffer indexed by chunk sequence number.
The I/O thread drains the ring buffer in sequence order, blocking
when the next expected chunk is not yet complete. This bounds the
reordering buffer to a fixed number of in-flight chunks (one per worker
thread) and prevents unbounded memory growth regardless of archive size
or member count.

**Cancellation.** The thread pool must support a cancellation signal. On
any fatal error during a parallel operation (create or extract), the I/O
thread sets a shared cancellation flag visible to all workers before
joining them. Workers check this flag between chunks and exit their
compression or decompression loop cleanly when it is set. The I/O thread
joins all workers before proceeding to error handling or cleanup. No
worker thread may access shared context state after the cancellation flag
is set. This requirement applies to both create and extract subcommands.

**Worker-to-I/O error propagation.** A worker thread may itself encounter
a fatal error. On the create path this means `ark_deflate_compress`
returning -1. On the extract path this means `ark_deflate_decompress`
returning -1. In neither case does the worker generate an `ark_err_t`
error code: error classification (`ARK_ERR_IO_WRITE` for compression
failure, `ARK_ERR_FMT_DATA` for decompression failure) is the I/O
thread's responsibility. Workers signal failure only via the abort
sentinel mechanism. When a worker encounters a fatal error, it must not
simply exit, as the I/O thread will be parked waiting for that worker's
chunk slot in the ring buffer and will deadlock. The required sequence for
a worker that encounters a fatal error is:
1. Write a sentinel value indicating failure (not a valid result) to the
   shared atomic error flag so the I/O thread knows an error occurred.
2. Write an abort sentinel to the worker's ring buffer slot rather than
   a valid result.
3. Exit the worker loop.

The I/O thread must check each ring buffer slot for the abort sentinel
before consuming it. On detecting an abort sentinel, the I/O thread reads
the atomic error flag, classifies the error into the appropriate
`ark_err_t`, sets the cancellation flag for all remaining workers, joins
all workers, and then proceeds with the five-step cleanup sequence in
§14.3 using the classified error code. This ensures the I/O thread is
never permanently blocked waiting on a worker that has already exited
with an error.

Threading is implemented using pthreads on both Linux and OpenBSD. pthreads
is the POSIX threading interface and is available identically on both
platforms. No platform-specific threading code exists.

**Platform-specific sandbox and thread ordering.** The correct ordering
of sandbox application relative to thread pool creation differs by platform
and must not be unified:

- **Linux (Landlock):** `landlock_restrict_self()` restricts only the
  calling thread. New threads created after the call inherit the Landlock
  restriction through the credential mechanism; threads already existing
  when `landlock_restrict_self()` is called are not restricted. Therefore
  on Linux, Landlock must be applied in the main thread *before* the
  worker thread pool is created. Workers then inherit the Landlock
  ruleset at creation time and operate within the sandbox for their entire
  lifetime. The sequence is: argument parsing → open destination dirfd →
  apply Landlock → create thread pool → run operation.

- **OpenBSD (pledge):** `pledge()` restricts the entire process and
  does not permit `pthread_create` under the pledges used for create
  and extract. Therefore on OpenBSD, the thread pool must be created
  *before* `pledge()` is called. The sequence is: argument parsing →
  open destination dirfd → create thread pool → apply pledge+unveil →
  run operation.

These two sequences are incompatible and require a platform-conditional
initialisation path in `main.c`. The `#ifdef __linux__` / `#ifdef __OpenBSD__`
guards around this ordering are the one location where the platform
split is visible at the top level. All other platform-specific code
lives within its respective sandbox implementation.

The fixed chunk size is the parallelism granularity. On a 50GB archive
with 1MB chunks, up to 51,200 chunks are available for parallel processing,
far exceeding the core count of any current or near-future hardware.

### 6.4 Incompressible Content

Deflate handles incompressible content internally via stored blocks. When
a chunk compresses to a size equal to or larger than the uncompressed
input, the writer stores the chunk as a Deflate stored block. The overhead
is a few bytes of Deflate framing. No format-level indication of
incompressible content is needed; the chunk_count and per-chunk compressed
sizes in the index are sufficient for the reader to locate and decompress
each chunk correctly regardless of whether Deflate used compressed or
stored blocks internally.

---

## 7. Compression

**DECIDED. No open items.**

### 7.1 Algorithm

Deflate (RFC 1951). Integrated into the archive format; not a separate tool.
Compression is always on; there is no store-only mode. Deflate handles
incompressible content via stored blocks internally with negligible overhead.

### 7.2 Compressor Quality

The compressor implements all of the following quality levers in v1.
A naive compressor is not acceptable.

**Hash-chain match finding with lazy matching.** The minimum quality bar.
Hash chains with lazy matching achieve competitive ratio. Lazy matching
evaluates the next byte before committing to a match, improving ratio
by 3-5% over greedy matching.

**Raw-store fallback per chunk.** When the Deflate output for a chunk
equals or exceeds the uncompressed input size, the writer emits a Deflate
stored block instead. This is essential for already-compressed content
(JPEG, video, existing archives). The chunk size entry in the index
records the stored block size; the reader handles both cases transparently.

**Near-optimal parsing for archival mode.** Rather than committing to the
first match found, the parser evaluates multiple match candidates and
selects the optimal sequence. Adds approximately 300-500 lines but
provides meaningful ratio improvement on compressible content. Archival
mode is the default; a faster mode using greedy parsing may be provided
as a CLI option.

**Aggressive block boundary decisions.** Deflate divides compressed data
into blocks, each with its own Huffman table. Choosing block boundaries
to minimise total output size improves ratio. The compressor evaluates
block splits and selects boundaries that minimise the combined cost of
the Huffman table and compressed literals/references.

### 7.3 Implementation

Implemented in `deflate.c` / `deflate.h` as a standalone component with a
clean API: caller provides input bytes and receives output bytes. No I/O,
no allocation owned by the component. The caller owns all buffers.

Estimated implementation size: ~2,000-2,500 lines of C11 for compressor
and decompressor combined.

**Compression ratio reference (100MB input):**

| Content type | LZ4 | Deflate (good impl) | zstd default |
|---|---|---|---|
| Text only | ~50 MB | ~37 MB | ~33 MB |
| Mixed | ~62 MB | ~50 MB | ~45 MB |

### 7.4 Public API

Implemented in `deflate.c` / `deflate.h` as a standalone component. No I/O,
no allocation owned by the component. The caller owns all buffers. The
component is extractable for reuse in other projects without modification.

```c
typedef enum {
    ARK_DEFLATE_DEFAULT,   /* near-optimal parsing, archival quality (default) */
    ARK_DEFLATE_FAST       /* greedy parsing, faster compression (--fast flag) */
} ark_deflate_mode_t;

/* Returns the maximum compressed size for src_len bytes of uncompressed input.
   Caller uses this to allocate dst before calling ark_deflate_compress. */
size_t  ark_deflate_bound(size_t src_len);

/* Compress src into dst. Returns compressed size on success, -1 on error.
   dst must be at least ark_deflate_bound(src_len) bytes.
   When compressed output >= src_len, emits a Deflate stored block. */
ssize_t ark_deflate_compress(const uint8_t *src, size_t src_len,
                              uint8_t       *dst, size_t dst_cap,
                              ark_deflate_mode_t mode);

/* Decompress src into dst. Returns decompressed size on success, -1 on error.
   dst must be large enough to hold the decompressed output. */
ssize_t ark_deflate_decompress(const uint8_t *src, size_t src_len,
                                uint8_t       *dst, size_t dst_cap);
```

**Mode semantics.** `ARK_DEFLATE_DEFAULT` uses near-optimal parsing and
aggressive block boundary decisions. This is the default mode used by the
`ark` CLI. `ARK_DEFLATE_FAST` uses greedy parsing for users who explicitly
prioritise compression speed over ratio, enabled via the `--fast` CLI flag.

---

## 8. Integrity

**DECIDED. No open items.**

### 8.1 Algorithms Supported

| Identifier | Algorithm | Default |
|---|---|---|
| 0x01 | BLAKE3 | Yes |
| 0x02 | SHA-256 | No |

One algorithm applies to the entire archive. Selected at creation time via
CLI flag. BLAKE3 is used when no flag is specified.

### 8.2 What Is Hashed

**Per-member hash:** hash of the compressed bytes of the entire member,
fed chunk by chunk into a single running hash context in order, finalised
after the last chunk. Computed immediately after each chunk is compressed,
before the chunk is written to the archive. No pre-pass over source data
is required; hashing occurs as part of the compress-then-write pipeline.
Stored in the member's index entry. Allows verification of individual
members without reading any other member's data.

On extraction, the reader feeds each compressed chunk into the hash context
in chunk order before decompressing it. Each chunk is then decompressed and
written to the filesystem in the same pass. The finalised hash is compared
against the stored value after all chunks have been processed and written.
If the hash does not match, the member data is corrupt; the reader aborts,
cleans up all files extracted in this run, and exits with
`ARK_ERR_HASH_MEMBER`. Decompression and writing occur as part of the
streaming pass; the hash check is the final gate after the last chunk.

**Index hash:** hash of the entire serialised index block. Stored in the
footer. Verified before any index entry is parsed or any filesystem
operation is performed.

There is no whole-archive hash. Per-member hashes plus index hash provide
complete end-to-end verification. See §1.4 for rationale.

### 8.3 Verification Model

The reader verifies in this order before any filesystem side effect:
1. Footer magic_confirm
2. index_hash (verifies entire index block)
3. All member paths are validated against the canonical path grammar. Each
   violation has an explicit error code that exactly matches §11.4:
   - Empty path (path_len == 0): `ARK_ERR_FMT_INDEX`
   - Contains NUL byte (0x00): `ARK_ERR_FMT_INDEX`; must be checked on raw
     bytes before any C string construction
   - Has empty component (`a//b`): `ARK_ERR_FMT_INDEX`
   - Has `.` component: `ARK_ERR_FMT_INDEX`
   - Has trailing slash: `ARK_ERR_FMT_INDEX`
   - Begins with `/` (absolute path): `ARK_ERR_PATH_ABSOLUTE`
   - Contains `..` component: `ARK_ERR_PATH_TRAVERSAL`
   - Contains invalid UTF-8: `ARK_ERR_PATH_ENCODING`
4. All member paths against local PATH_MAX; exceeding PATH_MAX is
   `ARK_ERR_PATH_TOO_LONG`
5. All member paths: maximum length 1023 bytes; a path exceeding 1023 bytes
   is `ARK_ERR_PATH_TOO_LONG`
6. All symlink and hardlink link fields, with explicit per-violation codes
   matching §11.4:
   - Contains NUL byte: `ARK_ERR_FMT_INDEX`
   - Contains `..` component: `ARK_ERR_PATH_TRAVERSAL`
   - Is an absolute path (begins with `/`): `ARK_ERR_PATH_ABSOLUTE`
   - Contains invalid UTF-8: `ARK_ERR_PATH_ENCODING`
   - Exceeds 1023 bytes: `ARK_ERR_FMT_INDEX`
7. All hardlink targets exist in the index and appear before the hardlink
   entry (earlier index position); a missing or forward-referencing target
   is `ARK_ERR_FMT_INDEX`
8. No duplicate member paths; a repeated path is `ARK_ERR_FMT_INDEX`;
   comparison is performed on the canonical path bytes as stored
9. For full extraction: every member's parent path either is the extraction
   root or is itself a directory member appearing earlier in the index;
   a missing or non-directory ancestor is `ARK_ERR_FMT_INDEX`
10. For --member selective extraction: every selected member's ancestor paths
    that are present in the archive index must be directory members appearing
    earlier in the index; a present non-directory ancestor or a later-ordered
    directory ancestor is `ARK_ERR_FMT_INDEX`. Ancestors absent from the
    index will be created implicitly and are not an error (see §14.4).
11. For each regular member with `size_original > 0`: `size_compressed`
    equals the sum of its `chunk_sizes` entries; a mismatch is
    `ARK_ERR_FMT_INDEX`. Regular members with `size_original == 0` have
    `size_compressed == 0` and `chunk_count == 0`; no chunk size sum check
    is performed for empty files.
12. For each regular member with `size_original > 0`: `data_offset >= 16`
    and `data_offset + size_compressed <= index_offset`; either condition
    failing is `ARK_ERR_FMT_INDEX`. Empty regular files have `data_offset == 0`
    and are exempt from this check.
13. All regular member data ranges with `size_original > 0` are
    non-overlapping; ranges are sorted by `data_offset` and verified to not
    intersect; overlap is `ARK_ERR_FMT_INDEX`. Empty regular files have no
    body range and are excluded from overlap detection.
14. All hardlink target entries have type 0x01 (regular file); a hardlink
    targeting a directory (0x02), symlink (0x03), or another hardlink
    (0x04) is `ARK_ERR_FMT_INDEX`. POSIX `link()` behaviour on non-regular
    targets is unspecified or fails; rejecting such targets at validation
    time prevents mid-extraction failure with partial filesystem state.
15. Structural layout: `index_offset + index_size == file_size - 64`; any
    mismatch indicates hidden bytes between the index and footer and is
    `ARK_ERR_FMT_INDEX`. Additionally, the non-empty regular member data
    ranges, when sorted by `data_offset`, must form a contiguous sequence
    starting at byte 16 with no gaps between members and ending exactly at
    `index_offset` (i.e. the last range's `data_offset + size_compressed`
    must equal `index_offset`); any gap between members or between the final
    member and the index indicates hidden bytes and is `ARK_ERR_FMT_INDEX`.
    Archives containing only empty regular files, directories, symlinks, and
    hardlinks (no non-empty body) are valid with `index_offset == 16`.
16. For every zero-data member - directories (type 0x02), symlinks (type
    0x03), hardlinks (type 0x04), and empty regular files (type 0x01 with
    `size_original == 0`) - the stored hash field must equal the empty-input
    digest for the archive's hash algorithm (BLAKE3 or SHA-256 of zero bytes
    of input). A mismatch is `ARK_ERR_HASH_MEMBER`. This check applies to
    all zero-data members before any filesystem side effect, not only at
    per-member extraction time. The empty-input digest is a fixed constant
    for each algorithm and can be precomputed once at reader startup.

**Overflow-safe arithmetic.** All offset and length additions performed
during checks 12 and 15 use attacker-controlled u64 values from the
index and footer. Implementations must use checked arithmetic for every
such addition: before computing `data_offset + size_compressed` or
`index_offset + index_size`, verify that the addition will not overflow
u64. Any overflow is treated as `ARK_ERR_FMT_INDEX` before the result is
used in any comparison or seek. The same rule applies to accumulating chunk
sizes in check 11: the running sum must be checked for overflow after each
addition.

All sixteen checks complete before any filesystem operation is performed.
Checks 3 through 16 operate on the already hash-verified in-memory index.

Per-member hash verification occurs at extraction time for each member.
A per-member hash mismatch always indicates post-creation corruption or
tampering, never a creation-time bug. The hash stored in the index is
correct by construction at creation time - it is computed from the data
just written in the same pass.

### 8.4 Public API

Both components follow identical API shape: streaming context plus single-shot
convenience wrapper. No I/O, no allocation. Caller owns all buffers. Both
components are stack-allocatable (no opaque pointer, fully defined structs in
headers) and extractable for reuse in other projects without modification.

All implementations must be validated against official test vectors before
acceptance. NIST publishes SHA-256 test vectors. The BLAKE3 reference
repository provides an extensive test vector suite. Passing official test
vectors is a hard requirement, not optional.

**sha256.h:**

```c
typedef struct ark_sha256_ctx ark_sha256_ctx_t;

void ark_sha256_init  (ark_sha256_ctx_t *ctx);
void ark_sha256_update(ark_sha256_ctx_t *ctx,
                       const uint8_t *data, size_t len);
void ark_sha256_final (ark_sha256_ctx_t *ctx,
                       uint8_t digest[32]);

/* Single-shot convenience wrapper over init/update/final. */
void ark_sha256(const uint8_t *data, size_t len,
                uint8_t digest[32]);
```

**blake3.h:**

```c
typedef struct ark_blake3_ctx ark_blake3_ctx_t;

void ark_blake3_init  (ark_blake3_ctx_t *ctx);
void ark_blake3_update(ark_blake3_ctx_t *ctx,
                       const uint8_t *data, size_t len);
void ark_blake3_final (ark_blake3_ctx_t *ctx,
                       uint8_t digest[32]);

/* Single-shot convenience wrapper over init/update/final. */
void ark_blake3(const uint8_t *data, size_t len,
                uint8_t digest[32]);
```

**Output length.** Both APIs produce exactly 32 bytes of output, matching the
hash field size in the index entry. BLAKE3 natively supports variable-length
output; that capability is intentionally not exposed. ark has no use for output
lengths other than 32 bytes and exposing it adds caller complexity for no
benefit.

**BLAKE3 tree parallelism.** BLAKE3's internal tree hashing is not exposed in
the API. ark uses BLAKE3 in sequential mode only. Internal exploitation of
tree parallelism within `ark_blake3_update` is permitted as an implementation
detail but is not required.

---

## 9. Crash Safety

**DECIDED.**

The archive writer uses libchevron's streaming interface exclusively. The
sequence is:

```
chevron_open()                   open parent dir, create temp file
chevron_write_chunk() x N        stream all member data, index, footer
chevron_commit()                 fsync, close, renameat, dir fsync
```

The target `.ark` file either exists complete and verified or does not exist.
A partial write caused by process crash or power loss never leaves a corrupt
or partial file at the target path. libchevron's `CHEVRON_FULL` durability
level is used.

libchevron is vendored at a pinned commit inside the ark repository. It is
the author's own library under the same ISC license and technical standards.
The project description states "zero external dependencies"; libchevron is
not an external dependency.

---

## 10. Platform Behaviour

**DECIDED. No open items.**

### 10.1 Byte Order

Little-endian throughout. No exceptions. All multi-byte integer fields in
header, index entries, and footer are little-endian.

### 10.2 PATH_MAX Cross-Platform Behaviour

| Platform | PATH_MAX |
|---|---|
| Linux | 4096 bytes |
| OpenBSD | 1024 bytes |
| macOS | 1024 bytes |

ark enforces a maximum path length of 1023 bytes at archive creation time
regardless of the creating platform. This ensures archives are extractable
on OpenBSD and macOS without platform-specific failure.

A conforming ark archive can never contain a path longer than 1023 bytes.
The reader's PATH_MAX check on extraction is a defence against malformed or
maliciously crafted archives, not a real portability concern. A hash mismatch
on extraction always indicates post-creation corruption or tampering.

When extraction is attempted and a member path exceeds PATH_MAX on the local
platform, the reader reports all offending paths before touching the
filesystem. The error message includes a human-friendly explanation:

> "This archive contains paths exceeding the maximum path length on this
> system (1024 bytes). The archive was likely created on a system with a
> larger PATH_MAX limit (Linux allows 4096 bytes). Extraction cannot proceed."

### 10.3 uid/gid Behaviour on Cross-Platform Extraction

uid and gid values from the creating system are stored verbatim in the index.
On extraction:
- If running as non-root: extracted files are owned by the current process
  effective uid/gid; stored uid/gid is ignored
- If running as root: ark attempts to restore original uid/gid via chown;
  EPERM is non-fatal and is reported as a warning, not an error

This matches the behaviour of tar and is a documented limitation.

### 10.4 Sandboxing

**DECIDED. No open items.**

**Minimum kernel requirement (Linux):** Linux 5.13. Landlock filesystem access
control is available from 5.13 (released July 2021). If Landlock is unavailable
at runtime, ark fails immediately with a clear error identifying the minimum
supported kernel version. There is no silent degradation, no fallback path, and
no ifdef-guarded alternative behaviour. This is stated explicitly in the man
page and README.

**OpenBSD:** pledge (available since OpenBSD 5.9) and unveil (available since
OpenBSD 6.4) are universally present on any OpenBSD installation in active use.
No version check is needed.

Sandboxing policy is applied per subcommand with platform-specific ordering
relative to thread pool creation (see §6.3 for the full rationale):
- **Linux:** Landlock is applied in the main thread before worker threads
  are created. Workers inherit the Landlock restriction at creation time.
  Pre-sandbox setup (argument parsing, opening the destination dirfd)
  occurs before Landlock application.
- **OpenBSD:** The thread pool is created before `pledge()` is called,
  because `pledge()` does not permit `pthread_create` under the pledges
  required for create and extract. Pre-sandbox setup and thread pool
  creation both occur before pledge+unveil application.

**Pre-sandbox setup for extract.** Before applying the sandbox, the extract
subcommand must open the destination directory with `open(O_DIRECTORY|O_CLOEXEC)`
and hold the resulting fd throughout extraction. This serves two purposes:
(1) it verifies the destination exists and is a directory, failing with
`ARK_ERR_IO_OPEN` before any sandbox is applied if it does not; (2) it
provides the dirfd for all `*at()` extraction syscalls (see §14.2). The
Landlock policy is applied immediately after opening the destination dirfd.

**pre-sandbox setup for generate-reader.** Before applying the sandbox,
the generate-reader subcommand must verify the output path's parent
directory exists and is accessible. libchevron requires write+create
access to the parent directory (to create a temp file and rename). The
unveil and Landlock policies for generate-reader cover the parent directory
of the output path, not the output path itself.

The complete syscall footprint of libchevron is documented in
libchevron/ARCHITECTURE.md §8.5 and is included in the create subcommand
policy. The footprint is narrow and fixed.

**Policies per subcommand:**

| Subcommand | OpenBSD pledge | OpenBSD unveil | Linux Landlock |
|---|---|---|---|
| `create` | `stdio rpath wpath cpath fattr pthread` | src: `r`, dst parent: `rwc` | read src, read+write+create+truncate dst parent |
| `extract` | `stdio rpath wpath cpath fattr pthread` | archive: `r`, dst dir: `rwc` | read archive, read+write+create+truncate+refer+remove-file+remove-dir dst dir |
| `list` | `stdio rpath` | archive: `r` | read archive only |
| `verify` | `stdio rpath` | archive: `r` | read archive only |
| `generate-reader` | `stdio wpath cpath` | output parent dir: `rwc` | write+create+truncate output parent dir |

**Notes:**
- `wpath` covers `unlink` and `rmdir` on OpenBSD; `--overwrite` and
  cleanup on extract require no additional pledge promises
- `pthread` is required on OpenBSD for `pthread_create`; it must appear in
  the pledge strings for `create` and `extract`. On OpenBSD the thread pool
  is created before `pledge()` is called (see §6.3); `pthread_create` is
  therefore called before pledge is in effect and does not require the
  `pthread` promise for the creation call itself. However `pthread_create`
  may be called again if the pool is reused or expanded, so the `pthread`
  promise must be present in the pledge string as a defence-in-depth
  requirement.
- The extract subcommand opens the destination directory as a dirfd before
  sandboxing. All extraction syscalls use `*at()` variants relative to this
  dirfd: `openat`, `mkdirat`, `symlinkat`, `linkat`, `unlinkat`, `fstatat`,
  `utimensat`. No full path concatenation is performed during extraction.
  This eliminates the risk of PATH_MAX violations from destination prefix
  plus member path and improves TOCTOU resistance.
- The `--output` argument for extract must name an existing directory.
  If the path does not exist or is not a directory, ark fails with
  `ARK_ERR_IO_OPEN` before applying the sandbox. No directory is created
  silently.
- Linux Landlock policies for `create` and `extract` must include
  `LANDLOCK_ACCESS_FS_TRUNCATE` (available from Landlock ABI v3, Linux 6.2)
  in addition to write and create rights. The `--overwrite` unlink-before-
  create path does not use `open(O_TRUNC)` or `ftruncate()`; however
  truncate rights remain required for any `ftruncate()` calls in the
  libchevron write path. ark detects the available Landlock ABI version at
  runtime and applies truncate rights when available; on kernels between
  5.13 and 6.1 the write right is sufficient for the operations performed.
- `LANDLOCK_ACCESS_FS_REMOVE_FILE` and `LANDLOCK_ACCESS_FS_REMOVE_DIR`
  are required for the `extract` subcommand on Linux. `REMOVE_FILE` is
  required for the `unlink()` calls in the `--overwrite` path and in
  best-effort cleanup on fatal error. `REMOVE_DIR` is required for the
  `rmdir()` calls in best-effort cleanup on fatal error. Both rights are
  available from Landlock ABI v1 (Linux 5.13) and require no ABI version
  check on any supported kernel.
- `LANDLOCK_ACCESS_FS_REFER` is required for the `extract` subcommand on
  Linux when the archive contains hardlink members. `REFER` is available
  from Landlock ABI v2 (Linux 5.19), not ABI v1. On Linux 5.13-5.18
  (ABI v1), `REFER` is not available; including it in the handled access
  mask on those kernels is a runtime error. ark detects the available
  Landlock ABI version via `landlock_create_ruleset` at runtime:
  - ABI v2+ (Linux 5.19+): include `REFER` in the extract ruleset;
    hardlink extraction proceeds normally.
  - ABI v1 (Linux 5.13-5.18): `REFER` is absent. If the archive being
    extracted contains any hardlink members (type 0x04), ark rejects
    extraction before any filesystem side effects with `ARK_ERR_USAGE`
    and a message identifying the minimum kernel version required for
    hardlink extraction (Linux 5.19). Archives containing no hardlinks
    extract normally under ABI v1 without `REFER`.
  This is consistent with the no-silent-degradation policy: ark never
  silently produces incomplete extraction. The restriction is documented
  in the man page.
- `generate-reader` uses libchevron which requires read+write+create+truncate
  access to the parent directory of the output path (to open the parent dir,
  create a temp file, write it, rename to output, and fsync the parent dir).
  The Landlock policy and unveil path cover the parent directory. If the
  output path already exists, it is atomically replaced via libchevron's
  rename mechanism. This is the documented behavior: generate-reader
  always overwrites an existing file at the output path.
- The Linux seccomp-bpf filter per subcommand must be a concrete syscall
  whitelist. It cannot be fully specified before the implementation exists
  because the exact syscall set depends on the implementation's code paths
  and all library call chains (libchevron, pthreads, libc). The whitelist
  must be produced as a required pre-launch artifact by running each
  subcommand under `strace` with realistic inputs to enumerate the minimal
  required syscall set. This whitelist must be completed and reviewed before
  the first release; it is a blocking pre-launch security requirement, not
  an optional enhancement. The pledge strings above are the reference
  footprint from which the Linux syscall set is derived, but the derivation
  is not 1:1 and must be explicitly audited. The syscall whitelist is tracked
  as a separate implementation artifact but is part of the security
  architecture of this document.
- For `list` and `verify`, `rpath` is the minimum OpenBSD pledge needed to
  open and read the archive file. The `unveil` restriction to the archive
  path alone provides the effective confinement; `rpath` without `unveil`
  would be over-broad.

---

## 11. Error Model

**DECIDED. No open items.**

Every failure produces a specific, actionable error identifying the operation
that failed. Errors with non-obvious causes include a human-friendly
explanation alongside the technical error code and errno value. Error detail
is always written to stderr. stdout is reserved for requested output (member
listings, etc.).

ANSI colour codes are emitted to stderr when `isatty(STDERR_FILENO)` is true.
Warnings are yellow. Errors are red. Plain text is emitted when stderr is
redirected or piped.

### 11.1 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage error (bad flags, missing arguments, unknown subcommand) |
| 2 | I/O error (read, write, filesystem operation failed) |
| 3 | Format error (bad magic, unknown version, malformed index) |
| 4 | Integrity error (hash mismatch - member or index) |
| 5 | Security error (path traversal, path exceeds PATH_MAX) |
| 6 | Consistency error (source modified during archiving) |

Exit code 6 is the only retriable failure class. A shell script can branch
on it specifically to retry once the source filesystem is quiescent.

### 11.2 Error Struct

```c
typedef struct {
    ark_err_t  code;        /* enum: maps to exit codes above */
    int        sys_errno;   /* errno at point of failure, 0 if not applicable */
    char       msg[256];    /* human-readable detail, no path content */
    char       path[1024];  /* offending path, empty string if not applicable */
} ark_error_t;
```

`msg` carries the explanation formatted at the point of detection using
context available there. `path` carries the offending member path,
null-terminated, empty if the error does not implicate a specific path.
Upper layers propagate the struct unchanged. The CLI formats msg and path
together at output time.

**Return convention.** Functions that return only success or failure return
`int` (0 success, -1 failure) with a caller-provided `ark_error_t *err`
out-parameter. Functions in the format layer (`archive.h`) that must convey
a byte count on success return `ssize_t` (byte count on success, -1 on
failure) with the same `ark_error_t *err` out-parameter. `err` may be NULL
in both cases; if NULL, error detail is discarded. This is consistent across
all components.

### 11.3 Error Code Enum

```c
typedef enum {
    ARK_OK              = 0,

    /* exit 1 - usage */
    ARK_ERR_USAGE,

    /* exit 2 - I/O */
    ARK_ERR_IO_READ,
    ARK_ERR_IO_WRITE,
    ARK_ERR_IO_SEEK,
    ARK_ERR_IO_OPEN,
    ARK_ERR_IO_FSYNC,
    ARK_ERR_IO_COMMIT,
    ARK_ERR_IO_MKDIR,
    ARK_ERR_IO_SYMLINK,
    ARK_ERR_IO_LINK,
    ARK_ERR_IO_CHMOD,
    ARK_ERR_IO_CHOWN,
    ARK_ERR_IO_UTIMES,  /* utimensat failure restoring mtime */
    ARK_ERR_IO_ALLOC,   /* memory allocation failure (malloc/realloc returned NULL) */

    /* exit 3 - format */
    ARK_ERR_FMT_MAGIC,
    ARK_ERR_FMT_VERSION,
    ARK_ERR_FMT_COMP_ALG,
    ARK_ERR_FMT_HASH_ALG,
    ARK_ERR_FMT_RESERVED,
    ARK_ERR_FMT_INDEX,
    ARK_ERR_FMT_MEMBER_TYPE,
    ARK_ERR_FMT_TRUNCATED,
    ARK_ERR_FMT_DATA,   /* invalid Deflate stream or decompressed length mismatch */

    /* exit 4 - integrity */
    ARK_ERR_HASH_INDEX,
    ARK_ERR_HASH_MEMBER,

    /* exit 5 - security */
    ARK_ERR_PATH_TRAVERSAL,
    ARK_ERR_PATH_TOO_LONG,
    ARK_ERR_PATH_ABSOLUTE,
    ARK_ERR_PATH_ENCODING,

    /* exit 6 - consistency */
    ARK_ERR_MODIFIED,
} ark_err_t;
```

**libchevron error mapping.** libchevron errors map to ark errors as follows:

| chevron_err_t | ark_err_t |
|---|---|
| CHEVRON_ERR_OPEN | ARK_ERR_IO_OPEN |
| CHEVRON_ERR_WRITE | ARK_ERR_IO_WRITE |
| CHEVRON_ERR_FSYNC | ARK_ERR_IO_FSYNC |
| CHEVRON_ERR_CLOSE | ARK_ERR_IO_WRITE (delayed writeback) |
| CHEVRON_ERR_RENAME | ARK_ERR_IO_COMMIT |
| CHEVRON_ERR_PERMISSION | ARK_ERR_IO_OPEN |
| CHEVRON_ERR_INVALID | ARK_ERR_USAGE |

### 11.4 Error Conditions Per Operation

**create:**

| Condition | ark_err_t |
|---|---|
| Bad flags, missing arguments, unknown subcommand | ARK_ERR_USAGE |
| Destination archive path is inside the source tree | ARK_ERR_USAGE |
| Source path does not exist or is not accessible | ARK_ERR_IO_OPEN |
| Source path component read permission denied | ARK_ERR_IO_READ |
| Target path parent directory not writable | ARK_ERR_IO_OPEN |
| Target path exists and is a directory | ARK_ERR_IO_OPEN |
| Member path exceeds 1023 bytes | ARK_ERR_PATH_TOO_LONG |
| Member path contains invalid UTF-8 | ARK_ERR_PATH_ENCODING |
| Member path begins with `/` or contains `..` | ARK_ERR_PATH_TRAVERSAL |
| Memory allocation failure | ARK_ERR_IO_ALLOC |
| chevron_open failure | ARK_ERR_IO_OPEN |
| chevron_write_chunk failure | ARK_ERR_IO_WRITE |
| chevron_commit failure pre-rename (fsync) | ARK_ERR_IO_FSYNC |
| chevron_commit failure pre-rename (close) | ARK_ERR_IO_WRITE |
| chevron_commit failure at rename | ARK_ERR_IO_COMMIT |
| chevron_commit failure post-rename (dir fsync) | ARK_ERR_IO_FSYNC |
| Source file modified during read | ARK_ERR_MODIFIED |
| Source file mtime outside representable range (see §5.2) | ARK_ERR_IO_READ |

**extract:**

| Condition | ark_err_t |
|---|---|
| Bad flags, missing arguments | ARK_ERR_USAGE |
| --output path does not exist or is not a directory | ARK_ERR_IO_OPEN |
| Archive contains hardlinks and Landlock ABI v1 (Linux < 5.19) | ARK_ERR_USAGE |
| Archive file does not exist or is not readable | ARK_ERR_IO_OPEN |
| Footer magic invalid or missing | ARK_ERR_FMT_MAGIC |
| Footer magic_confirm invalid | ARK_ERR_FMT_MAGIC |
| ver_major unsupported | ARK_ERR_FMT_VERSION |
| Unknown comp_alg value | ARK_ERR_FMT_COMP_ALG |
| Unknown hash_alg value | ARK_ERR_FMT_HASH_ALG |
| Reserved header or footer fields non-zero | ARK_ERR_FMT_RESERVED |
| Archive file truncated | ARK_ERR_FMT_TRUNCATED |
| Index hash mismatch | ARK_ERR_HASH_INDEX |
| Malformed index entry (unknown member type) | ARK_ERR_FMT_MEMBER_TYPE |
| Malformed index entry (cannot parse) | ARK_ERR_FMT_INDEX |
| Member path is empty | ARK_ERR_FMT_INDEX |
| Member path contains NUL byte | ARK_ERR_FMT_INDEX |
| Member path has empty component (`a//b`) or `.` component | ARK_ERR_FMT_INDEX |
| Member path has trailing slash | ARK_ERR_FMT_INDEX |
| Member path begins with `/` (absolute path) | ARK_ERR_PATH_ABSOLUTE |
| Member path contains `..` component | ARK_ERR_PATH_TRAVERSAL |
| Member path contains invalid UTF-8 | ARK_ERR_PATH_ENCODING |
| Member path exceeds 1023 bytes | ARK_ERR_PATH_TOO_LONG |
| Member path exceeds local PATH_MAX | ARK_ERR_PATH_TOO_LONG |
| Link field contains NUL byte | ARK_ERR_FMT_INDEX |
| Link field contains `..` component | ARK_ERR_PATH_TRAVERSAL |
| Link field is an absolute path (begins with `/`) | ARK_ERR_PATH_ABSOLUTE |
| Link field contains invalid UTF-8 | ARK_ERR_PATH_ENCODING |
| Link field exceeds 1023 bytes | ARK_ERR_FMT_INDEX |
| Parent directory missing in index order (malformed archive) | ARK_ERR_FMT_INDEX |
| chunk_index out of range for member | ARK_ERR_FMT_INDEX |
| Memory allocation failure | ARK_ERR_IO_ALLOC |
| Cannot create target directory | ARK_ERR_IO_MKDIR |
| Cannot open output file for writing | ARK_ERR_IO_OPEN |
| Write failure during extraction (including ENOSPC, EDQUOT) | ARK_ERR_IO_WRITE |
| Read failure reading member data | ARK_ERR_IO_READ |
| Seek failure | ARK_ERR_IO_SEEK |
| Member hash mismatch | ARK_ERR_HASH_MEMBER |
| Cannot create symlink | ARK_ERR_IO_SYMLINK |
| Cannot create hardlink | ARK_ERR_IO_LINK |
| chmod failure | ARK_ERR_IO_CHMOD |
| lchown failure (root only, EPERM): warning only, non-fatal | warning to stderr |
| lchown failure (root only, other errno): fatal | ARK_ERR_IO_CHOWN |
| lchown failure (non-root): always silent | (no error) |
| utimensat failure on regular file | ARK_ERR_IO_UTIMES |
| utimensat failure on directory (deferred pass): warning only, non-fatal | warning to stderr |
| utimensat failure on symlink (AT_SYMLINK_NOFOLLOW): warning only, non-fatal | warning to stderr |
| chmod failure on directory (deferred pass): warning only, non-fatal | warning to stderr |
| lchown failure on directory (deferred pass, EPERM): warning only, non-fatal | warning to stderr |
| lchown failure on directory (deferred pass, other errno): warning only, non-fatal | warning to stderr |
| Invalid Deflate stream in member data | ARK_ERR_FMT_DATA |
| Decompressed chunk length does not match expected size | ARK_ERR_FMT_DATA |

**list:**

| Condition | ark_err_t |
|---|---|
| Bad flags, missing arguments | ARK_ERR_USAGE |
| Archive file does not exist or is not readable | ARK_ERR_IO_OPEN |
| Footer magic invalid or missing | ARK_ERR_FMT_MAGIC |
| Footer magic_confirm invalid | ARK_ERR_FMT_MAGIC |
| ver_major unsupported | ARK_ERR_FMT_VERSION |
| Unknown comp_alg value | ARK_ERR_FMT_COMP_ALG |
| Unknown hash_alg value | ARK_ERR_FMT_HASH_ALG |
| Reserved header or footer fields non-zero | ARK_ERR_FMT_RESERVED |
| Archive file truncated | ARK_ERR_FMT_TRUNCATED |
| Index hash mismatch | ARK_ERR_HASH_INDEX |
| Malformed index entry (unknown member type) | ARK_ERR_FMT_MEMBER_TYPE |
| Malformed index entry (cannot parse) | ARK_ERR_FMT_INDEX |
| Memory allocation failure | ARK_ERR_IO_ALLOC |
| Read failure | ARK_ERR_IO_READ |
| Seek failure | ARK_ERR_IO_SEEK |

**verify:**

| Condition | ark_err_t |
|---|---|
| Bad flags, missing arguments | ARK_ERR_USAGE |
| Archive file does not exist or is not readable | ARK_ERR_IO_OPEN |
| Footer magic invalid or missing | ARK_ERR_FMT_MAGIC |
| Footer magic_confirm invalid | ARK_ERR_FMT_MAGIC |
| ver_major unsupported | ARK_ERR_FMT_VERSION |
| Unknown comp_alg value | ARK_ERR_FMT_COMP_ALG |
| Unknown hash_alg value | ARK_ERR_FMT_HASH_ALG |
| Reserved header or footer fields non-zero | ARK_ERR_FMT_RESERVED |
| Archive file truncated | ARK_ERR_FMT_TRUNCATED |
| Index hash mismatch | ARK_ERR_HASH_INDEX |
| Malformed index entry (unknown member type) | ARK_ERR_FMT_MEMBER_TYPE |
| Malformed index entry (cannot parse) | ARK_ERR_FMT_INDEX |
| Memory allocation failure | ARK_ERR_IO_ALLOC |
| Read failure | ARK_ERR_IO_READ |
| Seek failure | ARK_ERR_IO_SEEK |
| Member hash mismatch | ARK_ERR_HASH_MEMBER |
| Invalid Deflate stream in member data | ARK_ERR_FMT_DATA |
| Decompressed chunk length does not match expected size | ARK_ERR_FMT_DATA |

**generate-reader:**

| Condition | ark_err_t |
|---|---|
| Bad flags, missing arguments | ARK_ERR_USAGE |
| Output path not writable | ARK_ERR_IO_OPEN |
| Write failure | ARK_ERR_IO_WRITE |

---

## 12. CLI Interface

**DECIDED. No open items.**

### 12.1 Subcommand Model

Model B: subcommands only, each with its own flag surface. Full subcommand
names only; no abbreviations, no single-letter aliases. This matches modern
CLI convention (git, cargo, go) and keeps the flag surface per subcommand
clean and unambiguous.

ark is not tar. The tar flag model is a historical artifact of single-purpose
tape tools and is not adopted here.

### 12.2 Subcommand Surface

```
ark create          [--hash blake3|sha256] [--fast] [--verbose] archive.ark path
ark extract         [--output dir] [--member path] [--overwrite] [--verbose] archive.ark
ark list            [--verbose] [--human] archive.ark
ark verify          [--member path] [--verbose] archive.ark
ark generate-reader [output.c]
```

**create flags:**
- `--hash blake3|sha256` - select hash algorithm; default BLAKE3
- `--fast` - greedy Deflate parsing; faster compression, lower ratio
- `--verbose` - print each member path as it is added
- `path` - source file or directory; single file or full directory tree

**extract flags:**
- `--output dir` - extract into dir; default is current working directory
- `--member path` - extract only the named member; may be specified multiple
  times to extract a specific set of members; if a named member is a hardlink
  and its target member is not also named, the target member is automatically
  included to satisfy the `link()` call; if a named member is a hardlink and
  its target is missing from the archive index, extraction aborts with
  `ARK_ERR_FMT_INDEX`
- `--overwrite` - overwrite existing files at extraction target; default is
  to check all conflicts before touching the filesystem and abort if any exist
- `--verbose` - print each member path as it is extracted

**list flags:**
- `--verbose` - print full metadata per member (mode, uid, gid, mtime,
  compressed size, original size) in addition to the path
- `--human` - print sizes in human-readable form (KB, MB, GB); only
  meaningful alongside `--verbose`; without `--verbose` produces a warning
  to stderr

**verify flags:**
- `--member path` - verify only the named member; may be specified multiple
  times; uses the random-access capability of the index to seek directly to
  the named member without reading the rest of the archive. If a named
  member is a hardlink, the hardlink entry itself stores the empty-input
  hash and has no compressed data; verifying only the hardlink entry would
  succeed even when the target regular-file member's compressed data is
  corrupt. Therefore `verify --member` on a hardlink automatically includes
  the hardlink's target regular-file member in the verification set, using
  the same target-inclusion rule as `extract --member`. The target is
  verified for data integrity; it is not extracted.
- `--verbose` - print each member path as it is verified, with pass/fail

**generate-reader:**
- `output.c` - path to write the recovery reader source; defaults to
  `recovery.c` in the current working directory if not specified
- Produces a single self-contained C11 source file containing: Deflate
  decompressor, both BLAKE3 and SHA-256 implementations, archive read path,
  minimal extraction main(), and a large comment block covering format
  description, field layout, compilation instructions, and recovery procedure
- No flags beyond the optional output path argument

### 12.3 Default Behaviour

No arguments or unknown subcommand: print a one-line error identifying the
problem to stderr, followed by `"See man ark for usage."`, exit code 1.
No inline usage summary. The man page is the canonical reference.

Man pages follow OpenBSD style.

### 12.4 list as Discovery Tool

`ark list` is the primary mechanism for inspecting archive contents before
extraction. The intended workflow for selective extraction from a large archive:

```
ark list archive.ark                        # discover member paths
ark extract --member path archive.ark       # extract specific members
```

list reads and verifies only the index; no member data is decompressed.
This makes it fast regardless of archive size.

---

## 13. Writer Behaviour

**DECIDED. No open items.**

### 13.1 Filesystem Traversal

Depth-first, pre-order. Each directory is recorded in the archive before
its children. This guarantees that on extraction a parent directory always
precedes its children in the archive, allowing the reader to create
directories sequentially without lookahead or reordering.

**Deterministic ordering.** At each directory level, all entries are
collected from `readdir()` and sorted before any entry is processed or
recursed into. The entries `.` and `..` are discarded immediately when
encountered during `readdir()` collection and are never sorted, archived,
or recursed into. Sort order is `memcmp` byte-order comparison on the raw
UTF-8 filename bytes, ascending. No locale-aware collation is used.
This guarantees that two invocations of `ark create` on identical content
produce bit-identical archives with identical hashes at every level:
per-member, index, and footer. This property enables archive-level
regression testing and backup deduplication.

**Determinism scope.** The bit-identical guarantee applies to the same
ark binary running on the same platform. It does not require two
independent implementations of this specification to produce identical
Deflate streams: the compressor quality levers in §7.2 specify qualitative
targets (near-optimal parsing, aggressive block boundary decisions), not
an exact algorithm. Two compliant compressors may produce different but
equally valid Deflate output for the same input. The guarantee is scoped
to a single binary and is sufficient for regression testing and
deduplication across repeated runs of that binary.

### 13.2 Hardlink Detection

A hash table keyed on `(dev_t, ino_t)` pairs is maintained across the
entire traversal. When a file is encountered whose `(dev, ino)` is already
in the table, it is recorded as type `0x04` (hardlink) with the link target
field pointing to the path of the first member seen with that inode.

The first file encountered with a given inode is stored as a regular file
with its full compressed data. Subsequent encounters are stored as hardlinks.
Pre-order depth-first traversal makes the first-seen ordering deterministic.

**Hash table implementation** (`inode.c` / `inode.h`):
- Open-addressing with linear probing
- Key: `(dev_t, ino_t)` pair
- Hash: `(uint64_t)dev * 2654435761ULL ^ (uint64_t)ino` (Knuth multiplicative
  hash on dev XORed with ino)
- Value: path of first-seen member with this inode (`char path[1024]`)
- Initial capacity: 4096 slots
- Load factor threshold: 0.75; resize by doubling on breach
- Empty slot sentinel: `ino == 0` (inode 0 is never allocated by any POSIX
  filesystem)
- Single heap allocation for the backing array; realloc on resize
- Lookup and insert: O(1) average

Purpose-built single-caller implementation. No generic hash table abstraction.

### 13.3 Symlink Handling

Symlinks are always stored as type `0x03` with the link target from
`readlink()` stored in the link field. Symlinks are never followed during
traversal.

**Rationale.** Following symlinks opens two unacceptable problems: symlink
cycles cause infinite traversal, and following symlinks can silently pull in
files outside the source tree. Both contradict ark's correctness and security
goals.

### 13.4 Files Modified During Archiving

After reading each file, the writer `fstat`s the fd and compares `mtime`
and `st_size` against values recorded before reading began.

If a modification is detected:
1. A warning is emitted immediately to stderr identifying the offending path
   (yellow ANSI colour when stderr is a terminal)
2. Traversal continues
3. After traversal completes, if any modifications were detected: abort
   without committing the archive via libchevron, exit with code 6
   (`ARK_ERR_MODIFIED`), print a summary of all affected paths

**Source modification detection is best-effort.** The detection compares
`mtime` and `st_size` before and after reading each file. This has known
failure modes where a torn member may be committed undetected:
- A file modified within one timestamp tick (FAT: 2-second granularity;
  some CIFS/network mounts: 1-second granularity; ext4/xfs: nanosecond
  but clock resolution may still leave a window)
- A process that restores the original `mtime` after modifying content
- A modification that leaves `st_size` unchanged (in-place overwrite)

The detection window is also narrow: only modifications that occur while a
specific file is being read are caught. Modifications to already-processed
files after ark has moved on are not detectable. Directory contents (children
added or removed between `opendir()` and recursive descent completion) are
similarly undetectable. The guarantee is therefore: ark commits no archive
that it detects as modified; undetected concurrent modifications may result
in a committed archive whose members contain bytes from an unstable source.
For live filesystems where strict consistency is required, a filesystem
snapshot (LVM/btrfs on Linux, softdep snapshot on OpenBSD) should be taken
before archiving. This limitation is documented in the man page and in §17.

### 13.5 Destination Inside Source Tree

Before traversal begins, the writer must verify that the destination
archive path is not located inside the source tree being archived. If the
destination is inside the source, traversal would encounter the archive
file or libchevron's temporary file mid-write, causing the archive to
archive itself, trigger source-modification detection on its own output,
or produce nondeterministic results depending on traversal order.

The check is performed using resolved absolute paths:
1. Resolve the destination archive path to its parent directory using
   `realpath(3)` (the destination file may not yet exist; resolve the
   parent directory).
2. Resolve the source root path using `realpath(3)`.
3. If the resolved destination parent directory is equal to or is a
   subdirectory of the resolved source root, reject with `ARK_ERR_USAGE`
   and a descriptive message before any I/O begins.

This check applies to every source argument when multiple source paths
are provided. The check must occur before libchevron is initialised
(before the temp file is created), so no cleanup is needed on rejection.

**Example rejections:**
- `ark create out.ark .` - destination parent `.` equals source `.`
- `ark create project/archive.ark project` - destination parent
  `project/` is inside source `project/`
- `ark create /tmp/a.ark /tmp` - destination parent `/tmp/` equals
  source `/tmp/`

**Non-rejection:**
- `ark create ../archive.ark .` - destination parent `..` is outside
  source `.`; accepted

### 13.6 Path Stripping

The source path argument is resolved to an absolute path using `realpath(3)`
before any stripping occurs. This handles relative paths (`.`, `..`,
`../project`), symlinks in the source path, and trailing slashes uniformly.
The resolved absolute path is then used as the prefix to strip from all
member paths. The result is always a clean relative path from the source root
with no leading slash.

**Source root directory is not archived as a member.** When the source
argument resolves to a directory, the directory itself is not added to the
archive as a member. Only its descendants are archived. Stripping the source
prefix from the root's own path would produce an empty string, which violates
the canonical path grammar (§5.2 forbids empty member paths). The omission
of the root directory is intentional and consistent: extracting an archive
into an existing directory tree populates that directory with the archived
contents without creating an extra nesting level. When the source argument
resolves to a regular file, the file is archived as a single-member archive
with its basename as the path.

The use of `realpath(3)` on the source argument is intentional and does not
conflict with the symlink-never-followed rule in §13.3. That rule applies
to symlinks encountered as members during traversal of the source tree. The
source argument itself is resolved once before traversal begins; if it
resolves through a symlink, the user deliberately nominated that path and
traversal proceeds from the resolved target. Symlinks discovered inside the
tree during traversal are always stored as type 0x03 and never followed.

Examples:
- Source `/home/user/project/`, member `/home/user/project/src/main.c`
  stored as `src/main.c`; the directory `/home/user/project/` itself is
  not archived
- Source `/home/user/project` (no trailing slash): identical result
- Source `./project` resolved to `/home/user/project`: identical result
- Source `/home/user/project/main.c` (single file): stored as `main.c`

### 13.7 Cross-Device Traversal

ark does not cross mount point boundaries. When a mount point is encountered
during traversal, ark stops at that boundary and emits a warning to stderr
identifying the skipped mount point (yellow ANSI colour when stderr is a
terminal). Traversal continues within the current device.

The user can archive a mount point explicitly as a separate source argument
if desired.

### 13.8 Permission Errors During Traversal

When a file or directory cannot be read due to insufficient permissions:
1. A warning is emitted immediately to stderr identifying the affected path
   (yellow ANSI colour when stderr is a terminal)
2. Traversal continues
3. After traversal completes, if any permission errors were encountered:
   abort without committing the archive, exit with code 2
   (`ARK_ERR_IO_READ`), print a summary of all affected paths

No incomplete archive is ever committed.

### 13.9 Special Filesystem Objects

Traversal will encounter filesystem objects that are not regular files,
directories, symbolic links, or hardlinks: FIFOs, Unix domain sockets,
block devices, and character devices. The `type` field defines no values
for these object types and they cannot be represented in the ark format.

When a special filesystem object is encountered during traversal:
1. A warning is emitted immediately to stderr identifying the path and
   object type (yellow ANSI colour when stderr is a terminal)
2. The object is skipped; traversal continues
3. No summary or abort follows; skipping special objects is not an error

This matches the established pattern for mount point crossings in §13.7.
Special filesystem objects are common on real systems (sockets in `/run`,
device nodes, named pipes) and aborting on their presence would make ark
unusable for archiving any directory tree that overlaps with system paths.
The warning ensures the user is informed of what was skipped.

---

## 14. Reader Behaviour

**DECIDED. No open items.**

### 14.1 Extraction Target Directory

When `--output dir` is not specified, extraction proceeds into the current
working directory. No directory is created silently.

The `--output` argument must name a path that already exists and is a
directory. If the path does not exist, is not accessible, or is not a
directory, ark fails with `ARK_ERR_IO_OPEN` and a descriptive message
before applying the sandbox. The destination directory is opened with
`open(O_DIRECTORY|O_CLOEXEC)` as part of pre-sandbox setup; this call
performs the verification and provides the dirfd for all extraction
`*at()` syscalls (see §10.4 and §14.2).

### 14.2 Existing File Handling

Before touching the filesystem, the reader checks all member paths against
the extraction target for conflicts. If any member path already exists and
`--overwrite` is not specified:
- All conflicting paths are collected and reported to stderr
- Extraction is aborted without creating, modifying, or deleting any file
- Exit code 2 (`ARK_ERR_IO_OPEN`)

For `--member` selective extraction, the preflight must also check all
ancestor directory paths that will be created implicitly for the selected
members. For each selected member, derive the set of all ancestor paths
that are not in the selected member set, regardless of whether those
ancestors appear in the archive index. Any ancestor not in the selected
set will be created implicitly if it is missing from the filesystem
(see §14.4). For each such ancestor path, check whether an object already
exists at that path in the extraction target: if it exists and is not a
directory, it is a conflict. Collect all such conflicts and report them
before any filesystem side effect, using the same abort model as explicit
conflicts.

This pre-flight check is an advisory early-exit optimisation. The
authoritative conflict detection occurs at extraction time: each output
file is opened with `openat(destfd, path, O_CREAT|O_EXCL, ...)` without
`--overwrite`. If `EEXIST` is returned, extraction aborts with
`ARK_ERR_IO_OPEN`. This eliminates the TOCTOU race between the pre-flight
check and the actual file creation.

**Extraction uses `*at()` syscalls relative to a destination dirfd.**
All filesystem operations during extraction use the `*at()` family of
syscalls relative to the destination directory fd opened in §14.1 and
§10.4. No full path strings are constructed by concatenating the
destination prefix with member paths. Specifically:
- Regular file creation: `openat(destfd, member_path, O_CREAT|O_WRONLY|O_NOFOLLOW, ...)`
- Directory creation: `mkdirat(destfd, member_path, 0700)`
- Symlink creation: `symlinkat(link_target, destfd, member_path)`
- Hardlink creation: `linkat(destfd, target_path, destfd, member_path, 0)`
- Removal (--overwrite, cleanup): `unlinkat(destfd, member_path, 0)` or
  `unlinkat(destfd, member_path, AT_REMOVEDIR)`
- Stat: `fstatat(destfd, member_path, &st, AT_SYMLINK_NOFOLLOW)`
- Regular file metadata (fd-based, while output fd is open):
  `fchmod(fd, mode)`, `fchown(fd, uid, gid)`, `futimens(fd, times)`
- Directory metadata (deferred pass, dirfd-relative):
  `fchownat(destfd, path, uid, gid, 0)`,
  `fchmodat(destfd, path, mode, 0)`,
  `utimensat(destfd, path, times, 0)`
- Symlink metadata (dirfd-relative):
  `fchownat(destfd, path, uid, gid, AT_SYMLINK_NOFOLLOW)`,
  `utimensat(destfd, path, times, AT_SYMLINK_NOFOLLOW)`

No `AT_FDCWD` is used anywhere in the extraction or metadata path.
This model ensures that PATH_MAX applies only to the member path component
(already limited to 1023 bytes), not to any concatenation with the
destination prefix. It also improves TOCTOU resistance: the dirfd is
anchored to the opened directory inode, so a concurrent rename of the
output directory does not redirect extraction.

**Threat model for intermediate path components.** The `*at()` calls with
multi-component paths (e.g. `openat(destfd, "a/b/c", O_NOFOLLOW)`) protect
only the final component from symlink substitution via `O_NOFOLLOW` or
`AT_SYMLINK_NOFOLLOW`. Intermediate components (`a`, `a/b`) are resolved
by the kernel's standard path walk and can follow symlinks if those
components have been replaced concurrently. Defending against this requires
component-by-component descent using per-component `O_DIRECTORY|O_NOFOLLOW`
opens, which adds significant implementation complexity. Concurrent
modification of the extraction target directory by another process while
ark is extracting is outside ark's threat model. The pre-extraction
validation pass (§8.3) verifies all archive paths before any filesystem
operation; any symlinks found during that pass are rejected. The residual
risk is an attacker who can write to the extraction target directory while
extraction is in progress, a condition under which the extraction operation
itself is compromised regardless of path-resolution strategy. This
limitation is documented in the man page.

With `--overwrite`: the behaviour depends on both the archive member type
and the type of any existing object at the target path. The following
matrix defines the exact action for each combination. All stat and
removal calls use the destfd-relative *at() variants consistent with
the §14.2 extraction model.

**Existing target is a regular file, symlink, or special file (FIFO,
socket, device node) and the archived member is not a directory:**
1. Call `fstatat(destfd, member_path, &st, AT_SYMLINK_NOFOLLOW)`.
2. Call `unlinkat(destfd, member_path, 0)` to remove the existing object.
   Failure is `ARK_ERR_IO_OPEN`. Special files are unlinked identically
   to regular files and symlinks; no special handling is needed.
3. Proceed with normal member creation (file `openat`, `symlinkat`,
   or `linkat` call).

**Archived member is a directory, existing target is a directory:**
- Skip `mkdirat`; the directory already exists. Proceed to deferred
  metadata restoration (see §14.5 and deferred directory metadata below).

**Archived member is a directory, existing target is a regular file,
symlink, or special file:**
- Return `ARK_ERR_IO_OPEN` immediately. A directory cannot replace a
  non-directory at the same path. No unlink is attempted.

**Archived member is a symlink, existing target is a directory:**
- Return `ARK_ERR_IO_OPEN` immediately. A symlink cannot replace a
  directory.

**Archived member is a regular file or hardlink, existing target is a
directory:**
- Return `ARK_ERR_IO_OPEN` immediately. A file cannot replace a directory.

**No existing target (any member type):** proceed with normal member
creation exactly as without `--overwrite`.

For the regular-file unlink-before-create path: open with
`openat(destfd, member_path, O_CREAT|O_WRONLY|O_NOFOLLOW, ...)`.
`O_NOFOLLOW` is included as defence in depth against a symlink being
created between the `unlinkat()` and the `openat()`; an `ELOOP` error
from `openat()` is treated as `ARK_ERR_IO_OPEN`.

**`--overwrite` is not rollback-safe.** The no-partial-extraction guarantee
in §1.3 does not apply when `--overwrite` is specified. Pre-existing file
contents are destroyed by `unlinkat()` before the replacement content is
written and before later members are known to be valid. If extraction
aborts after some members have been overwritten, the original contents of
those members are irrecoverably lost; §14.3 cleanup will remove files
created in this run but cannot restore destroyed originals. Users who
require atomic replacement should extract to a staging directory and
rename the result. This limitation is documented in the man page and in
§17.

### 14.3 Per-Member Hash Failure and Extraction Cleanup

Per-member hash verification is performed during extraction in a single pass:
read compressed chunks, feed to hash context, decompress, write to filesystem.
On first hash mismatch:
- Abort immediately
- Clean up all files and directories already extracted in this run
- Report the offending member path and exit with code 4 (`ARK_ERR_HASH_MEMBER`)

A per-member hash mismatch always indicates post-creation corruption or
tampering of the archive file. It is never a creation-time bug.

**Cleanup on all fatal errors.** The cleanup requirement applies to all
fatal errors during extraction, not only hash mismatches. If extraction
aborts due to any error after filesystem side effects have begun (files or
directories already created), the reader must attempt to remove all
files and directories created in this run before exiting. Cleanup is
best-effort: if cleanup itself encounters errors they are reported as
warnings to stderr but do not change the exit code. The original error
code and message are always preserved and reported.

**Cleanup failure and residual state.** If cleanup fails for any object
(e.g. `unlinkat` returns `EACCES` or `EROFS`), that object remains on
disk after ark exits. In this case the extraction target directory
contains a mix of successfully removed objects and residual partially
extracted content. This is a known limitation: ark cannot guarantee
complete removal of all extracted content when the filesystem denies
cleanup operations. The condition is reported via warnings to stderr.
Users who require guaranteed cleanup should extract to a dedicated
temporary directory on a filesystem they control. This limitation is
documented in §17.

**Thread quiescence before cleanup.** When extraction uses a worker thread
pool and a fatal error occurs, the following sequence is mandatory before
any cleanup or error reporting:
1. Set the shared cancellation flag (see §6.3).
2. Stop submitting new work to the thread pool.
3. Join all worker threads.
4. Close the current output file descriptor if one is open.
5. Only then begin best-effort cleanup of created filesystem objects.

This sequence prevents workers from writing into paths that cleanup is
simultaneously removing, from holding file descriptors open on files being
unlinked, or from creating new files after cleanup has completed. No
filesystem operation in the cleanup pass may race an active worker.

Verify decompresses all member data into a temporary in-memory buffer
(bounded by the 1MB chunk size), computes the hash over the compressed
bytes, and discards the buffer without writing to the filesystem. Memory
pressure is bounded and predictable regardless of archive size.

### 14.4 Directory Creation Ordering

The reader extracts members sequentially in index order. A conforming archive
always contains parent directories before their children (enforced by the
writer's depth-first pre-order traversal; see §13.1). The reader does not
reorder, lookahead, or create parent directories implicitly during full
extraction.

If a member is encountered whose parent directory does not yet exist during
full extraction, the archive is malformed. The reader reports
`ARK_ERR_FMT_INDEX` with the offending path and aborts before creating any
further files or directories. No silent recovery, no implicit `mkdir -p`.
This is consistent with the correctness principle: a malformed archive is a
format error, not a condition to accommodate.

**Selective extraction (`--member`) parent directory handling.** When
extracting a subset of members via `--member`, the selected set may not
include the parent directories of requested leaf members. In this case the
reader creates any missing parent directories implicitly, as needed, before
extracting each requested member. These implicitly created directories use
mode `0700`. Implicitly created directories are tracked in the same cleanup
list as all other filesystem objects created during the extraction run and
are subject to the same cleanup policy in §14.3. If extraction aborts after
implicit directories have been created, they are removed along with all
other created objects. This is the only case where implicit directory
creation is permitted; it applies exclusively to `--member` selective
extraction and not to full extraction.

### 14.5 Metadata Restoration Per Member Type

Metadata restoration behaviour differs by member type. The following rules
apply after the member content (file data, symlink target, or hardlink) has
been created successfully.

**Regular files.** Metadata is applied while the output file descriptor is
still open, immediately after writing all chunks and before closing the fd.
Using the open fd avoids any path-based race between creation and metadata
application and is consistent with the dirfd-anchored extraction model:
- `fchmod(fd, mode & 0777)`: apply permission bits; setuid, setgid, and
  sticky bits are never applied (see §5.2 `mode` field); failure is
  `ARK_ERR_IO_CHMOD`
- `fchown(fd, uid, gid)`: apply uid and gid if running as root; `EPERM` is
  non-fatal and reported as a warning; any other errno is `ARK_ERR_IO_CHOWN`
- `futimens(fd, times)`: restore mtime; failure is `ARK_ERR_IO_UTIMES`

`fchmod`, `fchown`, and `futimens` are all POSIX.1-2008 and available on
Linux and OpenBSD. The fd is closed after all three calls complete (or fail).

**Directories - deferred metadata.** Directory metadata is not applied
immediately after `mkdirat`. It is deferred until after all descendants
have been extracted. Applying directory metadata immediately causes two
problems: (1) a directory mode that removes owner write or execute
permission prevents subsequent child creation from succeeding; (2) any
filesystem operation inside a directory updates its mtime, making any
mtime restoration before descendants are complete produce the wrong value.

Deferred directory metadata restoration sequence:
1. Create each directory with `mkdirat(destfd, path, 0700)`.
2. After all members have been extracted, apply directory metadata in
   reverse depth order (deepest first, root-most last) using
   destfd-relative calls:
   - `fchownat(destfd, path, uid, gid, 0)`: apply uid and gid if running
     as root; `EPERM` and all other errors are non-fatal warnings
   - `fchmodat(destfd, path, mode & 0777, 0)`: apply permission bits;
     setuid, setgid, and sticky bits are never applied; failure is a
     non-fatal warning
   - `utimensat(destfd, path, times, 0)`: restore mtime; failure is a
     non-fatal warning
3. Reverse depth order ensures that applying a restrictive mode to a
   parent does not prevent metadata calls on children already processed.

`fchownat` and `fchmodat` are POSIX.1-2008 and available on Linux and
OpenBSD. `utimensat` with a dirfd is likewise POSIX.1-2008 on both
platforms. No `AT_FDCWD` is used anywhere in the metadata restoration pass.

**All deferred directory metadata failures are non-fatal warnings.** By
the time the deferred pass runs, content extraction has completed
successfully. The user has all their files on disk. Metadata restoration
failures are reported to stderr as warnings but do not trigger filesystem
cleanup and do not change the exit code if extraction otherwise succeeded.
Making deferred directory metadata failures non-fatal eliminates an
intractable cleanup problem: if a chmod to a restrictive mode has already
been applied to a directory earlier in the deferred pass when a later
metadata operation fails, cleanup would be unable to descend into the
now-restricted directory to remove its contents. Users who need exact
directory metadata can run `chmod`/`touch` manually; the warnings identify
the affected paths.

Directory entries are tracked in a deferred list during extraction. This
list is populated in the order members are extracted; reverse iteration
at the end produces the required reverse depth order because the writer
always stores parent directories before their children (§13.1).

**Symbolic links:**
- `chmod`: skip entirely. `lchmod()` does not exist on Linux; on OpenBSD
  it affects the symlink inode but has no security relevance for archived
  symlinks. Mode bits for symlinks are not restored on any platform.
- `fchownat(destfd, path, uid, gid, AT_SYMLINK_NOFOLLOW)`: apply uid and
  gid if running as root; modifies the symlink inode without following the
  link. `EPERM` is non-fatal and reported as a warning; any other errno is
  `ARK_ERR_IO_CHOWN`.
- `utimensat(destfd, path, times, AT_SYMLINK_NOFOLLOW)`: restore mtime on
  the symlink inode without following the link. On Linux this requires the
  process to own the symlink or hold `CAP_FOWNER`; failure is non-fatal and
  reported as a warning rather than `ARK_ERR_IO_UTIMES`. On OpenBSD failure
  is similarly non-fatal. A dangling symlink target does not affect this
  call.

**Hardlinks:**
- Hardlinks share the inode of their target member. Metadata is already
  restored when the target member is processed. No metadata operations are
  performed for hardlink entries themselves.

---

## 15. Self-Describing Recovery

**DECIDED. No open items.**

### 15.1 Design Intent

Long-term archive recovery is an opt-in concern, not a universal one. Most
users have no century-scale preservation requirement. Embedding recovery
machinery into every archive unconditionally would impose cost on all users
for a feature only some need. The feature is therefore user-invoked, not
automatic.

### 15.2 ark generate-reader

`ark generate-reader [output.c]` writes a self-contained C11 recovery reader
to the specified path (default: `recovery.c` in the current working directory).

The generated file contains:
- A large comment block at the top: complete ark format description including
  all field layouts, recovery procedure, compilation instructions, and
  rationale for the format design choices. This comment is the sole
  human-readable recovery guide - no separate RECOVER.txt is produced.
- Deflate decompressor (read path only; no compressor)
- BLAKE3 implementation (sequential mode)
- SHA-256 implementation
- Archive read path (no write path)
- Minimal extraction `main()` with no external dependencies beyond libc

Both hash implementations are always included regardless of which algorithm
a specific archive uses. This produces one recovery file that handles all
ark archives, regardless of the hash algorithm selected at creation time.
The ~200-250 line cost of including both is accepted in exchange for
universal applicability.

The generated file is approximately 2,200-2,700 lines of C11. It compiles
with any C11 compiler: `cc -O2 recovery.c -o recover && ./recover archive.ark`.

**Endian neutrality.** The ark format is strictly little-endian throughout.
The generated `recovery.c` must parse all multi-byte integer fields using
explicit byte-by-byte reads with manual assembly into host-typed integers.
No host-endian struct casts are permitted. No `le32toh` / `le64toh` macros
are used: these macros require either `<endian.h>` (Linux) or `<sys/endian.h>`
(OpenBSD) and are not universally available. Instead, all field reads use
the form:

```c
uint32_t val = (uint32_t)buf[0]
             | ((uint32_t)buf[1] << 8)
             | ((uint32_t)buf[2] << 16)
             | ((uint32_t)buf[3] << 24);
```

This produces correct results on any host byte order and requires no
platform-specific headers. The recovery reader must be compilable and
correct on any architecture, including future big-endian systems, without
modification.

### 15.3 Build-Time Amalgamation

The recovery reader is produced at build time by an amalgamation script
(`tools/make_recovery.sh`) that:
- Takes the decompressor half of `deflate.c`, `blake3.c`, `sha256.c`, the
  read path of `archive.c`, and `recover_main.c`
- Inlines all internal `#include` references
- Strips the compressor from `deflate.c` and the write path from `archive.c`
- Prepends the comment block
- Produces a single `recovery.c` amalgamation

The amalgamation is then converted to a C byte array using `xxd -i`, producing
`recovery_blob.h` containing `static const unsigned char ark_recovery_src[]`
and its length. This header is compiled into the ark binary as a static
constant. `ark generate-reader` at runtime writes this byte array to the
output file.

A `make recovery.c` build target produces the amalgamation for inspection.
The modular sources are always the ground truth. The amalgamation and the
embedded blob are derived artifacts and are never edited directly.

**deflate.c internal boundary.** The amalgamation script strips the
compressor from `deflate.c` and retains only the decompressor. This requires
that all symbols, tables, and constants used exclusively by the decompressor
are not defined only within the compressor section. The implementation must
maintain a clean internal boundary between compressor and decompressor code
within `deflate.c`, such that the decompressor-only subset compiles and
links correctly as a standalone unit. This is a hard implementation
requirement, not a style preference.

**Size overhead:** approximately 60-70KB of C source text embedded in the
ark binary. This is negligible for a systems tool.

### 15.4 Preservation Guidance

The man page states clearly: users archiving collections for long-term
preservation should run `ark generate-reader` once and keep the output
alongside their archives. Both files must be kept together. The recovery
reader has no value without an archive, and an archive has reduced recovery
guarantees without a recovery reader.

No mechanism is provided to embed the recovery reader inside the archive
itself. Doing so would require changes to the core format for a non-core
feature, which contradicts the design principle that peripheral concerns
do not drive core structure.

---

## 16. archive.h API

**DECIDED. No open items.**

### 16.1 Design Principles

`archive.c` / `archive.h` is the format read/write layer sitting above the
deflate and hash components and below `main.c`. It follows the same discipline
as all other components: no I/O, no allocation beyond what is necessary for
internal context state, no ownership of file descriptors or paths. `main.c`
owns all I/O, all libchevron calls, all filesystem traversal, and all
parallelism coordination.

This placement is driven by the same four-lens evaluation applied to all
architectural decisions. Correctness: sequencing enforcement is cleanest in
the component that owns format knowledge. Security: zero I/O in `archive.c`
means a clean, auditable syscall footprint - the sandboxing policy in §10.4
is entirely visible in `main.c`. Auditability: `archive.c` is a pure format
component readable in isolation. Performance: parallelism is owned and visible
in `main.c` where I/O and threading decisions belong together.

`archive.c` is included in the `ark generate-reader` amalgamation (read path
only). Its zero-I/O discipline makes this inclusion clean: the recovery
reader's `main()` owns all I/O without entanglement from `archive.c`.

**Context state after error.** When any `ark_write_*` or `ark_read_*`
function returns -1, the context is in an indeterminate state. The only
valid operation on a context that has returned an error is to call
`ark_write_free` or `ark_read_free` respectively. All other calls after
an error return are undefined behaviour. `ark_write_free` and
`ark_read_free` are always safe to call regardless of prior error state.

### 16.2 Shared Types

```c
typedef enum {
    ARK_HASH_BLAKE3  = 0x01,
    ARK_HASH_SHA256  = 0x02
} ark_hash_alg_t;

typedef struct {
    uint8_t    type;             /* 0x01 file, 0x02 dir, 0x03 symlink, 0x04 hardlink */
    uint32_t   mode;
    uint32_t   uid;
    uint32_t   gid;
    uint64_t   mtime;
    uint64_t   size_original;
    uint64_t   size_compressed;
    uint64_t   data_offset;
    uint8_t    hash[32];
    char       path[1024];       /* null-terminated relative path */
    char       link[1024];       /* null-terminated; empty for type 0x01 and 0x02 */
    uint32_t   chunk_count;
    uint32_t  *chunk_sizes;      /* owned by the enclosing read or write context;
                                    caller must not free directly;
                                    valid only until ark_read_free or ark_write_free */
} ark_member_meta_t;

typedef struct ark_write_ctx ark_write_ctx_t;
typedef struct ark_read_ctx ark_read_ctx_t;

#define ARK_WRITE_CTX_STORAGE_SIZE 8192U
#define ARK_READ_CTX_STORAGE_SIZE 16384U

typedef union {
    max_align_t align;
    uint8_t     bytes[ARK_WRITE_CTX_STORAGE_SIZE];
} ark_write_ctx_storage_t;

typedef union {
    max_align_t align;
    uint8_t     bytes[ARK_READ_CTX_STORAGE_SIZE];
} ark_read_ctx_storage_t;
```

`ark_write_ctx_t` and `ark_read_ctx_t` are semantically opaque: callers must
not inspect or depend on their private fields. Callers allocate the matching
storage union, zero it before the first init/header call, and pass a pointer to
`bytes` cast to the opaque context pointer type. `archive.c` contains C11
static assertions that the public storage size and alignment are sufficient.

### 16.3 Write Path

**Write context state machine.** The write context progresses through the
following states. Invalid transitions return -1 with `ARK_ERR_USAGE`.
`ark_write_free` is valid in any state.

```
UNINIT  --ark_write_init-->        READY
READY   --ark_write_header-->      IDLE
IDLE    --ark_write_member_begin--> MEMBER
IDLE    --ark_write_index-->       INDEXED   (zero-member archive)
MEMBER  --ark_write_chunk-->       MEMBER    (repeats per chunk)
MEMBER  --ark_write_member_end-->  IDLE
IDLE    --ark_write_index-->       INDEXED
INDEXED --ark_write_footer-->      DONE
```

Calling `ark_write_chunk` outside MEMBER state, calling
`ark_write_member_begin` while already in MEMBER state, calling
`ark_write_index` before all members are ended, or calling
`ark_write_footer` before `ark_write_index` all return -1 with
`ARK_ERR_USAGE`. Calling `ark_write_member_end` outside MEMBER state
returns -1 with `ARK_ERR_USAGE`. Calling `ark_write_chunk` for a member
type other than 0x01 (regular file) returns -1 with `ARK_ERR_USAGE`.
The format stores each chunk size as a u32 field (maximum 4,294,967,295
bytes). Passing `src_len > UINT32_MAX` to `ark_write_chunk` returns -1
with `ARK_ERR_USAGE`: the value cannot be stored in the index without
truncation. In practice the CLI's 1MB uncompressed chunk pipeline cannot
produce compressed output approaching this limit even for maximally
incompressible content; the check exists to enforce the API contract
regardless of caller behaviour.

```c
/* Initialise a write context. hash_alg and mode apply to all subsequent
   operations on this context. Returns 0 on success, -1 on error. */
int ark_write_init(ark_write_ctx_t    *ctx,
                   ark_hash_alg_t      hash_alg,
                   ark_deflate_mode_t  mode,
                   ark_error_t        *err);

/* Serialise the fixed header into dst. Returns bytes written or -1.
   dst_cap must be at least 16 bytes; if not, returns -1 with
   ARK_ERR_IO_ALLOC. Must be the first write call on a new context. */
ssize_t ark_write_header(ark_write_ctx_t *ctx,
                         uint8_t         *dst,
                         size_t           dst_cap,
                         ark_error_t     *err);

/* Begin a new member. Caller provides fully populated metadata.
   Prepares internal state for subsequent ark_write_chunk calls.
   chunk_sizes in meta must be NULL on the write path; the write context
   accumulates chunk sizes internally as ark_write_chunk is called.
   chunk_sizes is an output field on the read path only (populated by
   ark_read_index). Callers of the write path must never populate or read
   chunk_sizes from ark_member_meta_t; the write context owns this data
   internally until ark_write_free.
   Returns 0 on success, -1 on error. */
int ark_write_member_begin(ark_write_ctx_t         *ctx,
                           const ark_member_meta_t *meta,
                           ark_error_t             *err);

/* Record one pre-compressed chunk of member data into dst.
   src contains already-compressed bytes produced by ark_deflate_compress
   in a worker thread; this function does NOT perform compression.
   src_len is the compressed byte count. Updates internal hash state for
   the current member over the compressed bytes and records the chunk size.
   Copies compressed bytes to dst for handoff to chevron_write_chunk.
   Worker threads compress chunks using ark_deflate_compress directly;
   this function is called only from the I/O thread, in chunk order, after
   the ring buffer has delivered the compressed result for that chunk.
   If dst_cap < src_len, returns -1 with ARK_ERR_IO_ALLOC: the caller
   undersized the staging buffer. main.c must ensure dst_cap >=
   ark_deflate_bound(ARK_CHUNK_SIZE) before calling.
   If src_len > UINT32_MAX, returns -1 with ARK_ERR_USAGE: the value
   cannot be stored in the u32 chunk_sizes index field.
   Returns bytes written to dst on success, -1 on error. */
ssize_t ark_write_chunk(ark_write_ctx_t *ctx,
                        const uint8_t   *src,
                        size_t           src_len,
                        uint8_t         *dst,
                        size_t           dst_cap,
                        ark_error_t     *err);

/* Finalise the current member. Completes the per-member hash and records
   the chunk table and hash into the write context for later index
   serialisation. Must be called after the final ark_write_chunk for each
   member. Returns -1 with ARK_ERR_USAGE if called outside MEMBER state. */
int ark_write_member_end(ark_write_ctx_t *ctx,
                         ark_error_t     *err);

/* Serialise the index block into dst. Returns bytes written or -1.
   Must be called after all members are finalised via ark_write_member_end.
   Computes the index hash over the serialised index bytes and stores it
   in the write context. ark_write_footer retrieves this stored hash from
   the context; no separate hash parameter is needed.
   If dst_cap is insufficient to hold the serialised index, returns -1 with
   ARK_ERR_IO_ALLOC: the caller undersized the buffer. The required size
   can be computed from the accumulated member metadata before this call;
   main.c is responsible for allocating a sufficient buffer. */
ssize_t ark_write_index(ark_write_ctx_t *ctx,
                        uint8_t         *dst,
                        size_t           dst_cap,
                        ark_error_t     *err);

/* Serialise the footer into dst. Returns bytes written or -1.
   dst_cap must be at least 64 bytes; if not, returns -1 with
   ARK_ERR_IO_ALLOC. index_offset and index_size are supplied by main.c
   which tracks the byte positions of all written blocks. The index_hash
   written into the footer is retrieved from the write context where it
   was stored by ark_write_index; it must not be supplied by the caller.
   Must be the final write call before ark_write_free. */
ssize_t ark_write_footer(ark_write_ctx_t *ctx,
                         uint64_t         index_offset,
                         uint64_t         index_size,
                         uint8_t         *dst,
                         size_t           dst_cap,
                         ark_error_t     *err);

/* Release all resources owned by the write context. */
void ark_write_free(ark_write_ctx_t *ctx);
```

### 16.4 Read Path

The read path requires two initialisation calls before index access:
`ark_read_header` parses and validates the 16-byte fixed header;
`ark_read_init` parses and validates the 64-byte footer. Both must succeed
before `ark_read_index` is called. The required call sequence is:

```
ark_read_header   (validates header, populates comp_alg, hash_alg, version)
ark_read_init     (validates footer, populates index_offset, index_size, member_count)
ark_read_index    (loads, verifies, and parses the index block)
ark_read_member_meta / ark_read_find_member / ark_read_chunk /
    ark_read_verify_*  (per-member access)
ark_read_free
```

```c
/* Parse and validate the 16-byte fixed header. header_buf must be exactly
   16 bytes loaded by main.c from byte offset 0. Validates magic bytes,
   ver_major (rejects unsupported values with ARK_ERR_FMT_VERSION), flags
   (rejects non-zero with ARK_ERR_FMT_RESERVED), comp_alg (rejects unknown
   values with ARK_ERR_FMT_COMP_ALG), hash_alg (rejects unknown values with
   ARK_ERR_FMT_HASH_ALG), and reserved bytes (rejects non-zero with
   ARK_ERR_FMT_RESERVED). Populates ctx with comp_alg, hash_alg, ver_major,
   and ver_minor for use by subsequent calls.
   Must be the first read call on a new context.
   Returns 0 on success, -1 on format error. */
int ark_read_header(ark_read_ctx_t  *ctx,
                    const uint8_t   *header_buf,
                    size_t           header_len,
                    ark_error_t     *err);

/* Parse and validate the 64-byte footer. footer_buf must be exactly 64
   bytes loaded by main.c from file_size - 64. Validates magic_confirm
   and reserved bytes. Populates ctx with index_offset, index_size,
   member_count, and index_hash for use by ark_read_index.
   hash_alg is read from the context populated by ark_read_header; this
   function does not re-read it from the footer (the footer contains no
   hash_alg field). Must be called after ark_read_header.
   The five file-size-dependent bounds checks (file_size >= 80,
   index_offset >= 16, no overflow, structural equality) are the
   responsibility of main.c and must be performed before this call
   using the file_size value from fstat(). See §5.1. ark_read_init
   does not have access to file_size and does not re-perform those checks.
   Returns 0 on success, -1 on format or integrity error. */
int ark_read_init(ark_read_ctx_t  *ctx,
                  const uint8_t   *footer_buf,
                  size_t           footer_len,
                  ark_error_t     *err);

/* Verify and parse the index block. index_buf must be index_size bytes
   loaded by main.c from index_offset. Verifies the index hash using the
   hash_alg from the context before parsing any entry. Validates
   member_count against index_size (see §5.1 pre-allocation bound) before
   allocating the entry array. Returns -1 on integrity or format error. */
int ark_read_index(ark_read_ctx_t *ctx,
                   const uint8_t  *index_buf,
                   size_t          index_len,
                   ark_error_t    *err);

/* Return a pointer to parsed member metadata at index position pos.
   Returns NULL if pos >= member_count. Points into context-owned memory;
   valid until ark_read_free. No allocation. */
const ark_member_meta_t *ark_read_member_meta(const ark_read_ctx_t *ctx,
                                               uint32_t              pos);

/* Find the member position for an archive path. path is compared byte for
   byte with member paths (no normalisation). ark_read_index builds a path
   index sorted by (path bytes, position), so the lookup is a binary search
   (O(log member_count)) and returns the smallest position with that path.
   Returns 0 and stores the position in *pos on success, -1 when no member
   has the path, for NULL arguments, or before ark_read_index. The path
   index is context-owned and released by ark_read_free. No allocation. */
int ark_read_find_member(const ark_read_ctx_t *ctx,
                         const char           *path,
                         uint32_t             *pos);

/* Decompress one pre-compressed chunk of member data. src contains the
   compressed chunk bytes as read from the archive; src_len must equal
   chunk_sizes[chunk_index] from meta. dst receives the decompressed output.
   Validates that the decompressed byte count equals the expected chunk size:
   1048576 bytes for all chunks except the last, and
   (size_original mod 1048576) bytes for the last chunk (or 1048576 if
   size_original is an exact multiple). A src_len mismatch against the
   indexed compressed chunk size returns -1 with ARK_ERR_FMT_DATA. A
   decompressed length mismatch returns -1 with ARK_ERR_FMT_DATA. An invalid
   Deflate stream returns -1 with
   ARK_ERR_FMT_DATA. Returns decompressed bytes written on success, -1 on
   error. chunk_index must be in range [0, meta->chunk_count).
   Single-threaded extraction: main.c calls this in the main loop after
   reading each compressed chunk. Parallel extraction: workers call
   ark_deflate_decompress directly and never call this function; the I/O
   thread performs length validation and ARK_ERR_FMT_DATA classification
   after draining each ring buffer slot (see §6.3). */
ssize_t ark_read_chunk(ark_read_ctx_t          *ctx,
                       const ark_member_meta_t *meta,
                       uint32_t                 chunk_index,
                       const uint8_t           *src,
                       size_t                   src_len,
                       uint8_t                 *dst,
                       size_t                   dst_cap,
                       ark_error_t             *err);

/* Initialise the per-member hash context for a new member. Must be called
   once before the first ark_read_verify_member_update call for each member.
   Resets internal hash state so that hash residue from a previous member
   does not contaminate the current member's verification. Returns 0 on
   success, -1 on error. */
int ark_read_verify_member_begin(ark_read_ctx_t          *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t             *err);

/* Feed one compressed chunk into the per-member hash context. Must be
   called with chunk_index equal to the next expected index, with the
   compressed bytes just read from the
   archive, before decompression. main.c calls this immediately after
   reading the compressed chunk from the archive file, before passing
   it to ark_read_chunk for decompression. Memory bound is one compressed
   chunk at a time regardless of member size.
   The read context tracks the expected chunk index internally, reset to 0
   by ark_read_verify_member_begin. If chunk_index is supplied out of order
   (i.e. not the next expected index in sequence), this function returns
   -1 with ARK_ERR_FMT_INDEX immediately rather than producing a silent
   hash mismatch at the final gate.
   Returns 0 on success, -1 on error. */
int ark_read_verify_member_update(ark_read_ctx_t          *ctx,
                                  const ark_member_meta_t *meta,
                                  uint32_t                 chunk_index,
                                  const uint8_t           *chunk_data,
                                  size_t                   chunk_len,
                                  ark_error_t             *err);

/* Finalise per-member hash verification after all chunks have been fed
   via ark_read_verify_member_update. Compares the computed hash against
   meta->hash. Returns 0 on match, -1 on mismatch (ARK_ERR_HASH_MEMBER).
   Does not reset internal state; ark_read_verify_member_begin must be
   called before processing the next member. */
int ark_read_verify_member_final(ark_read_ctx_t          *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t             *err);

/* Release all resources owned by the read context. */
void ark_read_free(ark_read_ctx_t *ctx);
```

---

## 17. Known Limitations (Confirmed)

These are confirmed design decisions, not defects.

**`--overwrite` is not rollback-safe.** The no-partial-extraction guarantee
does not apply when `--overwrite` is specified. Pre-existing file contents
are destroyed before the replacement is written and before later members are
known to be valid. If extraction fails mid-run, overwritten files are
irrecoverably lost. Users requiring atomic replacement should extract to a
staging directory and rename the result. This is documented in the man page.

**Recovery reader covers v1 format only.** `ark generate-reader` embeds a
Deflate decompressor only. Archives created with a future format version
using a different `comp_alg` value are not recoverable by a v1 recovery
reader. Users archiving for long-term preservation should regenerate the
recovery reader with each new major version of ark. This is documented in
the man page.

**Index loaded entirely into memory.** The entire index block is loaded and
verified in one operation before any extraction begins. For archives
containing tens of millions of small files the index may reach several
hundred megabytes. There is no streaming or paged index fallback. Systems
with severe memory constraints may be unable to extract pathological
archives. Normal archives (large files, moderate member counts) are not
affected.

**Writer index buffered entirely in memory.** The writer accumulates
metadata, paths, and chunk size tables for every member in memory across
the entire traversal, as the index is serialised and written only after all
member data is written. This imposes the same memory constraint on archive
creation as on extraction: for archives containing tens of millions of small
files the in-memory index accumulation may reach several hundred megabytes.
There is no incremental index flush mechanism. This is a symmetric
consequence of writing the index last, which is required by the format
structure.

**No store-only mode.** Compression is always on. Deflate stored blocks
handle incompressible content with negligible overhead. A --no-compress flag
is not provided and is not planned.

**No ACL or extended attribute preservation.** mode, uid, and gid only.
Callers that depend on ACLs, SELinux contexts, or xattrs must restore them
after extraction.

**Maximum path length 1023 bytes.** Enforced at creation time regardless of
creating platform. Archives containing longer paths cannot be extracted on
OpenBSD or macOS.

**No multi-writer coordination.** Concurrent writes to the same target path
are not serialised. The caller is responsible for coordination.

**No network filesystem guarantees.** Local POSIX filesystem behaviour only.

**uid/gid values are not portable across systems.** Numeric uid/gid is stored
and restored on a best-effort basis (root only). Non-root extraction uses
current process credentials.

**No append or update.** An existing archive cannot be extended or modified.
Creating a new archive is always a complete operation.

**Orphaned temp files on crash.** If the process crashes after libchevron
creates the temp file but before commit, the temp file remains as an orphan
in the parent directory. This is a libchevron known limitation inherited by
ark. The temp file does not affect the target path.

**Fixed 1MB chunk size.** The chunk size is a format constant and is not
configurable. Archives produced by v1 always use 1MB chunks. A future format
version may introduce a different chunk size but v1 readers are not required
to support it.

**Deflate optimisation guardrails (implementation-level only).** Future
compressor/decompressor optimisations are permitted only when they preserve
all v1 format invariants. In particular, the following must not change:
- 1MB fixed chunk size and one independent Deflate stream per chunk
  (see §6.2)
- raw-store fallback semantics for incompressible content (see §6.4, §7.2)
- determinism scope for identical input on the same binary (see §13.1)
- public Deflate API contract in `deflate.h` (see §7.4)
- decompressor/compiler boundary required by recovery amalgamation
  (`deflate.c` decompressor subset remains standalone; see §15.3)

Within those constraints, the implementation may improve Huffman code-length
assignment quality, dynamic-header coding efficiency, parsing-pass count,
and internal match-finder/reset costs, provided RFC 1951 validity is
preserved and output remains deterministic within the documented scope.

**Partial modification detection during archiving.** The writer detects
modifications to a file only while that specific file is being read, and
only when mtime or st_size changes. Files modified within one timestamp
tick, files whose mtime is restored after modification, and in-place
overwrites that leave size unchanged are undetectable. Files modified
after ark has finished reading them and moved on are also undetectable.
The guarantee is: ark commits no archive it detects as modified; undetected
concurrent modifications may result in a committed archive with torn members.
For filesystems where strict consistency is required, a snapshot should be
taken before archiving.

**Hardlink extraction requires Linux 5.19+ (Landlock ABI v2).** The
`LANDLOCK_ACCESS_FS_REFER` right required for `linkat()` in hardlink
extraction is available only from Landlock ABI v2 (Linux 5.19). On Linux
5.13-5.18 (ABI v1), extracting archives that contain hardlinks is rejected
before any filesystem side effects. Archives without hardlinks extract
normally on Linux 5.13+.

**Cleanup failure may leave residual extracted content.** If post-error
cleanup fails for any object (e.g. the filesystem denies `unlinkat()`),
that object remains on disk after ark exits. The overall extraction is
still a fatal error but the target directory may contain partially extracted
content. This is reported via warnings to stderr. Users requiring guaranteed
cleanup should extract to a dedicated temporary directory on a filesystem
they control.

**Recovery reader separation risk.** `ark generate-reader` produces a
companion `.c` file alongside archives. The two files can be separated.
ark does not embed the recovery reader inside the archive format. Users
archiving for long-term preservation are responsible for keeping the recovery
reader alongside their archives. This is documented in the man page.

**Minimum Linux kernel 5.13.** Landlock filesystem access control requires
Linux 5.13 (released July 2021). Older kernels are not supported. ark fails
at startup with a clear error on kernels below this version. Hardlink
extraction requires Linux 5.19 (see above).
