#ifndef ARK_ARCHIVE_H
#define ARK_ARCHIVE_H

/*
 * archive.h - Archive format read/write public API.
 *
 * This component declares format-layer shared types, error model types,
 * and read/write context APIs used by main.c.
 *
 * See ARCHITECTURE.md section 11.2, 11.3, 16.2, 16.3, and 16.4.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "deflate.h"

typedef enum {
	ARK_OK = 0,

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
	ARK_ERR_IO_UTIMES,
	ARK_ERR_IO_ALLOC,

	/* exit 3 - format */
	ARK_ERR_FMT_MAGIC,
	ARK_ERR_FMT_VERSION,
	ARK_ERR_FMT_COMP_ALG,
	ARK_ERR_FMT_HASH_ALG,
	ARK_ERR_FMT_RESERVED,
	ARK_ERR_FMT_INDEX,
	ARK_ERR_FMT_MEMBER_TYPE,
	ARK_ERR_FMT_TRUNCATED,
	ARK_ERR_FMT_DATA,

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

/*
 * ark_error_t - Detailed error payload propagated across layers.
 *
 * code maps to ark exit classes. sys_errno is errno at failure site or 0
 * if not applicable. msg is human-readable detail without path content.
 * path is the offending path or empty string when not path-specific.
 *
 * See ARCHITECTURE.md section 11.2.
 */
typedef struct {
	ark_err_t code;
	int sys_errno;
	char msg[256];
	char path[1024];
} ark_error_t;

typedef enum {
	ARK_HASH_BLAKE3 = 0x01,
	ARK_HASH_SHA256 = 0x02,
} ark_hash_alg_t;

/*
 * ark_member_meta_t - Parsed or caller-supplied member metadata.
 *
 * path and link are stored as null-terminated relative UTF-8 strings.
 * link is empty for regular files and directories.
 *
 * NOTE: chunk_sizes is an output field on the read path. On the write path,
 * callers keep chunk_sizes NULL; chunk sizes are accumulated internally by
 * the write context.
 *
 * OWNERSHIP: chunk_sizes is owned by the enclosing context and remains valid
 * only until ark_read_free() or ark_write_free(). Callers must not free it.
 *
 * See ARCHITECTURE.md section 5.2 and 16.2.
 */
typedef struct {
	uint8_t type;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t mtime;
	uint64_t size_original;
	uint64_t size_compressed;
	uint64_t data_offset;
	uint8_t hash[32];
	char path[1024];
	char link[1024];
	uint32_t chunk_count;
	uint32_t *chunk_sizes;
} ark_member_meta_t;

typedef struct ark_write_ctx ark_write_ctx_t;
typedef struct ark_read_ctx ark_read_ctx_t;

#define ARK_WRITE_CTX_STORAGE_SIZE 8192U
#define ARK_READ_CTX_STORAGE_SIZE 16384U

/*
 * Opaque context storage.
 *
 * Callers allocate one of these storage objects, zero it before first use,
 * and pass a pointer to its bytes cast to ark_write_ctx_t or ark_read_ctx_t.
 * The concrete context fields remain private to archive.c. The storage sizes
 * are guarded by compile-time assertions in archive.c.
 */
typedef union {
	max_align_t align;
	uint8_t bytes[ARK_WRITE_CTX_STORAGE_SIZE];
} ark_write_ctx_storage_t;

typedef union {
	max_align_t align;
	uint8_t bytes[ARK_READ_CTX_STORAGE_SIZE];
} ark_read_ctx_storage_t;

/*
 * ark_write_init - Initialize a write context.
 *
 * hash_alg selects archive hash algorithm; mode selects compressor behavior
 * passed through to writer-side chunk handling policy.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: populates err when non-NULL.
 * Preconditions: ctx must point to zero-initialized ark_write_ctx_storage_t
 * storage and be in UNINIT state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
int ark_write_init(ark_write_ctx_t *ctx, ark_hash_alg_t hash_alg,
                   ark_deflate_mode_t mode, ark_error_t *err);

/*
 * ark_write_header - Serialize fixed 16-byte header into dst.
 *
 * Returns bytes written on success, -1 on failure.
 * Failure contract: returns ARK_ERR_IO_ALLOC when dst_cap < 16.
 * Preconditions: ctx in READY state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
ssize_t ark_write_header(ark_write_ctx_t *ctx, uint8_t *dst, size_t dst_cap,
                         ark_error_t *err);

/*
 * ark_write_member_begin - Begin a new member in the write state machine.
 *
 * meta supplies member metadata for the next member.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: returns ARK_ERR_USAGE on invalid state transitions.
 * Preconditions: ctx in IDLE state; meta non-NULL; write-path callers keep
 * meta->chunk_sizes NULL.
 *
 * See ARCHITECTURE.md section 16.3.
 */
int ark_write_member_begin(ark_write_ctx_t *ctx, const ark_member_meta_t *meta,
                           ark_error_t *err);

/*
 * ark_write_chunk - Record one pre-compressed member chunk.
 *
 * src contains compressed bytes; dst receives bytes for caller handoff.
 *
 * Returns bytes written on success, -1 on failure.
 * Failure contract: returns ARK_ERR_USAGE on invalid state/member type;
 * returns ARK_ERR_IO_ALLOC when dst_cap < src_len.
 * Preconditions: ctx in MEMBER state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
ssize_t ark_write_chunk(ark_write_ctx_t *ctx, const uint8_t *src,
                        size_t src_len, uint8_t *dst, size_t dst_cap,
                        ark_error_t *err);

/*
 * ark_write_member_end - Finalize the active member.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: returns ARK_ERR_USAGE when called outside MEMBER state.
 * Preconditions: ctx in MEMBER state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
int ark_write_member_end(ark_write_ctx_t *ctx, ark_error_t *err);

/*
 * ark_write_index - Serialize index block into dst and store index hash.
 *
 * Returns bytes written on success, -1 on failure.
 * Failure contract: returns ARK_ERR_IO_ALLOC when dst buffer is undersized.
 * Preconditions: ctx in IDLE state after all members are finalized.
 *
 * See ARCHITECTURE.md section 16.3.
 */
ssize_t ark_write_index(ark_write_ctx_t *ctx, uint8_t *dst, size_t dst_cap,
                        ark_error_t *err);

/*
 * ark_write_footer - Serialize 64-byte footer into dst.
 *
 * index_offset/index_size are provided by caller from archive layout tracking.
 *
 * Returns bytes written on success, -1 on failure.
 * Failure contract: returns ARK_ERR_IO_ALLOC when dst_cap < 64.
 * Preconditions: ctx in INDEXED state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
ssize_t ark_write_footer(ark_write_ctx_t *ctx, uint64_t index_offset,
                         uint64_t index_size, uint8_t *dst, size_t dst_cap,
                         ark_error_t *err);

/*
 * ark_write_free - Release all resources owned by a write context.
 *
 * Returns no value.
 * Failure contract: none.
 * Preconditions: may be called in any write-context state.
 *
 * See ARCHITECTURE.md section 16.3.
 */
void ark_write_free(ark_write_ctx_t *ctx);

/*
 * ark_read_header - Parse and validate the fixed 16-byte header.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: format errors are reported via err.
 * Preconditions: called first on a new read context.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_header(ark_read_ctx_t *ctx, const uint8_t *header_buf,
                    size_t header_len, ark_error_t *err);

/*
 * ark_read_init - Parse and validate the 64-byte footer.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: format/integrity errors are reported via err.
 * Preconditions: ark_read_header() already succeeded.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_init(ark_read_ctx_t *ctx, const uint8_t *footer_buf,
                  size_t footer_len, ark_error_t *err);

/*
 * ark_read_index - Verify hash and parse index buffer.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: reports ARK_ERR_HASH_INDEX/ARK_ERR_FMT_* via err.
 * Preconditions: ark_read_header() and ark_read_init() succeeded.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_index(ark_read_ctx_t *ctx, const uint8_t *index_buf,
                   size_t index_len, ark_error_t *err);

/*
 * ark_read_member_meta - Return parsed metadata for member position pos.
 *
 * Returns pointer to context-owned metadata on success, NULL when out of
 * range.
 * Failure contract: no err parameter; NULL signals out-of-range access.
 * Preconditions: ark_read_index() succeeded.
 *
 * See ARCHITECTURE.md section 16.4.
 */
const ark_member_meta_t *ark_read_member_meta(const ark_read_ctx_t *ctx,
                                              uint32_t pos);

/*
 * ark_read_find_member - Find the member position for an archive path.
 *
 * path is compared byte for byte with member paths (no normalisation). The
 * lookup is a binary search over a path index built by ark_read_index, so
 * it costs O(log member_count).
 *
 * Returns 0 and stores the member position in *pos when a member has that
 * path, -1 when none does.
 * Failure contract: no err parameter; -1 also covers NULL arguments and a
 * context whose index has not been read.
 * Preconditions: ark_read_index() succeeded.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_find_member(const ark_read_ctx_t *ctx, const char *path,
                         uint32_t *pos);

/*
 * ark_read_chunk - Decompress one member chunk.
 *
 * Returns decompressed byte count on success, -1 on failure.
 * Failure contract: compressed byte-count mismatch, invalid Deflate stream,
 * or expected decompressed-length mismatch maps to ARK_ERR_FMT_DATA via err.
 * Preconditions: chunk_index in [0, meta->chunk_count).
 *
 * See ARCHITECTURE.md section 16.4.
 */
ssize_t ark_read_chunk(const ark_read_ctx_t *ctx, const ark_member_meta_t *meta,
                       uint32_t chunk_index, const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, ark_error_t *err);

/*
 * ark_read_verify_member_begin - Reset per-member verification state.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: reports validation/setup errors via err.
 * Preconditions: ark_read_index() succeeded.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_verify_member_begin(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err);

/*
 * ark_read_verify_member_update - Feed one compressed chunk to member hash.
 *
 * Returns 0 on success, -1 on failure.
 * Failure contract: out-of-order chunk_index values return
 * ARK_ERR_FMT_INDEX via err.
 * Preconditions: ark_read_verify_member_begin() already called for meta.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_verify_member_update(ark_read_ctx_t *ctx,
                                  const ark_member_meta_t *meta,
                                  uint32_t chunk_index,
                                  const uint8_t *chunk_data, size_t chunk_len,
                                  ark_error_t *err);

/*
 * ark_read_verify_member_final - Finalize and compare per-member hash.
 *
 * Returns 0 on hash match, -1 on mismatch/failure.
 * Failure contract: hash mismatch returns ARK_ERR_HASH_MEMBER via err.
 * Preconditions: all member chunks have been fed in order.
 *
 * See ARCHITECTURE.md section 16.4.
 */
int ark_read_verify_member_final(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err);

/*
 * ark_read_free - Release all resources owned by a read context.
 *
 * Returns no value.
 * Failure contract: none.
 * Preconditions: may be called after partial initialization or error.
 *
 * See ARCHITECTURE.md section 16.4.
 */
void ark_read_free(ark_read_ctx_t *ctx);

#endif /* ARK_ARCHIVE_H */
