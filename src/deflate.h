#ifndef ARK_DEFLATE_H
#define ARK_DEFLATE_H

/*
 * deflate.h - Deflate compression API.
 *
 * This component implements RFC 1951 Deflate as a standalone pure-C layer.
 * No I/O and no component-owned allocation; the caller owns all buffers.
 *
 * See ARCHITECTURE.md section 7.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * ARK_CHUNK_SIZE - Maximum input size in bytes for one ark_deflate_compress
 * call.  The caller must split larger payloads into chunks of this size.
 * See ARCHITECTURE.md section 7.4.
 */
#define ARK_CHUNK_SIZE 1048576U

typedef enum { ARK_DEFLATE_DEFAULT, ARK_DEFLATE_FAST } ark_deflate_mode_t;

/*
 * ark_deflate_bound - Return a safe upper bound for compressed output size.
 *
 * src_len is the uncompressed input size in bytes.
 * Returns a maximum compressed size that is safe to use for dst allocation
 * before calling ark_deflate_compress.
 */
size_t ark_deflate_bound(size_t src_len);

/*
 * ark_deflate_compress - Compress one Deflate stream into caller-provided dst.
 *
 * src points to src_len uncompressed bytes. dst points to dst_cap writable
 * bytes. mode selects ARCHITECTURE.md section 7.4 compressor behavior.
 *
 * Preconditions:
 * - src_len must be at most 1048576 bytes (one ARK chunk).
 * - dst_cap must be at least ark_deflate_bound(src_len).
 *
 * Returns compressed byte count on success, -1 on failure.
 */
ssize_t ark_deflate_compress(const uint8_t *src, size_t src_len, uint8_t *dst,
                             size_t dst_cap, ark_deflate_mode_t mode);

/*
 * ark_deflate_decompress - Decompress one Deflate stream into dst.
 *
 * src points to src_len compressed bytes. dst points to dst_cap writable
 * bytes for the decompressed output.
 *
 * Returns decompressed byte count on success, -1 on failure.
 * This component does not produce ark_error_t codes. archive.c synthesizes
 * ARK_ERR_FMT_DATA when ark_deflate_decompress returns -1.
 */
ssize_t ark_deflate_decompress(const uint8_t *src, size_t src_len, uint8_t *dst,
                               size_t dst_cap);

#endif /* ARK_DEFLATE_H */
