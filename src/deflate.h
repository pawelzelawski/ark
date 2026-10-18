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
 * ARK_DEFLATE_MAX_INPUT - Maximum input size in bytes for one
 * ark_deflate_compress call. The compressor's working tables are sized for
 * it; the caller splits larger payloads. See ARCHITECTURE.md section 7.4.
 */
#define ARK_DEFLATE_MAX_INPUT 1048576U

typedef enum { ARK_DEFLATE_DEFAULT, ARK_DEFLATE_FAST } ark_deflate_mode_t;

/*
 * ark_deflate_bound - Return a safe upper bound for compressed output size.
 *
 * Parameters:
 * - src_len: uncompressed input size in bytes.
 *
 * Returns a maximum compressed size that is safe to use for dst allocation
 * before calling ark_deflate_compress(): src_len plus 5 bytes per started
 * 65,535-byte stored block plus 1 byte of bit padding.
 * Failure contract: returns 0 when that bound is not representable in
 * size_t (src_len within a few bytes of SIZE_MAX). Every representable
 * bound is at least 6, so 0 never means "no output space needed".
 * Preconditions: none.
 */
size_t ark_deflate_bound(size_t src_len);

/*
 * ark_deflate_compress - Compress one Deflate stream into caller-provided dst.
 *
 * Parameters:
 * - src: input byte buffer; may be NULL only when src_len is 0.
 * - src_len: number of input bytes; at most ARK_DEFLATE_MAX_INPUT.
 * - dst: writable output buffer owned by the caller.
 * - dst_cap: writable byte capacity of dst.
 * - mode: ARCHITECTURE.md section 7.4 compressor behavior selector.
 *
 * Returns compressed byte count on success, -1 on failure.
 * Failure contract: returns -1 for invalid arguments, unsupported mode, input
 * larger than ARK_DEFLATE_MAX_INPUT, or dst_cap smaller than
 * ark_deflate_bound().
 * Preconditions:
 * - src_len must be at most ARK_DEFLATE_MAX_INPUT bytes.
 * - dst_cap must be at least ark_deflate_bound(src_len).
 */
ssize_t ark_deflate_compress(const uint8_t *src, size_t src_len, uint8_t *dst,
                             size_t dst_cap, ark_deflate_mode_t mode);

/*
 * ark_deflate_decompress - Decompress one Deflate stream into dst.
 *
 * Parameters:
 * - src: compressed Deflate byte stream; may be NULL only when src_len is 0.
 * - src_len: compressed input byte count.
 * - dst: writable output buffer owned by the caller; may be NULL only when
 *   dst_cap is 0.
 * - dst_cap: maximum decompressed output bytes to write.
 *
 * Returns decompressed byte count on success, -1 on failure.
 * Failure contract: returns -1 for invalid arguments, malformed Deflate input,
 * reserved block types, invalid back-references, or output buffer overflow.
 * Preconditions: dst_cap must describe the full writable extent of dst.
 */
ssize_t ark_deflate_decompress(const uint8_t *src, size_t src_len, uint8_t *dst,
                               size_t dst_cap);

#endif /* ARK_DEFLATE_H */
