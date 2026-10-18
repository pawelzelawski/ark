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
 * ARK_DEFLATE_MAX_INPUT - Largest max_input an encoder accepts, so the largest
 * src_len of one ark_deflate_enc_oneshot call. The caller splits larger
 * payloads. See ARCHITECTURE.md section 7.4.
 */
#define ARK_DEFLATE_MAX_INPUT 1048576U

/* Compression levels accepted by ark_deflate_params_t.level (zlib numbering).
 */
#define ARK_DEFLATE_LEVEL_FAST 1
#define ARK_DEFLATE_LEVEL_DEFAULT 6

/* LZ77 window size range: 1 << window_bits bytes (RFC 1951, RFC 7692). */
#define ARK_DEFLATE_MIN_WINDOW_BITS 8U
#define ARK_DEFLATE_MAX_WINDOW_BITS 15U

/*
 * ark_deflate_status_t - Result of the encoder (and later decoder) calls.
 * END, NEED_INPUT and NEED_OUTPUT are reserved for the streaming calls.
 */
typedef enum {
	ARK_DEFLATE_OK = 0,
	ARK_DEFLATE_END,
	ARK_DEFLATE_NEED_INPUT,
	ARK_DEFLATE_NEED_OUTPUT,
	ARK_DEFLATE_ERR_USAGE,
	ARK_DEFLATE_ERR_DATA,
	ARK_DEFLATE_ERR_OUTPUT
} ark_deflate_status_t;

/*
 * ark_deflate_params_t - Encoder parameters; every field must be set.
 *
 * - level: ARK_DEFLATE_LEVEL_FAST or ARK_DEFLATE_LEVEL_DEFAULT.
 * - window_bits: ARK_DEFLATE_MIN_WINDOW_BITS..ARK_DEFLATE_MAX_WINDOW_BITS;
 *   no emitted distance exceeds 1 << window_bits.
 * - max_input: largest src_len per one-shot call, 1..ARK_DEFLATE_MAX_INPUT.
 * - streaming: must be 0 (streaming calls are not implemented yet).
 */
typedef struct {
	int level;
	unsigned int window_bits;
	size_t max_input;
	int streaming;
} ark_deflate_params_t;

/*
 * ark_deflate_enc_t - Opaque encoder state living in caller memory.
 *
 * The caller allocates ark_deflate_enc_size() bytes, aligned for uint64_t
 * (malloc memory qualifies), and passes them to ark_deflate_enc_init(). The
 * encoder holds pointers into that memory: it must not be copied or moved,
 * and it is released by freeing the memory. One encoder serves any number of
 * sequential calls, never two calls at once.
 */
typedef struct ark_deflate_enc ark_deflate_enc_t;

/*
 * ark_deflate_enc_size - Return the memory size an encoder needs.
 *
 * Parameters:
 * - params: encoder parameters.
 *
 * Returns the size in bytes, or 0 when params is NULL or invalid.
 * Failure contract: returns 0; does not fail otherwise.
 * Preconditions: none.
 */
size_t ark_deflate_enc_size(const ark_deflate_params_t *params);

/*
 * ark_deflate_enc_init - Initialize an encoder in caller memory.
 *
 * Parameters:
 * - mem: caller memory, aligned for uint64_t.
 * - mem_len: byte size of mem; at least ark_deflate_enc_size(params).
 * - params: encoder parameters, copied into the encoder.
 *
 * Returns the encoder (located in mem), or NULL on failure.
 * Failure contract: returns NULL for NULL arguments, invalid params,
 * misaligned mem or mem_len smaller than the size query; mem is unchanged.
 * Preconditions: mem is not in use by another encoder.
 */
ark_deflate_enc_t *ark_deflate_enc_init(void *mem, size_t mem_len,
                                        const ark_deflate_params_t *params);

/*
 * ark_deflate_enc_oneshot - Compress src into one complete raw RFC 1951
 * stream (final block marked).
 *
 * Parameters:
 * - enc: initialized encoder.
 * - src: input bytes; may be NULL only when src_len is 0.
 * - src_len: input size; at most the encoder's max_input.
 * - dst: output buffer owned by the caller.
 * - dst_cap: byte capacity of dst; at least ark_deflate_bound(src_len).
 * - dst_len: receives the compressed size (0 on failure).
 *
 * Returns ARK_DEFLATE_OK on success.
 * Failure contract: ARK_DEFLATE_ERR_USAGE for NULL arguments or src_len above
 * max_input; ARK_DEFLATE_ERR_OUTPUT when dst_cap is below
 * ark_deflate_bound(src_len). dst contents are unspecified after a failure;
 * the encoder stays valid for later calls.
 * Preconditions: enc was returned by ark_deflate_enc_init().
 */
ark_deflate_status_t ark_deflate_enc_oneshot(ark_deflate_enc_t *enc,
                                             const uint8_t *src, size_t src_len,
                                             uint8_t *dst, size_t dst_cap,
                                             size_t *dst_len);

/*
 * ark_deflate_bound - Return a safe upper bound for compressed output size.
 *
 * Parameters:
 * - src_len: uncompressed input size in bytes.
 *
 * Returns a maximum compressed size that is safe to use for dst allocation
 * before calling ark_deflate_enc_oneshot(): src_len plus 5 bytes per started
 * 65,535-byte stored block plus 1 byte of bit padding.
 * Failure contract: returns 0 when that bound is not representable in
 * size_t (src_len within a few bytes of SIZE_MAX). Every representable
 * bound is at least 6, so 0 never means "no output space needed".
 * Preconditions: none.
 */
size_t ark_deflate_bound(size_t src_len);

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
