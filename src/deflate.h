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

/*
 * ARK_DEFLATE_MAX_INPUT - Largest max_input an encoder accepts, so the largest
 * src_len of one ark_deflate_enc_oneshot call. The caller splits larger
 * payloads. See ARCHITECTURE.md section 7.4.
 */
#define ARK_DEFLATE_MAX_INPUT 1048576U

/*
 * Compression levels for ark_deflate_params_t.level, zlib numbering: 0
 * stores without compressing, 1 is the fastest and 9 the smallest.
 */
#define ARK_DEFLATE_LEVEL_NONE 0
#define ARK_DEFLATE_LEVEL_FAST 1
#define ARK_DEFLATE_LEVEL_DEFAULT 6
#define ARK_DEFLATE_LEVEL_BEST 9

/* LZ77 window size range: 1 << window_bits bytes (RFC 1951, RFC 7692). */
#define ARK_DEFLATE_MIN_WINDOW_BITS 8U
#define ARK_DEFLATE_MAX_WINDOW_BITS 15U

/*
 * ark_deflate_status_t - Result of the encoder and decoder calls.
 * END, NEED_INPUT and NEED_OUTPUT come only from the streaming calls.
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
 * - level: ARK_DEFLATE_LEVEL_NONE (0) .. ARK_DEFLATE_LEVEL_BEST (9).
 * - window_bits: ARK_DEFLATE_MIN_WINDOW_BITS..ARK_DEFLATE_MAX_WINDOW_BITS;
 *   no emitted distance exceeds 1 << window_bits.
 * - max_input: largest src_len per one-shot call, 1..ARK_DEFLATE_MAX_INPUT.
 *   A streaming encoder compresses its input in pieces of at most max_input
 *   bytes; a larger max_input gives larger blocks and better ratio, a
 *   smaller one less memory.
 * - streaming: 0 for one-shot calls only; 1 adds the history and the
 *   buffers ark_deflate_enc_stream() needs.
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
 * On a streaming encoder the call also resets the stream, as
 * ark_deflate_enc_reset(enc, 0) does.
 * Preconditions: enc was returned by ark_deflate_enc_init().
 */
ark_deflate_status_t ark_deflate_enc_oneshot(ark_deflate_enc_t *enc,
                                             const uint8_t *src, size_t src_len,
                                             uint8_t *dst, size_t dst_cap,
                                             size_t *dst_len);

/*
 * ark_deflate_flush_t - What ark_deflate_enc_stream() does once all of its
 * input is taken.
 *
 * - NONE: nothing; input may stay buffered in the encoder.
 * - SYNC: compress everything buffered and end it with an empty stored
 *   block (00 00 FF FF after byte alignment), so a decoder can produce all
 *   of the input so far. The stream continues (RFC 7692 messages).
 * - FINISH: compress everything buffered into the final block and end the
 *   stream.
 */
typedef enum {
	ARK_DEFLATE_FLUSH_NONE = 0,
	ARK_DEFLATE_FLUSH_SYNC,
	ARK_DEFLATE_FLUSH_FINISH
} ark_deflate_flush_t;

/*
 * ark_deflate_enc_stream - Compress the next piece of a raw RFC 1951
 * stream on an encoder initialized with streaming = 1.
 *
 * Parameters:
 * - enc: streaming encoder.
 * - in, in_len: the next input bytes; in may be NULL only when in_len is 0.
 * - in_used: receives the input bytes taken.
 * - out, out_cap: output space; out may be NULL only when out_cap is 0.
 * - out_used: receives the output bytes written.
 * - flush: see ark_deflate_flush_t.
 *
 * Matches reach back over earlier input of the stream, including input of
 * earlier messages after a SYNC, up to 1 << window_bits bytes.
 *
 * Returns:
 * - ARK_DEFLATE_NEED_INPUT (flush NONE): all input was taken.
 * - ARK_DEFLATE_OK (flush SYNC): all input was taken and the sync flush is
 *   completely written; the output so far ends at a byte boundary. Each
 *   SYNC call that returns OK writes one sync flush, also without input.
 * - ARK_DEFLATE_END (flush FINISH): the final block is completely written.
 *   Later calls return END until ark_deflate_enc_reset().
 * - ARK_DEFLATE_NEED_OUTPUT: out is full and output is waiting; call again
 *   with more space, the input not taken (in + in_used) and the same flush.
 * - ARK_DEFLATE_ERR_USAGE: NULL out-parameters, NULL enc, an encoder
 *   without streaming, a NULL buffer with a non-zero size, an unknown flush,
 *   or input after the stream ended; nothing is taken, and the stream is
 *   unchanged.
 * in_used and out_used are always set (0 on usage errors).
 * Preconditions: enc was returned by ark_deflate_enc_init().
 */
ark_deflate_status_t ark_deflate_enc_stream(ark_deflate_enc_t *enc,
                                            const uint8_t *in, size_t in_len,
                                            size_t *in_used, uint8_t *out,
                                            size_t out_cap, size_t *out_used,
                                            ark_deflate_flush_t flush);

/*
 * ark_deflate_enc_reset - Start a new stream on a streaming encoder. Input
 * still buffered and output not yet returned are dropped. With
 * keep_history non-zero the input of the previous stream stays as history
 * for matches (RFC 7692 context takeover; the decoder must keep its history
 * too); with 0 it is forgotten. A NULL enc or an encoder without streaming
 * is ignored.
 */
void ark_deflate_enc_reset(ark_deflate_enc_t *enc, int keep_history);

/*
 * ark_deflate_enc_set_dict - Use dict as preset history (zlib's
 * deflateSetDictionary): matches may refer into its last 1 << window_bits
 * bytes. The decoder must be given the same dictionary
 * (ark_deflate_dec_set_dict()).
 *
 * Returns ARK_DEFLATE_OK, or ARK_DEFLATE_ERR_USAGE for a NULL enc, an
 * encoder without streaming, NULL dict with dict_len non-zero, or a stream
 * that has already taken input or written output since init or reset. The
 * dictionary replaces any kept history.
 */
ark_deflate_status_t ark_deflate_enc_set_dict(ark_deflate_enc_t *enc,
                                              const uint8_t *dict,
                                              size_t dict_len);

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
 * ark_deflate_dec_oneshot - Decode one complete raw RFC 1951 stream.
 *
 * Parameters:
 * - src: compressed bytes; may be NULL only when src_len is 0. Bytes after
 *   the stream's final block are allowed and left unread.
 * - src_len: number of bytes available at src.
 * - src_used: receives the bytes the stream occupies, up to and including
 *   the byte holding the last bit of its final block.
 * - dst: output buffer owned by the caller; may be NULL only when dst_cap
 *   is 0.
 * - dst_cap: byte capacity of dst.
 * - dst_len: receives the decompressed size.
 *
 * Returns ARK_DEFLATE_OK on success.
 * Failure contract: ARK_DEFLATE_ERR_USAGE for NULL out-parameters or a NULL
 * buffer with a non-zero size; ARK_DEFLATE_ERR_DATA for malformed or
 * truncated input (including length 258 coded as 284 + 31, which RFC 1951
 * does not allow); ARK_DEFLATE_ERR_OUTPUT when the output exceeds dst_cap.
 * src_used and dst_len are 0 after a failure; dst contents are unspecified.
 * Preconditions: dst_cap must describe the full writable extent of dst.
 * Uses about 30 KiB of stack for decode tables.
 */
ark_deflate_status_t ark_deflate_dec_oneshot(const uint8_t *src, size_t src_len,
                                             size_t *src_used, uint8_t *dst,
                                             size_t dst_cap, size_t *dst_len);

/*
 * ark_deflate_dec_t - Opaque streaming decoder state in caller memory.
 *
 * The caller allocates ark_deflate_dec_size() bytes, aligned for uint64_t
 * (malloc memory qualifies), and passes them to ark_deflate_dec_init(). The
 * state holds the history window of the stream: it must not be copied or
 * moved, and it is released by freeing the memory. One decoder serves one
 * stream at a time, called sequentially.
 */
typedef struct ark_deflate_dec ark_deflate_dec_t;

/*
 * ark_deflate_dec_size - Return the memory size of a streaming decoder.
 *
 * Parameters:
 * - window_bits: ARK_DEFLATE_MIN_WINDOW_BITS..ARK_DEFLATE_MAX_WINDOW_BITS;
 *   the decoder keeps 1 << window_bits bytes of history and rejects
 *   distances beyond that.
 *
 * Returns the size in bytes (about 30 KiB plus the window), or 0 when
 * window_bits is out of range.
 * Failure contract: returns 0; does not fail otherwise.
 * Preconditions: none.
 */
size_t ark_deflate_dec_size(unsigned int window_bits);

/*
 * ark_deflate_dec_init - Initialize a streaming decoder in caller memory,
 * ready for the start of a stream with empty history.
 *
 * Returns the decoder (located in mem), or NULL for NULL mem, window_bits
 * out of range, misaligned mem or mem_len smaller than the size query.
 * Preconditions: mem is not in use by another decoder or encoder.
 */
ark_deflate_dec_t *ark_deflate_dec_init(void *mem, size_t mem_len,
                                        unsigned int window_bits);

/*
 * ark_deflate_dec_stream - Decode the next piece of a raw RFC 1951 stream.
 *
 * Parameters:
 * - dec: initialized decoder.
 * - in, in_len: the next input bytes; in may be NULL only when in_len is 0.
 * - in_used: receives the input bytes consumed.
 * - out, out_cap: output space; out may be NULL only when out_cap is 0.
 *   Nothing is written past out_cap, so a caller limits the total output
 *   (decompression bombs) through the space it offers.
 * - out_used: receives the output bytes written.
 *
 * Returns:
 * - ARK_DEFLATE_END: the final block is complete. in_used counts the bytes
 *   up to and including the one holding its last bit; later bytes are not
 *   consumed. Further calls return END until ark_deflate_dec_reset().
 * - ARK_DEFLATE_NEED_INPUT: all input was consumed and the stream is not
 *   finished. A stream that ends without a final block (RFC 7692 messages
 *   end in a sync flush) stops here, between blocks.
 * - ARK_DEFLATE_NEED_OUTPUT: out is full; call again with more space.
 * - ARK_DEFLATE_ERR_DATA: malformed input, including a distance beyond the
 *   window or the history so far, and length 258 coded as 284 + 31. The
 *   error is sticky until ark_deflate_dec_reset().
 * - ARK_DEFLATE_ERR_USAGE: NULL out-parameters, NULL dec, or a NULL buffer
 *   with a non-zero size; nothing is consumed.
 * in_used and out_used are always set (0 on usage errors).
 * Preconditions: dec was returned by ark_deflate_dec_init().
 */
ark_deflate_status_t ark_deflate_dec_stream(ark_deflate_dec_t *dec,
                                            const uint8_t *in, size_t in_len,
                                            size_t *in_used, uint8_t *out,
                                            size_t out_cap, size_t *out_used);

/*
 * ark_deflate_dec_reset - Start a new stream on dec: clears the block
 * state and any error. With keep_history non-zero the history window stays,
 * so the new stream may refer back into the previous one's output (RFC
 * 7692 context takeover across messages); with 0 it is emptied. A NULL dec
 * is ignored.
 */
void ark_deflate_dec_reset(ark_deflate_dec_t *dec, int keep_history);

/*
 * ark_deflate_dec_set_dict - Use dict as the history window (zlib's
 * inflateSetDictionary), so the stream may refer into its last
 * 1 << window_bits bytes. Call after init or reset, before the stream's
 * first input.
 *
 * Returns ARK_DEFLATE_OK, or ARK_DEFLATE_ERR_USAGE for a NULL dec, NULL
 * dict with dict_len non-zero, or a decoder that has taken input since init
 * or reset.
 */
ark_deflate_status_t ark_deflate_dec_set_dict(ark_deflate_dec_t *dec,
                                              const uint8_t *dict,
                                              size_t dict_len);

#endif /* ARK_DEFLATE_H */
