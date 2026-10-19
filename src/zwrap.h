#ifndef ARK_ZWRAP_H
#define ARK_ZWRAP_H

/*
 * zwrap.h - zlib format (RFC 1950) over the Deflate component, and Adler-32.
 *
 * A zlib stream is a 2-byte header (method, window size, check bits,
 * preset-dictionary flag, level hint), an optional 4-byte dictionary id,
 * a raw RFC 1951 stream and the Adler-32 of the uncompressed data
 * (big-endian). The calls run on the encoders and decoders of deflate.h;
 * like them they do no I/O and no allocation, and all state is in caller
 * memory. ark itself does not use this layer.
 *
 * See ARCHITECTURE.md section 7.5 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

#include "deflate.h"

/*
 * ark_adler32 - Update a running Adler-32 with data[0..len) and return it.
 * Start with ARK_ADLER32_INIT. data may be NULL only when len is 0.
 */
#define ARK_ADLER32_INIT 1U
uint32_t ark_adler32(uint32_t adler, const uint8_t *data, size_t len);

/*
 * ark_zlib_bound - Return a safe output size for ark_zlib_enc_oneshot():
 * ark_deflate_bound(src_len) plus 6 bytes of header and trailer, or 0 when
 * that does not fit in size_t.
 */
size_t ark_zlib_bound(size_t src_len);

/*
 * ark_zlib_enc_oneshot - Compress src into one complete zlib stream with
 * enc (any encoder from ark_deflate_enc_init()). The header carries the
 * encoder's window bits and a level hint; no preset dictionary.
 *
 * Returns ARK_DEFLATE_OK; ARK_DEFLATE_ERR_USAGE or ARK_DEFLATE_ERR_OUTPUT
 * as ark_deflate_enc_oneshot() does, with dst_cap checked against
 * ark_zlib_bound(src_len). dst_len is 0 after a failure.
 */
ark_deflate_status_t ark_zlib_enc_oneshot(ark_deflate_enc_t *enc,
                                          const uint8_t *src, size_t src_len,
                                          uint8_t *dst, size_t dst_cap,
                                          size_t *dst_len);

/*
 * ark_zlib_dec_oneshot - Decode one complete zlib stream.
 *
 * src_used receives the bytes of the stream (header, Deflate data and
 * trailer); later bytes are left unread, so back-to-back streams (Git pack
 * entries) can be decoded one after another.
 *
 * Returns ARK_DEFLATE_OK; ARK_DEFLATE_ERR_DATA for a malformed header
 * (method other than 8, window above 32 KiB, check bits) or a stream that
 * needs a preset dictionary (use the streaming decoder), malformed or
 * truncated Deflate data, a missing or wrong Adler-32;
 * ARK_DEFLATE_ERR_OUTPUT when the output exceeds dst_cap;
 * ARK_DEFLATE_ERR_USAGE as ark_deflate_dec_oneshot(). src_used and dst_len
 * are 0 after a failure.
 */
ark_deflate_status_t ark_zlib_dec_oneshot(const uint8_t *src, size_t src_len,
                                          size_t *src_used, uint8_t *dst,
                                          size_t dst_cap, size_t *dst_len);

/*
 * ark_zlib_enc_t - Streaming zlib encoder: header and trailer state around
 * a streaming Deflate encoder (streaming = 1) that the caller owns. The
 * fields are private; the struct may live anywhere (stack, embedded), and
 * one serves one stream at a time, called sequentially.
 */
typedef struct {
	ark_deflate_enc_t *enc;
	uint32_t adler;
	int phase;
	unsigned int buf_len;
	unsigned int buf_pos;
	uint8_t buf[6];
} ark_zlib_enc_t;

/*
 * ark_zlib_enc_begin - Start a zlib stream on z over enc: resets enc
 * (ark_deflate_enc_reset(enc, 0); a zlib stream never refers into an
 * earlier one) and stages the header.
 */
void ark_zlib_enc_begin(ark_zlib_enc_t *z, ark_deflate_enc_t *enc);

/*
 * ark_zlib_enc_set_dict - Compress with a preset dictionary: sets the
 * header's dictionary flag and id (the Adler-32 of all of dict) and calls
 * ark_deflate_enc_set_dict(). Only right after ark_zlib_enc_begin().
 * Returns ARK_DEFLATE_OK or ARK_DEFLATE_ERR_USAGE.
 */
ark_deflate_status_t
ark_zlib_enc_set_dict(ark_zlib_enc_t *z, const uint8_t *dict, size_t dict_len);

/*
 * ark_zlib_enc_stream - Compress the next piece of the zlib stream; same
 * parameters and statuses as ark_deflate_enc_stream(). After FINISH the
 * trailer follows the Deflate data, and END means it is written too.
 * ERR_USAGE also for a NULL z or a z that was not begun on a streaming
 * encoder.
 */
ark_deflate_status_t ark_zlib_enc_stream(ark_zlib_enc_t *z, const uint8_t *in,
                                         size_t in_len, size_t *in_used,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_used,
                                         ark_deflate_flush_t flush);

/*
 * ark_zlib_dec_t - Streaming zlib decoder: header and trailer state around
 * a streaming Deflate decoder the caller owns. The fields are private; the
 * struct may live anywhere.
 */
typedef struct {
	ark_deflate_dec_t *dec;
	uint32_t adler;
	uint32_t dict_id;
	int have_dict;
	int phase;
	unsigned int buf_len;
	uint8_t buf[4];
} ark_zlib_dec_t;

/*
 * ark_zlib_dec_begin - Start decoding a zlib stream on z with dec: resets
 * dec (ark_deflate_dec_reset(dec, 0)).
 */
void ark_zlib_dec_begin(ark_zlib_dec_t *z, ark_deflate_dec_t *dec);

/*
 * ark_zlib_dec_set_dict - Provide the preset dictionary a stream may ask
 * for (its dictionary id must equal the Adler-32 of dict). Only right
 * after ark_zlib_dec_begin(). A stream without the dictionary flag is then
 * decoded without it. Returns ARK_DEFLATE_OK or ARK_DEFLATE_ERR_USAGE.
 */
ark_deflate_status_t
ark_zlib_dec_set_dict(ark_zlib_dec_t *z, const uint8_t *dict, size_t dict_len);

/*
 * ark_zlib_dec_stream - Decode the next piece of the zlib stream; same
 * parameters and statuses as ark_deflate_dec_stream(). END comes after the
 * trailer is checked; in_used then ends with the trailer, and later bytes
 * are not consumed. ERR_DATA (sticky until ark_zlib_dec_begin()) also for
 * a malformed header, a window larger than the decoder's, a dictionary
 * flag without a matching dictionary, and a wrong Adler-32.
 */
ark_deflate_status_t ark_zlib_dec_stream(ark_zlib_dec_t *z, const uint8_t *in,
                                         size_t in_len, size_t *in_used,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_used);

#endif /* ARK_ZWRAP_H */
