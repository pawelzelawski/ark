/*
 * zwrap.c - zlib format (RFC 1950) over the Deflate component, and Adler-32.
 *
 * Implements ark_adler32 and the ark_zlib_* calls from zwrap.h on top of
 * the deflate.h encoders and decoders. Pure in-memory transformation: no
 * I/O, no allocation, no global or thread-local mutable state. See
 * ARCHITECTURE.md section 7.5.
 */

#include <stddef.h>
#include <stdint.h>

#include "deflate.h"
#include "zwrap.h"

/* Adler-32 modulus, and the most bytes summed before b can overflow. */
#define ARK_ADLER_MOD 65521U
#define ARK_ADLER_NMAX 5552U

/* RFC 1950 header fields. */
#define ARK_ZLIB_CM_DEFLATE 8U
#define ARK_ZLIB_FDICT 0x20U

/* Streaming phases of ark_zlib_enc_t and ark_zlib_dec_t. */
enum {
	ARK_ZP_NONE = 0, /* not begun */
	ARK_ZP_HEADER,
	ARK_ZP_DICTID,
	ARK_ZP_BODY,
	ARK_ZP_TRAILER,
	ARK_ZP_DONE,
	ARK_ZP_ERROR,
};

/*
 * Adler-32 (RFC 1950 section 8.2): a = 1 + sum of bytes, b = sum of the a
 * values, both modulo 65521. Summing at most 5552 bytes between reductions
 * keeps b below 2^32.
 */
uint32_t ark_adler32(uint32_t adler, const uint8_t *data, size_t len)
{
	uint32_t a;
	uint32_t b;
	size_t i;

	a = adler & 0xffffU;
	b = adler >> 16;
	i = 0U;
	while (i < len) {
		size_t end;

		end = len - i > ARK_ADLER_NMAX ? i + ARK_ADLER_NMAX : len;
		for (; i < end; i++) {
			a += data[i];
			b += a;
		}
		a %= ARK_ADLER_MOD;
		b %= ARK_ADLER_MOD;
	}
	return (b << 16) | a;
}

size_t ark_zlib_bound(size_t src_len)
{
	size_t bound;

	bound = ark_deflate_bound(src_len);
	if (bound == 0U || bound > SIZE_MAX - 6U)
		return 0U;
	return bound + 6U;
}

/* p + off, keeping a NULL buffer NULL (its size is then 0). */
static const uint8_t *in_at(const uint8_t *p, size_t off)
{
	return p == NULL ? NULL : p + off;
}

static uint8_t *out_at(uint8_t *p, size_t off)
{
	return p == NULL ? NULL : p + off;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
 * Write the 2-byte header for an encoder's parameters: CINFO from the
 * window bits, FLEVEL as zlib maps levels (0-1 fastest, 2-5 fast, 6
 * default, 7-9 maximum), FDICT when dict is set, FCHECK so that the header
 * read as a big-endian number is a multiple of 31.
 */
static void zlib_header(const ark_deflate_params_t *p, int dict, uint8_t *out)
{
	unsigned int cmf;
	unsigned int flg;

	cmf = ((p->window_bits - 8U) << 4) | ARK_ZLIB_CM_DEFLATE;
	flg = p->level < 2 ? 0U : p->level < 6 ? 1U : p->level == 6 ? 2U : 3U;
	flg <<= 6;
	if (dict)
		flg |= ARK_ZLIB_FDICT;
	flg += (31U - ((cmf << 8) | flg) % 31U) % 31U;
	out[0] = (uint8_t)cmf;
	out[1] = (uint8_t)flg;
}

/*
 * Check a header: method 8, window at most max_bits, check bits. Returns
 * 1 when valid.
 */
static int zlib_header_ok(const uint8_t *h, unsigned int max_bits)
{
	unsigned int cmf;

	cmf = h[0];
	return (cmf & 0x0fU) == ARK_ZLIB_CM_DEFLATE && (cmf >> 4) <= 7U &&
	       (cmf >> 4) + 8U <= max_bits && ((cmf << 8) | h[1]) % 31U == 0U;
}

ark_deflate_status_t ark_zlib_enc_oneshot(ark_deflate_enc_t *enc,
                                          const uint8_t *src, size_t src_len,
                                          uint8_t *dst, size_t dst_cap,
                                          size_t *dst_len)
{
	ark_deflate_params_t p;
	ark_deflate_status_t st;
	size_t bound;
	size_t n;

	if (dst_len == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*dst_len = 0U;
	if (enc == NULL || dst == NULL || (src == NULL && src_len != 0U))
		return ARK_DEFLATE_ERR_USAGE;
	ark_deflate_enc_params(enc, &p);
	if (src_len > p.max_input)
		return ARK_DEFLATE_ERR_USAGE;
	bound = ark_zlib_bound(src_len);
	if (bound == 0U || dst_cap < bound)
		return ARK_DEFLATE_ERR_OUTPUT;
	zlib_header(&p, 0, dst);
	st = ark_deflate_enc_oneshot(enc, src, src_len, dst + 2, dst_cap - 6U,
	                             &n);
	if (st != ARK_DEFLATE_OK)
		return st;
	put_be32(dst + 2 + n, ark_adler32(ARK_ADLER32_INIT, src, src_len));
	*dst_len = n + 6U;
	return ARK_DEFLATE_OK;
}

ark_deflate_status_t ark_zlib_dec_oneshot(const uint8_t *src, size_t src_len,
                                          size_t *src_used, uint8_t *dst,
                                          size_t dst_cap, size_t *dst_len)
{
	ark_deflate_status_t st;
	size_t used;
	size_t n;

	if (src_used == NULL || dst_len == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*src_used = 0U;
	*dst_len = 0U;
	if ((src == NULL && src_len != 0U) || (dst == NULL && dst_cap != 0U))
		return ARK_DEFLATE_ERR_USAGE;
	if (src_len < 2U || !zlib_header_ok(src, 15U) ||
	    (src[1] & ARK_ZLIB_FDICT) != 0U)
		return ARK_DEFLATE_ERR_DATA;
	st = ark_deflate_dec_oneshot(src + 2, src_len - 2U, &used, dst, dst_cap,
	                             &n);
	if (st != ARK_DEFLATE_OK)
		return st;
	if (src_len - 2U - used < 4U ||
	    get_be32(src + 2 + used) != ark_adler32(ARK_ADLER32_INIT, dst, n))
		return ARK_DEFLATE_ERR_DATA;
	*src_used = used + 6U;
	*dst_len = n;
	return ARK_DEFLATE_OK;
}

void ark_zlib_enc_begin(ark_zlib_enc_t *z, ark_deflate_enc_t *enc)
{
	ark_deflate_params_t p;

	if (z == NULL)
		return;
	z->enc = enc;
	z->adler = ARK_ADLER32_INIT;
	z->buf_pos = 0U;
	z->buf_len = 0U;
	z->phase = ARK_ZP_NONE;
	if (enc == NULL)
		return;
	ark_deflate_enc_params(enc, &p);
	if (!p.streaming)
		return;
	ark_deflate_enc_reset(enc, 0);
	zlib_header(&p, 0, z->buf);
	z->buf_len = 2U;
	z->phase = ARK_ZP_HEADER;
}

ark_deflate_status_t ark_zlib_enc_set_dict(ark_zlib_enc_t *z,
                                           const uint8_t *dict, size_t dict_len)
{
	ark_deflate_params_t p;
	ark_deflate_status_t st;

	if (z == NULL || z->phase != ARK_ZP_HEADER || z->buf_pos != 0U)
		return ARK_DEFLATE_ERR_USAGE;
	st = ark_deflate_enc_set_dict(z->enc, dict, dict_len);
	if (st != ARK_DEFLATE_OK)
		return st;
	ark_deflate_enc_params(z->enc, &p);
	zlib_header(&p, 1, z->buf);
	put_be32(z->buf + 2, ark_adler32(ARK_ADLER32_INIT, dict, dict_len));
	z->buf_len = 6U;
	return ARK_DEFLATE_OK;
}

/*
 * ark_zlib_enc_stream - Staged header or trailer bytes go out first; in
 * between, the Deflate encoder runs and the Adler-32 follows the input it
 * takes. See ARCHITECTURE.md section 7.5.
 */
ark_deflate_status_t ark_zlib_enc_stream(ark_zlib_enc_t *z, const uint8_t *in,
                                         size_t in_len, size_t *in_used,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_used,
                                         ark_deflate_flush_t flush)
{
	ark_deflate_status_t st;
	size_t ip;
	size_t op;

	if (in_used == NULL || out_used == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*in_used = 0U;
	*out_used = 0U;
	if (z == NULL || z->phase == ARK_ZP_NONE ||
	    (in == NULL && in_len != 0U) || (out == NULL && out_cap != 0U) ||
	    (flush != ARK_DEFLATE_FLUSH_NONE &&
	     flush != ARK_DEFLATE_FLUSH_SYNC &&
	     flush != ARK_DEFLATE_FLUSH_FINISH))
		return ARK_DEFLATE_ERR_USAGE;
	if (z->phase == ARK_ZP_DONE)
		return in_len != 0U ? ARK_DEFLATE_ERR_USAGE : ARK_DEFLATE_END;

	ip = 0U;
	op = 0U;
	for (;;) {
		size_t iu;
		size_t ou;

		while (z->buf_pos < z->buf_len && op < out_cap)
			out[op++] = z->buf[z->buf_pos++];
		if (z->buf_pos < z->buf_len) {
			st = ARK_DEFLATE_NEED_OUTPUT;
			break;
		}
		if (z->phase == ARK_ZP_HEADER) {
			z->phase = ARK_ZP_BODY;
			continue;
		}
		if (z->phase == ARK_ZP_TRAILER) {
			z->phase = ARK_ZP_DONE;
			st = ARK_DEFLATE_END;
			break;
		}
		st = ark_deflate_enc_stream(z->enc, in_at(in, ip), in_len - ip,
		                            &iu, out_at(out, op), out_cap - op,
		                            &ou, flush);
		z->adler = ark_adler32(z->adler, in_at(in, ip), iu);
		ip += iu;
		op += ou;
		if (st != ARK_DEFLATE_END)
			break;
		put_be32(z->buf, z->adler);
		z->buf_pos = 0U;
		z->buf_len = 4U;
		z->phase = ARK_ZP_TRAILER;
	}
	*in_used = ip;
	*out_used = op;
	return st;
}

void ark_zlib_dec_begin(ark_zlib_dec_t *z, ark_deflate_dec_t *dec)
{
	if (z == NULL)
		return;
	z->dec = dec;
	z->adler = ARK_ADLER32_INIT;
	z->dict_id = 0U;
	z->have_dict = 0;
	z->buf_len = 0U;
	z->phase = dec == NULL ? ARK_ZP_NONE : ARK_ZP_HEADER;
	ark_deflate_dec_reset(dec, 0);
}

ark_deflate_status_t ark_zlib_dec_set_dict(ark_zlib_dec_t *z,
                                           const uint8_t *dict, size_t dict_len)
{
	ark_deflate_status_t st;

	if (z == NULL || z->phase != ARK_ZP_HEADER || z->buf_len != 0U)
		return ARK_DEFLATE_ERR_USAGE;
	st = ark_deflate_dec_set_dict(z->dec, dict, dict_len);
	if (st != ARK_DEFLATE_OK)
		return st;
	z->dict_id = ark_adler32(ARK_ADLER32_INIT, dict, dict_len);
	z->have_dict = 1;
	return ARK_DEFLATE_OK;
}

/*
 * Move input bytes into z->buf until it holds want bytes. Returns 1 when
 * it does, 0 when the input ran out first.
 */
static int zlib_collect(ark_zlib_dec_t *z, const uint8_t *in, size_t in_len,
                        size_t *ip, unsigned int want)
{
	while (z->buf_len < want && *ip < in_len)
		z->buf[z->buf_len++] = in[(*ip)++];
	return z->buf_len == want;
}

/*
 * ark_zlib_dec_stream - Header, dictionary id, Deflate data (with the
 * Adler-32 of the output) and trailer in turn, each resumable at any byte.
 * See ARCHITECTURE.md section 7.5.
 */
ark_deflate_status_t ark_zlib_dec_stream(ark_zlib_dec_t *z, const uint8_t *in,
                                         size_t in_len, size_t *in_used,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_used)
{
	ark_deflate_status_t st;
	size_t ip;
	size_t op;

	if (in_used == NULL || out_used == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*in_used = 0U;
	*out_used = 0U;
	if (z == NULL || z->phase == ARK_ZP_NONE ||
	    (in == NULL && in_len != 0U) || (out == NULL && out_cap != 0U))
		return ARK_DEFLATE_ERR_USAGE;
	if (z->phase == ARK_ZP_ERROR)
		return ARK_DEFLATE_ERR_DATA;
	if (z->phase == ARK_ZP_DONE)
		return ARK_DEFLATE_END;

	ip = 0U;
	op = 0U;
	for (;;) {
		size_t iu;
		size_t ou;

		if (z->phase == ARK_ZP_HEADER) {
			if (!zlib_collect(z, in, in_len, &ip, 2U)) {
				st = ARK_DEFLATE_NEED_INPUT;
				break;
			}
			if (!zlib_header_ok(
			        z->buf, ark_deflate_dec_window_bits(z->dec)))
				goto bad;
			z->buf_len = 0U;
			if ((z->buf[1] & ARK_ZLIB_FDICT) != 0U) {
				if (!z->have_dict)
					goto bad;
				z->phase = ARK_ZP_DICTID;
				continue;
			}
			/* The stream does not use the dictionary given. */
			if (z->have_dict)
				ark_deflate_dec_reset(z->dec, 0);
			z->phase = ARK_ZP_BODY;
			continue;
		}
		if (z->phase == ARK_ZP_DICTID) {
			if (!zlib_collect(z, in, in_len, &ip, 4U)) {
				st = ARK_DEFLATE_NEED_INPUT;
				break;
			}
			if (get_be32(z->buf) != z->dict_id)
				goto bad;
			z->buf_len = 0U;
			z->phase = ARK_ZP_BODY;
			continue;
		}
		if (z->phase == ARK_ZP_TRAILER) {
			if (!zlib_collect(z, in, in_len, &ip, 4U)) {
				st = ARK_DEFLATE_NEED_INPUT;
				break;
			}
			if (get_be32(z->buf) != z->adler)
				goto bad;
			z->phase = ARK_ZP_DONE;
			st = ARK_DEFLATE_END;
			break;
		}
		st = ark_deflate_dec_stream(z->dec, in_at(in, ip), in_len - ip,
		                            &iu, out_at(out, op), out_cap - op,
		                            &ou);
		z->adler = ark_adler32(z->adler, out_at(out, op), ou);
		ip += iu;
		op += ou;
		if (st == ARK_DEFLATE_ERR_DATA)
			z->phase = ARK_ZP_ERROR;
		if (st != ARK_DEFLATE_END)
			break;
		z->buf_len = 0U;
		z->phase = ARK_ZP_TRAILER;
	}
	*in_used = ip;
	*out_used = op;
	return st;
bad:
	z->phase = ARK_ZP_ERROR;
	*in_used = ip;
	*out_used = op;
	return ARK_DEFLATE_ERR_DATA;
}
