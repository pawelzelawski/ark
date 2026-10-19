#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deflate.h"
#include "zwrap.h"

/* xorshift32 step (fixed seeds). */
static uint32_t zt_rnd(uint32_t *x)
{
	*x ^= *x << 13;
	*x ^= *x >> 17;
	*x ^= *x << 5;
	return *x;
}

/* Word text with long repeats at many distances. */
static void zt_fill_text(uint8_t *buf, size_t len)
{
	static const char *const words[] = {
	    "loose ",  "object ", "pack ",  "blob ", "tree ",
	    "commit ", "zlib ",   "adler ", "a ",    "of\n",
	};
	uint32_t x;
	size_t i;

	x = 0x2468aceU;
	i = 0U;
	while (i < len) {
		const char *w;

		w = words[zt_rnd(&x) % (sizeof(words) / sizeof(words[0]))];
		while (*w != '\0' && i < len)
			buf[i++] = (uint8_t)*w++;
	}
}

/* zt_enc_new - Encoder in malloc memory (free() releases it); NULL on
 * failure. */
static ark_deflate_enc_t *zt_enc_new(int level, unsigned int window_bits,
                                     size_t max_input, int streaming)
{
	ark_deflate_params_t p;
	ark_deflate_enc_t *enc;
	void *mem;
	size_t size;

	p = (ark_deflate_params_t){level, window_bits, max_input, streaming};
	size = ark_deflate_enc_size(&p);
	mem = size == 0U ? NULL : malloc(size);
	if (mem == NULL)
		return NULL;
	enc = ark_deflate_enc_init(mem, size, &p);
	if (enc == NULL)
		free(mem);
	return enc;
}

/* zt_dec_new - Streaming decoder in malloc memory; NULL on failure. */
static ark_deflate_dec_t *zt_dec_new(unsigned int window_bits)
{
	ark_deflate_dec_t *dec;
	void *mem;
	size_t size;

	size = ark_deflate_dec_size(window_bits);
	mem = size == 0U ? NULL : malloc(size);
	if (mem == NULL)
		return NULL;
	dec = ark_deflate_dec_init(mem, size, window_bits);
	if (dec == NULL)
		free(mem);
	return dec;
}

/*
 * zt_enc_feed - Compress src with z in random input pieces (flush NONE,
 * or SYNC with 1 in sync_odds pieces when sync_odds is non-zero; FINISH
 * on the last) and random output pieces (out_piece 0) or out_piece bytes
 * per call. Input pieces and flushes come from *seed, output pieces from a
 * separate sequence, so the same *seed gives the same input calls for any
 * out_piece. Returns 0 at END with the size in *n, 1 otherwise.
 */
static int zt_enc_feed(ark_zlib_enc_t *z, const uint8_t *src, size_t len,
                       uint8_t *out, size_t cap, size_t out_piece,
                       unsigned int sync_odds, uint32_t *seed, size_t *n)
{
	uint32_t oseed;
	size_t ip;

	oseed = 0x0be7U;
	ip = 0U;
	*n = 0U;
	for (;;) {
		ark_deflate_flush_t f;
		ark_deflate_status_t st;
		size_t il;

		il = len - ip;
		if (il > 0U)
			il = 1U + zt_rnd(seed) % (il < 2000U ? il : 2000U);
		f = ip + il == len ? ARK_DEFLATE_FLUSH_FINISH
		    : sync_odds != 0U && zt_rnd(seed) % sync_odds == 0U
		        ? ARK_DEFLATE_FLUSH_SYNC
		        : ARK_DEFLATE_FLUSH_NONE;
		do {
			size_t ol;
			size_t iu;
			size_t ou;

			ol = cap - *n;
			if (out_piece != 0U && ol > out_piece)
				ol = out_piece;
			else if (out_piece == 0U && ol > 0U)
				ol = 1U +
				     zt_rnd(&oseed) % (ol < 500U ? ol : 500U);
			st = ark_zlib_enc_stream(z, src + ip, il, &iu, out + *n,
			                         ol, &ou, f);
			ip += iu;
			il -= iu;
			*n += ou;
		} while (st == ARK_DEFLATE_NEED_OUTPUT && *n < cap);
		if (f == ARK_DEFLATE_FLUSH_FINISH)
			return st == ARK_DEFLATE_END ? 0 : 1;
		if (st != (f == ARK_DEFLATE_FLUSH_SYNC
		               ? ARK_DEFLATE_OK
		               : ARK_DEFLATE_NEED_INPUT))
			return 1;
	}
}

/*
 * zt_dec_feed - Decode src with z in pieces of in_piece / out_piece bytes
 * (0 = random). Returns the last status; totals in *iu_total, *ou_total.
 */
static ark_deflate_status_t zt_dec_feed(ark_zlib_dec_t *z, const uint8_t *src,
                                        size_t len, uint8_t *out, size_t cap,
                                        size_t in_piece, size_t out_piece,
                                        uint32_t *seed, size_t *iu_total,
                                        size_t *ou_total)
{
	*iu_total = 0U;
	*ou_total = 0U;
	for (;;) {
		ark_deflate_status_t st;
		size_t il;
		size_t ol;
		size_t iu;
		size_t ou;

		il = len - *iu_total;
		ol = cap - *ou_total;
		if (in_piece != 0U && il > in_piece)
			il = in_piece;
		else if (in_piece == 0U && il > 0U)
			il = 1U + zt_rnd(seed) % (il < 700U ? il : 700U);
		if (out_piece != 0U && ol > out_piece)
			ol = out_piece;
		else if (out_piece == 0U && ol > 0U)
			ol = 1U + zt_rnd(seed) % (ol < 700U ? ol : 700U);
		st = ark_zlib_dec_stream(z, src + *iu_total, il, &iu,
		                         out + *ou_total, ol, &ou);
		*iu_total += iu;
		*ou_total += ou;
		if (st == ARK_DEFLATE_NEED_INPUT && *iu_total < len)
			continue;
		if (st == ARK_DEFLATE_NEED_OUTPUT && *ou_total < cap)
			continue;
		return st;
	}
}

/*
 * Adler-32 known values (RFC 1950 definition, checked with Python's zlib):
 * empty, "a", "abc", "Wikipedia", 5552 and 5553 bytes of 0xff (the
 * reduction boundary) and 1 MiB of 0xff; any split of the updates gives
 * the one-shot value.
 */
int test_zwrap_adler32_known(void)
{
	static const struct {
		size_t len;
		uint32_t adler;
	} ff[] = {{5552U, 0xf18f9b8cU},
	          {5553U, 0x8e299c8bU},
	          {1048576U, 0x8e88ef11U}};
	uint8_t *buf;
	uint32_t seed;
	size_t i;
	int rc;

	if (ark_adler32(ARK_ADLER32_INIT, NULL, 0U) != 1U ||
	    ark_adler32(ARK_ADLER32_INIT, (const uint8_t *)"a", 1U) !=
	        0x00620062U ||
	    ark_adler32(ARK_ADLER32_INIT, (const uint8_t *)"abc", 3U) !=
	        0x024d0127U ||
	    ark_adler32(ARK_ADLER32_INIT, (const uint8_t *)"Wikipedia", 9U) !=
	        0x11e60398U)
		return 1;
	buf = malloc(1048576U);
	if (buf == NULL)
		return 1;
	for (i = 0; i < 1048576U; i++)
		buf[i] = 0xffU;
	rc = 0;
	for (i = 0; i < sizeof(ff) / sizeof(ff[0]); i++) {
		if (ark_adler32(ARK_ADLER32_INIT, buf, ff[i].len) !=
		    ff[i].adler)
			rc = 1;
	}
	seed = 0xad1e5U;
	zt_fill_text(buf, 200000U);
	for (i = 0; rc == 0 && i < 20U; i++) {
		uint32_t a;
		size_t pos;

		a = ARK_ADLER32_INIT;
		pos = 0U;
		while (pos < 200000U) {
			size_t n;

			n = zt_rnd(&seed) % 12000U;
			if (n > 200000U - pos)
				n = 200000U - pos;
			a = ark_adler32(a, buf + pos, n);
			pos += n;
		}
		if (a != ark_adler32(ARK_ADLER32_INIT, buf, 200000U))
			rc = 1;
	}
	free(buf);
	return rc;
}

/*
 * Streams made by zlib and by Git decode: Python's
 * zlib.compress(b"hello world") and the loose object Git 2.x writes for
 * the blob "hello\n" ("blob 6\0hello\n"), each followed by junk bytes;
 * src_used is the stream size.
 */
int test_zwrap_decodes_zlib_and_git(void)
{
	static const uint8_t hello[] = {
	    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f,
	    0xca, 0x49, 0x01, 0x00, 0x1a, 0x0b, 0x04, 0x5d, 0xaa, 0xbb};
	static const uint8_t loose[] = {
	    0x78, 0x01, 0x4b, 0xca, 0xc9, 0x4f, 0x52, 0x30, 0x63, 0xc8, 0x48,
	    0xcd, 0xc9, 0xc9, 0xe7, 0x02, 0x00, 0x1d, 0xc5, 0x04, 0x14, 0x00};
	static const char blob[] = "blob 6\0hello\n";
	uint8_t out[64];
	size_t used;
	size_t n;

	if (ark_zlib_dec_oneshot(hello, sizeof(hello), &used, out, sizeof(out),
	                         &n) != ARK_DEFLATE_OK ||
	    used != sizeof(hello) - 2U || n != 11U ||
	    memcmp(out, "hello world", 11U) != 0)
		return 1;
	if (ark_zlib_dec_oneshot(loose, sizeof(loose), &used, out, sizeof(out),
	                         &n) != ARK_DEFLATE_OK ||
	    used != sizeof(loose) - 1U || n != sizeof(blob) - 1U ||
	    memcmp(out, blob, n) != 0)
		return 1;
	return 0;
}

/*
 * One-shot round trip at levels 0, 1, 6, 9 and window bits 8, 12, 15:
 * header CMF/FLG as zlib writes them (78 01 / 78 9C / 78 DA at window 15;
 * check bits valid everywhere), Adler-32 trailer, and back-to-back streams
 * plus junk decode one after another by src_used (Git pack entries).
 */
int test_zwrap_oneshot_round_trip(void)
{
	static const int levels[] = {0, 1, 6, 9};
	static const uint8_t flg15[] = {0x01, 0x01, 0x9c, 0xda};
	static const unsigned int wbs[] = {8U, 12U, 15U};
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	size_t len;
	size_t cap;
	size_t li;
	size_t wi;
	int rc;

	rc = 1;
	len = 50000U;
	cap = 3U * ark_zlib_bound(len) + 3U;
	in = malloc(len);
	comp = malloc(cap);
	out = malloc(len);
	if (in == NULL || comp == NULL || out == NULL)
		goto done;
	zt_fill_text(in, len);
	for (li = 0; li < 4U; li++) {
		for (wi = 0; wi < 3U; wi++) {
			ark_deflate_enc_t *enc;
			size_t sizes[3];
			size_t pos;
			size_t k;
			int ok;

			enc = zt_enc_new(levels[li], wbs[wi], len, 0);
			ok = enc != NULL;
			pos = 0U;
			/* Three streams: 50000, 0 and 7 input bytes. */
			for (k = 0; ok && k < 3U; k++) {
				size_t m;

				m = k == 0U ? len : k == 1U ? 0U : 7U;
				ok =
				    ark_zlib_enc_oneshot(
				        enc, in, m, comp + pos, cap - pos,
				        &sizes[k]) == ARK_DEFLATE_OK &&
				    comp[pos] == (((wbs[wi] - 8U) << 4) | 8U) &&
				    ((((unsigned int)comp[pos] << 8) |
				      comp[pos + 1U]) %
				     31U) == 0U &&
				    (wbs[wi] != 15U ||
				     comp[pos + 1U] == flg15[li]);
				pos += sizes[k];
			}
			comp[pos++] = 0x5aU;
			pos = 0U;
			for (k = 0; ok && k < 3U; k++) {
				size_t m;
				size_t used;
				size_t n;

				m = k == 0U ? len : k == 1U ? 0U : 7U;
				ok = ark_zlib_dec_oneshot(
				         comp + pos, cap - pos, &used, out, len,
				         &n) == ARK_DEFLATE_OK &&
				     used == sizes[k] && n == m &&
				     memcmp(out, in, m) == 0;
				pos += used;
			}
			free(enc);
			if (!ok)
				goto done;
		}
	}
	rc = 0;
done:
	free(out);
	free(comp);
	free(in);
	return rc;
}

/*
 * Malformed streams are ERR_DATA: method 7 and window 64 KiB (CINFO 8),
 * each with valid check bits; bad check bits, the dictionary flag (one-shot), a
 * wrong Adler-32, every truncation of the trailer and a truncated body; an
 * output buffer one byte short is ERR_OUTPUT; NULL arguments and an encoder
 * input above max_input are ERR_USAGE; a too small dst for the encoder is
 * ERR_OUTPUT.
 */
int test_zwrap_oneshot_errors(void)
{
	static const uint8_t ok_stream[] = {
	    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf,
	    0x2f, 0xca, 0x49, 0x01, 0x00, 0x1a, 0x0b, 0x04, 0x5d};
	ark_deflate_enc_t *enc;
	uint8_t s[sizeof(ok_stream)];
	uint8_t out[16];
	uint8_t comp[64];
	size_t used;
	size_t n;
	size_t k;
	int rc;

	rc = 0;
	memcpy(s, ok_stream, sizeof(s));
	/* Method 7 and CINFO 8, each with valid check bits (FLEVEL 2). */
	s[0] = 0x77U;
	s[1] = (uint8_t)(0x80U + (31U - (0x7780U % 31U)) % 31U);
	if (ark_zlib_dec_oneshot(s, sizeof(s), &used, out, sizeof(out), &n) !=
	    ARK_DEFLATE_ERR_DATA)
		rc = 1;
	s[0] = 0x88U;
	s[1] = (uint8_t)(0x80U + (31U - (0x8880U % 31U)) % 31U);
	if (ark_zlib_dec_oneshot(s, sizeof(s), &used, out, sizeof(out), &n) !=
	    ARK_DEFLATE_ERR_DATA)
		rc = 1;
	s[0] = 0x78U;
	s[1] = 0x9dU; /* check bits */
	if (ark_zlib_dec_oneshot(s, sizeof(s), &used, out, sizeof(out), &n) !=
	    ARK_DEFLATE_ERR_DATA)
		rc = 1;
	s[1] = 0xbbU; /* 0x78bb = FDICT, level 2, valid check bits */
	if (ark_zlib_dec_oneshot(s, sizeof(s), &used, out, sizeof(out), &n) !=
	    ARK_DEFLATE_ERR_DATA)
		rc = 1;
	memcpy(s, ok_stream, sizeof(s));
	s[sizeof(s) - 1U] ^= 1U;
	if (ark_zlib_dec_oneshot(s, sizeof(s), &used, out, sizeof(out), &n) !=
	        ARK_DEFLATE_ERR_DATA ||
	    used != 0U || n != 0U)
		rc = 1;
	for (k = 0; k < sizeof(ok_stream); k++) {
		if (ark_zlib_dec_oneshot(ok_stream, k, &used, out, sizeof(out),
		                         &n) != ARK_DEFLATE_ERR_DATA)
			rc = 1;
	}
	if (ark_zlib_dec_oneshot(ok_stream, sizeof(ok_stream), &used, out, 10U,
	                         &n) != ARK_DEFLATE_ERR_OUTPUT ||
	    ark_zlib_dec_oneshot(ok_stream, sizeof(ok_stream), NULL, out,
	                         sizeof(out), &n) != ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_dec_oneshot(NULL, 3U, &used, out, sizeof(out), &n) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_dec_oneshot(ok_stream, sizeof(ok_stream), &used, NULL, 5U,
	                         &n) != ARK_DEFLATE_ERR_USAGE)
		rc = 1;

	enc = zt_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 32U, 0);
	if (enc == NULL ||
	    ark_zlib_enc_oneshot(enc, ok_stream, 33U, comp, sizeof(comp), &n) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_oneshot(enc, ok_stream, 10U, comp,
	                         ark_zlib_bound(10U) - 1U,
	                         &n) != ARK_DEFLATE_ERR_OUTPUT ||
	    n != 0U ||
	    ark_zlib_enc_oneshot(enc, ok_stream, 10U, NULL, sizeof(comp), &n) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_oneshot(NULL, ok_stream, 10U, comp, sizeof(comp),
	                         &n) != ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_bound(SIZE_MAX) != 0U ||
	    ark_zlib_bound(0U) != ark_deflate_bound(0U) + 6U)
		rc = 1;
	free(enc);
	return rc;
}

/*
 * Streaming zlib at window 15 and 10, levels 6 and 1, with random SYNC
 * flushes: the same bytes with random and one-byte output pieces (the
 * header and trailer split), one-shot decodable, and decoded by the
 * streaming zlib decoder whole, one input byte per call and in random
 * pieces, followed by junk: END with in_used exactly the stream size.
 */
int test_zwrap_stream_round_trip(void)
{
	static const unsigned int wbs[] = {15U, 10U};
	static const int levels[] = {ARK_DEFLATE_LEVEL_DEFAULT,
	                             ARK_DEFLATE_LEVEL_FAST};
	uint8_t *in;
	uint8_t *comp;
	uint8_t *comp2;
	uint8_t *out;
	uint32_t seed;
	size_t len;
	size_t cap;
	size_t k;
	int rc;

	rc = 1;
	seed = 0x21b1U;
	len = 40000U;
	cap = 50000U;
	in = malloc(len);
	comp = malloc(cap);
	comp2 = malloc(cap);
	out = malloc(len);
	if (in == NULL || comp == NULL || comp2 == NULL || out == NULL)
		goto done;
	zt_fill_text(in, len);
	for (k = 0; k < 4U; k++) {
		ark_deflate_enc_t *enc;
		ark_deflate_dec_t *dec;
		ark_zlib_enc_t ze;
		ark_zlib_dec_t zd;
		uint32_t s2;
		size_t n;
		size_t n2;
		size_t p;
		int ok;

		enc = zt_enc_new(levels[k & 1U], wbs[k >> 1], 4096U, 1);
		dec = zt_dec_new(wbs[k >> 1]);
		ok = enc != NULL && dec != NULL;
		s2 = seed;
		n = 0U;
		if (ok) {
			ark_zlib_enc_begin(&ze, enc);
			ok = zt_enc_feed(&ze, in, len, comp, cap, 0U, 5U, &seed,
			                 &n) == 0;
		}
		if (ok) {
			/* Same input pieces and flushes (same seed), one
			 * output byte per call. */
			ark_zlib_enc_begin(&ze, enc);
			ok = zt_enc_feed(&ze, in, len, comp2, cap, 1U, 5U, &s2,
			                 &n2) == 0 &&
			     n2 == n && memcmp(comp, comp2, n) == 0;
		}
		if (ok) {
			size_t used;
			size_t dn;

			ok = ark_zlib_dec_oneshot(comp, n, &used, out, len,
			                          &dn) == ARK_DEFLATE_OK &&
			     used == n && dn == len &&
			     memcmp(out, in, len) == 0;
		}
		comp[n] = 0x11U;
		comp[n + 1U] = 0x22U;
		for (p = 0; ok && p < 3U; p++) {
			size_t iu;
			size_t ou;

			ark_zlib_dec_begin(&zd, dec);
			ok = zt_dec_feed(&zd, comp, n + 2U, out, len,
			                 p == 0U   ? SIZE_MAX
			                 : p == 1U ? 1U
			                           : 0U,
			                 0U, &seed, &iu,
			                 &ou) == ARK_DEFLATE_END &&
			     iu == n && ou == len && memcmp(out, in, len) == 0;
		}
		free(dec);
		free(enc);
		if (!ok)
			goto done;
	}
	rc = 0;
done:
	free(out);
	free(comp2);
	free(comp);
	free(in);
	return rc;
}

/*
 * Preset dictionary: the header has FDICT and the dictionary's Adler-32;
 * the one-shot decoder refuses it; the streaming decoder decodes it with
 * the dictionary and refuses it without one or with another (ERR_DATA,
 * sticky until begin), also when the other dictionary differs only
 * outside the window (the dictionary id alone tells them apart); a stream
 * without FDICT decodes even though a dictionary was given, and cannot
 * refer into it (the same body under a header without FDICT is
 * ERR_DATA); and a zlib-made stream (Python, zdict=b"hello
 * world hello") decodes with the same dictionary.
 */
int test_zwrap_stream_dictionary(void)
{
	static const uint8_t py[] = {0x78, 0xf9, 0x3b, 0x20, 0x06, 0x91,
	                             0xcb, 0x40, 0x17, 0x80, 0xb0, 0x01,
	                             0x69, 0xe7, 0x08, 0xd9};
	static const char py_dict[] = "hello world hello";
	static const char py_msg[] = "hello world hello world";
	ark_deflate_enc_t *enc;
	ark_deflate_dec_t *dec;
	ark_zlib_enc_t ze;
	ark_zlib_dec_t zd;
	uint8_t *big;
	uint8_t *big2;
	uint8_t dict[3000];
	uint8_t other[3000];
	uint8_t comp[4000];
	uint8_t out[3000];
	uint32_t seed;
	size_t n;
	size_t iu;
	size_t ou;
	int rc;

	rc = 1;
	seed = 0xd1c7U;
	big = NULL;
	big2 = NULL;
	zt_fill_text(dict, sizeof(dict));
	memcpy(other, dict, sizeof(other));
	other[0] ^= 1U;
	enc = zt_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 4096U, 1);
	dec = zt_dec_new(15U);
	if (enc == NULL || dec == NULL)
		goto done;
	ark_zlib_enc_begin(&ze, enc);
	if (ark_zlib_enc_set_dict(&ze, dict, sizeof(dict)) != ARK_DEFLATE_OK ||
	    zt_enc_feed(&ze, dict, sizeof(dict), comp, sizeof(comp), 0U, 0U,
	                &seed, &n) != 0 ||
	    (comp[1] & 0x20U) == 0U ||
	    (((unsigned int)comp[0] << 8) | comp[1]) % 31U != 0U ||
	    ((uint32_t)comp[2] << 24 | (uint32_t)comp[3] << 16 |
	     (uint32_t)comp[4] << 8 | comp[5]) !=
	        ark_adler32(ARK_ADLER32_INIT, dict, sizeof(dict)) ||
	    n > 100U ||
	    ark_zlib_dec_oneshot(comp, n, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_ERR_DATA)
		goto done;

	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, dict, sizeof(dict)) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp, n, out, sizeof(out), 0U, 0U, &seed, &iu,
	                &ou) != ARK_DEFLATE_END ||
	    iu != n || ou != sizeof(dict) || memcmp(out, dict, ou) != 0)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (zt_dec_feed(&zd, comp, n, out, sizeof(out), SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA ||
	    ark_zlib_dec_stream(&zd, comp, n, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, other, sizeof(other)) !=
	        ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp, n, out, sizeof(out), SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;

	/* The body under a header without FDICT (78 9C): its matches into
	 * the dictionary are out of range. */
	comp[4] = 0x78U;
	comp[5] = 0x9cU;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, dict, sizeof(dict)) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp + 4, n - 4U, out, sizeof(out), SIZE_MAX,
	                SIZE_MAX, &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;

	/* Dictionaries of 40000 bytes differing only in byte 0, outside
	 * the 32 KiB window. */
	big = malloc(40000U);
	big2 = malloc(40000U);
	if (big == NULL || big2 == NULL)
		goto done;
	zt_fill_text(big, 40000U);
	memcpy(big2, big, 40000U);
	big2[0] ^= 1U;
	ark_zlib_enc_begin(&ze, enc);
	if (ark_zlib_enc_set_dict(&ze, big, 40000U) != ARK_DEFLATE_OK ||
	    zt_enc_feed(&ze, big + 39000, 1000U, comp, sizeof(comp), 0U, 0U,
	                &seed, &n) != 0)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, big2, 40000U) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp, n, out, sizeof(out), SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, big, 40000U) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp, n, out, sizeof(out), SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_END ||
	    ou != 1000U || memcmp(out, big + 39000, 1000U) != 0)
		goto done;

	/* No FDICT in the stream: the given dictionary is dropped. */
	ark_zlib_enc_begin(&ze, enc);
	if (zt_enc_feed(&ze, dict, 500U, comp, sizeof(comp), 0U, 0U, &seed,
	                &n) != 0)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, dict, sizeof(dict)) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, comp, n, out, sizeof(out), 0U, 0U, &seed, &iu,
	                &ou) != ARK_DEFLATE_END ||
	    ou != 500U || memcmp(out, dict, 500U) != 0)
		goto done;

	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_set_dict(&zd, (const uint8_t *)py_dict,
	                          sizeof(py_dict) - 1U) != ARK_DEFLATE_OK ||
	    zt_dec_feed(&zd, py, sizeof(py), out, sizeof(out), 1U, 1U, &seed,
	                &iu, &ou) != ARK_DEFLATE_END ||
	    iu != sizeof(py) || ou != sizeof(py_msg) - 1U ||
	    memcmp(out, py_msg, ou) != 0)
		goto done;
	rc = 0;
done:
	free(big2);
	free(big);
	free(dec);
	free(enc);
	return rc;
}

/*
 * Streaming errors and usage: a header asking for a larger window than
 * the decoder has (also for data needing no window), FDICT without a
 * dictionary (id 0), and a wrong trailer are ERR_DATA and stay so until
 * begin; a truncated stream is NEED_INPUT; END repeats without consuming
 * later bytes. A wrapper begun without an encoder or on a one-shot
 * encoder, NULL arguments and input after END are ERR_USAGE; set_dict
 * after the header started going out is ERR_USAGE on both sides.
 */
int test_zwrap_stream_errors(void)
{
	static const uint8_t hello[] = {
	    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf,
	    0x2f, 0xca, 0x49, 0x01, 0x00, 0x1a, 0x0b, 0x04, 0x5d};
	uint8_t fdict[sizeof(hello) + 4U];
	ark_deflate_enc_t *enc;
	ark_deflate_enc_t *plain;
	ark_deflate_dec_t *dec9;
	ark_deflate_dec_t *dec;
	ark_zlib_enc_t ze;
	ark_zlib_dec_t zd;
	uint8_t text[2000];
	uint8_t comp[2100];
	uint8_t out[2000];
	uint32_t seed;
	size_t n;
	size_t iu;
	size_t ou;
	int rc;

	rc = 1;
	seed = 0xe44U;
	zt_fill_text(text, sizeof(text));
	enc = zt_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 4096U, 1);
	plain = zt_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 4096U, 0);
	dec9 = zt_dec_new(9U);
	dec = zt_dec_new(15U);
	if (enc == NULL || plain == NULL || dec9 == NULL || dec == NULL)
		goto done;
	ark_zlib_enc_begin(&ze, enc);
	if (zt_enc_feed(&ze, text, sizeof(text), comp, sizeof(comp), 0U, 0U,
	                &seed, &n) != 0 ||
	    ark_zlib_enc_stream(&ze, NULL, 0U, &iu, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_FINISH) != ARK_DEFLATE_END ||
	    ark_zlib_enc_stream(&ze, text, 1U, &iu, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_FINISH) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    iu != 0U)
		goto done;

	/* A window-15 header on a window-9 decoder, though the data needs
	 * no window ("hello world"); the error stays, also for input that
	 * would decode by itself (the bare Deflate data). */
	ark_zlib_dec_begin(&zd, dec9);
	if (ark_zlib_dec_stream(&zd, hello, sizeof(hello), &iu, out,
	                        sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA ||
	    ark_zlib_dec_stream(&zd, hello + 2, sizeof(hello) - 2U, &iu, out,
	                        sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (zt_dec_feed(&zd, hello, sizeof(hello), out, sizeof(out), 1U, 1U,
	                &seed, &iu, &ou) != ARK_DEFLATE_END ||
	    ou != 11U)
		goto done;

	/* FDICT with dictionary id 0 and no dictionary given. */
	memcpy(fdict, hello, sizeof(hello));
	fdict[1] = 0xbbU;
	memset(fdict + 2, 0, 4U);
	memcpy(fdict + 6, hello + 2, sizeof(hello) - 2U);
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_stream(&zd, fdict, sizeof(fdict), &iu, out,
	                        sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;

	/* Truncated, then wrong trailer, then END repeated. */
	ark_zlib_dec_begin(&zd, dec);
	if (zt_dec_feed(&zd, comp, n - 1U, out, sizeof(out), 0U, 0U, &seed, &iu,
	                &ou) != ARK_DEFLATE_NEED_INPUT ||
	    iu != n - 1U)
		goto done;
	comp[n - 1U] ^= 0x80U;
	if (ark_zlib_dec_stream(&zd, comp + n - 1U, 1U, &iu, out, sizeof(out),
	                        &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	comp[n - 1U] ^= 0x80U;
	ark_zlib_dec_begin(&zd, dec);
	if (zt_dec_feed(&zd, comp, n, out, sizeof(out), SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_END ||
	    ark_zlib_dec_stream(&zd, comp, n, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_END ||
	    iu != 0U || ou != 0U)
		goto done;

	/* Usage. */
	ark_zlib_enc_begin(&ze, plain);
	if (ark_zlib_enc_stream(&ze, text, 1U, &iu, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	    ARK_DEFLATE_ERR_USAGE)
		goto done;
	ark_zlib_enc_begin(&ze, NULL);
	ark_zlib_dec_begin(&zd, NULL);
	ark_zlib_enc_begin(NULL, enc);
	ark_zlib_dec_begin(NULL, dec);
	if (ark_zlib_enc_stream(&ze, text, 1U, &iu, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_dec_stream(&zd, comp, 1U, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_stream(NULL, text, 1U, &iu, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_dec_stream(NULL, comp, 1U, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_ERR_USAGE)
		goto done;
	ark_zlib_enc_begin(&ze, enc);
	if (ark_zlib_enc_stream(&ze, text, 1U, NULL, comp, sizeof(comp), &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_stream(&ze, text, 1U, &iu, NULL, 3U, &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_stream(&ze, text, 1U, &iu, comp, sizeof(comp), &ou,
	                        (ark_deflate_flush_t)9) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_enc_stream(&ze, text, 1U, &iu, comp, 1U, &ou,
	                        ARK_DEFLATE_FLUSH_NONE) !=
	        ARK_DEFLATE_NEED_OUTPUT ||
	    ou != 1U ||
	    ark_zlib_enc_set_dict(&ze, text, 10U) != ARK_DEFLATE_ERR_USAGE)
		goto done;
	ark_zlib_dec_begin(&zd, dec);
	if (ark_zlib_dec_stream(&zd, comp, 1U, &iu, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_NEED_INPUT ||
	    ark_zlib_dec_set_dict(&zd, text, 10U) != ARK_DEFLATE_ERR_USAGE ||
	    ark_zlib_dec_stream(&zd, comp, 1U, NULL, out, sizeof(out), &ou) !=
	        ARK_DEFLATE_ERR_USAGE)
		goto done;
	rc = 0;
done:
	free(dec);
	free(dec9);
	free(plain);
	free(enc);
	return rc;
}
