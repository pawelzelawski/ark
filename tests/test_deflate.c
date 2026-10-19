#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "deflate.h"

/* ARK_DEFLATE_TEST-only accessors defined in src/deflate.c. */
int ark_deflate_test_length_symbol(size_t, unsigned int *, unsigned int *,
                                   uint16_t *);
int ark_deflate_test_limit_lengths(const uint32_t *, size_t, uint8_t *,
                                   unsigned int);
int ark_deflate_test_cl_plan(const uint8_t *, size_t, const uint8_t *, size_t,
                             uint8_t[19], size_t *);
int ark_deflate_test_header_bits(const uint8_t *, size_t, const uint8_t *,
                                 size_t, size_t *, size_t *);
ark_deflate_status_t ark_deflate_test_decompress_window(const uint8_t *, size_t,
                                                        uint8_t *, size_t,
                                                        unsigned int, size_t *);
size_t ark_deflate_test_table_cap(int);
int ark_deflate_test_table_fits(const uint8_t *, size_t, int, size_t);
void ark_deflate_test_token_symbols(size_t, size_t, unsigned int *,
                                    unsigned int *);
size_t ark_deflate_test_equal_low_bytes(uint64_t);

static void fill_pattern(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)(i % 251U);
}

static void fill_randomish(uint8_t *buf, size_t len)
{
	uint32_t x;
	size_t i;

	x = 0x9e3779b9U;
	for (i = 0; i < len; i++) {
		x = x * 1664525U + 1013904223U;
		buf[i] = (uint8_t)(x >> 24);
	}
}

/*
 * test_enc_new - Allocate and initialize an encoder; NULL on failure. The
 * encoder lives at the start of the allocation, so free() releases it.
 */
static ark_deflate_enc_t *test_enc_new(int level, unsigned int window_bits,
                                       size_t max_input)
{
	ark_deflate_params_t params;
	ark_deflate_enc_t *enc;
	void *mem;
	size_t size;

	params = (ark_deflate_params_t){level, window_bits, max_input, 0};
	size = ark_deflate_enc_size(&params);
	if (size == 0U)
		return NULL;
	mem = malloc(size);
	if (mem == NULL)
		return NULL;
	enc = ark_deflate_enc_init(mem, size, &params);
	if (enc == NULL)
		free(mem);
	return enc;
}

/*
 * test_deflate_compress - Compress src at level with a fresh window-15
 * encoder; return the compressed size or -1. Shared with test_archive.c.
 */
ssize_t test_deflate_compress(const uint8_t *src, size_t src_len, uint8_t *dst,
                              size_t dst_cap, int level)
{
	ark_deflate_enc_t *enc;
	size_t dst_len;
	ark_deflate_status_t st;

	enc = test_enc_new(level, 15U, ARK_DEFLATE_MAX_INPUT);
	if (enc == NULL)
		return -1;
	st = ark_deflate_enc_oneshot(enc, src, src_len, dst, dst_cap, &dst_len);
	free(enc);
	return st == ARK_DEFLATE_OK ? (ssize_t)dst_len : -1;
}

/*
 * test_deflate_decompress - Decode one stream with ark_deflate_dec_oneshot;
 * return the decompressed size or -1 for any failure status. Bytes after
 * the stream are ignored here; tests of src_used check it directly.
 */
static ssize_t test_deflate_decompress(const uint8_t *src, size_t src_len,
                                       uint8_t *dst, size_t dst_cap)
{
	size_t used;
	size_t n;

	if (ark_deflate_dec_oneshot(src, src_len, &used, dst, dst_cap, &n) !=
	    ARK_DEFLATE_OK)
		return -1;
	return (ssize_t)n;
}

static int round_trip(const uint8_t *src, size_t src_len)
{
	uint8_t *comp;
	uint8_t *out;
	size_t bound;
	ssize_t comp_len;
	ssize_t out_len;

	bound = ark_deflate_bound(src_len);
	comp = malloc(bound);
	if (comp == NULL)
		return 1;
	out = malloc(src_len == 0U ? 1U : src_len);
	if (out == NULL) {
		free(comp);
		return 1;
	}

	comp_len = test_deflate_compress(src, src_len, comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len < 0 || (size_t)comp_len > bound) {
		free(out);
		free(comp);
		return 1;
	}

	out_len = test_deflate_decompress(comp, (size_t)comp_len, out, src_len);
	if (out_len < 0 || (size_t)out_len != src_len) {
		free(out);
		free(comp);
		return 1;
	}

	if (src_len != 0U && memcmp(src, out, src_len) != 0) {
		free(out);
		free(comp);
		return 1;
	}

	free(out);
	free(comp);
	return 0;
}

int test_deflate_round_trip_text(void)
{
	static const uint8_t text[] =
	    "The quick brown fox jumps over the lazy dog. "
	    "The quick brown fox jumps over the lazy dog. "
	    "The quick brown fox jumps over the lazy dog.";

	return round_trip(text, sizeof(text) - 1U);
}

int test_deflate_round_trip_binary(void)
{
	uint8_t data[4096];

	fill_pattern(data, sizeof(data));
	return round_trip(data, sizeof(data));
}

int test_deflate_round_trip_empty(void)
{
	return round_trip(NULL, 0U);
}

int test_deflate_round_trip_single_byte(void)
{
	const uint8_t b = 0x5a;

	return round_trip(&b, 1U);
}

int test_deflate_round_trip_exact_chunk(void)
{
	uint8_t *data;
	int rc;

	data = malloc(ARK_DEFLATE_MAX_INPUT);
	if (data == NULL)
		return 1;
	fill_pattern(data, ARK_DEFLATE_MAX_INPUT);
	rc = round_trip(data, ARK_DEFLATE_MAX_INPUT);
	free(data);
	return rc;
}

int test_deflate_round_trip_sub_chunk(void)
{
	uint8_t *data;
	int rc;

	data = malloc(ARK_DEFLATE_MAX_INPUT / 2U);
	if (data == NULL)
		return 1;
	fill_pattern(data, ARK_DEFLATE_MAX_INPUT / 2U);
	rc = round_trip(data, ARK_DEFLATE_MAX_INPUT / 2U);
	free(data);
	return rc;
}

int test_deflate_incompressible_within_bound(void)
{
	uint8_t *data;
	uint8_t *comp;
	size_t len;
	size_t bound;
	ssize_t comp_len;
	int rc;

	len = 200000U;
	data = malloc(len);
	if (data == NULL)
		return 1;
	fill_randomish(data, len);

	bound = ark_deflate_bound(len);
	comp = malloc(bound);
	if (comp == NULL) {
		free(data);
		return 1;
	}

	comp_len = test_deflate_compress(data, len, comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	rc = (comp_len >= 0 && (size_t)comp_len <= bound) ? 0 : 1;

	free(comp);
	free(data);
	return rc;
}

int test_deflate_bound_non_zero(void)
{
	static const size_t sizes[] = {
	    0U,
	    1U,
	    2U,
	    3U,
	    7U,
	    31U,
	    255U,
	    1024U,
	    65535U,
	    65536U,
	    ARK_DEFLATE_MAX_INPUT,
	};
	size_t i;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		if (ark_deflate_bound(sizes[i]) <= sizes[i])
			return 1;
	}
	return 0;
}

/*
 * test_deflate_bound_exact_values - The bound is src_len + 5 bytes per
 * started 65,535-byte stored block + 1, with one block for empty input.
 * Pins the values so the overflow-safe arithmetic changes none of them.
 */
int test_deflate_bound_exact_values(void)
{
	static const size_t cases[][2] = {
	    {0U, 6U},
	    {1U, 7U},
	    {65534U, 65540U},
	    {65535U, 65541U},
	    {65536U, 65547U},
	    {131070U, 131081U},
	    {131071U, 131087U},
	    {ARK_DEFLATE_MAX_INPUT, ARK_DEFLATE_MAX_INPUT + 17U * 5U + 1U},
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (ark_deflate_bound(cases[i][0]) != cases[i][1])
			return 1;
	}
	return 0;
}

/*
 * test_deflate_bound_overflow - Near SIZE_MAX the bound is not
 * representable: ark_deflate_bound returns 0 instead of a wrapped value,
 * and every non-zero result is larger than its input.
 */
int test_deflate_bound_overflow(void)
{
	size_t k;

	if (ark_deflate_bound(SIZE_MAX) != 0U)
		return 1;
	for (k = 0U; k < 70000U; k += 7U) {
		size_t n = SIZE_MAX - k;
		size_t b = ark_deflate_bound(n);

		if (b != 0U && b <= n)
			return 1;
	}
	if (ark_deflate_bound(SIZE_MAX / 2U) <= SIZE_MAX / 2U)
		return 1;
	return 0;
}

/*
 * test_deflate_rejects_oversize_input - One byte more than
 * ARK_DEFLATE_MAX_INPUT is rejected without writing output.
 */
int test_deflate_rejects_oversize_input(void)
{
	uint8_t *data;
	uint8_t *comp;
	size_t len;
	size_t bound;
	int rc;

	len = (size_t)ARK_DEFLATE_MAX_INPUT + 1U;
	bound = ark_deflate_bound(len);
	data = calloc(1U, len);
	comp = malloc(bound);
	rc = 1;
	if (data != NULL && comp != NULL) {
		ssize_t n = test_deflate_compress(data, len, comp, bound,
		                                  ARK_DEFLATE_LEVEL_DEFAULT);

		rc = n == -1 ? 0 : 1;
	}
	free(comp);
	free(data);
	return rc;
}

int test_deflate_stored_block_valid(void)
{
	uint8_t *data;
	uint8_t *comp;
	uint8_t *out;
	size_t len;
	size_t bound;
	ssize_t comp_len;
	ssize_t out_len;
	int rc;

	len = 65536U + 77U;
	data = malloc(len);
	if (data == NULL)
		return 1;
	fill_randomish(data, len);

	bound = ark_deflate_bound(len);
	comp = malloc(bound);
	out = malloc(len);
	if (comp == NULL || out == NULL) {
		free(out);
		free(comp);
		free(data);
		return 1;
	}

	comp_len = test_deflate_compress(data, len, comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len < 0) {
		free(out);
		free(comp);
		free(data);
		return 1;
	}

	/*
	 * Verify first stored block structure (RFC 1951 §3.2.4):
	 *   byte 0: BFINAL=0 | BTYPE=00 | 5 padding zeros → 0x00
	 *   bytes 1-2: LEN little-endian (65535 = 0xFFFF for first block)
	 *   bytes 3-4: NLEN = one's complement of LEN (0x0000)
	 */
	if (comp[0] != 0x00U) {
		free(out);
		free(comp);
		free(data);
		return 1;
	}
	if (comp[1] != 0xFFU || comp[2] != 0xFFU) {
		free(out);
		free(comp);
		free(data);
		return 1;
	}
	if (comp[3] != 0x00U || comp[4] != 0x00U) {
		free(out);
		free(comp);
		free(data);
		return 1;
	}

	out_len = test_deflate_decompress(comp, (size_t)comp_len, out, len);
	rc = (out_len == (ssize_t)len && memcmp(out, data, len) == 0) ? 0 : 1;

	free(out);
	free(comp);
	free(data);
	return rc;
}

int test_deflate_default_emits_dynamic_block(void)
{
	uint8_t in[8192];
	uint8_t *comp;
	size_t bound;
	ssize_t comp_len;
	size_t i;
	int rc;

	for (i = 0; i < sizeof(in); i++)
		in[i] = 'a';

	bound = ark_deflate_bound(sizeof(in));
	comp = malloc(bound);
	if (comp == NULL)
		return 1;

	comp_len = test_deflate_compress(in, sizeof(in), comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	rc = (comp_len > 0 && (comp[0] & 0x06U) == 0x04U) ? 0 : 1;

	free(comp);
	return rc;
}

/*
 * The fast level costs fixed against dynamic codes like the other levels;
 * for 128 bytes of text the fixed codes are cheaper.
 */
int test_deflate_fast_emits_fixed_block(void)
{
	static const char text[] = "The quick brown fox jumps over the lazy "
	                           "dog. ";
	uint8_t in[128];
	uint8_t *comp;
	size_t bound;
	ssize_t comp_len;
	size_t i;
	int rc;

	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)text[i % (sizeof(text) - 1U)];

	bound = ark_deflate_bound(sizeof(in));
	comp = malloc(bound);
	if (comp == NULL)
		return 1;

	comp_len = test_deflate_compress(in, sizeof(in), comp, bound,
	                                 ARK_DEFLATE_LEVEL_FAST);
	rc = (comp_len > 0 && (size_t)comp_len < sizeof(in) &&
	      (comp[0] & 0x06U) == 0x02U)
	         ? 0
	         : 1;

	free(comp);
	return rc;
}

int test_deflate_invalid_stream(void)
{
	const uint8_t bad[] = {0x06};
	uint8_t out[32];

	return test_deflate_decompress(bad, sizeof(bad), out, sizeof(out)) < 0
	           ? 0
	           : 1;
}

int test_deflate_truncated_stream(void)
{
	uint8_t in[4096];
	uint8_t *comp;
	uint8_t out[4096];
	size_t bound;
	ssize_t comp_len;

	fill_pattern(in, sizeof(in));
	bound = ark_deflate_bound(sizeof(in));
	comp = malloc(bound);
	if (comp == NULL)
		return 1;

	comp_len = test_deflate_compress(in, sizeof(in), comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len < 2) {
		free(comp);
		return 1;
	}

	if (test_deflate_decompress(comp, (size_t)comp_len - 1U, out,
	                            sizeof(out)) >= 0) {
		free(comp);
		return 1;
	}

	free(comp);
	return 0;
}

int test_deflate_output_buffer_too_small(void)
{
	uint8_t in[1024];
	uint8_t *comp;
	uint8_t out[1023];
	size_t bound;
	ssize_t comp_len;

	fill_pattern(in, sizeof(in));
	bound = ark_deflate_bound(sizeof(in));
	comp = malloc(bound);
	if (comp == NULL)
		return 1;

	comp_len = test_deflate_compress(in, sizeof(in), comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len < 0) {
		free(comp);
		return 1;
	}

	if (test_deflate_decompress(comp, (size_t)comp_len, out, sizeof(out)) >=
	    0) {
		free(comp);
		return 1;
	}

	free(comp);
	return 0;
}

int test_deflate_output_buffer_exact(void)
{
	uint8_t in[8192];
	uint8_t *comp;
	uint8_t out[8192 + 16];
	size_t bound;
	size_t i;
	ssize_t comp_len;
	ssize_t out_len;

	fill_pattern(in, sizeof(in));
	bound = ark_deflate_bound(sizeof(in));
	comp = malloc(bound);
	if (comp == NULL)
		return 1;

	comp_len = test_deflate_compress(in, sizeof(in), comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len < 0) {
		free(comp);
		return 1;
	}

	memset(out, 0xa5, sizeof(out));
	out_len =
	    test_deflate_decompress(comp, (size_t)comp_len, out, sizeof(in));
	if (out_len != (ssize_t)sizeof(in)) {
		free(comp);
		return 1;
	}
	if (memcmp(out, in, sizeof(in)) != 0) {
		free(comp);
		return 1;
	}
	for (i = sizeof(in); i < sizeof(out); i++) {
		if (out[i] != 0xa5) {
			free(comp);
			return 1;
		}
	}

	free(comp);
	return 0;
}

/*
 * compress_size - Compress src at level; return compressed size or -1. When
 * btype is non-NULL it receives the BTYPE of the first block.
 */
static ssize_t compress_size(const uint8_t *src, size_t src_len, int level,
                             int *btype)
{
	uint8_t *comp;
	size_t bound;
	ssize_t comp_len;

	bound = ark_deflate_bound(src_len);
	comp = malloc(bound);
	if (comp == NULL)
		return -1;
	comp_len = test_deflate_compress(src, src_len, comp, bound, level);
	if (btype != NULL && comp_len > 0)
		*btype = (comp[0] >> 1) & 3;
	free(comp);
	return comp_len;
}

/*
 * kraft_check - Check one set of code lengths: every used symbol has a
 * length in 1..max_bits, unused symbols have none, and with two or more used
 * symbols the code is complete (Kraft sum exactly 1).
 */
static int kraft_check(const uint32_t *freq, const uint8_t *lengths,
                       size_t n_symbols, unsigned int max_bits)
{
	uint32_t total;
	size_t used;
	size_t i;

	total = 0U;
	used = 0U;
	for (i = 0; i < n_symbols; i++) {
		if (freq[i] == 0U) {
			if (lengths[i] != 0U)
				return 1;
			continue;
		}
		if (lengths[i] == 0U || lengths[i] > max_bits)
			return 1;
		used++;
		total += 1U << (max_bits - lengths[i]);
	}
	if (used >= 2U && total != 1U << max_bits)
		return 1;
	return 0;
}

int test_deflate_length_symbol_mapping(void)
{
	static const struct {
		size_t len;
		unsigned int sym;
		unsigned int extra_n;
		uint16_t extra_v;
	} cases[] = {
	    {3, 257, 0, 0},    {10, 264, 0, 0},   {11, 265, 1, 0},
	    {12, 265, 1, 1},   {226, 283, 5, 31}, {227, 284, 5, 0},
	    {257, 284, 5, 30}, {258, 285, 0, 0},
	};
	unsigned int sym;
	unsigned int extra_n;
	uint16_t extra_v;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (ark_deflate_test_length_symbol(cases[i].len, &sym, &extra_n,
		                                   &extra_v) != 0 ||
		    sym != cases[i].sym || extra_n != cases[i].extra_n ||
		    extra_v != cases[i].extra_v)
			return 1;
	}
	if (ark_deflate_test_length_symbol(2, &sym, &extra_n, &extra_v) == 0 ||
	    ark_deflate_test_length_symbol(259, &sym, &extra_n, &extra_v) == 0)
		return 1;
	return 0;
}

int test_deflate_zero_run_uses_code_285(void)
{
	uint8_t *in;
	ssize_t def_len;
	ssize_t fast_len;
	int rc;

	in = calloc(1U, ARK_DEFLATE_MAX_INPUT);
	if (in == NULL)
		return 1;
	/*
	 * Long zero runs are coded as length-258 matches. With code 285 (no
	 * extra bits) 1 MiB of zeros needs ~1.1 KiB in default mode and
	 * ~6.5 KiB in fast mode; the old 284+31 form needed 4,783 and 9,149.
	 */
	def_len = compress_size(in, ARK_DEFLATE_MAX_INPUT,
	                        ARK_DEFLATE_LEVEL_DEFAULT, NULL);
	fast_len = compress_size(in, ARK_DEFLATE_MAX_INPUT,
	                         ARK_DEFLATE_LEVEL_FAST, NULL);
	rc = def_len > 0 && def_len < 2048 && fast_len > 0 && fast_len < 8192
	         ? round_trip(in, ARK_DEFLATE_MAX_INPUT)
	         : 1;
	free(in);
	return rc;
}

int test_deflate_round_trip_all_match_lengths(void)
{
	uint8_t *in;
	size_t len;
	size_t n;
	int rc;

	/* Runs of every length 3..260, split by a varying separator byte. */
	in = malloc(40000U);
	if (in == NULL)
		return 1;
	n = 0U;
	for (len = 3U; len <= 260U; len++) {
		in[n++] = (uint8_t)(len | 1U);
		memset(in + n, 'z', len);
		n += len;
	}
	rc = round_trip(in, n);
	if (rc == 0) {
		uint8_t *comp;
		uint8_t *out;
		size_t bound;

		bound = ark_deflate_bound(n);
		comp = malloc(bound);
		out = malloc(n);
		rc = 1;
		if (comp != NULL && out != NULL) {
			ssize_t fast_len;

			fast_len = test_deflate_compress(
			    in, n, comp, bound, ARK_DEFLATE_LEVEL_FAST);
			if (fast_len > 0 &&
			    test_deflate_decompress(comp, (size_t)fast_len, out,
			                            n) == (ssize_t)n &&
			    memcmp(in, out, n) == 0)
				rc = 0;
		}
		free(out);
		free(comp);
	}
	free(in);
	return rc;
}

int test_deflate_limit_lengths_fibonacci(void)
{
	static const size_t counts[] = {17, 20, 23, 30};
	uint32_t freq[286];
	uint8_t lengths[286];
	size_t c;

	/* Fibonacci frequencies give an unlimited Huffman depth of n - 1. */
	for (c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
		uint32_t a;
		uint32_t b;
		size_t i;

		memset(freq, 0, sizeof(freq));
		a = 1U;
		b = 1U;
		for (i = 0; i < counts[c]; i++) {
			uint32_t t;

			freq[i * 9U] = a;
			t = a + b;
			a = b;
			b = t;
		}
		freq[256] = 1U;
		if (ark_deflate_test_limit_lengths(freq, 286U, lengths, 15U) !=
		        0 ||
		    kraft_check(freq, lengths, 286U, 15U) != 0)
			return 1;
	}
	return 0;
}

int test_deflate_limit_lengths_small_alphabets(void)
{
	uint32_t freq[30];
	uint8_t lengths[30];
	size_t i;

	/* Distance alphabet: 30 Fibonacci frequencies, max 15 bits. */
	freq[0] = 1U;
	freq[1] = 1U;
	for (i = 2; i < 30U; i++)
		freq[i] = freq[i - 1U] + freq[i - 2U];
	if (ark_deflate_test_limit_lengths(freq, 30U, lengths, 15U) != 0 ||
	    kraft_check(freq, lengths, 30U, 15U) != 0)
		return 1;
	/* Code-length alphabet: 19 halving frequencies, max 7 bits. */
	for (i = 0; i < 19U; i++)
		freq[i] = 1U << (18U - i);
	if (ark_deflate_test_limit_lengths(freq, 19U, lengths, 7U) != 0 ||
	    kraft_check(freq, lengths, 19U, 7U) != 0)
		return 1;
	/* One used symbol: a single 1-bit code. */
	memset(freq, 0, sizeof(freq));
	freq[7] = 5U;
	if (ark_deflate_test_limit_lengths(freq, 30U, lengths, 15U) != 0 ||
	    kraft_check(freq, lengths, 30U, 15U) != 0 || lengths[7] != 1U)
		return 1;
	/* No used symbol: symbol 0 gets a 1-bit code (empty distance tree). */
	memset(freq, 0, sizeof(freq));
	if (ark_deflate_test_limit_lengths(freq, 30U, lengths, 15U) != 0 ||
	    lengths[0] != 1U)
		return 1;
	for (i = 1; i < 30U; i++) {
		if (lengths[i] != 0U)
			return 1;
	}
	return 0;
}

int test_deflate_cl_code_always_complete(void)
{
	static const uint8_t lit[3] = {5, 5, 5};
	uint8_t cl_len[19];
	uint32_t freq[19];
	size_t hclen;
	size_t used;
	size_t i;

	/* Three equal lengths, too short for a repeat: one CL symbol only. */
	if (ark_deflate_test_cl_plan(lit, 3U, NULL, 0U, cl_len, &hclen) != 0)
		return 1;
	used = 0U;
	for (i = 0; i < 19U; i++) {
		freq[i] = cl_len[i] != 0U ? 1U : 0U;
		if (cl_len[i] != 0U)
			used++;
	}
	if (used != 2U || cl_len[5] != 1U || hclen < 4U || hclen > 19U)
		return 1;
	return kraft_check(freq, cl_len, 19U, 7U);
}

int test_deflate_header_cost_matches_emitted(void)
{
	uint8_t lit[286];
	uint8_t dist[30];
	size_t cost;
	size_t emitted;
	size_t i;

	/* Fixed-Huffman shaped lengths: long equal runs (symbol 16). */
	for (i = 0; i < 286U; i++)
		lit[i] = i < 144U ? 8U : i < 256U ? 9U : i < 280U ? 7U : 8U;
	for (i = 0; i < 30U; i++)
		dist[i] = 5U;
	if (ark_deflate_test_header_bits(lit, 286U, dist, 30U, &cost,
	                                 &emitted) != 0 ||
	    cost != emitted)
		return 1;
	/* Sparse lengths: zero runs of every size (symbols 17 and 18). */
	memset(lit, 0, sizeof(lit));
	memset(dist, 0, sizeof(dist));
	lit[0] = 2U;
	lit[3] = 3U;
	lit[14] = 3U;
	lit[160] = 4U;
	lit[256] = 4U;
	lit[257] = 4U;
	lit[258] = 4U;
	lit[259] = 4U;
	lit[260] = 4U;
	lit[261] = 3U;
	dist[0] = 1U;
	if (ark_deflate_test_header_bits(lit, 262U, dist, 1U, &cost,
	                                 &emitted) != 0 ||
	    cost != emitted)
		return 1;
	return 0;
}

int test_deflate_small_input_not_stored(void)
{
	static const char text[] = "The quick brown fox jumps over the lazy "
	                           "dog. ";
	uint8_t in[128];
	ssize_t comp_len;
	size_t i;
	int btype;

	/*
	 * The old fixed 4-bit header cost pushed small inputs to stored. At
	 * this size a dynamic header costs more than the fixed codes save, so
	 * the default level writes a fixed block.
	 */
	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)text[i % (sizeof(text) - 1U)];
	btype = -1;
	comp_len =
	    compress_size(in, sizeof(in), ARK_DEFLATE_LEVEL_DEFAULT, &btype);
	if (comp_len <= 0 || (size_t)comp_len >= sizeof(in) || btype != 1)
		return 1;
	return round_trip(in, sizeof(in));
}

/* Test-side bit writer for hand-built Deflate streams (LSB first). */
typedef struct {
	uint8_t buf[64];
	size_t bits;
} tbits_t;

static void tb_init(tbits_t *t)
{
	memset(t, 0, sizeof(*t));
}

/* Append n bits of v, least significant bit first (header fields, extras). */
static void tb_put(tbits_t *t, uint32_t v, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (((v >> i) & 1U) != 0U)
			t->buf[t->bits >> 3] |= (uint8_t)(1U << (t->bits & 7U));
		t->bits++;
	}
}

/* Append a Huffman code of n bits, most significant bit first. */
static void tb_put_code(tbits_t *t, uint32_t code, unsigned int n)
{
	while (n > 0U) {
		n--;
		tb_put(t, (code >> n) & 1U, 1U);
	}
}

/* Append one fixed-Huffman lit/len symbol (RFC 1951 section 3.2.6). */
static void tb_fixed_sym(tbits_t *t, unsigned int sym)
{
	if (sym < 144U)
		tb_put_code(t, 0x30U + sym, 8U);
	else if (sym < 256U)
		tb_put_code(t, 0x190U + sym - 144U, 9U);
	else if (sym < 280U)
		tb_put_code(t, sym - 256U, 7U);
	else
		tb_put_code(t, 0xc0U + sym - 280U, 8U);
}

static size_t tb_bytes(const tbits_t *t)
{
	return (t->bits + 7U) >> 3;
}

/* Final fixed block: 'A', code 284 with the given extra, distance 1, EOB. */
static void tb_fixed_match_stream(tbits_t *t, uint32_t extra)
{
	tb_init(t);
	tb_put(t, 1U, 1U);
	tb_put(t, 1U, 2U);
	tb_fixed_sym(t, 'A');
	tb_fixed_sym(t, 284U);
	tb_put(t, extra, 5U);
	tb_put_code(t, 0U, 5U);
	tb_fixed_sym(t, 256U);
}

/*
 * decode_expect - Decompress a raw stream. want == NULL expects failure;
 * otherwise the output must equal want[0..want_len).
 */
static int decode_expect(const uint8_t *src, size_t src_len,
                         const uint8_t *want, size_t want_len)
{
	uint8_t out[512];
	ssize_t n;

	n = test_deflate_decompress(src, src_len, out, sizeof(out));
	if (want == NULL)
		return n == -1 ? 0 : 1;
	if (n < 0 || (size_t)n != want_len)
		return 1;
	return memcmp(out, want, want_len) == 0 ? 0 : 1;
}

int test_deflate_fixed_then_stored(void)
{
	/* Fixed block "A", then stored block "XYZ": the stored header must be
	 * read from the input, not from bits buffered by the fixed block. */
	static const uint8_t in[] = {0x72, 0x04, 0x04, 0x03, 0x00,
	                             0xfc, 0xff, 0x58, 0x59, 0x5a};

	return decode_expect(in, sizeof(in), (const uint8_t *)"AXYZ", 4U);
}

int test_deflate_rejects_legacy_length_258(void)
{
	tbits_t legacy;
	tbits_t max284;
	uint8_t out[300];
	uint8_t want[258];
	size_t used;
	size_t n;

	/*
	 * Fixed block: 'A', then code 284 + extra 31 (length 258, as written
	 * by pre-v1.1.0 ark encoders) at distance 1: not allowed by RFC 1951.
	 * The same stream with extra 30 (length 257) stays valid.
	 */
	tb_fixed_match_stream(&legacy, 31U);
	tb_fixed_match_stream(&max284, 30U);
	if (ark_deflate_dec_oneshot(legacy.buf, tb_bytes(&legacy), &used, out,
	                            sizeof(out), &n) != ARK_DEFLATE_ERR_DATA ||
	    used != 0U || n != 0U)
		return 1;
	memset(want, 'A', sizeof(want));
	return decode_expect(max284.buf, tb_bytes(&max284), want, sizeof(want));
}

int test_deflate_rejects_incomplete_trees(void)
{
	/* Code-length code with an unused code (incomplete). */
	static const uint8_t cl_incomplete[] = {
	    0x05, 0xc0, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	};
	/* Literal/length code with only 'A' and end-of-block, both 2 bits. */
	static const uint8_t lit_incomplete[] = {
	    0x05, 0x80, 0x01, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	};
	/* Code-length code with three 1-bit codes (oversubscribed). */
	static const uint8_t cl_oversubscribed[] = {
	    0x05, 0xc0, 0x81, 0x04, 0x00, 0x00, 0x00,
	    0x00, 0x10, 0xb6, 0xfe, 0x52, 0x09,
	};

	if (decode_expect(cl_incomplete, sizeof(cl_incomplete), NULL, 0U) !=
	        0 ||
	    decode_expect(lit_incomplete, sizeof(lit_incomplete), NULL, 0U) !=
	        0 ||
	    decode_expect(cl_oversubscribed, sizeof(cl_oversubscribed), NULL,
	                  0U) != 0)
		return 1;
	return 0;
}

int test_deflate_accepts_allowed_incomplete_trees(void)
{
	/* Dynamic block "AA" whose distance code has no codes at all. */
	static const uint8_t no_dist[] = {0x05, 0xc0, 0x01, 0x05, 0x00,
	                                  0x00, 0x00, 0x00, 0xa0, 0x6d,
	                                  0xfd, 0x3f, 0x15, 0x02};
	/* Dynamic block "A" + match(3, 1) with a single 1-bit distance code. */
	static const uint8_t one_dist[] = {0x0d, 0xc0, 0x01, 0x01, 0x00,
	                                   0x00, 0x00, 0x80, 0x90, 0x6d,
	                                   0xfd, 0x3f, 0x15, 0x31};

	if (decode_expect(no_dist, sizeof(no_dist), (const uint8_t *)"AA",
	                  2U) != 0)
		return 1;
	return decode_expect(one_dist, sizeof(one_dist),
	                     (const uint8_t *)"AAAA", 4U);
}

int test_deflate_round_trip_periodic(void)
{
	uint8_t *in;
	size_t period;
	size_t n;
	size_t i;
	int rc;

	/* Periods 1..17 give match distances on both sides of the 8-byte
	 * word-copy threshold, with long overlapping matches. */
	in = malloc(17U * 600U);
	if (in == NULL)
		return 1;
	n = 0U;
	for (period = 1U; period <= 17U; period++) {
		for (i = 0; i < 600U; i++)
			in[n + i] = (uint8_t)(period * 16U + i % period);
		n += 600U;
	}
	rc = round_trip(in, n);
	free(in);
	return rc;
}

/*
 * Mixed test input: a byte pattern with repeats at many distances (short,
 * near 256, near 32 KiB) plus pseudo-random runs, so every window size has
 * matches it may use and matches it must not use.
 */
static void fill_windowed(uint8_t *buf, size_t len)
{
	uint32_t x;
	size_t i;

	x = 0x2545f491U;
	for (i = 0; i < len; i++) {
		x = x * 1664525U + 1013904223U;
		if (i >= 300U && (x >> 28) < 6U)
			buf[i] = buf[i - 3U - (size_t)((x >> 8) % 280U)];
		else if (i >= 33000U && (x >> 28) < 10U)
			buf[i] = buf[i - 32700U - (size_t)((x >> 8) % 60U)];
		else
			buf[i] = (uint8_t)(x >> 24);
	}
}

/*
 * Encoder size query: for levels 1..9 head and prev follow the window and
 * one 4-byte token is added per max_input byte; level 0 stores and needs
 * only a small header.
 */
int test_deflate_enc_size_query(void)
{
	ark_deflate_params_t p;
	size_t base;
	size_t size15;
	unsigned int wb;
	int level;

	p = (ark_deflate_params_t){ARK_DEFLATE_LEVEL_FAST, 15U, 1U, 0};
	size15 = ark_deflate_enc_size(&p);
	/* head and prev: 2 x 32768 x 4 bytes, one token, a small struct. */
	if (size15 <= 262144U + 4U || size15 > 262144U + 4U + 256U)
		return 1;
	for (level = 1; level <= ARK_DEFLATE_LEVEL_BEST; level++) {
		p.level = level;
		p.max_input = 1U;
		if (ark_deflate_enc_size(&p) != size15)
			return 1;
		p.max_input = ARK_DEFLATE_MAX_INPUT;
		if (ark_deflate_enc_size(&p) !=
		    size15 + 4U * (ARK_DEFLATE_MAX_INPUT - 1U))
			return 1;
	}
	p.level = ARK_DEFLATE_LEVEL_NONE;
	if (ark_deflate_enc_size(&p) == 0U || ark_deflate_enc_size(&p) > 256U)
		return 1;

	p.level = ARK_DEFLATE_LEVEL_DEFAULT;
	p.max_input = 1U;
	p.window_bits = 8U;
	base = ark_deflate_enc_size(&p);
	if (base == 0U || base > 2048U + 4U + 256U)
		return 1;
	for (wb = 8U; wb <= 15U; wb++) {
		p.window_bits = wb;
		if (ark_deflate_enc_size(&p) !=
		    base + 8U * (((size_t)1U << wb) - 256U))
			return 1;
	}
	return 0;
}

/* Invalid parameters give size 0 and no encoder. */
int test_deflate_enc_rejects_invalid_params(void)
{
	static const ark_deflate_params_t bad[] = {
	    {-1, 15U, 1024U, 0},
	    {10, 15U, 1024U, 0},
	    {ARK_DEFLATE_LEVEL_DEFAULT, 7U, 1024U, 0},
	    {ARK_DEFLATE_LEVEL_DEFAULT, 16U, 1024U, 0},
	    {ARK_DEFLATE_LEVEL_DEFAULT, 15U, 0U, 0},
	    {ARK_DEFLATE_LEVEL_DEFAULT, 15U, ARK_DEFLATE_MAX_INPUT + 1U, 0},
	    {ARK_DEFLATE_LEVEL_FAST, 15U, 1024U, 1},
	};
	ark_deflate_params_t good;
	void *mem;
	size_t mem_len;
	size_t i;
	int rc;

	if (ark_deflate_enc_size(NULL) != 0U)
		return 1;
	good = (ark_deflate_params_t){ARK_DEFLATE_LEVEL_DEFAULT, 15U, 1024U, 0};
	mem_len = ark_deflate_enc_size(&good);
	mem = malloc(mem_len);
	if (mem == NULL)
		return 1;
	rc = ark_deflate_enc_init(mem, mem_len, NULL) == NULL ? 0 : 1;
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		if (ark_deflate_enc_size(&bad[i]) != 0U ||
		    ark_deflate_enc_init(mem, mem_len, &bad[i]) != NULL)
			rc = 1;
	}
	free(mem);
	return rc;
}

/* init rejects NULL, short and misaligned memory; exact size works. */
int test_deflate_enc_init_memory_checks(void)
{
	ark_deflate_params_t p;
	uint8_t *mem;
	size_t size;
	int rc;

	p = (ark_deflate_params_t){ARK_DEFLATE_LEVEL_DEFAULT, 9U, 4096U, 0};
	size = ark_deflate_enc_size(&p);
	mem = malloc(size + 8U);
	if (mem == NULL)
		return 1;
	rc = 0;
	if (ark_deflate_enc_init(NULL, size, &p) != NULL)
		rc = 1;
	if (ark_deflate_enc_init(mem, size - 1U, &p) != NULL)
		rc = 1;
	if (ark_deflate_enc_init(mem + 1, size, &p) != NULL)
		rc = 1;
	if (ark_deflate_enc_init(mem, size, &p) != (ark_deflate_enc_t *)mem)
		rc = 1;
	free(mem);
	return rc;
}

/*
 * One-shot statuses: usage and output errors report dst_len 0 and leave the
 * encoder usable; the next call matches a fresh encoder's output.
 */
int test_deflate_enc_oneshot_status(void)
{
	ark_deflate_enc_t *enc;
	ark_deflate_enc_t *fresh;
	uint8_t in[1001];
	size_t bound;
	size_t n;
	size_t ref_n;
	int rc;

	fill_pattern(in, sizeof(in));
	bound = ark_deflate_bound(1000U);
	enc = test_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 1000U);
	fresh = test_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, 1000U);
	rc = enc == NULL || fresh == NULL;
	if (rc == 0) {
		uint8_t out[2048];
		uint8_t ref[2048];

		n = 7U;
		if (ark_deflate_enc_oneshot(enc, in, 1000U, out, bound, NULL) !=
		        ARK_DEFLATE_ERR_USAGE ||
		    ark_deflate_enc_oneshot(NULL, in, 1000U, out, bound, &n) !=
		        ARK_DEFLATE_ERR_USAGE ||
		    n != 0U)
			rc = 1;
		n = 7U;
		if (ark_deflate_enc_oneshot(enc, in, 1001U, out, sizeof(out),
		                            &n) != ARK_DEFLATE_ERR_USAGE ||
		    n != 0U)
			rc = 1;
		if (ark_deflate_enc_oneshot(enc, NULL, 10U, out, sizeof(out),
		                            &n) != ARK_DEFLATE_ERR_USAGE)
			rc = 1;
		n = 7U;
		if (ark_deflate_enc_oneshot(enc, in, 1000U, out, bound - 1U,
		                            &n) != ARK_DEFLATE_ERR_OUTPUT ||
		    n != 0U)
			rc = 1;
		if (ark_deflate_enc_oneshot(enc, in, 1000U, out, bound, &n) !=
		        ARK_DEFLATE_OK ||
		    ark_deflate_enc_oneshot(fresh, in, 1000U, ref, bound,
		                            &ref_n) != ARK_DEFLATE_OK ||
		    n != ref_n || memcmp(out, ref, n) != 0)
			rc = 1;
	}
	free(fresh);
	free(enc);
	return rc;
}

/*
 * A reused encoder gives the same output as a fresh one: no state leaks
 * from one call into the next (the hash heads are reset per parse and stale
 * chain slots are never read).
 */
int test_deflate_enc_reuse_deterministic(void)
{
	static const int levels[] = {ARK_DEFLATE_LEVEL_DEFAULT,
	                             ARK_DEFLATE_LEVEL_FAST};
	uint8_t *a;
	uint8_t *b;
	uint8_t *out;
	uint8_t *ref;
	size_t len_a;
	size_t len_b;
	size_t cap;
	size_t li;
	int rc;

	len_a = 200000U;
	len_b = 70000U;
	cap = ark_deflate_bound(len_a);
	a = malloc(len_a);
	b = malloc(len_b);
	out = malloc(cap);
	ref = malloc(cap);
	rc = a == NULL || b == NULL || out == NULL || ref == NULL;
	if (rc == 0) {
		fill_windowed(a, len_a);
		fill_randomish(b, len_b);
		memcpy(b, a + 1000U, 30000U);
	}
	for (li = 0; rc == 0 && li < sizeof(levels) / sizeof(levels[0]); li++) {
		const uint8_t *inputs[3];
		size_t lens[3];
		ark_deflate_enc_t *enc;
		size_t k;

		inputs[0] = a;
		inputs[1] = b;
		inputs[2] = a;
		lens[0] = len_a;
		lens[1] = len_b;
		lens[2] = len_a;
		enc = test_enc_new(levels[li], 15U, ARK_DEFLATE_MAX_INPUT);
		if (enc == NULL)
			rc = 1;
		for (k = 0; rc == 0 && k < 3U; k++) {
			size_t n;
			ssize_t ref_n;

			ref_n = test_deflate_compress(inputs[k], lens[k], ref,
			                              cap, levels[li]);
			if (ark_deflate_enc_oneshot(enc, inputs[k], lens[k],
			                            out, cap,
			                            &n) != ARK_DEFLATE_OK ||
			    ref_n < 0 || n != (size_t)ref_n ||
			    memcmp(out, ref, n) != 0)
				rc = 1;
		}
		free(enc);
	}
	free(ref);
	free(out);
	free(b);
	free(a);
	return rc;
}

/*
 * Every window size 8..15 and every level 0..9 round-trip mixed input,
 * decoded by a decoder that rejects any back-reference beyond the encoder's
 * window.
 */
int test_deflate_window_bits_round_trip(void)
{
	static const int levels[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	size_t len;
	size_t cap;
	unsigned int wb;
	size_t li;
	int rc;

	len = 100000U;
	cap = ark_deflate_bound(len);
	in = malloc(len);
	comp = malloc(cap);
	out = malloc(len);
	rc = in == NULL || comp == NULL || out == NULL;
	if (rc == 0)
		fill_windowed(in, len);
	for (wb = 8U; rc == 0 && wb <= 15U; wb++) {
		for (li = 0; rc == 0 && li < sizeof(levels) / sizeof(levels[0]);
		     li++) {
			ark_deflate_enc_t *enc;
			size_t n;

			enc = test_enc_new(levels[li], wb, len);
			if (enc == NULL ||
			    ark_deflate_enc_oneshot(enc, in, len, comp, cap,
			                            &n) != ARK_DEFLATE_OK) {
				rc = 1;
			} else {
				size_t d;

				if (ark_deflate_test_decompress_window(
				        comp, n, out, len, wb, &d) !=
				        ARK_DEFLATE_OK ||
				    d != len || memcmp(in, out, len) != 0)
					rc = 1;
			}
			free(enc);
		}
	}
	free(out);
	free(comp);
	free(in);
	return rc;
}

/*
 * A random block repeated at a distance just beyond the window must not be
 * matched: with window_bits wb the output stays incompressible, while the
 * full 32 KiB window finds the repeat and halves the size.
 */
int test_deflate_window_limits_distance(void)
{
	static const int levels[] = {ARK_DEFLATE_LEVEL_DEFAULT,
	                             ARK_DEFLATE_LEVEL_FAST};
	uint8_t *in;
	uint8_t *comp;
	unsigned int wb;
	size_t li;
	int rc;

	in = malloc(2U * 16448U);
	comp = malloc(ark_deflate_bound(2U * 16448U));
	rc = in == NULL || comp == NULL;
	for (wb = 8U; rc == 0 && wb <= 14U; wb++) {
		size_t half;
		size_t len;
		size_t cap;

		half = ((size_t)1U << wb) + 64U;
		len = 2U * half;
		cap = ark_deflate_bound(len);
		fill_randomish(in, half);
		memcpy(in + half, in, half);
		for (li = 0; rc == 0 && li < sizeof(levels) / sizeof(levels[0]);
		     li++) {
			ark_deflate_enc_t *narrow;
			ark_deflate_enc_t *wide;
			size_t n_narrow;
			size_t n_wide;

			narrow = test_enc_new(levels[li], wb, len);
			wide = test_enc_new(levels[li], 15U, len);
			if (narrow == NULL || wide == NULL ||
			    ark_deflate_enc_oneshot(narrow, in, len, comp, cap,
			                            &n_narrow) !=
			        ARK_DEFLATE_OK ||
			    ark_deflate_enc_oneshot(wide, in, len, comp, cap,
			                            &n_wide) !=
			        ARK_DEFLATE_OK ||
			    n_narrow < len || n_wide > half + half / 4U)
				rc = 1;
			free(wide);
			free(narrow);
		}
	}
	free(comp);
	free(in);
	return rc;
}

/*
 * The window-limited test decoder is strict: a window-15 stream of input
 * with ~32 KiB repeats decodes at window 15 but is rejected at every smaller
 * window, and out-of-range window bits are refused.
 */
int test_deflate_window_checker_rejects_far(void)
{
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	size_t len;
	size_t cap;
	int rc;

	len = 100000U;
	cap = ark_deflate_bound(len);
	in = malloc(len);
	comp = malloc(cap);
	out = malloc(len);
	rc = in == NULL || comp == NULL || out == NULL;
	if (rc == 0) {
		ssize_t n;
		size_t d;
		unsigned int wb;

		fill_windowed(in, len);
		n = test_deflate_compress(in, len, comp, cap,
		                          ARK_DEFLATE_LEVEL_DEFAULT);
		if (n < 0 ||
		    ark_deflate_test_decompress_window(
		        comp, (size_t)n, out, len, 15U, &d) != ARK_DEFLATE_OK ||
		    d != len)
			rc = 1;
		for (wb = 8U; rc == 0 && wb <= 14U; wb++) {
			if (ark_deflate_test_decompress_window(
			        comp, (size_t)n, out, len, wb, &d) !=
			    ARK_DEFLATE_ERR_DATA)
				rc = 1;
		}
		if (rc == 0 && (ark_deflate_test_decompress_window(
		                    comp, (size_t)n, out, len, 7U, &d) !=
		                    ARK_DEFLATE_ERR_USAGE ||
		                ark_deflate_test_decompress_window(
		                    comp, (size_t)n, out, len, 16U, &d) !=
		                    ARK_DEFLATE_ERR_USAGE))
			rc = 1;
	}
	free(out);
	free(comp);
	free(in);
	return rc;
}

/*
 * A stream's final block may end at any bit of its last byte: src_used
 * counts that byte and none of the bytes after it. Fixed blocks of b 9-bit
 * literals (b = 0..7) end at every bit offset.
 */
int test_deflate_dec_src_used_bit_offsets(void)
{
	static const uint8_t junk[3] = {0xa5U, 0x00U, 0xffU};
	unsigned int b;

	for (b = 0U; b < 8U; b++) {
		tbits_t t;
		uint8_t in[67];
		uint8_t out[16];
		size_t bytes;
		size_t used;
		size_t n;
		unsigned int i;

		tb_init(&t);
		tb_put(&t, 1U, 1U);
		tb_put(&t, 1U, 2U);
		for (i = 0; i < b; i++)
			tb_fixed_sym(&t, 200U + i);
		tb_fixed_sym(&t, 256U);
		if (t.bits != 10U + 9U * b)
			return 1;
		bytes = tb_bytes(&t);
		memcpy(in, t.buf, bytes);
		memcpy(in + bytes, junk, sizeof(junk));
		if (ark_deflate_dec_oneshot(in, bytes + sizeof(junk), &used,
		                            out, sizeof(out),
		                            &n) != ARK_DEFLATE_OK ||
		    used != bytes || n != b)
			return 1;
		for (i = 0; i < b; i++) {
			if (out[i] != (uint8_t)(200U + i))
				return 1;
		}
	}
	return 0;
}

/*
 * src_used for each block type (stored, fixed, dynamic) with trailing bytes
 * after the stream, and back-to-back streams decoded one after the other.
 */
int test_deflate_dec_src_used_concatenated(void)
{
	/* Random input stores, a short pattern takes a fixed block at the
	 * fast level, mixed input takes dynamic blocks at the default level. */
	static const int levels[3] = {ARK_DEFLATE_LEVEL_DEFAULT,
	                              ARK_DEFLATE_LEVEL_FAST,
	                              ARK_DEFLATE_LEVEL_DEFAULT};
	static const size_t lens[3] = {3000U, 5000U, 70000U};
	uint8_t *in[3] = {NULL, NULL, NULL};
	uint8_t *cat;
	uint8_t *out;
	size_t clen[3];
	size_t total;
	size_t off;
	size_t k;
	int rc;

	rc = 1;
	cat = malloc(ark_deflate_bound(70000U) * 3U + 16U);
	out = malloc(70000U);
	for (k = 0; k < 3U; k++)
		in[k] = malloc(lens[k]);
	if (cat == NULL || out == NULL || in[0] == NULL || in[1] == NULL ||
	    in[2] == NULL)
		goto done;
	fill_randomish(in[0], lens[0]);
	fill_pattern(in[1], lens[1]);
	fill_windowed(in[2], lens[2]);

	total = 0U;
	for (k = 0; k < 3U; k++) {
		ssize_t c;

		c = test_deflate_compress(in[k], lens[k], cat + total,
		                          ark_deflate_bound(lens[k]),
		                          levels[k]);
		/* Expected first block types: stored, fixed, dynamic. */
		if (c <= 0 || ((cat[total] >> 1) & 3) != (int)k)
			goto done;
		clen[k] = (size_t)c;
		total += clen[k];
	}
	memset(cat + total, 0x5a, 16U);

	off = 0U;
	for (k = 0; k < 3U; k++) {
		size_t used;
		size_t n;

		if (ark_deflate_dec_oneshot(cat + off, total + 16U - off, &used,
		                            out, lens[k],
		                            &n) != ARK_DEFLATE_OK ||
		    used != clen[k] || n != lens[k] ||
		    memcmp(out, in[k], n) != 0)
			goto done;
		off += used;
	}
	rc = off == total ? 0 : 1;
done:
	for (k = 0; k < 3U; k++)
		free(in[k]);
	free(out);
	free(cat);
	return rc;
}

/*
 * Status codes: NULL out-parameters and NULL buffers with a size are usage
 * errors; output one byte short is ERR_OUTPUT for Huffman and stored data;
 * truncated and malformed input are ERR_DATA; counts are 0 after failure.
 */
int test_deflate_dec_status_codes(void)
{
	static const uint8_t bad[] = {0x06};
	uint8_t in[1024];
	uint8_t rnd[600];
	uint8_t comp[2048];
	uint8_t out[1024];
	size_t used;
	size_t n;
	ssize_t c;
	ssize_t cr;

	fill_pattern(in, sizeof(in));
	fill_randomish(rnd, sizeof(rnd));
	c = test_deflate_compress(in, sizeof(in), comp, sizeof(comp),
	                          ARK_DEFLATE_LEVEL_DEFAULT);
	if (c <= 1)
		return 1;
	if (ark_deflate_dec_oneshot(comp, (size_t)c, NULL, out, sizeof(out),
	                            &n) != ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_oneshot(comp, (size_t)c, &used, out, sizeof(out),
	                            NULL) != ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_oneshot(NULL, 4U, &used, out, sizeof(out), &n) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_oneshot(comp, (size_t)c, &used, NULL, 4U, &n) !=
	        ARK_DEFLATE_ERR_USAGE)
		return 1;
	used = 9U;
	n = 9U;
	if (ark_deflate_dec_oneshot(comp, (size_t)c, &used, out,
	                            sizeof(in) - 1U,
	                            &n) != ARK_DEFLATE_ERR_OUTPUT ||
	    used != 0U || n != 0U)
		return 1;
	if (ark_deflate_dec_oneshot(comp, (size_t)c - 1U, &used, out,
	                            sizeof(out), &n) != ARK_DEFLATE_ERR_DATA ||
	    ark_deflate_dec_oneshot(bad, sizeof(bad), &used, out, sizeof(out),
	                            &n) != ARK_DEFLATE_ERR_DATA)
		return 1;
	cr = test_deflate_compress(rnd, sizeof(rnd), comp, sizeof(comp),
	                           ARK_DEFLATE_LEVEL_DEFAULT);
	if (cr <= 0 || (comp[0] & 0x06U) != 0U)
		return 1;
	if (ark_deflate_dec_oneshot(comp, (size_t)cr, &used, out,
	                            sizeof(rnd) - 1U,
	                            &n) != ARK_DEFLATE_ERR_OUTPUT ||
	    ark_deflate_dec_oneshot(comp, (size_t)cr, &used, out, sizeof(rnd),
	                            &n) != ARK_DEFLATE_OK ||
	    used != (size_t)cr || n != sizeof(rnd))
		return 1;
	return 0;
}

/*
 * Build the worst-case complete code for a decode table: popcount(2^root -
 * p) codes up to root bits, a chain root+1..15,15 in one root prefix and two
 * root+1 codes in each of the other p - 1 prefixes. It must fill the table
 * capacity exactly (fits at cap, fails at cap - 1).
 */
static int table_worst_case(int dist, unsigned int root, size_t p,
                            size_t n_symbols)
{
	uint8_t lengths[288];
	size_t cap;
	size_t slots;
	size_t k;
	unsigned int bit;
	unsigned int len;

	memset(lengths, 0, sizeof(lengths));
	k = 0U;
	slots = ((size_t)1U << root) - p;
	for (bit = root; bit-- > 0U;) {
		if (((slots >> bit) & 1U) != 0U)
			lengths[k++] = (uint8_t)(root - bit);
	}
	for (len = root + 1U; len <= 15U; len++)
		lengths[k++] = (uint8_t)len;
	lengths[k++] = 15U;
	while (k + 2U <= n_symbols && p > 1U) {
		lengths[k++] = (uint8_t)(root + 1U);
		lengths[k++] = (uint8_t)(root + 1U);
		p--;
	}
	if (p != 1U || k != n_symbols)
		return 1;
	cap = ark_deflate_test_table_cap(dist);
	if (cap != ((size_t)1U << root) + (n_symbols == 286U ? 137U : 10U) *
	                                      ((size_t)1U << (15U - root)))
		return 1;
	if (ark_deflate_test_table_fits(lengths, n_symbols, dist, cap) != 0)
		return 1;
	return ark_deflate_test_table_fits(lengths, n_symbols, dist,
	                                   cap - 1U) == -1
	           ? 0
	           : 1;
}

/* Decode tables are sized exactly for the worst-case lit/len and dist codes. */
int test_deflate_table_worst_case(void)
{
	if (table_worst_case(0, 10U, 137U, 286U) != 0)
		return 1;
	return table_worst_case(1, 8U, 10U, 32U);
}

/*
 * The encoder's length and distance symbol tables agree with the
 * RFC 1951 ranges for every length 3..258 and distance 1..32768.
 */
int test_deflate_token_symbol_tables(void)
{
	static const uint16_t dist_base[30] = {
	    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
	    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
	    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
	};
	unsigned int expect_dist;
	size_t len;
	size_t dist;

	for (len = 3U; len <= 258U; len++) {
		unsigned int sym;
		unsigned int extra_n;
		uint16_t extra_v;
		unsigned int lsym;
		unsigned int dsym;

		if (ark_deflate_test_length_symbol(len, &sym, &extra_n,
		                                   &extra_v) != 0)
			return 1;
		ark_deflate_test_token_symbols(len, 1U, &lsym, &dsym);
		if (lsym != sym)
			return 1;
	}
	expect_dist = 0U;
	for (dist = 1U; dist <= 32768U; dist++) {
		unsigned int lsym;
		unsigned int dsym;

		if (expect_dist < 29U && dist >= dist_base[expect_dist + 1U])
			expect_dist++;
		ark_deflate_test_token_symbols(3U, dist, &lsym, &dsym);
		if (dsym != expect_dist)
			return 1;
	}
	return expect_dist == 29U ? 0 : 1;
}

/*
 * The portable trailing-equal-byte count used by the match search: every
 * position of the lowest differing bit, with and without higher bits set.
 */
int test_deflate_equal_low_bytes(void)
{
	unsigned int bit;

	for (bit = 0U; bit < 64U; bit++) {
		uint64_t low;

		low = (uint64_t)1U << bit;
		if (ark_deflate_test_equal_low_bytes(low) != bit / 8U)
			return 1;
		if (ark_deflate_test_equal_low_bytes(low | ~(low - 1U)) !=
		    bit / 8U)
			return 1;
	}
	return 0;
}

/*
 * One parse spans the whole input, so a block's matches reach back into the
 * previous block. 1 MiB made of one repeated 16 KiB random piece: blocks
 * end every 16..128 KiB, and a parse restarting per block would store the
 * piece's literals again in each of them (140,305 bytes before the single
 * parse; 23,854 with it).
 */
int test_deflate_default_matches_across_blocks(void)
{
	const size_t piece = 16384U;
	const size_t len = ARK_DEFLATE_MAX_INPUT;
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	size_t bound;
	ssize_t comp_len;
	size_t i;
	int rc;

	rc = 1;
	bound = ark_deflate_bound(len);
	in = malloc(len);
	comp = malloc(bound);
	out = malloc(len);
	if (in == NULL || comp == NULL || out == NULL)
		goto done;
	fill_randomish(in, piece);
	for (i = piece; i < len; i++)
		in[i] = in[i - piece];
	comp_len = test_deflate_compress(in, len, comp, bound,
	                                 ARK_DEFLATE_LEVEL_DEFAULT);
	if (comp_len <= 0 || (size_t)comp_len > 2U * piece)
		goto done;
	if (test_deflate_decompress(comp, (size_t)comp_len, out, len) !=
	        (ssize_t)len ||
	    memcmp(out, in, len) != 0)
		goto done;
	rc = 0;
done:
	free(out);
	free(comp);
	free(in);
	return rc;
}

/*
 * The default-level token buffer holds exactly max_input tokens: input of
 * max_input bytes that is nearly all literals fills it (the encoder memory
 * is allocated at its exact size, so an overrun is caught by ASan), and a
 * reused encoder still matches a fresh one.
 */
int test_deflate_default_token_buffer_full(void)
{
	ark_deflate_enc_t *enc;
	ark_deflate_enc_t *fresh;
	uint8_t in[3000];
	uint8_t out[3100];
	uint8_t ref[3100];
	uint8_t back[3000];
	size_t n;
	size_t ref_n;
	int rc;

	fill_randomish(in, sizeof(in));
	enc = test_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, sizeof(in));
	fresh = test_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 15U, sizeof(in));
	rc = 1;
	if (enc == NULL || fresh == NULL)
		goto done;
	if (ark_deflate_enc_oneshot(enc, in, sizeof(in), out, sizeof(out),
	                            &n) != ARK_DEFLATE_OK ||
	    test_deflate_decompress(out, n, back, sizeof(back)) !=
	        (ssize_t)sizeof(in) ||
	    memcmp(back, in, sizeof(in)) != 0)
		goto done;
	fill_pattern(in, sizeof(in));
	if (ark_deflate_enc_oneshot(enc, in, sizeof(in), out, sizeof(out),
	                            &n) != ARK_DEFLATE_OK ||
	    ark_deflate_enc_oneshot(fresh, in, sizeof(in), ref, sizeof(ref),
	                            &ref_n) != ARK_DEFLATE_OK ||
	    n != ref_n || memcmp(out, ref, n) != 0)
		goto done;
	rc = 0;
done:
	free(fresh);
	free(enc);
	return rc;
}

/* fill_text - Pseudo-random English-like text from a small word list. */
static void fill_text(uint8_t *buf, size_t len)
{
	static const char *const words[] = {
	    "the ",     "archive ", "stores ", "files ", "with ",
	    "deflate ", "and ",     "a ",      "hash ",  "index ",
	    "member ",  "chunk ",   "of ",     "data, ", "level.\n",
	};
	uint32_t x;
	size_t i;

	x = 0x1234567U;
	i = 0U;
	while (i < len) {
		const char *w;

		x = x * 1664525U + 1013904223U;
		w = words[(x >> 24) % (sizeof(words) / sizeof(words[0]))];
		while (*w != '\0' && i < len)
			buf[i++] = (uint8_t)*w++;
	}
}

/*
 * Every level 0..9 round-trips text. Level 0 writes only stored blocks
 * (exactly ark_deflate_bound(n) - 1 bytes: no padding byte is needed);
 * higher levels search harder, so on this input level 1 is smaller than
 * stored, level 3 than level 1, level 6 than level 3 and level 9 is not
 * larger than level 6.
 */
int test_deflate_levels_round_trip(void)
{
	const size_t len = 300000U;
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	size_t bound;
	size_t size[10];
	int level;
	int rc;

	rc = 1;
	bound = ark_deflate_bound(len);
	in = malloc(len);
	comp = malloc(bound);
	out = malloc(len);
	if (in == NULL || comp == NULL || out == NULL)
		goto done;
	fill_text(in, len);
	for (level = 0; level <= ARK_DEFLATE_LEVEL_BEST; level++) {
		ssize_t c;

		c = test_deflate_compress(in, len, comp, bound, level);
		if (c <= 0 ||
		    test_deflate_decompress(comp, (size_t)c, out, len) !=
		        (ssize_t)len ||
		    memcmp(out, in, len) != 0)
			goto done;
		if (level == 0 && ((comp[0] >> 1) & 3) != 0)
			goto done;
		size[level] = (size_t)c;
	}
	if (size[0] != bound - 1U || size[1] >= size[0] || size[3] >= size[1] ||
	    size[6] >= size[3] || size[9] > size[6])
		goto done;
	rc = 0;
done:
	free(out);
	free(comp);
	free(in);
	return rc;
}

/*
 * test_dec_new - Allocate and initialize a streaming decoder; NULL on
 * failure. free() releases it.
 */
static ark_deflate_dec_t *test_dec_new(unsigned int window_bits)
{
	ark_deflate_dec_t *dec;
	void *mem;
	size_t size;

	size = ark_deflate_dec_size(window_bits);
	if (size == 0U)
		return NULL;
	mem = malloc(size);
	if (mem == NULL)
		return NULL;
	dec = ark_deflate_dec_init(mem, size, window_bits);
	if (dec == NULL)
		free(mem);
	return dec;
}

/* xorshift32 step for the streaming tests (fixed seeds). */
static uint32_t test_rnd(uint32_t *x)
{
	*x ^= *x << 13;
	*x ^= *x >> 17;
	*x ^= *x << 5;
	return *x;
}

/*
 * stream_feed - Decode src[0..src_len) with dec from its current state,
 * offering in_piece input and out_piece output bytes per call (0 = random
 * piece sizes from *seed). Stops at END, an error, or when the input is
 * used up (NEED_INPUT) or the output is full (NEED_OUTPUT); returns that
 * status and the totals consumed and written.
 */
static ark_deflate_status_t
stream_feed(ark_deflate_dec_t *dec, const uint8_t *src, size_t src_len,
            uint8_t *out, size_t out_cap, size_t in_piece, size_t out_piece,
            uint32_t *seed, size_t *in_total, size_t *out_total)
{
	*in_total = 0U;
	*out_total = 0U;
	for (;;) {
		ark_deflate_status_t st;
		size_t il;
		size_t ol;
		size_t iu;
		size_t ou;

		il = src_len - *in_total;
		ol = out_cap - *out_total;
		if (in_piece != 0U && il > in_piece)
			il = in_piece;
		else if (in_piece == 0U && il > 0U)
			il = 1U + test_rnd(seed) % (il < 700U ? il : 700U);
		if (out_piece != 0U && ol > out_piece)
			ol = out_piece;
		else if (out_piece == 0U && ol > 0U)
			ol = 1U + test_rnd(seed) % (ol < 700U ? ol : 700U);
		st = ark_deflate_dec_stream(dec, src + *in_total, il, &iu,
		                            out + *out_total, ol, &ou);
		*in_total += iu;
		*out_total += ou;
		if (st == ARK_DEFLATE_NEED_INPUT && *in_total < src_len)
			continue;
		if (st == ARK_DEFLATE_NEED_OUTPUT && *out_total < out_cap)
			continue;
		return st;
	}
}

/*
 * Stored, fixed, dynamic and level-1 streams, each followed by junk bytes,
 * decode identically whole, one input byte per call, one output byte per
 * call and in random pieces: END, exact in_used, original bytes.
 */
int test_deflate_dec_stream_splits(void)
{
	static const size_t lens[4] = {3000U, 128U, 20000U, 20000U};
	static const int levels[4] = {
	    ARK_DEFLATE_LEVEL_DEFAULT, ARK_DEFLATE_LEVEL_FAST,
	    ARK_DEFLATE_LEVEL_DEFAULT, ARK_DEFLATE_LEVEL_FAST};
	static const size_t pieces[5][2] = {{SIZE_MAX, SIZE_MAX},
	                                    {1U, SIZE_MAX},
	                                    {SIZE_MAX, 1U},
	                                    {0U, 0U},
	                                    {0U, 0U}};
	ark_deflate_dec_t *dec;
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	uint32_t seed;
	size_t k;
	int rc;

	rc = 1;
	seed = 0x51a5U;
	dec = test_dec_new(15U);
	in = malloc(20000U);
	comp = malloc(ark_deflate_bound(20000U) + 5U);
	out = malloc(20000U);
	if (dec == NULL || in == NULL || comp == NULL || out == NULL)
		goto done;
	for (k = 0; k < 4U; k++) {
		ssize_t c;
		size_t p;

		if (k == 0U) {
			fill_randomish(in, lens[k]);
		} else if (k == 1U) {
			static const char fox[] = "The quick brown fox jumps "
			                          "over the lazy dog. ";
			size_t i;

			for (i = 0; i < lens[k]; i++)
				in[i] = (uint8_t)fox[i % (sizeof(fox) - 1U)];
		} else if (k == 2U)
			fill_windowed(in, lens[k]);
		else
			fill_text(in, lens[k]);
		c = test_deflate_compress(
		    in, lens[k], comp, ark_deflate_bound(lens[k]), levels[k]);
		/* First block types: stored, fixed, dynamic, dynamic. */
		if (c <= 0 || ((comp[0] >> 1) & 3) != (k == 3U ? 2 : (int)k))
			goto done;
		memset(comp + c, 0xa5, 5U);
		for (p = 0; p < 5U; p++) {
			size_t iu;
			size_t ou;

			ark_deflate_dec_reset(dec, 0);
			if (stream_feed(dec, comp, (size_t)c + 5U, out, lens[k],
			                pieces[p][0], pieces[p][1], &seed, &iu,
			                &ou) != ARK_DEFLATE_END ||
			    iu != (size_t)c || ou != lens[k] ||
			    memcmp(out, in, lens[k]) != 0)
				goto done;
		}
	}
	rc = 0;
done:
	free(out);
	free(comp);
	free(in);
	free(dec);
	return rc;
}

/*
 * tb_sync_flush - End a hand-built message as RFC 7692 senders do: an
 * empty non-final stored block (00 00 FF FF after byte alignment).
 */
static void tb_sync_flush(tbits_t *t)
{
	tb_put(t, 0U, 3U);
	t->bits = (t->bits + 7U) & ~(size_t)7U;
	tb_put(t, 0x0000U, 16U);
	tb_put(t, 0xffffU, 16U);
}

/*
 * Messages without a final block (RFC 7692): each ends in a sync flush, the
 * decoder stops with NEED_INPUT after all of it, and the next message may
 * copy from the previous one's output (history in the decoder). A match
 * from history delivered one output byte per call resumes correctly;
 * without history the same message is malformed, and the error stays
 * until reset.
 */
int test_deflate_dec_stream_sync_flush(void)
{
	static const char hello[] = "hello";
	ark_deflate_dec_t *dec;
	tbits_t m1;
	tbits_t m2;
	uint8_t out[16];
	uint32_t seed;
	size_t iu;
	size_t ou;
	size_t i;
	int rc;

	/* Message 1: "hello" as fixed literals; message 2: length 5,
	 * distance 5 (code 259, distance code 4 + 1 extra bit). */
	tb_init(&m1);
	tb_put(&m1, 0U, 1U);
	tb_put(&m1, 1U, 2U);
	for (i = 0; i < 5U; i++)
		tb_fixed_sym(&m1, (unsigned char)hello[i]);
	tb_fixed_sym(&m1, 256U);
	tb_sync_flush(&m1);
	tb_init(&m2);
	tb_put(&m2, 0U, 1U);
	tb_put(&m2, 1U, 2U);
	tb_fixed_sym(&m2, 259U);
	tb_put_code(&m2, 4U, 5U);
	tb_put(&m2, 0U, 1U);
	tb_fixed_sym(&m2, 256U);
	tb_sync_flush(&m2);

	seed = 7U;
	rc = 1;
	dec = test_dec_new(15U);
	if (dec == NULL)
		goto done;
	if (stream_feed(dec, m1.buf, tb_bytes(&m1), out, sizeof(out), 1U,
	                SIZE_MAX, &seed, &iu, &ou) != ARK_DEFLATE_NEED_INPUT ||
	    iu != tb_bytes(&m1) || ou != 5U || memcmp(out, hello, 5U) != 0)
		goto done;
	if (stream_feed(dec, m2.buf, tb_bytes(&m2), out, sizeof(out), SIZE_MAX,
	                1U, &seed, &iu, &ou) != ARK_DEFLATE_NEED_INPUT ||
	    iu != tb_bytes(&m2) || ou != 5U || memcmp(out, hello, 5U) != 0)
		goto done;

	/* keep_history: a new stream still sees the earlier output. */
	ark_deflate_dec_reset(dec, 1);
	if (stream_feed(dec, m2.buf, tb_bytes(&m2), out, sizeof(out), SIZE_MAX,
	                SIZE_MAX, &seed, &iu, &ou) != ARK_DEFLATE_NEED_INPUT ||
	    ou != 5U || memcmp(out, hello, 5U) != 0)
		goto done;

	/* Without history the distance is invalid; the error is sticky. */
	ark_deflate_dec_reset(dec, 0);
	if (stream_feed(dec, m2.buf, tb_bytes(&m2), out, sizeof(out), SIZE_MAX,
	                SIZE_MAX, &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA ||
	    ark_deflate_dec_stream(dec, m1.buf, tb_bytes(&m1), &iu, out,
	                           sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA ||
	    iu != 0U || ou != 0U)
		goto done;
	ark_deflate_dec_reset(dec, 0);
	if (stream_feed(dec, m1.buf, tb_bytes(&m1), out, sizeof(out), SIZE_MAX,
	                SIZE_MAX, &seed, &iu, &ou) != ARK_DEFLATE_NEED_INPUT ||
	    ou != 5U)
		goto done;
	rc = 0;
done:
	free(dec);
	return rc;
}

/*
 * The decoder's window bits bound the distance: a window-15 stream with
 * distances near 32 KiB decodes at 15 and is malformed at 14; so is a
 * stream whose only far matches (distance 20,000) sit mid-stream, decoded
 * whole (fast path), one output byte per call and in the last input bytes
 * (slow path); a window-9
 * stream decodes at 9 in random pieces (history window wraps many times).
 */
int test_deflate_dec_stream_window_limit(void)
{
	const size_t len = 70000U;
	ark_deflate_dec_t *dec15;
	ark_deflate_dec_t *dec14;
	ark_deflate_dec_t *dec9;
	ark_deflate_enc_t *enc9;
	uint8_t *in;
	uint8_t *comp;
	uint8_t *out;
	uint32_t seed;
	size_t c9;
	size_t iu;
	size_t ou;
	ssize_t c;
	int rc;

	rc = 1;
	seed = 99U;
	dec15 = test_dec_new(15U);
	dec14 = test_dec_new(14U);
	dec9 = test_dec_new(9U);
	enc9 = test_enc_new(ARK_DEFLATE_LEVEL_DEFAULT, 9U, len);
	in = malloc(len);
	comp = malloc(ark_deflate_bound(len));
	out = malloc(len);
	if (dec15 == NULL || dec14 == NULL || dec9 == NULL || enc9 == NULL ||
	    in == NULL || comp == NULL || out == NULL)
		goto done;
	fill_windowed(in, len);
	c = test_deflate_compress(in, len, comp, ark_deflate_bound(len),
	                          ARK_DEFLATE_LEVEL_DEFAULT);
	if (c <= 0 ||
	    stream_feed(dec15, comp, (size_t)c, out, len, SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_END ||
	    ou != len || memcmp(out, in, len) != 0 ||
	    stream_feed(dec14, comp, (size_t)c, out, len, SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	/* Random 20,000 bytes, its first 10,000 again, a random tail. */
	ark_deflate_dec_reset(dec15, 0);
	ark_deflate_dec_reset(dec14, 0);
	seed = 0x7a11U;
	for (iu = 0; iu < 33000U; iu++)
		in[iu] = (iu >= 20000U && iu < 30000U)
		             ? in[iu - 20000U]
		             : (uint8_t)(test_rnd(&seed) >> 24);
	c = test_deflate_compress(in, 33000U, comp, ark_deflate_bound(len),
	                          ARK_DEFLATE_LEVEL_DEFAULT);
	if (c <= 0 || (size_t)c > 25000U ||
	    stream_feed(dec15, comp, (size_t)c, out, 33000U, SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_END ||
	    ou != 33000U ||
	    stream_feed(dec14, comp, (size_t)c, out, 33000U, SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA ||
	    ou > 20000U)
		goto done;
	ark_deflate_dec_reset(dec14, 0);
	if (stream_feed(dec14, comp, (size_t)c, out, 33000U, SIZE_MAX, 1U,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA ||
	    ou > 20000U)
		goto done;
	/* The far match last: 12 random bytes, zeros, the 12 bytes again at
	 * distance 20,000. The match is in the final input bytes, which the
	 * slow path decodes even with a large output buffer. */
	for (iu = 12U; iu < 20000U; iu++)
		in[iu] = 0U;
	for (iu = 20000U; iu < 20012U; iu++)
		in[iu] = in[iu - 20000U];
	c = test_deflate_compress(in, 20012U, comp, ark_deflate_bound(len),
	                          ARK_DEFLATE_LEVEL_DEFAULT);
	ark_deflate_dec_reset(dec14, 0);
	if (c <= 0 ||
	    stream_feed(dec14, comp, (size_t)c, out, 20012U, SIZE_MAX, SIZE_MAX,
	                &seed, &iu, &ou) != ARK_DEFLATE_ERR_DATA ||
	    ou != 20000U)
		goto done;
	fill_windowed(in, len);
	if (ark_deflate_enc_oneshot(enc9, in, len, comp, ark_deflate_bound(len),
	                            &c9) != ARK_DEFLATE_OK ||
	    stream_feed(dec9, comp, c9, out, len, 0U, 0U, &seed, &iu, &ou) !=
	        ARK_DEFLATE_END ||
	    iu != c9 || ou != len || memcmp(out, in, len) != 0)
		goto done;
	rc = 0;
done:
	free(out);
	free(comp);
	free(in);
	free(enc9);
	free(dec9);
	free(dec14);
	free(dec15);
	return rc;
}

/*
 * Back-to-back streams: each ends with END at its exact size, further
 * calls return END without consuming, and reset starts the next stream.
 */
int test_deflate_dec_stream_concatenated(void)
{
	static const size_t lens[3] = {3000U, 5000U, 9000U};
	ark_deflate_dec_t *dec;
	uint8_t in[9000];
	uint8_t cat[3 * 9100];
	uint8_t out[9000];
	size_t clen[3];
	size_t total;
	size_t off;
	size_t k;
	int rc;

	rc = 1;
	dec = test_dec_new(15U);
	if (dec == NULL)
		return 1;
	total = 0U;
	for (k = 0; k < 3U; k++) {
		ssize_t c;

		fill_text(in, lens[k]);
		in[0] = (uint8_t)k;
		c = test_deflate_compress(in, lens[k], cat + total,
		                          ark_deflate_bound(lens[k]),
		                          k == 1U ? ARK_DEFLATE_LEVEL_FAST
		                                  : ARK_DEFLATE_LEVEL_DEFAULT);
		if (c <= 0)
			goto done;
		clen[k] = (size_t)c;
		total += clen[k];
	}
	off = 0U;
	for (k = 0; k < 3U; k++) {
		size_t iu;
		size_t ou;

		ark_deflate_dec_reset(dec, 0);
		if (ark_deflate_dec_stream(dec, cat + off, total - off, &iu,
		                           out, sizeof(out),
		                           &ou) != ARK_DEFLATE_END ||
		    iu != clen[k] || ou != lens[k] || out[0] != (uint8_t)k)
			goto done;
		off += iu;
		if (ark_deflate_dec_stream(dec, cat + off, total - off, &iu,
		                           out, sizeof(out),
		                           &ou) != ARK_DEFLATE_END ||
		    iu != 0U || ou != 0U)
			goto done;
	}
	rc = off == total ? 0 : 1;
done:
	free(dec);
	return rc;
}

/*
 * Size query, init checks, usage errors (nothing consumed), malformed
 * input (reserved block type, stored LEN/NLEN mismatch, length 258 as
 * 284 + 31) and truncation (NEED_INPUT with all input used).
 */
int test_deflate_dec_stream_errors(void)
{
	static const uint8_t reserved[] = {0x07};
	static const uint8_t bad_stored[] = {0x01, 0x05, 0x00, 0xfa, 0xfe};
	ark_deflate_dec_t *dec;
	tbits_t t;
	uint8_t out[300];
	uint8_t comp[64];
	void *mem;
	size_t size;
	size_t iu;
	size_t ou;
	ssize_t c;
	int rc;

	if (ark_deflate_dec_size(7U) != 0U || ark_deflate_dec_size(16U) != 0U ||
	    ark_deflate_dec_size(9U) - ark_deflate_dec_size(8U) != 256U)
		return 1;
	size = ark_deflate_dec_size(15U);
	mem = malloc(size + 8U);
	if (mem == NULL)
		return 1;
	rc = 1;
	if (ark_deflate_dec_init(NULL, size, 15U) != NULL ||
	    ark_deflate_dec_init(mem, size - 1U, 15U) != NULL ||
	    ark_deflate_dec_init(mem, size, 16U) != NULL ||
	    ark_deflate_dec_init((uint8_t *)mem + 1, size, 15U) != NULL)
		goto done;
	dec = ark_deflate_dec_init(mem, size, 15U);
	if (dec == NULL || (void *)dec != mem)
		goto done;

	c = test_deflate_compress((const uint8_t *)"abcabcabcabc", 12U, comp,
	                          sizeof(comp), ARK_DEFLATE_LEVEL_DEFAULT);
	if (c <= 0 ||
	    ark_deflate_dec_stream(dec, comp, (size_t)c, NULL, out, 12U, &ou) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_stream(NULL, comp, (size_t)c, &iu, out, 12U, &ou) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_stream(dec, NULL, 1U, &iu, out, 12U, &ou) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    ark_deflate_dec_stream(dec, comp, (size_t)c, &iu, NULL, 1U, &ou) !=
	        ARK_DEFLATE_ERR_USAGE ||
	    iu != 0U || ou != 0U)
		goto done;
	/* Truncated: all input used, more needed; then the rest ends it. */
	if (ark_deflate_dec_stream(dec, comp, (size_t)c - 1U, &iu, out, 12U,
	                           &ou) != ARK_DEFLATE_NEED_INPUT ||
	    iu != (size_t)c - 1U ||
	    ark_deflate_dec_stream(dec, comp + c - 1, 1U, &iu, out + ou,
	                           12U - ou, &ou) != ARK_DEFLATE_END ||
	    memcmp(out, "abcabcabcabc", 12U) != 0)
		goto done;

	ark_deflate_dec_reset(dec, 0);
	if (ark_deflate_dec_stream(dec, reserved, sizeof(reserved), &iu, out,
	                           sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_deflate_dec_reset(dec, 0);
	if (ark_deflate_dec_stream(dec, bad_stored, sizeof(bad_stored), &iu,
	                           out, sizeof(out),
	                           &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_deflate_dec_reset(dec, 0);
	tb_fixed_match_stream(&t, 31U);
	if (ark_deflate_dec_stream(dec, t.buf, tb_bytes(&t), &iu, out,
	                           sizeof(out), &ou) != ARK_DEFLATE_ERR_DATA)
		goto done;
	ark_deflate_dec_reset(dec, 0);
	tb_fixed_match_stream(&t, 30U);
	if (ark_deflate_dec_stream(dec, t.buf, tb_bytes(&t), &iu, out,
	                           sizeof(out), &ou) != ARK_DEFLATE_END ||
	    ou != 258U)
		goto done;
	rc = 0;
done:
	free(mem);
	return rc;
}

/*
 * Differential fuzz against the one-shot decoder (fixed seed): mutated
 * streams give END with the same bytes and in_used exactly where one-shot
 * succeeds, ERR_DATA or NEED_INPUT (truncation) where it reports malformed
 * input, NEED_OUTPUT where its output overflows; feeding in random pieces
 * reaches the same status and output as feeding whole.
 */
int test_deflate_dec_stream_fuzz(void)
{
	const size_t len = 3000U;
	const size_t cap = 4096U;
	ark_deflate_dec_t *dec;
	uint8_t *in;
	uint8_t *comp;
	uint8_t *mut;
	uint8_t *ref;
	uint8_t *out1;
	uint8_t *out2;
	size_t clen[2];
	uint32_t x;
	unsigned int n;
	int rc;

	rc = 1;
	x = 0xc0ffeeU;
	dec = test_dec_new(15U);
	in = malloc(len);
	comp = malloc(2U * ark_deflate_bound(len));
	mut = malloc(ark_deflate_bound(len));
	ref = malloc(cap);
	out1 = malloc(cap);
	out2 = malloc(cap);
	if (dec == NULL || in == NULL || comp == NULL || mut == NULL ||
	    ref == NULL || out1 == NULL || out2 == NULL)
		goto done;
	fill_text(in, len);
	for (n = 0; n < 2U; n++) {
		ssize_t c;

		c = test_deflate_compress(in, len,
		                          comp + n * ark_deflate_bound(len),
		                          ark_deflate_bound(len),
		                          n == 0U ? ARK_DEFLATE_LEVEL_DEFAULT
		                                  : ARK_DEFLATE_LEVEL_FAST);
		if (c <= 0)
			goto done;
		clen[n] = (size_t)c;
	}
	for (n = 0; n < 400U; n++) {
		const uint8_t *src;
		ark_deflate_status_t one;
		ark_deflate_status_t s1;
		ark_deflate_status_t s2;
		size_t mlen;
		size_t used;
		size_t rlen;
		size_t iu1;
		size_t ou1;
		size_t iu2;
		size_t ou2;
		unsigned int k;

		src = comp + (n & 1U) * ark_deflate_bound(len);
		mlen = clen[n & 1U];
		memcpy(mut, src, mlen);
		for (k = 0; k < 1U + test_rnd(&x) % 4U; k++)
			mut[test_rnd(&x) % mlen] ^=
			    (uint8_t)(1U << (test_rnd(&x) % 8U));
		if (test_rnd(&x) % 4U == 0U)
			mlen = 1U + test_rnd(&x) % mlen;

		one =
		    ark_deflate_dec_oneshot(mut, mlen, &used, ref, cap, &rlen);
		ark_deflate_dec_reset(dec, 0);
		s1 = stream_feed(dec, mut, mlen, out1, cap, SIZE_MAX, SIZE_MAX,
		                 &x, &iu1, &ou1);
		ark_deflate_dec_reset(dec, 0);
		s2 = stream_feed(dec, mut, mlen, out2, cap, 0U, 0U, &x, &iu2,
		                 &ou2);
		if (s1 != s2 || ou1 != ou2 || memcmp(out1, out2, ou1) != 0)
			goto done;
		if (one == ARK_DEFLATE_OK &&
		    (s1 != ARK_DEFLATE_END || iu1 != used || ou1 != rlen ||
		     memcmp(out1, ref, rlen) != 0))
			goto done;
		if (one == ARK_DEFLATE_ERR_DATA && s1 != ARK_DEFLATE_ERR_DATA &&
		    s1 != ARK_DEFLATE_NEED_INPUT)
			goto done;
		if (one == ARK_DEFLATE_ERR_OUTPUT &&
		    s1 != ARK_DEFLATE_NEED_OUTPUT)
			goto done;
	}
	rc = 0;
done:
	free(out2);
	free(out1);
	free(ref);
	free(mut);
	free(comp);
	free(in);
	free(dec);
	return rc;
}
