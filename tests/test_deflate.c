#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deflate.h"

/* ARK_DEFLATE_TEST-only encoder accessors defined in src/deflate.c. */
int ark_deflate_test_length_symbol(size_t, unsigned int *, unsigned int *,
                                   uint16_t *);
int ark_deflate_test_limit_lengths(const uint32_t *, size_t, uint8_t *,
                                   unsigned int);
int ark_deflate_test_cl_plan(const uint8_t *, size_t, const uint8_t *, size_t,
                             uint8_t[19], size_t *);
int ark_deflate_test_header_bits(const uint8_t *, size_t, const uint8_t *,
                                 size_t, size_t *, size_t *);
ssize_t ark_deflate_test_decompress_window(const uint8_t *, size_t, uint8_t *,
                                           size_t, unsigned int);

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

	out_len = ark_deflate_decompress(comp, (size_t)comp_len, out, src_len);
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

	out_len = ark_deflate_decompress(comp, (size_t)comp_len, out, len);
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

int test_deflate_fast_emits_fixed_block(void)
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
	                                 ARK_DEFLATE_LEVEL_FAST);
	rc = (comp_len > 0 && (comp[0] & 0x06U) == 0x02U) ? 0 : 1;

	free(comp);
	return rc;
}

int test_deflate_invalid_stream(void)
{
	const uint8_t bad[] = {0x06};
	uint8_t out[32];

	return ark_deflate_decompress(bad, sizeof(bad), out, sizeof(out)) < 0
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

	if (ark_deflate_decompress(comp, (size_t)comp_len - 1U, out,
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

	if (ark_deflate_decompress(comp, (size_t)comp_len, out, sizeof(out)) >=
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
	    ark_deflate_decompress(comp, (size_t)comp_len, out, sizeof(in));
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
			    ark_deflate_decompress(comp, (size_t)fast_len, out,
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

	/* The old fixed 4-bit header cost pushed small inputs to stored. */
	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)text[i % (sizeof(text) - 1U)];
	btype = -1;
	comp_len =
	    compress_size(in, sizeof(in), ARK_DEFLATE_LEVEL_DEFAULT, &btype);
	if (comp_len <= 0 || (size_t)comp_len >= sizeof(in) || btype != 2)
		return 1;
	return round_trip(in, sizeof(in));
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

	n = ark_deflate_decompress(src, src_len, out, sizeof(out));
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

int test_deflate_accepts_legacy_length_258(void)
{
	/* Fixed block: 'A', then length 258 written as code 284 + extra 31
	 * (pre-2026-10 ark encoders) at distance 1. */
	static const uint8_t in[] = {0x73, 0x1c, 0xf9, 0x00, 0x00};
	uint8_t want[259];

	memset(want, 'A', sizeof(want));
	return decode_expect(in, sizeof(in), want, sizeof(want));
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

/* Encoder size query: window-dependent, level-independent, exact deltas. */
int test_deflate_enc_size_query(void)
{
	ark_deflate_params_t p;
	size_t base;
	size_t size15;
	unsigned int wb;

	p = (ark_deflate_params_t){ARK_DEFLATE_LEVEL_DEFAULT, 15U,
	                           ARK_DEFLATE_MAX_INPUT, 0};
	size15 = ark_deflate_enc_size(&p);
	/* head and prev: 2 x 32768 x 4 bytes plus a small struct. */
	if (size15 <= 262144U || size15 > 262144U + 256U)
		return 1;
	p.level = ARK_DEFLATE_LEVEL_FAST;
	if (ark_deflate_enc_size(&p) != size15)
		return 1;
	p.max_input = 1U;
	if (ark_deflate_enc_size(&p) != size15)
		return 1;

	p.window_bits = 8U;
	base = ark_deflate_enc_size(&p);
	if (base == 0U || base > 2048U + 256U)
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
	    {0, 15U, 1024U, 0},
	    {2, 15U, 1024U, 0},
	    {9, 15U, 1024U, 0},
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
 * Every window size 8..15 and both levels round-trip mixed input, decoded by
 * a decoder that rejects any back-reference beyond the encoder's window.
 */
int test_deflate_window_bits_round_trip(void)
{
	static const int levels[] = {ARK_DEFLATE_LEVEL_DEFAULT,
	                             ARK_DEFLATE_LEVEL_FAST};
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
				ssize_t d;

				d = ark_deflate_test_decompress_window(
				    comp, n, out, len, wb);
				if (d < 0 || (size_t)d != len ||
				    memcmp(in, out, len) != 0)
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
		unsigned int wb;

		fill_windowed(in, len);
		n = test_deflate_compress(in, len, comp, cap,
		                          ARK_DEFLATE_LEVEL_DEFAULT);
		if (n < 0 ||
		    ark_deflate_test_decompress_window(
		        comp, (size_t)n, out, len, 15U) != (ssize_t)len)
			rc = 1;
		for (wb = 8U; rc == 0 && wb <= 14U; wb++) {
			if (ark_deflate_test_decompress_window(
			        comp, (size_t)n, out, len, wb) != -1)
				rc = 1;
		}
		if (rc == 0 && (ark_deflate_test_decompress_window(
		                    comp, (size_t)n, out, len, 7U) != -1 ||
		                ark_deflate_test_decompress_window(
		                    comp, (size_t)n, out, len, 16U) != -1))
			rc = 1;
	}
	free(out);
	free(comp);
	free(in);
	return rc;
}
