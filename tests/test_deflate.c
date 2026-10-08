#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deflate.h"

/* ARK_TEST-only encoder accessors defined in src/deflate.c. */
int ark_deflate_test_length_symbol(size_t, unsigned int *, unsigned int *,
                                   uint16_t *);
int ark_deflate_test_limit_lengths(const uint32_t *, size_t, uint8_t *,
                                   unsigned int);
int ark_deflate_test_cl_plan(const uint8_t *, size_t, const uint8_t *, size_t,
                             uint8_t[19], size_t *);
int ark_deflate_test_header_bits(const uint8_t *, size_t, const uint8_t *,
                                 size_t, size_t *, size_t *);

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

	comp_len = ark_deflate_compress(src, src_len, comp, bound,
	                                ARK_DEFLATE_DEFAULT);
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

	data = malloc(ARK_CHUNK_SIZE);
	if (data == NULL)
		return 1;
	fill_pattern(data, ARK_CHUNK_SIZE);
	rc = round_trip(data, ARK_CHUNK_SIZE);
	free(data);
	return rc;
}

int test_deflate_round_trip_sub_chunk(void)
{
	uint8_t *data;
	int rc;

	data = malloc(ARK_CHUNK_SIZE / 2U);
	if (data == NULL)
		return 1;
	fill_pattern(data, ARK_CHUNK_SIZE / 2U);
	rc = round_trip(data, ARK_CHUNK_SIZE / 2U);
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

	comp_len =
	    ark_deflate_compress(data, len, comp, bound, ARK_DEFLATE_DEFAULT);
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
	    ARK_CHUNK_SIZE,
	};
	size_t i;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		if (ark_deflate_bound(sizes[i]) <= sizes[i])
			return 1;
	}
	return 0;
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

	comp_len =
	    ark_deflate_compress(data, len, comp, bound, ARK_DEFLATE_DEFAULT);
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

	comp_len = ark_deflate_compress(in, sizeof(in), comp, bound,
	                                ARK_DEFLATE_DEFAULT);
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

	comp_len =
	    ark_deflate_compress(in, sizeof(in), comp, bound, ARK_DEFLATE_FAST);
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

	comp_len = ark_deflate_compress(in, sizeof(in), comp, bound,
	                                ARK_DEFLATE_DEFAULT);
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

	comp_len = ark_deflate_compress(in, sizeof(in), comp, bound,
	                                ARK_DEFLATE_DEFAULT);
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

	comp_len = ark_deflate_compress(in, sizeof(in), comp, bound,
	                                ARK_DEFLATE_DEFAULT);
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
 * compress_size - Compress src in mode; return compressed size or -1. When
 * btype is non-NULL it receives the BTYPE of the first block.
 */
static ssize_t compress_size(const uint8_t *src, size_t src_len,
                             ark_deflate_mode_t mode, int *btype)
{
	uint8_t *comp;
	size_t bound;
	ssize_t comp_len;

	bound = ark_deflate_bound(src_len);
	comp = malloc(bound);
	if (comp == NULL)
		return -1;
	comp_len = ark_deflate_compress(src, src_len, comp, bound, mode);
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

	in = calloc(1U, ARK_CHUNK_SIZE);
	if (in == NULL)
		return 1;
	/*
	 * Long zero runs are coded as length-258 matches. With code 285 (no
	 * extra bits) 1 MiB of zeros needs ~1.1 KiB in default mode and
	 * ~6.5 KiB in fast mode; the old 284+31 form needed 4,783 and 9,149.
	 */
	def_len = compress_size(in, ARK_CHUNK_SIZE, ARK_DEFLATE_DEFAULT, NULL);
	fast_len = compress_size(in, ARK_CHUNK_SIZE, ARK_DEFLATE_FAST, NULL);
	rc = def_len > 0 && def_len < 2048 && fast_len > 0 && fast_len < 8192
	         ? round_trip(in, ARK_CHUNK_SIZE)
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

			fast_len = ark_deflate_compress(in, n, comp, bound,
			                                ARK_DEFLATE_FAST);
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
	comp_len = compress_size(in, sizeof(in), ARK_DEFLATE_DEFAULT, &btype);
	if (comp_len <= 0 || (size_t)comp_len >= sizeof(in) || btype != 2)
		return 1;
	return round_trip(in, sizeof(in));
}
