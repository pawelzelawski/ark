#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deflate.h"

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
