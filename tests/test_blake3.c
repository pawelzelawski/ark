#include "blake3.h"
#include "blake3_cpu.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ARK_BLAKE3_TEST-only accessor defined in src/blake3.c. */
int ark_blake3_test_hash_many(ark_blake3_backend_t, const uint8_t *const *,
                              size_t, size_t, uint64_t, int, uint32_t, uint32_t,
                              uint32_t, uint8_t *);

typedef struct {
	size_t input_len;
	uint8_t digest[32];
} blake3_vector_t;

/*
 * Official BLAKE3 vectors from BLAKE3-team/BLAKE3 test_vectors.json.
 * The API is fixed to 32-byte output, so each entry stores the first 32 bytes.
 */
static const blake3_vector_t g_blake3_vectors[] = {
    {0,
     {
         0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d,
         0xea, 0x36, 0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1,
         0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
     }},
    {1,
     {
         0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1, 0x4c, 0x88, 0x6e,
         0x35, 0xaf, 0xa0, 0x36, 0x73, 0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27,
         0xb5, 0xc1, 0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13,
     }},
    {2,
     {
         0x7b, 0x70, 0x15, 0xbb, 0x92, 0xcf, 0x0b, 0x31, 0x80, 0x37, 0x70,
         0x2a, 0x6c, 0xdd, 0x81, 0xde, 0xe4, 0x12, 0x24, 0xf7, 0x34, 0x68,
         0x4c, 0x2c, 0x12, 0x2c, 0xd6, 0x35, 0x9c, 0xb1, 0xee, 0x63,
     }},
    {3,
     {
         0xe1, 0xbe, 0x4d, 0x7a, 0x8a, 0xb5, 0x56, 0x0a, 0xa4, 0x19, 0x9e,
         0xea, 0x33, 0x98, 0x49, 0xba, 0x8e, 0x29, 0x3d, 0x55, 0xca, 0x0a,
         0x81, 0x00, 0x67, 0x26, 0xd1, 0x84, 0x51, 0x9e, 0x64, 0x7f,
     }},
    {4,
     {
         0xf3, 0x0f, 0x5a, 0xb2, 0x8f, 0xe0, 0x47, 0x90, 0x40, 0x37, 0xf7,
         0x7b, 0x6d, 0xa4, 0xfe, 0xa1, 0xe2, 0x72, 0x41, 0xc5, 0xd1, 0x32,
         0x63, 0x8d, 0x8b, 0xed, 0xce, 0x9d, 0x40, 0x49, 0x4f, 0x32,
     }},
    {5,
     {
         0xb4, 0x0b, 0x44, 0xdf, 0xd9, 0x7e, 0x7a, 0x84, 0xa9, 0x96, 0xa9,
         0x1a, 0xf8, 0xb8, 0x51, 0x88, 0xc6, 0x6c, 0x12, 0x69, 0x40, 0xba,
         0x7a, 0xad, 0x2e, 0x7a, 0xe6, 0xb3, 0x85, 0x40, 0x2a, 0xa2,
     }},
    {6,
     {
         0x06, 0xc4, 0xe8, 0xff, 0xb6, 0x87, 0x2f, 0xad, 0x96, 0xf9, 0xaa,
         0xca, 0x5e, 0xee, 0x15, 0x53, 0xeb, 0x62, 0xae, 0xd0, 0xad, 0x71,
         0x98, 0xce, 0xf4, 0x2e, 0x87, 0xf6, 0xa6, 0x16, 0xc8, 0x44,
     }},
    {7,
     {
         0x3f, 0x87, 0x70, 0xf3, 0x87, 0xfa, 0xad, 0x08, 0xfa, 0xa9, 0xd8,
         0x41, 0x4e, 0x9f, 0x44, 0x9a, 0xc6, 0x8e, 0x6f, 0xf0, 0x41, 0x7f,
         0x67, 0x3f, 0x60, 0x2a, 0x64, 0x6a, 0x89, 0x14, 0x19, 0xfe,
     }},
    {8,
     {
         0x23, 0x51, 0x20, 0x7d, 0x04, 0xfc, 0x16, 0xad, 0xe4, 0x3c, 0xca,
         0xb0, 0x86, 0x00, 0x93, 0x9c, 0x7c, 0x1f, 0xa7, 0x0a, 0x5c, 0x0a,
         0xac, 0xa7, 0x60, 0x63, 0xd0, 0x4c, 0x32, 0x28, 0xea, 0xeb,
     }},
    {63,
     {
         0xe9, 0xbc, 0x37, 0xa5, 0x94, 0xda, 0xad, 0x83, 0xbe, 0x94, 0x70,
         0xdf, 0x7f, 0x7b, 0x37, 0x98, 0x29, 0x7c, 0x3d, 0x83, 0x4c, 0xe8,
         0x0b, 0xa8, 0x5d, 0x6e, 0x20, 0x76, 0x27, 0xb7, 0xdb, 0x7b,
     }},
    {64,
     {
         0x4e, 0xed, 0x71, 0x41, 0xea, 0x4a, 0x5c, 0xd4, 0xb7, 0x88, 0x60,
         0x6b, 0xd2, 0x3f, 0x46, 0xe2, 0x12, 0xaf, 0x9c, 0xac, 0xeb, 0xac,
         0xdc, 0x7d, 0x1f, 0x4c, 0x6d, 0xc7, 0xf2, 0x51, 0x1b, 0x98,
     }},
    {65,
     {
         0xde, 0x1e, 0x5f, 0xa0, 0xbe, 0x70, 0xdf, 0x6d, 0x2b, 0xe8, 0xff,
         0xfd, 0x0e, 0x99, 0xce, 0xaa, 0x8e, 0xb6, 0xe8, 0xc9, 0x3a, 0x63,
         0xf2, 0xd8, 0xd1, 0xc3, 0x0e, 0xcb, 0x6b, 0x26, 0x3d, 0xee,
     }},
    {127,
     {
         0xd8, 0x12, 0x93, 0xfd, 0xa8, 0x63, 0xf0, 0x08, 0xc0, 0x9e, 0x92,
         0xfc, 0x38, 0x2a, 0x81, 0xf5, 0xa0, 0xb4, 0xa1, 0x25, 0x1c, 0xba,
         0x16, 0x34, 0x01, 0x6a, 0x0f, 0x86, 0xa6, 0xbd, 0x64, 0x0d,
     }},
    {128,
     {
         0xf1, 0x7e, 0x57, 0x05, 0x64, 0xb2, 0x65, 0x78, 0xc3, 0x3b, 0xb7,
         0xf4, 0x46, 0x43, 0xf5, 0x39, 0x62, 0x4b, 0x05, 0xdf, 0x1a, 0x76,
         0xc8, 0x1f, 0x30, 0xac, 0xd5, 0x48, 0xc4, 0x4b, 0x45, 0xef,
     }},
    {129,
     {
         0x68, 0x3a, 0xaa, 0xe9, 0xf3, 0xc5, 0xba, 0x37, 0xea, 0xaf, 0x07,
         0x2a, 0xed, 0x0f, 0x9e, 0x30, 0xba, 0xc0, 0x86, 0x51, 0x37, 0xba,
         0xe6, 0x8b, 0x1f, 0xde, 0x4c, 0xa2, 0xae, 0xbd, 0xcb, 0x12,
     }},
    {1023,
     {
         0x10, 0x10, 0x89, 0x70, 0xee, 0xda, 0x3e, 0xb9, 0x32, 0xba, 0xac,
         0x14, 0x28, 0xc7, 0xa2, 0x16, 0x3b, 0x0e, 0x92, 0x4c, 0x9a, 0x9e,
         0x25, 0xb3, 0x5b, 0xba, 0x72, 0xb2, 0x8f, 0x70, 0xbd, 0x11,
     }},
    {1024,
     {
         0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06, 0xf3, 0xfc, 0x83,
         0xde, 0xb8, 0x89, 0x74, 0x4a, 0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d,
         0xaa, 0x55, 0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85, 0x5a, 0xf7,
     }},
    {1025,
     {
         0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3, 0x4f, 0xae, 0xcf,
         0x67, 0xb4, 0xfe, 0x26, 0x3f, 0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1,
         0xff, 0xd9, 0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b, 0x84, 0x44,
     }},
    {2048,
     {
         0xe7, 0x76, 0xb6, 0x02, 0x8c, 0x7c, 0xd2, 0x2a, 0x4d, 0x0b, 0xa1,
         0x82, 0xa8, 0xbf, 0x62, 0x20, 0x5d, 0x2e, 0xf5, 0x76, 0x46, 0x7e,
         0x83, 0x8e, 0xd6, 0xf2, 0x52, 0x9b, 0x85, 0xfb, 0xa2, 0x4a,
     }},
    {2049,
     {
         0x5f, 0x4d, 0x72, 0xf4, 0x0d, 0x7a, 0x5f, 0x82, 0xb1, 0x5c, 0xa2,
         0xb2, 0xe4, 0x4b, 0x1d, 0xe3, 0xc2, 0xef, 0x86, 0xc4, 0x26, 0xc9,
         0x5c, 0x1a, 0xf0, 0xb6, 0x87, 0x95, 0x22, 0x56, 0x30, 0x30,
     }},
    {3072,
     {
         0xb9, 0x8c, 0xb0, 0xff, 0x36, 0x23, 0xbe, 0x03, 0x32, 0x6b, 0x37,
         0x3d, 0xe6, 0xb9, 0x09, 0x52, 0x18, 0x51, 0x3e, 0x64, 0xf1, 0xee,
         0x2e, 0xdd, 0x25, 0x25, 0xc7, 0xad, 0x1e, 0x5c, 0xff, 0xd2,
     }},
    {3073,
     {
         0x71, 0x24, 0xb4, 0x95, 0x01, 0x01, 0x2f, 0x81, 0xcc, 0x7f, 0x11,
         0xca, 0x06, 0x9e, 0xc9, 0x22, 0x6c, 0xec, 0xb8, 0xa2, 0xc8, 0x50,
         0xcf, 0xe6, 0x44, 0xe3, 0x27, 0xd2, 0x2d, 0x3e, 0x1c, 0xd3,
     }},
    {4096,
     {
         0x01, 0x50, 0x94, 0x01, 0x3f, 0x57, 0xa5, 0x27, 0x7b, 0x59, 0xd8,
         0x47, 0x5c, 0x05, 0x01, 0x04, 0x2c, 0x0b, 0x64, 0x2e, 0x53, 0x1b,
         0x0a, 0x1c, 0x8f, 0x58, 0xd2, 0x16, 0x32, 0x29, 0xe9, 0x69,
     }},
    {4097,
     {
         0x9b, 0x40, 0x52, 0xb3, 0x8f, 0x1c, 0x5f, 0xc8, 0xb1, 0xf9, 0xff,
         0x7a, 0xc7, 0xb2, 0x7c, 0xd2, 0x42, 0x48, 0x7b, 0x3d, 0x89, 0x0d,
         0x15, 0xc9, 0x6a, 0x1c, 0x25, 0xb8, 0xaa, 0x0f, 0xb9, 0x95,
     }},
    {5120,
     {
         0x9c, 0xad, 0xc1, 0x5f, 0xed, 0x8b, 0x5d, 0x85, 0x45, 0x62, 0xb2,
         0x6a, 0x95, 0x36, 0xd9, 0x70, 0x7c, 0xad, 0xed, 0xa9, 0xb1, 0x43,
         0x97, 0x8f, 0x31, 0x9a, 0xb3, 0x42, 0x30, 0x53, 0x58, 0x33,
     }},
    {5121,
     {
         0x62, 0x8b, 0xd2, 0xcb, 0x20, 0x04, 0x69, 0x4a, 0xda, 0xab, 0x7b,
         0xbd, 0x77, 0x8a, 0x25, 0xdf, 0x25, 0xc4, 0x7b, 0x9d, 0x41, 0x55,
         0xa5, 0x5f, 0x8f, 0xbd, 0x79, 0xf2, 0xfe, 0x15, 0x4c, 0xff,
     }},
    {6144,
     {
         0x3e, 0x2e, 0x5b, 0x74, 0xe0, 0x48, 0xf3, 0xad, 0xd6, 0xd2, 0x1f,
         0xaa, 0xb3, 0xf8, 0x3a, 0xa4, 0x4d, 0x3b, 0x22, 0x78, 0xaf, 0xb8,
         0x3b, 0x80, 0xb3, 0xc3, 0x51, 0x64, 0xeb, 0xec, 0xa2, 0x05,
     }},
    {6145,
     {
         0xf1, 0x32, 0x3a, 0x86, 0x31, 0x44, 0x6c, 0xc5, 0x05, 0x36, 0xa9,
         0xf7, 0x05, 0xee, 0x5c, 0xb6, 0x19, 0x42, 0x4d, 0x46, 0x88, 0x7f,
         0x3c, 0x37, 0x6c, 0x69, 0x5b, 0x70, 0xe0, 0xf0, 0x50, 0x7f,
     }},
    {7168,
     {
         0x61, 0xda, 0x95, 0x7e, 0xc2, 0x49, 0x9a, 0x95, 0xd6, 0xb8, 0x02,
         0x3e, 0x2b, 0x0e, 0x60, 0x4e, 0xc7, 0xf6, 0xb5, 0x0e, 0x80, 0xa9,
         0x67, 0x8b, 0x89, 0xd2, 0x62, 0x8e, 0x99, 0xad, 0xa7, 0x7a,
     }},
    {7169,
     {
         0xa0, 0x03, 0xfc, 0x7a, 0x51, 0x75, 0x4a, 0x9b, 0x3c, 0x7f, 0xae,
         0x03, 0x67, 0xab, 0x3d, 0x78, 0x2d, 0xcc, 0xf2, 0x88, 0x55, 0xa0,
         0x3d, 0x43, 0x5f, 0x8c, 0xfe, 0x74, 0x60, 0x5e, 0x78, 0x17,
     }},
    {8192,
     {
         0xaa, 0xe7, 0x92, 0x48, 0x4c, 0x8e, 0xfe, 0x4f, 0x19, 0xe2, 0xca,
         0x7d, 0x37, 0x1d, 0x8c, 0x46, 0x7f, 0xfb, 0x10, 0x74, 0x8d, 0x8a,
         0x5a, 0x1a, 0xe5, 0x79, 0x94, 0x8f, 0x71, 0x8a, 0x2a, 0x63,
     }},
    {8193,
     {
         0xba, 0xb6, 0xc0, 0x9c, 0xb8, 0xce, 0x8c, 0xf4, 0x59, 0x26, 0x13,
         0x98, 0xd2, 0xe7, 0xae, 0xf3, 0x57, 0x00, 0xbf, 0x48, 0x81, 0x16,
         0xce, 0xb9, 0x4a, 0x36, 0xd0, 0xf5, 0xf1, 0xb7, 0xbc, 0x3b,
     }},
    {16384,
     {
         0xf8, 0x75, 0xd6, 0x64, 0x6d, 0xe2, 0x89, 0x85, 0x64, 0x6f, 0x34,
         0xee, 0x13, 0xbe, 0x9a, 0x57, 0x6f, 0xd5, 0x15, 0xf7, 0x6b, 0x5b,
         0x0a, 0x26, 0xbb, 0x32, 0x47, 0x35, 0x04, 0x1d, 0xdd, 0xe4,
     }},
    {31744,
     {
         0x62, 0xb6, 0x96, 0x0e, 0x1a, 0x44, 0xbc, 0xc1, 0xeb, 0x1a, 0x61,
         0x1a, 0x8d, 0x62, 0x35, 0xb6, 0xb4, 0xb7, 0x8f, 0x32, 0xe7, 0xab,
         0xc4, 0xfb, 0x4c, 0x6c, 0xdc, 0xce, 0x94, 0x89, 0x5c, 0x47,
     }},
    {102400,
     {
         0xbc, 0x3e, 0x3d, 0x41, 0xa1, 0x14, 0x6b, 0x06, 0x9a, 0xbf, 0xfa,
         0xd3, 0xc0, 0xd4, 0x48, 0x60, 0xcf, 0x66, 0x43, 0x90, 0xaf, 0xce,
         0x4d, 0x96, 0x61, 0xf7, 0x90, 0x2e, 0x79, 0x43, 0xe0, 0x85,
     }},
};

/* Fill input with the official vector byte pattern 0..250 repeating. */
static void fill_vector_input(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)(i % 251U);
}

/* Locate the expected 32-byte digest for one official input length. */
static int find_vector(size_t input_len, const uint8_t **digest)
{
	size_t i;

	for (i = 0; i < sizeof(g_blake3_vectors) / sizeof(g_blake3_vectors[0]);
	     i++) {
		if (g_blake3_vectors[i].input_len != input_len)
			continue;
		*digest = g_blake3_vectors[i].digest;
		return 0;
	}
	return 1;
}

/* Deterministic xorshift32 generator; a fixed seed keeps runs reproducible. */
static uint32_t next_random(uint32_t *state)
{
	uint32_t x;

	x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

/*
 * Feed input into ctx in pieces of random size, empty pieces included. Most
 * pieces are short so that block and chunk boundaries fall inside them; one
 * in four may take any part of the remaining input.
 */
static void update_random_splits(ark_blake3_ctx_t *ctx, const uint8_t *input,
                                 size_t len, uint32_t *rng)
{
	size_t off;

	off = 0;
	while (off < len) {
		size_t n;
		uint32_t r;

		r = next_random(rng);
		if ((r & 3U) == 0)
			n = (size_t)(r >> 2) % (len - off + 1);
		else
			n = (size_t)(r >> 2) % 1100U;
		if (n > len - off)
			n = len - off;
		ark_blake3_update(ctx, input + off, n);
		off += n;
	}
}

/* Compare two fixed-size BLAKE3 digests byte-for-byte. */
static int digest_matches(const uint8_t actual[32], const uint8_t expected[32])
{
	return memcmp(actual, expected, 32) == 0;
}

int test_blake3_vectors_all(void)
{
	uint8_t input[102400];
	uint8_t digest[32];
	size_t i;

	for (i = 0; i < sizeof(g_blake3_vectors) / sizeof(g_blake3_vectors[0]);
	     i++) {
		fill_vector_input(input, g_blake3_vectors[i].input_len);
		ark_blake3(input, g_blake3_vectors[i].input_len, digest);
		if (!digest_matches(digest, g_blake3_vectors[i].digest))
			return 1;
	}
	return 0;
}

int test_blake3_empty(void)
{
	uint8_t digest[32];
	const uint8_t *expected;

	if (find_vector(0, &expected) != 0)
		return 1;
	ark_blake3(NULL, 0, digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

int test_blake3_single_chunk(void)
{
	uint8_t input[1024];
	uint8_t digest[32];
	const uint8_t *expected;

	if (find_vector(1024, &expected) != 0)
		return 1;
	fill_vector_input(input, sizeof(input));
	ark_blake3(input, sizeof(input), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

int test_blake3_multi_chunk(void)
{
	uint8_t input[1025];
	uint8_t digest[32];
	const uint8_t *expected;

	if (find_vector(1025, &expected) != 0)
		return 1;
	fill_vector_input(input, sizeof(input));
	ark_blake3(input, sizeof(input), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

int test_blake3_large(void)
{
	uint8_t input[31744];
	uint8_t digest[32];
	const uint8_t *expected;

	if (find_vector(31744, &expected) != 0)
		return 1;
	fill_vector_input(input, sizeof(input));
	ark_blake3(input, sizeof(input), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

int test_blake3_output_fixed_32(void)
{
	uint8_t out[64];
	const uint8_t msg[] = {'a', 'r', 'k'};
	size_t i;

	memset(out, 0xa5, sizeof(out));
	ark_blake3(msg, sizeof(msg), out);
	for (i = 32; i < sizeof(out); i++) {
		if (out[i] != 0xa5)
			return 1;
	}
	return 0;
}

int test_blake3_single_shot_matches_streaming(void)
{
	ark_blake3_ctx_t ctx;
	uint8_t input[4097];
	uint8_t digest_stream[32];
	uint8_t digest_single[32];

	fill_vector_input(input, sizeof(input));

	ark_blake3_init(&ctx);
	ark_blake3_update(&ctx, input, 1000);
	ark_blake3_update(&ctx, input + 1000, 2048);
	ark_blake3_update(&ctx, input + 3048, sizeof(input) - 3048);
	ark_blake3_final(&ctx, digest_stream);

	ark_blake3(input, sizeof(input), digest_single);
	return digest_matches(digest_stream, digest_single) ? 0 : 1;
}

int test_blake3_independent_contexts(void)
{
	ark_blake3_ctx_t ctx_a;
	ark_blake3_ctx_t ctx_b;
	uint8_t input_a[63];
	uint8_t input_b[64];
	uint8_t digest_a[32];
	uint8_t digest_b[32];

	fill_vector_input(input_a, sizeof(input_a));
	fill_vector_input(input_b, sizeof(input_b));

	ark_blake3_init(&ctx_a);
	ark_blake3_update(&ctx_a, input_a, sizeof(input_a));
	ark_blake3_final(&ctx_a, digest_a);

	ark_blake3_init(&ctx_b);
	ark_blake3_update(&ctx_b, input_b, sizeof(input_b));
	ark_blake3_final(&ctx_b, digest_b);

	return memcmp(digest_a, digest_b, 32) != 0 ? 0 : 1;
}

int test_blake3_incremental_updates(void)
{
	ark_blake3_ctx_t ctx;
	uint8_t input[2049];
	uint8_t digest_inc[32];
	uint8_t digest_single[32];
	size_t i;

	fill_vector_input(input, sizeof(input));

	ark_blake3_init(&ctx);
	for (i = 0; i < sizeof(input); i++)
		ark_blake3_update(&ctx, input + i, 1);
	ark_blake3_final(&ctx, digest_inc);

	ark_blake3(input, sizeof(input), digest_single);
	return digest_matches(digest_inc, digest_single) ? 0 : 1;
}

/* Every official vector, fed in randomly sized pieces (fixed seed). */
int test_blake3_vectors_random_splits(void)
{
	ark_blake3_ctx_t ctx;
	uint8_t input[102400];
	uint8_t digest[32];
	uint32_t rng;
	size_t i;

	rng = 0xb1a4e301U;
	for (i = 0; i < sizeof(g_blake3_vectors) / sizeof(g_blake3_vectors[0]);
	     i++) {
		fill_vector_input(input, g_blake3_vectors[i].input_len);
		ark_blake3_init(&ctx);
		update_random_splits(&ctx, input, g_blake3_vectors[i].input_len,
		                     &rng);
		ark_blake3_final(&ctx, digest);
		if (!digest_matches(digest, g_blake3_vectors[i].digest))
			return 1;
	}
	return 0;
}

/*
 * Random inputs of random length (up to eight chunks), hashed once in one
 * update and once in randomly sized pieces, must give the same digest.
 */
int test_blake3_random_splits(void)
{
	ark_blake3_ctx_t ctx;
	uint8_t input[8 * 1024 + 1];
	uint8_t digest_split[32];
	uint8_t digest_single[32];
	uint32_t rng;
	size_t i;

	rng = 0xb1a4e302U;
	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)next_random(&rng);

	for (i = 0; i < 100; i++) {
		size_t len;

		len = (size_t)next_random(&rng) % (sizeof(input) + 1);
		ark_blake3(input, len, digest_single);

		ark_blake3_init(&ctx);
		update_random_splits(&ctx, input, len, &rng);
		ark_blake3_final(&ctx, digest_split);
		if (!digest_matches(digest_split, digest_single))
			return 1;
	}
	return 0;
}

/* Every backend, in enum order, with the name the tests print. */
static const struct {
	ark_blake3_backend_t backend;
	const char *name;
} g_blake3_backends[] = {
    {ARK_BLAKE3_BACKEND_PORTABLE, "portable"},
    {ARK_BLAKE3_BACKEND_SSE41, "x86 SSE4.1"},
    {ARK_BLAKE3_BACKEND_AVX2, "x86 AVX2"},
    {ARK_BLAKE3_BACKEND_NEON, "arm64 NEON"},
};

#define BLAKE3_TEST_BACKENDS                                                   \
	(sizeof(g_blake3_backends) / sizeof(g_blake3_backends[0]))

/*
 * Hash input with backend b: in one update when piece is 0, else in
 * pieces of piece bytes (the last one shorter).
 */
static int backend_digest(ark_blake3_backend_t b, const uint8_t *input,
                          size_t len, size_t piece, uint8_t digest[32])
{
	ark_blake3_ctx_t ctx;
	size_t off;

	if (ark_blake3_init_backend(&ctx, b) != 0)
		return -1;
	if (piece == 0)
		piece = len;
	off = 0;
	while (off < len) {
		size_t n;

		n = len - off < piece ? len - off : piece;
		ark_blake3_update(&ctx, input + off, n);
		off += n;
	}
	ark_blake3_final(&ctx, digest);
	return 0;
}

/*
 * Every official vector through every backend the CPU supports, in one
 * update and in random pieces; prints which backends ran. A supported
 * backend must be accepted by ark_blake3_init_backend().
 */
int test_blake3_backend_vectors(void)
{
	static uint8_t input[102400];
	uint8_t digest[32];
	uint32_t rng;
	size_t b;
	size_t i;
	int rc;

	rc = 0;
	rng = 0xb1a4e303U;
	printf("blake3 backends tested:");
	for (b = 0; b < BLAKE3_TEST_BACKENDS; b++) {
		ark_blake3_backend_t be;

		be = g_blake3_backends[b].backend;
		if (!ark_blake3_cpu_supports(be))
			continue;
		printf(" [%s]", g_blake3_backends[b].name);
		for (i = 0;
		     i < sizeof(g_blake3_vectors) / sizeof(g_blake3_vectors[0]);
		     i++) {
			ark_blake3_ctx_t ctx;
			size_t len;

			len = g_blake3_vectors[i].input_len;
			fill_vector_input(input, len);
			if (backend_digest(be, input, len, 0, digest) != 0 ||
			    !digest_matches(digest, g_blake3_vectors[i].digest))
				rc = 1;
			if (ark_blake3_init_backend(&ctx, be) != 0)
				rc = 1;
			update_random_splits(&ctx, input, len, &rng);
			ark_blake3_final(&ctx, digest);
			if (!digest_matches(digest, g_blake3_vectors[i].digest))
				rc = 1;
		}
	}
	printf("\n");
	return rc;
}

/*
 * Whole chunks hashed as subtrees (one large update) give the digest of
 * chunk-by-chunk hashing (updates of at most one chunk never take the
 * subtree path), for every supported backend: lengths around subtree
 * sizes up to 3 x 64 chunks, and a first update of a few chunks so that
 * the following subtrees start at counters that are not multiples of 64.
 */
int test_blake3_subtree_matches_sequential(void)
{
	static const size_t chunks[] = {1,  2,  3,  4,   5,   7,   8,
	                                9,  15, 16, 17,  31,  32,  33,
	                                63, 64, 65, 127, 128, 129, 192};
	static uint8_t input[193 * 1024];
	uint32_t rng;
	size_t b;
	size_t i;
	int rc;

	rc = 0;
	rng = 0xb1a4e304U;
	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)next_random(&rng);
	for (b = 0; b < BLAKE3_TEST_BACKENDS; b++) {
		ark_blake3_backend_t be;

		be = g_blake3_backends[b].backend;
		if (!ark_blake3_cpu_supports(be))
			continue;
		for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
			static const size_t extra[] = {0, 1, 1023};
			size_t e;

			for (e = 0; e < 3; e++) {
				ark_blake3_ctx_t ctx;
				uint8_t want[32];
				uint8_t got[32];
				size_t len;
				size_t first;

				len = chunks[i] * 1024U + extra[e];
				if (backend_digest(be, input, len, 1024,
				                   want) != 0 ||
				    backend_digest(be, input, len, 0, got) !=
				        0 ||
				    !digest_matches(got, want))
					rc = 1;
				/* 1..5 chunks first, then the rest at once. */
				first = (i % 5U + 1U) * 1024U;
				if (first > len)
					first = len;
				if (ark_blake3_init_backend(&ctx, be) != 0)
					rc = 1;
				ark_blake3_update(&ctx, input, first);
				ark_blake3_update(&ctx, input + first,
				                  len - first);
				ark_blake3_final(&ctx, got);
				if (!digest_matches(got, want))
					rc = 1;
			}
		}
	}
	return rc;
}

/*
 * Each supported SIMD backend agrees with the portable one on 40 random
 * lengths up to 160 KiB fed in random pieces from an odd address
 * (unaligned loads), and on 1 MiB hashed in one update.
 */
int test_blake3_backend_differential(void)
{
	static uint8_t msg[1048576 + 1];
	uint32_t rng;
	size_t b;
	size_t i;
	int rc;

	rc = 0;
	rng = 0xb1a4e305U;
	for (i = 0; i < sizeof(msg); i++)
		msg[i] = (uint8_t)next_random(&rng);
	for (b = 1; b < BLAKE3_TEST_BACKENDS; b++) {
		ark_blake3_backend_t be;
		uint8_t want[32];
		uint8_t got[32];

		be = g_blake3_backends[b].backend;
		if (!ark_blake3_cpu_supports(be))
			continue;
		for (i = 0; i < 40; i++) {
			ark_blake3_ctx_t ctx;
			size_t len;

			len = (size_t)next_random(&rng) % (160U * 1024U + 1U);
			ark_blake3(msg + 1, len, want);
			if (ark_blake3_init_backend(&ctx, be) != 0)
				rc = 1;
			update_random_splits(&ctx, msg + 1, len, &rng);
			ark_blake3_final(&ctx, got);
			if (!digest_matches(got, want))
				rc = 1;
		}
		ark_blake3(msg, sizeof(msg) - 1U, want);
		if (backend_digest(be, msg, sizeof(msg) - 1U, 0, got) != 0 ||
		    !digest_matches(got, want))
			rc = 1;
	}
	return rc;
}

/*
 * An unknown backend, and a SIMD backend this build does not have, make
 * ark_blake3_init_backend() return -1 and leave a working portable
 * context; ark_blake3_cpu_supports() reports only what init accepts, and
 * ark_blake3_cpu_best() returns a supported backend.
 */
int test_blake3_backend_selection(void)
{
	static uint8_t input[2048];
	ark_blake3_ctx_t ctx;
	uint8_t digest[32];
	const uint8_t *expected;
	size_t b;
	int rc;

	rc = 0;
	if (find_vector(2048, &expected) != 0)
		return 1;
	fill_vector_input(input, sizeof(input));
	if (ark_blake3_init_backend(&ctx, (ark_blake3_backend_t)99) != -1 ||
	    ctx.backend != ARK_BLAKE3_BACKEND_PORTABLE)
		rc = 1;
	ark_blake3_update(&ctx, input, sizeof(input));
	ark_blake3_final(&ctx, digest);
	if (!digest_matches(digest, expected) ||
	    ark_blake3_cpu_supports((ark_blake3_backend_t)99) != 0 ||
	    !ark_blake3_cpu_supports(ark_blake3_cpu_best()))
		rc = 1;
	for (b = 0; b < BLAKE3_TEST_BACKENDS; b++) {
		ark_blake3_backend_t be;
		int built;

		be = g_blake3_backends[b].backend;
		built = ark_blake3_init_backend(&ctx, be) == 0;
		if (ark_blake3_cpu_supports(be) && !built)
			rc = 1;
		if (!built && ctx.backend != ARK_BLAKE3_BACKEND_PORTABLE)
			rc = 1;
	}
	return rc;
}

/*
 * Each supported SIMD backend's lanes equal the portable code for 13
 * inputs (8 + 4 lanes + 1 portable on AVX2) in four cases: whole chunks
 * with counters that carry into the high 32 bits inside a lane group,
 * one-block parents (no counter increment), three blocks with all flag
 * arguments distinct, and a counter above 2^32 without increment.
 */
int test_blake3_backend_lanes(void)
{
	static const struct {
		size_t blocks;
		uint64_t counter;
		int increment;
		uint32_t flags;
		uint32_t start;
		uint32_t end;
	} c[] = {
	    {16, 0xfffffffaU, 1, 0x00U, 0x01U, 0x02U},
	    {1, 0, 0, 0x04U, 0x00U, 0x00U},
	    {3, 0x123456789aU, 1, 0x10U, 0x01U, 0x22U},
	    {2, 0x200000007U, 0, 0x00U, 0x01U, 0x02U},
	};
	static uint8_t input[13 * 1024 + 3];
	const uint8_t *inputs[13];
	uint8_t want[13 * 32];
	uint8_t got[13 * 32];
	uint32_t rng;
	size_t b;
	size_t i;
	size_t k;
	int rc;

	rc = 0;
	rng = 0xb1a4e306U;
	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)next_random(&rng);
	for (i = 0; i < 13; i++)
		inputs[i] = input + 3 + i * 1024U - (i % 3U);
	for (b = 1; b < BLAKE3_TEST_BACKENDS; b++) {
		ark_blake3_backend_t be;

		be = g_blake3_backends[b].backend;
		if (!ark_blake3_cpu_supports(be))
			continue;
		for (k = 0; k < sizeof(c) / sizeof(c[0]); k++) {
			if (ark_blake3_test_hash_many(
			        ARK_BLAKE3_BACKEND_PORTABLE, inputs, 13,
			        c[k].blocks, c[k].counter, c[k].increment,
			        c[k].flags, c[k].start, c[k].end, want) != 0 ||
			    ark_blake3_test_hash_many(
			        be, inputs, 13, c[k].blocks, c[k].counter,
			        c[k].increment, c[k].flags, c[k].start,
			        c[k].end, got) != 0 ||
			    memcmp(want, got, sizeof(want)) != 0)
				rc = 1;
		}
	}
	return rc;
}
