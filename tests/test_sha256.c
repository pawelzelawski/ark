#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha256.h"

/* Fill a buffer with deterministic byte values 0..255 repeating. */
static void fill_sequential(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)i;
}

/* Compare two SHA-256 digests byte-for-byte. */
static int digest_matches(const uint8_t actual[32], const uint8_t expected[32])
{
	return memcmp(actual, expected, 32) == 0;
}

/* NIST SHA-256 vector for empty input. */
int test_sha256_empty(void)
{
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
	    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
	    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	};

	ark_sha256(NULL, 0, digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* NIST SHA-256 vector for "abc". */
int test_sha256_abc(void)
{
	const uint8_t msg[] = {'a', 'b', 'c'};
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
	    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
	    0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};

	ark_sha256(msg, sizeof(msg), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* NIST SHA-256 vector for the standard 448-bit message. */
int test_sha256_448_bits(void)
{
	const uint8_t msg[] =
	    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
	    0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
	    0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
	};

	ark_sha256(msg, sizeof(msg) - 1, digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* 55-byte one-block input vector. */
int test_sha256_one_block(void)
{
	uint8_t msg[55];
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0x46, 0x3e, 0xb2, 0x8e, 0x72, 0xf8, 0x2e, 0x0a, 0x96, 0xc0, 0xa4,
	    0xcc, 0x53, 0x69, 0x0c, 0x57, 0x12, 0x81, 0x13, 0x1f, 0x67, 0x2a,
	    0xa2, 0x29, 0xe0, 0xd4, 0x5a, 0xe5, 0x9b, 0x59, 0x8b, 0x59,
	};

	fill_sequential(msg, sizeof(msg));
	ark_sha256(msg, sizeof(msg), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* Exact 64-byte block input vector. */
int test_sha256_exact_block(void)
{
	uint8_t msg[64];
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58,
	    0xcd, 0xc9, 0xa2, 0x9e, 0x8f, 0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11,
	    0x60, 0x3a, 0x8c, 0x44, 0x7c, 0xd1, 0xd9, 0x15, 0x11, 0x08,
	};

	fill_sequential(msg, sizeof(msg));
	ark_sha256(msg, sizeof(msg), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* 56-byte boundary case split across update calls. */
int test_sha256_block_boundary(void)
{
	ark_sha256_ctx_t ctx_split;
	ark_sha256_ctx_t ctx_single;
	uint8_t msg[56];
	uint8_t digest_split[32];
	uint8_t digest_single[32];
	static const uint8_t expected[32] = {
	    0xda, 0x2a, 0xe4, 0xd6, 0xb3, 0x67, 0x48, 0xf2, 0xa3, 0x18, 0xf2,
	    0x3e, 0x7a, 0xb1, 0xdf, 0xdf, 0x45, 0xac, 0xdc, 0x9d, 0x04, 0x9b,
	    0xd8, 0x0e, 0x59, 0xde, 0x82, 0xa6, 0x08, 0x95, 0xf5, 0x62,
	};

	fill_sequential(msg, sizeof(msg));

	ark_sha256_init(&ctx_split);
	ark_sha256_update(&ctx_split, msg, 55);
	ark_sha256_update(&ctx_split, msg + 55, 1);
	ark_sha256_final(&ctx_split, digest_split);

	ark_sha256_init(&ctx_single);
	ark_sha256_update(&ctx_single, msg, sizeof(msg));
	ark_sha256_final(&ctx_single, digest_single);

	if (!digest_matches(digest_split, digest_single))
		return 1;
	return digest_matches(digest_single, expected) ? 0 : 1;
}

/* 65-byte input crossing into a second block. */
int test_sha256_two_blocks(void)
{
	uint8_t msg[65];
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0x4b, 0xfd, 0x2c, 0x8b, 0x6f, 0x1e, 0xec, 0x7a, 0x2a, 0xfe, 0xb4,
	    0x8b, 0x93, 0x4e, 0xe4, 0xb2, 0x69, 0x41, 0x82, 0x02, 0x7e, 0x6d,
	    0x0f, 0xc0, 0x75, 0x07, 0x4f, 0x2f, 0xab, 0xb3, 0x17, 0x81,
	};

	fill_sequential(msg, sizeof(msg));
	ark_sha256(msg, sizeof(msg), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* 1KB multi-block input vector. */
int test_sha256_multiblock(void)
{
	uint8_t msg[1024];
	uint8_t digest[32];
	static const uint8_t expected[32] = {
	    0x78, 0x5b, 0x07, 0x51, 0xfc, 0x2c, 0x53, 0xdc, 0x14, 0xa4, 0xce,
	    0x3d, 0x80, 0x0e, 0x69, 0xef, 0x9c, 0xe1, 0x00, 0x9e, 0xb3, 0x27,
	    0xcc, 0xf4, 0x58, 0xaf, 0xe0, 0x9c, 0x24, 0x2c, 0x26, 0xc9,
	};

	fill_sequential(msg, sizeof(msg));
	ark_sha256(msg, sizeof(msg), digest);
	return digest_matches(digest, expected) ? 0 : 1;
}

/* Single-shot wrapper and streaming API must match exactly. */
int test_sha256_single_shot_matches_streaming(void)
{
	ark_sha256_ctx_t ctx;
	uint8_t msg[333];
	uint8_t digest_stream[32];
	uint8_t digest_single[32];

	fill_sequential(msg, sizeof(msg));

	ark_sha256_init(&ctx);
	ark_sha256_update(&ctx, msg, 100);
	ark_sha256_update(&ctx, msg + 100, 111);
	ark_sha256_update(&ctx, msg + 211, sizeof(msg) - 211);
	ark_sha256_final(&ctx, digest_stream);

	ark_sha256(msg, sizeof(msg), digest_single);
	return digest_matches(digest_stream, digest_single) ? 0 : 1;
}

/* Verify digest write is exactly 32 bytes and does not clobber tail bytes. */
int test_sha256_output_length(void)
{
	uint8_t out[64];
	const uint8_t msg[] = {'a', 'b', 'c'};
	size_t i;

	memset(out, 0xa5, sizeof(out));
	ark_sha256(msg, sizeof(msg), out);

	for (i = 32; i < sizeof(out); i++) {
		if (out[i] != 0xa5)
			return 1;
	}
	return 0;
}

/* Distinct contexts fed different data must produce different digests. */
int test_sha256_independent_contexts(void)
{
	ark_sha256_ctx_t ctx_a;
	ark_sha256_ctx_t ctx_b;
	const uint8_t msg_a[] = {'a', 'b', 'c'};
	const uint8_t msg_b[] = {'a', 'b', 'c', 'd'};
	uint8_t digest_a[32];
	uint8_t digest_b[32];

	ark_sha256_init(&ctx_a);
	ark_sha256_update(&ctx_a, msg_a, sizeof(msg_a));
	ark_sha256_final(&ctx_a, digest_a);

	ark_sha256_init(&ctx_b);
	ark_sha256_update(&ctx_b, msg_b, sizeof(msg_b));
	ark_sha256_final(&ctx_b, digest_b);

	return memcmp(digest_a, digest_b, 32) != 0 ? 0 : 1;
}
