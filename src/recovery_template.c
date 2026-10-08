/*
 * recovery_template.c - standalone ark recovery reader.
 *
 * This file is embedded by `ark generate-reader` and is intended to be built
 * independently as C11:
 *
 *   cc -O2 recovery.c -o recover
 *   ./recover archive.ark
 *
 * It implements footer parsing, index parsing with hash verification,
 * Deflate decompression, and extraction into the current directory.
 *
 * ARCHITECTURE.md cross-reference:
 * - Section 15.2: standalone generated recovery source
 * - Section 2.2: little-endian format fields decoded byte-by-byte
 * - Section 8.2: member hash is over compressed bytes
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define REC_CHUNK_SIZE 1048576U
#define REC_HASH_LEN 32U
#define REC_HEADER_SIZE 16U
#define REC_FOOTER_SIZE 64U
#define REC_MAX_PATH 1023U

#define REC_HASH_BLAKE3 0x01U
#define REC_HASH_SHA256 0x02U

#define REC_TYPE_FILE 0x01U
#define REC_TYPE_DIR 0x02U
#define REC_TYPE_SYMLINK 0x03U
#define REC_TYPE_HARDLINK 0x04U

typedef struct {
	uint8_t type;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t mtime;
	uint64_t size_original;
	uint64_t size_compressed;
	uint64_t data_offset;
	uint8_t hash[REC_HASH_LEN];
	char *path;
	char *link;
	uint32_t chunk_count;
	uint32_t *chunk_sizes;
} rec_member_t;

/* ------------------------------ LE decoding ------------------------------ */

static uint16_t le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

/* ------------------------------- SHA-256 -------------------------------- */

typedef struct {
	uint32_t state[8];
	uint32_t schedule[64];
	uint8_t block[64];
	uint64_t byte_count;
	size_t block_len;
} rec_sha256_ctx_t;

static const uint32_t rec_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rec_rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32U - n));
}

static uint32_t rec_load_be32(const uint8_t src[4])
{
	return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

static void rec_store_be32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)(x >> 24);
	dst[1] = (uint8_t)(x >> 16);
	dst[2] = (uint8_t)(x >> 8);
	dst[3] = (uint8_t)x;
}

static void rec_store_be64(uint8_t dst[8], uint64_t x)
{
	dst[0] = (uint8_t)(x >> 56);
	dst[1] = (uint8_t)(x >> 48);
	dst[2] = (uint8_t)(x >> 40);
	dst[3] = (uint8_t)(x >> 32);
	dst[4] = (uint8_t)(x >> 24);
	dst[5] = (uint8_t)(x >> 16);
	dst[6] = (uint8_t)(x >> 8);
	dst[7] = (uint8_t)x;
}

static void rec_sha256_compress(rec_sha256_ctx_t *ctx, const uint8_t block[64])
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t i;

	for (i = 0; i < 16; i++)
		ctx->schedule[i] = rec_load_be32(block + (size_t)i * 4U);
	for (; i < 64; i++) {
		uint32_t w0, w1;

		w0 = rec_rotr32(ctx->schedule[i - 15], 7) ^
		     rec_rotr32(ctx->schedule[i - 15], 18) ^
		     (ctx->schedule[i - 15] >> 3);
		w1 = rec_rotr32(ctx->schedule[i - 2], 17) ^
		     rec_rotr32(ctx->schedule[i - 2], 19) ^
		     (ctx->schedule[i - 2] >> 10);
		ctx->schedule[i] =
		    ctx->schedule[i - 16] + w0 + ctx->schedule[i - 7] + w1;
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		uint32_t ch, maj, s0, s1, t1, t2;

		s1 = rec_rotr32(e, 6) ^ rec_rotr32(e, 11) ^ rec_rotr32(e, 25);
		ch = (e & f) ^ ((~e) & g);
		t1 = h + s1 + ch + rec_sha256_k[i] + ctx->schedule[i];
		s0 = rec_rotr32(a, 2) ^ rec_rotr32(a, 13) ^ rec_rotr32(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void rec_sha256_init(rec_sha256_ctx_t *ctx)
{
	ctx->state[0] = 0x6a09e667U;
	ctx->state[1] = 0xbb67ae85U;
	ctx->state[2] = 0x3c6ef372U;
	ctx->state[3] = 0xa54ff53aU;
	ctx->state[4] = 0x510e527fU;
	ctx->state[5] = 0x9b05688cU;
	ctx->state[6] = 0x1f83d9abU;
	ctx->state[7] = 0x5be0cd19U;
	ctx->byte_count = 0;
	ctx->block_len = 0;
	memset(ctx->block, 0, sizeof(ctx->block));
	memset(ctx->schedule, 0, sizeof(ctx->schedule));
}

static void rec_sha256_update(rec_sha256_ctx_t *ctx, const uint8_t *data,
                              size_t len)
{
	ctx->byte_count += (uint64_t)len;

	if (ctx->block_len != 0U) {
		size_t n;

		n = sizeof(ctx->block) - ctx->block_len;
		if (n > len)
			n = len;
		memcpy(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
		if (ctx->block_len == sizeof(ctx->block)) {
			rec_sha256_compress(ctx, ctx->block);
			ctx->block_len = 0;
		}
	}

	while (len >= sizeof(ctx->block)) {
		rec_sha256_compress(ctx, data);
		data += sizeof(ctx->block);
		len -= sizeof(ctx->block);
	}

	if (len != 0U) {
		memcpy(ctx->block, data, len);
		ctx->block_len = len;
	}
}

static void rec_sha256_final(rec_sha256_ctx_t *ctx, uint8_t digest[32])
{
	uint8_t zeros[64];
	uint8_t one;
	uint8_t len_be[8];
	uint64_t bit_count;
	size_t pad_zero_len;
	size_t i;

	bit_count = ctx->byte_count * 8U;
	memset(zeros, 0, sizeof(zeros));
	one = 0x80U;
	rec_sha256_update(ctx, &one, 1U);
	if (ctx->block_len <= 56U)
		pad_zero_len = 56U - ctx->block_len;
	else
		pad_zero_len = (64U - ctx->block_len) + 56U;
	while (pad_zero_len > 0U) {
		size_t n;

		n = pad_zero_len;
		if (n > sizeof(zeros))
			n = sizeof(zeros);
		rec_sha256_update(ctx, zeros, n);
		pad_zero_len -= n;
	}
	rec_store_be64(len_be, bit_count);
	rec_sha256_update(ctx, len_be, sizeof(len_be));
	for (i = 0; i < 8U; i++)
		rec_store_be32(digest + i * 4U, ctx->state[i]);
}

/* -------------------------------- BLAKE3 -------------------------------- */

typedef struct {
	uint32_t key[8];
	uint32_t cv[8];
	uint8_t block[64];
	size_t block_len;
	uint8_t blocks_compressed;
	uint64_t chunk_counter;
	uint32_t cv_stack[64][8];
	size_t cv_stack_len;
} rec_blake3_ctx_t;

typedef struct {
	uint32_t input_cv[8];
	uint32_t block[16];
	uint64_t counter;
	uint32_t block_len;
	uint32_t flags;
} rec_blake3_output_t;

#define REC_B3_BLOCK_LEN 64U
#define REC_B3_CHUNK_LEN 1024U
#define REC_B3_FLAG_CHUNK_START 0x01U
#define REC_B3_FLAG_CHUNK_END 0x02U
#define REC_B3_FLAG_PARENT 0x04U
#define REC_B3_FLAG_ROOT 0x08U

static const uint32_t rec_blake3_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const uint8_t rec_blake3_msg_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

static uint32_t rec_load_le32(const uint8_t src[4])
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static void rec_store_le32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)x;
	dst[1] = (uint8_t)(x >> 8);
	dst[2] = (uint8_t)(x >> 16);
	dst[3] = (uint8_t)(x >> 24);
}

static void rec_block_to_words(const uint8_t block[64], uint32_t words[16])
{
	size_t i;

	for (i = 0; i < 16U; i++)
		words[i] = rec_load_le32(block + i * 4U);
}

static size_t rec_b3_chunk_len(const rec_blake3_ctx_t *ctx)
{
	return (size_t)ctx->blocks_compressed * REC_B3_BLOCK_LEN +
	       ctx->block_len;
}

static void rec_b3_g_mix(uint32_t state[16], size_t a, size_t b, size_t c,
                         size_t d, uint32_t mx, uint32_t my)
{
	state[a] = state[a] + state[b] + mx;
	state[d] = rec_rotr32(state[d] ^ state[a], 16);
	state[c] += state[d];
	state[b] = rec_rotr32(state[b] ^ state[c], 12);
	state[a] = state[a] + state[b] + my;
	state[d] = rec_rotr32(state[d] ^ state[a], 8);
	state[c] += state[d];
	state[b] = rec_rotr32(state[b] ^ state[c], 7);
}

static void rec_b3_round(uint32_t state[16], const uint32_t m[16],
                         const uint8_t sched[16])
{
	rec_b3_g_mix(state, 0, 4, 8, 12, m[sched[0]], m[sched[1]]);
	rec_b3_g_mix(state, 1, 5, 9, 13, m[sched[2]], m[sched[3]]);
	rec_b3_g_mix(state, 2, 6, 10, 14, m[sched[4]], m[sched[5]]);
	rec_b3_g_mix(state, 3, 7, 11, 15, m[sched[6]], m[sched[7]]);
	rec_b3_g_mix(state, 0, 5, 10, 15, m[sched[8]], m[sched[9]]);
	rec_b3_g_mix(state, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
	rec_b3_g_mix(state, 2, 7, 8, 13, m[sched[12]], m[sched[13]]);
	rec_b3_g_mix(state, 3, 4, 9, 14, m[sched[14]], m[sched[15]]);
}

static void rec_b3_compress(const uint32_t cv[8], const uint32_t block[16],
                            uint64_t counter, uint32_t block_len,
                            uint32_t flags, uint32_t out[16])
{
	uint32_t state[16];
	size_t i;

	for (i = 0; i < 8U; i++) {
		state[i] = cv[i];
		state[i + 8U] = rec_blake3_iv[i];
	}
	state[12] = (uint32_t)counter;
	state[13] = (uint32_t)(counter >> 32);
	state[14] = block_len;
	state[15] = flags;

	for (i = 0; i < 7U; i++)
		rec_b3_round(state, block, rec_blake3_msg_schedule[i]);

	for (i = 0; i < 8U; i++) {
		out[i] = state[i] ^ state[i + 8U];
		out[i + 8U] = state[i + 8U] ^ cv[i];
	}
}

static void rec_b3_output_cv(const rec_blake3_output_t *out, uint32_t cv[8])
{
	uint32_t words[16];
	size_t i;

	rec_b3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags, words);
	for (i = 0; i < 8U; i++)
		cv[i] = words[i];
}

static void rec_b3_output_root(const rec_blake3_output_t *out,
                               uint8_t digest[32])
{
	uint32_t words[16];
	size_t i;

	rec_b3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags | REC_B3_FLAG_ROOT, words);
	for (i = 0; i < 8U; i++)
		rec_store_le32(digest + i * 4U, words[i]);
}

static void rec_b3_chunk_output(const rec_blake3_ctx_t *ctx,
                                rec_blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		out->input_cv[i] = ctx->cv[i];
	rec_block_to_words(ctx->block, out->block);
	out->counter = ctx->chunk_counter;
	out->block_len = (uint32_t)ctx->block_len;
	out->flags = REC_B3_FLAG_CHUNK_END;
	if (ctx->blocks_compressed == 0)
		out->flags |= REC_B3_FLAG_CHUNK_START;
}

static void rec_b3_parent_output(const uint32_t left_cv[8],
                                 const uint32_t right_cv[8],
                                 rec_blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8U; i++) {
		out->input_cv[i] = rec_blake3_iv[i];
		out->block[i] = left_cv[i];
		out->block[i + 8U] = right_cv[i];
	}
	out->counter = 0;
	out->block_len = REC_B3_BLOCK_LEN;
	out->flags = REC_B3_FLAG_PARENT;
}

static void rec_b3_push_chunk_cv(rec_blake3_ctx_t *ctx,
                                 const uint32_t chunk_cv[8],
                                 uint64_t total_chunks)
{
	uint32_t cv[8];
	size_t i;

	for (i = 0; i < 8U; i++)
		cv[i] = chunk_cv[i];
	while ((total_chunks & 1U) == 0U) {
		rec_blake3_output_t parent;
		uint32_t left_cv[8];
		uint32_t parent_cv[8];

		ctx->cv_stack_len--;
		for (i = 0; i < 8U; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		rec_b3_parent_output(left_cv, cv, &parent);
		rec_b3_output_cv(&parent, parent_cv);
		for (i = 0; i < 8U; i++)
			cv[i] = parent_cv[i];
		total_chunks >>= 1U;
	}
	for (i = 0; i < 8U; i++)
		ctx->cv_stack[ctx->cv_stack_len][i] = cv[i];
	ctx->cv_stack_len++;
}

static void rec_b3_reset_chunk(rec_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		ctx->cv[i] = ctx->key[i];
	ctx->block_len = 0;
	ctx->blocks_compressed = 0;
	memset(ctx->block, 0, sizeof(ctx->block));
}

static void rec_b3_finalize_chunk(rec_blake3_ctx_t *ctx)
{
	rec_blake3_output_t out;
	uint32_t cv[8];

	rec_b3_chunk_output(ctx, &out);
	rec_b3_output_cv(&out, cv);
	rec_b3_push_chunk_cv(ctx, cv, ctx->chunk_counter + 1U);
	ctx->chunk_counter++;
	rec_b3_reset_chunk(ctx);
}

static void rec_blake3_init(rec_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		ctx->key[i] = rec_blake3_iv[i];
	ctx->chunk_counter = 0;
	ctx->cv_stack_len = 0;
	rec_b3_reset_chunk(ctx);
}

static void rec_blake3_update(rec_blake3_ctx_t *ctx, const uint8_t *data,
                              size_t len)
{
	while (len > 0U) {
		size_t n;

		if (rec_b3_chunk_len(ctx) == REC_B3_CHUNK_LEN) {
			rec_b3_finalize_chunk(ctx);
			continue;
		}
		if (ctx->block_len == REC_B3_BLOCK_LEN) {
			uint32_t block_words[16];
			uint32_t out_words[16];
			uint32_t flags;
			size_t i;

			flags = 0;
			if (ctx->blocks_compressed == 0)
				flags |= REC_B3_FLAG_CHUNK_START;
			rec_block_to_words(ctx->block, block_words);
			rec_b3_compress(ctx->cv, block_words,
			                ctx->chunk_counter, REC_B3_BLOCK_LEN,
			                flags, out_words);
			for (i = 0; i < 8U; i++)
				ctx->cv[i] = out_words[i];
			ctx->blocks_compressed++;
			ctx->block_len = 0;
			memset(ctx->block, 0, sizeof(ctx->block));
		}

		n = REC_B3_BLOCK_LEN - ctx->block_len;
		if (n > len)
			n = len;
		memcpy(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
	}
}

static void rec_blake3_final(rec_blake3_ctx_t *ctx, uint8_t digest[32])
{
	rec_blake3_output_t out;
	uint32_t cv[8];

	rec_b3_chunk_output(ctx, &out);
	rec_b3_output_cv(&out, cv);
	while (ctx->cv_stack_len > 0U) {
		uint32_t left_cv[8];
		size_t i;

		ctx->cv_stack_len--;
		for (i = 0; i < 8U; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		rec_b3_parent_output(left_cv, cv, &out);
		rec_b3_output_cv(&out, cv);
	}
	rec_b3_output_root(&out, digest);
}

/* ----------------------------- Deflate decode ---------------------------- */

#define REC_DEFLATE_TABLE_BITS 15U
#define REC_DEFLATE_TABLE_SIZE (1U << REC_DEFLATE_TABLE_BITS)

typedef struct {
	const uint8_t *src;
	size_t len;
	size_t pos;
	uint64_t bits;
	unsigned int nbits;
} rec_bit_reader_t;

typedef struct {
	int16_t sym[REC_DEFLATE_TABLE_SIZE];
	uint8_t len[REC_DEFLATE_TABLE_SIZE];
} rec_huff_table_t;

static const uint16_t rec_len_base[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23,  27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};

static const uint8_t rec_len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

static const uint16_t rec_dist_base[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};

static const uint8_t rec_dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

static const uint8_t rec_cl_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

static uint16_t rec_bit_reverse(uint16_t v, unsigned int n)
{
	uint16_t out;
	unsigned int i;

	out = 0;
	for (i = 0; i < n; i++) {
		out <<= 1;
		out |= (uint16_t)(v & 1U);
		v >>= 1U;
	}
	return out;
}

static int rec_br_ensure_bits(rec_bit_reader_t *br, unsigned int n)
{
	while (br->nbits < n) {
		if (br->pos >= br->len)
			break;
		br->bits |= ((uint64_t)br->src[br->pos++]) << br->nbits;
		br->nbits += 8U;
	}
	return br->nbits >= n ? 0 : -1;
}

static int rec_br_get_bits(rec_bit_reader_t *br, unsigned int n, uint16_t *out)
{
	if (n == 0U) {
		*out = 0;
		return 0;
	}
	if (rec_br_ensure_bits(br, n) != 0)
		return -1;
	*out = (uint16_t)(br->bits & ((1U << n) - 1U));
	br->bits >>= n;
	br->nbits -= n;
	return 0;
}

static int rec_huff_build(rec_huff_table_t *tab, const uint8_t *lengths,
                          size_t n_symbols, unsigned int max_bits)
{
	uint16_t count[16];
	uint16_t next_code[16];
	unsigned int bits;
	uint16_t code;
	size_t i;

	if (max_bits > REC_DEFLATE_TABLE_BITS)
		return -1;
	for (i = 0; i < REC_DEFLATE_TABLE_SIZE; i++) {
		tab->sym[i] = -1;
		tab->len[i] = 0;
	}
	memset(count, 0, sizeof(count));
	memset(next_code, 0, sizeof(next_code));

	for (i = 0; i < n_symbols; i++) {
		if (lengths[i] > max_bits)
			return -1;
		if (lengths[i] != 0U)
			count[lengths[i]]++;
	}

	code = 0;
	for (bits = 1U; bits <= max_bits; bits++) {
		code = (uint16_t)((code + count[bits - 1U]) << 1U);
		next_code[bits] = code;
	}

	for (i = 0; i < n_symbols; i++) {
		uint8_t len;
		uint16_t rev;
		unsigned int fill_shift;
		unsigned int fill_count;
		unsigned int j;

		len = lengths[i];
		if (len == 0U)
			continue;
		rev = rec_bit_reverse(next_code[len], len);
		next_code[len]++;
		fill_shift = REC_DEFLATE_TABLE_BITS - len;
		fill_count = 1U << fill_shift;
		for (j = 0; j < fill_count; j++) {
			unsigned int idx;

			idx = ((unsigned int)rev) | (j << len);
			if (tab->len[idx] != 0U)
				return -1;
			tab->len[idx] = len;
			tab->sym[idx] = (int16_t)i;
		}
	}
	return 0;
}

static int rec_huff_decode(rec_bit_reader_t *br, const rec_huff_table_t *tab,
                           int *sym)
{
	uint16_t idx;
	uint8_t n;

	if (rec_br_ensure_bits(br, 1U) != 0)
		return -1;
	(void)rec_br_ensure_bits(br, REC_DEFLATE_TABLE_BITS);
	idx = (uint16_t)(br->bits & (REC_DEFLATE_TABLE_SIZE - 1U));
	n = tab->len[idx];
	if (n == 0U)
		return -1;
	if (rec_br_ensure_bits(br, n) != 0)
		return -1;
	*sym = tab->sym[idx];
	br->bits >>= n;
	br->nbits -= n;
	return *sym >= 0 ? 0 : -1;
}

static int rec_decode_huffman_block(rec_bit_reader_t *br,
                                    const rec_huff_table_t *lit_tab,
                                    const rec_huff_table_t *dist_tab,
                                    uint8_t *dst, size_t dst_cap,
                                    size_t *dst_pos)
{
	int sym;
	size_t i;

	for (;;) {
		if (rec_huff_decode(br, lit_tab, &sym) != 0)
			return -1;
		if (sym < 256) {
			if (*dst_pos >= dst_cap)
				return -1;
			dst[(*dst_pos)++] = (uint8_t)sym;
			continue;
		}
		if (sym == 256)
			return 0;
		if (sym > 285)
			return -1;
		{
			unsigned int li;
			size_t len;
			size_t dist;
			uint16_t extra;
			int dsym;

			li = (unsigned int)(sym - 257);
			len = rec_len_base[li];
			if (rec_len_extra[li] != 0U) {
				if (rec_br_get_bits(br, rec_len_extra[li],
				                    &extra) != 0)
					return -1;
				len += extra;
			}
			if (rec_huff_decode(br, dist_tab, &dsym) != 0)
				return -1;
			if (dsym < 0 || dsym > 29)
				return -1;
			dist = rec_dist_base[dsym];
			if (rec_dist_extra[dsym] != 0U) {
				if (rec_br_get_bits(br, rec_dist_extra[dsym],
				                    &extra) != 0)
					return -1;
				dist += extra;
			}
			if (dist == 0U || dist > *dst_pos)
				return -1;
			if (*dst_pos + len > dst_cap)
				return -1;
			for (i = 0; i < len; i++)
				dst[*dst_pos + i] = dst[*dst_pos + i - dist];
			*dst_pos += len;
		}
	}
}

static int rec_decode_fixed_block(rec_bit_reader_t *br, uint8_t *dst,
                                  size_t dst_cap, size_t *dst_pos)
{
	rec_huff_table_t lit_tab;
	rec_huff_table_t dist_tab;
	uint8_t lit_len[288];
	uint8_t dist_len[32];
	size_t i;

	for (i = 0; i <= 143U; i++)
		lit_len[i] = 8U;
	for (; i <= 255U; i++)
		lit_len[i] = 9U;
	for (; i <= 279U; i++)
		lit_len[i] = 7U;
	for (; i <= 287U; i++)
		lit_len[i] = 8U;
	for (i = 0; i < 32U; i++)
		dist_len[i] = 5U;

	if (rec_huff_build(&lit_tab, lit_len, 288U, 9U) != 0)
		return -1;
	if (rec_huff_build(&dist_tab, dist_len, 32U, 5U) != 0)
		return -1;
	return rec_decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
	                                dst_pos);
}

static int rec_decode_dynamic_block(rec_bit_reader_t *br, uint8_t *dst,
                                    size_t dst_cap, size_t *dst_pos)
{
	rec_huff_table_t cl_tab;
	rec_huff_table_t lit_tab;
	rec_huff_table_t dist_tab;
	uint8_t cl_len[19];
	uint8_t lit_len[288];
	uint8_t dist_len[32];
	uint8_t lens[288 + 32];
	uint16_t v;
	size_t hlit, hdist, hclen, n, i;

	memset(cl_len, 0, sizeof(cl_len));
	memset(lit_len, 0, sizeof(lit_len));
	memset(dist_len, 0, sizeof(dist_len));

	if (rec_br_get_bits(br, 5U, &v) != 0)
		return -1;
	hlit = (size_t)v + 257U;
	if (rec_br_get_bits(br, 5U, &v) != 0)
		return -1;
	hdist = (size_t)v + 1U;
	if (rec_br_get_bits(br, 4U, &v) != 0)
		return -1;
	hclen = (size_t)v + 4U;
	if (hlit > 286U || hdist > 32U)
		return -1;

	for (i = 0; i < hclen; i++) {
		if (rec_br_get_bits(br, 3U, &v) != 0)
			return -1;
		cl_len[rec_cl_order[i]] = (uint8_t)v;
	}
	if (rec_huff_build(&cl_tab, cl_len, 19U, 7U) != 0)
		return -1;

	n = 0U;
	while (n < hlit + hdist) {
		int sym;

		if (rec_huff_decode(br, &cl_tab, &sym) != 0)
			return -1;
		if (sym >= 0 && sym <= 15) {
			lens[n++] = (uint8_t)sym;
			continue;
		}
		if (sym == 16) {
			size_t rep;
			uint8_t prev;

			if (n == 0U)
				return -1;
			if (rec_br_get_bits(br, 2U, &v) != 0)
				return -1;
			rep = (size_t)v + 3U;
			if (n + rep > hlit + hdist)
				return -1;
			prev = lens[n - 1U];
			for (i = 0; i < rep; i++)
				lens[n++] = prev;
			continue;
		}
		if (sym == 17) {
			size_t rep;

			if (rec_br_get_bits(br, 3U, &v) != 0)
				return -1;
			rep = (size_t)v + 3U;
			if (n + rep > hlit + hdist)
				return -1;
			for (i = 0; i < rep; i++)
				lens[n++] = 0U;
			continue;
		}
		if (sym == 18) {
			size_t rep;

			if (rec_br_get_bits(br, 7U, &v) != 0)
				return -1;
			rep = (size_t)v + 11U;
			if (n + rep > hlit + hdist)
				return -1;
			for (i = 0; i < rep; i++)
				lens[n++] = 0U;
			continue;
		}
		return -1;
	}

	for (i = 0; i < hlit; i++)
		lit_len[i] = lens[i];
	for (i = 0; i < hdist; i++)
		dist_len[i] = lens[hlit + i];
	if (rec_huff_build(&lit_tab, lit_len, 288U, 15U) != 0)
		return -1;
	if (rec_huff_build(&dist_tab, dist_len, 32U, 15U) != 0)
		return -1;

	return rec_decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
	                                dst_pos);
}

static int rec_decode_stored_block(rec_bit_reader_t *br, uint8_t *dst,
                                   size_t dst_cap, size_t *dst_pos)
{
	uint16_t len, nlen;
	size_t i;

	if ((br->nbits & 7U) != 0U) {
		unsigned int drop;

		drop = br->nbits & 7U;
		br->bits >>= drop;
		br->nbits -= drop;
	}
	if (rec_br_get_bits(br, 16U, &len) != 0)
		return -1;
	if (rec_br_get_bits(br, 16U, &nlen) != 0)
		return -1;
	if (((uint16_t)~len) != nlen)
		return -1;
	if (*dst_pos + len > dst_cap)
		return -1;
	if (br->pos + len > br->len)
		return -1;
	for (i = 0; i < len; i++)
		dst[(*dst_pos)++] = br->src[br->pos++];
	return 0;
}

static ssize_t rec_deflate_decompress(const uint8_t *src, size_t src_len,
                                      uint8_t *dst, size_t dst_cap)
{
	rec_bit_reader_t br;
	size_t out_pos;

	if (src == NULL && src_len != 0U)
		return -1;
	if (dst == NULL && dst_cap != 0U)
		return -1;

	br.src = src;
	br.len = src_len;
	br.pos = 0;
	br.bits = 0;
	br.nbits = 0;
	out_pos = 0U;

	for (;;) {
		uint16_t bfinal;
		uint16_t btype;

		if (rec_br_get_bits(&br, 1U, &bfinal) != 0)
			return -1;
		if (rec_br_get_bits(&br, 2U, &btype) != 0)
			return -1;
		if (btype == 0U) {
			if (rec_decode_stored_block(&br, dst, dst_cap,
			                            &out_pos) != 0)
				return -1;
		} else if (btype == 1U) {
			if (rec_decode_fixed_block(&br, dst, dst_cap,
			                           &out_pos) != 0)
				return -1;
		} else if (btype == 2U) {
			if (rec_decode_dynamic_block(&br, dst, dst_cap,
			                             &out_pos) != 0)
				return -1;
		} else {
			return -1;
		}
		if (bfinal != 0U)
			break;
	}
	return (ssize_t)out_pos;
}

/* ---------------------------- Recovery helpers --------------------------- */

static void member_free(rec_member_t *m)
{
	free(m->path);
	free(m->link);
	free(m->chunk_sizes);
	m->path = NULL;
	m->link = NULL;
	m->chunk_sizes = NULL;
}

static void members_free(rec_member_t *members, uint32_t count)
{
	uint32_t i;

	if (members == NULL)
		return;
	for (i = 0U; i < count; i++)
		member_free(&members[i]);
	free(members);
}

static int path_is_safe(const char *path)
{
	const char *p;
	const char *start;

	if (path == NULL || path[0] == '\0')
		return 0;
	if (path[0] == '/')
		return 0;
	for (p = path; *p != '\0'; p++)
		;
	if (p > path && p[-1] == '/')
		return 0;
	start = path;
	for (p = path;; p++) {
		if (*p == '/' || *p == '\0') {
			size_t len;

			len = (size_t)(p - start);
			if (len == 0U)
				return 0;
			if (len == 1U && start[0] == '.')
				return 0;
			if (len == 2U && start[0] == '.' && start[1] == '.')
				return 0;
			if (*p == '\0')
				break;
			start = p + 1;
		}
	}
	return 1;
}

static int mkdirs_for_path(const char *path)
{
	char *tmp;
	char *p;

	/* OWNERSHIP: tmp is released before return on all paths. */
	tmp = strdup(path);
	if (tmp == NULL)
		return -1;
	for (p = tmp + 1; *p != '\0'; p++) {
		struct stat st;

		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0700) != 0) {
			if (errno != EEXIST) {
				free(tmp);
				return -1;
			}
			if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) {
				free(tmp);
				return -1;
			}
		}
		*p = '/';
	}
	free(tmp);
	return 0;
}

static int write_full_fd(int fd, const uint8_t *buf, size_t len)
{
	while (len > 0U) {
		ssize_t n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static void hash_init(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                      rec_blake3_ctx_t *bctx)
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_init(sctx);
	else
		rec_blake3_init(bctx);
}

static void hash_update(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                        rec_blake3_ctx_t *bctx, const uint8_t *data, size_t len)
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_update(sctx, data, len);
	else
		rec_blake3_update(bctx, data, len);
}

static void hash_final(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                       rec_blake3_ctx_t *bctx, uint8_t out[REC_HASH_LEN])
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_final(sctx, out);
	else
		rec_blake3_final(bctx, out);
}

static void compute_empty_digest(uint8_t hash_alg, uint8_t out[REC_HASH_LEN])
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;

	hash_init(hash_alg, &sctx, &bctx);
	hash_final(hash_alg, &sctx, &bctx, out);
}

static int read_whole_file(const char *path, uint8_t **out, size_t *out_len)
{
	FILE *fp;
	long size_long;
	size_t size;
	uint8_t *buf;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return -1;
	}
	size_long = ftell(fp);
	if (size_long < 0) {
		fclose(fp);
		return -1;
	}
	size = (size_t)size_long;
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return -1;
	}
	/* OWNERSHIP: caller frees returned file buffer. */
	buf = (uint8_t *)malloc(size == 0U ? 1U : size);
	if (buf == NULL) {
		fclose(fp);
		return -1;
	}
	if (size > 0U && fread(buf, 1, size, fp) != size) {
		free(buf);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	*out = buf;
	*out_len = size;
	return 0;
}

static int parse_header(const uint8_t *file, size_t file_size,
                        uint8_t *hash_alg)
{
	if (file_size < REC_HEADER_SIZE)
		return -1;
	if (file[0] != 'a' || file[1] != 'r' || file[2] != 'k' ||
	    file[3] != '!' || file[4] != '\n')
		return -1;
	if (file[5] != 0x01U)
		return -1;
	if (file[7] != 0x00U)
		return -1;
	if (file[8] != 0x01U)
		return -1;
	if (file[9] != REC_HASH_BLAKE3 && file[9] != REC_HASH_SHA256)
		return -1;
	if (file[10] != 0U || file[11] != 0U || file[12] != 0U ||
	    file[13] != 0U || file[14] != 0U || file[15] != 0U)
		return -1;
	*hash_alg = file[9];
	return 0;
}

static int parse_footer(const uint8_t *file, size_t file_size,
                        uint64_t *index_offset, uint64_t *index_size,
                        uint32_t *member_count, const uint8_t **index_hash)
{
	const uint8_t *f;

	if (file_size < REC_HEADER_SIZE + REC_FOOTER_SIZE)
		return -1;
	f = file + file_size - REC_FOOTER_SIZE;
	if (le32(f + 52U) != 0x4b52410aU)
		return -1;
	if (f[56] != 0U || f[57] != 0U || f[58] != 0U || f[59] != 0U ||
	    f[60] != 0U || f[61] != 0U || f[62] != 0U || f[63] != 0U)
		return -1;

	*index_offset = le64(f + 0U);
	*index_size = le64(f + 8U);
	*member_count = le32(f + 48U);
	*index_hash = f + 16U;

	if (*index_offset < REC_HEADER_SIZE)
		return -1;
	if (*index_offset > (uint64_t)(file_size - REC_FOOTER_SIZE))
		return -1;
	if (UINT64_MAX - *index_offset < *index_size)
		return -1;
	if (*index_offset + *index_size !=
	    (uint64_t)(file_size - REC_FOOTER_SIZE))
		return -1;
	return 0;
}

static int verify_index_hash(uint8_t hash_alg, const uint8_t *index,
                             size_t index_size,
                             const uint8_t expected[REC_HASH_LEN])
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;
	uint8_t digest[REC_HASH_LEN];

	hash_init(hash_alg, &sctx, &bctx);
	hash_update(hash_alg, &sctx, &bctx, index, index_size);
	hash_final(hash_alg, &sctx, &bctx, digest);
	return memcmp(digest, expected, REC_HASH_LEN) == 0 ? 0 : -1;
}

static int parse_members(const uint8_t *index, size_t index_size,
                         uint32_t member_count, rec_member_t **out_members)
{
	rec_member_t *members;
	size_t off;
	uint32_t i;

	/* OWNERSHIP: caller owns members array and nested allocations. */
	members = (rec_member_t *)calloc(member_count, sizeof(*members));
	if (members == NULL)
		return -1;
	off = 0U;

	for (i = 0U; i < member_count; i++) {
		rec_member_t *m;
		uint16_t path_len;

		m = &members[i];
		if (off + 79U > index_size)
			goto fail;
		m->type = index[off + 0U];
		m->mode = le32(index + off + 1U);
		m->uid = le32(index + off + 5U);
		m->gid = le32(index + off + 9U);
		m->mtime = le64(index + off + 13U);
		m->size_original = le64(index + off + 21U);
		m->size_compressed = le64(index + off + 29U);
		m->data_offset = le64(index + off + 37U);
		memcpy(m->hash, index + off + 45U, REC_HASH_LEN);
		path_len = le16(index + off + 77U);
		off += 79U;

		if (path_len == 0U || path_len > REC_MAX_PATH)
			goto fail;
		if (off + path_len > index_size)
			goto fail;
		m->path = (char *)malloc((size_t)path_len + 1U);
		if (m->path == NULL)
			goto fail;
		memcpy(m->path, index + off, path_len);
		m->path[path_len] = '\0';
		off += path_len;

		if (m->type == REC_TYPE_SYMLINK ||
		    m->type == REC_TYPE_HARDLINK) {
			uint16_t link_len;

			if (off + 2U > index_size)
				goto fail;
			link_len = le16(index + off);
			off += 2U;
			if (link_len == 0U || link_len > REC_MAX_PATH)
				goto fail;
			if (off + link_len > index_size)
				goto fail;
			m->link = (char *)malloc((size_t)link_len + 1U);
			if (m->link == NULL)
				goto fail;
			memcpy(m->link, index + off, link_len);
			m->link[link_len] = '\0';
			off += link_len;
		}

		if (off + 4U > index_size)
			goto fail;
		m->chunk_count = le32(index + off);
		off += 4U;
		if (m->chunk_count > 0U) {
			size_t j;
			uint64_t sum;

			if (off + (size_t)m->chunk_count * 4U > index_size)
				goto fail;
			m->chunk_sizes = (uint32_t *)calloc(m->chunk_count,
			                                    sizeof(uint32_t));
			if (m->chunk_sizes == NULL)
				goto fail;
			sum = 0U;
			for (j = 0U; j < m->chunk_count; j++) {
				m->chunk_sizes[j] = le32(index + off + j * 4U);
				sum += m->chunk_sizes[j];
			}
			off += (size_t)m->chunk_count * 4U;
			if (m->type != REC_TYPE_FILE ||
			    m->size_compressed != sum)
				goto fail;
		}
	}
	if (off != index_size)
		goto fail;

	*out_members = members;
	return 0;

fail:
	members_free(members, member_count);
	return -1;
}

static int extract_regular(const uint8_t *file, size_t file_size,
                           uint64_t index_offset, uint8_t hash_alg,
                           const rec_member_t *m)
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;
	uint8_t digest[REC_HASH_LEN];
	uint8_t *out_buf;
	uint64_t chunk_off;
	uint32_t i;
	int fd;
	int rc;

	if (mkdirs_for_path(m->path) != 0)
		return -1;
	/*
	 * SAFETY: O_NOFOLLOW so a symlink already at the member path is not
	 * followed; open fails instead of writing outside the destination.
	 * See ARCHITECTURE.md section 14.2.
	 */
	fd = open(m->path,
	          O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd == -1)
		return -1;

	hash_init(hash_alg, &sctx, &bctx);
	/* OWNERSHIP: out_buf is freed before return on all paths. */
	out_buf = (uint8_t *)malloc(REC_CHUNK_SIZE);
	if (out_buf == NULL) {
		close(fd);
		return -1;
	}

	chunk_off = m->data_offset;
	rc = -1;
	for (i = 0U; i < m->chunk_count; i++) {
		uint32_t csz;
		const uint8_t *comp;
		ssize_t out_len;
		size_t expected;

		csz = m->chunk_sizes[i];
		if (csz == 0U)
			goto out;
		if (chunk_off > index_offset)
			goto out;
		if (chunk_off + csz > index_offset)
			goto out;
		if (chunk_off + csz > file_size)
			goto out;
		comp = file + chunk_off;

		/* Hash verification is over compressed bytes as stored on disk.
		 */
		hash_update(hash_alg, &sctx, &bctx, comp, csz);
		out_len =
		    rec_deflate_decompress(comp, csz, out_buf, REC_CHUNK_SIZE);
		if (out_len < 0)
			goto out;

		if (m->chunk_count == 0U)
			expected = 0U;
		else if (i + 1U < m->chunk_count)
			expected = REC_CHUNK_SIZE;
		else {
			expected = (size_t)(m->size_original % REC_CHUNK_SIZE);
			if (expected == 0U)
				expected = REC_CHUNK_SIZE;
		}
		if ((size_t)out_len != expected)
			goto out;
		if (write_full_fd(fd, out_buf, (size_t)out_len) != 0)
			goto out;
		chunk_off += csz;
	}

	hash_final(hash_alg, &sctx, &bctx, digest);
	if (memcmp(digest, m->hash, REC_HASH_LEN) != 0)
		goto out;
	rc = 0;

out:
	free(out_buf);
	if (close(fd) != 0)
		rc = -1;
	return rc;
}

static int extract_members(const uint8_t *file, size_t file_size,
                           uint64_t index_offset, uint8_t hash_alg,
                           const uint8_t empty_digest[REC_HASH_LEN],
                           rec_member_t *members, uint32_t member_count)
{
	uint32_t i;

	for (i = 0U; i < member_count; i++) {
		rec_member_t *m;

		m = &members[i];
		if (!path_is_safe(m->path))
			return -1;
		if (m->link != NULL && !path_is_safe(m->link))
			return -1;

		if (m->type == REC_TYPE_DIR || m->type == REC_TYPE_SYMLINK ||
		    m->type == REC_TYPE_HARDLINK ||
		    (m->type == REC_TYPE_FILE && m->size_original == 0U)) {
			if (memcmp(m->hash, empty_digest, REC_HASH_LEN) != 0)
				return -1;
		}

		switch (m->type) {
		case REC_TYPE_DIR:
			if (mkdirs_for_path(m->path) != 0)
				return -1;
			if (mkdir(m->path, 0700) != 0 && errno != EEXIST)
				return -1;
			break;
		case REC_TYPE_SYMLINK:
			if (mkdirs_for_path(m->path) != 0)
				return -1;
			(void)unlink(m->path);
			if (symlink(m->link, m->path) != 0)
				return -1;
			break;
		case REC_TYPE_HARDLINK:
			if (mkdirs_for_path(m->path) != 0)
				return -1;
			(void)unlink(m->path);
			if (link(m->link, m->path) != 0)
				return -1;
			break;
		case REC_TYPE_FILE:
			if (m->size_original == 0U) {
				int fd;

				if (mkdirs_for_path(m->path) != 0)
					return -1;
				/* SAFETY: O_NOFOLLOW as in extract_regular. */
				fd = open(m->path,
				          O_WRONLY | O_CREAT | O_TRUNC |
				              O_NOFOLLOW | O_CLOEXEC,
				          0600);
				if (fd == -1)
					return -1;
				if (close(fd) != 0)
					return -1;
				break;
			}
			if (extract_regular(file, file_size, index_offset,
			                    hash_alg, m) != 0)
				return -1;
			break;
		default:
			return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t *file;
	size_t file_size;
	uint8_t hash_alg;
	uint64_t index_offset;
	uint64_t index_size_u64;
	uint32_t member_count;
	const uint8_t *footer_index_hash;
	const uint8_t *index;
	size_t index_size;
	rec_member_t *members;
	uint8_t empty_digest[REC_HASH_LEN];
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s archive.ark\n", argv[0]);
		return 1;
	}

	file = NULL;
	file_size = 0U;
	members = NULL;
	member_count = 0U;
	rc = 1;

	if (read_whole_file(argv[1], &file, &file_size) != 0) {
		fprintf(stderr, "recover: failed to read %s\n", argv[1]);
		goto out;
	}
	if (parse_header(file, file_size, &hash_alg) != 0) {
		fprintf(stderr, "recover: invalid ark header\n");
		goto out;
	}
	if (parse_footer(file, file_size, &index_offset, &index_size_u64,
	                 &member_count, &footer_index_hash) != 0) {
		fprintf(stderr, "recover: invalid ark footer\n");
		goto out;
	}
	if (index_size_u64 > (uint64_t)SIZE_MAX) {
		fprintf(stderr, "recover: index too large\n");
		goto out;
	}
	index_size = (size_t)index_size_u64;
	index = file + (size_t)index_offset;

	if (verify_index_hash(hash_alg, index, index_size, footer_index_hash) !=
	    0) {
		fprintf(stderr, "recover: index hash mismatch\n");
		goto out;
	}
	if (parse_members(index, index_size, member_count, &members) != 0) {
		fprintf(stderr, "recover: malformed index\n");
		goto out;
	}

	compute_empty_digest(hash_alg, empty_digest);
	if (extract_members(file, file_size, index_offset, hash_alg,
	                    empty_digest, members, member_count) != 0) {
		fprintf(stderr, "recover: extraction failed\n");
		goto out;
	}

	printf("recovery complete: %u member(s) extracted\n", member_count);
	rc = 0;

out:
	members_free(members, member_count);
	free(file);
	return rc;
}
