#include "blake3.h"

#define BLAKE3_BLOCK_LEN 64U
#define BLAKE3_CHUNK_LEN 1024U
#define BLAKE3_FLAG_CHUNK_START 0x01U
#define BLAKE3_FLAG_CHUNK_END 0x02U
#define BLAKE3_FLAG_PARENT 0x04U
#define BLAKE3_FLAG_ROOT 0x08U

typedef struct blake3_output {
	uint32_t input_cv[8];
	uint32_t block[16];
	uint64_t counter;
	uint32_t block_len;
	uint32_t flags;
} blake3_output_t;

static const uint32_t blake3_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const uint8_t blake3_msg_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/* Rotate-right primitive used by the BLAKE3 mixing function. */
static uint32_t rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32U - n));
}

/* Local zeroing helper to avoid libc calls in this component. */
static void zero_bytes(uint8_t *dst, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = 0;
}

/* Local copy helper for fixed-size internal buffers. */
static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = src[i];
}

/* Load one little-endian 32-bit word from byte input. */
static uint32_t load_le32(const uint8_t src[4])
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

/* Store one 32-bit word as little-endian bytes. */
static void store_le32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)x;
	dst[1] = (uint8_t)(x >> 8);
	dst[2] = (uint8_t)(x >> 16);
	dst[3] = (uint8_t)(x >> 24);
}

/* Convert a 64-byte block into sixteen little-endian words. */
static void block_to_words(const uint8_t block[64], uint32_t words[16])
{
	size_t i;

	for (i = 0; i < 16; i++)
		words[i] = load_le32(block + i * 4);
}

/* Compute current chunk length from compressed-block count and buffer fill. */
static size_t chunk_len(const ark_blake3_ctx_t *ctx)
{
	return (size_t)ctx->blocks_compressed * BLAKE3_BLOCK_LEN +
	       ctx->block_len;
}

/* One BLAKE3 G mixing operation over four state words and two message words. */
static void g_mix(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
                  uint32_t mx, uint32_t my)
{
	state[a] = state[a] + state[b] + mx;
	state[d] = rotr32(state[d] ^ state[a], 16);
	state[c] += state[d];
	state[b] = rotr32(state[b] ^ state[c], 12);
	state[a] = state[a] + state[b] + my;
	state[d] = rotr32(state[d] ^ state[a], 8);
	state[c] += state[d];
	state[b] = rotr32(state[b] ^ state[c], 7);
}

/* Execute one BLAKE3 round with the provided message permutation. */
static void round_fn(uint32_t state[16], const uint32_t m[16],
                     const uint8_t sched[16])
{
	g_mix(state, 0, 4, 8, 12, m[sched[0]], m[sched[1]]);
	g_mix(state, 1, 5, 9, 13, m[sched[2]], m[sched[3]]);
	g_mix(state, 2, 6, 10, 14, m[sched[4]], m[sched[5]]);
	g_mix(state, 3, 7, 11, 15, m[sched[6]], m[sched[7]]);
	g_mix(state, 0, 5, 10, 15, m[sched[8]], m[sched[9]]);
	g_mix(state, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
	g_mix(state, 2, 7, 8, 13, m[sched[12]], m[sched[13]]);
	g_mix(state, 3, 4, 9, 14, m[sched[14]], m[sched[15]]);
}

/* Compress one BLAKE3 block and return the 16-word output state. */
static void blake3_compress(const uint32_t cv[8], const uint32_t block[16],
                            uint64_t counter, uint32_t block_len,
                            uint32_t flags, uint32_t out[16])
{
	uint32_t state[16];
	size_t i;

	for (i = 0; i < 8; i++) {
		state[i] = cv[i];
		state[i + 8] = blake3_iv[i];
	}
	state[12] = (uint32_t)counter;
	state[13] = (uint32_t)(counter >> 32);
	state[14] = block_len;
	state[15] = flags;

	for (i = 0; i < 7; i++)
		round_fn(state, block, blake3_msg_schedule[i]);

	for (i = 0; i < 8; i++) {
		out[i] = state[i] ^ state[i + 8];
		out[i + 8] = state[i + 8] ^ cv[i];
	}
}

/* Derive an 8-word chaining value from a compression output descriptor. */
static void output_chaining_value(const blake3_output_t *out, uint32_t cv[8])
{
	uint32_t words[16];
	size_t i;

	blake3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags, words);
	for (i = 0; i < 8; i++)
		cv[i] = words[i];
}

/* Serialize the fixed 32-byte root digest output. See ARCHITECTURE.md §8.4. */
static void output_root_bytes(const blake3_output_t *out, uint8_t digest[32])
{
	uint32_t words[16];
	size_t i;

	blake3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags | BLAKE3_FLAG_ROOT, words);
	for (i = 0; i < 8; i++)
		store_le32(digest + i * 4, words[i]);
}

/* Build the final block descriptor for the current chunk. */
static void chunk_output(const ark_blake3_ctx_t *ctx, blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8; i++)
		out->input_cv[i] = ctx->cv[i];
	block_to_words(ctx->block, out->block);
	out->counter = ctx->chunk_counter;
	out->block_len = (uint32_t)ctx->block_len;
	out->flags = BLAKE3_FLAG_CHUNK_END;
	if (ctx->blocks_compressed == 0)
		out->flags |= BLAKE3_FLAG_CHUNK_START;
}

/* Build the parent-node descriptor from two child chaining values. */
static void parent_output(const uint32_t left_cv[8], const uint32_t right_cv[8],
                          blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8; i++) {
		out->input_cv[i] = blake3_iv[i];
		out->block[i] = left_cv[i];
		out->block[i + 8] = right_cv[i];
	}
	out->counter = 0;
	out->block_len = BLAKE3_BLOCK_LEN;
	out->flags = BLAKE3_FLAG_PARENT;
}

/* Push one completed chunk chaining value into the binary-tree stack. */
static void push_chunk_cv(ark_blake3_ctx_t *ctx, const uint32_t chunk_cv[8],
                          uint64_t total_chunks)
{
	uint32_t cv[8];
	size_t i;

	for (i = 0; i < 8; i++)
		cv[i] = chunk_cv[i];

	while ((total_chunks & 1U) == 0U) {
		blake3_output_t parent;
		uint32_t parent_cv[8];
		uint32_t left_cv[8];

		ctx->cv_stack_len--;
		for (i = 0; i < 8; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		parent_output(left_cv, cv, &parent);
		output_chaining_value(&parent, parent_cv);
		for (i = 0; i < 8; i++)
			cv[i] = parent_cv[i];
		total_chunks >>= 1;
	}

	for (i = 0; i < 8; i++)
		ctx->cv_stack[ctx->cv_stack_len][i] = cv[i];
	ctx->cv_stack_len++;
}

/* Reset context fields that track one chunk's in-progress compression state. */
static void reset_chunk_state(ark_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8; i++)
		ctx->cv[i] = ctx->key[i];
	ctx->block_len = 0;
	ctx->blocks_compressed = 0;
	zero_bytes(ctx->block, sizeof(ctx->block));
}

/*
 * Finalize a completed 1024-byte chunk into the tree stack.
 * See ARCHITECTURE.md §8.4 (sequential mode BLAKE3).
 */
static void finalize_current_chunk(ark_blake3_ctx_t *ctx)
{
	blake3_output_t out;
	uint32_t cv[8];

	chunk_output(ctx, &out);
	output_chaining_value(&out, cv);
	push_chunk_cv(ctx, cv, ctx->chunk_counter + 1U);
	ctx->chunk_counter++;
	reset_chunk_state(ctx);
}

void ark_blake3_init(ark_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8; i++)
		ctx->key[i] = blake3_iv[i];
	ctx->chunk_counter = 0;
	ctx->cv_stack_len = 0;
	reset_chunk_state(ctx);
}

void ark_blake3_update(ark_blake3_ctx_t *ctx, const uint8_t *data, size_t len)
{
	while (len > 0) {
		size_t n;

		if (chunk_len(ctx) == BLAKE3_CHUNK_LEN) {
			finalize_current_chunk(ctx);
			continue;
		}

		/*
		 * Compress buffered full blocks only when more input is
		 * available. The last block of a chunk is finalized with
		 * CHUNK_END in final().
		 */
		if (ctx->block_len == BLAKE3_BLOCK_LEN) {
			uint32_t block_words[16];
			uint32_t out_words[16];
			uint32_t flags;
			size_t i;

			flags = 0;
			if (ctx->blocks_compressed == 0)
				flags |= BLAKE3_FLAG_CHUNK_START;
			block_to_words(ctx->block, block_words);
			blake3_compress(ctx->cv, block_words,
			                ctx->chunk_counter, BLAKE3_BLOCK_LEN,
			                flags, out_words);
			for (i = 0; i < 8; i++)
				ctx->cv[i] = out_words[i];
			ctx->blocks_compressed++;
			ctx->block_len = 0;
			zero_bytes(ctx->block, sizeof(ctx->block));
		}

		n = BLAKE3_BLOCK_LEN - ctx->block_len;
		if (n > len)
			n = len;
		copy_bytes(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
	}
}

void ark_blake3_final(ark_blake3_ctx_t *ctx, uint8_t digest[32])
{
	blake3_output_t out;
	uint32_t cv[8];

	/*
	 * SAFETY: BLAKE3 requires one final root-compression step with ROOT
	 * flag. We preserve the final node descriptor and apply ROOT only at
	 * serialization. See ARCHITECTURE.md §8.4.
	 */
	chunk_output(ctx, &out);
	output_chaining_value(&out, cv);

	while (ctx->cv_stack_len > 0) {
		uint32_t left_cv[8];
		size_t i;

		ctx->cv_stack_len--;
		for (i = 0; i < 8; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		parent_output(left_cv, cv, &out);
		output_chaining_value(&out, cv);
	}

	output_root_bytes(&out, digest);
}

void ark_blake3(const uint8_t *data, size_t len, uint8_t digest[32])
{
	ark_blake3_ctx_t ctx;

	ark_blake3_init(&ctx);
	ark_blake3_update(&ctx, data, len);
	ark_blake3_final(&ctx, digest);
}
