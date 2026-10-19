#include "blake3.h"

#define BLAKE3_BLOCK_LEN 64U
#define BLAKE3_CHUNK_LEN 1024U
#define BLAKE3_FLAG_CHUNK_START 0x01U
#define BLAKE3_FLAG_CHUNK_END 0x02U
#define BLAKE3_FLAG_PARENT 0x04U
#define BLAKE3_FLAG_ROOT 0x08U

/*
 * Most whole chunks hashed as one subtree by update(): a power of two, so
 * the subtree's chaining values fit on the stack (64 x 32 bytes).
 */
#define BLAKE3_MAX_SUBTREE_CHUNKS 64U

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

/*
 * One BLAKE3 G mixing operation over four state words and two message
 * words. G and the round are macros, and the seven rounds are written out,
 * so every state index is a constant: compilers then keep the state in
 * registers. As functions, gcc does not inline the 56 G calls per block and
 * runs at about half of clang's speed (ARCHITECTURE.md §8.4).
 */
#define BLAKE3_G(s, a, b, c, d, mx, my)                                        \
	do {                                                                   \
		(s)[(a)] = (s)[(a)] + (s)[(b)] + (mx);                         \
		(s)[(d)] = rotr32((s)[(d)] ^ (s)[(a)], 16);                    \
		(s)[(c)] += (s)[(d)];                                          \
		(s)[(b)] = rotr32((s)[(b)] ^ (s)[(c)], 12);                    \
		(s)[(a)] = (s)[(a)] + (s)[(b)] + (my);                         \
		(s)[(d)] = rotr32((s)[(d)] ^ (s)[(a)], 8);                     \
		(s)[(c)] += (s)[(d)];                                          \
		(s)[(b)] = rotr32((s)[(b)] ^ (s)[(c)], 7);                     \
	} while (0)

/* One BLAKE3 round with message permutation r of blake3_msg_schedule. */
#define BLAKE3_ROUND(s, m, r)                                                  \
	do {                                                                   \
		const uint8_t *sc_ = blake3_msg_schedule[(r)];                 \
		BLAKE3_G((s), 0, 4, 8, 12, (m)[sc_[0]], (m)[sc_[1]]);          \
		BLAKE3_G((s), 1, 5, 9, 13, (m)[sc_[2]], (m)[sc_[3]]);          \
		BLAKE3_G((s), 2, 6, 10, 14, (m)[sc_[4]], (m)[sc_[5]]);         \
		BLAKE3_G((s), 3, 7, 11, 15, (m)[sc_[6]], (m)[sc_[7]]);         \
		BLAKE3_G((s), 0, 5, 10, 15, (m)[sc_[8]], (m)[sc_[9]]);         \
		BLAKE3_G((s), 1, 6, 11, 12, (m)[sc_[10]], (m)[sc_[11]]);       \
		BLAKE3_G((s), 2, 7, 8, 13, (m)[sc_[12]], (m)[sc_[13]]);        \
		BLAKE3_G((s), 3, 4, 9, 14, (m)[sc_[14]], (m)[sc_[15]]);        \
	} while (0)

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

	BLAKE3_ROUND(state, block, 0);
	BLAKE3_ROUND(state, block, 1);
	BLAKE3_ROUND(state, block, 2);
	BLAKE3_ROUND(state, block, 3);
	BLAKE3_ROUND(state, block, 4);
	BLAKE3_ROUND(state, block, 5);
	BLAKE3_ROUND(state, block, 6);

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

/*
 * Push the chaining value of a completed subtree into the binary-tree
 * stack: a chunk (total = chunks done, this one included) or an aligned
 * subtree of 2^k chunks (total = chunks done >> k). Merges with the stack
 * while total is even.
 */
static void push_cv(ark_blake3_ctx_t *ctx, const uint32_t subtree_cv[8],
                    uint64_t total)
{
	uint32_t cv[8];
	size_t i;

	for (i = 0; i < 8; i++)
		cv[i] = subtree_cv[i];

	while ((total & 1U) == 0U) {
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
		total >>= 1;
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
	push_cv(ctx, cv, ctx->chunk_counter + 1U);
	ctx->chunk_counter++;
	reset_chunk_state(ctx);
}

/*
 * Portable hash of one input of `blocks` blocks: the per-lane work of the
 * SIMD functions (see blake3.h), written to out as 32 bytes.
 */
static void hash_one(const uint8_t *input, size_t blocks, const uint32_t key[8],
                     uint64_t counter, uint32_t flags, uint32_t flags_start,
                     uint32_t flags_end, uint8_t out[32])
{
	uint32_t cv[8];
	uint32_t block_flags;
	size_t i;

	for (i = 0; i < 8; i++)
		cv[i] = key[i];
	block_flags = flags | flags_start;
	while (blocks > 0U) {
		uint32_t block_words[16];
		uint32_t out_words[16];

		if (blocks == 1U)
			block_flags |= flags_end;
		block_to_words(input, block_words);
		blake3_compress(cv, block_words, counter, BLAKE3_BLOCK_LEN,
		                block_flags, out_words);
		for (i = 0; i < 8; i++)
			cv[i] = out_words[i];
		block_flags = flags;
		input += BLAKE3_BLOCK_LEN;
		blocks--;
	}
	for (i = 0; i < 8; i++)
		store_le32(out + i * 4, cv[i]);
}

/*
 * Hash n inputs of `blocks` blocks each into n chaining values at out
 * (32 bytes each), with the context's backend: groups of 8 (AVX2) and 4
 * (SSE4.1, NEON) lanes, the rest one by one. The SIMD functions exist only
 * in builds that define their macro.
 */
static void hash_many(const ark_blake3_ctx_t *ctx, const uint8_t *const *inputs,
                      size_t n, size_t blocks, const uint32_t key[8],
                      uint64_t counter, int increment_counter, uint32_t flags,
                      uint32_t flags_start, uint32_t flags_end, uint8_t *out)
{
	/* Unused without the SIMD macros: only the portable loop is left. */
	(void)ctx;
#ifdef ARK_BLAKE3_X86
	while (ctx->backend == ARK_BLAKE3_BACKEND_AVX2 && n >= 8U) {
		ark_blake3_x86_avx2_hash8(inputs, blocks, key, counter,
		                          increment_counter, flags, flags_start,
		                          flags_end, out);
		inputs += 8;
		n -= 8U;
		counter += increment_counter ? 8U : 0U;
		out += (size_t)8U * 32U;
	}
	while ((ctx->backend == ARK_BLAKE3_BACKEND_AVX2 ||
	        ctx->backend == ARK_BLAKE3_BACKEND_SSE41) &&
	       n >= 4U) {
		ark_blake3_x86_sse41_hash4(inputs, blocks, key, counter,
		                           increment_counter, flags,
		                           flags_start, flags_end, out);
		inputs += 4;
		n -= 4U;
		counter += increment_counter ? 4U : 0U;
		out += (size_t)4U * 32U;
	}
#endif
#ifdef ARK_BLAKE3_ARM
	while (ctx->backend == ARK_BLAKE3_BACKEND_NEON && n >= 4U) {
		ark_blake3_arm_neon_hash4(inputs, blocks, key, counter,
		                          increment_counter, flags, flags_start,
		                          flags_end, out);
		inputs += 4;
		n -= 4U;
		counter += increment_counter ? 4U : 0U;
		out += (size_t)4U * 32U;
	}
#endif
	while (n > 0U) {
		hash_one(*inputs, blocks, key, counter, flags, flags_start,
		         flags_end, out);
		inputs++;
		n--;
		counter += increment_counter ? 1U : 0U;
		out += 32;
	}
}

/*
 * Hash whole chunks straight from data as one subtree and push its
 * chaining value; returns the bytes used. Called at a chunk boundary with
 * len > BLAKE3_CHUNK_LEN. The subtree is the largest power of two of
 * chunks, at most BLAKE3_MAX_SUBTREE_CHUNKS, that leaves at least one byte
 * of data and that chunk_counter is a multiple of: such a subtree is a
 * subtree of the final tree, and never its root because input follows it.
 * Its chunks, then each level of parents, go through hash_many(). See
 * ARCHITECTURE.md §8.4.
 */
static size_t hash_subtree(ark_blake3_ctx_t *ctx, const uint8_t *data,
                           size_t len)
{
	const uint8_t *inputs[BLAKE3_MAX_SUBTREE_CHUNKS] = {NULL};
	uint8_t cvs[2][BLAKE3_MAX_SUBTREE_CHUNKS * 32U];
	uint32_t root[8];
	size_t avail;
	size_t n;
	size_t i;
	unsigned int level;
	unsigned int cur;

	avail = (len - 1U) / BLAKE3_CHUNK_LEN;
	n = BLAKE3_MAX_SUBTREE_CHUNKS;
	while (n > avail || (ctx->chunk_counter & (uint64_t)(n - 1U)) != 0U)
		n >>= 1;

	for (i = 0; i < n; i++)
		inputs[i] = data + i * BLAKE3_CHUNK_LEN;
	hash_many(ctx, inputs, n, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, ctx->key,
	          ctx->chunk_counter, 1, 0U, BLAKE3_FLAG_CHUNK_START,
	          BLAKE3_FLAG_CHUNK_END, cvs[0]);

	/* Two neighbouring chaining values are one parent block. */
	level = 0;
	cur = 0;
	while ((n >> level) > 1U) {
		size_t parents;

		parents = n >> (level + 1U);
		for (i = 0; i < parents; i++)
			inputs[i] = cvs[cur] + i * 64U;
		hash_many(ctx, inputs, parents, 1, blake3_iv, 0, 0,
		          BLAKE3_FLAG_PARENT, 0U, 0U, cvs[cur ^ 1U]);
		cur ^= 1U;
		level++;
	}

	for (i = 0; i < 8; i++)
		root[i] = load_le32(cvs[cur] + i * 4);
	push_cv(ctx, root, (ctx->chunk_counter >> level) + 1U);
	ctx->chunk_counter += (uint64_t)n;
	return n * BLAKE3_CHUNK_LEN;
}

void ark_blake3_init(ark_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8; i++)
		ctx->key[i] = blake3_iv[i];
	ctx->chunk_counter = 0;
	ctx->cv_stack_len = 0;
	ctx->backend = ARK_BLAKE3_BACKEND_PORTABLE;
	reset_chunk_state(ctx);
}

int ark_blake3_init_backend(ark_blake3_ctx_t *ctx, ark_blake3_backend_t backend)
{
	ark_blake3_init(ctx);
	switch (backend) {
	case ARK_BLAKE3_BACKEND_PORTABLE:
		return 0;
#ifdef ARK_BLAKE3_X86
	case ARK_BLAKE3_BACKEND_SSE41:
	case ARK_BLAKE3_BACKEND_AVX2:
		ctx->backend = backend;
		return 0;
#endif
#ifdef ARK_BLAKE3_ARM
	case ARK_BLAKE3_BACKEND_NEON:
		ctx->backend = backend;
		return 0;
#endif
	default:
		return -1;
	}
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
		 * At a chunk boundary, whole chunks followed by more input
		 * are hashed as subtrees, several chunks at once with a SIMD
		 * backend.
		 */
		if (chunk_len(ctx) == 0U && len > BLAKE3_CHUNK_LEN) {
			n = hash_subtree(ctx, data, len);
			data += n;
			len -= n;
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

		/*
		 * Whole blocks that are not their chunk's last block are
		 * compressed straight from the input, without the copy into
		 * ctx->block, when more input follows them.
		 */
		while (ctx->block_len == 0U && len > BLAKE3_BLOCK_LEN &&
		       ctx->blocks_compressed + 1U <
		           BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN) {
			uint32_t block_words[16];
			uint32_t out_words[16];
			size_t i;

			block_to_words(data, block_words);
			blake3_compress(ctx->cv, block_words,
			                ctx->chunk_counter, BLAKE3_BLOCK_LEN,
			                ctx->blocks_compressed == 0
			                    ? BLAKE3_FLAG_CHUNK_START
			                    : 0U,
			                out_words);
			for (i = 0; i < 8; i++)
				ctx->cv[i] = out_words[i];
			ctx->blocks_compressed++;
			data += BLAKE3_BLOCK_LEN;
			len -= BLAKE3_BLOCK_LEN;
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

#ifdef ARK_BLAKE3_TEST
/*
 * ARK_BLAKE3_TEST only: hash_many() with the given backend and the BLAKE3
 * IV as key, so tests can compare SIMD lanes with the portable code for
 * any counter, flags and block count (whole-input tests never reach
 * chunk counters above 2^32). Returns -1 when the backend is not built in.
 * Compiled out of production builds; tests declare it locally.
 */
int ark_blake3_test_hash_many(ark_blake3_backend_t backend,
                              const uint8_t *const *inputs, size_t n,
                              size_t blocks, uint64_t counter,
                              int increment_counter, uint32_t flags,
                              uint32_t flags_start, uint32_t flags_end,
                              uint8_t *out)
{
	ark_blake3_ctx_t ctx;

	if (ark_blake3_init_backend(&ctx, backend) != 0)
		return -1;
	hash_many(&ctx, inputs, n, blocks, ctx.key, counter, increment_counter,
	          flags, flags_start, flags_end, out);
	return 0;
}
#endif
