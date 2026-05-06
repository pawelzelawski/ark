#include "sha256.h"

static const uint32_t sha256_k[64] = {
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

/* Rotate-right primitive used by SHA-256 sigma/Sigma functions. */
static uint32_t rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32U - n));
}

/* Load one big-endian 32-bit word from byte input. */
static uint32_t load_be32(const uint8_t src[4])
{
	return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

/* Store one 32-bit word as big-endian bytes. */
static void store_be32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)(x >> 24);
	dst[1] = (uint8_t)(x >> 16);
	dst[2] = (uint8_t)(x >> 8);
	dst[3] = (uint8_t)x;
}

/* Store one 64-bit word as big-endian bytes. */
static void store_be64(uint8_t dst[8], uint64_t x)
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

/* Local zeroing helper to avoid libc calls in this component. */
static void zero_bytes(uint8_t *dst, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = 0;
}

/* Local copy helper for small fixed-size buffers. */
static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = src[i];
}

/* Compress one 512-bit block into the running SHA-256 state. */
static void sha256_compress(ark_sha256_ctx_t *ctx, const uint8_t block[64])
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;
	uint32_t i;

	for (i = 0; i < 16; i++)
		ctx->schedule[i] = load_be32(block + (size_t)i * 4);
	/* Expand the 16 input words into the 64-word message schedule. */
	for (; i < 64; i++) {
		uint32_t w0;
		uint32_t w1;

		w0 = rotr32(ctx->schedule[i - 15], 7) ^
		     rotr32(ctx->schedule[i - 15], 18) ^
		     (ctx->schedule[i - 15] >> 3);
		w1 = rotr32(ctx->schedule[i - 2], 17) ^
		     rotr32(ctx->schedule[i - 2], 19) ^
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
		uint32_t ch;
		uint32_t maj;
		uint32_t s0;
		uint32_t s1;
		uint32_t t1;
		uint32_t t2;

		s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		ch = (e & f) ^ ((~e) & g);
		t1 = h + s1 + ch + sha256_k[i] + ctx->schedule[i];
		s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
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

/* cppcheck-suppress staticFunction */
void ark_sha256_init(ark_sha256_ctx_t *ctx)
{
	size_t i;

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
	zero_bytes(ctx->block, sizeof(ctx->block));
	for (i = 0; i < 64; i++)
		ctx->schedule[i] = 0;
}

/* cppcheck-suppress staticFunction */
void ark_sha256_update(ark_sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
	ctx->byte_count += (uint64_t)len;

	if (ctx->block_len != 0) {
		size_t n;

		n = sizeof(ctx->block) - ctx->block_len;
		if (n > len)
			n = len;
		copy_bytes(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
		if (ctx->block_len == sizeof(ctx->block)) {
			sha256_compress(ctx, ctx->block);
			ctx->block_len = 0;
		}
	}

	while (len >= sizeof(ctx->block)) {
		sha256_compress(ctx, data);
		data += sizeof(ctx->block);
		len -= sizeof(ctx->block);
	}

	if (len != 0) {
		copy_bytes(ctx->block, data, len);
		ctx->block_len = len;
	}
}

/* cppcheck-suppress staticFunction */
void ark_sha256_final(ark_sha256_ctx_t *ctx, uint8_t digest[32])
{
	uint8_t zeros[64];
	uint8_t one;
	uint8_t len_be[8];
	uint64_t bit_count;
	size_t pad_zero_len;
	size_t i;

	bit_count = ctx->byte_count * 8U;
	zero_bytes(zeros, sizeof(zeros));
	one = 0x80U;
	ark_sha256_update(ctx, &one, 1);

	if (ctx->block_len <= 56)
		pad_zero_len = 56 - ctx->block_len;
	else
		pad_zero_len = (64 - ctx->block_len) + 56;
	/* Pad with zeros so the final 64-bit length occupies the last 8 bytes.
	 */
	while (pad_zero_len > 0) {
		size_t n;

		n = pad_zero_len;
		if (n > sizeof(zeros))
			n = sizeof(zeros);
		ark_sha256_update(ctx, zeros, n);
		pad_zero_len -= n;
	}

	/* Append message length in bits as required by FIPS 180-4. */
	store_be64(len_be, bit_count);
	ark_sha256_update(ctx, len_be, sizeof(len_be));

	for (i = 0; i < 8; i++)
		store_be32(digest + i * 4, ctx->state[i]);
}

void ark_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
	ark_sha256_ctx_t ctx;

	ark_sha256_init(&ctx);
	ark_sha256_update(&ctx, data, len);
	ark_sha256_final(&ctx, digest);
}
