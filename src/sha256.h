#ifndef ARK_SHA256_H
#define ARK_SHA256_H

/*
 * sha256.h - SHA-256 hash API.
 *
 * Streaming usage:
 *   ark_sha256_ctx_t ctx;
 *   ark_sha256_init(&ctx);
 *   ark_sha256_update(&ctx, data, len);  [x N]
 *   ark_sha256_final(&ctx, digest);
 *
 * Single-shot usage:
 *   ark_sha256(data, len, digest);
 *
 * See ARCHITECTURE.md section 8.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct ark_sha256_ctx {
	uint32_t state[8];
	uint32_t schedule[64];
	uint8_t block[64];
	uint64_t byte_count;
	size_t block_len;
} ark_sha256_ctx_t;

/*
 * ark_sha256_init - Initialize SHA-256 context state.
 *
 * ctx must be non-NULL. Resets all internal state for a new hash stream.
 */
void ark_sha256_init(ark_sha256_ctx_t *ctx);

/*
 * ark_sha256_update - Feed message bytes into an initialized context.
 *
 * ctx must be initialized with ark_sha256_init.
 * data points to len bytes of input to hash.
 */
void ark_sha256_update(ark_sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * ark_sha256_final - Finalize the digest and write 32 output bytes.
 *
 * ctx must be initialized and may have zero or more update calls.
 * digest must point to a writable 32-byte buffer.
 */
void ark_sha256_final(ark_sha256_ctx_t *ctx, uint8_t digest[32]);

/*
 * ark_sha256 - Convenience wrapper over init/update/final.
 *
 * data points to len bytes of input; digest receives exactly 32 bytes.
 */
void ark_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* ARK_SHA256_H */
