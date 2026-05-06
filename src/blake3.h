#ifndef ARK_BLAKE3_H
#define ARK_BLAKE3_H

/*
 * blake3.h - BLAKE3 hash API.
 *
 * Streaming usage:
 *   ark_blake3_ctx_t ctx;
 *   ark_blake3_init(&ctx);
 *   ark_blake3_update(&ctx, data, len);  [x N]
 *   ark_blake3_final(&ctx, digest);
 *
 * Single-shot usage:
 *   ark_blake3(data, len, digest);
 *
 * See ARCHITECTURE.md section 8.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct ark_blake3_ctx {
	uint32_t key[8];
	uint32_t cv[8];
	uint8_t block[64];
	size_t block_len;
	uint8_t blocks_compressed;
	uint64_t chunk_counter;
	uint32_t cv_stack[64][8];
	size_t cv_stack_len;
} ark_blake3_ctx_t;

/*
 * ark_blake3_init - Initialize BLAKE3 context state.
 *
 * ctx must be non-NULL. Resets all internal state for a new hash stream.
 * This function does not fail.
 */
void ark_blake3_init(ark_blake3_ctx_t *ctx);

/*
 * ark_blake3_update - Feed message bytes into an initialized context.
 *
 * ctx must be initialized with ark_blake3_init.
 * data points to len bytes of input to hash (may be NULL when len is 0).
 * This function does not fail.
 */
void ark_blake3_update(ark_blake3_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * ark_blake3_final - Finalize the digest and write 32 output bytes.
 *
 * ctx must be initialized and may have zero or more update calls.
 * digest must point to a writable 32-byte buffer.
 * This function does not fail.
 */
void ark_blake3_final(ark_blake3_ctx_t *ctx, uint8_t digest[32]);

/*
 * ark_blake3 - Convenience wrapper over init/update/final.
 *
 * data points to len bytes of input; digest receives exactly 32 bytes.
 * This function does not fail.
 */
void ark_blake3(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* ARK_BLAKE3_H */
