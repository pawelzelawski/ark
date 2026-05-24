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
 * Parameters:
 * - ctx: writable BLAKE3 context storage.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx must be non-NULL.
 */
void ark_blake3_init(ark_blake3_ctx_t *ctx);

/*
 * ark_blake3_update - Feed message bytes into an initialized context.
 *
 * Parameters:
 * - ctx: initialized BLAKE3 context.
 * - data: input byte buffer; may be NULL only when len is 0.
 * - len: number of input bytes to hash.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx must be non-NULL and initialized by ark_blake3_init().
 */
void ark_blake3_update(ark_blake3_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * ark_blake3_final - Finalize the digest and write 32 output bytes.
 *
 * Parameters:
 * - ctx: initialized BLAKE3 context after zero or more update calls.
 * - digest: writable 32-byte output buffer.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx and digest must be non-NULL; ctx must be initialized by
 * ark_blake3_init().
 */
void ark_blake3_final(ark_blake3_ctx_t *ctx, uint8_t digest[32]);

/*
 * ark_blake3 - Convenience wrapper over init/update/final.
 *
 * Parameters:
 * - data: input byte buffer; may be NULL only when len is 0.
 * - len: number of input bytes to hash.
 * - digest: writable 32-byte output buffer.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: digest must be non-NULL.
 */
void ark_blake3(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* ARK_BLAKE3_H */
