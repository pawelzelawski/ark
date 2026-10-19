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
 * SIMD functions that hash several whole chunks at once (x86 SSE4.1 and
 * AVX2, arm64 NEON) are optional: a program builds blake3_x86.c or
 * blake3_arm.c with ARK_BLAKE3_X86 or ARK_BLAKE3_ARM defined for every
 * file and picks the backend with ark_blake3_init_backend() (blake3_cpu.h
 * tells which one the CPU has). Without those macros this file and
 * blake3.c are plain C11 and only the portable backend exists.
 *
 * See ARCHITECTURE.md section 8.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * ark_blake3_backend_t - Function that hashes whole chunks for a context.
 * Every backend gives the same digests; PORTABLE is plain C and always
 * available.
 */
typedef enum {
	ARK_BLAKE3_BACKEND_PORTABLE = 0,
	ARK_BLAKE3_BACKEND_SSE41, /* x86 SSE4.1: 4 chunks at once */
	ARK_BLAKE3_BACKEND_AVX2,  /* x86 AVX2: 8 chunks at once (+ SSE4.1) */
	ARK_BLAKE3_BACKEND_NEON   /* arm64 NEON: 4 chunks at once */
} ark_blake3_backend_t;

typedef struct ark_blake3_ctx {
	uint32_t key[8];
	uint32_t cv[8];
	uint8_t block[64];
	size_t block_len;
	uint8_t blocks_compressed;
	uint64_t chunk_counter;
	uint32_t cv_stack[64][8];
	size_t cv_stack_len;
	ark_blake3_backend_t backend;
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
 * ark_blake3_init_backend - Initialize ctx like ark_blake3_init(), with
 * the given chunk function.
 *
 * Returns 0, or -1 when backend is unknown or not built into this program
 * (its file and macro were not compiled in); ctx then uses the portable
 * backend and is still valid.
 * Preconditions: ctx must be non-NULL; the CPU must have the instructions
 * of the backend (ark_blake3_cpu_supports() in blake3_cpu.h), otherwise
 * the program faults on the first whole chunk.
 */
int ark_blake3_init_backend(ark_blake3_ctx_t *ctx,
                            ark_blake3_backend_t backend);

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
 * Postconditions: ctx is consumed. Further ark_blake3_update() or
 * ark_blake3_final() calls on it are invalid until ark_blake3_init()
 * initializes it again.
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

/*
 * SIMD functions, defined in blake3_x86.c and blake3_arm.c and called by
 * blake3.c only when ARK_BLAKE3_X86 / ARK_BLAKE3_ARM is defined. Each
 * hashes 4 (or 8) inputs of `blocks` 64-byte blocks in parallel lanes,
 * starting from key: lane i uses counter + i when increment_counter is
 * nonzero (else counter), flags on every block, plus flags_start on the
 * first and flags_end on the last; it writes lane i's 32-byte chaining
 * value, little-endian, to out + 32 * i. Whole chunks: 16 blocks, chunk
 * counter, CHUNK_START / CHUNK_END; parent nodes: 1 block, PARENT.
 */
void ark_blake3_x86_sse41_hash4(const uint8_t *const inputs[4], size_t blocks,
                                const uint32_t key[8], uint64_t counter,
                                int increment_counter, uint32_t flags,
                                uint32_t flags_start, uint32_t flags_end,
                                uint8_t out[128]);
void ark_blake3_x86_avx2_hash8(const uint8_t *const inputs[8], size_t blocks,
                               const uint32_t key[8], uint64_t counter,
                               int increment_counter, uint32_t flags,
                               uint32_t flags_start, uint32_t flags_end,
                               uint8_t out[256]);
void ark_blake3_arm_neon_hash4(const uint8_t *const inputs[4], size_t blocks,
                               const uint32_t key[8], uint64_t counter,
                               int increment_counter, uint32_t flags,
                               uint32_t flags_start, uint32_t flags_end,
                               uint8_t out[128]);

#endif /* ARK_BLAKE3_H */
