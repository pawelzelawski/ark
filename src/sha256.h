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
 * Hardware block functions (x86 SHA-NI, ARMv8 SHA2) are optional: a
 * program builds sha256_x86.c or sha256_arm.c with ARK_SHA256_X86 or
 * ARK_SHA256_ARM defined for every file and picks the backend with
 * ark_sha256_init_backend() (sha256_cpu.h tells which one the CPU has).
 * Without those macros this file and sha256.c are plain C11 and only the
 * portable backend exists.
 *
 * See ARCHITECTURE.md section 8.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * ark_sha256_backend_t - Block function a context uses. Every backend
 * gives the same digests; PORTABLE is plain C and always available.
 */
typedef enum {
	ARK_SHA256_BACKEND_PORTABLE = 0,
	ARK_SHA256_BACKEND_X86_SHANI, /* x86 SHA extensions + SSE4.1 */
	ARK_SHA256_BACKEND_ARMV8      /* ARMv8 SHA2 instructions */
} ark_sha256_backend_t;

typedef struct ark_sha256_ctx {
	uint32_t state[8];
	uint8_t block[64];
	uint64_t byte_count;
	size_t block_len;
	ark_sha256_backend_t backend;
} ark_sha256_ctx_t;

/*
 * ark_sha256_init - Initialize SHA-256 context state.
 *
 * Parameters:
 * - ctx: writable SHA-256 context storage.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx must be non-NULL.
 */
void ark_sha256_init(ark_sha256_ctx_t *ctx);

/*
 * ark_sha256_init_backend - Initialize ctx like ark_sha256_init(), with
 * the given block function.
 *
 * Returns 0, or -1 when backend is unknown or not built into this program
 * (its file and macro were not compiled in); ctx then uses the portable
 * backend and is still valid.
 * Preconditions: ctx must be non-NULL; the CPU must have the instructions
 * of the backend (ark_sha256_cpu_supports() in sha256_cpu.h), otherwise
 * the program faults on the first block.
 */
int ark_sha256_init_backend(ark_sha256_ctx_t *ctx,
                            ark_sha256_backend_t backend);

/*
 * ark_sha256_update - Feed message bytes into an initialized context.
 *
 * Parameters:
 * - ctx: initialized SHA-256 context.
 * - data: input byte buffer; may be NULL only when len is 0.
 * - len: number of input bytes to hash.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx must be non-NULL and initialized by ark_sha256_init().
 */
void ark_sha256_update(ark_sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * ark_sha256_final - Finalize the digest and write 32 output bytes.
 *
 * Parameters:
 * - ctx: initialized SHA-256 context after zero or more update calls.
 * - digest: writable 32-byte output buffer.
 *
 * Returns no value.
 * Failure contract: does not fail.
 * Preconditions: ctx and digest must be non-NULL; ctx must be initialized by
 * ark_sha256_init().
 * Postconditions: ctx is consumed. Further ark_sha256_update() or
 * ark_sha256_final() calls on it are invalid until ark_sha256_init()
 * initializes it again.
 */
void ark_sha256_final(ark_sha256_ctx_t *ctx, uint8_t digest[32]);

/*
 * ark_sha256 - Convenience wrapper over init/update/final.
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
void ark_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

/*
 * Hardware block functions, defined in sha256_x86.c and sha256_arm.c and
 * called by sha256.c only when ARK_SHA256_X86 / ARK_SHA256_ARM is defined:
 * compress nblocks consecutive 64-byte blocks of data into state.
 */
void ark_sha256_x86_blocks(uint32_t state[8], const uint8_t *data,
                           size_t nblocks);
void ark_sha256_arm_blocks(uint32_t state[8], const uint8_t *data,
                           size_t nblocks);

#endif /* ARK_SHA256_H */
