/*
 * sha256_arm.c - SHA-256 block function with the ARMv8 SHA2 instructions.
 *
 * Compiled only on arm64 builds that define ARK_SHA256_ARM (the Makefile
 * does both). Uses compiler intrinsics (<arm_neon.h>) and a target
 * attribute, so it needs gcc or clang; sha256.c stays plain C11 without it.
 * Callers select it with ark_sha256_init_backend() only when the CPU has
 * SHA2 (sha256_cpu.h). Pure computation: no I/O, no allocation. See
 * ARCHITECTURE.md section 8.4.
 */

#include <arm_neon.h>
#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

/* Round constants (FIPS 180-4). */
static const uint32_t sha256_arm_k[64] = {
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

/* Four rounds with message words m (W[4g..4g+3]) and constants group g. */
#define SHA256_ARM_ROUNDS4(m, g)                                               \
	do {                                                                   \
		uint32x4_t t_ = vaddq_u32(                                     \
		    (m), vld1q_u32(&sha256_arm_k[(size_t)(g) * 4U]));          \
		uint32x4_t abcd_ = s0;                                         \
		s0 = vsha256hq_u32(s0, s1, t_);                                \
		s1 = vsha256h2q_u32(s1, abcd_, t_);                            \
	} while (0)

/* Message schedule: W[4g+16..] from the four previous groups, over w0. */
#define SHA256_ARM_SCHEDULE(w0, w1, w2, w3)                                    \
	do {                                                                   \
		(w0) =                                                         \
		    vsha256su1q_u32(vsha256su0q_u32((w0), (w1)), (w2), (w3));  \
	} while (0)

/* Load 16 bytes as four big-endian 32-bit words. */
#define SHA256_ARM_LOAD(p) vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)))

/*
 * The instructions take the state in its natural order as ABCD and EFGH
 * lanes, so state[] is loaded and stored directly.
 */
__attribute__((target("+sha2"))) void
ark_sha256_arm_blocks(uint32_t state[8], const uint8_t *data, size_t nblocks)
{
	uint32x4_t s0;
	uint32x4_t s1;

	s0 = vld1q_u32(&state[0]);
	s1 = vld1q_u32(&state[4]);
	while (nblocks > 0U) {
		uint32x4_t abcd;
		uint32x4_t efgh;
		uint32x4_t w0;
		uint32x4_t w1;
		uint32x4_t w2;
		uint32x4_t w3;

		abcd = s0;
		efgh = s1;
		w0 = SHA256_ARM_LOAD(data);
		w1 = SHA256_ARM_LOAD(data + 16);
		w2 = SHA256_ARM_LOAD(data + 32);
		w3 = SHA256_ARM_LOAD(data + 48);

		SHA256_ARM_ROUNDS4(w0, 0);
		SHA256_ARM_SCHEDULE(w0, w1, w2, w3);
		SHA256_ARM_ROUNDS4(w1, 1);
		SHA256_ARM_SCHEDULE(w1, w2, w3, w0);
		SHA256_ARM_ROUNDS4(w2, 2);
		SHA256_ARM_SCHEDULE(w2, w3, w0, w1);
		SHA256_ARM_ROUNDS4(w3, 3);
		SHA256_ARM_SCHEDULE(w3, w0, w1, w2);
		SHA256_ARM_ROUNDS4(w0, 4);
		SHA256_ARM_SCHEDULE(w0, w1, w2, w3);
		SHA256_ARM_ROUNDS4(w1, 5);
		SHA256_ARM_SCHEDULE(w1, w2, w3, w0);
		SHA256_ARM_ROUNDS4(w2, 6);
		SHA256_ARM_SCHEDULE(w2, w3, w0, w1);
		SHA256_ARM_ROUNDS4(w3, 7);
		SHA256_ARM_SCHEDULE(w3, w0, w1, w2);
		SHA256_ARM_ROUNDS4(w0, 8);
		SHA256_ARM_SCHEDULE(w0, w1, w2, w3);
		SHA256_ARM_ROUNDS4(w1, 9);
		SHA256_ARM_SCHEDULE(w1, w2, w3, w0);
		SHA256_ARM_ROUNDS4(w2, 10);
		SHA256_ARM_SCHEDULE(w2, w3, w0, w1);
		SHA256_ARM_ROUNDS4(w3, 11);
		SHA256_ARM_SCHEDULE(w3, w0, w1, w2);
		SHA256_ARM_ROUNDS4(w0, 12);
		SHA256_ARM_ROUNDS4(w1, 13);
		SHA256_ARM_ROUNDS4(w2, 14);
		SHA256_ARM_ROUNDS4(w3, 15);

		s0 = vaddq_u32(s0, abcd);
		s1 = vaddq_u32(s1, efgh);
		data += 64;
		nblocks--;
	}
	vst1q_u32(&state[0], s0);
	vst1q_u32(&state[4], s1);
}
