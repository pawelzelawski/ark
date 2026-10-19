/*
 * blake3_arm.c - BLAKE3 chunk hashing with arm64 NEON (4 lanes).
 *
 * Compiled only on arm64 builds that define ARK_BLAKE3_ARM (the Makefile
 * does both). Uses compiler intrinsics (<arm_neon.h>), so it needs gcc or
 * clang; blake3.c stays plain C11 without it. NEON is part of every arm64
 * CPU, so no detection is needed. Each lane hashes one input: the sixteen
 * state words of all lanes are kept in sixteen vectors (word w of lane i
 * in element i of vector w), and each block's message words are loaded the
 * same way with a transpose. Little-endian only, like the arm64 systems
 * ark runs on. Pure computation: no I/O, no allocation. See
 * ARCHITECTURE.md section 8.4.
 */

#include <arm_neon.h>
#include <stddef.h>
#include <stdint.h>

#include "blake3.h"

#if defined(__ARM_BIG_ENDIAN)
#error "blake3_arm.c expects little-endian arm64"
#endif

#define BLAKE3_ARM_BLOCK_LEN 64U

static const uint32_t blake3_arm_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const uint8_t blake3_arm_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/* Rotations right of every 32-bit element. */
#define BLAKE3_ARM_ROT16(x)                                                    \
	vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
#define BLAKE3_ARM_ROT12(x) vsriq_n_u32(vshlq_n_u32((x), 20), (x), 12)
#define BLAKE3_ARM_ROT8(x) vsriq_n_u32(vshlq_n_u32((x), 24), (x), 8)
#define BLAKE3_ARM_ROT7(x) vsriq_n_u32(vshlq_n_u32((x), 25), (x), 7)

/* Half of G (a += b + m; d = rotr(d ^ a); c += d; b = rotr(b ^ c)). */
#define BLAKE3_ARM_G_HALF(v, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3,   \
                          d0, d1, d2, d3, m0, m1, m2, m3, rot_d, rot_b)        \
	do {                                                                   \
		(v)[a0] = vaddq_u32(vaddq_u32((v)[a0], (m0)), (v)[b0]);        \
		(v)[a1] = vaddq_u32(vaddq_u32((v)[a1], (m1)), (v)[b1]);        \
		(v)[a2] = vaddq_u32(vaddq_u32((v)[a2], (m2)), (v)[b2]);        \
		(v)[a3] = vaddq_u32(vaddq_u32((v)[a3], (m3)), (v)[b3]);        \
		(v)[d0] = rot_d(veorq_u32((v)[d0], (v)[a0]));                  \
		(v)[d1] = rot_d(veorq_u32((v)[d1], (v)[a1]));                  \
		(v)[d2] = rot_d(veorq_u32((v)[d2], (v)[a2]));                  \
		(v)[d3] = rot_d(veorq_u32((v)[d3], (v)[a3]));                  \
		(v)[c0] = vaddq_u32((v)[c0], (v)[d0]);                         \
		(v)[c1] = vaddq_u32((v)[c1], (v)[d1]);                         \
		(v)[c2] = vaddq_u32((v)[c2], (v)[d2]);                         \
		(v)[c3] = vaddq_u32((v)[c3], (v)[d3]);                         \
		(v)[b0] = rot_b(veorq_u32((v)[b0], (v)[c0]));                  \
		(v)[b1] = rot_b(veorq_u32((v)[b1], (v)[c1]));                  \
		(v)[b2] = rot_b(veorq_u32((v)[b2], (v)[c2]));                  \
		(v)[b3] = rot_b(veorq_u32((v)[b3], (v)[c3]));                  \
	} while (0)

/*
 * Four G operations G(a_k, b_k, c_k, d_k) side by side, k = 0..3, with
 * first message words x0..x3 and second message words y0..y3.
 */
#define BLAKE3_ARM_G4(v, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0,   \
                      d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3)              \
	do {                                                                   \
		BLAKE3_ARM_G_HALF((v), a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, \
		                  c2, c3, d0, d1, d2, d3, x0, x1, x2, x3,      \
		                  BLAKE3_ARM_ROT16, BLAKE3_ARM_ROT12);         \
		BLAKE3_ARM_G_HALF((v), a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, \
		                  c2, c3, d0, d1, d2, d3, y0, y1, y2, y3,      \
		                  BLAKE3_ARM_ROT8, BLAKE3_ARM_ROT7);           \
	} while (0)

/*
 * One round over the vectors v[16] with message vectors m[16]: the four
 * column G operations, then the four diagonal ones; s is the round's
 * message permutation.
 */
#define BLAKE3_ARM_ROUND(v, m, s)                                              \
	do {                                                                   \
		BLAKE3_ARM_G4((v), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,   \
		              13, 14, 15, (m)[(s)[0]], (m)[(s)[2]],            \
		              (m)[(s)[4]], (m)[(s)[6]], (m)[(s)[1]],           \
		              (m)[(s)[3]], (m)[(s)[5]], (m)[(s)[7]]);          \
		BLAKE3_ARM_G4((v), 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15,   \
		              12, 13, 14, (m)[(s)[8]], (m)[(s)[10]],           \
		              (m)[(s)[12]], (m)[(s)[14]], (m)[(s)[9]],         \
		              (m)[(s)[11]], (m)[(s)[13]], (m)[(s)[15]]);       \
	} while (0)

/* Transpose four vectors of four words: v[i] word j <-> v[j] word i. */
static void neon_transpose(uint32x4_t v[4])
{
	uint32x4x2_t ab = vtrnq_u32(v[0], v[1]);
	uint32x4x2_t cd = vtrnq_u32(v[2], v[3]);

	/* ab.val[0] = a0 b0 a2 b2, ab.val[1] = a1 b1 a3 b3; same for cd. */
	v[0] = vcombine_u32(vget_low_u32(ab.val[0]), vget_low_u32(cd.val[0]));
	v[1] = vcombine_u32(vget_low_u32(ab.val[1]), vget_low_u32(cd.val[1]));
	v[2] = vcombine_u32(vget_high_u32(ab.val[0]), vget_high_u32(cd.val[0]));
	v[3] = vcombine_u32(vget_high_u32(ab.val[1]), vget_high_u32(cd.val[1]));
}

/* Message vectors m[16] (word w of every lane in m[w]) of one block. */
static void neon_load_msg(const uint8_t *const inputs[4], size_t offset,
                          uint32x4_t m[16])
{
	size_t q;
	size_t i;

	for (q = 0; q < 4; q++) {
		for (i = 0; i < 4; i++)
			m[q * 4 + i] = vreinterpretq_u32_u8(
			    vld1q_u8(inputs[i] + offset + q * 16U));
		neon_transpose(&m[q * 4]);
	}
}

void ark_blake3_arm_neon_hash4(const uint8_t *const inputs[4], size_t blocks,
                               const uint32_t key[8], uint64_t counter,
                               int increment_counter, uint32_t flags,
                               uint32_t flags_start, uint32_t flags_end,
                               uint8_t out[128])
{
	uint32_t c_low[4];
	uint32_t c_high[4];
	uint32x4_t h[8];
	uint32x4_t counter_low;
	uint32x4_t counter_high;
	uint32_t block_flags;
	size_t block;
	size_t i;

	for (i = 0; i < 4; i++) {
		uint64_t c;

		c = counter + (increment_counter ? (uint64_t)i : 0U);
		c_low[i] = (uint32_t)c;
		c_high[i] = (uint32_t)(c >> 32);
	}
	counter_low = vld1q_u32(c_low);
	counter_high = vld1q_u32(c_high);
	for (i = 0; i < 8; i++)
		h[i] = vdupq_n_u32(key[i]);

	block_flags = flags | flags_start;
	for (block = 0; block < blocks; block++) {
		uint32x4_t m[16];
		uint32x4_t v[16];

		if (block + 1U == blocks)
			block_flags |= flags_end;
		neon_load_msg(inputs, block * BLAKE3_ARM_BLOCK_LEN, m);
		for (i = 0; i < 8; i++)
			v[i] = h[i];
		for (i = 0; i < 4; i++)
			v[i + 8] = vdupq_n_u32(blake3_arm_iv[i]);
		v[12] = counter_low;
		v[13] = counter_high;
		v[14] = vdupq_n_u32(BLAKE3_ARM_BLOCK_LEN);
		v[15] = vdupq_n_u32(block_flags);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[0]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[1]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[2]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[3]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[4]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[5]);
		BLAKE3_ARM_ROUND(v, m, blake3_arm_schedule[6]);
		for (i = 0; i < 8; i++)
			h[i] = veorq_u32(v[i], v[i + 8]);
		block_flags = flags;
	}

	/* Back to one chaining value per lane: words 0-3, then 4-7. */
	neon_transpose(&h[0]);
	neon_transpose(&h[4]);
	for (i = 0; i < 4; i++) {
		vst1q_u8(out + i * 32U, vreinterpretq_u8_u32(h[i]));
		vst1q_u8(out + i * 32U + 16U, vreinterpretq_u8_u32(h[i + 4]));
	}
}
