/*
 * blake3_x86.c - BLAKE3 chunk hashing with x86 SSE4.1 (4 lanes) and AVX2
 * (8 lanes).
 *
 * Compiled only on x86-64 builds that define ARK_BLAKE3_X86 (the Makefile
 * does both). Uses compiler intrinsics (<immintrin.h>) and target
 * attributes, so it needs gcc or clang; blake3.c stays plain C11 without
 * it. Each lane hashes one input: the sixteen state words of all lanes are
 * kept in sixteen vectors (word w of lane i in element i of vector w), and
 * each block's message words are loaded the same way with a transpose.
 * Callers select it with ark_blake3_init_backend() only when the CPU has
 * the instructions (blake3_cpu.h). Pure computation: no I/O, no
 * allocation. See ARCHITECTURE.md section 8.4.
 */

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "blake3.h"

#define BLAKE3_X86_BLOCK_LEN 64U

static const uint32_t blake3_x86_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const uint8_t blake3_x86_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/*
 * One round over the vectors v[16] with message vectors m[16]: the four
 * column G operations, then the four diagonal ones, each step applied to
 * four vectors at once. ADD, XOR and the rotations (ROT16 .. ROT7) are
 * macros of the including width; s is the round's message permutation.
 */
#define BLAKE3_X86_ROUND(v, m, s)                                              \
	do {                                                                   \
		BLAKE3_X86_G4((v), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,   \
		              13, 14, 15, (m)[(s)[0]], (m)[(s)[2]],            \
		              (m)[(s)[4]], (m)[(s)[6]], (m)[(s)[1]],           \
		              (m)[(s)[3]], (m)[(s)[5]], (m)[(s)[7]]);          \
		BLAKE3_X86_G4((v), 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15,   \
		              12, 13, 14, (m)[(s)[8]], (m)[(s)[10]],           \
		              (m)[(s)[12]], (m)[(s)[14]], (m)[(s)[9]],         \
		              (m)[(s)[11]], (m)[(s)[13]], (m)[(s)[15]]);       \
	} while (0)

/*
 * Four G operations G(a_k, b_k, c_k, d_k) side by side, k = 0..3, with
 * first message words x0..x3 and second message words y0..y3.
 */
#define BLAKE3_X86_G4(v, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0,   \
                      d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3)              \
	do {                                                                   \
		BLAKE3_X86_G_HALF((v), a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, \
		                  c2, c3, d0, d1, d2, d3, x0, x1, x2, x3,      \
		                  ROT16, ROT12);                               \
		BLAKE3_X86_G_HALF((v), a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, \
		                  c2, c3, d0, d1, d2, d3, y0, y1, y2, y3,      \
		                  ROT8, ROT7);                                 \
	} while (0)

/* Half of G (a += b + m; d = rotr(d ^ a); c += d; b = rotr(b ^ c)). */
#define BLAKE3_X86_G_HALF(v, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3,   \
                          d0, d1, d2, d3, m0, m1, m2, m3, rot_d, rot_b)        \
	do {                                                                   \
		(v)[a0] = ADD(ADD((v)[a0], (m0)), (v)[b0]);                    \
		(v)[a1] = ADD(ADD((v)[a1], (m1)), (v)[b1]);                    \
		(v)[a2] = ADD(ADD((v)[a2], (m2)), (v)[b2]);                    \
		(v)[a3] = ADD(ADD((v)[a3], (m3)), (v)[b3]);                    \
		(v)[d0] = rot_d(XOR((v)[d0], (v)[a0]));                        \
		(v)[d1] = rot_d(XOR((v)[d1], (v)[a1]));                        \
		(v)[d2] = rot_d(XOR((v)[d2], (v)[a2]));                        \
		(v)[d3] = rot_d(XOR((v)[d3], (v)[a3]));                        \
		(v)[c0] = ADD((v)[c0], (v)[d0]);                               \
		(v)[c1] = ADD((v)[c1], (v)[d1]);                               \
		(v)[c2] = ADD((v)[c2], (v)[d2]);                               \
		(v)[c3] = ADD((v)[c3], (v)[d3]);                               \
		(v)[b0] = rot_b(XOR((v)[b0], (v)[c0]));                        \
		(v)[b1] = rot_b(XOR((v)[b1], (v)[c1]));                        \
		(v)[b2] = rot_b(XOR((v)[b2], (v)[c2]));                        \
		(v)[b3] = rot_b(XOR((v)[b3], (v)[c3]));                        \
	} while (0)

/* Seven rounds over v with message vectors m. */
#define BLAKE3_X86_ROUNDS(v, m)                                                \
	do {                                                                   \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[0]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[1]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[2]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[3]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[4]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[5]);            \
		BLAKE3_X86_ROUND((v), (m), blake3_x86_schedule[6]);            \
	} while (0)

/* SSE4.1: 4 lanes of 32 bits in __m128i. */
#define ADD(a, b) _mm_add_epi32((a), (b))
#define XOR(a, b) _mm_xor_si128((a), (b))
#define ROT16(x)                                                               \
	_mm_shuffle_epi8((x), _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, \
	                                   7, 6, 1, 0, 3, 2))
#define ROT12(x) _mm_or_si128(_mm_srli_epi32((x), 12), _mm_slli_epi32((x), 20))
#define ROT8(x)                                                                \
	_mm_shuffle_epi8((x), _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, \
	                                   6, 5, 0, 3, 2, 1))
#define ROT7(x) _mm_or_si128(_mm_srli_epi32((x), 7), _mm_slli_epi32((x), 25))

/* Transpose four vectors of four words: v[i] word j <-> v[j] word i. */
__attribute__((target("sse4.1"))) static void sse41_transpose(__m128i v[4])
{
	__m128i ab01 = _mm_unpacklo_epi32(v[0], v[1]);
	__m128i ab23 = _mm_unpackhi_epi32(v[0], v[1]);
	__m128i cd01 = _mm_unpacklo_epi32(v[2], v[3]);
	__m128i cd23 = _mm_unpackhi_epi32(v[2], v[3]);

	v[0] = _mm_unpacklo_epi64(ab01, cd01);
	v[1] = _mm_unpackhi_epi64(ab01, cd01);
	v[2] = _mm_unpacklo_epi64(ab23, cd23);
	v[3] = _mm_unpackhi_epi64(ab23, cd23);
}

/* Message vectors m[16] (word w of every lane in m[w]) of one block. */
__attribute__((target("sse4.1"))) static void
sse41_load_msg(const uint8_t *const inputs[4], size_t offset, __m128i m[16])
{
	size_t q;
	size_t i;

	for (q = 0; q < 4; q++) {
		for (i = 0; i < 4; i++)
			m[q * 4 + i] = _mm_loadu_si128(
			    (const __m128i *)(inputs[i] + offset + q * 16U));
		sse41_transpose(&m[q * 4]);
	}
}

__attribute__((target("sse4.1"))) void ark_blake3_x86_sse41_hash4(
    const uint8_t *const inputs[4], size_t blocks, const uint32_t key[8],
    uint64_t counter, int increment_counter, uint32_t flags,
    uint32_t flags_start, uint32_t flags_end, uint8_t out[128])
{
	uint64_t c[4];
	__m128i h[8];
	__m128i counter_low;
	__m128i counter_high;
	uint32_t block_flags;
	size_t block;
	size_t i;

	for (i = 0; i < 4; i++)
		c[i] = counter + (increment_counter ? (uint64_t)i : 0U);
	counter_low = _mm_set_epi32((int)(uint32_t)c[3], (int)(uint32_t)c[2],
	                            (int)(uint32_t)c[1], (int)(uint32_t)c[0]);
	counter_high = _mm_set_epi32(
	    (int)(uint32_t)(c[3] >> 32), (int)(uint32_t)(c[2] >> 32),
	    (int)(uint32_t)(c[1] >> 32), (int)(uint32_t)(c[0] >> 32));
	for (i = 0; i < 8; i++)
		h[i] = _mm_set1_epi32((int)key[i]);

	block_flags = flags | flags_start;
	for (block = 0; block < blocks; block++) {
		__m128i m[16];
		__m128i v[16];

		if (block + 1U == blocks)
			block_flags |= flags_end;
		sse41_load_msg(inputs, block * BLAKE3_X86_BLOCK_LEN, m);
		for (i = 0; i < 8; i++)
			v[i] = h[i];
		for (i = 0; i < 4; i++)
			v[i + 8] = _mm_set1_epi32((int)blake3_x86_iv[i]);
		v[12] = counter_low;
		v[13] = counter_high;
		v[14] = _mm_set1_epi32((int)BLAKE3_X86_BLOCK_LEN);
		v[15] = _mm_set1_epi32((int)block_flags);
		BLAKE3_X86_ROUNDS(v, m);
		for (i = 0; i < 8; i++)
			h[i] = XOR(v[i], v[i + 8]);
		block_flags = flags;
	}

	/* Back to one chaining value per lane: words 0-3, then 4-7. */
	sse41_transpose(&h[0]);
	sse41_transpose(&h[4]);
	for (i = 0; i < 4; i++) {
		_mm_storeu_si128((__m128i *)(out + i * 32U), h[i]);
		_mm_storeu_si128((__m128i *)(out + i * 32U + 16U), h[i + 4]);
	}
}

#undef ADD
#undef XOR
#undef ROT16
#undef ROT12
#undef ROT8
#undef ROT7

/* AVX2: 8 lanes of 32 bits in __m256i. */
#define ADD(a, b) _mm256_add_epi32((a), (b))
#define XOR(a, b) _mm256_xor_si256((a), (b))
#define ROT16(x)                                                               \
	_mm256_shuffle_epi8((x), _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, \
	                                         5, 4, 7, 6, 1, 0, 3, 2, 13,   \
	                                         12, 15, 14, 9, 8, 11, 10, 5,  \
	                                         4, 7, 6, 1, 0, 3, 2))
#define ROT12(x)                                                               \
	_mm256_or_si256(_mm256_srli_epi32((x), 12), _mm256_slli_epi32((x), 20))
#define ROT8(x)                                                                \
	_mm256_shuffle_epi8((x), _mm256_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, \
	                                         4, 7, 6, 5, 0, 3, 2, 1, 12,   \
	                                         15, 14, 13, 8, 11, 10, 9, 4,  \
	                                         7, 6, 5, 0, 3, 2, 1))
#define ROT7(x)                                                                \
	_mm256_or_si256(_mm256_srli_epi32((x), 7), _mm256_slli_epi32((x), 25))

/* Transpose eight vectors of eight words: v[i] word j <-> v[j] word i. */
__attribute__((target("avx2"))) static void avx2_transpose(__m256i v[8])
{
	/* Within each 128-bit half first, then the halves are exchanged. */
	__m256i ab0145 = _mm256_unpacklo_epi32(v[0], v[1]);
	__m256i ab2367 = _mm256_unpackhi_epi32(v[0], v[1]);
	__m256i cd0145 = _mm256_unpacklo_epi32(v[2], v[3]);
	__m256i cd2367 = _mm256_unpackhi_epi32(v[2], v[3]);
	__m256i ef0145 = _mm256_unpacklo_epi32(v[4], v[5]);
	__m256i ef2367 = _mm256_unpackhi_epi32(v[4], v[5]);
	__m256i gh0145 = _mm256_unpacklo_epi32(v[6], v[7]);
	__m256i gh2367 = _mm256_unpackhi_epi32(v[6], v[7]);
	__m256i abcd04 = _mm256_unpacklo_epi64(ab0145, cd0145);
	__m256i abcd15 = _mm256_unpackhi_epi64(ab0145, cd0145);
	__m256i abcd26 = _mm256_unpacklo_epi64(ab2367, cd2367);
	__m256i abcd37 = _mm256_unpackhi_epi64(ab2367, cd2367);
	__m256i efgh04 = _mm256_unpacklo_epi64(ef0145, gh0145);
	__m256i efgh15 = _mm256_unpackhi_epi64(ef0145, gh0145);
	__m256i efgh26 = _mm256_unpacklo_epi64(ef2367, gh2367);
	__m256i efgh37 = _mm256_unpackhi_epi64(ef2367, gh2367);

	v[0] = _mm256_permute2x128_si256(abcd04, efgh04, 0x20);
	v[1] = _mm256_permute2x128_si256(abcd15, efgh15, 0x20);
	v[2] = _mm256_permute2x128_si256(abcd26, efgh26, 0x20);
	v[3] = _mm256_permute2x128_si256(abcd37, efgh37, 0x20);
	v[4] = _mm256_permute2x128_si256(abcd04, efgh04, 0x31);
	v[5] = _mm256_permute2x128_si256(abcd15, efgh15, 0x31);
	v[6] = _mm256_permute2x128_si256(abcd26, efgh26, 0x31);
	v[7] = _mm256_permute2x128_si256(abcd37, efgh37, 0x31);
}

/* Message vectors m[16] (word w of every lane in m[w]) of one block. */
__attribute__((target("avx2"))) static void
avx2_load_msg(const uint8_t *const inputs[8], size_t offset, __m256i m[16])
{
	size_t q;
	size_t i;

	for (q = 0; q < 2; q++) {
		for (i = 0; i < 8; i++)
			m[q * 8 + i] = _mm256_loadu_si256(
			    (const __m256i *)(inputs[i] + offset + q * 32U));
		avx2_transpose(&m[q * 8]);
	}
}

__attribute__((target("avx2"))) void ark_blake3_x86_avx2_hash8(
    const uint8_t *const inputs[8], size_t blocks, const uint32_t key[8],
    uint64_t counter, int increment_counter, uint32_t flags,
    uint32_t flags_start, uint32_t flags_end, uint8_t out[256])
{
	uint32_t c_low[8];
	uint32_t c_high[8];
	__m256i h[8];
	__m256i counter_low;
	__m256i counter_high;
	uint32_t block_flags;
	size_t block;
	size_t i;

	for (i = 0; i < 8; i++) {
		uint64_t c;

		c = counter + (increment_counter ? (uint64_t)i : 0U);
		c_low[i] = (uint32_t)c;
		c_high[i] = (uint32_t)(c >> 32);
	}
	counter_low = _mm256_loadu_si256((const __m256i *)c_low);
	counter_high = _mm256_loadu_si256((const __m256i *)c_high);
	for (i = 0; i < 8; i++)
		h[i] = _mm256_set1_epi32((int)key[i]);

	block_flags = flags | flags_start;
	for (block = 0; block < blocks; block++) {
		__m256i m[16];
		__m256i v[16];

		if (block + 1U == blocks)
			block_flags |= flags_end;
		avx2_load_msg(inputs, block * BLAKE3_X86_BLOCK_LEN, m);
		for (i = 0; i < 8; i++)
			v[i] = h[i];
		for (i = 0; i < 4; i++)
			v[i + 8] = _mm256_set1_epi32((int)blake3_x86_iv[i]);
		v[12] = counter_low;
		v[13] = counter_high;
		v[14] = _mm256_set1_epi32((int)BLAKE3_X86_BLOCK_LEN);
		v[15] = _mm256_set1_epi32((int)block_flags);
		BLAKE3_X86_ROUNDS(v, m);
		for (i = 0; i < 8; i++)
			h[i] = XOR(v[i], v[i + 8]);
		block_flags = flags;
	}

	/* Back to one chaining value (8 words) per lane. */
	avx2_transpose(h);
	for (i = 0; i < 8; i++)
		_mm256_storeu_si256((__m256i *)(out + i * 32U), h[i]);
}
