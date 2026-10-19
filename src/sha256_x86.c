/*
 * sha256_x86.c - SHA-256 block function with the x86 SHA extensions.
 *
 * Compiled only on x86-64 builds that define ARK_SHA256_X86 (the Makefile
 * does both). Uses compiler intrinsics (<immintrin.h>) and a target
 * attribute, so it needs gcc or clang; sha256.c stays plain C11 without it.
 * Callers select it with ark_sha256_init_backend() only when the CPU has
 * SHA and SSE4.1 (sha256_cpu.h). Pure computation: no I/O, no allocation.
 * See ARCHITECTURE.md section 8.4.
 */

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

/* Round constants, four per 128-bit lane group (FIPS 180-4). */
static const uint32_t sha256_x86_k[64] = {
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

/*
 * Four rounds with message words m (W[4g..4g+3]) and constants group g:
 * sha256rnds2 does two rounds; the high half of the sum feeds the next two.
 */
#define SHA256_X86_ROUNDS4(m, g)                                               \
	do {                                                                   \
		__m128i t_ = _mm_add_epi32(                                    \
		    (m),                                                       \
		    _mm_loadu_si128(                                           \
		        (const __m128i *)&sha256_x86_k[(size_t)(g) * 4U]));    \
		s1 = _mm_sha256rnds2_epu32(s1, s0, t_);                        \
		t_ = _mm_shuffle_epi32(t_, 0x0e);                              \
		s0 = _mm_sha256rnds2_epu32(s0, s1, t_);                        \
	} while (0)

/*
 * Message schedule: W[4g+16..] from the four previous groups, written over
 * w0 (W[4g..]): msg1(w0, w1) + (w3:w2 shifted by one word), then msg2.
 */
#define SHA256_X86_SCHEDULE(w0, w1, w2, w3)                                    \
	do {                                                                   \
		(w0) = _mm_add_epi32(_mm_sha256msg1_epu32((w0), (w1)),         \
		                     _mm_alignr_epi8((w3), (w2), 4));          \
		(w0) = _mm_sha256msg2_epu32((w0), (w3));                       \
	} while (0)

/*
 * The instructions keep the state as ABEF and CDGH lanes: state[] is
 * converted on entry and back on exit, and each 64-byte block is loaded
 * with its words byte-swapped to big-endian order.
 */
__attribute__((target("sha,sse4.1"))) void
ark_sha256_x86_blocks(uint32_t state[8], const uint8_t *data, size_t nblocks)
{
	const __m128i bswap =
	    _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
	__m128i s0;
	__m128i s1;
	__m128i t;

	t = _mm_loadu_si128((const __m128i *)&state[0]);
	s1 = _mm_loadu_si128((const __m128i *)&state[4]);
	t = _mm_shuffle_epi32(t, 0xb1);    /* CDAB */
	s1 = _mm_shuffle_epi32(s1, 0x1b);  /* EFGH */
	s0 = _mm_alignr_epi8(t, s1, 8);    /* ABEF */
	s1 = _mm_blend_epi16(s1, t, 0xf0); /* CDGH */

	while (nblocks > 0U) {
		__m128i abef;
		__m128i cdgh;
		__m128i w0;
		__m128i w1;
		__m128i w2;
		__m128i w3;

		abef = s0;
		cdgh = s1;
		w0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)data),
		                      bswap);
		w1 = _mm_shuffle_epi8(
		    _mm_loadu_si128((const __m128i *)(data + 16)), bswap);
		w2 = _mm_shuffle_epi8(
		    _mm_loadu_si128((const __m128i *)(data + 32)), bswap);
		w3 = _mm_shuffle_epi8(
		    _mm_loadu_si128((const __m128i *)(data + 48)), bswap);

		SHA256_X86_ROUNDS4(w0, 0);
		SHA256_X86_SCHEDULE(w0, w1, w2, w3);
		SHA256_X86_ROUNDS4(w1, 1);
		SHA256_X86_SCHEDULE(w1, w2, w3, w0);
		SHA256_X86_ROUNDS4(w2, 2);
		SHA256_X86_SCHEDULE(w2, w3, w0, w1);
		SHA256_X86_ROUNDS4(w3, 3);
		SHA256_X86_SCHEDULE(w3, w0, w1, w2);
		SHA256_X86_ROUNDS4(w0, 4);
		SHA256_X86_SCHEDULE(w0, w1, w2, w3);
		SHA256_X86_ROUNDS4(w1, 5);
		SHA256_X86_SCHEDULE(w1, w2, w3, w0);
		SHA256_X86_ROUNDS4(w2, 6);
		SHA256_X86_SCHEDULE(w2, w3, w0, w1);
		SHA256_X86_ROUNDS4(w3, 7);
		SHA256_X86_SCHEDULE(w3, w0, w1, w2);
		SHA256_X86_ROUNDS4(w0, 8);
		SHA256_X86_SCHEDULE(w0, w1, w2, w3);
		SHA256_X86_ROUNDS4(w1, 9);
		SHA256_X86_SCHEDULE(w1, w2, w3, w0);
		SHA256_X86_ROUNDS4(w2, 10);
		SHA256_X86_SCHEDULE(w2, w3, w0, w1);
		SHA256_X86_ROUNDS4(w3, 11);
		SHA256_X86_SCHEDULE(w3, w0, w1, w2);
		SHA256_X86_ROUNDS4(w0, 12);
		SHA256_X86_ROUNDS4(w1, 13);
		SHA256_X86_ROUNDS4(w2, 14);
		SHA256_X86_ROUNDS4(w3, 15);

		s0 = _mm_add_epi32(s0, abef);
		s1 = _mm_add_epi32(s1, cdgh);
		data += 64;
		nblocks--;
	}

	t = _mm_shuffle_epi32(s0, 0x1b);   /* FEBA */
	s1 = _mm_shuffle_epi32(s1, 0xb1);  /* DCHG */
	s0 = _mm_blend_epi16(t, s1, 0xf0); /* DCBA */
	s1 = _mm_alignr_epi8(s1, t, 8);    /* HGFE */
	_mm_storeu_si128((__m128i *)&state[0], s0);
	_mm_storeu_si128((__m128i *)&state[4], s1);
}
