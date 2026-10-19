/*
 * blake3_cpu.c - BLAKE3 backend detection (blake3_cpu.h).
 *
 * x86: SSE4.1 needs SSSE3 and SSE4.1 (CPUID leaf 1, ECX bits 9 and 19);
 * AVX2 needs those, AVX2 (leaf 7, EBX bit 5), and an OS that saves the
 * 256-bit registers: OSXSAVE and AVX (leaf 1, ECX bits 27 and 28), then
 * XCR0 bits 1 and 2 (SSE and AVX state) read with xgetbv. Read with the
 * compiler's <cpuid.h> and <immintrin.h>. arm64: NEON is always present.
 * Every other platform, or a build without the SIMD files, reports
 * PORTABLE only. No allocation, no state, no OS call. See ARCHITECTURE.md
 * section 8.4.
 */

#include "blake3_cpu.h"

#if defined(ARK_BLAKE3_X86) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
#include <immintrin.h>

#define ARK_CPUID1_ECX_SSSE3 (1U << 9)
#define ARK_CPUID1_ECX_SSE41 (1U << 19)
#define ARK_CPUID1_ECX_OSXSAVE (1U << 27)
#define ARK_CPUID1_ECX_AVX (1U << 28)
#define ARK_CPUID7_EBX_AVX2 (1U << 5)
#define ARK_XCR0_SSE_AVX 0x6U

/* XCR0: which register states the OS saves. Only after OSXSAVE is seen. */
__attribute__((target("xsave"))) static unsigned long long read_xcr0(void)
{
	return (unsigned long long)_xgetbv(0);
}

/* Return 1 when the CPU has SSSE3 and SSE4.1. */
static int cpu_has_sse41(void)
{
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;

	if (__get_cpuid(1U, &a, &b, &c, &d) == 0)
		return 0;
	return (c & ARK_CPUID1_ECX_SSSE3) != 0U &&
	       (c & ARK_CPUID1_ECX_SSE41) != 0U;
}

/* Return 1 when the CPU has AVX2 and SSE4.1 and the OS saves AVX state. */
static int cpu_has_avx2(void)
{
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;

	if (!cpu_has_sse41() || __get_cpuid(1U, &a, &b, &c, &d) == 0)
		return 0;
	if ((c & ARK_CPUID1_ECX_OSXSAVE) == 0U ||
	    (c & ARK_CPUID1_ECX_AVX) == 0U)
		return 0;
	if ((read_xcr0() & ARK_XCR0_SSE_AVX) != ARK_XCR0_SSE_AVX)
		return 0;
	if (__get_cpuid_max(0U, NULL) < 7U)
		return 0;
	__cpuid_count(7U, 0U, a, b, c, d);
	return (b & ARK_CPUID7_EBX_AVX2) != 0U;
}
#endif

int ark_blake3_cpu_supports(ark_blake3_backend_t backend)
{
	switch (backend) {
#if defined(ARK_BLAKE3_ARM) && defined(__aarch64__)
	case ARK_BLAKE3_BACKEND_NEON: /* part of every arm64 CPU */
#endif
	case ARK_BLAKE3_BACKEND_PORTABLE:
		return 1;
#if defined(ARK_BLAKE3_X86) && (defined(__x86_64__) || defined(__i386__))
	case ARK_BLAKE3_BACKEND_SSE41:
		return cpu_has_sse41();
	case ARK_BLAKE3_BACKEND_AVX2:
		return cpu_has_avx2();
#endif
	default:
		return 0;
	}
}

ark_blake3_backend_t ark_blake3_cpu_best(void)
{
	if (ark_blake3_cpu_supports(ARK_BLAKE3_BACKEND_AVX2))
		return ARK_BLAKE3_BACKEND_AVX2;
	if (ark_blake3_cpu_supports(ARK_BLAKE3_BACKEND_SSE41))
		return ARK_BLAKE3_BACKEND_SSE41;
	if (ark_blake3_cpu_supports(ARK_BLAKE3_BACKEND_NEON))
		return ARK_BLAKE3_BACKEND_NEON;
	return ARK_BLAKE3_BACKEND_PORTABLE;
}
