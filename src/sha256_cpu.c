/*
 * sha256_cpu.c - SHA-256 backend detection (sha256_cpu.h).
 *
 * x86: SHA extensions (CPUID leaf 7, EBX bit 29) plus SSSE3 and SSE4.1
 * (leaf 1, ECX bits 9 and 19), read with the compiler's <cpuid.h>.
 * arm64: HWCAP_SHA2 from the kernel's auxiliary vector. Every other
 * platform, or a build without the hardware files, reports PORTABLE only.
 * No allocation, no state. See ARCHITECTURE.md section 8.4.
 */

#include "sha256_cpu.h"

#if defined(ARK_SHA256_X86) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>

#define ARK_CPUID1_ECX_SSSE3 (1U << 9)
#define ARK_CPUID1_ECX_SSE41 (1U << 19)
#define ARK_CPUID7_EBX_SHA (1U << 29)

/* Return 1 when the CPU has SHA, SSSE3 and SSE4.1. */
static int cpu_has_sha_ni(void)
{
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;

	if (__get_cpuid(1U, &a, &b, &c, &d) == 0)
		return 0;
	if ((c & ARK_CPUID1_ECX_SSSE3) == 0U ||
	    (c & ARK_CPUID1_ECX_SSE41) == 0U)
		return 0;
	if (__get_cpuid_max(0U, NULL) < 7U)
		return 0;
	__cpuid_count(7U, 0U, a, b, c, d);
	return (b & ARK_CPUID7_EBX_SHA) != 0U;
}
#endif

#if defined(ARK_SHA256_ARM) && defined(__aarch64__)
#include <sys/auxv.h>

#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 6)
#endif

/* Return 1 when the kernel reports the ARMv8 SHA2 instructions. */
static int cpu_has_armv8_sha2(void)
{
#if defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0U;
#elif defined(__OpenBSD__)
	unsigned long hw;

	hw = 0U;
	if (elf_aux_info(AT_HWCAP, &hw, (int)sizeof(hw)) != 0)
		return 0;
	return (hw & HWCAP_SHA2) != 0U;
#else
	return 0;
#endif
}
#endif

int ark_sha256_cpu_supports(ark_sha256_backend_t backend)
{
	switch (backend) {
	case ARK_SHA256_BACKEND_PORTABLE:
		return 1;
#if defined(ARK_SHA256_X86) && (defined(__x86_64__) || defined(__i386__))
	case ARK_SHA256_BACKEND_X86_SHANI:
		return cpu_has_sha_ni();
#endif
#if defined(ARK_SHA256_ARM) && defined(__aarch64__)
	case ARK_SHA256_BACKEND_ARMV8:
		return cpu_has_armv8_sha2();
#endif
	default:
		return 0;
	}
}

ark_sha256_backend_t ark_sha256_cpu_best(void)
{
	if (ark_sha256_cpu_supports(ARK_SHA256_BACKEND_X86_SHANI))
		return ARK_SHA256_BACKEND_X86_SHANI;
	if (ark_sha256_cpu_supports(ARK_SHA256_BACKEND_ARMV8))
		return ARK_SHA256_BACKEND_ARMV8;
	return ARK_SHA256_BACKEND_PORTABLE;
}
