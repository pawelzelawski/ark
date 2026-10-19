#ifndef ARK_SHA256_CPU_H
#define ARK_SHA256_CPU_H

/*
 * sha256_cpu.h - Which SHA-256 backend the running CPU supports.
 *
 * The only SHA-256 file that asks the CPU or the OS: x86 uses the cpuid
 * instruction; arm64 asks the kernel (getauxval(AT_HWCAP) on Linux,
 * elf_aux_info(AT_HWCAP) on OpenBSD). A program that wants no OS
 * dependency leaves this file out and passes a backend to
 * ark_sha256_init_backend() itself. A backend counts only when it is also
 * built in (ARK_SHA256_X86 / ARK_SHA256_ARM).
 *
 * See ARCHITECTURE.md section 8.4.
 */

#include "sha256.h"

/*
 * ark_sha256_cpu_supports - Return 1 when backend is built into this
 * program and the CPU has its instructions, else 0. PORTABLE is always
 * supported.
 */
int ark_sha256_cpu_supports(ark_sha256_backend_t backend);

/*
 * ark_sha256_cpu_best - Return the fastest supported backend: a hardware
 * one when ark_sha256_cpu_supports() says so, else PORTABLE. Each call asks
 * the CPU again; callers keep the result.
 */
ark_sha256_backend_t ark_sha256_cpu_best(void);

#endif /* ARK_SHA256_CPU_H */
