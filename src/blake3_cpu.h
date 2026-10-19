#ifndef ARK_BLAKE3_CPU_H
#define ARK_BLAKE3_CPU_H

/*
 * blake3_cpu.h - Which BLAKE3 backend the running CPU supports.
 *
 * The only BLAKE3 file that asks the CPU: x86 uses the cpuid and xgetbv
 * instructions (no OS call); arm64 needs no question, since NEON is part
 * of every arm64 CPU. A program that wants no compiler-specific code
 * leaves this file out and passes a backend to ark_blake3_init_backend()
 * itself. A backend counts only when it is also built in (ARK_BLAKE3_X86 /
 * ARK_BLAKE3_ARM).
 *
 * See ARCHITECTURE.md section 8.4.
 */

#include "blake3.h"

/*
 * ark_blake3_cpu_supports - Return 1 when backend is built into this
 * program and the CPU (and, for AVX2, the OS's saved register state) has
 * its instructions, else 0. PORTABLE is always supported.
 */
int ark_blake3_cpu_supports(ark_blake3_backend_t backend);

/*
 * ark_blake3_cpu_best - Return the fastest supported backend: AVX2, then
 * SSE4.1, then NEON when ark_blake3_cpu_supports() says so, else PORTABLE.
 * Each call asks the CPU again; callers keep the result.
 */
ark_blake3_backend_t ark_blake3_cpu_best(void);

#endif /* ARK_BLAKE3_CPU_H */
