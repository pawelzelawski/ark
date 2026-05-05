# Tech Stack

## 1. Language

### C (C11)

ark is written in C11. No C++, no scripting languages, no code generation.

**Standard**: C11 (`-std=c11`)

**Why C11 over C99**:
- `_Static_assert` for compile-time verification of struct layout assumptions,
  integer type widths, and format constant correctness
- Designated initialisers for internal state initialisation macros
- `_Bool` for internal boolean flags in thread pool and ring buffer state

**Feature test macros** (defined in Makefile, not in source files):
```c
_POSIX_C_SOURCE=200809L   /* POSIX.1-2008 */
_XOPEN_SOURCE=700         /* XSI extensions */
```

Do not define `_GNU_SOURCE` - it pulls in non-portable extensions and breaks
OpenBSD builds.

---

## 2. External Dependencies

ark has **zero external library dependencies**. This is a hard requirement,
not a preference.

The only runtime dependencies are the C standard library and POSIX interfaces
available on every supported platform without installation. There are no
package manager files and no submodules beyond libchevron.

**libchevron** is vendored at a pinned commit inside the ark repository. It
is the author's own library under the same ISC license and identical technical
standards. It is not an external dependency in any meaningful sense: one
repository clone produces a complete, buildable source tree with no network
access required.

**sha256, blake3, deflate** are internal implementations compiled directly
into the `ark` binary. Each is a self-contained two-file component (`.h` +
`.c`) with a clean public API and no dependencies beyond libc. They are
independently portable: copying `blake3.h` and `blake3.c` to another project
produces a fully functional standalone component.

---

## 3. System Libraries

These are part of the C standard library or POSIX and require no installation.

### 3.1 Standard C Library

```c
#include <stddef.h>     /* size_t, NULL                                  */
#include <stdint.h>     /* uint8_t, uint32_t, uint64_t, int64_t          */
#include <stdbool.h>    /* bool, true, false (internal use only)         */
#include <string.h>     /* memset, memcpy, memcmp, strlen, strerror      */
#include <stdlib.h>     /* malloc, free, exit                            */
#include <stdio.h>      /* fprintf, snprintf, stderr                     */
#include <errno.h>      /* errno — syscall error inspection              */
#include <limits.h>     /* PATH_MAX, NAME_MAX                            */
#include <assert.h>     /* _Static_assert (via assert.h in C11)          */
```

### 3.2 POSIX File and Directory Operations

```c
#include <fcntl.h>      /* open, O_RDONLY, O_WRONLY, O_CREAT, O_NOFOLLOW,
                           O_CLOEXEC, O_DIRECTORY                        */
#include <unistd.h>     /* read, write, close, lstat, unlink, rmdir,
                           link, lchown, utimensat, isatty              */
#include <sys/stat.h>   /* stat, lstat, mode_t, AT_SYMLINK_NOFOLLOW      */
#include <sys/types.h>  /* uid_t, gid_t, ssize_t                         */
#include <dirent.h>     /* opendir, readdir, closedir, struct dirent      */
```

### 3.3 POSIX Threading

```c
#include <pthread.h>    /* pthread_create, pthread_join, pthread_mutex_*,
                           pthread_cond_*, pthread_attr_*               */
```

pthreads is used for the worker thread pool on both Linux and OpenBSD.
No platform-specific threading API exists anywhere in the codebase.

### 3.4 POSIX Realpath and Path Operations

```c
#include <stdlib.h>     /* realpath(3) — POSIX.1-2008                    */
```

`realpath` is used exclusively in `main.c` for source path resolution before
traversal. It is not used in any library component.

### 3.5 Syslog

```c
#include <syslog.h>     /* openlog, syslog, closelog                     */
```

All diagnostic output goes to syslog. No file-based logging exists.
`stderr` is used only for interactive terminal output (warnings, errors,
progress) when `isatty(STDERR_FILENO)` is true.

### 3.6 Linux-Specific Headers (conditional)

```c
#ifdef __linux__
#include <linux/landlock.h>   /* LANDLOCK_ACCESS_FS_*, landlock_ruleset_attr */
#include <linux/seccomp.h>    /* SECCOMP_SET_MODE_FILTER, seccomp_data       */
#include <linux/filter.h>     /* sock_filter, sock_fprog                      */
#include <sys/prctl.h>        /* prctl, PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS  */
#include <sys/syscall.h>      /* syscall, SYS_landlock_create_ruleset, etc.   */
#endif
```

All Landlock and seccomp-bpf code is guarded by `#ifdef __linux__`. No
platform-specific code exists outside these guards. The Linux sandboxing
headers are always present on any Linux 5.13+ build host; no installation
beyond the standard kernel headers package is required.

### 3.7 OpenBSD-Specific Headers (conditional)

```c
#ifdef __OpenBSD__
#include <unistd.h>     /* pledge(2), unveil(2) — part of base unistd.h  */
#endif
```

`pledge` and `unveil` are declared in `<unistd.h>` on OpenBSD. No additional
headers are required. These calls are absent on Linux; all call sites are
guarded by `#ifdef __OpenBSD__`.

---

## 4. Compiler

### 4.1 Primary Compiler - Clang

**Minimum version**: Clang 14.0

Clang is the primary and required compiler. It is used for all builds,
including sanitiser builds (ASan, UBSan, TSan). clang-tidy static analysis
requires a Clang installation.

Clang 14.0 is the default compiler on Ubuntu 22.04 LTS, which targets
Linux 5.15 - the earliest practical deployment kernel for ark given the
Linux 5.13 Landlock requirement. Clang 14.0 is also available on
OpenBSD 7.x via the base system.

### 4.2 Secondary Compiler - GCC

**Minimum version**: GCC 11.0

GCC is supported as a secondary compiler. GCC builds are validated on Linux
only. TSan is not run under GCC - the TSan build target requires Clang.
GCC 11.0 is the default on Ubuntu 22.04 LTS.

### 4.3 Compiler Flags

**Release build** (`make release`):
```makefile
CFLAGS_RELEASE = -std=c11 -O2                   \
                 -Wall -Wextra -Wpedantic         \
                 -Wno-unused-parameter            \
                 -D_POSIX_C_SOURCE=200809L        \
                 -D_XOPEN_SOURCE=700
```

**Development build** (`make dev`, default):
```makefile
CFLAGS_DEV = -std=c11 -O0 -g3 -gdwarf-4         \
             -Wall -Wextra -Wpedantic              \
             -Wno-unused-parameter                 \
             -Werror                               \
             -fno-omit-frame-pointer               \
             -fsanitize=address,undefined          \
             -D_POSIX_C_SOURCE=200809L             \
             -D_XOPEN_SOURCE=700
```

ASan/UBSan (`-fsanitize=address,undefined`) is enabled on Linux only.
OpenBSD clang does not ship the sanitiser runtimes.

**TSan build** (`make test-tsan`, Linux/Clang only):
```makefile
CFLAGS_TSAN = -std=c11 -O1 -g3                   \
              -Wall -Wextra -Wpedantic              \
              -Wno-unused-parameter                 \
              -fsanitize=thread                     \
              -fno-omit-frame-pointer               \
              -D_POSIX_C_SOURCE=200809L             \
              -D_XOPEN_SOURCE=700
```

TSan and ASan are mutually exclusive; TSan runs as a separate target.
TSan is required at phase boundaries for any phase that introduces or
modifies concurrent data structures. See DEVELOPMENT.md for the specific
phase milestones at which TSan is required.

**Valgrind build** (`make valgrind`, Linux only):
```makefile
CFLAGS_VG  = -std=c11 -O0 -g3 -gdwarf-4          \
             -Wall -Wextra -Wpedantic               \
             -Wno-unused-parameter                  \
             -D_POSIX_C_SOURCE=200809L              \
             -D_XOPEN_SOURCE=700
```

No sanitisers in the Valgrind build - ASan and Valgrind conflict.

`-Werror` is enabled in development builds only. Release builds do not treat
warnings as errors - this prevents release breakage from compiler version
differences across platforms.

**Link flags** (all targets):
```makefile
LDFLAGS = -lpthread
```

`-lpthread` is required on Linux to link the pthread implementation. On
OpenBSD, pthreads are part of libc and no additional link flag is needed;
the Makefile conditionally omits `-lpthread` on OpenBSD.

---

## 5. Build System

### 5.1 Make

ark uses a single `Makefile`. No CMake, no Meson, no Autoconf. The build
system must be auditable, portable, and require nothing beyond `make` and
a C11 compiler.

Compatible with GNU make (Linux) and BSD make (OpenBSD). Uses `!=` for shell
assignment, which is portable to both. No pattern rules or substitution
references that are GNU-make-only.

**Primary targets**:

```sh
make              # equivalent to make dev
make dev          # debug build with ASan/UBSan (Linux), runs tests
make release      # optimised binary
make test         # run test suite (dev build)
make test-tsan    # TSan build and test run (Linux/Clang only)
make valgrind     # Valgrind run (Linux only, no sanitisers)
make lint         # clang-tidy + cppcheck
make format       # clang-format -i on all source files
make clean        # remove build artefacts
make install      # install ark binary
```

**Platform detection**:

```makefile
OS != uname -s
```

Platform is detected via `uname -s` at build time. The `!=` operator is
portable to both GNU make and BSD make. No manual platform flag is required.
All platform-conditional Makefile logic branches on `$(OS)`.

### 5.2 Build Output

```
build/ark           — binary (sole build artefact)
build/tests/run_tests — test binary
```

The `ark` binary is the only artefact. There is no static library output.
The internal components (sha256, blake3, deflate, archive) are compiled
directly into the binary. They are not exposed as installable library
artefacts.

### 5.3 Install Target

`make install` installs one file:

```sh
$(BINDIR)/ark
```

Default install prefix is `/usr/local`. Override with `PREFIX=/path make install`.
The man page is installed to `$(MANDIR)/man1/ark.1`.

---

## 6. Test Infrastructure

### 6.1 Test Harness

ark uses a minimal hand-written test harness - no external test framework.
Tests are plain C functions that return 0 on pass and non-zero on fail.
A coordinator in `tests/run_tests.c` calls each test function in sequence
and reports results.

### 6.2 Fault Injection

Fault injection uses compile-time substitution via `#define`. Library
component source files use wrapper macros for all syscalls that can fail.
In production builds the macros resolve directly to the real syscalls with
zero overhead. In test builds (`-DARK_TEST`) the macros resolve to stub
functions controlled by a test state struct.

This is the only approach that works correctly and identically on both Linux
and OpenBSD. `LD_PRELOAD` interposition is restricted on OpenBSD; linker
`--wrap` is not supported on OpenBSD.

The wrapped syscalls cover all operations that can fail in the component
under test. Each component defines its own wrapper set. See TESTING.md for
the full per-component syscall wrapper list.

### 6.3 Test Files

```
tests/
├── run_tests.c           # test binary entry point; calls all test suites
├── ark_stubs.c           # fault injection stubs (compiled with -DARK_TEST only)
├── test_sha256.c         # SHA-256 implementation against NIST test vectors
├── test_blake3.c         # BLAKE3 implementation against official test vectors
├── test_deflate.c        # Deflate compress/decompress round-trip and edge cases
├── test_archive.c        # archive.h API unit tests: write path, read path, error model
├── test_thread.c         # thread pool: cancellation, worker error propagation,
│                         #   ring buffer abort sentinel, quiescence sequence
├── test_extract.c        # extraction: path validation, cleanup, --overwrite,
│                         #   symlink handling, hardlink, metadata restoration
├── test_fault.c          # fault injection at each sequence step across all components
├── test_edge.c           # boundary conditions, malformed archives, adversarial inputs
└── test_integration.c    # end-to-end: create then extract, verify, list; round-trip
                          #   correctness on realistic archive sizes
```

See TESTING.md for the full test catalogue.

---

## 7. Development Tools

### 7.1 Valgrind (Linux only)

**Purpose**: Memory error detection - leaks, use-after-free, uninitialised reads.

**Installation**: `apt install valgrind`

**Usage**:
```sh
make valgrind
# equivalent to:
valgrind --leak-check=full          \
         --show-leak-kinds=all      \
         --track-origins=yes        \
         --error-exitcode=1         \
         ./build/tests/run_tests
```

All tests must pass Valgrind clean. Valgrind is not available on OpenBSD.

### 7.2 AddressSanitizer + UndefinedBehaviorSanitizer

**Purpose**: Runtime memory and undefined behaviour detection.

**Compiler flags**: `-fsanitize=address,undefined` (included in `make dev`)

Available on Linux with Clang. OpenBSD clang does not ship the sanitiser
runtimes. All tests must pass ASan/UBSan clean on Linux. OpenBSD correctness
is verified via the standard test suite without sanitisers.

### 7.3 ThreadSanitizer

**Purpose**: Data race detection in the parallel compression and extraction
thread pool, the ring buffer, and the shared cancellation and error state.

```sh
make test-tsan    # Linux/Clang only
```

TSan and ASan are mutually exclusive. TSan is required at phase boundaries
for any phase that introduces or modifies concurrent data structures. See
DEVELOPMENT.md for the specific phase milestones.

**TSan availability**: Clang only. The `make test-tsan` target checks for
Clang availability and fails with a clear message when built with GCC.

### 7.4 clang-tidy

**Purpose**: Static analysis.

**Installation**: included with Clang.

```sh
make lint
```

### 7.5 cppcheck

**Purpose**: Complementary static analysis.

**Installation**: `apt install cppcheck` / `pkg_add cppcheck`

```sh
cppcheck --enable=all --error-exitcode=1 \
         --suppress=missingIncludeSystem \
         src/
```

### 7.6 clang-format

**Purpose**: Consistent code formatting.

**Configuration**: `.clang-format` in repository root. KNF-based style.

```sh
make format
```

---

## 8. Platforms and Architectures

### 8.1 Supported Platforms

Both platforms are first-class. No platform is secondary or best-effort.

| Platform | Minimum Version | Requirement | Notes |
|---|---|---|---|
| Linux | Kernel 5.13 | Hard - Landlock ABI v1 | ASan/UBSan; TSan; Valgrind |
| OpenBSD | 6.4 | Hard - unveil(2) | Standard test suite; no sanitisers |

**Linux 5.13 is a hard minimum.** Landlock is not optional and there is no
fallback path for older kernels. ark fails immediately on startup with a
clear error on any Linux kernel below 5.13. This is documented in the man
page and README.

Landlock ABI v3 features (`LANDLOCK_ACCESS_FS_TRUNCATE`, available from
Linux 6.2) are detected at runtime via the ABI version returned by
`landlock_create_ruleset`. On kernels 5.13-6.1 the truncate right is absent
and the write right is sufficient for the operations performed; no user-
visible behaviour difference results.

**OpenBSD 6.4** is the minimum because `unveil(2)` was introduced in that
release. `pledge(2)` has been available since 5.9. Any OpenBSD installation
in active use will satisfy both requirements.

### 8.2 Supported Architectures

| Architecture | Status |
|---|---|
| x86_64 | First-class |
| ARM64 | First-class |

No architecture-specific code exists in ark. The codebase is pure POSIX C
with no inline assembly, no SIMD, and no architecture-specific intrinsics.
The sha256, blake3, and deflate implementations are portable C with no
platform-specific acceleration paths.

### 8.3 Platform-Specific Behaviour Summary

| Feature | Linux | OpenBSD |
|---|---|---|
| Sandboxing | Landlock + seccomp-bpf | pledge + unveil |
| Thread safety | pthread (libc) | pthread (libc) |
| Link flag | `-lpthread` | none (pthread in libc) |
| Sanitisers | ASan, UBSan, TSan | none (runtimes absent) |
| Valgrind | yes | no |
| `lchown` | yes (POSIX) | yes (POSIX) |
| `utimensat AT_SYMLINK_NOFOLLOW` | yes | yes |
| `O_NOFOLLOW` | yes | yes |

---

## 9. Dependency Summary

| Dependency | Version | Type | Purpose | Platforms |
|---|---|---|---|---|
| Clang | >= 14.0 | Build tool | Compilation, sanitisers, clang-tidy | Linux, OpenBSD |
| GCC | >= 11.0 | Build tool | Secondary compiler (no TSan) | Linux only |
| libc | system | System lib | Standard C, POSIX interfaces | Linux, OpenBSD |
| libpthread | system | System lib | Thread pool (via `-lpthread`) | Linux only |
| Linux kernel | >= 5.13 | Runtime | Landlock sandboxing | Linux only |
| OpenBSD | >= 6.4 | Runtime | unveil sandboxing | OpenBSD only |
| Valgrind | latest | Dev tool | Memory checking | Linux only |
| cppcheck | latest | Dev tool | Static analysis | Linux, OpenBSD |
| libchevron | pinned commit | Vendored | Crash-safe archive write | Linux, OpenBSD |

**Runtime dependencies for end users**:
- Linux: libc, libpthread, Linux kernel 5.13+
- OpenBSD: libc (pthread included), OpenBSD 6.4+

**Development-only dependencies** (not required to build or run):
- Valgrind (Linux only)
- cppcheck
