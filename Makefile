# Makefile - ark
#
# GNU make and BSD make compatible.

OS != uname -s

CC = clang

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

BUILD_DIR = build
TEST_DIR = $(BUILD_DIR)/tests
TSAN_DIR = $(BUILD_DIR)/tsan
VG_DIR = $(BUILD_DIR)/vg
REL_DIR = $(BUILD_DIR)/rel

ARK_BIN = $(BUILD_DIR)/ark
TEST_BIN = $(TEST_DIR)/run_tests
TEST_BIN_TSAN = $(TEST_DIR)/run_tests_tsan
TEST_BIN_VG = $(TEST_DIR)/run_tests_vg

RECOVERY_HEADER = $(BUILD_DIR)/recovery_template_data.h

LDFLAGS_COMMON = -pthread

SANITIZERS != if [ "$(OS)" = "Linux" ]; then \
	echo "-fsanitize=address,undefined"; \
else \
	echo ""; \
fi

# SHA-256 hardware block function for the build machine's architecture
# (ARCHITECTURE.md section 8.4): sha256_x86.c on x86-64, sha256_arm.c on
# arm64, none elsewhere; sha256.c calls it only under the matching macro.
SHA256_HW_SRCS != case "$$(uname -m)" in \
	x86_64|amd64) echo src/sha256_x86.c ;; \
	aarch64|arm64) echo src/sha256_arm.c ;; \
esac

SHA256_HW_DEFS != case "$$(uname -m)" in \
	x86_64|amd64) echo -DARK_SHA256_X86 ;; \
	aarch64|arm64) echo -DARK_SHA256_ARM ;; \
esac

# BLAKE3 SIMD chunk functions, the same way: blake3_x86.c (SSE4.1, AVX2) on
# x86-64, blake3_arm.c (NEON) on arm64; blake3.c calls them only under the
# matching macro.
BLAKE3_HW_SRCS != case "$$(uname -m)" in \
	x86_64|amd64) echo src/blake3_x86.c ;; \
	aarch64|arm64) echo src/blake3_arm.c ;; \
esac

BLAKE3_HW_DEFS != case "$$(uname -m)" in \
	x86_64|amd64) echo -DARK_BLAKE3_X86 ;; \
	aarch64|arm64) echo -DARK_BLAKE3_ARM ;; \
esac

# clang-tidy is told where its own version of clang's headers (<cpuid.h>,
# <immintrin.h>) is: a packaged clang-tidy (OpenBSD's clang-tools-extra)
# does not find them by itself, and another clang version's headers do not
# parse. The first directory named after clang-tidy's major version is used:
# clang's own, the LLVM package's (/usr/local/llvmN), then /usr/lib/clang.
TIDY_RESOURCE_DIR != v=$$(clang-tidy --version 2>/dev/null | \
	sed -n 's/.*LLVM version \([0-9][0-9]*\).*/\1/p' | head -n 1); \
	for r in "$$(clang -print-resource-dir 2>/dev/null)" \
	    /usr/local/llvm$$v/lib/clang/$$v /usr/lib/clang/$$v; do \
		if [ -n "$$v" ] && [ "$$(basename "$$r")" = "$$v" ] && \
		    [ -d "$$r/include" ]; then \
			echo "-resource-dir=$$r"; break; \
		fi; \
	done; true

CFLAGS_COMMON = -std=c11 -Wall -Wextra -Wpedantic        \
		-Wno-unused-parameter                               \
		-D_POSIX_C_SOURCE=200809L                           \
		-D_XOPEN_SOURCE=700                                 \
		$(SHA256_HW_DEFS) $(BLAKE3_HW_DEFS)

CFLAGS_DEV = $(CFLAGS_COMMON)                             \
	-O0 -g3 -gdwarf-4                                   \
	-Werror                                              \
	-fno-omit-frame-pointer                              \
	$(SANITIZERS)

CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2

CFLAGS_TEST = $(CFLAGS_DEV) -DARK_TEST -DARK_DEFLATE_TEST -DARK_BLAKE3_TEST

CFLAGS_TSAN = $(CFLAGS_COMMON)                            \
	-O1 -g3                                              \
	-fsanitize=thread                                    \
	-fno-omit-frame-pointer                              \
	-DARK_TEST -DARK_DEFLATE_TEST -DARK_BLAKE3_TEST

CFLAGS_VG = $(CFLAGS_COMMON)                              \
	-O0 -g3 -gdwarf-4                                    \
	-DARK_TEST -DARK_DEFLATE_TEST -DARK_BLAKE3_TEST

INCLUDES = -I. -I./src -I./vendor/libchevron/include -I./$(BUILD_DIR)

APP_SRCS = src/archive.c src/blake3.c src/blake3_cpu.c $(BLAKE3_HW_SRCS) \
	src/deflate.c src/main.c src/sha256.c src/sha256_cpu.c \
	$(SHA256_HW_SRCS) vendor/libchevron/src/chevron.c

CORE_SRCS = src/archive.c src/blake3.c src/blake3_cpu.c $(BLAKE3_HW_SRCS) \
	src/deflate.c src/main.c src/sha256.c src/sha256_cpu.c \
	$(SHA256_HW_SRCS) src/zwrap.c vendor/libchevron/src/chevron.c

TEST_SRCS = tests/run_tests.c tests/ark_stubs.c tests/test_archive.c \
	tests/test_blake3.c tests/test_deflate.c tests/test_edge.c \
	tests/test_extract.c tests/test_fault.c tests/test_integration.c \
	tests/test_sha256.c tests/test_thread.c tests/test_zwrap.c

FORMAT_SRCS = src/archive.c src/archive.h src/ark_internal.h src/blake3.c \
	src/blake3.h src/blake3_arm.c src/blake3_cpu.c src/blake3_cpu.h \
	src/blake3_x86.c src/deflate.c src/deflate.h src/main.c \
	src/recovery_template.c src/sha256.c src/sha256.h src/sha256_arm.c \
	src/sha256_cpu.c src/sha256_cpu.h src/sha256_x86.c src/zwrap.c \
	src/zwrap.h \
	tests/ark_stubs.c tests/run_tests.c tests/test_archive.c \
	tests/test_blake3.c tests/test_deflate.c tests/test_edge.c \
	tests/test_extract.c tests/test_fault.c tests/test_integration.c \
	tests/test_sha256.c tests/test_thread.c tests/test_zwrap.c

.PHONY: all dev release test test-tsan valgrind test-qemu lint format clean install

all: dev

dev: $(RECOVERY_HEADER) $(APP_SRCS) $(TEST_BIN)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_DEV) $(INCLUDES) $(APP_SRCS) -o $(ARK_BIN) $(LDFLAGS_COMMON)
	$(TEST_BIN)

release: $(RECOVERY_HEADER) $(APP_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) $(APP_SRCS) -o $(ARK_BIN) $(LDFLAGS_COMMON)

test: $(ARK_BIN) $(TEST_BIN)
	$(TEST_BIN)

test-tsan: $(ARK_BIN)
	@command -v clang >/dev/null 2>&1 || \
		{ echo "test-tsan: TSan requires Clang"; exit 1; }
	@if [ "$(OS)" != "Linux" ]; then \
		echo "test-tsan: Linux only"; exit 1; \
	fi
	@mkdir -p $(TSAN_DIR) $(TEST_DIR)
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) $(CORE_SRCS) $(TEST_SRCS) \
		-o $(TEST_BIN_TSAN) $(LDFLAGS_COMMON)
	$(TEST_BIN_TSAN)

valgrind: $(ARK_BIN) $(TEST_BIN_VG)
	@if [ "$(OS)" != "Linux" ]; then \
		echo "valgrind: Linux only"; exit 1; \
	fi
	valgrind --leak-check=full              \
		 --show-leak-kinds=all          \
		 --track-origins=yes            \
		 --error-exitcode=1             \
		 $(TEST_BIN_VG)

# SHA-256 and BLAKE3 tests on an emulated CPU with the x86 SHA extensions
# and AVX2, which the build machine may lack: the uninstrumented test
# binary under qemu-x86_64 -cpu max (x86-64 Linux with qemu-user only).
test-qemu: $(TEST_BIN_VG)
	@command -v qemu-x86_64 >/dev/null 2>&1 || \
		{ echo "test-qemu: qemu-x86_64 not found"; exit 1; }
	qemu-x86_64 -cpu max $(TEST_BIN_VG) test_sha256
	qemu-x86_64 -cpu max $(TEST_BIN_VG) test_blake3

lint:
	clang-tidy src/archive.c src/blake3.c src/blake3_cpu.c $(BLAKE3_HW_SRCS) \
		src/deflate.c src/main.c src/sha256.c src/sha256_cpu.c \
		$(SHA256_HW_SRCS) src/zwrap.c \
		-- $(CFLAGS_RELEASE) $(INCLUDES) $(TIDY_RESOURCE_DIR)
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --error-exitcode=1 \
			 --suppress=missingIncludeSystem \
			 --suppress=unusedFunction \
			 --suppress=checkersReport \
			 --suppress=normalCheckLevelMaxBranches \
			 --suppress=unmatchedSuppression \
			 -I src -I build -I vendor/libchevron/include \
			 src/ tests/; \
	else \
		echo "cppcheck not found; skipping"; \
	fi

format:
	clang-format -i $(FORMAT_SRCS)

clean:
	rm -rf $(BUILD_DIR)

install: release
	install -d $(BINDIR) $(MANDIR)/man1
	install -m 755 $(ARK_BIN) $(BINDIR)/ark
	install -m 644 man/ark.1 $(MANDIR)/man1/ark.1

$(ARK_BIN): $(RECOVERY_HEADER) $(APP_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_DEV) $(INCLUDES) $(APP_SRCS) -o $(ARK_BIN) $(LDFLAGS_COMMON)


$(TEST_BIN): $(RECOVERY_HEADER) $(CORE_SRCS) $(TEST_SRCS)
	@mkdir -p $(TEST_DIR)
	$(CC) $(CFLAGS_TEST) $(INCLUDES) $(CORE_SRCS) $(TEST_SRCS) \
		-o $(TEST_BIN) $(LDFLAGS_COMMON)

$(TEST_BIN_VG): $(RECOVERY_HEADER) $(CORE_SRCS) $(TEST_SRCS)
	@mkdir -p $(VG_DIR) $(TEST_DIR)
	$(CC) $(CFLAGS_VG) $(INCLUDES) $(CORE_SRCS) $(TEST_SRCS) \
		-o $(TEST_BIN_VG) $(LDFLAGS_COMMON)

$(RECOVERY_HEADER): src/recovery_template.c
	@mkdir -p $(BUILD_DIR)
	{ \
		echo "static const unsigned char recovery_template[] = {"; \
		od -An -v -tx1 src/recovery_template.c | \
		awk '{ for (i = 1; i <= NF; i++) printf "0x%s,", $$i; print "" }'; \
		echo "0x00};"; \
	} > $(RECOVERY_HEADER)
