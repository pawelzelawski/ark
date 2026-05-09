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

LDFLAGS_COMMON != if [ "$(OS)" = "Linux" ]; then \
	echo "-lpthread"; \
else \
	echo ""; \
fi

SANITIZERS != if [ "$(OS)" = "Linux" ]; then \
	echo "-fsanitize=address,undefined"; \
else \
	echo ""; \
fi

CFLAGS_COMMON = -std=c11 -Wall -Wextra -Wpedantic        \
		-Wno-unused-parameter                               \
		-D_POSIX_C_SOURCE=200809L                           \
		-D_XOPEN_SOURCE=700

CFLAGS_DEV = $(CFLAGS_COMMON)                             \
	-O0 -g3 -gdwarf-4                                   \
	-Werror                                              \
	-fno-omit-frame-pointer                              \
	$(SANITIZERS)

CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2

CFLAGS_TEST = $(CFLAGS_DEV) -DARK_TEST

CFLAGS_TSAN = $(CFLAGS_COMMON)                            \
	-O1 -g3                                              \
	-fsanitize=thread                                    \
	-fno-omit-frame-pointer                              \
	-DARK_TEST

CFLAGS_VG = $(CFLAGS_COMMON)                              \
	-O0 -g3 -gdwarf-4                                    \
	-DARK_TEST

INCLUDES = -I. -I./src -I./vendor/libchevron/include -I./$(BUILD_DIR)

APP_SRCS = src/archive.c src/blake3.c src/deflate.c src/main.c \
	src/recovery_template.c src/sha256.c vendor/libchevron/src/chevron.c

CORE_SRCS = src/archive.c src/blake3.c src/deflate.c src/sha256.c \
	vendor/libchevron/src/chevron.c

TEST_SRCS = tests/run_tests.c tests/ark_stubs.c tests/test_archive.c \
	tests/test_blake3.c tests/test_deflate.c tests/test_edge.c \
	tests/test_extract.c tests/test_fault.c tests/test_integration.c \
	tests/test_sha256.c tests/test_thread.c

FORMAT_SRCS = src/archive.c src/archive.h src/ark_internal.h src/blake3.c \
	src/blake3.h src/deflate.c src/deflate.h src/main.c \
	src/recovery_template.c src/sha256.c src/sha256.h \
	tests/ark_stubs.c tests/run_tests.c tests/test_archive.c \
	tests/test_blake3.c tests/test_deflate.c tests/test_edge.c \
	tests/test_extract.c tests/test_fault.c tests/test_integration.c \
	tests/test_sha256.c tests/test_thread.c

.PHONY: all dev release test test-tsan valgrind lint format clean install

all: dev

dev: $(RECOVERY_HEADER) $(APP_SRCS) $(TEST_BIN)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_DEV) $(INCLUDES) $(APP_SRCS) -o $(ARK_BIN) $(LDFLAGS_COMMON)
	$(TEST_BIN)

release: $(RECOVERY_HEADER) $(APP_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) $(APP_SRCS) -o $(ARK_BIN) $(LDFLAGS_COMMON)

test: $(TEST_BIN)
	$(TEST_BIN)

test-tsan:
	@command -v clang >/dev/null 2>&1 || \
		{ echo "test-tsan: TSan requires Clang"; exit 1; }
	@if [ "$(OS)" != "Linux" ]; then \
		echo "test-tsan: Linux only"; exit 1; \
	fi
	@mkdir -p $(TSAN_DIR) $(TEST_DIR)
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) $(CORE_SRCS) $(TEST_SRCS) \
		-o $(TEST_BIN_TSAN) $(LDFLAGS_COMMON)
	$(TEST_BIN_TSAN)

valgrind: $(TEST_BIN_VG)
	@if [ "$(OS)" != "Linux" ]; then \
		echo "valgrind: Linux only"; exit 1; \
	fi
	valgrind --leak-check=full              \
		 --show-leak-kinds=all          \
		 --track-origins=yes            \
		 --error-exitcode=1             \
		 $(TEST_BIN_VG)

lint:
	clang-tidy src/archive.c src/blake3.c src/deflate.c src/main.c src/sha256.c \
		-- $(CFLAGS_RELEASE) $(INCLUDES)
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
	awk 'BEGIN { print "static const unsigned char recovery_template[] =" } \
		{ gsub(/\\\\/, "\\\\\\\\"); gsub(/"/, "\\\\\""); \
		  print "\"" $$0 "\\n\"" } \
		END { print ";" }' src/recovery_template.c > $(RECOVERY_HEADER)
