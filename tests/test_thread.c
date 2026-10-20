/*
 * test_thread.c - Thread pool and ring buffer tests for Phase 6.6.
 *
 * Exercises ARCHITECTURE.md sections 6.3 and 14.3 behavior required by
 * TESTING.md section 4.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "archive.h"
#include "ark_internal.h"
#include "deflate.h"

typedef struct ring_buf ring_buf_t;
typedef struct ark_pool ark_pool_t;

ring_buf_t *ring_buf_init(size_t, ark_error_t *);
int ring_buf_write(ring_buf_t *, uint64_t, const uint8_t *, size_t, ark_err_t,
                   ark_error_t *);
int ring_buf_abort(ring_buf_t *, uint64_t, ark_err_t, ark_error_t *);
int ring_buf_read(ring_buf_t *, uint64_t, uint8_t **, size_t *, int *,
                  ark_err_t *, ark_error_t *);
void ring_buf_free(ring_buf_t *);

ark_pool_t *pool_test_init(int, int, ark_error_t *);
int pool_test_submit(ark_pool_t *, uint64_t, const uint8_t *, size_t);
int pool_test_read(ark_pool_t *, uint64_t, uint8_t **, size_t *, int *,
                   ark_err_t *, ark_error_t *);
void pool_test_cancel(ark_pool_t *);
void pool_test_shutdown(ark_pool_t *);
int pool_get_cancel_flag(const ark_pool_t *);
ark_error_t pool_get_shared_err(const ark_pool_t *);
void pool_test_store_error(ark_pool_t *, const ark_error_t *);
void pool_test_reset_shared_err(ark_pool_t *);
int pool_get_sentinel_count(const ark_pool_t *);
unsigned int pool_get_error_event(const ark_pool_t *);
unsigned int pool_get_abort_event(const ark_pool_t *);
void pool_inject_worker_error(ark_pool_t *, ark_err_t, int);
int ark_test_create_archive(const char *, const char **, size_t, int,
                            ark_hash_alg_t, int, ark_error_t *);
int ark_test_extract_archive(const char *, const char *, int, const char *, int,
                             ark_error_t *);
void ark_test_cli_fault_reset(void);
void ark_test_cli_fault_inject(int, int, ark_err_t, int);

/* Command fault points of main.c used here (same values as test_fault.c). */
enum {
	ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE = 2,
	ARK_CLI_FAULT_CREATE_WORKER = 6
};

typedef struct {
	ring_buf_t *ring;
	uint64_t seq;
	uint8_t *data;
	size_t len;
	int abort;
	ark_err_t worker_err;
	int rc;
} reader_arg_t;

static const uint8_t g_pool_src[] = {
    0x61, 0x72, 0x6b, 0x2d, 0x74, 0x68, 0x72, 0x65,
    0x61, 0x64, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x73,
};

/*
 * dup_bytes - Allocate and copy one test payload buffer.
 */
static uint8_t *dup_bytes(const uint8_t *src, size_t len)
{
	uint8_t *dst;

	dst = malloc(len == 0U ? 1U : len);
	if (dst == NULL)
		return NULL;
	if (len > 0U)
		memcpy(dst, src, len);
	return dst;
}

/*
 * reader_thread - Block on one expected sequence during unblock tests.
 */
static void *reader_thread(void *arg)
{
	reader_arg_t *ra;
	ark_error_t err = {0};

	ra = (reader_arg_t *)arg;
	ra->rc = ring_buf_read(ra->ring, ra->seq, &ra->data, &ra->len,
	                       &ra->abort, &ra->worker_err, &err);
	return NULL;
}

/*
 * monotonic_ns - Return CLOCK_MONOTONIC timestamp in nanoseconds.
 */
static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * path_join - Join dir/name into dst as "dir/name".
 */
static int path_join(char *dst, size_t dst_sz, const char *dir,
                     const char *name)
{
	int n;

	n = snprintf(dst, dst_sz, "%s/%s", dir, name);
	if (n < 0)
		return -1;
	if ((size_t)n >= dst_sz)
		return -1;
	return 0;
}

/*
 * write_full_fd - Write all bytes to fd unless a hard write error occurs.
 */
static int write_full_fd(int fd, const uint8_t *buf, size_t len)
{
	while (len > 0U) {
		ssize_t n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * write_pattern_file - Write deterministic byte pattern of exactly total bytes.
 */
static int write_pattern_file(const char *path, size_t total)
{
	uint8_t block[4096];
	int fd;
	size_t i;
	size_t rem;

	for (i = 0U; i < sizeof(block); i++)
		block[i] = (uint8_t)(i & 0xffU);

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0)
		return -1;

	rem = total;
	while (rem > 0U) {
		size_t chunk;

		chunk = rem < sizeof(block) ? rem : sizeof(block);
		if (write_full_fd(fd, block, chunk) != 0) {
			(void)close(fd);
			return -1;
		}
		rem -= chunk;
	}
	if (close(fd) != 0)
		return -1;
	return 0;
}

/*
 * read_file_bytes - Read one file into a newly allocated buffer.
 *
 * OWNERSHIP: on success *out is owned by the caller and must be freed.
 */
static int read_file_bytes(const char *path, uint8_t **out, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	int fd;
	size_t off;

	if (stat(path, &st) != 0 || st.st_size < 0)
		return -1;
	buf = malloc((size_t)st.st_size == 0U ? 1U : (size_t)st.st_size);
	if (buf == NULL)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	off = 0U;
	while (off < (size_t)st.st_size) {
		ssize_t n;

		n = read(fd, buf + off, (size_t)st.st_size - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			(void)close(fd);
			free(buf);
			return -1;
		}
		if (n == 0) {
			(void)close(fd);
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}
	if (close(fd) != 0) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = (size_t)st.st_size;
	return 0;
}

/*
 * remove_tree - Recursively remove one test directory subtree.
 */
static int remove_tree(const char *path)
{
	struct stat st;
	DIR *dir;
	const struct dirent *de;

	if (lstat(path, &st) != 0)
		return errno == ENOENT ? 0 : -1;
	if (!S_ISDIR(st.st_mode))
		return unlink(path);

	dir = opendir(path);
	if (dir == NULL)
		return -1;
	while ((de = readdir(dir)) != NULL) {
		char child[1024];

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		if (path_join(child, sizeof(child), path, de->d_name) != 0) {
			(void)closedir(dir);
			return -1;
		}
		if (remove_tree(child) != 0) {
			(void)closedir(dir);
			return -1;
		}
	}
	if (closedir(dir) != 0)
		return -1;
	return rmdir(path);
}

/*
 * prepare_source_tree - Create a fixed input tree for create determinism tests.
 */
static int prepare_source_tree(const char *root, char *src_dir, size_t src_sz)
{
	char subdir[1024];
	char tiny[1024];
	char medium[1024];
	char large[1024];
	static const uint8_t tiny_data[] = "thread-pool-determinism\n";

	if (path_join(src_dir, src_sz, root, "src") != 0)
		return -1;
	if (mkdir(src_dir, 0755) != 0)
		return -1;
	if (path_join(subdir, sizeof(subdir), src_dir, "nested") != 0)
		return -1;
	if (mkdir(subdir, 0755) != 0)
		return -1;

	if (path_join(tiny, sizeof(tiny), src_dir, "a.txt") != 0)
		return -1;
	if (path_join(medium, sizeof(medium), subdir, "b.bin") != 0)
		return -1;
	if (path_join(large, sizeof(large), subdir, "c.large") != 0)
		return -1;

	{
		int fd;

		fd = open(tiny, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0)
			return -1;
		if (write_full_fd(fd, tiny_data, sizeof(tiny_data) - 1U) != 0) {
			(void)close(fd);
			return -1;
		}
		if (close(fd) != 0)
			return -1;
	}
	if (write_pattern_file(medium, 131072U) != 0)
		return -1;
	if (write_pattern_file(large, ARK_CHUNK_SIZE * 5U + 17U) != 0)
		return -1;
	return 0;
}

/*
 * create_and_compare_archives - Run create and compare archive bytes.
 */
static int create_and_compare_archives(const char *src_dir, const char *a_path,
                                       int a_workers, const char *b_path,
                                       int b_workers)
{
	ark_error_t err = {0};
	const char *sources[1];
	uint8_t *a_bytes;
	uint8_t *b_bytes;
	size_t a_len;
	size_t b_len;

	a_bytes = NULL;
	b_bytes = NULL;
	a_len = 0U;
	b_len = 0U;
	sources[0] = src_dir;

	/*
	 * ARCHITECTURE.md section 6.3: deterministic in-order drain must yield
	 * byte-identical output regardless of worker completion order.
	 */
	if (ark_test_create_archive(a_path, sources, 1U, a_workers,
	                            ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                            &err) != 0)
		goto fail;
	if (ark_test_create_archive(b_path, sources, 1U, b_workers,
	                            ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                            &err) != 0)
		goto fail;
	if (read_file_bytes(a_path, &a_bytes, &a_len) != 0)
		goto fail;
	if (read_file_bytes(b_path, &b_bytes, &b_len) != 0)
		goto fail;
	if (a_len != b_len)
		goto fail;
	if (memcmp(a_bytes, b_bytes, a_len) != 0)
		goto fail;

	free(b_bytes);
	free(a_bytes);
	return 0;

fail:
	free(b_bytes);
	free(a_bytes);
	return 1;
}

int test_ring_normal_produce_consume(void)
{
	ark_error_t err = {0};
	const uint8_t src[] = {0x10, 0x11, 0x12};
	ring_buf_t *ring;
	uint8_t *in;
	uint8_t *out;
	size_t out_len;
	int is_abort;
	ark_err_t worker_err;

	ring = ring_buf_init(2U, &err);
	if (ring == NULL)
		return 1;
	in = dup_bytes(src, sizeof(src));
	if (in == NULL) {
		ring_buf_free(ring);
		return 1;
	}
	if (ring_buf_write(ring, 0U, in, sizeof(src), ARK_OK, &err) != 0) {
		free(in);
		ring_buf_free(ring);
		return 1;
	}
	free(in);
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(src) ||
	    memcmp(out, src, sizeof(src)) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	ring_buf_free(ring);
	return 0;
}

int test_ring_out_of_order_completion(void)
{
	ark_error_t err = {0};
	const uint8_t s0[] = {0x01};
	const uint8_t s1[] = {0x02, 0x03};
	ring_buf_t *ring;
	uint8_t *in0;
	uint8_t *in1;
	uint8_t *out;
	size_t out_len;
	int is_abort;
	ark_err_t worker_err;

	ring = ring_buf_init(2U, &err);
	if (ring == NULL)
		return 1;
	in0 = dup_bytes(s0, sizeof(s0));
	in1 = dup_bytes(s1, sizeof(s1));
	if (in0 == NULL || in1 == NULL) {
		free(in0);
		free(in1);
		ring_buf_free(ring);
		return 1;
	}
	if (ring_buf_write(ring, 1U, in1, sizeof(s1), ARK_OK, &err) != 0)
		goto fail;
	free(in1);
	in1 = NULL;
	if (ring_buf_write(ring, 0U, in0, sizeof(s0), ARK_OK, &err) != 0)
		goto fail;
	free(in0);
	in0 = NULL;
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(s0) ||
	    memcmp(out, s0, sizeof(s0)) != 0) {
		goto fail;
	}
	if (ring_buf_read(ring, 1U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(s1) ||
	    memcmp(out, s1, sizeof(s1)) != 0) {
		goto fail;
	}
	ring_buf_free(ring);
	return 0;

fail:
	free(in0);
	free(in1);
	ring_buf_free(ring);
	return 1;
}

int test_ring_abort_sentinel_written(void)
{
	ark_error_t err = {0};
	ring_buf_t *ring;
	uint8_t *out;
	size_t out_len;
	int is_abort;
	ark_err_t worker_err;

	ring = ring_buf_init(2U, &err);
	if (ring == NULL)
		return 1;
	if (ring_buf_abort(ring, 0U, ARK_ERR_IO_WRITE, &err) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	if (!is_abort || worker_err != ARK_ERR_IO_WRITE || out != NULL ||
	    out_len != 0U) {
		ring_buf_free(ring);
		return 1;
	}
	ring_buf_free(ring);
	return 0;
}

int test_ring_io_thread_unblocks_on_abort(void)
{
	ark_error_t err = {0};
	struct timespec ts;
	pthread_t tid;
	reader_arg_t arg;
	ring_buf_t *ring;

	ring = ring_buf_init(1U, &err);
	if (ring == NULL)
		return 1;
	arg = (reader_arg_t){0};
	arg.ring = ring;
	arg.seq = 5U;
	if (pthread_create(&tid, NULL, reader_thread, &arg) != 0) {
		ring_buf_free(ring);
		return 1;
	}

	ts.tv_sec = 0;
	ts.tv_nsec = 20000000L;
	(void)nanosleep(&ts, NULL);

	if (ring_buf_abort(ring, 5U, ARK_ERR_FMT_DATA, &err) != 0) {
		(void)pthread_join(tid, NULL);
		ring_buf_free(ring);
		return 1;
	}
	if (pthread_join(tid, NULL) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	if (arg.rc != 0 || !arg.abort || arg.worker_err != ARK_ERR_FMT_DATA ||
	    arg.data != NULL || arg.len != 0U) {
		ring_buf_free(ring);
		return 1;
	}
	ring_buf_free(ring);
	return 0;
}

int test_ring_abort_does_not_block(void)
{
	ark_error_t err = {0};
	ring_buf_t *ring;
	uint8_t *out;
	size_t out_len;
	int is_abort;
	ark_err_t worker_err;

	ring = ring_buf_init(2U, &err);
	if (ring == NULL)
		return 1;
	if (ring_buf_abort(ring, 0U, ARK_ERR_IO_WRITE, &err) != 0)
		goto fail;
	if (ring_buf_abort(ring, 1U, ARK_ERR_FMT_DATA, &err) != 0)
		goto fail;
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (!is_abort || worker_err != ARK_ERR_IO_WRITE || out != NULL ||
	    out_len != 0U)
		goto fail;
	if (ring_buf_read(ring, 1U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (!is_abort || worker_err != ARK_ERR_FMT_DATA || out != NULL ||
	    out_len != 0U)
		goto fail;
	ring_buf_free(ring);
	return 0;

fail:
	ring_buf_free(ring);
	return 1;
}

int test_worker_error_stores_first(void)
{
	ark_error_t err = {0};
	ark_error_t shared;
	ark_pool_t *pool;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;

	pool_inject_worker_error(pool, ARK_ERR_IO_WRITE, EIO);
	shared = pool_get_shared_err(pool);
	if (shared.code != ARK_ERR_IO_WRITE || shared.sys_errno != EIO) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

int test_worker_error_subsequent_discarded(void)
{
	ark_error_t err = {0};
	ark_error_t shared;
	ark_pool_t *pool;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;

	pool_inject_worker_error(pool, ARK_ERR_FMT_DATA, EINVAL);
	pool_inject_worker_error(pool, ARK_ERR_IO_ALLOC, ENOMEM);
	shared = pool_get_shared_err(pool);
	if (shared.code != ARK_ERR_FMT_DATA || shared.sys_errno != EINVAL) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

int test_worker_error_then_sentinel(void)
{
	ark_error_t err = {0};
	ark_error_t shared;
	ark_pool_t *pool;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;

	pool_inject_worker_error(pool, ARK_ERR_IO_WRITE, EIO);
	shared = pool_get_shared_err(pool);
	if (shared.code != ARK_ERR_IO_WRITE ||
	    pool_get_sentinel_count(pool) < 1 ||
	    pool_get_error_event(pool) == 0U ||
	    pool_get_abort_event(pool) == 0U ||
	    pool_get_error_event(pool) >= pool_get_abort_event(pool)) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

#define SHARED_ERR_WRITERS 4
#define SHARED_ERR_ROUNDS 200

typedef struct {
	ark_pool_t *pool;
	int *start;
	ark_error_t err;
} shared_err_writer_t;

/*
 * shared_err_payload - Fill one self-consistent error payload for writer k.
 */
static void shared_err_payload(ark_error_t *e, int k)
{
	*e = (ark_error_t){0};
	e->code = ARK_ERR_FMT_DATA;
	e->sys_errno = 100 + k;
	memset(e->msg, 'a' + k, sizeof(e->msg) - 1U);
	memset(e->path, 'A' + k, sizeof(e->path) - 1U);
}

/*
 * shared_err_writer - Wait for the start flag, then store one error.
 */
static void *shared_err_writer(void *arg)
{
	shared_err_writer_t *w = arg;

	/* Yield while waiting: Valgrind runs one guest thread at a time, and
	 * a pure spin would hold the CPU for a whole scheduling slice. */
	while (__atomic_load_n(w->start, __ATOMIC_ACQUIRE) == 0)
		(void)sched_yield();
	pool_test_store_error(w->pool, &w->err);
	return NULL;
}

/*
 * test_worker_error_published_complete - Concurrent first-error stores while
 * the I/O side polls: any error the reader sees must be one writer's whole
 * payload, never a partly copied one. See ARCHITECTURE.md section 6.3.
 */
int test_worker_error_published_complete(void)
{
	shared_err_writer_t writers[SHARED_ERR_WRITERS];
	pthread_t tids[SHARED_ERR_WRITERS];
	const ark_error_t zero = {0};
	ark_error_t err = {0};
	ark_error_t seen;
	ark_error_t want;
	ark_pool_t *pool;
	int start;
	int round;
	int started;
	int rc;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;
	rc = 0;
	for (round = 0; round < SHARED_ERR_ROUNDS && rc == 0; round++) {
		pool_test_reset_shared_err(pool);
		start = 0;
		for (started = 0; started < SHARED_ERR_WRITERS; started++) {
			writers[started].pool = pool;
			writers[started].start = &start;
			shared_err_payload(&writers[started].err, started);
			if (pthread_create(&tids[started], NULL,
			                   shared_err_writer,
			                   &writers[started]) != 0) {
				rc = 1;
				break;
			}
		}
		__atomic_store_n(&start, 1, __ATOMIC_RELEASE);
		if (rc == 0) {
			int k;

			/* Poll until anything is visible; a snapshot taken
			 * during the copy shows mixed or partly zero bytes. */
			for (;;) {
				seen = pool_get_shared_err(pool);
				if (memcmp(&seen, &zero, sizeof(zero)) != 0)
					break;
				(void)sched_yield();
			}
			k = seen.sys_errno - 100;
			if (k < 0 || k >= SHARED_ERR_WRITERS) {
				rc = 1;
			} else {
				shared_err_payload(&want, k);
				if (memcmp(&seen, &want, sizeof(want)) != 0)
					rc = 1;
			}
		}
		while (started > 0)
			(void)pthread_join(tids[--started], NULL);
	}
	pool_test_shutdown(pool);
	return rc;
}

int test_io_thread_reads_worker_error(void)
{
	ark_error_t err = {0};
	ark_error_t shared;
	ark_pool_t *pool;
	uint8_t *data;
	size_t len;
	int is_abort;
	ark_err_t worker_err;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;

	pool_inject_worker_error(pool, ARK_ERR_FMT_DATA, EILSEQ);
	if (pool_test_read(pool, 0U, &data, &len, &is_abort, &worker_err,
	                   &err) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (!is_abort || worker_err != ARK_ERR_FMT_DATA || data != NULL ||
	    len != 0U) {
		pool_test_shutdown(pool);
		return 1;
	}

	shared = pool_get_shared_err(pool);
	if (shared.code != ARK_ERR_FMT_DATA || shared.sys_errno != EILSEQ) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

int test_worker_error_triggers_cancel(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	uint8_t *data;
	size_t len;
	int is_abort;
	ark_err_t worker_err;

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL)
		return 1;

	pool_inject_worker_error(pool, ARK_ERR_IO_WRITE, EIO);
	if (pool_test_read(pool, 0U, &data, &len, &is_abort, &worker_err,
	                   &err) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (!is_abort || worker_err != ARK_ERR_IO_WRITE) {
		pool_test_shutdown(pool);
		return 1;
	}

	/*
	 * ARCHITECTURE.md section 6.3: I/O thread sets cancellation after
	 * detecting an abort sentinel.
	 */
	pool_test_cancel(pool);
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src)) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

int test_cancel_workers_exit_cleanly(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;

	pool = pool_test_init(2, 0, &err);
	if (pool == NULL)
		return 1;

	if (pool_test_submit(pool, 0U, g_pool_src, sizeof(g_pool_src)) != 0 ||
	    pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src)) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_cancel(pool);
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (pool_test_submit(pool, 2U, g_pool_src, sizeof(g_pool_src)) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_shutdown(pool);
	return 0;
}

int test_cancel_join_completes(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	uint64_t t0;
	uint64_t t1;

	pool = pool_test_init(2, 0, &err);
	if (pool == NULL)
		return 1;

	if (pool_test_submit(pool, 0U, g_pool_src, sizeof(g_pool_src)) != 0 ||
	    pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src)) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}

	t0 = monotonic_ns();
	pool_test_cancel(pool);
	pool_test_shutdown(pool);
	t1 = monotonic_ns();
	if (t0 == 0U || t1 == 0U)
		return 1;
	if (t1 - t0 > 3000000000ULL)
		return 1;
	return 0;
}

/*
 * test_pool_init_create_failure_wakes_workers - Worker creation fails while
 * an earlier worker is between its queue-empty check and its condition wait.
 *
 * The stub hooks hold the started worker in that window until the failing
 * ARK_PTHREAD_CREATE returns, so a cancellation broadcast sent without the
 * pool mutex is lost and pool_init blocks forever in pthread_join.
 * See ARCHITECTURE.md section 6.3.
 */
int test_pool_init_create_failure_wakes_workers(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	int entered;

	fault_inject(ARK_FAULT_PTHREAD_CREATE, 2, EAGAIN);
	__atomic_store_n(&ark_fault.cond_wait_delay_ms, 50, __ATOMIC_RELEASE);
	pool = pool_test_init(2, 0, &err);
	entered =
	    __atomic_load_n(&ark_fault.cond_wait_entered, __ATOMIC_ACQUIRE);
	fault_reset();
	if (pool != NULL) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (err.code != ARK_ERR_IO_ALLOC || err.sys_errno != EAGAIN)
		return 1;
	/* The handshake must have run, or the window was not exercised. */
	return entered == 1 ? 0 : 1;
}

/*
 * test_pool_init_create_failure_cleans_up - Worker creation fails at the
 * first and at a later worker; pool_init must report ARK_ERR_IO_ALLOC and
 * release everything (checked by ASan/Valgrind leak detection).
 */
int test_pool_init_create_failure_cleans_up(void)
{
	static const int fail_on[] = {1, 3};
	size_t i;

	for (i = 0U; i < sizeof(fail_on) / sizeof(fail_on[0]); i++) {
		ark_error_t err;
		ark_pool_t *pool;

		err = (ark_error_t){0};
		fault_inject(ARK_FAULT_PTHREAD_CREATE, fail_on[i], EAGAIN);
		pool = pool_test_init(4, 0, &err);
		fault_reset();
		if (pool != NULL) {
			pool_test_shutdown(pool);
			return 1;
		}
		if (err.code != ARK_ERR_IO_ALLOC || err.sys_errno != EAGAIN)
			return 1;
	}
	return 0;
}

/*
 * test_ring_init_sync_failure_cleans_up - Ring mutex or condition
 * initialisation fails after every slot payload is allocated; ring_buf_init
 * must report ARK_ERR_IO_ALLOC and free the payloads (checked by ASan and
 * Valgrind leak detection).
 */
int test_ring_init_sync_failure_cleans_up(void)
{
	static const int which[] = {ARK_FAULT_PTHREAD_MUTEX_INIT,
	                            ARK_FAULT_PTHREAD_COND_INIT};
	size_t i;

	for (i = 0U; i < sizeof(which) / sizeof(which[0]); i++) {
		ark_error_t err;
		ring_buf_t *ring;

		err = (ark_error_t){0};
		fault_inject(which[i], 1, EAGAIN);
		ring = ring_buf_init(4U, &err);
		fault_reset();
		if (ring != NULL) {
			ring_buf_free(ring);
			return 1;
		}
		if (err.code != ARK_ERR_IO_ALLOC || err.sys_errno != EAGAIN)
			return 1;
	}
	return 0;
}

/*
 * test_pool_init_sync_failure_cleans_up - Every mutex and condition
 * initialisation in pool_init (pool and ring) fails in turn; pool_init must
 * report ARK_ERR_IO_ALLOC and release everything.
 */
int test_pool_init_sync_failure_cleans_up(void)
{
	static const struct {
		int which;
		int fail_on;
	} cases[] = {
	    {ARK_FAULT_PTHREAD_MUTEX_INIT, 1}, /* pool->mutex */
	    {ARK_FAULT_PTHREAD_COND_INIT, 1},  /* pool->cv_not_empty */
	    {ARK_FAULT_PTHREAD_COND_INIT, 2},  /* pool->cv_not_full */
	    {ARK_FAULT_PTHREAD_MUTEX_INIT, 2}, /* ring->mutex */
	    {ARK_FAULT_PTHREAD_COND_INIT, 3},  /* ring->cond */
	};
	size_t i;

	for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ark_error_t err;
		ark_pool_t *pool;

		err = (ark_error_t){0};
		fault_inject(cases[i].which, cases[i].fail_on, EAGAIN);
		pool = pool_test_init(2, 0, &err);
		fault_reset();
		if (pool != NULL) {
			pool_test_shutdown(pool);
			return 1;
		}
		if (err.code != ARK_ERR_IO_ALLOC || err.sys_errno != EAGAIN)
			return 1;
	}
	return 0;
}

int test_quiescence_sequence_order(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	char root[] = "/tmp/ark-thread-quiet-XXXXXX";
	char cleanup_file[1024];
	const char *tmp;
	uint8_t *data;
	size_t len;
	int fd;
	int is_abort;
	ark_err_t worker_err;

	tmp = mkdtemp(root);
	if (tmp == NULL)
		return 1;
	if (path_join(cleanup_file, sizeof(cleanup_file), tmp,
	              "created-output") != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	fd = open(cleanup_file, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd == -1) {
		(void)remove_tree(tmp);
		return 1;
	}

	pool = pool_test_init(1, 0, &err);
	if (pool == NULL) {
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}

	pool_inject_worker_error(pool, ARK_ERR_IO_WRITE, EIO);
	if (pool_test_read(pool, 0U, &data, &len, &is_abort, &worker_err,
	                   &err) != 0) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}
	if (!is_abort) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}

	/*
	 * SAFETY: test the complete quiescence order from ARCHITECTURE.md
	 * section 14.3: cancel, stop submit, join, close fd, cleanup. The
	 * order is fixed by the call sequence below; each step is checked as
	 * it happens.
	 */
	pool_test_cancel(pool);
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}
	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src)) == 0) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}
	pool_test_shutdown(pool);
	if (close(fd) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	if (unlink(cleanup_file) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	if (remove_tree(tmp) != 0)
		return 1;
	return 0;
}

int test_no_resource_leak_on_cancel(void)
{
	int i;

	for (i = 0; i < 32; i++) {
		ark_error_t err = {0};
		ark_pool_t *pool;

		pool = pool_test_init(1, 0, &err);
		if (pool == NULL)
			return 1;
		pool_test_cancel(pool);
		pool_test_shutdown(pool);
	}
	return 0;
}

int test_no_cleanup_race(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	uint8_t *data;
	size_t len;
	int is_abort;
	ark_err_t worker_err;

	pool = pool_test_init(2, 0, &err);
	if (pool == NULL)
		return 1;

	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src)) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	pool_inject_worker_error(pool, ARK_ERR_IO_WRITE, EIO);
	if (pool_test_read(pool, 0U, &data, &len, &is_abort, &worker_err,
	                   &err) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (!is_abort || worker_err != ARK_ERR_IO_WRITE) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_cancel(pool);
	pool_test_shutdown(pool);
	return 0;
}

int test_create_deterministic_single_worker(void)
{
	char root[] = "/tmp/ark-thread-det-XXXXXX";
	char src[1024];
	char out_a[1024];
	char out_b[1024];
	const char *tmp;
	int rc;

	tmp = mkdtemp(root);
	if (tmp == NULL)
		return 1;
	if (prepare_source_tree(tmp, src, sizeof(src)) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	if (path_join(out_a, sizeof(out_a), tmp, "single-a.ark") != 0 ||
	    path_join(out_b, sizeof(out_b), tmp, "single-b.ark") != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	rc = create_and_compare_archives(src, out_a, 1, out_b, 1);
	if (remove_tree(tmp) != 0)
		return 1;
	return rc;
}

int test_create_deterministic_multi_worker_matches_single(void)
{
	char root[] = "/tmp/ark-thread-det-XXXXXX";
	char src[1024];
	char out_single[1024];
	char out_parallel[1024];
	const char *tmp;
	int rc;

	tmp = mkdtemp(root);
	if (tmp == NULL)
		return 1;
	if (prepare_source_tree(tmp, src, sizeof(src)) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	if (path_join(out_single, sizeof(out_single), tmp, "single.ark") != 0 ||
	    path_join(out_parallel, sizeof(out_parallel), tmp,
	              "parallel.ark") != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	rc = create_and_compare_archives(src, out_single, 1, out_parallel, 4);
	if (remove_tree(tmp) != 0)
		return 1;
	return rc;
}

/*
 * write_seeded_file - Write total bytes of compressible data that differ per
 * seed, so a chunk written for the wrong member changes the archive.
 */
static int write_seeded_file(const char *path, size_t total, uint32_t seed)
{
	uint8_t block[4096];
	uint32_t x;
	size_t done;
	int fd;

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0)
		return -1;
	x = seed * 2654435761U + 1U;
	done = 0U;
	while (done < total) {
		size_t n;
		size_t i;

		n = total - done < sizeof(block) ? total - done : sizeof(block);
		for (i = 0U; i < n; i++) {
			x = x * 1103515245U + 12345U;
			block[i] = (uint8_t)('a' + ((x >> 16) & 7U));
		}
		if (write_full_fd(fd, block, n) != 0) {
			(void)close(fd);
			return -1;
		}
		done += n;
	}
	return close(fd);
}

/*
 * pipeline_file_size - Size of c.dir/fNNN in the pipeline tree: mostly small,
 * some empty, every 50th two chunks long.
 */
static size_t pipeline_file_size(unsigned int i)
{
	if (i % 50U == 7U)
		return ARK_CHUNK_SIZE + 1U + i;
	if (i % 17U == 0U)
		return 0U;
	return (size_t)((i * 977U) % 6000U) + 1U;
}

/*
 * prepare_pipeline_tree - Source tree for the cross-file create pipeline.
 *
 * Traversal order: a.big (four chunks), 150 symlinks b000-b149 queued behind
 * its chunks (more than the pending queue holds), c.dir with 200 files of
 * mixed sizes, d.link (hardlink to c.dir/f001) and the empty e.empty.
 */
static int prepare_pipeline_tree(const char *root, char *src_dir, size_t src_sz)
{
	char path[1024];
	char name[64];
	unsigned int i;

	if (path_join(src_dir, src_sz, root, "src") != 0 ||
	    mkdir(src_dir, 0755) != 0)
		return -1;
	if (path_join(path, sizeof(path), src_dir, "a.big") != 0 ||
	    write_seeded_file(path, ARK_CHUNK_SIZE * 3U + 5U, 1000U) != 0)
		return -1;
	for (i = 0U; i < 150U; i++) {
		(void)snprintf(name, sizeof(name), "b%03u", i);
		if (path_join(path, sizeof(path), src_dir, name) != 0 ||
		    symlink("a.big", path) != 0)
			return -1;
	}
	if (path_join(path, sizeof(path), src_dir, "c.dir") != 0 ||
	    mkdir(path, 0755) != 0)
		return -1;
	for (i = 0U; i < 200U; i++) {
		(void)snprintf(name, sizeof(name), "c.dir/f%03u", i);
		if (path_join(path, sizeof(path), src_dir, name) != 0 ||
		    write_seeded_file(path, pipeline_file_size(i), i) != 0)
			return -1;
	}
	{
		char target[1024];

		if (path_join(target, sizeof(target), src_dir, "c.dir/f001") !=
		        0 ||
		    path_join(path, sizeof(path), src_dir, "d.link") != 0 ||
		    link(target, path) != 0)
			return -1;
	}
	if (path_join(path, sizeof(path), src_dir, "e.empty") != 0 ||
	    write_seeded_file(path, 0U, 0U) != 0)
		return -1;
	return 0;
}

/*
 * same_file_bytes - Whether two regular files have identical contents.
 */
static int same_file_bytes(const char *a, const char *b)
{
	uint8_t *a_bytes = NULL;
	uint8_t *b_bytes = NULL;
	size_t a_len = 0U;
	size_t b_len = 0U;
	int same;

	same = read_file_bytes(a, &a_bytes, &a_len) == 0 &&
	       read_file_bytes(b, &b_bytes, &b_len) == 0 && a_len == b_len &&
	       (a_len == 0U || memcmp(a_bytes, b_bytes, a_len) == 0);
	free(a_bytes);
	free(b_bytes);
	return same;
}

/*
 * check_pipeline_extract - Extract archive into out and compare it with src.
 */
static int check_pipeline_extract(const char *archive, const char *src,
                                  const char *out)
{
	ark_error_t err = {0};
	char a[1024];
	char b[1024];
	char name[64];
	char link_buf[64];
	struct stat st_a;
	struct stat st_b;
	unsigned int i;

	if (mkdir(out, 0755) != 0 ||
	    ark_test_extract_archive(archive, out, 0, NULL, 2, &err) != 0)
		return -1;
	if (path_join(a, sizeof(a), src, "a.big") != 0 ||
	    path_join(b, sizeof(b), out, "a.big") != 0 ||
	    !same_file_bytes(a, b))
		return -1;
	for (i = 0U; i < 150U; i++) {
		ssize_t n;

		(void)snprintf(name, sizeof(name), "b%03u", i);
		if (path_join(b, sizeof(b), out, name) != 0)
			return -1;
		n = readlink(b, link_buf, sizeof(link_buf));
		if (n != 5 || memcmp(link_buf, "a.big", 5U) != 0)
			return -1;
	}
	for (i = 0U; i < 200U; i++) {
		(void)snprintf(name, sizeof(name), "c.dir/f%03u", i);
		if (path_join(a, sizeof(a), src, name) != 0 ||
		    path_join(b, sizeof(b), out, name) != 0 ||
		    !same_file_bytes(a, b))
			return -1;
	}
	if (path_join(a, sizeof(a), out, "c.dir/f001") != 0 ||
	    path_join(b, sizeof(b), out, "d.link") != 0 ||
	    stat(a, &st_a) != 0 || stat(b, &st_b) != 0 ||
	    st_a.st_ino != st_b.st_ino)
		return -1;
	if (path_join(b, sizeof(b), out, "e.empty") != 0 ||
	    stat(b, &st_b) != 0 || !S_ISREG(st_b.st_mode) || st_b.st_size != 0)
		return -1;
	return 0;
}

/*
 * only_entry_is_src - Whether root holds nothing but "src" (no archive and no
 * temporary file after a failed create).
 */
static int only_entry_is_src(const char *root)
{
	DIR *dir;
	const struct dirent *de;
	int ok = 1;

	dir = opendir(root);
	if (dir == NULL)
		return 0;
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0 &&
		    strcmp(de->d_name, "src") != 0)
			ok = 0;
	}
	(void)closedir(dir);
	return ok;
}

int test_create_pipeline_matches_across_workers(void)
{
	char root[] = "/tmp/ark-thread-pipe-XXXXXX";
	static const int workers[] = {2, 3, 4, 16};
	char src[1024];
	char out_one[1024];
	char out_n[1024];
	char out_dir[1024];
	const char *tmp;
	size_t i;
	int rc = 1;

	tmp = mkdtemp(root);
	if (tmp == NULL)
		return 1;
	if (prepare_pipeline_tree(tmp, src, sizeof(src)) != 0 ||
	    path_join(out_one, sizeof(out_one), tmp, "one.ark") != 0 ||
	    path_join(out_n, sizeof(out_n), tmp, "n.ark") != 0 ||
	    path_join(out_dir, sizeof(out_dir), tmp, "out") != 0)
		goto done;
	/*
	 * ARCHITECTURE.md section 6.3: chunks of many files are in flight at
	 * once and still written in traversal order, so every worker count
	 * gives the bytes of the single-worker archive.
	 */
	for (i = 0U; i < sizeof(workers) / sizeof(workers[0]); i++) {
		if (create_and_compare_archives(src, out_one, 1, out_n,
		                                workers[i]) != 0)
			goto done;
	}
	if (check_pipeline_extract(out_one, src, out_dir) != 0)
		goto done;
	rc = 0;

done:
	if (remove_tree(tmp) != 0)
		return 1;
	return rc;
}

/*
 * expect_pipeline_fault - Fail one create of the pipeline tree.
 *
 * kind >= 1000 selects a command fault (kind - 1000), otherwise a syscall
 * fault. The create must fail with code and EIO-style errno, leaving neither
 * an archive nor a temporary file.
 */
static int expect_pipeline_fault(int kind, int fail_on, int n_workers,
                                 ark_err_t code, int errno_value)
{
	char root[] = "/tmp/ark-thread-pipe-XXXXXX";
	char src[1024];
	char archive[1024];
	const char *sources[1];
	const char *tmp;
	ark_error_t err = {0};
	int rc = 1;

	tmp = mkdtemp(root);
	if (tmp == NULL)
		return 1;
	if (prepare_pipeline_tree(tmp, src, sizeof(src)) != 0 ||
	    path_join(archive, sizeof(archive), tmp, "fail.ark") != 0)
		goto done;
	sources[0] = src;
	fault_reset();
	ark_test_cli_fault_reset();
	if (kind >= 1000)
		ark_test_cli_fault_inject(kind - 1000, fail_on, code,
		                          errno_value);
	else
		fault_inject(kind, fail_on, errno_value);
	if (ark_test_create_archive(archive, sources, 1U, n_workers,
	                            ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                            &err) == 0)
		goto done;
	if (err.code != code || err.sys_errno != errno_value)
		goto done;
	if (!only_entry_is_src(tmp))
		goto done;
	rc = 0;

done:
	fault_reset();
	ark_test_cli_fault_reset();
	if (remove_tree(tmp) != 0)
		return 1;
	return rc;
}

int test_create_pipeline_read_fault(void)
{
	/* Read 30 is in c.dir, with chunks of earlier files in flight. */
	return expect_pipeline_fault(ARK_FAULT_READ, 30, 4, ARK_ERR_IO_READ,
	                             EIO);
}

int test_create_pipeline_write_fault(void)
{
	/* Archive write 1 is the header; 40 is a chunk of a c.dir file. */
	return expect_pipeline_fault(1000 + ARK_CLI_FAULT_CREATE_WRITE_ARCHIVE,
	                             40, 4, ARK_ERR_IO_WRITE, EIO);
}

int test_create_pipeline_worker_fault(void)
{
	/* Chunk 3 is in a.big (symlinks queued behind it); chunk 60 is in
	 * c.dir. */
	if (expect_pipeline_fault(1000 + ARK_CLI_FAULT_CREATE_WORKER, 3, 1,
	                          ARK_ERR_IO_ALLOC, ENOMEM) != 0)
		return 1;
	return expect_pipeline_fault(1000 + ARK_CLI_FAULT_CREATE_WORKER, 60, 4,
	                             ARK_ERR_IO_ALLOC, ENOMEM);
}
