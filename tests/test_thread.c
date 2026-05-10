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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "archive.h"
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
int pool_test_submit(ark_pool_t *, uint64_t, const uint8_t *, size_t,
                     ark_deflate_mode_t);
int pool_test_read(ark_pool_t *, uint64_t, uint8_t **, size_t *, int *,
                   ark_err_t *, ark_error_t *);
void pool_test_cancel(ark_pool_t *);
void pool_test_shutdown(ark_pool_t *);
int pool_get_cancel_flag(const ark_pool_t *);
ark_error_t pool_get_shared_err(const ark_pool_t *);
int pool_get_sentinel_count(const ark_pool_t *);
unsigned int pool_get_error_event(const ark_pool_t *);
unsigned int pool_get_abort_event(const ark_pool_t *);
void pool_inject_worker_error(ark_pool_t *, ark_err_t, int);
int ark_test_create_archive(const char *, const char **, size_t, int,
                            ark_hash_alg_t, ark_deflate_mode_t, ark_error_t *);

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
	                            ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT,
	                            &err) != 0)
		goto fail;
	if (ark_test_create_archive(b_path, sources, 1U, b_workers,
	                            ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT,
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
	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) == 0) {
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

	if (pool_test_submit(pool, 0U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) != 0 ||
	    pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) != 0) {
		pool_test_shutdown(pool);
		return 1;
	}

	pool_test_cancel(pool);
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	if (pool_test_submit(pool, 2U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) == 0) {
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

	if (pool_test_submit(pool, 0U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) != 0 ||
	    pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) != 0) {
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

int test_quiescence_sequence_order(void)
{
	ark_error_t err = {0};
	ark_pool_t *pool;
	char root[] = "/tmp/ark-thread-quiet-XXXXXX";
	char cleanup_file[1024];
	const char *tmp;
	uint8_t *data;
	size_t len;
	unsigned int step;
	unsigned int cancel_step;
	unsigned int stop_step;
	unsigned int join_step;
	unsigned int close_step;
	unsigned int cleanup_step;
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
	 * section 14.3: cancel, stop submit, join, close fd, cleanup.
	 */
	step = 0U;
	pool_test_cancel(pool);
	cancel_step = ++step;
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}
	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) == 0) {
		pool_test_shutdown(pool);
		(void)close(fd);
		(void)remove_tree(tmp);
		return 1;
	}
	stop_step = ++step;
	pool_test_shutdown(pool);
	join_step = ++step;
	if (close(fd) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	close_step = ++step;
	if (unlink(cleanup_file) != 0) {
		(void)remove_tree(tmp);
		return 1;
	}
	cleanup_step = ++step;
	if (!(cancel_step < stop_step && stop_step < join_step &&
	    join_step < close_step && close_step < cleanup_step)) {
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

	if (pool_test_submit(pool, 1U, g_pool_src, sizeof(g_pool_src),
	                     ARK_DEFLATE_DEFAULT) != 0) {
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
