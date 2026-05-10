/*
 * test_thread.c - Thread pool and ring buffer tests for Phase 6.6.
 *
 * Exercises ARCHITECTURE.md sections 6.3 and 14.3 behavior required by
 * TESTING.md section 4.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "archive.h"

typedef struct ring_buf ring_buf_t;
typedef struct ark_pool ark_pool_t;

ring_buf_t *ring_buf_init(size_t, ark_error_t *);
int ring_buf_write(ring_buf_t *, uint64_t, uint8_t *, size_t, ark_err_t,
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
void pool_inject_worker_error(ark_pool_t *, ark_err_t, int);

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
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0) {
		ring_buf_free(ring);
		return 1;
	}
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(src) ||
	    memcmp(out, src, sizeof(src)) != 0) {
		free(out);
		ring_buf_free(ring);
		return 1;
	}
	free(out);
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
	if (ring_buf_write(ring, 0U, in0, sizeof(s0), ARK_OK, &err) != 0)
		goto fail;
	if (ring_buf_read(ring, 0U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(s0) ||
	    memcmp(out, s0, sizeof(s0)) != 0) {
		free(out);
		goto fail;
	}
	free(out);
	if (ring_buf_read(ring, 1U, &out, &out_len, &is_abort, &worker_err,
	                  &err) != 0)
		goto fail;
	if (is_abort || worker_err != ARK_OK || out_len != sizeof(s1) ||
	    memcmp(out, s1, sizeof(s1)) != 0) {
		free(out);
		goto fail;
	}
	free(out);
	ring_buf_free(ring);
	return 0;

fail:
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
		free(out);
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
		free(arg.data);
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
	    pool_get_sentinel_count(pool) < 1) {
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
		free(data);
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
		free(data);
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
	if (!is_abort) {
		pool_test_shutdown(pool);
		return 1;
	}

	/*
	 * SAFETY: test the thread-pool quiescence prefix order from
	 * ARCHITECTURE.md section 14.3: cancel first, then join via shutdown.
	 */
	pool_test_cancel(pool);
	if (pool_get_cancel_flag(pool) == 0) {
		pool_test_shutdown(pool);
		return 1;
	}
	pool_test_shutdown(pool);
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
