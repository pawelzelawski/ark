/*
 * main.c - CLI entry point, argument parsing, and create traversal.
 *
 * This file implements subcommand parsing, sandbox setup, and create-side
 * filesystem traversal for ark.
 *
 * See ARCHITECTURE.md sections 12 and 13 for CLI and traversal contract
 * details.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "archive.h"
#include "ark_internal.h"
#include "chevron.h"
#include "recovery_template_data.h"

#ifdef __linux__
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

extern long syscall(long, ...);
#endif

#ifdef __OpenBSD__
extern int pledge(const char *, const char *);
extern int unveil(const char *, const char *);
extern int sysctl(int *, unsigned int, void *, size_t *, const void *, size_t);

/* OpenBSD sysctl namespace constants (sys/sysctl.h):
 * CTL_HW = 6, HW_NCPU = 3. */
enum {
	ARK_CTL_HW = 6,
	ARK_HW_NCPU = 3,
};
#endif

#define ARK_MAX_WORKERS 16

typedef enum {
	ARK_CMD_NONE = 0,
	ARK_CMD_CREATE,
	ARK_CMD_EXTRACT,
	ARK_CMD_LIST,
	ARK_CMD_VERIFY,
	ARK_CMD_GENERATE_READER,
} ark_cmd_t;

typedef struct {
	ark_cmd_t cmd;
	ark_hash_alg_t hash_alg;
	ark_deflate_mode_t deflate_mode;
	int overwrite;
	int verbose;
	int human;
	const char *output_path;
	const char *archive_path;
	const char *generate_reader_output;

	const char **member_paths;
	size_t member_count;

	const char **create_paths;
	size_t create_path_count;
} ark_args_t;

typedef struct {
	dev_t dev;
	ino_t ino;
	char path[1024];
} inode_slot_t;

typedef struct {
	inode_slot_t *slots;
	size_t capacity;
	size_t count;
} inode_table_t;

typedef struct {
	char **names;
	size_t count;
	size_t capacity;
} dir_entry_list_t;

typedef struct {
	char **paths;
	size_t count;
	size_t capacity;
} modified_path_list_t;

typedef struct {
	char path[1024];
	int is_dir;
} cleanup_entry_t;

typedef struct {
	cleanup_entry_t *entries;
	size_t count;
	size_t capacity;
} cleanup_tracker_t;

typedef struct {
	const ark_member_meta_t **items;
	size_t count;
	size_t capacity;
} dir_deferred_meta_t;

typedef struct ark_pool ark_pool_t;
typedef struct ark_worker_arg ark_worker_arg_t;

typedef struct {
	char root[PATH_MAX];
	dev_t root_dev;
	ark_write_ctx_t *write_ctx;
	chevron_handle_t *chev_handle;
	ark_pool_t *pool;
	ark_deflate_mode_t deflate_mode;
	modified_path_list_t *modified_paths;
	inode_table_t inodes;
	uint8_t *input_buf;
	uint8_t *comp_buf;
	uint8_t *write_buf;
	size_t comp_cap;
	uint64_t *output_offset;
	int permission_error;
} traverse_ctx_t;

typedef struct ring_buf ring_buf_t;

typedef enum {
	ARK_POOL_COMPRESS = 0,
	ARK_POOL_DECOMPRESS,
} ark_pool_mode_t;

typedef struct {
	_Atomic int recorded;
	ark_error_t error;
} ark_shared_err_t;

typedef struct {
	uint64_t seq;
	uint8_t *data;
	size_t len;
	size_t cap;
	int ready;
	int abort;
	ark_err_t worker_err;
} ring_slot_t;

typedef struct {
	uint64_t seq;
	uint8_t *src;
	size_t src_len;
	uint8_t *dst;
	size_t dst_cap;
	ark_deflate_mode_t mode;
} pool_work_t;

typedef struct {
	uint8_t *src;
	size_t cap;
} pool_queue_slot_t;

struct ark_worker_arg {
	ark_pool_t *pool;
	uint8_t *src;
	uint8_t *dst;
	size_t src_cap;
	size_t dst_cap;
};

struct ring_buf {
	size_t n_slots;
	ring_slot_t *slots;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct ark_pool {
	int n_workers;
	ark_pool_mode_t mode;
	pthread_t *workers;
	ark_worker_arg_t *worker_args;
	pool_queue_slot_t *queue_slots;
	pool_work_t *queue;
	size_t q_cap;
	size_t q_head;
	size_t q_tail;
	size_t q_count;
	pthread_mutex_t mutex;
	pthread_cond_t cv_not_empty;
	pthread_cond_t cv_not_full;
	_Atomic int cancelled;
	ring_buf_t *ring;
	ark_shared_err_t shared_err;
#ifdef ARK_TEST
	_Atomic unsigned int event_seq;
	_Atomic unsigned int error_event;
	_Atomic unsigned int abort_event;
#endif
};

ring_buf_t *ring_buf_init(size_t, ark_error_t *);
int ring_buf_write(ring_buf_t *, uint64_t, const uint8_t *, size_t, ark_err_t,
                   ark_error_t *);
int ring_buf_abort(ring_buf_t *, uint64_t, ark_err_t, ark_error_t *);
int ring_buf_read(ring_buf_t *, uint64_t, uint8_t **, size_t *, int *,
                  ark_err_t *, ark_error_t *);
static void ring_buf_release(ring_buf_t *, uint64_t);
void ring_buf_free(ring_buf_t *);
static void error_store_once(ark_shared_err_t *, const ark_error_t *);
static ark_pool_t *pool_init(int, ark_pool_mode_t, ark_error_t *);
static int pool_submit(ark_pool_t *, uint64_t, const uint8_t *, size_t,
                       ark_deflate_mode_t);
static void pool_shutdown(ark_pool_t *);

static void *worker_compress(void *);
static void *worker_decompress(void *);

static int fail_error(ark_error_t *, ark_err_t, const char *, const char *,
                      int);

/*
 * ring_buf_init - Allocate a fixed-size ring buffer for worker results.
 *
 * n_slots must be greater than zero and typically matches worker count.
 *
 * Returns a new ring buffer pointer on success, NULL on error.
 * Failure details are reported through err when err is non-NULL.
 *
 * OWNERSHIP: the returned ring pointer is owned by the caller and must be
 * released with ring_buf_free.
 */
ring_buf_t *ring_buf_init(size_t n_slots, ark_error_t *err)
{
	ring_buf_t *ring;
	size_t i;
	int rc;

	if (n_slots == 0U) {
		(void)fail_error(
		    err, ARK_ERR_USAGE,
		    "ring buffer slot count must be greater than zero", "", 0);
		return NULL;
	}

	/* OWNERSHIP: ring is released by ring_buf_free. */
	ring = (ring_buf_t *)calloc(1U, sizeof(*ring));
	if (ring == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "ring buffer allocation failed", "", 0);
		return NULL;
	}
	/* OWNERSHIP: ring->slots is owned by ring and released by
	 * ring_buf_free. */
	ring->slots = (ring_slot_t *)calloc(n_slots, sizeof(ring->slots[0]));
	if (ring->slots == NULL) {
		free(ring);
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "ring slot allocation failed", "", 0);
		return NULL;
	}
	ring->n_slots = n_slots;
	for (i = 0U; i < n_slots; i++) {
		ring->slots[i].cap = ark_deflate_bound(ARK_CHUNK_SIZE);
		/* OWNERSHIP: each ring slot owns one fixed payload buffer until
		 * ring_buf_free. */
		ring->slots[i].data = malloc(ring->slots[i].cap);
		if (ring->slots[i].data == NULL) {
			while (i > 0U)
				free(ring->slots[--i].data);
			free(ring->slots);
			free(ring);
			(void)fail_error(err, ARK_ERR_IO_ALLOC,
			                 "ring payload allocation failed", "",
			                 0);
			return NULL;
		}
		ring->slots[i].seq = UINT64_MAX;
	}

	rc = pthread_mutex_init(&ring->mutex, NULL);
	if (rc != 0) {
		free(ring->slots);
		free(ring);
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "ring mutex initialisation failed", "", rc);
		return NULL;
	}
	rc = pthread_cond_init(&ring->cond, NULL);
	if (rc != 0) {
		(void)pthread_mutex_destroy(&ring->mutex);
		free(ring->slots);
		free(ring);
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "ring condition initialisation failed", "",
		                 rc);
		return NULL;
	}

	return ring;
}

/*
 * ring_buf_write - Publish one completed worker result into the ring buffer.
 *
 * The caller's data bytes are copied into a preallocated ring slot buffer.
 * The I/O thread receives a borrowed pointer via ring_buf_read and must call
 * ring_buf_release after consuming the slot.
 *
 * Returns 0 on success, -1 on error.
 * Fails with ARK_ERR_USAGE on invalid arguments or duplicate sequence publish.
 *
 * Preconditions: seq is unique for each published chunk and data is non-NULL
 * when len is non-zero.
 */
int ring_buf_write(ring_buf_t *ring, uint64_t seq, const uint8_t *data,
                   size_t len, ark_err_t worker_err, ark_error_t *err)
{
	ring_slot_t *slot;
	size_t idx;
	size_t i;
	int rc;

	if (ring == NULL)
		return fail_error(err, ARK_ERR_USAGE, "ring buffer is null", "",
		                  0);
	if (len > 0U && data == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "ring write data is null for non-zero length",
		                  "", 0);

	idx = (size_t)(seq % ring->n_slots);
	slot = &ring->slots[idx];

	rc = pthread_mutex_lock(&ring->mutex);
	if (rc != 0)
		return fail_error(err, ARK_ERR_USAGE, "ring mutex lock failed",
		                  "", rc);
	while (slot->ready && slot->seq != seq) {
		rc = pthread_cond_wait(&ring->cond, &ring->mutex);
		if (rc != 0) {
			(void)pthread_mutex_unlock(&ring->mutex);
			return fail_error(err, ARK_ERR_USAGE,
			                  "ring condition wait failed", "", rc);
		}
	}
	if (slot->ready && slot->seq == seq) {
		(void)pthread_mutex_unlock(&ring->mutex);
		return fail_error(err, ARK_ERR_USAGE,
		                  "ring sequence already published", "", 0);
	}
	if (len > slot->cap) {
		(void)pthread_mutex_unlock(&ring->mutex);
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "ring slot capacity exceeded", "", 0);
	}

	/*
	 * SAFETY: ring slots are reused modulo n_slots. Writers must not
	 * overwrite a still-owned slot for another sequence; waiting here
	 * preserves strict in-order drain semantics from ARCHITECTURE.md
	 * section 6.3.
	 */
	slot->seq = seq;
	for (i = 0U; i < len; i++)
		slot->data[i] = data[i];
	slot->len = len;
	slot->abort = 0;
	slot->worker_err = worker_err;
	slot->ready = 1;
	(void)pthread_cond_broadcast(&ring->cond);
	(void)pthread_mutex_unlock(&ring->mutex);
	return 0;
}

/*
 * ring_buf_abort - Publish an abort sentinel for one sequence slot.
 *
 * Returns 0 on success, -1 on error.
 * Fails with ARK_ERR_USAGE on invalid arguments or duplicate sequence publish.
 */
int ring_buf_abort(ring_buf_t *ring, uint64_t seq, ark_err_t worker_err,
                   ark_error_t *err)
{
	ring_slot_t *slot;
	size_t idx;
	int rc;

	if (ring == NULL)
		return fail_error(err, ARK_ERR_USAGE, "ring buffer is null", "",
		                  0);

	idx = (size_t)(seq % ring->n_slots);
	slot = &ring->slots[idx];

	rc = pthread_mutex_lock(&ring->mutex);
	if (rc != 0)
		return fail_error(err, ARK_ERR_USAGE, "ring mutex lock failed",
		                  "", rc);
	while (slot->ready && slot->seq != seq) {
		rc = pthread_cond_wait(&ring->cond, &ring->mutex);
		if (rc != 0) {
			(void)pthread_mutex_unlock(&ring->mutex);
			return fail_error(err, ARK_ERR_USAGE,
			                  "ring condition wait failed", "", rc);
		}
	}
	if (slot->ready && slot->seq == seq) {
		(void)pthread_mutex_unlock(&ring->mutex);
		return fail_error(err, ARK_ERR_USAGE,
		                  "ring sequence already published", "", 0);
	}

	/*
	 * SAFETY: worker error paths must publish abort before worker exit to
	 * unblock the I/O thread waiting on this sequence slot. See
	 * ARCHITECTURE.md section 6.3.
	 */
	slot->seq = seq;
	slot->len = 0U;
	slot->abort = 1;
	slot->worker_err = worker_err;
	slot->ready = 1;
	(void)pthread_cond_broadcast(&ring->cond);
	(void)pthread_mutex_unlock(&ring->mutex);
	return 0;
}

/*
 * ring_buf_read - Wait for and consume one expected sequence slot.
 *
 * On success, data/len/abort/worker_err are populated for seq. data is a
 * borrowed pointer into the ring slot and remains valid until ring_buf_release.
 *
 * Returns 0 on success, -1 on error.
 * Fails with ARK_ERR_USAGE on invalid arguments or synchronisation failures.
 */
int ring_buf_read(ring_buf_t *ring, uint64_t seq, uint8_t **data, size_t *len,
                  int *abort, ark_err_t *worker_err, ark_error_t *err)
{
	ring_slot_t *slot;
	size_t idx;
	int rc;

	if (ring == NULL || data == NULL || len == NULL || abort == NULL ||
	    worker_err == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "ring read argument is null", "", 0);

	idx = (size_t)(seq % ring->n_slots);
	slot = &ring->slots[idx];

	rc = pthread_mutex_lock(&ring->mutex);
	if (rc != 0)
		return fail_error(err, ARK_ERR_USAGE, "ring mutex lock failed",
		                  "", rc);
	while (!slot->ready || slot->seq != seq) {
		rc = pthread_cond_wait(&ring->cond, &ring->mutex);
		if (rc != 0) {
			(void)pthread_mutex_unlock(&ring->mutex);
			return fail_error(err, ARK_ERR_USAGE,
			                  "ring condition wait failed", "", rc);
		}
	}

	*data = slot->abort ? NULL : slot->data;
	*len = slot->len;
	*abort = slot->abort;
	*worker_err = slot->worker_err;
	(void)pthread_mutex_unlock(&ring->mutex);
	return 0;
}

static void ring_buf_release(ring_buf_t *ring, uint64_t seq)
{
	ring_slot_t *slot;
	size_t idx;

	if (ring == NULL)
		return;
	idx = (size_t)(seq % ring->n_slots);
	slot = &ring->slots[idx];
	if (pthread_mutex_lock(&ring->mutex) != 0)
		return;
	if (slot->ready && slot->seq == seq) {
		/* SAFETY: release occurs only after the I/O thread consumes the
		 * borrowed slot payload, allowing modulo slot reuse without
		 * racing a writer. See ARCHITECTURE.md section 6.3. */
		slot->len = 0U;
		slot->abort = 0;
		slot->worker_err = ARK_OK;
		slot->seq = UINT64_MAX;
		slot->ready = 0;
		(void)pthread_cond_broadcast(&ring->cond);
	}
	(void)pthread_mutex_unlock(&ring->mutex);
}

/*
 * ring_buf_free - Release a ring buffer and any still-owned slot payloads.
 */
void ring_buf_free(ring_buf_t *ring)
{
	size_t i;

	if (ring == NULL)
		return;
	for (i = 0U; i < ring->n_slots; i++)
		free(ring->slots[i].data);
	(void)pthread_cond_destroy(&ring->cond);
	(void)pthread_mutex_destroy(&ring->mutex);
	free(ring->slots);
	free(ring);
}

/*
 * error_store_once - Store the first worker error in shared state.
 *
 * Uses compare-and-swap so only the first worker publishes an error copy;
 * subsequent worker failures are intentionally discarded.
 *
 * Returns void. Invalid arguments are ignored.
 *
 * See ARCHITECTURE.md section 6.3 and CODING_STANDARDS.md section 5.3.
 */
static void error_store_once(ark_shared_err_t *shared, const ark_error_t *err)
{
	int expected;

	if (shared == NULL || err == NULL)
		return;

	expected = 0;
	/* NOTE: use compiler atomics directly so this path does not depend on
	 * <stdatomic.h> header availability across toolchains; cast to int *
	 * matches __atomic_compare_exchange_n argument requirements. */
	if (!__atomic_compare_exchange_n((int *)&shared->recorded, &expected, 1,
	                                 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;

	/*
	 * SAFETY: only the compare-and-swap winner writes shared->error.
	 * This preserves first-error-wins semantics for worker-to-I/O error
	 * propagation from ARCHITECTURE.md section 6.3.
	 */
	shared->error = *err;
}

/*
 * pool_init - Allocate and initialise a worker pool bound to one mode.
 *
 * mode selects a fixed worker routine for the lifetime of the pool:
 * compress pools run worker_compress, decompress pools run
 * worker_decompress. Mixing modes in one pool is intentionally unsupported.
 *
 * Returns a new pool on success, NULL on failure.
 *
 * OWNERSHIP: returned pool is owned by the caller and must be released with
 * pool_shutdown.
 *
 * See ARCHITECTURE.md section 6.3.
 */
static ark_pool_t *pool_init(int n_workers, ark_pool_mode_t mode,
                             ark_error_t *err)
{
	ark_pool_t *pool;
	void *(*entry)(void *);
	int i;
	int rc;

	if (n_workers <= 0)
		return NULL;
	if (mode != ARK_POOL_COMPRESS && mode != ARK_POOL_DECOMPRESS)
		return NULL;

	/* OWNERSHIP: pool is released only by pool_shutdown. */
	pool = (ark_pool_t *)calloc(1U, sizeof(*pool));
	if (pool == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool allocation failed", "", 0);
		return NULL;
	}
	pool->n_workers = n_workers;
	pool->mode = mode;
	pool->q_cap = (size_t)n_workers;

	/* OWNERSHIP: pool->workers is released by pool_shutdown. */
	pool->workers =
	    (pthread_t *)calloc((size_t)n_workers, sizeof(pool->workers[0]));
	if (pool->workers == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool worker array allocation failed",
		                 "", 0);
		free(pool);
		return NULL;
	}
	pool->worker_args = (ark_worker_arg_t *)calloc(
	    (size_t)n_workers, sizeof(pool->worker_args[0]));
	if (pool->worker_args == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool worker arg allocation failed", "",
		                 0);
		free(pool->workers);
		free(pool);
		return NULL;
	}
	for (i = 0; i < n_workers; i++) {
		pool->worker_args[i].pool = pool;
		pool->worker_args[i].src_cap = ARK_CHUNK_SIZE;
		pool->worker_args[i].dst_cap =
		    ark_deflate_bound(ARK_CHUNK_SIZE);
		pool->worker_args[i].src = malloc(ARK_CHUNK_SIZE);
		pool->worker_args[i].dst = malloc(pool->worker_args[i].dst_cap);
		if (pool->worker_args[i].src == NULL ||
		    pool->worker_args[i].dst == NULL) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
			while (i > 0) {
				i--;
				free(pool->worker_args[i].src);
				free(pool->worker_args[i].dst);
			}
			free(pool->worker_args);
			free(pool->workers);
			free(pool);
			(void)fail_error(
			    err, ARK_ERR_IO_ALLOC,
			    "thread pool worker buffer allocation failed", "",
			    0);
			return NULL;
		}
	}
	/* OWNERSHIP: pool->queue_slots and their buffers are owned by pool
	 * until pool_shutdown. */
	pool->queue_slots = (pool_queue_slot_t *)calloc(
	    (size_t)n_workers, sizeof(pool->queue_slots[0]));
	if (pool->queue_slots == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool queue slot allocation failed", "",
		                 0);
		for (i = 0; i < n_workers; i++) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}
	for (i = 0; i < n_workers; i++) {
		pool->queue_slots[i].cap = ARK_CHUNK_SIZE;
		pool->queue_slots[i].src = malloc(ARK_CHUNK_SIZE);
		if (pool->queue_slots[i].src == NULL) {
			free(pool->queue_slots[i].src);
			while (i > 0) {
				i--;
				free(pool->queue_slots[i].src);
			}
			free(pool->queue_slots);
			for (i = 0; i < n_workers; i++) {
				free(pool->worker_args[i].src);
				free(pool->worker_args[i].dst);
			}
			free(pool->worker_args);
			free(pool->workers);
			free(pool);
			(void)fail_error(
			    err, ARK_ERR_IO_ALLOC,
			    "thread pool queue buffer allocation failed", "",
			    0);
			return NULL;
		}
	}
	/* OWNERSHIP: pool->queue descriptors are owned by pool until shutdown.
	 */
	pool->queue =
	    (pool_work_t *)calloc((size_t)n_workers, sizeof(pool->queue[0]));
	if (pool->queue == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool queue allocation failed", "", 0);
		for (i = 0; i < n_workers; i++) {
			free(pool->queue_slots[i].src);
		}
		free(pool->queue_slots);
		for (i = 0; i < n_workers; i++) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}

	rc = pthread_mutex_init(&pool->mutex, NULL);
	if (rc != 0) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "thread pool mutex initialisation failed", "",
		                 rc);
		free(pool->queue);
		for (i = 0; i < n_workers; i++) {
			free(pool->queue_slots[i].src);
		}
		free(pool->queue_slots);
		for (i = 0; i < n_workers; i++) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}
	rc = pthread_cond_init(&pool->cv_not_empty, NULL);
	if (rc != 0) {
		(void)fail_error(
		    err, ARK_ERR_IO_ALLOC,
		    "thread pool queue condition initialisation failed", "",
		    rc);
		(void)pthread_mutex_destroy(&pool->mutex);
		free(pool->queue);
		for (i = 0; i < n_workers; i++) {
			free(pool->queue_slots[i].src);
		}
		free(pool->queue_slots);
		for (i = 0; i < n_workers; i++) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}
	rc = pthread_cond_init(&pool->cv_not_full, NULL);
	if (rc != 0) {
		(void)fail_error(
		    err, ARK_ERR_IO_ALLOC,
		    "thread pool queue condition initialisation failed", "",
		    rc);
		(void)pthread_cond_destroy(&pool->cv_not_empty);
		(void)pthread_mutex_destroy(&pool->mutex);
		free(pool->queue);
		for (i = 0; i < n_workers; i++) {
			free(pool->queue_slots[i].src);
		}
		free(pool->queue_slots);
		for (i = 0; i < n_workers; i++) {
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}

	/*
	 * ARCHITECTURE.md section 6.3 requires a fixed-size result ring with
	 * one slot per worker.
	 */
	pool->ring = ring_buf_init((size_t)n_workers, err);
	if (pool->ring == NULL) {
		(void)pthread_cond_destroy(&pool->cv_not_full);
		(void)pthread_cond_destroy(&pool->cv_not_empty);
		(void)pthread_mutex_destroy(&pool->mutex);
		free(pool->queue);
		for (i = 0; i < n_workers; i++) {
			free(pool->queue_slots[i].src);
			free(pool->worker_args[i].src);
			free(pool->worker_args[i].dst);
		}
		free(pool->queue_slots);
		free(pool->worker_args);
		free(pool->workers);
		free(pool);
		return NULL;
	}
	pool->shared_err.recorded = 0;

	entry = mode == ARK_POOL_COMPRESS ? worker_compress : worker_decompress;
	for (i = 0; i < n_workers; i++) {
		rc = pthread_create(&pool->workers[i], NULL, entry,
		                    &pool->worker_args[i]);
		if (rc != 0) {
			(void)fail_error(err, ARK_ERR_IO_ALLOC,
			                 "thread pool worker creation failed",
			                 "", rc);
			__atomic_store_n((int *)&pool->cancelled, 1,
			                 __ATOMIC_RELEASE);
			(void)pthread_cond_broadcast(&pool->cv_not_empty);
			while (--i >= 0)
				(void)pthread_join(pool->workers[i], NULL);
			ring_buf_free(pool->ring);
			(void)pthread_cond_destroy(&pool->cv_not_full);
			(void)pthread_cond_destroy(&pool->cv_not_empty);
			(void)pthread_mutex_destroy(&pool->mutex);
			free(pool->queue);
			for (i = 0; i < n_workers; i++) {
				free(pool->queue_slots[i].src);
				free(pool->worker_args[i].src);
				free(pool->worker_args[i].dst);
			}
			free(pool->queue_slots);
			free(pool->worker_args);
			free(pool->workers);
			free(pool);
			return NULL;
		}
	}

	return pool;
}

/*
 * pool_submit - Enqueue one chunk for processing by a mode-bound worker pool.
 *
 * Blocks while the queue is full. Returns -1 if cancellation is active.
 *
 * pool_submit copies src bytes into a preallocated queue slot. No allocation
 * occurs on the per-chunk hot path.
 */
static int pool_submit(ark_pool_t *pool, uint64_t seq, const uint8_t *src,
                       size_t src_len, ark_deflate_mode_t mode)
{
	pool_queue_slot_t *qslot;
	int rc;

	if (pool == NULL)
		return -1;
	if (src_len > 0U && src == NULL)
		return -1;
	if (src_len > ARK_CHUNK_SIZE)
		return -1;
	if (__atomic_load_n((int *)&pool->cancelled, __ATOMIC_ACQUIRE) != 0)
		return -1;

	rc = pthread_mutex_lock(&pool->mutex);
	if (rc != 0)
		return -1;
	while (pool->q_count == pool->q_cap &&
	       __atomic_load_n((int *)&pool->cancelled, __ATOMIC_ACQUIRE) ==
	           0) {
		rc = pthread_cond_wait(&pool->cv_not_full, &pool->mutex);
		if (rc != 0) {
			(void)pthread_mutex_unlock(&pool->mutex);
			return -1;
		}
	}
	if (__atomic_load_n((int *)&pool->cancelled, __ATOMIC_ACQUIRE) != 0) {
		(void)pthread_mutex_unlock(&pool->mutex);
		return -1;
	}

	qslot = &pool->queue_slots[pool->q_tail];
	if (src_len > qslot->cap) {
		(void)pthread_mutex_unlock(&pool->mutex);
		return -1;
	}
	for (size_t i = 0U; i < src_len; i++)
		qslot->src[i] = src[i];
	pool->queue[pool->q_tail] = (pool_work_t){
	    .seq = seq,
	    .src = qslot->src,
	    .src_len = src_len,
	    .mode = mode,
	};
	pool->q_tail = (pool->q_tail + 1U) % pool->q_cap;
	pool->q_count++;
	(void)pthread_cond_signal(&pool->cv_not_empty);
	(void)pthread_mutex_unlock(&pool->mutex);
	return 0;
}

/*
 * pool_shutdown - Cancel all workers, join, and release all pool resources.
 *
 * See ARCHITECTURE.md section 6.3 for cancellation and worker lifetime rules.
 */
static void pool_shutdown(ark_pool_t *pool)
{
	int i;

	if (pool == NULL)
		return;

	__atomic_store_n((int *)&pool->cancelled, 1, __ATOMIC_RELEASE);
	if (pthread_mutex_lock(&pool->mutex) == 0) {
		(void)pthread_cond_broadcast(&pool->cv_not_empty);
		(void)pthread_cond_broadcast(&pool->cv_not_full);
		(void)pthread_mutex_unlock(&pool->mutex);
	}

	for (i = 0; i < pool->n_workers; i++)
		(void)pthread_join(pool->workers[i], NULL);

	ring_buf_free(pool->ring);
	(void)pthread_cond_destroy(&pool->cv_not_full);
	(void)pthread_cond_destroy(&pool->cv_not_empty);
	(void)pthread_mutex_destroy(&pool->mutex);
	free(pool->queue);
	for (i = 0; i < pool->n_workers; i++) {
		free(pool->queue_slots[i].src);
		free(pool->worker_args[i].src);
		free(pool->worker_args[i].dst);
	}
	free(pool->queue_slots);
	free(pool->worker_args);
	free(pool->workers);
	free(pool);
}

/*
 * worker_compress - Worker thread loop for compress-mode pools.
 *
 * Each dequeued input chunk is compressed with ark_deflate_compress and
 * published to the ring buffer slot identified by seq.
 *
 * See ARCHITECTURE.md section 6.3 and CODING_STANDARDS.md section 5.1.
 */
static void *worker_compress(void *arg)
{
	ark_worker_arg_t *warg;
	ark_pool_t *pool;

	warg = (ark_worker_arg_t *)arg;
	if (warg == NULL || warg->pool == NULL)
		return NULL;
	pool = warg->pool;

	for (;;) {
		pool_work_t work;
		int rc;

		if (__atomic_load_n((int *)&pool->cancelled,
		                    __ATOMIC_ACQUIRE) != 0)
			break;

		rc = pthread_mutex_lock(&pool->mutex);
		if (rc != 0)
			break;
		while (pool->q_count == 0U &&
		       __atomic_load_n((int *)&pool->cancelled,
		                       __ATOMIC_ACQUIRE) == 0) {
			rc = pthread_cond_wait(&pool->cv_not_empty,
			                       &pool->mutex);
			if (rc != 0)
				break;
		}
		if (rc != 0 || (pool->q_count == 0U &&
		                __atomic_load_n((int *)&pool->cancelled,
		                                __ATOMIC_ACQUIRE) != 0)) {
			(void)pthread_mutex_unlock(&pool->mutex);
			break;
		}

		work = pool->queue[pool->q_head];
		if (work.src_len > warg->src_cap) {
			(void)pthread_mutex_unlock(&pool->mutex);
			break;
		}
		for (size_t i = 0U; i < work.src_len; i++)
			warg->src[i] = work.src[i];
		work.src = warg->src;
		work.dst = warg->dst;
		work.dst_cap = warg->dst_cap;
		pool->queue[pool->q_head] = (pool_work_t){0};
		pool->q_head = (pool->q_head + 1U) % pool->q_cap;
		pool->q_count--;
		(void)pthread_cond_signal(&pool->cv_not_full);
		(void)pthread_mutex_unlock(&pool->mutex);

		if (__atomic_load_n((int *)&pool->cancelled,
		                    __ATOMIC_ACQUIRE) != 0) {
			break;
		}

		size_t out_cap;
		uint8_t *out;
		ssize_t out_len;

		out_cap = ark_deflate_bound(work.src_len);
		out = work.dst;
		if (out == NULL || out_cap > work.dst_cap) {
			ark_error_t local_err = {0};

			(void)fail_error(&local_err, ARK_ERR_IO_ALLOC,
			                 "worker output buffer unavailable", "",
			                 0);
			error_store_once(&pool->shared_err, &local_err);
			(void)ring_buf_abort(pool->ring, work.seq,
			                     ARK_ERR_IO_ALLOC, NULL);
			break;
		}

		out_len = ark_deflate_compress(work.src, work.src_len, out,
		                               work.dst_cap, work.mode);
		if (out_len < 0) {
			/* SAFETY: publish abort before worker exit. See
			 * ARCHITECTURE.md section 6.3. */
			(void)ring_buf_abort(pool->ring, work.seq, ARK_OK,
			                     NULL);
			break;
		}

		if (ring_buf_write(pool->ring, work.seq, out, (size_t)out_len,
		                   ARK_OK, NULL) != 0) {
			ark_error_t local_err = {0};

			(void)fail_error(&local_err, ARK_ERR_IO_WRITE,
			                 "worker ring publish failed", "", 0);
			error_store_once(&pool->shared_err, &local_err);
			(void)ring_buf_abort(pool->ring, work.seq,
			                     ARK_ERR_IO_WRITE, NULL);
			break;
		}
	}

	return NULL;
}

/*
 * worker_decompress - Worker thread loop for decompress-mode pools.
 *
 * Each dequeued compressed chunk is decompressed with
 * ark_deflate_decompress and published to the ring buffer slot identified by
 * seq.
 *
 * See ARCHITECTURE.md section 6.3 and CODING_STANDARDS.md section 5.1.
 */
static void *worker_decompress(void *arg)
{
	ark_worker_arg_t *warg;
	ark_pool_t *pool;

	warg = (ark_worker_arg_t *)arg;
	if (warg == NULL || warg->pool == NULL)
		return NULL;
	pool = warg->pool;

	for (;;) {
		pool_work_t work;
		uint8_t *out;
		ssize_t out_len;
		int rc;

		if (__atomic_load_n((int *)&pool->cancelled,
		                    __ATOMIC_ACQUIRE) != 0)
			break;

		rc = pthread_mutex_lock(&pool->mutex);
		if (rc != 0)
			break;
		while (pool->q_count == 0U &&
		       __atomic_load_n((int *)&pool->cancelled,
		                       __ATOMIC_ACQUIRE) == 0) {
			rc = pthread_cond_wait(&pool->cv_not_empty,
			                       &pool->mutex);
			if (rc != 0)
				break;
		}
		if (rc != 0 || (pool->q_count == 0U &&
		                __atomic_load_n((int *)&pool->cancelled,
		                                __ATOMIC_ACQUIRE) != 0)) {
			(void)pthread_mutex_unlock(&pool->mutex);
			break;
		}

		work = pool->queue[pool->q_head];
		if (work.src_len > warg->src_cap) {
			(void)pthread_mutex_unlock(&pool->mutex);
			break;
		}
		for (size_t i = 0U; i < work.src_len; i++)
			warg->src[i] = work.src[i];
		work.src = warg->src;
		work.dst = warg->dst;
		pool->queue[pool->q_head] = (pool_work_t){0};
		pool->q_head = (pool->q_head + 1U) % pool->q_cap;
		pool->q_count--;
		(void)pthread_cond_signal(&pool->cv_not_full);
		(void)pthread_mutex_unlock(&pool->mutex);

		if (__atomic_load_n((int *)&pool->cancelled,
		                    __ATOMIC_ACQUIRE) != 0) {
			break;
		}

		out = work.dst;

		out_len = ark_deflate_decompress(work.src, work.src_len, out,
		                                 ARK_CHUNK_SIZE);
		if (out_len < 0) {
			/* SAFETY: publish abort before worker exit. See
			 * ARCHITECTURE.md section 6.3. */
			(void)ring_buf_abort(pool->ring, work.seq, ARK_OK,
			                     NULL);
			break;
		}

		if (ring_buf_write(pool->ring, work.seq, out, (size_t)out_len,
		                   ARK_OK, NULL) != 0) {
			ark_error_t local_err = {0};

			(void)fail_error(&local_err, ARK_ERR_IO_WRITE,
			                 "worker ring publish failed", "", 0);
			error_store_once(&pool->shared_err, &local_err);
			(void)ring_buf_abort(pool->ring, work.seq,
			                     ARK_ERR_IO_WRITE, NULL);
			break;
		}
	}

	return NULL;
}

static int parse_args(int, char **, ark_args_t *, ark_error_t *);
static void args_init(ark_args_t *);
static void args_free(ark_args_t *);
static int default_worker_count(void);
static int usage_error(ark_error_t *, const char *);
static int parse_subcommand(const char *, ark_cmd_t *, ark_error_t *);
static int parse_hash(const char *, ark_hash_alg_t *, ark_error_t *);
static int push_member(ark_args_t *, const char *, int, ark_error_t *);
static void print_usage(const char *);
static void copy_msg(char *, size_t, const char *);
static int parent_dir(const char *, char *, size_t, ark_error_t *);
static int cmd_create(const ark_args_t *, ark_pool_t *, ark_error_t *);
static int cmd_extract(const ark_args_t *, int, ark_pool_t *, ark_error_t *);
static int cmd_list(const ark_args_t *, ark_error_t *);
static int cmd_verify(const ark_args_t *, ark_error_t *);
static int cmd_generate_reader(const ark_args_t *, ark_error_t *);
static int traverse_dir(const char *, ark_write_ctx_t *, chevron_handle_t *,
                        ark_pool_t *, ark_deflate_mode_t, uint64_t *,
                        modified_path_list_t *, ark_error_t *);
static int traverse_entry(traverse_ctx_t *, const char *, const char *,
                          ark_error_t *);
static int traverse_directory_abs(traverse_ctx_t *, const char *, const char *,
                                  ark_error_t *);
static int emit_regular_file(traverse_ctx_t *, const char *, const char *,
                             const struct stat *, ark_error_t *);
static int emit_nonfile_member(traverse_ctx_t *, const ark_member_meta_t *,
                               ark_error_t *);
static int chevron_write_or_fail(chevron_handle_t *, const void *, size_t,
                                 const char *, ark_error_t *);
static int emit_symlink_member(traverse_ctx_t *, const char *, const char *,
                               const struct stat *, ark_error_t *);
static int inode_table_init(inode_table_t *, ark_error_t *);
static void inode_table_free(inode_table_t *);
static const char *inode_table_lookup(const inode_table_t *, dev_t, ino_t);
static int inode_table_insert(inode_table_t *, dev_t, ino_t, const char *,
                              ark_error_t *);
static int sandbox_apply(ark_cmd_t, const char **, int, const char *,
                         const char *, ark_error_t *);
static int modified_path_list_push(modified_path_list_t *, const char *,
                                   ark_error_t *);
static void modified_path_list_free(modified_path_list_t *);
static void print_modified_summary(const modified_path_list_t *);
static int create_validate_destination_outside_sources(const char *,
                                                       const char **, size_t,
                                                       ark_error_t *);
static int create_serialize_index(ark_write_ctx_t *, uint8_t **, size_t *,
                                  ark_error_t *);
static int create_serialize_footer(ark_write_ctx_t *, uint64_t, uint64_t,
                                   uint8_t **, size_t *, ark_error_t *);
static int chevron_error_fail(ark_error_t *, const chevron_error_t *,
                              const char *, const char *);
static int exit_code_from_err(ark_err_t);
static int read_full(int, void *, size_t, const char *, ark_error_t *);
static int write_full(int, const void *, size_t, const char *, ark_error_t *);
static uint64_t le64_decode(const uint8_t *);
static int read_archive_index(int, const char *, ark_read_ctx_t *, uint8_t **,
                              size_t *, ark_error_t *);
static size_t read_member_count(const ark_read_ctx_t *);
static int find_member_pos(const ark_read_ctx_t *, const char *, uint32_t *);
static int build_extract_selection(const ark_args_t *, const ark_read_ctx_t *,
                                   size_t, unsigned char *, ark_error_t *);
static int preflight_conflicts(const ark_args_t *, const ark_read_ctx_t *,
                               size_t, const unsigned char *, int,
                               ark_error_t *);
static int cleanup_track(cleanup_tracker_t *, const char *, int, ark_error_t *);
static void cleanup_run(cleanup_tracker_t *, int);
static void cleanup_free(cleanup_tracker_t *);
static int dir_deferred_push(dir_deferred_meta_t *, const ark_member_meta_t *,
                             ark_error_t *);
static void dir_deferred_free(dir_deferred_meta_t *);
static int ensure_parent_dirs(const ark_member_meta_t *, int, int,
                              cleanup_tracker_t *, ark_error_t *);
static void decode_mtime(uint64_t, struct timespec[2]);
static int restore_regular_meta(int, const ark_member_meta_t *, ark_error_t *);
static void restore_symlink_meta(int, const ark_member_meta_t *);
static void apply_deferred_dir_meta(int, const dir_deferred_meta_t *);
static void print_error(const ark_error_t *);
static void print_warning(const char *, const char *);
static int print_member(const ark_member_meta_t *, int, int);
static void format_u64_dec(uint64_t, char *, size_t);
static void format_size_human(uint64_t, char *, size_t);
static void format_mtime_human(uint64_t, char *, size_t);

#ifdef ARK_TEST
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
#endif

#ifdef __linux__
static uint64_t landlock_read_rights(void);
static uint64_t landlock_create_rights(int);
static uint64_t landlock_extract_rights(int);
static int landlock_detect_abi(ark_error_t *);
static int landlock_add_path_rule(int, const char *, uint64_t, ark_error_t *);
#endif

/*
 * modified_path_list_push - Append one modified-source path.
 */
static int modified_path_list_push(modified_path_list_t *list, const char *path,
                                   ark_error_t *err)
{
	char *copy;
	char **new_paths;
	size_t len;

	if (list == NULL || path == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "invalid modified-path tracking argument", "",
		                  0);
	if (list->count == list->capacity) {
		size_t new_cap;

		new_cap = list->capacity == 0U ? 32U : list->capacity * 2U;
		/* OWNERSHIP: list owns paths and frees them in
		 * modified_path_list_free. */
		new_paths = (char **)realloc((void *)list->paths,
		                             new_cap * sizeof(list->paths[0]));
		if (new_paths == NULL)
			return fail_error(
			    err, ARK_ERR_IO_ALLOC,
			    "modified-path list allocation failed", "", 0);
		list->paths = new_paths;
		list->capacity = new_cap;
	}
	len = strlen(path);
	/* OWNERSHIP: list entry copy is owned by list and freed at cleanup. */
	copy = (char *)calloc(len + 1U, 1U);
	if (copy == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "modified-path copy allocation failed", "",
		                  0);
	copy_msg(copy, len + 1U, path);
	list->paths[list->count++] = copy;
	return 0;
}

/*
 * modified_path_list_free - Release all source-modification path entries.
 */
static void modified_path_list_free(modified_path_list_t *list)
{
	size_t i;

	for (i = 0U; i < list->count; i++)
		free(list->paths[i]);
	free((void *)list->paths);
	list->paths = NULL;
	list->count = 0U;
	list->capacity = 0U;
}

/*
 * print_modified_summary - Emit post-traversal modified-source summary.
 *
 * ARCHITECTURE.md section 13.4 requires immediate warnings and an end-of-run
 * summary of all affected paths.
 */
static void print_modified_summary(const modified_path_list_t *list)
{
	size_t i;

	syslog(LOG_ERR, "source files modified during archiving");
	(void)fputs("ark: source files modified during archiving:\n", stderr);
	for (i = 0U; i < list->count; i++) {
		syslog(LOG_ERR, "%s", list->paths[i]);
		(void)fputs("ark:   ", stderr);
		(void)fputs(list->paths[i], stderr);
		(void)fputc('\n', stderr);
	}
}

/*
 * create_path_contains - Return 1 when child is equal to or under root.
 */
static int create_path_contains(const char *root, const char *child)
{
	size_t rlen;

	if (strcmp(root, "/") == 0)
		return 1;
	rlen = strlen(root);
	if (strncmp(root, child, rlen) != 0)
		return 0;
	if (child[rlen] == '\0' || child[rlen] == '/')
		return 1;
	return 0;
}

/*
 * create_validate_destination_outside_sources - Enforce create precondition.
 *
 * ARCHITECTURE.md section 13.5 requires destination parent realpath to be
 * outside every source root before libchevron setup and traversal.
 */
static int create_validate_destination_outside_sources(const char *archive_path,
                                                       const char **sources,
                                                       size_t source_count,
                                                       ark_error_t *err)
{
	char parent_raw[PATH_MAX];
	char dst_parent[PATH_MAX];
	char src_root[PATH_MAX];
	size_t i;

	if (archive_path == NULL || sources == NULL || source_count == 0U)
		return fail_error(err, ARK_ERR_USAGE,
		                  "create destination/source paths missing", "",
		                  0);
	if (parent_dir(archive_path, parent_raw, sizeof(parent_raw), err) != 0)
		return -1;
	if (ARK_REALPATH(parent_raw, dst_parent) == NULL)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "destination parent path resolution failed",
		                  parent_raw, errno);
	for (i = 0U; i < source_count; i++) {
		if (ARK_REALPATH(sources[i], src_root) == NULL)
			return fail_error(err, ARK_ERR_IO_READ,
			                  "source path resolution failed",
			                  sources[i], errno);
		if (create_path_contains(src_root, dst_parent))
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "destination archive path is inside source tree",
			    archive_path, 0);
	}
	return 0;
}

/*
 * default_worker_count - Derive default pool width from host CPU count.
 *
 * Linux uses sysconf(_SC_NPROCESSORS_ONLN). OpenBSD uses sysctl hw.ncpu.
 * Result is clamped to [1, ARK_MAX_WORKERS] and is not user-configurable.
 * See DEVELOPMENT.md task 6.4.
 */
static int default_worker_count(void)
{
	long ncpu;

#ifdef __linux__
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 1;
#elif defined(__OpenBSD__)
	int mib[2];
	int value;
	size_t vlen;

	mib[0] = ARK_CTL_HW;
	mib[1] = ARK_HW_NCPU;
	value = 1;
	vlen = sizeof(value);
	ncpu = 1;
	/*
	 * OpenBSD worker-count source required by DEVELOPMENT.md task 6.4:
	 * query "hw.ncpu" from the sysctl namespace.
	 */
	if (sysctl(mib, 2U, &value, &vlen, NULL, 0) == 0 &&
	    vlen == sizeof(value) && value > 0)
		ncpu = value;
#else
	ncpu = 1;
#endif

	if (ncpu > ARK_MAX_WORKERS)
		ncpu = ARK_MAX_WORKERS;
	return (int)ncpu;
}

/*
 * create_serialize_index - Allocate and serialize the index block.
 *
 * OWNERSHIP: on success *out_buf transfers to caller and is freed by
 * cmd_create cleanup.
 */
static int create_serialize_index(ark_write_ctx_t *ctx, uint8_t **out_buf,
                                  size_t *out_len, ark_error_t *err)
{
	uint8_t *buf;
	size_t cap;

	cap = 4096U;
	for (;;) {
		ssize_t n;

		/* OWNERSHIP: temporary buffer is freed here on retry/failure.
		 */
		buf = (uint8_t *)malloc(cap);
		if (buf == NULL)
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "index buffer allocation failed", "",
			                  0);
		n = ark_write_index(ctx, buf, cap, err);
		if (n >= 0) {
			*out_buf = buf;
			*out_len = (size_t)n;
			return 0;
		}
		if (err == NULL || err->code != ARK_ERR_IO_ALLOC) {
			free(buf);
			return -1;
		}
		free(buf);
		if (cap > (SIZE_MAX / 2U))
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "index buffer size overflow", "", 0);
		cap *= 2U;
	}
}

/*
 * create_serialize_footer - Allocate and serialize the fixed footer.
 *
 * OWNERSHIP: on success *out_buf transfers to caller and is freed by
 * cmd_create cleanup.
 */
static int create_serialize_footer(ark_write_ctx_t *ctx, uint64_t index_offset,
                                   uint64_t index_size, uint8_t **out_buf,
                                   size_t *out_len, ark_error_t *err)
{
	uint8_t *buf;
	ssize_t n;

	/* OWNERSHIP: footer buffer is freed by cmd_create cleanup. */
	buf = (uint8_t *)malloc(64U);
	if (buf == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "footer buffer allocation failed", "", 0);
	n = ark_write_footer(ctx, index_offset, index_size, buf, 64U, err);
	if (n < 0) {
		free(buf);
		return -1;
	}
	*out_buf = buf;
	*out_len = (size_t)n;
	return 0;
}

/*
 * chevron_error_fail - Map libchevron failure class into ark_error_t.
 *
 * Mapping follows ARCHITECTURE.md section 11.3.
 */
static int chevron_error_fail(ark_error_t *err, const chevron_error_t *cerr,
                              const char *msg, const char *path)
{
	ark_err_t code;

	switch (cerr->err) {
	case CHEVRON_ERR_OPEN:
		code = ARK_ERR_IO_OPEN;
		break;
	case CHEVRON_ERR_WRITE:
		code = ARK_ERR_IO_WRITE;
		break;
	case CHEVRON_ERR_FSYNC:
		code = ARK_ERR_IO_FSYNC;
		break;
	case CHEVRON_ERR_CLOSE:
		code = ARK_ERR_IO_WRITE;
		break;
	case CHEVRON_ERR_RENAME:
		code = ARK_ERR_IO_COMMIT;
		break;
	case CHEVRON_ERR_PERMISSION:
		code = ARK_ERR_IO_OPEN;
		break;
	case CHEVRON_ERR_INVALID:
		code = ARK_ERR_USAGE;
		break;
	case CHEVRON_ERR_NONE:
	default:
		code = ARK_ERR_IO_WRITE;
		break;
	}
	return fail_error(err, code, msg, path, cerr->errno_value);
}

/*
 * cmd_create - Execute archive creation with worker-pool compression.
 *
 * Runs the write sequence from ARCHITECTURE.md section 16.3, streams bytes
 * through libchevron per section 9, enforces destination preconditions per
 * section 13.5, and performs source-modification checks per section 13.4.
 * Parallel chunk compression and in-order I/O drain follow section 6.3.
 */
static int cmd_create(const ark_args_t *args, ark_pool_t *pool,
                      ark_error_t *err)
{
	ark_write_ctx_storage_t wstorage = {0};
	ark_write_ctx_t *wctx;
	chevron_handle_t handle = CHEVRON_HANDLE_INIT;
	chevron_error_t cerr = {0};
	modified_path_list_t modified = {0};
	uint8_t header[16];
	uint8_t *index_buf = NULL;
	uint8_t *footer_buf = NULL;
	size_t index_len;
	size_t footer_len;
	ssize_t n;
	uint64_t output_offset;
	uint64_t index_offset;
	int opened;
	int rc;
	size_t i;

	if (args == NULL || pool == NULL || args->archive_path == NULL ||
	    args->create_path_count == 0U)
		return fail_error(err, ARK_ERR_USAGE,
		                  "create requires worker pool, archive path, "
		                  "and source paths",
		                  "", 0);

	if (create_validate_destination_outside_sources(
	        args->archive_path, args->create_paths, args->create_path_count,
	        err) != 0)
		return -1;

	wctx = (ark_write_ctx_t *)wstorage.bytes;
	opened = 0;
	rc = -1;
	output_offset = 0U;

	if (ark_write_init(wctx, args->hash_alg, args->deflate_mode, err) != 0)
		goto cleanup;

	if (chevron_open(&handle, args->archive_path, CHEVRON_FULL,
	                 CHEVRON_MODE_DEFAULT, &cerr) != 0) {
		rc = chevron_error_fail(err, &cerr, "archive open failed",
		                        args->archive_path);
		goto cleanup;
	}
	opened = 1;

	n = ark_write_header(wctx, header, sizeof(header), err);
	if (n < 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, header, (size_t)n,
	                          args->archive_path, err) != 0)
		goto cleanup;
	output_offset = (uint64_t)n;

	for (i = 0U; i < args->create_path_count; i++) {
		if (traverse_dir(args->create_paths[i], wctx, &handle, pool,
		                 args->deflate_mode, &output_offset, &modified,
		                 err) != 0)
			goto cleanup;
	}

	if (modified.count > 0U) {
		print_modified_summary(&modified);
		(void)fail_error(err, ARK_ERR_MODIFIED,
		                 "source files modified during archiving", "",
		                 0);
		goto cleanup;
	}

	index_offset = output_offset;
	if (create_serialize_index(wctx, &index_buf, &index_len, err) != 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, index_buf, index_len,
	                          args->archive_path, err) != 0)
		goto cleanup;
	if (UINT64_MAX - output_offset < (uint64_t)index_len) {
		(void)fail_error(err, ARK_ERR_USAGE, "archive offset overflow",
		                 args->archive_path, 0);
		goto cleanup;
	}
	output_offset += (uint64_t)index_len;

	if (create_serialize_footer(wctx, index_offset, (uint64_t)index_len,
	                            &footer_buf, &footer_len, err) != 0)
		goto cleanup;
	if (chevron_write_or_fail(&handle, footer_buf, footer_len,
	                          args->archive_path, err) != 0)
		goto cleanup;

	/*
	 * SAFETY: commit occurs only after successful header, member data,
	 * index, and footer writes; all error paths abort the handle before
	 * returning. See ARCHITECTURE.md sections 9 and 16.3.
	 */
	if (chevron_commit(&handle, &cerr) != 0) {
		rc = chevron_error_fail(err, &cerr, "archive commit failed",
		                        args->archive_path);
		opened = 0;
		goto cleanup;
	}
	opened = 0;
	rc = 0;

cleanup:
	/*
	 * SAFETY: quiesce workers before archive handle teardown so no worker
	 * can race output finalisation on failure paths. See ARCHITECTURE.md
	 * sections 6.3 and 14.3.
	 */
	pool_shutdown(pool);
	if (rc != 0 && opened)
		chevron_abort(&handle);
	free(footer_buf);
	free(index_buf);
	modified_path_list_free(&modified);
	ark_write_free(wctx);
	return rc;
}

/*
 * read_full - Read exactly len bytes unless EOF or a hard read error occurs.
 */
static int read_full(int fd, void *buf, size_t len, const char *path,
                     ark_error_t *err)
{
	uint8_t *p;

	p = (uint8_t *)buf;
	while (len > 0U) {
		ssize_t n;

		n = ARK_READ(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return fail_error(err, ARK_ERR_IO_READ,
			                  "archive read failed", path, errno);
		}
		if (n == 0)
			return fail_error(err, ARK_ERR_FMT_TRUNCATED,
			                  "archive truncated", path, 0);
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * write_full - Write exactly len bytes unless a hard write error occurs.
 */
static int write_full(int fd, const void *buf, size_t len, const char *path,
                      ark_error_t *err)
{
	const uint8_t *p;

	p = (const uint8_t *)buf;
	while (len > 0U) {
		ssize_t n;

		n = ARK_WRITE(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return fail_error(err, ARK_ERR_IO_WRITE,
			                  "output write failed", path, errno);
		}
		if (n == 0)
			return fail_error(err, ARK_ERR_IO_WRITE,
			                  "output write made no progress", path,
			                  0);
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * le64_decode - Decode one little-endian u64 from an unaligned byte buffer.
 */
static uint64_t le64_decode(const uint8_t *p)
{
	return ((uint64_t)p[0] | ((uint64_t)p[1] << 8) |
	        ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	        ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	        ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56));
}

/*
 * read_archive_index - Read and validate header/footer/index for read paths.
 *
 * ARCHITECTURE.md section 16.4 defines call order. ARCHITECTURE.md section
 * 5.1 requires footer-bound checks in main.c before ark_read_init.
 *
 * OWNERSHIP: *index_buf is caller-owned on success and freed by caller.
 */
static int read_archive_index(int fd, const char *archive_path,
                              ark_read_ctx_t *rctx, uint8_t **index_buf,
                              size_t *index_len, ark_error_t *err)
{
	struct stat sb;
	uint8_t header[16];
	uint8_t footer[64];
	uint64_t file_size;
	uint64_t index_offset;
	uint64_t idx_size_u64;
	uint64_t body_end;
	uint8_t *idx;

	if (ARK_FSTAT(fd, &sb) != 0)
		return fail_error(err, ARK_ERR_IO_READ, "archive fstat failed",
		                  archive_path, errno);
	if (sb.st_size < 0)
		return fail_error(err, ARK_ERR_FMT_TRUNCATED,
		                  "archive size invalid", archive_path, 0);
	file_size = (uint64_t)sb.st_size;

	if (ARK_LSEEK(fd, (off_t)0, SEEK_SET) == (off_t)-1)
		return fail_error(err, ARK_ERR_IO_SEEK, "archive seek failed",
		                  archive_path, errno);
	if (read_full(fd, header, sizeof(header), archive_path, err) != 0)
		return -1;
	if (ark_read_header(rctx, header, sizeof(header), err) != 0)
		return -1;

	if (file_size < 80U)
		return fail_error(err, ARK_ERR_FMT_TRUNCATED,
		                  "archive shorter than minimum size",
		                  archive_path, 0);
	if (ARK_LSEEK(fd, (off_t)(file_size - 64U), SEEK_SET) == (off_t)-1)
		return fail_error(err, ARK_ERR_IO_SEEK, "archive seek failed",
		                  archive_path, errno);
	if (read_full(fd, footer, sizeof(footer), archive_path, err) != 0)
		return -1;

	index_offset = le64_decode(footer + 0U);
	idx_size_u64 = le64_decode(footer + 8U);
	if (index_offset < 16U)
		return fail_error(err, ARK_ERR_FMT_INDEX,
		                  "index offset overlaps fixed header",
		                  archive_path, 0);
	if (!(idx_size_u64 > 0U || index_offset == 16U))
		return fail_error(err, ARK_ERR_FMT_INDEX,
		                  "zero index size requires index_offset == 16",
		                  archive_path, 0);
	if (UINT64_MAX - index_offset < idx_size_u64)
		return fail_error(err, ARK_ERR_FMT_INDEX,
		                  "index offset and size overflow",
		                  archive_path, 0);
	body_end = file_size - 64U;
	if (index_offset + idx_size_u64 != body_end)
		return fail_error(err, ARK_ERR_FMT_INDEX,
		                  "index layout mismatch before footer",
		                  archive_path, 0);

	if (ark_read_init(rctx, footer, sizeof(footer), err) != 0)
		return -1;

	if (idx_size_u64 > (uint64_t)SIZE_MAX)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "index buffer too large", archive_path, 0);
	*index_len = (size_t)idx_size_u64;
	/* OWNERSHIP: caller frees this buffer in command cleanup. */
	idx = (uint8_t *)malloc(*index_len == 0U ? 1U : *index_len);
	if (idx == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "index buffer allocation failed",
		                  archive_path, 0);

	if (ARK_LSEEK(fd, (off_t)index_offset, SEEK_SET) == (off_t)-1) {
		free(idx);
		return fail_error(err, ARK_ERR_IO_SEEK, "archive seek failed",
		                  archive_path, errno);
	}
	if (*index_len > 0U &&
	    read_full(fd, idx, *index_len, archive_path, err) != 0) {
		free(idx);
		return -1;
	}
	if (ark_read_index(rctx, idx, *index_len, err) != 0) {
		free(idx);
		return -1;
	}
	*index_buf = idx;
	return 0;
}

/*
 * read_member_count - Count parsed members exposed by ark_read_member_meta.
 */
static size_t read_member_count(const ark_read_ctx_t *rctx)
{
	size_t n;

	for (n = 0U; ark_read_member_meta(rctx, (uint32_t)n) != NULL; n++)
		;
	return n;
}

/*
 * find_member_pos - Locate one member path and return its positional index.
 */
static int find_member_pos(const ark_read_ctx_t *rctx, const char *path,
                           uint32_t *pos)
{
	uint32_t i;

	for (i = 0U;; i++) {
		const ark_member_meta_t *meta;

		meta = ark_read_member_meta(rctx, i);
		if (meta == NULL)
			break;
		if (strcmp(meta->path, path) == 0) {
			*pos = i;
			return 0;
		}
	}
	return -1;
}

/*
 * build_extract_selection - Build selected-members bitmap for extraction.
 *
 * ARCHITECTURE.md section 12.2: selected hardlinks include their target file.
 */
static int build_extract_selection(const ark_args_t *args,
                                   const ark_read_ctx_t *rctx,
                                   size_t member_count, unsigned char *selected,
                                   ark_error_t *err)
{
	uint32_t i;

	if (args->member_count == 0U) {
		for (i = 0U; i < member_count; i++)
			selected[i] = 1U;
		return 0;
	}

	for (i = 0U; i < args->member_count; i++) {
		uint32_t pos;

		if (find_member_pos(rctx, args->member_paths[i], &pos) != 0)
			return fail_error(
			    err, ARK_ERR_FMT_INDEX,
			    "requested member not found in archive",
			    args->member_paths[i], 0);
		if ((size_t)pos >= member_count)
			return fail_error(
			    err, ARK_ERR_FMT_INDEX,
			    "requested member index out of bounds",
			    args->member_paths[i], 0);
		selected[pos] = 1U;
	}

	for (;;) {
		int changed;

		changed = 0;
		for (i = 0U; i < member_count; i++) {
			const ark_member_meta_t *meta;
			uint32_t target_pos;

			if (selected[i] == 0U)
				continue;
			meta = ark_read_member_meta(rctx, i);
			if (meta->type != 0x04)
				continue;
			if (find_member_pos(rctx, meta->link, &target_pos) != 0)
				return fail_error(
				    err, ARK_ERR_FMT_INDEX,
				    "hardlink target missing in archive",
				    meta->link, 0);
			if ((size_t)target_pos >= member_count)
				return fail_error(
				    err, ARK_ERR_FMT_INDEX,
				    "hardlink target index out of bounds",
				    meta->link, 0);
			if (selected[target_pos] == 0U) {
				selected[target_pos] = 1U;
				changed = 1;
			}
		}
		if (!changed)
			break;
	}
	return 0;
}

/*
 * conflict_path_seen - Return 1 when a conflict path was already collected.
 */
static int conflict_path_seen(const modified_path_list_t *list,
                              const char *path)
{
	size_t i;

	for (i = 0U; i < list->count; i++) {
		if (strcmp(list->paths[i], path) == 0)
			return 1;
	}
	return 0;
}

/*
 * preflight_conflicts - Collect extraction conflicts before side effects.
 *
 * ARCHITECTURE.md section 14.2 requires complete conflict reporting when
 * --overwrite is not used.
 */
static int preflight_conflicts(const ark_args_t *args,
                               const ark_read_ctx_t *rctx, size_t member_count,
                               const unsigned char *selected, int dest_fd,
                               ark_error_t *err)
{
	modified_path_list_t conflicts = {0};
	uint32_t i;

	if (args->overwrite)
		return 0;

	for (i = 0U; i < member_count; i++) {
		const ark_member_meta_t *meta;
		struct stat st;

		if (selected[i] == 0U)
			continue;
		meta = ark_read_member_meta(rctx, i);
		if (ARK_FSTATAT(dest_fd, meta->path, &st,
		                AT_SYMLINK_NOFOLLOW) == 0) {
			if (!conflict_path_seen(&conflicts, meta->path) &&
			    modified_path_list_push(&conflicts, meta->path,
			                            err) != 0) {
				modified_path_list_free(&conflicts);
				return -1;
			}
		} else if (errno != ENOENT) {
			modified_path_list_free(&conflicts);
			return fail_error(err, ARK_ERR_IO_OPEN,
			                  "preflight stat failed", meta->path,
			                  errno);
		}

		if (args->member_count > 0U) {
			char ancestor[1024];
			size_t len;

			copy_msg(ancestor, sizeof(ancestor), meta->path);
			len = strlen(ancestor);
			while (len > 0U) {
				char *slash;
				uint32_t pos;

				slash = strrchr(ancestor, '/');
				if (slash == NULL)
					break;
				*slash = '\0';
				len = strlen(ancestor);
				if (find_member_pos(rctx, ancestor, &pos) ==
				        0 &&
				    selected[pos] != 0U)
					continue;
				if (ARK_FSTATAT(dest_fd, ancestor, &st,
				                AT_SYMLINK_NOFOLLOW) == 0) {
					if (!S_ISDIR(st.st_mode) &&
					    !conflict_path_seen(&conflicts,
					                        ancestor) &&
					    modified_path_list_push(&conflicts,
					                            ancestor,
					                            err) != 0) {
						modified_path_list_free(
						    &conflicts);
						return -1;
					}
				} else if (errno != ENOENT) {
					modified_path_list_free(&conflicts);
					return fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "preflight ancestor stat failed",
					    ancestor, errno);
				}
			}
		}
	}

	if (conflicts.count > 0U) {
		size_t j;

		syslog(LOG_ERR, "extraction conflicts found");
		(void)fputs("ark: extraction conflicts found:\n", stderr);
		for (j = 0U; j < conflicts.count; j++) {
			syslog(LOG_ERR, "%s", conflicts.paths[j]);
			(void)fputs("ark:   ", stderr);
			(void)fputs(conflicts.paths[j], stderr);
			(void)fputc('\n', stderr);
		}
		modified_path_list_free(&conflicts);
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "conflicting output paths found", "", 0);
	}

	modified_path_list_free(&conflicts);
	return 0;
}

/*
 * cleanup_track - Record one created path for reverse-order fatal cleanup.
 */
static int cleanup_track(cleanup_tracker_t *tracker, const char *path,
                         int is_dir, ark_error_t *err)
{
	cleanup_entry_t *new_entries;

	if (tracker->count == tracker->capacity) {
		size_t new_cap;

		new_cap =
		    tracker->capacity == 0U ? 64U : tracker->capacity * 2U;
		/* OWNERSHIP: tracker owns entries and frees them in
		 * cleanup_free. */
		new_entries = (cleanup_entry_t *)realloc(
		    tracker->entries, new_cap * sizeof(tracker->entries[0]));
		if (new_entries == NULL)
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "cleanup tracker allocation failed",
			                  "", 0);
		tracker->entries = new_entries;
		tracker->capacity = new_cap;
	}
	copy_msg(tracker->entries[tracker->count].path,
	         sizeof(tracker->entries[tracker->count].path), path);
	tracker->entries[tracker->count].is_dir = is_dir;
	tracker->count++;
	return 0;
}

/*
 * cleanup_run - Remove created paths in reverse order on fatal errors.
 *
 * ARCHITECTURE.md section 14.3 requires best-effort cleanup while preserving
 * the original primary error.
 */
static void cleanup_run(cleanup_tracker_t *tracker, int dest_fd)
{
	ssize_t i;

	for (i = (ssize_t)tracker->count - 1; i >= 0; i--) {
		int flags;

		flags = tracker->entries[i].is_dir ? AT_REMOVEDIR : 0;
		if (ARK_UNLINKAT(dest_fd, tracker->entries[i].path, flags) !=
		        0 &&
		    errno != ENOENT)
			print_warning("cleanup failed",
			              tracker->entries[i].path);
	}
}

/*
 * cleanup_free - Release cleanup tracker storage.
 */
static void cleanup_free(cleanup_tracker_t *tracker)
{
	free(tracker->entries);
	tracker->entries = NULL;
	tracker->count = 0U;
	tracker->capacity = 0U;
}

/*
 * dir_deferred_push - Queue one directory for deferred metadata restore.
 */
static int dir_deferred_push(dir_deferred_meta_t *list,
                             const ark_member_meta_t *meta, ark_error_t *err)
{
	const ark_member_meta_t **new_items;

	if (list->count == list->capacity) {
		size_t new_cap;

		new_cap = list->capacity == 0U ? 32U : list->capacity * 2U;
		/* OWNERSHIP: list owns pointer array and frees it in
		 * dir_deferred_free. */
		new_items = (const ark_member_meta_t **)realloc(
		    (void *)list->items, new_cap * sizeof(list->items[0]));
		if (new_items == NULL)
			return fail_error(
			    err, ARK_ERR_IO_ALLOC,
			    "deferred directory list allocation failed", "", 0);
		list->items = new_items;
		list->capacity = new_cap;
	}
	list->items[list->count++] = meta;
	return 0;
}

/*
 * dir_deferred_free - Release deferred-directory pointer array storage.
 */
static void dir_deferred_free(dir_deferred_meta_t *list)
{
	free((void *)list->items);
	list->items = NULL;
	list->count = 0U;
	list->capacity = 0U;
}

/*
 * ensure_parent_dirs - Handle parent dir precondition for a member path.
 *
 * ARCHITECTURE.md section 14.4: full extraction rejects missing parents as
 * format error; selective extraction may create missing parents with mode 0700.
 */
static int ensure_parent_dirs(const ark_member_meta_t *meta, int dest_fd,
                              int selective, cleanup_tracker_t *tracker,
                              ark_error_t *err)
{
	char path[1024];
	char *slash;

	copy_msg(path, sizeof(path), meta->path);
	for (slash = strchr(path, '/'); slash != NULL;
	     slash = strchr(slash + 1, '/')) {
		struct stat st;

		*slash = '\0';
		if (ARK_FSTATAT(dest_fd, path, &st, AT_SYMLINK_NOFOLLOW) == 0) {
			if (!S_ISDIR(st.st_mode))
				return fail_error(
				    err, ARK_ERR_FMT_INDEX,
				    "ancestor path is not a directory",
				    meta->path, 0);
			*slash = '/';
			continue;
		}
		if (errno != ENOENT)
			return fail_error(err, ARK_ERR_IO_OPEN,
			                  "ancestor stat failed", meta->path,
			                  errno);
		if (!selective)
			return fail_error(
			    err, ARK_ERR_FMT_INDEX,
			    "missing ancestor directory in archive order",
			    meta->path, 0);
		if (ARK_MKDIRAT(dest_fd, path, 0700) != 0)
			return fail_error(err, ARK_ERR_IO_MKDIR,
			                  "implicit directory creation failed",
			                  path, errno);
		/*
		 * SAFETY: track created object immediately after mkdirat and
		 * before any subsequent fallible operation. See ARCHITECTURE.md
		 * section 14.3.
		 */
		if (cleanup_track(tracker, path, 1, err) != 0)
			return -1;
		*slash = '/';
	}
	return 0;
}

/*
 * decode_mtime - Convert stored nanoseconds since epoch into timespec pair.
 */
static void decode_mtime(uint64_t mtime, struct timespec times[2])
{
	int64_t ns_total;
	int64_t sec;
	int64_t nsec;

	ns_total = (int64_t)mtime;
	sec = ns_total / INT64_C(1000000000);
	nsec = ns_total % INT64_C(1000000000);
	if (nsec < 0) {
		sec--;
		nsec += INT64_C(1000000000);
	}
	times[0].tv_sec = 0;
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = (time_t)sec;
	times[1].tv_nsec = (long)nsec;
}

/*
 * restore_regular_meta - Restore regular file metadata while fd is open.
 *
 * SAFETY: ARK_FCHOWN runs before ARK_FCHMOD. See ARCHITECTURE.md section 14.5.
 */
static int restore_regular_meta(int fd, const ark_member_meta_t *meta,
                                ark_error_t *err)
{
	struct timespec times[2];
	int rc;

	decode_mtime(meta->mtime, times);
	if (geteuid() == 0) {
		do {
			rc = ARK_FCHOWN(fd, (uid_t)meta->uid, (gid_t)meta->gid);
		} while (rc != 0 && errno == EINTR);
		if (rc != 0 && errno != EPERM)
			return fail_error(err, ARK_ERR_IO_CHOWN,
			                  "fchown failed", meta->path, errno);
		if (rc != 0 && errno == EPERM)
			print_warning("ownership restore not permitted",
			              meta->path);
	}
	do {
		rc = ARK_FCHMOD(fd, (mode_t)(meta->mode & 0777U));
	} while (rc != 0 && errno == EINTR);
	if (rc != 0)
		return fail_error(err, ARK_ERR_IO_CHMOD, "fchmod failed",
		                  meta->path, errno);
	do {
		rc = ARK_FUTIMENS(fd, times);
	} while (rc != 0 && errno == EINTR);
	if (rc != 0)
		return fail_error(err, ARK_ERR_IO_UTIMES, "futimens failed",
		                  meta->path, errno);
	return 0;
}

/*
 * restore_symlink_meta - Best-effort symlink owner/mtime restoration.
 */
static void restore_symlink_meta(int dest_fd, const ark_member_meta_t *meta)
{
	struct timespec times[2];
	int rc;

	decode_mtime(meta->mtime, times);
	if (geteuid() == 0) {
		do {
			rc =
			    ARK_FCHOWNAT(dest_fd, meta->path, (uid_t)meta->uid,
			                 (gid_t)meta->gid, AT_SYMLINK_NOFOLLOW);
		} while (rc != 0 && errno == EINTR);
		if (rc != 0)
			print_warning("symlink ownership restore failed",
			              meta->path);
	}
	do {
		rc = ARK_UTIMENSAT(dest_fd, meta->path, times,
		                   AT_SYMLINK_NOFOLLOW);
	} while (rc != 0 && errno == EINTR);
	if (rc != 0)
		print_warning("symlink mtime restore failed", meta->path);
}

/*
 * apply_deferred_dir_meta - Restore directory metadata in reverse index order.
 */
static void apply_deferred_dir_meta(int dest_fd,
                                    const dir_deferred_meta_t *list)
{
	ssize_t i;

	for (i = (ssize_t)list->count - 1; i >= 0; i--) {
		const ark_member_meta_t *meta;
		struct timespec times[2];
		int rc;

		meta = list->items[i];
		decode_mtime(meta->mtime, times);
		if (geteuid() == 0) {
			do {
				rc = ARK_FCHOWNAT(dest_fd, meta->path,
				                  (uid_t)meta->uid,
				                  (gid_t)meta->gid, 0);
			} while (rc != 0 && errno == EINTR);
			if (rc != 0)
				print_warning(
				    "directory ownership restore failed",
				    meta->path);
		}
		do {
			rc = ARK_FCHMODAT(dest_fd, meta->path,
			                  (mode_t)(meta->mode & 0777U), 0);
		} while (rc != 0 && errno == EINTR);
		if (rc != 0)
			print_warning("directory mode restore failed",
			              meta->path);
		do {
			rc = ARK_UTIMENSAT(dest_fd, meta->path, times, 0);
		} while (rc != 0 && errno == EINTR);
		if (rc != 0)
			print_warning("directory mtime restore failed",
			              meta->path);
	}
}

/*
 * format_u64_dec - Convert unsigned 64-bit value to decimal C string.
 */
static void format_u64_dec(uint64_t value, char *out, size_t out_len)
{
	char tmp[32];
	size_t i;
	size_t j;

	if (out_len == 0U)
		return;
	if (value == 0U) {
		out[0] = '0';
		if (out_len > 1U)
			out[1] = '\0';
		return;
	}

	i = 0U;
	while (value > 0U && i < sizeof(tmp) - 1U) {
		tmp[i++] = (char)('0' + (value % 10U));
		value /= 10U;
	}

	j = 0U;
	while (i > 0U && j + 1U < out_len)
		out[j++] = tmp[--i];
	out[j] = '\0';
}

/*
 * format_size_human - Render a list size field using B/KB/MB/GB units.
 */
static void format_size_human(uint64_t bytes, char *out, size_t out_len)
{
	const char *unit_str;
	char whole_buf[32];
	unsigned int unit;
	uint64_t div;
	uint64_t whole;
	uint64_t rem;
	uint64_t frac;
	size_t off;

	unit = 0U;
	div = 1U;
	while ((bytes / div) >= 1024U && unit < 3U) {
		div *= 1024U;
		unit++;
	}

	if (unit == 0U) {
		format_u64_dec(bytes, out, out_len);
		off = strlen(out);
		if (off + 1U < out_len) {
			out[off++] = 'B';
			out[off] = '\0';
		}
		return;
	}

	if (unit == 1U)
		unit_str = "KB";
	else if (unit == 2U)
		unit_str = "MB";
	else
		unit_str = "GB";

	whole = bytes / div;
	rem = bytes % div;
	frac = ((rem * 10U) + (div / 2U)) / div;
	if (frac >= 10U) {
		whole++;
		frac = 0U;
	}

	format_u64_dec(whole, whole_buf, sizeof(whole_buf));
	copy_msg(out, out_len, whole_buf);
	off = strlen(out);
	if (off + 1U < out_len) {
		out[off++] = '.';
		out[off++] = (char)('0' + frac);
		out[off] = '\0';
	}
	if (off + strlen(unit_str) < out_len)
		copy_msg(out + off, out_len - off, unit_str);
}

/*
 * format_mtime_human - Render archive nanosecond timestamp as UTC text.
 *
 * NOTE: Human mtime formatting is used only for list --human output. See
 * ARCHITECTURE.md section 12.2.
 */
static void format_mtime_human(uint64_t mtime, char *out, size_t out_len)
{
	int64_t ns_total;
	int64_t sec;
	time_t tv_sec;
	struct tm tm;

	ns_total = (int64_t)mtime;
	sec = ns_total / INT64_C(1000000000);
	if ((ns_total % INT64_C(1000000000)) < 0)
		sec--;
	tv_sec = (time_t)sec;
	if ((int64_t)tv_sec != sec || gmtime_r(&tv_sec, &tm) == NULL) {
		copy_msg(out, out_len, "invalid-time");
		return;
	}
	if (strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		copy_msg(out, out_len, "invalid-time");
}

/*
 * print_member - Print one list row according to --verbose/--human flags.
 *
 * ARCHITECTURE.md section 12.2 defines these list output modes:
 * - default: path only
 * - --verbose: type, size, mode, mtime, path
 * - --human: same columns with human-readable size and mtime
 */
static int print_member(const ark_member_meta_t *meta, int verbose, int human)
{
	const char *type;

	if (!verbose)
		return printf("%s\n", meta->path) < 0 ? -1 : 0;

	switch (meta->type) {
	case 0x01:
		type = "file";
		break;
	case 0x02:
		type = "dir";
		break;
	case 0x03:
		type = "symlink";
		break;
	case 0x04:
		type = "hardlink";
		break;
	default:
		type = "unknown";
		break;
	}

	if (human) {
		char size_buf[32];
		char mtime_buf[64];

		format_size_human(meta->size_original, size_buf,
		                  sizeof(size_buf));
		format_mtime_human(meta->mtime, mtime_buf, sizeof(mtime_buf));
		if (printf("%-8s %12s %04o %20s %s\n", type, size_buf,
		           (unsigned int)(meta->mode & 0777U), mtime_buf,
		           meta->path) < 0)
			return -1;
		return 0;
	}

	if (printf("%-8s %12llu %04o %20llu %s\n", type,
	           (unsigned long long)meta->size_original,
	           (unsigned int)(meta->mode & 0777U),
	           (unsigned long long)meta->mtime, meta->path) < 0)
		return -1;
	return 0;
}

/*
 * cmd_list - Validate archive and print member rows from the index.
 */
static int cmd_list(const ark_args_t *args, ark_error_t *err)
{
	ark_read_ctx_storage_t rstorage = {0};
	ark_read_ctx_t *rctx;
	uint8_t *index_buf;
	int fd;
	int rc;

	rctx = (ark_read_ctx_t *)rstorage.bytes;
	index_buf = NULL;
	rc = -1;
	fd = ARK_OPEN(args->archive_path, O_RDONLY | O_CLOEXEC, 0);
	if (fd == -1)
		return fail_error(err, ARK_ERR_IO_OPEN, "archive open failed",
		                  args->archive_path, errno);
	if (read_archive_index(fd, args->archive_path, rctx, &index_buf,
	                       &(size_t){0}, err) != 0)
		goto cleanup;

	if (args->human && !args->verbose)
		print_warning("--human ignored without --verbose", "");

	if (args->member_count == 0U) {
		size_t i;

		for (i = 0U;; i++) {
			const ark_member_meta_t *meta;

			meta = ark_read_member_meta(rctx, (uint32_t)i);
			if (meta == NULL)
				break;
			if (print_member(meta, args->verbose, args->human) !=
			    0) {
				(void)fail_error(err, ARK_ERR_IO_WRITE,
				                 "list output failed", "",
				                 errno);
				goto cleanup;
			}
		}
	} else {
		size_t i;

		for (i = 0U; i < args->member_count; i++) {
			uint32_t pos;
			const ark_member_meta_t *meta;

			if (find_member_pos(rctx, args->member_paths[i],
			                    &pos) != 0) {
				(void)fail_error(
				    err, ARK_ERR_FMT_INDEX,
				    "requested member not found in archive",
				    args->member_paths[i], 0);
				goto cleanup;
			}
			meta = ark_read_member_meta(rctx, pos);
			if (print_member(meta, args->verbose, args->human) !=
			    0) {
				(void)fail_error(err, ARK_ERR_IO_WRITE,
				                 "list output failed", "",
				                 errno);
				goto cleanup;
			}
		}
	}
	rc = 0;

cleanup:
	if (ARK_CLOSE(fd) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_OPEN, "archive close failed",
		                args->archive_path, errno);
	free(index_buf);
	ark_read_free(rctx);
	return rc;
}

/*
 * cmd_verify - Validate archive and verify selected regular members.
 *
 * ARCHITECTURE.md section 14.3: verify hashes compressed bytes while
 * decompressing each chunk into a bounded temporary buffer with no
 * filesystem writes.
 */
static int cmd_verify(const ark_args_t *args, ark_error_t *err)
{
	ark_read_ctx_storage_t rstorage = {0};
	ark_read_ctx_t *rctx;
	uint8_t *index_buf;
	unsigned char *selected;
	uint8_t *comp_buf;
	uint8_t *decomp_buf;
	size_t index_len;
	size_t member_count;
	size_t comp_cap;
	int archive_fd;
	int rc;

	rctx = (ark_read_ctx_t *)rstorage.bytes;
	index_buf = NULL;
	selected = NULL;
	comp_buf = NULL;
	decomp_buf = NULL;
	rc = -1;

	archive_fd = ARK_OPEN(args->archive_path, O_RDONLY | O_CLOEXEC, 0);
	if (archive_fd == -1)
		return fail_error(err, ARK_ERR_IO_OPEN, "archive open failed",
		                  args->archive_path, errno);
	if (read_archive_index(archive_fd, args->archive_path, rctx, &index_buf,
	                       &index_len, err) != 0)
		goto cleanup;

	member_count = read_member_count(rctx);
	selected = (unsigned char *)calloc(member_count + 1U, 1U);
	if (selected == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "selection allocation failed", "", 0);
		goto cleanup;
	}
	if (build_extract_selection(args, rctx, member_count, selected, err) !=
	    0)
		goto cleanup;

	comp_cap = ark_deflate_bound(ARK_CHUNK_SIZE);
	/* OWNERSHIP: command cleanup frees both verification buffers. */
	comp_buf = (uint8_t *)malloc(comp_cap);
	decomp_buf = (uint8_t *)malloc(ARK_CHUNK_SIZE);
	if (comp_buf == NULL || decomp_buf == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "verification buffer allocation failed", "",
		                 0);
		goto cleanup;
	}

	for (uint32_t i = 0U; i < member_count; i++) {
		const ark_member_meta_t *meta;
		uint32_t chunk;
		uint64_t chunk_off;

		if (selected[i] == 0U)
			continue;
		meta = ark_read_member_meta(rctx, i);
		if (meta->type != 0x01)
			continue;

		if (args->verbose) {
			if (printf("verify: %s\n", meta->path) < 0) {
				(void)fail_error(err, ARK_ERR_IO_WRITE,
				                 "verify output failed", "",
				                 errno);
				goto cleanup;
			}
		}

		if (ark_read_verify_member_begin(rctx, meta, err) != 0)
			goto cleanup;
		chunk_off = meta->data_offset;
		for (chunk = 0U; chunk < meta->chunk_count; chunk++) {
			size_t csz;

			csz = (size_t)meta->chunk_sizes[chunk];
			if (csz > comp_cap) {
				(void)fail_error(err, ARK_ERR_FMT_INDEX,
				                 "chunk size exceeds bound",
				                 meta->path, 0);
				goto cleanup;
			}
			if (ARK_LSEEK(archive_fd, (off_t)chunk_off, SEEK_SET) ==
			    (off_t)-1) {
				(void)fail_error(err, ARK_ERR_IO_SEEK,
				                 "archive seek failed",
				                 meta->path, errno);
				goto cleanup;
			}
			if (read_full(archive_fd, comp_buf, csz, meta->path,
			              err) != 0)
				goto cleanup;
			/*
			 * SAFETY: verification hashes compressed bytes in
			 * on-disk chunk order before decompression. See
			 * ARCHITECTURE.md section 14.3.
			 */
			if (ark_read_verify_member_update(
			        rctx, meta, chunk, comp_buf, csz, err) != 0)
				goto cleanup;
			if (ark_read_chunk(rctx, meta, chunk, comp_buf, csz,
			                   decomp_buf, ARK_CHUNK_SIZE, err) < 0)
				goto cleanup;
			if (UINT64_MAX - chunk_off < (uint64_t)csz) {
				(void)fail_error(err, ARK_ERR_FMT_INDEX,
				                 "chunk offset overflow",
				                 meta->path, 0);
				goto cleanup;
			}
			chunk_off += (uint64_t)csz;
		}
		if (ark_read_verify_member_final(rctx, meta, err) != 0)
			goto cleanup;
	}

	rc = 0;

cleanup:
	free(decomp_buf);
	free(comp_buf);
	free(selected);
	free(index_buf);
	if (ARK_CLOSE(archive_fd) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_OPEN, "archive close failed",
		                args->archive_path, errno);
	(void)index_len;
	ark_read_free(rctx);
	return rc;
}

/*
 * cmd_generate_reader - Atomically write embedded recovery source output.
 *
 * ARCHITECTURE.md sections 10.4 and 15.2 require generate-reader to emit the
 * embedded template and use libchevron for atomic replacement semantics.
 */
static int cmd_generate_reader(const ark_args_t *args, ark_error_t *err)
{
	chevron_handle_t handle = CHEVRON_HANDLE_INIT;
	chevron_error_t cerr = {0};
	size_t len;

	len = sizeof(recovery_template);
	/* The awk-emitted string form is NUL-terminated; do not write
	 * terminator. */
	len--;

	if (chevron_open(&handle, args->generate_reader_output, CHEVRON_FULL,
	                 CHEVRON_MODE_DEFAULT, &cerr) != 0)
		return chevron_error_fail(err, &cerr,
		                          "generate-reader output open failed",
		                          args->generate_reader_output);

	if (chevron_write_or_fail(&handle, recovery_template, len,
	                          args->generate_reader_output, err) != 0) {
		chevron_abort(&handle);
		return -1;
	}

	if (chevron_commit(&handle, &cerr) != 0)
		return chevron_error_fail(
		    err, &cerr, "generate-reader output commit failed",
		    args->generate_reader_output);
	return 0;
}

/*
 * cmd_extract - Validate archive and extract selected members in index order.
 *
 * Uses worker-pool decompression with I/O-thread ordered drain from the ring
 * buffer per ARCHITECTURE.md section 6.3. Fatal paths quiesce workers before
 * filesystem cleanup per section 14.3.
 */
static int cmd_extract(const ark_args_t *args, int dest_fd, ark_pool_t *pool,
                       ark_error_t *err)
{
	ark_read_ctx_storage_t rstorage = {0};
	ark_read_ctx_t *rctx;
	cleanup_tracker_t tracker = {0};
	dir_deferred_meta_t deferred_dirs = {0};
	uint8_t *index_buf;
	unsigned char *selected;
	uint8_t *comp_buf;
	uint8_t *out_buf;
	size_t index_len;
	size_t member_count;
	size_t comp_cap;
	size_t max_in_flight;
	int archive_fd;
	int out_fd;
	int rc;

	rctx = (ark_read_ctx_t *)rstorage.bytes;
	index_buf = NULL;
	selected = NULL;
	comp_buf = NULL;
	out_buf = NULL;
	out_fd = -1;
	rc = -1;
	if (pool == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "extract worker pool is required", "", 0);
	max_in_flight = (size_t)pool->n_workers;
	if (max_in_flight == 0U)
		return fail_error(err, ARK_ERR_USAGE,
		                  "extract worker pool has zero workers", "",
		                  0);

	archive_fd = ARK_OPEN(args->archive_path, O_RDONLY | O_CLOEXEC, 0);
	if (archive_fd == -1)
		return fail_error(err, ARK_ERR_IO_OPEN, "archive open failed",
		                  args->archive_path, errno);
	if (read_archive_index(archive_fd, args->archive_path, rctx, &index_buf,
	                       &index_len, err) != 0)
		goto cleanup;

	member_count = read_member_count(rctx);
	selected = (unsigned char *)calloc(member_count + 1U, 1U);
	if (selected == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "selection allocation failed", "", 0);
		goto cleanup;
	}
	if (build_extract_selection(args, rctx, member_count, selected, err) !=
	    0)
		goto cleanup;
	if (preflight_conflicts(args, rctx, member_count, selected, dest_fd,
	                        err) != 0)
		goto cleanup;

	comp_cap = ark_deflate_bound(ARK_CHUNK_SIZE);
	/* OWNERSHIP: command cleanup frees comp_buf and any drained out_buf. */
	comp_buf = (uint8_t *)malloc(comp_cap);
	if (comp_buf == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "chunk buffer allocation failed", "", 0);
		goto cleanup;
	}

	for (uint32_t i = 0U; i < member_count; i++) {
		const ark_member_meta_t *meta;
		int selective;
		struct stat st;
		int exists;

		if (selected[i] == 0U)
			continue;
		meta = ark_read_member_meta(rctx, i);
		selective = (args->member_count > 0U);
		if (ensure_parent_dirs(meta, dest_fd, selective, &tracker,
		                       err) != 0)
			goto cleanup;

		exists = (ARK_FSTATAT(dest_fd, meta->path, &st,
		                      AT_SYMLINK_NOFOLLOW) == 0);
		if (!exists && errno != ENOENT) {
			(void)fail_error(err, ARK_ERR_IO_OPEN,
			                 "destination stat failed", meta->path,
			                 errno);
			goto cleanup;
		}

		switch (meta->type) {
		case 0x02:
			if (exists) {
				if (!S_ISDIR(st.st_mode)) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "directory cannot replace "
					    "non-directory",
					    meta->path, 0);
					goto cleanup;
				}
			} else {
				if (ARK_MKDIRAT(dest_fd, meta->path, 0700) !=
				    0) {
					(void)fail_error(
					    err, ARK_ERR_IO_MKDIR,
					    "directory create failed",
					    meta->path, errno);
					goto cleanup;
				}
				if (cleanup_track(&tracker, meta->path, 1,
				                  err) != 0)
					goto cleanup;
			}
			if (dir_deferred_push(&deferred_dirs, meta, err) != 0)
				goto cleanup;
			break;
		case 0x03:
			if (exists) {
				if (S_ISDIR(st.st_mode)) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "symlink cannot replace directory",
					    meta->path, 0);
					goto cleanup;
				}
				if (!args->overwrite) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "destination already exists",
					    meta->path, EEXIST);
					goto cleanup;
				}
				if (ARK_UNLINKAT(dest_fd, meta->path, 0) != 0) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "overwrite unlink failed",
					    meta->path, errno);
					goto cleanup;
				}
			}
			if (ARK_SYMLINKAT(meta->link, dest_fd, meta->path) !=
			    0) {
				(void)fail_error(err, ARK_ERR_IO_SYMLINK,
				                 "symlink create failed",
				                 meta->path, errno);
				goto cleanup;
			}
			if (cleanup_track(&tracker, meta->path, 0, err) != 0)
				goto cleanup;
			restore_symlink_meta(dest_fd, meta);
			break;
		case 0x04:
			if (exists) {
				if (S_ISDIR(st.st_mode)) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "hardlink cannot replace directory",
					    meta->path, 0);
					goto cleanup;
				}
				if (!args->overwrite) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "destination already exists",
					    meta->path, EEXIST);
					goto cleanup;
				}
				if (ARK_UNLINKAT(dest_fd, meta->path, 0) != 0) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "overwrite unlink failed",
					    meta->path, errno);
					goto cleanup;
				}
			}
			if (ARK_LINKAT(dest_fd, meta->link, dest_fd, meta->path,
			               0) != 0) {
				(void)fail_error(err, ARK_ERR_IO_LINK,
				                 "hardlink create failed",
				                 meta->path, errno);
				goto cleanup;
			}
			if (cleanup_track(&tracker, meta->path, 0, err) != 0)
				goto cleanup;
			break;
		case 0x01: {
			uint32_t chunk;
			uint64_t submit_seq;
			uint64_t drain_seq;
			uint64_t chunk_off;
			size_t in_flight;

			if (exists) {
				if (S_ISDIR(st.st_mode)) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "file cannot replace directory",
					    meta->path, 0);
					goto cleanup;
				}
				if (!args->overwrite) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "destination already exists",
					    meta->path, EEXIST);
					goto cleanup;
				}
				if (ARK_UNLINKAT(dest_fd, meta->path, 0) != 0) {
					(void)fail_error(
					    err, ARK_ERR_IO_OPEN,
					    "overwrite unlink failed",
					    meta->path, errno);
					goto cleanup;
				}
			}
			/*
			 * SAFETY: O_NOFOLLOW is required on extraction output
			 * opens to prevent symlink substitution races. See
			 * ARCHITECTURE.md section 14.2.
			 */
			out_fd = ARK_OPENAT(dest_fd, meta->path,
			                    O_CREAT | O_WRONLY | O_NOFOLLOW |
			                        O_CLOEXEC |
			                        (args->overwrite ? 0 : O_EXCL),
			                    0600);
			if (out_fd == -1) {
				(void)fail_error(err, ARK_ERR_IO_OPEN,
				                 "output open failed",
				                 meta->path, errno);
				goto cleanup;
			}
			if (cleanup_track(&tracker, meta->path, 0, err) != 0)
				goto cleanup;

			if (ark_read_verify_member_begin(rctx, meta, err) != 0)
				goto cleanup;
			chunk_off = meta->data_offset;
			submit_seq = 0U;
			drain_seq = 0U;
			in_flight = 0U;
			for (chunk = 0U; chunk < meta->chunk_count; chunk++) {
				size_t csz;

				csz = (size_t)meta->chunk_sizes[chunk];
				if (csz > comp_cap) {
					(void)fail_error(
					    err, ARK_ERR_FMT_INDEX,
					    "chunk size exceeds bound",
					    meta->path, 0);
					goto cleanup;
				}
				if (ARK_LSEEK(archive_fd, (off_t)chunk_off,
				              SEEK_SET) == (off_t)-1) {
					(void)fail_error(err, ARK_ERR_IO_SEEK,
					                 "archive seek failed",
					                 meta->path, errno);
					goto cleanup;
				}
				if (read_full(archive_fd, comp_buf, csz,
				              meta->path, err) != 0)
					goto cleanup;
				if (ark_read_verify_member_update(
				        rctx, meta, chunk, comp_buf, csz,
				        err) != 0)
					goto cleanup;
				if (pool_submit(pool, submit_seq, comp_buf, csz,
				                ARK_DEFLATE_DEFAULT) != 0) {
					if (__atomic_load_n(
					        (int *)&pool->shared_err
					            .recorded,
					        __ATOMIC_ACQUIRE) != 0)
						*err = pool->shared_err.error;
					else
						(void)fail_error(
						    err, ARK_ERR_FMT_DATA,
						    "extract worker submit "
						    "failed",
						    meta->path, 0);
					goto cleanup;
				}
				submit_seq++;
				in_flight++;
				chunk_off += (uint64_t)csz;

				while (in_flight >= max_in_flight) {
					int is_abort;
					ark_err_t worker_err;
					size_t out_len;
					size_t expected_len;

					out_buf = NULL;
					if (ring_buf_read(
					        pool->ring, drain_seq, &out_buf,
					        &out_len, &is_abort,
					        &worker_err, err) != 0)
						goto cleanup;
					if (is_abort) {
						if (__atomic_load_n(
						        (int *)&pool->shared_err
						            .recorded,
						        __ATOMIC_ACQUIRE) != 0)
							*err = pool->shared_err
							           .error;
						else if (worker_err != ARK_OK)
							(void)fail_error(
							    err, worker_err,
							    "extract worker "
							    "aborted",
							    meta->path, 0);
						else
							(void)fail_error(
							    err,
							    ARK_ERR_FMT_DATA,
							    "extract worker "
							    "aborted",
							    meta->path, 0);
						ring_buf_release(pool->ring,
						                 drain_seq);
						out_buf = NULL;
						goto cleanup;
					}

					if ((uint32_t)(drain_seq + 1U) <
					    meta->chunk_count)
						expected_len = ARK_CHUNK_SIZE;
					else {
						expected_len =
						    (size_t)(meta->size_original %
						             (uint64_t)
						                 ARK_CHUNK_SIZE);
						if (expected_len == 0U)
							expected_len =
							    ARK_CHUNK_SIZE;
					}
					if (out_len != expected_len) {
						(void)fail_error(
						    err, ARK_ERR_FMT_DATA,
						    "decompressed chunk length "
						    "mismatch",
						    meta->path, 0);
						ring_buf_release(pool->ring,
						                 drain_seq);
						out_buf = NULL;
						goto cleanup;
					}
					if (write_full(out_fd, out_buf, out_len,
					               meta->path, err) != 0) {
						ring_buf_release(pool->ring,
						                 drain_seq);
						out_buf = NULL;
						goto cleanup;
					}
					ring_buf_release(pool->ring, drain_seq);
					out_buf = NULL;
					drain_seq++;
					in_flight--;
				}
			}
			while (in_flight > 0U) {
				int is_abort;
				ark_err_t worker_err;
				size_t out_len;
				size_t expected_len;

				out_buf = NULL;
				if (ring_buf_read(pool->ring, drain_seq,
				                  &out_buf, &out_len, &is_abort,
				                  &worker_err, err) != 0)
					goto cleanup;
				if (is_abort) {
					if (__atomic_load_n(
					        (int *)&pool->shared_err
					            .recorded,
					        __ATOMIC_ACQUIRE) != 0)
						*err = pool->shared_err.error;
					else if (worker_err != ARK_OK)
						(void)fail_error(
						    err, worker_err,
						    "extract worker aborted",
						    meta->path, 0);
					else
						(void)fail_error(
						    err, ARK_ERR_FMT_DATA,
						    "extract worker aborted",
						    meta->path, 0);
					ring_buf_release(pool->ring, drain_seq);
					out_buf = NULL;
					goto cleanup;
				}

				if ((uint32_t)(drain_seq + 1U) <
				    meta->chunk_count)
					expected_len = ARK_CHUNK_SIZE;
				else {
					expected_len =
					    (size_t)(meta->size_original %
					             (uint64_t)ARK_CHUNK_SIZE);
					if (expected_len == 0U)
						expected_len = ARK_CHUNK_SIZE;
				}
				if (out_len != expected_len) {
					(void)fail_error(err, ARK_ERR_FMT_DATA,
					                 "decompressed chunk "
					                 "length mismatch",
					                 meta->path, 0);
					ring_buf_release(pool->ring, drain_seq);
					out_buf = NULL;
					goto cleanup;
				}
				if (write_full(out_fd, out_buf, out_len,
				               meta->path, err) != 0) {
					ring_buf_release(pool->ring, drain_seq);
					out_buf = NULL;
					goto cleanup;
				}
				ring_buf_release(pool->ring, drain_seq);
				out_buf = NULL;
				drain_seq++;
				in_flight--;
			}
			if (ark_read_verify_member_final(rctx, meta, err) != 0)
				goto cleanup;
			if (restore_regular_meta(out_fd, meta, err) != 0)
				goto cleanup;
			if (ARK_CLOSE(out_fd) != 0) {
				(void)fail_error(err, ARK_ERR_IO_WRITE,
				                 "output close failed",
				                 meta->path, errno);
				goto cleanup;
			}
			out_fd = -1;
			break;
		}
		default:
			(void)fail_error(err, ARK_ERR_FMT_MEMBER_TYPE,
			                 "unsupported member type", meta->path,
			                 0);
			goto cleanup;
		}
	}

	apply_deferred_dir_meta(dest_fd, &deferred_dirs);
	rc = 0;

cleanup:
	/*
	 * SAFETY: apply quiescence sequence before cleanup filesystem work:
	 * cancel/join workers, close current output fd, then run cleanup.
	 * See ARCHITECTURE.md section 14.3.
	 */
	pool_shutdown(pool);
	if (out_fd != -1)
		(void)ARK_CLOSE(out_fd);
	if (rc != 0 && tracker.count > 0U) {
		ark_error_t saved;

		saved = *err;
		cleanup_run(&tracker, dest_fd);
		*err = saved;
	}
	cleanup_free(&tracker);
	dir_deferred_free(&deferred_dirs);
	free(comp_buf);
	free(selected);
	free(index_buf);
	if (ARK_CLOSE(archive_fd) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_OPEN, "archive close failed",
		                args->archive_path, errno);
	(void)index_len;
	ark_read_free(rctx);
	return rc;
}

/*
 * exit_code_from_err - Map ark_err_t class to process exit code.
 *
 * See ARCHITECTURE.md section 11.1.
 */
static int exit_code_from_err(ark_err_t code)
{
	switch (code) {
	case ARK_ERR_USAGE:
		return 1;
	case ARK_ERR_IO_READ:
	case ARK_ERR_IO_WRITE:
	case ARK_ERR_IO_SEEK:
	case ARK_ERR_IO_OPEN:
	case ARK_ERR_IO_FSYNC:
	case ARK_ERR_IO_COMMIT:
	case ARK_ERR_IO_MKDIR:
	case ARK_ERR_IO_SYMLINK:
	case ARK_ERR_IO_LINK:
	case ARK_ERR_IO_CHMOD:
	case ARK_ERR_IO_CHOWN:
	case ARK_ERR_IO_UTIMES:
	case ARK_ERR_IO_ALLOC:
		return 2;
	case ARK_ERR_FMT_MAGIC:
	case ARK_ERR_FMT_VERSION:
	case ARK_ERR_FMT_COMP_ALG:
	case ARK_ERR_FMT_HASH_ALG:
	case ARK_ERR_FMT_RESERVED:
	case ARK_ERR_FMT_INDEX:
	case ARK_ERR_FMT_MEMBER_TYPE:
	case ARK_ERR_FMT_TRUNCATED:
	case ARK_ERR_FMT_DATA:
		return 3;
	case ARK_ERR_HASH_INDEX:
	case ARK_ERR_HASH_MEMBER:
		return 4;
	case ARK_ERR_PATH_TRAVERSAL:
	case ARK_ERR_PATH_TOO_LONG:
	case ARK_ERR_PATH_ABSOLUTE:
	case ARK_ERR_PATH_ENCODING:
		return 5;
	case ARK_ERR_MODIFIED:
		return 6;
	case ARK_OK:
	default:
		return 1;
	}
}

/*
 * usage_error - Set ARK_ERR_USAGE with a descriptive parser message.
 */
static int usage_error(ark_error_t *err, const char *msg)
{
	if (err != NULL) {
		err->code = ARK_ERR_USAGE;
		err->sys_errno = 0;
		copy_msg(err->msg, sizeof(err->msg), msg);
		err->path[0] = '\0';
	}
	return -1;
}

/*
 * fail_error - Set a structured failure payload and return -1.
 */
static int fail_error(ark_error_t *err, ark_err_t code, const char *msg,
                      const char *path, int sys_errno)
{
	if (err != NULL) {
		err->code = code;
		err->sys_errno = sys_errno;
		copy_msg(err->msg, sizeof(err->msg), msg);
		copy_msg(err->path, sizeof(err->path),
		         path != NULL ? path : "");
	}
	return -1;
}

/*
 * copy_msg - Copy a C string into a fixed-size destination buffer.
 */
static void copy_msg(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (dst_len == 0)
		return;

	if (src == NULL)
		src = "";

	i = 0;
	while (i + 1 < dst_len && src[i] != '\0') {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

/*
 * parent_dir - Resolve the parent directory component of a path.
 *
 * Returns 0 on success, -1 with ARK_ERR_USAGE on invalid input.
 */
static int parent_dir(const char *path, char *dst, size_t dst_len,
                      ark_error_t *err)
{
	size_t len;
	size_t end;
	size_t i;
	size_t j;

	if (path == NULL || path[0] == '\0')
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox parent path is empty", "", 0);

	len = strlen(path);
	end = len;
	while (end > 1 && path[end - 1] == '/')
		end--;

	for (i = end; i > 0; i--) {
		if (path[i - 1] == '/') {
			if (i == 1) {
				if (dst_len < 2)
					return fail_error(
					    err, ARK_ERR_USAGE,
					    "sandbox path buffer too small",
					    path, 0);
				dst[0] = '/';
				dst[1] = '\0';
				return 0;
			}
			if (i > dst_len)
				return fail_error(
				    err, ARK_ERR_USAGE,
				    "sandbox path buffer too small", path, 0);
			for (j = 0; j + 1 < i; j++)
				dst[j] = path[j];
			dst[i - 1] = '\0';
			return 0;
		}
	}

	if (dst_len < 2)
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox path buffer too small", path, 0);
	dst[0] = '.';
	dst[1] = '\0';
	return 0;
}

/*
 * print_warning - Emit warning text to stderr and syslog.
 *
 * ARCHITECTURE.md section 11 requires yellow ANSI warnings on TTY stderr.
 * TECH_STACK.md section 3.5 requires diagnostic mirroring to syslog.
 */
static void print_warning(const char *msg, const char *path)
{
	int color;

	if (path != NULL && path[0] != '\0')
		syslog(LOG_WARNING, "%s: %s", msg, path);
	else
		syslog(LOG_WARNING, "%s", msg);

	color = isatty(STDERR_FILENO);
	if (color)
		(void)fputs("\033[33m", stderr);
	(void)fputs("ark: warning: ", stderr);
	(void)fputs(msg, stderr);
	if (path != NULL && path[0] != '\0') {
		(void)fputs(": ", stderr);
		(void)fputs(path, stderr);
	}
	if (color)
		(void)fputs("\033[0m", stderr);
	(void)fputc('\n', stderr);
}

/*
 * print_error - Emit ark_error_t to stderr and syslog.
 *
 * ARCHITECTURE.md section 11 requires red ANSI errors on TTY stderr.
 */
static void print_error(const ark_error_t *err)
{
	int color;

	if (err == NULL)
		return;

	if (err->path[0] != '\0' && err->sys_errno != 0)
		syslog(LOG_ERR, "%s: %s (errno=%d: %s)", err->msg, err->path,
		       err->sys_errno, strerror(err->sys_errno));
	else if (err->path[0] != '\0')
		syslog(LOG_ERR, "%s: %s", err->msg, err->path);
	else if (err->sys_errno != 0)
		syslog(LOG_ERR, "%s (errno=%d: %s)", err->msg, err->sys_errno,
		       strerror(err->sys_errno));
	else
		syslog(LOG_ERR, "%s", err->msg);

	color = isatty(STDERR_FILENO);
	if (color)
		(void)fputs("\033[31m", stderr);
	(void)fputs("ark: ", stderr);
	(void)fputs(err->msg, stderr);
	if (err->path[0] != '\0') {
		(void)fputs(": ", stderr);
		(void)fputs(err->path, stderr);
	}
	if (err->sys_errno != 0) {
		(void)fputs(" (", stderr);
		(void)fputs(strerror(err->sys_errno), stderr);
		(void)fputc(')', stderr);
	}
	if (color)
		(void)fputs("\033[0m", stderr);
	(void)fputc('\n', stderr);
}

/*
 * inode_hash - Hash a (dev, ino) key for the create hardlink table.
 *
 * The constants and key material come from ARCHITECTURE.md section 13.2.
 */
static uint64_t inode_hash(dev_t dev, ino_t ino)
{
	return ((uint64_t)dev * UINT64_C(2654435761)) ^ (uint64_t)ino;
}

/*
 * inode_table_init - Allocate the create hardlink detection table.
 *
 * Returns 0 on success or -1 with ARK_ERR_IO_ALLOC. The initial capacity is
 * the 4096-slot requirement from ARCHITECTURE.md section 13.2.
 */
static int inode_table_init(inode_table_t *table, ark_error_t *err)
{
	table->capacity = 4096U;
	table->count = 0U;
	/* OWNERSHIP: table owns slots and releases them in inode_table_free. */
	table->slots = calloc(table->capacity, sizeof(table->slots[0]));
	if (table->slots == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "inode table allocation failed", "", 0);
	return 0;
}

/*
 * inode_table_free - Release hardlink table storage owned by traversal.
 */
static void inode_table_free(inode_table_t *table)
{
	free(table->slots);
	table->slots = NULL;
	table->capacity = 0U;
	table->count = 0U;
}

/*
 * inode_table_lookup - Return first-seen member path for an inode key.
 *
 * Returns NULL when the inode has not been recorded. The returned pointer is
 * table-owned and valid until inode_table_free.
 */
static const char *inode_table_lookup(const inode_table_t *table, dev_t dev,
                                      ino_t ino)
{
	size_t i;
	size_t pos;

	if (ino == 0 || table->capacity == 0U)
		return NULL;
	pos = (size_t)(inode_hash(dev, ino) % table->capacity);
	for (i = 0U; i < table->capacity; i++) {
		inode_slot_t *slot;

		slot = &table->slots[(pos + i) % table->capacity];
		if (slot->ino == 0)
			return NULL;
		if (slot->ino == ino && slot->dev == dev)
			return slot->path;
	}
	return NULL;
}

/*
 * inode_table_place - Insert one slot into a table with known free capacity.
 */
static void inode_table_place(inode_slot_t *slots, size_t capacity, dev_t dev,
                              ino_t ino, const char *path)
{
	size_t i;
	size_t pos;

	pos = (size_t)(inode_hash(dev, ino) % capacity);
	for (i = 0U; i < capacity; i++) {
		inode_slot_t *slot;

		slot = &slots[(pos + i) % capacity];
		if (slot->ino != 0)
			continue;
		slot->dev = dev;
		slot->ino = ino;
		copy_msg(slot->path, sizeof(slot->path), path);
		return;
	}
}

/*
 * inode_table_grow - Double hardlink table capacity at 0.75 load factor.
 *
 * OWNERSHIP: on success, ownership transfers from the old slots allocation to
 * the new allocation; on failure, the original table remains owned by table.
 */
static int inode_table_grow(inode_table_t *table, ark_error_t *err)
{
	inode_slot_t *new_slots;
	size_t new_cap;
	size_t i;

	new_cap = table->capacity * 2U;
	/* OWNERSHIP: new_slots replaces table->slots after successful rehash.
	 */
	new_slots = calloc(new_cap, sizeof(new_slots[0]));
	if (new_slots == NULL)
		return fail_error(err, ARK_ERR_IO_ALLOC,
		                  "inode table resize failed", "", 0);
	for (i = 0U; i < table->capacity; i++) {
		inode_slot_t *slot;

		slot = &table->slots[i];
		if (slot->ino != 0)
			inode_table_place(new_slots, new_cap, slot->dev,
			                  slot->ino, slot->path);
	}
	free(table->slots);
	table->slots = new_slots;
	table->capacity = new_cap;
	return 0;
}

/*
 * inode_table_insert - Record first-seen path for a regular-file inode.
 *
 * The table is open-addressed with linear probing as specified by
 * ARCHITECTURE.md section 13.2.
 */
static int inode_table_insert(inode_table_t *table, dev_t dev, ino_t ino,
                              const char *path, ark_error_t *err)
{
	if (ino == 0)
		return 0;
	if ((table->count + 1U) * 4U > table->capacity * 3U) {
		if (inode_table_grow(table, err) != 0)
			return -1;
	}
	inode_table_place(table->slots, table->capacity, dev, ino, path);
	table->count++;
	return 0;
}

/*
 * path_join - Join an absolute parent path and one directory entry name.
 */
static int path_join(const char *parent, const char *name, char *dst,
                     size_t dst_len, ark_error_t *err)
{
	size_t plen;
	size_t nlen;
	size_t need;

	plen = strlen(parent);
	nlen = strlen(name);
	need = plen + nlen + 2U;
	if (strcmp(parent, "/") == 0)
		need--;
	if (need > dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "filesystem path too long", parent, 0);
	dst[0] = '\0';
	if (strcmp(parent, "/") == 0) {
		dst[0] = '/';
		copy_msg(dst + 1U, dst_len - 1U, name);
	} else {
		copy_msg(dst, dst_len, parent);
		dst[plen] = '/';
		copy_msg(dst + plen + 1U, dst_len - plen - 1U, name);
	}
	return 0;
}

/*
 * member_path_from_abs - Strip resolved source root from an absolute path.
 *
 * The root directory itself is omitted by callers; this helper maps only
 * descendants to clean relative member paths per ARCHITECTURE.md section 13.6.
 */
static int member_path_from_abs(const char *root, const char *abs_path,
                                char *dst, size_t dst_len, ark_error_t *err)
{
	size_t rlen;
	const char *rel;
	size_t rel_len;

	rlen = strlen(root);
	if (strcmp(root, "/") == 0) {
		rel = abs_path + 1;
		rel_len = strlen(rel);
	} else {
		if (strncmp(abs_path, root, rlen) != 0 || abs_path[rlen] != '/')
			return fail_error(err, ARK_ERR_USAGE,
			                  "path outside traversal root",
			                  abs_path, 0);
		rel = abs_path + rlen + 1U;
		rel_len = strlen(rel);
	}
	if (rel_len == 0U || rel_len >= dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "member path too long", abs_path, 0);
	copy_msg(dst, dst_len, rel);
	return 0;
}

/*
 * basename_member_path - Derive the member name for a single-file source.
 */
static int basename_member_path(const char *abs_path, char *dst, size_t dst_len,
                                ark_error_t *err)
{
	const char *base;

	base = strrchr(abs_path, '/');
	if (base == NULL)
		base = abs_path;
	else
		base++;
	if (base[0] == '\0' || strlen(base) >= dst_len)
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "member path too long", abs_path, 0);
	copy_msg(dst, dst_len, base);
	return 0;
}

/*
 * stat_mtime_nsec - Convert struct stat mtime to archive u64 nanoseconds.
 *
 * Uses signed 64-bit arithmetic and rejects unrepresentable timestamps as
 * required by ARCHITECTURE.md section 5.2.
 */
static int stat_mtime_nsec(const struct stat *sb, const char *path,
                           uint64_t *out, ark_error_t *err)
{
	int64_t sec;
	int64_t nsec;
	int64_t base;
	int64_t total;

	sec = (int64_t)sb->st_mtim.tv_sec;
	nsec = (int64_t)sb->st_mtim.tv_nsec;
	if (sec > INT64_C(9223372036) || sec < -INT64_C(9223372036))
		return fail_error(err, ARK_ERR_IO_READ,
		                  "mtime outside representable range", path, 0);
	base = sec * INT64_C(1000000000);
	if (base > INT64_MAX - nsec)
		return fail_error(err, ARK_ERR_IO_READ,
		                  "mtime outside representable range", path, 0);
	total = base + nsec;
	*out = (uint64_t)total;
	return 0;
}

/*
 * member_meta_init - Populate common metadata from lstat output.
 *
 * See ARCHITECTURE.md section 5.2 for raw mode, uid, gid, and mtime fields.
 */
static int member_meta_init(ark_member_meta_t *meta, uint8_t type,
                            const char *member_path, const struct stat *sb,
                            ark_error_t *err)
{
	*meta = (ark_member_meta_t){0};
	meta->type = type;
	meta->mode = (uint32_t)(sb->st_mode & 0xffffU);
	meta->uid = (uint32_t)sb->st_uid;
	meta->gid = (uint32_t)sb->st_gid;
	if (stat_mtime_nsec(sb, member_path, &meta->mtime, err) != 0)
		return -1;
	copy_msg(meta->path, sizeof(meta->path), member_path);
	return 0;
}

/*
 * emit_nonfile_member - Write a directory, symlink, or hardlink index member.
 *
 * Non-file members have no data body; ark_write_member_end finalizes the hash
 * of the empty byte sequence. See ARCHITECTURE.md sections 5.2 and 16.3.
 */
static int emit_nonfile_member(traverse_ctx_t *ctx,
                               const ark_member_meta_t *meta, ark_error_t *err)
{
	if (ark_write_member_begin(ctx->write_ctx, meta, err) != 0)
		return -1;
	return ark_write_member_end(ctx->write_ctx, err);
}

/*
 * chevron_write_or_fail - Write one serialized chunk to the archive handle.
 */
static int chevron_write_or_fail(chevron_handle_t *handle, const void *buf,
                                 size_t len, const char *path, ark_error_t *err)
{
	chevron_error_t cerr = {0};

	if (chevron_write_chunk(handle, buf, len, &cerr) != 0)
		return fail_error(err, ARK_ERR_IO_WRITE,
		                  "archive chunk write failed", path,
		                  cerr.errno_value);
	return 0;
}

/*
 * emit_regular_file - Compress and write one regular-file member.
 *
 * Single-threaded Phase 5 compression happens directly in traversal. The
 * per-chunk buffers are traversal-owned and allocated before this hot path.
 * See ARCHITECTURE.md sections 13.1 and 16.3.
 */
static int emit_regular_file(traverse_ctx_t *ctx, const char *abs_path,
                             const char *member_path, const struct stat *sb,
                             ark_error_t *err)
{
	ark_member_meta_t meta;
	struct stat meta_sb;
	ssize_t n;
	ssize_t written;
	uint64_t remaining;
	uint64_t submit_seq;
	uint64_t drain_seq;
	size_t want;
	size_t got;
	size_t in_flight;
	size_t max_in_flight;
	int fd = -1;
	int rc = -1;
	uint8_t *slot_data;
	size_t slot_len;
	int slot_abort;
	ark_err_t slot_worker_err;

	if (sb->st_size < 0)
		return fail_error(err, ARK_ERR_IO_READ, "negative file size",
		                  abs_path, 0);
	if (member_meta_init(&meta, 0x01U, member_path, sb, err) != 0)
		return -1;
	meta.size_original = (uint64_t)sb->st_size;
	if (meta.size_original != 0U)
		meta.data_offset = *ctx->output_offset;

	/*
	 * SAFETY: O_NOFOLLOW is required on extraction output
	 * opens to prevent symlink substitution races. See
	 * ARCHITECTURE.md section 14.2.
	 */
	fd = ARK_OPEN(abs_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
	if (fd == -1) {
		if (errno == EACCES || errno == EPERM) {
			print_warning("permission denied", abs_path);
			ctx->permission_error = 1;
			return 0;
		}
		return fail_error(err, ARK_ERR_IO_READ,
		                  "member file open failed", abs_path, errno);
	}

	if (ark_write_member_begin(ctx->write_ctx, &meta, err) != 0)
		goto cleanup;

	/*
	 * SAFETY: input, compression, and write buffers are allocated by
	 * traverse_dir before entering the per-chunk loop; no hot-path
	 * allocation.
	 */
	remaining = meta.size_original;
	submit_seq = 0U;
	drain_seq = 0U;
	in_flight = 0U;
	max_in_flight = (size_t)ctx->pool->n_workers;
	if (max_in_flight == 0U) {
		rc = fail_error(err, ARK_ERR_USAGE,
		                "create worker pool has zero workers", abs_path,
		                0);
		goto cleanup;
	}
	while (remaining > 0U) {
		want = remaining > (uint64_t)ARK_CHUNK_SIZE
		           ? (size_t)ARK_CHUNK_SIZE
		           : (size_t)remaining;
		got = 0U;
		while (got < want) {
			n = ARK_READ(fd, ctx->input_buf + got, want - got);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				rc = fail_error(err, ARK_ERR_IO_READ,
				                "member file read failed",
				                abs_path, errno);
				goto cleanup;
			}
			if (n == 0) {
				rc = fail_error(err, ARK_ERR_IO_READ,
				                "member file ended early",
				                abs_path, 0);
				goto cleanup;
			}
			got += (size_t)n;
		}

		if (pool_submit(ctx->pool, submit_seq, ctx->input_buf, want,
		                ctx->deflate_mode) != 0) {
			if (__atomic_load_n(
			        (int *)&ctx->pool->shared_err.recorded,
			        __ATOMIC_ACQUIRE) != 0)
				*err = ctx->pool->shared_err.error;
			else
				rc = fail_error(err, ARK_ERR_IO_WRITE,
				                "create worker submit failed",
				                abs_path, 0);
			goto cleanup;
		}
		submit_seq++;
		in_flight++;

		while (in_flight >= max_in_flight) {
			slot_data = NULL;
			if (ring_buf_read(ctx->pool->ring, drain_seq,
			                  &slot_data, &slot_len, &slot_abort,
			                  &slot_worker_err, err) != 0)
				goto cleanup;
			if (slot_abort) {
				if (__atomic_load_n(
				        (int *)&ctx->pool->shared_err.recorded,
				        __ATOMIC_ACQUIRE) != 0)
					*err = ctx->pool->shared_err.error;
				else if (slot_worker_err != ARK_OK)
					(void)fail_error(
					    err, slot_worker_err,
					    "create worker aborted", abs_path,
					    0);
				else
					(void)fail_error(
					    err, ARK_ERR_IO_WRITE,
					    "create worker aborted", abs_path,
					    0);
				ring_buf_release(ctx->pool->ring, drain_seq);
				goto cleanup;
			}
			/*
			 * SAFETY: ark_write_chunk is called only by the I/O
			 * path and ring slots are drained strictly in sequence
			 * order. See ARCHITECTURE.md sections 6.3 and 16.3.
			 */
			written =
			    ark_write_chunk(ctx->write_ctx, slot_data, slot_len,
			                    ctx->write_buf, ctx->comp_cap, err);
			if (written < 0) {
				ring_buf_release(ctx->pool->ring, drain_seq);
				goto cleanup;
			}
			if (chevron_write_or_fail(
			        ctx->chev_handle, ctx->write_buf,
			        (size_t)written, abs_path, err) != 0) {
				ring_buf_release(ctx->pool->ring, drain_seq);
				goto cleanup;
			}
			if (UINT64_MAX - *ctx->output_offset <
			    (uint64_t)written) {
				ring_buf_release(ctx->pool->ring, drain_seq);
				rc = fail_error(err, ARK_ERR_USAGE,
				                "archive offset overflow",
				                abs_path, 0);
				goto cleanup;
			}
			*ctx->output_offset += (uint64_t)written;
			ring_buf_release(ctx->pool->ring, drain_seq);
			drain_seq++;
			in_flight--;
		}
		remaining -= want;
	}
	while (in_flight > 0U) {
		slot_data = NULL;
		if (ring_buf_read(ctx->pool->ring, drain_seq, &slot_data,
		                  &slot_len, &slot_abort, &slot_worker_err,
		                  err) != 0)
			goto cleanup;
		if (slot_abort) {
			if (__atomic_load_n(
			        (int *)&ctx->pool->shared_err.recorded,
			        __ATOMIC_ACQUIRE) != 0)
				*err = ctx->pool->shared_err.error;
			else if (slot_worker_err != ARK_OK)
				(void)fail_error(err, slot_worker_err,
				                 "create worker aborted",
				                 abs_path, 0);
			else
				(void)fail_error(err, ARK_ERR_IO_WRITE,
				                 "create worker aborted",
				                 abs_path, 0);
			ring_buf_release(ctx->pool->ring, drain_seq);
			goto cleanup;
		}
		written = ark_write_chunk(ctx->write_ctx, slot_data, slot_len,
		                          ctx->write_buf, ctx->comp_cap, err);
		if (written < 0) {
			ring_buf_release(ctx->pool->ring, drain_seq);
			goto cleanup;
		}
		if (chevron_write_or_fail(ctx->chev_handle, ctx->write_buf,
		                          (size_t)written, abs_path,
		                          err) != 0) {
			ring_buf_release(ctx->pool->ring, drain_seq);
			goto cleanup;
		}
		if (UINT64_MAX - *ctx->output_offset < (uint64_t)written) {
			ring_buf_release(ctx->pool->ring, drain_seq);
			rc = fail_error(err, ARK_ERR_USAGE,
			                "archive offset overflow", abs_path, 0);
			goto cleanup;
		}
		*ctx->output_offset += (uint64_t)written;
		ring_buf_release(ctx->pool->ring, drain_seq);
		drain_seq++;
		in_flight--;
	}

	/*
	 * ARCHITECTURE.md section 13.4: compare pre-read lstat metadata with
	 * post-read fstat metadata on the same fd to detect source changes
	 * during archiving.
	 */
	if (ARK_FSTAT(fd, &meta_sb) != 0) {
		rc = fail_error(err, ARK_ERR_IO_READ,
		                "member file fstat failed", abs_path, errno);
		goto cleanup;
	}
	if (meta_sb.st_size != sb->st_size ||
	    meta_sb.st_mtim.tv_sec != sb->st_mtim.tv_sec ||
	    meta_sb.st_mtim.tv_nsec != sb->st_mtim.tv_nsec) {
		print_warning("source file modified during read", abs_path);
		if (modified_path_list_push(ctx->modified_paths, abs_path,
		                            err) != 0) {
			rc = -1;
			goto cleanup;
		}
	}

	if (ark_write_member_end(ctx->write_ctx, err) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (fd != -1 && ARK_CLOSE(fd) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_READ,
		                "member file close failed", abs_path, errno);
	return rc;
}

/*
 * emit_hardlink_member - Record a later path to a first-seen regular file.
 *
 * See ARCHITECTURE.md section 13.2 for first-seen hardlink target behavior.
 */
static int emit_hardlink_member(traverse_ctx_t *ctx, const char *member_path,
                                const char *target_path, const struct stat *sb,
                                ark_error_t *err)
{
	ark_member_meta_t meta;

	if (member_meta_init(&meta, 0x04U, member_path, sb, err) != 0)
		return -1;
	copy_msg(meta.link, sizeof(meta.link), target_path);
	return emit_nonfile_member(ctx, &meta, err);
}

/*
 * emit_symlink_member - Read and store one symlink target without following it.
 *
 * readlink is used after lstat classification. See ARCHITECTURE.md section
 * 13.3 for the symlink-never-followed rule.
 */
static int emit_symlink_member(traverse_ctx_t *ctx, const char *abs_path,
                               const char *member_path, const struct stat *sb,
                               ark_error_t *err)
{
	ark_member_meta_t meta;
	ssize_t n;

	if (member_meta_init(&meta, 0x03U, member_path, sb, err) != 0)
		return -1;
	n = ARK_READLINK(abs_path, meta.link, sizeof(meta.link));
	if (n < 0)
		return fail_error(err, ARK_ERR_IO_READ, "symlink read failed",
		                  abs_path, errno);
	if ((size_t)n >= sizeof(meta.link))
		return fail_error(err, ARK_ERR_PATH_TOO_LONG,
		                  "symlink target too long", abs_path, 0);
	meta.link[n] = '\0';
	return emit_nonfile_member(ctx, &meta, err);
}

/*
 * dir_entry_cmp - qsort comparator using raw byte-order filename comparison.
 */
static int dir_entry_cmp(const void *a, const void *b)
{
	const char *const *sa;
	const char *const *sb;
	size_t la;
	size_t lb;
	size_t min;
	int cmp;

	sa = (const char *const *)a;
	sb = (const char *const *)b;
	la = strlen(*sa);
	lb = strlen(*sb);
	min = la < lb ? la : lb;
	cmp = memcmp(*sa, *sb, min);
	if (cmp != 0)
		return cmp;
	if (la < lb)
		return -1;
	if (la > lb)
		return 1;
	return 0;
}

/*
 * dir_entry_list_free - Release names collected from one directory level.
 */
static void dir_entry_list_free(dir_entry_list_t *list)
{
	size_t i;

	for (i = 0U; i < list->count; i++)
		free(list->names[i]);
	free((void *)list->names);
	list->names = NULL;
	list->count = 0U;
	list->capacity = 0U;
}

/*
 * dir_entry_name_dup - Copy a readdir d_name into list-owned storage.
 */
static char *dir_entry_name_dup(const char *name)
{
	char *copy;
	size_t len;

	len = strlen(name);
	/* OWNERSHIP: returned name is freed by dir_entry_list_free after push.
	 */
	copy = calloc(len + 1U, 1U);
	if (copy == NULL)
		return NULL;
	copy_msg(copy, len + 1U, name);
	return copy;
}

/*
 * dir_entry_list_push - Append one owned name to a directory entry list.
 *
 * OWNERSHIP: on success, list owns name and frees it in dir_entry_list_free.
 */
static int dir_entry_list_push(dir_entry_list_t *list, char *name,
                               ark_error_t *err)
{
	char **new_names;

	if (list->count == list->capacity) {
		size_t new_cap;

		new_cap = list->capacity == 0U ? 32U : list->capacity * 2U;
		/* OWNERSHIP: list retains ownership across successful realloc.
		 */
		new_names = (char **)realloc((void *)list->names,
		                             new_cap * sizeof(list->names[0]));
		if (new_names == NULL) {
			free(name);
			return fail_error(err, ARK_ERR_IO_ALLOC,
			                  "directory entry allocation failed",
			                  "", 0);
		}
		list->names = new_names;
		list->capacity = new_cap;
	}
	list->names[list->count++] = name;
	return 0;
}

/*
 * dir_entries_collect - Read, own, and sort one directory's entry names.
 *
 * Entries '.' and '..' are discarded before sorting. Sorting uses raw
 * memcmp byte order as required by ARCHITECTURE.md section 13.1.
 */
static int dir_entries_collect(const char *abs_path, dir_entry_list_t *list,
                               ark_error_t *err)
{
	DIR *dir = NULL;
	const struct dirent *dent;
	char *name;
	int rc = -1;

	dir = ARK_OPENDIR(abs_path);
	if (dir == NULL) {
		if (errno == EACCES || errno == EPERM)
			return 1;
		return fail_error(err, ARK_ERR_IO_READ, "directory open failed",
		                  abs_path, errno);
	}

	errno = 0;
	while ((dent = ARK_READDIR(dir)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		name = dir_entry_name_dup(dent->d_name);
		if (name == NULL) {
			rc = fail_error(err, ARK_ERR_IO_ALLOC,
			                "directory entry allocation failed",
			                abs_path, 0);
			goto cleanup;
		}
		if (dir_entry_list_push(list, name, err) != 0)
			goto cleanup;
	}
	if (errno != 0) {
		if (errno == EACCES || errno == EPERM) {
			rc = 1;
			goto cleanup;
		}
		rc = fail_error(err, ARK_ERR_IO_READ, "directory read failed",
		                abs_path, errno);
		goto cleanup;
	}
	/*
	 * SAFETY: entries are sorted before processing or recursion to preserve
	 * deterministic archive output. See ARCHITECTURE.md section 13.1.
	 */
	if (list->count > 1U)
		qsort((void *)list->names, list->count, sizeof(list->names[0]),
		      dir_entry_cmp);
	rc = 0;

cleanup:
	if (dir != NULL && ARK_CLOSEDIR(dir) != 0 && rc == 0)
		rc = fail_error(err, ARK_ERR_IO_READ, "directory close failed",
		                abs_path, errno);
	if (rc != 0)
		dir_entry_list_free(list);
	return rc;
}

/*
 * traverse_directory_abs - Depth-first traversal of one absolute directory.
 *
 * The directory itself is already emitted by traverse_entry except for the
 * source root, which is intentionally omitted per ARCHITECTURE.md section
 * 13.6.
 */
static int traverse_directory_abs(traverse_ctx_t *ctx, const char *abs_path,
                                  const char *member_path, ark_error_t *err)
{
	dir_entry_list_t list = {0};
	char child_abs[PATH_MAX];
	char child_member[1024];
	size_t i;
	int rc;

	(void)member_path;
	rc = dir_entries_collect(abs_path, &list, err);
	if (rc == 1) {
		print_warning("permission denied", abs_path);
		ctx->permission_error = 1;
		return 0;
	}
	if (rc != 0)
		return -1;

	for (i = 0U; i < list.count; i++) {
		if (path_join(abs_path, list.names[i], child_abs,
		              sizeof(child_abs), err) != 0)
			goto fail;
		if (member_path_from_abs(ctx->root, child_abs, child_member,
		                         sizeof(child_member), err) != 0)
			goto fail;
		if (traverse_entry(ctx, child_abs, child_member, err) != 0)
			goto fail;
	}
	dir_entry_list_free(&list);
	return 0;

fail:
	dir_entry_list_free(&list);
	return -1;
}

/*
 * traverse_entry - Classify and emit one filesystem entry.
 *
 * Uses ARK_LSTAT only, so symlinks encountered inside the tree are never
 * followed. See ARCHITECTURE.md sections 13.1, 13.3, 13.7, and 13.9.
 */
static int traverse_entry(traverse_ctx_t *ctx, const char *abs_path,
                          const char *member_path, ark_error_t *err)
{
	ark_member_meta_t meta;
	struct stat sb;

	/* SAFETY: lstat classifies the entry without following symlinks. */
	if (ARK_LSTAT(abs_path, &sb) != 0) {
		if (errno == EACCES || errno == EPERM) {
			print_warning("permission denied", abs_path);
			ctx->permission_error = 1;
			return 0;
		}
		return fail_error(err, ARK_ERR_IO_READ, "lstat failed",
		                  abs_path, errno);
	}

	if (S_ISDIR(sb.st_mode)) {
		/*
		 * SAFETY: do not recurse across device boundaries; a mount
		 * point is skipped with a warning. See ARCHITECTURE.md
		 * section 13.7.
		 */
		if (sb.st_dev != ctx->root_dev) {
			print_warning("skipping mount point", abs_path);
			return 0;
		}
		if (member_meta_init(&meta, 0x02U, member_path, &sb, err) != 0)
			return -1;
		if (emit_nonfile_member(ctx, &meta, err) != 0)
			return -1;
		return traverse_directory_abs(ctx, abs_path, member_path, err);
	}

	if (S_ISREG(sb.st_mode)) {
		const char *target;

		/* ARCHITECTURE.md section 13.2: first inode stores data; later
		 * matches become hardlink members. */
		target = inode_table_lookup(&ctx->inodes, sb.st_dev, sb.st_ino);
		if (target != NULL)
			return emit_hardlink_member(ctx, member_path, target,
			                            &sb, err);
		if (sb.st_nlink > 1) {
			if (inode_table_insert(&ctx->inodes, sb.st_dev,
			                       sb.st_ino, member_path,
			                       err) != 0)
				return -1;
		}
		return emit_regular_file(ctx, abs_path, member_path, &sb, err);
	}

	if (S_ISLNK(sb.st_mode))
		return emit_symlink_member(ctx, abs_path, member_path, &sb,
		                           err);

	/* ARCHITECTURE.md section 13.9: unsupported special objects are
	 * skipped. */
	print_warning("skipping special filesystem object", abs_path);
	return 0;
}

/*
 * traverse_dir - Resolve and archive one create source path.
 *
 * Resolves the source path once with ARK_REALPATH, strips that resolved root
 * from all descendant member paths, and walks directories depth-first in
 * deterministic byte order. Returns 0 on success or -1 with err populated.
 *
 * Preconditions: write_ctx is initialized, header has been written, and
 * chev_handle is an active libchevron streaming handle. See ARCHITECTURE.md
 * sections 13.1, 13.2, 13.6, and 16.3.
 */
static int traverse_dir(const char *src_path, ark_write_ctx_t *write_ctx,
                        chevron_handle_t *chev_handle, ark_pool_t *pool,
                        ark_deflate_mode_t deflate_mode,
                        uint64_t *output_offset,
                        modified_path_list_t *modified_paths, ark_error_t *err)
{
	traverse_ctx_t ctx;
	struct stat sb;
	char member_path[1024];
	int rc = -1;

	ctx = (traverse_ctx_t){0};
	ctx.write_ctx = write_ctx;
	ctx.chev_handle = chev_handle;
	ctx.pool = pool;
	ctx.deflate_mode = deflate_mode;
	ctx.output_offset = output_offset;
	ctx.modified_paths = modified_paths;

	if (src_path == NULL || write_ctx == NULL || chev_handle == NULL ||
	    pool == NULL || output_offset == NULL || modified_paths == NULL)
		return fail_error(err, ARK_ERR_USAGE,
		                  "invalid traversal argument", "", 0);
	if (ARK_REALPATH(src_path, ctx.root) == NULL)
		return fail_error(err, ARK_ERR_IO_READ,
		                  "source path resolution failed", src_path,
		                  errno);
	if (ARK_LSTAT(ctx.root, &sb) != 0)
		return fail_error(err, ARK_ERR_IO_READ, "lstat failed",
		                  ctx.root, errno);
	ctx.root_dev = sb.st_dev;

	if (inode_table_init(&ctx.inodes, err) != 0)
		goto cleanup;
	/* OWNERSHIP: traversal owns chunk buffers and frees them at cleanup. */
	ctx.input_buf = malloc(ARK_CHUNK_SIZE);
	ctx.comp_cap = ark_deflate_bound(ARK_CHUNK_SIZE);
	ctx.comp_buf = malloc(ctx.comp_cap);
	ctx.write_buf = malloc(ctx.comp_cap);
	if (ctx.input_buf == NULL || ctx.comp_buf == NULL ||
	    ctx.write_buf == NULL) {
		(void)fail_error(err, ARK_ERR_IO_ALLOC,
		                 "traversal buffer allocation failed", "", 0);
		goto cleanup;
	}

	if (S_ISDIR(sb.st_mode)) {
		/* ARCHITECTURE.md section 13.6: source root directory is
		 * omitted. */
		if (traverse_directory_abs(&ctx, ctx.root, "", err) != 0)
			goto cleanup;
	} else {
		if (basename_member_path(ctx.root, member_path,
		                         sizeof(member_path), err) != 0)
			goto cleanup;
		if (traverse_entry(&ctx, ctx.root, member_path, err) != 0)
			goto cleanup;
	}

	if (ctx.permission_error) {
		(void)fail_error(err, ARK_ERR_IO_READ,
		                 "permission errors during traversal", src_path,
		                 0);
		goto cleanup;
	}
	rc = 0;

cleanup:
	free(ctx.write_buf);
	free(ctx.comp_buf);
	free(ctx.input_buf);
	inode_table_free(&ctx.inodes);
	return rc;
}

#ifdef __linux__
/*
 * landlock_read_rights - Filesystem read rights used by all readers.
 */
static uint64_t landlock_read_rights(void)
{
	return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

/*
 * landlock_create_rights - Create writer rights for create/generate-reader.
 *
 * See ARCHITECTURE.md section 10.4 policy table.
 */
static uint64_t landlock_create_rights(int abi)
{
	uint64_t rights;

	/*
	 * libchevron commit uses rename + temp cleanup in output parent, so
	 * create needs REFER and REMOVE_FILE in addition to write/create
	 * rights. See ARCHITECTURE.md section 10.4.
	 */
	rights = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	         LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		rights |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
	return rights;
}

/*
 * landlock_extract_rights - Extract writer rights for destination dir.
 *
 * See ARCHITECTURE.md section 10.4 (remove-file/remove-dir/refer notes).
 */
static uint64_t landlock_extract_rights(int abi)
{
	uint64_t rights;

	rights = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	         LANDLOCK_ACCESS_FS_REMOVE_FILE |
	         LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	         LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		rights |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
	return rights;
}

/*
 * landlock_detect_abi - Query Landlock ABI version and enforce Linux minimum.
 *
 * If Landlock is unavailable, fail immediately with the minimum kernel message
 * required by ARCHITECTURE.md section 10.4.
 */
static int landlock_detect_abi(ark_error_t *err)
{
	int abi;

	/*
	 * Linux ABI contract: LANDLOCK_CREATE_RULESET_VERSION probe requires
	 * attr=NULL and size=0, otherwise EINVAL even when Landlock exists.
	 */
	abi = (int)syscall(SYS_landlock_create_ruleset, (void *)0, 0,
	                   LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock unavailable; minimum supported "
		                  "kernel is Linux 5.13",
		                  "", errno);
	return abi;
}

/*
 * landlock_add_path_rule - Add one path-beneath rule for a sandboxed path.
 */
static int landlock_add_path_rule(int ruleset_fd, const char *path,
                                  uint64_t rights, ark_error_t *err)
{
	struct landlock_path_beneath_attr rule = {0};
	int path_fd;

	path_fd = ARK_OPEN(path, O_RDONLY | O_CLOEXEC, 0);
	if (path_fd == -1)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "sandbox path open failed", path, errno);

	rule.allowed_access = rights;
	rule.parent_fd = path_fd;
	if (syscall(SYS_landlock_add_rule, ruleset_fd,
	            LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0) {
		(void)ARK_CLOSE(path_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock add rule failed", path, errno);
	}

	if (ARK_CLOSE(path_fd) != 0)
		return fail_error(err, ARK_ERR_IO_OPEN,
		                  "sandbox path close failed", path, errno);
	return 0;
}
#endif

/*
 * sandbox_apply - Apply per-subcommand sandbox policy.
 *
 * src_paths/src_count are used by create so all source roots are registered in
 * one additive policy application. dst_path is extract --output or
 * generate-reader output path depending on cmd.
 *
 * Returns 0 on success, -1 on error with err populated.
 *
 * See ARCHITECTURE.md section 10.4 for policy strings and path scope.
 */
static int sandbox_apply(ark_cmd_t cmd, const char **src_paths, int src_count,
                         const char *archive_path, const char *dst_path,
                         ark_error_t *err)
{
#ifdef __OpenBSD__
	int i;
	char parent[PATH_MAX];

	/*
	 * OpenBSD policy mapping per subcommand. See ARCHITECTURE.md section
	 * 10.4.
	 */
	switch (cmd) {
	case ARK_CMD_CREATE:
		if (archive_path == NULL)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "create archive path missing for sandbox", "", 0);
		for (i = 0; i < src_count; i++) {
			if (unveil(src_paths[i], "r") != 0)
				return fail_error(
				    err, ARK_ERR_USAGE,
				    "unveil failed for create source path",
				    src_paths[i], errno);
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) != 0)
			return -1;
		if (unveil(parent, "rwc") != 0)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "unveil failed for create destination parent",
			    parent, errno);
		/*
		 * SAFETY: lock unveil before pledge so no broader path view
		 * remains reachable after process promises are reduced.
		 */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath wpath cpath fattr pthread", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_EXTRACT:
		if (archive_path == NULL || dst_path == NULL)
			return fail_error(err, ARK_ERR_USAGE,
			                  "extract paths missing for sandbox",
			                  "", 0);
		if (unveil(archive_path, "r") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for archive path",
			                  archive_path, errno);
		if (unveil(dst_path, "rwc") != 0)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "unveil failed for extract destination", dst_path,
			    errno);
		/*
		 * SAFETY: lock unveil before pledge to keep extraction path
		 * scope immutable. See ARCHITECTURE.md section 10.4.
		 */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath wpath cpath fattr pthread", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_LIST:
	case ARK_CMD_VERIFY:
		if (archive_path == NULL)
			return fail_error(err, ARK_ERR_USAGE,
			                  "archive path missing for sandbox",
			                  "", 0);
		if (unveil(archive_path, "r") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for archive path",
			                  archive_path, errno);
		/* SAFETY: lock unveil before pledge to keep read scope
		 * immutable. */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		if (pledge("stdio rpath", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	case ARK_CMD_GENERATE_READER:
		if (dst_path == NULL)
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "generate-reader output path missing for sandbox",
			    "", 0);
		if (parent_dir(dst_path, parent, sizeof(parent), err) != 0)
			return -1;
		if (unveil(parent, "rwc") != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil failed for output parent",
			                  parent, errno);
		/* SAFETY: lock unveil before pledge to keep write scope
		 * immutable. */
		if (unveil(NULL, NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE,
			                  "unveil lock failed", "", errno);
		/*
		 * NOTE: libchevron opens the output parent directory read-only
		 * in chevron_open(), so generate-reader requires rpath in
		 * addition to wpath/cpath under pledge. commit also applies
		 * ownership/mode (fchown/fchmod), which requires fattr.
		 */
		if (pledge("stdio rpath wpath cpath fattr", NULL) != 0)
			return fail_error(err, ARK_ERR_USAGE, "pledge failed",
			                  "", errno);
		return 0;
	default:
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox policy unavailable for subcommand",
		                  "", 0);
	}
#elif defined(__linux__)
	int abi;
	int ruleset_fd;
	int i;
	uint64_t handled;
	struct landlock_ruleset_attr ruleset_attr = {0};
	char parent[PATH_MAX];

	abi = landlock_detect_abi(err);
	if (abi < 1)
		return -1;

	handled = landlock_read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
	          LANDLOCK_ACCESS_FS_REMOVE_FILE |
	          LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		handled |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif

	ruleset_attr.handled_access_fs = handled;
	ruleset_fd = (int)syscall(SYS_landlock_create_ruleset, &ruleset_attr,
	                          sizeof(ruleset_attr), 0);
	if (ruleset_fd == -1)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock ruleset creation failed", "",
		                  errno);

	switch (cmd) {
	case ARK_CMD_CREATE:
		if (archive_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "create archive path missing for sandbox", "", 0);
		}
		for (i = 0; i < src_count; i++) {
			if (landlock_add_path_rule(ruleset_fd, src_paths[i],
			                           landlock_read_rights(),
			                           err) != 0) {
				(void)ARK_CLOSE(ruleset_fd);
				return -1;
			}
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) !=
		    0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_create_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_EXTRACT:
		if (archive_path == NULL || dst_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(err, ARK_ERR_USAGE,
			                  "extract paths missing for sandbox",
			                  "", 0);
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) !=
		    0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_read_rights(), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, dst_path,
		                           landlock_extract_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_LIST:
	case ARK_CMD_VERIFY:
		if (archive_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(err, ARK_ERR_USAGE,
			                  "archive path missing for sandbox",
			                  "", 0);
		}
		if (parent_dir(archive_path, parent, sizeof(parent), err) !=
		    0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_read_rights(), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	case ARK_CMD_GENERATE_READER:
		if (dst_path == NULL) {
			(void)ARK_CLOSE(ruleset_fd);
			return fail_error(
			    err, ARK_ERR_USAGE,
			    "generate-reader output path missing for sandbox",
			    "", 0);
		}
		if (parent_dir(dst_path, parent, sizeof(parent), err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		if (landlock_add_path_rule(ruleset_fd, parent,
		                           landlock_create_rights(abi),
		                           err) != 0) {
			(void)ARK_CLOSE(ruleset_fd);
			return -1;
		}
		break;
	default:
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "sandbox policy unavailable for subcommand",
		                  "", 0);
	}

	/*
	 * SAFETY: PR_SET_NO_NEW_PRIVS must be active before Landlock
	 * enforcement. See ARCHITECTURE.md section 10.4.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "prctl(PR_SET_NO_NEW_PRIVS) failed", "",
		                  errno);
	}
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
		(void)ARK_CLOSE(ruleset_fd);
		return fail_error(err, ARK_ERR_USAGE,
		                  "landlock_restrict_self failed", "", errno);
	}
	if (ARK_CLOSE(ruleset_fd) != 0)
		return fail_error(err, ARK_ERR_USAGE,
		                  "Landlock ruleset close failed", "", errno);
	return 0;
#else
	(void)cmd;
	(void)src_paths;
	(void)src_count;
	(void)archive_path;
	(void)dst_path;
	return fail_error(err, ARK_ERR_USAGE,
	                  "sandbox unsupported on this platform", "", 0);
#endif
}

/*
 * args_init - Initialize parsed-argument defaults.
 *
 * See ARCHITECTURE.md section 12.2 for default hash and output behavior.
 */
static void args_init(ark_args_t *args)
{
	*args = (ark_args_t){0};
	args->hash_alg = ARK_HASH_BLAKE3;
	args->deflate_mode = ARK_DEFLATE_DEFAULT;
	args->output_path = ".";
	args->generate_reader_output = "recovery.c";
}

/*
 * args_free - Release parser-owned arrays.
 *
 * OWNERSHIP: parse_args allocates member_paths and create_paths arrays;
 * args_free releases both arrays exactly once.
 */
static void args_free(ark_args_t *args)
{
	free((void *)args->member_paths);
	args->member_paths = NULL;
	args->member_count = 0;

	free((void *)args->create_paths);
	args->create_paths = NULL;
	args->create_path_count = 0;
}

/*
 * parse_subcommand - Map CLI subcommand token to internal enum.
 */
static int parse_subcommand(const char *s, ark_cmd_t *cmd, ark_error_t *err)
{
	if (strcmp(s, "create") == 0) {
		*cmd = ARK_CMD_CREATE;
		return 0;
	}
	if (strcmp(s, "extract") == 0) {
		*cmd = ARK_CMD_EXTRACT;
		return 0;
	}
	if (strcmp(s, "list") == 0) {
		*cmd = ARK_CMD_LIST;
		return 0;
	}
	if (strcmp(s, "verify") == 0) {
		*cmd = ARK_CMD_VERIFY;
		return 0;
	}
	if (strcmp(s, "generate-reader") == 0) {
		*cmd = ARK_CMD_GENERATE_READER;
		return 0;
	}

	return usage_error(err, "unknown subcommand");
}

/*
 * parse_hash - Parse --hash value.
 */
static int parse_hash(const char *s, ark_hash_alg_t *hash_alg, ark_error_t *err)
{
	if (strcmp(s, "blake3") == 0) {
		*hash_alg = ARK_HASH_BLAKE3;
		return 0;
	}
	if (strcmp(s, "sha256") == 0) {
		*hash_alg = ARK_HASH_SHA256;
		return 0;
	}

	return usage_error(err, "invalid value for --hash");
}

/*
 * push_member - Append one --member path into parser-owned storage.
 */
static int push_member(ark_args_t *args, const char *member, int max_members,
                       ark_error_t *err)
{
	if ((int)args->member_count >= max_members)
		return usage_error(err, "too many --member arguments");
	args->member_paths[args->member_count++] = member;
	return 0;
}

/*
 * parse_args - Parse subcommand, flags, and operands into ark_args_t.
 *
 * Enforces ARCHITECTURE.md section 12.2 CLI surface and rejects invalid
 * flag/subcommand combinations with ARK_ERR_USAGE.
 */
static int parse_args(int argc, char **argv, ark_args_t *args, ark_error_t *err)
{
	int i;
	int max_items;
	int hash_seen;
	int output_seen;
	int operands_start;

	if (argc < 2)
		return usage_error(err, "missing subcommand");

	args_init(args);

	max_items = argc;
	args->member_paths = (const char **)calloc(
	    (size_t)max_items, sizeof(args->member_paths[0]));
	if (args->member_paths == NULL)
		return usage_error(err, "memory allocation failed");

	args->create_paths = (const char **)calloc(
	    (size_t)max_items, sizeof(args->create_paths[0]));
	if (args->create_paths == NULL) {
		args_free(args);
		return usage_error(err, "memory allocation failed");
	}

	if (parse_subcommand(argv[1], &args->cmd, err) != 0)
		goto fail;

	/*
	 * NOTE: Flags are parsed before operands for deterministic CLI
	 * semantics. See ARCHITECTURE.md section 12.2.
	 */
	hash_seen = 0;
	output_seen = 0;
	for (i = 2; i < argc; i++) {
		if (strncmp(argv[i], "--", 2) != 0)
			break;

		if (strcmp(argv[i], "--verbose") == 0) {
			args->verbose = 1;
			continue;
		}

		if (strcmp(argv[i], "--fast") == 0) {
			if (args->cmd != ARK_CMD_CREATE)
				goto fail_usage_fast;
			args->deflate_mode = ARK_DEFLATE_FAST;
			continue;
		}

		if (strcmp(argv[i], "--overwrite") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT)
				goto fail_usage_overwrite;
			args->overwrite = 1;
			continue;
		}

		if (strcmp(argv[i], "--human") == 0) {
			if (args->cmd != ARK_CMD_LIST)
				goto fail_usage_human;
			args->human = 1;
			continue;
		}

		if (strcmp(argv[i], "--hash") == 0) {
			if (args->cmd != ARK_CMD_CREATE)
				goto fail_usage_hash_scope;
			if (hash_seen)
				goto fail_usage_hash_dup;
			if (++i >= argc)
				goto fail_usage_hash_missing;
			if (parse_hash(argv[i], &args->hash_alg, err) != 0)
				goto fail;
			hash_seen = 1;
			continue;
		}

		if (strcmp(argv[i], "--output") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT)
				goto fail_usage_output_scope;
			if (output_seen)
				goto fail_usage_output_dup;
			if (++i >= argc)
				goto fail_usage_output_missing;
			args->output_path = argv[i];
			output_seen = 1;
			continue;
		}

		if (strcmp(argv[i], "--member") == 0) {
			if (args->cmd != ARK_CMD_EXTRACT &&
			    args->cmd != ARK_CMD_VERIFY &&
			    args->cmd != ARK_CMD_LIST)
				goto fail_usage_member_scope;
			if (++i >= argc)
				goto fail_usage_member_missing;
			if (push_member(args, argv[i], max_items, err) != 0)
				goto fail;
			continue;
		}

		goto fail_usage_unknown_flag;
	}
	operands_start = i;

	/*
	 * Enforce subcommand operand contracts from ARCHITECTURE.md
	 * section 12.2.
	 */
	switch (args->cmd) {
	case ARK_CMD_CREATE:
		if ((argc - operands_start) < 2)
			goto fail_usage_create_operands;
		args->archive_path = argv[operands_start];
		for (i = operands_start + 1; i < argc; i++)
			args->create_paths[args->create_path_count++] = argv[i];
		break;
	case ARK_CMD_EXTRACT:
		if ((argc - operands_start) != 1)
			goto fail_usage_extract_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_LIST:
		if ((argc - operands_start) != 1)
			goto fail_usage_list_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_VERIFY:
		if ((argc - operands_start) != 1)
			goto fail_usage_verify_operands;
		args->archive_path = argv[operands_start];
		break;
	case ARK_CMD_GENERATE_READER:
		if ((argc - operands_start) > 1)
			goto fail_usage_generate_reader_operands;
		if ((argc - operands_start) == 1)
			args->generate_reader_output = argv[operands_start];
		break;
	default:
		goto fail_usage_unknown_subcommand;
	}

	return 0;

fail_usage_fast:
	(void)usage_error(err, "--fast is valid only for create");
	goto fail;
fail_usage_overwrite:
	(void)usage_error(err, "--overwrite is valid only for extract");
	goto fail;
fail_usage_human:
	(void)usage_error(err, "--human is valid only for list");
	goto fail;
fail_usage_hash_scope:
	(void)usage_error(err, "--hash is valid only for create");
	goto fail;
fail_usage_hash_dup:
	(void)usage_error(err, "duplicate --hash flag");
	goto fail;
fail_usage_hash_missing:
	(void)usage_error(err, "missing value for --hash");
	goto fail;
fail_usage_output_scope:
	(void)usage_error(err, "--output is valid only for extract");
	goto fail;
fail_usage_output_dup:
	(void)usage_error(err, "duplicate --output flag");
	goto fail;
fail_usage_output_missing:
	(void)usage_error(err, "missing value for --output");
	goto fail;
fail_usage_member_scope:
	(void)usage_error(
	    err, "--member is valid only for extract, list, or verify");
	goto fail;
fail_usage_member_missing:
	(void)usage_error(err, "missing value for --member");
	goto fail;
fail_usage_unknown_flag:
	(void)usage_error(err, "unknown flag");
	goto fail;
fail_usage_create_operands:
	(void)usage_error(
	    err, "create requires archive path and at least one source path");
	goto fail;
fail_usage_extract_operands:
	(void)usage_error(err, "extract requires exactly one archive path");
	goto fail;
fail_usage_list_operands:
	(void)usage_error(err, "list requires exactly one archive path");
	goto fail;
fail_usage_verify_operands:
	(void)usage_error(err, "verify requires exactly one archive path");
	goto fail;
fail_usage_generate_reader_operands:
	(void)usage_error(err,
	                  "generate-reader accepts at most one output path");
	goto fail;
fail_usage_unknown_subcommand:
	(void)usage_error(err, "unknown subcommand");
	goto fail;

fail:
	args_free(args);
	return -1;
}

/*
 * print_usage - Emit usage guidance for invalid invocation and exit 1.
 *
 * ARCHITECTURE.md section 12.3 requires one-line problem detail followed by
 * "See man ark for usage." with no inline synopsis.
 */
static void print_usage(const char *problem)
{
	if (problem != NULL && problem[0] != '\0') {
		syslog(LOG_ERR, "%s", problem);
		(void)fputs("ark: ", stderr), (void)fputs(problem, stderr),
		    (void)fputc('\n', stderr);
	} else {
		syslog(LOG_ERR, "invalid invocation");
		(void)fputs("ark: invalid invocation\n", stderr);
	}
	syslog(LOG_ERR, "See man ark for usage.");
	(void)fputs("See man ark for usage.\n", stderr);
	closelog();
	exit(1);
}

#ifdef ARK_TEST
/* ARK_TEST only: create a test pool (decompress non-zero selects worker mode).
 */
ark_pool_t *pool_test_init(int n_workers, int decompress, ark_error_t *err)
{
	ark_pool_mode_t mode;

	mode = decompress ? ARK_POOL_DECOMPRESS : ARK_POOL_COMPRESS;
	return pool_init(n_workers, mode, err);
}

/* ARK_TEST only: submit one work item into a test pool queue. */
int pool_test_submit(ark_pool_t *pool, uint64_t seq, const uint8_t *src,
                     size_t src_len, ark_deflate_mode_t mode)
{
	return pool_submit(pool, seq, src, src_len, mode);
}

/* ARK_TEST only: read one ring slot through pool-owned ring buffer. */
int pool_test_read(ark_pool_t *pool, uint64_t seq, uint8_t **data, size_t *len,
                   int *abort, ark_err_t *worker_err, ark_error_t *err)
{
	if (pool == NULL)
		return -1;
	return ring_buf_read(pool->ring, seq, data, len, abort, worker_err,
	                     err);
}

/* ARK_TEST only: emulate I/O-thread cancellation signaling for tests. */
void pool_test_cancel(ark_pool_t *pool)
{
	if (pool == NULL)
		return;
	__atomic_store_n((int *)&pool->cancelled, 1, __ATOMIC_RELEASE);
	if (pthread_mutex_lock(&pool->mutex) == 0) {
		(void)pthread_cond_broadcast(&pool->cv_not_empty);
		(void)pthread_cond_broadcast(&pool->cv_not_full);
		(void)pthread_mutex_unlock(&pool->mutex);
	}
}

/* ARK_TEST only: release test pool and join workers. */
void pool_test_shutdown(ark_pool_t *pool)
{
	pool_shutdown(pool);
}

/*
 * ark_test_create_archive - Run create with explicit pool width in tests.
 *
 * Uses the same worker-pool create path as production so tests can verify
 * byte-identical archive output across worker counts. See ARCHITECTURE.md
 * section 6.3.
 *
 * Returns 0 on success, -1 on error with details in err.
 *
 * Preconditions:
 * - archive_path != NULL
 * - create_paths != NULL
 * - create_path_count > 0
 * - n_workers > 0
 */
int ark_test_create_archive(const char *archive_path, const char **create_paths,
                            size_t create_path_count, int n_workers,
                            ark_hash_alg_t hash_alg,
                            ark_deflate_mode_t deflate_mode, ark_error_t *err)
{
	ark_args_t args;
	ark_pool_t *pool;

	if (archive_path == NULL || create_paths == NULL ||
	    create_path_count == 0U || n_workers <= 0)
		return fail_error(
		    err, ARK_ERR_USAGE,
		    "ARK_TEST create helper received invalid arguments", "", 0);

	args = (ark_args_t){0};
	args.cmd = ARK_CMD_CREATE;
	args.hash_alg = hash_alg;
	args.deflate_mode = deflate_mode;
	args.archive_path = archive_path;
	args.create_paths = create_paths;
	args.create_path_count = create_path_count;

	pool = pool_init(n_workers, ARK_POOL_COMPRESS, err);
	if (pool == NULL)
		return -1;
	return cmd_create(&args, pool, err);
}

/* ARK_TEST only: expose current cancellation flag for thread tests. */
int pool_get_cancel_flag(const ark_pool_t *pool)
{
	if (pool == NULL)
		return 0;
	return __atomic_load_n((const int *)&pool->cancelled, __ATOMIC_ACQUIRE);
}

/* ARK_TEST only: return a snapshot copy of shared first-worker error. */
ark_error_t pool_get_shared_err(const ark_pool_t *pool)
{
	ark_error_t out;

	out = (ark_error_t){0};
	if (pool == NULL)
		return out;
	if (__atomic_load_n((const int *)&pool->shared_err.recorded,
	                    __ATOMIC_ACQUIRE) == 0)
		return out;
	return pool->shared_err.error;
}

/* ARK_TEST only: count ring slots currently holding abort sentinels. */
int pool_get_sentinel_count(const ark_pool_t *pool)
{
	int count;
	size_t i;

	if (pool == NULL || pool->ring == NULL)
		return 0;
	if (pthread_mutex_lock(&pool->ring->mutex) != 0)
		return 0;
	count = 0;
	for (i = 0U; i < pool->ring->n_slots; i++) {
		if (pool->ring->slots[i].ready && pool->ring->slots[i].abort)
			count++;
	}
	(void)pthread_mutex_unlock(&pool->ring->mutex);
	return count;
}

unsigned int pool_get_error_event(const ark_pool_t *pool)
{
	if (pool == NULL)
		return 0U;
	return __atomic_load_n((const unsigned int *)&pool->error_event,
	                       __ATOMIC_ACQUIRE);
}

unsigned int pool_get_abort_event(const ark_pool_t *pool)
{
	if (pool == NULL)
		return 0U;
	return __atomic_load_n((const unsigned int *)&pool->abort_event,
	                       __ATOMIC_ACQUIRE);
}

/* ARK_TEST only: inject worker error + abort sentinel (slot sequence 0). */
void pool_inject_worker_error(ark_pool_t *pool, ark_err_t code, int errno_value)
{
	ark_error_t local_err;

	if (pool == NULL || pool->ring == NULL)
		return;

	local_err = (ark_error_t){0};
	(void)fail_error(&local_err, code, "ARK_TEST injected worker error", "",
	                 errno_value);
	error_store_once(&pool->shared_err, &local_err);
	__atomic_store_n((unsigned int *)&pool->error_event,
	                 __atomic_add_fetch((unsigned int *)&pool->event_seq,
	                                    1U, __ATOMIC_ACQ_REL),
	                 __ATOMIC_RELEASE);
	/* SAFETY: publish abort sentinel after shared error is stored so
	 * the I/O thread observes first-error metadata before abort handling.
	 * See ARCHITECTURE.md section 6.3. */
	(void)ring_buf_abort(pool->ring, 0U, code, NULL);
	__atomic_store_n((unsigned int *)&pool->abort_event,
	                 __atomic_add_fetch((unsigned int *)&pool->event_seq,
	                                    1U, __ATOMIC_ACQ_REL),
	                 __ATOMIC_RELEASE);
}

/*
 * ark_test_keep_main_symbols - Keep CLI-only static roots referenced in
 * ARK_TEST builds where main() is intentionally excluded.
 */
void ark_test_keep_main_symbols(void)
{
	(void)&parse_args;
	(void)&default_worker_count;
	(void)&pool_init;
	(void)&pool_submit;
	(void)&pool_shutdown;
	(void)&ark_test_create_archive;
	(void)&print_usage;
	(void)&cmd_create;
	(void)&cmd_extract;
	(void)&cmd_list;
	(void)&cmd_verify;
	(void)&cmd_generate_reader;
	(void)&sandbox_apply;
	(void)&exit_code_from_err;
	(void)&print_error;
}
#endif

#ifndef ARK_TEST
int main(int argc, char **argv)
{
	ark_args_t args;
	ark_error_t err = {0};
	ark_pool_t *io_pool;
	int extract_dest_fd;
	int rc;

	io_pool = NULL;
	extract_dest_fd = -1;
	openlog("ark", LOG_PID, LOG_USER);

	if (parse_args(argc, argv, &args, &err) != 0) {
		if (err.code == ARK_ERR_USAGE)
			print_usage(err.msg);
		print_error(&err);
		closelog();
		return 1;
	}

	if (args.cmd == ARK_CMD_EXTRACT) {
		/*
		 * Extract pre-sandbox setup must open destination dirfd before
		 * sandbox application. See ARCHITECTURE.md section 10.4.
		 */
		extract_dest_fd = ARK_OPEN(
		    args.output_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		if (extract_dest_fd == -1) {
			(void)fail_error(&err, ARK_ERR_IO_OPEN,
			                 "output directory open failed",
			                 args.output_path, errno);
			print_error(&err);
			args_free(&args);
			closelog();
			return exit_code_from_err(err.code);
		}
	}
	if (args.cmd == ARK_CMD_GENERATE_READER) {
		char parent[PATH_MAX];
		int parent_fd;

		/*
		 * ARCHITECTURE.md section 10.4: verify output parent path
		 * accessibility before sandbox application.
		 */
		if (parent_dir(args.generate_reader_output, parent,
		               sizeof(parent), &err) != 0) {
			print_error(&err);
			args_free(&args);
			closelog();
			return exit_code_from_err(err.code);
		}
		parent_fd =
		    ARK_OPEN(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
		if (parent_fd == -1) {
			(void)fail_error(
			    &err, ARK_ERR_IO_OPEN,
			    "generate-reader output parent open failed", parent,
			    errno);
			print_error(&err);
			args_free(&args);
			closelog();
			return exit_code_from_err(err.code);
		}
		(void)ARK_CLOSE(parent_fd);
	}

#if defined(__OpenBSD__) && !defined(__linux__)
	/*
	 * SAFETY: OpenBSD requires thread-pool creation before pledge for
	 * create/extract. See ARCHITECTURE.md sections 6.3 and 10.4.
	 */
	if (args.cmd == ARK_CMD_CREATE || args.cmd == ARK_CMD_EXTRACT) {
		io_pool =
		    pool_init(default_worker_count(),
		              args.cmd == ARK_CMD_CREATE ? ARK_POOL_COMPRESS
		                                         : ARK_POOL_DECOMPRESS,
		              &err);
		if (io_pool == NULL) {
			print_error(&err);
			args_free(&args);
			if (extract_dest_fd != -1)
				(void)ARK_CLOSE(extract_dest_fd);
			closelog();
			return exit_code_from_err(err.code);
		}
	}
#endif

#if defined(__linux__) || defined(__OpenBSD__)
	const char *sandbox_dst;

	if (args.cmd == ARK_CMD_EXTRACT)
		sandbox_dst = args.output_path;
	else if (args.cmd == ARK_CMD_GENERATE_READER)
		sandbox_dst = args.generate_reader_output;
	else
		sandbox_dst = NULL;

	/*
	 * Platform-specific ordering scaffold for Phase 6 integration.
	 * See ARCHITECTURE.md section 6.3 and 10.4.
	 */
	if (sandbox_apply(args.cmd, args.create_paths,
	                  (int)args.create_path_count, args.archive_path,
	                  sandbox_dst, &err) != 0) {
		if (err.code == ARK_ERR_USAGE)
			print_usage(err.msg);
		print_error(&err);
		args_free(&args);
		if (io_pool != NULL)
			pool_shutdown(io_pool);
		if (extract_dest_fd != -1)
			(void)ARK_CLOSE(extract_dest_fd);
		closelog();
		return 1;
	}
#endif

#if defined(__linux__) && !defined(__OpenBSD__)
	/*
	 * SAFETY: Linux requires sandbox application before worker creation so
	 * workers inherit Landlock at thread start. See ARCHITECTURE.md
	 * sections 6.3 and 10.4.
	 */
	if (args.cmd == ARK_CMD_CREATE || args.cmd == ARK_CMD_EXTRACT) {
		io_pool =
		    pool_init(default_worker_count(),
		              args.cmd == ARK_CMD_CREATE ? ARK_POOL_COMPRESS
		                                         : ARK_POOL_DECOMPRESS,
		              &err);
		if (io_pool == NULL) {
			print_error(&err);
			args_free(&args);
			if (extract_dest_fd != -1)
				(void)ARK_CLOSE(extract_dest_fd);
			closelog();
			return exit_code_from_err(err.code);
		}
	}
#endif

	if (args.cmd == ARK_CMD_CREATE)
		rc = cmd_create(&args, io_pool, &err), io_pool = NULL;
	else if (args.cmd == ARK_CMD_EXTRACT)
		rc = cmd_extract(&args, extract_dest_fd, io_pool, &err),
		io_pool = NULL;
	else if (args.cmd == ARK_CMD_LIST)
		rc = cmd_list(&args, &err);
	else if (args.cmd == ARK_CMD_VERIFY)
		rc = cmd_verify(&args, &err);
	else if (args.cmd == ARK_CMD_GENERATE_READER)
		rc = cmd_generate_reader(&args, &err);
	else
		rc = 0;

	if (rc != 0) {
		print_error(&err);
		args_free(&args);
		if (io_pool != NULL)
			pool_shutdown(io_pool);
		if (extract_dest_fd != -1)
			(void)ARK_CLOSE(extract_dest_fd);
		closelog();
		return exit_code_from_err(err.code);
	}

	args_free(&args);
	if (io_pool != NULL)
		pool_shutdown(io_pool);
	if (extract_dest_fd != -1)
		(void)ARK_CLOSE(extract_dest_fd);
	closelog();
	return 0;
}
#endif
