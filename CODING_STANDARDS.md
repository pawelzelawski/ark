# Coding Standards

## 1. Code Style

### 1.1 OpenBSD KNF (Kernel Normal Form)

ark follows OpenBSD's Kernel Normal Form style. This is the style used
throughout the OpenBSD base system and is required for all source files in
`src/` and `include/`.

**Indentation**:
- Tabs for indentation, 8-character display width
- Spaces only for alignment within a line, never for indentation
- Never mix tabs and spaces for indentation

```c
/* Correct */
static int
read_chunk(ark_read_ctx_t *ctx, int fd, uint8_t *dst,
    size_t len, ark_error_t *err)
{
	const uint8_t	*p = dst;
	ssize_t		 n;

	while (len > 0) {
		n = ARK_READ(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return ark_fail(err, ARK_ERR_IO_READ,
			    "read chunk", errno);
		}
		p   += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Wrong - spaces used for indentation */
static int
read_chunk(ark_read_ctx_t *ctx, int fd, uint8_t *dst,
    size_t len, ark_error_t *err)
{
    const uint8_t *p = dst;   /* spaces, not tabs */
}
```

**Braces**:
```c
/* Functions: opening brace on its own line */
static int
validate_member_path(const char *path, size_t len, ark_error_t *err)
{
	/* body */
}

/* Control structures: opening brace on same line */
if (len > ARK_PATH_MAX) {
	return ark_fail(err, ARK_ERR_PATH_TOO_LONG,
	    "path exceeds maximum", 0);
}

/* Single-statement bodies: no braces, indented on next line */
if (ctx == NULL)
	return ark_fail(err, ARK_ERR_USAGE, "null context", 0);

/* Loop with single statement */
for (i = 0; i < chunk_count; i++)
	sizes[i] = ark_le32(buf + off + i * 4);
```

**Line length**: Maximum 80 characters. Break long lines at logical points,
aligning continuation with the opening parenthesis or using one extra tab:

```c
/* Break at logical point, align with opening paren */
rc = ark_write_member_begin(ctx, meta, &err);

/* Extra tab indent for continuation */
return ark_fail(err, ARK_ERR_IO_WRITE,
	"failed to write chunk", errno);
```

**Naming conventions**:
```c
/* Variables and function parameters: lowercase with underscores */
int              rc;
size_t           len;
uint32_t         chunk_count;
ark_read_ctx_t  *ctx;
ark_error_t      err;

/* Public API functions: ark_ prefix, lowercase with underscores */
int     ark_write_init(ark_write_ctx_t *, ark_hash_alg_t,
            ark_deflate_mode_t, ark_error_t *);
int     ark_read_header(ark_read_ctx_t *, const uint8_t *,
            size_t, ark_error_t *);
ssize_t ark_write_chunk(ark_write_ctx_t *, const uint8_t *,
            size_t, uint8_t *, size_t, ark_error_t *);

/* Internal functions: no ark_ prefix, descriptive verb-noun names */
static int    parse_index_entry(const uint8_t *, size_t,
                  ark_member_meta_t *, ark_error_t *);
static int    validate_path(const char *, size_t, ark_error_t *);
static void   ring_buf_abort(ark_ring_buf_t *, ark_err_t, int);
static int    extract_regular(const ark_member_meta_t *, int,
                  ark_error_t *);
static void   cleanup_created(ark_cleanup_t *, int);

/* Constants and macros: uppercase with underscores, ARK_ prefix */
#define ARK_CHUNK_SIZE      1048576U
#define ARK_PATH_MAX        1023U
#define ARK_MAGIC           "\x61\x72\x6b\x21\x0a"
#define ARK_HASH_LEN        32U

/* Structs and typedefs: lowercase, _t suffix */
typedef struct ark_write_ctx   ark_write_ctx_t;
typedef struct ark_read_ctx    ark_read_ctx_t;
typedef struct ark_member_meta ark_member_meta_t;
typedef struct ark_error       ark_error_t;

/* Enums: uppercase values with ARK_ prefix */
typedef enum {
	ARK_HASH_BLAKE3 = 0x01,
	ARK_HASH_SHA256 = 0x02,
} ark_hash_alg_t;
```

**Spacing**:
```c
/* Space after keywords, not after function names */
if (ctx->state != ARK_STATE_MEMBER)       /* correct */
if(ctx->state != ARK_STATE_MEMBER)        /* wrong */
ark_write_free(ctx)                       /* correct */
ark_write_free (ctx)                      /* wrong */

/* No space inside parentheses */
if (n > 0)                                /* correct */
if ( n > 0 )                              /* wrong */

/* Space around binary operators */
len -= (size_t)n;
off += chunk_sizes[i];
```

**Return type on its own line**:
```c
/* Correct */
static int
parse_index_entry(const uint8_t *buf, size_t len,
    ark_member_meta_t *meta, ark_error_t *err)
{
	/* ... */
}

/* Wrong */
static int parse_index_entry(const uint8_t *buf, size_t len,
    ark_member_meta_t *meta, ark_error_t *err)
{
	/* ... */
}
```

### 1.2 File Organisation

**Component public headers** (`src/sha256.h`, `src/blake3.h`,
`src/deflate.h`, `src/archive.h`):

Each component header exposes only the public API for that component.
Internal types and implementation details are never declared here. Each
header is self-contained and copyable to other projects without modification.

```c
#ifndef ARK_BLAKE3_H
#define ARK_BLAKE3_H

/*
 * blake3.h - BLAKE3 hash implementation
 *
 * Streaming:
 *   ark_blake3_ctx_t ctx;
 *   ark_blake3_init(&ctx);
 *   ark_blake3_update(&ctx, data, len);  [x N]
 *   ark_blake3_final(&ctx, digest);
 *
 * Single-shot:
 *   ark_blake3(data, len, digest);
 *
 * See ARCHITECTURE.md §8.4 for API contract.
 */

#include <stddef.h>
#include <stdint.h>

/* ... types and function declarations ... */

#endif /* ARK_BLAKE3_H */
```

**Internal header** (`src/ark_internal.h`):

```c
#ifndef ARK_INTERNAL_H
#define ARK_INTERNAL_H

/*
 * ark_internal.h - shared internal types and syscall wrapper macros
 *
 * Not part of any component's public API. Included by all .c files
 * in src/. Never included by tests directly; tests include component
 * headers only.
 */

/* Syscall wrapper macros for fault injection - see TESTING.md §3 */
#ifndef ARK_TEST
#define ARK_READ        read
#define ARK_WRITE       write
#define ARK_OPEN        open
#define ARK_CLOSE       close
#define ARK_LSTAT       lstat
#define ARK_UNLINK      unlink
#define ARK_RMDIR       rmdir
#define ARK_LINK        link
#define ARK_LCHOWN      lchown
#define ARK_UTIMENSAT   utimensat
#define ARK_MKDIR       mkdir
#define ARK_OPENDIR     opendir
#define ARK_READDIR     readdir
#define ARK_CLOSEDIR    closedir
#define ARK_REALPATH    realpath
#endif

/* ... internal type declarations ... */

#endif /* ARK_INTERNAL_H */
```

**Source files** (`.c`):
```c
/*
 * archive.c - archive format read and write implementation
 *
 * Implements the write path (ark_write_*) and read path (ark_read_*)
 * defined in archive.h. No I/O, no allocation beyond context lifetime,
 * no threading. See ARCHITECTURE.md §16 for the full API contract and
 * §16.3 for the write context state machine.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "archive.h"
#include "ark_internal.h"
```

**Include order** (within each group, alphabetical):
```c
/* 1. System headers */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* 2. Platform-conditional system headers */
#ifdef __linux__
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

/* 3. Component public headers, alphabetical */
#include "archive.h"
#include "blake3.h"
#include "deflate.h"
#include "sha256.h"

/* 4. Internal header last */
#include "ark_internal.h"
```

---

## 2. Error Handling

### 2.1 Error Model

Every function that can fail returns `int` (0 success, -1 failure) with a
caller-provided `ark_error_t *err`. Functions that return a value on success
(bytes written, pointer) return -1 or NULL on failure. The `err` parameter
is always the last parameter. `err` may be NULL; callers that do not need
error detail pass NULL.

Errors are populated at the point of detection using context available there.
Upper layers propagate the struct unchanged. No layer may overwrite an error
already populated by a lower layer.

```c
/*
 * ark_fail - populate err and return -1.
 *
 * Convenience wrapper used at every failure site. Returns -1 always so
 * callers can write: return ark_fail(err, code, msg, sys_errno);
 *
 * If err is NULL this is a no-op aside from returning -1.
 */
static int
ark_fail(ark_error_t *err, ark_err_t code, const char *msg, int sys_errno)
{
	if (err == NULL)
		return -1;
	err->code      = code;
	err->sys_errno = sys_errno;
	strlcpy(err->msg, msg, sizeof(err->msg));
	return -1;
}
```

### 2.2 Error Propagation

Check every return value. Propagate immediately without modifying the error
struct. The original error takes precedence over any subsequent failure
(including cleanup failures).

```c
/* Correct - propagate immediately, preserve original error */
rc = ark_read_header(ctx, header_buf, 16, &err);
if (rc != 0)
	goto done;

rc = ark_read_init(ctx, footer_buf, 64, &err);
if (rc != 0)
	goto done;

/* Correct - capture error before cleanup, do not overwrite */
rc = extract_member(meta, dst_dir, &err);
if (rc != 0) {
	saved_err = err;           /* capture */
	cleanup_created(&tracker); /* may fail; err not consulted */
	err = saved_err;           /* restore */
	goto done;
}

/* Wrong - overwriting original error with cleanup failure */
rc = extract_member(meta, dst_dir, &err);
if (rc != 0) {
	cleanup_created(&tracker, &err);   /* clobbers original error */
	goto done;
}
```

### 2.3 Errno Capture

Capture `errno` immediately at the point of the failing syscall before any
other call that could modify it.

```c
/* Correct */
n = ARK_READ(fd, buf, len);
if (n < 0) {
	saved_errno = errno;   /* captured before any other call */
	return ark_fail(err, ARK_ERR_IO_READ, "read member data",
	    saved_errno);
}

/* Wrong - errno may have changed */
n = ARK_READ(fd, buf, len);
some_other_call();
if (n < 0)
	return ark_fail(err, ARK_ERR_IO_READ, "read member data", errno);
```

---

## 3. Resource Management and Cleanup

### 3.1 goto cleanup Pattern

Multi-step resource acquisition uses the `goto cleanup` pattern. One cleanup
label handles all failure paths acquired before the point of no return.

```c
static int
extract_member(const ark_member_meta_t *meta, int dir_fd,
    ark_error_t *err)
{
	uint8_t		*buf = NULL;
	int		 out_fd = -1;
	int		 rc;

	buf = malloc(ARK_CHUNK_SIZE);
	if (buf == NULL)
		return ark_fail(err, ARK_ERR_IO_ALLOC, "chunk buffer", 0);

	out_fd = ARK_OPEN(meta->path, O_CREAT|O_WRONLY|O_NOFOLLOW, 0600);
	if (out_fd == -1) {
		rc = ark_fail(err, ARK_ERR_IO_OPEN, meta->path, errno);
		goto cleanup;
	}

	/* ... extraction steps ... */
	rc = 0;

cleanup:
	if (out_fd != -1)
		ARK_CLOSE(out_fd);
	free(buf);
	return rc;
}
```

### 3.2 Memory Ownership

malloc/free is used in ark. It is not prohibited. It must be used with
discipline:

- Every `malloc` has exactly one matching `free` on all paths. The `goto
  cleanup` pattern enforces this.
- Memory is never allocated in the hot path (inside the per-chunk compression
  or decompression loop). Buffers required for the hot path are allocated once
  at context initialisation.
- Ownership is documented at the allocation site. If a pointer is transferred
  to another struct or returned to the caller, the comment must state who is
  responsible for freeing it.

```c
/* Correct - documented ownership, freed in context teardown */
ctx->chunk_buf = malloc(ARK_CHUNK_SIZE);
if (ctx->chunk_buf == NULL)
	return ark_fail(err, ARK_ERR_IO_ALLOC, "chunk buffer", 0);
/* OWNERSHIP: ctx->chunk_buf freed by ark_write_free. */

/* Wrong - allocated in the hot path */
for (i = 0; i < chunk_count; i++) {
	tmp = malloc(ARK_CHUNK_SIZE);   /* never in the chunk loop */
	/* ... */
	free(tmp);
}
```

### 3.3 File Descriptor Discipline

Every opened file descriptor is stored in a local variable initialised to -1
before the open call. The cleanup path closes only if the value is not -1.

```c
int fd = -1;

fd = ARK_OPEN(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC, 0);
if (fd == -1) {
	rc = ark_fail(err, ARK_ERR_IO_OPEN, path, errno);
	goto cleanup;
}

/* ... use fd ... */

cleanup:
if (fd != -1)
	ARK_CLOSE(fd);
```

`O_CLOEXEC` is set on all file descriptors at open time. ark does not fork,
but O_CLOEXEC is the correct default for any fd not explicitly intended to
survive exec.

`close` is not retried on `EINTR`. On Linux the fd is closed regardless
of whether `close` returns `EINTR`. Retrying would operate on an
already-closed fd. Set the local variable to -1 immediately after close.

```c
ARK_CLOSE(fd);
fd = -1;   /* guard against double-close in cleanup */
```

### 3.4 Extraction Cleanup Tracking

Every filesystem object created during extraction is registered with the
cleanup tracker immediately after creation, before any subsequent operation
that could fail. Registration itself must not be able to fail: reserve the
tracker entry with `cleanup_reserve` before creating the object, so that
`cleanup_track` after creation only appends.

```c
/* Correct - reserve first, register before next fallible operation */
if (cleanup_reserve(&tracker, err) != 0)          /* may fail: nothing */
	goto cleanup;                                  /* created yet       */
rc = ARK_MKDIR(path, 0700);
if (rc != 0) {
	return ark_fail(err, ARK_ERR_IO_MKDIR, path, errno);
}
cleanup_track(&tracker, path, 1);                 /* cannot fail */

rc = set_dir_metadata(path, meta, err);           /* next fallible op */
if (rc != 0)
	goto cleanup;                                  /* tracker has the dir */

/* Wrong - create then fail before registering */
rc = ARK_MKDIR(path, 0700);
if (rc != 0)
	goto cleanup;

rc = set_dir_metadata(path, meta, err);           /* fails here */
if (rc != 0)
	goto cleanup;                                  /* dir is not tracked */

cleanup_track(&tracker, path, 1);                 /* never reached */

/* Wrong - registration that can fail after creation */
rc = ARK_MKDIR(path, 0700);
if (rc != 0)
	goto cleanup;
if (tracker_append_grow(&tracker, path, err) != 0) /* allocation fails */
	goto cleanup;                                  /* dir is not tracked */
```

---

## 4. Syscall Wrapper Discipline

### 4.1 Always Use the Wrapper Macros

All syscall invocations in `src/` must use the wrapper macros defined in
`ark_internal.h` (`ARK_READ`, `ARK_WRITE`, `ARK_OPEN`, `ARK_LSTAT`, etc.),
never the raw syscall names.

```c
/* Correct */
n = ARK_READ(fd, buf, len);

/* Wrong - bypasses fault injection */
n = read(fd, buf, len);
```

In production builds the macros expand to the real syscalls with zero
overhead. In test builds (`-DARK_TEST`) they expand to stubs. Bypassing
the macros silently breaks fault injection coverage.

### 4.2 EINTR Retry Pattern

All retryable syscalls use the same retry loop pattern:

```c
/* Correct - consistent EINTR retry */
do {
	rc = ARK_LCHOWN(path, uid, gid);
} while (rc != 0 && errno == EINTR);
if (rc != 0)
	return ark_fail(err, ARK_ERR_IO_CHOWN, path, errno);

/* Wrong - treating EINTR as hard failure */
if (ARK_LCHOWN(path, uid, gid) != 0)
	return ark_fail(err, ARK_ERR_IO_CHOWN, path, errno);
```

`close` is the explicit exception: never retry on `EINTR`.

### 4.3 Symlink-Safe Metadata Calls

Metadata operations on extracted members must not follow symlinks. Use the
no-follow variants:

```c
/* Correct - operates on the symlink inode, not the target */
ARK_LCHOWN(path, uid, gid);
ARK_UTIMENSAT(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);

/* Wrong - follows the symlink */
chown(path, uid, gid);
utimensat(AT_FDCWD, path, times, 0);
```

`chmod` is never called on symlinks. Mode bits for symlink members are
silently skipped. See ARCHITECTURE.md §14.5.

### 4.4 lchown Before chmod

`lchown` must always precede `chmod` or `fchmod` for regular files and
directories. On Linux, `chown`/`lchown` unconditionally clears setuid and
setgid bits. `chmod` after restores them.

```c
/* Correct */
ARK_LCHOWN(path, meta->uid, meta->gid);
ARK_CHMOD(path, meta->mode & 0777);     /* after lchown */

/* Wrong */
ARK_CHMOD(path, meta->mode & 0777);     /* setuid/setgid bits set here */
ARK_LCHOWN(path, meta->uid, meta->gid); /* cleared here - wrong */
```

---

## 5. Threading Discipline

### 5.1 Worker Thread Constraints

Worker threads compress or decompress chunks and nothing else. They do not
call `ark_write_chunk`, do not modify the write or read context, and do not
touch any shared struct except the ring buffer and the shared error state.

```c
/* Correct - worker calls ark_deflate_compress directly */
static void *
worker_compress(void *arg)
{
	ark_worker_arg_t *w = arg;
	ssize_t           clen;

	clen = ark_deflate_compress(w->in, w->in_len, w->out,
	    w->out_cap, w->mode);
	ring_buf_write(w->ring, w->seq, w->out, clen);
	return NULL;
}

/* Wrong - worker calls write API directly */
static void *
worker_compress(void *arg)
{
	/* ... */
	ark_write_chunk(ctx, ...);   /* never from a worker */
	return NULL;
}
```

`ark_write_chunk` is called only from the I/O thread, in chunk sequence order,
after the ring buffer delivers each completed slot. This rule is absolute.

### 5.2 Cancellation Flag

The shared cancellation flag is a `volatile int` or `_Atomic int`. All
workers check it between chunks and exit cleanly when it is set. Workers
never access shared context state after the cancellation flag is set.

```c
/* Correct - check flag at each chunk boundary */
while (chunks_remaining > 0) {
	if (atomic_load(&pool->cancel))
		break;
	/* compress next chunk */
}
```

The I/O thread sets the flag, never workers. Workers signal errors via the
error propagation path (§5.3), not by setting the cancellation flag.

### 5.3 Worker Error Propagation

When a worker encounters a fatal error it must not simply exit. The I/O
thread will deadlock waiting for the worker's ring buffer slot.

Required sequence for a worker that encounters a fatal error:
1. Write the error code and a copy of `ark_error_t` to the shared atomic
   error struct. Use compare-and-swap: only the first worker error is
   recorded; subsequent errors are discarded.
2. Write an abort sentinel to the worker's ring buffer slot.
3. Exit the worker function.

```c
/* Correct - abort sentinel written before worker exit */
clen = ark_deflate_compress(w->in, w->in_len, w->out, w->out_cap,
    w->mode);
if (clen < 0) {
	ark_fail(&local_err, ARK_ERR_FMT_DATA, "compress failed", 0);
	error_store_once(&pool->shared_err, &local_err);  /* step 1 */
	ring_buf_abort(w->ring, w->seq);                  /* step 2 */
	return NULL;                                       /* step 3 */
}

/* Wrong - worker exits without writing sentinel; I/O thread deadlocks */
if (clen < 0)
	return NULL;
```

The I/O thread checks each ring buffer slot for the abort sentinel before
consuming it. On detecting an abort sentinel the I/O thread reads the shared
error struct, sets the cancellation flag, joins all workers, and proceeds to
the five-step cleanup sequence. See ARCHITECTURE.md §6.3.

### 5.4 Thread Quiescence Before Cleanup

On any fatal error during a parallel operation, cleanup must not begin until
all workers are joined. The sequence is fixed and must not be reordered:

```c
/* Correct - quiescence before cleanup */
atomic_store(&pool->cancel, 1);    /* step 1: signal cancellation    */
/* step 2: stop submitting new work - done implicitly by I/O thread  */
for (i = 0; i < pool->nworkers; i++)
	pthread_join(pool->workers[i], NULL);  /* step 3: join all      */
if (out_fd != -1) {
	ARK_CLOSE(out_fd);             /* step 4: close current output  */
	out_fd = -1;
}
cleanup_created(&tracker);        /* step 5: filesystem cleanup     */
```

No filesystem cleanup may race an active worker. A worker that has received
the abort sentinel has already exited its main loop, but `pthread_join` is
still required to ensure memory visibility before cleanup reads any shared
state.

---

## 6. Write and Read Context Discipline

### 6.1 Write Context State Machine

The write context must be called in strict sequence. See ARCHITECTURE.md
§16.3 for the state diagram. Any out-of-sequence call returns -1 with
`ARK_ERR_USAGE` and is a caller programming error.

```c
/* Correct - follows state machine sequence */
ark_write_init(&ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err);
ark_write_header(&ctx, header_buf, sizeof(header_buf), &err);
ark_write_member_begin(&ctx, &meta, &err);
ark_write_chunk(&ctx, comp_data, comp_len, out, out_cap, &err);
ark_write_member_end(&ctx, &err);
ark_write_index(&ctx, idx_buf, idx_cap, &err);
ark_write_footer(&ctx, idx_offset, idx_len, footer_buf, 64, &err);
ark_write_free(&ctx);

/* Wrong - chunk called after member_end */
ark_write_member_end(&ctx, &err);
ark_write_chunk(&ctx, data, len, out, cap, &err);   /* ARK_ERR_USAGE */
```

`ark_write_free` is valid in any state and must always be called to release
context resources, even after an error return from any other write function.

### 6.2 chunk_sizes Ownership

`chunk_sizes` in `ark_member_meta_t` is an output field on the read path
only. It is never populated or read by callers of the write path.

```c
/* Correct - chunk_sizes NULL on write path */
memset(&meta, 0, sizeof(meta));
meta.size_original = file_size;
meta.type          = ARK_TYPE_REGULAR;
/* meta.chunk_sizes intentionally left NULL */
ark_write_member_begin(&ctx, &meta, &err);

/* Wrong - populating chunk_sizes on write path */
meta.chunk_sizes = my_array;   /* context owns this internally */
ark_write_member_begin(&ctx, &meta, &err);
```

### 6.3 Read Context Sequence

`ark_read_header` must be called before `ark_read_init`. Both must succeed
before `ark_read_index`. Per-member functions are valid only after
`ark_read_index` succeeds. See ARCHITECTURE.md §16.4.

```c
/* Correct */
if (ark_read_header(&ctx, header_buf, 16, &err) != 0)
	goto done;
if (ark_read_init(&ctx, footer_buf, 64, &err) != 0)
	goto done;
if (ark_read_index(&ctx, index_buf, index_len, &err) != 0)
	goto done;
/* per-member access follows */
```

### 6.4 Per-Member Verification Sequence

`ark_read_verify_member_begin` must be called once per member before any
`ark_read_verify_member_update` calls. `ark_read_verify_member_update` must
be called with the next expected chunk index; out-of-order calls return
`ARK_ERR_FMT_INDEX` immediately.

```c
/* Correct */
ark_read_verify_member_begin(&ctx, meta, &err);
for (i = 0; i < meta->chunk_count; i++) {
	read_compressed_chunk(fd, chunk_buf, meta->chunk_sizes[i]);
	ark_read_verify_member_update(&ctx, meta, i, chunk_buf,
	    meta->chunk_sizes[i], &err);
	ark_read_chunk(&ctx, meta, i, chunk_buf, meta->chunk_sizes[i],
	    decomp_buf, ARK_CHUNK_SIZE, &err);
	write_decompressed(out_fd, decomp_buf, decomp_len);
}
ark_read_verify_member_final(&ctx, meta, &err);
```

`ark_read_verify_member_update` is called with the compressed bytes before
passing them to `ark_read_chunk`. This order is fixed: hash verification
covers the compressed data as stored; decompression follows.

---

## 7. Documentation

### 7.1 Function Comments

Every public API function has a block comment describing what it does, its
parameters, return values, failure contract, and preconditions. Internal
static helpers have a brief comment unless the name is entirely
self-explanatory.

```c
/*
 * ark_write_chunk - record one pre-compressed chunk into the write context.
 *
 * src contains compressed bytes produced by ark_deflate_compress in a worker
 * thread. This function does not compress. It updates the per-member hash
 * state over the compressed bytes, records the chunk size, and copies the
 * compressed bytes to dst for handoff to chevron_write_chunk.
 *
 * Must be called only from the I/O thread and only in chunk sequence order
 * while the write context is in MEMBER state. See ARCHITECTURE.md §16.3.
 *
 * src_len is the compressed byte count. No upper bound is imposed on src_len;
 * incompressible content produces output slightly larger than ARK_CHUNK_SIZE.
 *
 * Returns bytes written to dst on success, -1 on error.
 * Returns -1 with ARK_ERR_USAGE if called outside MEMBER state.
 */
ssize_t
ark_write_chunk(ark_write_ctx_t *ctx, const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_cap, ark_error_t *err);
```

### 7.2 Architecture Cross-Reference Comments

When implementing a decision from ARCHITECTURE.md, reference the relevant
section:

```c
/*
 * Pre-extraction validation: sixteen checks in order before any filesystem
 * side effect. See ARCHITECTURE.md §8.3.
 */

/*
 * mtime normalisation: if tv_nsec < 0 after signed division, adjust to
 * keep tv_nsec in [0, 999999999]. See ARCHITECTURE.md §5.2.
 */

/*
 * member_count pre-allocation bound: reject if member_count > index_size / 84
 * before allocating the entry array. See ARCHITECTURE.md §5.1.
 */

/*
 * lchown before chmod: lchown clears setuid/setgid bits on Linux.
 * chmod after restores them. Order must not be changed.
 * See ARCHITECTURE.md §14.5.
 */

/*
 * Hash of empty byte sequence for non-file member types (directories,
 * symlinks, hardlinks). See ARCHITECTURE.md §5.2.
 */
```

### 7.3 SAFETY Comments

Mark safety-critical invariants explicitly. The format is `/* SAFETY: ... */`
on its own line before the guarded code.

```c
/*
 * SAFETY: ark_write_chunk is called only from the I/O thread and only in
 * chunk sequence order. Worker threads call ark_deflate_compress directly.
 * Calling ark_write_chunk from a worker thread is undefined behaviour.
 * See ARCHITECTURE.md §6.3.
 */

/*
 * SAFETY: write abort sentinel to ring buffer slot before worker exits on
 * error. Exiting without writing the sentinel causes the I/O thread to
 * block indefinitely waiting for the slot. See ARCHITECTURE.md §6.3.
 */

/*
 * SAFETY: join all workers before cleanup. A worker that has received the
 * cancellation flag may still be executing; pthread_join ensures memory
 * visibility before any shared state is read during cleanup.
 * See ARCHITECTURE.md §14.3.
 */

/*
 * SAFETY: register extracted object with cleanup tracker before the next
 * fallible operation. Failing to register before the next goto means the
 * object is leaked on error. See ARCHITECTURE.md §14.3.
 */

/*
 * SAFETY: do not retry close() on EINTR. On Linux the fd is closed
 * regardless. Retrying operates on an already-closed fd.
 */

/*
 * SAFETY: lchown before chmod. lchown clears setuid/setgid bits.
 * chmod after restores them. Order must not be changed.
 * See ARCHITECTURE.md §14.5.
 */

/*
 * SAFETY: O_NOFOLLOW on all extraction open() calls. Prevents writing
 * through a symlink that was created between lstat and open.
 * See ARCHITECTURE.md §14.2.
 */

/*
 * SAFETY: mode bits are masked to 0777 before chmod. Setuid, setgid, and
 * sticky bits from the archive are never applied. See ARCHITECTURE.md §5.2.
 */
```

### 7.4 NOTE Comments

```c
/* NOTE: src_len in ark_write_chunk is the compressed byte count, not the
 *       uncompressed input size. Incompressible content produces compressed
 *       output slightly larger than ARK_CHUNK_SIZE. No upper bound check.
 *       See ARCHITECTURE.md §16.3. */

/* NOTE: chunk_sizes in ark_member_meta_t is an output field on the read
 *       path only. It is never populated by callers on the write path.
 *       The write context owns chunk sizes internally. */

/* NOTE: AT_SYMLINK_NOFOLLOW is required for utimensat on symlink members.
 *       Without it, utimensat follows the symlink and modifies the target's
 *       mtime. See ARCHITECTURE.md §14.5. */

/* NOTE: The minimum valid index entry is 84 bytes. The pre-allocation bound
 *       member_count > index_size / 84 must be checked before any allocation.
 *       See ARCHITECTURE.md §5.1. */
```

---

## 8. Pre-Commit Checklist

Before every commit:

- [ ] Compiles without warnings on Linux
      (`-Wall -Wextra -Wpedantic -Werror`)
- [ ] Compiles without warnings on OpenBSD
      (`-Wall -Wextra -Wpedantic -Werror`)
- [ ] All tests pass (`make test`)
- [ ] Valgrind clean on Linux (`make valgrind`)
- [ ] ASan/UBSan clean on Linux (`make dev`)
- [ ] clang-format clean (`make format`)
- [ ] All syscall invocations in `src/` use `ARK_*` wrapper macros - verify:
      `grep -n "\bread\b\|\bwrite\b\|\bopen\b\|\blstat\b\|\bunlink\b\|\blchown\b\|\butimensat\b" src/*.c`
- [ ] No malloc in the hot path (per-chunk loop) - verify:
      `grep -n "malloc\|calloc\|realloc" src/archive.c src/main.c`
- [ ] Every malloc has a matching free on all paths, including error paths
- [ ] Every opened fd is initialised to -1 and closed only if != -1
- [ ] `O_CLOEXEC` set on every `open` call
- [ ] `close` is not retried on `EINTR` anywhere
- [ ] `lchown` always precedes `chmod` on all metadata restoration paths
- [ ] `chmod` is never called on symlink members
- [ ] `utimensat` uses `AT_SYMLINK_NOFOLLOW` for symlink members
- [ ] `O_NOFOLLOW` on all extraction `open` calls
- [ ] Mode bits masked to `0777` before every `chmod` / `fchmod` call
- [ ] `ark_write_chunk` is never called from a worker thread
- [ ] Worker error path writes abort sentinel before returning
- [ ] Worker error path stores error in shared atomic struct before sentinel
- [ ] I/O thread checks ring buffer slots for abort sentinel before consuming
- [ ] Thread quiescence sequence follows §14.3 order: cancel flag, stop
      submission, join workers, close fd, cleanup
- [ ] No filesystem cleanup races an active worker
- [ ] Every extracted object is registered with cleanup tracker immediately
      after creation, before the next fallible operation
- [ ] `chunk_sizes` in `ark_member_meta_t` is NULL on all write-path call sites
- [ ] `ark_write_free` is called on all paths including error paths
- [ ] Primary error is captured before `goto cleanup` on every failure path
- [ ] `cleanup_created` does not modify `ark_error_t`
- [ ] `SAFETY:` comment present on every new safety-critical invariant
- [ ] New public API functions have complete doc comment blocks
- [ ] New sequence steps have ARCHITECTURE.md cross-reference comments
- [ ] No `FIXME` added without a comment explaining what is deferred and why
- [ ] TSan clean at phase boundaries involving concurrent data structures
      (`make test-tsan`)
