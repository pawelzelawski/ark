/*
 * archive.c - Archive format read/write implementation.
 *
 * Implements archive.h write/read APIs. This phase implements the write path
 * state machine and byte serialization rules from ARCHITECTURE.md section 16.3.
 */

#include "archive.h"
#include "ark_internal.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"
#include "sha256.h"

#define ARK_HEADER_SIZE 16U
#define ARK_FOOTER_SIZE 64U
#define ARK_INDEX_FIXED_META_SIZE 79U

enum ark_write_state {
	ARK_WRITE_STATE_UNINIT = 0,
	ARK_WRITE_STATE_READY,
	ARK_WRITE_STATE_IDLE,
	ARK_WRITE_STATE_MEMBER,
	ARK_WRITE_STATE_INDEXED,
	ARK_WRITE_STATE_DONE,
};

typedef struct {
	ark_hash_alg_t alg;
	union {
		ark_blake3_ctx_t blake3;
		ark_sha256_ctx_t sha256;
	} u;
} ark_hash_state_t;

struct ark_write_ctx {
	enum ark_write_state state;
	ark_hash_alg_t hash_alg;
	ark_deflate_mode_t mode;
	ark_member_meta_t *members;
	uint32_t member_count;
	uint32_t member_cap;
	ark_member_meta_t current;
	uint32_t current_chunk_cap;
	uint8_t index_hash[32];
	int index_hash_valid;
	ark_hash_state_t member_hash;
};

struct ark_read_ctx {
	int state;
};

static void buf_zero(void *dst, size_t len)
{
	uint8_t *p;
	size_t i;

	p = (uint8_t *)dst;
	for (i = 0U; i < len; i++)
		p[i] = 0U;
}

static void buf_copy(void *dst, const void *src, size_t len)
{
	uint8_t *d;
	const uint8_t *s;
	size_t i;

	d = (uint8_t *)dst;
	s = (const uint8_t *)src;
	for (i = 0U; i < len; i++)
		d[i] = s[i];
}

static void msg_copy(char *dst, size_t dst_cap, const char *src)
{
	size_t i;

	if (dst_cap == 0U)
		return;
	i = 0U;
	while (src[i] != '\0' && i + 1U < dst_cap) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

static int ark_fail(ark_error_t *err, ark_err_t code, const char *msg,
                    int sys_errno)
{
	if (err != NULL) {
		err->code = code;
		err->sys_errno = sys_errno;
		msg_copy(err->msg, sizeof(err->msg), msg);
		err->path[0] = '\0';
	}
	return -1;
}

static void le16_put(uint8_t *dst, uint16_t v)
{
	dst[0] = (uint8_t)(v & 0xffU);
	dst[1] = (uint8_t)((v >> 8) & 0xffU);
}

static void le32_put(uint8_t *dst, uint32_t v)
{
	dst[0] = (uint8_t)(v & 0xffU);
	dst[1] = (uint8_t)((v >> 8) & 0xffU);
	dst[2] = (uint8_t)((v >> 16) & 0xffU);
	dst[3] = (uint8_t)((v >> 24) & 0xffU);
}

static void le64_put(uint8_t *dst, uint64_t v)
{
	dst[0] = (uint8_t)(v & 0xffU);
	dst[1] = (uint8_t)((v >> 8) & 0xffU);
	dst[2] = (uint8_t)((v >> 16) & 0xffU);
	dst[3] = (uint8_t)((v >> 24) & 0xffU);
	dst[4] = (uint8_t)((v >> 32) & 0xffU);
	dst[5] = (uint8_t)((v >> 40) & 0xffU);
	dst[6] = (uint8_t)((v >> 48) & 0xffU);
	dst[7] = (uint8_t)((v >> 56) & 0xffU);
}

static int size_add_overflow(size_t a, size_t b, size_t *out)
{
	if (SIZE_MAX - a < b)
		return 1;
	*out = a + b;
	return 0;
}

static int hash_init(ark_hash_state_t *st, ark_hash_alg_t alg, ark_error_t *err)
{
	st->alg = alg;
	if (alg == ARK_HASH_BLAKE3) {
		ark_blake3_init(&st->u.blake3);
		return 0;
	}
	if (alg == ARK_HASH_SHA256) {
		ark_sha256_init(&st->u.sha256);
		return 0;
	}
	return ark_fail(err, ARK_ERR_USAGE, "unknown hash algorithm", 0);
}

static void hash_update(ark_hash_state_t *st, const uint8_t *buf, size_t len)
{
	if (st->alg == ARK_HASH_BLAKE3) {
		ark_blake3_update(&st->u.blake3, buf, len);
		return;
	}
	ark_sha256_update(&st->u.sha256, buf, len);
}

static void hash_final(ark_hash_state_t *st, uint8_t out[32])
{
	if (st->alg == ARK_HASH_BLAKE3) {
		ark_blake3_final(&st->u.blake3, out);
		return;
	}
	ark_sha256_final(&st->u.sha256, out);
}

static void member_clear(ark_member_meta_t *m)
{
	if (m->chunk_sizes != NULL)
		free(m->chunk_sizes);
	buf_zero(m, sizeof(*m));
}

static int members_grow(ark_write_ctx_t *ctx, ark_error_t *err)
{
	ark_member_meta_t *new_members;
	uint32_t new_cap;

	new_cap = ctx->member_cap == 0U ? 8U : ctx->member_cap * 2U;
	new_members =
	    realloc(ctx->members, (size_t)new_cap * sizeof(ctx->members[0]));
	if (new_members == NULL)
		return ark_fail(err, ARK_ERR_IO_ALLOC, "grow member array", 0);
	/* OWNERSHIP: ctx->members remains owned by ctx and freed in
	 * ark_write_free. */
	ctx->members = new_members;
	ctx->member_cap = new_cap;
	return 0;
}

static int current_chunks_grow(ark_write_ctx_t *ctx, ark_error_t *err)
{
	uint32_t *new_chunks;
	uint32_t new_cap;

	new_cap =
	    ctx->current_chunk_cap == 0U ? 8U : ctx->current_chunk_cap * 2U;
	new_chunks =
	    realloc(ctx->current.chunk_sizes,
	            (size_t)new_cap * sizeof(ctx->current.chunk_sizes[0]));
	if (new_chunks == NULL)
		return ark_fail(err, ARK_ERR_IO_ALLOC, "grow chunk size array",
		                0);
	/* OWNERSHIP: current chunk_sizes stays context-owned until
	 * ark_write_free. */
	ctx->current.chunk_sizes = new_chunks;
	ctx->current_chunk_cap = new_cap;
	return 0;
}

static int member_append(ark_write_ctx_t *ctx, ark_error_t *err)
{
	if (ctx->member_count == ctx->member_cap) {
		if (members_grow(ctx, err) != 0)
			return -1;
	}
	/* OWNERSHIP: chunk_sizes pointer transfers from ctx->current to
	 * members[]. */
	ctx->members[ctx->member_count++] = ctx->current;
	buf_zero(&ctx->current, sizeof(ctx->current));
	ctx->current_chunk_cap = 0;
	return 0;
}

static int member_index_size(const ark_member_meta_t *m, size_t *out,
                             ark_error_t *err)
{
	size_t total;
	size_t path_len;
	size_t add;

	path_len = strnlen(m->path, sizeof(m->path));
	if (path_len == 0U || path_len >= sizeof(m->path))
		return ark_fail(err, ARK_ERR_USAGE, "invalid member path", 0);
	if (path_len > UINT16_MAX)
		return ark_fail(err, ARK_ERR_USAGE, "path too long for u16", 0);

	total = ARK_INDEX_FIXED_META_SIZE;
	if (size_add_overflow(total, path_len, &total) != 0)
		return ark_fail(err, ARK_ERR_USAGE, "index size overflow", 0);

	if (m->type == 0x03U || m->type == 0x04U) {
		size_t link_len;

		link_len = strnlen(m->link, sizeof(m->link));
		if (link_len >= sizeof(m->link))
			return ark_fail(err, ARK_ERR_USAGE,
			                "invalid link field", 0);
		if (link_len > UINT16_MAX)
			return ark_fail(err, ARK_ERR_USAGE,
			                "link too long for u16", 0);
		if (size_add_overflow(total, 2U, &total) != 0)
			return ark_fail(err, ARK_ERR_USAGE,
			                "index size overflow", 0);
		if (size_add_overflow(total, link_len, &total) != 0)
			return ark_fail(err, ARK_ERR_USAGE,
			                "index size overflow", 0);
	}

	if (size_add_overflow(total, 4U, &total) != 0)
		return ark_fail(err, ARK_ERR_USAGE, "index size overflow", 0);
	add = (size_t)m->chunk_count * sizeof(uint32_t);
	if (size_add_overflow(total, add, &total) != 0)
		return ark_fail(err, ARK_ERR_USAGE, "index size overflow", 0);

	*out = total;
	return 0;
}

/*
 * Serialize one index entry as specified by ARCHITECTURE.md section 5.2.
 */
static int member_write_index(const ark_member_meta_t *m, uint8_t *dst,
                              size_t dst_cap, size_t *written, ark_error_t *err)
{
	size_t need;
	size_t off;
	size_t path_len;
	size_t link_len;
	uint32_t i;

	if (member_index_size(m, &need, err) != 0)
		return -1;
	if (dst_cap < need)
		return ark_fail(err, ARK_ERR_IO_ALLOC,
		                "index destination too small", 0);

	path_len = strnlen(m->path, sizeof(m->path));
	link_len = strnlen(m->link, sizeof(m->link));

	off = 0U;
	dst[off++] = m->type;
	le32_put(dst + off, m->mode);
	off += 4U;
	le32_put(dst + off, m->uid);
	off += 4U;
	le32_put(dst + off, m->gid);
	off += 4U;
	le64_put(dst + off, m->mtime);
	off += 8U;
	le64_put(dst + off, m->size_original);
	off += 8U;
	le64_put(dst + off, m->size_compressed);
	off += 8U;
	le64_put(dst + off, m->data_offset);
	off += 8U;
	buf_copy(dst + off, m->hash, sizeof(m->hash));
	off += sizeof(m->hash);
	le16_put(dst + off, (uint16_t)path_len);
	off += 2U;

	buf_copy(dst + off, m->path, path_len);
	off += path_len;

	if (m->type == 0x03U || m->type == 0x04U) {
		le16_put(dst + off, (uint16_t)link_len);
		off += 2U;
		buf_copy(dst + off, m->link, link_len);
		off += link_len;
	}

	le32_put(dst + off, m->chunk_count);
	off += 4U;
	for (i = 0U; i < m->chunk_count; i++) {
		le32_put(dst + off, m->chunk_sizes[i]);
		off += 4U;
	}

	*written = off;
	return 0;
}

int ark_write_init(ark_write_ctx_t *ctx, ark_hash_alg_t hash_alg,
                   ark_deflate_mode_t mode, ark_error_t *err)
{
	if (ctx == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null write context", 0);
	if (ctx->state != ARK_WRITE_STATE_UNINIT)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write init out of sequence", 0);
	if (hash_alg != ARK_HASH_BLAKE3 && hash_alg != ARK_HASH_SHA256)
		return ark_fail(err, ARK_ERR_USAGE, "invalid hash algorithm",
		                0);

	buf_zero(ctx, sizeof(*ctx));
	ctx->hash_alg = hash_alg;
	ctx->mode = mode;
	ctx->state = ARK_WRITE_STATE_READY;
	return 0;
}

ssize_t ark_write_header(ark_write_ctx_t *ctx, uint8_t *dst, size_t dst_cap,
                         ark_error_t *err)
{
	if (ctx == NULL || dst == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null header argument", 0);
	/* ARCHITECTURE.md section 16.3: READY -> IDLE transition only. */
	if (ctx->state != ARK_WRITE_STATE_READY)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write header out of sequence", 0);
	if (dst_cap < ARK_HEADER_SIZE)
		return ark_fail(err, ARK_ERR_IO_ALLOC,
		                "header destination too small", 0);

	/* ARCHITECTURE.md section 3 fixed 16-byte header layout. */
	dst[0] = 0x61U;
	dst[1] = 0x72U;
	dst[2] = 0x6bU;
	dst[3] = 0x21U;
	dst[4] = 0x0aU;
	dst[5] = 0x01U;
	dst[6] = 0x00U;
	dst[7] = 0x00U;
	dst[8] = 0x01U;
	dst[9] = (uint8_t)ctx->hash_alg;
	buf_zero(dst + 10U, 6U);

	ctx->state = ARK_WRITE_STATE_IDLE;
	return (ssize_t)ARK_HEADER_SIZE;
}

int ark_write_member_begin(ark_write_ctx_t *ctx, const ark_member_meta_t *meta,
                           ark_error_t *err)
{
	size_t path_len;

	if (ctx == NULL || meta == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null member argument", 0);
	/* ARCHITECTURE.md section 16.3: IDLE -> MEMBER transition only. */
	if (ctx->state != ARK_WRITE_STATE_IDLE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write member begin out of sequence", 0);

	path_len = strnlen(meta->path, sizeof(meta->path));
	if (path_len == 0U || path_len >= sizeof(meta->path))
		return ark_fail(err, ARK_ERR_USAGE, "invalid member path", 0);
	if (meta->type == 0x03U || meta->type == 0x04U) {
		size_t link_len;

		link_len = strnlen(meta->link, sizeof(meta->link));
		if (link_len >= sizeof(meta->link))
			return ark_fail(err, ARK_ERR_USAGE,
			                "invalid member link", 0);
	}

	ctx->current = *meta;
	ctx->current.chunk_sizes = NULL;
	ctx->current.chunk_count = 0U;
	ctx->current_chunk_cap = 0U;

	if (ctx->current.type != 0x01U) {
		ctx->current.size_original = 0U;
		ctx->current.size_compressed = 0U;
		ctx->current.data_offset = 0U;
		ctx->current.chunk_count = 0U;
	}

	if (hash_init(&ctx->member_hash, ctx->hash_alg, err) != 0)
		return -1;

	ctx->state = ARK_WRITE_STATE_MEMBER;
	return 0;
}

ssize_t ark_write_chunk(ark_write_ctx_t *ctx, const uint8_t *src,
                        size_t src_len, uint8_t *dst, size_t dst_cap,
                        ark_error_t *err)
{
	if (ctx == NULL || dst == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null chunk argument", 0);
	/*
	 * SAFETY: write chunk is valid only while a regular-file member is
	 * active. See ARCHITECTURE.md section 16.3.
	 */
	if (ctx->state != ARK_WRITE_STATE_MEMBER)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write chunk out of sequence", 0);
	if (ctx->current.type != 0x01U)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write chunk on non-regular member", 0);
	if (src_len > (size_t)UINT32_MAX)
		return ark_fail(err, ARK_ERR_USAGE, "chunk size exceeds u32",
		                0);
	if (dst_cap < src_len)
		return ark_fail(err, ARK_ERR_IO_ALLOC,
		                "chunk destination too small", 0);
	if (src_len > 0U && src == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null chunk source", 0);

	if (ctx->current.chunk_count == ctx->current_chunk_cap) {
		if (current_chunks_grow(ctx, err) != 0)
			return -1;
	}

	/* NOTE: src_len is compressed size, not uncompressed input size. */
	hash_update(&ctx->member_hash, src, src_len);
	ctx->current.chunk_sizes[ctx->current.chunk_count++] =
	    (uint32_t)src_len;
	ctx->current.size_compressed += (uint64_t)src_len;
	if (src_len > 0U)
		buf_copy(dst, src, src_len);
	return (ssize_t)src_len;
}

int ark_write_member_end(ark_write_ctx_t *ctx, ark_error_t *err)
{
	if (ctx == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null write context", 0);
	if (ctx->state != ARK_WRITE_STATE_MEMBER)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write member end out of sequence", 0);

	/* ARCHITECTURE.md section 8.2: member hash covers compressed bytes
	 * only. */
	hash_final(&ctx->member_hash, ctx->current.hash);
	/*
	 * ARCHITECTURE.md section 5.2: non-file members carry no data ranges.
	 * SAFETY: force zeroed size/data/chunk fields for non-regular entries.
	 */
	if (ctx->current.type != 0x01U) {
		ctx->current.size_original = 0U;
		ctx->current.size_compressed = 0U;
		ctx->current.data_offset = 0U;
		ctx->current.chunk_count = 0U;
	}
	if (member_append(ctx, err) != 0)
		return -1;

	ctx->state = ARK_WRITE_STATE_IDLE;
	return 0;
}

ssize_t ark_write_index(ark_write_ctx_t *ctx, uint8_t *dst, size_t dst_cap,
                        ark_error_t *err)
{
	ark_hash_state_t idx_hash;
	size_t i;
	size_t need;
	size_t total;
	size_t written;

	if (ctx == NULL || dst == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null index argument", 0);
	/* ARCHITECTURE.md section 16.3: IDLE -> INDEXED transition only. */
	if (ctx->state != ARK_WRITE_STATE_IDLE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write index out of sequence", 0);

	total = 0U;
	for (i = 0U; i < ctx->member_count; i++) {
		if (member_index_size(&ctx->members[i], &need, err) != 0)
			return -1;
		if (size_add_overflow(total, need, &total) != 0)
			return ark_fail(err, ARK_ERR_USAGE,
			                "index size overflow", 0);
	}
	if (dst_cap < total)
		return ark_fail(err, ARK_ERR_IO_ALLOC,
		                "index destination too small", 0);

	if (hash_init(&idx_hash, ctx->hash_alg, err) != 0)
		return -1;

	total = 0U;
	for (i = 0U; i < ctx->member_count; i++) {
		if (member_write_index(&ctx->members[i], dst + total,
		                       dst_cap - total, &written, err) != 0)
			return -1;
		/* ARCHITECTURE.md section 8.2: index hash is over full
		 * serialized index. */
		hash_update(&idx_hash, dst + total, written);
		total += written;
	}

	hash_final(&idx_hash, ctx->index_hash);
	ctx->index_hash_valid = 1;
	ctx->state = ARK_WRITE_STATE_INDEXED;
	return (ssize_t)total;
}

ssize_t ark_write_footer(ark_write_ctx_t *ctx, uint64_t index_offset,
                         uint64_t index_size, uint8_t *dst, size_t dst_cap,
                         ark_error_t *err)
{
	if (ctx == NULL || dst == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null footer argument", 0);
	if (ctx->state != ARK_WRITE_STATE_INDEXED)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write footer out of sequence", 0);
	if (dst_cap < ARK_FOOTER_SIZE)
		return ark_fail(err, ARK_ERR_IO_ALLOC,
		                "footer destination too small", 0);
	if (ctx->index_hash_valid == 0)
		return ark_fail(err, ARK_ERR_USAGE, "missing index hash", 0);

	/* ARCHITECTURE.md section 4 fixed 64-byte footer layout. */
	le64_put(dst + 0U, index_offset);
	le64_put(dst + 8U, index_size);
	buf_copy(dst + 16U, ctx->index_hash, sizeof(ctx->index_hash));
	le32_put(dst + 48U, ctx->member_count);
	le32_put(dst + 52U, 0x4b52410aU);
	buf_zero(dst + 56U, 8U);

	ctx->state = ARK_WRITE_STATE_DONE;
	return (ssize_t)ARK_FOOTER_SIZE;
}

void ark_write_free(ark_write_ctx_t *ctx)
{
	uint32_t i;

	if (ctx == NULL)
		return;

	member_clear(&ctx->current);
	for (i = 0U; i < ctx->member_count; i++)
		member_clear(&ctx->members[i]);
	free(ctx->members);
	buf_zero(ctx, sizeof(*ctx));
}

int ark_read_header(ark_read_ctx_t *ctx, const uint8_t *header_buf,
                    size_t header_len, ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)header_buf;
	(void)header_len;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

int ark_read_init(ark_read_ctx_t *ctx, const uint8_t *footer_buf,
                  size_t footer_len, ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)footer_buf;
	(void)footer_len;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

int ark_read_index(ark_read_ctx_t *ctx, const uint8_t *index_buf,
                   size_t index_len, ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)index_buf;
	(void)index_len;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

const ark_member_meta_t *ark_read_member_meta(const ark_read_ctx_t *ctx,
                                              uint32_t pos)
{
	if (ctx != NULL)
		(void)ctx->state;
	(void)ctx;
	(void)pos;
	return NULL;
}

ssize_t ark_read_chunk(ark_read_ctx_t *ctx, const ark_member_meta_t *meta,
                       uint32_t chunk_index, const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)meta;
	(void)chunk_index;
	(void)src;
	(void)src_len;
	(void)dst;
	(void)dst_cap;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

int ark_read_verify_member_begin(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)meta;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

int ark_read_verify_member_update(ark_read_ctx_t *ctx,
                                  const ark_member_meta_t *meta,
                                  const uint8_t *chunk_data, size_t chunk_len,
                                  ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)meta;
	(void)chunk_data;
	(void)chunk_len;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

int ark_read_verify_member_final(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err)
{
	if (ctx != NULL)
		ctx->state = 0;
	(void)ctx;
	(void)meta;
	return ark_fail(err, ARK_ERR_USAGE, "read path not implemented", 0);
}

void ark_read_free(ark_read_ctx_t *ctx)
{
	if (ctx == NULL)
		return;
	buf_zero(ctx, sizeof(*ctx));
}
