/*
 * archive.c - Archive format read/write implementation.
 *
 * Implements archive.h write/read APIs. This phase implements the write path
 * state machine and byte serialization rules from ARCHITECTURE.md section 16.3.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "blake3.h"
#include "deflate.h"
#include "sha256.h"

#include "ark_internal.h"

#define ARK_HEADER_SIZE 16U
#define ARK_FOOTER_SIZE 64U
#define ARK_INDEX_FIXED_META_SIZE 79U
#define ARK_INDEX_MIN_ENTRY_SIZE 84U

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

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
	enum ark_read_state {
		ARK_READ_STATE_UNINIT = 0,
		ARK_READ_STATE_HEADER_DONE,
		ARK_READ_STATE_FOOTER_DONE,
		ARK_READ_STATE_INDEX_DONE,
	} state;
	uint8_t comp_alg;
	ark_hash_alg_t hash_alg;
	uint8_t ver_major;
	uint8_t ver_minor;
	uint64_t index_offset;
	uint64_t index_size;
	uint32_t member_count;
	uint8_t index_hash[32];
	ark_member_meta_t *members;
	ark_hash_state_t verify_hash;
	const ark_member_meta_t *verify_meta;
	uint32_t verify_next_chunk;
	int verify_active;
};

_Static_assert(sizeof(struct ark_write_ctx) <= ARK_WRITE_CTX_STORAGE_SIZE,
               "ark_write_ctx_storage_t too small");
_Static_assert(sizeof(struct ark_read_ctx) <= ARK_READ_CTX_STORAGE_SIZE,
               "ark_read_ctx_storage_t too small");
_Static_assert(_Alignof(struct ark_write_ctx) <= _Alignof(max_align_t),
               "ark_write_ctx_storage_t alignment too small");
_Static_assert(_Alignof(struct ark_read_ctx) <= _Alignof(max_align_t),
               "ark_read_ctx_storage_t alignment too small");

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

static uint16_t le16_get(const uint8_t *src)
{
	return (uint16_t)src[0] | ((uint16_t)src[1] << 8);
}

static uint32_t le32_get(const uint8_t *src)
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static uint64_t le64_get(const uint8_t *src)
{
	return (uint64_t)src[0] | ((uint64_t)src[1] << 8) |
	       ((uint64_t)src[2] << 16) | ((uint64_t)src[3] << 24) |
	       ((uint64_t)src[4] << 32) | ((uint64_t)src[5] << 40) |
	       ((uint64_t)src[6] << 48) | ((uint64_t)src[7] << 56);
}

static int size_add_overflow(size_t a, size_t b, size_t *out)
{
	if (SIZE_MAX - a < b)
		return 1;
	*out = a + b;
	return 0;
}

static int u64_add_overflow(uint64_t a, uint64_t b, uint64_t *out)
{
	if (UINT64_MAX - a < b)
		return 1;
	*out = a + b;
	return 0;
}

static int utf8_valid(const uint8_t *s, size_t len)
{
	size_t i;

	i = 0U;
	while (i < len) {
		uint8_t c;

		c = s[i++];
		if (c <= 0x7fU)
			continue;
		if (c >= 0xc2U && c <= 0xdfU) {
			if (i >= len || (s[i] & 0xc0U) != 0x80U)
				return 0;
			i++;
			continue;
		}
		if (c == 0xe0U) {
			if (i + 1U >= len)
				return 0;
			if (s[i] < 0xa0U || s[i] > 0xbfU ||
			    (s[i + 1U] & 0xc0U) != 0x80U)
				return 0;
			i += 2U;
			continue;
		}
		if ((c >= 0xe1U && c <= 0xecU) || (c >= 0xeeU && c <= 0xefU)) {
			if (i + 1U >= len)
				return 0;
			if ((s[i] & 0xc0U) != 0x80U ||
			    (s[i + 1U] & 0xc0U) != 0x80U)
				return 0;
			i += 2U;
			continue;
		}
		if (c == 0xedU) {
			if (i + 1U >= len)
				return 0;
			if (s[i] < 0x80U || s[i] > 0x9fU ||
			    (s[i + 1U] & 0xc0U) != 0x80U)
				return 0;
			i += 2U;
			continue;
		}
		if (c == 0xf0U) {
			if (i + 2U >= len)
				return 0;
			if (s[i] < 0x90U || s[i] > 0xbfU ||
			    (s[i + 1U] & 0xc0U) != 0x80U ||
			    (s[i + 2U] & 0xc0U) != 0x80U)
				return 0;
			i += 3U;
			continue;
		}
		if (c >= 0xf1U && c <= 0xf3U) {
			if (i + 2U >= len)
				return 0;
			if ((s[i] & 0xc0U) != 0x80U ||
			    (s[i + 1U] & 0xc0U) != 0x80U ||
			    (s[i + 2U] & 0xc0U) != 0x80U)
				return 0;
			i += 3U;
			continue;
		}
		if (c == 0xf4U) {
			if (i + 2U >= len)
				return 0;
			if (s[i] < 0x80U || s[i] > 0x8fU ||
			    (s[i + 1U] & 0xc0U) != 0x80U ||
			    (s[i + 2U] & 0xc0U) != 0x80U)
				return 0;
			i += 3U;
			continue;
		}
		return 0;
	}
	return 1;
}

static int validate_path_components(const uint8_t *raw, size_t len,
                                    int reject_dot, ark_error_t *err)
{
	size_t i;
	size_t cstart;

	cstart = 0U;
	for (i = 0U; i <= len; i++) {
		size_t clen;

		if (i != len && raw[i] != '/')
			continue;
		clen = i - cstart;
		if (clen == 0U)
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "empty path component", 0);
		if (reject_dot != 0 && clen == 1U && raw[cstart] == '.')
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "dot component rejected", 0);
		if (clen == 2U && raw[cstart] == '.' && raw[cstart + 1U] == '.')
			return ark_fail(err, ARK_ERR_PATH_TRAVERSAL,
			                "dotdot component rejected", 0);
		cstart = i + 1U;
	}

	return 0;
}

static int validate_member_path_raw(const uint8_t *raw, size_t len,
                                    ark_error_t *err)
{
	size_t i;

	if (len == 0U)
		return ark_fail(err, ARK_ERR_FMT_INDEX, "empty path", 0);
	if (len > 1023U)
		return ark_fail(err, ARK_ERR_PATH_TOO_LONG,
		                "path exceeds 1023 bytes", 0);
	if (len >= (size_t)PATH_MAX)
		return ark_fail(err, ARK_ERR_PATH_TOO_LONG,
		                "path exceeds local PATH_MAX", 0);
	if (raw[0] == '/')
		return ark_fail(err, ARK_ERR_PATH_ABSOLUTE,
		                "absolute path rejected", 0);
	if (raw[len - 1U] == '/')
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "trailing slash rejected", 0);
	for (i = 0U; i < len; i++) {
		if (raw[i] == '\0')
			return ark_fail(err, ARK_ERR_FMT_INDEX, "NUL in path",
			                0);
	}
	if (utf8_valid(raw, len) == 0)
		return ark_fail(err, ARK_ERR_PATH_ENCODING,
		                "invalid UTF-8 path", 0);

	return validate_path_components(raw, len, 1, err);
}

static int validate_symlink_target_raw(const uint8_t *raw, size_t len,
                                       ark_error_t *err)
{
	size_t i;
	size_t cstart;

	if (len == 0U)
		return ark_fail(err, ARK_ERR_FMT_INDEX, "empty symlink target",
		                0);
	if (len > 1023U)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "link target exceeds 1023 bytes", 0);
	if (raw[0] == '/')
		return ark_fail(err, ARK_ERR_PATH_ABSOLUTE,
		                "absolute link target rejected", 0);
	for (i = 0U; i < len; i++) {
		if (raw[i] == '\0')
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "NUL in link target", 0);
	}
	if (utf8_valid(raw, len) == 0)
		return ark_fail(err, ARK_ERR_PATH_ENCODING,
		                "invalid UTF-8 link target", 0);

	cstart = 0U;
	for (i = 0U; i <= len; i++) {
		size_t clen;

		if (i != len && raw[i] != '/')
			continue;
		clen = i - cstart;
		if (clen == 2U && raw[cstart] == '.' && raw[cstart + 1U] == '.')
			return ark_fail(err, ARK_ERR_PATH_TRAVERSAL,
			                "dotdot link target rejected", 0);
		cstart = i + 1U;
	}

	return 0;
}

static int validate_hardlink_target_raw(const uint8_t *raw, size_t len,
                                        ark_error_t *err)
{
	if (len > 1023U)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "hardlink target exceeds 1023 bytes", 0);
	return validate_member_path_raw(raw, len, err);
}

static int find_member_by_path(const ark_member_meta_t *members, uint32_t n,
                               const char *path)
{
	uint32_t i;

	for (i = 0U; i < n; i++) {
		if (strcmp(members[i].path, path) == 0)
			return (int)i;
	}
	return -1;
}

static int validate_ancestors_full(const ark_member_meta_t *members,
                                   uint32_t member_count, uint32_t idx,
                                   ark_error_t *err)
{
	const char *path;
	const char *slash;
	char parent[1024];

	path = members[idx].path;
	slash = path;
	while ((slash = strchr(slash, '/')) != NULL) {
		size_t plen;
		int pidx;

		plen = (size_t)(slash - path);
		if (plen >= sizeof(parent))
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "ancestor path too long", 0);
		buf_copy(parent, path, plen);
		parent[plen] = '\0';
		pidx = find_member_by_path(members, member_count, parent);
		if (pidx < 0)
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "missing ancestor member", 0);
		if ((uint32_t)pidx >= idx)
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "ancestor appears after child", 0);
		if (members[pidx].type != 0x02U)
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "ancestor is not directory", 0);
		slash++;
	}

	return 0;
}

static int validate_present_ancestor_dirs(const ark_member_meta_t *members,
                                          uint32_t member_count, uint32_t idx,
                                          ark_error_t *err)
{
	const char *path;
	const char *slash;
	char parent[1024];

	path = members[idx].path;
	slash = path;
	while ((slash = strchr(slash, '/')) != NULL) {
		size_t plen;
		int pidx;

		plen = (size_t)(slash - path);
		if (plen >= sizeof(parent))
			return ark_fail(err, ARK_ERR_FMT_INDEX,
			                "ancestor path too long", 0);
		buf_copy(parent, path, plen);
		parent[plen] = '\0';
		pidx = find_member_by_path(members, member_count, parent);
		if (pidx >= 0) {
			if ((uint32_t)pidx >= idx)
				return ark_fail(err, ARK_ERR_FMT_INDEX,
				                "ancestor appears after child",
				                0);
			if (members[pidx].type != 0x02U)
				return ark_fail(
				    err, ARK_ERR_FMT_INDEX,
				    "present ancestor not directory", 0);
		}
		slash++;
	}

	return 0;
}

static int member_has_zero_data(const ark_member_meta_t *m)
{
	if (m->type != 0x01U)
		return 1;
	return m->size_original == 0U ? 1 : 0;
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

static int expected_chunk_count(uint64_t size_original, uint32_t *out)
{
	uint64_t n;

	if (size_original == 0U) {
		*out = 0U;
		return 0;
	}
	n = size_original / (uint64_t)ARK_CHUNK_SIZE;
	if (size_original % (uint64_t)ARK_CHUNK_SIZE != 0U)
		n++;
	if (n > (uint64_t)UINT32_MAX)
		return -1;
	*out = (uint32_t)n;
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
	size_t link_len;

	if (ctx == NULL || meta == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null member argument", 0);
	/* ARCHITECTURE.md section 16.3: IDLE -> MEMBER transition only. */
	if (ctx->state != ARK_WRITE_STATE_IDLE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write member begin out of sequence", 0);

	if (meta->type != 0x01U && meta->type != 0x02U && meta->type != 0x03U &&
	    meta->type != 0x04U)
		return ark_fail(err, ARK_ERR_USAGE, "invalid member type", 0);
	if (meta->chunk_sizes != NULL)
		return ark_fail(err, ARK_ERR_USAGE,
		                "write-path chunk_sizes must be NULL", 0);

	path_len = strnlen(meta->path, sizeof(meta->path));
	if (path_len == 0U || path_len >= sizeof(meta->path))
		return ark_fail(err, ARK_ERR_USAGE, "invalid member path", 0);
	if (validate_member_path_raw((const uint8_t *)meta->path, path_len,
	                             err) != 0)
		return -1;

	link_len = strnlen(meta->link, sizeof(meta->link));
	if (meta->type == 0x03U || meta->type == 0x04U) {
		if (link_len == 0U || link_len >= sizeof(meta->link))
			return ark_fail(err, ARK_ERR_USAGE,
			                "invalid member link", 0);
		if (meta->type == 0x03U) {
			if (validate_symlink_target_raw(
			        (const uint8_t *)meta->link, link_len, err) !=
			    0)
				return -1;
		} else {
			if (validate_hardlink_target_raw(
			        (const uint8_t *)meta->link, link_len, err) !=
			    0)
				return -1;
		}
	} else if (link_len != 0U) {
		return ark_fail(err, ARK_ERR_USAGE,
		                "link field present for non-link member", 0);
	}

	ctx->current = *meta;
	ctx->current.chunk_sizes = NULL;
	ctx->current.chunk_count = 0U;
	ctx->current.size_compressed = 0U;
	ctx->current_chunk_cap = 0U;

	if (ctx->current.type == 0x01U && ctx->current.size_original == 0U)
		ctx->current.data_offset = 0U;
	else if (ctx->current.type != 0x01U) {
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
	if (ctx->current.chunk_count == UINT32_MAX)
		return ark_fail(err, ARK_ERR_USAGE, "too many chunks", 0);
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
	if (u64_add_overflow(ctx->current.size_compressed, (uint64_t)src_len,
	                     &ctx->current.size_compressed) != 0)
		return ark_fail(err, ARK_ERR_USAGE, "compressed size overflow",
		                0);
	if (src_len > 0U)
		buf_copy(dst, src, src_len);
	return (ssize_t)src_len;
}

int ark_write_member_end(ark_write_ctx_t *ctx, ark_error_t *err)
{
	uint32_t expected_chunks;

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
	if (ctx->current.type == 0x01U) {
		if (expected_chunk_count(ctx->current.size_original,
		                         &expected_chunks) != 0)
			return ark_fail(err, ARK_ERR_USAGE,
			                "regular member too large", 0);
		if (ctx->current.chunk_count != expected_chunks)
			return ark_fail(err, ARK_ERR_USAGE,
			                "regular member chunk count mismatch",
			                0);
		if (ctx->current.size_original == 0U) {
			ctx->current.size_compressed = 0U;
			ctx->current.data_offset = 0U;
		} else if (ctx->current.data_offset < ARK_HEADER_SIZE) {
			return ark_fail(err, ARK_ERR_USAGE,
			                "regular member data offset too low",
			                0);
		}
	} else {
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
	if (ctx == NULL || header_buf == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null read header argument",
		                0);
	/* ARCHITECTURE.md section 16.4: header must be first read call. */
	if (ctx->state != ARK_READ_STATE_UNINIT)
		return ark_fail(err, ARK_ERR_USAGE,
		                "read header out of sequence", 0);
	if (header_len != ARK_HEADER_SIZE)
		return ark_fail(err, ARK_ERR_FMT_TRUNCATED,
		                "header length must be 16 bytes", 0);

	/* ARCHITECTURE.md section 3 fixed header validation. */
	if (header_buf[0] != 0x61U || header_buf[1] != 0x72U ||
	    header_buf[2] != 0x6bU || header_buf[3] != 0x21U ||
	    header_buf[4] != 0x0aU)
		return ark_fail(err, ARK_ERR_FMT_MAGIC, "header magic mismatch",
		                0);
	if (header_buf[5] != 0x01U)
		return ark_fail(err, ARK_ERR_FMT_VERSION,
		                "unsupported major version", 0);
	if (header_buf[7] != 0x00U)
		return ark_fail(err, ARK_ERR_FMT_RESERVED,
		                "header flags must be zero", 0);
	if (header_buf[8] != 0x01U)
		return ark_fail(err, ARK_ERR_FMT_COMP_ALG,
		                "unknown compression algorithm", 0);
	if (header_buf[9] != (uint8_t)ARK_HASH_BLAKE3 &&
	    header_buf[9] != (uint8_t)ARK_HASH_SHA256)
		return ark_fail(err, ARK_ERR_FMT_HASH_ALG,
		                "unknown hash algorithm", 0);
	if (header_buf[10] != 0U || header_buf[11] != 0U ||
	    header_buf[12] != 0U || header_buf[13] != 0U ||
	    header_buf[14] != 0U || header_buf[15] != 0U)
		return ark_fail(err, ARK_ERR_FMT_RESERVED,
		                "header reserved bytes must be zero", 0);

	ctx->comp_alg = header_buf[8];
	ctx->hash_alg = (ark_hash_alg_t)header_buf[9];
	ctx->ver_major = header_buf[5];
	ctx->ver_minor = header_buf[6];
	ctx->state = ARK_READ_STATE_HEADER_DONE;
	return 0;
}

int ark_read_init(ark_read_ctx_t *ctx, const uint8_t *footer_buf,
                  size_t footer_len, ark_error_t *err)
{
	if (ctx == NULL || footer_buf == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null read footer argument",
		                0);
	if (ctx->state != ARK_READ_STATE_HEADER_DONE)
		return ark_fail(err, ARK_ERR_USAGE, "read init out of sequence",
		                0);
	if (footer_len != ARK_FOOTER_SIZE)
		return ark_fail(err, ARK_ERR_FMT_TRUNCATED,
		                "footer length must be 64 bytes", 0);

	/* ARCHITECTURE.md section 4 footer parse and validation. */
	if (le32_get(footer_buf + 52U) != 0x4b52410aU)
		return ark_fail(err, ARK_ERR_FMT_MAGIC,
		                "footer magic confirmation mismatch", 0);
	if (footer_buf[56] != 0U || footer_buf[57] != 0U ||
	    footer_buf[58] != 0U || footer_buf[59] != 0U ||
	    footer_buf[60] != 0U || footer_buf[61] != 0U ||
	    footer_buf[62] != 0U || footer_buf[63] != 0U)
		return ark_fail(err, ARK_ERR_FMT_RESERVED,
		                "footer reserved bytes must be zero", 0);

	ctx->index_offset = le64_get(footer_buf + 0U);
	ctx->index_size = le64_get(footer_buf + 8U);
	ctx->member_count = le32_get(footer_buf + 48U);
	buf_copy(ctx->index_hash, footer_buf + 16U, sizeof(ctx->index_hash));
	ctx->state = ARK_READ_STATE_FOOTER_DONE;
	return 0;
}

int ark_read_index(ark_read_ctx_t *ctx, const uint8_t *index_buf,
                   size_t index_len, ark_error_t *err)
{
	ark_hash_state_t idx_hash;
	ark_member_meta_t *members;
	uint8_t empty_hash[32];
	struct body_range {
		uint64_t start;
		uint64_t end;
	} *ranges;
	uint32_t i;
	size_t off;

	if (ctx == NULL || index_buf == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null read index argument",
		                0);
	if (ctx->state != ARK_READ_STATE_FOOTER_DONE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "read index out of sequence", 0);
	if (ctx->index_size > (uint64_t)SIZE_MAX)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "index size does not fit platform size_t", 0);
	if (index_len != (size_t)ctx->index_size)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "index buffer length mismatch", 0);

	/* ARCHITECTURE.md section 5.1 pre-allocation bound (minimum entry 84B).
	 */
	if (ctx->member_count >
	    (uint32_t)(ctx->index_size / ARK_INDEX_MIN_ENTRY_SIZE))
		return ark_fail(
		    err, ARK_ERR_FMT_INDEX,
		    "member_count exceeds index pre-allocation bound", 0);

	/* ARCHITECTURE.md section 8.3 check 2: verify index hash before parse.
	 */
	if (hash_init(&idx_hash, ctx->hash_alg, err) != 0)
		return -1;
	hash_update(&idx_hash, index_buf, index_len);
	hash_final(&idx_hash, empty_hash);
	if (memcmp(empty_hash, ctx->index_hash, sizeof(empty_hash)) != 0)
		return ark_fail(err, ARK_ERR_HASH_INDEX, "index hash mismatch",
		                0);

	members = NULL;
	ranges = NULL;
	if (ctx->member_count > 0U) {
		members = calloc(ctx->member_count, sizeof(members[0]));
		if (members == NULL)
			return ark_fail(err, ARK_ERR_IO_ALLOC,
			                "allocate index member table", 0);
	}
	/* OWNERSHIP: members and nested chunk_sizes transfer to ctx on success
	 * and are released by ark_read_free. */

	off = 0U;
	for (i = 0U; i < ctx->member_count; i++) {
		ark_member_meta_t *m;
		size_t path_len;
		size_t chunk_bytes;
		uint64_t chunk_sum;
		uint32_t expected_chunks;
		uint32_t j;

		m = &members[i];
		if (off > index_len ||
		    index_len - off < ARK_INDEX_FIXED_META_SIZE)
			goto fmt_index;

		m->type = index_buf[off + 0U];
		if (m->type != 0x01U && m->type != 0x02U && m->type != 0x03U &&
		    m->type != 0x04U)
			goto fmt_member_type;
		m->mode = le32_get(index_buf + off + 1U);
		m->uid = le32_get(index_buf + off + 5U);
		m->gid = le32_get(index_buf + off + 9U);
		m->mtime = le64_get(index_buf + off + 13U);
		m->size_original = le64_get(index_buf + off + 21U);
		m->size_compressed = le64_get(index_buf + off + 29U);
		m->data_offset = le64_get(index_buf + off + 37U);
		buf_copy(m->hash, index_buf + off + 45U, sizeof(m->hash));
		path_len = (size_t)le16_get(index_buf + off + 77U);
		off += ARK_INDEX_FIXED_META_SIZE;

		if (path_len == 0U)
			goto fmt_index;
		if (path_len >= sizeof(m->path)) {
			ark_fail(err, ARK_ERR_PATH_TOO_LONG,
			         "path exceeds 1023 bytes", 0);
			goto fail;
		}
		if (off > index_len || index_len - off < path_len)
			goto fmt_index;
		if (validate_member_path_raw(index_buf + off, path_len, err) !=
		    0)
			goto fail;
		buf_copy(m->path, index_buf + off, path_len);
		m->path[path_len] = '\0';
		off += path_len;

		m->link[0] = '\0';
		if (m->type == 0x03U || m->type == 0x04U) {
			size_t link_len;

			if (off > index_len || index_len - off < 2U)
				goto fmt_index;
			link_len = (size_t)le16_get(index_buf + off);
			off += 2U;
			if (link_len == 0U || link_len >= sizeof(m->link))
				goto fmt_index;
			if (off > index_len || index_len - off < link_len)
				goto fmt_index;
			if (m->type == 0x03U) {
				if (validate_symlink_target_raw(
				        index_buf + off, link_len, err) != 0)
					goto fail;
			} else if (validate_hardlink_target_raw(
			               index_buf + off, link_len, err) != 0) {
				goto fail;
			}
			buf_copy(m->link, index_buf + off, link_len);
			m->link[link_len] = '\0';
			off += link_len;
		}

		if (off > index_len || index_len - off < 4U)
			goto fmt_index;
		m->chunk_count = le32_get(index_buf + off);
		off += 4U;

		if (m->type != 0x01U) {
			if (m->size_original != 0U ||
			    m->size_compressed != 0U || m->data_offset != 0U ||
			    m->chunk_count != 0U)
				goto fmt_index;
		} else {
			if (m->size_original == 0U) {
				if (m->size_compressed != 0U ||
				    m->data_offset != 0U ||
				    m->chunk_count != 0U)
					goto fmt_index;
			} else {
				if (expected_chunk_count(m->size_original,
				                         &expected_chunks) != 0)
					goto fmt_index;
				if (m->chunk_count != expected_chunks)
					goto fmt_index;
			}
		}

		if ((size_t)m->chunk_count > SIZE_MAX / sizeof(uint32_t))
			goto fmt_index;
		chunk_bytes = (size_t)m->chunk_count * sizeof(uint32_t);
		if (m->chunk_count > 0U) {
			if (off > index_len || index_len - off < chunk_bytes)
				goto fmt_index;
			m->chunk_sizes = malloc(chunk_bytes);
			if (m->chunk_sizes == NULL)
				goto oom;
			/* OWNERSHIP: m->chunk_sizes is context-owned until
			 * ark_read_free. */
		}
		chunk_sum = 0U;
		for (j = 0U; j < m->chunk_count; j++) {
			m->chunk_sizes[j] =
			    le32_get(index_buf + off + (size_t)j * 4U);
			if (u64_add_overflow(chunk_sum,
			                     (uint64_t)m->chunk_sizes[j],
			                     &chunk_sum) != 0)
				goto fmt_index;
		}
		off += chunk_bytes;

		if (m->type == 0x01U && m->size_original > 0U) {
			uint64_t data_end;

			/* ARCHITECTURE.md section 8.3 check 11. */
			if (chunk_sum != m->size_compressed)
				goto fmt_index;
			/* SAFETY: checked arithmetic on attacker-controlled
			 * offsets. See ARCHITECTURE.md section 8.3
			 * overflow-safe arithmetic. */
			if (u64_add_overflow(m->data_offset, m->size_compressed,
			                     &data_end) != 0)
				goto fmt_index;
			/* ARCHITECTURE.md section 8.3 check 12. */
			if (m->data_offset < ARK_HEADER_SIZE ||
			    data_end > ctx->index_offset)
				goto fmt_index;
		}
	}

	if (off != index_len)
		goto fmt_index;

	/* ARCHITECTURE.md section 8.3 check 7. */
	for (i = 0U; i < ctx->member_count; i++) {
		if (members[i].type == 0x04U) {
			if (find_member_by_path(members, i, members[i].link) <
			    0)
				goto fmt_index;
		}
	}

	/* ARCHITECTURE.md section 8.3 check 8. */
	for (i = 0U; i < ctx->member_count; i++) {
		if (find_member_by_path(members, i, members[i].path) >= 0)
			goto fmt_index;
	}

	/* ARCHITECTURE.md section 8.3 check 9. */
	for (i = 0U; i < ctx->member_count; i++) {
		if (validate_ancestors_full(members, ctx->member_count, i,
		                            err) != 0)
			goto fail;
	}

	/* ARCHITECTURE.md section 8.3 check 10. */
	for (i = 0U; i < ctx->member_count; i++) {
		if (validate_present_ancestor_dirs(members, ctx->member_count,
		                                   i, err) != 0)
			goto fail;
	}

	{
		uint32_t range_count;

		range_count = 0U;
		for (i = 0U; i < ctx->member_count; i++) {
			if (members[i].type == 0x01U &&
			    members[i].size_original > 0U)
				range_count++;
		}
		if (range_count > 0U) {
			ranges = calloc(range_count, sizeof(ranges[0]));
			if (ranges == NULL)
				goto oom;
		}

		range_count = 0U;
		for (i = 0U; i < ctx->member_count; i++) {
			uint64_t end;

			if (members[i].type != 0x01U ||
			    members[i].size_original == 0U)
				continue;
			if (u64_add_overflow(members[i].data_offset,
			                     members[i].size_compressed,
			                     &end) != 0)
				goto fmt_index;
			ranges[range_count].start = members[i].data_offset;
			ranges[range_count].end = end;
			range_count++;
		}

		for (i = 0U; i < range_count; i++) {
			uint32_t j;

			for (j = i + 1U; j < range_count; j++) {
				if (ranges[j].start < ranges[i].start) {
					struct body_range tmp;

					tmp = ranges[i];
					ranges[i] = ranges[j];
					ranges[j] = tmp;
				}
			}
		}

		/* ARCHITECTURE.md section 8.3 check 13. */
		for (i = 1U; i < range_count; i++) {
			if (ranges[i].start < ranges[i - 1U].end)
				goto fmt_index;
		}
	}

	/* ARCHITECTURE.md section 8.3 check 14. */
	for (i = 0U; i < ctx->member_count; i++) {
		int t;

		if (members[i].type != 0x04U)
			continue;
		t = find_member_by_path(members, i, members[i].link);
		if (t < 0)
			goto fmt_index;
		if (members[t].type != 0x01U)
			goto fmt_index;
	}

	{
		uint32_t range_count;

		range_count = 0U;
		for (i = 0U; i < ctx->member_count; i++) {
			if (members[i].type == 0x01U &&
			    members[i].size_original > 0U)
				range_count++;
		}
		/* ARCHITECTURE.md section 8.3 check 15 contiguous body. */
		if (range_count == 0U) {
			if (ctx->index_offset != ARK_HEADER_SIZE)
				goto fmt_index;
		} else {
			if (ranges[0].start != ARK_HEADER_SIZE)
				goto fmt_index;
			for (i = 1U; i < range_count; i++) {
				if (ranges[i].start != ranges[i - 1U].end)
					goto fmt_index;
			}
			if (ranges[range_count - 1U].end != ctx->index_offset)
				goto fmt_index;
		}
	}

	/* ARCHITECTURE.md section 8.3 check 16 empty-input hash on zero-data.
	 */
	if (hash_init(&idx_hash, ctx->hash_alg, err) != 0)
		goto fail;
	hash_final(&idx_hash, empty_hash);
	for (i = 0U; i < ctx->member_count; i++) {
		if (member_has_zero_data(&members[i]) != 0) {
			if (memcmp(members[i].hash, empty_hash,
			           sizeof(empty_hash)) != 0) {
				ark_fail(err, ARK_ERR_HASH_MEMBER,
				         "zero-data member hash mismatch", 0);
				goto fail;
			}
		}
	}

	ctx->members = members;
	ctx->state = ARK_READ_STATE_INDEX_DONE;
	free(ranges);
	return 0;

fmt_member_type:
	ark_fail(err, ARK_ERR_FMT_MEMBER_TYPE, "unknown member type", 0);
	goto fail;
fmt_index:
	ark_fail(err, ARK_ERR_FMT_INDEX, "malformed index", 0);
	goto fail;
oom:
	ark_fail(err, ARK_ERR_IO_ALLOC, "allocate index parse structures", 0);
fail:
	if (members != NULL) {
		for (i = 0U; i < ctx->member_count; i++)
			member_clear(&members[i]);
		free(members);
	}
	free(ranges);
	return -1;
}

const ark_member_meta_t *ark_read_member_meta(const ark_read_ctx_t *ctx,
                                              uint32_t pos)
{
	if (ctx == NULL)
		return NULL;
	if (ctx->state != ARK_READ_STATE_INDEX_DONE)
		return NULL;
	if (pos >= ctx->member_count)
		return NULL;
	return &ctx->members[pos];
}

ssize_t ark_read_chunk(const ark_read_ctx_t *ctx, const ark_member_meta_t *meta,
                       uint32_t chunk_index, const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, ark_error_t *err)
{
	uint64_t expected_u64;
	ssize_t dec_len;

	if (ctx == NULL || meta == NULL || dst == NULL)
		return ark_fail(err, ARK_ERR_USAGE, "null read chunk argument",
		                0);
	if (ctx->state != ARK_READ_STATE_INDEX_DONE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "read chunk out of sequence", 0);
	if (meta->type != 0x01U)
		return ark_fail(err, ARK_ERR_USAGE,
		                "read chunk on non-regular member", 0);
	if (chunk_index >= meta->chunk_count)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "chunk index out of range", 0);
	if (src_len != (size_t)meta->chunk_sizes[chunk_index])
		return ark_fail(err, ARK_ERR_FMT_DATA,
		                "compressed chunk length mismatch", 0);
	if (src == NULL && src_len > 0U)
		return ark_fail(err, ARK_ERR_USAGE, "null compressed chunk", 0);

	if (chunk_index + 1U < meta->chunk_count) {
		expected_u64 = (uint64_t)ARK_CHUNK_SIZE;
	} else {
		expected_u64 = meta->size_original % (uint64_t)ARK_CHUNK_SIZE;
		if (expected_u64 == 0U)
			expected_u64 = (uint64_t)ARK_CHUNK_SIZE;
	}
	if (expected_u64 > (uint64_t)SIZE_MAX)
		return ark_fail(err, ARK_ERR_FMT_DATA,
		                "expected chunk length overflows size_t", 0);

	dec_len = ark_deflate_decompress(src, src_len, dst, dst_cap);
	if (dec_len < 0)
		return ark_fail(err, ARK_ERR_FMT_DATA, "invalid deflate stream",
		                0);
	if ((uint64_t)dec_len != expected_u64)
		return ark_fail(err, ARK_ERR_FMT_DATA,
		                "decompressed chunk length mismatch", 0);

	return dec_len;
}

int ark_read_verify_member_begin(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err)
{
	if (ctx == NULL || meta == NULL)
		return ark_fail(err, ARK_ERR_USAGE,
		                "null verify begin argument", 0);
	if (ctx->state != ARK_READ_STATE_INDEX_DONE)
		return ark_fail(err, ARK_ERR_USAGE,
		                "verify begin out of sequence", 0);
	if (hash_init(&ctx->verify_hash, ctx->hash_alg, err) != 0)
		return -1;
	ctx->verify_meta = meta;
	ctx->verify_next_chunk = 0U;
	ctx->verify_active = 1;
	return 0;
}

int ark_read_verify_member_update(ark_read_ctx_t *ctx,
                                  const ark_member_meta_t *meta,
                                  uint32_t chunk_index,
                                  const uint8_t *chunk_data, size_t chunk_len,
                                  ark_error_t *err)
{
	if (ctx == NULL || meta == NULL)
		return ark_fail(err, ARK_ERR_USAGE,
		                "null verify update argument", 0);
	if (ctx->state != ARK_READ_STATE_INDEX_DONE || ctx->verify_active == 0)
		return ark_fail(err, ARK_ERR_USAGE,
		                "verify update out of sequence", 0);
	if (ctx->verify_meta != meta)
		return ark_fail(err, ARK_ERR_USAGE,
		                "verify update member mismatch", 0);
	/* SAFETY: this guard enforces strict chunk-order verification as
	 * required by ARCHITECTURE.md section 16.4 and 8.2. */
	if (chunk_index != ctx->verify_next_chunk)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "verify update chunk out of order", 0);
	if (ctx->verify_next_chunk >= meta->chunk_count)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "too many verify update calls", 0);
	if (chunk_len != (size_t)meta->chunk_sizes[ctx->verify_next_chunk])
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "verify update chunk out of order", 0);
	if (chunk_data == NULL && chunk_len > 0U)
		return ark_fail(err, ARK_ERR_USAGE, "null verify chunk data",
		                0);

	hash_update(&ctx->verify_hash, chunk_data, chunk_len);
	ctx->verify_next_chunk++;
	return 0;
}

int ark_read_verify_member_final(ark_read_ctx_t *ctx,
                                 const ark_member_meta_t *meta,
                                 ark_error_t *err)
{
	uint8_t digest[32];

	if (ctx == NULL || meta == NULL)
		return ark_fail(err, ARK_ERR_USAGE,
		                "null verify final argument", 0);
	if (ctx->state != ARK_READ_STATE_INDEX_DONE || ctx->verify_active == 0)
		return ark_fail(err, ARK_ERR_USAGE,
		                "verify final out of sequence", 0);
	if (ctx->verify_meta != meta)
		return ark_fail(err, ARK_ERR_USAGE,
		                "verify final member mismatch", 0);
	if (ctx->verify_next_chunk != meta->chunk_count)
		return ark_fail(err, ARK_ERR_FMT_INDEX,
		                "verify final before all chunks", 0);

	hash_final(&ctx->verify_hash, digest);
	ctx->verify_active = 0;
	ctx->verify_meta = NULL;
	ctx->verify_next_chunk = 0U;
	if (memcmp(digest, meta->hash, sizeof(digest)) != 0)
		return ark_fail(err, ARK_ERR_HASH_MEMBER,
		                "member hash mismatch", 0);
	return 0;
}

void ark_read_free(ark_read_ctx_t *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->members != NULL) {
		uint32_t i;

		for (i = 0U; i < ctx->member_count; i++)
			member_clear(&ctx->members[i]);
	}
	free(ctx->members);
	buf_zero(ctx, sizeof(*ctx));
}
