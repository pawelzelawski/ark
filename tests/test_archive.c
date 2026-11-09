#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "archive.h"
#include "blake3.h"
#include "sha256.h"

/* Compress helper defined in test_deflate.c (fresh encoder per call). */
ssize_t test_deflate_compress(const uint8_t *, size_t, uint8_t *, size_t, int);
/* In-process extract defined in src/main.c (ARK_TEST). */
int ark_test_extract_archive(const char *, const char *, int, const char *, int,
                             ark_error_t *);
int ark_test_verify_archive(const char *, const char *, int, int,
                            ark_error_t *);

typedef ark_write_ctx_storage_t write_ctx_storage_t;

static uint16_t le16_get(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32_get(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t le64_get(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

static void hash_bytes(ark_hash_alg_t alg, const uint8_t *buf, size_t len,
                       uint8_t out[32])
{
	if (alg == ARK_HASH_BLAKE3) {
		ark_blake3(buf, len, out);
		return;
	}
	ark_sha256(buf, len, out);
}

static ark_write_ctx_t *ctx_from_storage(write_ctx_storage_t *storage)
{
	(void)storage->align;
	memset(storage, 0, sizeof(*storage));
	return (ark_write_ctx_t *)(void *)storage->bytes;
}

static void meta_init(ark_member_meta_t *meta, uint8_t type, const char *path)
{
	memset(meta, 0, sizeof(*meta));
	meta->type = type;
	meta->mode = 0644U;
	meta->uid = 1000U;
	meta->gid = 1000U;
	meta->mtime = 1U;
	meta->path = path;
}

int test_write_valid_sequence_zero_members(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[8];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	if (idx_len != 0)
		return 1;
	if (ark_write_footer(ctx, 16U, (uint64_t)idx_len, footer,
	                     sizeof(footer), &err) != 64)
		return 1;
	ark_write_free(ctx);
	return 0;
}

int test_write_valid_sequence_one_member(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	const uint8_t chunk[] = {0x11, 0x22, 0x33};
	uint8_t out[16];
	uint8_t header[16];
	uint8_t index[256];
	uint8_t footer[64];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = sizeof(chunk);
	meta.data_offset = 16U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
	                    &err) != (ssize_t)sizeof(chunk))
		return 1;
	if (memcmp(out, chunk, sizeof(chunk)) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	if (idx_len <= 0)
		return 1;
	if (ark_write_footer(ctx, 16U + (uint64_t)sizeof(chunk),
	                     (uint64_t)idx_len, footer, sizeof(footer),
	                     &err) != 64)
		return 1;
	ark_write_free(ctx);
	return 0;
}

int test_write_valid_sequence_multi_member(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t file;
	ark_member_meta_t dir;
	ark_member_meta_t sym;
	ark_member_meta_t hard;
	ark_error_t err;
	const uint8_t chunk[] = {0xaa, 0xbb};
	uint8_t out[8];
	uint8_t header[16];
	uint8_t index[512];
	uint8_t footer[64];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);

	meta_init(&file, 0x01U, "f");
	file.size_original = sizeof(chunk);
	file.data_offset = 16U;
	meta_init(&dir, 0x02U, "d");
	meta_init(&sym, 0x03U, "s");
	sym.link = "t";
	meta_init(&hard, 0x04U, "h");
	hard.link = "f";

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;

	if (ark_write_member_begin(ctx, &file, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
	                    &err) != (ssize_t)sizeof(chunk))
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;

	if (ark_write_member_begin(ctx, &dir, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;

	if (ark_write_member_begin(ctx, &sym, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;

	if (ark_write_member_begin(ctx, &hard, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;

	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	if (idx_len <= 0)
		return 1;
	if (ark_write_footer(ctx, 16U + (uint64_t)sizeof(chunk),
	                     (uint64_t)idx_len, footer, sizeof(footer),
	                     &err) != 64)
		return 1;

	ark_write_free(ctx);
	return 0;
}

int test_write_chunk_outside_member(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t out[1];
	const uint8_t in[1] = {0x00};

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_chunk(ctx, in, sizeof(in), out, sizeof(out), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_member_begin_while_active(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = 1U;
	meta.data_offset = 16U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_member_end_outside_member(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_end(ctx, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_index_before_member_end(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[64];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = 1U;
	meta.data_offset = 16U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_index(ctx, index, sizeof(index), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_footer_before_index(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t footer[64];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_footer(ctx, 16U, 0U, footer, sizeof(footer), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_chunk_non_regular_member(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t out[4];
	const uint8_t in[4] = {0, 1, 2, 3};

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x02U, "d");

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, in, sizeof(in), out, sizeof(out), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_free_any_state(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	ark_write_free(ctx);

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	ark_write_free(ctx);

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "f");
	meta.size_original = 0U;
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	ark_write_free(ctx);

	return 0;
}

int test_write_header_dst_cap_undersize(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[15];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_IO_ALLOC ? 0 : 1;
}

int test_write_footer_dst_cap_undersize(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[8];
	uint8_t footer[63];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_index(ctx, index, sizeof(index), &err) != 0)
		return 1;
	if (ark_write_footer(ctx, 16U, 0U, footer, sizeof(footer), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_IO_ALLOC ? 0 : 1;
}

int test_write_index_dst_cap_undersize(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[4];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = 0U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	if (ark_write_index(ctx, index, sizeof(index), &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_IO_ALLOC ? 0 : 1;
}

/*
 * Begin and end one member; regular members get nchunks one-byte chunks.
 */
static int add_member(ark_write_ctx_t *ctx, ark_member_meta_t *meta,
                      unsigned nchunks, ark_error_t *err)
{
	const uint8_t chunk[1] = {0x5a};
	uint8_t out[4];
	unsigned i;

	meta->size_original = (uint64_t)nchunks * ARK_CHUNK_SIZE;
	meta->data_offset = nchunks == 0U ? 0U : 16U;
	if (ark_write_member_begin(ctx, meta, err) != 0)
		return -1;
	for (i = 0U; i < nchunks; i++) {
		if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
		                    err) != 1)
			return -1;
	}
	return ark_write_member_end(ctx, err);
}

/*
 * ark_write_index_size reports the exact index size after every member
 * (entry size per ARCHITECTURE.md 5.2: 79 fixed bytes, path, a u16 length
 * plus target for links, u32 chunk count, u32 per chunk), leaves the context
 * usable, and ark_write_index then needs exactly that many bytes.
 */
int test_write_index_size_query(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[512];
	size_t size;
	size_t expect;
	int rc;

	rc = 1;
	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		goto done;
	size = 1U;
	if (ark_write_index_size(ctx, &size, &err) != 0 || size != 0U)
		goto done;

	meta_init(&meta, 0x02U, "d");
	if (add_member(ctx, &meta, 0U, &err) != 0)
		goto done;
	expect = 79U + 1U + 4U;
	if (ark_write_index_size(ctx, &size, &err) != 0 || size != expect)
		goto done;

	meta_init(&meta, 0x01U, "d/file");
	if (add_member(ctx, &meta, 3U, &err) != 0)
		goto done;
	expect += 79U + 6U + 4U + 3U * 4U;
	if (ark_write_index_size(ctx, &size, &err) != 0 || size != expect)
		goto done;

	meta_init(&meta, 0x03U, "d/sym");
	meta.link = "target";
	if (add_member(ctx, &meta, 0U, &err) != 0)
		goto done;
	expect += 79U + 5U + 2U + 6U + 4U;
	meta_init(&meta, 0x04U, "d/hard");
	meta.link = "d/file";
	if (add_member(ctx, &meta, 0U, &err) != 0)
		goto done;
	expect += 79U + 6U + 2U + 6U + 4U;
	if (ark_write_index_size(ctx, &size, &err) != 0 || size != expect)
		goto done;
	/* A second query gives the same answer: the query changes nothing. */
	if (ark_write_index_size(ctx, &size, &err) != 0 || size != expect)
		goto done;

	/* One byte short is still the serializer's undersized error. */
	if (ark_write_index(ctx, index, size - 1U, &err) != -1 ||
	    err.code != ARK_ERR_IO_ALLOC)
		goto done;
	if (ark_write_index(ctx, index, size, &err) != (ssize_t)size)
		goto done;
	rc = 0;
done:
	ark_write_free(ctx);
	return rc;
}

/*
 * The size query is valid in IDLE state only and rejects NULL arguments.
 */
int test_write_index_size_out_of_sequence(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[256];
	size_t size;
	int rc;

	if (ark_write_index_size(NULL, &size, &err) != -1 ||
	    err.code != ARK_ERR_USAGE)
		return 1;

	rc = 1;
	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	/* READY: header not written yet. */
	if (ark_write_index_size(ctx, &size, &err) != -1 ||
	    err.code != ARK_ERR_USAGE)
		goto done;
	ark_write_free(ctx);

	/* MEMBER: a member is still open. */
	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16 ||
	    ark_write_index_size(ctx, NULL, &err) != -1 ||
	    err.code != ARK_ERR_USAGE)
		goto done;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		goto done;
	if (ark_write_index_size(ctx, &size, &err) != -1 ||
	    err.code != ARK_ERR_USAGE)
		goto done;
	ark_write_free(ctx);

	/* INDEXED: the index is already written. */
	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16 ||
	    add_member(ctx, &meta, 0U, &err) != 0 ||
	    ark_write_index(ctx, index, sizeof(index), &err) <= 0)
		goto done;
	if (ark_write_index_size(ctx, &size, &err) != -1 ||
	    err.code != ARK_ERR_USAGE)
		goto done;
	rc = 0;
done:
	ark_write_free(ctx);
	return rc;
}

int test_write_header_magic(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	return header[0] == 0x61U && header[1] == 0x72U && header[2] == 0x6bU &&
	               header[3] == 0x21U && header[4] == 0x0aU
	           ? 0
	           : 1;
}

int test_write_header_version(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	return (header[5] == 0x01U && header[6] == 0x00U) ? 0 : 1;
}

int test_write_header_flags_zero(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	return header[7] == 0x00U ? 0 : 1;
}

int test_write_header_comp_alg(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	return header[8] == 0x01U ? 0 : 1;
}

int test_write_header_hash_alg(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	if (header[9] != 0x01U)
		return 1;

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	return header[9] == 0x02U ? 0 : 1;
}

int test_write_header_reserved_zero(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	size_t i;

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	for (i = 10U; i < 16U; i++) {
		if (header[i] != 0x00U)
			return 1;
	}
	return 0;
}

int test_write_footer_magic_confirm(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[8];
	uint8_t footer[64];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_index(ctx, index, sizeof(index), &err) != 0)
		return 1;
	if (ark_write_footer(ctx, 16U, 0U, footer, sizeof(footer), &err) != 64)
		return 1;
	ark_write_free(ctx);
	return le32_get(footer + 52U) == 0x4b52410aU ? 0 : 1;
}

int test_write_footer_index_offset(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	ark_member_meta_t meta;
	const uint8_t chunk[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t out[8];
	uint8_t header[16];
	uint8_t index[256];
	uint8_t footer[64];
	ssize_t idx_len;
	uint64_t index_offset;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = sizeof(chunk);
	meta.data_offset = 16U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
	                    &err) != (ssize_t)sizeof(chunk))
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	if (idx_len <= 0)
		return 1;
	index_offset = 16U + (uint64_t)sizeof(chunk);
	if (ark_write_footer(ctx, index_offset, (uint64_t)idx_len, footer,
	                     sizeof(footer), &err) != 64)
		return 1;
	ark_write_free(ctx);
	return le64_get(footer) == index_offset ? 0 : 1;
}

int test_write_index_little_endian(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[256];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.mode = 0x11223344U;
	meta.uid = 0x55667788U;
	meta.gid = 0x99aabbccU;
	meta.mtime = UINT64_C(0x0102030405060708);
	meta.size_original = 0U;
	meta.data_offset = 0U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	ark_write_free(ctx);
	if (idx_len <= 0)
		return 1;

	if (index[0] != 0x01U)
		return 1;
	if (le32_get(index + 1U) != 0x11223344U)
		return 1;
	if (le32_get(index + 5U) != 0x55667788U)
		return 1;
	if (le32_get(index + 9U) != 0x99aabbccU)
		return 1;
	if (le64_get(index + 13U) != UINT64_C(0x0102030405060708))
		return 1;
	return 0;
}

int test_write_empty_file_chunk_count_zero(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[256];
	ssize_t idx_len;
	size_t off;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "e");
	meta.size_original = 0U;
	meta.data_offset = 0U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	ark_write_free(ctx);
	if (idx_len <= 0)
		return 1;

	off = 79U + (size_t)le16_get(index + 77U);
	if (off + 4U > (size_t)idx_len)
		return 1;
	return le32_get(index + off) == 0U ? 0 : 1;
}

int test_write_member_hash_non_file_types(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t dir;
	ark_member_meta_t sym;
	ark_member_meta_t hard;
	ark_error_t err;
	uint8_t header[16];
	uint8_t index[512];
	uint8_t empty_hash[32];
	ssize_t idx_len;
	size_t off;

	ctx = ctx_from_storage(&storage);
	meta_init(&dir, 0x02U, "d");
	meta_init(&sym, 0x03U, "s");
	sym.link = "t";
	meta_init(&hard, 0x04U, "h");
	hard.link = "d";

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &dir, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	if (ark_write_member_begin(ctx, &sym, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	if (ark_write_member_begin(ctx, &hard, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	ark_write_free(ctx);
	if (idx_len <= 0)
		return 1;

	hash_bytes(ARK_HASH_SHA256, NULL, 0U, empty_hash);

	off = 0U;
	if (memcmp(index + off + 45U, empty_hash, sizeof(empty_hash)) != 0)
		return 1;
	off += 79U + 1U + 4U;
	if (memcmp(index + off + 45U, empty_hash, sizeof(empty_hash)) != 0)
		return 1;
	off += 79U + 1U + 2U + 1U + 4U;
	if (memcmp(index + off + 45U, empty_hash, sizeof(empty_hash)) != 0)
		return 1;
	return 0;
}

int test_write_index_hash_matches_footer(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t expected[32];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = 0U;

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	if (idx_len <= 0)
		return 1;
	if (ark_write_footer(ctx, 16U, (uint64_t)idx_len, footer,
	                     sizeof(footer), &err) != 64)
		return 1;
	ark_write_free(ctx);

	hash_bytes(ARK_HASH_BLAKE3, index, (size_t)idx_len, expected);
	return memcmp(footer + 16U, expected, sizeof(expected)) == 0 ? 0 : 1;
}

int test_write_member_hash_matches_compressed_bytes(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	const uint8_t chunk[] = {0xde, 0xad, 0xbe, 0xef};
	uint8_t out[8];
	uint8_t header[16];
	uint8_t index[256];
	uint8_t expected[32];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = sizeof(chunk);
	meta.data_offset = 16U;

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
	                    &err) != (ssize_t)sizeof(chunk))
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	ark_write_free(ctx);
	if (idx_len <= 0)
		return 1;

	hash_bytes(ARK_HASH_SHA256, chunk, sizeof(chunk), expected);
	return memcmp(index + 45U, expected, sizeof(expected)) == 0 ? 0 : 1;
}

int test_write_member_begin_invalid_type(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0xffU, "bad");
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_member_begin_rejects_bad_path(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a/../b");
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_PATH_TRAVERSAL ? 0 : 1;
}

int test_write_member_begin_rejects_bad_link(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x03U, "s");
	meta.link = "/target";
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_PATH_ABSOLUTE ? 0 : 1;
}

int test_write_member_begin_rejects_chunk_sizes(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	uint32_t chunk_sizes[1] = {1U};
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.chunk_sizes = chunk_sizes;
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != -1)
		return 1;
	ark_write_free(ctx);
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_write_size_compressed_owned_by_context(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_member_meta_t meta;
	ark_error_t err;
	const uint8_t chunk[] = {0xde, 0xad, 0xbe};
	uint8_t out[8];
	uint8_t header[16];
	uint8_t index[256];
	ssize_t idx_len;

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "a");
	meta.size_original = sizeof(chunk);
	meta.size_compressed = 999U;
	meta.data_offset = 16U;
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	if (ark_write_member_begin(ctx, &meta, &err) != 0)
		return 1;
	if (ark_write_chunk(ctx, chunk, sizeof(chunk), out, sizeof(out),
	                    &err) != (ssize_t)sizeof(chunk))
		return 1;
	if (ark_write_member_end(ctx, &err) != 0)
		return 1;
	idx_len = ark_write_index(ctx, index, sizeof(index), &err);
	ark_write_free(ctx);
	if (idx_len <= 0)
		return 1;
	return le64_get(index + 29U) == (uint64_t)sizeof(chunk) ? 0 : 1;
}

/*
 * begin_once - Run ark_write_member_begin on a fresh context; *code receives
 * the error code (ARK_OK on success).
 */
static int begin_once(const ark_member_meta_t *meta, ark_err_t *code)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	int rc;

	ctx = ctx_from_storage(&storage);
	err = (ark_error_t){0};
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0 ||
	    ark_write_header(ctx, header, sizeof(header), &err) != 16) {
		ark_write_free(ctx);
		return -2;
	}
	rc = ark_write_member_begin(ctx, meta, &err);
	*code = rc == 0 ? ARK_OK : err.code;
	ark_write_free(ctx);
	return rc;
}

/*
 * test_write_member_begin_string_limits - Caller strings are pointers, so
 * ark_write_member_begin bounds them itself: NULL or over-long paths and
 * links are usage errors; a NULL link means none for files and directories.
 * See ARCHITECTURE.md section 16.2.
 */
int test_write_member_begin_string_limits(void)
{
	static char max_str[ARK_MEMBER_PATH_MAX + 1U];
	static char over_str[ARK_MEMBER_PATH_MAX + 2U];
	ark_member_meta_t meta;
	ark_err_t code;

	memset(max_str, 'a', ARK_MEMBER_PATH_MAX);
	max_str[ARK_MEMBER_PATH_MAX] = '\0';
	memset(over_str, 'a', ARK_MEMBER_PATH_MAX + 1U);
	over_str[ARK_MEMBER_PATH_MAX + 1U] = '\0';

	meta_init(&meta, 0x02U, "d");
	meta.path = NULL;
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;
	meta.path = over_str;
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;
	meta.path = max_str;
	if (begin_once(&meta, &code) != 0)
		return 1;
	meta.path = "d";
	meta.link = NULL;
	if (begin_once(&meta, &code) != 0)
		return 1;
	meta.link = "";
	if (begin_once(&meta, &code) != 0)
		return 1;
	meta.link = "x";
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;

	meta_init(&meta, 0x03U, "s");
	meta.link = NULL;
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;
	meta.link = over_str;
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;
	meta.link = max_str;
	if (begin_once(&meta, &code) != 0)
		return 1;
	meta_init(&meta, 0x04U, "h");
	meta.link = over_str;
	if (begin_once(&meta, &code) != -1 || code != ARK_ERR_USAGE)
		return 1;
	return 0;
}

typedef ark_read_ctx_storage_t read_ctx_storage_t;

typedef struct {
	uint8_t type;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t mtime;
	uint64_t size_original;
	uint64_t size_compressed;
	uint64_t data_offset;
	uint8_t hash[32];
	const uint8_t *path;
	size_t path_len;
	const uint8_t *link;
	size_t link_len;
	uint32_t chunk_count;
	const uint32_t *chunk_sizes;
} read_entry_t;

static ark_read_ctx_t *read_ctx_from_storage(read_ctx_storage_t *storage)
{
	(void)storage->align;
	memset(storage, 0, sizeof(*storage));
	return (ark_read_ctx_t *)(void *)storage->bytes;
}

static void le16_put(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xffU);
	p[1] = (uint8_t)((v >> 8) & 0xffU);
}

static void le32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffU);
	p[1] = (uint8_t)((v >> 8) & 0xffU);
	p[2] = (uint8_t)((v >> 16) & 0xffU);
	p[3] = (uint8_t)((v >> 24) & 0xffU);
}

static void le64_put(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v & 0xffU);
	p[1] = (uint8_t)((v >> 8) & 0xffU);
	p[2] = (uint8_t)((v >> 16) & 0xffU);
	p[3] = (uint8_t)((v >> 24) & 0xffU);
	p[4] = (uint8_t)((v >> 32) & 0xffU);
	p[5] = (uint8_t)((v >> 40) & 0xffU);
	p[6] = (uint8_t)((v >> 48) & 0xffU);
	p[7] = (uint8_t)((v >> 56) & 0xffU);
}

static void build_header(uint8_t header[16], ark_hash_alg_t alg)
{
	memset(header, 0, 16U);
	header[0] = 0x61U;
	header[1] = 0x72U;
	header[2] = 0x6bU;
	header[3] = 0x21U;
	header[4] = 0x0aU;
	header[5] = 0x01U;
	header[6] = 0x00U;
	header[7] = 0x00U;
	header[8] = 0x01U;
	header[9] = (uint8_t)alg;
}

static void build_footer(uint8_t footer[64], uint64_t index_offset,
                         size_t index_len, uint32_t member_count,
                         const uint8_t index_hash[32])
{
	memset(footer, 0, 64U);
	le64_put(footer + 0U, index_offset);
	le64_put(footer + 8U, (uint64_t)index_len);
	memcpy(footer + 16U, index_hash, 32U);
	le32_put(footer + 48U, member_count);
	le32_put(footer + 52U, 0x4b52410aU);
}

/* Serialize synthetic index entries directly for malformed-input tests. */
static int build_index(const read_entry_t *entries, size_t n, uint8_t *out,
                       size_t out_cap, size_t *out_len)
{
	size_t i;
	size_t off;

	off = 0U;
	for (i = 0U; i < n; i++) {
		const read_entry_t *e;
		size_t need;
		size_t j;

		e = &entries[i];
		need = 79U + e->path_len + 4U + (size_t)e->chunk_count * 4U;
		if (e->type == 0x03U || e->type == 0x04U)
			need += 2U + e->link_len;
		if (off + need > out_cap)
			return -1;

		out[off + 0U] = e->type;
		le32_put(out + off + 1U, e->mode);
		le32_put(out + off + 5U, e->uid);
		le32_put(out + off + 9U, e->gid);
		le64_put(out + off + 13U, e->mtime);
		le64_put(out + off + 21U, e->size_original);
		le64_put(out + off + 29U, e->size_compressed);
		le64_put(out + off + 37U, e->data_offset);
		memcpy(out + off + 45U, e->hash, 32U);
		le16_put(out + off + 77U, (uint16_t)e->path_len);
		off += 79U;
		memcpy(out + off, e->path, e->path_len);
		off += e->path_len;

		if (e->type == 0x03U || e->type == 0x04U) {
			le16_put(out + off, (uint16_t)e->link_len);
			off += 2U;
			memcpy(out + off, e->link, e->link_len);
			off += e->link_len;
		}

		le32_put(out + off, e->chunk_count);
		off += 4U;
		for (j = 0U; j < e->chunk_count; j++) {
			le32_put(out + off, e->chunk_sizes[j]);
			off += 4U;
		}
	}
	*out_len = off;
	return 0;
}

static void entry_base(read_entry_t *e, uint8_t type, const char *path)
{
	memset(e, 0, sizeof(*e));
	e->type = type;
	e->mode = 0644U;
	e->uid = 1000U;
	e->gid = 1000U;
	e->mtime = 1U;
	e->path = (const uint8_t *)path;
	e->path_len = strlen(path);
}

/* Drive read_header/read_init/read_index and assert the expected read_index
 * error code for adversarial index cases. */
static int parse_index_expect(const uint8_t *header, const uint8_t *footer,
                              const uint8_t *index, size_t index_len,
                              ark_err_t code)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	int rc;

	ctx = read_ctx_from_storage(&storage);
	if (ark_read_header(ctx, header, 16U, &err) != 0)
		return 1;
	if (ark_read_init(ctx, footer, 64U, &err) != 0)
		return 1;
	rc = ark_read_index(ctx, index, index_len, &err);
	ark_read_free(ctx);
	if (rc != -1)
		return 1;
	return err.code == code ? 0 : 1;
}

/* Build a fully parsed read context for per-member verify/chunk API tests. */
static int parse_index_ok(const uint8_t *header, const uint8_t *footer,
                          const uint8_t *index, size_t index_len,
                          read_ctx_storage_t *storage, ark_read_ctx_t **ctx_out)
{
	ark_error_t err;
	ark_read_ctx_t *ctx;

	ctx = read_ctx_from_storage(storage);
	if (ark_read_header(ctx, header, 16U, &err) != 0)
		return 1;
	if (ark_read_init(ctx, footer, 64U, &err) != 0)
		return 1;
	if (ark_read_index(ctx, index, index_len, &err) != 0)
		return 1;
	*ctx_out = ctx;
	return 0;
}

int test_read_header_bad_magic(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[0] = 0x00U;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_MAGIC ? 0 : 1;
}

int test_read_header_bad_version(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[5] = 0x02U;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_VERSION ? 0 : 1;
}

int test_read_header_unknown_comp_alg(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[8] = 0xffU;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_COMP_ALG ? 0 : 1;
}

int test_read_header_unknown_hash_alg(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[9] = 0xffU;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_HASH_ALG ? 0 : 1;
}

int test_read_header_nonzero_flags(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[7] = 0x01U;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_RESERVED ? 0 : 1;
}

int test_read_header_nonzero_reserved(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	header[10] = 0x01U;
	if (ark_read_header(ctx, header, sizeof(header), &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_RESERVED ? 0 : 1;
}

int test_read_header_before_init(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t footer[64];

	ctx = read_ctx_from_storage(&storage);
	memset(footer, 0, sizeof(footer));
	if (ark_read_init(ctx, footer, sizeof(footer), &err) != -1)
		return 1;
	return err.code == ARK_ERR_USAGE ? 0 : 1;
}

int test_read_header_truncated(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = read_ctx_from_storage(&storage);
	build_header(header, ARK_HASH_BLAKE3);
	if (ark_read_header(ctx, header, 15U, &err) != -1)
		return 1;
	return err.code == ARK_ERR_FMT_TRUNCATED ? 0 : 1;
}

int test_read_check1_bad_footer_magic(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	footer[52] ^= 0x01U;

	{
		read_ctx_storage_t storage;
		ark_read_ctx_t *ctx;
		ark_error_t err;

		ctx = read_ctx_from_storage(&storage);
		if (ark_read_header(ctx, header, 16U, &err) != 0)
			return 1;
		if (ark_read_init(ctx, footer, 64U, &err) != -1)
			return 1;
		return err.code == ARK_ERR_FMT_MAGIC ? 0 : 1;
	}
}

int test_read_check2_index_hash_mismatch(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	index[0] ^= 0x01U;
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_HASH_INDEX);
}

int test_read_check3_path_absolute(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "/a");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_ABSOLUTE);
}

int test_read_check3_path_dotdot(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a/../b");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_TRAVERSAL);
}

int test_read_check3_path_empty_component_fmt(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a//b");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check3_path_invalid_utf8(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	const uint8_t path[2] = {0xffU, 'a'};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.path = path;
	e.path_len = sizeof(path);
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_ENCODING);
}

int test_read_index_unknown_member_type(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0xffU, "a");
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_MEMBER_TYPE);
}

int test_read_check4_path_too_long(void)
{
	read_entry_t e;
	uint8_t path[1025];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[1400];
	uint8_t digest[32];
	size_t index_len;

	memset(path, 'a', 1024U);
	path[1024] = '\0';
	entry_base(&e, 0x02U, "x");
	e.path = path;
	e.path_len = 1024U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_TOO_LONG);
}

int test_read_check5_link_absolute(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x03U, "s");
	e.link = (const uint8_t *)"/x";
	e.link_len = 2U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_ABSOLUTE);
}

int test_read_check5_link_dotdot(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x03U, "s");
	e.link = (const uint8_t *)"a/../b";
	e.link_len = 6U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_PATH_TRAVERSAL);
}

int test_read_check5_link_too_long(void)
{
	read_entry_t e;
	uint8_t link[1025];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[1400];
	uint8_t digest[32];
	size_t index_len;

	memset(link, 'a', 1024U);
	link[1024] = '\0';
	entry_base(&e, 0x03U, "s");
	e.link = link;
	e.link_len = 1024U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check6_hardlink_missing_target(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x04U, "h");
	e.link = (const uint8_t *)"missing";
	e.link_len = strlen((const char *)e.link);
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check6_hardlink_forward_reference(void)
{
	read_entry_t e[2];
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x04U, "h");
	e[0].link = (const uint8_t *)"t";
	e[0].link_len = 1U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[0].hash);

	entry_base(&e[1], 0x01U, "t");
	e[1].size_original = 1U;
	e[1].size_compressed = 1U;
	e[1].data_offset = 16U;
	e[1].chunk_count = 1U;
	e[1].chunk_sizes = sizes;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[1].hash);

	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check7_duplicate_path(void)
{
	read_entry_t e[2];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x02U, "d");
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[0].hash);
	entry_base(&e[1], 0x02U, "d");
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[1].hash);
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check8_missing_ancestor(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "d/f");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check9_present_ancestor_non_directory(void)
{
	read_entry_t e[2];
	const uint32_t sizes0[1] = {1U};
	const uint32_t sizes1[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x01U, "d");
	e[0].size_original = 1U;
	e[0].size_compressed = 1U;
	e[0].data_offset = 16U;
	e[0].chunk_count = 1U;
	e[0].chunk_sizes = sizes0;
	entry_base(&e[1], 0x01U, "d/f");
	e[1].size_original = 1U;
	e[1].size_compressed = 1U;
	e[1].data_offset = 17U;
	e[1].chunk_count = 1U;
	e[1].chunk_sizes = sizes1;
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 18U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check10_size_mismatch(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 2U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 18U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check11_data_offset_low(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 1U;
	e.data_offset = 15U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check11_data_range_exceeds_body(void)
{
	read_entry_t e;
	const uint32_t sizes[1] = {2U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 2U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = sizes;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 17U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check12_overlapping_ranges(void)
{
	read_entry_t e[2];
	const uint32_t sizes0[1] = {2U};
	const uint32_t sizes1[1] = {2U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x01U, "a");
	e[0].size_original = 1U;
	e[0].size_compressed = 2U;
	e[0].data_offset = 16U;
	e[0].chunk_count = 1U;
	e[0].chunk_sizes = sizes0;
	entry_base(&e[1], 0x01U, "b");
	e[1].size_original = 1U;
	e[1].size_compressed = 2U;
	e[1].data_offset = 17U;
	e[1].chunk_count = 1U;
	e[1].chunk_sizes = sizes1;
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 19U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check13_hardlink_targets_dir(void)
{
	read_entry_t e[2];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x02U, "d");
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[0].hash);
	entry_base(&e[1], 0x04U, "h");
	e[1].link = (const uint8_t *)"d";
	e[1].link_len = 1U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[1].hash);
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check13_hardlink_targets_symlink(void)
{
	read_entry_t e[2];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x03U, "s");
	e[0].link = (const uint8_t *)"target";
	e[0].link_len = strlen((const char *)e[0].link);
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[0].hash);
	entry_base(&e[1], 0x04U, "h");
	e[1].link = (const uint8_t *)"s";
	e[1].link_len = 1U;
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[1].hash);
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check14_structural_gap(void)
{
	read_entry_t e[2];
	const uint32_t sizes0[1] = {1U};
	const uint32_t sizes1[1] = {1U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[512];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e[0], 0x01U, "a");
	e[0].size_original = 1U;
	e[0].size_compressed = 1U;
	e[0].data_offset = 16U;
	e[0].chunk_count = 1U;
	e[0].chunk_sizes = sizes0;
	entry_base(&e[1], 0x01U, "b");
	e[1].size_original = 1U;
	e[1].size_compressed = 1U;
	e[1].data_offset = 18U;
	e[1].chunk_count = 1U;
	e[1].chunk_sizes = sizes1;
	if (build_index(e, 2U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 19U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_check15_zero_data_hash_mismatch(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x02U, "d");
	memset(e.hash, 0x11, sizeof(e.hash));
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_HASH_MEMBER);
}

int test_read_check16_zero_data_hash_mismatch(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "e");
	memset(e.hash, 0x22, sizeof(e.hash));
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_HASH_MEMBER);
}

int test_read_member_count_too_large(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x02U, "d");
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 2U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_regular_size_overflow_rejected(void)
{
	read_entry_t e;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;

	entry_base(&e, 0x01U, "a");
	e.size_original = UINT64_MAX;
	e.size_compressed = 0U;
	e.data_offset = 0U;
	e.chunk_count = 0U;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	return parse_index_expect(header, footer, index, index_len,
	                          ARK_ERR_FMT_INDEX);
}

int test_read_verify_hash_match(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint32_t csz[1];
	uint8_t src[] = {0x61, 0x62, 0x63};
	uint8_t comp[128];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	ssize_t clen;
	size_t index_len;
	const ark_member_meta_t *meta;

	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0)
		return 1;
	csz[0] = (uint32_t)clen;
	entry_base(&e, 0x01U, "a");
	e.size_original = sizeof(src);
	e.size_compressed = (uint64_t)clen;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	hash_bytes(ARK_HASH_BLAKE3, comp, (size_t)clen, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U + (uint64_t)clen, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_verify_member_begin(ctx, meta, &err) != 0)
		return 1;
	if (ark_read_verify_member_update(ctx, meta, 0U, comp, (size_t)clen,
	                                  &err) != 0)
		return 1;
	if (ark_read_verify_member_final(ctx, meta, &err) != 0)
		return 1;
	ark_read_free(ctx);
	return 0;
}

int test_read_verify_hash_mismatch(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint32_t csz[1];
	uint8_t src[] = {0x61, 0x62, 0x63};
	uint8_t comp[128];
	uint8_t bad[128];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	ssize_t clen;
	size_t index_len;
	const ark_member_meta_t *meta;

	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0)
		return 1;
	memcpy(bad, comp, (size_t)clen);
	bad[0] ^= 0x01U;
	csz[0] = (uint32_t)clen;
	entry_base(&e, 0x01U, "a");
	e.size_original = sizeof(src);
	e.size_compressed = (uint64_t)clen;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	hash_bytes(ARK_HASH_BLAKE3, comp, (size_t)clen, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U + (uint64_t)clen, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_verify_member_begin(ctx, meta, &err) != 0)
		return 1;
	if (ark_read_verify_member_update(ctx, meta, 0U, bad, (size_t)clen,
	                                  &err) != 0)
		return 1;
	if (ark_read_verify_member_final(ctx, meta, &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_HASH_MEMBER ? 0 : 1;
}

int test_read_verify_out_of_order_chunk(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	const uint32_t csz[2] = {3U, 3U};
	uint8_t chunk2[3] = {1U, 2U, 3U};
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;
	const ark_member_meta_t *meta;

	entry_base(&e, 0x01U, "a");
	e.size_original = (uint64_t)ARK_CHUNK_SIZE + 1U;
	e.size_compressed = 6U;
	e.data_offset = 16U;
	e.chunk_count = 2U;
	e.chunk_sizes = csz;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 22U, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_verify_member_begin(ctx, meta, &err) != 0)
		return 1;
	if (ark_read_verify_member_update(ctx, meta, 1U, chunk2, sizeof(chunk2),
	                                  &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_FMT_INDEX ? 0 : 1;
}

int test_read_chunk_invalid_deflate(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	const uint32_t csz[1] = {3U};
	uint8_t bad[3] = {0xffU, 0xffU, 0xffU};
	uint8_t out[32];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;
	const ark_member_meta_t *meta;

	entry_base(&e, 0x01U, "a");
	e.size_original = 1U;
	e.size_compressed = 3U;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 19U, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_chunk(ctx, meta, 0U, bad, sizeof(bad), out, sizeof(out),
	                   &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_FMT_DATA ? 0 : 1;
}

int test_read_chunk_length_mismatch(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t src[] = {0x41U};
	uint8_t comp[64];
	uint8_t out[64];
	uint32_t csz[1];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	ssize_t clen;
	size_t index_len;
	const ark_member_meta_t *meta;

	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0)
		return 1;
	csz[0] = (uint32_t)clen;
	entry_base(&e, 0x01U, "a");
	e.size_original = 2U;
	e.size_compressed = (uint64_t)clen;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U + (uint64_t)clen, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_chunk(ctx, meta, 0U, comp, (size_t)clen, out, sizeof(out),
	                   &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_FMT_DATA ? 0 : 1;
}

int test_read_chunk_compressed_size_mismatch(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t src[] = {0x41U};
	uint8_t comp[64];
	uint8_t out[64];
	uint32_t csz[1];
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	ssize_t clen;
	size_t index_len;
	const ark_member_meta_t *meta;

	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 1)
		return 1;
	csz[0] = (uint32_t)clen;
	entry_base(&e, 0x01U, "a");
	e.size_original = sizeof(src);
	e.size_compressed = (uint64_t)clen;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U + (uint64_t)clen, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (ark_read_chunk(ctx, meta, 0U, comp, (size_t)clen - 1U, out,
	                   sizeof(out), &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_FMT_DATA ? 0 : 1;
}

/*
 * test_archive_one_chunk_at - Serialize a valid one-member archive: regular
 * file `path` (no other members, so no ancestor directories) of
 * size_original bytes stored as the single chunk `chunk`, with BLAKE3
 * member and index hashes. Writes header, chunk, index and footer into buf;
 * reports the index size and returns the archive length, or 0 when buf is
 * too small. Shared with test_integration.c.
 */
size_t test_archive_one_chunk_at(uint8_t *buf, size_t cap, const char *path,
                                 const uint8_t *chunk, size_t chunk_len,
                                 uint64_t size_original, size_t *index_len)
{
	read_entry_t e;
	uint8_t index[256];
	uint8_t digest[32];
	uint32_t csz[1];
	size_t off;

	csz[0] = (uint32_t)chunk_len;
	entry_base(&e, 0x01U, path);
	e.size_original = size_original;
	e.size_compressed = chunk_len;
	e.data_offset = 16U;
	e.chunk_count = 1U;
	e.chunk_sizes = csz;
	hash_bytes(ARK_HASH_BLAKE3, chunk, chunk_len, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), index_len) != 0)
		return 0U;
	if (16U + chunk_len + *index_len + 64U > cap)
		return 0U;
	hash_bytes(ARK_HASH_BLAKE3, index, *index_len, digest);
	build_header(buf, ARK_HASH_BLAKE3);
	off = 16U;
	memcpy(buf + off, chunk, chunk_len);
	off += chunk_len;
	memcpy(buf + off, index, *index_len);
	off += *index_len;
	build_footer(buf + off, 16U + chunk_len, *index_len, 1U, digest);
	return off + 64U;
}

/* test_archive_one_chunk_at() for member "a". Shared with test_integration.c.
 */
size_t test_archive_one_chunk(uint8_t *buf, size_t cap, const uint8_t *chunk,
                              size_t chunk_len, uint64_t size_original,
                              size_t *index_len)
{
	return test_archive_one_chunk_at(buf, cap, "a", chunk, chunk_len,
	                                 size_original, index_len);
}

/*
 * One-member archive "a" whose single chunk is a Deflate stream of "abc"
 * followed by `extra` zero bytes; the chunk size, member hash and index hash
 * all cover the padding, so only the stream-end check can reject it. Reports
 * the chunk and index sizes; returns the archive length, or 0.
 */
static size_t build_padded_chunk_archive(uint8_t *buf, size_t cap, size_t extra,
                                         size_t *chunk_len, size_t *index_len)
{
	uint8_t src[] = {0x61U, 0x62U, 0x63U};
	uint8_t comp[128];
	ssize_t clen;

	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0 || (size_t)clen + extra > sizeof(comp))
		return 0U;
	memset(comp + clen, 0, extra);
	*chunk_len = (size_t)clen + extra;
	return test_archive_one_chunk(buf, cap, comp, *chunk_len, sizeof(src),
	                              index_len);
}

/*
 * ark_read_chunk accepts a chunk that is exactly one Deflate stream and
 * rejects the same chunk with one byte after the stream (ARK_ERR_FMT_DATA).
 */
int test_read_chunk_trailing_bytes(void)
{
	size_t extra;

	for (extra = 0U; extra <= 1U; extra++) {
		read_ctx_storage_t storage;
		ark_read_ctx_t *ctx;
		ark_error_t err;
		const ark_member_meta_t *meta;
		uint8_t buf[512];
		uint8_t out[64];
		size_t len;
		size_t chunk_len;
		size_t index_len;
		ssize_t n;

		len = build_padded_chunk_archive(buf, sizeof(buf), extra,
		                                 &chunk_len, &index_len);
		if (len == 0U ||
		    parse_index_ok(buf, buf + len - 64U, buf + 16U + chunk_len,
		                   index_len, &storage, &ctx) != 0)
			return 1;
		meta = ark_read_member_meta(ctx, 0U);
		if (meta == NULL)
			return 1;
		n = ark_read_chunk(ctx, meta, 0U, buf + 16U, chunk_len, out,
		                   sizeof(out), &err);
		ark_read_free(ctx);
		if (extra == 0U && (n != 3 || memcmp(out, "abc", 3U) != 0))
			return 1;
		if (extra != 0U &&
		    (n != -1 || err.code != ARK_ERR_FMT_DATA ||
		     strstr(err.msg, "bytes after deflate stream") == NULL))
			return 1;
	}
	return 0;
}

/*
 * Extract (worker pool path) restores the exact-stream archive and fails
 * the padded one with ARK_ERR_FMT_DATA, leaving no extracted file.
 */
int test_extract_chunk_trailing_bytes(void)
{
	char dir[] = "/tmp/ark-trailing.XXXXXX";
	char arc[64];
	char out_dir[64];
	char member[80];
	size_t extra;
	int rc;

	if (mkdtemp(dir) == NULL)
		return 1;
	(void)snprintf(arc, sizeof(arc), "%s/t.ark", dir);
	(void)snprintf(out_dir, sizeof(out_dir), "%s/out", dir);
	(void)snprintf(member, sizeof(member), "%s/a", out_dir);
	rc = 0;
	for (extra = 0U; rc == 0 && extra <= 1U; extra++) {
		ark_error_t err;
		uint8_t buf[512];
		size_t len;
		size_t chunk_len;
		size_t index_len;
		FILE *f;
		int xrc;

		len = build_padded_chunk_archive(buf, sizeof(buf), extra,
		                                 &chunk_len, &index_len);
		f = fopen(arc, "wb");
		if (len == 0U || f == NULL) {
			if (f != NULL)
				(void)fclose(f);
			rc = 1;
			break;
		}
		if (fwrite(buf, 1U, len, f) != len)
			rc = 1;
		if (fclose(f) != 0 || rc != 0 || mkdir(out_dir, 0700) != 0) {
			rc = 1;
			break;
		}
		memset(&err, 0, sizeof(err));
		xrc = ark_test_verify_archive(arc, NULL, 0, 1, &err);
		if (extra == 0U ? xrc != 0
		                : xrc != -1 || err.code != ARK_ERR_FMT_DATA)
			rc = 1;
		memset(&err, 0, sizeof(err));
		xrc = ark_test_extract_archive(arc, out_dir, 0, NULL, 1, &err);
		if (extra == 0U) {
			uint8_t got[8];

			f = fopen(member, "rb");
			if (xrc != 0 || f == NULL ||
			    fread(got, 1U, sizeof(got), f) != 3U ||
			    memcmp(got, "abc", 3U) != 0)
				rc = 1;
			if (f != NULL)
				(void)fclose(f);
		} else if (xrc != -1 || err.code != ARK_ERR_FMT_DATA ||
		           access(member, F_OK) == 0) {
			rc = 1;
		}
		(void)unlink(member);
		(void)rmdir(out_dir);
	}
	(void)unlink(arc);
	(void)rmdir(dir);
	return rc;
}

/*
 * extract_built_archive - Write len bytes of archive buf to dir/t.ark, verify
 * it and extract it into dir/out, both with four workers. Returns 0 when both
 * fail with code and extraction leaves dir/out empty, 1 otherwise.
 */
static int extract_built_archive(const char *dir, const uint8_t *buf,
                                 size_t len, ark_err_t code)
{
	char arc[64];
	char out_dir[64];
	char member[80];
	ark_error_t err;
	FILE *f;
	int rc;

	(void)snprintf(arc, sizeof(arc), "%s/t.ark", dir);
	(void)snprintf(out_dir, sizeof(out_dir), "%s/out", dir);
	(void)snprintf(member, sizeof(member), "%s/a", out_dir);
	f = fopen(arc, "wb");
	if (f == NULL)
		return 1;
	rc = fwrite(buf, 1U, len, f) == len ? 0 : 1;
	if (fclose(f) != 0 || rc != 0 || mkdir(out_dir, 0700) != 0) {
		(void)unlink(arc);
		return 1;
	}
	memset(&err, 0, sizeof(err));
	if (ark_test_verify_archive(arc, NULL, 0, 4, &err) != -1 ||
	    err.code != code)
		rc = 1;
	memset(&err, 0, sizeof(err));
	if (ark_test_extract_archive(arc, out_dir, 0, NULL, 4, &err) != -1 ||
	    err.code != code || access(member, F_OK) == 0)
		rc = 1;
	(void)unlink(member);
	(void)rmdir(out_dir);
	(void)unlink(arc);
	return rc;
}

/*
 * A chunk that decodes cleanly to fewer or more bytes than the member's
 * size_original says fails extraction with ARK_ERR_FMT_DATA (ARCHITECTURE.md
 * section 6.3); the member hash covers the chunk, so only the length check
 * can reject it.
 */
int test_extract_chunk_length_mismatch(void)
{
	static const uint64_t sizes[] = {2U, 4U};
	char dir[] = "/tmp/ark-xlen.XXXXXX";
	uint8_t src[] = {0x61U, 0x62U, 0x63U};
	uint8_t comp[128];
	uint8_t buf[512];
	ssize_t clen;
	size_t index_len;
	size_t i;
	int rc = 0;

	if (mkdtemp(dir) == NULL)
		return 1;
	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	for (i = 0U; rc == 0 && i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		size_t len;

		len = clen > 0 ? test_archive_one_chunk(buf, sizeof(buf), comp,
		                                        (size_t)clen, sizes[i],
		                                        &index_len)
		               : 0U;
		if (len == 0U ||
		    extract_built_archive(dir, buf, len, ARK_ERR_FMT_DATA) != 0)
			rc = 1;
	}
	(void)rmdir(dir);
	return rc;
}

/*
 * A chunk one byte larger than ark_deflate_bound(ARK_CHUNK_SIZE) is
 * rejected with ARK_ERR_FMT_INDEX before it is read into the chunk buffer
 * (which has exactly that bound); the index itself does not limit chunk
 * sizes.
 */
int test_extract_chunk_over_bound(void)
{
	char dir[] = "/tmp/ark-xbound.XXXXXX";
	uint8_t *chunk;
	uint8_t *buf;
	size_t chunk_len;
	size_t cap;
	size_t index_len;
	int rc = 1;

	if (mkdtemp(dir) == NULL)
		return 1;
	chunk_len = ark_deflate_bound(ARK_CHUNK_SIZE) + 1U;
	cap = chunk_len + 1024U;
	chunk = (uint8_t *)calloc(chunk_len, 1U);
	buf = (uint8_t *)malloc(cap);
	if (chunk != NULL && buf != NULL) {
		size_t len;

		len = test_archive_one_chunk(buf, cap, chunk, chunk_len,
		                             ARK_CHUNK_SIZE, &index_len);
		if (len != 0U && extract_built_archive(dir, buf, len,
		                                       ARK_ERR_FMT_INDEX) == 0)
			rc = 0;
	}
	free(buf);
	free(chunk);
	(void)rmdir(dir);
	return rc;
}

/*
 * Write buf to dir/t.ark, then run verify and extract (all members and
 * --member `member`) into an empty dir/out. With expect == 0 every run must
 * succeed; otherwise every run must fail with ARK_ERR_FMT_INDEX and leave
 * dir/out empty.
 */
static int ancestry_runs(const char *dir, const uint8_t *buf, size_t len,
                         const char *member, int expect)
{
	char arc[64];
	char out_dir[64];
	char path[128];
	ark_error_t err;
	FILE *f;
	int pass;
	int rc;

	(void)snprintf(arc, sizeof(arc), "%s/t.ark", dir);
	(void)snprintf(out_dir, sizeof(out_dir), "%s/out", dir);
	f = fopen(arc, "wb");
	if (f == NULL)
		return 1;
	rc = fwrite(buf, 1U, len, f) == len ? 0 : 1;
	if (fclose(f) != 0)
		rc = 1;
	for (pass = 0; rc == 0 && pass < 4; pass++) {
		const char *sel;
		int got;

		sel = (pass & 1) != 0 ? member : NULL;
		memset(&err, 0, sizeof(err));
		if (mkdir(out_dir, 0700) != 0) {
			rc = 1;
			break;
		}
		if (pass < 2)
			got = ark_test_verify_archive(arc, sel, 0, 4, &err);
		else
			got = ark_test_extract_archive(arc, out_dir, 0, sel, 4,
			                               &err);
		if (expect == 0) {
			if (got != 0)
				rc = 1;
		} else if (got != -1 || err.code != ARK_ERR_FMT_INDEX ||
		           rmdir(out_dir) != 0) {
			rc = 1; /* failed differently or created something */
			break;
		}
		if (expect == 0) {
			/* Remove what a successful extract created. */
			(void)snprintf(path, sizeof(path), "%s/%s", out_dir,
			               member);
			(void)unlink(path);
			if (strchr(member, '/') != NULL) {
				char *slash;

				slash = strrchr(path, '/');
				*slash = '\0';
				(void)rmdir(path);
			}
			if (rmdir(out_dir) != 0)
				rc = 1;
		}
	}
	(void)rmdir(out_dir);
	(void)unlink(arc);
	return rc;
}

/*
 * Every index needs full ancestry, for selective extraction too
 * (ARCHITECTURE.md section 8.3 checks 9 and 10, section 14.4): an archive
 * whose only member is "absent/victim", with no "absent" directory member,
 * is rejected by verify and extract, with and without --member, before
 * anything is created. The same member without a parent ("victim") is
 * accepted by all four runs, so the missing ancestor is the only cause.
 */
int test_read_selective_requires_full_ancestry(void)
{
	char dir[] = "/tmp/ark-anc.XXXXXX";
	uint8_t src[] = {0x61U, 0x62U, 0x63U};
	uint8_t comp[128];
	uint8_t buf[512];
	ssize_t clen;
	size_t index_len;
	size_t len;
	int rc = 1;

	if (mkdtemp(dir) == NULL)
		return 1;
	clen = test_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                             ARK_DEFLATE_LEVEL_DEFAULT);
	if (clen <= 0)
		goto done;
	len = test_archive_one_chunk_at(buf, sizeof(buf), "absent/victim", comp,
	                                (size_t)clen, sizeof(src), &index_len);
	if (len == 0U || ancestry_runs(dir, buf, len, "absent/victim", -1) != 0)
		goto done;
	len = test_archive_one_chunk_at(buf, sizeof(buf), "victim", comp,
	                                (size_t)clen, sizeof(src), &index_len);
	if (len == 0U || ancestry_runs(dir, buf, len, "victim", 0) != 0)
		goto done;
	rc = 0;
done:
	(void)rmdir(dir);
	return rc;
}

int test_read_empty_file_chunk_count_zero(void)
{
	read_entry_t e;
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[256];
	uint8_t digest[32];
	size_t index_len;
	const ark_member_meta_t *meta;

	entry_base(&e, 0x01U, "e");
	hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e.hash);
	if (build_index(&e, 1U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 1U, digest);
	if (parse_index_ok(header, footer, index, index_len, &storage, &ctx) !=
	    0)
		return 1;
	meta = ark_read_member_meta(ctx, 0U);
	if (meta == NULL)
		return 1;
	if (meta->chunk_count != 0U)
		return 1;
	if (meta->size_original != 0U)
		return 1;
	ark_read_free(ctx);
	return 0;
}

int test_read_find_member(void)
{
	static const char *const paths[] = {"b", "a", "a/x", "a/x/y", "c"};
	static const char *const missing[] = {"a/x/", "a/xy", "a/",
	                                      "d",    "",     "a/x/y/z"};
	read_entry_t e[5];
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[1024];
	uint8_t digest[32];
	size_t index_len;
	uint32_t pos;
	size_t i;
	int rc;

	for (i = 0U; i < 5U; i++) {
		entry_base(&e[i], 0x02U, paths[i]);
		hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[i].hash);
	}
	if (build_index(e, 5U, index, sizeof(index), &index_len) != 0)
		return 1;
	hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
	build_header(header, ARK_HASH_BLAKE3);
	build_footer(footer, 16U, index_len, 5U, digest);

	/* Not usable before the index is read. */
	ctx = read_ctx_from_storage(&storage);
	if (ark_read_header(ctx, header, 16U, &err) != 0 ||
	    ark_read_init(ctx, footer, 64U, &err) != 0)
		return 1;
	if (ark_read_find_member(ctx, "a", &pos) != -1)
		return 1;
	if (ark_read_index(ctx, index, index_len, &err) != 0)
		return 1;

	rc = 0;
	for (i = 0U; i < 5U; i++) {
		if (ark_read_find_member(ctx, paths[i], &pos) != 0 ||
		    pos != (uint32_t)i)
			rc = 1;
	}
	for (i = 0U; i < sizeof(missing) / sizeof(missing[0]); i++) {
		if (ark_read_find_member(ctx, missing[i], &pos) != -1)
			rc = 1;
	}
	if (ark_read_find_member(NULL, "a", &pos) != -1 ||
	    ark_read_find_member(ctx, NULL, &pos) != -1 ||
	    ark_read_find_member(ctx, "a", NULL) != -1)
		rc = 1;
	ark_read_free(ctx);
	return rc;
}

/*
 * strings_write_member - Begin a member from scratch copies of path and link,
 * overwrite the copies, write its chunks and end it. The context must have
 * kept its own copies.
 */
static int strings_write_member(ark_write_ctx_t *ctx,
                                const ark_member_meta_t *meta, const char *path,
                                const char *link, const uint32_t *chunk_lens,
                                uint32_t n)
{
	ark_member_meta_t m;
	char pbuf[64];
	char lbuf[64];
	uint8_t data[8];
	uint8_t out[8];
	ark_error_t err;
	uint32_t i;

	(void)snprintf(pbuf, sizeof(pbuf), "%s", path);
	(void)snprintf(lbuf, sizeof(lbuf), "%s", link);
	m = *meta;
	m.path = pbuf;
	m.link = lbuf;
	if (ark_write_member_begin(ctx, &m, &err) != 0)
		return 1;
	memset(pbuf, 'X', sizeof(pbuf) - 1U);
	memset(lbuf, 'Y', sizeof(lbuf) - 1U);
	memset(data, 0x5a, sizeof(data));
	for (i = 0U; i < n; i++) {
		if (ark_write_chunk(ctx, data, chunk_lens[i], out, sizeof(out),
		                    &err) != (ssize_t)chunk_lens[i])
			return 1;
	}
	return ark_write_member_end(ctx, &err) != 0 ? 1 : 0;
}

/*
 * test_member_strings_owned_by_context - The write context copies member
 * strings at member_begin (the caller's buffers are overwritten right
 * after), and the read context keeps paths, links and chunk sizes in its own
 * store (the raw index is freed right after ark_read_index, as ark does).
 * See ARCHITECTURE.md section 16.2.
 */
int test_member_strings_owned_by_context(void)
{
	static const char *const paths[] = {"d", "d/s", "d/big", "d/one",
	                                    "d/h"};
	static const char *const links[] = {"", "t", "", "", "d/one"};
	static const uint32_t big_chunks[] = {3U, 5U};
	static const uint32_t one_chunks[] = {2U};
	write_ctx_storage_t wstorage;
	read_ctx_storage_t rstorage;
	ark_write_ctx_t *wctx;
	ark_read_ctx_t *rctx;
	ark_member_meta_t meta;
	const ark_member_meta_t *m;
	ark_error_t err;
	uint8_t header[16];
	uint8_t footer[64];
	uint8_t index[1024];
	uint8_t *copy;
	ssize_t idx_len;
	uint32_t pos;
	uint32_t i;
	int rc;

	wctx = ctx_from_storage(&wstorage);
	if (ark_write_init(wctx, ARK_HASH_BLAKE3, ARK_DEFLATE_LEVEL_DEFAULT,
	                   &err) != 0 ||
	    ark_write_header(wctx, header, sizeof(header), &err) != 16)
		return 1;
	rc = 0;
	meta_init(&meta, 0x02U, paths[0]);
	rc |= strings_write_member(wctx, &meta, paths[0], links[0], NULL, 0U);
	meta_init(&meta, 0x03U, paths[1]);
	rc |= strings_write_member(wctx, &meta, paths[1], links[1], NULL, 0U);
	meta_init(&meta, 0x01U, paths[2]);
	meta.size_original = (uint64_t)ARK_CHUNK_SIZE + 1U;
	meta.data_offset = 16U;
	rc |= strings_write_member(wctx, &meta, paths[2], links[2], big_chunks,
	                           2U);
	meta_init(&meta, 0x01U, paths[3]);
	meta.size_original = 1U;
	meta.data_offset = 24U;
	rc |= strings_write_member(wctx, &meta, paths[3], links[3], one_chunks,
	                           1U);
	meta_init(&meta, 0x04U, paths[4]);
	rc |= strings_write_member(wctx, &meta, paths[4], links[4], NULL, 0U);
	idx_len =
	    rc != 0 ? -1 : ark_write_index(wctx, index, sizeof(index), &err);
	if (idx_len <= 0 ||
	    ark_write_footer(wctx, 26U, (uint64_t)idx_len, footer,
	                     sizeof(footer), &err) != 64) {
		ark_write_free(wctx);
		return 1;
	}
	ark_write_free(wctx);

	copy = (uint8_t *)malloc((size_t)idx_len);
	if (copy == NULL)
		return 1;
	memcpy(copy, index, (size_t)idx_len);
	rctx = read_ctx_from_storage(&rstorage);
	if (ark_read_header(rctx, header, 16U, &err) != 0 ||
	    ark_read_init(rctx, footer, 64U, &err) != 0 ||
	    ark_read_index(rctx, copy, (size_t)idx_len, &err) != 0) {
		free(copy);
		ark_read_free(rctx);
		return 1;
	}
	/* Under ASan, any later use of the raw index is a use after free. */
	free(copy);

	for (i = 0U; i < 5U; i++) {
		m = ark_read_member_meta(rctx, i);
		if (m == NULL || m->path == NULL || m->link == NULL ||
		    strcmp(m->path, paths[i]) != 0 ||
		    strcmp(m->link, links[i]) != 0)
			rc = 1;
		if (ark_read_find_member(rctx, paths[i], &pos) != 0 || pos != i)
			rc = 1;
	}
	m = ark_read_member_meta(rctx, 2U);
	if (m == NULL || m->chunk_count != 2U || m->chunk_sizes == NULL ||
	    m->chunk_sizes[0] != 3U || m->chunk_sizes[1] != 5U)
		rc = 1;
	m = ark_read_member_meta(rctx, 3U);
	if (m == NULL || m->chunk_count != 1U || m->chunk_sizes == NULL ||
	    m->chunk_sizes[0] != 2U)
		rc = 1;
	m = ark_read_member_meta(rctx, 0U);
	if (m == NULL || m->chunk_count != 0U || m->chunk_sizes != NULL)
		rc = 1;
	ark_read_free(rctx);
	return rc;
}

#define MANY_MEMBERS 20000U

/*
 * many_members_index - Serialize MANY_MEMBERS directory members in reverse
 * name order (plus an optional duplicate of the first one) and parse it.
 * Returns the ark_read_index result; *ctx_out holds the context on success.
 */
static int many_members_index(int add_duplicate, read_ctx_storage_t *storage,
                              ark_read_ctx_t **ctx_out, ark_error_t *err)
{
	static char names[MANY_MEMBERS][8];
	read_entry_t *e;
	uint8_t *index;
	size_t index_len;
	size_t cap;
	size_t n;
	size_t i;
	int rc;

	n = MANY_MEMBERS + (add_duplicate ? 1U : 0U);
	cap = n * (79U + 8U + 4U);
	e = calloc(n, sizeof(e[0]));
	index = malloc(cap);
	if (e == NULL || index == NULL) {
		free(e);
		free(index);
		return -2;
	}
	for (i = 0U; i < MANY_MEMBERS; i++) {
		(void)snprintf(names[i], sizeof(names[i]), "d%05zu",
		               MANY_MEMBERS - 1U - i);
		entry_base(&e[i], 0x02U, names[i]);
		hash_bytes(ARK_HASH_BLAKE3, NULL, 0U, e[i].hash);
	}
	if (add_duplicate)
		e[MANY_MEMBERS] = e[0];
	rc = -2;
	if (build_index(e, n, index, cap, &index_len) == 0) {
		ark_read_ctx_t *ctx;
		uint8_t header[16];
		uint8_t footer[64];
		uint8_t digest[32];

		hash_bytes(ARK_HASH_BLAKE3, index, index_len, digest);
		build_header(header, ARK_HASH_BLAKE3);
		build_footer(footer, 16U, index_len, (uint32_t)n, digest);
		ctx = read_ctx_from_storage(storage);
		if (ark_read_header(ctx, header, 16U, err) == 0 &&
		    ark_read_init(ctx, footer, 64U, err) == 0) {
			rc = ark_read_index(ctx, index, index_len, err);
			*ctx_out = ctx;
		}
	}
	free(index);
	free(e);
	return rc;
}

int test_read_index_many_members(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;
	uint32_t pos;
	int rc;

	ctx = NULL;
	if (many_members_index(0, &storage, &ctx, &err) != 0)
		return 1;
	/* Names were written in reverse order: d19999 is member 0. */
	rc = 0;
	if (ark_read_find_member(ctx, "d19999", &pos) != 0 || pos != 0U ||
	    ark_read_find_member(ctx, "d00000", &pos) != 0 ||
	    pos != MANY_MEMBERS - 1U ||
	    ark_read_find_member(ctx, "d12345", &pos) != 0 ||
	    pos != MANY_MEMBERS - 1U - 12345U ||
	    ark_read_find_member(ctx, "d20000", &pos) != -1)
		rc = 1;
	ark_read_free(ctx);
	return rc;
}

int test_read_index_many_members_duplicate(void)
{
	read_ctx_storage_t storage;
	ark_read_ctx_t *ctx;
	ark_error_t err;

	ctx = NULL;
	if (many_members_index(1, &storage, &ctx, &err) != -1)
		return 1;
	ark_read_free(ctx);
	return err.code == ARK_ERR_FMT_INDEX ? 0 : 1;
}
