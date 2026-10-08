#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "blake3.h"
#include "sha256.h"

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
	(void)snprintf(meta->path, sizeof(meta->path), "%s", path);
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	(void)snprintf(sym.link, sizeof(sym.link), "%s", "t");
	meta_init(&hard, 0x04U, "h");
	(void)snprintf(hard.link, sizeof(hard.link), "%s", "f");

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
		return 1;
	ark_write_free(ctx);

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);

	ctx = ctx_from_storage(&storage);
	meta_init(&meta, 0x01U, "f");
	meta.size_original = 0U;
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

int test_write_header_magic(void)
{
	write_ctx_storage_t storage;
	ark_write_ctx_t *ctx;
	ark_error_t err;
	uint8_t header[16];

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
		return 1;
	if (ark_write_header(ctx, header, sizeof(header), &err) != 16)
		return 1;
	ark_write_free(ctx);
	if (header[9] != 0x01U)
		return 1;

	ctx = ctx_from_storage(&storage);
	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	(void)snprintf(sym.link, sizeof(sym.link), "%s", "t");
	meta_init(&hard, 0x04U, "h");
	(void)snprintf(hard.link, sizeof(hard.link), "%s", "d");

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	if (ark_write_init(ctx, ARK_HASH_SHA256, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	(void)snprintf(meta.link, sizeof(meta.link), "%s", "/target");
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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
	if (ark_write_init(ctx, ARK_HASH_BLAKE3, ARK_DEFLATE_DEFAULT, &err) !=
	    0)
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

	clen = ark_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                            ARK_DEFLATE_DEFAULT);
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

	clen = ark_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                            ARK_DEFLATE_DEFAULT);
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

	clen = ark_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                            ARK_DEFLATE_DEFAULT);
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

	clen = ark_deflate_compress(src, sizeof(src), comp, sizeof(comp),
	                            ARK_DEFLATE_DEFAULT);
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
