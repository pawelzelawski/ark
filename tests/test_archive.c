#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "archive.h"
#include "blake3.h"
#include "sha256.h"

typedef union {
	max_align_t align;
	uint8_t bytes[8192];
} write_ctx_storage_t;

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
