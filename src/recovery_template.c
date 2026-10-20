/*
 * recovery.c - standalone recovery reader for ark archives (format v1).
 *
 * This file was written by `ark generate-reader`. Keep it next to your
 * archives: it extracts any ark v1 archive without ark itself, and the
 * comment below describes the format completely, so that the data stays
 * recoverable even if neither ark nor this program can be built any more.
 *
 * ========================================================================
 * 1. Building and running
 * ========================================================================
 *
 * Any C11 compiler on a POSIX.1-2008 system (no other libraries):
 *
 *   cc -O2 recovery.c -o recover
 *   mkdir out && cd out && ../recover ../archive.ark
 *
 * The archive is extracted into the current directory, which must not
 * already hold any of the archive's files (existing directories are
 * reused). Mode, mtime and, when run as root, ownership are restored.
 * Nothing is written before the whole index has passed every check of
 * section 4. The first member that fails (damaged data, an existing file)
 * stops the recovery; the members extracted before it are complete and
 * verified, and the failing member's file is removed.
 *
 * Exit status: 0 recovered; 1 usage, I/O or extraction failure; 2 the
 * archive was rejected before anything was written (invalid header, footer
 * or index).
 *
 * ========================================================================
 * 2. Format
 * ========================================================================
 *
 * All integers are little-endian (u16, u32, u64: least significant byte
 * first), with no padding anywhere. An archive is:
 *
 *   [header]       16 bytes at offset 0
 *   [body]         the compressed member data, back to back
 *   [index]        one entry per member
 *   [footer]       64 bytes, the last 64 bytes of the file
 *
 * Header:
 *
 *   offset size  field       value
 *   0      5     magic       "ark!\n" (61 72 6B 21 0A)
 *   5      1     ver_major   1
 *   6      1     ver_minor   0 (readers ignore it)
 *   7      1     flags       0
 *   8      1     comp_alg    1 = Deflate (RFC 1951), the only value
 *   9      1     hash_alg    1 = BLAKE3, 2 = SHA-256
 *   10     6     reserved    0
 *
 * Footer (at file_size - 64):
 *
 *   offset size  field          value
 *   0      8     index_offset   u64, file offset of the index
 *   8      8     index_size     u64, length of the index in bytes
 *   16     32    index_hash     hash of the whole index (hash_alg)
 *   48     4     member_count   u32, number of index entries
 *   52     4     magic_confirm  u32 0x4B52410A (bytes 0A 41 52 4B)
 *   56     8     reserved       0
 *
 * index_offset + index_size equals file_size - 64.
 *
 * Index entry (member_count of them, back to back):
 *
 *   offset size  field            meaning
 *   0      1     type             1 file, 2 directory, 3 symlink, 4 hardlink
 *   1      4     mode             st_mode & 0xFFFF; only 0777 is restored
 *   5      4     uid              owner, restored by root only
 *   9      4     gid              group, restored by root only
 *   13     8     mtime            nanoseconds since 1970-01-01 UTC, as a
 *                                 signed 64-bit value stored in a u64
 *   21     8     size_original    file size in bytes
 *   29     8     size_compressed  sum of the chunk sizes below
 *   37     8     data_offset      file offset of the member's first chunk
 *   45     32    hash             see "Hashes" below
 *   77     2     path_len         u16
 *   79     path_len               path, UTF-8, not NUL-terminated
 *   then, for types 3 and 4 only:
 *          2     link_len         u16
 *          link_len               symlink target, or hardlink target path
 *   then:
 *          4     chunk_count      u32
 *          4 x chunk_count        compressed size of each chunk, u32
 *
 * Only regular files with size_original > 0 have data: chunk_count =
 * ceil(size_original / 1048576). For every other member (directories,
 * symlinks, hardlinks, empty regular files) size_original,
 * size_compressed, data_offset and chunk_count are all 0.
 *
 * Paths are relative, separated by '/', at most 1023 bytes, valid UTF-8,
 * without NUL bytes, a leading or trailing '/', empty components, "." or
 * "..". Every parent of a path is a directory member earlier in the index.
 * Paths are unique. A hardlink target is the path of an earlier regular
 * file member (same rules). A symlink target is stored as readlink()
 * returned it: not absolute, no ".." component, no NUL, valid UTF-8 ("."
 * and empty components are allowed).
 *
 * Body and chunks: a file's content is cut into 1 MiB (1048576-byte)
 * pieces, the last one shorter; each piece is compressed on its own as one
 * complete raw Deflate stream (RFC 1951, no zlib or gzip wrapper) and
 * stored as one chunk, with nothing after its final block. A member's
 * chunks follow each other from data_offset; the members' chunk runs fill
 * the body from offset 16 to index_offset exactly, without gaps or
 * overlaps. A chunk is at most 1048662 bytes (1 MiB stored in 17 Deflate
 * blocks of at most 65535 bytes, 5 header bytes each, plus 1).
 *
 * Hashes: hash_alg selects BLAKE3 (the standard hash mode, 32-byte output)
 * or SHA-256 (FIPS 180-4) for the whole archive. A file's hash is taken
 * over its compressed chunks, concatenated in order, exactly as stored. A
 * member without data carries the hash of empty input:
 *   BLAKE3:  af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
 *   SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * The footer's index_hash covers the index bytes from index_offset to
 * index_offset + index_size.
 *
 * ========================================================================
 * 3. Recovering by hand
 * ========================================================================
 *
 * Without this program: read the footer, check magic_confirm, hash the
 * index and compare with index_hash; walk the entries as above. For each
 * regular file, read chunk_count chunks starting at data_offset (chunk i
 * starts where chunk i-1 ended), inflate each one with any raw Deflate
 * decoder (for example zlib's inflate with windowBits = -15, or Python's
 * zlib.decompress(chunk, -15)) and concatenate the output; the result is
 * size_original bytes long. Hash the stored chunks to check the data.
 *
 * ========================================================================
 * 4. Checks
 * ========================================================================
 *
 * Before writing anything this reader applies the checks of ark's own
 * reader, so it accepts exactly the archives ark accepts: header and footer
 * fields; the index hash; every entry's type, path, link target and size
 * fields; the chunk count and sizes; data inside the body; unique paths;
 * parents and hardlink targets earlier in the index and of the right type;
 * a gap-free, overlap-free body; the empty-input hash on members without
 * data. While extracting it checks every chunk (valid Deflate, nothing
 * after the final block, exact length) and each file's hash. Code 284 with
 * extra value 31 (an old, non-standard way to code length 258 that some
 * decoders accept) is rejected, as ark does.
 *
 * ========================================================================
 * 5. Why the format looks like this
 * ========================================================================
 *
 * - Fixed-size header and footer with plain magic bytes: an archive is
 *   recognisable in any hex viewer, and the index is found with one seek.
 * - Index at the end: ark writes an archive in one pass, without seeking
 *   back; the index hash proves the metadata before anything is extracted.
 * - Independent 1 MiB chunks: compressed in parallel, and damage stays
 *   inside one chunk of one member.
 * - Hashes over the stored (compressed) bytes: a member is verified without
 *   decompressing it; there is no whole-archive hash, the per-member hashes
 *   and the index hash cover every byte.
 * - Raw Deflate: the most widely implemented compression format, decodable
 *   by many independent implementations.
 *
 * Source map: ARCHITECTURE.md in the ark repository, sections 2-6 (format),
 * 8.2-8.3 (hashes, checks) and 15 (this reader). Integer fields are decoded
 * byte by byte, so the program is correct on any byte order.
 */

/*
 * The reader uses POSIX.1-2008 interfaces (openat and the other *at calls,
 * pread, futimens, O_NOFOLLOW, O_DIRECTORY, O_CLOEXEC). A strict C11 build
 * (cc -std=c11) hides them unless the source requests them, so the
 * feature-test macro must precede every #include. _FILE_OFFSET_BITS asks
 * 32-bit systems for a 64-bit off_t, so archives over 2 GiB stay readable.
 * ARCHITECTURE.md section 15.2.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define REC_CHUNK_SIZE 1048576U
/*
 * Largest compressed chunk ark writes: the Deflate bound of one 1 MiB chunk
 * (1 MiB + 5 bytes per 65,535-byte stored block + 1). Larger chunk sizes in
 * an index are rejected, so one buffer of this size holds any chunk.
 */
#define REC_MAX_COMP_CHUNK (REC_CHUNK_SIZE + 17U * 5U + 1U)
#define REC_HASH_LEN 32U
#define REC_HEADER_SIZE 16U
#define REC_FOOTER_SIZE 64U
#define REC_MAX_PATH 1023U

#define REC_HASH_BLAKE3 0x01U
#define REC_HASH_SHA256 0x02U

#define REC_TYPE_FILE 0x01U
#define REC_TYPE_DIR 0x02U
#define REC_TYPE_SYMLINK 0x03U
#define REC_TYPE_HARDLINK 0x04U

typedef struct {
	uint8_t type;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t mtime;
	uint64_t size_original;
	uint64_t size_compressed;
	uint64_t data_offset;
	uint8_t hash[REC_HASH_LEN];
	char *path;
	char *link;
	uint32_t chunk_count;
	uint32_t *chunk_sizes;
} rec_member_t;

/* ------------------------------ LE decoding ------------------------------ */

static uint16_t le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

/* ------------------------------- SHA-256 -------------------------------- */

typedef struct {
	uint32_t state[8];
	uint32_t schedule[64];
	uint8_t block[64];
	uint64_t byte_count;
	size_t block_len;
} rec_sha256_ctx_t;

static const uint32_t rec_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rec_rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32U - n));
}

static uint32_t rec_load_be32(const uint8_t src[4])
{
	return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

static void rec_store_be32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)(x >> 24);
	dst[1] = (uint8_t)(x >> 16);
	dst[2] = (uint8_t)(x >> 8);
	dst[3] = (uint8_t)x;
}

static void rec_store_be64(uint8_t dst[8], uint64_t x)
{
	dst[0] = (uint8_t)(x >> 56);
	dst[1] = (uint8_t)(x >> 48);
	dst[2] = (uint8_t)(x >> 40);
	dst[3] = (uint8_t)(x >> 32);
	dst[4] = (uint8_t)(x >> 24);
	dst[5] = (uint8_t)(x >> 16);
	dst[6] = (uint8_t)(x >> 8);
	dst[7] = (uint8_t)x;
}

static void rec_sha256_compress(rec_sha256_ctx_t *ctx, const uint8_t block[64])
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t i;

	for (i = 0; i < 16; i++)
		ctx->schedule[i] = rec_load_be32(block + (size_t)i * 4U);
	for (; i < 64; i++) {
		uint32_t w0, w1;

		w0 = rec_rotr32(ctx->schedule[i - 15], 7) ^
		     rec_rotr32(ctx->schedule[i - 15], 18) ^
		     (ctx->schedule[i - 15] >> 3);
		w1 = rec_rotr32(ctx->schedule[i - 2], 17) ^
		     rec_rotr32(ctx->schedule[i - 2], 19) ^
		     (ctx->schedule[i - 2] >> 10);
		ctx->schedule[i] =
		    ctx->schedule[i - 16] + w0 + ctx->schedule[i - 7] + w1;
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		uint32_t ch, maj, s0, s1, t1, t2;

		s1 = rec_rotr32(e, 6) ^ rec_rotr32(e, 11) ^ rec_rotr32(e, 25);
		ch = (e & f) ^ ((~e) & g);
		t1 = h + s1 + ch + rec_sha256_k[i] + ctx->schedule[i];
		s0 = rec_rotr32(a, 2) ^ rec_rotr32(a, 13) ^ rec_rotr32(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void rec_sha256_init(rec_sha256_ctx_t *ctx)
{
	ctx->state[0] = 0x6a09e667U;
	ctx->state[1] = 0xbb67ae85U;
	ctx->state[2] = 0x3c6ef372U;
	ctx->state[3] = 0xa54ff53aU;
	ctx->state[4] = 0x510e527fU;
	ctx->state[5] = 0x9b05688cU;
	ctx->state[6] = 0x1f83d9abU;
	ctx->state[7] = 0x5be0cd19U;
	ctx->byte_count = 0;
	ctx->block_len = 0;
	memset(ctx->block, 0, sizeof(ctx->block));
	memset(ctx->schedule, 0, sizeof(ctx->schedule));
}

static void rec_sha256_update(rec_sha256_ctx_t *ctx, const uint8_t *data,
                              size_t len)
{
	ctx->byte_count += (uint64_t)len;

	if (ctx->block_len != 0U) {
		size_t n;

		n = sizeof(ctx->block) - ctx->block_len;
		if (n > len)
			n = len;
		memcpy(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
		if (ctx->block_len == sizeof(ctx->block)) {
			rec_sha256_compress(ctx, ctx->block);
			ctx->block_len = 0;
		}
	}

	while (len >= sizeof(ctx->block)) {
		rec_sha256_compress(ctx, data);
		data += sizeof(ctx->block);
		len -= sizeof(ctx->block);
	}

	if (len != 0U) {
		memcpy(ctx->block, data, len);
		ctx->block_len = len;
	}
}

static void rec_sha256_final(rec_sha256_ctx_t *ctx, uint8_t digest[32])
{
	uint8_t zeros[64];
	uint8_t one;
	uint8_t len_be[8];
	uint64_t bit_count;
	size_t pad_zero_len;
	size_t i;

	bit_count = ctx->byte_count * 8U;
	memset(zeros, 0, sizeof(zeros));
	one = 0x80U;
	rec_sha256_update(ctx, &one, 1U);
	if (ctx->block_len <= 56U)
		pad_zero_len = 56U - ctx->block_len;
	else
		pad_zero_len = (64U - ctx->block_len) + 56U;
	while (pad_zero_len > 0U) {
		size_t n;

		n = pad_zero_len;
		if (n > sizeof(zeros))
			n = sizeof(zeros);
		rec_sha256_update(ctx, zeros, n);
		pad_zero_len -= n;
	}
	rec_store_be64(len_be, bit_count);
	rec_sha256_update(ctx, len_be, sizeof(len_be));
	for (i = 0; i < 8U; i++)
		rec_store_be32(digest + i * 4U, ctx->state[i]);
}

/* -------------------------------- BLAKE3 -------------------------------- */

typedef struct {
	uint32_t key[8];
	uint32_t cv[8];
	uint8_t block[64];
	size_t block_len;
	uint8_t blocks_compressed;
	uint64_t chunk_counter;
	uint32_t cv_stack[64][8];
	size_t cv_stack_len;
} rec_blake3_ctx_t;

typedef struct {
	uint32_t input_cv[8];
	uint32_t block[16];
	uint64_t counter;
	uint32_t block_len;
	uint32_t flags;
} rec_blake3_output_t;

#define REC_B3_BLOCK_LEN 64U
#define REC_B3_CHUNK_LEN 1024U
#define REC_B3_FLAG_CHUNK_START 0x01U
#define REC_B3_FLAG_CHUNK_END 0x02U
#define REC_B3_FLAG_PARENT 0x04U
#define REC_B3_FLAG_ROOT 0x08U

static const uint32_t rec_blake3_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const uint8_t rec_blake3_msg_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

static uint32_t rec_load_le32(const uint8_t src[4])
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static void rec_store_le32(uint8_t dst[4], uint32_t x)
{
	dst[0] = (uint8_t)x;
	dst[1] = (uint8_t)(x >> 8);
	dst[2] = (uint8_t)(x >> 16);
	dst[3] = (uint8_t)(x >> 24);
}

static void rec_block_to_words(const uint8_t block[64], uint32_t words[16])
{
	size_t i;

	for (i = 0; i < 16U; i++)
		words[i] = rec_load_le32(block + i * 4U);
}

static size_t rec_b3_chunk_len(const rec_blake3_ctx_t *ctx)
{
	return (size_t)ctx->blocks_compressed * REC_B3_BLOCK_LEN +
	       ctx->block_len;
}

static void rec_b3_g_mix(uint32_t state[16], size_t a, size_t b, size_t c,
                         size_t d, uint32_t mx, uint32_t my)
{
	state[a] = state[a] + state[b] + mx;
	state[d] = rec_rotr32(state[d] ^ state[a], 16);
	state[c] += state[d];
	state[b] = rec_rotr32(state[b] ^ state[c], 12);
	state[a] = state[a] + state[b] + my;
	state[d] = rec_rotr32(state[d] ^ state[a], 8);
	state[c] += state[d];
	state[b] = rec_rotr32(state[b] ^ state[c], 7);
}

static void rec_b3_round(uint32_t state[16], const uint32_t m[16],
                         const uint8_t sched[16])
{
	rec_b3_g_mix(state, 0, 4, 8, 12, m[sched[0]], m[sched[1]]);
	rec_b3_g_mix(state, 1, 5, 9, 13, m[sched[2]], m[sched[3]]);
	rec_b3_g_mix(state, 2, 6, 10, 14, m[sched[4]], m[sched[5]]);
	rec_b3_g_mix(state, 3, 7, 11, 15, m[sched[6]], m[sched[7]]);
	rec_b3_g_mix(state, 0, 5, 10, 15, m[sched[8]], m[sched[9]]);
	rec_b3_g_mix(state, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
	rec_b3_g_mix(state, 2, 7, 8, 13, m[sched[12]], m[sched[13]]);
	rec_b3_g_mix(state, 3, 4, 9, 14, m[sched[14]], m[sched[15]]);
}

static void rec_b3_compress(const uint32_t cv[8], const uint32_t block[16],
                            uint64_t counter, uint32_t block_len,
                            uint32_t flags, uint32_t out[16])
{
	uint32_t state[16];
	size_t i;

	for (i = 0; i < 8U; i++) {
		state[i] = cv[i];
		state[i + 8U] = rec_blake3_iv[i];
	}
	state[12] = (uint32_t)counter;
	state[13] = (uint32_t)(counter >> 32);
	state[14] = block_len;
	state[15] = flags;

	for (i = 0; i < 7U; i++)
		rec_b3_round(state, block, rec_blake3_msg_schedule[i]);

	for (i = 0; i < 8U; i++) {
		out[i] = state[i] ^ state[i + 8U];
		out[i + 8U] = state[i + 8U] ^ cv[i];
	}
}

static void rec_b3_output_cv(const rec_blake3_output_t *out, uint32_t cv[8])
{
	uint32_t words[16];
	size_t i;

	rec_b3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags, words);
	for (i = 0; i < 8U; i++)
		cv[i] = words[i];
}

static void rec_b3_output_root(const rec_blake3_output_t *out,
                               uint8_t digest[32])
{
	uint32_t words[16];
	size_t i;

	rec_b3_compress(out->input_cv, out->block, out->counter, out->block_len,
	                out->flags | REC_B3_FLAG_ROOT, words);
	for (i = 0; i < 8U; i++)
		rec_store_le32(digest + i * 4U, words[i]);
}

static void rec_b3_chunk_output(const rec_blake3_ctx_t *ctx,
                                rec_blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		out->input_cv[i] = ctx->cv[i];
	rec_block_to_words(ctx->block, out->block);
	out->counter = ctx->chunk_counter;
	out->block_len = (uint32_t)ctx->block_len;
	out->flags = REC_B3_FLAG_CHUNK_END;
	if (ctx->blocks_compressed == 0)
		out->flags |= REC_B3_FLAG_CHUNK_START;
}

static void rec_b3_parent_output(const uint32_t left_cv[8],
                                 const uint32_t right_cv[8],
                                 rec_blake3_output_t *out)
{
	size_t i;

	for (i = 0; i < 8U; i++) {
		out->input_cv[i] = rec_blake3_iv[i];
		out->block[i] = left_cv[i];
		out->block[i + 8U] = right_cv[i];
	}
	out->counter = 0;
	out->block_len = REC_B3_BLOCK_LEN;
	out->flags = REC_B3_FLAG_PARENT;
}

static void rec_b3_push_chunk_cv(rec_blake3_ctx_t *ctx,
                                 const uint32_t chunk_cv[8],
                                 uint64_t total_chunks)
{
	uint32_t cv[8];
	size_t i;

	for (i = 0; i < 8U; i++)
		cv[i] = chunk_cv[i];
	while ((total_chunks & 1U) == 0U) {
		rec_blake3_output_t parent;
		uint32_t left_cv[8];
		uint32_t parent_cv[8];

		ctx->cv_stack_len--;
		for (i = 0; i < 8U; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		rec_b3_parent_output(left_cv, cv, &parent);
		rec_b3_output_cv(&parent, parent_cv);
		for (i = 0; i < 8U; i++)
			cv[i] = parent_cv[i];
		total_chunks >>= 1U;
	}
	for (i = 0; i < 8U; i++)
		ctx->cv_stack[ctx->cv_stack_len][i] = cv[i];
	ctx->cv_stack_len++;
}

static void rec_b3_reset_chunk(rec_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		ctx->cv[i] = ctx->key[i];
	ctx->block_len = 0;
	ctx->blocks_compressed = 0;
	memset(ctx->block, 0, sizeof(ctx->block));
}

static void rec_b3_finalize_chunk(rec_blake3_ctx_t *ctx)
{
	rec_blake3_output_t out;
	uint32_t cv[8];

	rec_b3_chunk_output(ctx, &out);
	rec_b3_output_cv(&out, cv);
	rec_b3_push_chunk_cv(ctx, cv, ctx->chunk_counter + 1U);
	ctx->chunk_counter++;
	rec_b3_reset_chunk(ctx);
}

static void rec_blake3_init(rec_blake3_ctx_t *ctx)
{
	size_t i;

	for (i = 0; i < 8U; i++)
		ctx->key[i] = rec_blake3_iv[i];
	ctx->chunk_counter = 0;
	ctx->cv_stack_len = 0;
	rec_b3_reset_chunk(ctx);
}

static void rec_blake3_update(rec_blake3_ctx_t *ctx, const uint8_t *data,
                              size_t len)
{
	while (len > 0U) {
		size_t n;

		if (rec_b3_chunk_len(ctx) == REC_B3_CHUNK_LEN) {
			rec_b3_finalize_chunk(ctx);
			continue;
		}
		if (ctx->block_len == REC_B3_BLOCK_LEN) {
			uint32_t block_words[16];
			uint32_t out_words[16];
			uint32_t flags;
			size_t i;

			flags = 0;
			if (ctx->blocks_compressed == 0)
				flags |= REC_B3_FLAG_CHUNK_START;
			rec_block_to_words(ctx->block, block_words);
			rec_b3_compress(ctx->cv, block_words,
			                ctx->chunk_counter, REC_B3_BLOCK_LEN,
			                flags, out_words);
			for (i = 0; i < 8U; i++)
				ctx->cv[i] = out_words[i];
			ctx->blocks_compressed++;
			ctx->block_len = 0;
			memset(ctx->block, 0, sizeof(ctx->block));
		}

		n = REC_B3_BLOCK_LEN - ctx->block_len;
		if (n > len)
			n = len;
		memcpy(ctx->block + ctx->block_len, data, n);
		ctx->block_len += n;
		data += n;
		len -= n;
	}
}

static void rec_blake3_final(rec_blake3_ctx_t *ctx, uint8_t digest[32])
{
	rec_blake3_output_t out;
	uint32_t cv[8];

	rec_b3_chunk_output(ctx, &out);
	rec_b3_output_cv(&out, cv);
	while (ctx->cv_stack_len > 0U) {
		uint32_t left_cv[8];
		size_t i;

		ctx->cv_stack_len--;
		for (i = 0; i < 8U; i++)
			left_cv[i] = ctx->cv_stack[ctx->cv_stack_len][i];
		rec_b3_parent_output(left_cv, cv, &out);
		rec_b3_output_cv(&out, cv);
	}
	rec_b3_output_root(&out, digest);
}

/* ----------------------------- Deflate decode ---------------------------- */

#define REC_DEFLATE_TABLE_BITS 15U
#define REC_DEFLATE_TABLE_SIZE (1U << REC_DEFLATE_TABLE_BITS)

typedef struct {
	const uint8_t *src;
	size_t len;
	size_t pos;
	uint64_t bits;
	unsigned int nbits;
} rec_bit_reader_t;

typedef struct {
	int16_t sym[REC_DEFLATE_TABLE_SIZE];
	uint8_t len[REC_DEFLATE_TABLE_SIZE];
} rec_huff_table_t;

static const uint16_t rec_len_base[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23,  27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};

static const uint8_t rec_len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

static const uint16_t rec_dist_base[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};

static const uint8_t rec_dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

static const uint8_t rec_cl_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

static uint16_t rec_bit_reverse(uint16_t v, unsigned int n)
{
	uint16_t out;
	unsigned int i;

	out = 0;
	for (i = 0; i < n; i++) {
		out <<= 1;
		out |= (uint16_t)(v & 1U);
		v >>= 1U;
	}
	return out;
}

static int rec_br_ensure_bits(rec_bit_reader_t *br, unsigned int n)
{
	while (br->nbits < n) {
		if (br->pos >= br->len)
			break;
		br->bits |= ((uint64_t)br->src[br->pos++]) << br->nbits;
		br->nbits += 8U;
	}
	return br->nbits >= n ? 0 : -1;
}

static int rec_br_get_bits(rec_bit_reader_t *br, unsigned int n, uint16_t *out)
{
	if (n == 0U) {
		*out = 0;
		return 0;
	}
	if (rec_br_ensure_bits(br, n) != 0)
		return -1;
	*out = (uint16_t)(br->bits & ((1U << n) - 1U));
	br->bits >>= n;
	br->nbits -= n;
	return 0;
}

/* Which RFC 1951 alphabet a decode table is built for (validation rules). */
enum {
	REC_TREE_CODELEN = 0,
	REC_TREE_LITLEN,
	REC_TREE_DIST,
};

/*
 * Build a direct decode table from canonical Huffman code lengths. The code
 * is validated as in ark's deflate.c and zlib: oversubscribed codes are
 * rejected; incomplete codes are rejected except a lit/len or distance code
 * with exactly one code of length 1, or a distance code with no codes. The
 * code-length code must be complete.
 */
static int rec_huff_build(rec_huff_table_t *tab, const uint8_t *lengths,
                          size_t n_symbols, unsigned int max_bits, int kind)
{
	uint16_t count[16];
	uint16_t next_code[16];
	unsigned int bits;
	uint16_t code;
	size_t codes;
	size_t i;
	long left;

	if (max_bits > REC_DEFLATE_TABLE_BITS)
		return -1;
	for (i = 0; i < REC_DEFLATE_TABLE_SIZE; i++) {
		tab->sym[i] = -1;
		tab->len[i] = 0;
	}
	memset(count, 0, sizeof(count));
	memset(next_code, 0, sizeof(next_code));

	codes = 0U;
	for (i = 0; i < n_symbols; i++) {
		if (lengths[i] > max_bits)
			return -1;
		if (lengths[i] != 0U) {
			count[lengths[i]]++;
			codes++;
		}
	}

	/* Kraft accounting: left counts unused codes of the current length. */
	left = 1;
	for (bits = 1U; bits <= max_bits; bits++) {
		left = left * 2 - (long)count[bits];
		if (left < 0)
			return -1;
	}
	if (left > 0) {
		if (kind == REC_TREE_CODELEN)
			return -1;
		if (!(codes == 1U && count[1] == 1U) &&
		    !(kind == REC_TREE_DIST && codes == 0U))
			return -1;
	}

	code = 0;
	for (bits = 1U; bits <= max_bits; bits++) {
		code = (uint16_t)((code + count[bits - 1U]) << 1U);
		next_code[bits] = code;
	}

	for (i = 0; i < n_symbols; i++) {
		uint8_t len;
		uint16_t rev;
		unsigned int fill_shift;
		unsigned int fill_count;
		unsigned int j;

		len = lengths[i];
		if (len == 0U)
			continue;
		rev = rec_bit_reverse(next_code[len], len);
		next_code[len]++;
		fill_shift = REC_DEFLATE_TABLE_BITS - len;
		fill_count = 1U << fill_shift;
		for (j = 0; j < fill_count; j++) {
			unsigned int idx;

			idx = ((unsigned int)rev) | (j << len);
			if (tab->len[idx] != 0U)
				return -1;
			tab->len[idx] = len;
			tab->sym[idx] = (int16_t)i;
		}
	}
	return 0;
}

static int rec_huff_decode(rec_bit_reader_t *br, const rec_huff_table_t *tab,
                           int *sym)
{
	uint16_t idx;
	uint8_t n;

	if (rec_br_ensure_bits(br, 1U) != 0)
		return -1;
	(void)rec_br_ensure_bits(br, REC_DEFLATE_TABLE_BITS);
	idx = (uint16_t)(br->bits & (REC_DEFLATE_TABLE_SIZE - 1U));
	n = tab->len[idx];
	if (n == 0U)
		return -1;
	if (rec_br_ensure_bits(br, n) != 0)
		return -1;
	*sym = tab->sym[idx];
	br->bits >>= n;
	br->nbits -= n;
	return *sym >= 0 ? 0 : -1;
}

static int rec_decode_huffman_block(rec_bit_reader_t *br,
                                    const rec_huff_table_t *lit_tab,
                                    const rec_huff_table_t *dist_tab,
                                    uint8_t *dst, size_t dst_cap,
                                    size_t *dst_pos)
{
	int sym;
	size_t i;

	for (;;) {
		if (rec_huff_decode(br, lit_tab, &sym) != 0)
			return -1;
		if (sym < 256) {
			if (*dst_pos >= dst_cap)
				return -1;
			dst[(*dst_pos)++] = (uint8_t)sym;
			continue;
		}
		if (sym == 256)
			return 0;
		if (sym > 285)
			return -1;
		{
			unsigned int li;
			size_t len;
			size_t dist;
			uint16_t extra;
			int dsym;

			li = (unsigned int)(sym - 257);
			len = rec_len_base[li];
			if (rec_len_extra[li] != 0U) {
				if (rec_br_get_bits(br, rec_len_extra[li],
				                    &extra) != 0)
					return -1;
				len += extra;
			}
			/* RFC 1951: 258 is code 285 only, never 284 + 31. */
			if (sym == 284 && len == 258U)
				return -1;
			if (rec_huff_decode(br, dist_tab, &dsym) != 0)
				return -1;
			if (dsym < 0 || dsym > 29)
				return -1;
			dist = rec_dist_base[dsym];
			if (rec_dist_extra[dsym] != 0U) {
				if (rec_br_get_bits(br, rec_dist_extra[dsym],
				                    &extra) != 0)
					return -1;
				dist += extra;
			}
			if (dist == 0U || dist > *dst_pos)
				return -1;
			if (*dst_pos + len > dst_cap)
				return -1;
			for (i = 0; i < len; i++)
				dst[*dst_pos + i] = dst[*dst_pos + i - dist];
			*dst_pos += len;
		}
	}
}

static int rec_decode_fixed_block(rec_bit_reader_t *br, uint8_t *dst,
                                  size_t dst_cap, size_t *dst_pos)
{
	rec_huff_table_t lit_tab;
	rec_huff_table_t dist_tab;
	uint8_t lit_len[288];
	uint8_t dist_len[32];
	size_t i;

	for (i = 0; i <= 143U; i++)
		lit_len[i] = 8U;
	for (; i <= 255U; i++)
		lit_len[i] = 9U;
	for (; i <= 279U; i++)
		lit_len[i] = 7U;
	for (; i <= 287U; i++)
		lit_len[i] = 8U;
	for (i = 0; i < 32U; i++)
		dist_len[i] = 5U;

	if (rec_huff_build(&lit_tab, lit_len, 288U, 9U, REC_TREE_LITLEN) != 0)
		return -1;
	if (rec_huff_build(&dist_tab, dist_len, 32U, 5U, REC_TREE_DIST) != 0)
		return -1;
	return rec_decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
	                                dst_pos);
}

static int rec_decode_dynamic_block(rec_bit_reader_t *br, uint8_t *dst,
                                    size_t dst_cap, size_t *dst_pos)
{
	rec_huff_table_t cl_tab;
	rec_huff_table_t lit_tab;
	rec_huff_table_t dist_tab;
	uint8_t cl_len[19];
	uint8_t lit_len[288];
	uint8_t dist_len[32];
	uint8_t lens[288 + 32];
	uint16_t v;
	size_t hlit, hdist, hclen, n, i;

	memset(cl_len, 0, sizeof(cl_len));
	memset(lit_len, 0, sizeof(lit_len));
	memset(dist_len, 0, sizeof(dist_len));

	if (rec_br_get_bits(br, 5U, &v) != 0)
		return -1;
	hlit = (size_t)v + 257U;
	if (rec_br_get_bits(br, 5U, &v) != 0)
		return -1;
	hdist = (size_t)v + 1U;
	if (rec_br_get_bits(br, 4U, &v) != 0)
		return -1;
	hclen = (size_t)v + 4U;
	if (hlit > 286U || hdist > 32U)
		return -1;

	for (i = 0; i < hclen; i++) {
		if (rec_br_get_bits(br, 3U, &v) != 0)
			return -1;
		cl_len[rec_cl_order[i]] = (uint8_t)v;
	}
	if (rec_huff_build(&cl_tab, cl_len, 19U, 7U, REC_TREE_CODELEN) != 0)
		return -1;

	n = 0U;
	while (n < hlit + hdist) {
		int sym;

		if (rec_huff_decode(br, &cl_tab, &sym) != 0)
			return -1;
		if (sym >= 0 && sym <= 15) {
			lens[n++] = (uint8_t)sym;
			continue;
		}
		if (sym == 16) {
			size_t rep;
			uint8_t prev;

			if (n == 0U)
				return -1;
			if (rec_br_get_bits(br, 2U, &v) != 0)
				return -1;
			rep = (size_t)v + 3U;
			if (n + rep > hlit + hdist)
				return -1;
			prev = lens[n - 1U];
			for (i = 0; i < rep; i++)
				lens[n++] = prev;
			continue;
		}
		if (sym == 17) {
			size_t rep;

			if (rec_br_get_bits(br, 3U, &v) != 0)
				return -1;
			rep = (size_t)v + 3U;
			if (n + rep > hlit + hdist)
				return -1;
			for (i = 0; i < rep; i++)
				lens[n++] = 0U;
			continue;
		}
		if (sym == 18) {
			size_t rep;

			if (rec_br_get_bits(br, 7U, &v) != 0)
				return -1;
			rep = (size_t)v + 11U;
			if (n + rep > hlit + hdist)
				return -1;
			for (i = 0; i < rep; i++)
				lens[n++] = 0U;
			continue;
		}
		return -1;
	}

	for (i = 0; i < hlit; i++)
		lit_len[i] = lens[i];
	for (i = 0; i < hdist; i++)
		dist_len[i] = lens[hlit + i];
	/* RFC 1951 section 3.2.7: every block must be able to end. */
	if (lit_len[256] == 0U)
		return -1;
	if (rec_huff_build(&lit_tab, lit_len, 288U, 15U, REC_TREE_LITLEN) != 0)
		return -1;
	if (rec_huff_build(&dist_tab, dist_len, 32U, 15U, REC_TREE_DIST) != 0)
		return -1;

	return rec_decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
	                                dst_pos);
}

static int rec_decode_stored_block(rec_bit_reader_t *br, uint8_t *dst,
                                   size_t dst_cap, size_t *dst_pos)
{
	uint16_t len, nlen;
	size_t i;

	if ((br->nbits & 7U) != 0U) {
		unsigned int drop;

		drop = br->nbits & 7U;
		br->bits >>= drop;
		br->nbits -= drop;
	}
	if (rec_br_get_bits(br, 16U, &len) != 0)
		return -1;
	if (rec_br_get_bits(br, 16U, &nlen) != 0)
		return -1;
	if (((uint16_t)~len) != nlen)
		return -1;
	if (*dst_pos + len > dst_cap)
		return -1;
	if (br->pos + len > br->len)
		return -1;
	for (i = 0; i < len; i++)
		dst[(*dst_pos)++] = br->src[br->pos++];
	return 0;
}

static ssize_t rec_deflate_decompress(const uint8_t *src, size_t src_len,
                                      uint8_t *dst, size_t dst_cap)
{
	rec_bit_reader_t br;
	size_t out_pos;

	if (src == NULL && src_len != 0U)
		return -1;
	if (dst == NULL && dst_cap != 0U)
		return -1;

	br.src = src;
	br.len = src_len;
	br.pos = 0;
	br.bits = 0;
	br.nbits = 0;
	out_pos = 0U;

	for (;;) {
		uint16_t bfinal;
		uint16_t btype;

		if (rec_br_get_bits(&br, 1U, &bfinal) != 0)
			return -1;
		if (rec_br_get_bits(&br, 2U, &btype) != 0)
			return -1;
		if (btype == 0U) {
			if (rec_decode_stored_block(&br, dst, dst_cap,
			                            &out_pos) != 0)
				return -1;
		} else if (btype == 1U) {
			if (rec_decode_fixed_block(&br, dst, dst_cap,
			                           &out_pos) != 0)
				return -1;
		} else if (btype == 2U) {
			if (rec_decode_dynamic_block(&br, dst, dst_cap,
			                             &out_pos) != 0)
				return -1;
		} else {
			return -1;
		}
		if (bfinal != 0U)
			break;
	}
	/*
	 * A chunk is exactly one Deflate stream: bytes after the final block
	 * are rejected, as ark does. The bit reader loads whole bytes, so
	 * nbits / 8 of them were read ahead and not used.
	 */
	if (br.pos - br.nbits / 8U != src_len)
		return -1;
	return (ssize_t)out_pos;
}

/* ---------------------------- Recovery helpers --------------------------- */

static void member_free(rec_member_t *m)
{
	free(m->path);
	free(m->link);
	free(m->chunk_sizes);
	m->path = NULL;
	m->link = NULL;
	m->chunk_sizes = NULL;
}

static void members_free(rec_member_t *members, uint32_t count)
{
	uint32_t i;

	if (members == NULL)
		return;
	for (i = 0U; i < count; i++)
		member_free(&members[i]);
	free(members);
}

/* -------------------------- Index validation ---------------------------- */

/*
 * The checks below are those of ark's own reader (ark_read_index and the
 * footer checks before it), in the same order, so the reader accepts exactly
 * the archives ark accepts. Each check returns NULL when it passes, or a
 * short reason. All of them finish before the first filesystem change.
 * ARCHITECTURE.md section 8.3 numbers them 1-16.
 */

static int utf8_valid(const uint8_t *s, size_t len)
{
	size_t i;

	i = 0U;
	while (i < len) {
		uint8_t c;
		uint8_t lo;
		uint8_t hi;
		size_t n;
		size_t k;

		c = s[i++];
		if (c <= 0x7fU)
			continue;
		/* Lead byte: continuation count and range of the first one. */
		lo = 0x80U;
		hi = 0xbfU;
		if (c >= 0xc2U && c <= 0xdfU) {
			n = 1U;
		} else if (c >= 0xe0U && c <= 0xefU) {
			n = 2U;
			if (c == 0xe0U)
				lo = 0xa0U;
			else if (c == 0xedU)
				hi = 0x9fU;
		} else if (c >= 0xf0U && c <= 0xf4U) {
			n = 3U;
			if (c == 0xf0U)
				lo = 0x90U;
			else if (c == 0xf4U)
				hi = 0x8fU;
		} else {
			return 0;
		}
		if (len - i < n)
			return 0;
		if (s[i] < lo || s[i] > hi)
			return 0;
		for (k = 1U; k < n; k++) {
			if ((s[i + k] & 0xc0U) != 0x80U)
				return 0;
		}
		i += n;
	}
	return 1;
}

/* Check 3: no empty component, no "..", and no "." when reject_dot. */
static const char *check_components(const uint8_t *raw, size_t len,
                                    int reject_dot)
{
	size_t i;
	size_t start;

	start = 0U;
	for (i = 0U; i <= len; i++) {
		size_t clen;

		if (i != len && raw[i] != '/')
			continue;
		clen = i - start;
		if (clen == 0U && reject_dot)
			return "empty path component";
		if (reject_dot && clen == 1U && raw[start] == '.')
			return "dot path component";
		if (clen == 2U && raw[start] == '.' && raw[start + 1U] == '.')
			return "dotdot path component";
		start = i + 1U;
	}
	return NULL;
}

/* Checks 3-5: a member path (also a hardlink target) as stored. */
static const char *check_member_path(const uint8_t *raw, size_t len)
{
	if (len == 0U)
		return "empty path";
	if (len > REC_MAX_PATH)
		return "path exceeds 1023 bytes";
#ifdef PATH_MAX
	if (len >= (size_t)PATH_MAX)
		return "path exceeds local PATH_MAX";
#endif
	if (raw[0] == '/')
		return "absolute path";
	if (raw[len - 1U] == '/')
		return "trailing slash in path";
	if (memchr(raw, '\0', len) != NULL)
		return "NUL byte in path";
	if (!utf8_valid(raw, len))
		return "invalid UTF-8 in path";
	return check_components(raw, len, 1);
}

/*
 * Check 6: a symlink target. Unlike member paths, "." and empty components
 * are valid targets ("." names the link's own directory); only "..", an
 * absolute target, NUL and invalid UTF-8 are refused.
 */
static const char *check_symlink_target(const uint8_t *raw, size_t len)
{
	if (raw[0] == '/')
		return "absolute symlink target";
	if (memchr(raw, '\0', len) != NULL)
		return "NUL byte in symlink target";
	if (!utf8_valid(raw, len))
		return "invalid UTF-8 in symlink target";
	return check_components(raw, len, 0);
}

static char *copy_field(const uint8_t *raw, size_t len)
{
	char *s;

	/* OWNERSHIP: caller frees the copy (member_free). */
	s = (char *)malloc(len + 1U);
	if (s == NULL)
		return NULL;
	memcpy(s, raw, len);
	s[len] = '\0';
	return s;
}

/*
 * Parse member_count entries (ARCHITECTURE.md section 5.2) and apply every
 * check that needs one entry only: the member type, checks 3-6, the size
 * fields of zero-data members, the chunk count, check 11 and check 12.
 */
static const char *parse_members(const uint8_t *index, size_t index_size,
                                 uint32_t member_count, uint64_t index_offset,
                                 rec_member_t **out_members)
{
	rec_member_t *members;
	const char *why;
	size_t off;
	uint32_t i;

	/* Every entry takes at least 84 bytes (79 fixed, path, chunk count). */
	if (member_count > index_size / 84U)
		return "member count exceeds the index size";
	/* OWNERSHIP: caller owns members array and nested allocations. */
	members = (rec_member_t *)calloc(member_count == 0U ? 1U : member_count,
	                                 sizeof(*members));
	if (members == NULL)
		return "out of memory";
	off = 0U;
	why = "truncated or malformed index entry";

	for (i = 0U; i < member_count; i++) {
		rec_member_t *m;
		size_t path_len;
		uint64_t sum;
		uint32_t j;

		m = &members[i];
		if (index_size - off < 79U)
			goto fail;
		m->type = index[off + 0U];
		if (m->type < REC_TYPE_FILE || m->type > REC_TYPE_HARDLINK) {
			why = "unknown member type";
			goto fail;
		}
		m->mode = le32(index + off + 1U);
		m->uid = le32(index + off + 5U);
		m->gid = le32(index + off + 9U);
		m->mtime = le64(index + off + 13U);
		m->size_original = le64(index + off + 21U);
		m->size_compressed = le64(index + off + 29U);
		m->data_offset = le64(index + off + 37U);
		memcpy(m->hash, index + off + 45U, REC_HASH_LEN);
		path_len = le16(index + off + 77U);
		off += 79U;

		if (path_len == 0U || index_size - off < path_len)
			goto fail;
		if ((why = check_member_path(index + off, path_len)) != NULL)
			goto fail;
		why = "truncated or malformed index entry";
		m->path = copy_field(index + off, path_len);
		if (m->path == NULL) {
			why = "out of memory";
			goto fail;
		}
		off += path_len;

		if (m->type == REC_TYPE_SYMLINK ||
		    m->type == REC_TYPE_HARDLINK) {
			size_t link_len;

			if (index_size - off < 2U)
				goto fail;
			link_len = le16(index + off);
			off += 2U;
			if (link_len == 0U || link_len > REC_MAX_PATH ||
			    index_size - off < link_len)
				goto fail;
			if (m->type == REC_TYPE_SYMLINK)
				why =
				    check_symlink_target(index + off, link_len);
			else
				why = check_member_path(index + off, link_len);
			if (why != NULL)
				goto fail;
			why = "truncated or malformed index entry";
			m->link = copy_field(index + off, link_len);
			if (m->link == NULL) {
				why = "out of memory";
				goto fail;
			}
			off += link_len;
		}

		if (index_size - off < 4U)
			goto fail;
		m->chunk_count = le32(index + off);
		off += 4U;

		if (m->type != REC_TYPE_FILE || m->size_original == 0U) {
			/* Zero-data members have no body and no chunks. */
			if ((m->type != REC_TYPE_FILE &&
			     m->size_original != 0U) ||
			    m->size_compressed != 0U || m->data_offset != 0U ||
			    m->chunk_count != 0U) {
				why = "size fields of a member without data";
				goto fail;
			}
		} else if ((m->size_original - 1U) / REC_CHUNK_SIZE + 1U !=
		           m->chunk_count) {
			why = "chunk count does not match the size";
			goto fail;
		}

		if ((index_size - off) / 4U < m->chunk_count)
			goto fail;
		if (m->chunk_count > 0U) {
			m->chunk_sizes = (uint32_t *)calloc(m->chunk_count,
			                                    sizeof(uint32_t));
			if (m->chunk_sizes == NULL) {
				why = "out of memory";
				goto fail;
			}
		}
		/* A u32 count of u32 sizes cannot overflow the u64 sum. */
		sum = 0U;
		for (j = 0U; j < m->chunk_count; j++) {
			m->chunk_sizes[j] = le32(index + off + (size_t)j * 4U);
			sum += m->chunk_sizes[j];
		}
		off += (size_t)m->chunk_count * 4U;

		if (m->chunk_count > 0U) {
			/* Checks 11 and 12, overflow-checked. */
			if (sum != m->size_compressed) {
				why = "chunk sizes do not add up";
				goto fail;
			}
			if (m->data_offset < REC_HEADER_SIZE ||
			    m->data_offset > index_offset ||
			    m->size_compressed >
			        index_offset - m->data_offset) {
				why = "member data outside the body";
				goto fail;
			}
		}
	}
	if (off != index_size)
		goto fail;

	*out_members = members;
	return NULL;

fail:
	members_free(members, member_count);
	return why;
}

/* One member path and its index position, sorted by (path, position). */
typedef struct {
	const char *path;
	uint32_t idx;
} rec_path_ref_t;

static int path_ref_cmp(const void *a, const void *b)
{
	const rec_path_ref_t *x;
	const rec_path_ref_t *y;
	int c;

	x = (const rec_path_ref_t *)a;
	y = (const rec_path_ref_t *)b;
	c = strcmp(x->path, y->path);
	if (c != 0)
		return c;
	return x->idx < y->idx ? -1 : x->idx > y->idx ? 1 : 0;
}

/*
 * Smallest index of a member whose path equals key[0..key_len) (the key
 * need not end in NUL, so ancestor prefixes are looked up in place), or -1.
 */
static int64_t path_find(const rec_path_ref_t *refs, uint32_t n,
                         const char *key, size_t key_len)
{
	uint32_t lo;
	uint32_t hi;

	lo = 0U;
	hi = n;
	while (lo < hi) {
		uint32_t mid;
		int c;

		mid = lo + (hi - lo) / 2U;
		c = strncmp(refs[mid].path, key, key_len);
		if (c == 0 && refs[mid].path[key_len] != '\0')
			c = 1;
		if (c < 0)
			lo = mid + 1U;
		else
			hi = mid;
	}
	if (lo < n && strncmp(refs[lo].path, key, key_len) == 0 &&
	    refs[lo].path[key_len] == '\0')
		return (int64_t)refs[lo].idx;
	return -1;
}

/* One member body [start, end) in the archive. */
typedef struct {
	uint64_t start;
	uint64_t end;
} rec_range_t;

/* Start ascending, then end descending, so equal starts count as overlap. */
static int range_cmp(const void *a, const void *b)
{
	const rec_range_t *x;
	const rec_range_t *y;

	x = (const rec_range_t *)a;
	y = (const rec_range_t *)b;
	if (x->start != y->start)
		return x->start < y->start ? -1 : 1;
	if (x->end != y->end)
		return x->end > y->end ? -1 : 1;
	return 0;
}

/*
 * The checks across entries: 7 (hardlink target earlier), 8 (no duplicate
 * path), 9 (every parent is an earlier directory member), 13 (no overlap),
 * 14 (hardlinks name regular files), 15 (bodies fill the archive from byte
 * 16 to the index without gaps) and 16 (zero-data members carry the
 * empty-input hash). Check 10 concerns ark's selective extraction; check 9
 * implies it for the reader, which always extracts everything.
 */
static const char *check_members(const rec_member_t *members, uint32_t count,
                                 uint64_t index_offset,
                                 const uint8_t empty_digest[REC_HASH_LEN])
{
	rec_path_ref_t *refs;
	rec_range_t *ranges;
	const char *why;
	uint32_t nranges;
	uint32_t i;

	/* OWNERSHIP: both arrays are freed before return. */
	refs =
	    (rec_path_ref_t *)calloc(count == 0U ? 1U : count, sizeof(*refs));
	ranges =
	    (rec_range_t *)calloc(count == 0U ? 1U : count, sizeof(*ranges));
	if (refs == NULL || ranges == NULL) {
		why = "out of memory";
		goto out;
	}
	nranges = 0U;
	for (i = 0U; i < count; i++) {
		refs[i].path = members[i].path;
		refs[i].idx = i;
		if (members[i].chunk_count > 0U) {
			ranges[nranges].start = members[i].data_offset;
			ranges[nranges].end =
			    members[i].data_offset + members[i].size_compressed;
			nranges++;
		}
	}
	qsort(refs, count, sizeof(*refs), path_ref_cmp);
	qsort(ranges, nranges, sizeof(*ranges), range_cmp);

	for (i = 1U; i < count; i++) {
		if (strcmp(refs[i - 1U].path, refs[i].path) == 0) {
			why = "duplicate member path";
			goto out;
		}
	}
	for (i = 0U; i < count; i++) {
		const rec_member_t *m;
		const char *slash;

		m = &members[i];
		if (m->type == REC_TYPE_HARDLINK) {
			int64_t t;

			t = path_find(refs, count, m->link, strlen(m->link));
			if (t < 0 || (uint64_t)t >= i) {
				why = "hardlink target missing or later";
				goto out;
			}
			if (members[t].type != REC_TYPE_FILE) {
				why = "hardlink target is not a regular file";
				goto out;
			}
		}
		for (slash = strchr(m->path, '/'); slash != NULL;
		     slash = strchr(slash + 1, '/')) {
			int64_t p;

			p = path_find(refs, count, m->path,
			              (size_t)(slash - m->path));
			if (p < 0 || (uint64_t)p >= i ||
			    members[p].type != REC_TYPE_DIR) {
				why = "parent is not an earlier directory "
				      "member";
				goto out;
			}
		}
	}
	why = "member bodies overlap or leave gaps";
	if (nranges == 0U) {
		if (index_offset != REC_HEADER_SIZE)
			goto out;
	} else {
		if (ranges[0].start != REC_HEADER_SIZE ||
		    ranges[nranges - 1U].end != index_offset)
			goto out;
		for (i = 1U; i < nranges; i++) {
			if (ranges[i].start != ranges[i - 1U].end)
				goto out;
		}
	}
	for (i = 0U; i < count; i++) {
		if (members[i].chunk_count == 0U &&
		    memcmp(members[i].hash, empty_digest, REC_HASH_LEN) != 0) {
			why = "member without data has a non-empty hash";
			goto out;
		}
	}
	why = NULL;

out:
	free(refs);
	free(ranges);
	return why;
}

/* ------------------------------ Extraction ------------------------------ */

/*
 * Open the directory that holds path's last component, walking from root_fd
 * one component at a time with O_DIRECTORY | O_NOFOLLOW: a parent that is a
 * symlink or not a directory fails instead of being followed, so nothing is
 * created outside the extraction directory. Every parent is an earlier
 * directory member (check 9), so it already exists. path must have passed
 * check_member_path(). Returns a new fd that the caller closes, or -1;
 * *leaf points into path at the last component. ARCHITECTURE.md 15.2.
 */
static int open_parent_dir(int root_fd, const char *path, const char **leaf)
{
	char comp[REC_MAX_PATH + 1U];
	const char *start;
	const char *slash;
	int fd;

	fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1)
		return -1;
	start = path;
	while ((slash = strchr(start, '/')) != NULL) {
		size_t len;
		int next;

		len = (size_t)(slash - start);
		memcpy(comp, start, len);
		comp[len] = '\0';
		next = openat(fd, comp,
		              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		(void)close(fd);
		if (next == -1)
			return -1;
		fd = next;
		start = slash + 1;
	}
	*leaf = start;
	return fd;
}

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

static void hash_init(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                      rec_blake3_ctx_t *bctx)
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_init(sctx);
	else
		rec_blake3_init(bctx);
}

static void hash_update(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                        rec_blake3_ctx_t *bctx, const uint8_t *data, size_t len)
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_update(sctx, data, len);
	else
		rec_blake3_update(bctx, data, len);
}

static void hash_final(uint8_t hash_alg, rec_sha256_ctx_t *sctx,
                       rec_blake3_ctx_t *bctx, uint8_t out[REC_HASH_LEN])
{
	if (hash_alg == REC_HASH_SHA256)
		rec_sha256_final(sctx, out);
	else
		rec_blake3_final(bctx, out);
}

static void compute_empty_digest(uint8_t hash_alg, uint8_t out[REC_HASH_LEN])
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;

	hash_init(hash_alg, &sctx, &bctx);
	hash_final(hash_alg, &sctx, &bctx, out);
}

/*
 * Read exactly len bytes at offset off of fd (pread, retried on EINTR and
 * short reads). Fails on an offset off_t cannot hold and on end of file.
 */
static int read_full_at(int fd, uint8_t *buf, size_t len, uint64_t off)
{
	uint64_t off_max;

	/* Largest off_t: 2^(bits - 1) - 1 (off_t is a signed integer type). */
	off_max = ((uint64_t)1 << (sizeof(off_t) * 8U - 1U)) - 1U;
	if (off > off_max || (uint64_t)len > off_max - off)
		return -1;
	while (len > 0U) {
		ssize_t n;

		n = pread(fd, buf, len, (off_t)off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
		off += (uint64_t)n;
	}
	return 0;
}

static int parse_header(const uint8_t file[REC_HEADER_SIZE], uint8_t *hash_alg)
{
	if (file[0] != 'a' || file[1] != 'r' || file[2] != 'k' ||
	    file[3] != '!' || file[4] != '\n')
		return -1;
	if (file[5] != 0x01U)
		return -1;
	if (file[7] != 0x00U)
		return -1;
	if (file[8] != 0x01U)
		return -1;
	if (file[9] != REC_HASH_BLAKE3 && file[9] != REC_HASH_SHA256)
		return -1;
	if (file[10] != 0U || file[11] != 0U || file[12] != 0U ||
	    file[13] != 0U || file[14] != 0U || file[15] != 0U)
		return -1;
	*hash_alg = file[9];
	return 0;
}

/* Check 1 and the first part of check 15: the index ends at the footer. */
static int parse_footer(const uint8_t f[REC_FOOTER_SIZE], uint64_t file_size,
                        uint64_t *index_offset, uint64_t *index_size,
                        uint32_t *member_count, const uint8_t **index_hash)
{
	if (le32(f + 52U) != 0x4b52410aU)
		return -1;
	if (f[56] != 0U || f[57] != 0U || f[58] != 0U || f[59] != 0U ||
	    f[60] != 0U || f[61] != 0U || f[62] != 0U || f[63] != 0U)
		return -1;

	*index_offset = le64(f + 0U);
	*index_size = le64(f + 8U);
	*member_count = le32(f + 48U);
	*index_hash = f + 16U;

	if (*index_offset < REC_HEADER_SIZE)
		return -1;
	if (*index_offset > file_size - REC_FOOTER_SIZE)
		return -1;
	if (UINT64_MAX - *index_offset < *index_size)
		return -1;
	if (*index_offset + *index_size != file_size - REC_FOOTER_SIZE)
		return -1;
	return 0;
}

/* Check 2: the index hash, before any entry is parsed. */
static int verify_index_hash(uint8_t hash_alg, const uint8_t *index,
                             size_t index_size,
                             const uint8_t expected[REC_HASH_LEN])
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;
	uint8_t digest[REC_HASH_LEN];

	hash_init(hash_alg, &sctx, &bctx);
	hash_update(hash_alg, &sctx, &bctx, index, index_size);
	hash_final(hash_alg, &sctx, &bctx, digest);
	return memcmp(digest, expected, REC_HASH_LEN) == 0 ? 0 : -1;
}

/*
 * Stored mtime (nanoseconds since the epoch) as the futimens/utimensat pair;
 * the access time is left alone, as ark does.
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
 * Restore owner (root only), mode and mtime on an open file or directory,
 * as ark does: chown before chmod, so a chown cannot clear the restored
 * mode bits; the mode is masked to 0777. Returns -1 when chmod or the time
 * fails; an ownership change refused with EPERM is only a warning.
 * ARCHITECTURE.md section 14.5.
 */
static int restore_meta(int fd, const rec_member_t *m)
{
	struct timespec times[2];

	if (geteuid() == 0 && fchown(fd, (uid_t)m->uid, (gid_t)m->gid) != 0) {
		if (errno != EPERM)
			return -1;
		fprintf(stderr, "recover: %s: ownership not restored\n",
		        m->path);
	}
	if (fchmod(fd, (mode_t)(m->mode & 0777U)) != 0)
		return -1;
	decode_mtime(m->mtime, times);
	return futimens(fd, times);
}

/*
 * Buffers for one compressed chunk and its decompressed output; the reader
 * holds no more of the archive body than this at a time.
 */
typedef struct {
	uint8_t *comp;
	uint8_t *out;
} rec_bufs_t;

/*
 * Write the data of regular member m (size_original > 0) to fd, reading its
 * chunks from the archive one at a time, and check its hash.
 */
static int write_regular(int archive_fd, uint8_t hash_alg,
                         const rec_member_t *m, int fd, const rec_bufs_t *bufs)
{
	rec_sha256_ctx_t sctx;
	rec_blake3_ctx_t bctx;
	uint8_t digest[REC_HASH_LEN];
	uint64_t chunk_off;
	uint32_t i;

	hash_init(hash_alg, &sctx, &bctx);
	/* Checks 11 and 12 keep every chunk inside the archive body. */
	chunk_off = m->data_offset;
	for (i = 0U; i < m->chunk_count; i++) {
		uint32_t csz;
		ssize_t out_len;
		size_t expected;

		csz = m->chunk_sizes[i];
		if (csz == 0U || csz > REC_MAX_COMP_CHUNK)
			return -1;
		if (read_full_at(archive_fd, bufs->comp, csz, chunk_off) != 0)
			return -1;

		/* Hash verification is over compressed bytes as stored on disk.
		 */
		hash_update(hash_alg, &sctx, &bctx, bufs->comp, csz);
		out_len = rec_deflate_decompress(bufs->comp, csz, bufs->out,
		                                 REC_CHUNK_SIZE);
		if (out_len < 0)
			return -1;

		if (i + 1U < m->chunk_count)
			expected = REC_CHUNK_SIZE;
		else {
			expected = (size_t)(m->size_original % REC_CHUNK_SIZE);
			if (expected == 0U)
				expected = REC_CHUNK_SIZE;
		}
		if ((size_t)out_len != expected)
			return -1;
		if (write_full_fd(fd, bufs->out, (size_t)out_len) != 0)
			return -1;
		chunk_off += csz;
	}

	hash_final(hash_alg, &sctx, &bctx, digest);
	return memcmp(digest, m->hash, REC_HASH_LEN) == 0 ? 0 : -1;
}

/*
 * Create regular member m as leaf in parent_fd. O_EXCL refuses any existing
 * object, a symlink included, so nothing is written through a link and the
 * reader only ever removes a file it created itself: when the data, the
 * hash or the metadata fail, the file is removed again.
 */
static int extract_regular(int archive_fd, uint8_t hash_alg,
                           const rec_member_t *m, int parent_fd,
                           const char *leaf, const rec_bufs_t *bufs)
{
	int fd;
	int rc;

	/*
	 * SAFETY: O_EXCL | O_NOFOLLOW: an object already at the member path,
	 * a symlink in particular, fails the open instead of being written
	 * through. See ARCHITECTURE.md sections 14.2 and 15.2.
	 */
	fd = openat(parent_fd, leaf,
	            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd == -1)
		return -1;
	rc = 0;
	if (m->chunk_count > 0U)
		rc = write_regular(archive_fd, hash_alg, m, fd, bufs);
	if (rc == 0)
		rc = restore_meta(fd, m);
	if (close(fd) != 0)
		rc = -1;
	if (rc != 0)
		(void)unlinkat(parent_fd, leaf, 0);
	return rc;
}

/*
 * Create member m below root_fd, relative to its parent directory. An
 * existing directory is reused for a directory member, as ark does; any
 * other existing object fails the member (mkdirat, symlinkat, linkat and
 * O_EXCL refuse it). A hardlink's target is resolved the same way.
 * Directory metadata is restored at the end (restore_dirs).
 */
static int extract_member(int archive_fd, uint8_t hash_alg,
                          const rec_member_t *m, int root_fd,
                          const rec_bufs_t *bufs)
{
	struct timespec times[2];
	struct stat st;
	const char *leaf;
	const char *target_leaf;
	int parent_fd;
	int target_fd;
	int rc;

	parent_fd = open_parent_dir(root_fd, m->path, &leaf);
	if (parent_fd == -1)
		return -1;
	rc = -1;
	switch (m->type) {
	case REC_TYPE_DIR:
		if (mkdirat(parent_fd, leaf, 0700) == 0 ||
		    (errno == EEXIST &&
		     fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
		     S_ISDIR(st.st_mode)))
			rc = 0;
		break;
	case REC_TYPE_SYMLINK:
		if (symlinkat(m->link, parent_fd, leaf) != 0)
			break;
		rc = 0;
		/* Best effort, as in ark: the link itself, never its target. */
		decode_mtime(m->mtime, times);
		if ((geteuid() == 0 &&
		     fchownat(parent_fd, leaf, (uid_t)m->uid, (gid_t)m->gid,
		              AT_SYMLINK_NOFOLLOW) != 0) ||
		    utimensat(parent_fd, leaf, times, AT_SYMLINK_NOFOLLOW) != 0)
			fprintf(stderr, "recover: %s: metadata not restored\n",
			        m->path);
		break;
	case REC_TYPE_HARDLINK:
		target_fd = open_parent_dir(root_fd, m->link, &target_leaf);
		if (target_fd == -1)
			break;
		if (linkat(target_fd, target_leaf, parent_fd, leaf, 0) == 0)
			rc = 0;
		(void)close(target_fd);
		break;
	default:
		rc = extract_regular(archive_fd, hash_alg, m, parent_fd, leaf,
		                     bufs);
		break;
	}
	(void)close(parent_fd);
	return rc;
}

/*
 * Restore directory metadata after all members exist, in reverse index
 * order: children come after their parents in the index, so a directory's
 * mtime is set after its last entry was created, and a read-only directory
 * no longer needs to be entered. Failures are warnings, as in ark.
 */
static void restore_dirs(const rec_member_t *members, uint32_t count,
                         int root_fd)
{
	uint32_t i;

	for (i = count; i > 0U; i--) {
		const rec_member_t *m;
		const char *leaf;
		int parent_fd;
		int fd;

		m = &members[i - 1U];
		if (m->type != REC_TYPE_DIR)
			continue;
		fd = -1;
		parent_fd = open_parent_dir(root_fd, m->path, &leaf);
		if (parent_fd != -1) {
			fd = openat(parent_fd, leaf,
			            O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
			                O_CLOEXEC);
			(void)close(parent_fd);
		}
		if (fd == -1 || restore_meta(fd, m) != 0)
			fprintf(stderr, "recover: %s: metadata not restored\n",
			        m->path);
		if (fd != -1)
			(void)close(fd);
	}
}

static int extract_members(int archive_fd, uint8_t hash_alg,
                           const rec_member_t *members, uint32_t member_count)
{
	rec_bufs_t bufs;
	uint32_t i;
	int root_fd;
	int rc;

	/* The extraction directory is the current one, held as an fd. */
	root_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root_fd == -1) {
		perror("recover: cannot open the current directory");
		return -1;
	}
	/* OWNERSHIP: both buffers are freed before return. */
	bufs.comp = (uint8_t *)malloc(REC_MAX_COMP_CHUNK);
	bufs.out = (uint8_t *)malloc(REC_CHUNK_SIZE);
	rc = -1;
	if (bufs.comp == NULL || bufs.out == NULL) {
		fprintf(stderr, "recover: out of memory\n");
		goto out;
	}

	/*
	 * The first failing member stops the recovery. Members already
	 * extracted were fully verified and stay; the failing one is removed
	 * (extract_regular). ARCHITECTURE.md section 15.2.
	 */
	for (i = 0U; i < member_count; i++) {
		if (extract_member(archive_fd, hash_alg, &members[i], root_fd,
		                   &bufs) != 0) {
			fprintf(stderr,
			        "recover: %s: extraction failed after %u of "
			        "%u member(s)\n",
			        members[i].path, i, member_count);
			goto out;
		}
	}
	restore_dirs(members, member_count, root_fd);
	rc = 0;

out:
	free(bufs.comp);
	free(bufs.out);
	(void)close(root_fd);
	return rc;
}

int main(int argc, char **argv)
{
	uint8_t header[REC_HEADER_SIZE];
	uint8_t footer[REC_FOOTER_SIZE];
	struct stat st;
	uint64_t file_size;
	uint8_t hash_alg;
	uint64_t index_offset;
	uint64_t index_size_u64;
	uint32_t member_count;
	const uint8_t *footer_index_hash;
	uint8_t *index;
	size_t index_size;
	rec_member_t *members;
	uint8_t empty_digest[REC_HASH_LEN];
	const char *why;
	int archive_fd;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s archive.ark\n", argv[0]);
		return 1;
	}

	index = NULL;
	members = NULL;
	member_count = 0U;
	rc = 1;

	/*
	 * The archive is read in pieces (header, footer, index, then one
	 * chunk at a time), so memory use does not grow with its size.
	 */
	archive_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (archive_fd == -1 || fstat(archive_fd, &st) != 0 || st.st_size < 0) {
		fprintf(stderr, "recover: failed to read %s\n", argv[1]);
		goto out;
	}
	/* From here, a rejected archive exits with 2 before any write. */
	rc = 2;
	file_size = (uint64_t)st.st_size;
	if (file_size < REC_HEADER_SIZE + REC_FOOTER_SIZE ||
	    read_full_at(archive_fd, header, sizeof(header), 0U) != 0 ||
	    parse_header(header, &hash_alg) != 0) {
		fprintf(stderr, "recover: invalid ark header\n");
		goto out;
	}
	if (read_full_at(archive_fd, footer, sizeof(footer),
	                 file_size - REC_FOOTER_SIZE) != 0 ||
	    parse_footer(footer, file_size, &index_offset, &index_size_u64,
	                 &member_count, &footer_index_hash) != 0) {
		fprintf(stderr, "recover: invalid ark footer\n");
		goto out;
	}
	if (index_size_u64 > (uint64_t)SIZE_MAX - 1U) {
		fprintf(stderr, "recover: index too large\n");
		goto out;
	}
	index_size = (size_t)index_size_u64;
	/* OWNERSHIP: index is freed at out. */
	index = (uint8_t *)malloc(index_size == 0U ? 1U : index_size);
	if (index == NULL ||
	    read_full_at(archive_fd, index, index_size, index_offset) != 0) {
		fprintf(stderr, "recover: failed to read the index\n");
		rc = 1;
		goto out;
	}

	if (verify_index_hash(hash_alg, index, index_size, footer_index_hash) !=
	    0) {
		fprintf(stderr, "recover: index hash mismatch\n");
		goto out;
	}
	compute_empty_digest(hash_alg, empty_digest);
	why = parse_members(index, index_size, member_count, index_offset,
	                    &members);
	if (why == NULL)
		why = check_members(members, member_count, index_offset,
		                    empty_digest);
	if (why != NULL) {
		fprintf(stderr, "recover: invalid index: %s\n", why);
		goto out;
	}

	rc = 1;
	if (extract_members(archive_fd, hash_alg, members, member_count) != 0)
		goto out;

	printf("recovery complete: %u member(s) extracted\n", member_count);
	rc = 0;

out:
	members_free(members, member_count);
	free(index);
	if (archive_fd != -1)
		(void)close(archive_fd);
	return rc;
}
