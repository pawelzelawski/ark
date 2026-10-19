/*
 * deflate.c - RFC 1951 Deflate component implementation.
 *
 * Implements ark_deflate_bound, the encoder (ark_deflate_enc_*, one-shot
 * and streaming) and the decoder (ark_deflate_dec_*) from deflate.h. This
 * component performs pure in-memory transformation only: no I/O, no
 * component-owned allocation and no global or thread-local mutable state;
 * encoder and decoder state live in caller memory. See ARCHITECTURE.md
 * section 7.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate.h"

#define ARK_DEFLATE_MIN_MATCH 3U
#define ARK_DEFLATE_MAX_MATCH 258U
/* Largest distance RFC 1951 can encode (window_bits 15). */
#define ARK_DEFLATE_WINDOW_SIZE 32768U

/*
 * Two-level Huffman decode tables. A root table indexed by the next
 * root_bits input bits holds a symbol entry, or a link to a subtable for
 * codes longer than root_bits. Entry layout (uint32_t):
 *   bits 0..7   code bits consumed at this level (0 marks an invalid code)
 *   bits 8..11  subtable index bits (link entries only)
 *   bit 15      link flag
 *   bits 16..31 symbol, or subtable offset for link entries
 * All subtables of one table have 2^(longest code - root_bits) entries, one
 * per root prefix that has codes longer than root_bits.
 *
 * Worst-case table sizes (exact for this layout). A table needs
 * 2^root + p * 2^(L - root) entries for longest code L and p long-code root
 * prefixes. The code must be complete (the one-code exceptions are tiny),
 * so the prefix holding the length-L code needs at least L - root + 1
 * symbols, every other long-code prefix at least 2, and the remaining
 * 2^root - p root slots at least popcount(2^root - p) shorter codes. With at
 * most 286 lit/len symbols (root 10) that allows p = 137 at L = 15; with at
 * most 32 distance symbols (root 8), p = 10. Codes reaching these sizes
 * are tested (test_deflate_table_worst_case).
 */
#define ARK_INFLATE_LINK 0x8000U
#define ARK_INFLATE_LIT_ROOT 10U
#define ARK_INFLATE_DIST_ROOT 8U
#define ARK_INFLATE_CL_ROOT 7U
#define ARK_INFLATE_FIXED_LIT_ROOT 9U
#define ARK_INFLATE_FIXED_DIST_ROOT 5U
#define ARK_INFLATE_LIT_TABLE                                                  \
	((1U << ARK_INFLATE_LIT_ROOT) +                                        \
	 137U * (1U << (15U - ARK_INFLATE_LIT_ROOT)))
#define ARK_INFLATE_DIST_TABLE                                                 \
	((1U << ARK_INFLATE_DIST_ROOT) +                                       \
	 10U * (1U << (15U - ARK_INFLATE_DIST_ROOT)))
#define ARK_INFLATE_CL_TABLE (1U << ARK_INFLATE_CL_ROOT)

/* Internal decoder results: malformed input, or output larger than dst. */
#define ARK_INFLATE_ERR_DATA (-1)
#define ARK_INFLATE_ERR_OUTPUT (-2)

typedef struct {
	uint8_t *dst;
	size_t cap;
	size_t pos;
	uint64_t bits;
	unsigned int nbits;
} ark_bit_writer_t;

typedef struct {
	const uint8_t *src;
	size_t len;
	size_t pos;
	uint64_t bits;
	unsigned int nbits;
} ark_bit_reader_t;

/* Which RFC 1951 alphabet a decode table is built for (validation rules). */
typedef enum {
	ARK_TREE_CODELEN = 0,
	ARK_TREE_LITLEN,
	ARK_TREE_DIST,
} ark_tree_kind_t;

/*
 * Hash-chain match finder. head has 1 << hash_bits entries (newest position
 * per hash, -1 for none); prev has window_size entries indexed by
 * position & (window_size - 1) (previous position with the same hash). Both
 * arrays live in the encoder's caller memory.
 */
typedef struct {
	int32_t *head;
	int32_t *prev;
	unsigned int hash_bits;
	size_t window_size;
} ark_match_finder_t;

/*
 * Match-search parameters of one compression level (zlib's
 * configuration table, adapted). max_chain: hash-chain candidates tried
 * per search; nice_len: a match this long ends the search; max_lazy:
 * matches shorter than this are checked against the next position's match
 * (0 means greedy: every match found is taken); good_len: after a match of
 * at least this length, the look-ahead tries max_chain / 4 candidates.
 */
typedef struct {
	uint16_t max_chain;
	uint16_t nice_len;
	uint16_t max_lazy;
	uint16_t good_len;
} ark_level_params_t;

/* Streaming encoder phases (ark_deflate_enc_stream). */
typedef enum {
	ARK_SE_ACTIVE = 0, /* taking input */
	ARK_SE_FINISHING,  /* final block staged, output not all returned */
	ARK_SE_DONE,
	ARK_SE_ERROR,
} ark_se_mode_t;

/*
 * Streaming state. win holds the stream's recent input: win[0..start) is
 * history (matches reach back up to window_size bytes of it), and
 * win[start..fill) is input taken but not compressed yet, at most max_input
 * bytes. Hash positions are offsets into win; positions below ins are in
 * the hash chains. obuf stages the compressed bytes of one step, returned
 * from obuf_pos; bits and nbits hold the bits of a byte not complete yet.
 */
typedef struct {
	uint8_t *win;
	size_t win_cap;
	size_t hist;
	size_t start;
	size_t fill;
	size_t ins;
	uint8_t *obuf;
	size_t obuf_cap;
	size_t obuf_len;
	size_t obuf_pos;
	uint64_t bits;
	unsigned int nbits;
	ark_se_mode_t mode;
	int synced;
	int started;
} ark_enc_stream_t;

/*
 * Encoder state. The struct sits at the start of the caller's memory; tables
 * holds the match-finder arrays: head (1 << hash_bits entries), then prev
 * (window_size entries), then the token buffer (max_input entries). Level 0
 * has no tables (head, prev and tokens are NULL). A streaming encoder adds
 * the bytes of win and obuf after them.
 */
struct ark_deflate_enc {
	ark_match_finder_t mf;
	uint32_t *tokens;
	ark_level_params_t lp;
	int level;
	int streaming;
	size_t max_input;
	ark_enc_stream_t s;
	int32_t tables[];
};

/*
 * Encoder tokens, one uint32_t per literal or match. A literal is its
 * byte value. A match sets ARK_TOKEN_MATCH and holds length - 3 in bits
 * 15..22 and distance - 1 in bits 0..14 (distances never exceed 32768).
 */
#define ARK_TOKEN_MATCH 0x80000000U
#define ARK_TOKEN_LEN_SHIFT 15U
#define ARK_TOKEN_DIST_MASK 0x7fffU

/*
 * Search parameters per level 1..9 (level 0 stores without searching).
 * Levels 1-3 match greedily, 4-9 lazily. Level 6 (the default) is the
 * search of v1.2's single-pass compressor and must not change, so that
 * default-level output stays byte-identical.
 */
static const ark_level_params_t g_level_params[10] = {
    {0U, 0U, 0U, 0U},         /* 0: stored blocks only */
    {4U, 8U, 0U, 0U},         /* 1: fast */
    {8U, 16U, 0U, 0U},        /* 2 */
    {32U, 32U, 0U, 0U},       /* 3 */
    {32U, 32U, 8U, 4U},       /* 4 */
    {32U, 32U, 16U, 8U},      /* 5 */
    {128U, 258U, 258U, 32U},  /* 6: default */
    {256U, 258U, 258U, 32U},  /* 7 */
    {1024U, 258U, 258U, 32U}, /* 8 */
    {4096U, 258U, 258U, 32U}, /* 9 */
};

typedef struct {
	uint32_t lit[286];
	uint32_t dist[30];
} ark_freq_t;

typedef struct {
	ark_freq_t freq;
	uint8_t lit_len[286];
	uint8_t dist_len[30];
	size_t hlit_count;
	size_t hdist_count;
} ark_dynamic_plan_t;

typedef struct {
	uint16_t code[288];
	uint8_t len[288];
} ark_codebook_t;

typedef struct {
	uint64_t freq;
	int16_t parent;
	uint16_t min_sym;
} ark_huff_node_t;

/* RFC 1951 length code base values and extra-bit widths (257..285). */
static const uint16_t g_len_base[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23,  27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};

static const uint8_t g_len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

/* RFC 1951 distance code base values and extra-bit widths (0..29). */
static const uint16_t g_dist_base[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};

static const uint8_t g_dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

static const uint8_t g_cl_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

static const size_t g_default_block_candidates[] = {
    (size_t)16U * 1024U,
    (size_t)32U * 1024U,
    (size_t)64U * 1024U,
    (size_t)128U * 1024U,
};

/* Length code index (symbol - 257) for match length 3 + i, i = 0..255. */
static const uint8_t g_len_sym[256] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9,  10, 10, 11, 11, 12, 12, 12,
    12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16,
    16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19,
    19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23,
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 28,
};

/*
 * Distance symbol for d = distance - 1: g_dist_sym[d] when d < 256, else
 * g_dist_sym[256 + (d >> 7)] (entries 256 and 257 are unused).
 */
static const uint8_t g_dist_sym[512] = {
    0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,  8,  8,  8,
    8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,  10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 0,  0,  16, 17, 18, 18, 19, 19, 20, 20,
    20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23,
    23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
};

/*
 * Shared by the compressor and the decompressor (see ARCHITECTURE.md
 * section 15.3). Read 8 bytes from p as a little-endian 64-bit value without
 * memcpy.
 */
static uint64_t load_u64_le(const uint8_t *p)
{
	return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Reverse the low n bits of v for Deflate's LSB-first bitstream. */
static uint16_t bit_reverse(uint16_t v, unsigned int n)
{
	uint16_t out;
	unsigned int i;

	out = 0;
	for (i = 0; i < n; i++) {
		out <<= 1;
		out |= (uint16_t)(v & 1U);
		v >>= 1;
	}
	return out;
}

/* Append up to 16 bits to dst; bytes are emitted as soon as they are full. */
static int bw_put_bits(ark_bit_writer_t *bw, uint16_t bits, unsigned int n)
{
	if (n > 16U)
		return -1;
	bw->bits |= ((uint64_t)bits) << bw->nbits;
	bw->nbits += n;
	while (bw->nbits >= 8U) {
		if (bw->pos >= bw->cap)
			return -1;
		bw->dst[bw->pos++] = (uint8_t)(bw->bits & 0xffU);
		bw->bits >>= 8;
		bw->nbits -= 8U;
	}
	return 0;
}

/* Flush partially filled byte with zero padding. */
static int bw_flush_to_byte(ark_bit_writer_t *bw)
{
	if (bw->nbits == 0U)
		return 0;
	if (bw->pos >= bw->cap)
		return -1;
	bw->dst[bw->pos++] = (uint8_t)(bw->bits & 0xffU);
	bw->bits = 0;
	bw->nbits = 0;
	return 0;
}

/*
 * Top up the bit buffer. With at least 8 input bytes left, one little-endian
 * 8-byte load fills it to 56..63 valid bits; near the end of the input it
 * is filled byte by byte. Bits above nbits are always zero.
 */
static void br_refill(ark_bit_reader_t *br)
{
	if (br->len - br->pos >= 8U) {
		unsigned int nbytes;

		nbytes = (63U - br->nbits) >> 3;
		br->bits |= load_u64_le(br->src + br->pos) << br->nbits;
		br->pos += nbytes;
		br->nbits += nbytes * 8U;
		br->bits &= ((uint64_t)1U << br->nbits) - 1U;
		return;
	}
	while (br->nbits <= 48U && br->pos < br->len) {
		br->bits |= (uint64_t)br->src[br->pos++] << br->nbits;
		br->nbits += 8U;
	}
}

/* Make at least n (<= 32) bits available; fails at the end of the input. */
static int br_ensure_bits(ark_bit_reader_t *br, unsigned int n)
{
	if (br->nbits < n)
		br_refill(br);
	return br->nbits >= n ? 0 : -1;
}

/* Consume n bits and return them in the low bits of *out. */
static int br_get_bits(ark_bit_reader_t *br, unsigned int n, uint16_t *out)
{
	if (n == 0U) {
		*out = 0;
		return 0;
	}
	if (br_ensure_bits(br, n) != 0)
		return -1;
	*out = (uint16_t)(br->bits & ((1U << n) - 1U));
	br->bits >>= n;
	br->nbits -= n;
	return 0;
}

/*
 * Build a two-level decode table from canonical Huffman code lengths.
 *
 * Validates the code first, as zlib does (RFC 1951 section 3.2.2): an
 * oversubscribed code is always rejected; an incomplete code is rejected
 * except for a lit/len or distance code with exactly one code of length 1,
 * or a distance code with no codes at all. The code-length code must be
 * complete. Unused table entries keep length 0 and fail to decode.
 *
 * Returns 0 on success, -1 for an invalid code or a table that would not
 * fit in tab_cap entries.
 */
static int inflate_table_build(uint32_t *tab, size_t tab_cap,
                               const uint8_t *lengths, size_t n_symbols,
                               unsigned int root_bits, ark_tree_kind_t kind)
{
	uint16_t count[16];
	uint16_t next_code[16];
	unsigned int max_len;
	unsigned int sub_bits;
	unsigned int bits;
	size_t root_size;
	size_t used;
	size_t codes;
	size_t i;
	int32_t left;
	uint16_t code;

	for (i = 0; i < 16U; i++)
		count[i] = 0U;
	max_len = 0U;
	codes = 0U;
	for (i = 0; i < n_symbols; i++) {
		if (lengths[i] > 15U)
			return -1;
		if (lengths[i] == 0U)
			continue;
		count[lengths[i]]++;
		codes++;
		if (lengths[i] > max_len)
			max_len = lengths[i];
	}

	/*
	 * SAFETY: Kraft accounting. left is the number of unused codes of the
	 * current length; it must never go negative (oversubscribed code).
	 * Rejecting bad codes here also keeps every code prefix-free, which
	 * the table fill below relies on.
	 */
	left = 1;
	for (bits = 1U; bits <= 15U; bits++) {
		left <<= 1;
		left -= (int32_t)count[bits];
		if (left < 0)
			return -1;
	}
	if (left > 0) {
		if (kind == ARK_TREE_CODELEN)
			return -1;
		if (!(codes == 1U && count[1] == 1U) &&
		    !(kind == ARK_TREE_DIST && codes == 0U))
			return -1;
	}

	root_size = (size_t)1U << root_bits;
	if (root_size > tab_cap)
		return -1;
	for (i = 0; i < root_size; i++)
		tab[i] = 0U;

	code = 0U;
	next_code[0] = 0U;
	for (bits = 1U; bits <= 15U; bits++) {
		code = (uint16_t)((code + count[bits - 1U]) << 1U);
		next_code[bits] = code;
	}

	sub_bits = max_len > root_bits ? max_len - root_bits : 0U;
	used = root_size;
	for (i = 0; i < n_symbols; i++) {
		unsigned int len;
		size_t rev;
		size_t j;

		len = lengths[i];
		if (len == 0U)
			continue;
		rev = bit_reverse(next_code[len]++, len);
		if (len <= root_bits) {
			for (j = rev; j < root_size; j += (size_t)1U << len)
				tab[j] = ((uint32_t)i << 16) | len;
		} else {
			uint32_t *sub;
			size_t root_idx;
			size_t sub_size;

			root_idx = rev & (root_size - 1U);
			sub_size = (size_t)1U << sub_bits;
			if ((tab[root_idx] & ARK_INFLATE_LINK) == 0U) {
				if (tab_cap - used < sub_size)
					return -1;
				for (j = 0; j < sub_size; j++)
					tab[used + j] = 0U;
				tab[root_idx] =
				    ((uint32_t)used << 16) | ARK_INFLATE_LINK |
				    ((uint32_t)sub_bits << 8) | root_bits;
				used += sub_size;
			}
			sub = tab + (tab[root_idx] >> 16);
			for (j = rev >> root_bits; j < sub_size;
			     j += (size_t)1U << (len - root_bits))
				sub[j] =
				    ((uint32_t)i << 16) | (len - root_bits);
		}
	}
	return 0;
}

/* Build bit-reversed canonical codes for Deflate output. */
static int build_codes(const uint8_t *lengths, size_t n_symbols,
                       unsigned int max_bits, ark_codebook_t *book)
{
	uint16_t count[16];
	uint16_t next_code[16];
	unsigned int bits;
	uint16_t code;
	size_t i;

	if (max_bits > 15U || n_symbols > 288U)
		return -1;

	for (i = 0; i < 288U; i++) {
		book->code[i] = 0;
		book->len[i] = 0;
	}
	for (i = 0; i < 16U; i++) {
		count[i] = 0;
		next_code[i] = 0;
	}

	for (i = 0; i < n_symbols; i++) {
		if (lengths[i] > max_bits)
			return -1;
		if (lengths[i] != 0U)
			count[lengths[i]]++;
	}

	code = 0;
	for (bits = 1; bits <= max_bits; bits++) {
		code = (uint16_t)((code + count[bits - 1U]) << 1U);
		next_code[bits] = code;
	}

	for (i = 0; i < n_symbols; i++) {
		uint8_t len;

		len = lengths[i];
		if (len == 0U)
			continue;
		book->code[i] = bit_reverse(next_code[len], len);
		book->len[i] = len;
		next_code[len]++;
	}

	return 0;
}

/* Decode one Huffman symbol with a two-level table built for root_bits. */
static int inflate_decode_sym(ark_bit_reader_t *br, const uint32_t *tab,
                              unsigned int root_bits, unsigned int *sym)
{
	uint32_t e;
	unsigned int n;

	if (br->nbits < 15U)
		br_refill(br);
	e = tab[br->bits & (((uint64_t)1U << root_bits) - 1U)];
	if ((e & ARK_INFLATE_LINK) != 0U) {
		unsigned int sub_bits;

		n = e & 0xffU;
		if (n > br->nbits)
			return -1;
		br->bits >>= n;
		br->nbits -= n;
		sub_bits = (e >> 8) & 0xfU;
		e = tab[(e >> 16) +
		        (br->bits & (((uint64_t)1U << sub_bits) - 1U))];
	}
	n = e & 0xffU;
	if (n == 0U || n > br->nbits)
		return -1;
	br->bits >>= n;
	br->nbits -= n;
	*sym = e >> 16;
	return 0;
}

/*
 * Write src as RFC 1951 stored blocks of at most 65535 bytes after the bits
 * already in bw; final marks the last block. An empty src gives one empty
 * block (with final 0, the sync-flush marker 00 00 FF FF).
 */
static int emit_stored(ark_bit_writer_t *bw, const uint8_t *src, size_t src_len,
                       unsigned int final)
{
	size_t off;

	off = 0;
	do {
		uint16_t chunk;
		uint16_t nlen;
		size_t i;

		chunk = (uint16_t)((src_len - off) > 65535U ? 65535U
		                                            : (src_len - off));
		nlen = (uint16_t)~chunk;
		if (bw_put_bits(bw,
		                (uint16_t)(off + chunk == src_len ? final : 0U),
		                1U) != 0)
			return -1;
		if (bw_put_bits(bw, 0U, 2U) != 0)
			return -1;
		if (bw_flush_to_byte(bw) != 0)
			return -1;

		if (bw->pos + 4U + chunk > bw->cap)
			return -1;
		bw->dst[bw->pos++] = (uint8_t)(chunk & 0xffU);
		bw->dst[bw->pos++] = (uint8_t)(chunk >> 8);
		bw->dst[bw->pos++] = (uint8_t)(nlen & 0xffU);
		bw->dst[bw->pos++] = (uint8_t)(nlen >> 8);
		for (i = 0; i < chunk; i++)
			bw->dst[bw->pos + i] = src[off + i];
		bw->pos += (size_t)chunk;
		off += chunk;
	} while (off < src_len);
	return 0;
}

/* Emit src as one complete stream of stored blocks; returns its size. */
static int emit_stored_blocks(const uint8_t *src, size_t src_len, uint8_t *dst,
                              size_t dst_cap)
{
	ark_bit_writer_t bw;

	bw.dst = dst;
	bw.cap = dst_cap;
	bw.pos = 0;
	bw.bits = 0;
	bw.nbits = 0;
	if (emit_stored(&bw, src, src_len, 1U) != 0)
		return -1;
	return (int)bw.pos;
}

/* Emit one canonical Huffman symbol. */
static int emit_code_symbol(ark_bit_writer_t *bw, const ark_codebook_t *book,
                            unsigned int sym)
{
	if (sym >= 288U || book->len[sym] == 0U)
		return -1;
	return bw_put_bits(bw, book->code[sym], book->len[sym]);
}

/* Deflate hash over three bytes for LZ77 match candidate lookup. */
static unsigned int hash3(const uint8_t *p, unsigned int hash_bits)
{
	uint32_t h;

	h = ((uint32_t)p[0] << 16) ^ ((uint32_t)p[1] << 8) ^ (uint32_t)p[2];
	h *= 0x1e35a7bdU;
	return (unsigned int)(h >> (32U - hash_bits));
}

/*
 * Start a parse: forget every hash head. prev is not cleared: a chain is
 * entered only through head, and every prev slot reached from it belongs to
 * a position inserted during this parse, whose insert wrote that slot.
 * Stale prev slots from earlier parses are therefore never read, and the
 * output equals a parse over fully cleared tables.
 */
static void match_finder_begin_parse(ark_match_finder_t *mf)
{
	size_t i;
	size_t n;

	n = (size_t)1U << mf->hash_bits;
	for (i = 0; i < n; i++)
		mf->head[i] = -1;
}

/* Return the newest position with hash h, or -1. */
static int32_t match_finder_head_get(const ark_match_finder_t *mf,
                                     unsigned int h)
{
	return mf->head[h];
}

/* Store the newest position for hash h. */
static void match_finder_head_set(ark_match_finder_t *mf, unsigned int h,
                                  int32_t pos)
{
	mf->head[h] = pos;
}

/* Return the chain predecessor recorded for pos. */
static int32_t match_finder_prev_get(const ark_match_finder_t *mf, size_t pos)
{
	return mf->prev[pos & (mf->window_size - 1U)];
}

/* Record the chain predecessor for pos. */
static void match_finder_prev_set(ark_match_finder_t *mf, size_t pos,
                                  int32_t prev)
{
	mf->prev[pos & (mf->window_size - 1U)] = prev;
}

/* Insert one position into hash chain and return previous head candidate. */
static int insert_hash(const uint8_t *src, size_t src_len, size_t pos,
                       ark_match_finder_t *mf)
{
	unsigned int h;
	int32_t old;

	if (pos + 2U >= src_len)
		return -1;
	h = hash3(src + pos, mf->hash_bits);
	old = match_finder_head_get(mf, h);
	match_finder_prev_set(mf, pos, old);
	match_finder_head_set(mf, h, (int32_t)pos);
	return old;
}

/* Deterministic symbol ordering: lower frequency first, then symbol id. */
static void sort_symbols_by_freq(const uint32_t *freq, const uint16_t *sym,
                                 size_t count, uint16_t *out)
{
	size_t i;

	for (i = 0; i < count; i++) {
		size_t j;

		out[i] = sym[i];
		j = i;
		while (j > 0 && (freq[out[j - 1U]] > freq[out[j]] ||
		                 (freq[out[j - 1U]] == freq[out[j]] &&
		                  out[j - 1U] > out[j]))) {
			uint16_t tmp;

			tmp = out[j - 1U];
			out[j - 1U] = out[j];
			out[j] = tmp;
			j--;
		}
	}
}

/* Pick and remove the smallest active Huffman node. */
static int16_t pick_smallest_node(int16_t *active, size_t *active_count,
                                  const ark_huff_node_t *nodes)
{
	int16_t best;
	size_t best_i;
	size_t i;

	best = active[0];
	best_i = 0U;
	for (i = 1U; i < *active_count; i++) {
		int16_t idx;

		idx = active[i];
		if (nodes[idx].freq < nodes[best].freq ||
		    (nodes[idx].freq == nodes[best].freq &&
		     nodes[idx].min_sym < nodes[best].min_sym)) {
			best = idx;
			best_i = i;
		}
	}
	active[best_i] = active[*active_count - 1U];
	(*active_count)--;
	return best;
}

/*
 * Build Deflate-compliant length-limited code lengths from symbol frequencies.
 * Uses deterministic Huffman construction then enforces max_bits constraints.
 * See ARCHITECTURE.md §7.2 and RFC 1951 limits.
 */
static int build_length_limited_lengths(const uint32_t *freq, size_t n_symbols,
                                        uint8_t *lengths, unsigned int max_bits)
{
	ark_huff_node_t nodes[2U * 288U - 1U];
	uint16_t used_sym[288];
	uint16_t order[288];
	int16_t active[2U * 288U - 1U];
	uint16_t leaf_node[288];
	uint16_t bl_count[16];
	size_t used;
	size_t active_count;
	size_t node_count;
	size_t i;
	size_t overflow;
	size_t idx;

	if (n_symbols > 288U || max_bits == 0U || max_bits > 15U)
		return -1;

	for (i = 0; i < n_symbols; i++)
		lengths[i] = 0;
	for (i = 0; i < 16U; i++)
		bl_count[i] = 0;
	overflow = 0U;

	used = 0U;
	for (i = 0; i < n_symbols; i++) {
		if (freq[i] == 0U)
			continue;
		used_sym[used++] = (uint16_t)i;
	}

	if (used == 0U) {
		lengths[0] = 1U;
		return 0;
	}
	if (used == 1U) {
		lengths[used_sym[0]] = 1U;
		return 0;
	}

	node_count = 0U;
	active_count = 0U;
	for (i = 0; i < used; i++) {
		uint16_t s;

		s = used_sym[i];
		nodes[node_count].freq = freq[s];
		nodes[node_count].parent = -1;
		nodes[node_count].min_sym = s;
		leaf_node[i] = (uint16_t)node_count;
		active[active_count++] = (int16_t)node_count;
		node_count++;
	}

	while (active_count > 1U) {
		int16_t a;
		int16_t b;
		int16_t p;

		a = pick_smallest_node(active, &active_count, nodes);
		b = pick_smallest_node(active, &active_count, nodes);
		p = (int16_t)node_count;
		nodes[p].freq = nodes[a].freq + nodes[b].freq;
		nodes[p].parent = -1;
		nodes[p].min_sym = nodes[a].min_sym < nodes[b].min_sym
		                       ? nodes[a].min_sym
		                       : nodes[b].min_sym;
		nodes[a].parent = p;
		nodes[b].parent = p;
		active[active_count++] = p;
		node_count++;
	}

	for (i = 0; i < used; i++) {
		unsigned int depth;
		int16_t n;

		depth = 0U;
		n = (int16_t)leaf_node[i];
		while (nodes[n].parent >= 0) {
			depth++;
			n = nodes[n].parent;
		}
		if (depth == 0U)
			depth = 1U;
		if (depth > max_bits) {
			overflow++;
			depth = max_bits;
		}
		bl_count[depth]++;
	}

	/*
	 * Leaves deeper than max_bits were clamped to max_bits, which
	 * oversubscribes the code (Kraft sum above 1). Repair it as miniz
	 * does: each step drops one leaf from max_bits and splits one leaf at
	 * the deepest shorter level into two leaves one level down. The leaf
	 * count stays the same and the Kraft total, scaled by 2^max_bits,
	 * drops by one, so the loop ends with a complete code.
	 */
	if (overflow > 0U) {
		uint32_t total;
		unsigned int b;

		total = 0U;
		for (b = max_bits; b > 0U; b--)
			total += (uint32_t)bl_count[b] << (max_bits - b);
		while (total != (1UL << max_bits)) {
			if (bl_count[max_bits] == 0U)
				return -1;
			bl_count[max_bits]--;
			for (b = max_bits - 1U; b > 0U; b--) {
				if (bl_count[b] != 0U)
					break;
			}
			if (b == 0U)
				return -1;
			bl_count[b]--;
			bl_count[b + 1U] += 2U;
			total--;
		}
	}

	sort_symbols_by_freq(freq, used_sym, used, order);
	idx = 0U;
	for (i = max_bits; i > 0U; i--) {
		size_t n;

		n = bl_count[i];
		while (n-- > 0U) {
			if (idx >= used)
				return -1;
			lengths[order[idx++]] = (uint8_t)i;
		}
	}
	if (idx != used)
		return -1;
	return 0;
}

static size_t freq_extra_bits(const ark_freq_t *freq)
{
	size_t bits;
	size_t i;

	bits = 0U;
	for (i = 257U; i < 286U; i++)
		bits += (size_t)freq->lit[i] * g_len_extra[i - 257U];
	for (i = 0; i < 30U; i++)
		bits += (size_t)freq->dist[i] * g_dist_extra[i];
	return bits;
}

static size_t huff_data_bits(const ark_freq_t *freq, const uint8_t *lit_len,
                             const uint8_t *dist_len)
{
	size_t bits;
	size_t i;

	bits = freq_extra_bits(freq);
	for (i = 0; i < 286U; i++)
		bits += (size_t)freq->lit[i] * lit_len[i];
	for (i = 0; i < 30U; i++)
		bits += (size_t)freq->dist[i] * dist_len[i];
	return bits;
}

/*
 * Code-length (CL) plan for one dynamic block header: the run-length coded
 * sequence of literal/length and distance code lengths, and the Huffman code
 * for the 19-symbol CL alphabet. See RFC 1951 section 3.2.7.
 */
typedef struct {
	uint8_t sym[286 + 30];
	uint8_t extra[286 + 30];
	size_t count;
	uint32_t freq[19];
	uint8_t len[19];
	size_t hclen;
} ark_cl_plan_t;

/* Extra-bit widths of CL repeat symbols 16, 17 and 18. */
static const uint8_t g_cl_extra[19] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7,
};

/* Append one CL symbol and its repeat-count extra value to the plan. */
static void cl_plan_push(ark_cl_plan_t *cp, unsigned int sym, size_t extra)
{
	cp->sym[cp->count] = (uint8_t)sym;
	cp->extra[cp->count] = (uint8_t)extra;
	cp->count++;
	cp->freq[sym]++;
}

/*
 * Run-length code the concatenated lit/len and distance code lengths with
 * CL symbols 16 (repeat previous 3..6), 17 (zeros 3..10) and 18 (zeros
 * 11..138), then build the CL Huffman code (at most 7 bits) and trim HCLEN.
 *
 * The CL code must be complete: a single used CL symbol would get one 1-bit
 * code, which strict decoders such as zlib reject, so an unused symbol is
 * given the other 1-bit code. See RFC 1951 section 3.2.7.
 */
static int cl_plan_build(const uint8_t *lit_len, size_t hlit,
                         const uint8_t *dist_len, size_t hdist,
                         ark_cl_plan_t *cp)
{
	uint8_t all[286 + 30];
	size_t used;
	size_t n;
	size_t i;

	if (hlit > 286U || hdist > 30U)
		return -1;
	n = hlit + hdist;
	for (i = 0; i < hlit; i++)
		all[i] = lit_len[i];
	for (i = 0; i < hdist; i++)
		all[hlit + i] = dist_len[i];
	for (i = 0; i < 19U; i++)
		cp->freq[i] = 0U;
	cp->count = 0U;

	i = 0U;
	while (i < n) {
		uint8_t v;
		size_t run;
		size_t r;

		v = all[i];
		run = 1U;
		while (i + run < n && all[i + run] == v)
			run++;
		i += run;
		if (v == 0U) {
			r = run;
			while (r >= 11U) {
				size_t k;

				k = r > 138U ? 138U : r;
				cl_plan_push(cp, 18U, k - 11U);
				r -= k;
			}
			if (r >= 3U) {
				cl_plan_push(cp, 17U, r - 3U);
				r = 0U;
			}
			while (r-- > 0U)
				cl_plan_push(cp, 0U, 0U);
			continue;
		}
		cl_plan_push(cp, v, 0U);
		r = run - 1U;
		while (r >= 3U) {
			size_t k;

			k = r > 6U ? 6U : r;
			cl_plan_push(cp, 16U, k - 3U);
			r -= k;
		}
		while (r-- > 0U)
			cl_plan_push(cp, v, 0U);
	}

	if (build_length_limited_lengths(cp->freq, 19U, cp->len, 7U) != 0)
		return -1;
	used = 0U;
	for (i = 0; i < 19U; i++) {
		if (cp->len[i] != 0U)
			used++;
	}
	if (used == 1U) {
		/* Complete the code with the first unused symbol in HCLEN
		 * order. */
		for (i = 0; i < 19U; i++) {
			if (cp->len[g_cl_order[i]] == 0U) {
				cp->len[g_cl_order[i]] = 1U;
				break;
			}
		}
	}

	cp->hclen = 19U;
	while (cp->hclen > 4U && cp->len[g_cl_order[cp->hclen - 1U]] == 0U)
		cp->hclen--;
	return 0;
}

/*
 * Exact bit size of a dynamic block header for plan cp: block header (3),
 * HLIT/HDIST/HCLEN (14), CL code lengths and the coded CL sequence. Must
 * match what emit_dynamic_header writes, plus the 3-bit block header.
 */
static size_t cl_plan_bits(const ark_cl_plan_t *cp)
{
	size_t bits;
	size_t i;

	bits = 3U + 5U + 5U + 4U + cp->hclen * 3U;
	for (i = 0; i < 19U; i++)
		bits += (size_t)cp->freq[i] * (cp->len[i] + g_cl_extra[i]);
	return bits;
}

/*
 * Emit a dynamic block header (after BFINAL/BTYPE): HLIT, HDIST, HCLEN, the
 * CL code lengths and the run-length coded code lengths. Also builds the
 * lit/len and distance codebooks used for the block data.
 * See RFC 1951 section 3.2.7.
 */
static int emit_dynamic_header(ark_bit_writer_t *bw, const uint8_t *lit_len,
                               const uint8_t *dist_len, size_t hlit_count,
                               size_t hdist_count, ark_codebook_t *lit_book,
                               ark_codebook_t *dist_book)
{
	ark_codebook_t cl_book;
	ark_cl_plan_t cp;
	size_t i;

	if (build_codes(lit_len, 286U, 15U, lit_book) != 0)
		return -1;
	if (build_codes(dist_len, 30U, 15U, dist_book) != 0)
		return -1;
	if (cl_plan_build(lit_len, hlit_count, dist_len, hdist_count, &cp) != 0)
		return -1;
	if (build_codes(cp.len, 19U, 7U, &cl_book) != 0)
		return -1;

	if (bw_put_bits(bw, (uint16_t)(hlit_count - 257U), 5U) != 0)
		return -1;
	if (bw_put_bits(bw, (uint16_t)(hdist_count - 1U), 5U) != 0)
		return -1;
	if (bw_put_bits(bw, (uint16_t)(cp.hclen - 4U), 4U) != 0)
		return -1;
	for (i = 0; i < cp.hclen; i++) {
		if (bw_put_bits(bw, cp.len[g_cl_order[i]], 3U) != 0)
			return -1;
	}
	for (i = 0; i < cp.count; i++) {
		unsigned int sym;

		sym = cp.sym[i];
		if (emit_code_symbol(bw, &cl_book, sym) != 0)
			return -1;
		if (g_cl_extra[sym] != 0U &&
		    bw_put_bits(bw, cp.extra[i], g_cl_extra[sym]) != 0)
			return -1;
	}
	return 0;
}

/*
 * Number of equal low-order bytes of two 8-byte little-endian loads, given
 * x = a ^ b != 0. Portable count of trailing zero bytes: x & (0 - x) keeps
 * the lowest set bit, so subtracting 1 sets every bit below it; bit 7 of
 * each byte then marks a fully equal byte, and the multiply sums those
 * marks into the top byte.
 */
static size_t equal_low_bytes(uint64_t x)
{
	uint64_t below;

	below = (x & (0U - x)) - 1U;
	below = (below >> 7) & 0x0101010101010101U;
	return (size_t)((below * 0x0101010101010101U) >> 56);
}

/*
 * Search the hash chain from candidate for a match at pos longer than
 * prev_len and at least ARK_DEFLATE_MIN_MATCH bytes. Candidates further
 * back than the window end the search; at most max_chain candidates are
 * tried, and a match of nice_len bytes stops it. Returns the length found,
 * or 0 when none is longer, and stores its distance in *dist.
 */
static size_t find_longer_match(const uint8_t *src, size_t src_len, size_t pos,
                                int32_t candidate, const ark_match_finder_t *mf,
                                unsigned int max_chain, size_t nice_len,
                                size_t prev_len, size_t *dist)
{
	size_t floor_len;
	size_t best;
	size_t max_len;
	int32_t min_pos;

	floor_len = prev_len < 2U ? 2U : prev_len;
	if (src_len - pos < ARK_DEFLATE_MIN_MATCH)
		return 0U;
	max_len = src_len - pos;
	if (max_len > ARK_DEFLATE_MAX_MATCH)
		max_len = ARK_DEFLATE_MAX_MATCH;
	if (floor_len >= max_len)
		return 0U;
	best = floor_len;
	min_pos = (int32_t)(pos > mf->window_size ? pos - mf->window_size : 0U);

	while (candidate >= min_pos && max_chain > 0U) {
		size_t cand;

		max_chain--;
		cand = (size_t)candidate;
		if (cand >= pos)
			break;
		/* best < max_len, so src[pos + best] is inside the input. The
		 * byte that would make the match longer is checked first. */
		if (src[cand + best] == src[pos + best] &&
		    src[cand] == src[pos] && src[cand + 1U] == src[pos + 1U]) {
			size_t len;

			len = 2U;
			for (;;) {
				uint64_t x;

				if (len + 8U > max_len) {
					while (len < max_len &&
					       src[cand + len] ==
					           src[pos + len])
						len++;
					break;
				}
				x = load_u64_le(src + cand + len) ^
				    load_u64_le(src + pos + len);
				if (x != 0U) {
					len += equal_low_bytes(x);
					break;
				}
				len += 8U;
			}
			if (len > best) {
				best = len;
				*dist = pos - cand;
				if (len >= nice_len || len >= max_len)
					break;
			}
		}
		candidate = match_finder_prev_get(mf, cand);
	}
	return best > floor_len ? best : 0U;
}

/*
 * Parse src[start..src_len) once into enc->tokens with the level's search
 * parameters; the positions before start are history the caller has already
 * inserted into the hash chains. With lazy matching (max_lazy > 0) a match
 * shorter than max_lazy is deferred by one literal when the next position
 * has a longer one, as in zlib's default levels; greedy levels take every
 * match found. The hash chains span the whole input, so matches reach back
 * across block boundaries within the window. Returns the token count (at
 * most src_len - start).
 */
static size_t parse_tokens(ark_deflate_enc_t *enc, const uint8_t *src,
                           size_t start, size_t src_len)
{
	const ark_level_params_t *lp;
	ark_match_finder_t *mf;
	uint32_t *tokens;
	size_t count;
	size_t pos;
	size_t cur_len;
	size_t cur_dist;
	int32_t candidate;

	lp = &enc->lp;
	mf = &enc->mf;
	tokens = enc->tokens;
	count = 0U;
	pos = start;
	cur_dist = 0U;
	candidate = insert_hash(src, src_len, pos, mf);
	cur_len = find_longer_match(src, src_len, pos, candidate, mf,
	                            lp->max_chain, lp->nice_len, 0U, &cur_dist);
	while (pos < src_len) {
		if (cur_len >= ARK_DEFLATE_MIN_MATCH) {
			size_t from;
			size_t i;

			from = pos + 1U;
			if (cur_len < lp->max_lazy) {
				size_t next_len;
				size_t next_dist;

				next_dist = 0U;
				candidate =
				    insert_hash(src, src_len, pos + 1U, mf);
				next_len = find_longer_match(
				    src, src_len, pos + 1U, candidate, mf,
				    cur_len >= lp->good_len
				        ? (unsigned int)lp->max_chain >> 2
				        : lp->max_chain,
				    lp->nice_len, cur_len, &next_dist);
				if (next_len > cur_len) {
					tokens[count++] = src[pos];
					pos++;
					cur_len = next_len;
					cur_dist = next_dist;
					continue;
				}
				from = pos + 2U;
			}
			/*
			 * SAFETY: cur_len <= 258 and cur_dist <= window_size
			 * <= 32768, so both fit their token fields.
			 */
			tokens[count++] =
			    ARK_TOKEN_MATCH |
			    ((uint32_t)(cur_len - ARK_DEFLATE_MIN_MATCH)
			     << ARK_TOKEN_LEN_SHIFT) |
			    (uint32_t)(cur_dist - 1U);
			for (i = from; i < pos + cur_len; i++)
				(void)insert_hash(src, src_len, i, mf);
			pos += cur_len;
		} else {
			tokens[count++] = src[pos];
			pos++;
		}
		cur_len = 0U;
		if (pos < src_len) {
			candidate = insert_hash(src, src_len, pos, mf);
			cur_len = find_longer_match(
			    src, src_len, pos, candidate, mf, lp->max_chain,
			    lp->nice_len, 0U, &cur_dist);
		}
	}
	return count;
}

/* Length code index (symbol - 257) of a match token. */
static unsigned int token_len_index(uint32_t t)
{
	return g_len_sym[(t >> ARK_TOKEN_LEN_SHIFT) & 0xffU];
}

/* Distance symbol of a match token. */
static unsigned int token_dist_sym(uint32_t t)
{
	uint32_t d;

	d = t & ARK_TOKEN_DIST_MASK;
	return d < 256U ? g_dist_sym[d] : g_dist_sym[256U + (d >> 7)];
}

/* Input bytes a token covers. */
static size_t token_bytes(uint32_t t)
{
	if ((t & ARK_TOKEN_MATCH) == 0U)
		return 1U;
	return (size_t)((t >> ARK_TOKEN_LEN_SHIFT) & 0xffU) +
	       ARK_DEFLATE_MIN_MATCH;
}

/* Add a token's symbols to freq. */
static void token_count(uint32_t t, ark_freq_t *freq)
{
	if ((t & ARK_TOKEN_MATCH) == 0U) {
		freq->lit[t]++;
		return;
	}
	freq->lit[257U + token_len_index(t)]++;
	freq->dist[token_dist_sym(t)]++;
}

/* Emit tokens[first..end) and the end-of-block symbol with the codebooks. */
static int emit_tokens(ark_bit_writer_t *bw, const uint32_t *tokens,
                       size_t first, size_t end, const ark_codebook_t *lit_book,
                       const ark_codebook_t *dist_book)
{
	size_t k;

	for (k = first; k < end; k++) {
		uint32_t t;
		unsigned int li;
		unsigned int ds;
		uint32_t d;

		t = tokens[k];
		if ((t & ARK_TOKEN_MATCH) == 0U) {
			if (emit_code_symbol(bw, lit_book, t) != 0)
				return -1;
			continue;
		}
		li = token_len_index(t);
		ds = token_dist_sym(t);
		d = (t & ARK_TOKEN_DIST_MASK) + 1U;
		if (emit_code_symbol(bw, lit_book, 257U + li) != 0)
			return -1;
		if (g_len_extra[li] != 0U &&
		    bw_put_bits(bw, (uint16_t)(token_bytes(t) - g_len_base[li]),
		                g_len_extra[li]) != 0)
			return -1;
		if (emit_code_symbol(bw, dist_book, ds) != 0)
			return -1;
		if (g_dist_extra[ds] != 0U &&
		    bw_put_bits(bw, (uint16_t)(d - g_dist_base[ds]),
		                g_dist_extra[ds]) != 0)
			return -1;
	}
	return emit_code_symbol(bw, lit_book, 256U);
}

/*
 * Fill in the code lengths and HLIT/HDIST of plan from plan->freq and store
 * the exact size in bits of the dynamic block (3-bit block header, code
 * header and data) in *bits_out.
 */
static int plan_from_freq(ark_dynamic_plan_t *plan, size_t *bits_out)
{
	ark_cl_plan_t cp;
	size_t i;

	if (build_length_limited_lengths(plan->freq.lit, 286U, plan->lit_len,
	                                 15U) != 0)
		return -1;
	if (build_length_limited_lengths(plan->freq.dist, 30U, plan->dist_len,
	                                 15U) != 0)
		return -1;

	plan->hlit_count = 257U;
	for (i = 257U; i < 286U; i++) {
		if (plan->lit_len[i] != 0U)
			plan->hlit_count = i + 1U;
	}
	plan->hdist_count = 1U;
	for (i = 1U; i < 30U; i++) {
		if (plan->dist_len[i] != 0U)
			plan->hdist_count = i + 1U;
	}

	if (cl_plan_build(plan->lit_len, plan->hlit_count, plan->dist_len,
	                  plan->hdist_count, &cp) != 0)
		return -1;
	*bits_out = cl_plan_bits(&cp) +
	            huff_data_bits(&plan->freq, plan->lit_len, plan->dist_len);
	return 0;
}

/* Exact size in bits of a fixed-Huffman block with symbol counts freq. */
static size_t fixed_block_bits(const ark_freq_t *freq)
{
	size_t bits;
	size_t i;

	bits = 3U + freq_extra_bits(freq);
	for (i = 0; i < 286U; i++) {
		unsigned int nbits;

		nbits = i <= 143U ? 8U : i <= 255U ? 9U : i <= 279U ? 7U : 8U;
		bits += (size_t)freq->lit[i] * nbits;
	}
	for (i = 0; i < 30U; i++)
		bits += (size_t)freq->dist[i] * 5U;
	return bits;
}

/* Build the RFC 1951 fixed lit/len and distance codebooks (section 3.2.6). */
static int build_fixed_codebooks(ark_codebook_t *lit_book,
                                 ark_codebook_t *dist_book)
{
	uint8_t lit_len[288];
	uint8_t dist_len[30];
	size_t i;

	for (i = 0; i < 288U; i++)
		lit_len[i] = i <= 143U   ? 8U
		             : i <= 255U ? 9U
		             : i <= 279U ? 7U
		                         : 8U;
	for (i = 0; i < 30U; i++)
		dist_len[i] = 5U;
	if (build_codes(lit_len, 288U, 9U, lit_book) != 0)
		return -1;
	return build_codes(dist_len, 30U, 5U, dist_book);
}

/*
 * Choose the next block from tokens[first..count): grow it through the
 * input lengths in g_default_block_candidates (each rounded up to a token
 * boundary), cost each as a dynamic block, and keep the cheapest per input
 * byte (the first on ties). Stores the end token in *end, the plan in
 * *plan and its dynamic size in bits in *bits.
 */
static int choose_block(const uint32_t *tokens, size_t first, size_t count,
                        ark_dynamic_plan_t *plan, size_t *end, size_t *bits)
{
	ark_freq_t freq;
	uint64_t best_score;
	size_t bytes;
	size_t k;
	size_t i;

	for (i = 0; i < 286U; i++)
		freq.lit[i] = 0U;
	for (i = 0; i < 30U; i++)
		freq.dist[i] = 0U;
	best_score = UINT64_MAX;
	bytes = 0U;
	k = first;
	for (i = 0; i < sizeof(g_default_block_candidates) /
	                    sizeof(g_default_block_candidates[0]);
	     i++) {
		ark_dynamic_plan_t cand;
		size_t cand_bits;
		uint64_t score;

		while (k < count && bytes < g_default_block_candidates[i]) {
			token_count(tokens[k], &freq);
			bytes += token_bytes(tokens[k]);
			k++;
		}
		cand.freq = freq;
		cand.freq.lit[256]++;
		if (plan_from_freq(&cand, &cand_bits) != 0)
			return -1;
		score = ((uint64_t)cand_bits * 65536U) / bytes;
		if (score < best_score) {
			best_score = score;
			*plan = cand;
			*end = k;
			*bits = cand_bits;
		}
		if (k == count)
			break;
	}
	return 0;
}

/*
 * Write enc->tokens[0..count) as blocks cut from the token stream
 * (choose_block) after the bits already in bw; final marks the last block.
 * A block is written with the fixed codes when that is smaller than its
 * dynamic encoding.
 */
static int emit_token_blocks(const ark_deflate_enc_t *enc, size_t count,
                             ark_bit_writer_t *bw, unsigned int final)
{
	ark_codebook_t fixed_lit;
	ark_codebook_t fixed_dist;
	int fixed_ready;
	size_t first;

	fixed_ready = 0;
	first = 0U;
	while (first < count) {
		ark_dynamic_plan_t plan;
		size_t end;
		size_t bits;

		end = first;
		bits = 0U;
		if (choose_block(enc->tokens, first, count, &plan, &end,
		                 &bits) != 0 ||
		    end <= first)
			return -1;
		if (bw_put_bits(bw, (uint16_t)(end == count ? final : 0U),
		                1U) != 0)
			return -1;
		if (fixed_block_bits(&plan.freq) < bits) {
			if (!fixed_ready) {
				if (build_fixed_codebooks(&fixed_lit,
				                          &fixed_dist) != 0)
					return -1;
				fixed_ready = 1;
			}
			if (bw_put_bits(bw, 1U, 2U) != 0 ||
			    emit_tokens(bw, enc->tokens, first, end, &fixed_lit,
			                &fixed_dist) != 0)
				return -1;
		} else {
			ark_codebook_t lit_book;
			ark_codebook_t dist_book;

			if (bw_put_bits(bw, 2U, 2U) != 0 ||
			    emit_dynamic_header(bw, plan.lit_len, plan.dist_len,
			                        plan.hlit_count,
			                        plan.hdist_count, &lit_book,
			                        &dist_book) != 0 ||
			    emit_tokens(bw, enc->tokens, first, end, &lit_book,
			                &dist_book) != 0)
				return -1;
		}
		first = end;
	}
	return 0;
}

/*
 * Compress at levels 1-9: one parse of the whole input into tokens with the
 * level's search, then blocks cut from the token stream. Deterministic for
 * a given input (§13.1). See ARCHITECTURE.md section 7.2.
 */
static int compress_tokens(ark_deflate_enc_t *enc, const uint8_t *src,
                           size_t src_len, uint8_t *dst, size_t dst_cap)
{
	ark_bit_writer_t bw;
	size_t count;

	if (src_len == 0U)
		return emit_stored_blocks(src, src_len, dst, dst_cap);

	match_finder_begin_parse(&enc->mf);
	count = parse_tokens(enc, src, 0U, src_len);
	bw.dst = dst;
	bw.cap = dst_cap;
	bw.pos = 0;
	bw.bits = 0;
	bw.nbits = 0;
	if (emit_token_blocks(enc, count, &bw, 1U) != 0 ||
	    bw_flush_to_byte(&bw) != 0)
		return -1;
	return bw.pos > (size_t)INT_MAX ? -1 : (int)bw.pos;
}

/* Store v at p as 8 little-endian bytes without memcpy. */
static void store_u64_le(uint8_t *p, uint64_t v)
{
	unsigned int i;

	for (i = 0; i < 8U; i++)
		p[i] = (uint8_t)(v >> (i * 8U));
}

/*
 * Copy a len-byte match that starts dist bytes back. Source and destination
 * overlap whenever dist < len, so the copy runs forward: 8-byte words only
 * when dist >= 8 (a word never reads bytes it writes), a fill for dist 1,
 * and single bytes otherwise. Never writes past d[len - 1].
 */
static void copy_match(uint8_t *d, size_t dist, size_t len)
{
	const uint8_t *s;

	s = d - dist;
	if (dist == 1U) {
		uint8_t v;

		v = s[0];
		while (len-- > 0U)
			*d++ = v;
		return;
	}
	if (dist >= 8U) {
		while (len >= 8U) {
			store_u64_le(d, load_u64_le(s));
			d += 8;
			s += 8;
			len -= 8U;
		}
	}
	while (len-- > 0U)
		*d++ = *s++;
}

/*
 * Decode one Huffman-coded Deflate block until end-of-block marker. max_dist
 * is the decoder's window: a back-reference further than that is invalid.
 */
static int decode_huffman_block(ark_bit_reader_t *br, const uint32_t *lit_tab,
                                unsigned int lit_root, const uint32_t *dist_tab,
                                unsigned int dist_root, size_t max_dist,
                                uint8_t *dst, size_t dst_cap, size_t *dst_pos)
{
	size_t out;

	out = *dst_pos;
	for (;;) {
		unsigned int sym;
		unsigned int li;
		unsigned int dsym;
		size_t len;
		size_t dist;
		uint16_t extra;

		if (inflate_decode_sym(br, lit_tab, lit_root, &sym) != 0)
			return -1;
		if (sym < 256U) {
			if (out >= dst_cap)
				return ARK_INFLATE_ERR_OUTPUT;
			dst[out++] = (uint8_t)sym;
			continue;
		}
		if (sym == 256U) {
			*dst_pos = out;
			return 0;
		}
		if (sym > 285U)
			return -1;

		li = sym - 257U;
		len = g_len_base[li];
		if (g_len_extra[li] != 0U) {
			if (br_get_bits(br, g_len_extra[li], &extra) != 0)
				return -1;
			len += extra;
		}
		/*
		 * RFC 1951 section 3.2.5: code 284 covers lengths 227..257;
		 * 258 is code 285 only. Pre-v1.1.0 ark wrote 258 as 284 + 31;
		 * such streams are rejected (ARCHITECTURE.md section 7.4).
		 */
		if (sym == 284U && len == 258U)
			return -1;
		if (inflate_decode_sym(br, dist_tab, dist_root, &dsym) != 0)
			return -1;
		if (dsym > 29U)
			return -1;
		dist = g_dist_base[dsym];
		if (g_dist_extra[dsym] != 0U) {
			if (br_get_bits(br, g_dist_extra[dsym], &extra) != 0)
				return -1;
			dist += extra;
		}

		/*
		 * SAFETY: match copy must reference already-produced bytes
		 * inside the window and fit in dst. Distances beyond the output
		 * so far or the window are malformed input; lengths beyond
		 * dst_cap are an output overflow. Both must fail hard.
		 */
		if (dist > out || dist > max_dist)
			return -1;
		if (len > dst_cap - out)
			return ARK_INFLATE_ERR_OUTPUT;
		copy_match(dst + out, dist, len);
		out += len;
	}
}

/*
 * Build RFC 1951 fixed-Huffman decode tables (section 3.2.6). Called at
 * most once per inflate_window call, on the first fixed block;
 * the tables live in the caller's frame, so no state outlives the call.
 */
static int build_fixed_decode_tables(uint32_t *lit_tab, uint32_t *dist_tab)
{
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

	if (inflate_table_build(lit_tab, 1U << ARK_INFLATE_FIXED_LIT_ROOT,
	                        lit_len, 288U, ARK_INFLATE_FIXED_LIT_ROOT,
	                        ARK_TREE_LITLEN) != 0)
		return -1;
	if (inflate_table_build(dist_tab, 1U << ARK_INFLATE_FIXED_DIST_ROOT,
	                        dist_len, 32U, ARK_INFLATE_FIXED_DIST_ROOT,
	                        ARK_TREE_DIST) != 0)
		return -1;
	return 0;
}

/* Decode one dynamic-Huffman Deflate block. */
static int decode_dynamic_block(ark_bit_reader_t *br, size_t max_dist,
                                uint8_t *dst, size_t dst_cap, size_t *dst_pos)
{
	uint32_t cl_tab[ARK_INFLATE_CL_TABLE];
	uint32_t lit_tab[ARK_INFLATE_LIT_TABLE];
	uint32_t dist_tab[ARK_INFLATE_DIST_TABLE];
	uint8_t cl_len[19];
	uint8_t lens[288 + 32];
	uint16_t v;
	size_t hlit;
	size_t hdist;
	size_t hclen;
	size_t n;
	size_t i;

	for (i = 0; i < 19U; i++)
		cl_len[i] = 0U;

	if (br_get_bits(br, 5U, &v) != 0)
		return -1;
	hlit = (size_t)v + 257U;
	if (br_get_bits(br, 5U, &v) != 0)
		return -1;
	hdist = (size_t)v + 1U;
	if (br_get_bits(br, 4U, &v) != 0)
		return -1;
	hclen = (size_t)v + 4U;

	if (hlit > 286U || hdist > 32U)
		return -1;

	for (i = 0; i < hclen; i++) {
		if (br_get_bits(br, 3U, &v) != 0)
			return -1;
		cl_len[g_cl_order[i]] = (uint8_t)v;
	}
	if (inflate_table_build(cl_tab, ARK_INFLATE_CL_TABLE, cl_len, 19U,
	                        ARK_INFLATE_CL_ROOT, ARK_TREE_CODELEN) != 0)
		return -1;

	n = 0U;
	while (n < hlit + hdist) {
		unsigned int sym;
		uint8_t fill;
		size_t rep;

		if (inflate_decode_sym(br, cl_tab, ARK_INFLATE_CL_ROOT, &sym) !=
		    0)
			return -1;
		if (sym <= 15U) {
			lens[n++] = (uint8_t)sym;
			continue;
		}
		if (sym == 16U) {
			if (n == 0U)
				return -1;
			if (br_get_bits(br, 2U, &v) != 0)
				return -1;
			fill = lens[n - 1U];
			rep = (size_t)v + 3U;
		} else if (sym == 17U) {
			if (br_get_bits(br, 3U, &v) != 0)
				return -1;
			fill = 0U;
			rep = (size_t)v + 3U;
		} else if (sym == 18U) {
			if (br_get_bits(br, 7U, &v) != 0)
				return -1;
			fill = 0U;
			rep = (size_t)v + 11U;
		} else {
			return -1;
		}
		if (rep > hlit + hdist - n)
			return -1;
		for (i = 0; i < rep; i++)
			lens[n++] = fill;
	}

	/* RFC 1951 section 3.2.7: every block must be able to end. */
	if (lens[256] == 0U)
		return -1;
	if (inflate_table_build(lit_tab, ARK_INFLATE_LIT_TABLE, lens, hlit,
	                        ARK_INFLATE_LIT_ROOT, ARK_TREE_LITLEN) != 0)
		return -1;
	if (inflate_table_build(dist_tab, ARK_INFLATE_DIST_TABLE, lens + hlit,
	                        hdist, ARK_INFLATE_DIST_ROOT,
	                        ARK_TREE_DIST) != 0)
		return -1;

	return decode_huffman_block(br, lit_tab, ARK_INFLATE_LIT_ROOT, dist_tab,
	                            ARK_INFLATE_DIST_ROOT, max_dist, dst,
	                            dst_cap, dst_pos);
}

/*
 * Decode one RFC 1951 stored block into dst (section 3.2.4). The bit reader
 * may hold input bytes read ahead; after dropping to a byte boundary they
 * are given back so LEN, NLEN and the payload are read from the input.
 */
static int decode_stored_block(ark_bit_reader_t *br, uint8_t *dst,
                               size_t dst_cap, size_t *dst_pos)
{
	const uint8_t *p;
	size_t len;
	size_t nlen;
	size_t i;

	br->nbits -= br->nbits & 7U;
	br->pos -= br->nbits >> 3;
	br->bits = 0U;
	br->nbits = 0U;

	if (br->len - br->pos < 4U)
		return -1;
	p = br->src + br->pos;
	len = (size_t)p[0] | ((size_t)p[1] << 8);
	nlen = (size_t)p[2] | ((size_t)p[3] << 8);
	br->pos += 4U;
	if ((len ^ 0xffffU) != nlen)
		return -1;
	if (len > dst_cap - *dst_pos)
		return ARK_INFLATE_ERR_OUTPUT;
	if (len > br->len - br->pos)
		return -1;

	for (i = 0; i < len; i++)
		dst[*dst_pos + i] = br->src[br->pos + i];
	*dst_pos += len;
	br->pos += len;
	return 0;
}

/*
 * ark_deflate_bound - Return safe maximum compressed size for src_len bytes.
 *
 * The bound accounts for stored-block framing in the worst incompressible
 * case (RFC 1951) and includes one-byte headroom for bit padding. Returns 0
 * when the bound does not fit in size_t. See ARCHITECTURE.md sections 7.1,
 * 7.2 and 7.4.
 */
size_t ark_deflate_bound(size_t src_len)
{
	size_t blocks;
	size_t overhead;

	/* Ceiling division; src_len + 65534 would wrap near SIZE_MAX. */
	blocks = src_len / 65535U + (src_len % 65535U != 0U ? 1U : 0U);
	if (blocks == 0U)
		blocks = 1U;
	/* blocks <= SIZE_MAX / 65535, so blocks * 5 + 1 cannot wrap. */
	overhead = blocks * 5U + 1U;
	if (src_len > SIZE_MAX - overhead)
		return 0U;
	return src_len + overhead;
}

/* Return 1 when params describe an encoder this build supports. */
static int enc_params_valid(const ark_deflate_params_t *params)
{
	if (params == NULL)
		return 0;
	if (params->level < ARK_DEFLATE_LEVEL_NONE ||
	    params->level > ARK_DEFLATE_LEVEL_BEST)
		return 0;
	if (params->window_bits < ARK_DEFLATE_MIN_WINDOW_BITS ||
	    params->window_bits > ARK_DEFLATE_MAX_WINDOW_BITS)
		return 0;
	if (params->max_input == 0U ||
	    params->max_input > ARK_DEFLATE_MAX_INPUT)
		return 0;
	if (params->streaming != 0 && params->streaming != 1)
		return 0;
	return 1;
}

/*
 * Streaming buffers: win keeps window_size bytes of history (none at level
 * 0, which never matches) plus up to max_input bytes of new input, with
 * room to slide by whole windows (stream_slide); obuf holds one step's
 * output, at most stored blocks of max_input bytes plus the bits carried
 * in, a sync-flush marker and an empty final block.
 */
static size_t enc_win_cap(const ark_deflate_params_t *params)
{
	if (params->level == ARK_DEFLATE_LEVEL_NONE)
		return params->max_input;
	return 2U * ((size_t)1U << params->window_bits) + params->max_input;
}

static size_t enc_obuf_cap(const ark_deflate_params_t *params)
{
	return ark_deflate_bound(params->max_input) + 16U;
}

/*
 * Encoder memory size: the struct, then for levels 1-9 head and prev in its
 * tables member and one token per input byte; level 0 stores and needs no
 * tables. The hash size follows the window, so window_bits 15 keeps the
 * 15-bit hash of earlier releases. Streaming adds win and obuf.
 * max_input <= ARK_DEFLATE_MAX_INPUT keeps the sum small.
 */
static size_t enc_mem_size(const ark_deflate_params_t *params)
{
	size_t size;

	size = sizeof(struct ark_deflate_enc);
	if (params->level != ARK_DEFLATE_LEVEL_NONE)
		size +=
		    2U * ((size_t)1U << params->window_bits) * sizeof(int32_t) +
		    params->max_input * sizeof(uint32_t);
	if (params->streaming)
		size += enc_win_cap(params) + enc_obuf_cap(params);
	return size;
}

size_t ark_deflate_enc_size(const ark_deflate_params_t *params)
{
	if (!enc_params_valid(params))
		return 0U;
	return enc_mem_size(params);
}

ark_deflate_enc_t *ark_deflate_enc_init(void *mem, size_t mem_len,
                                        const ark_deflate_params_t *params)
{
	ark_deflate_enc_t *enc;
	int32_t *tail;

	if (mem == NULL || !enc_params_valid(params))
		return NULL;
	if ((uintptr_t)mem % _Alignof(uint64_t) != 0U)
		return NULL;
	if (mem_len < enc_mem_size(params))
		return NULL;

	enc = mem;
	enc->level = params->level;
	enc->streaming = params->streaming;
	enc->lp = g_level_params[params->level];
	enc->max_input = params->max_input;
	enc->mf.hash_bits = params->window_bits;
	enc->mf.window_size = (size_t)1U << params->window_bits;
	enc->mf.head = NULL;
	enc->mf.prev = NULL;
	enc->tokens = NULL;
	tail = enc->tables;
	if (enc->level != ARK_DEFLATE_LEVEL_NONE) {
		size_t i;

		enc->mf.head = enc->tables;
		enc->mf.prev = enc->tables + ((size_t)1U << enc->mf.hash_bits);
		/* The token buffer follows prev; C11 6.5p7 lets the unsigned
		 * type access int32_t storage. */
		enc->tokens = (uint32_t *)(enc->mf.prev + enc->mf.window_size);
		tail = enc->mf.prev + enc->mf.window_size + enc->max_input;
		/* prev is never read before written; clearing once keeps it
		 * defined. */
		for (i = 0; i < enc->mf.window_size; i++)
			enc->mf.prev[i] = -1;
		match_finder_begin_parse(&enc->mf);
	}
	if (enc->streaming) {
		enc->s.win = (uint8_t *)tail;
		enc->s.win_cap = enc_win_cap(params);
		enc->s.hist = enc->level == ARK_DEFLATE_LEVEL_NONE
		                  ? 0U
		                  : enc->mf.window_size;
		enc->s.obuf = enc->s.win + enc->s.win_cap;
		enc->s.obuf_cap = enc_obuf_cap(params);
		ark_deflate_enc_reset(enc, 0);
	}
	return enc;
}

/*
 * ark_deflate_enc_oneshot - Compress one buffer into a raw RFC 1951 stream.
 *
 * Levels 1-9 parse the input once (greedy matching at 1-3, lazy at 4-9,
 * with longer searches at higher levels) and write blocks whose lengths and
 * codes (dynamic or fixed Huffman) are chosen by exact cost; level 0 writes
 * stored blocks only. For incompressible input, falls back to stored blocks
 * when that yields smaller output. See ARCHITECTURE.md sections 7.2 and
 * 7.4.
 */
ark_deflate_status_t ark_deflate_enc_oneshot(ark_deflate_enc_t *enc,
                                             const uint8_t *src, size_t src_len,
                                             uint8_t *dst, size_t dst_cap,
                                             size_t *dst_len)
{
	int fixed_len;

	if (dst_len == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*dst_len = 0U;
	if (enc == NULL || dst == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	if (src_len > enc->max_input)
		return ARK_DEFLATE_ERR_USAGE;
	if (src_len != 0U && src == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	if (dst_cap < ark_deflate_bound(src_len))
		return ARK_DEFLATE_ERR_OUTPUT;

	if (enc->level == ARK_DEFLATE_LEVEL_NONE)
		fixed_len = -1;
	else
		fixed_len = compress_tokens(enc, src, src_len, dst, dst_cap);
	/* The parse reused the match finder: the stream starts over. */
	ark_deflate_enc_reset(enc, 0);

	/*
	 * ARCHITECTURE.md section 7.2: for incompressible data, emit stored
	 * blocks whenever compressed output is not smaller than input.
	 */
	if (fixed_len < 0 || (size_t)fixed_len >= src_len) {
		int stored_len;

		stored_len = emit_stored_blocks(src, src_len, dst, dst_cap);
		if (stored_len < 0)
			return ARK_DEFLATE_ERR_OUTPUT;
		*dst_len = (size_t)stored_len;
		return ARK_DEFLATE_OK;
	}

	*dst_len = (size_t)fixed_len;
	return ARK_DEFLATE_OK;
}

/* Bit writer over the stream's staging buffer, continuing its bits. */
static void stream_bw_load(const ark_enc_stream_t *s, ark_bit_writer_t *bw)
{
	bw->dst = s->obuf;
	bw->cap = s->obuf_cap;
	bw->pos = s->obuf_len;
	bw->bits = s->bits;
	bw->nbits = s->nbits;
}

static void stream_bw_store(ark_enc_stream_t *s, const ark_bit_writer_t *bw)
{
	s->obuf_len = bw->pos;
	s->bits = bw->bits;
	s->nbits = bw->nbits;
}

/*
 * Compress the input taken so far, win[start..fill), into obuf as blocks
 * after the bits carried in; final marks the stream's last block. Matches
 * reach into the history before start. Like the one-shot call, falls back
 * to stored blocks when compressing does not make the piece smaller.
 */
static int stream_step(ark_deflate_enc_t *enc, unsigned int final)
{
	ark_enc_stream_t *s;
	ark_bit_writer_t bw;
	ark_bit_writer_t saved;
	size_t pend;
	int rc;

	s = &enc->s;
	pend = s->fill - s->start;
	stream_bw_load(s, &bw);
	saved = bw;
	rc = -1;
	if (enc->level != ARK_DEFLATE_LEVEL_NONE) {
		size_t count;

		/* History not in the chains yet: the last two positions of the
		 * previous piece, or a preset dictionary. */
		while (s->ins < s->start && s->ins + 2U < s->fill)
			(void)insert_hash(s->win, s->fill, s->ins++, &enc->mf);
		count = parse_tokens(enc, s->win, s->start, s->fill);
		if (s->fill >= 2U && s->ins < s->fill - 2U)
			s->ins = s->fill - 2U;
		rc = emit_token_blocks(enc, count, &bw, final);
		if (rc == 0 && (bw.pos - saved.pos) * 8U + bw.nbits >=
		                   pend * 8U + saved.nbits)
			rc = -1;
	}
	if (rc != 0) {
		bw = saved;
		if (emit_stored(&bw, s->win + s->start, pend, final) != 0)
			return -1;
	}
	stream_bw_store(s, &bw);
	s->start = s->fill;
	return 0;
}

/*
 * Make room in a full win (nothing pending): keep the last window_size to
 * 2 * window_size - 1 bytes, moving by a multiple of window_size so prev
 * slots (indexed by position & (window_size - 1)) stay in place, and move
 * every hash position with them; positions that fall off become -1.
 */
static void stream_slide(ark_deflate_enc_t *enc)
{
	ark_enc_stream_t *s;
	size_t shift;
	size_t n;
	size_t i;

	s = &enc->s;
	if (s->hist == 0U) {
		s->start = 0U;
		s->fill = 0U;
		return;
	}
	shift = (s->fill - s->hist) / s->hist * s->hist;
	for (i = shift; i < s->fill; i++)
		s->win[i - shift] = s->win[i];
	n = (size_t)1U << enc->mf.hash_bits;
	for (i = 0; i < n; i++)
		enc->mf.head[i] = enc->mf.head[i] >= (int32_t)shift
		                      ? enc->mf.head[i] - (int32_t)shift
		                      : -1;
	for (i = 0; i < enc->mf.window_size; i++)
		enc->mf.prev[i] = enc->mf.prev[i] >= (int32_t)shift
		                      ? enc->mf.prev[i] - (int32_t)shift
		                      : -1;
	s->fill -= shift;
	s->start -= shift;
	s->ins = s->ins > shift ? s->ins - shift : 0U;
}

/*
 * Stage what a flush needs once all input is taken: SYNC compresses the
 * pending input and adds an empty stored block; FINISH compresses it into
 * the final block (an empty fixed block when nothing is pending) and pads
 * to a byte.
 */
static int stream_flush(ark_deflate_enc_t *enc, ark_deflate_flush_t flush)
{
	ark_enc_stream_t *s;
	ark_bit_writer_t bw;
	unsigned int final;

	s = &enc->s;
	final = flush == ARK_DEFLATE_FLUSH_FINISH ? 1U : 0U;
	if (s->fill > s->start) {
		if (stream_step(enc, final) != 0)
			return -1;
		stream_bw_load(s, &bw);
	} else {
		stream_bw_load(s, &bw);
		/* Empty final block: BFINAL, fixed codes, end of block. */
		if (final && (bw_put_bits(&bw, 3U, 3U) != 0 ||
		              bw_put_bits(&bw, 0U, 7U) != 0))
			return -1;
	}
	/* win is only a valid pointer here: the marker copies no bytes. */
	if (!final && emit_stored(&bw, s->win, 0U, 0U) != 0)
		return -1;
	if (final && bw_flush_to_byte(&bw) != 0)
		return -1;
	stream_bw_store(s, &bw);
	return 0;
}

/*
 * ark_deflate_enc_stream - Compress the next piece of a raw RFC 1951 stream.
 *
 * Staged output is returned first. Input is taken into win until max_input
 * bytes are pending or win is full, then compressed as one step
 * (stream_step) into obuf; the flush runs once all input is taken. See
 * ARCHITECTURE.md section 7.4.
 */
ark_deflate_status_t ark_deflate_enc_stream(ark_deflate_enc_t *enc,
                                            const uint8_t *in, size_t in_len,
                                            size_t *in_used, uint8_t *out,
                                            size_t out_cap, size_t *out_used,
                                            ark_deflate_flush_t flush)
{
	ark_enc_stream_t *s;
	ark_deflate_status_t st;
	size_t ip;
	size_t op;

	if (in_used == NULL || out_used == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*in_used = 0U;
	*out_used = 0U;
	if (enc == NULL || !enc->streaming || (in == NULL && in_len != 0U) ||
	    (out == NULL && out_cap != 0U) ||
	    (flush != ARK_DEFLATE_FLUSH_NONE &&
	     flush != ARK_DEFLATE_FLUSH_SYNC &&
	     flush != ARK_DEFLATE_FLUSH_FINISH))
		return ARK_DEFLATE_ERR_USAGE;
	s = &enc->s;
	if (s->mode == ARK_SE_ERROR)
		return ARK_DEFLATE_ERR_OUTPUT;
	if (s->mode != ARK_SE_ACTIVE && in_len != 0U)
		return ARK_DEFLATE_ERR_USAGE;
	if (s->mode == ARK_SE_DONE)
		return ARK_DEFLATE_END;

	ip = 0U;
	op = 0U;
	for (;;) {
		while (s->obuf_pos < s->obuf_len && op < out_cap)
			out[op++] = s->obuf[s->obuf_pos++];
		if (s->obuf_pos < s->obuf_len) {
			st = ARK_DEFLATE_NEED_OUTPUT;
			break;
		}
		s->obuf_pos = 0U;
		s->obuf_len = 0U;
		if (s->mode == ARK_SE_FINISHING) {
			s->mode = ARK_SE_DONE;
			st = ARK_DEFLATE_END;
			break;
		}
		if (ip < in_len) {
			size_t pend;
			size_t n;
			size_t i;

			pend = s->fill - s->start;
			if (pend != 0U &&
			    (pend == enc->max_input || s->fill == s->win_cap)) {
				if (stream_step(enc, 0U) != 0)
					goto fail;
				continue;
			}
			if (s->fill == s->win_cap)
				stream_slide(enc);
			n = in_len - ip;
			if (n > s->win_cap - s->fill)
				n = s->win_cap - s->fill;
			if (n > enc->max_input - pend)
				n = enc->max_input - pend;
			for (i = 0; i < n; i++)
				s->win[s->fill + i] = in[ip + i];
			s->fill += n;
			ip += n;
			s->synced = 0;
			s->started = 1;
			continue;
		}
		if (flush == ARK_DEFLATE_FLUSH_NONE) {
			st = ARK_DEFLATE_NEED_INPUT;
			break;
		}
		if (flush == ARK_DEFLATE_FLUSH_SYNC && s->synced) {
			/* This flush is written out completely. */
			s->synced = 0;
			st = ARK_DEFLATE_OK;
			break;
		}
		if (stream_flush(enc, flush) != 0)
			goto fail;
		s->started = 1;
		if (flush == ARK_DEFLATE_FLUSH_SYNC)
			s->synced = 1;
		else
			s->mode = ARK_SE_FINISHING;
	}
	*in_used = ip;
	*out_used = op;
	return st;
fail:
	/* Not reached with the buffer sizes of enc_mem_size(). */
	s->mode = ARK_SE_ERROR;
	*in_used = ip;
	*out_used = op;
	return ARK_DEFLATE_ERR_OUTPUT;
}

void ark_deflate_enc_reset(ark_deflate_enc_t *enc, int keep_history)
{
	ark_enc_stream_t *s;

	if (enc == NULL || !enc->streaming)
		return;
	s = &enc->s;
	s->obuf_len = 0U;
	s->obuf_pos = 0U;
	s->bits = 0U;
	s->nbits = 0U;
	s->mode = ARK_SE_ACTIVE;
	s->synced = 0;
	s->started = 0;
	/* Pending input is dropped; it is never in the hash chains. */
	s->fill = s->start;
	if (!keep_history || s->hist == 0U) {
		s->start = 0U;
		s->fill = 0U;
		s->ins = 0U;
		if (enc->level != ARK_DEFLATE_LEVEL_NONE)
			match_finder_begin_parse(&enc->mf);
	}
}

ark_deflate_status_t ark_deflate_enc_set_dict(ark_deflate_enc_t *enc,
                                              const uint8_t *dict,
                                              size_t dict_len)
{
	ark_enc_stream_t *s;
	size_t n;
	size_t i;

	if (enc == NULL || !enc->streaming ||
	    (dict == NULL && dict_len != 0U) || enc->s.started)
		return ARK_DEFLATE_ERR_USAGE;
	s = &enc->s;
	ark_deflate_enc_reset(enc, 0);
	n = dict_len < s->hist ? dict_len : s->hist;
	for (i = 0; i < n; i++)
		s->win[i] = dict[dict_len - n + i];
	s->start = n;
	s->fill = n;
	return ARK_DEFLATE_OK;
}

/*
 * Decode one raw RFC 1951 stream whose back-references stay within max_dist
 * bytes. Supports stored blocks (BTYPE 00), fixed-Huffman blocks (BTYPE 01),
 * and dynamic-Huffman blocks (BTYPE 10). Reserved BTYPE 11 and all malformed
 * input are rejected. Decoding stops after the final block; *src_used gets
 * the bytes up to and including the one holding its last bit, *dst_len the
 * output size. Returns 0, ARK_INFLATE_ERR_DATA or ARK_INFLATE_ERR_OUTPUT.
 */
static int inflate_window(const uint8_t *src, size_t src_len, uint8_t *dst,
                          size_t dst_cap, size_t max_dist, size_t *src_used,
                          size_t *dst_len)
{
	ark_bit_reader_t br;
	uint32_t fixed_lit_tab[1U << ARK_INFLATE_FIXED_LIT_ROOT];
	uint32_t fixed_dist_tab[1U << ARK_INFLATE_FIXED_DIST_ROOT];
	int fixed_ready;
	size_t out_pos;

	br.src = src;
	br.len = src_len;
	br.pos = 0;
	br.bits = 0;
	br.nbits = 0;
	out_pos = 0U;
	fixed_ready = 0;

	for (;;) {
		uint16_t bfinal;
		uint16_t btype;
		int rc;

		if (br_get_bits(&br, 1U, &bfinal) != 0)
			return ARK_INFLATE_ERR_DATA;
		if (br_get_bits(&br, 2U, &btype) != 0)
			return ARK_INFLATE_ERR_DATA;

		if (btype == 0U) {
			rc = decode_stored_block(&br, dst, dst_cap, &out_pos);
		} else if (btype == 1U) {
			if (!fixed_ready) {
				if (build_fixed_decode_tables(
				        fixed_lit_tab, fixed_dist_tab) != 0)
					return ARK_INFLATE_ERR_DATA;
				fixed_ready = 1;
			}
			rc = decode_huffman_block(
			    &br, fixed_lit_tab, ARK_INFLATE_FIXED_LIT_ROOT,
			    fixed_dist_tab, ARK_INFLATE_FIXED_DIST_ROOT,
			    max_dist, dst, dst_cap, &out_pos);
		} else if (btype == 2U) {
			rc = decode_dynamic_block(&br, max_dist, dst, dst_cap,
			                          &out_pos);
		} else {
			rc = ARK_INFLATE_ERR_DATA;
		}
		if (rc != 0)
			return rc;

		if (bfinal != 0U)
			break;
	}

	/*
	 * The 64-bit reader may have loaded bytes past the final block; whole
	 * bytes still in the bit buffer were not consumed.
	 */
	*src_used = br.pos - (size_t)(br.nbits >> 3);
	*dst_len = out_pos;
	return 0;
}

/* Map an internal decoder result to the public status. */
static ark_deflate_status_t inflate_status(int rc)
{
	if (rc == 0)
		return ARK_DEFLATE_OK;
	if (rc == ARK_INFLATE_ERR_OUTPUT)
		return ARK_DEFLATE_ERR_OUTPUT;
	return ARK_DEFLATE_ERR_DATA;
}

/*
 * ark_deflate_dec_oneshot - Decode one raw RFC 1951 stream with the full
 * 32 KiB window and report the input bytes it used. See ARCHITECTURE.md
 * section 7.4.
 */
ark_deflate_status_t ark_deflate_dec_oneshot(const uint8_t *src, size_t src_len,
                                             size_t *src_used, uint8_t *dst,
                                             size_t dst_cap, size_t *dst_len)
{
	size_t used;
	size_t len;
	int rc;

	if (src_used == NULL || dst_len == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*src_used = 0U;
	*dst_len = 0U;
	if ((src == NULL && src_len != 0U) || (dst == NULL && dst_cap != 0U))
		return ARK_DEFLATE_ERR_USAGE;

	rc = inflate_window(src, src_len, dst, dst_cap, ARK_DEFLATE_WINDOW_SIZE,
	                    &used, &len);
	if (rc != 0)
		return inflate_status(rc);
	*src_used = used;
	*dst_len = len;
	return ARK_DEFLATE_OK;
}

/*
 * Streaming decoder state machine (ark_deflate_dec_stream). Each state names
 * the next item to read; every state can stop for input or output space and
 * resume in a later call.
 */
typedef enum {
	ARK_SD_HEADER = 0, /* BFINAL and BTYPE */
	ARK_SD_STORED_LEN, /* LEN and NLEN of a stored block */
	ARK_SD_STORED_COPY,
	ARK_SD_TABLE,  /* HLIT, HDIST, HCLEN */
	ARK_SD_CLENS,  /* code-length code lengths */
	ARK_SD_LENS,   /* lit/len and distance code lengths */
	ARK_SD_CODES,  /* next lit/len symbol */
	ARK_SD_LIT,    /* decoded literal waiting for output space */
	ARK_SD_LENEXT, /* length extra bits */
	ARK_SD_DIST,   /* distance symbol */
	ARK_SD_DISTEXT,
	ARK_SD_COPY, /* match bytes waiting for output space */
	ARK_SD_DONE,
	ARK_SD_ERROR,
} ark_sd_mode_t;

/*
 * Streaming decoder state. The struct sits at the start of the caller's
 * memory; window holds the last window_size output bytes (a circular
 * buffer: whave valid bytes, next write at wnext), so matches can reach
 * output returned by earlier calls. The bit buffer only ever holds bits
 * pulled for the current item, so fewer than 8 remain after each item and
 * in_used is exact at the end of the stream.
 */
struct ark_deflate_dec {
	uint64_t bits;
	unsigned int nbits;
	ark_sd_mode_t mode;
	int last;
	const uint32_t *lit_tab;
	const uint32_t *dist_tab;
	unsigned int lit_root;
	unsigned int dist_root;
	size_t window_size;
	size_t whave;
	size_t wnext;
	size_t length;
	size_t dist;
	size_t index;
	size_t hlit;
	size_t hdist;
	size_t hclen;
	unsigned int len_index;
	int started;
	uint8_t literal;
	uint8_t cl_len[19];
	uint8_t lens[288 + 32];
	uint32_t cl_tab[ARK_INFLATE_CL_TABLE];
	uint32_t dyn_lit_tab[ARK_INFLATE_LIT_TABLE];
	uint32_t dyn_dist_tab[ARK_INFLATE_DIST_TABLE];
	uint32_t fixed_lit_tab[1U << ARK_INFLATE_FIXED_LIT_ROOT];
	uint32_t fixed_dist_tab[1U << ARK_INFLATE_FIXED_DIST_ROOT];
	uint8_t window[];
};

/* Input and output of one ark_deflate_dec_stream call. */
typedef struct {
	const uint8_t *in;
	size_t in_len;
	size_t ip;
	uint8_t *out;
	size_t out_cap;
	size_t op;
} ark_sd_io_t;

/* Pull input bytes until n (<= 32) bits are buffered; 0 when input ends. */
static int sd_need(ark_deflate_dec_t *d, ark_sd_io_t *io, unsigned int n)
{
	while (d->nbits < n) {
		if (io->ip == io->in_len)
			return 0;
		d->bits |= (uint64_t)io->in[io->ip++] << d->nbits;
		d->nbits += 8U;
	}
	return 1;
}

/* Take n buffered bits (n <= nbits, n <= 16). */
static unsigned int sd_take(ark_deflate_dec_t *d, unsigned int n)
{
	unsigned int v;

	v = (unsigned int)(d->bits & (((uint64_t)1U << n) - 1U));
	d->bits >>= n;
	d->nbits -= n;
	return v;
}

/*
 * Look up the next code of tab without consuming it. The bits above nbits
 * are zero, and a table entry is replicated for every value of the bits
 * after its code, so an entry whose length fits in nbits is the right one.
 * Returns 1 with *sym and *len set, 0 when more bits are needed, -1 for a
 * code the table does not contain.
 */
static int sd_peek(const ark_deflate_dec_t *d, const uint32_t *tab,
                   unsigned int root, unsigned int *sym, unsigned int *len)
{
	uint32_t e;
	unsigned int n;

	e = tab[d->bits & (((uint64_t)1U << root) - 1U)];
	if ((e & ARK_INFLATE_LINK) != 0U) {
		unsigned int sub_bits;

		if (d->nbits < root)
			return 0;
		sub_bits = (e >> 8) & 0xfU;
		e = tab[(e >> 16) + ((d->bits >> root) &
		                     (((uint64_t)1U << sub_bits) - 1U))];
		n = e & 0xffU;
		if (n == 0U)
			return d->nbits >= root + sub_bits ? -1 : 0;
		n += root;
	} else {
		n = e & 0xffU;
		if (n == 0U)
			return d->nbits >= root ? -1 : 0;
	}
	if (n > d->nbits)
		return 0;
	*sym = e >> 16;
	*len = n;
	return 1;
}

/*
 * Decode the next symbol of tab, pulling input as needed. Returns 1 with
 * *sym set, 0 at the end of the input (nothing consumed), -1 for an invalid
 * code.
 */
static int sd_symbol(ark_deflate_dec_t *d, ark_sd_io_t *io, const uint32_t *tab,
                     unsigned int root, unsigned int *sym)
{
	for (;;) {
		unsigned int len;
		int r;

		r = sd_peek(d, tab, root, sym, &len);
		if (r < 0)
			return -1;
		if (r > 0) {
			(void)sd_take(d, len);
			return 1;
		}
		if (!sd_need(d, io, d->nbits + 8U))
			return 0;
	}
}

/*
 * Output byte dist bytes back from the next output position: from this
 * call's output when it is there, otherwise from the history window.
 */
static uint8_t sd_back_byte(const ark_deflate_dec_t *d, const ark_sd_io_t *io,
                            size_t dist)
{
	if (dist <= io->op)
		return io->out[io->op - dist];
	return d->window[(d->wnext + d->window_size - (dist - io->op)) &
	                 (d->window_size - 1U)];
}

/* Append this call's output to the history window. */
static void sd_update_window(ark_deflate_dec_t *d, const uint8_t *out, size_t n)
{
	size_t i;

	if (out == NULL || n == 0U)
		return;
	if (n >= d->window_size) {
		for (i = 0; i < d->window_size; i++)
			d->window[i] = out[n - d->window_size + i];
		d->wnext = 0U;
		d->whave = d->window_size;
		return;
	}
	for (i = 0; i < n; i++) {
		d->window[d->wnext] = out[i];
		d->wnext = (d->wnext + 1U) & (d->window_size - 1U);
	}
	d->whave =
	    d->whave + n > d->window_size ? d->window_size : d->whave + n;
}

/* Finish a block: the stream ends after the final one. */
static ark_sd_mode_t sd_block_end(const ark_deflate_dec_t *d)
{
	return d->last ? ARK_SD_DONE : ARK_SD_HEADER;
}

/* Read the code lengths of a dynamic block and build its tables. */
static ark_deflate_status_t sd_read_lengths(ark_deflate_dec_t *d,
                                            ark_sd_io_t *io)
{
	while (d->index < d->hlit + d->hdist) {
		unsigned int sym;
		unsigned int len;
		unsigned int extra;
		size_t rep;
		uint8_t fill;
		int r;

		r = sd_peek(d, d->cl_tab, ARK_INFLATE_CL_ROOT, &sym, &len);
		if (r < 0)
			return ARK_DEFLATE_ERR_DATA;
		if (r == 0) {
			if (!sd_need(d, io, d->nbits + 8U))
				return ARK_DEFLATE_NEED_INPUT;
			continue;
		}
		if (sym <= 15U) {
			(void)sd_take(d, len);
			d->lens[d->index++] = (uint8_t)sym;
			continue;
		}
		/* A repeat code and its extra bits are taken together. */
		extra = g_cl_extra[sym];
		if (!sd_need(d, io, len + extra))
			return ARK_DEFLATE_NEED_INPUT;
		(void)sd_take(d, len);
		rep = sd_take(d, extra);
		if (sym == 16U) {
			if (d->index == 0U)
				return ARK_DEFLATE_ERR_DATA;
			fill = d->lens[d->index - 1U];
			rep += 3U;
		} else {
			fill = 0U;
			rep += sym == 17U ? 3U : 11U;
		}
		if (rep > d->hlit + d->hdist - d->index)
			return ARK_DEFLATE_ERR_DATA;
		while (rep-- > 0U)
			d->lens[d->index++] = fill;
	}

	/* RFC 1951 section 3.2.7: every block must be able to end. */
	if (d->lens[256] == 0U)
		return ARK_DEFLATE_ERR_DATA;
	if (inflate_table_build(d->dyn_lit_tab, ARK_INFLATE_LIT_TABLE, d->lens,
	                        d->hlit, ARK_INFLATE_LIT_ROOT,
	                        ARK_TREE_LITLEN) != 0 ||
	    inflate_table_build(d->dyn_dist_tab, ARK_INFLATE_DIST_TABLE,
	                        d->lens + d->hlit, d->hdist,
	                        ARK_INFLATE_DIST_ROOT, ARK_TREE_DIST) != 0)
		return ARK_DEFLATE_ERR_DATA;
	d->lit_tab = d->dyn_lit_tab;
	d->dist_tab = d->dyn_dist_tab;
	d->lit_root = ARK_INFLATE_LIT_ROOT;
	d->dist_root = ARK_INFLATE_DIST_ROOT;
	return ARK_DEFLATE_OK;
}

/*
 * Take n (<= 16) bits that br already holds. Only for sd_fast, which
 * refills once per item; the one-shot decoder keeps br_get_bits, so its
 * inlining there is not affected.
 */
static unsigned int sd_fast_take(ark_bit_reader_t *br, unsigned int n)
{
	unsigned int v;

	v = (unsigned int)(br->bits & (((uint64_t)1U << n) - 1U));
	br->bits >>= n;
	br->nbits -= n;
	return v;
}

/*
 * Fast path for ARK_SD_CODES while at least 8 input bytes and
 * ARK_DEFLATE_MAX_MATCH bytes of output space remain: one literal or match
 * per iteration with the one-shot decoder's 64-bit bit reader: one refill
 * gives at least 56 bits and an iteration reads at most 48. On exit the whole
 * bytes still in the bit buffer were read ahead in this call and are given
 * back, so fewer than 8 bits stay buffered, as after every slow-path item.
 * Returns ARK_DEFLATE_OK with d->mode set to continue, or ARK_DEFLATE_ERR_DATA.
 */
static ark_deflate_status_t sd_fast(ark_deflate_dec_t *d, ark_sd_io_t *io)
{
	ark_deflate_status_t st;
	ark_bit_reader_t br;

	br.src = io->in;
	br.len = io->in_len;
	br.pos = io->ip;
	br.bits = d->bits;
	br.nbits = d->nbits;
	st = ARK_DEFLATE_OK;
	while (br.len - br.pos >= 8U &&
	       io->out_cap - io->op >= ARK_DEFLATE_MAX_MATCH) {
		unsigned int sym;
		unsigned int li;
		size_t len;
		size_t dist;

		br_refill(&br);
		if (inflate_decode_sym(&br, d->lit_tab, d->lit_root, &sym) !=
		        0 ||
		    sym > 285U) {
			st = ARK_DEFLATE_ERR_DATA;
			break;
		}
		if (sym < 256U) {
			io->out[io->op++] = (uint8_t)sym;
			continue;
		}
		if (sym == 256U) {
			d->mode = sd_block_end(d);
			break;
		}
		li = sym - 257U;
		len =
		    (size_t)g_len_base[li] + sd_fast_take(&br, g_len_extra[li]);
		if (li == 27U && len == 258U) {
			st = ARK_DEFLATE_ERR_DATA;
			break;
		}
		if (inflate_decode_sym(&br, d->dist_tab, d->dist_root, &sym) !=
		        0 ||
		    sym > 29U) {
			st = ARK_DEFLATE_ERR_DATA;
			break;
		}
		dist = (size_t)g_dist_base[sym] +
		       sd_fast_take(&br, g_dist_extra[sym]);
		/* SAFETY: as in ARK_SD_DISTEXT. */
		if (dist > d->window_size || dist > d->whave + io->op) {
			st = ARK_DEFLATE_ERR_DATA;
			break;
		}
		if (dist <= io->op) {
			copy_match(io->out + io->op, dist, len);
			io->op += len;
		} else {
			while (len-- > 0U) {
				io->out[io->op] = sd_back_byte(d, io, dist);
				io->op++;
			}
		}
	}
	io->ip = br.pos - (br.nbits >> 3);
	d->nbits = br.nbits & 7U;
	d->bits = br.bits & (((uint64_t)1U << d->nbits) - 1U);
	return st;
}

/*
 * Run the state machine until the stream ends, the input runs out, the
 * output is full or the input is malformed.
 */
static ark_deflate_status_t sd_run(ark_deflate_dec_t *d, ark_sd_io_t *io)
{
	for (;;) {
		unsigned int v;
		unsigned int sym;
		int r;

		switch (d->mode) {
		case ARK_SD_HEADER:
			if (!sd_need(d, io, 3U))
				return ARK_DEFLATE_NEED_INPUT;
			d->last = (int)sd_take(d, 1U);
			v = sd_take(d, 2U);
			if (v == 0U) {
				/* Stored data starts at the next byte; fewer
				 * than 8 bits are buffered. */
				(void)sd_take(d, d->nbits);
				d->mode = ARK_SD_STORED_LEN;
			} else if (v == 1U) {
				d->lit_tab = d->fixed_lit_tab;
				d->dist_tab = d->fixed_dist_tab;
				d->lit_root = ARK_INFLATE_FIXED_LIT_ROOT;
				d->dist_root = ARK_INFLATE_FIXED_DIST_ROOT;
				d->mode = ARK_SD_CODES;
			} else if (v == 2U) {
				d->mode = ARK_SD_TABLE;
			} else {
				return ARK_DEFLATE_ERR_DATA;
			}
			break;
		case ARK_SD_STORED_LEN:
			if (!sd_need(d, io, 32U))
				return ARK_DEFLATE_NEED_INPUT;
			d->length = sd_take(d, 16U);
			if ((sd_take(d, 16U) ^ 0xffffU) != d->length)
				return ARK_DEFLATE_ERR_DATA;
			d->mode = ARK_SD_STORED_COPY;
			break;
		case ARK_SD_STORED_COPY:
			while (d->length > 0U) {
				if (io->op == io->out_cap)
					return ARK_DEFLATE_NEED_OUTPUT;
				if (io->ip == io->in_len)
					return ARK_DEFLATE_NEED_INPUT;
				io->out[io->op++] = io->in[io->ip++];
				d->length--;
			}
			d->mode = sd_block_end(d);
			break;
		case ARK_SD_TABLE:
			if (!sd_need(d, io, 14U))
				return ARK_DEFLATE_NEED_INPUT;
			d->hlit = (size_t)sd_take(d, 5U) + 257U;
			d->hdist = (size_t)sd_take(d, 5U) + 1U;
			d->hclen = (size_t)sd_take(d, 4U) + 4U;
			if (d->hlit > 286U)
				return ARK_DEFLATE_ERR_DATA;
			for (v = 0; v < 19U; v++)
				d->cl_len[v] = 0U;
			d->index = 0U;
			d->mode = ARK_SD_CLENS;
			break;
		case ARK_SD_CLENS:
			while (d->index < d->hclen) {
				if (!sd_need(d, io, 3U))
					return ARK_DEFLATE_NEED_INPUT;
				d->cl_len[g_cl_order[d->index++]] =
				    (uint8_t)sd_take(d, 3U);
			}
			if (inflate_table_build(
			        d->cl_tab, ARK_INFLATE_CL_TABLE, d->cl_len, 19U,
			        ARK_INFLATE_CL_ROOT, ARK_TREE_CODELEN) != 0)
				return ARK_DEFLATE_ERR_DATA;
			d->index = 0U;
			d->mode = ARK_SD_LENS;
			break;
		case ARK_SD_LENS: {
			ark_deflate_status_t st;

			st = sd_read_lengths(d, io);
			if (st != ARK_DEFLATE_OK)
				return st;
			d->mode = ARK_SD_CODES;
			break;
		}
		case ARK_SD_CODES:
			if (io->in_len - io->ip >= 8U &&
			    io->out_cap - io->op >= ARK_DEFLATE_MAX_MATCH) {
				if (sd_fast(d, io) != ARK_DEFLATE_OK)
					return ARK_DEFLATE_ERR_DATA;
				break;
			}
			r = sd_symbol(d, io, d->lit_tab, d->lit_root, &sym);
			if (r == 0)
				return ARK_DEFLATE_NEED_INPUT;
			if (r < 0 || sym > 285U)
				return ARK_DEFLATE_ERR_DATA;
			if (sym < 256U) {
				d->literal = (uint8_t)sym;
				d->mode = ARK_SD_LIT;
			} else if (sym == 256U) {
				d->mode = sd_block_end(d);
			} else {
				d->len_index = sym - 257U;
				d->mode = ARK_SD_LENEXT;
			}
			break;
		case ARK_SD_LIT:
			if (io->op == io->out_cap)
				return ARK_DEFLATE_NEED_OUTPUT;
			io->out[io->op++] = d->literal;
			d->mode = ARK_SD_CODES;
			break;
		case ARK_SD_LENEXT:
			if (!sd_need(d, io, g_len_extra[d->len_index]))
				return ARK_DEFLATE_NEED_INPUT;
			d->length = (size_t)g_len_base[d->len_index] +
			            sd_take(d, g_len_extra[d->len_index]);
			/* RFC 1951 section 3.2.5: 258 is code 285 only. */
			if (d->len_index == 27U && d->length == 258U)
				return ARK_DEFLATE_ERR_DATA;
			d->mode = ARK_SD_DIST;
			break;
		case ARK_SD_DIST:
			r = sd_symbol(d, io, d->dist_tab, d->dist_root, &sym);
			if (r == 0)
				return ARK_DEFLATE_NEED_INPUT;
			if (r < 0 || sym > 29U)
				return ARK_DEFLATE_ERR_DATA;
			d->len_index = sym;
			d->mode = ARK_SD_DISTEXT;
			break;
		case ARK_SD_DISTEXT:
			if (!sd_need(d, io, g_dist_extra[d->len_index]))
				return ARK_DEFLATE_NEED_INPUT;
			d->dist = (size_t)g_dist_base[d->len_index] +
			          sd_take(d, g_dist_extra[d->len_index]);
			/*
			 * SAFETY: a match must reference bytes already
			 * produced (this call's output or the history) and
			 * inside the window; anything else is malformed.
			 */
			if (d->dist > d->window_size ||
			    d->dist > d->whave + io->op)
				return ARK_DEFLATE_ERR_DATA;
			d->mode = ARK_SD_COPY;
			break;
		case ARK_SD_COPY:
			while (d->length > 0U) {
				if (io->op == io->out_cap)
					return ARK_DEFLATE_NEED_OUTPUT;
				io->out[io->op] = sd_back_byte(d, io, d->dist);
				io->op++;
				d->length--;
			}
			d->mode = ARK_SD_CODES;
			break;
		case ARK_SD_DONE:
			/* Padding bits of the last byte belong to the stream.
			 */
			(void)sd_take(d, d->nbits);
			return ARK_DEFLATE_END;
		case ARK_SD_ERROR:
		default:
			return ARK_DEFLATE_ERR_DATA;
		}
	}
}

size_t ark_deflate_dec_size(unsigned int window_bits)
{
	if (window_bits < ARK_DEFLATE_MIN_WINDOW_BITS ||
	    window_bits > ARK_DEFLATE_MAX_WINDOW_BITS)
		return 0U;
	return sizeof(struct ark_deflate_dec) + ((size_t)1U << window_bits);
}

ark_deflate_dec_t *ark_deflate_dec_init(void *mem, size_t mem_len,
                                        unsigned int window_bits)
{
	ark_deflate_dec_t *d;
	size_t size;

	size = ark_deflate_dec_size(window_bits);
	if (mem == NULL || size == 0U || mem_len < size)
		return NULL;
	if ((uintptr_t)mem % _Alignof(uint64_t) != 0U)
		return NULL;

	d = mem;
	d->window_size = (size_t)1U << window_bits;
	if (build_fixed_decode_tables(d->fixed_lit_tab, d->fixed_dist_tab) != 0)
		return NULL;
	ark_deflate_dec_reset(d, 0);
	return d;
}

void ark_deflate_dec_reset(ark_deflate_dec_t *dec, int keep_history)
{
	if (dec == NULL)
		return;
	dec->bits = 0U;
	dec->nbits = 0U;
	dec->mode = ARK_SD_HEADER;
	dec->last = 0;
	dec->lit_tab = dec->fixed_lit_tab;
	dec->dist_tab = dec->fixed_dist_tab;
	dec->lit_root = ARK_INFLATE_FIXED_LIT_ROOT;
	dec->dist_root = ARK_INFLATE_FIXED_DIST_ROOT;
	dec->length = 0U;
	dec->dist = 0U;
	dec->started = 0;
	if (!keep_history) {
		dec->whave = 0U;
		dec->wnext = 0U;
	}
}

/*
 * ark_deflate_dec_stream - Decode the next piece of a raw RFC 1951 stream.
 * See ARCHITECTURE.md section 7.4.
 */
ark_deflate_status_t ark_deflate_dec_stream(ark_deflate_dec_t *dec,
                                            const uint8_t *in, size_t in_len,
                                            size_t *in_used, uint8_t *out,
                                            size_t out_cap, size_t *out_used)
{
	ark_sd_io_t io;
	ark_deflate_status_t st;

	if (in_used == NULL || out_used == NULL)
		return ARK_DEFLATE_ERR_USAGE;
	*in_used = 0U;
	*out_used = 0U;
	if (dec == NULL || (in == NULL && in_len != 0U) ||
	    (out == NULL && out_cap != 0U))
		return ARK_DEFLATE_ERR_USAGE;

	io.in = in;
	io.in_len = in_len;
	io.ip = 0U;
	io.out = out;
	io.out_cap = out_cap;
	io.op = 0U;
	st = sd_run(dec, &io);
	if (st == ARK_DEFLATE_ERR_DATA)
		dec->mode = ARK_SD_ERROR;
	sd_update_window(dec, out, io.op);
	if (io.ip != 0U)
		dec->started = 1;
	*in_used = io.ip;
	*out_used = io.op;
	return st;
}

ark_deflate_status_t ark_deflate_dec_set_dict(ark_deflate_dec_t *dec,
                                              const uint8_t *dict,
                                              size_t dict_len)
{
	if (dec == NULL || (dict == NULL && dict_len != 0U) || dec->started)
		return ARK_DEFLATE_ERR_USAGE;
	dec->whave = 0U;
	dec->wnext = 0U;
	sd_update_window(dec, dict, dict_len);
	return ARK_DEFLATE_OK;
}

#ifdef ARK_DEFLATE_TEST
/*
 * ARK_DEFLATE_TEST-only accessors for encoder internals and a window-limited
 * decoder. They keep no state and are compiled out of production builds;
 * tests declare them locally.
 */

/*
 * ARK_DEFLATE_TEST only: decode like ark_deflate_dec_oneshot but reject any
 * back-reference further than 1 << window_bits bytes (strict window check
 * for encoder tests). ARK_DEFLATE_ERR_USAGE for window_bits outside 8..15.
 */
ark_deflate_status_t
ark_deflate_test_decompress_window(const uint8_t *src, size_t src_len,
                                   uint8_t *dst, size_t dst_cap,
                                   unsigned int window_bits, size_t *dst_len)
{
	size_t used;
	int rc;

	*dst_len = 0U;
	if (window_bits < ARK_DEFLATE_MIN_WINDOW_BITS ||
	    window_bits > ARK_DEFLATE_MAX_WINDOW_BITS)
		return ARK_DEFLATE_ERR_USAGE;
	rc = inflate_window(src, src_len, dst, dst_cap,
	                    (size_t)1U << window_bits, &used, dst_len);
	return inflate_status(rc);
}

/*
 * ARK_DEFLATE_TEST only: decode-table capacity for a lit/len (dist == 0) or
 * distance (dist != 0) table.
 */
size_t ark_deflate_test_table_cap(int dist)
{
	return dist ? ARK_INFLATE_DIST_TABLE : ARK_INFLATE_LIT_TABLE;
}

/*
 * ARK_DEFLATE_TEST only: build a dynamic lit/len or distance decode table
 * from code lengths into at most cap entries (cap <= the table capacity).
 * Returns 0 when it fits, -1 for an invalid code or a table larger than cap.
 */
int ark_deflate_test_table_fits(const uint8_t *lengths, size_t n_symbols,
                                int dist, size_t cap)
{
	uint32_t tab[ARK_INFLATE_LIT_TABLE];

	if (cap > ark_deflate_test_table_cap(dist))
		return -1;
	return inflate_table_build(tab, cap, lengths, n_symbols,
	                           dist ? ARK_INFLATE_DIST_ROOT
	                                : ARK_INFLATE_LIT_ROOT,
	                           dist ? ARK_TREE_DIST : ARK_TREE_LITLEN);
}

/*
 * ARK_DEFLATE_TEST only: RFC 1951 reference mapping of a match length
 * [3..258] to its length symbol and extra bits, which tests compare the
 * encoder's g_len_sym table against.
 */
static int length_symbol(size_t len, unsigned int *sym, unsigned int *extra_n,
                         uint16_t *extra_v)
{
	unsigned int i;

	if (len < ARK_DEFLATE_MIN_MATCH || len > ARK_DEFLATE_MAX_MATCH)
		return -1;
	/*
	 * RFC 1951 section 3.2.5: code 284 covers 227..257 and length 258 has
	 * its own code 285 with no extra bits. Code 284 with extra value 31
	 * also decodes as 258, so check 285 first rather than relying on the
	 * table scan order.
	 */
	if (len == ARK_DEFLATE_MAX_MATCH) {
		*sym = 285U;
		*extra_n = 0U;
		*extra_v = 0U;
		return 0;
	}
	for (i = 0; i < 28U; i++) {
		size_t base;
		size_t max;

		base = g_len_base[i];
		max = base + ((size_t)1U << g_len_extra[i]) - 1U;
		if (len < base || len > max)
			continue;
		*sym = 257U + i;
		*extra_n = g_len_extra[i];
		*extra_v = (uint16_t)(len - base);
		return 0;
	}
	return -1;
}

/* ARK_DEFLATE_TEST only: match length to length symbol + extra bits. */
int ark_deflate_test_length_symbol(size_t len, unsigned int *sym,
                                   unsigned int *extra_n, uint16_t *extra_v)
{
	return length_symbol(len, sym, extra_n, extra_v);
}

/*
 * ARK_DEFLATE_TEST only: lit/len and distance symbols the encoder's
 * tables give for a match of len (3..258) at dist (1..32768).
 */
void ark_deflate_test_token_symbols(size_t len, size_t dist,
                                    unsigned int *len_sym,
                                    unsigned int *dist_sym)
{
	uint32_t t;

	t = ARK_TOKEN_MATCH |
	    ((uint32_t)(len - ARK_DEFLATE_MIN_MATCH) << ARK_TOKEN_LEN_SHIFT) |
	    (uint32_t)(dist - 1U);
	*len_sym = 257U + token_len_index(t);
	*dist_sym = token_dist_sym(t);
}

/* ARK_DEFLATE_TEST only: equal low-order bytes for x = a ^ b != 0. */
size_t ark_deflate_test_equal_low_bytes(uint64_t x)
{
	return equal_low_bytes(x);
}

/*
 * ARK_DEFLATE_TEST only: check the hash chains of a streaming encoder.
 * Every chain, walked from its head while inside the window, must hold
 * strictly decreasing positions that were inserted (below ins) and hash to
 * the chain. Returns 1 when they do (always for level 0 or a one-shot
 * encoder), 0 otherwise.
 */
int ark_deflate_test_enc_chains_ok(const ark_deflate_enc_t *enc)
{
	const ark_enc_stream_t *s;
	size_t lo;
	size_t h;

	if (!enc->streaming || enc->level == ARK_DEFLATE_LEVEL_NONE)
		return 1;
	s = &enc->s;
	lo = s->fill > enc->mf.window_size ? s->fill - enc->mf.window_size : 0U;
	for (h = 0; h < ((size_t)1U << enc->mf.hash_bits); h++) {
		int32_t p;
		int32_t last;

		last = INT32_MAX;
		for (p = enc->mf.head[h]; p >= (int32_t)lo;
		     p = match_finder_prev_get(&enc->mf, (size_t)p)) {
			if (p >= last || (size_t)p >= s->ins ||
			    hash3(s->win + p, enc->mf.hash_bits) != h)
				return 0;
			last = p;
		}
	}
	return 1;
}

/* ARK_DEFLATE_TEST only: build length-limited Huffman code lengths. */
int ark_deflate_test_limit_lengths(const uint32_t *freq, size_t n_symbols,
                                   uint8_t *lengths, unsigned int max_bits)
{
	return build_length_limited_lengths(freq, n_symbols, lengths, max_bits);
}

/* ARK_DEFLATE_TEST only: code-length plan; returns CL lengths + HCLEN. */
int ark_deflate_test_cl_plan(const uint8_t *lit_len, size_t hlit,
                             const uint8_t *dist_len, size_t hdist,
                             uint8_t cl_len[19], size_t *hclen)
{
	ark_cl_plan_t cp;
	size_t i;

	if (cl_plan_build(lit_len, hlit, dist_len, hdist, &cp) != 0)
		return -1;
	for (i = 0; i < 19U; i++)
		cl_len[i] = cp.len[i];
	*hclen = cp.hclen;
	return 0;
}

/*
 * ARK_DEFLATE_TEST only: report the costed and the actually emitted size, in
 * bits, of a dynamic block header (including the 3-bit block header).
 */
int ark_deflate_test_header_bits(const uint8_t *lit_len, size_t hlit,
                                 const uint8_t *dist_len, size_t hdist,
                                 size_t *cost_bits, size_t *emitted_bits)
{
	ark_codebook_t lit_book;
	ark_codebook_t dist_book;
	ark_bit_writer_t bw;
	ark_cl_plan_t cp;
	uint8_t buf[1024];

	if (cl_plan_build(lit_len, hlit, dist_len, hdist, &cp) != 0)
		return -1;
	*cost_bits = cl_plan_bits(&cp);
	bw.dst = buf;
	bw.cap = sizeof(buf);
	bw.pos = 0U;
	bw.bits = 0U;
	bw.nbits = 0U;
	if (bw_put_bits(&bw, 2U << 1U, 3U) != 0)
		return -1;
	if (emit_dynamic_header(&bw, lit_len, dist_len, hlit, hdist, &lit_book,
	                        &dist_book) != 0)
		return -1;
	*emitted_bits = bw.pos * 8U + bw.nbits;
	return 0;
}
#endif
