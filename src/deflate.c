/*
 * deflate.c - RFC 1951 Deflate component implementation.
 *
 * Implements ark_deflate_bound, ark_deflate_compress, and
 * ark_deflate_decompress from deflate.h. This component performs pure
 * in-memory transformation only: no I/O and no component-owned allocation.
 * See ARCHITECTURE.md section 7.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate.h"

#define ARK_DEFLATE_MIN_MATCH 3U
#define ARK_DEFLATE_MAX_MATCH 258U
#define ARK_DEFLATE_WINDOW_SIZE 32768U
#define ARK_DEFLATE_HASH_BITS 15U
#define ARK_DEFLATE_HASH_SIZE (1U << ARK_DEFLATE_HASH_BITS)
#define ARK_DEFLATE_HASH_MASK (ARK_DEFLATE_HASH_SIZE - 1U)

#define ARK_DEFLATE_TABLE_BITS 15U
#define ARK_DEFLATE_TABLE_SIZE (1U << ARK_DEFLATE_TABLE_BITS)

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

typedef struct {
	int16_t sym[ARK_DEFLATE_TABLE_SIZE];
	uint8_t len[ARK_DEFLATE_TABLE_SIZE];
} ark_huff_table_t;

typedef struct {
	size_t len;
	size_t dist;
} ark_match_t;

typedef struct {
	int32_t head[ARK_DEFLATE_HASH_SIZE];
	int32_t prev[ARK_DEFLATE_WINDOW_SIZE];
	uint32_t head_gen[ARK_DEFLATE_HASH_SIZE];
	uint32_t prev_gen[ARK_DEFLATE_WINDOW_SIZE];
	uint32_t generation;
} ark_match_finder_t;

typedef struct {
	uint32_t lit[286];
	uint32_t dist[30];
} ark_freq_t;

typedef struct {
	size_t len;
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

/*
 * Match-finder state is thread-local so worker threads never share mutable
 * compressor state. See ARCHITECTURE.md §6.3.
 */
static _Thread_local ark_match_finder_t g_match_finder;

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

/* Pull bytes from src until at least n bits are available or input ends. */
static int br_ensure_bits(ark_bit_reader_t *br, unsigned int n)
{
	while (br->nbits < n) {
		if (br->pos >= br->len)
			break;
		br->bits |= ((uint64_t)br->src[br->pos++]) << br->nbits;
		br->nbits += 8U;
	}
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

/* Build a direct decode table from canonical Huffman code lengths. */
static int huff_build(ark_huff_table_t *tab, const uint8_t *lengths,
                      size_t n_symbols, unsigned int max_bits)
{
	uint16_t count[16];
	uint16_t next_code[16];
	unsigned int bits;
	uint16_t code;
	size_t i;

	if (max_bits > ARK_DEFLATE_TABLE_BITS)
		return -1;

	for (i = 0; i < ARK_DEFLATE_TABLE_SIZE; i++) {
		tab->sym[i] = -1;
		tab->len[i] = 0;
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
		uint16_t rev;
		unsigned int fill_shift;
		unsigned int fill_count;
		unsigned int j;

		len = lengths[i];
		if (len == 0U)
			continue;
		rev = bit_reverse(next_code[len], len);
		next_code[len]++;

		fill_shift = ARK_DEFLATE_TABLE_BITS - len;
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

/* Decode one Huffman symbol from the bitstream using a direct lookup table. */
static int huff_decode(ark_bit_reader_t *br, const ark_huff_table_t *tab,
                       int *sym)
{
	uint16_t idx;
	uint8_t n;

	if (br_ensure_bits(br, 1U) != 0)
		return -1;
	(void)br_ensure_bits(br, ARK_DEFLATE_TABLE_BITS);

	idx = (uint16_t)(br->bits & (ARK_DEFLATE_TABLE_SIZE - 1U));
	n = tab->len[idx];
	if (n == 0U)
		return -1;
	if (br_ensure_bits(br, n) != 0)
		return -1;

	*sym = tab->sym[idx];
	br->bits >>= n;
	br->nbits -= n;
	return *sym >= 0 ? 0 : -1;
}

/* Emit one RFC 1951 stored block, splitting as needed at 65535 bytes. */
static int emit_stored_blocks(const uint8_t *src, size_t src_len, uint8_t *dst,
                              size_t dst_cap)
{
	ark_bit_writer_t bw;
	size_t off;

	bw.dst = dst;
	bw.cap = dst_cap;
	bw.pos = 0;
	bw.bits = 0;
	bw.nbits = 0;
	off = 0;

	if (src_len == 0U) {
		if (bw_put_bits(&bw, 1U, 1U) != 0)
			return -1;
		if (bw_put_bits(&bw, 0U, 2U) != 0)
			return -1;
		if (bw_flush_to_byte(&bw) != 0)
			return -1;
		if (bw.pos + 4U > bw.cap)
			return -1;
		bw.dst[bw.pos++] = 0x00;
		bw.dst[bw.pos++] = 0x00;
		bw.dst[bw.pos++] = 0xff;
		bw.dst[bw.pos++] = 0xff;
		return (int)bw.pos;
	}

	while (off < src_len) {
		uint16_t chunk;
		uint16_t nlen;
		unsigned int final;
		size_t i;

		chunk = (uint16_t)((src_len - off) > 65535U ? 65535U
		                                            : (src_len - off));
		nlen = (uint16_t)~chunk;
		final = (off + chunk == src_len) ? 1U : 0U;

		if (bw_put_bits(&bw, (uint16_t) final, 1U) != 0)
			return -1;
		if (bw_put_bits(&bw, 0U, 2U) != 0)
			return -1;
		if (bw_flush_to_byte(&bw) != 0)
			return -1;

		if (bw.pos + 4U + chunk > bw.cap)
			return -1;
		bw.dst[bw.pos++] = (uint8_t)(chunk & 0xffU);
		bw.dst[bw.pos++] = (uint8_t)(chunk >> 8);
		bw.dst[bw.pos++] = (uint8_t)(nlen & 0xffU);
		bw.dst[bw.pos++] = (uint8_t)(nlen >> 8);
		for (i = 0; i < chunk; i++)
			bw.dst[bw.pos + i] = src[off + i];
		bw.pos += (size_t)chunk;
		off += chunk;
	}

	return (int)bw.pos;
}

/* RFC 1951 fixed literal/length code descriptor. */
static void fixed_lit_code(unsigned int sym, uint16_t *code,
                           unsigned int *nbits)
{
	if (sym <= 143U) {
		*nbits = 8U;
		*code = bit_reverse((uint16_t)(0x30U + sym), *nbits);
		return;
	}
	if (sym <= 255U) {
		*nbits = 9U;
		*code = bit_reverse((uint16_t)(0x190U + (sym - 144U)), *nbits);
		return;
	}
	if (sym <= 279U) {
		*nbits = 7U;
		*code = bit_reverse((uint16_t)(sym - 256U), *nbits);
		return;
	}
	*nbits = 8U;
	*code = bit_reverse((uint16_t)(0xc0U + (sym - 280U)), *nbits);
}

/* RFC 1951 fixed distance code descriptor. */
static void fixed_dist_code(unsigned int sym, uint16_t *code,
                            unsigned int *nbits)
{
	*nbits = 5U;
	*code = bit_reverse((uint16_t)sym, *nbits);
}

/* Map match length [3..258] to Deflate length symbol + extra bits. */
static int length_symbol(size_t len, unsigned int *sym, unsigned int *extra_n,
                         uint16_t *extra_v)
{
	unsigned int i;

	if (len < ARK_DEFLATE_MIN_MATCH || len > ARK_DEFLATE_MAX_MATCH)
		return -1;
	for (i = 0; i < 29U; i++) {
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

/* Map distance [1..32768] to Deflate distance symbol + extra bits. */
static int distance_symbol(size_t dist, unsigned int *sym,
                           unsigned int *extra_n, uint16_t *extra_v)
{
	unsigned int i;

	if (dist == 0U || dist > ARK_DEFLATE_WINDOW_SIZE)
		return -1;
	for (i = 0; i < 30U; i++) {
		size_t base;
		size_t max;

		base = g_dist_base[i];
		max = base + ((size_t)1U << g_dist_extra[i]) - 1U;
		if (dist < base || dist > max)
			continue;
		*sym = i;
		*extra_n = g_dist_extra[i];
		*extra_v = (uint16_t)(dist - base);
		return 0;
	}
	return -1;
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
static unsigned int hash3(const uint8_t *p)
{
	unsigned int h;

	h = ((unsigned int)p[0] << 16) ^ ((unsigned int)p[1] << 8) ^
	    (unsigned int)p[2];
	h *= 0x1e35a7bdU;
	return (h >> (32U - ARK_DEFLATE_HASH_BITS)) & ARK_DEFLATE_HASH_MASK;
}

/* Read 8 bytes from p as a little-endian 64-bit value without memcpy. */
static uint64_t load_u64_le(const uint8_t *p)
{
	return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Start a fresh parse generation without clearing full hash/chain tables. */
static void match_finder_begin_parse(ark_match_finder_t *mf)
{
	uint32_t next;

	if (mf->generation == UINT32_MAX) {
		size_t i;

		/*
		 * SAFETY: on generation wrap, clear all stamps before reusing
		 * generation values. Reusing wrapped generations without
		 * clearing would make stale hash/chain slots appear valid for
		 * the current parse.
		 */
		for (i = 0; i < ARK_DEFLATE_HASH_SIZE; i++)
			mf->head_gen[i] = 0U;
		for (i = 0; i < ARK_DEFLATE_WINDOW_SIZE; i++)
			mf->prev_gen[i] = 0U;
		next = 1U;
	} else
		next = mf->generation + 1U;
	mf->generation = next;
}

/* Return hash-head candidate only if it was written in this parse. */
static int32_t match_finder_head_get(const ark_match_finder_t *mf,
                                     unsigned int h)
{
	if (mf->head_gen[h] != mf->generation)
		return -1;
	return mf->head[h];
}

/* Store hash-head candidate for the current parse generation. */
static void match_finder_head_set(ark_match_finder_t *mf, unsigned int h,
                                  int32_t pos)
{
	mf->head[h] = pos;
	mf->head_gen[h] = mf->generation;
}

/* Return chain predecessor only if it was written in this parse. */
static int32_t match_finder_prev_get(const ark_match_finder_t *mf, size_t pos)
{
	size_t slot;

	slot = pos & (ARK_DEFLATE_WINDOW_SIZE - 1U);
	if (mf->prev_gen[slot] != mf->generation)
		return -1;
	return mf->prev[slot];
}

/* Store chain predecessor for the current parse generation. */
static void match_finder_prev_set(ark_match_finder_t *mf, size_t pos,
                                  int32_t prev)
{
	size_t slot;

	slot = pos & (ARK_DEFLATE_WINDOW_SIZE - 1U);
	mf->prev[slot] = prev;
	mf->prev_gen[slot] = mf->generation;
}

/* Insert one position into hash chain and return previous head candidate. */
static int insert_hash(const uint8_t *src, size_t src_len, size_t pos,
                       ark_match_finder_t *mf)
{
	unsigned int h;
	int32_t old;

	if (pos + 2U >= src_len)
		return -1;
	h = hash3(src + pos);
	old = match_finder_head_get(mf, h);
	match_finder_prev_set(mf, pos, old);
	match_finder_head_set(mf, h, (int32_t)pos);
	return old;
}

/*
 * Find the best LZ77 match for src[pos..] using hash chains.
 * See ARCHITECTURE.md section 7.2 (hash-chain finding + lazy matching).
 */
static ark_match_t find_match(const uint8_t *src, size_t src_len, size_t pos,
                              int32_t candidate, const ark_match_finder_t *mf,
                              unsigned int max_chain, size_t nice_len)
{
	ark_match_t best;
	size_t max_len;
	int32_t min_pos;
	unsigned int tries;

	best.len = 0U;
	best.dist = 0U;

	if (pos + ARK_DEFLATE_MIN_MATCH > src_len)
		return best;

	max_len = src_len - pos;
	if (max_len > ARK_DEFLATE_MAX_MATCH)
		max_len = ARK_DEFLATE_MAX_MATCH;
	min_pos = (int32_t)(pos > ARK_DEFLATE_WINDOW_SIZE
	                        ? pos - ARK_DEFLATE_WINDOW_SIZE
	                        : 0U);

	tries = 0U;
	while (candidate >= min_pos && tries < max_chain) {
		size_t cand;

		cand = (size_t)candidate;
		if (cand >= pos)
			break;
		if (src[cand] == src[pos] && src[cand + 1U] == src[pos + 1U] &&
		    src[cand + 2U] == src[pos + 2U]) {
			size_t len;

			len = 3U;
			while (len + 8U <= max_len) {
				uint64_t a, b;

				a = load_u64_le(src + cand + len);
				b = load_u64_le(src + pos + len);
				if (a != b)
					break;
				len += 8U;
			}
			while (len < max_len &&
			       src[cand + len] == src[pos + len])
				len++;
			if (len > best.len) {
				best.len = len;
				best.dist = pos - cand;
				if (best.len >= nice_len)
					break;
			}
		}
		candidate = match_finder_prev_get(mf, cand);
		tries++;
	}

	return best;
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
		if (depth > max_bits)
			overflow = (overflow + 1U);
		if (depth < 16U)
			bl_count[depth]++;
	}

	while (overflow > 0U) {
		int bits;

		bits = (int)max_bits - 1;
		while (bits > 0 && bl_count[bits] == 0U)
			bits--;
		if (bits == 0)
			return -1;
		if (overflow < 2U || bl_count[max_bits] == 0U)
			return -1;
		bl_count[bits]--;
		bl_count[bits + 1] += 2U;
		bl_count[max_bits]--;
		overflow -= 2U;
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

/* Parse a block once, optionally collecting frequencies or emitting symbols. */
static int parse_block(const uint8_t *src, size_t src_len,
                       ark_deflate_mode_t mode, ark_freq_t *freq,
                       ark_bit_writer_t *bw, const ark_codebook_t *lit_book,
                       const ark_codebook_t *dist_book)
{
	ark_match_finder_t *mf;
	unsigned int max_chain;
	size_t nice_len;
	size_t pos;
	size_t i;

	max_chain = (mode == ARK_DEFLATE_FAST) ? 32U : 128U;
	nice_len = (mode == ARK_DEFLATE_FAST) ? 32U : ARK_DEFLATE_MAX_MATCH;

	/*
	 * Reset match-finder visibility via generation stamping instead of full
	 * table clears. This keeps hash-chain lazy matching deterministic while
	 * reducing reset cost. See ARCHITECTURE.md §7.2 and §13.1.
	 */
	mf = &g_match_finder;
	match_finder_begin_parse(mf);

	if (freq != NULL) {
		for (i = 0; i < 286U; i++)
			freq->lit[i] = 0;
		for (i = 0; i < 30U; i++)
			freq->dist[i] = 0;
	}

	pos = 0U;
	while (pos < src_len) {
		ark_match_t m;
		int32_t candidate;

		candidate = insert_hash(src, src_len, pos, mf);
		m = find_match(src, src_len, pos, candidate, mf, max_chain,
		               nice_len);

		if (m.len >= ARK_DEFLATE_MIN_MATCH &&
		    mode == ARK_DEFLATE_DEFAULT) {
			ark_match_t m_next;

			m_next.len = 0U;
			m_next.dist = 0U;
			if (pos + 3U < src_len) {
				unsigned int hnext;
				int32_t cnext;

				hnext = hash3(src + pos + 1U);
				cnext = match_finder_head_get(mf, hnext);
				m_next =
				    find_match(src, src_len, pos + 1U, cnext,
				               mf, max_chain, nice_len);
			}
			if (m_next.len > m.len + 1U) {
				if (freq != NULL)
					freq->lit[src[pos]]++;
				if (bw != NULL &&
				    emit_code_symbol(bw, lit_book, src[pos]) !=
				        0)
					return -1;
				pos++;
				continue;
			}
		}

		if (m.len >= ARK_DEFLATE_MIN_MATCH) {
			unsigned int lsym;
			unsigned int lextra_n;
			uint16_t lextra_v;
			unsigned int dsym;
			unsigned int dextra_n;
			uint16_t dextra_v;

			if (length_symbol(m.len, &lsym, &lextra_n, &lextra_v) !=
			    0)
				return -1;
			if (distance_symbol(m.dist, &dsym, &dextra_n,
			                    &dextra_v) != 0)
				return -1;
			if (freq != NULL) {
				freq->lit[lsym]++;
				freq->dist[dsym]++;
			}
			if (bw != NULL) {
				if (emit_code_symbol(bw, lit_book, lsym) != 0)
					return -1;
				if (lextra_n != 0U &&
				    bw_put_bits(bw, lextra_v, lextra_n) != 0)
					return -1;
				if (emit_code_symbol(bw, dist_book, dsym) != 0)
					return -1;
				if (dextra_n != 0U &&
				    bw_put_bits(bw, dextra_v, dextra_n) != 0)
					return -1;
			}

			for (i = 1; i < m.len; i++)
				(void)insert_hash(src, src_len, pos + i, mf);
			pos += m.len;
			continue;
		}

		if (freq != NULL)
			freq->lit[src[pos]]++;
		if (bw != NULL && emit_code_symbol(bw, lit_book, src[pos]) != 0)
			return -1;
		pos++;
	}

	if (freq != NULL)
		freq->lit[256]++;
	if (bw != NULL && emit_code_symbol(bw, lit_book, 256U) != 0)
		return -1;
	return 0;
}

/* Emit one literal byte using fixed Huffman coding. */
static int emit_litlen_symbol(ark_bit_writer_t *bw, unsigned int sym)
{
	uint16_t code;
	unsigned int nbits;

	fixed_lit_code(sym, &code, &nbits);
	return bw_put_bits(bw, code, nbits);
}

/* Emit one literal byte using fixed Huffman coding. */
static int emit_literal(ark_bit_writer_t *bw, uint8_t lit)
{
	return emit_litlen_symbol(bw, (unsigned int)lit);
}

/* Emit one match pair (length + distance) using fixed Huffman coding. */
static int emit_match(ark_bit_writer_t *bw, size_t len, size_t dist)
{
	unsigned int lsym;
	unsigned int lextra_n;
	uint16_t lextra_v;
	unsigned int dsym;
	unsigned int dextra_n;
	uint16_t dextra_v;
	uint16_t code;
	unsigned int nbits;

	if (length_symbol(len, &lsym, &lextra_n, &lextra_v) != 0)
		return -1;
	if (distance_symbol(dist, &dsym, &dextra_n, &dextra_v) != 0)
		return -1;

	if (emit_litlen_symbol(bw, lsym) != 0)
		return -1;
	if (lextra_n != 0U && bw_put_bits(bw, lextra_v, lextra_n) != 0)
		return -1;

	fixed_dist_code(dsym, &code, &nbits);
	if (bw_put_bits(bw, code, nbits) != 0)
		return -1;
	if (dextra_n != 0U && bw_put_bits(bw, dextra_v, dextra_n) != 0)
		return -1;

	return 0;
}

/*
 * Compress with one fixed-Huffman block and deterministic lazy matching.
 * See ARCHITECTURE.md section 7.2.
 */
static int compress_fixed(const uint8_t *src, size_t src_len, uint8_t *dst,
                          size_t dst_cap, ark_deflate_mode_t mode)
{
	ark_bit_writer_t bw;
	ark_match_finder_t *mf;
	unsigned int max_chain;
	size_t nice_len;
	size_t pos;
	size_t i;

	max_chain = (mode == ARK_DEFLATE_FAST) ? 32U : 256U;
	nice_len = (mode == ARK_DEFLATE_FAST) ? 32U : 128U;
	mf = &g_match_finder;
	match_finder_begin_parse(mf);

	bw.dst = dst;
	bw.cap = dst_cap;
	bw.pos = 0;
	bw.bits = 0;
	bw.nbits = 0;

	if (bw_put_bits(&bw, 1U, 1U) != 0)
		return -1;
	if (bw_put_bits(&bw, 1U, 2U) != 0)
		return -1;

	pos = 0U;
	while (pos < src_len) {
		ark_match_t m;
		int32_t candidate;

		candidate = insert_hash(src, src_len, pos, mf);
		m = find_match(src, src_len, pos, candidate, mf, max_chain,
		               nice_len);

		if (m.len >= ARK_DEFLATE_MIN_MATCH &&
		    mode == ARK_DEFLATE_DEFAULT) {
			ark_match_t m_next;

			m_next.len = 0U;
			m_next.dist = 0U;

			if (pos + 1U < src_len) {
				if (pos + 3U <= src_len) {
					unsigned int hnext;
					int32_t cnext;

					hnext = hash3(src + pos + 1U);
					cnext =
					    match_finder_head_get(mf, hnext);
					m_next = find_match(
					    src, src_len, pos + 1U, cnext, mf,
					    max_chain, nice_len);
				}
			}

			if (m_next.len > m.len + 1U) {
				if (emit_literal(&bw, src[pos]) != 0)
					return -1;
				pos++;
				continue;
			}
		}

		if (m.len >= ARK_DEFLATE_MIN_MATCH) {
			/*
			 * SAFETY: emit match only with Deflate-legal distance
			 * and length. A malformed pair would violate RFC 1951
			 * stream invariants.
			 */
			if (m.dist == 0U || m.dist > ARK_DEFLATE_WINDOW_SIZE ||
			    m.len < ARK_DEFLATE_MIN_MATCH ||
			    m.len > ARK_DEFLATE_MAX_MATCH)
				return -1;
			if (emit_match(&bw, m.len, m.dist) != 0)
				return -1;

			for (i = 1; i < m.len; i++)
				(void)insert_hash(src, src_len, pos + i, mf);
			pos += m.len;
			continue;
		}

		if (emit_literal(&bw, src[pos]) != 0)
			return -1;
		pos++;
	}

	if (emit_litlen_symbol(&bw, 256U) != 0)
		return -1;
	if (bw_flush_to_byte(&bw) != 0)
		return -1;

	return (int)bw.pos;
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

static size_t dynamic_header_bits(size_t hlit_count, size_t hdist_count)
{
	return 3U + 5U + 5U + 4U + 19U * 3U + (hlit_count + hdist_count) * 4U;
}

/*
 * Build one dynamic-block coding plan for src[0..src_len) from a single
 * frequency parse. The plan is reused for selected-block emission to avoid
 * redundant full parse_block passes. See ARCHITECTURE.md §7.2.
 */
static int build_dynamic_plan(const uint8_t *src, size_t src_len,
                              ark_dynamic_plan_t *plan, size_t *bits_out)
{
	size_t i;

	if (parse_block(src, src_len, ARK_DEFLATE_DEFAULT, &plan->freq, NULL,
	                NULL, NULL) != 0)
		return -1;
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

	*bits_out = dynamic_header_bits(plan->hlit_count, plan->hdist_count) +
	            huff_data_bits(&plan->freq, plan->lit_len, plan->dist_len);
	return 0;
}

/*
 * Select a default-mode block plan from deterministic candidate lengths.
 * Candidate enumeration order and strict-better replacement preserve stable
 * block boundary selection. See ARCHITECTURE.md §7.2 and §13.1.
 */
static int choose_default_block_plan(const uint8_t *src, size_t remaining,
                                     ark_dynamic_plan_t *best_plan)
{
	ark_dynamic_plan_t best;
	size_t best_score;
	size_t i;

	best.len = remaining;
	best_score = (size_t)-1;

	for (i = 0; i < sizeof(g_default_block_candidates) /
	                    sizeof(g_default_block_candidates[0]);
	     i++) {
		ark_dynamic_plan_t cand;
		size_t len;
		size_t bits;
		size_t score;

		len = g_default_block_candidates[i];
		if (len > remaining)
			len = remaining;
		cand.len = len;
		if (build_dynamic_plan(src, len, &cand, &bits) != 0)
			continue;
		score = (bits * 65536U) / (len == 0U ? 1U : len);
		if (score < best_score) {
			best_score = score;
			best = cand;
		}
		if (len == remaining)
			break;
	}

	if (best_score == (size_t)-1)
		return -1;
	*best_plan = best;
	return 0;
}

static int emit_dynamic_header(ark_bit_writer_t *bw, const uint8_t *lit_len,
                               const uint8_t *dist_len, size_t hlit_count,
                               size_t hdist_count, ark_codebook_t *lit_book,
                               ark_codebook_t *dist_book)
{
	ark_codebook_t cl_book;
	uint8_t cl_len[19];
	size_t i;

	for (i = 0; i < 19U; i++)
		cl_len[i] = i <= 15U ? 4U : 0U;

	if (build_codes(lit_len, 286U, 15U, lit_book) != 0)
		return -1;
	if (build_codes(dist_len, 30U, 15U, dist_book) != 0)
		return -1;
	if (build_codes(cl_len, 19U, 7U, &cl_book) != 0)
		return -1;

	if (bw_put_bits(bw, (uint16_t)(hlit_count - 257U), 5U) != 0)
		return -1;
	if (bw_put_bits(bw, (uint16_t)(hdist_count - 1U), 5U) != 0)
		return -1;
	if (bw_put_bits(bw, 15U, 4U) != 0)
		return -1;

	for (i = 0; i < 19U; i++) {
		if (bw_put_bits(bw, cl_len[g_cl_order[i]], 3U) != 0)
			return -1;
	}
	for (i = 0; i < hlit_count; i++) {
		if (emit_code_symbol(bw, &cl_book, lit_len[i]) != 0)
			return -1;
	}
	for (i = 0; i < hdist_count; i++) {
		if (emit_code_symbol(bw, &cl_book, dist_len[i]) != 0)
			return -1;
	}

	return 0;
}

static int emit_dynamic_block(ark_bit_writer_t *bw, const uint8_t *src,
                              const ark_dynamic_plan_t *plan, int final)
{
	ark_codebook_t lit_book;
	ark_codebook_t dist_book;

	if (bw_put_bits(bw, final ? 1U : 0U, 1U) != 0)
		return -1;
	if (bw_put_bits(bw, 2U, 2U) != 0)
		return -1;
	if (emit_dynamic_header(bw, plan->lit_len, plan->dist_len,
	                        plan->hlit_count, plan->hdist_count, &lit_book,
	                        &dist_book) != 0)
		return -1;
	if (parse_block(src, plan->len, ARK_DEFLATE_DEFAULT, NULL, bw,
	                &lit_book, &dist_book) != 0)
		return -1;
	return 0;
}

/*
 * Compress default archival mode using dynamic Huffman blocks.
 * Candidate block sizes are costed before emission so deterministic block
 * boundaries are selected from the local cost model.
 */
static int compress_dynamic_default(const uint8_t *src, size_t src_len,
                                    uint8_t *dst, size_t dst_cap)
{
	ark_bit_writer_t bw;
	size_t off;

	off = 0U;
	if (src_len == 0U)
		return emit_stored_blocks(src, src_len, dst, dst_cap);

	bw.dst = dst;
	bw.cap = dst_cap;
	bw.pos = 0;
	bw.bits = 0;
	bw.nbits = 0;

	while (off < src_len) {
		ark_dynamic_plan_t plan;
		size_t len;
		int final;

		if (choose_default_block_plan(src + off, src_len - off,
		                              &plan) != 0)
			return -1;
		len = plan.len;
		if (len == 0U || len > src_len - off)
			return -1;
		final = off + len == src_len;
		if (emit_dynamic_block(&bw, src + off, &plan, final) != 0)
			return -1;
		off += len;
	}

	if (bw_flush_to_byte(&bw) != 0)
		return -1;
	return bw.pos > (size_t)INT_MAX ? -1 : (int)bw.pos;
}

/* Decode one Huffman-coded Deflate block until end-of-block marker. */
static int decode_huffman_block(ark_bit_reader_t *br,
                                const ark_huff_table_t *lit_tab,
                                const ark_huff_table_t *dist_tab, uint8_t *dst,
                                size_t dst_cap, size_t *dst_pos)
{
	int sym;
	size_t i;

	for (;;) {
		if (huff_decode(br, lit_tab, &sym) != 0)
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
			len = g_len_base[li];
			if (g_len_extra[li] != 0U) {
				if (br_get_bits(br, g_len_extra[li], &extra) !=
				    0)
					return -1;
				len += extra;
			}

			if (huff_decode(br, dist_tab, &dsym) != 0)
				return -1;
			if (dsym < 0 || dsym > 29)
				return -1;

			dist = g_dist_base[dsym];
			if (g_dist_extra[dsym] != 0U) {
				if (br_get_bits(br, g_dist_extra[dsym],
				                &extra) != 0)
					return -1;
				dist += extra;
			}

			/*
			 * SAFETY: match copy must reference already-produced
			 * bytes. Distances beyond dst_pos are invalid and must
			 * fail hard.
			 */
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

/*
 * Build RFC 1951 fixed-Huffman decode tables.
 *
 * The fixed tables are stream-invariant; build once and reuse across all
 * fixed blocks in a stream. This keeps decompressor-only table symbols local
 * to deflate.c, preserving the decompressor boundary used by recovery
 * amalgamation. See ARCHITECTURE.md section 15.3.
 */
static int build_fixed_decode_tables(ark_huff_table_t *lit_tab,
                                     ark_huff_table_t *dist_tab)
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

	if (huff_build(lit_tab, lit_len, 288U, 9U) != 0)
		return -1;
	if (huff_build(dist_tab, dist_len, 32U, 5U) != 0)
		return -1;
	return 0;
}

/* Decode one fixed-Huffman symbol set into dst; stops on end-of-block code. */
static int decode_fixed_block(ark_bit_reader_t *br,
                              const ark_huff_table_t *lit_tab,
                              const ark_huff_table_t *dist_tab, uint8_t *dst,
                              size_t dst_cap, size_t *dst_pos)
{
	return decode_huffman_block(br, lit_tab, dist_tab, dst, dst_cap,
	                            dst_pos);
}

/* Decode one dynamic-Huffman Deflate block. */
static int decode_dynamic_block(ark_bit_reader_t *br, uint8_t *dst,
                                size_t dst_cap, size_t *dst_pos)
{
	ark_huff_table_t cl_tab;
	ark_huff_table_t lit_tab;
	ark_huff_table_t dist_tab;
	uint8_t cl_len[19];
	uint8_t lit_len[288];
	uint8_t dist_len[32];
	uint8_t lens[288 + 32];
	uint16_t v;
	size_t hlit;
	size_t hdist;
	size_t hclen;
	size_t n;
	size_t i;

	for (i = 0; i < 19U; i++)
		cl_len[i] = 0;
	for (i = 0; i < 288U; i++)
		lit_len[i] = 0;
	for (i = 0; i < 32U; i++)
		dist_len[i] = 0;

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

	if (huff_build(&cl_tab, cl_len, 19U, 7U) != 0)
		return -1;

	n = 0U;
	while (n < hlit + hdist) {
		int sym;

		if (huff_decode(br, &cl_tab, &sym) != 0)
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
			if (br_get_bits(br, 2U, &v) != 0)
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

			if (br_get_bits(br, 3U, &v) != 0)
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

			if (br_get_bits(br, 7U, &v) != 0)
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

	if (huff_build(&lit_tab, lit_len, 288U, 15U) != 0)
		return -1;
	if (huff_build(&dist_tab, dist_len, 32U, 15U) != 0)
		return -1;

	return decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
	                            dst_pos);
}

/* Decode one RFC 1951 stored block into dst. */
static int decode_stored_block(ark_bit_reader_t *br, uint8_t *dst,
                               size_t dst_cap, size_t *dst_pos)
{
	uint16_t len;
	uint16_t nlen;
	size_t i;

	if ((br->nbits & 7U) != 0U) {
		unsigned int drop;

		drop = br->nbits & 7U;
		br->bits >>= drop;
		br->nbits -= drop;
	}

	if (br_get_bits(br, 16U, &len) != 0)
		return -1;
	if (br_get_bits(br, 16U, &nlen) != 0)
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

/*
 * ark_deflate_bound - Return safe maximum compressed size for src_len bytes.
 *
 * The bound accounts for stored-block framing in the worst incompressible
 * case (RFC 1951) and includes one-byte headroom for bit padding.
 * See ARCHITECTURE.md sections 7.1 and 7.2.
 */
size_t ark_deflate_bound(size_t src_len)
{
	size_t blocks;
	size_t overhead;

	blocks = (src_len == 0U) ? 1U : ((src_len + 65534U) / 65535U);
	overhead = blocks * 5U + 1U;
	return src_len + overhead;
}

/*
 * ark_deflate_compress - Compress one chunk into a raw RFC 1951 stream.
 *
 * Uses deterministic hash-chain + lazy matching and fixed-Huffman coding.
 * For incompressible input, falls back to stored blocks when that yields
 * smaller output. See ARCHITECTURE.md section 7.2.
 *
 * Returns compressed byte count on success, -1 on error.
 */
ssize_t ark_deflate_compress(const uint8_t *src, size_t src_len, uint8_t *dst,
                             size_t dst_cap, ark_deflate_mode_t mode)
{
	int fixed_len;

	if (dst == NULL)
		return -1;
	if (src_len > ARK_CHUNK_SIZE)
		return -1;
	if (src_len != 0U && src == NULL)
		return -1;
	if (mode != ARK_DEFLATE_DEFAULT && mode != ARK_DEFLATE_FAST)
		return -1;
	if (dst_cap < ark_deflate_bound(src_len))
		return -1;

	if (mode == ARK_DEFLATE_DEFAULT)
		fixed_len =
		    compress_dynamic_default(src, src_len, dst, dst_cap);
	else
		fixed_len = compress_fixed(src, src_len, dst, dst_cap, mode);

	/*
	 * ARCHITECTURE.md section 7.2: for incompressible data, emit stored
	 * blocks whenever compressed output is not smaller than input.
	 */
	if (fixed_len < 0 || (size_t)fixed_len >= src_len) {
		int stored_len;

		stored_len = emit_stored_blocks(src, src_len, dst, dst_cap);
		return stored_len < 0 ? -1 : stored_len;
	}

	return fixed_len;
}

/*
 * ark_deflate_decompress - Decompress one raw RFC 1951 Deflate stream.
 *
 * Supports stored blocks (BTYPE 00), fixed-Huffman blocks (BTYPE 01), and
 * dynamic-Huffman blocks (BTYPE 10). Reserved BTYPE 11 and all malformed
 * input are rejected.
 *
 * Returns decompressed byte count on success, -1 on error.
 */
ssize_t ark_deflate_decompress(const uint8_t *src, size_t src_len, uint8_t *dst,
                               size_t dst_cap)
{
	ark_bit_reader_t br;
	ark_huff_table_t fixed_lit_tab;
	ark_huff_table_t fixed_dist_tab;
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
	if (build_fixed_decode_tables(&fixed_lit_tab, &fixed_dist_tab) != 0)
		return -1;

	for (;;) {
		uint16_t bfinal;
		uint16_t btype;

		if (br_get_bits(&br, 1U, &bfinal) != 0)
			return -1;
		if (br_get_bits(&br, 2U, &btype) != 0)
			return -1;

		if (btype == 0U) {
			if (decode_stored_block(&br, dst, dst_cap, &out_pos) !=
			    0)
				return -1;
		} else if (btype == 1U) {
			if (decode_fixed_block(&br, &fixed_lit_tab,
			                       &fixed_dist_tab, dst, dst_cap,
			                       &out_pos) != 0)
				return -1;
		} else if (btype == 2U) {
			if (decode_dynamic_block(&br, dst, dst_cap, &out_pos) !=
			    0)
				return -1;
		} else {
			return -1;
		}

		if (bfinal != 0U)
			break;
	}

	return (ssize_t)out_pos;
}
