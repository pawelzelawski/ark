/*
 * deflate.c - RFC 1951 Deflate component implementation.
 *
 * Implements ark_deflate_bound, ark_deflate_compress, and
 * ark_deflate_decompress from deflate.h. This component performs pure
 * in-memory transformation only: no I/O and no component-owned allocation.
 * See ARCHITECTURE.md section 7.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate.h"

#define ARK_CHUNK_SIZE 1048576U

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

/* Deflate hash over three bytes for LZ77 match candidate lookup. */
static unsigned int hash3(const uint8_t *p)
{
	unsigned int h;

	h = ((unsigned int)p[0] << 16) ^ ((unsigned int)p[1] << 8) ^
	    (unsigned int)p[2];
	h *= 0x1e35a7bdU;
	return (h >> (32U - ARK_DEFLATE_HASH_BITS)) & ARK_DEFLATE_HASH_MASK;
}

/* Insert one position into hash chain and return previous head candidate. */
static int insert_hash(const uint8_t *src, size_t src_len, size_t pos,
                       int32_t *head, int32_t *prev)
{
	unsigned int h;
	int32_t old;

	if (pos + 2U >= src_len)
		return -1;
	h = hash3(src + pos);
	old = head[h];
	prev[pos & (ARK_DEFLATE_WINDOW_SIZE - 1U)] = old;
	head[h] = (int32_t)pos;
	return old;
}

/*
 * Find the best LZ77 match for src[pos..] using hash chains.
 * See ARCHITECTURE.md section 7.2 (hash-chain finding + lazy matching).
 */
static ark_match_t find_match(const uint8_t *src, size_t src_len, size_t pos,
                              int32_t candidate, const int32_t *prev,
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
		candidate = prev[cand & (ARK_DEFLATE_WINDOW_SIZE - 1U)];
		tries++;
	}

	return best;
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
	int32_t head[ARK_DEFLATE_HASH_SIZE];
	int32_t prev[ARK_DEFLATE_WINDOW_SIZE];
	unsigned int max_chain;
	size_t nice_len;
	size_t pos;
	size_t i;

	max_chain = (mode == ARK_DEFLATE_FAST) ? 32U : 256U;
	nice_len = (mode == ARK_DEFLATE_FAST) ? 32U : 128U;

	for (i = 0; i < ARK_DEFLATE_HASH_SIZE; i++)
		head[i] = -1;
	for (i = 0; i < ARK_DEFLATE_WINDOW_SIZE; i++)
		prev[i] = -1;

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

		candidate = insert_hash(src, src_len, pos, head, prev);
		m = find_match(src, src_len, pos, candidate, prev, max_chain,
		               nice_len);

		if (m.len >= ARK_DEFLATE_MIN_MATCH) {
			ark_match_t m_next;

			m_next.len = 0U;
			m_next.dist = 0U;

			if (pos + 1U < src_len) {
				if (pos + 3U <= src_len) {
					unsigned int hnext;
					int32_t cnext;

					hnext = hash3(src + pos + 1U);
					cnext = head[hnext];
					m_next = find_match(
					    src, src_len, pos + 1U, cnext, prev,
					    max_chain, nice_len);
				}
			}

			if (m_next.len > m.len + 1U) {
				if (emit_literal(&bw, src[pos]) != 0)
					return -1;
				pos++;
				continue;
			}

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
				(void)insert_hash(src, src_len, pos + i, head,
				                  prev);
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

/* Decode one fixed-Huffman symbol set into dst; stops on end-of-block code. */
static int decode_fixed_block(ark_bit_reader_t *br, uint8_t *dst,
                              size_t dst_cap, size_t *dst_pos)
{
	ark_huff_table_t lit_tab;
	ark_huff_table_t dist_tab;
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

	if (huff_build(&lit_tab, lit_len, 288U, 9U) != 0)
		return -1;
	if (huff_build(&dist_tab, dist_len, 32U, 5U) != 0)
		return -1;
	return decode_huffman_block(br, &lit_tab, &dist_tab, dst, dst_cap,
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
 * Supports stored and fixed-Huffman blocks and rejects malformed input.
 * Dynamic-Huffman blocks are currently rejected.
 *
 * Returns decompressed byte count on success, -1 on error.
 */
ssize_t ark_deflate_decompress(const uint8_t *src, size_t src_len, uint8_t *dst,
                               size_t dst_cap)
{
	ark_bit_reader_t br;
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

		if (br_get_bits(&br, 1U, &bfinal) != 0)
			return -1;
		if (br_get_bits(&br, 2U, &btype) != 0)
			return -1;

		if (btype == 0U) {
			if (decode_stored_block(&br, dst, dst_cap, &out_pos) !=
			    0)
				return -1;
		} else if (btype == 1U) {
			if (decode_fixed_block(&br, dst, dst_cap, &out_pos) !=
			    0)
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
