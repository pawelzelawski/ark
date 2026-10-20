# Performance Improvements

## Purpose

This file tracks Deflate optimisation performance across the Post-Phase 6 follow-up tasks.
Use it as the reference point for ratio/speed regressions and improvements.

Location choice: repository root (not `tests/`) so it is visible as an engineering log,
not test code.

---

## Baseline Freeze (P6F.1)

Date: 2026-05-11  
Platform: Linux  
Dataset: `/tmp/ark_tests`  
Artifacts: `/tmp/ark_bench`

### Raw baseline metrics

- Source dataset size: `516,025,504` bytes (`~492.12 MiB`)
- ark archive size: `175,306,086` bytes (`~167.18 MiB`)
- tar.gz archive size: `155,637,976` bytes (`~148.43 MiB`)

### Compression outcome

- ark ratio: `33.97%` of source
- tar.gz ratio: `30.16%` of source
- ark saving: `66.03%`
- tar.gz saving: `69.84%`
- Size delta (ark - tar.gz): `19,668,110` bytes (`~18.76 MiB`)

### Timing outcome

- ark create: `wall=29.51 user=156.30 sys=0.59`
- ark verify: `wall=2.02 user=1.99 sys=0.02`
- tar -czf create: `wall=9.73 user=9.62 sys=0.63`

### Create-time comparison

- Wall-time multiplier (ark / tar.gz): `~3.03x slower`
- Wall-time delta: `+19.78s` for ark

### Determinism baseline (same binary, same input)

- Result: `byte-identical=yes`

---

## Repro Commands (Linux)

```bash
make release
/usr/bin/time -f 'wall=%e user=%U sys=%S' -o /tmp/ark_bench/ark_create.time ./build/ark create /tmp/ark_bench/ark_baseline.ark /tmp/ark_tests
/usr/bin/time -f 'wall=%e user=%U sys=%S' -o /tmp/ark_bench/ark_verify.time ./build/ark verify /tmp/ark_bench/ark_baseline.ark
/usr/bin/time -f 'wall=%e user=%U sys=%S' -o /tmp/ark_bench/tar_create.time tar -czf /tmp/ark_bench/tar_baseline.tar.gz -C /tmp ark_tests
./build/ark create /tmp/ark_bench/ark_baseline_2.ark /tmp/ark_tests
cmp -s /tmp/ark_bench/ark_baseline.ark /tmp/ark_bench/ark_baseline_2.ark && echo 'byte-identical=yes' || echo 'byte-identical=no'
```

---

## Optimisation Run Log

Add one entry per task (`P6F.2`, `P6F.3`, ...):

| Task | Date | ark size (bytes) | Ratio (%) | Create wall (s) | Verify wall (s) | Size delta vs P6F.1 (bytes) | Create wall delta vs P6F.1 (s) | Determinism |
|---|---|---:|---:|---:|---:|---:|---:|---|
| P6F.1 (baseline) | 2026-05-11 | 175306086 | 33.97 | 29.51 | 2.02 | 0 | 0.00 | yes |
| P6F.2 (fixed decode table caching) | 2026-05-11 | 175306086 | 33.97 | 28.54 | 2.34 | 0 | -0.97 | yes |
| P6F.3 (match-finder reset-cost reduction) | 2026-05-11 | 175306086 | 33.97 | 32.17 | 2.30 | 0 | +2.66 | yes |
| P6F.4 (selected dynamic-block parse reuse) | 2026-05-11 | 175306086 | 33.97 | 26.69 | 2.28 | 0 | -2.82 | yes |
| P6F.5 (length-limited Huffman builder) | 2026-05-11 | 161047746 | 31.21 | 25.72 | 2.68 | -14258340 | -3.79 | yes |
| P6F.5 tuning trial (max_chain=128; full matrix) | 2026-05-11 | 161379463 | 31.27 | 15.98 | 2.76 | -13926623 | -13.53 | yes |
| P6F.5 tuning trial (max_chain=128 + word-at-a-time find_match; create+determinism) | 2026-05-11 | 161379463 | 31.27 | 15.61 | n/a | -13926623 | -13.90 | yes |



---

## Algorithm Audit Fixes (2026-10)

Platform: Linux, Intel i7-7500U (2 cores / 4 threads). Codec numbers are one
thread, 1 MiB chunks, `-O2`, measured back to back against the pre-audit
baseline (`9173a31`) on the same machine. These numbers are not comparable
with the P6F table above (different machine and dataset).

Datasets:
- Mixed corpus: 255,024,842 bytes (documentation, binaries, shared libraries,
  headers) concatenated into one file.
- Binary corpus: 121,540,894 bytes of executables.
- `/usr/include` per file: 7,570 files, 106,126,746 bytes, each compressed as
  its own stream(s).
- Archive: `ark create` of a symlink-resolved `/usr/include` copy.

| Change | Date | Mixed ratio (%) | Mixed compress (MB/s) | Mixed decompress (MB/s) | Binary ratio (%) | `/usr/include` per-file ratio (%) | `/usr/include` archive (bytes) | Determinism |
|---|---|---:|---:|---:|---:|---:|---:|---|
| Baseline (`9173a31`) | 2026-10-08 | 29.212 | 3.4 | 128 | 36.297 | 18.370 | 20,801,154 | yes |
| Encoder fixes: length 258 as code 285, Huffman length-limiter Kraft repair, run-length coded dynamic header | 2026-10-08 | 29.111 | 3.5 | 131 | 36.210 | 17.760 | 20,148,320 | yes |
| Decoder: two-level tables, 64-bit bit reader, word match copies, strict code validation | 2026-10-08 | 29.111 | 3.5 | 261 | 36.210 | 17.760 | 20,148,320 | yes |

Decoder change in detail (same machine, back to back, old vs new decoder on
the same streams):
- Mixed corpus, 244 chunks of 1 MiB: 122 -> 261 MB/s.
- `/usr/include` per file, 7,586 streams: 31 -> 330 MB/s; per-stream cost
  444 -> 42 us (table setup dominated small files).
- `ark verify` of the `/usr/include` archive (release build): 4.09 -> 1.00 s.
- `ark_deflate_decompress` stack frame: 492,360 -> 61,608 bytes.

Index validation and member lookup (`archive.c` sorted path index, used by
`main.c` through `ark_read_find_member`), release build, baseline `9173a31`
vs new. The `tN` archives hold N empty files in nested directories.

| Operation | Baseline (s) | New (s) |
|---|---:|---:|
| `ark list`, 5,000 members | 0.161 | 0.014 |
| `ark list`, 10,000 members | 0.618 | 0.031 |
| `ark list`, 20,000 members | 2.643 | 0.053 |
| `ark list`, 40,000 members | 18.761 | 0.114 |
| `ark extract --member` one file, 40,000 members | 19.092 | 0.112 |
| `ark extract` over an existing tree (40,002 conflicts reported), 40,000 members | 20.888 | 0.399 |
| `ark verify`, `/usr/include` archive (7,962 members; decoder change included) | 4.144 | 0.393 |

---

## v1.2 Round (2026-10)

Platform: Linux, Intel i7-7500U (2 cores / 4 threads, 256 KiB L2 per core),
clang `-O2`, one thread pinned to one CPU (`taskset`), 1 MiB chunks. Old and
new codec built from the same tree state except for the change measured.
Wall times on this machine vary by up to 20 % with other load, so changes
are judged by best-of-5 interleaved runs and by `perf stat` user-space
counters.

Dataset: the first 32 MiB of the mixed corpus above.

**Caller-owned encoder memory** (match-finder generation stamps removed: the
encoder clears its 128 KiB hash-head table per parse instead of keeping
`head_gen`/`prev_gen`; encoder memory 512 KiB -> 256 KiB). Compressed output
byte-identical.

| Level | Best of 5 compress (s), old -> new | Cycles (G), old -> new | L1 data load misses (G), old -> new |
|---|---|---|---|
| Default | 8.77 -> 7.42 | 31.85 -> 27.16 (-14.7 %) | 1.48 -> 0.75 |
| Fast | 1.08 -> 1.03 | 4.33 -> 4.19 (-3.3 %) | 0.21 -> 0.11 |

**Decoder status API and exact table sizes** (decode tables sized for the
worst-case code instead of a per-symbol bound: lit/len 10,240 -> 5,408 and
distance 4,352 -> 1,536 entries; dynamic-block stack about 57 -> 28 KiB).
Best of 5 interleaved decodes, then `perf stat`, old -> new:

| Data | Best decode (s) | Cycles (G) |
|---|---|---|
| 32 MiB corpus slice, 32 streams | 0.135 -> 0.127 | n/a |
| `/usr/include` per file, 7,661 streams | 0.311 -> 0.297 | 3.278 -> 3.100 (-5.4 %) |

**Single-pass default compressor** (one lazy-matching parse per chunk into a
token buffer in the encoder memory, blocks cut from the token stream instead
of up to five parses per block; matches reach across block boundaries; each
block takes fixed codes when they are smaller than its dynamic encoding).
Default-level output changes on purpose; fast-level output is byte-identical.
Old = `145a4f7`, new = this change; same method as above (best of 5
interleaved, then `perf stat` user-space counters):

| Level, 32 MiB slice | Best of 5 compress (s), old -> new | Cycles (G), old -> new | Ratio, old -> new |
|---|---|---|---|
| Default | 7.75 -> 1.34 (5.8x) | 27.40 -> 5.16 (-81 %) | 31.359 % -> 30.368 % |
| Fast | 1.03 -> 1.07 | 3.99 -> 4.16 | 36.334 % (identical bytes) |

The fast-level difference is code placement, not code: with every function
and block aligned the same way in both builds (`-mllvm
-align-all-functions=6 -mllvm -align-all-nofallthru-blocks=5`) the two take
4.14-4.18 G and 4.14-4.16 G cycles, and the new build runs 1.8 % fewer
instructions.

Full 255 MB corpus, one run each, one pinned thread:

| Level | Compress (s), old -> new | Ratio, old -> new |
|---|---|---|
| Default | 63.15 -> 10.80 (5.8x) | 29.111 % -> 28.301 % (gzip -6: 28.300 %) |
| Fast | 6.50 -> 6.74 | 33.558 % (identical bytes) |

`/usr/include` copy compressed file by file (7,645 files, 107,908,150 bytes):
19,248,668 -> 18,962,107 bytes (17.838 % -> 17.572 %); zlib decodes all
7,661 streams to the original bytes. Encoder memory at the default level
grows by the 4 MiB token buffer (one per compress worker).

**Compression levels 0-9** (a zlib-style search table; every level from 1
up uses the single-pass encoder, so the fast level gains dynamic blocks and
the table-driven token writer; the fixed-block-only fast path is removed).
Level 6 output is byte-identical to the single-pass compressor above. Old =
`23a3fa6`, one pinned thread.

Fast level (`--fast`, level 1: greedy, 4 chain candidates, a match of 8
ends the search), first 32 MiB of the mixed corpus, best of 5 interleaved,
then `perf stat`:

| Fast level | Compress (s) | Cycles (G) | Ratio | Decode (s) |
|---|---|---|---|---|
| Old (greedy, 32 candidates, one fixed block) | 1.05 | 4.20 | 36.334 % | 0.13 |
| Same search as old, single-pass encoder (level 3) | 0.70 | 3.02 | 31.458 % | 0.14-0.15 |
| New level 1 | 0.50 | 2.33 | 33.844 % | 0.16 |

Full 255 MB corpus, fast level: 6.97 -> 4.38 s, 33.558 % -> 31.462 %;
decoding its output 0.97 -> 1.17 s (more short matches and dynamic blocks;
default-level output is unaffected).

All levels, first 32 MiB, best of 3 (level 4 tuned so it falls between
levels 3 and 5; zlib's row gave 31.630 % at 0.64 s, larger than level 3):

| Level | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
|---|---|---|---|---|---|---|---|---|---|---|
| Compress (s) | 0.00 | 0.50 | 0.55 | 0.71 | 0.78 | 0.88 | 1.32 | 1.43 | 1.60 | 1.72 |
| Ratio (%) | 100.008 | 33.844 | 32.577 | 31.458 | 30.895 | 30.759 | 30.368 | 30.332 | 30.320 | 30.318 |

**Streaming decoder** (`ark_deflate_dec_stream`, new; ark itself keeps the
one-shot decoder). A fast loop with the 64-bit bit reader runs while at
least 8 input bytes and 258 bytes of output space remain; without it the
byte-at-a-time state machine decoded the `/usr/include` streams at 187 MB/s
against 357 MB/s one-shot. Best of 3, pinned, three rounds, whole buffers:

| Data | One-shot | Streaming |
|---|---|---|
| `/usr/include` per file, 7,661 streams | 351-356 MB/s | 343-350 MB/s |
| 32 MiB corpus slice, 32 streams of 1 MiB | 244-246 MB/s | 267-270 MB/s |

The one-shot decoder's code is unchanged. A first version of the fast loop
shared `br_get_bits` with it, which made the compiler stop inlining that
helper into the one-shot loop (+8 % instructions); the fast loop now takes
its bits with its own helper and the one-shot instruction count is back to
before (5.252 -> 5.256 G). The tools' one-shot build still measures about
4 % slower (3.21 -> 3.40 G cycles) but equal with both builds aligned the
same way (3.34-3.39 vs 3.36-3.39 G), so the difference is code placement;
`ark verify` of the `/usr/include` archive is 0.401 -> 0.383 s (best of 5).

**Adler-32** (`ark_adler32`, new, for the zlib format; ark does not use
it). Portable C with the modulo once per 5552 bytes: 64 MiB, best of 5,
pinned: 2,231 MB/s with clang, 1,665 MB/s with gcc (zlib-ng's SIMD version:
13,817 MB/s). That is several times the Deflate decoder's speed, so the
trailer check does not limit zlib-format decoding.

**BLAKE3 portable speed** (ark's default hash; it hashes the compressed
bytes of every chunk on the I/O thread). gcc did not inline the 56 G calls
per block (its heuristics called them cold), so the state lived in memory
and gcc ran at about half of clang's speed. G and the round became macros
with the seven rounds written out (constant state indices), and `update`
compresses whole blocks straight from the input instead of copying and
zeroing a 64-byte buffer per block. Plain C11, digests unchanged. 128 MiB
one-shot, best of 5, pinned, three rounds:

| Compiler | Before | After |
|---|---|---|
| clang 22 | 469-471 MB/s | 606-615 MB/s |
| gcc 16 | 252-257 MB/s | 588-592 MB/s |

Short inputs (ns per one-shot hash, clang / gcc): 64 B 251 -> 198 /
452 -> 228; 1 KiB 2,126 -> 1,639 / 3,955 -> 1,728; 4 KiB 8,577 -> 6,654 /
16,261 -> 6,875. Unrolling alone (without the direct-input path) gave
clang ~597 and gcc ~493 MB/s; a local copy of the message words changed
nothing.

**SHA-256 hardware block functions** (x86 SHA extensions, ARMv8 SHA2;
`--hash sha256` archives and library users such as arv). The reference
machine (i7-7500U) has no SHA extensions, so the x86 path was measured on an
AMD Ryzen 7 4800H (Zen 2, Fedora 44, on battery, `performance` governor,
boost on), where the test suite also ran the SHA-NI backend natively
(`sha256 backends tested: [portable] [x86 SHA-NI]`, 279/279). 128 MiB
one-shot, best of 5, pinned, three rounds, digests equal in every run:

| Ryzen 7 4800H | clang 22 | gcc 16 |
|---|---|---|
| SHA-256 portable | 303-304 MB/s | 302-303 MB/s |
| SHA-256 x86 SHA-NI | 2,056-2,069 MB/s | 2,062-2,074 MB/s |
| BLAKE3 (portable) | 743-749 MB/s | 707-708 MB/s |

SHA-NI is 6.8 times the portable code there and 2.8 times BLAKE3's portable
speed. The same run on the i7-7500U: SHA-256 portable 214-216 MB/s, BLAKE3
604-610 MB/s (clang). The ARMv8 path is not measured yet.

**BLAKE3 SIMD chunk functions** (x86 SSE4.1 and AVX2, arm64 NEON; ark's
default hash on create, verify and extract). Whole chunks are hashed 4
(SSE4.1, NEON) or 8 (AVX2) at a time in vector lanes, as subtrees of up to
64 chunks whose parent nodes also go through the lanes; the portable code
takes the same path one chunk at a time. i7-7500U (AVX2, no AVX-512),
128 MiB one-shot, best of 5, pinned, three rounds, digests equal:

| i7-7500U | clang 22 | gcc 16 |
|---|---|---|
| BLAKE3 portable | 582-589 MB/s | 588-596 MB/s |
| BLAKE3 x86 SSE4.1 | 1,224-1,249 MB/s | 1,067-1,108 MB/s |
| BLAKE3 x86 AVX2 | 2,200-2,290 MB/s | 1,973-2,013 MB/s |

AVX2 is 3.9 times the portable code with clang. The kernels alone (8 or 4
chunks per call, no tree) reach 2,375-2,451 and 1,370-1,401 MB/s, so the
tree costs about 4 %; the rest is register pressure (16 state and 16
message vectors in 16 registers). The portable speed is unchanged within
noise (interleaved against the previous code: clang 601-606 vs 583-596,
gcc 568-587 vs 589-599 MB/s), and so is every input size up to 4 KiB,
which needs at least four whole chunks before the next one to use the
lanes. One-shot time per hash, clang: 16 KiB 26.4 -> 12.6 us (AVX2) /
15.1 us (SSE4.1); 64 KiB 106 -> 29 / 45 us; 1 MiB 1.69 -> 0.35 / 0.65 ms.
ark (release, clang), best of 5, interleaved with the previous binary: a
256 MiB file of random bytes (stored chunks, so hashing dominates) verifies
in 0.13 s instead of 0.48 s and extracts in 0.45 s instead of 0.73 s; the
255 MB corpus archive (decode-bound) verifies in 0.98 s instead of 1.03 s
and extracts in 0.53 s instead of 0.59 s. The NEON path is tested under
qemu-aarch64 and on CI's arm64 runners but not measured.

**Create pipeline across files** (ark only; Improvements 21). The I/O thread
reads and submits the chunks of the next files while earlier ones are still
compressed, so a tree of small files keeps every worker busy; the ring holds
two slots per worker. Release builds, best of 3, interleaved with the
previous binary, archives byte-identical. i7-7500U (2C/4T, 4 workers):
`/usr/include` copy (121 MB, 7,645 files) 3.15 s at 103 % CPU -> 1.59 s at
266 %; 40,000 empty files 0.39 -> 0.40 s; 255 MB corpus file 4.85 ->
4.70 s. Ryzen 7 4800H (8C/16T, 16 workers, best of 5): `/usr/include` copy
(93 MB, 5,502 files) 2.54 s -> 0.54 s at 491 %; a 256 MiB random file
0.85 -> 0.80 s. One ring slot per worker gave 1.82-1.97 s here (0.70 s on
the Ryzen), four slots 1.56-1.71 s (0.49 s) for about 2 MiB more memory per
worker.

**Extract decode-ahead across members** (ark only; Improvements 22). The
I/O thread reads, hashes and submits the chunks of the members after the
one it is writing, up to one per ring slot, while it still creates and
writes members strictly in index order. Extract into tmpfs, release builds,
best of 5, interleaved with the previous binary, extracted trees identical.
i7-7500U (4 workers), each step measured on its own:

| Extract | Before | Decode-ahead | + `pread` per chunk | + parent-directory cache |
|---|---|---|---|---|
| `/usr/include` copy (121 MB, 7,645 files) | 0.78 s 96 % CPU | 0.39 s | 0.40 s | 0.38 s 190 % |
| 40,000 empty files | 0.74 s | 0.74 s | 0.75 s | 0.60 s |
| 255 MB corpus file | 0.54 s | 0.53 s | 0.54 s | 0.53 s |
| 256 MiB random file | 0.45 s | 0.45 s | 0.44 s | 0.46 s |

Ring depth for decode-ahead alone, `/usr/include` copy: one slot per worker
0.43 s, two 0.39 s, four 0.38 s; two are kept (the ring already had them).
Ryzen 7 4800H (8C/16T, 16 workers, extract into tmpfs, best of 5, all four
steps together): `/usr/include` copy (93 MB, 5,502 files) 0.55 s at 97 % CPU
-> 0.23 s at 220 %; 40,000 empty files 0.80 -> 0.63 s; a 256 MiB file
0.28 -> 0.28 s; one or four ring slots per worker give the same times.
Verify is unchanged (`/usr/include` copy 0.22 s, the 256 MiB file 0.48 s).
`pread` replaces a `lseek` + `read` pair per chunk (also in verify) without
a measurable change. The parent-directory cache skips the `fstatat` of every
ancestor below the last directory confirmed or created in this run, which
is most of the per-member cost for trees of empty files. After these
changes the I/O thread's per-member system calls (open, write, metadata,
close) bound trees of small files; single large files were already
parallel and are unchanged.
