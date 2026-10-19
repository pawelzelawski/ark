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
