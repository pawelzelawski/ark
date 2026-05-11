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


