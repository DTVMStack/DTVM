# MIR peephole traversal benchmark

Main `3469f8d` includes #659. Candidate `a118950` walks the MIR block's
statement list in place and scans short-block assignments backward.
Branch folding still applies the same edge and phi updates before
visiting the next statement. The long-block assignment index is reused.

## Pass time and ablation

Separate diagnostic binaries add a `steady_clock` span around
`MIRPeephole::runOnMFunction`. Each sample sums the pass time across all
compiled functions in one fresh process. Fixed serial lazy FastRA keeps
register allocation comparable between the variants. Rows show medians
and paired changes under randomized within-round order.

| Case | Rounds | Main (ms) | In-place (ms) | In-place + reverse (ms) | In-place vs main | Reverse vs in-place | Combined vs main |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tpl | 9 | 8.311 | 7.109 | 6.655 | -13.7% | -5.4% | -20.5% |
| viu | 9 | 9.268 | 7.987 | 7.581 | -15.2% | -5.3% | -18.1% |
| qr2text | 9 | 1.786 | 1.506 | 1.480 | -15.3% | -2.7% | -18.1% |
| bicg | 9 | 0.934 | 0.815 | 0.782 | -10.7% | -6.2% | -15.0% |
| base64cli | 9 | 4.818 | 3.785 | 3.766 | -22.7% | -1.2% | -23.9% |
| mvt | 9 | 1.010 | 0.847 | 0.827 | -16.1% | -2.6% | -19.0% |
| irb | 5 | 72.256 | 63.873 | 62.074 | -10.2% | -2.8% | -14.9% |

`irb` compiled 1,911 functions touching about 258,000 MIR basic blocks.
The statement traversal accounts for most of the improvement. Reverse
lookup saves additional prefix work in short blocks, while matching the
same most recent assignment.

The emitted guest disassembly matched after normalizing embedded host
addresses for every captured fixed-FastRA function object in `tpl`
(249), `viu` (281), `bicg` (35), `gemm` (35), and `2mm` (35).
Default lazy chooses its initial allocator under a time budget, so a
compilation change can affect its allocator decisions.

## Foreground compilation

The Release binaries also ran a separate cohort with
`--enable-statistics`. The metric is accumulated demanded compilation
in the default lazy path, as reported by DTVM.

| Series | Case | Rounds | Main foreground (ms) | Candidate foreground (ms) | D change [95%] | D A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| Initial | tpl | 15 | 169.21 | 164.28 | -3.0% [-6.5%, -0.1%] | -0.6% [-6.8%, +4.1%] |
| Initial | viu | 15 | 181.61 | 178.02 | -1.3% [-3.1%, +1.9%] | +4.7% [+0.1%, +8.4%] |
| Initial | qr2text | 15 | 38.61 | 39.22 | +2.2% [+0.5%, +8.4%] | +2.9% [-0.8%, +10.3%] |
| Initial | bicg | 15 | 21.68 | 21.66 | +6.2% [-10.5%, +9.4%] | -0.2% [-9.5%, +10.1%] |
| Initial | irb | 5 | 1672.13 | 1788.97 | +7.8% [-11.6%, +11.6%] | +1.6% [-8.9%, +4.8%] |
| Repeat | qr2text | 31 | 37.43 | 37.13 | -0.2% [-2.0%, +3.7%] | -0.2% [-2.7%, +1.2%] |
| Repeat | bicg | 31 | 20.20 | 20.19 | -0.8% [-1.2%, +2.3%] | +1.6% [-0.8%, +3.4%] |
| Balanced | irb | 6 | 1721.31 | 1740.53 | +3.6% [-1.9%, +4.0%] | +3.1% [-4.6%, +7.0%] |

For the 17 MiB Ruby `irb` fixture, each runtime evaluated `3+4` as 7.
In the initial series, the candidate immediately followed Wasmtime
in the first three rounds. The balanced repeat used all six
permutations of main, candidate, and the main A/A copy, followed
by Wasmtime at the end of every round.

| Series | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| Initial | 5 | 3669.98 | 3918.32 | 10133.80 | +6.8% [-6.6%, +11.9%] | +1.1% [-6.4%, +3.7%] |
| Balanced | 6 | 3886.70 | 3826.60 | 10194.00 | -0.4% [-10.8%, +8.2%] | -0.8% [-6.1%, +3.7%] |

## End-to-end process time

D is default lazy Multipass. F is lazy Multipass with serial FastRA. SP
is Singlepass. Each local sample used a fresh process pinned to CPU 0
on an AMD EPYC 9V74. Sizes and inputs come from the repository's paper
catalog. Wasmtime 45.0.0 ran with its compilation cache disabled. A/A
uses a byte-identical baseline copy. Changes are paired median ratios
with bootstrap intervals.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 99.92 | 98.68 | 473.59 | -0.4% [-4.3%, +1.5%] | +5.7% [+2.0%, +14.2%] | -0.6% [-2.6%, +4.2%] | -0.2% [-1.8%, +3.3%] |
| md5 | 21 | 25.60 | 24.56 | 40.52 | -4.1% [-5.0%, +0.8%] | -1.3% [-4.1%, +11.0%] | +0.2% [-4.4%, +3.8%] | +0.5% [-3.2%, +3.4%] |
| qr2text | 21 | 46.87 | 46.92 | 119.20 | +1.1% [-2.9%, +6.1%] | -0.6% [-3.9%, +5.0%] | -2.5% [-7.0%, +1.1%] | +1.4% [-10.4%, +5.8%] |
| tpl | 21 | 256.56 | 248.90 | 775.51 | -1.7% [-7.9%, +1.2%] | +3.5% [+0.3%, +7.8%] | -1.5% [-3.9%, +0.0%] | +0.3% [-0.7%, +5.1%] |
| viu | 21 | 215.43 | 210.37 | 1289.53 | -2.4% [-4.1%, -0.8%] | +0.1% [-3.8%, +2.1%] | +1.1% [-5.0%, +7.2%] | -0.7% [-2.2%, +1.2%] |
| atax | 21 | 52.80 | 52.43 | 62.46 | -0.7% [-3.5%, +4.5%] | +0.1% [-2.8%, +2.5%] | +1.3% [-2.4%, +4.8%] | -1.3% [-2.3%, +0.7%] |
| bicg | 21 | 59.89 | 60.96 | 69.97 | +1.9% [-0.3%, +3.1%] | +0.3% [-2.2%, +2.7%] | -1.5% [-5.2%, +1.4%] | -2.5% [-5.1%, +0.7%] |
| gemver | 21 | 61.20 | 60.37 | 71.93 | -1.5% [-3.5%, -0.4%] | -1.8% [-4.1%, +0.2%] | +2.0% [-1.1%, +4.7%] | +0.9% [-1.0%, +3.3%] |
| gesummv | 21 | 47.97 | 46.06 | 55.98 | -3.2% [-10.0%, -2.3%] | -2.1% [-5.6%, -0.6%] | -0.7% [-2.8%, +2.1%] | -0.4% [-2.5%, +0.8%] |
| mvt | 21 | 56.25 | 56.84 | 66.77 | +1.6% [-4.6%, +3.9%] | -0.9% [-2.2%, +3.3%] | -0.5% [-3.4%, +6.3%] | +1.4% [-1.0%, +3.7%] |
| gemm | 5 | 2247.33 | 2258.72 | 3009.24 | +0.5% [-5.6%, +5.3%] | -0.5% [-5.0%, +5.0%] | +3.4% [-3.0%, +6.1%] | — |
| 2mm | 5 | 2695.13 | 2684.37 | 3350.01 | -0.4% [-6.1%, +2.8%] | +0.4% [-4.6%, +3.3%] | +0.6% [-4.7%, +7.2%] | — |

Default lazy `viu` improved by 2.4% locally. On the independent machine,
the estimate was −0.2% and the interval crossed zero. Independent
`tpl` serial FastRA improved by 1.0% [−1.6%, −0.2%].
The throughput-sized PolyBench cases have five paired rounds each.
The default lazy large-case changes were +0.5% for `gemm` and −0.4%
for `2mm`, within the respective A/A intervals. Serial FastRA
`gemm` had a +3.4% point estimate with an interval crossing zero and
overlapping A/A. The sampled Singlepass changes also had intervals
crossing zero on both machines.

The initial `irb` process estimate was +6.8%. With balanced ordering
it was −0.4% [−10.8%, +8.2%], alongside an A/A estimate of −0.8%.
Its balanced foreground estimate of +3.6% was close to the +3.1%
A/A estimate. This fixture has a clear pass-level improvement and
wide whole-process intervals. The small initial foreground slowdown
on `qr2text` was absent in the 31-round repeat, which measured −0.2%.

## Independent runner

The [Ubuntu 24.04 hosted experiment](https://github.com/zoowii/DTVM/actions/runs/45539802639)
runs the same pinned, shuffled comparison. Its artifact contains
fixture hashes, commands and raw samples.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 21.37 | 22.19 | 35.57 | +1.6% [-1.0%, +12.2%] | +0.8% [-1.8%, +2.6%] | +0.0% [-2.5%, +3.1%] | +1.3% [-3.9%, +4.4%] |
| qr2text | 21 | 43.69 | 40.68 | 100.96 | +0.1% [-16.3%, +1.2%] | -0.5% [-3.9%, +0.7%] | -1.5% [-7.1%, +0.1%] | -1.2% [-6.0%, +0.5%] |
| viu | 21 | 190.07 | 187.93 | 1012.93 | -0.2% [-1.7%, +0.9%] | +0.1% [-1.6%, +0.6%] | -0.5% [-1.6%, +0.8%] | +0.5% [-0.4%, +1.1%] |
| tpl | 21 | 221.60 | 220.90 | 630.35 | -0.4% [-0.5%, +0.1%] | +0.6% [+0.0%, +0.8%] | -1.0% [-1.6%, -0.2%] | +0.1% [-0.2%, +0.3%] |
| atax | 21 | 50.60 | 50.04 | 60.97 | -1.0% [-2.6%, +0.2%] | +0.5% [+0.2%, +4.1%] | -0.2% [-1.0%, +2.5%] | -0.3% [-1.4%, +1.0%] |
| bicg | 21 | 57.35 | 57.06 | 64.40 | +0.2% [-1.7%, +1.5%] | +0.3% [-0.2%, +3.4%] | -0.6% [-1.9%, +2.0%] | -1.1% [-1.8%, +0.2%] |

## Reproduce

Configure the two Release builds with GCC 14, LLVM 15, and:

```bash
cmake -S . -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$llvm15_cmake" -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_CPU_EXCEPTION=ON -DZEN_ENABLE_EVM=OFF -DZEN_ENABLE_ASAN=OFF
cmake --build "$build" --target dtvm -j2

bench=(python3 docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
  --main "$main" --candidate "$candidate" --main-aa "$main_copy"
  --wasmtime "$wt45" --wasm benchmarks/paper/benchmarks/wapm/md5.wasm
  --default-lazy-aa --cpu 0)
"${bench[@]}" --group catalog --candidate-singlepass \
  --cases base64cli,md5,qr2text,tpl,viu,atax,bicg,gemver,gesummv,mvt \
  --rounds 21 --seed 659251 --out local-catalog
"${bench[@]}" --group catalog --omit-singlepass --cases gemm,2mm \
  --rounds 5 --long-rounds 5 --warmups 1 --seed 659252 --out local-large

python3 benchmarks/paper/harness/run.py --dtvm "$candidate" --wasmtime "$wt45" \
  --cases tpl,viu,qr2text,bicg,irb --dtvm-modes lazy-G-MT \
  --metric both --stats --repeats 5 --cpu 0 --out candidate-phases
```

The regression test verifies that the statement following an erased
branch still folds. Existing tests cover branch replacement, phi edge
cleanup, self-updates, and invalidation by dynamic assignments. All
seven CTest targets passed with the spec suite in default lazy
Multipass, serial lazy FastRA and eager Multipass. The repository
formatting check passed.
