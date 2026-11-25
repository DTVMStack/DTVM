# CgIR function teardown benchmark

Main is `67f3cafe` after #662. The candidate is `4abff7b`.
The experiment compares Release builds with LLVM 15 and uses Wasmtime
45.0.0 with its cache disabled. The local main executable was previously
built from `8e967b8`, whose Git tree is identical to `67f3cafe`. The
independent runner built both measured revisions from source.

A prior sampling run on `irb` attributed 45 of 3,159 CPU samples to
`CgInstruction::removeRegOperandsFromUseLists`. Whole-function
destruction can discard the use/def index together with the function.
The candidate walks each instruction list once to destroy the objects,
then resets the sentinel. Individual instruction removal retains its
existing bookkeeping.

## Teardown phase

The probe measured the sum of the `CgFunction` destructor bodies in
serial lazy FastRA. One instrumented Release binary selected the old
or new teardown path using an environment variable at process startup.
The path order was shuffled within each round on CPU 1. Values are
per-process medians in milliseconds. Changes are paired median ratios
with 95% bootstrap intervals.

| Case | Rounds | Functions | Old path (ms) | New path (ms) | Change [95%] |
| --- | --- | --- | --- | --- | --- |
| base64cli | 11 | 215 | 1.838 | 0.841 | -55.2% [-58.8%, -51.7%] |
| md5 | 11 | 31 | 0.338 | 0.145 | -53.5% [-60.6%, -50.3%] |
| tpl | 11 | 249 | 3.009 | 1.514 | -50.4% [-56.0%, -42.9%] |
| viu | 11 | 281 | 4.310 | 2.000 | -55.3% [-74.8%, -43.3%] |
| bicg | 11 | 35 | 0.377 | 0.172 | -53.8% [-61.0%, -47.5%] |
| irb | 7 | 1911–1912 | 41.319 | 23.305 | -45.9% [-48.6%, -37.6%] |

## Local process results

Fresh processes were pinned to a single core on an AMD EPYC 9V74.
The catalog used CPU 0 and the large cases used CPU 1. DTVM Singlepass
is a control. A/A repeats the main executable within each round.
Each table shows process wall time and independently shuffled orders.

### Default lazy Multipass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 100.11 | 100.99 | 482.88 | +3.4% [-1.0%, +5.9%] | -1.8% [-6.1%, +6.4%] |
| md5 | 21 | 25.19 | 24.92 | 40.39 | +0.6% [-2.6%, +5.5%] | -0.0% [-4.8%, +9.5%] |
| qr2text | 21 | 45.48 | 44.76 | 121.51 | -2.2% [-3.2%, +0.5%] | +1.5% [-5.0%, +3.4%] |
| tpl | 21 | 255.23 | 256.58 | 804.83 | +3.5% [-4.0%, +13.2%] | +5.7% [-1.3%, +7.8%] |
| viu | 21 | 216.47 | 210.51 | 1322.87 | -1.6% [-9.9%, +2.5%] | -2.7% [-9.7%, -0.9%] |
| atax | 21 | 51.64 | 52.88 | 62.98 | +1.5% [-13.6%, +7.3%] | -5.1% [-23.6%, +7.5%] |
| bicg | 21 | 61.44 | 63.98 | 76.26 | +6.0% [-2.7%, +8.9%] | +1.6% [-6.7%, +6.1%] |
| gemver | 21 | 63.78 | 62.71 | 75.92 | -1.6% [-8.4%, +12.9%] | -0.6% [-6.9%, +3.7%] |
| gesummv | 21 | 49.26 | 47.80 | 57.63 | +0.6% [-2.8%, +5.4%] | +0.9% [-3.8%, +8.5%] |
| mvt | 21 | 55.45 | 56.75 | 66.45 | +0.8% [-5.8%, +3.0%] | +0.5% [-2.6%, +2.2%] |
| gemm | 5 | 2404.62 | 2464.77 | 3281.10 | +2.5% [-10.9%, +10.4%] | -2.4% [-10.0%, +5.0%] |
| 2mm | 5 | 3193.89 | 2974.16 | 4033.46 | -7.1% [-23.2%, +9.2%] | -0.8% [-11.8%, +5.4%] |

### Serial lazy FastRA

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 98.13 | 98.95 | 482.88 | -0.3% [-2.0%, +6.0%] | -1.5% [-5.7%, +0.1%] |
| md5 | 21 | 22.25 | 22.93 | 40.39 | +4.0% [-0.8%, +7.9%] | +4.5% [+0.2%, +9.3%] |
| qr2text | 21 | 43.40 | 42.80 | 121.51 | -1.5% [-3.3%, +1.4%] | -3.1% [-13.0%, +1.6%] |
| tpl | 21 | 239.79 | 249.54 | 804.83 | +3.8% [-11.1%, +6.3%] | +2.9% [-6.9%, +7.9%] |
| viu | 21 | 209.70 | 207.33 | 1322.87 | -1.8% [-7.8%, +2.7%] | +3.6% [-4.4%, +9.1%] |
| atax | 21 | 63.94 | 65.37 | 62.98 | -0.5% [-4.6%, +1.1%] | +0.2% [-3.0%, +5.5%] |
| bicg | 21 | 63.94 | 65.19 | 76.26 | +2.8% [-5.3%, +8.6%] | -1.2% [-4.4%, +5.3%] |
| gemver | 21 | 91.10 | 88.38 | 75.92 | -3.2% [-5.7%, +1.0%] | +0.2% [-4.0%, +5.1%] |
| gesummv | 21 | 45.00 | 46.75 | 57.63 | +2.1% [-1.3%, +20.1%] | +0.5% [-0.5%, +17.2%] |
| mvt | 21 | 80.85 | 79.07 | 66.45 | -1.3% [-5.6%, +0.3%] | +1.0% [-6.6%, +3.5%] |
| gemm | 5 | 3435.32 | 3334.14 | 3281.10 | -4.9% [-10.4%, +7.5%] | +0.0% [-3.9%, +12.5%] |
| 2mm | 5 | 8467.13 | 8494.94 | 4033.46 | +1.7% [-3.4%, +3.1%] | -1.9% [-3.5%, +3.9%] |

### Singlepass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 24.04 | 23.71 | 482.88 | -0.1% [-6.4%, +2.0%] | -2.8% [-3.2%, +9.0%] |
| md5 | 21 | 6.86 | 6.66 | 40.39 | +3.7% [-7.2%, +9.5%] | +1.9% [-8.0%, +10.7%] |
| qr2text | 21 | 9.37 | 9.96 | 121.51 | +1.9% [-1.7%, +10.4%] | +4.4% [-3.8%, +11.8%] |
| tpl | 21 | 105.46 | 106.39 | 804.83 | -1.1% [-4.5%, +2.8%] | -0.9% [-7.8%, +1.0%] |
| viu | 21 | 63.06 | 65.01 | 1322.87 | +1.4% [-1.1%, +4.0%] | +1.0% [-1.6%, +4.6%] |
| atax | 21 | 84.56 | 89.28 | 62.98 | +6.3% [-2.6%, +9.2%] | -0.6% [-4.4%, +6.5%] |
| bicg | 21 | 84.94 | 85.11 | 76.26 | -0.6% [-2.3%, +6.0%] | -0.8% [-5.5%, +0.2%] |
| gemver | 21 | 167.13 | 170.30 | 75.92 | +2.0% [-1.0%, +3.2%] | +1.9% [+0.8%, +6.3%] |
| gesummv | 21 | 61.33 | 61.12 | 57.63 | +0.6% [-0.9%, +5.8%] | +1.3% [-4.2%, +3.9%] |
| mvt | 21 | 101.61 | 97.83 | 66.45 | -2.5% [-8.1%, +0.6%] | -0.0% [-6.3%, +4.0%] |

### Local repeat with a new seed

#### Default lazy Multipass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 41 | 98.09 | 99.51 | 491.58 | +1.0% [-1.8%, +3.4%] | +0.5% [-1.3%, +3.9%] |
| md5 | 41 | 24.71 | 24.03 | 41.07 | +0.6% [-3.0%, +4.0%] | -0.7% [-4.1%, +3.7%] |
| bicg | 41 | 58.80 | 58.42 | 69.14 | +0.2% [-0.9%, +1.2%] | -0.3% [-1.7%, +1.9%] |

#### Serial lazy FastRA

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 41 | 99.22 | 95.28 | 491.58 | -2.0% [-3.5%, -0.8%] | -2.5% [-4.3%, -0.5%] |
| md5 | 41 | 22.51 | 22.73 | 41.07 | +0.4% [-2.9%, +2.5%] | +1.7% [-1.4%, +4.4%] |
| bicg | 41 | 57.88 | 58.13 | 69.14 | -0.5% [-1.7%, +1.7%] | -0.3% [-2.0%, +2.6%] |

#### Singlepass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 41 | 24.07 | 24.15 | 491.58 | +2.5% [-4.3%, +4.0%] | -0.7% [-5.7%, +4.5%] |
| md5 | 41 | 6.27 | 6.53 | 41.07 | +2.7% [-5.3%, +9.4%] | +3.0% [-3.5%, +10.8%] |
| bicg | 41 | 79.72 | 80.02 | 69.14 | +0.7% [-0.7%, +3.3%] | -0.6% [-1.7%, +1.3%] |

## Foreground compilation and IRB wall time

These default-lazy runs used DTVM statistics. Wasmtime was measured with full process wall time and ran after the shuffled DTVM order on `irb`.

| Case | Rounds | Measurement | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- |
| viu | 21 | Foreground compilation | 187.37 | 186.96 | — | -1.6% [-6.3%, +1.2%] | -2.9% [-8.7%, -0.3%] |
| tpl | 21 | Foreground compilation | 234.78 | 221.03 | — | -4.6% [-17.5%, -0.8%] | -4.1% [-10.4%, -2.0%] |
| bicg | 21 | Foreground compilation | 26.14 | 27.03 | — | +1.2% [-4.9%, +7.0%] | +3.7% [-0.2%, +8.4%] |
| irb | 6 | Foreground compilation | 1759.48 | 1711.86 | — | -1.5% [-17.4%, +10.5%] | -1.3% [-12.7%, +7.7%] |
| irb | 6 | Process wall time | 3840.58 | 3859.87 | 10578.18 | +1.4% [-13.1%, +10.0%] | +0.2% [-7.8%, +6.6%] |

## Independent runner

The Ubuntu 24.04 runner recorded commands, executable and fixture hashes, and raw samples. [Hosted benchmark](https://github.com/zoowii/DTVM/actions/runs/45650776452)

### Default lazy Multipass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 25.19 | 21.76 | 36.07 | -5.8% [-18.0%, +8.4%] | -10.3% [-15.2%, +0.8%] |
| qr2text | 21 | 39.88 | 39.36 | 100.47 | -2.4% [-5.1%, +0.1%] | -0.8% [-2.5%, +1.3%] |
| viu | 21 | 180.86 | 177.88 | 1003.96 | -1.1% [-2.3%, -0.6%] | +0.3% [-0.1%, +0.6%] |
| tpl | 21 | 213.99 | 211.02 | 623.86 | -1.1% [-1.7%, -0.6%] | -0.0% [-0.4%, +0.5%] |
| atax | 21 | 49.46 | 49.23 | 61.49 | +1.2% [-1.1%, +3.0%] | +0.9% [-2.0%, +3.2%] |
| bicg | 21 | 58.94 | 56.42 | 64.25 | -1.9% [-6.5%, +2.1%] | -0.6% [-3.6%, +1.1%] |

### Serial lazy FastRA

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 20.16 | 21.63 | 36.07 | +3.4% [-3.2%, +13.2%] | -0.4% [-4.2%, +4.5%] |
| qr2text | 21 | 37.28 | 37.26 | 100.47 | -0.0% [-6.7%, +2.4%] | -0.3% [-3.6%, +5.8%] |
| viu | 21 | 176.07 | 173.76 | 1003.96 | -1.5% [-1.7%, -0.9%] | +0.2% [-0.6%, +0.6%] |
| tpl | 21 | 195.73 | 193.14 | 623.86 | -1.2% [-1.5%, -0.8%] | +0.5% [+0.2%, +1.1%] |
| atax | 21 | 57.47 | 55.82 | 61.49 | -0.4% [-4.7%, +0.3%] | -0.3% [-3.0%, +2.1%] |
| bicg | 21 | 56.59 | 60.32 | 64.25 | +2.5% [-0.6%, +7.4%] | -0.5% [-4.1%, +3.6%] |

### Singlepass

| Case | Rounds | Main (ms) | Candidate (ms) | Wasmtime 45 (ms) | Change [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 5.89 | 6.08 | 36.07 | +5.4% [-9.3%, +8.3%] | -2.9% [-7.8%, +3.9%] |
| qr2text | 21 | 9.89 | 9.13 | 100.47 | -2.3% [-9.1%, -0.6%] | -7.2% [-9.3%, -1.0%] |
| viu | 21 | 54.64 | 54.75 | 1003.96 | +0.9% [-1.3%, +2.5%] | +0.4% [-0.0%, +1.7%] |
| tpl | 21 | 93.44 | 93.66 | 623.86 | -0.3% [-0.7%, +0.5%] | +0.2% [-0.6%, +0.8%] |
| atax | 21 | 71.36 | 71.96 | 61.49 | +0.7% [-0.0%, +1.6%] | +0.5% [-0.2%, +1.4%] |
| bicg | 21 | 72.88 | 73.22 | 64.25 | +0.5% [-1.5%, +2.6%] | +0.4% [-1.2%, +2.1%] |

The independent runner measured 1.1% lower default-lazy process
time on both `viu` and `tpl`. Their 95% intervals were −2.3% to −0.6%
and −1.7% to −0.6%, respectively. Serial FastRA measured −1.5% on
`viu` and −1.2% on `tpl` in the same run.

The first local default-lazy `bicg` estimate was +6.0%. The 41-round
repeat estimated +0.2% [−0.9%, +1.2%] and the independent runner
estimated −1.9% [−6.5%, +2.1%]. All four paired estimates for `gemm`
and `2mm` in the two lazy modes had intervals crossing zero.
The `irb` process and foreground-compilation intervals also crossed zero.


## Validation

- CTest passed 7/7 in each of default lazy Multipass, fixed FastRA,
  eager Multipass, and Singlepass.
- Fixed-FastRA guest disassembly matched for all 881 compiled functions
  across `base64cli`, `md5`, `tpl`, `viu`, `bicg`, `gemm`, and `2mm`
  after normalizing embedded host addresses.
- The repository format check passed.
- The implementation's Wasm and EVM workflow runs cover the existing
  compiler and runtime modes. [Wasm](https://github.com/zoowii/DTVM/actions/runs/45650701423) · [EVM](https://github.com/zoowii/DTVM/actions/runs/45650701518)

## Reproduction

Build main and the candidate in the same Release CMake configuration
with LLVM 15, Singlepass, Multipass, built-in WASI, and CPU exceptions.
Use a byte-identical main copy for A/A and set the executable paths
in the following commands.

```bash
bench=(python3 docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
       --main "$main_dtvm" --main-aa "$main_aa_dtvm" --candidate "$candidate_dtvm"
       --wasmtime "$wasmtime45" --wasm benchmarks/paper/benchmarks/wapm/md5.wasm
       --default-lazy-aa --group catalog)
"${bench[@]}" --cpu 0 --candidate-singlepass \
  --cases base64cli,md5,qr2text,tpl,viu,atax,bicg,gemver,gesummv,mvt \
  --rounds 21 --seed 663211 --out catalog
"${bench[@]}" --cpu 1 --omit-singlepass --cases gemm,2mm \
  --rounds 5 --long-rounds 5 --warmups 1 --seed 663213 --out large
```
