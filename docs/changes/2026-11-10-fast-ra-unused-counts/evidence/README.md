# Measurement evidence

All samples use independent processes pinned to logical CPU 0, warmed file cache, randomized order within each round, and include loading, compilation, one call and teardown. The contract runner uses the same Wasm and native host implementation in each engine. Contract output and host-operation counts were checked on every run. Wasmtime 45 uses its C API; its callback adapter differs from DTVM's. The `rpow` and `tickmath` pilots are exploratory archived Wasm modules with input `generate(uint256=1)`; the expected values are cross-engine comparisons, not an independent semantic oracle or a claim that they reproduce the paper.

`screen-r21` and `confirm-r31` compare an experimental compiler archive with an otherwise identical control archive. Both share the same core and the same research compiler with its forced-Greedy switch disabled. Only the FastRA object differs. The archive's core also contains an unrelated singlepass compare/select experiment; therefore these two cohorts are evidence for *paired lazy* behavior, not production singlepass behavior.

`production-r31` compares the merged-main runner at `a5e466e2dc010d85e5cd4799a232c0eb46222e3b`, the independently built production candidate and Wasmtime 45. The intermediate research control is also included. Per-process hashes, inputs, configuration, raw samples, medians and paired bootstrap confidence intervals are recorded in each cohort. For example:

| Case | main singlepass ms | main lazy ms | candidate lazy ms | WT45 ms | paired candidate/main lazy median [95% CI] |
| --- | ---: | ---: | ---: | ---: | --- |
| Merkle WAT | 27.20 | 37.00 | 36.29 | 41.57 | 0.987 [0.981, 1.008] |
| Merkle C | 27.88 | 33.70 | 33.92 | 33.60 | 1.033 [0.989, 1.047] |
| Generative NFT | 24.48 | 31.03 | 31.83 | 35.91 | 1.007 [0.993, 1.030] |
| rpow pilot | 6.11 | 14.60 | 14.23 | 17.72 | 0.966 [0.934, 0.993] |
| TickMath pilot | 6.17 | 27.87 | 27.25 | 33.59 | 0.975 [0.966, 0.989] |

Medians in individual columns are not paired ratios. The two rpow/TickMath exploratory cohorts found paired improvements in the same direction; these pointwise intervals are not corrected for multiple comparisons. The native host performs thousands of full-width modular operations for Merkle/NFT and dominates their measurements. Call and host breakdowns in the separate instrumented study use a diagnostic build and are not pooled with these samples.

`wapm-paired-r21` and `wapm-confirm-r31` used candidate and baseline CLI executables on different filesystems and found an unexplained singlepass difference. They are retained rather than discarded. The follow-up `wapm-samefs-r31` copied both binaries into `/tmp/dtvm-contract-build/`, used randomized paired execution and found all singlepass confidence intervals include 1: md5 1.038 [0.988, 1.100], base64cli 0.983 [0.959, 1.013], cowsay 1.007 [0.977, 1.030]. Lazy-F-ST ratios were respectively 0.946 [0.922, 1.005], 0.980 [0.951, 0.996], and 0.982 [0.969, 1.007]. These results do not prove the cause of the earlier difference; process startup and executable layout can affect short timings. The WAPM script checks output equality between each DTVM pair, not against the Wasmtime CLI output.

`validation.json` contains 65 cross-engine contract correctness checks including independent Python references where the harness supports them. Running it requires the official Wasmtime 45 C API and PyCryptodome; use the commands in `benchmarks/paper/harness/contracts/README.md`.

The diagnostic compiler build identified the TickMath `fun_getSqrtRatioAtTick` Wasm body (19,846 instruction bytes according to the loader) as the largest demanded function; a single unpaired run attributed roughly 16.6 ms to foreground compilation. A separate instrumented run split FastRA-related code generation into several milliseconds each for lowering and allocation. This is diagnostic, not a formal pass-level benchmark. Captured x86-64 prologues showed a FastRA stack allocation of `0xd98` bytes plus saved registers, compared with Wasmtime's `0x990`-byte allocation. They compile different implementations with different runtime conventions, so this observation alone does not establish a regression or a speedup. Raw machine-code captures were made on the research builds and are not needed to apply this source change.
