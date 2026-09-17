# WAPM Reproduction Guide

WAPM-style CLI wasm modules used for **correctness testing** (`runtest_wapm.sh` / `runtest_webassembly.py`) and the **Time-to-First-Invocation** performance experiment (originally `test_lazy.sh`).

| Item | Value |
|------|-------|
| wasm + configs | `benchmarks/wapm/` (mirrors `case/wapm/` in the testsuite) |
| Correctness runner | `runtest_wapm.sh`, `runtest_webassembly.py -s wapm` |
| Performance runner | **`test_lazy.sh` (absent from the archive)** |
| Paper latency table | the paper's lazy-TTFI table (**20 cases**; not shipped) |
| Lab notebook | experiment archive, § lazy / WAPM |

---

## 1. Two Test Kinds — Do Not Mix

| Purpose | Script | Verdict | Timing |
|---------|--------|---------|--------|
| **Functional correctness** | `case/wapm/runtest_wapm.sh` | output diff / exit code | no lazy latency |
| **Functional correctness (Python)** | `runtest_webassembly.py -r <runtime> -s wapm` | expected / regex / special pass rules | wall time progress only |
| **Lazy TTFI** | `test_lazy.sh` (missing) | no output check (or subset only) | `Execution time` / `Average time` |

The paper's **latency table** came from **`test_lazy.sh` runs plus manual tabulation**, not from `runtest_wapm.sh` output.

---

## 2. Archive Gaps

| Item | Status |
|------|--------|
| `webassembly-testsuites/test_lazy.sh` | ❌ **missing** (the notebook has only its run log) |
| Latency-table **generator script** | ❌ **missing** |
| WAPM registry package names/versions | ❌ missing |
| jq's `-M .` filter | ⚠️ the archived `jq.wasm.conf` does **not** set it; the `test_lazy` log shows jq printing help only |
| `RANDOMCASE` in `iwasm.conf` | ⚠️ contains a typo `zuk.wasm.conf` (should be `zuk.wasm`) |

---

## 3. Environment and Directory Dependencies

Run from the **`webassembly-testsuites` root** (or an equivalent layout); the following must exist:

| Path | Purpose |
|------|---------|
| `case/wapm/*.wasm` | the modules under test |
| `case/wapm/*.wasm.conf` | per-case commands for the bash runner |
| `case/wapm/*_config.py` | per-case commands for the Python runner (occasionally differs from `.conf`) |
| `case/wapm/iwasm.conf` | `RANDOMCASE` list for iwasm mode |
| `case/wapm/wasmtime.conf` | skip list for wasmtime mode |
| `case/wapm/lib/` | bundled Python 3.6 stdlib for **python.wasm** |
| `case/wapm/fonts/` | fonts for **chkfont.wasm**, **figlet.wasm** |
| `case/wapm/benchmark/des.wasm` | sub-module applied by **wasm3.wasm** |
| `case/wapm/parallel-small.png` | input image for **viu.wasm** |
| `case/wapm/pee.wasm.expected` | comparison file for **pee.wasm** |
| `case/wapm/*.wasm.expected` | golden outputs for correctness checks |

### 3.1 DTVM (the paper's lazy column)

Build per `runtimes/dtvm/BUILD.md`, commit pin **`882c83155`**. Inferred lazy-benchmark options:

```bash
dtvm -m multipass \
  --enable-multipass-lazy \
  --disable-multipass-greedyra \
  --disable-multipass-multithread \
  case/wapm/<case>.wasm [args...]
```

Meaning: **Time to First Invocation** = module loaded and first executable code produced (post-loading & compilation), matching the metric used in the lab notebook and the Wasmer WAPM-revival blog post.

### 3.2 Baselines (latency-table columns)

| Column | Inferred command prefix |
|--------|-------------------------|
| wasmtime | `wasmtime case/wapm/<case>.wasm ...` (no `run` subcommand in the log) |
| wasmer cranelift | `wasmer run --cranelift ...` |
| wasmer llvm | `wasmer run --llvm ...` |
| wasmer singlepass | `wasmer run --singlepass ...` |

The `test_lazy.sh 10` log shows wasmer llvm was **repeated 10 times and averaged** (first run noticeably slower — compile/cache effects); bare `test_lazy.sh` ran **once per case**.

---

## 4. Correctness Runner: `runtest_wapm.sh`

Path: `case/wapm/runtest_wapm.sh`

```bash
cd webassembly-testsuites
./case/wapm/runtest_wapm.sh          # default iwasm
./case/wapm/runtest_wapm.sh wasmtime # wasmtime (skips FAILED_CASENAME)
```

### 4.1 Command Assembly

For each `*.wasm`:

1. Read `case/wapm/<name>.wasm.conf` (if present)
2. Default: `RUN_COMMAND="--heap-size=0 --stack-size=8000000 case/wapm/<name>.wasm"`
3. Execute: `$HEAD_COMMAND $COMMAND | $VM $DIR $RUN_COMMAND $PARAMETER`

With `HEAD_COMMAND=eval`, the shell resolves pipes/redirections (e.g. `eval echo 3+4 | ...`).

### 4.2 Three Case Strategies

#### A. Normal cases (golden output diff)

- `<case>.wasm.expected` is the expected output
- Actual output is stripped of NUL via **`tr -d '\000'`** before comparison
- **amirali NUL normalization**: the wasm stdout often carries `\0` padding; the golden file has none, so stripping is required to match `amirali.wasm.expected`

#### B. `RANDOMCASE` (exit-code only, no output diff)

Defined in `case/wapm/iwasm.conf`:

```bash
RANDOMCASE="uuid.wasm fortune.wasm md5.wasm erdtree.wasm greg.wasm zuk.wasm.conf"
```

On a match: **check exit code only** — no `tr -d '\000'`, no expected diff.

| case | Reason (inferred) |
|------|-------------------|
| **fortune** | random fortune each run; output not fixable |
| **greg** | calendar output depends on the date |
| **md5** | output is stable for a fixed input, but the archive still treats it as exit-only (same strategy as fortune) |
| **uuid** | generates a different UUID each run |
| **erdtree** | scans the file tree under `--dir=.`; output depends on directory contents |
| **zuk** | `generate 3 uuids` produces random output |

> ⚠️ The config's **`zuk.wasm.conf` should be `zuk.wasm`**; as written, zuk actually takes the golden-diff path instead of exit-only.

#### C. `UNEXPECTED_CASE` (main.wasm)

- `main.wasm.conf` sets `UNEXPECTED_CASE=("main.wasm")`
- Behavior: after running, **overwrite** `.expected` with the current output (a MySQL interaction; output is not reproducible)
- `wasmtime.conf` additionally lists `main.wasm python.wasm spidermonkey.wasm wasm3.wasm` in **`FAILED_CASENAME`**, skipping them in wasmtime mode

### 4.3 Extra Rules in the Python Runner (`runtest_webassembly.py`)

Coexists with the bash script; rules differ slightly:

| Mechanism | Behavior |
|-----------|----------|
| **NUL normalize** | `checkExpected()` applies `rstrip('\x00')` to both result and expected |
| **sam / suggest nonzero exit** | if `return_code == 1` **and** output still matches expected → **PASS** (`sam` ends with `Compiled without SDL support...` and often exits nonzero) |
| **ignore** | `config.py`: `ignore_case=sqlite.wasm`; `interp_ignore=main.wasm wasm3.wasm` |
| **no expected** | `expected == "OFF"` and `return_code == 0` → PASS |

---

## 5. Performance Runner: `test_lazy.sh` (inferred from its log)

Three invocations appear in the lab notebook:

```bash
bash ./test_lazy.sh wasmtime   # once per case; prints Execution time + Actual output
bash test_lazy.sh              # default runtime, once, prints Average time
bash ./test_lazy.sh 10         # 10 reps averaged (wasmer llvm in the log)
```

Output format:

```text
============ Testing amirali ============
Executing command:  : | /mnt/dtvm_test/wasmtime  case/wapm/amirali.wasm
Execution time: 42.255 ms
...
Average time for ' ... ': 7.120 ms
```

**Inferred logic** (pending confirmation against the original script):

1. Iterate the cases with commands matching **`*.wasm.conf` plus test_lazy-specific simplifications** (the lazy log does **not** use iwasm's `--heap-size=0 --stack-size=8000000`)
2. Time each case once or N times; write the average to the log
3. The paper's **20-case** table was **manually extracted** from the log into `latencytofirstinvocation.md` (no generator script exists)

### 5.1 The 20 Cases in the Latency Table

`amirali, base64cli, chkfont, code-stock, cowsay, dice, echo, erdtree, figlet, irb, md5, pi, pkg1, qr2text, sam, suggest, tpl, uuid, viu, zuk`

**Excluded** (10): `fortune, greg, jq, jyt, main, pee, python, spidermonkey, sqlite, wasm3` — mostly interactive / non-reproducible / wasmtime-skipped / unstable.

### 5.2 Latency-Table Columns

| Column | Meaning |
|--------|---------|
| wasm file size (KB) | module file size |
| **dtvm lazy** | DTVM `dtvm` + `--enable-multipass-lazy` Time to First Invocation (ms) |
| wasmtime / wasmer * | same metric for each baseline, in ms |
| `*/dtvm` | baseline divided by dtvm lazy |

---

## 6. Per-case Commands and Special Dependencies

Commands below come from **`*.wasm.conf`** (consistent with the `test_lazy.sh` log). Run from the `webassembly-testsuites` root.

| case | Command essence | Dependency | Correctness strategy | latency table |
|------|-----------------|------------|----------------------|:-------------:|
| amirali | `: \| wasmtime case/wapm/amirali.wasm` | — | golden + **NUL strip** | ✅ |
| base64cli | `... base64cli.wasm encode helloworld` | — | golden | ✅ |
| chkfont | `eval ... --dir=./fonts chkfont.wasm fonts/small.flf` | `fonts/` | golden | ✅ |
| code-stock | no args | — | golden | ✅ |
| cowsay | `eval ... cowsay.wasm hello` | — | golden | ✅ |
| dice | `echo help \| ... dice.wasm` | — | golden | ✅ |
| echo | `... echo.wasm 1234567890` | — | golden | ✅ |
| erdtree | `... --dir=. erdtree.wasm package` | file tree under CWD | **RANDOMCASE exit-only** | ✅ |
| figlet | `eval ... --dir=fonts figlet.wasm hello` | `fonts/` | golden | ✅ |
| fortune | no args | — | **RANDOMCASE exit-only** | ❌ |
| greg | no args | — | **RANDOMCASE exit-only** | ❌ |
| irb | `eval echo 3+4 \| ... irb.wasm` | stdin expression | golden (prints 7) | ✅ |
| jq | `echo {"zk":123456} \| ... jq.wasm` | should add **`-M .`** as filter (not configured in the archive) | golden missing/unstable | ❌ |
| jyt | `echo {...} \| ... jyt.wasm json-to-yaml` | — | interactive / long run | ❌ |
| main | `eval echo 'SHOW DATABASES;' \| ... --dir=. main.wasm` | MySQL wasm | UNEXPECTED / skip | ❌ |
| md5 | `... md5.wasm helloworld` | — | **RANDOMCASE exit-only** | ✅ |
| pee | `eval echo '' \| ... --dir=. pee.wasm -- pee.wasm.expected` | expected file | golden | ❌ |
| pi | `... pi.wasm 1` | — | golden | ✅ |
| pkg1 | no args | — | golden | ✅ |
| python | `... --dir=case/wapm/lib python.wasm -c 'print(...)'` | **`lib/`** Python 3.6 | needs correct quoting (see below) | ❌ |
| qr2text | `eval ... qr2text.wasm https://wapm.io` | — | golden | ✅ |
| sam | `... sam.wasm -debug sam.wav` | — | golden + **exit 1 allowed** | ✅ |
| spidermonkey | `eval echo 3+4 \| ... spidermonkey.wasm` | JS engine | wasmtime **skip** | ❌ |
| sqlite | `echo -e '.show\n.q' \| ... sqlite.wasm` | — | ignore | ❌ |
| suggest | `... suggest.wasm instakk update install` | — | golden + **exit 1 allowed** | ✅ |
| tpl | `echo 'Δ is 123456-123455.' \| ... tpl.wasm` | — | golden | ✅ |
| uuid | no args | — | **RANDOMCASE exit-only** | ✅ |
| viu | `eval ... --dir=. viu.wasm parallel-small.png` | **`parallel-small.png`** | golden | ✅ |
| wasm3 | `eval ... --dir=. wasm3.wasm --func apply benchmark/des.wasm` | **`benchmark/des.wasm`** | skip / ignore | ❌ |
| zuk | `... zuk.wasm generate 3 uuids` | — | **RANDOMCASE exit-only** | ✅ |

### 6.1 Notes on Special Cases

#### jq and `-M .`

- The archived `jq.wasm.conf` only pipes `echo '{"zk":123456}' | jq.wasm` with **no filter**; the `test_lazy` log shows jq printing its **help**.
- For a deterministic correctness test the usual command is `echo '{"zk":123456}' | jq.wasm -M .` (**`-M`** = monochrome, **`.`** = identity filter).
- **jq is not in the latency table.**

#### python.wasm

Recommended command (handwritten example in the lab notebook):

```bash
wasmtime --dir=case/wapm/lib case/wapm/python.wasm -c "$(echo 'print(f\"helloworld\")')"
# or
wasmtime --dir=case/wapm/lib case/wapm/python.wasm -c "$(echo 'print(123456789)')"
```

`*_config.py` uses `echo 'print(123456789)'`; wrong quoting causes bash syntax errors (visible in the log).

#### erdtree.wasm

- Requires **`--dir=.`** and the **`package`** subcommand (`.wasm.conf`)
- Scans and packages the current directory; output varies with directory contents → **RANDOMCASE**
- ⚠️ `erdtree_config.py` says `parameter=aarch64`, which is **inconsistent** with lazy/conf; the **`.wasm.conf`** wins

#### irb / spidermonkey

- Both use `eval echo 3+4 | ...` to feed an expression on stdin
- **irb**: expects `3+4 => 7` (in the latency table)
- **spidermonkey**: the log shows a long hang then ^C; **skipped** in wasmtime correctness

#### wasm3.wasm

- `eval ... --dir=. wasm3.wasm --func apply case/wapm/benchmark/des.wasm`
- Depends on **`benchmark/des.wasm`**; `config.py` ignores `wasm3.wasm` for the dtvm interpreter

---

## 7. Recommended Reproduction Steps

### 7.1 Setup

```bash
cd webassembly-testsuites   # or the equivalent layout under benchmarks/paper/benchmarks/wapm
# verify the wasm
shasum -a 256 -c benchmarks/wapm/SHA256SUMS   # when using the archived copy
```

### 7.2 Correctness Smoke (iwasm / dtvm)

```bash
./case/wapm/runtest_wapm.sh iwasm
# or
./runtest_webassembly.py -r /path/to/dtvm --dtvm-options="-m multipass" -s wapm
```

### 7.3 Lazy Latency (needs `test_lazy.sh` reconstructed or manual timing)

**Single-case example (wasmtime, matches the log):**

```bash
/usr/bin/time -f '%e' wasmtime case/wapm/echo.wasm 1234567890
```

**DTVM lazy:**

```bash
dtvm -m multipass --enable-multipass-lazy \
  --disable-multipass-greedyra --disable-multipass-multithread \
  case/wapm/echo.wasm 1234567890
```

Repeat for the **20 table cases**, record ms, and compare with the paper's latency table.

**Wasmer llvm 10-run average (matching the log's protocol):**

```bash
for i in $(seq 1 10); do
  /usr/bin/time -f '%e' wasmer run --llvm case/wapm/amirali.wasm
done
```

### 7.4 Assembling the Latency Table

The archive has **no** Excel/script generation step. The historical flow was:

1. `test_lazy.sh` → full log
2. Manually extract ms for 20 cases × 5 runtimes
3. Fill a latency table in the paper's format (including ratio columns)

---

## 8. Relationship to PolyBench Lazy

| Item | WAPM | PolyBench |
|------|------|-----------|
| Runner | `test_lazy.sh` | **none** (script missing) |
| DTVM lazy switch | `--enable-multipass-lazy` | same (the xlsx `+ lazy` column) |
| Timing meaning | Time to **First** Invocation | processing time (hot benchmark, different metric) |

---

## 9. Related Files

| File | Description |
|------|-------------|
| [`MANIFEST.md`](MANIFEST.md) | wasm inventory |
| [`README.md`](README.md) | directory overview |
| paper latency table | not shipped; see the paper |
| [`../../scripts/README.md`](../../scripts/README.md) | script index |
| experiment archive | original `test_lazy.sh` logs |

---

## 10. Open Questions for the Original Experimenters

1. **`test_lazy.sh` source** (timing implementation: bash / Rust wrapper / dtvm built-in?)
2. Whether the **latency table** used a **single run** everywhere or **10-run averages** for wasmer-type runtimes
3. Whether **jq** should use **`-M .`** and whether it was ever part of the latency measurement
4. Whether the **`zuk.wasm.conf` typo** in `iwasm.conf` was the original behavior
5. Whether DTVM lazy WAPM runs disabled the wasmtime/wasmer **module cache** (the log suggests wasmer llvm had a cache)
