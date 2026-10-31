# Multi-language LLM-driven PoC executor — design

Status: DRAFT (implement after the all-4 re-run completes; editing
`poc_validator.py` / `pipeline.py` mid-chain would change the not-yet-started
smartbugs run).

## Why

Today `PocValidator` (Layer 4.5) is **forge-only**:

- `validate_all` returns immediately unless `foundry.toml` exists.
- The PoC signal therefore only exists for Solidity.

Measured consequence (pygoat, 2026-06-11, neutral-prompt re-run):

```
baseline ship 81
full     ship 49   (all signals)
nopoc    ship 49   ← identical to full
nosource ship 43
```

`nopoc == full` proves the PoC signal contributes **zero** on Python — there is
no forge PoC, so removing the PoC signal changes nothing. The paper's
"multi-signal" claim is unsupported for non-Solidity unless PoC becomes a real,
execution-grounded signal in every language.

## Requirement (from Casper, verbatim intent)

- The thing verify consumes is a **verdict** (`poc_triggers_bug` + confidence),
  not the PoC code. So Layer 4.5's job is to produce that verdict, grounded in
  **concrete execution** — not LLM reasoning about whether it *would* trigger.
- Every language needs concrete execution evidence, not just Solidity.
- forge is demoted to **one auxiliary runner the LLM can call**, not the only
  path.

## Architecture — LLM-emitted execution recipe + ephemeral container

Instead of a hard-coded runner per language, the LLM emits a **self-describing
execution recipe**; the harness runs it inside a throwaway, network-less
container and destroys it. Adding a language costs zero harness code — the LLM
already knows the toolchain.

```
Layer 4.5  PocValidator.validate_all(opus_results, repo_path)
  └─ per L4 finding that warrants a PoC (CRITICAL/HIGH/exploit-MEDIUM):
       1. obtain a PoC RECIPE:
          .sol → wrap the existing L4 poc_solidity into a forge recipe
          others → PocGenerator (LLM) emits the recipe (below)
       2. spin up an EPHEMERAL container (docker run --rm --network none),
          bind-mount a fresh mkdtemp() as /poc (rw), write recipe.files there
       3. run  sh -c "<build_cmd> && <run_cmd>"  with a hard timeout
       4. parse output by recipe.trigger_on → same validation dict as forge:
          {poc_compile, poc_triggers_bug, ground_truth_confidence,
           counterexample, error, poc_method}
       5. container auto-removed (--rm); tmpdir deleted in finally.
```

The validation-dict shape is **unchanged**, so Layer 5.5
`_render_poc_signal` / `_verify_function_worker` need no changes — they already
read `poc_triggers_bug` + `ground_truth_confidence`. Only `poc_method` is added
(for the paper's per-runner breakdown).

### Execution recipe (PocGenerator output)

```json
{
  "files": [{"name": "poc.cpp", "content": "..."}],
  "build_cmd": "g++ -std=c++17 -fsanitize=address,undefined -g -o poc poc.cpp",
  "run_cmd": "./poc",
  "trigger_on": "sanitizer_report | marker | nonzero_exit | forge_fail | test_fail",
  "assert_marker": "PWNED_<uuid>",
  "poc_method": "forge|pytest|node|gotest|cpp-asan|rustc|java"
}
```

Per-language toolchain the LLM selects (oracle = concrete execution evidence):

| language | build | run | trigger oracle |
|----------|-------|-----|----------------|
| C/C++    | `clang++/g++ -fsanitize=address,undefined` | `./poc` | **sanitizer report** / crash |
| Rust     | `rustc` / `cargo build` | `./poc` | panic / ASan / marker |
| Go       | `go build` (`-race`) | `./poc` | race report / panic / marker |
| Python   | — | `python poc.py` | exploit assert / marker |
| JS/TS    | — | `node poc.mjs` | throw / marker |
| Java     | `javac` | `java Poc` | exception / marker |
| Solidity | `forge build` | `forge test` | `[FAIL]` |

forge is just one row — exactly "an auxiliary runner the LLM can call".
For C/C++ the sanitizer report is *stronger* than a marker: it is a runtime
proof the memory bug was actually hit, not LLM assertion.

### PocGenerator (new, LLM)

DSPy signature `GeneratePoC`; inputs: language, file_rel, func_name,
func_body, vuln_class, expected_outcome → outputs the recipe above.

Prompt rules:
- Self-contained: import/stub the vulnerable function directly; do NOT require
  the full app running (no live Django server, no DB).
- **Benign payload only**: prove RCE with `touch /poc/MARKER_<uuid>` or
  `print("PWNED_<uuid>")`, path-traversal by reading a sentinel under /poc,
  deserialization by setting a sentinel. For C/C++ rely on the sanitizer —
  no destructive payload needed. NEVER `rm`, network, real secrets.
- The oracle must distinguish *exploit fired* from *clean run*.

### Safety / isolation — ephemeral container (per Casper)

The container is the isolation boundary, so LLM-generated build/run commands
run with no allowlist gymnastics — they simply cannot escape:

- `docker run --rm` — container destroyed on exit (no leftover state).
- `--network none` — no network, full stop.
- `--memory=512m --cpus=1 --pids-limit=256` — resource caps (no fork bomb / OOM).
- `--read-only` rootfs + a single writable bind mount `/poc` (the tmpdir).
- Hard wall-clock timeout → `docker stop` / SIGKILL the run.
- tmpdir `rmtree` in `finally`; image is reused, containers are throwaway.
- Per-finding gate: if the docker daemon is unavailable, skip execution and
  fall back to source-only verify (same as forge-absent today). Knob
  `AISEC_POC_NO_EXEC=1` forces skip.

### Sandbox image

One polyglot toolchain image (`cevanex/poc-sandbox`) with clang/g++, python3,
node, go, rustc, openjdk, and foundry/forge preinstalled. Built once from a
`Dockerfile` checked into `frozen-code/docker/`. Pull/build is a one-time cost;
each PoC run is a fast `docker run` against the cached image.

### Verdict confidence

Execution-grounded True → 0.9; False → 0.1; compile/runtime error (no ground
truth) → 0.0 and `poc_compile=False` (verify falls back to source-only,
exactly as today). Sanitizer-confirmed C/C++ → 0.95 (runtime proof).

## Ablation impact

Once live, re-run the 4 benchmarks. Expected: on pygoat/nodegoat, `nopoc` now
diverges from `full` (PoC signal carries real weight), restoring the
multi-signal story across languages. PoC method breakdown (forge vs
pytest/node) becomes a paper table.

## Implementation checklist

- [ ] `PocConfig`: add `enable_llm_poc: bool = True`, `runners` map.
- [ ] `PocValidator.validate_all`: dispatch by extension; drop the hard
      `foundry.toml` early-return (only skip the forge runner when absent).
- [ ] `_run_forge` (refactor existing `_validate_one` body), `_run_python`,
      `_run_node`, `_run_go`.
- [ ] `PocGenerator` DSPy signature + a backend env
      `AISEC_POC_GEN_BACKEND` (chain, sonnet tail).
- [ ] Layer 4.5 in `pipeline.py`: call generator for non-Solidity findings
      before validate; `is_available()` becomes per-runner.
- [ ] `.env.example` + this doc + PIPELINE.md Layer 4.5 row.
- [ ] Unit tests: one per runner with a known-vulnerable + known-safe fixture.
