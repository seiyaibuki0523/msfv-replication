# MSFV Ground Truth — all benchmarks + scoring method

Single reference for the four benchmarks used in the MSFV paper: what counts
as a true vulnerability, how a scan is credited with catching it, and how the
verify-stage metrics (recall retention, shipped volume, FP-cut) are computed.

Authoritative sources on disk:
- `experiments/ground_truth/dvd.json` · `pygoat.json` · `nodegoat.json`
- SmartBugs: the dataset's own `vulnerabilities.json` (SmartBugs-Curated labels)
- Scoring implementation: `experiments/eval_recall.py` (this doc mirrors it)

| Benchmark  | GT unit                    | # GT items | Match granularity        | Label source                          |
|------------|----------------------------|-----------:|--------------------------|---------------------------------------|
| DVD (v4)   | challenge → vuln contract  | 18         | contract (file) level    | canonical challenge intent            |
| PyGoat     | labeled vuln site          | 11         | file level (line noted)  | verified against real source          |
| NodeGoat   | labeled vuln site          | 8          | file level (line noted)  | verified against real source          |
| SmartBugs  | labeled contract           | 143        | file + line (±8 window)  | SmartBugs-Curated `vulnerabilities.json` (DASP) |

---

## Scoring method (mirrors `eval_recall.py`)

### 1. When is a GT item "caught"?

A ground-truth vuln is **caught** if EITHER:
- an **L4** finding on its contract/file is present (baseline) or shipped (a
  verify config), matched by filename/path suffix; for SmartBugs the finding
  line must fall within **±8 lines** (`LINE_WINDOW`) of a labeled line, OR
- an **L5** global-query finding pins the vuln's file via a surviving (non-FP)
  function citation.

L5 matters: subtle DeFi logic bugs (oracle manipulation, arbitrary-call,
governance-flashloan) are **not** semgrep/L4-flaggable — they are caught by L5
semantic queries. An L4-only metric undercounted DVD recall (15→11), so both
layers are credited.

Citation precision: an L5 finding cites many functions across many contracts,
each with its **own** verify verdict. A contract is credited only when its
cited function's verdict ≠ `false_positive` — this stops one kept L5 finding
from crediting every contract it merely mentions.

### 2. Shipped policy (the precision/recall operating point)

`AISEC_SHIP_MIN_SEVERITY` selects the reporting threshold. A finding is
**not shipped** (i.e. dropped) when:
- L4 first line is `Confirmed: no` (analyser self-rejected FP), OR
- every verify verdict is `false_positive`, OR
- (`medium` only) every verdict is `false_positive`/`downgraded` with **no**
  `confirmed`, OR
- severity collapses to `info`.

| Threshold        | Downgraded findings | Stance                    |
|------------------|---------------------|---------------------------|
| `medium` (default) | dropped           | precision-first / aggressive |
| `low`            | shipped             | recall-first / balanced   |

Baseline = every candidate, **no verify** (`shipped_only=False`). Each verify
config re-scores with `shipped_only=True`.

### 3. Metrics

Per benchmark × config (`baseline`, `full`, `nosource`, `nopoc`):

```
TP_detected      = GT items caught by the BASELINE (pre-verify)
TP_retained      = GT items still caught after this verify config
recall_retention = TP_retained / TP_detected        # reject-everything → ~0
shipped_total    = # L4/L5 findings shipped          # the FP side of the trade
```

**FP-cut of the verify stage** (volume the verifier removed):

```
FP_cut(config) = (shipped_baseline − shipped_config) / shipped_baseline
```

Interpretation, and the honest caveat:
- These benchmarks label **known** vulns (a **recall** ground truth); they are
  **not** exhaustively labeled for every non-vuln line. So raw precision / an
  exact FP count is **not** directly computable.
- The defensible claim is therefore a **paired** one: verify removes
  `FP_cut` of the shipped volume **while** `recall_retention` stays ≈ 1.0.
  High retention ⇒ the removed volume was overwhelmingly false positive, so
  `FP_cut` is a lower-bounded FP-reduction proxy, not a raw FP precision gain.
- Report `FP_cut` and `recall_retention` **together**; a cut with retention < 1
  costs real TPs and must be stated as such (`lost_vs_detected` lists which).

Run it:
```
python experiments/eval_recall.py dvd       data/ablation/<label>
python experiments/eval_recall.py pygoat    data/ablation/<label>
python experiments/eval_recall.py nodegoat  data/ablation/<label>
python experiments/eval_recall.py smartbugs data/ablation/<label> <sb_repo>
```

---

## DVD — 18 challenges (contract-level recall)

| Challenge        | Category                 | Vulnerable contract |
|------------------|--------------------------|---------------------|
| unstoppable      | denial_of_service        | src/unstoppable/UnstoppableVault.sol |
| naive-receiver   | access_control           | src/naive-receiver/NaiveReceiverPool.sol |
| truster          | arbitrary_call           | src/truster/TrusterLenderPool.sol |
| side-entrance    | reentrancy               | src/side-entrance/SideEntranceLenderPool.sol |
| the-rewarder     | access_control           | src/the-rewarder/TheRewarderDistributor.sol |
| selfie           | governance_flashloan     | src/selfie/SelfiePool.sol |
| compromised      | oracle_manipulation      | src/compromised/Exchange.sol |
| puppet           | oracle_manipulation      | src/puppet/PuppetPool.sol |
| puppet-v2        | oracle_manipulation      | src/puppet-v2/PuppetV2Pool.sol |
| puppet-v3        | oracle_manipulation      | src/puppet-v3/PuppetV3Pool.sol |
| free-rider       | logic_price              | src/free-rider/FreeRiderNFTMarketplace.sol |
| backdoor         | access_control           | src/backdoor/WalletRegistry.sol |
| climber          | access_control_upgrade   | src/climber/ClimberTimelock.sol |
| wallet-mining    | access_control           | src/wallet-mining/WalletDeployer.sol |
| abi-smuggling    | access_control_calldata  | src/abi-smuggling/SelfAuthorizedVault.sol |
| shards           | logic_rounding           | src/shards/ShardsNFTMarketplace.sol |
| curvy-puppet     | oracle_manipulation      | src/curvy-puppet/CurvyPuppetLending.sol |
| withdrawal       | message_replay           | src/withdrawal/L1Gateway.sol |

---

## PyGoat — 11 vuln sites (file-level recall)

| Category                 | File : line | Name |
|--------------------------|-------------|------|
| sql_injection            | introduction/views.py:158 | SQL Injection (raw string concat) |
| command_injection        | introduction/views.py:430 | Command Injection (subprocess shell=True) |
| command_injection        | introduction/views.py:460 | Command Injection (eval) |
| insecure_deserialization | introduction/views.py:214 | Insecure Deserialization (pickle) |
| xxe                      | introduction/views.py:259 | XXE Injection |
| xss                      | introduction/views.py:101 | XSS Reflected (Lab1) |
| xss                      | introduction/templates/Lab/XSS/xss_lab_2.html:20 | XSS Stored (Lab2 template) |
| xss                      | introduction/templates/Lab/XSS/xss_lab_3.html:22 | XSS Script-context (Lab3 template) |
| broken_access_control    | introduction/views.py:347 | Broken Access Control (cookie) |
| insecure_deserialization | introduction/views.py:560 | YAML Deserialization (A9) |
| ssrf                     | introduction/views.py:963 | SSRF |

---

## NodeGoat — 8 vuln sites (file-level recall)

| Category              | File : line | Name |
|-----------------------|-------------|------|
| ssji                  | app/routes/contributions.js:32 | Server-Side JS Injection (eval) |
| nosql_injection       | app/data/allocations-dao.js:78 | NoSQL Injection ($where) |
| weak_crypto           | app/data/user-dao.js:25 | Plaintext Password Storage |
| redos                 | app/routes/profile.js:59 | ReDoS (catastrophic backtracking) |
| broken_access_control | app/routes/allocations.js:18 | Broken Access Control (IDOR) |
| xss                   | app/routes/profile.js:28 | Improper Output Encoding (XSS context) |
| xss                   | app/data/memos-dao.js:15 | Stored XSS via Memos |
| ssrf                  | app/routes/research.js:15 | SSRF via Research |

---

## SmartBugs-Curated — 143 labeled contracts (file + line ±8)

Ground truth is the dataset's own `vulnerabilities.json` (222 labeled vuln
line-sites across 143 contracts), grouped by DASP-10 category:

| DASP category             | # contracts |
|---------------------------|------------:|
| unchecked_low_level_calls | 52 |
| reentrancy                | 31 |
| access_control            | 18 |
| arithmetic                | 15 |
| bad_randomness            | 8  |
| denial_of_service         | 6  |
| time_manipulation         | 5  |
| front_running             | 4  |
| other                     | 3  |
| short_addresses           | 1  |
| **TOTAL**                 | **143** |

Per-contract line labels are not reproduced here — `eval_recall.py` reads them
directly from the dataset. A contract is caught when a finding lands within ±8
lines of any labeled line for that file, or an L5 finding names the file.
Contracts are `^0.4.x` pragma with no `foundry.toml`, so SmartBugs is
structurally **PoC-less** (no forge harness) — it runs the `baseline`/`full`
verify configs only.
