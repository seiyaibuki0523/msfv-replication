# Adjudication protocol (read fully before starting)

You are an independent security reviewer. Each item in your batch is a security
*claim* about a specific location in an open-source benchmark codebase. The claim
was produced by an automated pipeline (a static scanner rule plus an LLM analysis).
Your job is to decide, **from the actual source code only**, whether the claim is
true. You are not told, and must not guess, what any downstream tool decided about
the claim. Judge every item on its own merits.

## What you get per item (batch JSON)
- `id`, `benchmark`, `source_root` (absolute path of the checked-out repository)
- `file`, `line`, `end_line`: the location the claim is about (path relative to `source_root`)
- `rule_id`, `cwe`, `scanner_message`, `snippet`: what the static scanner flagged
- `detector_analysis`: the LLM's claim — impact, attack scenario, recommendation. **This is the claim you adjudicate.**
- `documented_entries_for_this_file`: the benchmark's own documented vulnerabilities for this file
  (may be empty). For SmartBugs each entry has `categories` and labelled `lines`; for the others
  an `id`/`category`.

## What you must do per item
1. Open `source_root/file` and read the flagged line **and the whole enclosing function**.
   Read callers/callees, decorators, middleware, modifiers, config or templates when the claim
   depends on them (authentication, input source, framework auto-escaping, `onlyOwner`, `nonReentrant`,
   Solidity version semantics, etc.). Use grep across `source_root` as needed. Spend the effort
   the item needs; do not skim.
2. Decide whether the claim is true **as stated**: does the code actually do what the analysis says,
   and is the described attack possible in this codebase (a lab application or an intentionally
   vulnerable contract counts as exploitable if the code path exists; requiring a logged-in user does
   **not** make a vulnerability false)?
3. Assign exactly one label:
   - `TRUE_DOCUMENTED` — the claim is correct, and it describes the same weakness as one of the
     documented entries for this file (same mechanism; for SmartBugs the same category, at or near a
     labelled line or clearly the same issue).
   - `TRUE_UNDOCUMENTED` — the claim is correct: a genuine weakness exists as described and is
     exploitable in principle in this codebase, but it is not among the documented entries
     (benchmarks only document a subset of what is in the code).
   - `OVERSTATED` — the code pattern the claim points at exists, but the claimed impact or
     exploitability is materially wrong: a guard, framework protection, unreachable condition,
     or missing data flow prevents the described attack, or the issue is only a best-practice /
     informational matter with no realistic security impact.
   - `FALSE` — the claim misdescribes the code: the pattern is not at that location, the data
     flow it asserts does not exist, the function does not behave as claimed, or the analysis
     talks about code that is not there. (This is a hallucinated finding.)
   - `UNSURE` — you could not determine it from the code (say why).
4. Record `matches_documented`: `true` if the weakness you judged is one of the documented entries
   for this file (regardless of label), `false` if not, `null` if there are no documented entries.
5. Record `confidence` (`high`/`medium`/`low`), `evidence` (file:line references you relied on,
   comma-separated), and a one- or two-sentence `justification` written for a security engineer.

## Rules
- Judge the claim, not the scanner rule: a correct scanner hit with a wrong LLM impact story is
  `OVERSTATED` or `FALSE` depending on whether the story is merely exaggerated or simply untrue.
- Do not reward vagueness: if the analysis names a specific mechanism (e.g. "reentrancy") and the
  code has a different weakness at that spot (e.g. an unchecked call), the claim is `FALSE` for the
  named mechanism unless the analysis also correctly describes the actual weakness.
- Solidity: respect the pragma (0.8+ has checked arithmetic; `unchecked` blocks do not),
  modifiers, and whether the function is actually reachable by an attacker.
- Django/Node: check auto-escaping, `|safe`, decorators like `@login_required`/`@csrf_exempt`,
  route registration, and whether user input actually reaches the sink.
- Benchmarks are intentionally vulnerable applications; that does not make every claim true.
  Many findings are real but undocumented (e.g. CSRF, cookie flags); many are exaggerated;
  some describe code that does not exist. Use all five labels as the evidence dictates.
- Work through every item in the batch. Do not skip. Do not change the ids.

## Output
Write a JSON array to the output path given in your instructions, one object per item:
```json
{"id": "...", "label": "TRUE_DOCUMENTED|TRUE_UNDOCUMENTED|OVERSTATED|FALSE|UNSURE",
 "matches_documented": true, "confidence": "high", "evidence": "src/x.sol:88-94",
 "justification": "..."}
```
Write the file incrementally (after every 5 items) so partial work is not lost, and make sure the
final file is valid JSON containing every id from your batch.
