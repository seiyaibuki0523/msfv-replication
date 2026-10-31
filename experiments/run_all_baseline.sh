#!/usr/bin/env bash
# Paper §4 baseline runner — 3 sequential hermetic runs.
#
#   detection-only (no verify, no PoC), all-layer Nemotron-only,
#   DVD target, fresh cache per run.
#
# Wall time: ~10 min/run × 3 = ~30 min total (post-21020b1 parallel fix).
#
# Output structure:
#   experiments/baseline_noverify_nopoc/
#     run_1/  findings.json + scan_state.json + metadata.json + stdout.log
#     run_2/  same
#     run_3/  same

set -euo pipefail

ROOT="<MSFV_ROOT>/experiments"
VENV="<AISEC_ROOT>/venv"
RUNNER="$ROOT/run_baseline.py"

source "$VENV/bin/activate"

SUMMARY="$ROOT/baseline_noverify_nopoc/SUMMARY.md"
mkdir -p "$ROOT/baseline_noverify_nopoc"
echo "# Baseline experiment — 3 runs" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Started: $(date)" >> "$SUMMARY"
echo "" >> "$SUMMARY"

OVERALL_START=$(date +%s)

for i in 1 2 3; do
    OUT_DIR="$ROOT/baseline_noverify_nopoc/run_$i"
    mkdir -p "$OUT_DIR"
    LOG="$OUT_DIR/stdout.log"

    echo "─────────────────────────────────────────────────────────────"
    echo "  starting run_$i  (log: $LOG)"
    echo "─────────────────────────────────────────────────────────────"

    RUN_START=$(date +%s)
    if python "$RUNNER" "$i" 2>&1 | tee "$LOG"; then
        STATUS="OK"
    else
        STATUS="ERROR"
    fi
    RUN_END=$(date +%s)
    RUN_ELAPSED=$((RUN_END - RUN_START))

    # Extract finding count from metadata
    META="$OUT_DIR/metadata.json"
    COUNT=$(python3 -c "import json; print(json.load(open('$META'))['findings_count'])" 2>/dev/null || echo "?")

    echo "- run_$i: $STATUS, findings=$COUNT, elapsed=${RUN_ELAPSED}s ($((RUN_ELAPSED/60))m $((RUN_ELAPSED%60))s)" >> "$SUMMARY"
done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))

echo "" >> "$SUMMARY"
echo "Total wall time: ${OVERALL_ELAPSED}s ($((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s)" >> "$SUMMARY"
echo "Finished: $(date)" >> "$SUMMARY"

echo
echo "═════════════════════════════════════════════════════════════"
echo "  ALL 3 RUNS DONE — see $SUMMARY"
echo "═════════════════════════════════════════════════════════════"
cat "$SUMMARY"
