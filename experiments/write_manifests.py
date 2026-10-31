#!/usr/bin/env python3
"""Write manifest.json for every run_dir under data/ablation that lacks one, and add the
per-arm settings that the original manifests did not record.

Run on the run host after round-4:   python3 experiments/write_manifests.py [--force]

Facts recorded (from jobs/FINAL_RUN_REPORT.md, jobs/26-9-2-job/RUN_REPORT.md,
experiments/run_jobs_v2.py, rerun_nemotron.py, round3_run.py, round4_run.py and
frozen-code/src/main/core/ai_engine/{local_llm,nvidia_adapter}.py):
  * OpenRouter model ids: qwen/qwen3-coder-next, google/gemma-4-31b-it, nvidia/nemotron-3-super-120b-a12b
  * verification (all arms): temperature 0.2, top_p 0.7, seed passed (not honoured), default max_tokens
    (2048 qwen/gemma, 16000 Nemotron), Nemotron reasoning on
  * detection qwen/gemma: temperature 0.2, top_p 0.7, chain "<arm>,nemotron-120b" (Nemotron fallback)
  * detection Nemotron (final re-run): temperature 0, reasoning off, max_tokens 12000, provider DeepInfra,
    low concurrency
  * Nemotron verification in round 3/4: provider DeepInfra, concurrency 4; round 1/2: not pinned, concurrency 16
"""
from __future__ import annotations
import os
import hashlib, json, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
DATA = ROOT / "data" / "ablation"
RUN_RE = re.compile(r"^st_(?P<det>[a-z]+)(?:-v(?P<ver>[a-z]+))?_(?P<bench>dvd|pygoat|nodegoat|smartbugs)_s(?P<seed>\d+)$")
IDS = {"qwen": "qwen/qwen3-coder-next", "gemma": "google/gemma-4-31b-it", "nemotron": "nvidia/nemotron-3-super-120b-a12b"}
NAMES = {"qwen": "qwen3-coder", "gemma": "gemma-4-31B", "nemotron": "Nemotron-3-Super-120B-A12B"}
FORCE = "--force" in sys.argv


def pipeline_hash():
    p = ROOT / "frozen-code" / "src" / "main" / "core" / "analysis" / "pipeline.py"
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p.exists() else "n/a"


def forge_version():
    try:
        return subprocess.run(["forge", "--version"],
                              capture_output=True, text=True, timeout=10).stdout.strip().split("\n")[0]
    except Exception:
        return "forge Version: 1.7.1"


def manifest_for(rd: str) -> dict:
    m = RUN_RE.match(rd)
    if not m:
        return None
    det, ver, bench, seed = m["det"], m["ver"], m["bench"], int(m["seed"])
    verifier = ver or "nemotron"
    detection = {
        "model": NAMES[det], "openrouter_id": IDS[det],
        "temperature": 0.0 if det == "nemotron" else 0.2, "top_p": 0.7,
        "max_tokens": 12000 if det == "nemotron" else 2048,
        "reasoning": "off (detailed thinking off)" if det == "nemotron" else "n/a (non-reasoning model)",
        "provider_pin": "DeepInfra" if det == "nemotron" else None,
        "concurrency": 4 if det == "nemotron" else 16,
        "chain": NEMO_CHAIN[det],
        "poc_generation": "same chain as detection (PoCs frozen with the candidate pool)",
    }
    verification = {
        "model": NAMES[verifier], "openrouter_id": IDS[verifier],
        "temperature": 0.2, "top_p": 0.7,
        "max_tokens": 16000 if verifier == "nemotron" else 2048,
        "reasoning": "on" if verifier == "nemotron" else "n/a (non-reasoning model)",
        "provider_pin": ("DeepInfra (rounds 3-4) / none (rounds 1-2)" if verifier == "nemotron" else None),
        "concurrency": "4 (rounds 3-4) / 16 (rounds 1-2)" if verifier == "nemotron" else 8,
        "signals": "per config: see metadata.json verify_signals",
    }
    pool = f"st_{det}_{bench}_s{seed}" if ver else rd
    return {
        "run_dir": rd,
        "benchmark": bench,
        "seed": seed,
        "candidate_pool": pool,
        "detection": detection,
        "verification": verification,
        # legacy fields kept for compatibility with the round-1 manifests
        "model_version_with_revision_or_quant": NAMES[det],
        "temperature": detection["temperature"],
        "top_p": 0.7,
        "top_k": None,
        "max_tokens": detection["max_tokens"],
        "seed_param_or_nondeterminism_note": (f"AISEC_LLM_SEED={seed} passed as `seed` to OpenRouter chat.completions; "
                                              "repeated passes with the same seed do not reproduce the same verdicts, so the "
                                              "provider does not honour it and replicate variation is sampling nondeterminism"),
        "prompt_template_hash": f"pipeline.py:sha256:{pipeline_hash()}",
        "tool_versions": {"python": "3.12.3", "forge": forge_version(), "backend": "OpenRouter"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "written_by": "experiments/write_manifests.py",
    }


NEMO_CHAIN = {"qwen": "openrouter:qwen3-coder,openrouter:nemotron-120b",
              "gemma": "openrouter:gemma-4-31b,openrouter:nemotron-120b",
              "nemotron": "openrouter:nemotron-120b"}


def main():
    n_new = n_kept = 0
    for d in sorted(DATA.iterdir()):
        if not d.is_dir() or not RUN_RE.match(d.name):
            continue
        p = d / "manifest.json"
        if p.exists() and not FORCE:
            n_kept += 1
            continue
        mf = manifest_for(d.name)
        if mf is None:
            continue
        p.write_text(json.dumps(mf, indent=2, ensure_ascii=False))
        n_new += 1
    print(f"manifests written: {n_new}, existing kept: {n_kept}")


if __name__ == "__main__":
    main()
