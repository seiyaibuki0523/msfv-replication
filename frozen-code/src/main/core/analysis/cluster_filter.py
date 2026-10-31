"""Cluster-mode Layer-3 filter with 3-tier retry ladder.

Replaces per-finding ``local_filter.filter_findings`` for the new
pipeline path (opt-in via ``AISEC_CLUSTER_MODE=1``). The legacy
per-finding path is left intact in ``local_filter.py``.

Pipeline:

  1. **Cluster formation** — group findings that live in the same
     file (and, by extension, share a callgraph neighbourhood). Cap
     each cluster at ``AISEC_CLUSTER_SIZE`` (default 6 — Liu et al's
     "Lost in the Middle" suggests attention degrades past ~5
     items, so 6 is a small step above what we believe is the safe
     band, leaving room for the retry ladder to catch dispersion).

  2. **Tier 1** — single batched cluster prompt. LLM emits
     per-finding verdicts + cross-cluster ``linkage_groups`` +
     ``batch_confidence`` self-rating.

  3. **Defocus check** — using ``defocus.decide()``. Hard signal
     (JSON broken, model self-rates ≤ 3, min conf < 0.2) or two
     soft signals trigger degrade.

  4. **Tier 2** — split cluster in half and retry. Same signature,
     smaller scope, model attention concentrated. Re-checks defocus.

  5. **Tier 3** — fall back to one-by-one per-finding calls with the
     legacy ``OllamaFilter``-style signature (no batching, max
     attention per finding). This is also where we land if Tier 2
     still defocuses.

The linkage_groups output from Tier 1/2 surfaces "these N findings
share the same root cause" without paying a separate dedupe call.
We persist it onto each contributing finding as
``cluster_linkage_root`` so Layer 4 can route same-root findings
through one Opus call.

All decision points + signal traces hit the triage JSONL log so we
can calibrate thresholds after a few hundred production runs.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from core.ai_engine.local_llm import log_triage_event
from core.analysis.defocus import DefocusDecision, decide, safe_confidences


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def is_enabled() -> bool:
    return os.getenv("AISEC_CLUSTER_MODE", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }


CLUSTER_SIZE       = _env_int("AISEC_CLUSTER_SIZE", 6)
RETRY_LADDER       = os.getenv("AISEC_RETRY_LADDER", "1").strip().lower() in {
    "1", "true", "yes", "on",
}
FORCE_TIER         = os.getenv("AISEC_TRIAGE_FORCE_TIER", "").strip()  # "1" / "2" / "3" for debug
PARALLEL_CLUSTERS  = _env_int("AISEC_PARALLEL_VLLM", 16)


# --------------------------------------------------------------------------- #
# DSPy signatures — cluster + per-finding fallback                            #
# --------------------------------------------------------------------------- #

def _build_cluster_signature():
    import dspy

    class ClusterTriage(dspy.Signature):
        """Triage a small cluster of Semgrep / interest findings from
        the same file.

        For every finding, decide TRUE_POSITIVE / FALSE_POSITIVE plus
        a confidence 0.0-1.0 and a refined severity hint. The cluster
        view is here so you can spot when N findings share the same
        root cause (mark those by their shared ``finding_id`` in
        ``linkage_groups``).

        Output schema (strict JSON list-of-dicts for per_finding):
          per_finding: [
            {"finding_id": "...", "verdict": "TRUE_POSITIVE",
             "confidence": 0.93, "severity_hint": "high",
             "attack_path": "one-paragraph or N/A",
             "brief": "one-line summary"}, …
          ]

        linkage_groups: list of lists of finding_ids that share a
        root cause. Empty list if every finding is independent.

        batch_confidence: 1-10 — your honest self-rating for how
        well you handled this batch. Low means "I was guessing on
        several of these".
        """

        file_path: str         = dspy.InputField()
        findings_json: str     = dspy.InputField(
            desc="JSON array of findings: [{finding_id, rule_id, line, message, code_or_context}, ...]",
        )
        file_context: str      = dspy.InputField(
            desc="Relevant function bodies + call chain summary for this file",
        )

        per_finding: list[dict] = dspy.OutputField(
            desc="One entry per input finding, see docstring for schema",
        )
        linkage_groups: list[list[str]] = dspy.OutputField(
            desc="Groups of finding_ids sharing a root cause; empty list if all independent",
        )
        batch_confidence: int   = dspy.OutputField(
            desc="1-10, your self-rating for the reliability of this whole batch",
        )

    return ClusterTriage


def _build_perfinding_signature():
    """Tier-3 fallback signature — single finding, deep analysis. Mirrors
    the legacy local_filter.NemotronFindingTriage so quality matches."""
    import dspy

    class PerFindingTriage(dspy.Signature):
        """Senior security reviewer triages ONE finding with full attention.

        This is the Tier-3 fallback called when cluster-mode batches
        produce malformed or low-confidence output. The cluster-level
        context is gone; you only see this finding.
        """

        rule_id: str       = dspy.InputField()
        severity: str      = dspy.InputField()
        message: str       = dspy.InputField()
        code_context: str  = dspy.InputField(
            desc="Full function body and call-chain context for the flagged line",
        )

        verdict: str       = dspy.OutputField(desc="TRUE_POSITIVE or FALSE_POSITIVE")
        confidence: float  = dspy.OutputField(desc="0.0 to 1.0")
        severity_hint: str = dspy.OutputField(
            desc="critical | high | medium | low | info",
        )
        attack_path: str   = dspy.OutputField(
            desc="Attack vector if TP, or 'N/A' if FP",
        )
        brief: str         = dspy.OutputField(desc="One-line summary")

    return PerFindingTriage


# --------------------------------------------------------------------------- #
# LM resolution                                                               #
# --------------------------------------------------------------------------- #

def _get_cluster_lm():
    """Resolve the cluster-mode LM as a FallbackLM chain.

    Uses ``resolve_task_chain`` so a server outage on the primary
    falls through to the next chain link automatically, matching the
    cevanex-adapter behaviour.

    Resolution order:
      1. ``AISEC_CLUSTER_MODEL`` if set
      2. ``AISEC_LOCAL_FILTER_MODEL`` (reuses Layer 3 config)
      3. Default chain from ``DEFAULT_TASK_CHAINS``
    """
    from core.ai_engine.local_llm import resolve_task_chain

    if os.getenv("AISEC_CLUSTER_MODEL", "").strip():
        return resolve_task_chain("AISEC_CLUSTER_MODEL", default_lm=None)
    return resolve_task_chain("AISEC_LOCAL_FILTER_MODEL", default_lm=None)


# --------------------------------------------------------------------------- #
# Cluster formation                                                           #
# --------------------------------------------------------------------------- #

def form_clusters(findings: list[dict]) -> list[list[dict]]:
    """Group findings into clusters. Strategy: by ``file`` first, then
    split any group > CLUSTER_SIZE into chunks of size CLUSTER_SIZE."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_file[f.get("file", "")].append(f)

    clusters: list[list[dict]] = []
    for file_path, group in by_file.items():
        # Stable sort by line to keep related findings adjacent
        group.sort(key=lambda x: int(x.get("line", 0) or 0))
        for i in range(0, len(group), CLUSTER_SIZE):
            clusters.append(group[i:i + CLUSTER_SIZE])
    return clusters


# --------------------------------------------------------------------------- #
# Cluster prompt building                                                     #
# --------------------------------------------------------------------------- #

def _build_findings_json(cluster: list[dict]) -> str:
    import json
    out = []
    for i, f in enumerate(cluster):
        out.append({
            "finding_id": f.get("finding_id") or f"F{i + 1}",
            "rule_id":    f.get("rule_id", ""),
            "line":       f.get("line", 0),
            "message":    f.get("message", ""),
            "severity":   f.get("severity", ""),
            "code_or_context": (f.get("code") or f.get("snippet") or "")[:1500],
        })
    return json.dumps(out, ensure_ascii=False)


def _build_file_context(cluster: list[dict], global_map: dict, source_root: str) -> str:
    """Stitch together function bodies referenced by the cluster's
    findings. Cap total length so we stay well under context budget."""
    if not global_map:
        return ""
    bodies = global_map.get("function_bodies", {}) or {}
    if not bodies:
        return ""

    file_path = cluster[0].get("file", "") if cluster else ""
    # Pick all bodies in this file (key prefix match), prioritised by
    # whether their lines are near any finding.
    finding_lines = {int(f.get("line", 0) or 0) for f in cluster}

    relevant_keys = []
    for k, body_obj in bodies.items():
        if not k.startswith(file_path + "::") and not k.startswith(file_path + ":"):
            continue
        if isinstance(body_obj, dict):
            line = int(body_obj.get("line", 0) or 0)
        else:
            line = 0
        # Score: how close is this body to any finding line
        if finding_lines:
            distance = min(abs(line - fl) for fl in finding_lines)
        else:
            distance = 9999
        relevant_keys.append((distance, k))
    relevant_keys.sort()

    parts: list[str] = []
    budget = 20_000
    for _, k in relevant_keys:
        body = bodies[k]
        if isinstance(body, dict):
            text = body.get("body", "") or ""
        else:
            text = body or ""
        snippet = f"// {k}\n{text}\n"
        if len(snippet) > budget:
            snippet = snippet[:budget] + "\n// (truncated)\n"
        parts.append(snippet)
        budget -= len(snippet)
        if budget < 1000:
            break
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Tier 1 / 2 — cluster call                                                   #
# --------------------------------------------------------------------------- #

def _run_cluster_call(
    cluster: list[dict],
    global_map: dict,
    source_root: str,
    signature,
    lm,
    tier: int,
) -> tuple[DefocusDecision, dict[str, Any] | None]:
    """Run one cluster-level DSPy call. Returns (defocus_decision,
    raw_result_dict_or_None). The result dict has keys
    ``per_finding``, ``linkage_groups``, ``batch_confidence``."""
    import dspy

    started = time.monotonic()
    file_path = cluster[0].get("file", "") if cluster else ""
    findings_json = _build_findings_json(cluster)
    file_context = _build_file_context(cluster, global_map, source_root)

    pred = None
    try:
        predictor = dspy.Predict(signature)
        if lm is not None:
            with dspy.context(lm=lm):
                pred = predictor(
                    file_path=file_path,
                    findings_json=findings_json,
                    file_context=file_context,
                )
        else:
            pred = predictor(
                file_path=file_path,
                findings_json=findings_json,
                file_context=file_context,
            )
    except Exception as exc:  # noqa: BLE001
        log_triage_event({
            "tag": "cluster_call",
            "tier": tier,
            "file": file_path,
            "cluster_size": len(cluster),
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        return DefocusDecision(
            True, f"cluster_call_exception_{type(exc).__name__}",
            [("call_exception", 1.0)],
        ), None

    per_finding_raw = getattr(pred, "per_finding", None)
    linkage_raw = getattr(pred, "linkage_groups", None) or []
    self_rating_raw = getattr(pred, "batch_confidence", None)

    # Normalise per_finding into list of dicts
    parsed: list[dict] | None
    if isinstance(per_finding_raw, list):
        parsed = [item if isinstance(item, dict) else {} for item in per_finding_raw]
    else:
        parsed = None

    # Normalise self_rating
    try:
        self_rating = int(self_rating_raw) if self_rating_raw is not None else None
    except (TypeError, ValueError):
        self_rating = None
    if self_rating is not None:
        self_rating = max(1, min(10, self_rating))

    confidences = safe_confidences(parsed or [])

    decision = decide(
        parsed=parsed,
        expected_count=len(cluster),
        confidences=confidences,
        self_rating=self_rating,
    )

    log_record = {
        "tag": "cluster_call",
        "tier": tier,
        "file": file_path,
        "cluster_size": len(cluster),
        "expected_findings": len(cluster),
        "parsed_findings": len(parsed) if parsed is not None else 0,
        "batch_confidence": self_rating,
        "latency_ms": int((time.monotonic() - started) * 1000),
    }
    log_record.update(decision.as_log_dict())
    log_triage_event(log_record)

    if decision.degrade:
        return decision, None

    return decision, {
        "per_finding": parsed or [],
        "linkage_groups": linkage_raw if isinstance(linkage_raw, list) else [],
        "batch_confidence": self_rating,
    }


# --------------------------------------------------------------------------- #
# Tier 3 — per-finding fallback                                               #
# --------------------------------------------------------------------------- #

def _run_perfinding_call(
    finding: dict,
    code_context: str,
    signature,
    lm,
) -> tuple[str, float, dict]:
    """Return (verdict, confidence, enrichment_dict). Conservative
    TRUE_POSITIVE on any error."""
    import dspy

    started = time.monotonic()
    try:
        predictor = dspy.Predict(signature)
        kwargs = dict(
            rule_id=str(finding.get("rule_id", "")),
            severity=str(finding.get("severity", "")),
            message=str(finding.get("message", "")),
            code_context=code_context[:20_000],
        )
        if lm is not None:
            with dspy.context(lm=lm):
                pred = predictor(**kwargs)
        else:
            pred = predictor(**kwargs)

        verdict_raw = str(getattr(pred, "verdict", "")).upper().strip()
        if "FALSE_POSITIVE" in verdict_raw:
            verdict = "FALSE_POSITIVE"
        else:
            verdict = "TRUE_POSITIVE"

        try:
            confidence = float(getattr(pred, "confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        confidence = max(0.0, min(1.0, confidence))

        enrichment = {
            "severity_hint": str(getattr(pred, "severity_hint", "")).strip(),
            "attack_path":   str(getattr(pred, "attack_path", "")).strip(),
            "brief":         str(getattr(pred, "brief", "")).strip()[:300],
        }
        log_triage_event({
            "tag": "perfinding_fallback",
            "tier": 3,
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "verdict": verdict,
            "confidence": confidence,
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        return verdict, confidence, enrichment

    except Exception as exc:  # noqa: BLE001
        log_triage_event({
            "tag": "perfinding_fallback",
            "tier": 3,
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file"),
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        # LLM errors previously returned (TRUE_POSITIVE, 1.0) — the
        # confidence-1.0 default promoted crashed verifications to a
        # certainty-confirmed verdict, polluting Layer 4 input with
        # un-triaged findings. Returning confidence 0.0 instead leaves
        # the verdict but lets the downstream confidence_threshold drop
        # the finding (default 0.5). Real findings still survive Tier 1/2
        # cluster path; only opaque LLM-error edges are filtered.
        return "TRUE_POSITIVE", 0.0, {}


def _file_context_for_finding(finding: dict, global_map: dict) -> str:
    """Stitch a minimal context for per-finding fallback. Try to find
    a function body that contains this line."""
    if not global_map:
        return finding.get("code") or finding.get("snippet") or ""
    bodies = global_map.get("function_bodies", {}) or {}
    file_path = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    best = None
    for k, body in bodies.items():
        if not (k.startswith(file_path + "::") or k.startswith(file_path + ":")):
            continue
        if isinstance(body, dict):
            body_line = int(body.get("line", 0) or 0)
            body_text = body.get("body", "") or ""
        else:
            body_line = 0
            body_text = body or ""
        if not body_text:
            continue
        body_end = body_line + len(body_text.splitlines())
        # prefer the body that contains this finding's line
        if body_line <= line <= body_end:
            return body_text
        # otherwise, closest one wins
        dist = abs(body_line - line)
        if best is None or dist < best[0]:
            best = (dist, body_text)
    if best is not None:
        return best[1]
    return finding.get("code") or finding.get("snippet") or ""


# --------------------------------------------------------------------------- #
# Main entrypoint                                                             #
# --------------------------------------------------------------------------- #

def _is_valid_finding(f: dict) -> bool:
    """Defense-in-depth: drop findings that downstream can't deep-analyse.

    A finding with empty ``file`` flows through Layer 4 producing an
    empty context_bundle. Opus then writes a generic "I don't have
    enough info" analysis that persists as a CRITICAL/HIGH placeholder
    with rule_id-as-title in the customer report. Reject at the gate.
    """
    file_v = (f.get("file") or "").strip()
    if not file_v:
        return False
    if not (f.get("message") or f.get("title") or "").strip():
        return False
    return True


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    """Drop near-duplicates that flag the same (file, line) region from
    multiple Semgrep rules.

    Key: ``(file, line // 5, rule_id_prefix)``. Same file, within a
    5-line window, with similar rule families collapses to a single
    finding (keeping the one with the most severe severity, breaking
    ties by longest message — usually the most descriptive).
    """
    SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}
    by_key: dict[tuple, dict] = {}
    for f in findings:
        file_v = (f.get("file") or "").strip()
        line = int(f.get("line", 0) or 0)
        rule = (f.get("rule_id") or "").lower()
        # Collapse "interest_*" subcategories to one family for dedup
        # so an interest_reentrancy + a Semgrep reentrancy rule at the
        # same spot fold into one finding.
        rule_family = rule.split("_")[0] if rule.startswith("interest_") else rule.split(".")[0]
        key = (file_v, line // 5, rule_family)

        if key not in by_key:
            by_key[key] = f
            continue

        # Tie-break: keep the higher-severity / longer-message finding
        prev = by_key[key]
        prev_rank = SEVERITY_RANK.get((prev.get("severity") or "").lower(), 0)
        new_rank  = SEVERITY_RANK.get((f.get("severity") or "").lower(), 0)
        if new_rank > prev_rank:
            by_key[key] = f
        elif new_rank == prev_rank:
            prev_msg_len = len(prev.get("message") or "")
            new_msg_len  = len(f.get("message") or "")
            if new_msg_len > prev_msg_len:
                by_key[key] = f

    return list(by_key.values())


def cluster_filter_findings(
    findings: list[dict],
    source_root: str,
    global_map: dict | None,
    confidence_threshold: float = 0.5,
) -> list[dict]:
    """Drop-in replacement for ``local_filter.filter_findings`` when
    cluster mode is enabled. Returns the list of TP findings,
    enriched with ``nemotron_*`` fields and ``cluster_linkage_root``
    when applicable."""
    if not findings:
        return []
    if global_map is None:
        global_map = {}

    # Gate + dedupe before any LLM call — saves Opus tokens on garbage
    # input and prevents placeholder findings from persisting downstream.
    original_count = len(findings)
    findings = [f for f in findings if _is_valid_finding(f)]
    after_validation = len(findings)
    findings = _dedupe_findings(findings)
    after_dedupe = len(findings)
    log_triage_event({
        "tag": "cluster_input_filter",
        "input_findings":   original_count,
        "after_validation": after_validation,
        "after_dedupe":     after_dedupe,
        "dropped_validation": original_count - after_validation,
        "dropped_dedupe":     after_validation - after_dedupe,
    })
    if not findings:
        return []

    cluster_sig    = _build_cluster_signature()
    perfinding_sig = _build_perfinding_signature()
    lm             = _get_cluster_lm()

    clusters = form_clusters(findings)
    log_triage_event({
        "tag": "cluster_form",
        "findings": len(findings),
        "clusters": len(clusters),
        "cluster_size_cap": CLUSTER_SIZE,
    })

    accepted_results: dict[int, tuple[str, float, dict]] = {}  # idx in findings -> (verdict, conf, enrichment)
    finding_index: dict[id, int] = {id(f): i for i, f in enumerate(findings)}
    linkage_roots: dict[id, str] = {}  # finding -> root id

    def _process_cluster(cluster: list[dict]) -> None:
        # ── Tier 1: full cluster ─────────────────────────────────────────
        if FORCE_TIER == "3":
            _tier3_fallback(cluster)
            return

        if FORCE_TIER not in {"2", "3"}:
            decision, result = _run_cluster_call(
                cluster, global_map, source_root, cluster_sig, lm, tier=1,
            )
            if not decision.degrade and result is not None:
                _commit_cluster_result(cluster, result, tier=1)
                return
            if not RETRY_LADDER:
                # Ladder disabled: degrade => give up on cluster, mark TP-default
                _tier3_fallback(cluster)
                return

        # ── Tier 2: sub-cluster (split half) ─────────────────────────────
        if len(cluster) > 1 and FORCE_TIER != "3":
            mid = len(cluster) // 2
            sub_a, sub_b = cluster[:mid], cluster[mid:]
            decision_a, result_a = _run_cluster_call(
                sub_a, global_map, source_root, cluster_sig, lm, tier=2,
            )
            decision_b, result_b = _run_cluster_call(
                sub_b, global_map, source_root, cluster_sig, lm, tier=2,
            )

            for sub, dec, res in ((sub_a, decision_a, result_a), (sub_b, decision_b, result_b)):
                if not dec.degrade and res is not None:
                    _commit_cluster_result(sub, res, tier=2)
                else:
                    # ── Tier 3 fallback for this half ────────────────────
                    _tier3_fallback(sub)
            return

        # Single-finding cluster — go straight to Tier 3
        _tier3_fallback(cluster)

    def _commit_cluster_result(cluster: list[dict], result: dict, tier: int) -> None:
        per_finding = result.get("per_finding", []) or []
        # Match per_finding entries to cluster items by index (order-preserving)
        for cluster_item, per_item in zip(cluster, per_finding):
            verdict_raw = str(per_item.get("verdict", "TRUE_POSITIVE")).upper()
            verdict = "FALSE_POSITIVE" if "FALSE_POSITIVE" in verdict_raw else "TRUE_POSITIVE"
            try:
                conf = float(per_item.get("confidence", 0.7))
            except (TypeError, ValueError):
                conf = 0.7
            conf = max(0.0, min(1.0, conf))
            enrichment = {
                "severity_hint": str(per_item.get("severity_hint", "")).strip(),
                "attack_path":   str(per_item.get("attack_path", "")).strip(),
                "brief":         str(per_item.get("brief", "")).strip()[:300],
            }
            idx = finding_index.get(id(cluster_item))
            if idx is not None:
                accepted_results[idx] = (verdict, conf, enrichment)

        # Capture linkage_groups for Layer-4 dedupe hint
        for group in result.get("linkage_groups", []) or []:
            if not isinstance(group, list) or len(group) < 2:
                continue
            root_id = group[0]
            for member_id in group:
                # Find the cluster item with matching finding_id
                for ci, per_item in zip(cluster, per_finding):
                    pid = per_item.get("finding_id")
                    if pid == member_id:
                        linkage_roots[id(ci)] = str(root_id)
                        break

    def _tier3_fallback(cluster: list[dict]) -> None:
        for item in cluster:
            ctx = _file_context_for_finding(item, global_map)
            verdict, conf, enrichment = _run_perfinding_call(
                item, ctx, perfinding_sig, lm,
            )
            idx = finding_index.get(id(item))
            if idx is not None:
                accepted_results[idx] = (verdict, conf, enrichment)

    # Process clusters in parallel (each cluster is its own DSPy call chain)
    workers = max(1, min(PARALLEL_CLUSTERS, len(clusters)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_process_cluster, c) for c in clusters]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                log_triage_event({
                    "tag": "cluster_outer_exception",
                    "error": f"{type(exc).__name__}: {exc}",
                })

    # Assemble final filtered list
    filtered: list[dict] = []
    for i, finding in enumerate(findings):
        verdict, conf, enrichment = accepted_results.get(
            i, ("TRUE_POSITIVE", 1.0, {}),
        )
        if verdict == "TRUE_POSITIVE" and conf >= confidence_threshold:
            finding["local_filter_confidence"] = conf
            if enrichment.get("severity_hint"):
                finding["nemotron_severity_hint"] = enrichment["severity_hint"]
            if enrichment.get("attack_path"):
                finding["nemotron_attack_path"] = enrichment["attack_path"]
            if enrichment.get("brief"):
                finding["nemotron_brief"] = enrichment["brief"]
            root = linkage_roots.get(id(finding))
            if root:
                finding["cluster_linkage_root"] = root
            filtered.append(finding)

    log_triage_event({
        "tag": "cluster_filter_summary",
        "input_findings":      len(findings),
        "clusters_processed":  len(clusters),
        "output_filtered":     len(filtered),
        "linkage_root_count":  len({r for r in linkage_roots.values()}),
    })

    return filtered


__all__ = [
    "is_enabled",
    "cluster_filter_findings",
    "form_clusters",
    "CLUSTER_SIZE",
]
