"""Render vault search results as prompt fragments for L4, L5, AutoSecAgent."""

from __future__ import annotations

from core.vault.search import (
    VaultSearchResult,
    hint_for_finding,
    hint_for_recon,
    patterns_for_query,
    read,
)


_HINT_HEADER_FINDING = (
    "## Vault Knowledge Hints\n"
    "The following notes from the vault knowledge base look relevant to this finding."
)

_HEADER_RECON = (
    "## Vault Knowledge Hints (target context)\n"
    "Pre-engagement knowledge selected from the vault for this target's stack and "
    "reconnaissance signature."
)

_PATTERNS_HEADER = "## Reference Patterns from Vault"


# --------------------------------------------------------------------------- #
# Layer 4 — per-finding hint                                                  #
# --------------------------------------------------------------------------- #

def render_finding_hint(
    finding: dict,
    *,
    lang_hint: str = "",
    inline_top: int = 3,
    list_remaining: int = 5,
    body_char_cap: int = 4000,
) -> str:
    """Return a prompt fragment for Layer 4. Empty when no API or no hits."""
    results = hint_for_finding(
        finding, lang_hint=lang_hint, k=inline_top + list_remaining
    )
    if not results:
        return ""

    parts = [_HINT_HEADER_FINDING]

    for result in results[:inline_top]:
        body = _fetch_body(result.path, body_char_cap)
        if not body:
            continue
        parts.append(_format_inline(result, body))

    rest = results[inline_top:]
    if rest:
        parts.append(
            "### Other potentially relevant vault notes\n"
            + "\n".join(f"- `{r.path}` — {r.title} [{r.note_type or '?'}]" for r in rest)
        )

    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# Layer 5 — push tag-matched pattern bodies                                   #
# --------------------------------------------------------------------------- #

def render_patterns_for_query(
    query_name: str, *, k: int = 4, body_char_cap: int = 6000
) -> str:
    """Return a prompt fragment for a Layer 5 query."""
    notes = patterns_for_query(query_name, k=k)
    if not notes:
        return ""

    parts = [_PATTERNS_HEADER]
    for note in notes:
        body = note.body.strip()
        if len(body) > body_char_cap:
            body = body[:body_char_cap] + "\n\n... [truncated]"
        tag_str = ", ".join(note.tags) if note.tags else "—"
        parts.append(
            f"### {note.title} — `{note.path}`\n"
            f"_tags: {tag_str}_\n\n"
            f"{body}"
        )
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# AutoSecAgent — full context-bundle render                                   #
# --------------------------------------------------------------------------- #

def render_recon_hint(
    recon_summary: str,
    target_description: str,
    *,
    inline_patterns: int = 2,
    inline_techniques: int = 1,
    body_char_cap: int = 2500,
) -> str:
    """Return a prompt fragment built from /v1/context-bundle."""
    bundle = hint_for_recon(recon_summary, target_description)
    if bundle is None:
        return ""

    parts = [_HEADER_RECON]

    if bundle.audit_walk:
        parts.append(
            "### Audit Walk (canonical methodology)\n"
            + "\n".join(bundle.audit_walk)
        )

    parts.append(_render_section("Patterns", bundle.patterns, inline_patterns, body_char_cap))
    parts.append(_render_section("Attack Techniques", bundle.techniques, inline_techniques, body_char_cap))

    if bundle.cves:
        parts.append(
            "### Relevant CVEs / Incidents\n"
            + "\n".join(_one_line_ref(r) for r in bundle.cves)
        )

    if bundle.chains:
        parts.append(
            "### Attack Chains\n"
            + "\n".join(_one_line_ref(r) for r in bundle.chains)
        )

    if bundle.mental_models:
        parts.append(
            "### Mental Models\n"
            + "\n".join(_one_line_ref(r) for r in bundle.mental_models)
        )

    return "\n\n".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
# Internal                                                                    #
# --------------------------------------------------------------------------- #

def _fetch_body(path: str, body_char_cap: int) -> str:
    note = read(path)
    if note is None:
        return ""
    body = note.body.strip()
    if len(body) > body_char_cap:
        body = body[:body_char_cap] + "\n\n... [truncated]"
    return body


def _format_inline(result: VaultSearchResult, body: str) -> str:
    tag_str = ", ".join(result.tags) if result.tags else "—"
    extras = []
    if result.note_type:
        extras.append(f"type={result.note_type}")
    if result.domain:
        extras.append(f"domain={result.domain}")
    if result.severity:
        extras.append(f"severity={result.severity}")
    extras_str = " | ".join(extras) if extras else "—"

    return (
        f"### {result.title} — `{result.path}`\n"
        f"_{extras_str}_  _tags: {tag_str}_\n\n"
        f"{body}"
    )


def _render_section(
    label: str,
    results: list[VaultSearchResult],
    inline_top: int,
    body_char_cap: int,
) -> str:
    if not results:
        return ""

    parts = [f"### {label}"]

    for result in results[:inline_top]:
        body = _fetch_body(result.path, body_char_cap)
        if body:
            parts.append(_format_inline(result, body))

    rest = results[inline_top:]
    if rest:
        parts.append(
            "**Other " + label.lower() + ":**\n"
            + "\n".join(_one_line_ref(r) for r in rest)
        )

    return "\n\n".join(parts)


def _one_line_ref(result: VaultSearchResult) -> str:
    bits = [f"`{result.path}` — {result.title}"]
    if result.note_type:
        bits.append(f"[{result.note_type}]")
    if result.severity:
        bits.append(f"sev={result.severity}")
    return "- " + " ".join(bits)
