"""Stellar Soroban (Rust) platform adapter.

Threat model differs sharply from EVM:
  - Host enforces ContractReentryMode::Prohibited by default → reentrancy
    findings are FALSE POSITIVES unless a contract explicitly opts in via
    `try_call(ContractReentryMode::Allowed)`.
  - Library helpers commonly disclaim auth in doc comments and use a
    ``_no_auth`` naming convention (OpenZeppelin Stellar contracts pattern).
    Flagging these as "missing auth" without checking the disclaimer / suffix
    yields the kind of false positive that wastes triage cycles and damages
    audit credibility.

Verified against soroban-env-host 25.0.1, src/host/frame.rs:952-984.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_RUST_PUB_FN  = re.compile(r"^\s*pub(?:\(crate\))?\s+(?:async\s+)?fn\s+\w+\s*(?:<[^>]*>)?\s*\(", re.MULTILINE)
_RE_RUST_WRITES  = re.compile(
    r"\b(?:env\.storage\(\)|"
    r"(?:instance|persistent|temporary)\(\)\.set\(|"
    r"set_\w+\s*\(|"
    r"storage\(\)\.(?:set|update|extend))"
)
_RE_RUST_AUTH    = re.compile(r"\brequire_auth\b")
_RE_NO_AUTH_SUFFIX = re.compile(r"\bfn\s+\w+_no_auth\s*\(")
_RE_NO_AUTH_DOC  = re.compile(
    r"NO\s+AUTHORI[ZS]ATION\s+CONTROLS|"
    r"responsibility\s+of\s+the\s+(?:implementer|caller|integrator)",
    re.IGNORECASE,
)


def _soroban_access_seed(key: str, body: str, ac: dict) -> bool:
    """Filter out OZ Stellar's intentional no-auth library helpers."""
    if _RE_NO_AUTH_SUFFIX.search(body):
        return False
    if _RE_NO_AUTH_DOC.search(body):
        return False
    ctrl = ac.get(key, "")
    if ctrl:
        if not ctrl.startswith("public"):
            return False
        if re.search(r"require_auth|access_control|only_[a-z_]+", ctrl, re.IGNORECASE):
            return False
        return bool(_RE_RUST_WRITES.search(body))
    return bool(
        _RE_RUST_PUB_FN.search(body)
        and _RE_RUST_WRITES.search(body)
        and not _RE_RUST_AUTH.search(body)
    )


def _soroban_reentrancy_seed(key: str, body: str, ac: dict) -> bool:
    """Only seed reentrancy on Soroban code that actively opts into reentry."""
    if "ContractReentryMode::Allowed" in body:
        return True
    if "reentry_mode: ContractReentryMode::Allowed" in body:
        return True
    return False


class SorobanAdapter(PlatformAdapter):
    name = "soroban"
    label = "Stellar Soroban (Rust)"
    file_extensions = (".rs",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".rs"):
            return 0.0
        score = 0.0
        if "use soroban_sdk" in content:
            score += 0.6
        if "#[contract]" in content or "#[contractimpl]" in content:
            score += 0.3
        if "soroban_sdk::Env" in content or " Env," in content or "&Env" in content:
            score += 0.2
        if "invoke_contract" in content or "require_auth" in content:
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Soroban. The host enforces ContractReentryMode::Prohibited "
                    "by default — re-entry into a contract already on the call stack is "
                    "rejected with `Error(Context, InvalidAction): Contract re-entry is "
                    "not allowed` BEFORE any user code runs. Reentrancy is therefore "
                    "ONLY exploitable when the codebase invokes `try_call(...)` or "
                    "passes `ContractReentryMode::Allowed` (or `SelfAllowed`). "
                    "Before reporting: confirm the codebase contains "
                    "`ContractReentryMode::Allowed`. If absent, output "
                    "`status: false_positive`, `reason: 'host-blocked'`. "
                    "Do NOT flag CEI ordering on its own — it is unreachable."
                ),
                severity_cap="medium",
                seed_matcher=_soroban_reentrancy_seed,
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Soroban. The OpenZeppelin Stellar contracts library "
                    "(and similar libraries) use TWO conventions to mark intentional "
                    "no-auth helpers: (1) the function name ends with `_no_auth` "
                    "(e.g. `grant_role_no_auth`, `cast_vote_no_auth`); (2) the doc "
                    "comment contains `⚠️ NO AUTHORIZATION CONTROLS ⚠️` or text like "
                    "'responsibility of the implementer/integrator/caller'. Both are "
                    "intentional API design — output `status: false_positive`. "
                    "Only flag missing auth on functions exposed via `#[contractimpl]` "
                    "(actual contract entry points) that lack `require_auth()` AND "
                    "carry no such disclaimer."
                ),
                seed_matcher=_soroban_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Soroban. Watch for: (a) `.unwrap()` / `.expect()` on "
                    "data sourced from cross-contract calls or user-supplied bytes; "
                    "(b) deserialisation of untrusted XDR without schema validation; "
                    "(c) implicit trust of token-client return values."
                ),
            ),
            # flash_loan_exposure not yet a primary risk class on Stellar
            # mainnet (composability + DEX depth are nascent). Re-enable
            # later once Soroban DeFi matures.
            "flash_loan_exposure": QuerySpec(
                enabled=False,
                notes="Flash-loan composability on Stellar is immature; revisit when DeFi TVL is meaningful.",
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "_no_auth suffix":       "Function name ends with `_no_auth` → intentionally no auth, do NOT flag",
            "NO AUTHORIZATION doc":  "Doc comment carries `⚠️ NO AUTHORIZATION CONTROLS` → integrator's responsibility, intentional",
            "#[contractimpl] gate":  "Real attack surface = functions inside `impl X { #[contractimpl] ... }`. Helpers in `pub mod storage` are library primitives.",
            "ContractReentryMode":   "If absent from codebase → host blocks all re-entry; reentrancy findings are FP",
            "require_auth call":     "`require_auth()` on the first line of an entry point is the canonical Soroban auth check",
        }

    def exploit_harness_kind(self) -> str:
        return "soroban_test"


register(SorobanAdapter())
