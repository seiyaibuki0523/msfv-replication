"""Sway (Fuel) platform adapter.

Sway is Rust-flavoured and compiles to FuelVM. Threat model is closest
to EVM but with UTXO-style asset semantics:
  - Reentrancy: FuelVM allows call recursion; OZ Sway and the Sway stdlib
    expose a ReentrancyGuard. Treat similarly to EVM.
  - Access control: `msg_sender()` checks, custom predicates, or the
    Sway-Libs Ownable pattern.
  - Asset transfers use coin transfers (UTXO-ish), so token-balance checks
    need different reasoning than ERC-20 .transfer().
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_SWAY_ABI       = re.compile(r"\babi\s+\w+\s*\{")
_RE_SWAY_FN        = re.compile(r"\bfn\s+\w+\s*\(")
_RE_SWAY_AUTH      = re.compile(
    r"\bmsg_sender\s*\(\s*\)|"
    r"\brequire\s*\(\s*[^)]*sender|"
    r"only_owner|only_role"
)


def _sway_access_seed(key: str, body: str, ac: dict) -> bool:
    if not _RE_SWAY_ABI.search(body) and not _RE_SWAY_FN.search(body):
        return False
    return not _RE_SWAY_AUTH.search(body)


class SwayAdapter(PlatformAdapter):
    name = "sway"
    label = "Sway (Fuel)"
    file_extensions = (".sw", ".sway")

    def detect(self, file_path: str, content: str) -> float:
        ext = file_path.lower().rsplit(".", 1)[-1] if "." in file_path else ""
        if ext not in {"sw", "sway"}:
            return 0.0
        score = 0.6
        if "contract;" in content or "predicate;" in content or "script;" in content:
            score += 0.3
        if "use std::" in content and ("auth" in content or "context" in content):
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Sway / FuelVM. Cross-contract calls do yield control; "
                    "the Sway-Libs `ReentrancyGuard` is the canonical mitigation. "
                    "Flag state mutation after `abi(...).func()` calls without a guard."
                ),
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Sway. Access control = `msg_sender()` comparisons, "
                    "Sway-Libs `Ownable` or `AccessControl`, or predicate-based gating. "
                    "Flag ABI-exposed methods mutating storage without any caller check."
                ),
                seed_matcher=_sway_access_seed,
            ),
            "flash_loan_exposure": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Fuel. AMM spot-price manipulation logic mirrors EVM; "
                    "TWAP / oracle / slippage requirements apply."
                ),
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Sway. UTXO-style coin transfers — reasoning about "
                    "balances is different from ERC-20 `.transfer()`. Watch implicit "
                    "trust of return data from `abi(...).method()` calls."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`contract;` keyword":   "Top-level contract program — primary attack surface",
            "`abi {...}` block":     "Public method list — equivalent of Solidity `external`",
            "Sway-Libs Ownable":     "Component-style access control; check it's used",
            "`msg_sender()`":        "Caller query; pair with explicit comparison",
        }

    def exploit_harness_kind(self) -> str:
        return "forc_test"


register(SwayAdapter())
