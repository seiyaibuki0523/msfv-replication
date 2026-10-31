"""Move (Aptos / Sui) platform adapter.

Threat model:
  - Resource-oriented: values cannot be silently copied or dropped. This
    eliminates a class of "lost token" bugs that haunt EVM ERC-20 logic.
  - No reentrancy in the EVM sense — Move's strict ownership model and
    the fact that public functions cannot invoke arbitrary code mid-mutation
    make classic reentrancy unreachable.
  - Access control = capability tokens: signer presence, capability
    objects (Sui), or the canonical `assert!(signer::address_of(s) == ...)`
    pattern (Aptos). Missing those is the real bug class.
  - Flash loans exist (Aptos, Sui) but composability is more constrained
    than EVM; spot manipulation is still a risk on AMMs.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_MOVE_PUBLIC = re.compile(r"\bpublic(?:\s*\(\s*friend\s*\))?\s+fun\b")
_RE_MOVE_ENTRY  = re.compile(r"\bpublic\s+entry\s+fun\b|\bentry\s+fun\b")
_RE_MOVE_SIGNER = re.compile(r"\bsigner\s*[,)]|\b&signer\b")
_RE_MOVE_CAP    = re.compile(r"\bCapability\b|\bAdminCap\b|\bMintCap\b|\b[A-Z]\w*Cap\b")
_RE_MOVE_ASSERT_AUTH = re.compile(
    r"assert!\s*\(\s*signer::address_of\s*\(|"
    r"assert!\s*\(\s*tx_context::sender\s*\(|"
    r"assert!\s*\([^)]*==\s*@"
)


def _move_access_seed(key: str, body: str, ac: dict) -> bool:
    is_public = bool(_RE_MOVE_PUBLIC.search(body) or _RE_MOVE_ENTRY.search(body))
    if not is_public:
        return False
    has_auth = bool(
        _RE_MOVE_SIGNER.search(body)
        and _RE_MOVE_ASSERT_AUTH.search(body)
    ) or bool(_RE_MOVE_CAP.search(body))
    return not has_auth


class MoveAdapter(PlatformAdapter):
    name = "move"
    label = "Move (Aptos / Sui)"
    file_extensions = (".move",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".move"):
            return 0.0
        score = 0.5
        if "module " in content and "::" in content:
            score += 0.2
        if "public fun" in content or "entry fun" in content:
            score += 0.2
        if "&signer" in content or "tx_context::sender" in content:
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=False,
                notes=(
                    "Move's resource model + linear types + lack of dynamic dispatch "
                    "in the public-function call graph make classic reentrancy "
                    "unreachable. Skip."
                ),
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Move (Aptos / Sui). Access control mechanisms: "
                    "(a) signer presence — `&signer` parameter PLUS "
                    "`assert!(signer::address_of(s) == @expected_addr, ...)`; "
                    "(b) capability objects — passing an `AdminCap` / `MintCap` / "
                    "similar `*Cap` object as a parameter (Sui object-capability model); "
                    "(c) Aptos `tx_context::sender(ctx)` checks. "
                    "An entry/public function that mutates module state but takes "
                    "neither a checked `&signer` nor a capability object is the bug. "
                    "Note: `friend` visibility means cross-module friend calls — "
                    "those are NOT public attack surface, do not flag."
                ),
                seed_matcher=_move_access_seed,
            ),
            "flash_loan_exposure": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Move (Aptos / Sui). Flash-loan composability via "
                    "`hot potato` resources (Sui) or atomic transaction blocks "
                    "(Aptos). AMM spot-price reads without TWAP / oracle / "
                    "slippage are manipulable."
                ),
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Move. Trust risks: "
                    "(a) `BCS::from_bytes` of untrusted data without invariants; "
                    "(b) accepting a generic `Coin<T>` without checking the type T "
                    "is the expected one; "
                    "(c) implicit trust of off-chain oracle data via signed-message "
                    "verification with weak nonce/replay protection."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`&signer` param":           "Compiler-enforced signer presence — auth check still required (`assert! address_of`)",
            "`AdminCap` / `*Cap` types": "Sui object-capability model; capability tokens authorise actions",
            "`friend` visibility":       "NOT public attack surface; cross-module-only call sites",
            "`tx_context::sender`":      "Aptos sender query — pair with assert! for actual gating",
            "linear types":              "Resources cannot silently disappear → many EVM bug classes don't apply",
        }

    def exploit_harness_kind(self) -> str:
        return "move_test"


register(MoveAdapter())
