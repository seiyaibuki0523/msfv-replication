"""Cairo (StarkNet) platform adapter.

Threat model:
  - StarkNet has its own execution model: account abstraction at the
    protocol level (every account is a contract), L1<>L2 messaging, and
    declare/deploy/invoke distinction. No EVM-style reentrancy in the
    classic sense, but cross-contract calls + state writes still need
    discipline.
  - Access control: `assert!(get_caller_address() == ...)` or the OZ
    Cairo `@external` + `Ownable` pattern (Cairo 1).
  - L1<>L2 message handlers are a unique trust-boundary class.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_CAIRO_EXTERNAL = re.compile(r"@external|#\[external\(v0\)\]|fn\s+__execute__")
_RE_CAIRO_AUTH     = re.compile(
    r"get_caller_address\s*\(\s*\)|"
    r"assert_only_owner|"
    r"_assert_only\w+|"
    r"only_role|"
    r"AccessControlComponent"
)


def _cairo_access_seed(key: str, body: str, ac: dict) -> bool:
    if not _RE_CAIRO_EXTERNAL.search(body):
        return False
    return not _RE_CAIRO_AUTH.search(body)


class CairoAdapter(PlatformAdapter):
    name = "cairo"
    label = "Cairo (StarkNet)"
    file_extensions = (".cairo",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".cairo"):
            return 0.0
        score = 0.6
        if "%lang starknet" in content or "#[starknet::contract]" in content:
            score += 0.3
        if "@external" in content or "#[external(v0)]" in content:
            score += 0.2
        if "get_caller_address" in content or "ContractAddress" in content:
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: StarkNet (Cairo). Cross-contract calls (`syscalls::call_contract`) "
                    "yield control to the callee, so reentrancy is reachable. The OZ Cairo "
                    "ReentrancyGuard component is the canonical mitigation; flag external "
                    "functions that mutate state after a `call_contract` without the guard."
                ),
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: StarkNet (Cairo). Access control = `get_caller_address()` "
                    "comparison or the OZ Cairo `Ownable` / `AccessControl` components. "
                    "Cairo 1 attribute syntax: `#[external(v0)]` is the public surface. "
                    "Flag external/entry points that mutate state without an explicit "
                    "caller check or component-mediated gate."
                ),
                seed_matcher=_cairo_access_seed,
            ),
            "flash_loan_exposure": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: StarkNet. AMM spot-price manipulation applies; StarkNet "
                    "DeFi is younger but the dynamics mirror EVM."
                ),
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: StarkNet. Watch L1<>L2 message handlers (`#[l1_handler]`) — "
                    "any function with this attribute trusts that the L1 sender was the "
                    "expected bridge contract; missing that check is a critical class. "
                    "Also: implicit trust of return data from cross-contract calls."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`#[external(v0)]`":     "Cairo 1 public function attribute — primary attack surface",
            "`#[l1_handler]`":       "L1→L2 message handler; sender check is critical",
            "OZ Ownable component":  "Component-based access control; check it's actually mounted",
            "`get_caller_address`":  "Manual caller check; pair with assert!",
            "ReentrancyGuard component": "OZ Cairo guard; absence on external state-mutating fn = flag",
        }

    def exploit_harness_kind(self) -> str:
        return "starknet_foundry"


register(CairoAdapter())
