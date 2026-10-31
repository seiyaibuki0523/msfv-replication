"""Typed call-graph primitives.

These dataclasses are produced by the Slither / tree-sitter builders
and consumed by ``context_bundle`` + Layer 5 seed code. They sit
alongside the regex output so downstream code can keep treating the
raw string list as a fallback when a typed edge isn't available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# Call-type enum. The string values are stable — Layer 5 seed code
# filters on them ("any edge with call_type in ('external', ...)").
CallType = Literal[
    "internal",            # same-contract / same-file Python-style call
    "external",            # cross-contract call with known target type
    "external_dynamic",    # cross-contract, target type not statically resolvable
    "library",             # via Solidity ``using for X``
    "delegatecall",        # low-level delegatecall
    "staticcall",          # low-level staticcall
    "low_level_call",      # low-level call() — value transfer + custom selector
    "modifier",            # modifier invocation (Solidity)
    "solidity_builtin",    # require / assert / keccak / etc. — usually skipped
    "unknown",             # parser couldn't classify
]


@dataclass
class StateVar:
    """One state-variable declaration. Solidity-focused but generic
    enough for any language that has module-scoped state.
    """

    name: str
    type: str                       # textual type ("uint256", "mapping(...)")
    visibility: str = ""            # public | private | internal (Solidity)
    is_constant: bool = False
    is_immutable: bool = False
    contract: str = ""              # owning contract / module
    file: str = ""                  # repo-relative path
    line: int = 0


@dataclass
class CallEdge:
    """One outgoing call from a function. Both the regex and the typed
    Slither paths populate ``target``; the typed path also fills the
    metadata fields below.
    """

    target: str                     # "Contract.fn" or just "fn" for unresolved
    call_type: CallType = "unknown"
    target_contract: str | None = None
    target_var: str | None = None   # variable name holding the target receiver
    line: int = 0

    # Edge metadata (Slither path fills these — regex path leaves them
    # at default). Downstream filters / scorers branch on these.
    is_state_modifying: bool | None = None     # target writes state?
    is_payable: bool = False                   # target is `payable`?
    has_value_transfer: bool = False           # this call sends ETH (call{value: x})
    is_in_loop: bool = False                   # call appears inside for/while
    is_in_unchecked: bool = False              # call inside `unchecked { }`
    has_try_catch: bool = False                # wrapped in try/catch
    arguments_summary: list[str] = field(default_factory=list)

    def is_external_like(self) -> bool:
        """True for edges that cross the contract boundary in some way.
        Layer 5 reentrancy / trust-boundary seeds use this.
        """
        return self.call_type in {
            "external", "external_dynamic", "low_level_call",
            "delegatecall", "staticcall", "library",
        }


__all__ = ["CallEdge", "CallType", "StateVar"]
