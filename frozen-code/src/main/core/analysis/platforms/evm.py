"""EVM (Solidity) platform adapter.

Threat model: post-Byzantium EVM contracts. Reentrancy is fully reachable;
state writes after low-level calls are unsafe by default. Flash loans are a
real risk on any contract reading spot prices.
"""

from __future__ import annotations

from .base import PlatformAdapter, QuerySpec, register


class EvmAdapter(PlatformAdapter):
    name = "evm"
    label = "EVM (Solidity)"
    file_extensions = (".sol",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".sol"):
            return 0.0
        score = 0.4  # extension alone
        if "pragma solidity" in content:
            score += 0.4
        if "contract " in content or "library " in content or "interface " in content:
            score += 0.1
        if "function " in content and ("public" in content or "external" in content):
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: EVM (Solidity). Reentrancy is fully exploitable: "
                    "external calls (.call / .transfer / .send / cross-contract) "
                    "yield control to the callee, which may re-enter. Apply strict "
                    "checks-effects-interactions; flag any state mutation that "
                    "follows an external call without a nonReentrant modifier or "
                    "OpenZeppelin ReentrancyGuard."
                ),
            ),
            "flash_loan_exposure": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: EVM. Flash loans (Aave, Balancer, dYdX) make spot-price "
                    "manipulation a single-block, capital-free attack. Any contract "
                    "reading getReserves(), token0/1 balanceOf, or a single-pool spot "
                    "price as a value source — without a TWAP, oracle, or slippage "
                    "guard — is at risk."
                ),
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: EVM. State-mutating public/external functions must be "
                    "gated by onlyOwner / onlyRole / msg.sender == ... or equivalent. "
                    "Note: tx.origin checks are NOT acceptable (phishable). Internal "
                    "and private functions are out of scope (not directly callable)."
                ),
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: EVM. Unchecked low-level call return values, missing "
                    "require() after .call(), implicit trust of arbitrary-target "
                    "delegatecall — all classic Solidity footguns."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "ReentrancyGuard import": "OpenZeppelin ReentrancyGuard / nonReentrant present → reentrancy mitigation in place",
            "Ownable / AccessControl import": "OZ access primitives in use → grep for missing modifier on state-mutating functions",
            "SafeERC20": "SafeERC20 wraps return-value checks → token transfers are safer than raw .transfer()",
            "tx.origin": "tx.origin used for auth → phishable, always flag",
        }

    def exploit_harness_kind(self) -> str:
        return "foundry"


register(EvmAdapter())
