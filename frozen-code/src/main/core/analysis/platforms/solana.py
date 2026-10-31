"""Solana (Anchor / native Rust) platform adapter.

Threat model:
  - No "reentrancy" in the EVM sense: cross-program invocations (CPI) push
    a separate execution context; the calling program does not yield
    control mid-instruction. That said, CPI-based privilege escalation IS
    a thing (e.g., calling a token program with a mis-derived authority),
    just not the same vuln class. We rebrand the query as "CPI-trust".
  - "Access control" on Solana means: signer checks, account-ownership
    checks, PDA seed validation, lamport accounting. The Anchor framework
    provides `Signer<'info>`, `#[account(...)]` constraints, has_one,
    and bump-seed discipline that an auditor must verify.
  - Flash loans exist but Solana DeFi composability differs from EVM;
    spot-price manipulation is still a risk on AMM tokens.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_SOLANA_SIGNER  = re.compile(r"\bSigner\s*<")
_RE_SOLANA_ACCOUNT = re.compile(r"#\[account\s*\(")
_RE_SOLANA_HAS_ONE = re.compile(r"\bhas_one\s*=")
_RE_SOLANA_BUMP    = re.compile(r"\bbump\s*=")
_RE_SOLANA_OWNER   = re.compile(r"\bowner\s*=\s*[A-Za-z_:]+\.id\(\)")
_RE_SOLANA_INSTR   = re.compile(r"^\s*pub\s+fn\s+\w+\s*\(\s*ctx\s*:\s*Context\s*<", re.MULTILINE)


def _solana_access_seed(key: str, body: str, ac: dict) -> bool:
    """Anchor instruction handlers that take a Context but don't validate
    signer / account / bump are seed candidates."""
    if not _RE_SOLANA_INSTR.search(body):
        return False
    has_signer  = bool(_RE_SOLANA_SIGNER.search(body))
    has_constr  = bool(_RE_SOLANA_ACCOUNT.search(body))
    has_has_one = bool(_RE_SOLANA_HAS_ONE.search(body))
    has_bump    = bool(_RE_SOLANA_BUMP.search(body))
    # Heuristic: an instruction with no Signer<>, no has_one, no bump is
    # missing one of the three core access checks; surface to the LLM.
    return not (has_signer and (has_constr or has_has_one or has_bump))


class SolanaAdapter(PlatformAdapter):
    name = "solana"
    label = "Solana (Anchor / native Rust)"
    file_extensions = (".rs",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".rs"):
            return 0.0
        score = 0.0
        if "use anchor_lang" in content:
            score += 0.6
        if "use solana_program" in content:
            score += 0.5
        if "#[program]" in content or "declare_id!" in content:
            score += 0.3
        if "Pubkey" in content and ("AccountInfo" in content or "Context<" in content):
            score += 0.2
        # Stronger signal than Soroban so detection differs even when both
        # mention "soroban" or generic Rust crates.
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check": QuerySpec(
                enabled=False,
                notes=(
                    "Classic reentrancy doesn't apply: Solana CPIs run in a separate "
                    "execution context and the caller does not yield mid-instruction. "
                    "CPI-trust is a separate concern (handled by trust_boundary)."
                ),
            ),
            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Solana (Anchor or native). Access control means: "
                    "(1) signer presence — the relevant authority must appear as "
                    "`Signer<'info>` in the accounts struct OR be checked via "
                    "`if !ctx.accounts.x.is_signer { return Err(...) }`; "
                    "(2) account ownership — Anchor's `#[account(owner = program_id::id())]` "
                    "or a manual `account.owner == &id()` check; "
                    "(3) PDA validation — `seeds = [...]` AND `bump = ctx.bumps.x` "
                    "in `#[account(...)]`, OR `Pubkey::find_program_address` re-derivation "
                    "in native code; "
                    "(4) `has_one = authority` constraints when an account stores its "
                    "own authority pubkey. "
                    "Missing any of these on a state-mutating instruction is the bug. "
                    "Also flag: missing token-program checks, mint authority confusion, "
                    "rent-exempt account drains."
                ),
                seed_matcher=_solana_access_seed,
            ),
            "flash_loan_exposure": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Solana. AMM spot-price reads (Raydium, Orca, Lifinity) "
                    "are manipulable in a single transaction via Solana's atomic "
                    "swaps. Flag any instruction that reads pool reserves or LP "
                    "share value and uses it for value-affecting decisions without "
                    "a TWAP / oracle / slippage guard."
                ),
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Solana. Trust-boundary risks: "
                    "(a) CPI to attacker-controlled program (program ID not pinned); "
                    "(b) deserialising AccountInfo data without verifying owner first "
                    "(`account.owner == &id()`); "
                    "(c) `try_from_slice` / `borsh` decode of untrusted account data "
                    "without subsequent invariant checks; "
                    "(d) treating `is_signer` as a sufficient authorisation when the "
                    "signer is just any user wallet."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "Anchor `#[account(...)]`":  "Validation lives in the accounts struct, not the instruction body. Read it.",
            "`Signer<'info>` type":      "Compiler-enforced signer presence — strong signal of intent",
            "`has_one = authority`":     "Cross-account binding; a missing one breaks privilege checks",
            "`seeds=[..], bump`":        "PDA discipline; weak/static seeds → squatting risk",
            "raw `AccountInfo`":         "No type-level guarantees; manually validate owner + signer + data layout",
        }

    def exploit_harness_kind(self) -> str:
        return "anchor_test"


register(SolanaAdapter())
