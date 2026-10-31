"""Language-specific Layer 5 query packs.

The legacy ``GLOBAL_PATTERN_QUERIES`` are tuned for Solidity / EVM DeFi —
they ask the LLM about reentrancy patterns (``.call`` / ``.transfer``),
flash loans, ``onlyOwner`` modifiers, etc. On C, Lua, Python or any other
language the LLM correctly answers "doesn't apply" and we end up with
zero useful findings.

This module produces a query list tailored to the dominant language(s)
in the repo. Selection is based on the file counts from
``language_router.classify_repo`` plus simple heuristics:

  - Repos with any Solidity (``.sol``) files → Solidity pack
  - Repos with mostly C / C++ → C-family pack
  - Repos with mostly Lua → Lua pack
  - Otherwise → generic-app pack (covers SQL injection, command
    injection, secrets, deserialisation — language-agnostic patterns)

A small "always-include" pack runs on every scan (secrets, hardcoded
credentials, insecure crypto) since those are independent of language.
"""

from __future__ import annotations

from cevanex.adapters.language_router import RouterResult


# --------------------------------------------------------------------------- #
# Query definitions                                                            #
# --------------------------------------------------------------------------- #

# Solidity / EVM smart-contract pack — matches the legacy default. Kept
# explicit here so the dispatch logic is single-sourced.
SOLIDITY_QUERIES: list[dict] = [
    {
        "name": "reentrancy_check",
        "query": (
            "Analyse the function implementations above for reentrancy vulnerabilities.\n"
            "A reentrancy bug exists when a function:\n"
            "  1. Makes an external call (.call / .transfer / .send / external contract)\n"
            "  2. Modifies state variables AFTER that external call\n"
            "  3. Does NOT have a reentrancy guard (nonReentrant or equivalent)\n"
            "Trace the exact control-flow path. Name the function, the external "
            "call site, the state variable modified after it, and the line numbers."
        ),
    },
    {
        "name": "flash_loan_exposure",
        "query": (
            "Analyse the function implementations above for flash-loan / "
            "price-manipulation exposure.\n"
            "Look for: spot price reads (no TWAP), oracle calls within the same "
            "block, large state changes based on a single-block price, absence "
            "of slippage checks.\n"
            "Name the vulnerable function, the oracle dependency, and the "
            "exploitable path."
        ),
    },
    {
        "name": "access_control_gaps",
        "query": (
            "Analyse the function implementations above for missing access control.\n"
            "For every public or external function that modifies state or transfers "
            "value, verify whether it has an access-control modifier (onlyOwner, "
            "onlyRole, require(msg.sender==...), etc.).\n"
            "List each function that can be called by ANY address and explain the impact."
        ),
    },
    {
        "name": "trust_boundary_violations",
        "query": (
            "Analyse the function implementations above for trust-boundary violations.\n"
            "Look for: unchecked return values from .call(), missing require() "
            "after external calls, implicit trust of external oracle or contract "
            "data without validation.\n"
            "Identify the specific call site and what could go wrong."
        ),
    },
    {
        "name": "oracle_manipulation",
        "query": (
            "Analyse the function implementations above for price-oracle "
            "manipulation, INDEPENDENT of flash loans.\n"
            "Look for: a price/exchange-rate derived from a manipulable source — "
            "DEX spot price (getReserves, balanceOf ratio, token0/token1), a "
            "single-block TWAP or too-short observation window, an oracle whose "
            "value an attacker can move by trading or by depositing. Any "
            "collateral/borrow/liquidation math that reads such a price is "
            "exploitable.\n"
            "Name the function, the price source, and how the attacker skews it."
        ),
    },
    {
        "name": "arbitrary_external_call",
        "query": (
            "Analyse the function implementations above for ARBITRARY external "
            "calls / call-injection (distinct from reentrancy).\n"
            "Look for: a function that takes a target address AND/OR calldata "
            "(bytes) from the caller and forwards it via .call/.delegatecall/"
            "functionCall, or that lets the caller choose which token/contract "
            "to invoke. This lets an attacker make the contract call anything as "
            "itself (e.g. approve/transfer the contract's own funds, or run code "
            "in the contract's storage context via delegatecall).\n"
            "Name the function, the attacker-controlled target/data parameter, "
            "and what the contract can be coerced to do."
        ),
    },
]


# C / C++ pack — memory safety + classic CWEs.
C_FAMILY_QUERIES: list[dict] = [
    {
        "name": "buffer_overflow",
        "query": (
            "Analyse the C / C++ function implementations above for buffer-overflow "
            "vulnerabilities (CWE-120, CWE-121, CWE-787).\n"
            "Look for: ``strcpy`` / ``strcat`` / ``sprintf`` without bounds, "
            "``gets``, ``memcpy``/``memmove`` with attacker-influenced size, "
            "fixed-size stack buffers written from network input, off-by-one "
            "loop conditions touching arrays.\n"
            "Name the function, the unsafe call, and a concrete input that "
            "triggers the overflow."
        ),
    },
    {
        "name": "format_string",
        "query": (
            "Analyse the function implementations for format-string vulnerabilities "
            "(CWE-134).\n"
            "Look for: ``printf`` / ``fprintf`` / ``snprintf`` / ``syslog`` whose "
            "first argument is a non-literal that flows from user input.\n"
            "Name the call site and the source of the untrusted format string."
        ),
    },
    {
        "name": "integer_issues",
        "query": (
            "Analyse the function implementations for integer overflow / underflow "
            "/ truncation bugs (CWE-190, CWE-191, CWE-197).\n"
            "Pay attention to size_t / ssize_t arithmetic feeding ``malloc`` / "
            "``memcpy`` size parameters, signed/unsigned comparisons in loop "
            "bounds, and downcasts that lose width.\n"
            "Name the function, the operation, and the consequence (heap-corruption, "
            "OOB read/write, infinite loop)."
        ),
    },
    {
        "name": "use_after_free_and_double_free",
        "query": (
            "Analyse the function implementations for use-after-free, double-free, "
            "and missing-null-check after free (CWE-416, CWE-415, CWE-476).\n"
            "Look for: ``free(p)`` followed by any read/write of ``p``, pointer "
            "aliasing where one alias is freed but the other dereferenced, "
            "missing reset to NULL after free in a long-lived struct.\n"
            "Name the lifecycle: allocate site → free site → re-use site."
        ),
    },
    {
        "name": "command_injection",
        "query": (
            "Analyse the function implementations for command / shell injection "
            "(CWE-78).\n"
            "Look for: ``system`` / ``popen`` / ``execl`` with strings concatenated "
            "from request data, ``execve`` with attacker-controlled argv. "
            "For nginx / Apache plugin code, request headers and query parameters "
            "count as untrusted input.\n"
            "Name the function and the data-flow from input → executed command."
        ),
    },
]


# Lua / OpenResty pack — focuses on the realistic threat model for nginx
# plugin / Kong / OpenResty Lua code.
LUA_QUERIES: list[dict] = [
    {
        "name": "sandbox_or_eval_escape",
        "query": (
            "Analyse the Lua function implementations above for sandbox escape and "
            "untrusted code execution.\n"
            "Look for: ``loadstring`` / ``load`` / ``loadfile`` called with strings "
            "derived from request data, ``os.execute`` / ``io.popen`` with non-"
            "literal arguments, dynamic require of attacker-controlled module names.\n"
            "Name the call site and the path from input → executed code."
        ),
    },
    {
        "name": "nginx_lua_injection",
        "query": (
            "Analyse the Lua / OpenResty function implementations for nginx-side "
            "injection vulnerabilities:\n"
            "  - SQL injection via ``ngx.location.capture`` to a SQL handler, "
            "or directly via lua-resty-* libraries with concatenated queries.\n"
            "  - Redis / Memcached command injection via raw command strings "
            "built from request data.\n"
            "  - HTTP response splitting via ``ngx.header`` set with unvalidated input.\n"
            "Name the data source, the injection sink, and what an attacker controls."
        ),
    },
    {
        "name": "ssrf_and_request_forwarding",
        "query": (
            "Analyse the Lua function implementations for SSRF / request-forwarding "
            "vulnerabilities (CWE-918).\n"
            "Look for: ``ngx.location.capture`` / ``http.request`` / ``socket.tcp`` "
            "where the target host or URI is derived from request input without "
            "an allowlist. For OpenResty proxies, header values being trusted as "
            "the upstream identity counts.\n"
            "Name the call site, the input source, and what internal endpoints "
            "an attacker can reach."
        ),
    },
    {
        "name": "auth_and_shared_dict_misuse",
        "query": (
            "Analyse the Lua function implementations for authentication / "
            "authorization gaps and unsafe shared-state usage in OpenResty:\n"
            "  - Public endpoints (no ngx.var.auth check / no JWT verification) "
            "that modify shared_dict, write Redis, or call privileged upstreams.\n"
            "  - Race conditions in ``ngx.shared.<dict>`` read-then-write without "
            "``incr`` / ``add`` (TOCTOU).\n"
            "  - Hardcoded credentials or secret rotation gaps in module-level "
            "locals.\n"
            "Name the endpoint, the missing check, and the impact."
        ),
    },
]


# Generic-application pack — language-agnostic patterns.
GENERIC_APP_QUERIES: list[dict] = [
    {
        "name": "injection_sinks",
        "query": (
            "Analyse the function implementations above for injection vulnerabilities:\n"
            "  - SQL injection: string-concatenated queries or unparametrised "
            "DB driver calls (CWE-89).\n"
            "  - Command injection: ``subprocess`` / ``exec`` / shell wrappers "
            "called with attacker-controlled input (CWE-78).\n"
            "  - Template injection: render functions whose template path or "
            "body comes from input (CWE-1336).\n"
            "Name the sink, the source of untrusted input, and the data-flow path."
        ),
    },
    {
        "name": "deserialization_and_eval",
        "query": (
            "Analyse the function implementations for unsafe deserialisation / "
            "dynamic code execution / remote class loading (CWE-502, CWE-95, "
            "CWE-470).\n"
            "Look for:\n"
            "  * Python: ``pickle.loads`` / ``yaml.load`` (unsafe loader) / "
            "``json.loads`` followed by ``eval`` / ``exec`` / ``Function()`` / "
            "``Marshal.load`` on attacker-controlled bytes.\n"
            "  * Java: ``ObjectInputStream.readObject`` on untrusted bytes, "
            "``XMLDecoder.readObject``, ``ScriptEngine.eval``, ``MVEL.eval``, "
            "Spring EL evaluation. **JNDI lookup** sinks "
            "(``Context.lookup``, ``InitialContext.lookup``, ``JndiLookup``, "
            "``JndiManager`` — CVE-2021-44228 Log4Shell pattern: any function "
            "that resolves a JNDI URI from a user-influenced string is a "
            "remote-class-loading sink, equivalent to deserialisation).\n"
            "  * JS/TS: ``eval`` / ``Function`` / ``vm.runInThisContext`` / "
            "prototype pollution flowing into a sink.\n"
            "Name the call site and what an attacker who controls the input can do."
        ),
    },
    {
        "name": "auth_and_authorization",
        "query": (
            "Analyse the function implementations for authentication and authorization "
            "gaps:\n"
            "  - Endpoints / RPC handlers that mutate state without verifying caller "
            "identity (CWE-862).\n"
            "  - Privilege checks that compare the wrong field (e.g. user.id vs "
            "object.owner_id mismatch — CWE-863, IDOR).\n"
            "  - JWT / session validation that trusts client-supplied claims "
            "without signature verification.\n"
            "Name the function, the missing check, and the affected resource."
        ),
    },
    {
        "name": "ssrf_and_path_traversal",
        "query": (
            "Analyse the function implementations for SSRF (CWE-918) and path "
            "traversal (CWE-22).\n"
            "Look for: HTTP client calls with non-allowlisted URLs from input, "
            "file operations whose path contains ``..`` from input, archive "
            "extraction (zip/tar) without checking entry paths.\n"
            "Name the call site, the input source, and the resource an attacker "
            "can reach or overwrite."
        ),
    },
]


# Always-on pack — runs regardless of language.
ALWAYS_ON_QUERIES: list[dict] = [
    {
        "name": "secrets_and_credentials",
        "query": (
            "Analyse the code above for hardcoded secrets / credentials "
            "(CWE-798): API keys, private keys, OAuth client secrets, DB "
            "passwords, signing keys, JWT HMAC secrets, hardcoded TLS keys.\n"
            "Report only values that look like real credentials (length, "
            "entropy, naming) — skip obvious placeholders like 'changeme' or "
            "'YOUR_KEY_HERE'.\n"
            "Name the file, line, and what the credential appears to grant."
        ),
    },
    {
        "name": "insecure_crypto",
        "query": (
            "Analyse the code above for insecure cryptographic primitives "
            "(CWE-327, CWE-338):\n"
            "  - Use of MD5 / SHA-1 / DES / RC4 for security-critical paths "
            "(password hashing, signing, key derivation).\n"
            "  - ``rand()`` / ``Math.random()`` / non-CSPRNG sources used to "
            "produce tokens, nonces, or session IDs.\n"
            "  - Hardcoded IVs, predictable salts, ECB mode block ciphers.\n"
            "Name the function, the primitive in use, and a safer alternative."
        ),
    },
]


# --------------------------------------------------------------------------- #
# Dispatch                                                                     #
# --------------------------------------------------------------------------- #

#: Extensions that strongly imply the C-family pack.
_C_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".ipp"})


def _dominant_pack(triage: RouterResult) -> tuple[str, list[dict]]:
    """Pick the most-applicable query pack for this repo's triage.

    Returns ``(label, queries)``. The label is logged so the operator
    knows which pack ran.
    """
    if triage.solidity:
        return "solidity", SOLIDITY_QUERIES

    # Count file types within `general` to pick a non-Solidity pack.
    ext_counts: dict[str, int] = {}
    for f in triage.general:
        from os.path import splitext
        ext = splitext(f.path)[1].lower()
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    c_count = sum(ext_counts.get(e, 0) for e in _C_EXTENSIONS)
    lua_count = ext_counts.get(".lua", 0)
    total = sum(ext_counts.values())

    if c_count and c_count >= max(lua_count, total - c_count):
        return "c_family", C_FAMILY_QUERIES
    if lua_count and lua_count >= max(c_count, total - lua_count):
        return "lua", LUA_QUERIES
    return "generic_app", GENERIC_APP_QUERIES


def select_query_pack(triage: RouterResult) -> tuple[str, list[dict]]:
    """Public API: return ``(label, queries)`` to pass as Pipeline.custom_queries.

    The pack combines a language-specific list with the always-on list
    (secrets, insecure crypto) so every scan checks for those classes
    regardless of language.
    """
    label, lang_queries = _dominant_pack(triage)
    return label, list(lang_queries) + list(ALWAYS_ON_QUERIES)
