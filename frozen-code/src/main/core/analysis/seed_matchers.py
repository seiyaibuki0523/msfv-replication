"""Per-language seed matchers for Layer 5 global-pattern queries.

Layer 5 asks the LLM "does this codebase contain pattern X?". For the LLM
to answer meaningfully, we need to hand it the *relevant* function bodies
— not every function in the repo (token budget), not zero functions
(then the LLM just guesses from names).

The "relevance" predicate is very language-specific:

    - Solidity reentrancy → look for ``.call(`` / ``.transfer(`` / …
    - Rust/Soroban reentrancy → look for ``token_client.transfer``,
      ``Client::new``, ``.await`` boundaries
    - Python access-control → look for Flask/FastAPI route decorators
      that aren't wrapped in an auth decorator
    - Go access-control → HTTP handlers without middleware.Auth

So we dispatch *per function* by the file extension embedded in the
function's ``path/foo.rs::name`` key. Mixed-language repos work natively:
a single reentrancy query can seed from both the Solidity and the Rust
sides of a cross-chain bridge, because each function independently picks
its own matcher.

Exposed API:
    - :func:`lang_of` — ``function_key`` → language label
    - :data:`MATCHERS` — ``{query_name: {lang: predicate}}``
    - :func:`match_seeds` — apply the right matcher to each function
"""

from __future__ import annotations

import os
import re
from typing import Callable, Dict


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_LANG_FROM_EXT: dict[str, str] = {
    ".sol":   "solidity",
    ".rs":    "rust",
    ".py":    "python",
    ".go":    "go",
    ".ts":    "ts", ".tsx": "ts", ".js": "ts", ".jsx": "ts",
    ".cpp":   "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".h":     "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".move":  "move",
    ".cairo": "cairo",
    ".sway":  "sway",
    ".java":  "java",
    ".kt":    "kotlin",
    ".swift": "swift",
    ".rb":    "ruby",
    ".php":   "php",
}


def lang_of(function_key: str) -> str:
    """Infer the implementation language from a function key.

    ``"packages/bridge/src/lib.rs::relay"`` → ``"rust"``.
    ``"contracts/Vault.sol::withdraw"`` → ``"solidity"``.
    Unknown extensions fall through to ``"generic"`` so callers always get
    a non-empty matcher.
    """
    path = function_key.split("::", 1)[0]
    ext = os.path.splitext(path)[1].lower()
    return _LANG_FROM_EXT.get(ext, "generic")


# ---------------------------------------------------------------------------
# Matcher type
# ---------------------------------------------------------------------------

# Signature: (function_key, body, access_control_map) -> bool
Matcher = Callable[[str, str, Dict[str, str]], bool]


def _re(pattern: str, flags: int = 0) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)
    return lambda text: bool(compiled.search(text or ""))


# ---------------------------------------------------------------------------
# reentrancy_check
# ---------------------------------------------------------------------------

_RE_SOL_EXTCALL  = _re(r"\.(call|transfer|send|delegatecall)\b")
_RE_RUST_SOROBAN = _re(
    r"\b(?:"
    r"token_client\.(?:transfer|balance|burn|mint|transfer_from|approve)"
    r"|Client::new"
    r"|invoke_contract"
    r"|env\.invoke_contract"
    r"|\.invoke\("
    r"|\.await\b"
    r")"
)
_RE_PY_NETCALL   = _re(r"\b(?:requests\.|httpx\.|urllib\.|subprocess\.|os\.system\(|socket\.)")
_RE_GO_NETCALL   = _re(r"\b(?:\.Call\(|http\.(?:Get|Post|Do)|exec\.Command|rpc\.)")
_RE_TS_NETCALL   = _re(r"\b(?:fetch\(|axios\.|\.call\(|\.send\()")
_RE_GENERIC_CALL = _re(r"\b(?:call|invoke|send|transfer|callback)\s*\(")

REENTRANCY_MATCHERS: dict[str, Matcher] = {
    "solidity": lambda k, b, ac: _RE_SOL_EXTCALL(b),
    "rust":     lambda k, b, ac: _RE_RUST_SOROBAN(b),
    "python":   lambda k, b, ac: _RE_PY_NETCALL(b),
    "go":       lambda k, b, ac: _RE_GO_NETCALL(b),
    "ts":       lambda k, b, ac: _RE_TS_NETCALL(b),
    "generic":  lambda k, b, ac: _RE_GENERIC_CALL(b),
}


# ---------------------------------------------------------------------------
# access_control_gaps
# ---------------------------------------------------------------------------

# Solidity: public/external function where the access_control index has no
# custom modifier (brackets ``[onlyOwner]`` would indicate one).
_RE_SOL_PUB_EXT  = _re(r"\b(public|external)\b")

# Rust/Soroban: pub fn entry point that writes storage without require_auth
_RE_RUST_PUB_FN  = _re(r"^\s*pub(?:\(crate\))?\s+(?:async\s+)?fn\s+\w+\s*(?:<[^>]*>)?\s*\(", re.MULTILINE)
_RE_RUST_WRITES  = _re(
    r"\b(?:env\.storage\(\)|"
    r"(?:instance|persistent|temporary)\(\)\.set\(|"
    r"set_\w+\s*\(|"
    r"storage\(\)\.(?:set|update|extend))"
)
_RE_RUST_AUTH    = _re(r"\brequire_auth\b")

# Python: Flask/FastAPI/Django route decorator without an auth decorator above
_RE_PY_ROUTE     = _re(r"@(?:app|router|blueprint|api)\.(?:route|get|post|put|delete|patch)")
_RE_PY_AUTH      = _re(r"@(?:login_required|requires_auth|permission_required|authentication_classes|jwt_required)")

# Go: HTTP handler without middleware.Auth
_RE_GO_HANDLER   = _re(r"func\s+\w+\s*\([^)]*http\.(?:Response|ResponseWriter)", re.MULTILINE)
_RE_GO_MIDDLE    = _re(r"\bmiddleware\.(?:Auth|Require|Protected)")

# TS/JS: express route without auth middleware
_RE_TS_ROUTE     = _re(r"(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(")
_RE_TS_AUTH      = _re(r"\b(?:authenticate|requireAuth|isAuthenticated|jwt\.verify)")

def _rust_access_ctrl(k: str, b: str, ac: Dict[str, str]) -> bool:
    """Rust: public-ish entry point that writes storage without auth.

    After the Rust parser enhancement, ``access_control[k]`` is either
    ``"public"`` / ``"pub(crate)"`` / ``"private"`` optionally followed by
    ``[macro1, macro2, require_auth]``. If the function is ``public`` AND
    the annotations don't include ``require_auth`` / ``access_control`` /
    ``only_*``, it's a real candidate for the LLM to inspect.

    We fall back to the body-level heuristic when ``ac`` has no entry
    (older state.json files from before the parser enhancement).
    """
    ctrl = ac.get(k, "")
    if ctrl:
        if not ctrl.startswith("public"):
            return False
        # Has an inline guard already — skip.
        if re.search(r"\[(?:[^\]]*\b)(?:require_auth|access_control|only_[a-z_]+|onlyowner|onlyrole)",
                     ctrl, re.IGNORECASE):
            return False
        # Writes storage in body?
        return bool(_RE_RUST_WRITES(b))
    # Fallback for pre-enhancement state files.
    return bool(
        _RE_RUST_PUB_FN(b)
        and _RE_RUST_WRITES(b)
        and not _RE_RUST_AUTH(b)
    )


ACCESS_CONTROL_MATCHERS: dict[str, Matcher] = {
    "solidity": lambda k, b, ac: (
        _RE_SOL_PUB_EXT(ac.get(k, "")) and "[" not in ac.get(k, "")
    ),
    "rust": _rust_access_ctrl,
    "python": lambda k, b, ac: (
        _RE_PY_ROUTE(b) and not _RE_PY_AUTH(b)
    ),
    "go": lambda k, b, ac: (
        _RE_GO_HANDLER(b) and not _RE_GO_MIDDLE(b)
    ),
    "ts": lambda k, b, ac: (
        _RE_TS_ROUTE(b) and not _RE_TS_AUTH(b)
    ),
    # Best-effort: any visibility keyword + state-mutating pattern, no auth
    "generic": lambda k, b, ac: bool(
        re.search(r"\b(?:public|pub|export|func)\b", b)
        and re.search(r"(?:=|\.set\(|mutate|update|save)", b)
        and not re.search(r"(?:auth|permission|role|owner)", b, re.IGNORECASE)
    ),
}


# ---------------------------------------------------------------------------
# flash_loan_exposure
# ---------------------------------------------------------------------------

_PRICE_KEYWORDS = (
    "price", "oracle", "reserve", "swap", "getamount", "getprice",
    "balanceof", "totalsupply", "getpair", "getreserves",
    "spot", "quote", "exchange_rate", "conversion_rate",
)


def _has_price_keyword(body: str) -> bool:
    lower = body.lower()
    return any(kw in lower for kw in _PRICE_KEYWORDS)


FLASHLOAN_MATCHERS: dict[str, Matcher] = {
    "solidity": lambda k, b, ac: _has_price_keyword(b),
    "rust":     lambda k, b, ac: _has_price_keyword(b),
    "python":   lambda k, b, ac: _has_price_keyword(b),
    "go":       lambda k, b, ac: _has_price_keyword(b),
    "ts":       lambda k, b, ac: _has_price_keyword(b),
    "generic":  lambda k, b, ac: _has_price_keyword(b),
}


# ---------------------------------------------------------------------------
# trust_boundary_violations
# ---------------------------------------------------------------------------

_RE_SOL_LOWLEVEL = _re(r"\.(call|send|delegatecall)\b")
_RE_RUST_UNWRAP  = _re(
    r"(?:\.unwrap\s*\(\s*\)|\.expect\s*\(|from_bytes|deserialize|"
    r"from_xdr|from_raw|Bytes::from)"
)
_RE_PY_DESERIAL  = _re(r"\b(?:pickle\.loads|yaml\.load|eval\s*\(|exec\s*\()")
_RE_GO_UNMARSHAL = _re(r"\b(?:json\.Unmarshal|xml\.Unmarshal|gob\.Decode)")
_RE_TS_DESERIAL  = _re(r"\b(?:JSON\.parse|eval\s*\(|Function\s*\()")
_RE_GENERIC_DESER = _re(r"\b(?:eval|deserialize|unmarshal|from_json|from_xml)\b")

TRUST_BOUNDARY_MATCHERS: dict[str, Matcher] = {
    "solidity": lambda k, b, ac: _RE_SOL_LOWLEVEL(b),
    "rust":     lambda k, b, ac: _RE_RUST_UNWRAP(b),
    "python":   lambda k, b, ac: _RE_PY_DESERIAL(b),
    "go":       lambda k, b, ac: _RE_GO_UNMARSHAL(b),
    "ts":       lambda k, b, ac: _RE_TS_DESERIAL(b),
    "generic":  lambda k, b, ac: _RE_GENERIC_DESER(b),
}


# ---------------------------------------------------------------------------
# generic_app pack matchers (deserialization, injection, auth, ssrf)
# ---------------------------------------------------------------------------
# Added 2026-06-08 to close the Log4j coverage gap. Without these the
# generic_app L5 queries fall through to "return everything" → 1260+
# Java functions sent to the LLM → context-window blowout → 0 findings.

# Java patterns — JNDI lookup, Java serialization sinks, expression-language
# evaluation. Pre-CVE-2021-44228 the JNDI patterns weren't widely known as
# deserialisation sinks; we encode them here so the L5 LLM at least *sees*
# JndiLookup / JndiManager bodies on Log4Shell-pattern targets.
_RE_JAVA_DESERIAL = _re(
    r"\b(?:ObjectInputStream|readObject|XMLDecoder|"
    r"JndiLookup|JndiManager|InitialContext|jndi:|\.lookup\s*\(|"
    r"ScriptEngine\.|MVEL\.|Spring(?:EL|ExpressionParser)|"
    r"ExpressionFactory\.|el-impl|"
    r"deserialize|fromJson|fromXml)\b"
)
_RE_GENERIC_DESER_V2 = _re(
    r"\b(?:eval|deserialize|unmarshal|from_json|from_xml|"
    r"lookup|jndi|ObjectInputStream)\b"
)

DESERIALIZATION_MATCHERS: dict[str, Matcher] = {
    "java":     lambda k, b, ac: _RE_JAVA_DESERIAL(b),
    "python":   lambda k, b, ac: _RE_PY_DESERIAL(b),
    "ts":       lambda k, b, ac: _RE_TS_DESERIAL(b),
    "go":       lambda k, b, ac: _RE_GO_UNMARSHAL(b),
    "generic":  lambda k, b, ac: _RE_GENERIC_DESER_V2(b),
}

# Injection sinks — SQL / command / template
_RE_JAVA_INJECT = _re(
    r"\b(?:Statement\.execute|createStatement|"
    r"Runtime\.exec|ProcessBuilder|"
    r"executeQuery|prepareStatement.*\+|"
    r"Velocity|Freemarker|Thymeleaf)\b"
)
_RE_PY_INJECT   = _re(
    r"\b(?:execute\s*\(\s*f?\"|format\s*\(|os\.system|subprocess\."
    r"(?:run|call|Popen)\s*\(\s*[^\[])"
)
_RE_TS_INJECT   = _re(
    r"\b(?:exec\s*\(|child_process\.(?:exec|spawn)|"
    r"sequelize\.query|raw\s*\(|\.query\s*\(`)"
)
_RE_GO_INJECT   = _re(
    r"\b(?:exec\.Command|db\.Query\s*\(\s*fmt\.|os/exec)"
)
_RE_GENERIC_INJECT = _re(
    r"\b(?:execute|exec|system|shell|query)\b.{0,60}?(?:\+|format|f\")"
)

INJECTION_MATCHERS: dict[str, Matcher] = {
    "java":     lambda k, b, ac: _RE_JAVA_INJECT(b),
    "python":   lambda k, b, ac: _RE_PY_INJECT(b),
    "ts":       lambda k, b, ac: _RE_TS_INJECT(b),
    "go":       lambda k, b, ac: _RE_GO_INJECT(b),
    "generic":  lambda k, b, ac: _RE_GENERIC_INJECT(b),
}

# Auth / authorization — endpoint handlers without access checks
_RE_JAVA_HANDLER = _re(
    r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|"
    r"Path|HandlerMethod)"
)
_RE_JAVA_AUTH    = _re(
    r"@(?:PreAuthorize|Secured|RolesAllowed|RequiresAuthentication|"
    r"AuthenticationPrincipal)\b|SecurityContext"
)
AUTH_MATCHERS: dict[str, Matcher] = {
    "java":     lambda k, b, ac: _RE_JAVA_HANDLER(b) and not _RE_JAVA_AUTH(b),
    "python":   lambda k, b, ac: _RE_PY_ROUTE(b) and not _RE_PY_AUTH(b),
    "go":       lambda k, b, ac: _RE_GO_HANDLER(b) and not _RE_GO_MIDDLE(b),
    "ts":       lambda k, b, ac: _RE_TS_ROUTE(b) and not _RE_TS_AUTH(b),
    "generic":  lambda k, b, ac: bool(re.search(r"\b(?:handler|controller|endpoint|route)\b", b, re.I)),
}

# SSRF + path traversal
_RE_JAVA_SSRF = _re(
    r"\b(?:URL\s*\(|HttpURLConnection|HttpClient|RestTemplate|"
    r"new\s+File\s*\(|Paths\.get|FileInputStream)"
)
_RE_PY_SSRF   = _re(r"\b(?:requests\.|urllib\.request\.|open\s*\(\s*[^\"'])")
_RE_TS_SSRF   = _re(r"\b(?:fetch\s*\(|axios\.|fs\.(?:readFile|createReadStream))")
_RE_GO_SSRF   = _re(r"\b(?:http\.(?:Get|Post|Do)|os\.Open|ioutil\.ReadFile)")
_RE_GENERIC_SSRF = _re(r"\b(?:fetch|request|http|url|file|open)\b")
SSRF_MATCHERS: dict[str, Matcher] = {
    "java":     lambda k, b, ac: _RE_JAVA_SSRF(b),
    "python":   lambda k, b, ac: _RE_PY_SSRF(b),
    "ts":       lambda k, b, ac: _RE_TS_SSRF(b),
    "go":       lambda k, b, ac: _RE_GO_SSRF(b),
    "generic":  lambda k, b, ac: _RE_GENERIC_SSRF(b),
}


# ---------------------------------------------------------------------------
# Query → matcher-table registry + dispatch
# ---------------------------------------------------------------------------

MATCHERS: dict[str, dict[str, Matcher]] = {
    # SOLIDITY_QUERIES (legacy)
    "reentrancy_check":          REENTRANCY_MATCHERS,
    "access_control_gaps":       ACCESS_CONTROL_MATCHERS,
    "flash_loan_exposure":       FLASHLOAN_MATCHERS,
    "trust_boundary_violations": TRUST_BOUNDARY_MATCHERS,
    # GENERIC_APP_QUERIES (added 2026-06-08 — Log4j coverage)
    "deserialization_and_eval":  DESERIALIZATION_MATCHERS,
    "injection_sinks":           INJECTION_MATCHERS,
    "auth_and_authorization":    AUTH_MATCHERS,
    "ssrf_and_path_traversal":   SSRF_MATCHERS,
}


def match_seeds(
    query_name: str,
    function_bodies: dict[str, str],
    access_control: dict[str, str],
) -> list[str]:
    """Return seed function keys relevant to ``query_name``, per-language.

    Unknown queries fall through to "everything" (capped by caller), so the
    LLM still sees something to analyse.
    """
    table = MATCHERS.get(query_name)
    if table is None:
        return list(function_bodies.keys())

    generic = table.get("generic")
    seeds: list[str] = []
    for key, body in function_bodies.items():
        matcher = table.get(lang_of(key), generic)
        if matcher is not None and matcher(key, body, access_control):
            seeds.append(key)
    return seeds
