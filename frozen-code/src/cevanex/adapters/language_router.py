"""Per-file language classifier for the unified Code Scan engine.

Walks a repository, classifies each file as belonging to one of the
supported analysis modes (Solidity smart contract vs general SAST), or
marks it ambiguous and defers classification to the LLM router.

The output of ``classify_repo`` is a triage of:

- ``solidity``: files to feed into the Solidity-specific pipeline
  (SWC registry rules + smart-contract verification prompt).
- ``general``: files to feed into the general SAST pipeline (OWASP rules
  + general verification prompt).
- ``config``: configuration files that get a light pass only (no deep
  analysis, kept for reference).
- ``ambiguous``: files where rules cannot decide. The caller passes
  these to the LLM router for classification.
- ``skipped``: files explicitly excluded (build artefacts, vendored
  dependencies, lockfiles meant for the future SCA engine).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

#: Path fragments that mark generated / vendored / build artefacts, or
#: demonstration code that customers don't want surfaced in their audit
#: report (intentionally simplified, often skips auth or uses unsafe
#: defaults for clarity).
#:
#: Tests stay IN scope: library test code often exposes real API attack
#: surface (auth-bypass helpers, weak fixtures) that becomes a customer
#: finding if it leaks into production.
SKIP_PATH_FRAGMENTS: tuple[str, ...] = (
    "/build/",
    "/dist/",
    "/node_modules/",
    "/.cache/",
    "/.git/",
    "/.tox/",
    "/.venv/",
    "/venv/",
    "/__pycache__/",
    "/coverage/",
    "/.next/",
    "/out/",
    "/target/",         # Rust / Java
    "/bin/",
    "/obj/",            # .NET
    # Demo / sample / example code — intentionally insecure for teaching,
    # not part of the shipping library surface. Customers see noise if
    # included.
    "/examples/",
    "/example/",
    "/demo/",
    "/demos/",
    "/sample/",
    "/samples/",
)

#: Extensions that map directly to Solidity analysis. Foundry / Hardhat
#: presence is verified via project markers (see CONFIDENT_PROJECTS).
SOLIDITY_EXTENSIONS: frozenset[str] = frozenset({".sol"})

#: Extensions that map directly to general SAST analysis.
GENERAL_SAST_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".pyi",
    ".go",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".scala",
    ".rs",
    ".rb",
    ".php",
    ".cs", ".vb",
    ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx", ".ipp",
    ".swift",
    # nginx / OpenResty / Kong ecosystem
    ".lua",
    # Apache / legacy plugin ecosystems
    ".pl", ".pm", ".perl",
    # Other languages we still want to attempt analysis on
    ".dart",
    ".m", ".mm",       # Objective-C
    ".erl", ".ex", ".exs",  # Erlang / Elixir
    ".clj", ".cljs",   # Clojure
    ".groovy",
    ".lisp", ".scm",
    ".r", ".R",
    ".vy",             # Vyper
    ".cairo",          # StarkNet
    ".move",           # Aptos / Sui
    ".huff",           # Low-level EVM
})

#: Extensions whose files are config — scanned lightly (secrets, weak
#: defaults) but not deeply analysed.
CONFIG_EXTENSIONS: frozenset[str] = frozenset({
    ".toml", ".yaml", ".yml", ".json", ".env",
    ".cfg", ".ini", ".conf",
})

#: Project markers — presence in the repo root signals a confident project type.
SOLIDITY_PROJECT_MARKERS: tuple[str, ...] = (
    "foundry.toml",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
    "remappings.txt",
)

#: Files that are NEVER deeply scanned but kept as references for future SCA.
LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "uv.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
})

#: Content markers — strong signals that override extension-based routing.
_PRAGMA_SOLIDITY = re.compile(r"^\s*pragma\s+solidity\s+", re.MULTILINE)
_PYTHON_SHEBANG = re.compile(r"^#!.*python", re.MULTILINE)
_NODE_SHEBANG = re.compile(r"^#!.*node", re.MULTILINE)

#: How many lines to read from each file when content-sniffing.
_HEAD_LINES = 50

#: Maximum file size to read (50 KB head sample). Larger files are still
#: classified by extension / project markers only.
_HEAD_BYTES = 50_000


# --------------------------------------------------------------------------- #
# Data types                                                                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FileClassification:
    """One file's routing decision."""
    path: str
    language: str  # "solidity" | "general" | "config" | "ambiguous" | "skipped"
    reason: str    # short tag explaining why


@dataclass
class RouterResult:
    """Aggregate triage of a repository walk."""
    solidity: list[FileClassification] = field(default_factory=list)
    general: list[FileClassification] = field(default_factory=list)
    config: list[FileClassification] = field(default_factory=list)
    ambiguous: list[FileClassification] = field(default_factory=list)
    skipped: list[FileClassification] = field(default_factory=list)

    def total_scanned(self) -> int:
        return len(self.solidity) + len(self.general) + len(self.config)

    def materialise(
        self,
        repo_root: str,
        *,
        include_config: bool = False,
        include_ambiguous: bool = True,
    ) -> list[str]:
        """Return absolute paths for files that should be sent to the pipeline.

        ``solidity`` and ``general`` are always included. ``ambiguous`` is
        included by default (the pipeline / LLM verification layer is the
        most cost-effective place to deal with unclassified files — the
        alternative is silent drop). ``config`` is excluded by default;
        callers that want secret-style scanning of YAML / TOML can flip
        the flag.
        """
        buckets: list[FileClassification] = list(self.solidity) + list(self.general)
        if include_ambiguous:
            buckets += list(self.ambiguous)
        if include_config:
            buckets += list(self.config)
        repo_root_abs = os.path.abspath(repo_root)
        return [os.path.join(repo_root_abs, f.path) for f in buckets]


# --------------------------------------------------------------------------- #
# Project-level detection                                                     #
# --------------------------------------------------------------------------- #

def detect_solidity_project(repo_root: str) -> bool:
    """True if the repo has any Solidity project marker at the root or one level deep."""
    root = Path(repo_root)
    for marker in SOLIDITY_PROJECT_MARKERS:
        if (root / marker).exists():
            return True
        # Common monorepo layouts:  contracts/foundry.toml, packages/<x>/foundry.toml
        for sub in root.iterdir() if root.exists() else []:
            if sub.is_dir() and (sub / marker).exists():
                return True
    return False


# --------------------------------------------------------------------------- #
# File-level classification                                                   #
# --------------------------------------------------------------------------- #

def _should_skip(path: str) -> bool:
    """Path lies inside a build / vendored / cache directory."""
    norm = "/" + path.replace("\\", "/").lstrip("/")
    return any(frag in norm for frag in SKIP_PATH_FRAGMENTS)


def _read_head(file_path: str) -> str:
    """Read up to _HEAD_BYTES of a file for content sniffing. Empty on error."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(_HEAD_BYTES)
        return chunk.decode("utf-8", errors="replace")
    except OSError:
        return ""


def classify_file(
    file_path: str,
    *,
    solidity_project: bool,
    head: str | None = None,
) -> FileClassification:
    """Classify one file. ``head`` is optional pre-read content."""
    name = os.path.basename(file_path)
    ext = os.path.splitext(name)[1].lower()

    # 1. Skip patterns
    if _should_skip(file_path):
        return FileClassification(file_path, "skipped", "build_or_vendored")

    # 2. Lockfiles — keep for future SCA, skip source scan
    if name in LOCKFILE_NAMES:
        return FileClassification(file_path, "skipped", "lockfile")

    # 3. Strong content markers (override extension)
    head_text = head if head is not None else _read_head(file_path)
    if _PRAGMA_SOLIDITY.search(head_text):
        return FileClassification(file_path, "solidity", "pragma_solidity")
    if _PYTHON_SHEBANG.search(head_text):
        return FileClassification(file_path, "general", "python_shebang")
    if _NODE_SHEBANG.search(head_text):
        return FileClassification(file_path, "general", "node_shebang")

    # 4. Known Solidity extensions
    if ext in SOLIDITY_EXTENSIONS:
        return FileClassification(file_path, "solidity", "ext_sol")

    # 5. Known general SAST extensions — confident only when project marker
    #    consistency check passes. A `.py` file inside a clearly Solidity-only
    #    repo may be a deploy script; we still classify general but flag the
    #    case as "general_no_framework_marker" so the caller could opt to
    #    confirm with LLM if desired.
    if ext in GENERAL_SAST_EXTENSIONS:
        reason = "ext_general" if not solidity_project else "ext_general_in_sol_project"
        return FileClassification(file_path, "general", reason)

    # 6. Config files — light pass only
    if ext in CONFIG_EXTENSIONS:
        return FileClassification(file_path, "config", "ext_config")

    # 7. Templates / unknown extensions / no extension → ambiguous
    if ext in {".tmpl", ".template", ".j2", ".jinja", ".hbs", ".in", ".example"}:
        return FileClassification(file_path, "ambiguous", "template_ext")
    if ext == "":
        # Files like Makefile, Dockerfile, etc. have well-known names
        if name in {"Makefile", "Dockerfile", "Jenkinsfile", "Procfile"}:
            return FileClassification(file_path, "config", "known_name")
        return FileClassification(file_path, "ambiguous", "no_extension")

    # 8. Unknown extension we haven't seen — let LLM decide
    return FileClassification(file_path, "ambiguous", "unknown_extension")


# --------------------------------------------------------------------------- #
# Repository walk                                                             #
# --------------------------------------------------------------------------- #

def classify_repo(repo_root: str, *, max_files: int = 5000) -> RouterResult:
    """Walk a repo and classify every file. Caps at max_files for safety."""
    result = RouterResult()
    solidity_project = detect_solidity_project(repo_root)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Prune skip dirs in-place so we don't descend into them.
        dirnames[:] = [
            d for d in dirnames
            if not _should_skip(os.path.join(dirpath, d))
        ]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, repo_root)
            cls = classify_file(rel, solidity_project=solidity_project)
            if cls.language == "solidity":
                result.solidity.append(cls)
            elif cls.language == "general":
                result.general.append(cls)
            elif cls.language == "config":
                result.config.append(cls)
            elif cls.language == "ambiguous":
                result.ambiguous.append(cls)
            else:
                result.skipped.append(cls)
            seen += 1
            if seen >= max_files:
                return result
    return result
