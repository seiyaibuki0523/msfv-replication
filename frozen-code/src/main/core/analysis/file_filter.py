"""
Layer 0 — File selection.

Zero LLM cost. Pure filesystem operations.
Outputs a sorted list of files worth analysing.
"""

from __future__ import annotations

import os
import zipfile
import tempfile
from pathlib import Path

# Extensions we care about
SUPPORTED_EXTENSIONS: set[str] = {
    ".sol",                          # Solidity
    ".huff",                         # Huff (low-level EVM)
    ".vy",                           # Vyper
    ".rs",                           # Rust
    ".py",                           # Python
    ".js", ".ts", ".jsx", ".tsx",    # JavaScript / TypeScript
    ".go",                           # Go
    ".java",                         # Java
    ".rb",                           # Ruby
    ".php",                          # PHP
    ".c", ".cpp", ".h", ".hpp",      # C / C++
    ".cs",                           # C#
    ".move",                         # Move (Sui/Aptos)
    ".cairo",                        # Cairo (StarkNet)
    ".html", ".htm",                 # templates (Django/Jinja/EJS) — XSS sinks
}

# Directories to skip entirely. Includes the usual VCS / build noise *plus*
# Foundry / Solidity vendor folder names that show up under ``lib/``. The
# walker prunes dirnames in-place, so a structure like
# ``project/lib/forge-std/...`` skips everything under ``forge-std`` while
# still descending into the project's own code under ``lib/`` if it lives
# there.
EXCLUDE_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "vendor", "bower_components",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".ruff_cache",
    "dist", "build", "out", "target",          # build artifacts
    "migrations", "alembic",                    # DB migrations
    ".idea", ".vscode",
    "coverage", ".nyc_output",
    "fixtures", "testdata", "test-data",
    "docs", "documentation",
    "examples", "demo", "samples",

    # ----- Foundry / Solidity vendor submodules -------------------------
    # These appear under ``lib/`` in every Foundry project and are not
    # ours to audit. Misclassifying them as target code wastes Opus tokens
    # and produces noise findings about library helpers.
    "forge-std", "ds-test",
    "openzeppelin-contracts", "openzeppelin-contracts-upgradeable",
    "@openzeppelin",
    "solmate", "solady",
    "weird-erc20",
    "foundry-huff", "huffmate", "huff-runtime", "forge-ctf",
    "solidity-stringutils",
    "clones-with-immutable-args",
    "PRBMath", "prb-math",
    "uniswap-v2-core", "uniswap-v3-core", "v2-core", "v3-core", "v4-core",
    "chainlink", "chainlink-evm",
    "balancer-v2-monorepo",
    "aave-v3-core", "aave-v3-periphery",
    # ----- Hardhat / npm-style ------------------------------------------
    "hardhat", "@types", "@nomicfoundation",
}

# Filename patterns indicating noise (test/mock/config/lock)
EXCLUDE_FILENAME_PATTERNS: tuple[str, ...] = (
    "test_", "_test.", ".test.", ".spec.", "_spec.",
    "mock_", "_mock.", ".mock.",
    "conftest", "setup.py", "setup.cfg",
    ".lock", ".sum", ".toml", ".yaml", ".yml",
    ".json",        # usually configs/ABIs — include ABIs separately if needed
    ".md", ".rst", ".txt",
    ".min.js", ".min.css",
    "Makefile", "Dockerfile", ".sh",
)

# Max file size to analyse (bytes) — large files deferred to chunking
MAX_FILE_SIZE: int = 200_000  # 200 KB


def filter_files(source_path: str) -> tuple[list[str], str]:
    """
    Layer 0: walk source_path (file, dir, or .zip) and return:
        - sorted list of selected file paths (ascending size → focused first)
        - the resolved root directory string

    Files exceeding MAX_FILE_SIZE are moved to the end of the list
    so they are processed last (or skipped by the pipeline).
    """
    root = _resolve_root(source_path)
    candidates: list[tuple[int, str]] = []  # (size, path)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs in-place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)

            if not _has_supported_extension(filename):
                continue
            if _is_noise_file(filename):
                continue
            if not _is_text_file(full_path):
                continue

            size = os.path.getsize(full_path)
            candidates.append((size, full_path))

    # Sort ascending by size (small focused files first)
    candidates.sort(key=lambda x: x[0])
    return [path for _, path in candidates], root


def extract_zip(zip_path: str, dest_dir: str | None = None) -> str:
    """Extract a zip archive and return the extraction root."""
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="aisec_")
    os.makedirs(dest_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)
    return dest_dir


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_root(source_path: str) -> str:
    """Unzip if needed; return the analysable root directory."""
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source path not found: {source_path}")
    if os.path.isfile(source_path) and source_path.endswith(".zip"):
        return extract_zip(source_path)
    if os.path.isfile(source_path):
        # Single file — treat its directory as root but only return it
        # The caller must handle the single-file case separately.
        return os.path.dirname(os.path.abspath(source_path))
    return source_path


def _has_supported_extension(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in SUPPORTED_EXTENSIONS


def _is_noise_file(filename: str) -> bool:
    lower = filename.lower()
    return any(pattern in lower for pattern in EXCLUDE_FILENAME_PATTERNS)


def _is_text_file(path: str, check_bytes: int = 1024) -> bool:
    """Return False if the file appears to be binary."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(check_bytes)
        # Null bytes → binary
        if b"\x00" in chunk:
            return False
        # High ratio of non-ASCII → likely binary
        non_printable = sum(1 for b in chunk if b < 9 or (13 < b < 32))
        return (non_printable / max(len(chunk), 1)) < 0.1
    except OSError:
        return False
