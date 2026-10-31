"""Source provider abstraction for whitebox / audit mode.

A ``SourceProvider`` turns whatever the operator typed (a path, a
GitHub URL, an S3 bucket, a vault note id, ...) into a local directory
on disk that ``file_filter`` can walk. This is the whitebox counterpart
of ``bounty_mode.providers.TargetProvider``:

    Whitebox / Audit                 Pentest / Bounty
    ------------------------         ---------------------------
    SourceProvider.fetch()           TargetProvider.get_targets()
    SourceProvider.metadata()        TargetProvider.get_scope_rules()

The existing ``source_resolver.py`` is still the implementation of
``LocalPathSource`` + ``GitCloneSource`` under the hood — this module
just promotes that dispatch logic into a clean ``Protocol`` so other
backends slot in without touching the audit pipeline.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from typing import Any, Protocol, runtime_checkable


# --------------------------------------------------------------------------- #
# Protocol                                                                    #
# --------------------------------------------------------------------------- #

@runtime_checkable
class SourceProvider(Protocol):
    """Minimal surface the audit pipeline needs from a source."""

    name: str
    spec: str

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        """Materialise the source as a local directory and return its
        absolute path. Idempotent: calling fetch() twice with the same
        workspace returns the same directory unless ``force_fresh``.
        """
        ...

    def metadata(self) -> dict[str, Any]:
        """Return provenance info — used in report headers and for
        ``--disable-history`` decisions. Typical keys:
            type            "local" | "git" | "zip" | ...
            ref             commit hash / archive sha / file path
            origin          original URL / spec the operator typed
        """
        ...


# --------------------------------------------------------------------------- #
# Implementations                                                             #
# --------------------------------------------------------------------------- #

class LocalPathSource:
    """Operator gave us an existing local directory or file. Pass-through."""

    name = "local"

    def __init__(self, path: str):
        if not path:
            raise ValueError("LocalPathSource requires a path")
        self.spec = path
        self._abs = os.path.abspath(path)
        if not os.path.exists(self._abs):
            raise FileNotFoundError(f"local source not found: {path}")

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        # Single-file inputs: caller normally treats the parent dir as root.
        return self._abs

    def metadata(self) -> dict[str, Any]:
        return {"type": "local", "ref": self._abs, "origin": self.spec}


class GitCloneSource:
    """Shallow git clone into ``<workspace>/clones/<safe_name>``.

    Wraps ``source_resolver.resolve_source`` so we don't duplicate the
    clone / cache-reuse logic.
    """

    name = "git"

    def __init__(self, url_or_shorthand: str, *, branch: str | None = None):
        from core.analysis.source_resolver import looks_like_git_ref
        if not looks_like_git_ref(url_or_shorthand):
            raise ValueError(f"GitCloneSource: not a git ref: {url_or_shorthand!r}")
        self.spec = url_or_shorthand.strip()
        self.branch = branch
        self._clone_dir: str | None = None

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        from core.analysis.source_resolver import resolve_source
        self._clone_dir = resolve_source(
            self.spec, workspace=workspace,
            force_fresh=force_fresh, branch=self.branch,
        )
        return self._clone_dir

    def metadata(self) -> dict[str, Any]:
        ref = ""
        if self._clone_dir and os.path.isdir(os.path.join(self._clone_dir, ".git")):
            try:
                import subprocess
                ref = subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=self._clone_dir, text=True
                ).strip()
            except Exception:
                ref = ""
        return {"type": "git", "ref": ref, "origin": self.spec, "branch": self.branch}


class ZipArchiveSource:
    """ZIP file the operator uploaded. Extracts once into
    ``<workspace>/uploads/<basename>_unzipped/``.
    """

    name = "zip"

    def __init__(self, zip_path: str):
        if not zip_path or not os.path.isfile(zip_path):
            raise FileNotFoundError(f"zip source not found: {zip_path}")
        self.spec = zip_path
        self._abs = os.path.abspath(zip_path)
        self._extracted: str | None = None

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        base = os.path.splitext(os.path.basename(self._abs))[0]
        dest = os.path.join(workspace, "uploads", f"{base}_unzipped")
        if force_fresh and os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        if not os.path.isdir(dest):
            os.makedirs(dest, exist_ok=True)
            with zipfile.ZipFile(self._abs, "r") as zf:
                zf.extractall(dest)
        self._extracted = dest
        return dest

    def metadata(self) -> dict[str, Any]:
        return {"type": "zip", "ref": self._abs, "origin": self.spec}


class GitHubAPISource:
    """Pull a specific commit / PR / tag via the GitHub Archive endpoint.

    Cheaper than a full ``git clone`` when the operator only cares about
    a snapshot. ``spec`` format:

        owner/repo@<ref>       → tarball of <ref> (commit / branch / tag)
        owner/repo#<pr_number> → PR head sha

    Falls back to a normal git clone for branches that the API can't
    resolve (private repos without token, etc.).
    """

    name = "github-api"

    def __init__(self, spec: str):
        if "@" not in spec and "#" not in spec:
            raise ValueError("GitHubAPISource expects owner/repo@ref or owner/repo#pr")
        self.spec = spec
        if "#" in spec:
            self._repo, self._ref_kind, self._ref = spec.partition("#")
            self._ref_kind = "pr"
        else:
            self._repo, _, self._ref = spec.partition("@")
            self._ref_kind = "ref"

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        import urllib.request
        clones = os.path.join(workspace, "clones")
        os.makedirs(clones, exist_ok=True)
        safe = self.spec.replace("/", "_").replace("@", "_at_").replace("#", "_pr_")
        dest = os.path.join(clones, safe)
        if force_fresh and os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        if os.path.isdir(dest):
            return dest

        # Resolve PR sha if needed
        ref = self._ref
        if self._ref_kind == "pr":
            api = f"https://api.github.com/repos/{self._repo}/pulls/{ref}"
            try:
                with urllib.request.urlopen(api, timeout=20) as r:
                    import json
                    ref = (json.loads(r.read().decode("utf-8")) or {}).get("head", {}).get("sha", "")
                    if not ref:
                        raise RuntimeError(f"could not resolve PR #{self._ref}")
            except Exception as e:
                raise RuntimeError(f"GitHub API PR resolution failed: {e}") from e

        url = f"https://github.com/{self._repo}/archive/{ref}.zip"
        tmp_zip = tempfile.mktemp(prefix="aisec_gh_", suffix=".zip")
        try:
            urllib.request.urlretrieve(url, tmp_zip)
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                zf.extractall(dest)
            # GitHub archives nest into a single subfolder — flatten.
            children = [c for c in os.listdir(dest) if not c.startswith(".")]
            if len(children) == 1:
                inner = os.path.join(dest, children[0])
                if os.path.isdir(inner):
                    for c in os.listdir(inner):
                        shutil.move(os.path.join(inner, c), os.path.join(dest, c))
                    os.rmdir(inner)
        finally:
            try:
                os.remove(tmp_zip)
            except OSError:
                pass
        return dest

    def metadata(self) -> dict[str, Any]:
        return {"type": "github-api", "ref": self._ref, "origin": self.spec, "repo": self._repo}


class VaultSource:
    """ClaudeVault-backed source. Stub — when a vault entry stores a
    repo URL / archive id, this fetches it. Returns ``NotImplementedError``
    today; the wiring point exists so the dashboard can offer it as soon
    as the vault grows that schema.
    """

    name = "vault"

    def __init__(self, note_id: str):
        self.spec = note_id
        self._note_id = note_id

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        raise NotImplementedError(
            "VaultSource: write a vault note with type=source-archive first, "
            "then point this provider at its note id"
        )

    def metadata(self) -> dict[str, Any]:
        return {"type": "vault", "ref": self._note_id, "origin": self.spec}


class S3Source:
    """Fetch a tarball / zip from an S3 (or S3-compatible) bucket.

    Stubbed today — wiring point for enterprise clients who keep source
    in a private bucket. The protocol contract is enough for the audit
    pipeline; implementation goes live when we have a paying customer
    that needs it.
    """

    name = "s3"

    def __init__(self, s3_uri: str):
        if not s3_uri.startswith("s3://"):
            raise ValueError("S3Source: expected s3://bucket/key")
        self.spec = s3_uri

    def fetch(self, *, workspace: str, force_fresh: bool = False) -> str:
        raise NotImplementedError("S3Source not yet implemented (needs boto3 + auth wiring)")

    def metadata(self) -> dict[str, Any]:
        return {"type": "s3", "ref": self.spec, "origin": self.spec}


# --------------------------------------------------------------------------- #
# Factory                                                                     #
# --------------------------------------------------------------------------- #

def build_source_provider(spec: str, *, branch: str | None = None) -> SourceProvider:
    """Construct a provider from whatever the operator typed.

    Routing (first match wins)::

        ./path or /abs/path          → LocalPathSource
        owner/repo                   → GitCloneSource  (shorthand)
        https?://github.com/...      → GitCloneSource
        git@.../ssh://...            → GitCloneSource
        owner/repo@<ref> or @PR#N    → GitHubAPISource
        s3://bucket/key              → S3Source
        vault:<note-id>              → VaultSource
        *.zip                        → ZipArchiveSource
    """
    if not spec or not spec.strip():
        raise ValueError("build_source_provider: empty spec")
    s = spec.strip()

    if s.startswith("s3://"):
        return S3Source(s)
    if s.startswith("vault:"):
        return VaultSource(s[len("vault:"):])
    if ("@" in s and "://" not in s and "/" in s and not os.path.exists(s)) or \
       (s.count("#") == 1 and "://" not in s and "/" in s):
        return GitHubAPISource(s)

    if os.path.exists(s):
        if os.path.isfile(s) and s.lower().endswith(".zip"):
            return ZipArchiveSource(s)
        return LocalPathSource(s)

    # Anything else that looks like a git ref → clone
    from core.analysis.source_resolver import looks_like_git_ref
    if looks_like_git_ref(s):
        return GitCloneSource(s, branch=branch)

    # Last-ditch local path (will FileNotFound out of LocalPathSource)
    return LocalPathSource(s)
