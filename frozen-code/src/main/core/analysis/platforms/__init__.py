"""Platform adapter package.

Importing this package registers every shipped adapter via the side-effect
of importing each adapter module. Callers use the public API:

    from core.analysis.platforms import (
        PlatformAdapter, QuerySpec, all_adapters,
        detect_for_file, primary_for_file, by_name,
        format_codebase_signals_block,
    )

To add a new adapter:
  1. Drop a new module here that subclasses ``PlatformAdapter`` and calls
     ``register(MyAdapter())`` at module scope.
  2. Add ``from . import my_module`` to the registration block below.
"""

from __future__ import annotations

from .base import (
    PlatformAdapter,
    QuerySpec,
    PlatformDetection,
    register,
    all_adapters,
    detect_for_file,
    primary_for_file,
    by_name,
    format_codebase_signals_block,
    cap_severity,
)

# ---------------------------------------------------------------------------
# Registration — order matters when two adapters might score the same file
# (e.g. Soroban vs Solana on .rs files). Detection is confidence-based, so
# both are evaluated; the higher score wins. List order is irrelevant for
# correctness but kept stable for readability.
# ---------------------------------------------------------------------------

# Smart-contract platforms
from . import evm           # noqa: F401
from . import soroban       # noqa: F401
from . import solana        # noqa: F401
from . import move_lang     # noqa: F401
from . import cairo         # noqa: F401
from . import sway          # noqa: F401

# Web / backend platforms
from . import web_python    # noqa: F401
from . import web_typescript  # noqa: F401
from . import web_go        # noqa: F401
from . import web_java      # noqa: F401
from . import web_csharp    # noqa: F401
from . import web_ruby      # noqa: F401
from . import web_php       # noqa: F401
from . import web_swift     # noqa: F401


__all__ = [
    "PlatformAdapter",
    "QuerySpec",
    "PlatformDetection",
    "register",
    "all_adapters",
    "detect_for_file",
    "primary_for_file",
    "by_name",
    "format_codebase_signals_block",
    "cap_severity",
]
