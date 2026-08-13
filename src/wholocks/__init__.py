"""wholocks - find which process is locking a file, then kill it or wait for it.

Public API:

    from wholocks import find_holders

    result = find_holders(["C:/work/report.docx"])
    for h in result.holders:
        print(h.pid, h.name, h.access)
"""

from .core import (  # noqa: F401
    BackendUnavailable,
    Holder,
    ScanResult,
    UsageError,
    find_holders,
)

__version__ = "0.3.0"

__all__ = [
    "find_holders",
    "Holder",
    "ScanResult",
    "UsageError",
    "BackendUnavailable",
    "__version__",
]
