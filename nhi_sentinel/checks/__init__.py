"""Check package: register all certified checks here (AT15: only certified checks run)."""
from .base import REGISTRY, Check, CheckOutcome, enabled_checks, register  # noqa: F401
from . import reference  # noqa: F401  (registers reference checks)

try:  # pilot pack lands with the checks work package (B13)
    from . import pilot  # noqa: F401
except ImportError:  # pragma: no cover - pack under construction
    pass
