"""k8s-traps: Kubernetes manifest traps that pass linters and still break production."""

from .loader import Bundle, load
from .traps import TRAPS, Finding, Trap, audit

__version__ = "0.1.0"
__all__ = ["Bundle", "Finding", "TRAPS", "Trap", "audit", "load", "__version__"]
