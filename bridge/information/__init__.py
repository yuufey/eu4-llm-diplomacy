"""Read-only information queries, exports and autonomous subscriptions."""
from .model import InformationError

__all__ = ["InformationError", "InformationService"]


def __getattr__(name):
    if name == "InformationService":
        from .service import InformationService
        return InformationService
    raise AttributeError(name)
