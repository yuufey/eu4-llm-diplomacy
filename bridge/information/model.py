"""Shared information contract. Values carry knowledge states; zero stays zero."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Protocol


class InformationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict:
        return {"error": {"code": self.code, "message": str(self)}}


def canonical(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise InformationError("invalid_json", str(exc)) from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def identifier(value: Any, label: str = "identifier") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise InformationError("invalid_identifier", f"Invalid {label}")
    return value


def keys(value: Any, allowed: set[str], required: set[str] = frozenset(), label: str = "config") -> None:
    if not isinstance(value, dict):
        raise InformationError("invalid_parameters", f"{label} must be an object")
    missing, extra = required - value.keys(), value.keys() - allowed
    if missing or extra:
        raise InformationError("invalid_parameters", f"{label}: missing={sorted(missing)}, unknown={sorted(extra)}")
    canonical(value)


class InformationSource(Protocol):
    def context(self) -> dict: ...
    def catalog(self) -> list[dict]: ...
    def read(self, query: dict, context: dict) -> dict: ...
    def poll_events(self, context: dict, cursor: Any) -> dict: ...


class OutputAdapter(Protocol):
    """deliver must deduplicate result_id; exceptions are never called delivered."""
    def deliver(self, result: dict) -> dict: ...
