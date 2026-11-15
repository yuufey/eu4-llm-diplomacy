"""Bounded static trade-node candidates for the T06 target adapter.

This reader deliberately owns only the static graph projection.  A ``members``
entry is a configuration membership, not proof of ownership, discovery, a
port, an estuary, eligibility, or an engine effect.  Route ``path`` values are
kept inside ``topology`` as opaque configuration vectors for the same reason:
the static trade schema does not classify their entries as territorial target
provinces.
"""

from __future__ import annotations

from copy import deepcopy
import math
import re
from collections.abc import Mapping
from typing import Any


_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_PROVINCE_ID = 0xFFFF
_MAX_RAW_ROWS = 4096
_MAX_VECTOR_ITEMS = 4096
_MAX_VECTOR_TOTAL = 1 << 16
_T01_FIELDS = ("provinces", "routes", "upstream", "downstream")
_CONTEXT_KEYS = (
    "status",
    "session_id",
    "observer",
    "game_version",
    "game_sha256",
    "game_date",
    "game_day",
    "world_id",
    "paused",
    "configuration_sha256",
    "config_sha256",
    "definitions_sha256",
    "trade_definitions_sha256",
    "trade_directory_members",
    "definition_files",
    "configuration_files",
    "enabled_mods",
)
_HASH_KEYS = (
    "game_version",
    "game_sha256",
    "configuration_sha256",
    "config_sha256",
    "definitions_sha256",
    "trade_definitions_sha256",
    "trade_directory_members",
    "definition_files",
    "configuration_files",
    "enabled_mods",
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _copy(value: Any) -> Any:
    return deepcopy(value)


def _failure(status: str, reason: str, source: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "reason": reason,
        "source": _copy(source) if isinstance(source, Mapping) else source,
        "complete": False,
        "partial": True,
        "game_fact": False,
    }
    return result


def _valid_node_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != "Null"
        and _NODE_ID.fullmatch(value) is not None
    )


def _valid_scalar(value: Any) -> bool:
    if type(value) is int or type(value) is str:
        return True
    return type(value) is float and math.isfinite(value)


def _context_guard(context: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return a deep, comparable identity for the static input and provider."""

    return tuple(_copy(context.get(key)) for key in _CONTEXT_KEYS)


def _supplied_context_matches(
    supplied: Mapping[str, Any] | None,
    static_context: Mapping[str, Any],
) -> bool:
    """Check only identities present on both sides.

    ``StaticTradeSource`` intentionally overlays session/date/observer values
    from a live caller onto its static context.  Mode is therefore not part of
    this comparison.  A caller value is authoritative for the read, but an
    explicitly known static value may not silently disagree with it.
    """

    if supplied is None:
        return True
    if supplied.get("status") not in (None, "ready"):
        return False
    for key in _CONTEXT_KEYS:
        if key in {"status", "configuration_sha256", "config_sha256", "definitions_sha256",
                   "trade_definitions_sha256", "trade_directory_members", "definition_files",
                   "configuration_files", "enabled_mods"}:
            # These are static-source facts.  If the caller supplies one, it
            # must match; otherwise the static source remains authoritative.
            if key in supplied and supplied.get(key) is not None and static_context.get(key) is not None:
                if supplied.get(key) != static_context.get(key):
                    return False
            continue
        if key == "game_sha256":
            if supplied.get(key) is not None and static_context.get(key) is not None:
                if supplied.get(key) != static_context.get(key):
                    return False
            continue
        if key == "game_version":
            if supplied.get(key) is not None and static_context.get(key) is not None:
                if supplied.get(key) != static_context.get(key):
                    return False
            continue
        # Provider identity/date is only checked when the static provider also
        # reported it.  A static-only fixture legitimately has null identity.
        if supplied.get(key) is not None and static_context.get(key) is not None:
            if supplied.get(key) != static_context.get(key):
                return False
    return True


def _source_identity_matches(source: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    if source.get("name") != "StaticTradeSource" or source.get("mode") != "static":
        return False
    if source.get("status") != "observed":
        return False
    provenance = source.get("provenance")
    if not isinstance(provenance, Mapping):
        return False

    version = context.get("game_version")
    if not isinstance(version, str) or not version or source.get("game_version") != version:
        return False

    context_config = context.get("configuration_sha256") or context.get("config_sha256")
    source_config = (
        source.get("configuration_sha256")
        or source.get("config_sha256")
        or provenance.get("configuration_sha256")
        or provenance.get("config_sha256")
    )
    context_definitions = context.get("definitions_sha256") or context.get("trade_definitions_sha256")
    source_definitions = (
        source.get("definitions_sha256")
        or source.get("trade_definitions_sha256")
        or provenance.get("definitions_sha256")
        or provenance.get("trade_definitions_sha256")
    )
    if (
        not isinstance(context_config, str)
        or _SHA256.fullmatch(context_config) is None
        or not isinstance(source_config, str)
        or _SHA256.fullmatch(source_config) is None
        or source_config != context_config
        or not isinstance(context_definitions, str)
        or _SHA256.fullmatch(context_definitions) is None
        or not isinstance(source_definitions, str)
        or _SHA256.fullmatch(source_definitions) is None
        or source_definitions != context_definitions
    ):
        return False

    source_game_sha = source.get("game_sha256", provenance.get("game_sha256"))
    context_game_sha = context.get("game_sha256")
    if context_game_sha is not None and source_game_sha != context_game_sha:
        return False
    for key in ("session_id", "observer"):
        if context.get(key) is not None and source.get(key) != context.get(key):
            return False

    # The static source records these manifests in provenance.  If the
    # context has one, a caller-supplied/stub source may not silently omit it.
    for key in ("definition_files", "configuration_files", "trade_directory_members", "enabled_mods"):
        expected = context.get(key)
        if expected is not None and provenance.get(key) != expected:
            return False
    return True


def _validate_node_lists(
    provinces: Any,
    upstream: Any,
    downstream: Any,
    routes: Any,
    node_id: str,
) -> str | None:
    if not isinstance(provinces, list) or len(provinces) > _MAX_RAW_ROWS:
        return "TRADE_TARGET_MEMBER_LIST_OVER_LIMIT"
    seen: set[int] = set()
    for province_id in provinces:
        if type(province_id) is not int or not 1 <= province_id <= _MAX_PROVINCE_ID:
            return "TRADE_TARGET_MEMBER_ID_INVALID"
        if province_id in seen:
            return "TRADE_TARGET_MEMBER_DUPLICATE"
        seen.add(province_id)

    for name, values in (("upstream", upstream), ("downstream", downstream)):
        if not isinstance(values, list) or len(values) > _MAX_RAW_ROWS:
            return f"TRADE_TARGET_{name.upper()}_LIST_INVALID"
        if any(not _valid_node_id(value) for value in values):
            return f"TRADE_TARGET_{name.upper()}_NODE_ID_INVALID"

    if not isinstance(routes, list) or len(routes) > _MAX_RAW_ROWS:
        return "TRADE_TARGET_ROUTE_LIST_OVER_LIMIT"
    total_vector_items = 0
    for route in routes:
        if not isinstance(route, Mapping):
            return "TRADE_TARGET_ROUTE_INVALID"
        if route.get("source") != node_id:
            return "TRADE_TARGET_ROUTE_SOURCE_MISMATCH"
        if not _valid_node_id(route.get("source")) or not _valid_node_id(route.get("target")):
            return "TRADE_TARGET_ROUTE_ENDPOINT_INVALID"
        if route.get("target") not in downstream:
            return "TRADE_TARGET_ROUTE_TARGET_NOT_DOWNSTREAM"
        for key in ("path", "control"):
            values = route.get(key)
            if not isinstance(values, list) or len(values) > _MAX_VECTOR_ITEMS:
                return f"TRADE_TARGET_ROUTE_{key.upper()}_INVALID"
            total_vector_items += len(values)
            if total_vector_items > _MAX_VECTOR_TOTAL:
                return "TRADE_TARGET_ROUTE_VECTOR_OVER_LIMIT"
            if any(not _valid_scalar(value) for value in values):
                return f"TRADE_TARGET_ROUTE_{key.upper()}_VALUE_INVALID"
    return None


class TradeTargetGraphReader:
    """Project one static trade node into bounded candidate membership rows."""

    def __init__(self, static_trade: Any):
        if not callable(getattr(static_trade, "context", None)):
            raise TypeError("static_trade must expose context")
        if not callable(getattr(static_trade, "read", None)):
            raise TypeError("static_trade must expose read")
        self.static_trade = static_trade

    def context(self) -> dict[str, Any]:
        context = self.static_trade.context()
        if not isinstance(context, Mapping):
            raise TypeError("static trade context must be an object")
        return _copy(dict(context))

    @staticmethod
    def _query(node_id: str) -> dict[str, Any]:
        return {
            "topic": "T01",
            "object": {"type": "trade_node", "node_id": node_id},
            "fields": list(_T01_FIELDS),
            "parameters": {},
        }

    def read(self, node_id: Any, context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not _valid_node_id(node_id):
            return _failure("unknown", "TRADE_TARGET_NODE_ID_INVALID")
        if context is not None and not isinstance(context, Mapping):
            return _failure("unknown", "TRADE_TARGET_CONTEXT_INVALID")

        supplied = _copy(dict(context)) if isinstance(context, Mapping) else None
        try:
            before = self.context()
        except Exception as exc:
            return _failure("unavailable", "TRADE_TARGET_STATIC_CONTEXT_UNAVAILABLE:" + type(exc).__name__)
        if before.get("status") != "ready":
            return _failure("unavailable", "TRADE_TARGET_STATIC_SOURCE_UNREADY")
        if not _supplied_context_matches(supplied, before):
            return _failure("unavailable", "TRADE_TARGET_CONTEXT_IDENTITY_MISMATCH")

        static_result: Any = None
        try:
            static_result = self.static_trade.read(
                self._query(node_id),
                supplied if supplied is not None else before,
            )
        except Exception as exc:
            return _failure("unavailable", "TRADE_TARGET_STATIC_READ_FAILED:" + type(exc).__name__)

        try:
            after = self.context()
        except Exception as exc:
            source = static_result.get("source") if isinstance(static_result, Mapping) else None
            return _failure(
                "unavailable",
                "TRADE_TARGET_STATIC_CONTEXT_UNAVAILABLE_AFTER_READ:" + type(exc).__name__,
                source,
            )

        source = static_result.get("source") if isinstance(static_result, Mapping) else None
        if _context_guard(before) != _context_guard(after):
            return _failure("unavailable", "TRADE_TARGET_STATIC_CONTEXT_CHANGED_DURING_READ", source)
        if after.get("status") != "ready":
            return _failure("unavailable", "TRADE_TARGET_STATIC_SOURCE_UNREADY_AFTER_READ", source)

        if not isinstance(static_result, Mapping) or static_result.get("topic") != "T01":
            return _failure("unknown", "TRADE_TARGET_T01_RESULT_INVALID", source)
        if not isinstance(source, Mapping) or not _source_identity_matches(source, before):
            return _failure("unknown", "TRADE_TARGET_T01_SOURCE_IDENTITY_INVALID", source)
        if static_result.get("objects") != [{"type": "trade_node", "node_id": node_id}]:
            return _failure("unknown", "TRADE_TARGET_T01_OBJECTS_INVALID", source)
        fields = static_result.get("fields")
        if not isinstance(fields, Mapping):
            return _failure("unknown", "TRADE_TARGET_T01_FIELDS_INVALID", source)

        values: dict[str, Any] = {}
        for field in _T01_FIELDS:
            item = fields.get(field)
            if not isinstance(item, Mapping):
                return _failure("unknown", "TRADE_TARGET_T01_FIELD_MISSING:" + field, source)
            status = item.get("status")
            if status == "unavailable":
                return _failure("unavailable", str(item.get("reason") or "TRADE_TARGET_T01_FIELD_UNAVAILABLE"), source)
            if status != "known":
                return _failure("unknown", str(item.get("reason") or "TRADE_TARGET_T01_FIELD_UNKNOWN"), source)
            values[field] = _copy(item.get("value"))

        reason = _validate_node_lists(
            values["provinces"], values["upstream"], values["downstream"], values["routes"], node_id
        )
        if reason is not None:
            return _failure("unknown", reason, source)

        rows = [
            {
                "province_id": province_id,
                "membership_kind": "member",
                "node_id": node_id,
            }
            for province_id in values["provinces"]
        ]
        return {
            "status": "known",
            "rows": rows,
            "topology": {
                "node_id": node_id,
                "upstream": values["upstream"],
                "downstream": values["downstream"],
                "routes": values["routes"],
                "route_path_semantics": "configuration_path_not_territorial_target_classification",
            },
            "source": _copy(dict(source)),
            "complete": False,
            "partial": True,
            "game_fact": False,
        }


__all__ = ["TradeTargetGraphReader"]
