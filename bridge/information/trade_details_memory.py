"""Read the bounded trade-node source details child.

The validated ``trade_income_memory`` record owns the complete graph and the
country-bound 192-byte entry snapshots.  This child reuses those snapshots,
then reads only the capital identity chain, bounded entry+0x90 dynamic lists,
and the entry+0x60/+0x78 transfer lists.  The four known point rows stay
separate from dynamic and transfer detail rows.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import trade_income_memory as _trade


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "trade-details-memory-1374-v3.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_INDEX_MAX_BYTES = 128 * 1024
# literal_localization pins the v3 profile before production acceptance.
EXPECTED_PROFILE_SHA256 = "e5df6c617090d1df63eaf03d88a9d4716667548f36af9f1e1c24be2b71b06cb1"
PROFILE_ID = "trade-details-memory-1374-v3"
EXPECTED_EXE_SHA256 = _trade.EXPECTED_EXE_SHA256
EXPECTED_VERSION = _trade.EXPECTED_VERSION
EXPECTED_COUNTRY = _trade.EXPECTED_COUNTRY
EXPECTED_TRADE_PROFILE_SHA256 = _trade.EXPECTED_PROFILE_SHA256
LEGACY_DETAILS_PROFILE_SHA256 = "2d04808a1e24ecaf7cb7cf162743f7ada7412fa95522ce324f9e5959bca522aa"

BASIS = "native_trade_node_share_source_capital_dynamic_and_transfer_tail"
UNIT = "mixed"
SCALE = 1000
PERIOD = "current"
VALUE_ORIGIN = "copied_native_cache"
COMPLETE = False

SHARE_OFFSET = 0x2C
ENTRY_WIDTH = 0xC0
I32_WIDTH = 4
QWORD_WIDTH = 8
SOURCE_KEYS = (
    "TP_PROVINCE_POWER",
    "TP_SHIP_POWER",
    "MERCHANT_DOWNSTREAM_BONUS",
)
SOURCE_OFFSETS = {
    "TP_PROVINCE_POWER": 0x28,
    "TP_SHIP_POWER": 0x1C,
    "MERCHANT_DOWNSTREAM_BONUS": 0x40,
}
SOURCE_ROWS_ORDER = (
    "TP_PROVINCE_POWER",
    "TP_SHIP_POWER",
    "TRADE_POWER_CAPITAL",
    "MERCHANT_DOWNSTREAM_BONUS",
)
UNIMPLEMENTED_SOURCE_KINDS = ["TRADE_MULTI_EXPLA"]

CAPITAL_DATABASE_GLOBAL_RVA = 0x233D8B0
CAPITAL_COUNTRY_TABLE_OFFSET = 0x118
CAPITAL_COUNTRY_FULLREF_OFFSET = 0x20
CAPITAL_COUNTRY_14C8_OFFSET = 0x14C8
CAPITAL_ANCHOR_NODE_OFFSET = 0xE8
CAPITAL_SCALAR_RVA = 0x233F2F0
CAPITAL_VECTOR_STRIDE = 8

DYNAMIC_HEAD_OFFSET = 0x90
DYNAMIC_LINK_ITEM_OFFSET = 0x0
DYNAMIC_LINK_NEXT_OFFSET = 0x10
DYNAMIC_ITEM_VALUE_OFFSET = 0x34
DYNAMIC_ITEM_NAME_OFFSET = 0x10
DYNAMIC_NAME_CAPACITY_OFFSET = 0x18
DYNAMIC_NAME_HEAP_POINTER_OFFSET = 0x0
DYNAMIC_NAME_INLINE_CAPACITY = 16
DYNAMIC_NAME_OBJECT_SIZE = 0x20
MAX_DYNAMIC_ITEMS_PER_NODE = 64
MAX_DYNAMIC_ITEMS_TOTAL = 256
MAX_DYNAMIC_NAME_BYTES = 1024

TRANSFER_TO_HEAD_OFFSET = 0x60
TRANSFER_FROM_HEAD_OFFSET = 0x78
TRANSFER_ELEMENT_FULLREF_OFFSET = 0x0
TRANSFER_ELEMENT_VALUE_OFFSET = 0x8
TRANSFER_ELEMENT_NEXT_OFFSET = 0x18
TRANSFER_MAX_COUNTRY_SLOT = 4095
MAX_TRANSFER_ITEMS_PER_CONTAINER = 64
MAX_TRANSFER_ITEMS_TOTAL = 256
MAX_CHILD_READ = 128 * 1024
MAX_SINGLE_READ = 64 * 1024

_ROOT = Path(__file__).resolve().parents[2]


class ProfileError(RuntimeError):
    """The pinned v3 profile or source index is unavailable or invalid."""


class ReadError(RuntimeError):
    """A bounded child read or derived source contract failed."""


class _Budget:
    """A per-child, per-pass bounded reader."""

    def __init__(self, reader: Any, limit: int = MAX_CHILD_READ):
        self.reader = reader
        self.limit = limit
        self.bytes_requested = 0
        self.calls = 0
        self.exhausted = False

    def read(self, address: int, size: int, label: str) -> bytes:
        if not _trade._valid_address(address):
            raise ReadError(f"read_address_invalid:{label}")
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_READ:
            raise ReadError(f"read_size_invalid:{label}")
        if self.bytes_requested + size > self.limit:
            self.exhausted = True
            raise ReadError(f"read_budget_exceeded:{label}")
        # Reserve the request before entering the underlying reader.  A
        # short/failed RPM still consumed the child budget: otherwise a
        # faulty address could be retried indefinitely and let a later pass
        # spend bytes that the v3 extension contract already attempted.
        self.bytes_requested += size
        self.calls += 1
        method = getattr(self.reader, "read", None)
        if not callable(method):
            raise ReadError("reader_read_method_missing")
        value = method(address, size, label)
        if not isinstance(value, (bytes, bytearray)) or len(value) != size:
            raise ReadError(f"read_short_or_invalid:{label}")
        return bytes(value)


def _deepcopy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _canonical_digest(record: Mapping[str, Any]) -> str:
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if parsed < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return parsed


def _bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _profile_section(layout: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = layout.get(name)
    return section if isinstance(section, Mapping) else layout


def _layout_value(layout: Mapping[str, Any], section: str, name: str, *aliases: str) -> Any:
    nested = _profile_section(layout, section)
    for source in (nested, layout):
        for key in (name, *aliases):
            if key in source:
                return source[key]
    raise ProfileError(f"profile_layout_missing:{section}.{name}")


def _profile_limits(profile: Mapping[str, Any]) -> dict[str, int]:
    raw = profile.get("limits")
    raw = raw if isinstance(raw, Mapping) else {}
    transfer_node_default = raw.get("max_elements_per_node_across_three_chains", MAX_TRANSFER_ITEMS_PER_CONTAINER)
    transfer_total_default = raw.get("max_elements_global_across_three_chains", MAX_TRANSFER_ITEMS_TOTAL)
    country_slot_default = raw.get("max_country_slot_for_read", TRANSFER_MAX_COUNTRY_SLOT)
    shared_node = _parse_int(transfer_node_default, "limits.max_elements_per_node_across_three_chains")
    shared_total = _parse_int(transfer_total_default, "limits.max_elements_global_across_three_chains")
    values = {
        "max_child_read_bytes": _parse_int(raw.get("max_child_read_bytes", raw.get("max_extension_read_bytes_per_pass", MAX_CHILD_READ)), "limits.max_child_read_bytes"),
        "max_single_read_bytes": _parse_int(raw.get("max_single_read_bytes", raw.get("max_single_rpm_bytes", MAX_SINGLE_READ)), "limits.max_single_read_bytes"),
        # Keep the legacy aliases in the normalized record for callers that
        # inspect them, while making the profile's v3 three-chain limits
        # explicit and authoritative for the reader/validator.
        "max_elements_per_node_across_three_chains": shared_node,
        "max_elements_global_across_three_chains": shared_total,
        "max_dynamic_items_per_node": _parse_int(raw.get("max_dynamic_items_per_node", shared_node), "limits.max_dynamic_items_per_node"),
        "max_dynamic_items_total": _parse_int(raw.get("max_dynamic_items_total", shared_total), "limits.max_dynamic_items_total"),
        "max_dynamic_name_bytes": _parse_int(raw.get("max_dynamic_name_bytes", MAX_DYNAMIC_NAME_BYTES), "limits.max_dynamic_name_bytes"),
        "max_transfer_items_per_container": _parse_int(raw.get("max_transfer_items_per_container", transfer_node_default), "limits.max_transfer_items_per_container"),
        "max_transfer_items_total": _parse_int(raw.get("max_transfer_items_total", transfer_total_default), "limits.max_transfer_items_total"),
        "max_country_slot": _parse_int(raw.get("max_country_slot", country_slot_default), "limits.max_country_slot"),
    }
    if values["max_child_read_bytes"] != MAX_CHILD_READ:
        raise ProfileError("profile_child_read_budget_mismatch")
    if values["max_single_read_bytes"] != MAX_SINGLE_READ:
        raise ProfileError("profile_single_read_budget_mismatch")
    if values["max_elements_per_node_across_three_chains"] != MAX_TRANSFER_ITEMS_PER_CONTAINER:
        raise ProfileError("profile_three_chain_node_limit_mismatch")
    if values["max_elements_global_across_three_chains"] != MAX_TRANSFER_ITEMS_TOTAL:
        raise ProfileError("profile_three_chain_total_limit_mismatch")
    if values["max_dynamic_items_per_node"] != MAX_DYNAMIC_ITEMS_PER_NODE:
        raise ProfileError("profile_dynamic_node_limit_mismatch")
    if values["max_dynamic_items_total"] != MAX_DYNAMIC_ITEMS_TOTAL:
        raise ProfileError("profile_dynamic_total_limit_mismatch")
    if values["max_dynamic_name_bytes"] != MAX_DYNAMIC_NAME_BYTES:
        raise ProfileError("profile_dynamic_name_limit_mismatch")
    if values["max_transfer_items_per_container"] != MAX_TRANSFER_ITEMS_PER_CONTAINER:
        raise ProfileError("profile_transfer_node_limit_mismatch")
    if values["max_transfer_items_total"] != MAX_TRANSFER_ITEMS_TOTAL:
        raise ProfileError("profile_transfer_total_limit_mismatch")
    if values["max_country_slot"] != TRANSFER_MAX_COUNTRY_SLOT:
        raise ProfileError("profile_transfer_country_slot_limit_mismatch")
    return values


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    native_tail = raw.get("native_tail") if isinstance(raw.get("native_tail"), Mapping) else {}
    transfer_section = raw.get("transfer") if isinstance(raw.get("transfer"), Mapping) else {}
    tail_chains = native_tail.get("chains") if isinstance(native_tail.get("chains"), Mapping) else {}
    tail_to = tail_chains.get("TRANSFER_TRADE_POWER_TO") if isinstance(tail_chains.get("TRANSFER_TRADE_POWER_TO"), Mapping) else {}
    tail_from = tail_chains.get("TRANSFER_TRADE_POWER_FROM") if isinstance(tail_chains.get("TRANSFER_TRADE_POWER_FROM"), Mapping) else {}
    tail_offsets = native_tail.get("element_offsets") if isinstance(native_tail.get("element_offsets"), Mapping) else {}
    capital_raw = raw.get("capital") if isinstance(raw.get("capital"), Mapping) else {}
    dynamic_raw = raw.get("dynamic") if isinstance(raw.get("dynamic"), Mapping) else {}
    country_fullref_raw = raw.get("country_fullref_offset")
    if country_fullref_raw is None:
        country_fullref_raw = capital_raw.get("country_fullref_offset", native_tail.get("country_object_fullref_offset"))
    transfer_to_raw = raw.get("transfer_to_head_offset", transfer_section.get("to_head_offset", tail_to.get("container_offset")))
    transfer_from_raw = raw.get("transfer_from_head_offset", transfer_section.get("from_head_offset", tail_from.get("container_offset")))
    transfer_fullref_raw = raw.get("transfer_element_fullref_offset", transfer_section.get("element_fullref_offset", tail_offsets.get("fullref")))
    transfer_value_raw = raw.get("transfer_element_value_offset", transfer_section.get("element_value_offset", tail_offsets.get("value")))
    transfer_next_raw = raw.get("transfer_element_next_offset", transfer_section.get("element_next_offset", tail_offsets.get("next")))
    transfer_slot_raw = raw.get("transfer_max_country_slot", transfer_section.get("max_country_slot", native_tail.get("max_country_slot_for_read")))
    try:
        share_offset = _parse_int(raw.get("share_offset"), "layout.share_offset")
        source_raw = raw.get("source_offsets")
        if not isinstance(source_raw, Mapping) or set(source_raw) != set(SOURCE_KEYS):
            raise ProfileError("profile_source_offsets_shape_invalid")
        source_offsets = {key: _parse_int(source_raw[key], f"layout.source_offsets.{key}") for key in SOURCE_KEYS}
        result = {
            "entry_size_bytes": _parse_int(raw.get("entry_size_bytes", ENTRY_WIDTH), "layout.entry_size_bytes"),
            "share_offset": share_offset,
            "source_offsets": source_offsets,
            "country_fullref_offset": _parse_int(country_fullref_raw, "layout.country_fullref_offset"),
            "capital_database_global_rva": _parse_int(_layout_value(raw, "capital", "database_global_rva"), "layout.capital.database_global_rva"),
            "capital_country_table_offset": _parse_int(_layout_value(raw, "capital", "country_table_offset", "table_offset", "vector_offset"), "layout.capital.country_table_offset"),
            "capital_country_14c8_offset": _parse_int(_layout_value(raw, "capital", "country_14c8_offset", "country_anchor_offset"), "layout.capital.country_14c8_offset"),
            "capital_anchor_node_offset": _parse_int(_layout_value(raw, "capital", "anchor_node_offset", "node_identity_offset"), "layout.capital.anchor_node_offset"),
            "capital_scalar_rva": _parse_int(_layout_value(raw, "capital", "scalar_rva", "global_scalar_rva"), "layout.capital.scalar_rva"),
            "capital_vector_stride": _parse_int(_layout_value(raw, "capital", "vector_stride", "country_vector_stride") if "vector_stride" in capital_raw or "country_vector_stride" in capital_raw else 8, "layout.capital.vector_stride"),
            "dynamic_head_offset": _parse_int(_layout_value(raw, "dynamic", "head_offset", "entry_head_offset", "link_head_offset"), "layout.dynamic.head_offset"),
            "dynamic_link_item_offset": _parse_int(_layout_value(raw, "dynamic", "link_item_offset"), "layout.dynamic.link_item_offset"),
            "dynamic_link_next_offset": _parse_int(_layout_value(raw, "dynamic", "link_next_offset"), "layout.dynamic.link_next_offset"),
            "dynamic_item_value_offset": _parse_int(_layout_value(raw, "dynamic", "item_value_offset"), "layout.dynamic.item_value_offset"),
            "dynamic_item_name_offset": _parse_int(_layout_value(raw, "dynamic", "item_name_offset", "name_object_offset"), "layout.dynamic.item_name_offset"),
            "dynamic_name_capacity_offset": _parse_int(_layout_value(raw, "dynamic", "name_capacity_offset", "name_capacity_offset_from_object"), "layout.dynamic.name_capacity_offset"),
            "dynamic_name_heap_pointer_offset": _parse_int(_layout_value(raw, "dynamic", "name_heap_pointer_offset", "name_heap_pointer_offset_from_object"), "layout.dynamic.name_heap_pointer_offset"),
            "dynamic_name_inline_capacity": _parse_int(_layout_value(raw, "dynamic", "name_inline_capacity", "name_inline_threshold"), "layout.dynamic.name_inline_capacity"),
            "dynamic_name_object_size": _parse_int(_layout_value(raw, "dynamic", "name_object_size") if "name_object_size" in dynamic_raw else 0x20, "layout.dynamic.name_object_size"),
            "transfer_to_head_offset": _parse_int(transfer_to_raw, "layout.transfer.to_head_offset"),
            "transfer_from_head_offset": _parse_int(transfer_from_raw, "layout.transfer.from_head_offset"),
            "transfer_element_fullref_offset": _parse_int(transfer_fullref_raw, "layout.transfer.element_fullref_offset"),
            "transfer_element_value_offset": _parse_int(transfer_value_raw, "layout.transfer.element_value_offset"),
            "transfer_element_next_offset": _parse_int(transfer_next_raw, "layout.transfer.element_next_offset"),
            "transfer_max_country_slot": _parse_int(transfer_slot_raw, "layout.transfer.max_country_slot"),
            "transfer_vector_stride": _parse_int(_layout_value(raw, "transfer", "vector_stride", "country_vector_stride") if "vector_stride" in transfer_section or "country_vector_stride" in transfer_section else 8, "layout.transfer.vector_stride"),
            "transfer_country_tag_offset": raw.get("transfer", {}).get("country_tag_offset") if isinstance(raw.get("transfer"), Mapping) else None,
            "transfer_country_tag_size": raw.get("transfer", {}).get("country_tag_size") if isinstance(raw.get("transfer"), Mapping) else None,
            "source_trade_profile_sha256": raw.get("source_trade_profile_sha256", EXPECTED_TRADE_PROFILE_SHA256),
            "reused_graph_profile_sha256": raw.get("reused_graph_profile_sha256"),
            "signed": raw.get("signed", True),
        }
    except KeyError as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc
    if result["entry_size_bytes"] != ENTRY_WIDTH or result["share_offset"] != SHARE_OFFSET:
        raise ProfileError("profile_entry_share_layout_mismatch")
    if result["source_offsets"] != SOURCE_OFFSETS:
        raise ProfileError("profile_source_offsets_mismatch")
    expected = {
        "country_fullref_offset": CAPITAL_COUNTRY_FULLREF_OFFSET,
        "capital_database_global_rva": CAPITAL_DATABASE_GLOBAL_RVA,
        "capital_country_table_offset": CAPITAL_COUNTRY_TABLE_OFFSET,
        "capital_country_14c8_offset": CAPITAL_COUNTRY_14C8_OFFSET,
        "capital_anchor_node_offset": CAPITAL_ANCHOR_NODE_OFFSET,
        "capital_scalar_rva": CAPITAL_SCALAR_RVA,
        "capital_vector_stride": CAPITAL_VECTOR_STRIDE,
        "dynamic_head_offset": DYNAMIC_HEAD_OFFSET,
        "dynamic_link_item_offset": DYNAMIC_LINK_ITEM_OFFSET,
        "dynamic_link_next_offset": DYNAMIC_LINK_NEXT_OFFSET,
        "dynamic_item_value_offset": DYNAMIC_ITEM_VALUE_OFFSET,
        "dynamic_item_name_offset": DYNAMIC_ITEM_NAME_OFFSET,
        "dynamic_name_capacity_offset": DYNAMIC_NAME_CAPACITY_OFFSET,
        "dynamic_name_heap_pointer_offset": DYNAMIC_NAME_HEAP_POINTER_OFFSET,
        "dynamic_name_inline_capacity": DYNAMIC_NAME_INLINE_CAPACITY,
        "dynamic_name_object_size": DYNAMIC_NAME_OBJECT_SIZE,
        "transfer_to_head_offset": TRANSFER_TO_HEAD_OFFSET,
        "transfer_from_head_offset": TRANSFER_FROM_HEAD_OFFSET,
        "transfer_element_fullref_offset": TRANSFER_ELEMENT_FULLREF_OFFSET,
        "transfer_element_value_offset": TRANSFER_ELEMENT_VALUE_OFFSET,
        "transfer_element_next_offset": TRANSFER_ELEMENT_NEXT_OFFSET,
        "transfer_max_country_slot": TRANSFER_MAX_COUNTRY_SLOT,
        "transfer_vector_stride": CAPITAL_VECTOR_STRIDE,
    }
    for key, value in expected.items():
        if result[key] != value:
            raise ProfileError(f"profile_{key}_mismatch")
    if result["signed"] is not True:
        raise ProfileError("profile_signed_contract_mismatch")
    if result["source_trade_profile_sha256"] != EXPECTED_TRADE_PROFILE_SHA256:
        raise ProfileError("profile_source_trade_profile_sha256_mismatch")
    if result["reused_graph_profile_sha256"] not in (None, EXPECTED_TRADE_PROFILE_SHA256, LEGACY_DETAILS_PROFILE_SHA256):
        raise ProfileError("profile_reused_graph_profile_sha256_mismatch")
    return result


def _profile_semantics(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("semantics")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_semantics_missing")
    values = {"basis": raw.get("basis"), "unit": raw.get("unit"), "scale": raw.get("scale"), "period": raw.get("period"), "value_origin": raw.get("value_origin"), "complete": raw.get("complete", profile.get("complete"))}
    if values["basis"] != BASIS or values["unit"] != UNIT or values["scale"] != SCALE or values["period"] != PERIOD or values["value_origin"] != VALUE_ORIGIN or values["complete"] is not COMPLETE:
        raise ProfileError("profile_semantics_mismatch")
    return values


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_missing")
    guards: list[tuple[str, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = item.get("name")
        raw_hex = item.get("hex", item.get("bytes"))
        if not isinstance(name, str) or not name or name in names or not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError("profile_code_guard_shape_invalid")
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        if not raw_bytes or len(raw_bytes) > MAX_SINGLE_READ:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        total += len(raw_bytes)
        if total > MAX_CHILD_READ:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        guards.append((name, rva, raw_bytes))
    return guards


def _source_index_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("profile_source_index_path_invalid")
    path = (_ROOT / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
    if path != _ROOT and _ROOT not in path.parents:
        raise ProfileError("profile_source_index_path_escape")
    return path


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("profile_source_index_missing")
    source_id = source.get("source_index_id")
    expected_sha = source.get("sha256")
    if not isinstance(source_id, str) or not source_id:
        raise ProfileError("profile_source_index_id_invalid")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        raise ProfileError("profile_source_index_sha256_invalid")
    path = _source_index_path(source.get("path"))
    raw = _bounded_bytes(path, SOURCE_INDEX_MAX_BYTES, "source_index")
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha.lower() != expected_sha.lower():
        raise ProfileError("profile_source_index_sha256_mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_source_index_json_invalid:{exc}") from exc
    if not isinstance(document, Mapping):
        raise ProfileError("profile_source_index_shape_invalid")
    if document.get("source_index_id") != source_id:
        raise ProfileError("profile_source_index_id_mismatch")
    if document.get("profile_id") not in (None, profile.get("profile_id")):
        raise ProfileError("profile_source_index_profile_id_mismatch")
    return {"source_index_id": source_id, "path": str(path), "sha256": expected_sha.lower(), "bytes": len(raw)}


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != PROFILE_ID:
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _profile_layout(profile)
    _profile_semantics(profile)
    _profile_limits(profile)
    _profile_code_guards(profile)


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or expected.startswith("pending-"):
        raise ProfileError("profile_sha256_pending_or_invalid")
    raw = _bounded_bytes(path, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    _validate_profile_shape(profile)
    result = dict(profile)
    result["_validated_source_index"] = _validate_source_index(profile)
    return result


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    return _load_profile()


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {"status": "unknown", "checks": {}, "unknown_conditions": [reason or "profile_unavailable"]}
    source = profile.get("_validated_source_index", profile.get("source_index", {}))
    source_ok = isinstance(source, Mapping) and all(isinstance(source.get(key), str) and bool(source.get(key)) for key in ("source_index_id", "path", "sha256"))
    checks: dict[str, bool] = {
        "profile_id": profile.get("profile_id") == PROFILE_ID,
        "game_version": profile.get("game_version") == EXPECTED_VERSION,
        "executable_sha256": isinstance(profile.get("executable"), Mapping) and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "source_index": source_ok,
    }
    for name, fn in (("layout", _profile_layout), ("semantics", _profile_semantics), ("limits", _profile_limits), ("code_guards", _profile_code_guards)):
        try:
            fn(profile)
            checks[name] = True
        except ProfileError:
            checks[name] = False
    failed = [name for name, ok in checks.items() if ok is not True]
    unknown = ["profile_contract_failed:" + ",".join(failed)] if failed else []
    if reason:
        unknown.append(reason)
    return {"status": "observed" if not failed else "unknown", "profile_id": profile.get("profile_id"), "profile_sha256": EXPECTED_PROFILE_SHA256, "checks": checks, "source_index": {key: source.get(key) for key in ("source_index_id", "path", "sha256", "bytes") if isinstance(source, Mapping) and key in source}, "unknown_conditions": unknown}


def _empty_capital_context(reason: str | None = None) -> dict[str, Any]:
    return {
        "status": "unknown", "database_global_address": None, "database_global_raw_hex": None,
        "database_root_pointer": None, "database_root_raw_hex": None, "country_table_address": None,
        "country_table_pointer": None, "country_table_raw_hex": None, "country_pointer": None,
        "country_fullref_address": None, "country_fullref_raw_hex": None, "country_slot": None,
        "selected_country_address": None, "selected_country_pointer": None, "selected_country_raw_hex": None,
        "selected_country_fullref_address": None, "selected_country_fullref_raw_hex": None,
        "country_14c8_address": None, "country_14c8_raw_hex": None, "anchor_pointer": None,
        "anchor_raw_hex": None, "anchor_node_address": None, "anchor_node_pointer": None,
        "anchor_node_raw_hex": None, "global_scalar_address": None, "global_raw": None,
        "global_raw_hex": None, "included_node_id": None, "reason": reason,
    }


def _empty_transfer_container(direction: str, reason: str | None = None, head_raw_hex: str | None = None) -> dict[str, Any]:
    native_key = "TRANSFER_TRADE_POWER_TO" if direction == "to" else "TRANSFER_TRADE_POWER_FROM"
    return {
        "status": "unknown" if reason else "observed",
        "direction": direction,
        "native_key": native_key,
        "unit": "trade_power",
        "scale": SCALE,
        "head_raw_hex": head_raw_hex,
        "items": [],
        "reason": reason,
    }


def _empty_record(reason: str, *, profile: Mapping[str, Any] | None = None, guard: Mapping[str, Any] | None = None, source: Mapping[str, Any] | None = None, source_digest: str | None = None, module_base: int | None = None) -> dict[str, Any]:
    source = source or {}
    try:
        limits = _profile_limits(profile) if isinstance(profile, Mapping) else None
    except ProfileError:
        limits = None
    limits = limits or {
        "max_child_read_bytes": MAX_CHILD_READ,
        "max_single_read_bytes": MAX_SINGLE_READ,
        "max_elements_per_node_across_three_chains": MAX_TRANSFER_ITEMS_PER_CONTAINER,
        "max_elements_global_across_three_chains": MAX_TRANSFER_ITEMS_TOTAL,
        "max_dynamic_items_per_node": MAX_DYNAMIC_ITEMS_PER_NODE,
        "max_dynamic_items_total": MAX_DYNAMIC_ITEMS_TOTAL,
        "max_dynamic_name_bytes": MAX_DYNAMIC_NAME_BYTES,
        "max_transfer_items_per_container": MAX_TRANSFER_ITEMS_PER_CONTAINER,
        "max_transfer_items_total": MAX_TRANSFER_ITEMS_TOTAL,
        "max_country_slot": TRANSFER_MAX_COUNTRY_SLOT,
    }
    return {
        "status": "unknown", "reason": reason, "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": _static_contract_guard(profile, reason if profile is None else None),
        "runtime_code_guard": _deepcopy(guard) if isinstance(guard, Mapping) else None,
        "module_base": _hex(module_base), "country_pointer": source.get("country_pointer"),
        "country": source.get("country", EXPECTED_COUNTRY), "country_fullref_raw_hex": source.get("country_fullref_raw_hex"),
        "country_slot": source.get("country_slot"), "source_trade_record_canonical_sha256": source_digest,
        "share_offset": _hex(SHARE_OFFSET), "source_offsets": {key: _hex(SOURCE_OFFSETS[key]) for key in SOURCE_KEYS},
        "capital_context": _empty_capital_context(reason), "transfer_lookup": {"status": "unknown", "reason": reason}, "nodes": None, "basis": BASIS, "unit": UNIT,
        "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "complete": COMPLETE,
        "unimplemented_source_kinds": list(UNIMPLEMENTED_SOURCE_KINDS), "limits": limits,
        "read_budget": {"bytes_requested": 0, "calls": 0, "max_bytes": limits["max_child_read_bytes"]},
        "observation": {"status": "unknown", "reason": reason},
    }


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], ctx: _Budget) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        if not _trade._valid_address(module_base):
            raise ReadError("module_base_invalid")
        for name, rva, expected in _profile_code_guards(profile):
            address = _trade._address_add(module_base, rva, f"trade_details_v3.code.{name}")
            actual = ctx.read(address, len(expected), f"trade_details_v3.code.{name}")
            result["records"][name] = {"rva": _hex(rva), "address": _hex(address), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _expected_runtime_guard(record: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    guard = record.get("runtime_code_guard")
    try:
        module = int(record.get("module_base"), 0)
        expected_guards = _profile_code_guards(profile)
    except (TypeError, ValueError, ProfileError):
        return False
    if not _trade._valid_address(module) or not isinstance(guard, Mapping) or guard.get("status") != "observed":
        return False
    checks, records = guard.get("checks"), guard.get("records")
    expected_names = {name for name, _rva, _raw in expected_guards}
    if not isinstance(checks, Mapping) or set(checks) != expected_names or any(value is not True for value in checks.values()) or not isinstance(records, Mapping) or set(records) != expected_names:
        return False
    for name, rva, expected in expected_guards:
        item = records.get(name)
        if not isinstance(item, Mapping) or item.get("rva") != _hex(rva) or item.get("address") != _hex(module + rva) or item.get("expected_hex") != expected.hex() or item.get("actual_hex") != expected.hex() or item.get("expected_sha256") != hashlib.sha256(expected).hexdigest() or item.get("actual_sha256") != hashlib.sha256(expected).hexdigest():
            return False
    return guard.get("module_base") == _hex(module) and guard.get("unknown_conditions") == []


def _valid_hex(raw: Any, width: int) -> bool:
    if not isinstance(raw, str) or len(raw) != width * 2:
        return False
    try:
        bytes.fromhex(raw)
    except ValueError:
        return False
    return True


def _i32_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(I32_WIDTH, "little", signed=False).hex()


def _pointer_raw_hex(value: int) -> str:
    return value.to_bytes(QWORD_WIDTH, "little", signed=False).hex()


def _i32_from_entry(entry_hex: Any, offset: int, label: str) -> tuple[int, str]:
    if not _valid_hex(entry_hex, ENTRY_WIDTH):
        raise ReadError(f"entry_raw_invalid:{label}")
    entry = bytes.fromhex(entry_hex)
    chunk = entry[offset:offset + I32_WIDTH]
    if len(chunk) != I32_WIDTH:
        raise ReadError(f"entry_field_out_of_bounds:{label}")
    return int.from_bytes(chunk, "little", signed=True), chunk.hex()


def _source_included(key: str, raw: int) -> bool:
    if key in ("TP_PROVINCE_POWER", "TP_SHIP_POWER"):
        return raw != 0
    if key == "MERCHANT_DOWNSTREAM_BONUS":
        return raw > 0
    raise ReadError(f"source_key_unknown:{key}")


def _source_row(key: str, raw: int, raw_hex: str) -> dict[str, Any]:
    return {"native_key": key, "raw": raw, "raw_hex": raw_hex, "unit": "trade_power", "scale": SCALE}


def _derive_base_node(source_node: Mapping[str, Any], layout: Mapping[str, Any]) -> dict[str, Any]:
    node_id = source_node.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise ReadError("source_node_id_invalid")
    share_raw, share_hex = _i32_from_entry(source_node.get("entry_raw_hex"), layout["share_offset"], f"{node_id}.share")
    source_inputs: dict[str, dict[str, Any]] = {}
    for key in SOURCE_KEYS:
        raw, raw_hex = _i32_from_entry(source_node.get("entry_raw_hex"), layout["source_offsets"][key], f"{node_id}.{key}")
        source_inputs[key] = {"raw": raw, "raw_hex": raw_hex, "included": _source_included(key, raw)}
    return {"node_id": node_id, "share_raw": share_raw, "share_raw_hex": share_hex, "source_inputs": source_inputs}


def _read_qword(ctx: _Budget, address: int, label: str, *, require_pointer: bool = True) -> tuple[int, bytes]:
    raw = ctx.read(address, QWORD_WIDTH, label)
    value = int.from_bytes(raw, "little", signed=False)
    if require_pointer and not _trade._valid_address(value):
        raise ReadError(f"pointer_invalid:{label}")
    return value, raw


def _capital_context(ctx: _Budget, module_base: int, source_record: Mapping[str, Any], source_nodes: list[Mapping[str, Any]], layout: Mapping[str, Any]) -> dict[str, Any]:
    result = _empty_capital_context()
    country_pointer = _trade._pointer_from_hex(source_record.get("country_pointer"))
    result["country_pointer"] = source_record.get("country_pointer")
    result["country_fullref_raw_hex"] = source_record.get("country_fullref_raw_hex")
    result["country_slot"] = source_record.get("country_slot")
    if country_pointer is not None:
        result["country_fullref_address"] = _hex(_trade._address_add(country_pointer, layout["country_fullref_offset"], "country.fullref"))
    try:
        if country_pointer is None:
            raise ReadError("capital_country_pointer_invalid")
        fullref_hex = source_record.get("country_fullref_raw_hex")
        if not _valid_hex(fullref_hex, QWORD_WIDTH) or bytes.fromhex(fullref_hex)[:4] != b"FRA\0":
            raise ReadError("capital_country_fullref_invalid")
        slot = source_record.get("country_slot")
        if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0 or slot > 32767:
            raise ReadError("capital_country_slot_invalid")
        db_address = _trade._address_add(module_base, layout["capital_database_global_rva"], "capital.database_global")
        db_root, db_raw = _read_qword(ctx, db_address, "capital.database_global")
        table_address = _trade._address_add(db_root, layout["capital_country_table_offset"], "capital.country_table")
        table, table_raw = _read_qword(ctx, table_address, "capital.country_table")
        selected_address = _trade._address_add(table, slot * layout["capital_vector_stride"], "capital.selected_country")
        selected, selected_raw = _read_qword(ctx, selected_address, "capital.selected_country")
        selected_fullref_address = _trade._address_add(selected, layout["country_fullref_offset"], "capital.selected_country_fullref")
        selected_fullref = ctx.read(selected_fullref_address, QWORD_WIDTH, "capital.selected_country_fullref")
        result.update({"database_global_address": _hex(db_address), "database_global_raw_hex": db_raw.hex(), "database_root_pointer": _hex(db_root), "database_root_raw_hex": db_raw.hex(), "country_table_address": _hex(table_address), "country_table_pointer": _hex(table), "country_table_raw_hex": table_raw.hex(), "selected_country_address": _hex(selected_address), "selected_country_pointer": _hex(selected), "selected_country_raw_hex": selected_raw.hex(), "selected_country_fullref_address": _hex(selected_fullref_address), "selected_country_fullref_raw_hex": selected_fullref.hex()})
        if selected != country_pointer:
            raise ReadError("capital_selected_country_mismatch")
        if selected_fullref.hex() != fullref_hex.lower():
            raise ReadError("capital_selected_country_fullref_mismatch")
        country_14c8_address = _trade._address_add(selected, layout["capital_country_14c8_offset"], "capital.country_14c8")
        anchor, anchor_raw = _read_qword(ctx, country_14c8_address, "capital.country_14c8")
        anchor_node_address = _trade._address_add(anchor, layout["capital_anchor_node_offset"], "capital.anchor_node")
        anchor_node, anchor_node_raw = _read_qword(ctx, anchor_node_address, "capital.anchor_node")
        result.update({"country_14c8_address": _hex(country_14c8_address), "country_14c8_raw_hex": anchor_raw.hex(), "anchor_pointer": _hex(anchor), "anchor_raw_hex": anchor_raw.hex(), "anchor_node_address": _hex(anchor_node_address), "anchor_node_pointer": _hex(anchor_node), "anchor_node_raw_hex": anchor_node_raw.hex()})
        match = next((node.get("node_id") for node in source_nodes if node.get("runtime_pointer") == _hex(anchor_node)), None)
        if match is None:
            result.update({"status": "observed", "reason": "capital_node_identity_not_found"})
            return result
        scalar_address = _trade._address_add(module_base, layout["capital_scalar_rva"], "capital.global_scalar")
        scalar_raw = ctx.read(scalar_address, I32_WIDTH, "capital.global_scalar")
        scalar = int.from_bytes(scalar_raw, "little", signed=True)
        result.update({"status": "observed", "reason": None, "included_node_id": match, "global_scalar_address": _hex(scalar_address), "global_raw": scalar, "global_raw_hex": scalar_raw.hex()})
        return result
    except Exception as exc:
        result["status"] = "unknown"
        result["reason"] = f"{type(exc).__name__}:{exc}"
        return result


def _dynamic_unknown(head_raw_hex: str | None, reason: str) -> dict[str, Any]:
    return {"status": "unknown", "head_raw_hex": head_raw_hex, "items": [], "reason": reason}


def _shared_chain_limits(limits: Mapping[str, int]) -> tuple[int, int]:
    """Return effective v3 per-node/global limits for dynamic + TO + FROM.

    The v3 profile has one cap shared by all three chains.  The two legacy
    aliases remain in normalized records for compatibility with earlier
    profiles/tests; taking the strictest value also makes an old caller-side
    override fail closed rather than silently widening the shared contract.
    """
    node_values = [
        limits.get("max_elements_per_node_across_three_chains", MAX_TRANSFER_ITEMS_PER_CONTAINER),
        limits.get("max_dynamic_items_per_node", MAX_DYNAMIC_ITEMS_PER_NODE),
        limits.get("max_transfer_items_per_container", MAX_TRANSFER_ITEMS_PER_CONTAINER),
    ]
    total_values = [
        limits.get("max_elements_global_across_three_chains", MAX_TRANSFER_ITEMS_TOTAL),
        limits.get("max_dynamic_items_total", MAX_DYNAMIC_ITEMS_TOTAL),
        limits.get("max_transfer_items_total", MAX_TRANSFER_ITEMS_TOTAL),
    ]
    return min(int(value) for value in node_values), min(int(value) for value in total_values)


def _reserve_chain_element(state: dict[str, int | bool], limits: Mapping[str, int]) -> None:
    """Consume one shared three-chain element slot before its first read."""
    node_limit, total_limit = _shared_chain_limits(limits)
    node_used = int(state.get("node_chain_items", 0))
    total_used = int(state.get("global_chain_items", 0))
    if node_used >= node_limit:
        raise ReadError("detail_elements_per_node_limit")
    if total_used >= total_limit:
        raise ReadError("detail_elements_global_limit")
    state["node_chain_items"] = node_used + 1
    state["global_chain_items"] = total_used + 1


def _read_dynamic(ctx: _Budget, source_node: Mapping[str, Any], layout: Mapping[str, Any], limits: Mapping[str, int], state: dict[str, int | bool]) -> dict[str, Any]:
    entry_hex = source_node.get("entry_raw_hex")
    if not _valid_hex(entry_hex, ENTRY_WIDTH):
        return _dynamic_unknown(None, "dynamic_entry_raw_invalid")
    entry = bytes.fromhex(entry_hex)
    head_raw = entry[layout["dynamic_head_offset"]:layout["dynamic_head_offset"] + QWORD_WIDTH]
    if len(head_raw) != QWORD_WIDTH:
        return _dynamic_unknown(None, "dynamic_head_out_of_bounds")
    head = int.from_bytes(head_raw, "little")
    if head == 0:
        return {"status": "observed", "head_raw_hex": head_raw.hex(), "items": [], "reason": None}
    if bool(state.get("exhausted")):
        return _dynamic_unknown(head_raw.hex(), "dynamic_read_budget_exhausted")
    seen: set[int] = set()
    current = head
    items: list[dict[str, Any]] = []
    try:
        while current:
            if not _trade._valid_address(current):
                raise ReadError("dynamic_link_pointer_invalid")
            if current in seen:
                raise ReadError("dynamic_cycle_detected")
            seen.add(current)
            # Reserve before the first link/item read.  Any subsequent RPM
            # failure leaves the slot consumed for the rest of this pass.
            _reserve_chain_element(state, limits)
            link_pointer = current
            item_address = _trade._address_add(link_pointer, layout["dynamic_link_item_offset"], "dynamic.link.item")
            item, item_raw = _read_qword(ctx, item_address, "dynamic.link.item")
            next_address = _trade._address_add(link_pointer, layout["dynamic_link_next_offset"], "dynamic.link.next")
            next_pointer, next_raw = _read_qword(ctx, next_address, "dynamic.link.next", require_pointer=False)
            if item == 0 or not _trade._valid_address(item):
                raise ReadError("dynamic_item_pointer_invalid")
            value_address = _trade._address_add(item, layout["dynamic_item_value_offset"], "dynamic.item.value")
            value_raw_bytes = ctx.read(value_address, I32_WIDTH, "dynamic.item.value")
            value = int.from_bytes(value_raw_bytes, "little", signed=True)
            name_object = _trade._address_add(item, layout["dynamic_item_name_offset"], "dynamic.item.name_object")
            name_object_raw = ctx.read(name_object, layout["dynamic_name_object_size"], "dynamic.item.name_object")
            cap_begin = layout["dynamic_name_capacity_offset"]
            cap_end = cap_begin + QWORD_WIDTH
            if cap_end > len(name_object_raw):
                raise ReadError("dynamic_name_capacity_out_of_bounds")
            capacity_raw = name_object_raw[cap_begin:cap_end]
            capacity = int.from_bytes(capacity_raw, "little", signed=False)
            if capacity < layout["dynamic_name_inline_capacity"]:
                name_pointer = name_object
                name_pointer_raw = _pointer_raw_hex(name_pointer)
                payload = name_object_raw[:layout["dynamic_name_inline_capacity"]]
                pointer_kind = "inline_object"
            else:
                pointer_begin = layout["dynamic_name_heap_pointer_offset"]
                pointer_end = pointer_begin + QWORD_WIDTH
                if pointer_end > len(name_object_raw):
                    raise ReadError("dynamic_name_pointer_out_of_bounds")
                pointer_raw = name_object_raw[pointer_begin:pointer_end]
                name_pointer = int.from_bytes(pointer_raw, "little", signed=False)
                if not _trade._valid_address(name_pointer):
                    raise ReadError("dynamic_name_pointer_invalid")
                name_pointer_raw = pointer_raw.hex()
                payload = ctx.read(name_pointer, limits["max_dynamic_name_bytes"] + 1, "dynamic.name_bytes")
                pointer_kind = "heap"
            nul = payload.find(b"\0")
            if nul < 0:
                raise ReadError("dynamic_name_nul_missing")
            if nul > limits["max_dynamic_name_bytes"]:
                raise ReadError("dynamic_name_too_long")
            name_raw = payload[:nul + 1]
            items.append({"index": len(items), "link_pointer": _hex(link_pointer), "item_pointer": _hex(item), "item_pointer_raw_hex": item_raw.hex(), "next_pointer": _hex(next_pointer) if next_pointer else None, "next_pointer_raw_hex": next_raw.hex(), "value_raw": value, "value_raw_hex": value_raw_bytes.hex(), "name_object_address": _hex(name_object), "name_object_raw_hex": name_object_raw.hex(), "name_capacity_raw_hex": capacity_raw.hex(), "name_capacity": capacity, "name_pointer": _hex(name_pointer), "name_pointer_raw_hex": name_pointer_raw, "name_pointer_kind": pointer_kind, "name_raw_hex": name_raw.hex()})
            current = next_pointer
        return {"status": "observed", "head_raw_hex": head_raw.hex(), "items": items, "reason": None}
    except Exception as exc:
        if "budget_exceeded" in str(exc):
            state["exhausted"] = True
            reason = "dynamic_read_budget_exhausted"
        else:
            reason = f"{type(exc).__name__}:{exc}"
        return _dynamic_unknown(head_raw.hex(), reason)


def _transfer_entry_head(source_node: Mapping[str, Any], offset: int, label: str) -> tuple[int, str]:
    entry_hex = source_node.get("entry_raw_hex")
    if not _valid_hex(entry_hex, ENTRY_WIDTH):
        raise ReadError(f"transfer_entry_raw_invalid:{label}")
    entry = bytes.fromhex(entry_hex)
    raw = entry[offset:offset + QWORD_WIDTH]
    if len(raw) != QWORD_WIDTH:
        raise ReadError(f"transfer_head_out_of_bounds:{label}")
    return int.from_bytes(raw, "little", signed=False), raw.hex()


def _transfer_lookup_context(ctx: _Budget, module_base: int, layout: Mapping[str, Any], capital_context: Mapping[str, Any], needed: bool) -> dict[str, Any]:
    """Resolve the bounded country table used by transfer fullrefs.

    A transfer element is retained only as a raw fullref/value when its table
    entry cannot be matched.  The reader never scans the table or asks for an
    unrelated country: it indexes only the slot carried by that element.
    """
    if not needed:
        return {"status": "not_needed", "reason": None}
    table = _validate_pointer_field(capital_context.get("country_table_pointer"))
    if table is not None:
        return {
            "status": "observed",
            "database_global_address": capital_context.get("database_global_address"),
            "database_global_raw_hex": capital_context.get("database_global_raw_hex"),
            "database_root_pointer": capital_context.get("database_root_pointer"),
            "database_root_raw_hex": capital_context.get("database_root_raw_hex"),
            "country_table_address": capital_context.get("country_table_address"),
            "country_table_pointer": capital_context.get("country_table_pointer"),
            "country_table_raw_hex": capital_context.get("country_table_raw_hex"),
            "country_fullref_offset": _hex(layout["country_fullref_offset"]),
            "vector_stride": layout["transfer_vector_stride"],
            "reason": None,
        }
    try:
        db_address = _trade._address_add(module_base, layout["capital_database_global_rva"], "transfer.database_global")
        db_root, db_raw = _read_qword(ctx, db_address, "transfer.database_global")
        table_address = _trade._address_add(db_root, layout["capital_country_table_offset"], "transfer.country_table")
        table, table_raw = _read_qword(ctx, table_address, "transfer.country_table")
        return {
            "status": "observed",
            "database_global_address": _hex(db_address),
            "database_global_raw_hex": db_raw.hex(),
            "database_root_pointer": _hex(db_root),
            "database_root_raw_hex": db_raw.hex(),
            "country_table_address": _hex(table_address),
            "country_table_pointer": _hex(table),
            "country_table_raw_hex": table_raw.hex(),
            "country_fullref_offset": _hex(layout["country_fullref_offset"]),
            "vector_stride": layout["transfer_vector_stride"],
            "reason": None,
        }
    except Exception as exc:
        return {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}"}


def _transfer_country(ctx: _Budget, table_context: Mapping[str, Any], fullref_raw: bytes, slot: int, layout: Mapping[str, Any]) -> dict[str, Any]:
    if table_context.get("status") != "observed":
        raise ReadError("transfer_country_table_unknown")
    table = _validate_pointer_field(table_context.get("country_table_pointer"))
    if table is None:
        raise ReadError("transfer_country_table_pointer_invalid")
    slot_address = _trade._address_add(table, slot * layout["transfer_vector_stride"], "transfer.country_slot")
    country, country_raw = _read_qword(ctx, slot_address, "transfer.country_pointer")
    fullref_address = _trade._address_add(country, layout["country_fullref_offset"], "transfer.country_fullref")
    country_fullref = ctx.read(fullref_address, QWORD_WIDTH, "transfer.country_fullref")
    matched = country_fullref == fullref_raw
    # The packed fullref carries the three-byte country tag.  Publish it only
    # after the bounded table object proves the exact fullref match; the
    # resolver's separate display-object path remains intentionally unused.
    country_tag: str | None = None
    if matched and fullref_raw[3] == 0 and all(0x30 <= value <= 0x39 or 0x41 <= value <= 0x5A for value in fullref_raw[:3]):
        country_tag = fullref_raw[:3].decode("ascii")
    return {
        "country_table_address": table_context.get("country_table_address"),
        "country_table_pointer": table_context.get("country_table_pointer"),
        "country_slot_address": _hex(slot_address),
        "country_pointer": _hex(country),
        "country_pointer_raw_hex": country_raw.hex(),
        "country_fullref_address": _hex(fullref_address),
        "country_fullref_raw_hex": country_fullref.hex(),
        "country_fullref_matched": matched,
        "country_tag": country_tag,
        "country_tag_status": "matched_fullref" if matched and country_tag is not None else ("matched_fullref_prefix_invalid" if matched else "fullref_mismatch"),
    }


def _read_transfer(ctx: _Budget, source_node: Mapping[str, Any], direction: str, layout: Mapping[str, Any], limits: Mapping[str, int], table_context: Mapping[str, Any], state: dict[str, int | bool]) -> dict[str, Any]:
    head_offset = layout["transfer_to_head_offset"] if direction == "to" else layout["transfer_from_head_offset"]
    native_key = "TRANSFER_TRADE_POWER_TO" if direction == "to" else "TRANSFER_TRADE_POWER_FROM"
    try:
        head, head_hex = _transfer_entry_head(source_node, head_offset, direction)
    except Exception as exc:
        return _empty_transfer_container(direction, f"{type(exc).__name__}:{exc}")
    if head == 0:
        result = _empty_transfer_container(direction, None, head_hex)
        result["native_key"] = native_key
        return result
    if bool(state.get("exhausted")):
        return _empty_transfer_container(direction, "transfer_read_budget_exhausted", head_hex)
    seen: set[int] = set()
    current = head
    items: list[dict[str, Any]] = []
    try:
        while current:
            if not _trade._valid_address(current):
                raise ReadError("transfer_element_pointer_invalid")
            if current in seen:
                raise ReadError("transfer_cycle_detected")
            seen.add(current)
            # TO and FROM consume the same per-node/global allowance as the
            # dynamic chain; reserve before the first element RPM.
            _reserve_chain_element(state, limits)
            fullref_address = _trade._address_add(current, layout["transfer_element_fullref_offset"], "transfer.element.fullref")
            fullref_raw = ctx.read(fullref_address, QWORD_WIDTH, "transfer.element.fullref")
            slot = int.from_bytes(fullref_raw[4:6], "little", signed=True)
            if slot < 0 or slot > limits["max_country_slot"]:
                raise ReadError("transfer_country_slot_out_of_bound")
            value_address = _trade._address_add(current, layout["transfer_element_value_offset"], "transfer.element.value")
            value_raw = ctx.read(value_address, I32_WIDTH, "transfer.element.value")
            value = int.from_bytes(value_raw, "little", signed=True)
            next_address = _trade._address_add(current, layout["transfer_element_next_offset"], "transfer.element.next")
            next_pointer, next_raw = _read_qword(ctx, next_address, "transfer.element.next", require_pointer=False)
            country = _transfer_country(ctx, table_context, fullref_raw, slot, layout)
            items.append({
                "index": len(items),
                "direction": direction,
                "native_key": native_key,
                "element_pointer": _hex(current),
                "element_pointer_raw_hex": _pointer_raw_hex(current),
                "fullref_address": _hex(fullref_address),
                "fullref_raw_hex": fullref_raw.hex(),
                "country_slot": slot,
                "value_address": _hex(value_address),
                "raw": value,
                "raw_hex": value_raw.hex(),
                "unit": "trade_power",
                "scale": SCALE,
                "next_pointer": _hex(next_pointer) if next_pointer else None,
                "next_pointer_raw_hex": next_raw.hex(),
                "next_address": _hex(next_address),
                **country,
            })
            current = next_pointer
        result = _empty_transfer_container(direction, None, head_hex)
        result["native_key"] = native_key
        result["items"] = items
        return result
    except Exception as exc:
        if "budget_exceeded" in str(exc):
            state["exhausted"] = True
            reason = "transfer_read_budget_exhausted"
        else:
            reason = f"{type(exc).__name__}:{exc}"
        return _empty_transfer_container(direction, reason, head_hex)


def _expected_capital_node(context: Mapping[str, Any], source_node: Mapping[str, Any]) -> dict[str, Any]:
    if context.get("status") != "observed":
        return {"status": "unknown", "included": False, "raw": None, "raw_hex": None, "reason": context.get("reason") or "capital_context_unknown"}
    if context.get("included_node_id") == source_node.get("node_id"):
        return {"status": "observed", "included": True, "raw": context.get("global_raw"), "raw_hex": context.get("global_raw_hex"), "reason": None}
    return {"status": "observed", "included": False, "raw": None, "raw_hex": None, "reason": context.get("reason") or "capital_node_identity_mismatch"}


def _make_node(base: Mapping[str, Any], capital: Mapping[str, Any], dynamic: Mapping[str, Any], transfer_sources: Mapping[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for key in ("TP_PROVINCE_POWER", "TP_SHIP_POWER"):
        source = base["source_inputs"][key]
        if source["included"]:
            rows.append(_source_row(key, source["raw"], source["raw_hex"]))
    if capital.get("included"):
        rows.append(_source_row("TRADE_POWER_CAPITAL", capital["raw"], capital["raw_hex"]))
    downstream = base["source_inputs"]["MERCHANT_DOWNSTREAM_BONUS"]
    if downstream["included"]:
        rows.append(_source_row("MERCHANT_DOWNSTREAM_BONUS", downstream["raw"], downstream["raw_hex"]))
    return {"node_id": base["node_id"], "share_raw": base["share_raw"], "share_raw_hex": base["share_raw_hex"], "source_inputs": _deepcopy(base["source_inputs"]), "source_rows": rows, "capital": _deepcopy(capital), "dynamic_sources": _deepcopy(dynamic), "transfer_sources": _deepcopy(transfer_sources)}


def read_fields(reader: Any, module_base: int, trade_income_record: Any) -> dict[str, Any]:
    """Derive fixed source rows plus independently bounded detail children."""
    if not isinstance(trade_income_record, Mapping) or not _trade.validate_record(trade_income_record):
        return _empty_record("trade_income_record_invalid")
    source_digest = _canonical_digest(trade_income_record)
    source_module = _trade._pointer_from_hex(trade_income_record.get("module_base"))
    if not isinstance(module_base, int) or isinstance(module_base, bool) or source_module != module_base:
        return _empty_record("module_base_source_mismatch", source=trade_income_record, source_digest=source_digest, module_base=module_base if isinstance(module_base, int) else None)
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
        limits = _profile_limits(profile)
        _profile_semantics(profile)
    except Exception as exc:
        return _empty_record(f"profile_unavailable:{type(exc).__name__}:{exc}", source=trade_income_record, source_digest=source_digest, module_base=module_base)
    static_guard = _static_contract_guard(profile)
    if static_guard.get("status") != "observed":
        return _empty_record("static_contract_guard_failed", profile=profile, source=trade_income_record, source_digest=source_digest, module_base=module_base)
    ctx = _Budget(reader, limits["max_child_read_bytes"])
    guard = _runtime_code_guard(reader, module_base, profile, ctx)
    if guard.get("status") != "observed":
        result = _empty_record("runtime_code_guard_failed", profile=profile, guard=guard, source=trade_income_record, source_digest=source_digest, module_base=module_base)
        result["limits"] = limits
        result["read_budget"] = {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls, "max_bytes": ctx.limit}
        return result
    source_nodes = trade_income_record.get("nodes")
    if not isinstance(source_nodes, list) or not source_nodes:
        return _empty_record("trade_income_nodes_missing", profile=profile, guard=guard, source=trade_income_record, source_digest=source_digest, module_base=module_base)
    try:
        bases = [_derive_base_node(node, layout) for node in source_nodes]
    except Exception as exc:
        return _empty_record(f"derive_base_failed:{type(exc).__name__}:{exc}", profile=profile, guard=guard, source=trade_income_record, source_digest=source_digest, module_base=module_base)
    capital = _capital_context(ctx, module_base, trade_income_record, source_nodes, layout)
    transfer_needed = False
    for source_node in source_nodes:
        try:
            to_head, _ = _transfer_entry_head(source_node, layout["transfer_to_head_offset"], "to")
            from_head, _ = _transfer_entry_head(source_node, layout["transfer_from_head_offset"], "from")
            transfer_needed = transfer_needed or bool(to_head or from_head)
        except Exception:
            transfer_needed = True
    transfer_lookup = _transfer_lookup_context(ctx, module_base, layout, capital, transfer_needed)
    state: dict[str, int | bool] = {"node_chain_items": 0, "global_chain_items": 0, "exhausted": False}
    nodes: list[dict[str, Any]] = []
    for base, source_node in zip(bases, source_nodes):
        # The per-node allowance spans dynamic, transfer-to and transfer-from.
        state["node_chain_items"] = 0
        capital_node = _expected_capital_node(capital, source_node)
        dynamic = _read_dynamic(ctx, source_node, layout, limits, state)
        transfers = {
            "to": _read_transfer(ctx, source_node, "to", layout, limits, transfer_lookup, state),
            "from": _read_transfer(ctx, source_node, "from", layout, limits, transfer_lookup, state),
        }
        nodes.append(_make_node(base, capital_node, dynamic, transfers))
    dynamic_unknown = sum(node["dynamic_sources"]["status"] == "unknown" for node in nodes)
    transfer_unknown = sum(node["transfer_sources"][direction]["status"] == "unknown" for node in nodes for direction in ("to", "from"))
    return {"status": "observed", "profile_sha256": EXPECTED_PROFILE_SHA256, "static_contract_guard": static_guard, "runtime_code_guard": guard, "module_base": _hex(module_base), "country_pointer": trade_income_record.get("country_pointer"), "country": EXPECTED_COUNTRY, "country_fullref_raw_hex": trade_income_record.get("country_fullref_raw_hex"), "country_slot": trade_income_record.get("country_slot"), "source_trade_record_canonical_sha256": source_digest, "share_offset": _hex(layout["share_offset"]), "source_offsets": {key: _hex(layout["source_offsets"][key]) for key in SOURCE_KEYS}, "capital_context": capital, "transfer_lookup": transfer_lookup, "nodes": nodes, "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "complete": COMPLETE, "unimplemented_source_kinds": list(UNIMPLEMENTED_SOURCE_KINDS), "limits": limits, "read_budget": {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls, "max_bytes": ctx.limit}, "observation": {"status": "observed", "module_base": _hex(module_base), "country_pointer": trade_income_record.get("country_pointer"), "country": EXPECTED_COUNTRY, "country_slot": trade_income_record.get("country_slot"), "node_count": len(nodes), "graph_reused": True, "entry_reads": 0, "capital_status": capital.get("status"), "dynamic_unknown_count": dynamic_unknown, "transfer_lookup_status": transfer_lookup.get("status"), "transfer_unknown_count": transfer_unknown}}


def _validate_static_guard(record: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    static = record.get("static_contract_guard")
    expected = _static_contract_guard(profile)
    return isinstance(static, Mapping) and static.get("status") == "observed" and static.get("profile_id") == expected.get("profile_id") == PROFILE_ID and static.get("profile_sha256") == EXPECTED_PROFILE_SHA256 and static.get("checks") == expected.get("checks") and static.get("source_index") == expected.get("source_index") and static.get("unknown_conditions") == []


def _validate_pointer_field(value: Any) -> int | None:
    pointer = _trade._pointer_from_hex(value)
    return pointer if pointer is not None and _trade._valid_address(pointer) else None


def _validate_capital_context(context: Any, record: Mapping[str, Any], source_record: Mapping[str, Any], source_nodes: list[Mapping[str, Any]], layout: Mapping[str, Any]) -> bool:
    if not isinstance(context, Mapping) or context.get("status") not in ("observed", "unknown"):
        return False
    module = _validate_pointer_field(record.get("module_base"))
    country = _validate_pointer_field(source_record.get("country_pointer"))
    if module is None or country is None:
        return False
    if context.get("country_pointer") != source_record.get("country_pointer") or context.get("country_fullref_raw_hex") != source_record.get("country_fullref_raw_hex") or context.get("country_slot") != source_record.get("country_slot"):
        return False
    if context.get("status") == "unknown":
        # A bounded reader may fail before the first database dereference.  In
        # that case there is no partially trusted address chain to validate;
        # retain the bound country identity and the explicit reason only.
        chain_fields = (
            "database_global_address", "database_global_raw_hex", "database_root_pointer",
            "database_root_raw_hex", "country_table_address", "country_table_pointer",
            "country_table_raw_hex", "selected_country_address", "selected_country_pointer",
            "selected_country_raw_hex", "selected_country_fullref_address",
            "selected_country_fullref_raw_hex", "country_14c8_address", "country_14c8_raw_hex",
            "anchor_pointer", "anchor_raw_hex", "anchor_node_address", "anchor_node_pointer",
            "anchor_node_raw_hex", "global_scalar_address", "global_raw", "global_raw_hex",
            "included_node_id",
        )
        if all(context.get(key) is None for key in chain_fields):
            return isinstance(context.get("reason"), str) and bool(context.get("reason"))
    expected_db = _trade._address_add(module, layout["capital_database_global_rva"], "validate.capital.database_global")
    if context.get("database_global_address") != _hex(expected_db) or not _valid_hex(context.get("database_global_raw_hex"), QWORD_WIDTH):
        return False
    root = _validate_pointer_field(context.get("database_root_pointer"))
    if root is None or context.get("database_root_raw_hex") != _pointer_raw_hex(root):
        return False
    table_address = _trade._address_add(root, layout["capital_country_table_offset"], "validate.capital.country_table")
    table = _validate_pointer_field(context.get("country_table_pointer"))
    if context.get("country_table_address") != _hex(table_address) or table is None or context.get("country_table_raw_hex") != _pointer_raw_hex(table):
        return False
    slot = source_record.get("country_slot")
    if not isinstance(slot, int) or slot < 0 or slot > 32767:
        return False
    selected_address = _trade._address_add(table, slot * layout["capital_vector_stride"], "validate.capital.selected_country")
    selected = _validate_pointer_field(context.get("selected_country_pointer"))
    if context.get("selected_country_address") != _hex(selected_address) or selected is None or context.get("selected_country_raw_hex") != _pointer_raw_hex(selected):
        return False
    fullref = source_record.get("country_fullref_raw_hex")
    if selected != country or context.get("selected_country_fullref_raw_hex") != fullref or not _valid_hex(fullref, QWORD_WIDTH):
        return False
    selected_fullref_address = _trade._address_add(selected, layout["country_fullref_offset"], "validate.capital.selected_fullref")
    if context.get("selected_country_fullref_address") != _hex(selected_fullref_address):
        return False
    if context.get("status") == "unknown":
        return isinstance(context.get("reason"), str) and bool(context.get("reason"))
    country_14c8 = _validate_pointer_field(context.get("anchor_pointer"))
    if country_14c8 is None or context.get("country_14c8_raw_hex") != _pointer_raw_hex(country_14c8):
        return False
    country_14c8_address = _trade._address_add(selected, layout["capital_country_14c8_offset"], "validate.capital.country_14c8")
    if context.get("country_14c8_address") != _hex(country_14c8_address) or context.get("anchor_raw_hex") != _pointer_raw_hex(country_14c8):
        return False
    anchor_node = _validate_pointer_field(context.get("anchor_node_pointer"))
    if anchor_node is None or context.get("anchor_node_raw_hex") != _pointer_raw_hex(anchor_node):
        return False
    anchor_node_address = _trade._address_add(country_14c8, layout["capital_anchor_node_offset"], "validate.capital.anchor_node")
    if context.get("anchor_node_address") != _hex(anchor_node_address):
        return False
    matching = [node.get("node_id") for node in source_nodes if node.get("runtime_pointer") == _hex(anchor_node)]
    if context.get("included_node_id") not in (None, *matching):
        return False
    if context.get("included_node_id") is None:
        return context.get("global_raw") is None and context.get("global_raw_hex") is None and context.get("global_scalar_address") is None
    if context.get("included_node_id") not in matching:
        return False
    scalar_address = _trade._address_add(module, layout["capital_scalar_rva"], "validate.capital.scalar")
    raw = context.get("global_raw")
    return context.get("global_scalar_address") == _hex(scalar_address) and isinstance(raw, int) and not isinstance(raw, bool) and -(1 << 31) <= raw < (1 << 31) and context.get("global_raw_hex") == _i32_hex(raw)


def _consume_validated_chain_element(counts: dict[str, int], limits: Mapping[str, int]) -> bool:
    node_limit, total_limit = _shared_chain_limits(limits)
    if counts.get("node", 0) >= node_limit or counts.get("global", 0) >= total_limit:
        return False
    counts["node"] = counts.get("node", 0) + 1
    counts["global"] = counts.get("global", 0) + 1
    return True


def _validate_dynamic(
    dynamic: Any,
    source_node: Mapping[str, Any],
    layout: Mapping[str, Any],
    limits: Mapping[str, int],
    shared_counts: dict[str, int] | None = None,
) -> bool:
    if not isinstance(dynamic, Mapping) or dynamic.get("status") not in ("observed", "unknown"):
        return False
    entry_hex = source_node.get("entry_raw_hex")
    if not _valid_hex(entry_hex, ENTRY_WIDTH):
        return False
    entry = bytes.fromhex(entry_hex)
    head_raw = entry[layout["dynamic_head_offset"]:layout["dynamic_head_offset"] + QWORD_WIDTH]
    if dynamic.get("head_raw_hex") != head_raw.hex() or not isinstance(dynamic.get("items"), list):
        return False
    items = dynamic["items"]
    if dynamic.get("status") == "unknown":
        return not items and isinstance(dynamic.get("reason"), str) and bool(dynamic.get("reason"))
    head = int.from_bytes(head_raw, "little")
    if head != 0 and not items:
        return False
    node_limit, _total_limit = _shared_chain_limits(limits)
    if len(items) > node_limit:
        return False
    previous_next = head
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping) or item.get("index") != index:
            return False
        if shared_counts is None:
            shared_counts = {"node": 0, "global": 0}
        if not _consume_validated_chain_element(shared_counts, limits):
            return False
        link = _validate_pointer_field(item.get("link_pointer"))
        node_item = _validate_pointer_field(item.get("item_pointer"))
        if link is None or node_item is None or item.get("link_pointer") in seen or link != previous_next:
            return False
        seen.add(item["link_pointer"])
        value = item.get("value_raw")
        if not isinstance(value, int) or isinstance(value, bool) or not -(1 << 31) <= value < (1 << 31) or item.get("value_raw_hex") != _i32_hex(value):
            return False
        if not _valid_hex(item.get("item_pointer_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(item["item_pointer_raw_hex"]), "little") != node_item:
            return False
        next_raw = item.get("next_pointer_raw_hex")
        next_pointer = _validate_pointer_field(item.get("next_pointer")) if item.get("next_pointer") is not None else 0
        if not _valid_hex(next_raw, QWORD_WIDTH) or int.from_bytes(bytes.fromhex(next_raw), "little") != (next_pointer or 0):
            return False
        capacity_raw = item.get("name_capacity_raw_hex")
        if not _valid_hex(capacity_raw, QWORD_WIDTH):
            return False
        capacity = int.from_bytes(bytes.fromhex(capacity_raw), "little")
        if item.get("name_capacity") != capacity:
            return False
        name_raw = item.get("name_raw_hex")
        if not isinstance(name_raw, str) or len(name_raw) < 2 or len(name_raw) % 2:
            return False
        try:
            name_bytes = bytes.fromhex(name_raw)
        except ValueError:
            return False
        if name_bytes[-1:] != b"\0" or b"\0" in name_bytes[:-1] or len(name_bytes) - 1 > limits["max_dynamic_name_bytes"]:
            return False
        if capacity < layout["dynamic_name_inline_capacity"]:
            if item.get("name_pointer_kind") != "inline_object":
                return False
        elif item.get("name_pointer_kind") != "heap" or _validate_pointer_field(item.get("name_pointer")) is None:
            return False
        previous_next = next_pointer
    return previous_next == 0


def _validate_transfer_lookup(lookup: Any, record: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    if not isinstance(lookup, Mapping) or lookup.get("status") not in ("not_needed", "observed", "unknown"):
        return False
    if lookup.get("status") == "not_needed":
        return lookup.get("reason") is None
    if lookup.get("status") == "unknown":
        return isinstance(lookup.get("reason"), str) and bool(lookup.get("reason"))
    module = _validate_pointer_field(record.get("module_base"))
    table = _validate_pointer_field(lookup.get("country_table_pointer"))
    root = _validate_pointer_field(lookup.get("database_root_pointer"))
    if module is None or table is None or root is None:
        return False
    db_address = _trade._address_add(module, layout["capital_database_global_rva"], "validate.transfer.database_global")
    if lookup.get("database_global_address") != _hex(db_address) or lookup.get("database_global_raw_hex") != _pointer_raw_hex(root):
        return False
    if lookup.get("database_root_raw_hex") != _pointer_raw_hex(root):
        return False
    table_address = _trade._address_add(root, layout["capital_country_table_offset"], "validate.transfer.country_table")
    if lookup.get("country_table_address") != _hex(table_address) or lookup.get("country_table_raw_hex") != _pointer_raw_hex(table):
        return False
    return lookup.get("country_fullref_offset") == _hex(layout["country_fullref_offset"]) and lookup.get("vector_stride") == layout["transfer_vector_stride"] and lookup.get("reason") is None


def _validate_transfer_container(
    container: Any,
    source_node: Mapping[str, Any],
    direction: str,
    layout: Mapping[str, Any],
    limits: Mapping[str, int],
    lookup: Mapping[str, Any],
    shared_counts: dict[str, int] | None = None,
) -> bool:
    if not isinstance(container, Mapping) or container.get("status") not in ("observed", "unknown"):
        return False
    native_key = "TRANSFER_TRADE_POWER_TO" if direction == "to" else "TRANSFER_TRADE_POWER_FROM"
    if container.get("direction") != direction or container.get("native_key") != native_key or container.get("unit") != "trade_power" or container.get("scale") != SCALE or not isinstance(container.get("items"), list):
        return False
    try:
        expected_head, expected_head_hex = _transfer_entry_head(source_node, layout["transfer_to_head_offset"] if direction == "to" else layout["transfer_from_head_offset"], direction)
    except Exception:
        return False
    if container.get("head_raw_hex") != expected_head_hex:
        return False
    items = container["items"]
    if container.get("status") == "unknown":
        return not items and isinstance(container.get("reason"), str) and bool(container.get("reason"))
    node_limit, _total_limit = _shared_chain_limits(limits)
    if container.get("reason") is not None or len(items) > node_limit:
        return False
    if expected_head == 0:
        return not items
    if not items or lookup.get("status") != "observed":
        return False
    current = expected_head
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping) or item.get("index") != index or item.get("direction") != direction or item.get("native_key") != native_key:
            return False
        if shared_counts is None:
            shared_counts = {"node": 0, "global": 0}
        if not _consume_validated_chain_element(shared_counts, limits):
            return False
        element = _validate_pointer_field(item.get("element_pointer"))
        if element is None or element != current or item.get("element_pointer") in seen:
            return False
        seen.add(item["element_pointer"])
        if not _valid_hex(item.get("element_pointer_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(item["element_pointer_raw_hex"]), "little") != element:
            return False
        fullref_hex = item.get("fullref_raw_hex")
        if not _valid_hex(fullref_hex, QWORD_WIDTH):
            return False
        fullref = bytes.fromhex(fullref_hex)
        expected_fullref_address = _trade._address_add(element, layout["transfer_element_fullref_offset"], "validate.transfer.element.fullref")
        if item.get("fullref_address") != _hex(expected_fullref_address):
            return False
        slot = int.from_bytes(fullref[4:6], "little", signed=True)
        if item.get("country_slot") != slot or slot < 0 or slot > limits["max_country_slot"]:
            return False
        raw = item.get("raw")
        expected_value_address = _trade._address_add(element, layout["transfer_element_value_offset"], "validate.transfer.element.value")
        if item.get("value_address") != _hex(expected_value_address):
            return False
        if not isinstance(raw, int) or isinstance(raw, bool) or not -(1 << 31) <= raw < (1 << 31) or item.get("raw_hex") != _i32_hex(raw) or item.get("unit") != "trade_power" or item.get("scale") != SCALE:
            return False
        next_hex = item.get("next_pointer_raw_hex")
        if not _valid_hex(next_hex, QWORD_WIDTH):
            return False
        next_value = int.from_bytes(bytes.fromhex(next_hex), "little")
        next_pointer = _validate_pointer_field(item.get("next_pointer")) if item.get("next_pointer") is not None else 0
        if next_value != (next_pointer or 0):
            return False
        expected_next_address = _trade._address_add(element, layout["transfer_element_next_offset"], "validate.transfer.element.next")
        if item.get("next_address") != _hex(expected_next_address):
            return False
        if item.get("country_table_pointer") != lookup.get("country_table_pointer") or not _valid_hex(item.get("country_pointer_raw_hex"), QWORD_WIDTH):
            return False
        country = _validate_pointer_field(item.get("country_pointer"))
        if country is None or int.from_bytes(bytes.fromhex(item["country_pointer_raw_hex"]), "little") != country:
            return False
        if not _valid_hex(item.get("country_fullref_raw_hex"), QWORD_WIDTH) or item.get("country_fullref_raw_hex") != fullref_hex:
            return False
        expected_country_fullref_address = _trade._address_add(country, layout["country_fullref_offset"], "validate.transfer.country_fullref")
        if item.get("country_fullref_address") != _hex(expected_country_fullref_address):
            return False
        expected_slot_address = _trade._address_add(_validate_pointer_field(lookup["country_table_pointer"]), slot * layout["transfer_vector_stride"], "validate.transfer.country_slot")
        if item.get("country_slot_address") != _hex(expected_slot_address):
            return False
        matched = item.get("country_fullref_matched")
        if matched is not True and matched is not False:
            return False
        tag = item.get("country_tag")
        if matched:
            if item.get("country_tag_status") not in ("matched_fullref", "matched_fullref_prefix_invalid"):
                return False
            if item.get("country_tag_status") == "matched_fullref":
                if not isinstance(tag, str) or len(tag) != 3 or not tag.isascii() or any(not ("0" <= char <= "9" or "A" <= char <= "Z") for char in tag) or tag != fullref[:3].decode("ascii", errors="ignore"):
                    return False
            elif tag is not None:
                return False
        elif tag is not None:
            return False
        if not matched and item.get("country_tag_status") != "fullref_mismatch":
            return False
        current = next_value
    return current == 0


def validate_record(record: Any, trade_income_record: Any) -> bool:
    """Validate parent binding, fixed rows, and independent detail containers."""
    if not isinstance(record, Mapping) or not isinstance(trade_income_record, Mapping) or not _trade.validate_record(trade_income_record):
        return False
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
        limits = _profile_limits(profile)
        _profile_semantics(profile)
    except Exception:
        return False
    if record.get("status") != "observed" or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or not _validate_static_guard(record, profile) or not _expected_runtime_guard(record, profile):
        return False
    module = _validate_pointer_field(record.get("module_base"))
    if module is None or module != _validate_pointer_field(trade_income_record.get("module_base")) or record.get("module_base") != trade_income_record.get("module_base"):
        return False
    for key in ("country_pointer", "country", "country_fullref_raw_hex", "country_slot"):
        if record.get(key) != trade_income_record.get(key):
            return False
    if record.get("country") != EXPECTED_COUNTRY or record.get("source_trade_record_canonical_sha256") != _canonical_digest(trade_income_record):
        return False
    if record.get("share_offset") != _hex(layout["share_offset"]) or record.get("source_offsets") != {key: _hex(layout["source_offsets"][key]) for key in SOURCE_KEYS} or record.get("basis") != BASIS or record.get("unit") != UNIT or record.get("scale") != SCALE or record.get("period") != PERIOD or record.get("value_origin") != VALUE_ORIGIN or record.get("complete") is not COMPLETE or record.get("unimplemented_source_kinds") != UNIMPLEMENTED_SOURCE_KINDS or record.get("limits") != limits:
        return False
    source_nodes, nodes = trade_income_record.get("nodes"), record.get("nodes")
    if not isinstance(source_nodes, list) or not source_nodes or not isinstance(nodes, list) or len(nodes) != len(source_nodes):
        return False
    if not _validate_capital_context(record.get("capital_context"), record, trade_income_record, source_nodes, layout):
        return False
    if not _validate_transfer_lookup(record.get("transfer_lookup"), record, layout):
        return False
    shared_counts = {"node": 0, "global": 0}
    for source_node, node in zip(source_nodes, nodes):
        if not isinstance(node, Mapping):
            return False
        try:
            base = _derive_base_node(source_node, layout)
        except Exception:
            return False
        expected_capital = _expected_capital_node(record["capital_context"], source_node)
        if node.get("node_id") != base["node_id"] or node.get("share_raw") != base["share_raw"] or node.get("share_raw_hex") != base["share_raw_hex"] or node.get("source_inputs") != base["source_inputs"] or node.get("capital") != expected_capital:
            return False
        shared_counts["node"] = 0
        if not _validate_dynamic(node.get("dynamic_sources"), source_node, layout, limits, shared_counts):
            return False
        transfers = node.get("transfer_sources")
        if not isinstance(transfers, Mapping) or not _validate_transfer_container(transfers.get("to"), source_node, "to", layout, limits, record["transfer_lookup"], shared_counts) or not _validate_transfer_container(transfers.get("from"), source_node, "from", layout, limits, record["transfer_lookup"], shared_counts):
            return False
        expected_rows = _make_node(base, expected_capital, node["dynamic_sources"], transfers)["source_rows"]
        if node.get("source_rows") != expected_rows:
            return False
    observation = record.get("observation")
    if not isinstance(observation, Mapping) or observation.get("status") != "observed" or observation.get("module_base") != _hex(module) or observation.get("country_pointer") != trade_income_record.get("country_pointer") or observation.get("country") != EXPECTED_COUNTRY or observation.get("country_slot") != trade_income_record.get("country_slot") or observation.get("node_count") != len(source_nodes) or observation.get("graph_reused") is not True or observation.get("entry_reads") != 0 or observation.get("capital_status") != record["capital_context"].get("status"):
        return False
    budget = record.get("read_budget")
    return isinstance(budget, Mapping) and isinstance(budget.get("bytes_requested"), int) and 0 <= budget["bytes_requested"] <= limits["max_child_read_bytes"] and budget.get("max_bytes") == limits["max_child_read_bytes"]


def retract_record(record: Mapping[str, Any] | None, reason: str) -> dict[str, Any]:
    """Retract all derived fixed, capital and dynamic values."""
    result = _deepcopy(record) if isinstance(record, Mapping) else _empty_record(reason)
    result["status"] = "unknown"
    result["reason"] = reason
    result["capital_context"] = _empty_capital_context(reason)
    result["transfer_lookup"] = {"status": "unknown", "reason": reason}
    result["nodes"] = None
    result["observation"] = {"status": "unknown", "reason": reason}
    return result


__all__ = [
    "BASIS", "COMPLETE", "EXPECTED_COUNTRY", "EXPECTED_EXE_SHA256", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_TRADE_PROFILE_SHA256", "EXPECTED_VERSION", "PERIOD", "PROFILE", "PROFILE_FILE",
    "SCALE", "UNIT", "VALUE_ORIGIN", "ProfileError", "ReadError", "read_fields", "validate_record",
    "retract_record",
]
