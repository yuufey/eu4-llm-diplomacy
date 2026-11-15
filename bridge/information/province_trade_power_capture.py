"""Own a read-only FRA observation of the current province trade-power cache.

The shared capture owner supplies process/session identity, a read-only handle,
code guards, two-pass replay, and cleanup. The province reader supplies the
existing admission and discovery checks; this module selects only the bounded
province trade-power leaf for the requested canonical province ID.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_technology_capture as _owner
from . import province_state_memory as _province
from . import province_trade_power_memory as _leaf


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "province-trade-power-memory-1374-v1-sampling-r1.json"
PROFILE_SHA256 = "1925cae16fadf1fc1aec8312277d0eef76090804b81ae75df1f243e0ca24ad85"
SCHEMA = "information.province_trade_power_capture.v1"
INNER_SCHEMA = "information.province_trade_power_observer_snapshot.v1"
_PROFILE_ID = "province-trade-power-memory-1374"
_PROFILE_VERSION = 1
_LAYOUT = {
    "scope_province_id_offset": "0x28",
    "province_manager_global_rva": "0x233feb8",
    "native_array_begin_offset": "0x6f0",
    "native_array_end_offset": "0x6f8",
    "record_stride": "0x2e10",
    "canonical_parent_global_rva": "0x233fe58",
    "canonical_parent_records_offset": "0x1ca8",
    "record_id_offset": "0x20",
    "lookup_pdata_range": ["0x9aa80", "0x9ac92"],
    "lookup_decoded_body_range": ["0x9aa80", "0x9ac91"],
    "cache_offset": "0x890",
    "cache_width": 4,
    "cache_signed": True,
    "trigger_threshold_offset": "0x68",
}


def _valid_id(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 0xFFFF


def _load_profile() -> dict[str, Any]:
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError("PROVINCE_TRADE_POWER_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("PROVINCE_TRADE_POWER_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != _PROFILE_ID
            or profile.get("profile_version") != _PROFILE_VERSION
            or profile.get("game_version") != "1.37.4"
            or profile.get("observer") != "FRA"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256
            or profile.get("layout", {}).get("province_trade_power") != _LAYOUT
            or profile.get("semantics", {}).get("supported_fields")
                != [_leaf.FIELD_PROVINCE_TRADE_POWER]
            or profile.get("semantics", {}).get("scale") != 1000
            or profile.get("semantics", {}).get("unit") != "trade_power"):
        raise ValueError("PROVINCE_TRADE_POWER_PROFILE_BUILD")
    evidence = profile.get("source_evidence")
    dependencies = profile.get("layout_dependencies")
    if (not isinstance(evidence, list) or not evidence
            or not isinstance(dependencies, list) or not dependencies):
        raise ValueError("PROVINCE_TRADE_POWER_PROFILE_DEPENDENCY")
    for item in [*evidence, *dependencies]:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or type(item.get("bytes")) is not int or item["bytes"] < 0
                or not isinstance(item.get("sha256"), str)
                or len(item["sha256"]) != 64):
            raise ValueError("PROVINCE_TRADE_POWER_PROFILE_DEPENDENCY")
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item["bytes"] or _owner._sha(path) != item["sha256"]:
            raise ValueError("PROVINCE_TRADE_POWER_PROFILE_DEPENDENCY")
    return profile


def _observe_for(province_id: int):
    def observe(reader, module_base, country, profile):
        if country != "FRA" or not _valid_id(province_id):
            raise ValueError("PROVINCE_TRADE_POWER_OBSERVER_SCOPE")

        def backend(read, base, observer_country):
            if observer_country != "FRA":
                raise ValueError("PROVINCE_TRADE_POWER_OBSERVER_SCOPE")
            return _province.read_two_pass(
                read,
                base,
                province_id,
                observer="FRA",
                fields=(_leaf.FIELD_PROVINCE_TRADE_POWER,),
                read_fields=_leaf.read_fields,
            )

        return _owner._observe(
            reader,
            module_base,
            country,
            profile,
            backend_reader=backend,
        )

    return observe


def capture(installation: Path, province_id: int, *, observer: str = "FRA") -> dict[str, Any]:
    if not _valid_id(province_id) or observer != "FRA":
        raise ValueError("PROVINCE_TRADE_POWER_REQUEST_SCOPE")
    inner = _owner._capture_common(
        installation,
        "FRA",
        observer=observer,
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id),
        allow_observer_target=True,
    )
    return {
        "schema": SCHEMA,
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "capture": inner,
    }


def validate_capture(report: Any, context: dict[str, Any], creation: int,
                     province_id: int) -> bool:
    if not _valid_id(province_id) or not isinstance(report, dict):
        return False
    if set(report) != {"schema", "observer", "object", "capture"}:
        return False
    if report["schema"] != SCHEMA or report["observer"] != "FRA":
        return False
    expected = {"type": "province", "province_id": province_id}
    if not _owner._same(report["object"], expected):
        return False
    return _owner._validate_capture_common(
        report["capture"],
        context,
        creation,
        "FRA",
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id),
        allow_observer_target=True,
        require_access=True,
    )


__all__ = ["capture", "validate_capture"]
