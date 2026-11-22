"""Identity-bound capture of the raw B23 direct-truce date inputs.

The capture deliberately stops at the two directed relation rows and the two
configuration integers.  Calendar arithmetic belongs to ``truce_date_math``
and is not performed while reading the process.
"""
from __future__ import annotations

from copy import deepcopy
from functools import partial
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import country_scale_capture as _base_capture
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "truce-date-memory-1374-v1.json"
PROFILE_SHA256 = "68596ee323049e992627a8a041a0e2c2a8212df2516c7667a86eaeb443febfd8"
PROFILE_ID = "truce-date-memory-1374"
PROFILE_VERSION = 1
BASE_PROFILE_FILE = Path(__file__).with_name("profiles") / "country-scale-memory-1374-v4.json"
BASE_PROFILE_SHA256 = "cb9b3b1591066d4b965f46798842a3ebfe28dc695cb1e74c98549c2f1618c356"
PROFILE_MAX_BYTES = 128 * 1024
EXE_SHA256 = _owner.EXE_SHA256
OBSERVER = "FRA"
FIELD = "R03.truce_until.inputs"
FIELDS = (FIELD,)
SCHEMA = "information.truce_date_capture.v1"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _pinned_path(item: Mapping[str, Any], reason: str) -> Path:
    path_value = item.get("path")
    size = item.get("bytes")
    expected = item.get("sha256")
    if (not isinstance(path_value, str) or type(size) is not int or size < 0
            or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
        raise ValueError(reason)
    path = (ROOT / path_value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(reason) from exc
    if not path.is_file() or path.stat().st_size != size or _sha(path) != expected:
        raise ValueError(reason)
    return path


def _load_profile() -> dict[str, Any]:
    if not 0 < PROFILE_FILE.stat().st_size <= PROFILE_MAX_BYTES:
        raise ValueError("TRUCE_DATE_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("TRUCE_DATE_PROFILE_PIN")
    manifest = json.loads(raw)
    if (manifest.get("profile_id") != PROFILE_ID
            or manifest.get("profile_version") != PROFILE_VERSION
            or manifest.get("game_version") != "1.37.4"
            or manifest.get("schema") != SCHEMA
            or manifest.get("field") != FIELD
            or manifest.get("executable", {}).get("sha256") != EXE_SHA256):
        raise ValueError("TRUCE_DATE_PROFILE_CONTRACT")

    base_meta = manifest.get("base_profile")
    if not isinstance(base_meta, Mapping):
        raise ValueError("TRUCE_DATE_BASE_PROFILE_MISSING")
    if (base_meta.get("path") != "bridge/information/profiles/country-scale-memory-1374-v4.json"
            or base_meta.get("sha256") != BASE_PROFILE_SHA256):
        raise ValueError("TRUCE_DATE_BASE_PROFILE_CONTRACT")
    _pinned_path(base_meta, "TRUCE_DATE_BASE_PROFILE_PIN")
    if _sha(BASE_PROFILE_FILE) != BASE_PROFILE_SHA256:
        raise ValueError("TRUCE_DATE_BASE_PROFILE_PIN")
    base = _base_capture._load_profile()

    source_pins = manifest.get("source_pins")
    if not isinstance(source_pins, list) or not source_pins:
        raise ValueError("TRUCE_DATE_SOURCE_PINS_MISSING")
    pinned: dict[str, Path] = {}
    pin_rows: list[dict[str, Any]] = []
    for item in source_pins:
        if not isinstance(item, Mapping):
            raise ValueError("TRUCE_DATE_SOURCE_PIN_INVALID")
        path_value = item.get("path")
        if not isinstance(path_value, str) or path_value in pinned:
            raise ValueError("TRUCE_DATE_SOURCE_PIN_INVALID")
        path = _pinned_path(item, "TRUCE_DATE_SOURCE_PIN_MISMATCH")
        pinned[path_value] = path
        pin_rows.append(deepcopy(dict(item)))

    guards = manifest.get("code_guards")
    if not isinstance(guards, list) or not guards:
        raise ValueError("TRUCE_DATE_GUARDS_MISSING")
    extra_guards: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in guards:
        if not isinstance(item, Mapping):
            raise ValueError("TRUCE_DATE_GUARD_INVALID")
        name = item.get("name")
        source_path = item.get("source_path")
        source_offset = item.get("source_offset", 0)
        source_length = item.get("source_length")
        try:
            rva = int(item["rva"], 0)
            end = int(item["end_rva_exclusive"], 0)
            body = bytes.fromhex(item["bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("TRUCE_DATE_GUARD_INVALID") from exc
        if (not isinstance(name, str) or not name or name in names
                or not isinstance(source_path, str) or source_path not in pinned
                or type(source_offset) is not int or source_offset < 0
                or type(source_length) is not int or source_length != len(body)
                or not 0 < len(body) <= 65536 or end != rva + len(body)
                or item.get("sha256") != hashlib.sha256(body).hexdigest()):
            raise ValueError("TRUCE_DATE_GUARD_INVALID")
        source = pinned[source_path].read_bytes()
        if (source_offset + source_length > len(source)
                or source[source_offset:source_offset + source_length] != body):
            raise ValueError("TRUCE_DATE_GUARD_SOURCE_MISMATCH")
        names.add(name)
        extra_guards.append(deepcopy(dict(item)))

    profile = deepcopy(base)
    profile.update({
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "schema": SCHEMA,
        "field": FIELD,
        "base_profile": deepcopy(dict(base_meta)),
        "source_pins": pin_rows,
        "truce_date": deepcopy(dict(manifest.get("truce_date", {}))),
        "semantics": deepcopy(dict(manifest.get("semantics", {}))),
        "code_guards": [*base.get("code_guards", []), *extra_guards],
    })
    return profile


def _fullref(binding: Mapping[str, Any]) -> int:
    value = binding.get("fullref")
    if isinstance(value, str):
        return int(value, 0)
    if type(value) is int:
        return value
    raise ValueError("TRUCE_DATE_FULLREF")


def _address(value: Any, reason: str) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise ValueError(reason) from exc
    if type(value) is not int:
        raise ValueError(reason)
    return _owner._pointer(value)


def read_inputs(read: Any, base: int, bindings: Mapping[str, Any], target: str,
                *, observer: str = OBSERVER) -> dict[str, Any]:
    """Read both observed country-pair rows without projecting a date."""
    if (not isinstance(target, str) or _TAG.fullmatch(target) is None
            or not isinstance(observer, str) or _TAG.fullmatch(observer) is None
            or target == observer or not isinstance(bindings, Mapping)):
        raise ValueError("TRUCE_DATE_PAIR_SCOPE")

    def raw(address: int, size: int, label: str) -> bytes:
        _owner._pointer(address)
        _owner._pointer(address + size - 1)
        value = read(address, size, label)
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError("TRUCE_DATE_SHORT_READ")
        return value

    configurations = []
    for rva in (0x233DC88, 0x233DD8C):
        value = raw(base + rva, 4, f"truce_date.global.{rva:x}")
        configurations.append({
            "rva": hex(rva),
            "raw_hex": value.hex(),
            "signed_i32": int.from_bytes(value, "little", signed=True),
        })

    records = []
    for actor, recipient in ((observer, target), (target, observer)):
        actor_binding = bindings.get(actor)
        recipient_binding = bindings.get(recipient)
        if not isinstance(actor_binding, Mapping) or not isinstance(recipient_binding, Mapping):
            raise ValueError("TRUCE_DATE_BINDING_MISSING")
        actor_pointer = _address(actor_binding.get("country_pointer"), "TRUCE_DATE_COUNTRY_POINTER")
        slot = recipient_binding.get("slot")
        if type(slot) is not int or not 0 <= slot < 4096:
            raise ValueError("TRUCE_DATE_SLOT")
        fullref = _fullref(recipient_binding)
        if ((fullref >> 32) & 0xFFFF) != slot:
            raise ValueError("TRUCE_DATE_SLOT_REF")
        table_raw = raw(actor_pointer + 0x1510, 8, f"truce_date.{actor}.table")
        table = _owner._pointer(int.from_bytes(table_raw, "little"))
        address = table + slot * 0x48
        row = raw(address, 0x48, f"truce_date.{actor}.{recipient}.row")
        _owner._pointer(int.from_bytes(row[:8], "little"))
        if int.from_bytes(row[0x10:0x18], "little") != fullref:
            raise ValueError("TRUCE_DATE_RECIPIENT_REF")
        records.append({
            "actor": actor,
            "target": recipient,
            "row_address": hex(address),
            "row_raw_hex": row.hex(),
            "recipient_fullref": hex(fullref),
            "table_pointer_raw_hex": table_raw.hex(),
            "direct_flag": bool(row[0x45] & 1),
            "adjustment_signed_i8": int.from_bytes(row[0x24:0x25], "little", signed=True),
            "date_input_signed_i32": int.from_bytes(row[0x34:0x38], "little", signed=True),
            "date_input_raw_hex": row[0x34:0x38].hex(),
            "computed_expiry": None,
        })
    return {
        "status": "known",
        "value": {"configuration_inputs": configurations, "directed_records": records},
        "basis": "private_raw_inputs_only_no_public_date",
        "complete": False,
    }


def _admission(read: Any, base: int, bindings: Mapping[str, Any],
               observer: str, target: str) -> dict[str, Any]:
    gate = _owner._bound_admission(read, base, bindings, observer, target)
    if not isinstance(gate, Mapping):
        return {"status": "unknown", "admitted": None,
                "reason": "TRUCE_DATE_ADMISSION_INVALID"}
    result = deepcopy(dict(gate))
    role = result.get("observer_nonplayer_role")
    if not isinstance(role, Mapping) or role.get("verified") is not True:
        result.update(status="unknown", admitted=None,
                      reason="OBSERVER_NONPLAYER_ROLE_UNVERIFIED")
    return result


def _observe(reader: Any, base: int, country: str, profile: Mapping[str, Any],
             *, observer: str = OBSERVER) -> dict[str, Any]:
    if (not isinstance(country, str) or _TAG.fullmatch(country) is None
            or country == observer):
        raise ValueError("TRUCE_DATE_PAIR_SCOPE")
    state: dict[str, Any] = {}

    def backend(read: Any, module_base: int, target: str) -> dict[str, Any]:
        def admission(limited_read: Any, current_base: int,
                      scan: Mapping[str, Any], observer: str,
                      requested: str) -> dict[str, Any]:
            gate = _admission(limited_read, current_base, scan, observer, requested)
            requested_bindings = scan.get("requested") if isinstance(scan, Mapping) else None
            state["bindings"] = deepcopy(dict(requested_bindings)) if isinstance(requested_bindings, Mapping) else None
            return gate

        def fields(limiter: Any, current_base: int,
                   target_binding: Mapping[str, Any], requested_fields: tuple[str, ...]) -> dict[str, Any]:
            if tuple(requested_fields) != FIELDS:
                raise ValueError("TRUCE_DATE_FIELD_SCOPE")
            bindings = state.get("bindings")
            if (not isinstance(bindings, Mapping)
                    or target_binding != bindings.get(target)):
                raise ValueError("TRUCE_DATE_TARGET_BINDING")
            return {FIELD: read_inputs(limiter.read, current_base, bindings, target, observer=observer)}

        return _backend.read_two_pass(
            read, module_base, observer, [target], FIELDS,
            read_fields=fields, admission_reader=admission,
        )

    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation: Path, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
    )


def validate_capture(report: Any, context: Mapping[str, Any],
                     creation: int, country: str) -> bool:
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True,
    )


__all__ = [
    "SCHEMA", "FIELD", "FIELDS", "PROFILE_ID", "PROFILE_FILE", "PROFILE_SHA256",
    "BASE_PROFILE_FILE", "BASE_PROFILE_SHA256", "read_inputs", "capture", "validate_capture",
]
