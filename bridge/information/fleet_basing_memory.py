"""Read-only current fleet-basing state from the audited native caches.

This child deliberately mirrors the bounded country/relation reader contract
without calling any game function.  The two native leaves are replayed from
copied owner vectors: ``received`` additionally follows the first matching
element's agreement pointer and compares ``agreement + 0x18``; ``granted``
uses only the first DWORD comparison.  Direction/expiry semantics are kept in
the profile and all public values remain partial because no live positive
sample has been accepted yet.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from . import relation_memory as _rel


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "fleet-basing-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_ID = "fleet-basing-memory-1374"
EXPECTED_PROFILE_SHA256 = "b8af6c56cb6831eb02ec9507fdcd296a22a44bb360d4f2144535dc6be09f1296"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
FIELDS = ("fleet_basing",)
FAMILIES = ("received", "granted")
BASIS = "native_current_fleet_basing_predicate"
VALUE_ORIGIN = "derived_from_copied_native_relation_row_and_owner_vectors"
UNIT = "relation_state"
SCALE = 1
PERIOD = "current"
GAPS = ["NO_ACTIVE_RUNTIME_SAMPLE", "FLEET_BASING_EXPIRY_UNREAD"]
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"

MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
NETWORK_MAX_TOTAL_RPM = 2 * 1024 * 1024
MAX_VECTOR_COUNT = 4096
MAX_COUNTRY_ENTRIES = 4096
PROCESS_ACCESS = _mm.PROCESS_ACCESS
AddressBoundedRPM = _crm.AddressBoundedRPM
NetworkAddressBoundedRPM = _rel.NetworkAddressBoundedRPM

_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_valid_pointer = _rel._valid_pointer
_safe_add = _rel._safe_add
_addr = _rel._addr
_field = _rel._field
_slot_from_fullref = _rel._slot_from_fullref
_signed_i16 = _rel._signed_i16
_tag_and_slot = _rel._tag_and_slot

SOURCE_MAX_BYTES = 8 * 1024 * 1024
SOURCE_PINS = {
    "fleet_source002_sha256": "90dc23321e41458e13875d5a74ba85f0845214897da77ce546aed96ab1a7ce04",
    "relation_contract005_sha256": "12d58a680bf26ad4c4abcdb3195349fcc7b81b54d694eed0d384539c3199cc79",
}
ACCEPTED_REA = {
    "received_leaf": {
        "rva": "0x52fc20",
        "evidence_id": "ev_3418777a0d84a54104eb52ca9b805d7464cd51a5d719199b3f1cb1b6b4c6423c",
        "path": "work/runtime/information-relation-remaining-20261027-001/rea-fleet-access-validity-001/evidence.json",
    },
    "granted_leaf": {
        "rva": "0x533fd0",
        "evidence_id": "ev_ae3b0ebc5d0ad925ef7550866b0fb7c81d645d184fb3485a399709d14eb662dc",
        "path": "work/runtime/information-relation-remaining-20261027-001/rea-offer-fleet-access-validity-001/evidence.json",
    },
    "validity_leaf": {
        "rva": "0xa69370",
        "evidence_id": "ev_0a6e0435ea758ec98fbb069e4e3576d4f2cb0fdc52c2c06e141a093965a250bf",
        "path": "work/runtime/information-relation-remaining-20261027-001/rea-fleet-current-predicate-001/evidence.json",
    },
}


class ProfileError(RuntimeError):
    """The pinned profile or bounded source contract is invalid."""


class ProbeError(RuntimeError):
    """A bounded read, identity, or derived predicate failed."""


def _sha256_file(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if limit is not None and size > limit:
                raise ProfileError(f"file_over_bound:{path}")
            digest.update(block)
    return digest.hexdigest()


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return result


def _workspace_path(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ProfileError("source_path_invalid")
    path = Path(raw)
    root = Path(__file__).resolve().parents[2]
    resolved = (path if path.is_absolute() else root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_path_outside_workspace")
    return resolved


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        with path.open("rb") as stream:
            raw = stream.read(PROFILE_MAX_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > PROFILE_MAX_BYTES:
        raise ProfileError("profile_read_size_changed")
    if not isinstance(expected, str) or len(expected) != 64 or expected.startswith("__"):
        raise ProfileError("profile_sha256_pin_invalid")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != EXPECTED_PROFILE_ID:
        raise ProfileError("profile_shape_invalid")
    return profile


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = _load_profile() if profile is None else profile
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or not guards:
        raise ProfileError("profile_code_guards_missing")
    result: list[tuple[str, int, bytes]] = []
    names: set[str] = set()
    for item in guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        raw_hex = item.get("bytes", item.get("hex"))
        if not isinstance(name, str) or not name or name in names or not isinstance(raw_hex, str):
            raise ProfileError("profile_code_guard_shape_invalid")
        try:
            expected = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError("profile_code_guard_hex_invalid") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        if item.get("end_rva_exclusive") not in (None, hex(rva + len(expected)), rva + len(expected)):
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if hashlib.sha256(expected).hexdigest() != str(item.get("sha256", "")).lower():
            raise ProfileError(f"profile_code_guard_sha_invalid:{name}")
        names.add(name)
        result.append((name, rva, expected))
    return result


def _profile_layout(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    profile = _load_profile() if profile is None else profile
    try:
        executable, globals_, country, relation = (profile["executable"], profile["globals"], profile["country"], profile["relation"])
        families, limits = profile["families"], profile["limits"]
        if profile.get("profile_id") != EXPECTED_PROFILE_ID or profile.get("game_version") != EXPECTED_VERSION:
            raise ProfileError("profile_identity_invalid")
        if str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
            raise ProfileError("profile_executable_sha_invalid")
        if country.get("supported_actor") != EXPECTED_COUNTRY:
            raise ProfileError("profile_supported_actor_invalid")
        if set(families) != set(FAMILIES):
            raise ProfileError("profile_family_set_invalid")
        result: dict[str, Any] = {
            "database_rva": _parse_int(globals_["database_rva"], "database_rva"),
            "game_rva": _parse_int(globals_["game_rva"], "game_rva"),
            "game_date_offset": _parse_int(globals_["game_date_offset"], "game_date_offset"),
            "country_table_offset": _parse_int(country["table_offset"], "country_table_offset"),
            "country_count_offset": _parse_int(country["count_offset"], "country_count_offset"),
            "country_fullref_offset": _parse_int(country["fullref_offset"], "country_fullref_offset"),
            "max_country_entries": _parse_int(country["max_entries"], "max_country_entries"),
            "relation_table_offset": _parse_int(relation["table_offset"], "relation_table_offset"),
            "relation_row_stride": _parse_int(relation["row_stride"], "relation_row_stride"),
            "relation_row_owner_offset": _parse_int(relation["row_owner_offset"], "relation_row_owner_offset"),
            "relation_row_recipient_offset": _parse_int(relation["row_recipient_fullref_offset"], "relation_row_recipient_offset"),
            "element_stride": _parse_int(relation["element_stride"], "element_stride"),
            "max_vector_count": _parse_int(limits["max_vector_count"], "max_vector_count"),
            "families": {},
        }
        for family in FAMILIES:
            spec = families[family]
            if not isinstance(spec, Mapping):
                raise ProfileError(f"profile_family_invalid:{family}")
            values = {key: _parse_int(spec[key], f"{family}.{key}") for key in ("vector_begin_offset", "vector_count_offset", "predicate_rva")}
            if family == "received":
                values.update(agreement_pointer_offset=_parse_int(spec["agreement_pointer_offset"], f"{family}.agreement_pointer_offset"), agreement_ref_offset=_parse_int(spec["agreement_ref_offset"], f"{family}.agreement_ref_offset"))
            result["families"][family] = values
        if result["max_country_entries"] != MAX_COUNTRY_ENTRIES or result["max_vector_count"] != MAX_VECTOR_COUNT or result["element_stride"] != 0x10:
            raise ProfileError("profile_bounds_invalid")
        return result
    except KeyError as exc:
        raise ProfileError(f"profile_layout_missing:{exc}") from exc


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _profile_source_checks(profile: Mapping[str, Any]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for item in profile.get("source_evidence", []):
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        path = _workspace_path(item.get("path"))
        expected = item.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise ProfileError("source_evidence_sha_invalid")
        actual = _sha256_file(path, SOURCE_MAX_BYTES)
        checks[str(item["path"])] = actual.lower() == expected.lower()
        if not checks[str(item["path"])]:
            raise ProfileError(f"source_evidence_sha_mismatch:{item['path']}")
    return checks


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "profile_sha256": EXPECTED_PROFILE_SHA256, "source_checks": {}, "accepted_rea": deepcopy(ACCEPTED_REA), "unknown_conditions": []}
    try:
        profile = _load_profile()
        _profile_layout(profile)
        result["source_checks"] = _profile_source_checks(profile)
        result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


class _ReadBudget:
    """Precharge each read before dispatching to the process/fake reader."""

    def __init__(self, limit: int = MAX_TOTAL_RPM):
        self.limit = int(limit)
        self.reserved = 0
        self.calls = 0
        self.log: list[dict[str, Any]] = []

    def read(self, reader: Any, address: int, size: int, label: str) -> bytes:
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_size:{label}")
        if not isinstance(address, int) or address < 0x10000 or address + size > MAX_USER_ADDRESS:
            raise ProbeError(f"invalid_address:{label}")
        if self.reserved + size > self.limit:
            self.log.append({"label": label, "address": hex(address), "size": size, "status": "budget_rejected"})
            raise ProbeError(f"RPM_TOTAL_BUDGET_EXCEEDED:{label}")
        self.reserved += size
        self.calls += 1
        try:
            raw = reader.read(address, size, label)
        except Exception as exc:
            self.log.append({"label": label, "address": hex(address), "size": size, "status": "error", "error": f"{type(exc).__name__}:{exc}"})
            raise
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            self.log.append({"label": label, "address": hex(address), "size": size, "status": "error", "error": "short_read"})
            raise ProbeError(f"short_read:{label}")
        value = bytes(raw)
        self.log.append({"label": label, "address": hex(address), "size": size, "status": "observed", "raw_hex": value.hex()})
        return value

    def qword(self, reader: Any, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(reader, address, 8, label)
        return int.from_bytes(raw, "little"), raw

    def i32(self, reader: Any, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(reader, address, 4, label)
        return int.from_bytes(raw, "little", signed=True), raw

    def snapshot(self) -> dict[str, Any]:
        return {"bytes_reserved": self.reserved, "calls_reserved": self.calls, "limit": self.limit}


def _runtime_code_guard(reader: Any, budget: _ReadBudget, module_base: int, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _addr(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            address = _safe_add(module_base, rva, f"code_guard.{name}")
            actual = budget.read(reader, address, len(expected), f"code_guard.{name}")
            result["records"][name] = {"rva": hex(rva), "address": _addr(address, module_base), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _unknown_direction(reason: str, family: str) -> dict[str, Any]:
    return {"status": "unknown", "family": family, "value": None, "reason": reason, "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "gaps": list(GAPS), "expires_at": {"status": "unknown", "reason": "FLEET_BASING_EXPIRY_UNREAD"}}


def _direction_value(family: str, value: bool, raw: Mapping[str, Any], proof: Mapping[str, Any]) -> dict[str, Any]:
    return {"status": "known", "family": family, "value": bool(value), "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "gaps": list(GAPS), "expires_at": {"status": "unknown", "reason": "FLEET_BASING_EXPIRY_UNREAD"}, "raw": deepcopy(dict(raw)), "proof": deepcopy(dict(proof))}


def _aggregate_field(directions: Mapping[str, Mapping[str, Any]], *, network: bool = False, rows: list[dict[str, Any]] | None = None, unknown_rows: list[dict[str, Any]] | None = None, candidate_failures: list[dict[str, Any]] | None = None, targets: int | None = None) -> dict[str, Any]:
    if network:
        unknown_rows = [] if unknown_rows is None else unknown_rows
        candidate_failures = [] if candidate_failures is None else candidate_failures
        status = "known" if not unknown_rows and not candidate_failures else "partial"
        active = [item for item in rows or [] if item.get("status") == "known" and item.get("active") is True]
        return {"status": status, "family": "fleet_basing", "value": [{"country": item["country"], "fullref_hex": item["fullref_hex"], "slot": item["slot"], "active": True, "direction": item["direction"]} for item in active], "rows": rows or [], "unknown_rows": unknown_rows, "candidate_failures": candidate_failures, "candidate_count": targets if targets is not None else len(rows or []), "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "gaps": list(GAPS), "expires_at": {"status": "unknown", "reason": "FLEET_BASING_EXPIRY_UNREAD"}}
    known = [value for value in directions.values() if value.get("status") == "known"]
    status = "known" if len(known) == len(FAMILIES) else "partial" if known else "unknown"
    return {"status": status, "family": "fleet_basing", "value": {family: deepcopy(directions.get(family, _unknown_direction("not_read", family))) for family in FAMILIES}, "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "gaps": list(GAPS), "expires_at": {"status": "unknown", "reason": "FLEET_BASING_EXPIRY_UNREAD"}}


def _vector_snapshot(reader: Any, budget: _ReadBudget, family: str, relation_row: Mapping[str, Any], layout: Mapping[str, Any], module_base: int, recipient_fullref: int | None = None) -> dict[str, Any]:
    spec = layout["families"][family]
    owner = int((relation_row["owner"]["va"] if isinstance(relation_row.get("owner"), Mapping) else relation_row["owner"]), 0) if isinstance(relation_row.get("owner"), Mapping) and isinstance(relation_row["owner"].get("va"), str) else int(relation_row["owner"]["va"] if isinstance(relation_row.get("owner"), Mapping) else relation_row["owner"])
    begin_address = _safe_add(owner, spec["vector_begin_offset"], f"{family}.vector_begin")
    count_address = _safe_add(owner, spec["vector_count_offset"], f"{family}.vector_count")
    begin, begin_raw = budget.qword(reader, begin_address, f"{family}.vector_begin")
    count, count_raw = budget.i32(reader, count_address, f"{family}.vector_count")
    if count < 0 or count > layout["max_vector_count"]:
        raise ProbeError(f"{family}.vector_count_out_of_bound")
    if count and not _valid_pointer(begin):
        raise ProbeError(f"{family}.vector_begin_invalid")
    raw_elements = budget.read(reader, begin, count * layout["element_stride"], f"{family}.vector.elements") if count else b""
    elements: list[dict[str, Any]] = []
    for index in range(count):
        chunk = raw_elements[index * 16:(index + 1) * 16]
        element_address = _safe_add(begin, index * 16, f"{family}.element[{index}]")
        elements.append({"index": index, "address": _addr(element_address, module_base), "raw_hex": chunk.hex(), "first_dword_raw_hex": chunk[:4].hex(), "first_dword": int.from_bytes(chunk[:4], "little"), "unread_tail_raw_hex": chunk[4:].hex(), "unread_tail_semantics": "+0x4..+0xf_unread_by_direct_leaf"})
    raw = {"owner_pointer": deepcopy(relation_row["owner"]), "owner_pointer_raw_hex": relation_row.get("owner_raw_hex"), "vector_begin": _field(begin_address, begin_raw, begin, module_base), "vector_count": _field(count_address, count_raw, count, module_base), "element_stride": layout["element_stride"], "elements": elements}
    proof: dict[str, Any] = {"family": family, "predicate_rva": hex(spec["predicate_rva"]), "leaf_va": hex(module_base + spec["predicate_rva"]), "unread_element_bytes": "+0x4..+0xf"}
    return {"raw": raw, "proof": proof}


def _project_vector(reader: Any, budget: _ReadBudget, family: str, cached: Mapping[str, Any], relation_row: Mapping[str, Any], recipient_fullref: int, module_base: int, layout: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
    raw = cached.get("raw")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
        raise ProbeError("owner_vector_cache_shape_invalid")
    expected = _signed_i16(_slot_from_fullref(recipient_fullref))
    matches = [element for element in raw["elements"] if isinstance(element, Mapping) and element.get("first_dword") == (expected & 0xffffffff)]
    proof = deepcopy(cached.get("proof", {}))
    proof["comparison_slot_signed_i16"] = expected
    if family == "granted":
        proof["matching_element_indices"] = [int(element["index"]) for element in matches]
        proof["native_leaf_al"] = bool(matches)
        return bool(matches), proof
    if not matches:
        proof["matching_element_indices"] = []
        proof["native_leaf_al"] = False
        proof["first_matching_element_index"] = None
        return False, proof
    first = matches[0]
    proof["matching_element_indices"] = [int(first["index"])]
    element_raw = bytes.fromhex(str(first["raw_hex"]))
    pointer_raw = element_raw[8:16]
    agreement_pointer = int.from_bytes(pointer_raw, "little")
    proof.update({"first_matching_element_index": int(first["index"]), "agreement_pointer": _addr(agreement_pointer, module_base), "agreement_pointer_raw_hex": pointer_raw.hex()})
    if agreement_pointer == 0:
        proof.update(agreement_status="null", native_leaf_al=False)
        return False, proof
    if not _valid_pointer(agreement_pointer):
        raise ProbeError("received_agreement_pointer_invalid")
    spec = layout["families"][family]
    agreement_address = _safe_add(agreement_pointer, spec["agreement_ref_offset"], "received.agreement_ref")
    agreement_ref, agreement_raw = budget.qword(reader, agreement_address, "received.agreement_ref")
    agreement_slot = _signed_i16(_slot_from_fullref(agreement_ref))
    proof.update({"agreement_ref": _field(agreement_address, agreement_raw, agreement_ref, module_base), "agreement_slot_signed_i16": agreement_slot, "agreement_status": "observed", "native_leaf_al": agreement_slot == expected})
    return agreement_slot == expected, proof


def _pair_pass(reader: Any, budget: _ReadBudget, module_base: int, actor: str, recipient: str, profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {"status": "unknown", "runtime_code_guard": None, "context": None, "relation_row": None, "fields": {"fleet_basing": _aggregate_field({family: _unknown_direction("not_read", family) for family in FAMILIES})}, "read_budget": None, "read_log": [], "unknown_conditions": [], "complete": False}
    start = len(budget.log)
    try:
        guard = _runtime_code_guard(reader, budget, module_base, profile)
        result["runtime_code_guard"] = guard
        if guard.get("status") != "observed":
            result["unknown_conditions"].append("runtime_code_guard_not_observed")
            return result
        context = _rel._context_snapshot(reader, budget, module_base, actor, recipient, layout)
        result["context"] = context
        if context.get("status") != "observed":
            result["unknown_conditions"].extend(context.get("unknown_conditions", []))
            return result
        row = _rel._relation_row(reader, budget, context["actor"], context["recipient"], layout, module_base)
        result["relation_row"] = row
        directions: dict[str, Mapping[str, Any]] = {}
        recipient_fullref = int(context["recipient"]["fullref"]["value"])
        for family in FAMILIES:
            try:
                cached = _vector_snapshot(reader, budget, family, row, layout, module_base, recipient_fullref)
                value, proof = _project_vector(reader, budget, family, cached, row, recipient_fullref, module_base, layout)
                raw = deepcopy(cached["raw"])
                raw["recipient_fullref"] = deepcopy(row["recipient_fullref"])
                raw["recipient_slot_signed_i16"] = _signed_i16(_slot_from_fullref(recipient_fullref))
                directions[family] = _direction_value(family, value, raw, proof)
            except Exception as exc:
                directions[family] = _unknown_direction(f"{type(exc).__name__}:{exc}", family)
        result["fields"] = {"fleet_basing": _aggregate_field(directions)}
        result["status"] = "observed"
        result["complete"] = all(value.get("status") == "known" for value in directions.values())
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = deepcopy(budget.log[start:])
    return result


def _network_pass(reader: Any, budget: _ReadBudget, module_base: int, actor: str, profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {"status": "unknown", "runtime_code_guard": None, "context": None, "targets": [], "owner_cache": {}, "candidate_failures": [], "fields": {"fleet_basing": _aggregate_field({}, network=True)}, "network_stats": {"candidate_count": 0, "known_rows": {family: 0 for family in FAMILIES}, "unknown_rows": {family: 0 for family in FAMILIES}}, "read_budget": None, "read_log": [], "unknown_conditions": [], "complete": False}
    start = len(budget.log)
    try:
        guard = _runtime_code_guard(reader, budget, module_base, profile)
        result["runtime_code_guard"] = guard
        if guard.get("status") != "observed":
            result["unknown_conditions"].append("runtime_code_guard_not_observed")
            return result
        context = _rel._network_context_snapshot(reader, budget, module_base, actor, layout)
        result["context"] = context
        if context.get("status") != "observed" or not isinstance(context.get("actor"), Mapping):
            result["unknown_conditions"].extend(context.get("unknown_conditions", []))
            return result
        result["candidate_failures"] = deepcopy(context.get("country_scan", {}).get("candidate_failures", []))
        actor_index = int(context["actor"]["index"])
        entries = context.get("country_scan", {}).get("entries", [])
        targets: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or entry.get("status") in {"empty", "null_sentinel", "unknown"} or entry.get("index") == actor_index:
                continue
            pointer = entry.get("pointer")
            fullref = (entry.get("fullref") or {}).get("value")
            if not isinstance(pointer, Mapping) or not isinstance(fullref, int) or not isinstance(entry.get("tag"), str) or not isinstance(entry.get("slot"), int):
                continue
            targets.append({"index": int(entry["index"]), "country": entry["tag"], "country_pointer": deepcopy(pointer), "fullref": fullref, "fullref_hex": (entry.get("fullref") or {}).get("raw_hex"), "slot": int(entry["slot"])})
        result["targets"] = targets
        result["network_stats"]["candidate_count"] = len(targets)
        for target in targets:
            try:
                target["relation_row"] = _rel._relation_row(reader, budget, context["actor"], {"pointer": target["country_pointer"], "fullref": {"value": target["fullref"], "raw_hex": target["fullref_hex"]}}, layout, module_base)
                target["row_status"] = "observed"
            except Exception as exc:
                target["row_status"] = "unknown"
                target["row_reason"] = f"{type(exc).__name__}:{exc}"
                target["relation_row"] = None
                result["candidate_failures"].append({"index": target["index"], "country": target["country"], "reason": target["row_reason"]})
        cache: dict[str, dict[str, Any]] = {}
        cache_failures: dict[str, str] = {}
        rows: list[dict[str, Any]] = []
        for target in targets:
            for family in FAMILIES:
                row_out = {"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "direction": family, "relation_row": deepcopy(target.get("relation_row")), "predicate_cache_key": None, "status": "unknown", "active": None}
                try:
                    if target.get("row_status") != "observed":
                        raise ProbeError(str(target.get("row_reason", "relation_row_unknown")))
                    owner = target["relation_row"]["owner"]["va"]
                    owner_int = int(owner, 0) if isinstance(owner, str) else int(owner)
                    cache_key = f"{owner_int:#x}:{family}"
                    row_out["predicate_cache_key"] = cache_key
                    cached = cache.get(cache_key)
                    if cache_key in cache_failures:
                        raise ProbeError(cache_failures[cache_key])
                    if cached is None:
                        try:
                            cached = _vector_snapshot(reader, budget, family, target["relation_row"], layout, module_base)
                        except Exception as exc:
                            cache_failures[cache_key] = f"{type(exc).__name__}:{exc}"
                            cache[cache_key] = {"status": "unknown", "reason": cache_failures[cache_key]}
                            raise
                        cache[cache_key] = deepcopy(cached)
                    value, proof = _project_vector(reader, budget, family, cached, target["relation_row"], target["fullref"], module_base, layout)
                    row_out.update(status="known", active=bool(value), predicate=proof)
                    result["network_stats"]["known_rows"][family] += 1
                except Exception as exc:
                    row_out.update(status="unknown", active=None, reason=f"{type(exc).__name__}:{exc}")
                    result["network_stats"]["unknown_rows"][family] += 1
                rows.append(row_out)
        result["owner_cache"] = cache
        unknown = [{"index": item["index"], "country": item["country"], "fullref_hex": item["fullref_hex"], "slot": item["slot"], "direction": item["direction"], "reason": item.get("reason", "unknown")} for item in rows if item.get("status") == "unknown"]
        result["fields"] = {"fleet_basing": _aggregate_field({}, network=True, rows=rows, unknown_rows=unknown, candidate_failures=result["candidate_failures"], targets=len(targets) * 2)}
        result["status"] = "observed"
        result["complete"] = not unknown and not result["candidate_failures"]
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = deepcopy(budget.log[start:])
    return result


def _without_volatile(value: Any) -> Any:
    return _rel._without_volatile(value)


def _diff_paths(left: Any, right: Any, prefix: str = "$") -> list[str]:
    return _rel._diff_paths(left, right, prefix)


def _base_report(installation: Path, actor: str, recipient: str | None) -> dict[str, Any]:
    network = recipient is None
    try:
        probe_sha = _sha256_file(Path(__file__).resolve())
    except Exception:
        probe_sha = None
    return {"schema": "information_fleet_basing_runtime.v1", "probe": "information-fleet-basing-memory", "probe_version": 1, "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": probe_sha, "read_only": True, "evidence_kind": "pure_runtime_observation_not_static_evidence", "profile": {"path": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID, "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES}, "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "families": list(FAMILIES), "mode": "network" if network else "pair"}, "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "image_base": "0x140000000"}, "source_pins": {**SOURCE_PINS, "accepted_rea": deepcopy(ACCEPTED_REA)}, "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None, "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False}, "module_base": None, "context_before": None, "context_after": None, "relation_row": None, "fields": {"fleet_basing": _aggregate_field({}, network=network)}, "before": None, "after": None, "owner_cache": {}, "targets": [], "network_stats": None, "doublepass": {"performed": False, "consistent": None, "mismatches": []}, "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": hex(PROCESS_ACCESS), "rpm_total_limit": NETWORK_MAX_TOTAL_RPM if network else MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False}, "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "errors": [], "completed": False}


def _valid_tag(tag: Any) -> bool:
    return isinstance(tag, str) and bool(re.fullmatch(r"[A-Z0-9]{3}", tag))


def _normalize_request(actor: Any, recipient: Any) -> None:
    if actor != EXPECTED_COUNTRY or (recipient is not None and (not _valid_tag(recipient) or recipient == actor)):
        raise ProbeError("actor_must_be_FRA_and_recipient_distinct_tag")


def _retract(report: dict[str, Any], reason: str) -> dict[str, Any]:
    result = deepcopy(report)
    field = result.get("fields", {}).get("fleet_basing") if isinstance(result.get("fields"), Mapping) else None
    if isinstance(field, Mapping):
        if isinstance(field.get("value"), dict):
            directions = {family: _unknown_direction(reason, family) for family in FAMILIES}
            result["fields"]["fleet_basing"] = _aggregate_field(directions)
        else:
            result["fields"]["fleet_basing"] = _aggregate_field({}, network=True, rows=[], unknown_rows=[{"reason": reason}], candidate_failures=[])
    for key in ("before", "after"):
        if isinstance(result.get(key), Mapping):
            result[key]["fields"] = deepcopy(result["fields"])
            result[key]["complete"] = False
    result["status"] = "unknown"
    result["completed"] = False
    result["unknown_conditions"] = list(result.get("unknown_conditions", [])) + [reason]
    return result


def capture(installation: Path, actor: str = EXPECTED_COUNTRY, recipient: str | None = None, families: Sequence[str] | None = None) -> dict[str, Any]:
    """Capture a pair or the actor's bounded network using read-only RPM."""
    installation = Path(installation)
    report = _base_report(installation, actor, recipient)
    if families is not None and (isinstance(families, (str, bytes)) or set(families) != set(FAMILIES)):
        report["status"] = "invalid_request"
        report["errors"].append({"stage": "request", "error": "fleet_basing_requires_received_and_granted"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    try:
        _normalize_request(actor, recipient)
    except ProbeError as exc:
        report["status"] = "unsupported_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": str(exc)})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    kernel = handle = reader = None
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        document = _load_installation(installation)
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise ProbeError("OpenProcess_failed")
        module_base = _capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True or not _valid_pointer(module_base):
            raise ProbeError("identity_binding_not_verified")
        report["module_base"] = _addr(module_base)
        report["file_code_guard"] = _file_code_guard(Path(report["identity"]["process_path"]), profile)
        if report["file_code_guard"].get("status") != "observed":
            raise ProbeError("file_code_guard_mismatch")
        reader = NetworkAddressBoundedRPM(kernel, handle, module_base) if recipient is None else AddressBoundedRPM(kernel, handle, module_base)
        budget = _ReadBudget(NETWORK_MAX_TOTAL_RPM if recipient is None else MAX_TOTAL_RPM)
        runner = _network_pass if recipient is None else _pair_pass
        first = runner(reader, budget, module_base, actor, profile) if recipient is None else runner(reader, budget, module_base, actor, recipient, profile)
        report["before"] = first
        report["context_before"] = deepcopy(first.get("context"))
        if first.get("status") != "observed":
            report["status"] = "unknown"
        else:
            second = runner(reader, budget, module_base, actor, profile) if recipient is None else runner(reader, budget, module_base, actor, recipient, profile)
            report["after"] = second
            report["context_after"] = deepcopy(second.get("context"))
            report["doublepass"]["performed"] = True
            mismatches = _diff_paths(_without_volatile(first), _without_volatile(second)) if second.get("status") == "observed" else ["$.after.status"]
            if second.get("status") == "observed" and not _rel._observation_dates_match(first.get("context"), second.get("context")):
                mismatches.append("$.context.game_date")
            report["doublepass"]["mismatches"] = mismatches[:256]
            report["doublepass"]["consistent"] = not mismatches
            if not mismatches:
                report["status"] = "observed"
                report["fields"] = deepcopy(second.get("fields", {}))
                report["relation_row"] = deepcopy(second.get("relation_row"))
                report["owner_cache"] = deepcopy(second.get("owner_cache", {}))
                report["targets"] = deepcopy(second.get("targets", []))
                report["network_stats"] = deepcopy(second.get("network_stats"))
            else:
                report["status"] = "doublepass_mismatch"
        before_guard = (report.get("before") or {}).get("runtime_code_guard", {})
        after_guard = (report.get("after") or {}).get("runtime_code_guard", {})
        report["runtime_code_guard"] = {"status": "observed" if before_guard.get("status") == "observed" and after_guard.get("status") == "observed" else "unknown", "passes": [before_guard, after_guard]}
        report["access"]["rpm_bytes_requested"] = reader.bytes_requested
        report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    report["cleanup"]["handle_close"] = _close_process_handle(kernel, handle)
    report["completed"] = report.get("status") == "observed" and report["cleanup"]["handle_close"].get("closed") is True
    if not report["completed"]:
        return _retract(report, "observation_not_completed")
    return report


capture_network = capture


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _validate_element(element: Mapping[str, Any], index: int, begin: int) -> bool:
    raw_hex = element.get("raw_hex")
    if element.get("index") != index or not isinstance(raw_hex, str) or len(raw_hex) != 32:
        return False
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return False
    address = _as_int((element.get("address") or {}).get("va"))
    return address == begin + index * 16 and element.get("first_dword") == int.from_bytes(raw[:4], "little") and element.get("first_dword_raw_hex") == raw[:4].hex() and element.get("unread_tail_raw_hex") == raw[4:].hex() and element.get("unread_tail_semantics") == "+0x4..+0xf_unread_by_direct_leaf"


def _validate_direction(direction: Mapping[str, Any], family: str, relation_row: Mapping[str, Any], context: Mapping[str, Any], layout: Mapping[str, Any], module_base: int | None) -> bool:
    if direction.get("status") == "unknown":
        return isinstance(direction.get("reason"), str) and direction.get("value") is None
    if direction.get("status") != "known" or type(direction.get("value")) is not bool or direction.get("family") != family or direction.get("unit") != UNIT or direction.get("scale") != SCALE or direction.get("period") != PERIOD:
        return False
    raw, proof = direction.get("raw"), direction.get("proof")
    if not isinstance(raw, Mapping) or not isinstance(proof, Mapping):
        return False
    owner = _as_int((relation_row.get("owner") or {}).get("va"))
    if owner is None or raw.get("owner_pointer_raw_hex") != owner.to_bytes(8, "little").hex() or _as_int((raw.get("owner_pointer") or {}).get("va")) != owner:
        return False
    expected_fullref = _as_int((context.get("recipient", {}).get("fullref") or {}).get("value"))
    if expected_fullref is None or _as_int((raw.get("recipient_fullref") or {}).get("value")) != expected_fullref or (raw.get("recipient_fullref") or {}).get("raw_hex") != expected_fullref.to_bytes(8, "little").hex() or raw.get("recipient_slot_signed_i16") != _signed_i16(_slot_from_fullref(expected_fullref)):
        return False
    spec = layout["families"].get(family)
    if not isinstance(spec, Mapping) or proof.get("predicate_rva") != hex(spec["predicate_rva"]):
        return False
    begin_field, count_field = raw.get("vector_begin"), raw.get("vector_count")
    begin = _as_int(begin_field.get("value")) if isinstance(begin_field, Mapping) else None
    count = _as_int(count_field.get("value")) if isinstance(count_field, Mapping) else None
    if begin is None or count is None or count < 0 or count > MAX_VECTOR_COUNT or (begin_field or {}).get("raw_hex") != begin.to_bytes(8, "little").hex() or (count_field or {}).get("raw_hex") != count.to_bytes(4, "little", signed=True).hex() or _as_int((begin_field or {}).get("address", {}).get("va")) != owner + spec["vector_begin_offset"] or _as_int((count_field or {}).get("address", {}).get("va")) != owner + spec["vector_count_offset"]:
        return False
    elements = raw.get("elements")
    if not isinstance(elements, list) or len(elements) != count or any(not isinstance(item, Mapping) or not _validate_element(item, index, begin) for index, item in enumerate(elements)):
        return False
    expected = _signed_i16(_slot_from_fullref(expected_fullref))
    matches = [item for item in elements if item.get("first_dword") == (expected & 0xffffffff)]
    if family == "received":
        expected_matches = [matches[0]] if matches else []
        if proof.get("matching_element_indices") != [int(item["index"]) for item in expected_matches] or proof.get("first_matching_element_index") != (int(matches[0]["index"]) if matches else None):
            return False
        if not matches:
            return direction.get("value") is False
        element_raw = bytes.fromhex(matches[0]["raw_hex"])
        pointer_raw = element_raw[8:16]
        agreement_pointer = int.from_bytes(pointer_raw, "little")
        if proof.get("agreement_pointer_raw_hex") != pointer_raw.hex():
            return False
        if agreement_pointer == 0:
            return direction.get("value") is False and proof.get("agreement_status") == "null"
        agreement = proof.get("agreement_ref")
        if not isinstance(agreement, Mapping):
            return False
        agreement_value = _as_int(agreement.get("value"))
        if agreement_value is None or agreement.get("raw_hex") != agreement_value.to_bytes(8, "little").hex() or _as_int((agreement.get("address") or {}).get("va")) != agreement_pointer + spec["agreement_ref_offset"]:
            return False
        agreement_slot = _signed_i16(_slot_from_fullref(agreement_value))
        return proof.get("agreement_slot_signed_i16") == agreement_slot and direction.get("value") is (agreement_slot == expected)
    return proof.get("matching_element_indices") == [int(item["index"]) for item in matches] and direction.get("value") is bool(matches)


def _validate_pair(report: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    context = report.get("context_after")
    fields = report.get("fields")
    row = report.get("relation_row")
    if not isinstance(context, Mapping) or not isinstance(fields, Mapping) or not isinstance(row, Mapping) or not isinstance(fields.get("fleet_basing"), Mapping):
        return False
    actor = context.get("actor")
    recipient = context.get("recipient")
    if not isinstance(actor, Mapping) or not isinstance(recipient, Mapping):
        return False
    actor_ptr = _as_int((actor.get("pointer") or {}).get("va")); recipient_fullref = _as_int((recipient.get("fullref") or {}).get("value"))
    table = row.get("relation_table")
    table_ptr = _as_int(table.get("value")) if isinstance(table, Mapping) else None
    row_address = _as_int((row.get("address") or {}).get("va"))
    owner = _as_int((row.get("owner") or {}).get("va"))
    if actor_ptr is None or recipient_fullref is None or table_ptr is None or owner is None or row_address != table_ptr + _slot_from_fullref(recipient_fullref) * layout["relation_row_stride"] or _as_int((table.get("address") or {}).get("va")) != actor_ptr + layout["relation_table_offset"] or table.get("raw_hex") != table_ptr.to_bytes(8, "little").hex() or row.get("owner_raw_hex") != owner.to_bytes(8, "little").hex() or _as_int((row.get("recipient_fullref") or {}).get("value")) != recipient_fullref or (row.get("recipient_fullref") or {}).get("raw_hex") != recipient_fullref.to_bytes(8, "little").hex():
        return False
    value = fields["fleet_basing"].get("value")
    if not isinstance(value, Mapping) or fields["fleet_basing"].get("status") not in {"known", "partial", "unknown"}:
        return False
    statuses = [value.get(family, {}).get("status") for family in FAMILIES if isinstance(value.get(family), Mapping)]
    expected_status = "known" if statuses == ["known", "known"] else "partial" if any(item == "known" for item in statuses) else "unknown"
    if fields["fleet_basing"].get("status") != expected_status:
        return False
    for family in FAMILIES:
        direction = value.get(family)
        if not isinstance(direction, Mapping) or not _validate_direction(direction, family, row, context, layout, _as_int((report.get("module_base") or {}).get("va"))):
            return False
    return True


def _validate_network(report: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    context = report.get("context_after")
    field = report.get("fields", {}).get("fleet_basing") if isinstance(report.get("fields"), Mapping) else None
    cache = report.get("owner_cache")
    if not isinstance(context, Mapping) or not isinstance(field, Mapping) or not isinstance(cache, Mapping) or not isinstance(field.get("rows"), list):
        return False
    scan = context.get("country_scan")
    actor = context.get("actor")
    if not isinstance(scan, Mapping) or not isinstance(actor, Mapping):
        return False
    expected_targets = [entry for entry in scan.get("entries", []) if isinstance(entry, Mapping) and entry.get("status") in {"match", "other"} and entry.get("index") != actor.get("index")]
    rows = field["rows"]
    if len(rows) != len(expected_targets) * 2 or field.get("candidate_failures") != scan.get("candidate_failures", []):
        return False
    expected_status = "known" if not field.get("unknown_rows") and not field.get("candidate_failures") else "partial"
    if field.get("status") != expected_status:
        return False
    actor_ptr = _as_int((actor.get("pointer") or {}).get("va"))
    if actor_ptr is None:
        return False
    expected_keys = {(int(entry["index"]), entry.get("tag"), (entry.get("fullref") or {}).get("raw_hex"), int(entry.get("slot")), family) for entry in expected_targets for family in FAMILIES}
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("country"), str) or row.get("direction") not in FAMILIES:
            return False
        key = (row.get("index"), row.get("country"), row.get("fullref_hex"), row.get("slot"), row.get("direction"))
        if key not in expected_keys or key in seen:
            return False
        seen.add(key)
        relation_row = row.get("relation_row")
        if row.get("status") == "unknown":
            if row.get("active") is not None or not isinstance(row.get("reason"), str):
                return False
            continue
        if row.get("status") != "known" or row.get("active") not in (True, False) or not isinstance(relation_row, Mapping):
            return False
        relation_table = relation_row.get("relation_table")
        table_ptr = _as_int(relation_table.get("value")) if isinstance(relation_table, Mapping) else None
        row_address = _as_int((relation_row.get("address") or {}).get("va"))
        row_fullref = _as_int((relation_row.get("recipient_fullref") or {}).get("value"))
        if row_fullref is None:
            return False
        try:
            expected_fullref = int.from_bytes(bytes.fromhex(str(row.get("fullref_hex"))), "little")
        except (ValueError, TypeError):
            return False
        if (table_ptr is None or not _valid_pointer(table_ptr) or _as_int((relation_table.get("address") or {}).get("va")) != actor_ptr + layout["relation_table_offset"] or relation_table.get("raw_hex") != table_ptr.to_bytes(8, "little").hex() or row_address != table_ptr + int(row.get("slot")) * layout["relation_row_stride"] or row_fullref != expected_fullref or (relation_row.get("recipient_fullref") or {}).get("raw_hex") != expected_fullref.to_bytes(8, "little").hex()):
            return False
        owner = _as_int((relation_row.get("owner") or {}).get("va"))
        if owner is None or relation_row.get("owner_raw_hex") != owner.to_bytes(8, "little").hex():
            return False
        cache_key = row.get("predicate_cache_key")
        if cache_key != f"{owner:#x}:{row['direction']}" or not isinstance(cache.get(cache_key), Mapping):
            return False
        # Recreate the vector comparison against the cached raw bytes.  A
        # received row's agreement proof is checked by the compact predicate
        # validator below; the cache itself must remain recipient-independent.
        cached = cache[cache_key]
        raw = cached.get("raw")
        if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
            return False
        fullref = _as_int(row.get("fullref_hex"))
        if fullref is None:
            try:
                raw_fullref = bytes.fromhex(str(row.get("fullref_hex")))
                if len(raw_fullref) != 8:
                    return False
                fullref = int.from_bytes(raw_fullref, "little")
            except (ValueError, TypeError):
                return False
        expected = _signed_i16(_slot_from_fullref(fullref))
        matches = [item for item in raw["elements"] if isinstance(item, Mapping) and item.get("first_dword") == (expected & 0xffffffff)]
        proof = row.get("predicate")
        if not isinstance(proof, Mapping):
            return False
        if row["direction"] == "granted":
            if proof.get("matching_element_indices") != [int(item["index"]) for item in matches] or row.get("active") is not bool(matches):
                return False
        else:
            if proof.get("first_matching_element_index") != (int(matches[0]["index"]) if matches else None):
                return False
            # Network raw rows carry the agreement result in proof; a null
            # agreement is a valid known false result.
            if matches and proof.get("agreement_status") not in {"null", "observed"}:
                return False
            if not matches and row.get("active") is not False:
                return False
    if seen != expected_keys:
        return False
    # Every known owner vector is copied once per direction.  Validate the
    # address/value bindings as well as the element bytes so a self-consistent
    # cache edit cannot pass merely by changing its derived predicate.
    expected_cache = {row.get("predicate_cache_key") for row in rows if isinstance(row.get("predicate_cache_key"), str)}
    if set(cache) != expected_cache:
        return False
    for key, cached in cache.items():
        try:
            owner_text, family = key.split(":", 1)
            owner = int(owner_text, 16)
        except (ValueError, AttributeError):
            return False
        if family not in FAMILIES or not isinstance(cached, Mapping):
            return False
        if cached.get("status") == "unknown":
            if not isinstance(cached.get("reason"), str):
                return False
            continue
        raw = cached.get("raw")
        proof = cached.get("proof")
        if not isinstance(raw, Mapping) or not isinstance(proof, Mapping) or _as_int((raw.get("owner_pointer") or {}).get("va")) != owner or raw.get("owner_pointer_raw_hex") != owner.to_bytes(8, "little").hex() or proof.get("predicate_rva") != hex(layout["families"][family]["predicate_rva"]):
            return False
        begin_field, count_field = raw.get("vector_begin"), raw.get("vector_count")
        begin = _as_int(begin_field.get("value")) if isinstance(begin_field, Mapping) else None
        count = _as_int(count_field.get("value")) if isinstance(count_field, Mapping) else None
        if begin is None or count is None or count < 0 or count > MAX_VECTOR_COUNT or (begin_field or {}).get("raw_hex") != begin.to_bytes(8, "little").hex() or (count_field or {}).get("raw_hex") != count.to_bytes(4, "little", signed=True).hex() or _as_int((begin_field or {}).get("address", {}).get("va")) != owner + layout["families"][family]["vector_begin_offset"] or _as_int((count_field or {}).get("address", {}).get("va")) != owner + layout["families"][family]["vector_count_offset"]:
            return False
        elements = raw.get("elements")
        if not isinstance(elements, list) or len(elements) != count or any(not isinstance(item, Mapping) or not _validate_element(item, index, begin) for index, item in enumerate(elements)):
            return False
    active_expected = [{"country": row["country"], "fullref_hex": row["fullref_hex"], "slot": row["slot"], "active": True, "direction": row["direction"]} for row in rows if row.get("status") == "known" and row.get("active") is True]
    return field.get("value") == active_expected


def _validate_budget_accounting(report: Mapping[str, Any]) -> bool:
    """Check precharged bytes/calls, including failed read reservations."""
    before, after = report.get("before"), report.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return False
    rb_before, rb_after = before.get("read_budget"), after.get("read_budget")
    log_before, log_after = before.get("read_log"), after.get("read_log")
    if not isinstance(rb_before, Mapping) or not isinstance(rb_after, Mapping) or not isinstance(log_before, list) or not isinstance(log_after, list):
        return False
    def accounted(log: list[Any]) -> tuple[int, int] | None:
        total = 0
        for item in log:
            if not isinstance(item, Mapping) or not isinstance(item.get("size"), int) or item["size"] <= 0:
                return None
            total += item["size"]
        return total, len(log)
    first = accounted(log_before); second = accounted(log_after)
    if first is None or second is None:
        return False
    before_bytes, before_calls = rb_before.get("bytes_reserved"), rb_before.get("calls_reserved")
    after_bytes, after_calls = rb_after.get("bytes_reserved"), rb_after.get("calls_reserved")
    if not all(isinstance(value, int) and value >= 0 for value in (before_bytes, before_calls, after_bytes, after_calls)):
        return False
    if (before_bytes, before_calls) != first or after_bytes < before_bytes or after_calls < before_calls or (after_bytes - before_bytes, after_calls - before_calls) != second:
        return False
    access = report.get("access", {})
    return access.get("rpm_bytes_requested") == after_bytes and access.get("rpm_calls") == after_calls


def validate_capture(report: Mapping[str, Any], context: Mapping[str, Any] | None = None, creation_filetime: int | None = None, actor: str | None = None, recipient: str | None = None) -> bool:
    """Validate identity, two-pass raw binding, guards, and both predicates."""
    if not isinstance(report, Mapping):
        return False
    try:
        if report.get("schema") != "information_fleet_basing_runtime.v1" or report.get("status") != "observed" or report.get("completed") is not True:
            return False
        cleanup = report.get("cleanup", {}).get("handle_close", {})
        access = report.get("access", {})
        if cleanup.get("closed") is not True or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False:
            return False
        if report.get("profile", {}).get("profile_id") != EXPECTED_PROFILE_ID or report.get("profile", {}).get("sha256") != EXPECTED_PROFILE_SHA256 or report.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
            return False
        if report.get("static_contract_guard", {}).get("status") != "observed" or report.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        identity = report.get("identity")
        if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_path_sha256_matches_expected") is not True or identity.get("process_creation_matches_installation") is not True:
            return False
        if creation_filetime is not None and identity.get("process_creation_filetime") != creation_filetime:
            return False
        request = report.get("request")
        if not isinstance(request, Mapping) or request.get("actor") != (EXPECTED_COUNTRY if actor is None else actor):
            return False
        if actor is not None and request.get("actor") != actor:
            return False
        if recipient is not None and request.get("recipient") != recipient:
            return False
        if request.get("recipient") is not None and not _valid_tag(request.get("recipient")):
            return False
        if report.get("doublepass", {}).get("performed") is not True or report.get("doublepass", {}).get("consistent") is not True:
            return False
        if not _validate_budget_accounting(report):
            return False
        before, after = report.get("before"), report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or _without_volatile(before) != _without_volatile(after)
                or not _rel._observation_dates_match(before.get("context"), after.get("context"))):
            return False
        if report.get("context_before") != before.get("context") or report.get("context_after") != after.get("context") or report.get("fields") != after.get("fields"):
            return False
        if report.get("runtime_code_guard", {}).get("status") != "observed" or before.get("runtime_code_guard", {}).get("status") != "observed" or after.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        context_after = report.get("context_after")
        if not isinstance(context_after, Mapping) or context_after.get("status") != "observed":
            return False
        if context is not None:
            if not isinstance(context, Mapping):
                return False
            for key in ("session_id", "process_creation_filetime", "game_date", "actor", "recipient"):
                if key not in context:
                    continue
                if key == "game_date":
                    if not _rel._observation_dates_match(before.get("context"), after.get("context"), context[key], anchor_present=True):
                        return False
                    continue
                observed = identity.get("installation_session_id") if key == "session_id" else identity.get("process_creation_filetime") if key == "process_creation_filetime" else context_after.get("game_date", {}).get("value") if key == "game_date" else request.get(key)
                if observed != context[key]:
                    return False
        layout = _profile_layout(_load_profile())
        if request.get("recipient") is None:
            return _validate_network(report, layout)
        return _validate_pair(report, layout)
    except (ProfileError, ProbeError, KeyError, TypeError, ValueError, AttributeError):
        return False


validate_network_capture = validate_capture


def retract_record(record: Mapping[str, Any], reason: str = "observation_retracted") -> dict[str, Any]:
    return _retract(dict(record), reason)


__all__ = ["AddressBoundedRPM", "NetworkAddressBoundedRPM", "PROFILE_FILE", "EXPECTED_PROFILE_ID", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FAMILIES", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "NETWORK_MAX_TOTAL_RPM", "ProfileError", "ProbeError", "capture", "capture_network", "validate_capture", "validate_network_capture", "retract_record", "_load_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_ReadBudget", "_pair_pass", "_network_pass"]
