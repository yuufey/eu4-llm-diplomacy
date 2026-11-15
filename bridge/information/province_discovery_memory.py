"""Bounded two-pass positive province-discovery membership reader.

The result covers only indexed positive province IDs ``1..count-1``. It does
not establish that this is the full native province domain, interpret ID zero,
or turn a static map listing into runtime membership. A stable ``known`` value
is therefore a partial positive-membership list, never a complete list of all
discovered provinces. The two passes are not an atomic snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from typing import Any

from . import country_reference_memory as _country
from . import foreign_technology_capture as _owner
from . import province_reference_memory as _province
from . import province_state_memory as _province_state


SCHEMA = "information.province_discovery_memory.v1"
OBSERVER = "FRA"
MAX_READ_CALLS = 40_000
MAX_TOTAL_READ_BYTES = 512 * 1024
MAX_SINGLE_READ_BYTES = 1024
MAX_PROVINCE_COUNT = 65_536
MIN_USER_ADDRESS = _province.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _province.MAX_USER_ADDRESS_EXCLUSIVE


class _ReadStop(ValueError):
    pass


class _BudgetReader:
    """Apply this leaf's stricter budget while forwarding every read."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.calls = 0
        self.bytes_requested = 0
        self.max_single_read = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or not MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
                or type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES
                or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
            raise _ReadStop("READ_ADDRESS_OR_SIZE_INVALID")
        if self.calls >= MAX_READ_CALLS:
            raise _ReadStop("READ_CALL_BUDGET_EXCEEDED")
        if self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            raise _ReadStop("READ_BYTE_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        self.max_single_read = max(self.max_single_read, size)
        method = getattr(self.source, "read", None)
        try:
            raw = method(address, size, label) if callable(method) else self.source(address, size, label)
        except Exception as exc:
            raise _ReadStop(f"READ_FAILED:{type(exc).__name__}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            raise _ReadStop("READ_SHORT_OR_INVALID")
        return bytes(raw)

    def summary(self) -> dict[str, Any]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_single_read": self.max_single_read,
                "limits": {"calls": MAX_READ_CALLS,
                           "bytes": MAX_TOTAL_READ_BYTES,
                           "single_read_bytes": MAX_SINGLE_READ_BYTES}}


def _unknown(reason: str, *, passes: list[dict[str, Any]] | None = None,
             budget: _BudgetReader | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "unknown",
        "basis": "indexed_positive_province_discovery_candidates",
        "observer": OBSERVER,
        "scope": {"province_ids": "1..count-1", "domain_complete": False,
                  "province_zero_semantics": "unknown"},
        "complete": False,
        "domain_complete": False,
        "reason": reason,
        "passes": passes or [],
        "consistency": {"status": "unknown"},
    }
    if budget is not None:
        result["budget"] = budget.summary()
    return result


def _int_hex(value: Any) -> int:
    if type(value) is not str:
        raise ValueError("HEX_VALUE_INVALID")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise ValueError("HEX_VALUE_INVALID") from exc
    if type(parsed) is not int:
        raise ValueError("HEX_VALUE_INVALID")
    return parsed


def _country_binding(scan: Mapping[str, Any], tag: str) -> dict[str, Any] | None:
    requested = scan.get("requested")
    item = requested.get(tag) if isinstance(requested, Mapping) else None
    if not isinstance(item, Mapping):
        return None
    return {key: deepcopy(item.get(key)) for key in (
        "tag", "slot", "country_pointer", "fullref", "fullref_raw_hex",
        "country_fullref_address", "table_entry_address", "table_entry_raw_hex")}


def _admission_summary(admission: Mapping[str, Any]) -> dict[str, Any]:
    role = admission.get("observer_nonplayer_role")
    if not isinstance(role, Mapping):
        role = {}
    return {
        "status": admission.get("status"),
        "admitted": admission.get("admitted"),
        "predicate_path": deepcopy(admission.get("predicate_path", [])),
        "observer_nonplayer_role": {
            key: deepcopy(role.get(key)) for key in
            ("observer", "slot", "human_count", "controller_type", "verified", "basis")
        },
    }


def _read_header(reader: _BudgetReader, base: int, world: int) -> dict[str, Any]:
    if type(world) is not int or not _province._is_user_address(world) or world & 7:
        raise ValueError("WORLD_POINTER_INVALID")
    cells = (
        ("array_begin", world + _province.ARRAY_BEGIN_OFFSET, 8),
        ("array_end", world + _province.ARRAY_END_OFFSET, 8),
        ("records_pointer", world + _province.RECORDS_POINTER_OFFSET, 8),
    )
    raw: dict[str, bytes] = {}
    values: dict[str, int] = {}
    for name, address, size in cells:
        data = reader.read(address, size, f"province_discovery.header.{name}")
        raw[name] = data
        values[name] = int.from_bytes(data, "little", signed=False)

    begin, end, records = (values["array_begin"], values["array_end"], values["records_pointer"])
    if (not _province._is_user_address(begin) or not _province._is_user_address(end)
            or begin & 7 or end & 7 or end < begin):
        raise ValueError("PROVINCE_ARRAY_BOUNDS_INVALID")
    byte_length = end - begin
    if byte_length % 8:
        raise ValueError("PROVINCE_ARRAY_BOUNDS_MISALIGNED")
    count = byte_length // 8
    if type(count) is not int or not 1 < count <= MAX_PROVINCE_COUNT:
        raise ValueError("PROVINCE_COUNT_OUT_OF_RANGE")
    if (not _province._is_user_address(records) or records & 7):
        raise ValueError("PROVINCE_RECORDS_POINTER_INVALID")
    records_range = _province._checked_range(records, count * _province.RECORD_STRIDE,
                                             "province_discovery_records")
    return {
        "world_pointer": hex(world),
        "array_begin": hex(begin), "array_begin_raw_hex": raw["array_begin"].hex(),
        "array_end": hex(end), "array_end_raw_hex": raw["array_end"].hex(),
        "records_pointer": hex(records), "records_pointer_raw_hex": raw["records_pointer"].hex(),
        "count": count,
        "records_range": [hex(records_range[0]), hex(records_range[1])],
        "candidate_id_range": [1, count - 1],
        "candidate_count": max(0, count - 1),
        "domain_complete": False,
    }


def _preflight_candidates(reader: _BudgetReader, candidate_count: int,
                          pass_number: int, candidate_bytes: int = 16,
                          country_slot_count: int = _country.MAX_COUNTRY_SLOTS) -> None:
    # A candidate uses an ID echo, a discovery pointer, and one u32 word per
    # pass. v1 reserves all 4096 possible country slots. v2 may reserve the
    # observed count provisionally; the hard limiter still withdraws any scan
    # whose second-pass table growth exceeds the unchanged overall budget.
    passes_left = 2 if pass_number == 1 else 1
    candidate_calls = candidate_count * 3 * passes_left
    candidate_bytes = candidate_count * candidate_bytes * passes_left
    if type(country_slot_count) is not int or not 0 < country_slot_count <= _country.MAX_COUNTRY_SLOTS:
        raise _ReadStop('COUNTRY_RESERVE_COUNT_INVALID')
    reserve_calls = ((country_slot_count * 2) + 256) if pass_number == 1 else 0
    reserve_bytes = ((country_slot_count * 16) + 2048) if pass_number == 1 else 0
    if reader.calls + candidate_calls + reserve_calls > MAX_READ_CALLS:
        raise _ReadStop("CANDIDATE_SCAN_EXCEEDS_CALL_BUDGET")
    if reader.bytes_requested + candidate_bytes + reserve_bytes > MAX_TOTAL_READ_BYTES:
        raise _ReadStop("CANDIDATE_SCAN_EXCEEDS_BYTE_BUDGET")


def _one_pass(reader: _BudgetReader, base: int, pass_number: int,
              observer: str, *, discovery_reader=None, candidate_bytes: int = 16,
              use_observed_country_count: bool = False) -> dict[str, Any]:
    context = _owner._context(reader, base)
    world = _int_hex(context.get("world_pointer"))
    physical_raw_hex = context.get("physical_client_reference_raw_hex")
    if type(physical_raw_hex) is not str:
        raise ValueError("PHYSICAL_CLIENT_REFERENCE_MISSING")
    try:
        physical_raw = bytes.fromhex(physical_raw_hex)
    except ValueError as exc:
        raise ValueError("PHYSICAL_CLIENT_REFERENCE_INVALID") from exc
    if len(physical_raw) != 8:
        raise ValueError("PHYSICAL_CLIENT_REFERENCE_WIDTH_INVALID")
    physical_fullref = int.from_bytes(physical_raw, "little", signed=False)
    physical_tag = _country._tag_from_fullref(physical_fullref)
    if physical_tag is None:
        raise ValueError("PHYSICAL_CLIENT_TAG_INVALID")

    tags = [observer] if physical_tag == observer else [observer, physical_tag]
    scan = _country.resolve_countries(
        reader.read, base, tags, expected_refs={physical_tag: physical_fullref})
    if scan.get("status") != "observed":
        raise ValueError("COUNTRY_BINDINGS_UNAVAILABLE")
    observer_binding = _country_binding(scan, observer)
    physical_binding = _country_binding(scan, physical_tag)
    if observer_binding is None or physical_binding is None:
        raise ValueError("COUNTRY_BINDING_MISSING")
    if _int_hex(physical_binding.get("fullref")) != physical_fullref:
        raise ValueError("PHYSICAL_CLIENT_FULLREF_MISMATCH")
    observer_fullref = _int_hex(observer_binding.get("fullref"))
    observer_slot = observer_binding.get("slot")
    if type(observer_slot) is not int or not 0 <= observer_slot < _country.MAX_COUNTRY_SLOTS:
        raise ValueError("OBSERVER_SLOT_INVALID")

    admission_raw = _owner._bound_admission(reader.read, base, scan, observer, observer)
    if not isinstance(admission_raw, Mapping):
        raise ValueError("ADMISSION_RESULT_INVALID")
    admission = _admission_summary(admission_raw)
    role = admission["observer_nonplayer_role"]
    if (admission.get("status") != "known" or admission.get("admitted") is not True
            or type(admission.get("admitted")) is not bool
            or role.get("verified") is not True or type(role.get("verified")) is not bool
            or role.get("observer") != observer or role.get("slot") != observer_slot):
        return {
            "pass": pass_number, "status": "unknown", "reason": "FRA_SELF_ADMISSION_OR_ROLE_NOT_VERIFIED",
            "context": context,
            "bindings": {"observer": observer_binding, "physical_client": physical_binding},
            "admission": admission, "header": None, "candidates": [],
        }

    header = _read_header(reader, base, world)
    try:
        reserve_count = scan['count'] if use_observed_country_count else _country.MAX_COUNTRY_SLOTS
        _preflight_candidates(reader, header["candidate_count"], pass_number, candidate_bytes, reserve_count)
    except _ReadStop as exc:
        return {
            "pass": pass_number, "status": "unknown", "reason": str(exc),
            "context": {"before": context, "after": None},
            "bindings": {"observer": observer_binding, "physical_client": physical_binding},
            "admission": admission, "header": {"before": header, "after": None},
            "candidates": [],
        }
    records = _int_hex(header["records_pointer"])
    candidates: list[dict[str, Any]] = []
    for province_id in range(1, header["count"]):
        record = _province._checked_add(records, province_id * _province.RECORD_STRIDE,
                                        f"province_record:{province_id}")
        record_range = _province._checked_range(record, _province.RECORD_STRIDE,
                                                f"province_record:{province_id}")
        if (record_range[0] < int(header["records_range"][0], 16)
                or record_range[1] > int(header["records_range"][1], 16)):
            raise ValueError("PROVINCE_RECORD_OUTSIDE_INDEXED_RANGE")
        echo_address = _province._checked_add(record, _province.RECORD_ID_OFFSET,
                                              f"province_id:{province_id}")
        echo_raw = reader.read(echo_address, 4, f"province_discovery.id[{province_id}]")
        echo = int.from_bytes(echo_raw, "little", signed=True)
        if echo != province_id:
            raise ValueError(f"PROVINCE_ID_ECHO_MISMATCH:{province_id}")
        discovery = (_province_state._read_discovery(reader, record, observer_slot)
                     if discovery_reader is None else discovery_reader(reader, record, observer_slot, base))
        if discovery.get("status") != "known" or type(discovery.get("value")) is not bool:
            reason = discovery.get("reason", "PROVINCE_DISCOVERY_UNKNOWN")
            candidates.append({"province_id": province_id, "status": "unknown",
                               "reason": str(reason)[:128]})
            return {
                "pass": pass_number, "status": "unknown", "reason": "CANDIDATE_DISCOVERY_UNKNOWN",
                "context": {"before": context, "after": None},
                "bindings": {"observer": observer_binding, "physical_client": physical_binding},
                "admission": admission, "header": {"before": header, "after": None}, "candidates": candidates,
            }
        pointer_raw_hex = discovery["raw_inputs"].get("bitset_pointer_raw_hex")
        word_raw_hex = discovery["raw_inputs"].get("word_raw_hex")
        if (type(pointer_raw_hex) is not str or type(word_raw_hex) is not str):
            raise ValueError("DISCOVERY_RAW_EVIDENCE_MISSING")
        sample_digest = hashlib.sha256(
            echo_raw + bytes.fromhex(pointer_raw_hex) + bytes.fromhex(word_raw_hex)
            + bytes.fromhex(discovery['raw_inputs'].get('header_raw_hex', ''))
        ).hexdigest()
        candidates.append({"province_id": province_id, "status": "known",
                           "value": discovery["value"],
                           "sample_sha256": sample_digest})

    context_after = _owner._context(reader, base)
    header_after = _read_header(reader, base, world)
    if not _owner._same(context, context_after):
        return {
            "pass": pass_number, "status": "unknown", "reason": "CONTEXT_CHANGED_DURING_PASS",
            "context": {"before": context, "after": context_after},
            "bindings": {"observer": observer_binding, "physical_client": physical_binding},
            "admission": admission, "header": {"before": header, "after": header_after},
            "candidates": candidates,
        }
    if not _owner._same(header, header_after):
        return {
            "pass": pass_number, "status": "unknown", "reason": "HEADER_CHANGED_DURING_PASS",
            "context": {"before": context, "after": context_after},
            "bindings": {"observer": observer_binding, "physical_client": physical_binding},
            "admission": admission, "header": {"before": header, "after": header_after},
            "candidates": candidates,
        }

    return {
        "pass": pass_number, "status": "known", "reason": None,
        "context": {"before": context, "after": context_after},
        "bindings": {"observer": observer_binding, "physical_client": physical_binding},
        "admission": admission, "header": {"before": header, "after": header_after}, "candidates": candidates,
        "observer_fullref": hex(observer_fullref),
        "physical_fullref": hex(physical_fullref),
    }


def _read_two_pass(reader: Any, module_base: int, observer: str = "FRA", *,
                   discovery_reader=None, candidate_bytes: int = 16,
                   use_observed_country_count: bool = False) -> dict[str, Any]:
    """Read and compare FRA's positive discovery bits over indexed IDs.

    Countries are resolved once in each pass (FRA and the physical client),
    then FRA's established self-admission and non-player role are checked
    before any province header or record is read. A known result is limited
    to stable candidate IDs ``1..count-1`` and never claims a complete native
    domain. No province ownership, controller, resource or owner fields are
    read. The two passes are sequential samples, not an atomic snapshot.
    """
    if type(observer) is not str or observer != OBSERVER:
        return _unknown("OBSERVER_SCOPE_INVALID")
    if not callable(reader) and not callable(getattr(reader, "read", None)):
        return _unknown("READER_NOT_CALLABLE")
    if (type(module_base) is not int or not MIN_USER_ADDRESS <= module_base < MAX_USER_ADDRESS_EXCLUSIVE
            or module_base & 7):
        return _unknown("MODULE_BASE_INVALID")
    budget = _BudgetReader(reader)
    passes: list[dict[str, Any]] = []
    try:
        for pass_number in (1, 2):
            current = _one_pass(budget, module_base, pass_number, observer,
                                discovery_reader=discovery_reader, candidate_bytes=candidate_bytes,
                                use_observed_country_count=use_observed_country_count)
            passes.append(current)
            if current.get("status") != "known":
                return _unknown(current.get("reason", "PASS_UNKNOWN"), passes=passes, budget=budget)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, (_ReadStop, ValueError)) else type(exc).__name__
        return _unknown(reason[:160], passes=passes, budget=budget)

    shared_keys = ("context", "bindings", "admission", "header", "candidates",
                   "observer_fullref", "physical_fullref")
    changed = [key for key in shared_keys
               if not _owner._same(passes[0].get(key), passes[1].get(key))]
    if changed:
        result = _unknown("TWO_PASS_EVIDENCE_CHANGED", passes=passes, budget=budget)
        result["consistency"] = {"status": "changed", "changed_components": changed}
        return result
    positive_ids = [item["province_id"] for item in passes[1]["candidates"]
                    if item["value"] is True]
    return {
        "schema": SCHEMA,
        "status": "known",
        "basis": "stable_fra_discovery_bits_for_indexed_positive_id_candidates",
        "observer": OBSERVER,
        "value": positive_ids,
        "scope": {"province_ids": "1..count-1",
                  "candidate_count": passes[1]["header"]["before"]["candidate_count"],
                  "domain_complete": False, "province_zero_semantics": "unknown"},
        "complete": False,
        "domain_complete": False,
        "consistency": {"status": "stable", "changed_components": []},
        "passes": passes,
        "limitations": ["indexed-positive-ids-only", "province-zero-semantics-unknown",
                        "native-domain-completeness-unproven", "two-pass-observation-not-atomic"],
        "budget": budget.summary(),
    }


def read_two_pass(reader: Any, module_base: int, observer: str = "FRA") -> dict[str, Any]:
    """Retain the original v1 positive-candidate contract and read budgets."""
    return _read_two_pass(reader, module_base, observer)


__all__ = ["SCHEMA", "read_two_pass", "MAX_READ_CALLS", "MAX_TOTAL_READ_BYTES",
           "MAX_SINGLE_READ_BYTES"]
