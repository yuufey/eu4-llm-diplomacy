"""Shared bounded country binding, admission and field reads; no process or UI claims."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_reference_memory

SCHEMA = "information.foreign_country_memory.v1"
MAX_TARGETS = 8
MAX_FIELDS = 16
MAX_FIELD_ID_LENGTH = 128
MAX_TOTAL_READ_BYTES = 512 * 1024
MAX_SINGLE_READ_BYTES = 65_536
MAX_READ_CALLS = 32_768
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000


class _BoundedReader:
    """Callable and .read-compatible wrapper shared by both passes."""
    def __init__(self, source: Any):
        self.source = source
        self.calls = self.requested = self.returned = self.rejected = self.max_single = 0
        self.errors: list[dict[str, Any]] = []

    def __call__(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def read(self, address: int, size: int, label: str) -> bytes:
        valid = (type(address) is int and MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
                 and type(size) is int and 0 < size <= MAX_SINGLE_READ_BYTES
                 and address <= MAX_USER_ADDRESS_EXCLUSIVE - size
                 and isinstance(label, str) and bool(label))
        if not valid:
            self.rejected += size if type(size) is int and size > 0 else 0
            raise ValueError("read_request_invalid")
        if self.requested + size > MAX_TOTAL_READ_BYTES or self.calls >= MAX_READ_CALLS:
            self.rejected += size
            code = "read_budget_exceeded" if self.requested + size > MAX_TOTAL_READ_BYTES else "read_call_budget_exceeded"
            self.errors.append({"code": code, "label": label, "requested_size": size})
            raise ValueError(code)
        self.calls += 1
        self.requested += size
        self.max_single = max(self.max_single, size)
        try:
            method = getattr(self.source, "read", None)
            if not callable(method):
                raise TypeError("reader_read_method_missing")
            raw = method(address, size, label)
        except Exception as exc:
            code = "reader_read_method_missing" if isinstance(exc, TypeError) and str(exc) == "reader_read_method_missing" else "reader_read_failed"
            self.errors.append({"code": code, "label": label, "error_type": type(exc).__name__})
            raise ValueError(f"{code}:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            self.errors.append({"code": "reader_read_invalid_type", "label": label})
            raise ValueError(f"reader_read_invalid_type:{label}")
        raw = bytes(raw)
        self.returned += len(raw)
        if len(raw) != size:
            self.errors.append({"code": "reader_short_read", "label": label,
                                "expected": size, "actual": len(raw)})
            raise ValueError(f"reader_short_read:{label}")
        return raw

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.requested,
                "bytes_returned": self.returned, "rejected_bytes": self.rejected,
                "max_single_read": self.max_single, "max_calls": MAX_READ_CALLS,
                "limit_bytes": MAX_TOTAL_READ_BYTES,
                "limit_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _tag_ok(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 3
            and all("A" <= c <= "Z" or "0" <= c <= "9" for c in value))


def _same_raw(left: Any, right: Any) -> bool:
    """Compare copied records strictly; for example bool is not integer 1."""
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return (set(left) == set(right)
                and all(_same_raw(left[key], right[key]) for key in left))
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(_same_raw(a, b) for a, b in zip(left, right))
    return left == right


def _base_result(observer: Any, targets: list[Any], fields: list[Any]) -> dict[str, Any]:
    field_ids = list(dict.fromkeys(x for x in fields if isinstance(x, str)))[:MAX_FIELDS]
    return {
        "schema": SCHEMA, "status": "unknown",
        "observer": {"tag": observer if _tag_ok(observer) else None, "fullref": None,
                     "binding_status": "unknown", "bindings_by_pass": {"pass1": None, "pass2": None}},
        "targets": [{
            "tag": tag if _tag_ok(tag) else None, "fullref": None, "binding_status": "unknown",
            "bindings_by_pass": {"pass1": None, "pass2": None},
            "admission_by_pass": {"pass1": None, "pass2": None},
            "fields": {field: {"status": "unknown", "reason": "not_read"} for field in field_ids},
            "field_consistency": {field: {"status": "unknown", "reason": "not_read"} for field in field_ids},
        } for tag in targets[:MAX_TARGETS + 1]],
        "pass_evidence": {"pass1": None, "pass2": None},
        "consistency": {"status": "unknown", "shared_mismatch_paths": []},
        "budget": {"calls": 0, "bytes_requested": 0, "bytes_returned": 0,
                    "rejected_bytes": 0, "max_single_read": 0, "max_calls": MAX_READ_CALLS,
                    "limit_bytes": MAX_TOTAL_READ_BYTES,
                    "limit_single_read_bytes": MAX_SINGLE_READ_BYTES},
        "visibility": {"status": "unknown", "reason": "FOREIGN_VISIBILITY_NOT_PROVEN"},
        "public_export_ready": False, "complete": False, "errors": [],
    }


def _normalize(observer: Any, targets: Any, fields: Any, expected_refs: Any):
    if not _tag_ok(observer):
        return None, None, None, "observer_tag_invalid"
    if not isinstance(targets, (list, tuple)) or len(targets) > MAX_TARGETS:
        return None, None, None, "targets_shape_or_count_invalid"
    tags: list[str] = []
    for tag in targets:
        if not _tag_ok(tag):
            return None, None, None, "target_tag_invalid"
        if tag in tags:
            return None, None, None, f"duplicate_target:{tag}"
        tags.append(tag)
    if not isinstance(fields, (list, tuple)) or not 1 <= len(fields) <= MAX_FIELDS:
        return None, None, None, "fields_shape_or_count_invalid"
    field_ids: list[str] = []
    for field in fields:
        if (not isinstance(field, str) or not field or len(field) > MAX_FIELD_ID_LENGTH
                or "\x00" in field):
            return None, None, None, "field_id_invalid"
        if field in field_ids:
            return None, None, None, f"duplicate_field:{field}"
        field_ids.append(field)
    if expected_refs is not None and not isinstance(expected_refs, Mapping):
        return None, None, None, "expected_refs_shape_invalid"
    allowed = {observer, *tags}
    if expected_refs is not None and len(expected_refs) > len(allowed):
        return None, None, None, "expected_refs_count_invalid"
    expected = dict(expected_refs or {})
    if any(tag not in allowed for tag in expected):
        return None, None, None, "expected_ref_tag_not_requested"
    return tags, field_ids, expected, None


def _binding(scan: Any, tag: str) -> dict[str, Any] | None:
    requested = scan.get("requested") if isinstance(scan, Mapping) else None
    item = requested.get(tag) if isinstance(requested, Mapping) else None
    return deepcopy(dict(item)) if isinstance(item, Mapping) else None


def _read_pass(number: int, limiter: _BoundedReader, base: int, observer: str,
               targets: list[str], fields: list[str], expected: dict[str, Any],
               admission_reader: Any, read_fields: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {"pass": number, "status": "unknown", "country_scan": None,
                                "bindings_by_tag": {}, "admission_by_tag": {},
                                "fields_raw_by_tag": {}, "errors": []}
    tags = list(dict.fromkeys([observer, *targets]))
    try:
        scan = country_reference_memory.resolve_countries(
            limiter.read, base, tags, expected_refs=expected)
    except Exception as exc:
        evidence["errors"].append({"code": "country_resolution_failed",
                                   "detail": f"{type(exc).__name__}:{exc}"})
        return evidence
    evidence["country_scan"] = scan
    evidence["bindings_by_tag"] = {tag: _binding(scan, tag) for tag in tags}
    if any(value is None for value in evidence["bindings_by_tag"].values()):
        evidence["errors"].append({"code": "country_binding_missing"})
        return evidence
    for target in targets:
        try:
            gate = admission_reader(limiter.read, base, scan, observer, target)
            if not isinstance(gate, Mapping):
                raise TypeError("admission_result_not_mapping")
            gate = deepcopy(dict(gate))
            if gate.get("status") != "known" or type(gate.get("admitted")) is not bool:
                if gate.get("status") == "known":
                    gate = {**gate, "status": "unknown", "reason": "admission_boolean_invalid"}
        except Exception as exc:
            gate = {"status": "unknown", "admitted": None,
                    "reason": f"admission_reader_failed:{type(exc).__name__}"}
            evidence["errors"].append({"code": "admission_reader_failed", "tag": target,
                                       "detail": f"{type(exc).__name__}:{exc}"})
        evidence["admission_by_tag"][target] = gate
        if gate.get("status") != "known" or gate.get("admitted") is not True:
            evidence["fields_raw_by_tag"][target] = None
            continue
        try:
            values = read_fields(limiter, base, evidence["bindings_by_tag"][target], tuple(fields))
            if not isinstance(values, Mapping):
                raise TypeError("field_collector_result_not_mapping")
            evidence["fields_raw_by_tag"][target] = deepcopy(dict(values))
        except Exception as exc:
            evidence["fields_raw_by_tag"][target] = {
                "__collector_error__": {"type": type(exc).__name__, "detail": str(exc)}}
            evidence["errors"].append({"code": "field_collector_failed", "tag": target,
                                       "detail": f"{type(exc).__name__}:{exc}"})
    evidence["status"] = "observed"
    return evidence


def read_two_pass(reader: Any, module_base: int, observer: str,
                  targets: list[str] | tuple[str, ...],
                  fields: list[str] | tuple[str, ...], *, read_fields: Any,
                  admission_reader: Any,
                  expected_refs: Mapping[str, int | str] | None = None) -> dict[str, Any]:
    """Read shared identity/gates twice, retaining stable fields independently.

    `read_fields(limiter, base, target_binding, tuple(fields))` is trusted
    application code, called only for a known admitted target. It may use
    `limiter.read` or the callable limiter. A stable identity/gate scan yields
    top-level `observed`, while individual fields remain unknown unless their
    full raw dictionaries match and both carry `status=known` plus `value`.
    """
    raw_targets = list(targets[:MAX_TARGETS + 1]) if isinstance(targets, (list, tuple)) else []
    raw_fields = list(fields[:MAX_FIELDS + 1]) if isinstance(fields, (list, tuple)) else []
    result = _base_result(observer, raw_targets, raw_fields)
    tags, field_ids, expected, invalid = _normalize(observer, targets, fields, expected_refs)
    if invalid:
        result["errors"].append({"code": "invalid_request", "detail": invalid})
        return result
    if not callable(getattr(reader, "read", None)):
        result["errors"].append({"code": "reader_read_method_missing"})
        return result
    if not callable(read_fields) or not callable(admission_reader):
        result["errors"].append({"code": "trusted_callback_not_callable"})
        return result
    if (type(module_base) is not int or not MIN_USER_ADDRESS <= module_base < MAX_USER_ADDRESS_EXCLUSIVE
            or module_base & 7):
        result["errors"].append({"code": "module_base_invalid"})
        return result
    assert tags is not None and field_ids is not None and expected is not None
    result = _base_result(observer, tags, field_ids)
    limiter = _BoundedReader(reader)
    passes = [_read_pass(index, limiter, module_base, observer, tags, field_ids,
                         expected, admission_reader, read_fields)
              for index in (1, 2)]
    result["pass_evidence"] = {f"pass{x['pass']}": x for x in passes}
    result["budget"] = limiter.summary()
    result["errors"] = [*limiter.errors, *(error for item in passes for error in item["errors"])]

    shared_mismatches: list[str] = []
    if any(item["status"] != "observed" for item in passes):
        shared_mismatches.append("pass_evidence.country_scan")
    else:
        if not _same_raw(passes[0]["country_scan"], passes[1]["country_scan"]):
            shared_mismatches.append("country_scan")
        for tag in tags:
            if not _same_raw(passes[0]["admission_by_tag"].get(tag),
                             passes[1]["admission_by_tag"].get(tag)):
                shared_mismatches.append(f"admission_by_tag.{tag}")

    if shared_mismatches:
        result["consistency"] = {
            "status": "changed" if all(p["status"] == "observed" for p in passes) else "unknown",
            "shared_mismatch_paths": shared_mismatches,
        }
        result["errors"].append({"code": "shared_evidence_not_stable", "paths": shared_mismatches})
        for target_result in result["targets"]:
            tag = target_result["tag"]
            target_result["bindings_by_pass"] = {
                f"pass{p['pass']}": _binding(p["country_scan"], tag) for p in passes}
            target_result["admission_by_pass"] = {
                f"pass{p['pass']}": p["admission_by_tag"].get(tag) for p in passes}
            for field in field_ids:
                target_result["fields"][field] = {"status": "unknown", "reason": "shared_evidence_changed"}
                target_result["field_consistency"][field] = {"status": "unknown", "reason": "shared_evidence_changed"}
        result["observer"]["bindings_by_pass"] = {
            f"pass{p['pass']}": _binding(p["country_scan"], observer) for p in passes}
        return result

    result["status"] = "observed"
    result["consistency"] = {"status": "stable", "shared_mismatch_paths": []}
    result["observer"].update({
        "binding_status": "observed",
        "bindings_by_pass": {f"pass{p['pass']}": _binding(p["country_scan"], observer) for p in passes},
        "fullref": _binding(passes[1]["country_scan"], observer)["fullref"],
    })
    for item in result["targets"]:
        tag = item["tag"]
        binding1, binding2 = (_binding(p["country_scan"], tag) for p in passes)
        gate1, gate2 = (p["admission_by_tag"].get(tag) for p in passes)
        raw1, raw2 = (p["fields_raw_by_tag"].get(tag) for p in passes)
        item.update({"binding_status": "observed", "fullref": binding2["fullref"],
                     "bindings_by_pass": {"pass1": binding1, "pass2": binding2},
                     "admission_by_pass": {"pass1": deepcopy(gate1), "pass2": deepcopy(gate2)}})
        gate_known = (isinstance(gate1, Mapping) and isinstance(gate2, Mapping)
                      and gate1.get("status") == gate2.get("status") == "known"
                      and type(gate1.get("admitted")) is bool and type(gate2.get("admitted")) is bool)
        for field in field_ids:
            if gate_known and gate1["admitted"] is False and gate2["admitted"] is False:
                item["fields"][field] = {"status": "invisible", "reason": "admission_denied"}
                item["field_consistency"][field] = {"status": "invisible", "reason": "admission_denied"}
                continue
            if not gate_known or gate1["admitted"] is not True or gate2["admitted"] is not True:
                item["fields"][field] = {"status": "unknown", "reason": "admission_unknown"}
                item["field_consistency"][field] = {"status": "unknown", "reason": "admission_unknown"}
                continue
            first = raw1.get(field) if isinstance(raw1, Mapping) else None
            second = raw2.get(field) if isinstance(raw2, Mapping) else None
            if not _same_raw(first, second):
                item["fields"][field] = {"status": "unknown", "reason": "field_raw_data_changed"}
                item["field_consistency"][field] = {"status": "changed"}
            elif (isinstance(second, Mapping) and second.get("status") == "known"
                  and "value" in second):
                item["fields"][field] = deepcopy(dict(second))
                item["field_consistency"][field] = {"status": "stable"}
            elif isinstance(second, Mapping) and second.get("status") == "unknown":
                item["fields"][field] = deepcopy(dict(second))
                item["field_consistency"][field] = {
                    "status": "unknown", "reason": second.get("reason", "collector_unknown")}
            else:
                item["fields"][field] = {"status": "unknown", "reason": "field_missing_or_invalid"}
                item["field_consistency"][field] = {"status": "unknown", "reason": "field_missing_or_invalid"}
    return result


__all__ = ["SCHEMA", "MAX_TARGETS", "MAX_FIELDS", "MAX_TOTAL_READ_BYTES",
           "MAX_SINGLE_READ_BYTES", "MAX_READ_CALLS", "read_two_pass"]
