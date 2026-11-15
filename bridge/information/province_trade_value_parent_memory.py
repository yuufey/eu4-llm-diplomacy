"""Compose the owner-scoped province trade-value child on a validated parent.

The parent owns the read handle, canonical province/discovery evidence and
controller bindings. This extension reuses that evidence and its one bounded
reader; it does not scan the country table again.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from . import foreign_country_memory as _shared
from . import province_trade_power_country_memory as _country


FIELD = "G02.province_trade_value_calculation"
_PHASES = ("pass1", "pass2")
_OWNER_SHARED_REBIND_ERRORS = {
    "COUNTRY_SCAN_UNVERIFIED",
    "COUNTRY_SCAN_METADATA_CHANGED",
    "COUNTRY_SCAN_ROW_MISSING",
    "COUNTRY_SCAN_ROW_CHANGED",
    "COUNTRY_SCAN_REFERENCE_CHANGED",
    "COUNTRY_SCAN_DUPLICATE_TAG",
    "COUNTRY_BINDING_CHANGED",
}


def _unknown(reason: str) -> dict:
    return {"status": "unknown", "complete": False, "period": "current",
            "reason": reason}


def _pointer(value):
    if type(value) is int:
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError("PROVINCE_TRADE_VALUE_POINTER_INVALID")


def _admission_for(limiter, base, scan, binding, *, label):
    rebound = _country._rebind(
        limiter, base, scan, bytes.fromhex(binding["fullref_raw_hex"]), label)
    _country._require(_shared._same_raw(rebound, binding), "COUNTRY_BINDING_CHANGED")
    gate = _country._admit(limiter, base, scan, rebound)
    return rebound, gate


def _owner_has_unique_retained_row(scan, raw_ref):
    if not isinstance(scan, Mapping) or scan.get("status") != "observed" or len(raw_ref) != 8:
        return False
    fullref = int.from_bytes(raw_ref, "little", signed=False)
    low = (fullref & 0xFFFFFFFF).to_bytes(4, "little")
    if ((fullref >> 56) == 0 or ((fullref >> 48) & 0xFF) == 7 or low[3] != 0
            or not all(0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A for byte in low[:3])):
        return False
    tag = low[:3].decode("ascii")
    slot = (fullref >> 32) & 0xFFFF
    rows = scan.get("rows")
    if not isinstance(rows, list):
        return False
    exact = [row for row in rows if isinstance(row, Mapping)
             and row.get("tag") == tag and type(row.get("slot")) is int
             and row.get("slot") == slot
             and isinstance(row.get("fullref_raw_hex"), str)
             and row["fullref_raw_hex"].lower() == raw_ref.hex()
             and row.get("fullref") == hex(fullref)]
    return len(exact) == 1


def _shared_snapshot(limiter, base, province_id, anchor, countries):
    province = _country._province
    _country._require(isinstance(anchor, Mapping), "PROVINCE_ANCHOR_MISSING")
    _country._require(isinstance(countries, Mapping), "COUNTRY_ANCHOR_MISSING")
    scan = anchor.get("country_scan")
    binding = anchor.get("province_binding")
    country_bindings = countries.get("bindings")
    parent_gates = countries.get("admission_before")
    _country._require(isinstance(scan, Mapping) and scan.get("status") == "observed",
                      "COUNTRY_SCAN_UNVERIFIED")
    _country._require(isinstance(binding, Mapping)
                      and binding.get("province_id") == province_id,
                      "PROVINCE_BINDING_UNVERIFIED")
    _country._require(isinstance(country_bindings, Mapping)
                      and isinstance(parent_gates, Mapping), "COUNTRY_ANCHOR_MISSING")
    observer = country_bindings.get("observer")
    controller = country_bindings.get("controller")
    _country._require(isinstance(observer, Mapping) and observer.get("tag") == "FRA",
                      "OBSERVER_BINDING_UNVERIFIED")
    _country._require(isinstance(controller, Mapping), "CONTROLLER_BINDING_UNVERIFIED")
    _country._require(_country._allowed(parent_gates.get("observer", {})),
                      "OBSERVER_ADMISSION_UNVERIFIED")

    record = _pointer(binding.get("record_pointer"))
    fresh_province = province._province.resolve_provinces(limiter, base, [province_id])
    _country._require(_shared._same_raw(fresh_province, anchor.get("province_scan")),
                      "PROVINCE_BINDING_CHANGED")
    discovery = province._read_discovery(limiter, record, observer["slot"])
    _country._require(_shared._same_raw(discovery, anchor.get("discovery"))
                      and discovery.get("status") == "known"
                      and discovery.get("value") is True,
                      "PROVINCE_DISCOVERY_CHANGED")

    observer_binding, observer_gate = _admission_for(
        limiter, base, scan, observer, label="province_trade_value.observer")
    _country._require(_country._allowed(observer_gate), "OBSERVER_ADMISSION_CHANGED")
    _country._require(observer_gate.get("observer_nonplayer_role", {}).get("verified") is True,
                      "OBSERVER_ROLE_NOT_VERIFIED")
    _country._require(_shared._same_raw(observer_gate, anchor.get("admission"))
                      and _shared._same_raw(observer_gate, parent_gates.get("observer")),
                      "OBSERVER_ADMISSION_CHANGED")

    controller_ref = limiter.read(
        record + province.CONTROLLER_FULLREF_OFFSET, 8,
        "province_trade_value.controller_ref")
    _country._require(controller_ref.hex() == controller.get("fullref_raw_hex"),
                      "CONTROLLER_REFERENCE_CHANGED")
    retained_controller_ref = countries.get("controller_ref_raw_hex")
    if retained_controller_ref is not None:
        _country._require(controller_ref.hex() == retained_controller_ref,
                          "CONTROLLER_REFERENCE_CHANGED")
    controller_binding, controller_gate = _admission_for(
        limiter, base, scan, controller, label="province_trade_value.controller")
    _country._require(_shared._same_raw(controller_gate, parent_gates.get("controller")),
                      "CONTROLLER_ADMISSION_CHANGED")

    owner_ref = limiter.read(
        record + province.OWNER_FULLREF_OFFSET, 8,
        "province_trade_value.owner_ref")
    owner_binding = None
    owner_gate = {"status": "unknown", "admitted": None,
                  "reason": "OWNER_BINDING_UNVERIFIED"}
    owner_error = None
    owner_row_retained = _owner_has_unique_retained_row(scan, owner_ref)
    try:
        owner_binding = _country._rebind(
            limiter, base, scan, owner_ref, "province_trade_value.owner")
        _country._require(owner_binding.get("status") != "unknown",
                          "OWNER_BINDING_UNVERIFIED")
    except _country._ObserverFailure:
        raise
    except Exception as exc:
        reason = str(exc).split(":", 1)[0]
        if reason in _OWNER_SHARED_REBIND_ERRORS or owner_row_retained:
            raise ValueError("OWNER_CANONICAL_BINDING_CHANGED") from None
        owner_binding = None
        owner_error = type(exc).__name__
    if owner_binding is not None:
        try:
            owner_gate = _country._admit(limiter, base, scan, owner_binding)
        except _country._ObserverFailure:
            raise
        except Exception as exc:
            owner_binding = None
            owner_gate = {"status": "unknown", "admitted": None,
                          "reason": "OWNER_ADMISSION_UNVERIFIED"}
            owner_error = type(exc).__name__

    return {
        "province_scan": fresh_province,
        "discovery": discovery,
        "observer": {"binding": observer_binding, "admission": observer_gate},
        "controller": {"binding": controller_binding, "admission": controller_gate,
                       "reference_raw_hex": controller_ref.hex()},
        "owner": {"binding": owner_binding, "admission": owner_gate,
                  "reference_raw_hex": owner_ref.hex(), "error_type": owner_error},
    }


def _round(limiter, base, province_id, anchor, countries, read_fields):
    evidence = {"shared_valid": False, "field": _unknown("PROVINCE_TRADE_VALUE_UNVERIFIED")}
    try:
        before = _shared_snapshot(limiter, base, province_id, anchor, countries)
        owner = before["owner"]
        if owner["binding"] is not None and _country._allowed(owner["admission"]):
            try:
                raw = read_fields(
                    limiter, base, anchor["province_binding"], anchor["province_scan"],
                    before["observer"]["binding"], owner["binding"])
                normalized = _country._province._normalize_field_results(raw, (FIELD,))
                evidence["field"] = normalized[FIELD]
            except Exception:
                evidence["field"] = _unknown("PROVINCE_TRADE_VALUE_FIELD_READ_FAILED")
        else:
            evidence["field"] = _unknown("OWNER_ADMISSION_NOT_ESTABLISHED")

        # Always repeat shared identity, both role checks and both owner refs,
        # even when the owner gate denied access or the private leaf failed.
        after = _shared_snapshot(limiter, base, province_id, anchor, countries)
        _country._require(_shared._same_raw(before, after),
                          "PROVINCE_TRADE_VALUE_SHARED_EVIDENCE_CHANGED")
        evidence.update(shared_valid=True, before=before, after=after,
                        bindings={role: deepcopy(before[role]["binding"])
                                  for role in ("observer", "controller", "owner")},
                        admissions={role: deepcopy(before[role]["admission"])
                                    for role in ("observer", "controller", "owner")})
    except _country._ObserverFailure:
        evidence["field"] = _unknown("OBSERVER_ROLE_NOT_VERIFIED")
    except Exception:
        evidence["field"] = _unknown("PROVINCE_TRADE_VALUE_SHARED_EVIDENCE_UNVERIFIED")
    return evidence


def _retract(result, target, reason):
    result["status"] = "unknown"
    result["consistency"] = {"status": "unknown", "shared_mismatch_paths": ["province_trade_value"]}
    for field in list(target.get("fields", {})):
        target["fields"][field] = _unknown(reason)
        target.setdefault("field_consistency", {})[field] = {"status": "unknown"}


def extend(reader, base, province_id, *, observer="FRA", parent_reader, read_fields):
    """Append the owner-scoped value leaf to one active two-pass G02 parent."""
    if (observer != "FRA" or type(province_id) is not int or not 1 <= province_id <= 0xFFFF
            or not callable(parent_reader) or not callable(read_fields)):
        raise ValueError("PROVINCE_TRADE_VALUE_PARENT_SCOPE_INVALID")
    limiter = _shared._BoundedReader(_country._province._ReaderAdapter(reader))
    result = parent_reader(limiter, base, province_id, observer=observer)
    targets = result.get("targets") if isinstance(result, Mapping) else None
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], Mapping):
        raise ValueError("PROVINCE_TRADE_VALUE_PARENT_RESULT_INVALID")
    target = targets[0]
    if target.get("province_id") != province_id:
        raise ValueError("PROVINCE_TRADE_VALUE_PARENT_BINDING_INVALID")
    target.setdefault("fields", {})
    target.setdefault("field_consistency", {})
    if FIELD in target["fields"]:
        raise ValueError("PROVINCE_TRADE_VALUE_DUPLICATE_FIELD")
    target["fields"][FIELD] = _unknown("PROVINCE_TRADE_VALUE_PARENT_UNVERIFIED")
    target["field_consistency"][FIELD] = {"status": "unknown"}

    if (result.get("status") != "observed"
            or result.get("consistency", {}).get("status") != "stable"):
        result["budget"] = limiter.summary()
        return result

    parent_fields = target["fields"]
    if target.get("field_consistency", {}).get(_country.CONTROLLER_FIELD, {}).get("status") == "changed":
        _retract(result, target, "PROVINCE_TRADE_VALUE_SHARED_EVIDENCE_UNVERIFIED")
        result["budget"] = limiter.summary()
        return result

    anchors = result.get("pass_evidence")
    country_rounds = result.get("country_inputs_evidence")
    ready = (isinstance(anchors, Mapping) and isinstance(country_rounds, Mapping)
             and all(isinstance(anchors.get(p), Mapping)
                     and isinstance(country_rounds.get(p), Mapping)
                     and country_rounds[p].get("shared_valid") is True
                     and isinstance(country_rounds[p].get("bindings", {}).get("observer"), Mapping)
                     and isinstance(country_rounds[p].get("bindings", {}).get("controller"), Mapping)
                     and _country._allowed(country_rounds[p].get("admission_before", {}).get("observer", {}))
                     for p in _PHASES))
    if not ready:
        result["budget"] = limiter.summary()
        return result

    rounds = {
        phase: _round(limiter, base, province_id, anchors[phase], country_rounds[phase], read_fields)
        for phase in _PHASES
    }
    result.setdefault("province_trade_value_evidence", {})[FIELD] = rounds
    result["budget"] = limiter.summary()
    result.setdefault("errors", []).extend(limiter.errors)

    if not all(rounds[p].get("shared_valid") is True for p in _PHASES):
        _retract(result, target, "PROVINCE_TRADE_VALUE_SHARED_EVIDENCE_UNVERIFIED")
        return result

    first, second = (rounds[p]["field"] for p in _PHASES)
    if not _shared._same_raw(first, second):
        target["fields"][FIELD] = _unknown("PROVINCE_TRADE_VALUE_CHANGED_BETWEEN_PASSES")
        target["field_consistency"][FIELD] = {"status": "changed"}
    else:
        target["fields"][FIELD] = deepcopy(second)
        target["field_consistency"][FIELD] = {
            "status": "stable" if second.get("status") == "known" else "unknown"}
    return result


__all__ = ["FIELD", "extend"]
