"""Private permission-gated F03 adapter for FRA's bilateral subsidies pair.

This adapter binds the selected pair to FRA's own fiscal relation rows. The
logical observer is FRA even when the physical client country is POR. A known
permission proves the selected pair's live bindings and capture date; it does
not prove actual UI rendering, target visibility, payment, or completeness.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import bilateral_subsidies_memory as _leaf
from . import foreign_quality_visibility_memory as _common


FIELD = "F03.observer_subsidies"
FIELDS = (FIELD,)
SCHEMA = "information.observer_subsidies_memory.v1"
BASIS = "private_native_fra_own_fiscal_subsidy_pair"
SCOPE = "observer_fiscal_bilateral_subsidies"
EXPECTED_EXE_SHA256 = _leaf.EXPECTED_EXE_SHA256
PREFERRED_IMAGE_BASE = _leaf.PREFERRED_IMAGE_BASE
WORLD_GLOBAL_RVA = _common.WORLD_GLOBAL_RVA
WORLD_DATE_OFFSET = 0x1DD0

MAX_READ_CALLS = _common.MAX_READ_CALLS
MAX_TOTAL_READ_BYTES = _common.MAX_TOTAL_READ_BYTES
MAX_SINGLE_READ_BYTES = _common.MAX_SINGLE_READ_BYTES
MIN_USER_ADDRESS = _common.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _common.MAX_USER_ADDRESS_EXCLUSIVE
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_SCOPE_EVIDENCE = {
    "executable_sha256": EXPECTED_EXE_SHA256,
    "relation_leaf_schema": _leaf.SCHEMA,
    "relation_leaf_basis": _leaf.BASIS,
    "scope_limit": "selected_pair_in_fra_own_fiscal_relation_rows",
    "logical_observer": "FRA",
    "physical_client_country_is_not_inferred": True,
    "does_not_establish": [
        "target_country_complete_contracts",
        "target_country_view_visibility",
        "actual_UI_rendering",
        "active_payment_obligation_or_payment",
        "term_legality",
    ],
}


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _json_value(value: Any) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is list:
        return all(_json_value(item) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _json_value(item)
                   for key, item in value.items())
    return False


def _json_binding(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    try:
        copied = dict(value)
    except Exception:
        return None
    return deepcopy(copied) if _json_value(copied) else None


def _strict_equal(left: Any, right: Any) -> bool:
    """Compare JSON values recursively without treating bool as int."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys()
                and all(_strict_equal(left[key], right[key]) for key in left))
    if type(left) is list:
        return (len(left) == len(right)
                and all(_strict_equal(a, b) for a, b in zip(left, right)))
    if left is None or type(left) in (str, bool, int):
        return left == right
    return False


def _binding_label(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "tag": binding["tag"],
        "slot": binding["slot"],
        "country_pointer": hex(binding["country_pointer"]),
        "fullref": hex(binding["fullref"]),
        "fullref_raw_hex": binding["fullref_raw_hex"],
    }


def _read_pair_row_binding(trace: Any, subject: Mapping[str, Any],
                           other: Mapping[str, Any], label: str) -> dict[str, Any]:
    """Read and validate one selected pair row without entering its vector."""
    rows_cell = _common._checked_add(
        subject["country_pointer"], _leaf.SUBSIDY_RELATION_ROWS_OFFSET, 8)
    rows_pointer = _common._pointer(
        trace.u64(rows_cell, f"permission.pair.{label}.rows_pointer"),
        f"{label.upper()}_ROWS")
    row_address = _common._checked_add(
        rows_pointer, other["slot"] * _leaf.SUBSIDY_ROW_STRIDE,
        _leaf.SUBSIDY_ROW_SIZE)
    raw_row = trace.exact(row_address, _leaf.SUBSIDY_ROW_SIZE,
                          f"permission.pair.{label}.row")
    owner = int.from_bytes(
        raw_row[_leaf.SUBSIDY_ROW_OWNER_OFFSET:
                _leaf.SUBSIDY_ROW_OWNER_OFFSET + 8], "little", signed=False)
    self_fullref = int.from_bytes(
        raw_row[_leaf.SUBSIDY_ROW_SELF_FULLREF_OFFSET:
                _leaf.SUBSIDY_ROW_SELF_FULLREF_OFFSET + 8], "little", signed=False)
    other_fullref = int.from_bytes(
        raw_row[_leaf.SUBSIDY_ROW_OTHER_FULLREF_OFFSET:
                _leaf.SUBSIDY_ROW_OTHER_FULLREF_OFFSET + 8], "little", signed=False)
    expected_owner = _common._checked_add(
        subject["country_pointer"], _leaf.SUBSIDY_ROW_OWNER_COUNTRY_OFFSET, 1)
    trace.reads[-1].update({
        "decode": "subsidy_pair_row_binding",
        "owner": hex(owner),
        "self_fullref": hex(self_fullref),
        "other_fullref": hex(other_fullref),
        "expected_owner": hex(expected_owner),
        "expected_self_fullref": hex(subject["fullref"]),
        "expected_other_fullref": hex(other["fullref"]),
    })
    if owner != expected_owner:
        raise _Unknown(f"{label.upper()}_PAIR_ROW_OWNER_MISMATCH")
    if self_fullref != subject["fullref"] or other_fullref != other["fullref"]:
        raise _Unknown(f"{label.upper()}_PAIR_ROW_FULLREF_MISMATCH")
    return {
        "label": label,
        "rows_pointer_cell": hex(rows_cell),
        "rows_pointer": hex(rows_pointer),
        "row_address": hex(row_address),
        "owner": hex(owner),
        "expected_owner": hex(expected_owner),
        "self_fullref": hex(self_fullref),
        "other_fullref": hex(other_fullref),
        "status": "known",
    }


def _permission_template(module_base: Any, observer_binding: Any,
                         target_binding: Any) -> dict[str, Any]:
    safe_observer = _json_binding(observer_binding)
    safe_target = _json_binding(target_binding)
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "admitted": None,
        "reason": None,
        "basis": BASIS,
        "scope": SCOPE,
        "observer": None,
        "target": None,
        "partial": True,
        "complete": False,
        "actual_UI_observed": False,
        "rendering_observed": False,
        "raw_inputs": {
            "request": {
                "module_base": module_base if _json_value(module_base) else None,
                "observer_binding": safe_observer,
                "target_binding": safe_target,
            },
            "scope_evidence": deepcopy(_SCOPE_EVIDENCE),
            "country_database_binding": None,
            "pair_row_bindings": None,
            "world": None,
            "ordered_read_trace": [],
            "read_budget": {
                "calls": 0,
                "bytes_requested": 0,
                "max_calls": MAX_READ_CALLS,
                "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            },
        },
    }


def read_permission(reader: Any, module_base: Any, observer_binding: Any,
                    target_binding: Any, *, logical_observer="FRA") -> dict[str, Any]:
    """Bind FRA and one other country to own-fiscal rows and one live date."""
    result = _permission_template(module_base, observer_binding, target_binding)
    raw = result["raw_inputs"]
    request = raw["request"]
    if logical_observer != "FRA":
        request["logical_observer"] = logical_observer
        raw["scope_evidence"]["logical_observer"] = logical_observer
        raw["scope_evidence"]["scope_limit"] = "selected_pair_in_bound_observer_fiscal_rows"
    if request["observer_binding"] is None or request["target_binding"] is None:
        result["reason"] = "BINDING_INPUT_NOT_JSON_SAFE"
        return result

    trace = _common._Trace(reader)

    def finish() -> dict[str, Any]:
        raw["ordered_read_trace"] = deepcopy(trace.reads)
        raw["read_budget"] = trace.summary()
        return result

    try:
        base = _common._pointer(module_base, "MODULE_BASE", alignment=0x1000)
        observer = _common._parse_binding(observer_binding, "observer")
        target = _common._parse_binding(target_binding, "target")
        if observer["tag"] != logical_observer:
            raise _Unknown("OBSERVER_MUST_BE_FRA" if logical_observer == "FRA" else "OBSERVER_BINDING_MISMATCH")
        if target["tag"] == logical_observer:
            raise _Unknown("TARGET_MUST_DIFFER_FROM_FRA" if logical_observer == "FRA" else "FOREIGN_TARGET_REQUIRED")
        if (observer["country_pointer"] == target["country_pointer"]
                or observer["slot"] == target["slot"]
                or observer["fullref"] == target["fullref"]):
            raise _Unknown("BILATERAL_BINDINGS_ALIAS")

        result["observer"] = _binding_label(observer)
        result["target"] = _binding_label(target)
        raw["request"]["module_base"] = base

        binding_before = _common._binding_evidence(trace, base, observer, target)
        pair_row_bindings = [
            _read_pair_row_binding(trace, observer, target, "observer_to_target"),
            _read_pair_row_binding(trace, target, observer, "target_to_observer"),
        ]
        world_cell = _common._checked_add(base, WORLD_GLOBAL_RVA, 8)
        world = _common._pointer(trace.u64(world_cell, "world.global_pointer"), "WORLD")
        if world in (base, observer["country_pointer"], target["country_pointer"]):
            raise _Unknown("WORLD_POINTER_ALIAS")
        date_address = _common._checked_add(world, WORLD_DATE_OFFSET, 4)
        date_raw = trace.i32(date_address, "world.date_i32")
        fresh_world = _common._pointer(
            trace.u64(world_cell, "world.fresh_global_pointer"), "WORLD_FRESH")
        fresh_date = trace.i32(date_address, "world.fresh_date_i32")
        if fresh_world != world:
            raise _Unknown("WORLD_POINTER_CHANGED_DURING_PERMISSION")
        if fresh_date != date_raw:
            raise _Unknown("WORLD_DATE_CHANGED_DURING_PERMISSION")

        binding_after = _common._binding_evidence(trace, base, observer, target)
        if not _strict_equal(binding_before, binding_after):
            raise _Unknown("COUNTRY_BINDINGS_CHANGED_DURING_PERMISSION")

        raw["country_database_binding"] = binding_before
        raw["pair_row_bindings"] = pair_row_bindings
        raw["world"] = {
            "global_cell": hex(world_cell),
            "pointer": hex(world),
            "fresh_pointer": hex(fresh_world),
            "date_address": hex(date_address),
            "date_raw_i32": date_raw,
            "fresh_date_raw_i32": fresh_date,
            "date_raw_hex": date_raw.to_bytes(4, "little", signed=True).hex(),
        }
        result.update({"status": "known", "admitted": True, "reason": None})
        return finish()
    except (_Unknown, _common._Unknown) as exc:
        result["reason"] = getattr(exc, "reason", str(exc))
        return finish()
    except Exception as exc:
        result["reason"] = f"INTERNAL_READ_ERROR:{type(exc).__name__}"
        return finish()


class _ReplayReader:
    """Replay the exact ordered bytes preserved by a permission record."""

    def __init__(self, rows: list[Any]):
        self.rows = rows
        self.index = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if self.index >= len(self.rows):
            raise RuntimeError("PERMISSION_TRACE_READ_MISSING")
        row = self.rows[self.index]
        self.index += 1
        if (type(row) is not dict or row.get("address") != hex(address)
                or type(row.get("size")) is not int or row.get("size") != size
                or row.get("label") != label):
            raise RuntimeError("PERMISSION_TRACE_READ_MISMATCH")
        status = row.get("status")
        if status == "ok":
            raw_hex = row.get("raw_hex")
            if type(raw_hex) is not str:
                raise RuntimeError("PERMISSION_TRACE_RAW_MISSING")
            try:
                data = bytes.fromhex(raw_hex)
            except ValueError as exc:
                raise RuntimeError("PERMISSION_TRACE_RAW_INVALID") from exc
            if len(data) != size:
                raise RuntimeError("PERMISSION_TRACE_RAW_SIZE_MISMATCH")
            return data
        if status == "failed" and type(row.get("error_type")) is str:
            error_type = type(row["error_type"], (Exception,), {})
            raise error_type("replayed read failure")
        raise RuntimeError("PERMISSION_TRACE_STATUS_INVALID")


def _validate_permission(record: Any) -> bool:
    """Strictly rederive a permission from its ordered raw-read receipt."""
    if type(record) is not dict or not _json_value(record):
        return False
    raw = record.get("raw_inputs")
    if type(raw) is not dict:
        return False
    request = raw.get("request")
    rows = raw.get("ordered_read_trace")
    if type(request) is not dict or type(rows) is not list:
        return False
    budget = raw.get("read_budget")
    if type(budget) is not dict:
        return False
    if (type(budget.get("calls")) is not int
            or type(budget.get("bytes_requested")) is not int
            or type(budget.get("max_calls")) is not int
            or type(budget.get("max_bytes")) is not int
            or type(budget.get("max_single_read_bytes")) is not int):
        return False
    successful_or_failed = [row for row in rows
                            if type(row) is dict and row.get("status") in ("ok", "failed")]
    if (budget["calls"] != len(successful_or_failed)
            or budget["calls"] > MAX_READ_CALLS
            or budget["bytes_requested"] != sum(
                row.get("size", -1) for row in successful_or_failed)
            or budget["bytes_requested"] > MAX_TOTAL_READ_BYTES
            or budget["max_calls"] != MAX_READ_CALLS
            or budget["max_bytes"] != MAX_TOTAL_READ_BYTES
            or budget["max_single_read_bytes"] != MAX_SINGLE_READ_BYTES):
        return False
    for ordinal, row in enumerate(rows, 1):
        if type(row) is not dict:
            return False
        if (type(row.get("ordinal")) is not int or row["ordinal"] != ordinal
                or type(row.get("address")) is not str
                or type(row.get("size")) is not int
                or not 0 < row["size"] <= MAX_SINGLE_READ_BYTES
                or type(row.get("label")) is not str):
            return False
        try:
            address = int(row["address"], 16)
        except ValueError:
            return False
        if not MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE:
            return False
        if row.get("status") == "ok":
            raw_hex = row.get("raw_hex")
            if type(raw_hex) is not str or len(raw_hex) != row["size"] * 2:
                return False
            try:
                if len(bytes.fromhex(raw_hex)) != row["size"]:
                    return False
            except ValueError:
                return False
        elif row.get("status") == "failed":
            if type(row.get("error_type")) is not str or not row["error_type"]:
                return False
        else:
            # The permission path is fixed-size and has no budget rejection.
            return False

    replay = _ReplayReader(rows)
    try:
        derived = read_permission(
            replay,
            request.get("module_base"),
            request.get("observer_binding"),
            request.get("target_binding"),
            **({"logical_observer": request["logical_observer"]} if "logical_observer" in request else {}),
        )
    except Exception:
        return False
    if replay.index != len(rows):
        return False
    return _strict_equal(record, derived)


def validate_permission(record: Any) -> bool:
    try:
        return _validate_permission(record)
    except Exception:
        return False


def _field_requested(fields: Any) -> bool:
    if type(fields) is str:
        return fields == FIELD
    return type(fields) in (list, tuple) and any(
        type(item) is str and item == FIELD for item in fields)


def _canonical_binding(binding: Any, label: str) -> dict[str, Any]:
    parsed = _common._parse_binding(binding, label)
    return {
        "tag": parsed["tag"],
        "slot": parsed["slot"],
        "country_pointer": hex(parsed["country_pointer"]),
        "fullref": hex(parsed["fullref"]),
        "fullref_raw_hex": parsed["fullref_raw_hex"],
    }


def _field_value(status: str, value: Any, reason: str | None,
                 permission: Any, state: Any = None) -> dict[str, Any]:
    raw_inputs = {"permission": deepcopy(permission), "state": deepcopy(state)}
    result: dict[str, Any] = {
        "status": status,
        "basis": BASIS,
        "partial": True,
        "complete": False,
        "unit": "bilateral_subsidies_relation",
        "scale": 1,
        "period": "current",
        "value": deepcopy(value),
        "raw_inputs": raw_inputs,
    }
    if reason is not None:
        result["reason"] = reason
    return result


def _unknown_field(reason: str, permission: Any, state: Any = None) -> dict[str, Any]:
    state_contract = (state.get("contract") if type(state) is dict else None)
    value = (state_contract if type(state_contract) is dict
             else {"status": "unknown", "reason": reason})
    return _field_value("unknown", value, reason, permission, state)


def read_fields(reader: Any, module_base: Any, observer_binding: Any,
                target_binding: Any, fields: Any, *,
                permission: Any) -> dict[str, Any]:
    """Read the private subsidy pair only after strict fresh permission replay."""
    if not _field_requested(fields):
        return {}
    if not validate_permission(permission):
        return {FIELD: _unknown_field("SUBSIDIES_PERMISSION_INVALID", permission)}
    if permission.get("status") != "known" or permission.get("admitted") is not True:
        return {FIELD: _unknown_field("SUBSIDIES_PERMISSION_NOT_ADMITTED", permission)}

    raw_permission = permission["raw_inputs"]
    request = raw_permission["request"]
    try:
        base = _common._pointer(module_base, "MODULE_BASE", alignment=0x1000)
        if type(request.get("module_base")) is not int or request["module_base"] != base:
            raise _Unknown("MODULE_BASE_MISMATCH")
        observer = _canonical_binding(observer_binding, "observer")
        target = _canonical_binding(target_binding, "target")
        if not _strict_equal(observer, permission["observer"]):
            raise _Unknown("OBSERVER_BINDING_MISMATCH")
        if not _strict_equal(target, permission["target"]):
            raise _Unknown("TARGET_BINDING_MISMATCH")
        if not _strict_equal(_json_binding(observer_binding), request["observer_binding"]):
            raise _Unknown("OBSERVER_BINDING_INPUT_MISMATCH")
        if not _strict_equal(_json_binding(target_binding), request["target_binding"]):
            raise _Unknown("TARGET_BINDING_INPUT_MISMATCH")

        world = raw_permission.get("world")
        if type(world) is not dict:
            raise _Unknown("PERMISSION_WORLD_MISSING")
        date_raw = world.get("date_raw_i32")
        fresh_date = world.get("fresh_date_raw_i32")
        if (type(date_raw) is not int or not INT32_MIN <= date_raw <= INT32_MAX
                or type(fresh_date) is not int or fresh_date != date_raw
                or type(world.get("pointer")) is not str
                or world.get("pointer") != world.get("fresh_pointer")):
            raise _Unknown("PERMISSION_DATE_INVALID")

        # Rebind this exact permission on the same reader before entering the
        # pair leaf. Any changed binding, owner, world pointer, or date denies it.
        scope = {"logical_observer": request["logical_observer"]} if "logical_observer" in request else {}
        fresh = read_permission(reader, base, observer_binding, target_binding, **scope)
        if not _strict_equal(permission, fresh):
            raise _Unknown("SUBSIDIES_PERMISSION_STALE")

        state = _leaf.read_state(reader, base, observer_binding, target_binding, **scope)
        contract = state.get("contract") if type(state) is dict else None
        if state.get("status") != "known" or type(contract) is not dict:
            return {FIELD: _unknown_field("BILATERAL_SUBSIDIES_STATE_UNKNOWN",
                                          permission, state)}

        directions = state.get("raw_inputs", {}).get("pair_directions")
        expected_owners = (
            hex(int(observer["country_pointer"], 0)
                + _leaf.SUBSIDY_ROW_OWNER_COUNTRY_OFFSET),
            hex(int(target["country_pointer"], 0)
                + _leaf.SUBSIDY_ROW_OWNER_COUNTRY_OFFSET),
        )
        if (type(directions) is not list or len(directions) != 2
                or any(type(row) is not dict for row in directions)
                or tuple(row.get("owner") for row in directions) != expected_owners):
            return {FIELD: _unknown_field("PAIR_OWNER_NOT_FRA_FISCAL_ROW",
                                          permission, state)}
        return {
            FIELD: _field_value("known", contract, None, permission, state),
        }
    except (_Unknown, _common._Unknown) as exc:
        reason = getattr(exc, "reason", str(exc))
        return {FIELD: _unknown_field(reason, permission)}
    except Exception as exc:
        return {FIELD: _unknown_field(f"SUBSIDIES_FIELD_READ_FAILED:{type(exc).__name__}",
                                      permission)}


__all__ = [
    "FIELD", "FIELDS", "SCHEMA", "BASIS", "SCOPE", "EXPECTED_EXE_SHA256",
    "PREFERRED_IMAGE_BASE", "read_permission", "validate_permission", "read_fields",
]
