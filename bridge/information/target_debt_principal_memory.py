"""Private adapter for one native AI-recipient target-principal candidate.

The permission binds an observer and a distinct AI target to the live country
database and to a stable world date, human count, and controller vector. A
positive candidate permission is not the final publication gate: host-session
controlled-country policy and other parent checks remain outside this module.
The final leaf reads only principal totals. It does not establish actual UI
rendering, interest, due dates, or complete target debt.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_visibility_memory as _common
from . import foreign_debt_principal_memory as _leaf
from . import native_ai_choice_mapping_memory as _choice


FIELD = "F03.target_debt_principal"
FIELDS = (FIELD,)
SCHEMA = "information.target_debt_principal_memory.v2"
BASIS = "private_native_diplomatic_target_principal"
SCOPE = "native_negotiated_ai_recipient_principal_candidate"
EXPECTED_EXE_SHA256 = _leaf.EXPECTED_EXE_SHA256
PREFERRED_IMAGE_BASE = _leaf.PREFERRED_IMAGE_BASE

WORLD_GLOBAL_RVA = _common.WORLD_GLOBAL_RVA
WORLD_DATE_OFFSET = 0x1DD0
WORLD_HUMAN_COUNT_OFFSET = 0x0A60
WORLD_CONTROLLERS_POINTER_OFFSET = 0x1D48
CONTROLLER_I32_STRIDE = 4
CURRENT_ACTION_MAP_CELL_RVA = 0x1C80A18
CURRENT_ACTION_MAP_GETTER_RVA = 0x004F5960
CURRENT_PRINCIPAL_REASON_CELL_RVA = 0x1C80AA0
CURRENT_PRINCIPAL_REASON_RVA = 0x004F5E90
CURRENT_VALIDITY_HELPER_CELL_RVA = 0x1C80A50
CURRENT_VALIDITY_HELPER_RVA = 0x0008F440
ACTION_EXCLUSION_TABLE_RVA = 0x1C35460
ACTION_EXCLUSION_TABLE_SIZE = 0x30
CURRENT_ACTION_TOKEN = 15310
EXPECTED_ACTION_EXCLUSION_TABLE_HEX = (
    "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
    "75330000cb3b0000cd3b000066380000"
)

MAX_READ_CALLS = _common.MAX_READ_CALLS
MAX_TOTAL_READ_BYTES = _common.MAX_TOTAL_READ_BYTES
MAX_SINGLE_READ_BYTES = _common.MAX_SINGLE_READ_BYTES
MIN_USER_ADDRESS = _common.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _common.MAX_USER_ADDRESS_EXCLUSIVE
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_SCOPE_EVIDENCE = {
    "executable_sha256": EXPECTED_EXE_SHA256,
    "principal_leaf_schema": _leaf.SCHEMA,
    "principal_leaf_basis": _leaf.BASIS,
    "candidate_scope": SCOPE,
    "country_scope": "distinct_observer_and_ai_target",
    "current_action_map": {
        "module_cell_rva": hex(CURRENT_ACTION_MAP_CELL_RVA),
        "expected_getter_rva": hex(CURRENT_ACTION_MAP_GETTER_RVA),
    },
    "current_principal_reason_map": {
        "module_cell_rva": hex(CURRENT_PRINCIPAL_REASON_CELL_RVA),
        "expected_reason_rva": hex(CURRENT_PRINCIPAL_REASON_RVA),
    },
    "current_validity_helper_map": {
        "module_cell_rva": hex(CURRENT_VALIDITY_HELPER_CELL_RVA),
        "native_true_predicate_rva": hex(CURRENT_VALIDITY_HELPER_RVA),
        "accepted_mapping_modes": ["native_true", "installed_observer_gui_forwarding"],
        "meaning": "AI choice predicate mapping; the certified GUI-forwarding hook is accepted",
        "hook_asset_sha256": _choice.ASSET_SHA256,
    },
    "current_action_exclusion_table": {
        "rva": hex(ACTION_EXCLUSION_TABLE_RVA),
        "size": ACTION_EXCLUSION_TABLE_SIZE,
        "current_action_token": CURRENT_ACTION_TOKEN,
        "expected_raw_hex_static_seed": EXPECTED_ACTION_EXCLUSION_TABLE_HEX,
        "runtime_policy": "stable table and current token absent; other tokens are not fixed here",
    },
    "does_not_establish": [
        "host_session_controlled_countries_policy",
        "final_publication_admission",
        "actual_UI_rendering",
        "interest_or_due_dates",
        "complete_target_country_debt",
    ],
    "native_validity_favors_cooldowns_and_opinion_are_not_permission_gates": True,
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
    """Compare typed JSON recursively; bool and int remain distinct."""
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


def _permission_template(module_base: Any, observer_binding: Any,
                         target_binding: Any) -> dict[str, Any]:
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
        "publication_admitted": False,
        "raw_inputs": {
            "request": {
                "module_base": module_base if _json_value(module_base) else None,
                "observer_binding": _json_binding(observer_binding),
                "target_binding": _json_binding(target_binding),
            },
            "scope_evidence": deepcopy(_SCOPE_EVIDENCE),
            "country_database_binding_before": None,
            "country_database_binding_after": None,
            "world": None,
            "current_algorithm_mapping": None,
            "current_action_exclusion_table": None,
            "candidate_gates": None,
            "controlled_countries_evaluated": False,
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


def _finish(result: dict[str, Any], trace: Any) -> dict[str, Any]:
    result["raw_inputs"]["ordered_read_trace"] = deepcopy(trace.reads)
    result["raw_inputs"]["read_budget"] = trace.summary()
    return result


def _read_current_algorithm_mapping(trace: Any, base: int, phase: str) -> dict[str, Any]:
    action_cell = _common._checked_add(base, CURRENT_ACTION_MAP_CELL_RVA, 8)
    reason_cell = _common._checked_add(base, CURRENT_PRINCIPAL_REASON_CELL_RVA, 8)
    validity_cell = _common._checked_add(base, CURRENT_VALIDITY_HELPER_CELL_RVA, 8)
    action_pointer = trace.u64(action_cell, f"native_map.action_getter_{phase}")
    reason_pointer = trace.u64(reason_cell, f"native_map.principal_reason_{phase}")
    validity_pointer = trace.u64(validity_cell, f"native_map.validity_helper_{phase}")
    expected_action = _common._checked_add(base, CURRENT_ACTION_MAP_GETTER_RVA, 1)
    expected_reason = _common._checked_add(base, CURRENT_PRINCIPAL_REASON_RVA, 1)
    validity_proof = _choice.read_mapping(trace, base, validity_pointer, phase=phase)
    mapping = {
        "action_cell": hex(action_cell),
        "action_pointer": hex(action_pointer),
        "expected_action_pointer": hex(expected_action),
        "principal_reason_cell": hex(reason_cell),
        "principal_reason_pointer": hex(reason_pointer),
        "expected_principal_reason_pointer": hex(expected_reason),
        "validity_helper_cell": hex(validity_cell),
        "validity_helper_pointer": hex(validity_pointer),
        "validity_helper_proof": validity_proof,
    }
    if action_pointer != expected_action:
        raise _Unknown("CURRENT_ACTION_GETTER_MAPPING_MISMATCH")
    if reason_pointer != expected_reason:
        raise _Unknown("CURRENT_PRINCIPAL_REASON_MAPPING_MISMATCH")
    return mapping


def _read_current_action_exclusions(trace: Any, base: int,
                                    phase: str) -> dict[str, Any]:
    address = _common._checked_add(base, ACTION_EXCLUSION_TABLE_RVA,
                                   ACTION_EXCLUSION_TABLE_SIZE)
    raw = trace.exact(address, ACTION_EXCLUSION_TABLE_SIZE,
                      f"native_exclusions.table_{phase}")
    tokens = [int.from_bytes(raw[offset:offset + 4], "little", signed=False)
              for offset in range(0, ACTION_EXCLUSION_TABLE_SIZE, 4)]
    return {
        "address": hex(address),
        "size": ACTION_EXCLUSION_TABLE_SIZE,
        "raw_hex": raw.hex(),
        "tokens_u32": tokens,
        "current_action_token": CURRENT_ACTION_TOKEN,
        "current_action_token_excluded": CURRENT_ACTION_TOKEN in tokens,
    }


def read_permission(reader: Any, module_base: Any, observer_binding: Any,
                    target_binding: Any) -> dict[str, Any]:
    """Observe a stable native AI-recipient candidate for the selected target."""
    result = _permission_template(module_base, observer_binding, target_binding)
    raw = result["raw_inputs"]
    if (raw["request"]["observer_binding"] is None
            or raw["request"]["target_binding"] is None):
        result["reason"] = "BINDING_INPUT_NOT_JSON_SAFE"
        return result

    trace = _common._Trace(reader)

    def deny(reason: str) -> dict[str, Any]:
        result.update({"status": "known", "admitted": False, "reason": reason})
        if type(raw.get("candidate_gates")) is dict:
            raw["candidate_gates"].update({"decision": "denied", "reason": reason})
        else:
            raw["candidate_gates"] = {
                "status": "known_denied", "decision": "denied", "reason": reason,
            }
        return _finish(result, trace)

    def unknown(reason: str) -> dict[str, Any]:
        result.update({"status": "unknown", "admitted": None, "reason": reason})
        return _finish(result, trace)

    try:
        base = _common._pointer(module_base, "MODULE_BASE", alignment=0x1000)
        observer = _common._parse_binding(observer_binding, "observer")
        target = _common._parse_binding(target_binding, "target")
        result["observer"] = _binding_label(observer)
        result["target"] = _binding_label(target)
        raw["request"]["module_base"] = base

        # Debt is an AI target operation; self-targets are never candidates.
        if observer["tag"] == target["tag"]:
            return deny("OBSERVER_TARGET_SAME_TAG")
        if (observer["country_pointer"] == target["country_pointer"]
                or observer["slot"] == target["slot"]
                or observer["fullref"] == target["fullref"]):
            raise _Unknown("OBSERVER_TARGET_BINDINGS_ALIAS")

        mapping_before = _read_current_algorithm_mapping(trace, base, "before")
        exclusions_before = _read_current_action_exclusions(trace, base, "before")
        binding_before = _common._binding_evidence(trace, base, observer, target)

        world_cell = _common._checked_add(base, WORLD_GLOBAL_RVA, 8)
        world = _common._pointer(
            trace.u64(world_cell, "world.global_pointer"), "WORLD")
        if world in (base, observer["country_pointer"], target["country_pointer"]):
            raise _Unknown("WORLD_POINTER_ALIAS")
        date_address = _common._checked_add(world, WORLD_DATE_OFFSET, 4)
        human_count_address = _common._checked_add(world, WORLD_HUMAN_COUNT_OFFSET, 4)
        controllers_pointer_address = _common._checked_add(
            world, WORLD_CONTROLLERS_POINTER_OFFSET, 8)
        date_raw = trace.i32(date_address, "world.date_i32")
        human_count = trace.i32(human_count_address, "world.human_count_i32")
        controllers_pointer = _common._pointer(
            trace.u64(controllers_pointer_address, "world.controllers_pointer"),
            "WORLD_CONTROLLERS")
        if controllers_pointer in (world, base, observer["country_pointer"], target["country_pointer"]):
            raise _Unknown("WORLD_CONTROLLERS_POINTER_ALIAS")
        observer_controller_address = _common._checked_add(
            controllers_pointer, observer["slot"] * CONTROLLER_I32_STRIDE, 4)
        target_controller_address = _common._checked_add(
            controllers_pointer, target["slot"] * CONTROLLER_I32_STRIDE, 4)
        observer_controller = trace.i32(
            observer_controller_address, "world.observer_controller_i32")
        target_controller = trace.i32(
            target_controller_address, "world.target_controller_i32")

        fresh_world = _common._pointer(
            trace.u64(world_cell, "world.fresh_global_pointer"), "WORLD_FRESH")
        fresh_date = trace.i32(date_address, "world.fresh_date_i32")
        fresh_human_count = trace.i32(
            human_count_address, "world.fresh_human_count_i32")
        fresh_controllers_pointer = _common._pointer(
            trace.u64(controllers_pointer_address, "world.fresh_controllers_pointer"),
            "WORLD_CONTROLLERS_FRESH")
        fresh_observer_controller = trace.i32(
            observer_controller_address, "world.fresh_observer_controller_i32")
        fresh_target_controller = trace.i32(
            target_controller_address, "world.fresh_target_controller_i32")

        binding_after = _common._binding_evidence(trace, base, observer, target)
        mapping_after = _read_current_algorithm_mapping(trace, base, "after")
        exclusions_after = _read_current_action_exclusions(trace, base, "after")
        raw["country_database_binding_before"] = binding_before
        raw["country_database_binding_after"] = binding_after
        raw["current_algorithm_mapping"] = {
            "before": mapping_before,
            "after": mapping_after,
        }
        raw["current_action_exclusion_table"] = {
            "before": exclusions_before,
            "after": exclusions_after,
        }
        raw["world"] = {
            "global_cell": hex(world_cell),
            "pointer": hex(world),
            "fresh_pointer": hex(fresh_world),
            "date_address": hex(date_address),
            "date_raw_i32": date_raw,
            "fresh_date_raw_i32": fresh_date,
            "date_raw_hex": date_raw.to_bytes(4, "little", signed=True).hex(),
            "human_count_address": hex(human_count_address),
            "human_count_i32": human_count,
            "fresh_human_count_i32": fresh_human_count,
            "controllers_pointer_address": hex(controllers_pointer_address),
            "controllers_pointer": hex(controllers_pointer),
            "fresh_controllers_pointer": hex(fresh_controllers_pointer),
            "observer_controller_address": hex(observer_controller_address),
            "observer_controller_i32": observer_controller,
            "fresh_observer_controller_i32": fresh_observer_controller,
            "target_controller_address": hex(target_controller_address),
            "target_controller_i32": target_controller,
            "fresh_target_controller_i32": fresh_target_controller,
        }

        if (fresh_world != world
                or fresh_date != date_raw
                or fresh_human_count != human_count
                or fresh_controllers_pointer != controllers_pointer
                or fresh_observer_controller != observer_controller
                or fresh_target_controller != target_controller):
            raise _Unknown("WORLD_ROLE_STATE_CHANGED_DURING_PERMISSION")
        if not _strict_equal(binding_before, binding_after):
            raise _Unknown("COUNTRY_DATABASE_BINDING_CHANGED_DURING_PERMISSION")
        if not _strict_equal(mapping_before, mapping_after):
            raise _Unknown("CURRENT_ALGORITHM_MAPPING_CHANGED_DURING_PERMISSION")
        if not _strict_equal(exclusions_before, exclusions_after):
            raise _Unknown("CURRENT_ACTION_EXCLUSION_TABLE_CHANGED_DURING_PERMISSION")

        if exclusions_before["current_action_token_excluded"]:
            return deny("CURRENT_ACTION_TOKEN_EXCLUDED")

        gates = {
            "distinct_country_tags": observer["tag"] != target["tag"],
            "target_controller_is_zero": target_controller == 0,
        }
        raw["candidate_gates"] = {
            "status": "observed",
            **gates,
            "human_count_i32": human_count,
            "observer_controller_i32": observer_controller,
            "target_controller_i32": target_controller,
        }
        if not gates["target_controller_is_zero"]:
            return deny("TARGET_CONTROLLER_NOT_ZERO")

        result.update({"status": "known", "admitted": True, "reason": None})
        raw["candidate_gates"]["decision"] = "admitted_candidate"
        return _finish(result, trace)
    except (_Unknown, _common._Unknown) as exc:
        return unknown(getattr(exc, "reason", str(exc)))
    except Exception as exc:
        return unknown(f"INTERNAL_READ_ERROR:{type(exc).__name__}")


class _ReplayReader:
    """Replay the exact ordered bytes held by a permission object."""

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
        if row.get("status") == "ok":
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
        if row.get("status") == "failed" and type(row.get("error_type")) is str:
            error_type = type(row["error_type"], (Exception,), {})
            raise error_type("replayed read failure")
        raise RuntimeError("PERMISSION_TRACE_STATUS_INVALID")


def _validate_permission(record: Any) -> bool:
    if type(record) is not dict or not _json_value(record):
        return False
    raw = record.get("raw_inputs")
    if type(raw) is not dict:
        return False
    request = raw.get("request")
    rows = raw.get("ordered_read_trace")
    budget = raw.get("read_budget")
    if type(request) is not dict or type(rows) is not list or type(budget) is not dict:
        return False

    read_rows: list[dict[str, Any]] = []
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
            return False
        read_rows.append(row)

    for key in ("calls", "bytes_requested", "max_calls", "max_bytes",
                "max_single_read_bytes"):
        if type(budget.get(key)) is not int:
            return False
    if (budget["calls"] != len(read_rows)
            or budget["calls"] > MAX_READ_CALLS
            or budget["bytes_requested"] != sum(row["size"] for row in read_rows)
            or budget["bytes_requested"] > MAX_TOTAL_READ_BYTES
            or budget["max_calls"] != MAX_READ_CALLS
            or budget["max_bytes"] != MAX_TOTAL_READ_BYTES
            or budget["max_single_read_bytes"] != MAX_SINGLE_READ_BYTES):
        return False

    replay = _ReplayReader(rows)
    try:
        derived = read_permission(
            replay,
            request.get("module_base"),
            request.get("observer_binding"),
            request.get("target_binding"),
        )
    except Exception:
        return False
    return replay.index == len(rows) and _strict_equal(record, derived)


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


def _field_result(status: str, reason: str | None,
                  permission: Any, state: Any = None,
                  value: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "basis": BASIS,
        "scope": SCOPE,
        "partial": True,
        "complete": False,
        "unit": "loan_principal_totals",
        "scale": 1,
        "period": "current",
        "publication_admitted": False,
        "raw_inputs": {"permission": deepcopy(permission), "state": deepcopy(state)},
    }
    if status == "known":
        result["value"] = deepcopy(value)
    if reason is not None:
        result["reason"] = reason
    return result


def read_fields(reader: Any, module_base: Any, observer_binding: Any,
                target_binding: Any, fields: Any, *,
                permission: Any) -> dict[str, Any]:
    """Read principal totals after strict permission replay and same-reader rebind."""
    if not _field_requested(fields):
        return {}
    if not validate_permission(permission):
        return {FIELD: _field_result("unknown", "TARGET_DEBT_PERMISSION_INVALID", permission)}
    if permission.get("status") != "known" or permission.get("admitted") is not True:
        return {FIELD: _field_result("unknown", "TARGET_DEBT_PERMISSION_NOT_ADMITTED", permission)}

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

        # The exact saved permission is re-read from this same reader before
        # the private leaf is entered. Parent session/ROM/role and controlled
        # country checks remain separate publication gates.
        fresh = read_permission(reader, base, observer_binding, target_binding)
        if not _strict_equal(permission, fresh):
            raise _Unknown("TARGET_DEBT_PERMISSION_STALE")

        state = _leaf.read_state(reader, base, observer_binding, target_binding)
        if (type(state) is not dict
                or state.get("schema") != _leaf.SCHEMA
                or state.get("status") != "known"
                or state.get("complete_loan_list") is not True
                or state.get("publication_admitted") is not False
                or type(state.get("value")) is not dict):
            return {FIELD: _field_result(
                "unknown", "TARGET_DEBT_PRINCIPAL_STATE_UNKNOWN", permission, state)}
        return {FIELD: _field_result(
            "known", None, permission, state, state["value"])}
    except (_Unknown, _common._Unknown) as exc:
        return {FIELD: _field_result(
            "unknown", getattr(exc, "reason", str(exc)), permission)}
    except Exception:
        return {FIELD: _field_result(
            "unknown", "TARGET_DEBT_FIELD_READ_FAILED", permission)}


__all__ = [
    "FIELD", "FIELDS", "SCHEMA", "BASIS", "SCOPE", "EXPECTED_EXE_SHA256",
    "PREFERRED_IMAGE_BASE", "read_permission", "validate_permission", "read_fields",
]
