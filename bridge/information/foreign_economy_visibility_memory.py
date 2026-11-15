"""Read the distinct native entry conditions used by foreign economy pages.

The income comparison and observer-lent loan paths have different scopes.
These private predicates do not establish FRA's role, country-view admission,
ROM, session identity or rendered UI; their parent must enforce those checks.
An admitted loan candidate still authorizes only records whose lender fullref
equals the bound observer, never all financial records of that target.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_ledger_membership_memory as _membership
from . import foreign_quality_visibility_memory as _common

SCHEMA = "information.foreign_economy_visibility_memory.v1"
INCOME_PAGE = "income_comparison"
LOANS_PAGE = "observer_lent_loans"
PAGES = (INCOME_PAGE, LOANS_PAGE)
BASIS = "native_economy_page_conditions_projected"


def _same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def read_permission(reader: Any, module_base: int, observer_binding: Any,
                    target_binding: Any, *, page: str) -> dict[str, Any]:
    """Read a bounded candidate predicate without reading economic resources."""
    trace = _common._Trace(reader)
    result = {
        "schema": SCHEMA, "basis": BASIS, "page": page,
        "status": "unknown", "admitted": None, "mode": "unknown", "reason": None,
        "module_base": hex(module_base) if type(module_base) is int else None,
        "observer_binding": deepcopy(dict(observer_binding)) if isinstance(observer_binding, Mapping) else None,
        "target_binding": deepcopy(dict(target_binding)) if isinstance(target_binding, Mapping) else None,
        "complete": False, "actual_UI_observed": False,
        "raw_inputs": {},
    }
    raw = result["raw_inputs"]

    def deny(reason: str) -> None:
        result.update(status="known", admitted=False, mode="denied", reason=reason)

    try:
        if page not in PAGES:
            raise _common._Unknown("ECONOMY_PAGE_INVALID")
        base = _common._pointer(module_base, "MODULE_BASE", alignment=0x1000)
        observer = _common._parse_binding(observer_binding, "observer")
        target = _common._parse_binding(target_binding, "target")
        if observer["fullref"] == target["fullref"]:
            raise _common._Unknown("FOREIGN_TARGET_REQUIRED")
        raw["binding_evidence"] = _common._binding_evidence(trace, base, observer, target)
        world_cell = base + _common.WORLD_GLOBAL_RVA
        world = _common._pointer(trace.u64(world_cell, "economy.world_pointer"), "WORLD")
        raw["world"] = {"global_address": hex(world_cell), "pointer": hex(world)}

        # This local gate registers the country-income comparison page. The
        # quality-specific cfc70/TLS condition is absent from this entry path.
        if page == INCOME_PAGE:
            byte6 = (observer["fullref"] >> 48) & 0xFF
            raw["observer_fullref_byte6"] = byte6
            if byte6 != 7:
                options_cell = world + _common.WORLD_OPTIONS_POINTER_OFFSET
                options = _common._pointer(trace.u64(options_cell, "economy.options_pointer"), "OPTIONS")
                option_address = options + _common.OPTIONS_QUALITY_INDEX * 4
                option = trace.i32(option_address, "economy.income_option_index17")
                raw["entry_gate"] = {"mode": "option_index17", "options_pointer": hex(options),
                                     "option_address": hex(option_address), "value": option}
                if option != 0:
                    deny("INCOME_COMPARISON_OPTION_BLOCKED")
                    return result
            else:
                raw["entry_gate"] = {"mode": "observer_fullref_byte6_7"}

        membership = _membership.read_membership(trace.exact, world, target_binding)
        raw["ledger_membership"] = membership
        if (not _membership.validate_membership(membership)
                or membership.get("status") != "known"):
            raise _common._Unknown("TARGET_LEDGER_MEMBERSHIP_UNKNOWN")
        if membership.get("member") is not True:
            deny("TARGET_NOT_LEDGER_CANDIDATE")
            return result

        if page == LOANS_PAGE:
            result.update(status="known", admitted=True, mode="observer_lent_loans_candidate")
            return result

        specials = []
        for label, rva in _common.SPECIAL_TARGET_SLOT_RVAS:
            value = trace.i32(base + rva, f"economy.{label}")
            specials.append({"rva": hex(rva), "value": value})
        raw["special_target_slots"] = specials
        if target["slot"] in {item["value"] for item in specials}:
            deny("SPECIAL_TARGET_SLOT")
            return result

        capital_cell = target["country_pointer"] + _common.COUNTRY_CAPITAL_OFFSET
        capital = _common._pointer(trace.u64(capital_cell, "economy.target_capital"), "CAPITAL")
        flags_address = capital + _common.CAPITAL_QUALITY_FLAGS_OFFSET
        flags = trace.u8(flags_address, "economy.target_capital_flags")
        raw["discovery"] = {"capital_pointer": hex(capital), "flags_address": hex(flags_address),
                            "flags": flags}
        high = observer["fullref"] >> 32
        if not flags & _common.QUALITY_FLAG_BIT:
            mode = "capital_flag_clear"
        elif (high >> 24) & 0xFF == 0:
            mode = "observer_high32_byte3_zero"
        elif (high >> 16) & 0xFF == 7:
            mode = "observer_high32_byte2_seven"
        else:
            bitmap_cell = capital + _common.CAPITAL_OBSERVER_BITSET_OFFSET
            bitmap = _common._pointer(trace.u64(bitmap_cell, "economy.discovery_bitmap"), "DISCOVERY_BITMAP")
            index = observer["slot"]
            word_address = bitmap + (index >> 5) * 4
            word = trace.u32(word_address, "economy.discovery_word")
            raw["discovery"].update(bitmap_pointer=hex(bitmap), word_address=hex(word_address),
                                    word=word, bit=index & 31)
            if not (word >> (index & 31)) & 1:
                deny("TARGET_CAPITAL_NOT_DISCOVERED")
                return result
            mode = "capital_discovery_bitmap"
        result.update(status="known", admitted=True, mode=mode)
    except _common._Unknown as exc:
        result.update(status="unknown", admitted=None, mode="unknown", reason=exc.reason)
    except Exception:
        result.update(status="unknown", admitted=None, mode="unknown", reason="ECONOMY_PERMISSION_READ_FAILED")
    finally:
        raw["reads"] = deepcopy(trace.reads)
        raw["read_budget"] = trace.summary()
    return result


def validate_permission(record: Any, *, page: str | None = None) -> bool:
    """Only a complete, exact ordered replay may authorize an economy read."""
    try:
        if (not isinstance(record, dict) or record.get("schema") != SCHEMA
                or record.get("status") != "known" or type(record.get("admitted")) is not bool
                or record.get("page") not in PAGES
                or (page is not None and record["page"] != page)):
            return False
        rows = record["raw_inputs"]["reads"]
        if not isinstance(rows, list) or not 0 < len(rows) <= _common.MAX_READ_CALLS:
            return False

        class Replay:
            index = 0

            def read(self, address, size, label):
                if self.index >= len(rows):
                    raise ValueError("ECONOMY_PERMISSION_TRACE_EXHAUSTED")
                row = rows[self.index]
                self.index += 1
                if (row.get("ordinal") != self.index or row.get("status") != "ok"
                        or row.get("address") != hex(address) or row.get("label") != label
                        or type(row.get("size")) is not int or row["size"] != size):
                    raise ValueError("ECONOMY_PERMISSION_TRACE_MISMATCH")
                value = bytes.fromhex(row["raw_hex"])
                if len(value) != size:
                    raise ValueError("ECONOMY_PERMISSION_TRACE_WIDTH")
                return value

        replay = Replay()
        rebuilt = read_permission(replay, int(record["module_base"], 16),
                                  record["observer_binding"], record["target_binding"], page=record["page"])
        return replay.index == len(rows) and _same(rebuilt, record)
    except Exception:
        return False


__all__ = ["SCHEMA", "BASIS", "INCOME_PAGE", "LOANS_PAGE", "PAGES",
           "read_permission", "validate_permission"]
