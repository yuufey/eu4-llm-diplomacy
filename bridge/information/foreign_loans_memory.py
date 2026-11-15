"""Bounded foreign loans lent by the logical observer; never total debt.

The native loans ledger visits the world's country rows and keeps their loan
records only when the lender slot is the client. This reader requires the
entire lender reference to match the bound observer before reading amounts.
Its parent owns process identity, ROM, nonplayer role and country-view checks.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_economy_visibility_memory as _permission
from . import foreign_quality_visibility_memory as _common
from .engine_dates import project_engine_date

FIELD = "F03.debt"
FIELDS = (FIELD,)
BASIS = "native_ledger_loans_lent_by_observer"
MAX_NODES = 64
MAX_READ_BYTES = 16 * 1024
MAX_READ_CALLS = 256


class _Trace:
    def __init__(self, reader):
        self.reader = getattr(reader, "read", None) or (reader if callable(reader) else None)
        self.reads = []
        self.bytes = 0

    def read(self, address, size, label):
        _common._checked_add(address, 0, size)
        if not 0 < size <= 1024 or self.bytes + size > MAX_READ_BYTES or len(self.reads) >= MAX_READ_CALLS:
            raise ValueError("FOREIGN_LOANS_READ_BUDGET")
        self.bytes += size
        row = {"address": hex(address), "size": size, "label": label, "status": "requested"}
        self.reads.append(row)
        try:
            data = self.reader(address, size, label)
            if not isinstance(data, bytes) or len(data) != size:
                raise ValueError("FOREIGN_LOANS_SHORT_READ")
            row.update(status="observed", raw_hex=data.hex())
            return data
        except Exception as exc:
            row.update(status="failed", error_type=type(exc).__name__)
            raise


def _unknown(reason, raw):
    return {"status": "unknown", "reason": reason, "complete": False, "partial": True,
            "basis": BASIS, "raw_inputs": deepcopy(raw)}


def read_fields(reader: Any, module_base: int, observer_binding: Any, target_binding: Any,
                fields: Any, *, permission: Any) -> dict[str, Any]:
    """Copy only matching lender records, with a complete bounded list walk."""
    requested = [key for key in FIELDS if key in fields] if isinstance(fields, (list, tuple)) else []
    if not requested:
        return {}
    raw = {"permission": deepcopy(permission), "reads": []}
    if (not _permission.validate_permission(permission, page=_permission.LOANS_PAGE)
            or permission.get("admitted") is not True):
        return {FIELD: _unknown("OBSERVER_LENT_LOANS_PERMISSION_NOT_ADMITTED", raw)}
    trace = _Trace(reader)
    try:
        base = _common._pointer(module_base, "MODULE_BASE", alignment=0x1000)
        observer = _common._parse_binding(observer_binding, "observer")
        target = _common._parse_binding(target_binding, "target")
        permitted_observer = _common._parse_binding(permission["observer_binding"], "observer")
        permitted_target = _common._parse_binding(permission["target_binding"], "target")
        if (permission.get("module_base") != hex(base)
                or not _permission._same(observer, permitted_observer)
                or not _permission._same(target, permitted_target)):
            return {FIELD: _unknown("OBSERVER_LENT_LOANS_BINDING_MISMATCH", raw)}
        for name, binding in (("observer", observer), ("target", target)):
            echo = trace.read(binding["country_pointer"] + 0x20, 8, f"foreign_loans.{name}_fullref")
            if echo.hex() != binding["fullref_raw_hex"]:
                raise ValueError("FOREIGN_LOANS_BINDING_CHANGED")
        head = int.from_bytes(trace.read(target["country_pointer"] + 0xDE8, 8,
                                         "foreign_loans.target_list_head"), "little")
        raw["list_head"] = hex(head)
        node = head
        visited = set()
        record_pointers = set()
        records = []
        scanned = 0
        while node:
            node = _common._pointer(node, "LOAN_NODE")
            if node in visited:
                raise ValueError("FOREIGN_LOANS_NODE_CYCLE")
            if len(visited) >= MAX_NODES:
                raise ValueError("FOREIGN_LOANS_NODE_LIMIT")
            visited.add(node)
            header = trace.read(node, 24, f"foreign_loans.node[{scanned}]")
            record = _common._pointer(int.from_bytes(header[:8], "little"), "LOAN_RECORD")
            if record in record_pointers:
                raise ValueError("FOREIGN_LOANS_DUPLICATE_RECORD")
            record_pointers.add(record)
            node = int.from_bytes(header[16:24], "little")
            lender_raw = trace.read(record + 0x20, 8, f"foreign_loans.lender[{scanned}]")
            # Do not copy a third party's principal, interest or due date.
            if lender_raw.hex() == observer["fullref_raw_hex"]:
                values = trace.read(record + 0x28, 12, f"foreign_loans.financials[{scanned}]")
                interest, principal, due = [int.from_bytes(values[i:i+4], "little", signed=True)
                                             for i in (0, 4, 8)]
                records.append({
                    "lender": observer["tag"], "borrower": target["tag"],
                    "principal": {"status": "known", "raw": principal, "value": principal,
                                  "unit": "ducats", "scale": 1},
                    "interest": {"status": "known", "raw": interest, "value": interest,
                                 "unit": "percent", "scale": 1000},
                    "due": {"status": "known", "raw": due, "raw_hex": values[8:12].hex(),
                            "unit": "eu4_hour_tick", "scale": 1,
                            "calendar": project_engine_date(due)},
                    "source_list_ordinal": scanned,
                })
            scanned += 1
        amount = sum(item["principal"]["raw"] for item in records)
        field = {
            "status": "known", "complete": False, "partial": True, "basis": BASIS,
            "value": {
                "total_debt": {"status": "unknown", "reason": "TOTAL_FOREIGN_DEBT_NOT_ESTABLISHED"},
                "loans_to_observer": {"status": "known", "records": records,
                    "record_count": len(records), "coverage": "observer_lent_loans_only",
                    "observed_principal_sum": {"status": "known", "raw": amount, "value": amount,
                                               "unit": "ducats", "scale": 1},
                    "complete_country_debt": False},
            },
            "unit": "observed_loan_records", "scale": 1, "period": "current",
            "raw_inputs": raw,
        }
        raw["scanned_list_nodes"] = scanned
    except Exception as exc:
        reason = str(exc)
        safe = reason if reason.startswith("FOREIGN_LOANS_") and reason.isupper() else "FOREIGN_LOANS_READ_FAILED"
        field = _unknown(safe, raw)
    raw["reads"] = deepcopy(trace.reads)
    raw["budget"] = {"calls": len(trace.reads), "bytes_requested": trace.bytes,
                     "max_calls": MAX_READ_CALLS, "max_bytes": MAX_READ_BYTES,
                     "max_nodes": MAX_NODES, "max_single_read_bytes": 1024}
    field["raw_inputs"] = deepcopy(raw)
    return {FIELD: field}


__all__ = ["FIELD", "FIELDS", "BASIS", "MAX_NODES", "read_fields"]
