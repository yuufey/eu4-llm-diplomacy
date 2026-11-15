"""Private bounded native existence predicate for one ordinary country."""
from __future__ import annotations

from typing import Any

from . import country_knowledge_memory as _knowledge
from . import province_reference_memory as _province


SCHEMA = "information.country_existence_memory.v1"
EXISTENCE_DWORD_OFFSET = 0x1344
COUNTRY_KIND_OFFSET = 0x26
SPECIAL_COUNTRY_KIND = 7
MAX_READ_CALLS = 2
MAX_TOTAL_READ_BYTES = 5
MAX_SINGLE_READ_BYTES = 4


class _Unknown(ValueError):
    pass


class _BudgetReader:
    """Enforce and retain this leaf's two-read/five-byte native-read budget."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.calls = 0
        self.bytes_requested = 0
        self.max_single_read = 0
        self.reads: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or not _province._is_user_address(address)
                or type(size) is not int or size not in (1, 4)):
            raise _Unknown("READ_ADDRESS_OR_SIZE_INVALID")
        try:
            _province._checked_range(address, size, label)
        except Exception as exc:
            raise _Unknown("READ_ADDRESS_OR_SIZE_INVALID") from exc
        if self.calls >= MAX_READ_CALLS:
            raise _Unknown("READ_CALL_BUDGET_EXCEEDED")
        if self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            raise _Unknown("READ_BYTE_BUDGET_EXCEEDED")

        self.calls += 1
        self.bytes_requested += size
        self.max_single_read = max(self.max_single_read, size)
        method = getattr(self.source, "read", None)
        try:
            raw = method(address, size, label) if callable(method) else self.source(address, size, label)
        except Exception as exc:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": type(exc).__name__})
            raise _Unknown(f"READ_FAILED:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            self.reads.append({"address": hex(address), "size": size, "label": label,
                               "status": "failed", "error_type": "short_or_invalid_read"})
            raise _Unknown(f"READ_SHORT_OR_INVALID:{label}")
        result = bytes(raw)
        self.reads.append({"address": hex(address), "size": size, "label": label,
                           "status": "ok", "raw_hex": result.hex()})
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "bytes_requested": self.bytes_requested,
            "max_single_read": self.max_single_read,
            "limits": {"calls": MAX_READ_CALLS, "bytes": MAX_TOTAL_READ_BYTES,
                       "single_read_bytes": MAX_SINGLE_READ_BYTES},
        }


def _finish_unknown(reason: str, raw_inputs: dict[str, Any],
                    budget: _BudgetReader) -> dict[str, Any]:
    raw_inputs["ordered_read_trace"] = list(budget.reads)
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": str(reason)[:160],
        "basis": "native_country_existence_predicate",
        "raw_inputs": raw_inputs,
        "read_budget": budget.summary(),
    }


def read_existence(reader: Any, module_base: int, target_binding: Any) -> dict[str, Any]:
    """Evaluate the native existence predicate for one validated target.

    Ordinary fullrefs are resolved by the shared country binding validator.
    The native DWORD at country ``+0x1344`` is interpreted as a raw bit
    pattern: every nonzero value is true. Only an exact zero reads the kind
    byte at ``+0x26``; a kind mismatch makes the result unknown.
    """
    budget = _BudgetReader(reader)
    raw_inputs: dict[str, Any] = {}
    try:
        if (type(module_base) is not int or not _province._is_user_address(module_base)
                or module_base & 7):
            raise _Unknown("MODULE_BASE_INVALID")
        if not callable(getattr(reader, "read", None)) and not callable(reader):
            raise _Unknown("READER_INVALID")
        target = _knowledge._validated_binding(target_binding, "target")
        raw_inputs.update({
            "module_base": hex(module_base),
            "target_binding": {
                "tag": target["tag"],
                "slot": target["slot"],
                "country_pointer": hex(target["country_pointer"]),
                "fullref": hex(target["fullref"]),
                "fullref_raw_hex": target["fullref_raw_hex"],
            },
            "existence_dword_address": hex(_province._checked_add(
                target["country_pointer"], EXISTENCE_DWORD_OFFSET,
                "country_existence.dword")),
            "bound_fullref_kind_u8": (target["fullref"] >> 48) & 0xFF,
        })

        dword_address = int(raw_inputs["existence_dword_address"], 16)
        dword_raw = budget.read(dword_address, 4, "country_existence.dword_u32")
        dword_value = int.from_bytes(dword_raw, "little", signed=False)
        raw_inputs.update({
            "existence_dword_raw_hex": dword_raw.hex(),
            "existence_dword_u32": dword_value,
            "existence_dword_nonzero": dword_value != 0,
        })
        if dword_value != 0:
            value = True
            raw_inputs["kind_check"] = {"status": "not_read", "reason": "NONZERO_DWORD"}
        else:
            kind_address = _province._checked_add(
                target["country_pointer"], COUNTRY_KIND_OFFSET,
                "country_existence.kind")
            kind_raw = budget.read(kind_address, 1, "country_existence.kind_u8")
            kind_value = kind_raw[0]
            expected_kind = raw_inputs["bound_fullref_kind_u8"]
            raw_inputs["kind_check"] = {
                "status": "read",
                "address": hex(kind_address),
                "raw_hex": kind_raw.hex(),
                "country_kind_u8": kind_value,
                "bound_fullref_kind_u8": expected_kind,
                "matches_fullref": kind_value == expected_kind,
            }
            if kind_value != expected_kind:
                raise _Unknown("COUNTRY_KIND_FULLREF_MISMATCH")
            value = kind_value == SPECIAL_COUNTRY_KIND

        raw_inputs["ordered_read_trace"] = list(budget.reads)
        return {
            "schema": SCHEMA,
            "status": "known",
            "value": value,
            "basis": "native_country_existence_predicate",
            "raw_inputs": raw_inputs,
            "read_budget": budget.summary(),
        }
    except _Unknown as exc:
        return _finish_unknown(str(exc), raw_inputs, budget)
    except ValueError as exc:
        # The shared target validator and checked-address helpers use
        # ValueError subclasses for malformed bindings and overflow.
        reason = str(exc) or type(exc).__name__
        return _finish_unknown(reason, raw_inputs, budget)
    except Exception as exc:
        return _finish_unknown(f"READ_OR_LAYOUT_INVALID:{type(exc).__name__}",
                               raw_inputs, budget)


__all__ = ["SCHEMA", "read_existence"]
