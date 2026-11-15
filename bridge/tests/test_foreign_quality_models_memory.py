from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import foreign_quality_models_memory as models


ROOT = Path(__file__).resolve().parents[2]
ORDINARY_REPORT = ROOT / (
    "work/runtime/information-foreign-military-quality-20261029-001/"
    "ordinary-quality-model-name-001/ordinary-quality-model-name-001.json"
)
ORDINARY_REPORT_SHA256 = "6f88634128c1a8e78e0bb9fc30197491f95c4720f05ab26dcd3afb52b625317c"
BASE = 0x140000000
TARGET = 0x500000
MODEL_POINTERS = {
    "navy.heavy_ship_model": 0x600000,
    "navy.light_ship_model": 0x610000,
    "navy.galley_model": 0x620000,
}
KEYS = {
    "navy.heavy_ship_model": "HULL_HEAVY",
    "navy.light_ship_model": "HULL_LIGHT_001",
    "navy.galley_model": "GALLEY_MODEL_LONG",
}
FULLREF = (1 << 56) | (46 << 32) | int.from_bytes(b"ENG", "little")


class FakeMemory:
    def __init__(self):
        self.regions: list[tuple[int, bytearray]] = []
        self.requests: list[tuple[int, int, str]] = []
        self.fail_addresses: set[int] = set()
        self.short_addresses: set[int] = set()

    def put(self, address: int, data: bytes) -> None:
        data = bytes(data)
        for start, region in self.regions:
            if start <= address and address + len(data) <= start + len(region):
                region[address - start:address - start + len(data)] = data
                return
        if any(start < address + len(data) and address < start + len(region)
               for start, region in self.regions):
            raise AssertionError("fixture regions overlap")
        self.regions.append((address, bytearray(data)))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.requests.append((address, size, label))
        if address in self.fail_addresses:
            raise OSError("owned fake read failure")
        for start, region in self.regions:
            if start <= address and address + size <= start + len(region):
                data = bytes(region[address - start:address - start + size])
                if address in self.short_addresses:
                    return data[:-1]
                return data
        raise OSError(f"unmapped owned fixture read: {address:#x}+{size:#x}")


def _pinned_report() -> dict:
    raw = ORDINARY_REPORT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORDINARY_REPORT_SHA256
    return json.loads(raw.decode("utf-8"))


def _profile() -> dict:
    report = _pinned_report()
    method = report["method"]["body"]
    source_rows = report["sources"]
    ordinary_raw = ORDINARY_REPORT.read_bytes()
    return {
        "schema": models.PROFILE_SCHEMA,
        "executable_sha256": report["executable"]["sha256"],
        "vt_rva": report["vtable_slot"]["vtable_rva"],
        "method_rva": method["rva_start"],
        "method_end_rva_exclusive": method["rva_end_exclusive"],
        "method_code_hex": method["code_hex"],
        "method_code_sha256": method["sha256"],
        "source_pins": [
            source_rows["rea_model_getter"],
            source_rows["metadata_research"],
            {"path": ORDINARY_REPORT.relative_to(ROOT).as_posix(),
             "bytes": len(ordinary_raw),
             "sha256": hashlib.sha256(ordinary_raw).hexdigest()},
        ],
    }


def _string32_inline(key: str | bytes, *, capacity: int = 15, terminator: int = 0) -> bytes:
    encoded = key.encode("ascii") if isinstance(key, str) else bytes(key)
    if len(encoded) > capacity or capacity >= 16:
        raise ValueError("inline fixture shape")
    header = bytearray(32)
    header[:len(encoded)] = encoded
    header[len(encoded)] = terminator
    header[0x10:0x18] = len(encoded).to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    return bytes(header)


def _string32_heap(key: str, data_pointer: int, *, capacity: int | None = None,
                   terminator: int = 0) -> tuple[bytes, bytes]:
    encoded = key.encode("ascii")
    cap = max(len(encoded), 16) if capacity is None else capacity
    header = bytearray(32)
    header[:8] = data_pointer.to_bytes(8, "little")
    header[0x10:0x18] = len(encoded).to_bytes(8, "little")
    header[0x18:0x20] = cap.to_bytes(8, "little")
    return bytes(header), encoded + bytes([terminator])


def _scenario(keys: dict[str, str | bytes] | None = None) -> tuple[FakeMemory, dict]:
    mem = FakeMemory()
    profile = _profile()
    method = bytes.fromhex(profile["method_code_hex"])
    mem.put(BASE + models.METHOD_RVA, method)
    mem.put(BASE + models.VT_RVA + models.VT_SLOT_OFFSET,
            (BASE + models.METHOD_RVA).to_bytes(8, "little"))
    mem.put(TARGET + 0x20, FULLREF.to_bytes(8, "little"))
    for index, (component, offset) in enumerate(models.MODEL_POINTER_OFFSETS.items()):
        pointer = MODEL_POINTERS[component]
        mem.put(TARGET + offset, pointer.to_bytes(8, "little"))
        mem.put(pointer, (BASE + models.VT_RVA).to_bytes(8, "little"))
        key = (keys or KEYS)[component]
        if len(key) <= 15:
            mem.put(pointer + models.MODEL_KEY_OFFSET, _string32_inline(key))
        else:
            data_pointer = 0x700000 + index * 0x1000
            header, payload = _string32_heap(key, data_pointer)
            mem.put(pointer + models.MODEL_KEY_OFFSET, header)
            mem.put(data_pointer, payload)
    return mem, profile


def _binding() -> dict:
    return {"tag": "ENG", "slot": 46, "country_pointer": hex(TARGET),
            "fullref": hex(FULLREF), "fullref_raw_hex": FULLREF.to_bytes(8, "little").hex()}


def _install_names(monkeypatch, outcomes: dict[str, dict] | None = None):
    calls: list[tuple[str, int]] = []
    mapping = outcomes or {}

    def lookup(reader, base, key):
        assert isinstance(reader, models._BudgetReader)
        assert reader.module_base == base
        calls.append((key, base))
        if key in mapping:
            return mapping[key]
        return {"status": "known", "raw_hex": "4669656c64",
                "language": "l_english", "raw_inputs": {"private_test_address": "0xfeed000"}}

    monkeypatch.setattr(models._localization_name, "read_cached_name", lookup)
    return calls


def test_inline_and_heap_string32_keys_keep_raw_localized_names(monkeypatch):
    mem, profile = _scenario()
    calls = _install_names(monkeypatch)
    result = models.read_models(mem, BASE, _binding(), model_profile=profile)

    assert set(result) == set(models.MODEL_POINTER_OFFSETS)
    assert all(result[name]["status"] == "known" for name in result)
    assert result["navy.heavy_ship_model"]["value"] == {
        "localization_key": "HULL_HEAVY",
        "name": {"status": "known", "raw_hex": "4669656c64", "language": "l_english"},
    }
    assert result["navy.galley_model"]["raw"] == "GALLEY_MODEL_LONG"
    assert result["navy.heavy_ship_model"]["unit"] == "ship_model"
    assert result["navy.heavy_ship_model"]["scale"] == 1
    assert len(calls) == 3
    assert "raw_inputs" not in result["navy.heavy_ship_model"]["value"]["name"]
    assert "private_test_address" in result["navy.heavy_ship_model"]["raw_inputs"]["localization_cache"]["lookup"]["raw_inputs"]


def test_unknown_cached_name_preserves_verified_model_key(monkeypatch):
    mem, profile = _scenario()
    calls = _install_names(monkeypatch, {
        KEYS["navy.heavy_ship_model"]: {
            "status": "unknown", "reason": "LOCALIZATION_KEY_NOT_FOUND",
            "raw_inputs": {"private": "trace"},
        },
    })
    result = models.read_models(mem, BASE, _binding(), model_profile=profile)

    value = result["navy.heavy_ship_model"]["value"]
    assert value["localization_key"] == KEYS["navy.heavy_ship_model"]
    assert value["name"] == {"status": "unknown", "reason": "LOCALIZATION_KEY_NOT_FOUND"}
    assert "raw_inputs" not in value["name"]
    assert len(calls) == 3


@pytest.mark.parametrize("bad_key,reason", [
    ("BAD$MODEL", "MODEL_KEY_GRAMMAR_INVALID"),
    (b"BAD\xe9MODEL", "MODEL_KEY_NOT_ASCII"),
])
def test_invalid_key_grammar_retracts_only_that_model(monkeypatch, bad_key, reason):
    keys = dict(KEYS)
    keys["navy.light_ship_model"] = bad_key
    mem, profile = _scenario(keys)
    calls = _install_names(monkeypatch)
    result = models.read_models(mem, BASE, _binding(), model_profile=profile)

    assert result["navy.light_ship_model"]["status"] == "unknown"
    assert result["navy.light_ship_model"]["reason"] == reason
    assert result["navy.heavy_ship_model"]["status"] == "known"
    assert result["navy.galley_model"]["status"] == "known"
    assert bad_key not in [key for key, _ in calls]


def test_string32_missing_terminator_and_bad_heap_terminator_are_unknown(monkeypatch):
    mem, profile = _scenario()
    inline = MODEL_POINTERS["navy.heavy_ship_model"] + models.MODEL_KEY_OFFSET
    mem.put(inline, _string32_inline(KEYS["navy.heavy_ship_model"], terminator=ord("X")))
    galley = MODEL_POINTERS["navy.galley_model"] + models.MODEL_KEY_OFFSET
    heap_header, heap_payload = _string32_heap(KEYS["navy.galley_model"], 0x720000, terminator=1)
    mem.put(galley, heap_header)
    mem.put(0x720000, heap_payload)
    _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert result["navy.heavy_ship_model"]["reason"] == "MODEL_KEY_NUL_TERMINATOR_INVALID"
    assert result["navy.galley_model"]["reason"] == "MODEL_KEY_NUL_TERMINATOR_INVALID"
    assert result["navy.light_ship_model"]["status"] == "known"


@pytest.mark.parametrize("capacity", [0, models.MAX_STRING_CAPACITY + 1])
def test_string32_capacity_bounds_retract_only_that_model(monkeypatch, capacity):
    mem, profile = _scenario()
    model_header = MODEL_POINTERS["navy.light_ship_model"] + models.MODEL_KEY_OFFSET
    header = bytearray(_string32_inline(KEYS["navy.light_ship_model"]))
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    mem.put(model_header, bytes(header))
    _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert result["navy.light_ship_model"]["status"] == "unknown"
    assert result["navy.light_ship_model"]["reason"] == "MODEL_KEY_CAPACITY_INVALID"
    assert result["navy.heavy_ship_model"]["status"] == "known"
    assert result["navy.galley_model"]["status"] == "known"


def test_null_model_pointer_is_unknown_not_absent(monkeypatch):
    mem, profile = _scenario()
    mem.put(TARGET + models.MODEL_POINTER_OFFSETS["navy.light_ship_model"], bytes(8))
    _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert result["navy.light_ship_model"]["status"] == "unknown"
    assert result["navy.light_ship_model"]["reason"] == "MODEL_POINTER_NULL"
    assert result["navy.heavy_ship_model"]["status"] == "known"
    assert result["navy.galley_model"]["status"] == "known"


def test_model_vtable_mismatch_skips_only_that_model_key_read(monkeypatch):
    mem, profile = _scenario()
    model_pointer = MODEL_POINTERS["navy.light_ship_model"]
    mem.put(model_pointer, (BASE + models.VT_RVA + 8).to_bytes(8, "little"))
    calls = _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert result["navy.light_ship_model"]["reason"] == "MODEL_VTABLE_MISMATCH"
    assert result["navy.heavy_ship_model"]["status"] == "known"
    assert result["navy.galley_model"]["status"] == "known"
    assert KEYS["navy.light_ship_model"] not in [key for key, _ in calls]
    assert not any(label == "quality_model.navy.light_ship_model.string32_header"
                   for _, _, label in mem.requests)


@pytest.mark.parametrize("guard", ["method", "vtable_slot"])
def test_global_method_or_vtable_guard_mismatch_reads_no_model_cells(monkeypatch, guard):
    mem, profile = _scenario()
    if guard == "method":
        mem.put(BASE + models.METHOD_RVA, b"\x90" + bytes.fromhex(profile["method_code_hex"])[1:])
    else:
        mem.put(BASE + models.VT_RVA + models.VT_SLOT_OFFSET,
                (BASE + models.METHOD_RVA + 8).to_bytes(8, "little"))
    calls = _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert all(value["status"] == "unknown" for value in result.values())
    assert all(value["reason"] == ("MODEL_METHOD_CODE_GUARD_MISMATCH" if guard == "method"
                                   else "MODEL_VTABLE_SLOT_GUARD_MISMATCH")
               for value in result.values())
    assert not any(label.endswith(".object_pointer") for _, _, label in mem.requests)
    assert calls == []


def test_target_fullref_change_withdraws_all_before_model_reads(monkeypatch):
    mem, profile = _scenario()
    mem.put(TARGET + 0x20, (FULLREF ^ (1 << 40)).to_bytes(8, "little"))
    calls = _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert all(value["status"] == "unknown" for value in result.values())
    assert all(value["reason"] == "TARGET_FULLREF_CHANGED" for value in result.values())
    assert [label for _, _, label in mem.requests] == ["quality_model.target.fullref"]
    assert calls == []


def test_invalid_target_binding_performs_no_memory_reads(monkeypatch):
    mem, profile = _scenario()
    calls = _install_names(monkeypatch)
    invalid = {**_binding(), "country_pointer": "0x500001"}
    result = models.read_models(mem, BASE, invalid, model_profile=profile)

    assert all(value["status"] == "unknown" for value in result.values())
    assert all(value["reason"] == "TARGET_BINDING_INVALID" for value in result.values())
    assert mem.requests == []
    assert calls == []


def test_model_component_read_failure_isolated(monkeypatch):
    mem, profile = _scenario()
    pointer_cell = TARGET + models.MODEL_POINTER_OFFSETS["navy.light_ship_model"]
    mem.fail_addresses.add(pointer_cell)
    _install_names(monkeypatch)

    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert result["navy.light_ship_model"]["status"] == "unknown"
    assert result["navy.light_ship_model"]["reason"] == "READ_FAILED"
    assert result["navy.heavy_ship_model"]["status"] == "known"
    assert result["navy.galley_model"]["status"] == "known"


def test_invalid_profile_fails_closed_without_reading_memory():
    mem, profile = _scenario()
    profile["method_code_sha256"] = "0" * 64
    result = models.read_models(mem, BASE, _binding(), model_profile=profile)
    assert all(value["status"] == "unknown" for value in result.values())
    assert all(value["reason"] == "MODEL_PROFILE_CODE_HASH_MISMATCH" for value in result.values())
    assert mem.requests == []


def test_budget_rejects_oversize_single_read_and_aggregate_boundaries():
    class ZeroReader:
        def __init__(self):
            self.calls = 0

        def read(self, address, size, label):
            self.calls += 1
            return bytes(size)

    source = ZeroReader()
    bounded = models._BudgetReader(source, BASE)
    with pytest.raises(models._LeafFailure, match="READ_RANGE_INVALID"):
        bounded.read(0x800000, models.MAX_SINGLE_READ_BYTES + 1, "oversized")
    assert source.calls == 0

    for index in range(models.MAX_TOTAL_READ_BYTES // models.MAX_SINGLE_READ_BYTES):
        bounded.read(0x800000, models.MAX_SINGLE_READ_BYTES, f"byte-budget-{index}")
    with pytest.raises(models._LeafFailure, match="LOCAL_BUDGET_EXCEEDED"):
        bounded.read(0x800000, 1, "past-byte-budget")
    assert bounded.bytes_requested == models.MAX_TOTAL_READ_BYTES
    assert source.calls == models.MAX_TOTAL_READ_BYTES // models.MAX_SINGLE_READ_BYTES

    calls = models._BudgetReader(source, BASE)
    for index in range(models.MAX_READ_CALLS):
        calls.read(0x800000, 1, f"call-budget-{index}")
    with pytest.raises(models._LeafFailure, match="LOCAL_BUDGET_EXCEEDED"):
        calls.read(0x800000, 1, "past-call-budget")
    assert calls.calls == models.MAX_READ_CALLS

