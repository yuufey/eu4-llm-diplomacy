"""Offline tests for selected-node current-income inputs and cache comparison."""
from __future__ import annotations

import pytest

from bridge.information import trade_income_calculation_memory as memory
from bridge.information import trade_power_sum_memory


MODULE_BASE = 0x140000000
DATABASE = 0x200000000
COUNTRY_TABLE = 0x200001000
COUNTRY = 0x200002000
NODE_RUNTIME = 0x200010000
NODE_TABLE = 0x200011000
NODE_DEFINITION = 0x200012000
COUNTRY_BASE_OBJECT = 0x200013000
MODIFIER_MANAGER = 0x200014000
DESCRIPTOR_KEY = 0x200015000
MODIFIER_VALUES = 0x200016000
SPARSE_VALUES = 0x200017000
COUNTRY_SLOT = 7
NODE_ID = "champagne"
SUM_RECORD = {
    "status": "observed",
    "observation": {
        "stable": True,
        "canonical_observer_verified": True,
        "observer_nonplayer_verified": True,
    },
}


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _fullref(tag: str = "FRA", slot: int = COUNTRY_SLOT, *, high_byte: int = 1) -> bytes:
    value = bytearray(8)
    value[:3] = tag.encode("ascii")
    value[4:6] = slot.to_bytes(2, "little", signed=True)
    value[7] = high_byte
    return bytes(value)


class SyntheticMemory:
    """Byte-addressable fake memory so production helpers can request subranges."""

    def __init__(self):
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_label_fragments: set[str] = set()
        self.stability_overrides: dict[tuple[int, int], bytes] = {}

    def write(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        override = next(
            (raw for fragment, raw in self._label_overrides.items() if fragment in label),
            None,
        ) if hasattr(self, "_label_overrides") else None
        if ".stability." in label and (address, size) in self.stability_overrides:
            override = self.stability_overrides[(address, size)]
        if override is None:
            try:
                raw = bytes(self.data[address + offset] for offset in range(size))
            except KeyError as exc:
                raise AssertionError(f"unexpected read {label} at {address:#x}+{size:#x}") from exc
        else:
            raw = override
        if any(fragment in label for fragment in self.short_label_fragments):
            return raw[:-1]
        return raw


def _environment(
    *,
    cache_income: int = 4589,
    cache_before: int = 3762,
    special_slot: int = COUNTRY_SLOT,
    flag_ae: int = 0,
    modifier_mode: str = "dense",
    modifier_raw: int = 0,
    sparse_pairs: list[tuple[int, int]] | None = None,
    sparse_count: int | None = None,
    key: str = "trade_efficiency",
    processor: int = 0,
    cache_state: int = 0,
    node_gate: int = 1,
    node_count: int = COUNTRY_SLOT + 1,
    node_fullref: bytes | None = None,
    country_fullref: bytes | None = None,
    conditional_bonus: int = 100,
) -> tuple[SyntheticMemory, dict, dict, dict]:
    memory_image = SyntheticMemory()
    source_fullref = _fullref()
    actual_country_fullref = source_fullref if country_fullref is None else country_fullref
    embedded_fullref = source_fullref if node_fullref is None else node_fullref

    memory_image.write(MODULE_BASE + 0x233D8B0, _qword(DATABASE))
    memory_image.write(DATABASE + 0x118, _qword(COUNTRY_TABLE))
    memory_image.write(COUNTRY_TABLE + COUNTRY_SLOT * 8, _qword(COUNTRY))
    memory_image.write(COUNTRY + 0x20, actual_country_fullref)
    memory_image.write(COUNTRY + 0x28C8, _i32(cache_state))
    memory_image.write(COUNTRY + 0x2440, _qword(COUNTRY_BASE_OBJECT))
    memory_image.write(COUNTRY_BASE_OBJECT + 0x20, _i32(120))

    row = bytearray(0xC0)
    row[0x10:0x18] = embedded_fullref
    row[0x2C:0x30] = _i32(408)
    row[0x34:0x38] = _i32(cache_income)
    row[0x38:0x3C] = _i32(cache_before)
    row[0xAE] = flag_ae
    entry = NODE_TABLE + COUNTRY_SLOT * 0xC0
    memory_image.write(NODE_RUNTIME + 0xA8, _qword(NODE_DEFINITION))
    memory_image.write(NODE_RUNTIME + 0x18, _qword(NODE_TABLE))
    memory_image.write(NODE_RUNTIME + 0x24, _i32(node_count))
    memory_image.write(NODE_RUNTIME + 0xD0, _i32(node_gate))
    memory_image.write(NODE_RUNTIME + 0xB0, _i32(9221))
    memory_image.write(entry, bytes(row))

    memory_image.write(MODULE_BASE + 0x2358060, _qword(MODIFIER_MANAGER))
    descriptor = bytearray(0x60)
    key_bytes = key.encode("ascii")
    descriptor[:8] = _qword(DESCRIPTOR_KEY)
    descriptor[16:24] = _qword(len(key_bytes))
    descriptor[24:32] = _qword(max(16, len(key_bytes)))
    descriptor[0x40:0x48] = _qword(processor)
    memory_image.write(MODIFIER_MANAGER + 14 * 0x60, bytes(descriptor))
    memory_image.write(DESCRIPTOR_KEY, key_bytes + b"\0")

    modifier_object = COUNTRY + 0x28D0
    if modifier_mode == "dense":
        memory_image.write(modifier_object + 0x10, b"\x01")
        memory_image.write(modifier_object + 0x58, _qword(MODIFIER_VALUES))
        memory_image.write(modifier_object + 0x64, _i32(0))
        memory_image.write(MODIFIER_VALUES + 14 * 8 + 4, _i32(modifier_raw))
    elif modifier_mode == "sparse":
        pairs = sparse_pairs or []
        memory_image.write(modifier_object + 0x10, b"\x00")
        memory_image.write(modifier_object + 0x58, _qword(SPARSE_VALUES))
        memory_image.write(modifier_object + 0x64, _i32(len(pairs) if sparse_count is None else sparse_count))
        if pairs:
            memory_image.write(SPARSE_VALUES, b"".join(_i32(key_id) + _i32(value) for key_id, value in pairs))
    else:
        raise ValueError("unsupported fixture modifier mode")

    memory_image.write(MODULE_BASE + 0x233D8B8, _i32(special_slot))
    memory_image.write(MODULE_BASE + 0x233E53C, _i32(conditional_bonus))

    country_pointer = hex(COUNTRY)
    country_fullref_hex = source_fullref.hex()
    trade_income_record = {
        "_synthetic_valid": True,
        "status": "observed",
        "country": "FRA",
        "country_pointer": country_pointer,
        "country_fullref_address": hex(COUNTRY + 0x20),
        "country_fullref_raw_hex": country_fullref_hex,
        "country_slot": COUNTRY_SLOT,
        "special_slot": special_slot,
        "nodes": [{
            "node_id": NODE_ID,
            "runtime_pointer": hex(NODE_RUNTIME),
            "table_pointer": hex(NODE_TABLE),
            "definition_pointer": hex(NODE_DEFINITION),
            "entry_pointer": hex(entry),
            "entry_raw_hex": bytes(row).hex(),
        }],
    }
    country_handle = {
        "address": {"va": hex(COUNTRY + 0x20)},
        "raw_hex": country_fullref_hex,
        "value": hex(int.from_bytes(source_fullref, "little", signed=False)),
        "tag": "FRA",
        "slot": COUNTRY_SLOT,
    }
    country_scan = {
        "status": "observed",
        "requested_country": "FRA",
        "scanned_entries": trade_power_sum_memory.MAX_SOURCE_SCAN_ENTRIES,
        "table_field": {
            "address": {"va": hex(DATABASE + 0x118)},
            "raw_hex": _qword(COUNTRY_TABLE).hex(),
            "value": hex(COUNTRY_TABLE),
        },
        "country_pointer": {"va": country_pointer},
        "country_handle": country_handle,
        "matches": [{"table_index": COUNTRY_SLOT, "country_pointer": {"va": country_pointer}}],
    }
    return memory_image, trade_income_record, country_scan, SUM_RECORD


@pytest.fixture(autouse=True)
def _mock_only_upstream_validators(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        memory._sum,
        "validate_record",
        lambda record, trade, scan: isinstance(record, dict) and record.get("status") == "observed",
    )
    monkeypatch.setattr(
        memory._identity._trade,
        "validate_record",
        lambda record: isinstance(record, dict) and record.get("_synthetic_valid") is True,
    )


def _read(env, *, node_id=NODE_ID):
    reader, trade_income_record, country_scan, sum_record = env
    return memory.read_fields(
        reader, MODULE_BASE, trade_income_record, country_scan, sum_record, node_id=node_id
    )


def test_default_observation_reconstructs_4589_and_uses_only_bounded_selected_inputs():
    env = _environment()
    result = _read(env)

    assert result["status"] == "observed"
    assert result["stable"] is True
    assert result["basis"] == "native_current_trade_income_cache_arithmetic"
    assert result["complete"] is False
    assert result["value"]["outputs"]["income_before_multiplier_raw"] == 3762
    assert result["value"]["outputs"]["income_raw"] == 4589
    assert result["value"]["cache"] == {
        "income_before_multiplier_raw": 3762,
        "income_raw": 4589,
    }
    assert result["value"]["matches_cache"] is True
    assert result["raw_inputs"]["modifier_storage"]["raw_inputs"]["modifier_id"] == 14
    assert result["raw_inputs"]["descriptor"]["key"] == "trade_efficiency"
    assert all(label.startswith("trade_income_calculation.") for _, _, label in env[0].reads)
    assert not any(address == COUNTRY_TABLE and size >= trade_power_sum_memory.MAX_SOURCE_SCAN_ENTRIES * 8
                   for address, size, _ in env[0].reads)
    assert result["raw_inputs"]["budget"]["bytes_requested"] <= 64 * 1024


def test_cache_mismatch_is_reported_without_erasing_current_calculation():
    result = _read(_environment(cache_income=5000, cache_before=4000))

    assert result["status"] == "observed"
    assert result["stable"] is True
    assert result["value"]["outputs"]["income_raw"] == 4589
    assert result["value"]["matches_cache"] is False
    assert result["value"]["cache"] == {
        "income_before_multiplier_raw": 4000,
        "income_raw": 5000,
    }


@pytest.mark.parametrize(
    "pairs, expected_raw, expected_index",
    [
        ([(14, 35), (14, 900)], 35, 0),
        ([(13, 35), (15, 900)], 0, None),
    ],
)
def test_sparse_modifier_uses_first_match_and_absent_key_is_known_zero(pairs, expected_raw, expected_index):
    result = _read(_environment(modifier_mode="sparse", sparse_pairs=pairs))

    assert result["status"] == "observed"
    assert result["value"]["inputs"]["modifier_raw"] == expected_raw
    storage = result["raw_inputs"]["modifier_storage"]["raw_inputs"]
    assert storage["mode"] == "sparse"
    assert storage["first_match_index"] == expected_index


@pytest.mark.parametrize(
    "special_slot, flag_ae, expected_applies",
    [
        (COUNTRY_SLOT, 0, True),
        (COUNTRY_SLOT + 1, 1, True),
        (COUNTRY_SLOT + 1, 0, False),
    ],
)
def test_bonus_applies_from_special_slot_or_row_flag(special_slot, flag_ae, expected_applies):
    result = _read(_environment(special_slot=special_slot, flag_ae=flag_ae))

    assert result["status"] == "observed"
    assert result["value"]["inputs"]["bonus_applies"] is expected_applies
    assert result["value"]["inputs"]["bonus_raw"] == (100 if expected_applies else 0)


@pytest.mark.parametrize(
    "options",
    [
        {"key": "wrong_efficiency"},
        {"processor": 0x200018000},
        {"cache_state": 1},
        {"node_gate": 0},
        {"node_fullref": _fullref("POR", COUNTRY_SLOT)},
        {"node_count": COUNTRY_SLOT},
    ],
)
def test_mismatched_key_processor_cache_gate_fullref_or_row_count_is_unknown(options):
    result = _read(_environment(**options))

    assert result["status"] == "unknown"
    assert result["complete"] is False
    assert isinstance(result.get("reason"), str)
    assert result["raw_inputs"]["reads"]


def test_stability_reread_drift_retracts_the_calculation():
    env = _environment()
    env[0].stability_overrides[(NODE_RUNTIME + 0xB0, 4)] = _i32(9222)

    result = _read(env)

    assert result["status"] == "unknown"
    assert result["reason"] == "INCOME_CALCULATION_INPUT_CHANGED"


def test_short_selected_read_is_unknown():
    env = _environment()
    env[0].short_label_fragments.add("node_cash")

    result = _read(env)

    assert result["status"] == "unknown"
    assert result["raw_inputs"]["reads"]


def test_sparse_modifier_count_above_storage_limit_is_unknown():
    result = _read(_environment(modifier_mode="sparse", sparse_count=8193))

    assert result["status"] == "unknown"
    assert result["reason"] == "INCOME_CALCULATION_STORAGE_UNVERIFIED"
    assert result["raw_inputs"]["modifier_storage"]["reason"] == "MODIFIER_COUNT_OUT_OF_RANGE"


def test_leaf_read_budget_is_enforced_during_sparse_absence_scan():
    pairs = [(13, index) for index in range(8192)]
    result = _read(_environment(modifier_mode="sparse", sparse_pairs=pairs))

    assert result["status"] == "unknown"
    assert result["raw_inputs"]["budget"]["bytes_requested"] <= 64 * 1024
    assert result["raw_inputs"]["budget"]["bytes_requested"] < 64 * 1024
    rejected = result["raw_inputs"]["reads"][-1]
    assert rejected["status"] == "failed"
    assert "sparse_entries" in rejected["label"]


def test_null_or_nonunique_node_selector_is_rejected_without_memory_reads():
    env = _environment()
    result = _read(env, node_id="Null")
    assert result["status"] == "unknown"
    assert env[0].reads == []

    env = _environment()
    env[1]["nodes"].append(dict(env[1]["nodes"][0]))
    result = _read(env)
    assert result["status"] == "unknown"
    assert result["reason"] == "INCOME_CALCULATION_NODE_NOT_UNIQUE"
    assert env[0].reads == []
