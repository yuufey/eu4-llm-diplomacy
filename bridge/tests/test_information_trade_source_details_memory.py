from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import trade_details_memory as details
from bridge.information import trade_income_memory as trade
from bridge.tests import test_information_trade_details_memory as old_details
from bridge.tests import test_information_trade_income_memory as old_income


MODULE_BASE = old_income.MODULE_BASE
COUNTRY_POINTER = old_income.COUNTRY_POINTER
DATABASE_ROOT = 0x300000000
COUNTRY_TABLE = 0x300001000
CAPITAL_ANCHOR = 0x300002000
FOREIGN_COUNTRY_ONE = 0x300003000
FOREIGN_COUNTRY_TWO = 0x300004000
TRANSFER_TO = 0x300005000
TRANSFER_FROM = 0x300006000
DYNAMIC_LINK_INLINE = 0x300007000
DYNAMIC_ITEM_INLINE = 0x300008000
DYNAMIC_LINK_HEAP = 0x300009000
DYNAMIC_ITEM_HEAP = 0x30000A000
DYNAMIC_HEAP_NAME = 0x30000B000


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _put(reader: old_income.Reader, address: int, payload: bytes) -> None:
    reader.data[(address, len(payload))] = payload


def _profile() -> dict:
    profile = old_details._details_profile()
    profile["profile_id"] = "trade-details-memory-1374-v3"
    return profile


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    trade_profile = old_income._profile()
    profile = _profile()
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(details, "EXPECTED_PROFILE_SHA256", "d" * 64)
    monkeypatch.setattr(details, "EXPECTED_TRADE_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(details, "_active_profile", lambda: profile)
    return profile


def _set_entry(reader: old_income.Reader, table: int, values: dict[int, int], pointers: dict[int, int] | None = None) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    for offset, value in values.items():
        raw[offset:offset + 4] = _i32(value)
    for offset, value in (pointers or {}).items():
        raw[offset:offset + 8] = _qword(value)
    reader.data[(address, 0xC0)] = bytes(raw)


def _inline_name(payload: bytes, capacity: int) -> bytes:
    raw = bytearray(32)
    raw[: len(payload)] = payload
    raw[0x18:0x20] = _qword(capacity)
    return bytes(raw)


def _install_details_memory(reader: old_income.Reader, *, include_dynamic: bool = True, include_transfer: bool = True) -> None:
    _put(reader, MODULE_BASE + 0x600, bytes.fromhex("aabb"))
    _put(reader, MODULE_BASE + 0x233D8B0, _qword(DATABASE_ROOT))
    _put(reader, DATABASE_ROOT + 0x118, _qword(COUNTRY_TABLE))
    fullref = reader.data[(COUNTRY_POINTER + 0x20, 8)]
    _put(reader, COUNTRY_TABLE + 7 * 8, _qword(COUNTRY_POINTER))
    _put(reader, COUNTRY_POINTER + 0x14C8, _qword(CAPITAL_ANCHOR))
    _put(reader, CAPITAL_ANCHOR + 0xE8, _qword(old_income.RUNTIME_ONE))
    _put(reader, MODULE_BASE + 0x233F2F0, _i32(2450))

    foreign_one_ref = b"ENG\0" + (8).to_bytes(2, "little", signed=True) + b"\0\0"
    foreign_two_ref = b"SAX\0" + (9).to_bytes(2, "little", signed=True) + b"\0\0"
    _put(reader, COUNTRY_TABLE + 8 * 8, _qword(FOREIGN_COUNTRY_ONE))
    _put(reader, COUNTRY_TABLE + 9 * 8, _qword(FOREIGN_COUNTRY_TWO))
    _put(reader, FOREIGN_COUNTRY_ONE + 0x20, foreign_one_ref)
    _put(reader, FOREIGN_COUNTRY_TWO + 0x20, foreign_two_ref)

    pointers: dict[int, int] = {}
    if include_dynamic:
        pointers[0x90] = DYNAMIC_LINK_INLINE
        _put(reader, DYNAMIC_LINK_INLINE, _qword(DYNAMIC_ITEM_INLINE))
        _put(reader, DYNAMIC_LINK_INLINE + 0x10, _qword(DYNAMIC_LINK_HEAP))
        _put(reader, DYNAMIC_ITEM_INLINE + 0x34, _i32(-13))
        _put(reader, DYNAMIC_ITEM_INLINE + 0x10, _inline_name(b"inline_key\0", 11))
        _put(reader, DYNAMIC_LINK_HEAP, _qword(DYNAMIC_ITEM_HEAP))
        _put(reader, DYNAMIC_LINK_HEAP + 0x10, _qword(0))
        _put(reader, DYNAMIC_ITEM_HEAP + 0x34, _i32(2048))
        heap_obj = bytearray(32)
        heap_obj[:8] = _qword(DYNAMIC_HEAP_NAME)
        heap_obj[0x18:0x20] = _qword(16)
        _put(reader, DYNAMIC_ITEM_HEAP + 0x10, bytes(heap_obj))
        _put(reader, DYNAMIC_HEAP_NAME, b"heap_key\0" + bytes(1016))
    if include_transfer:
        pointers[0x60] = TRANSFER_TO
        pointers[0x78] = TRANSFER_FROM
        _put(reader, TRANSFER_TO, _qword(int.from_bytes(foreign_one_ref, "little")))
        _put(reader, TRANSFER_TO + 0x8, _i32(-1200))
        _put(reader, TRANSFER_TO + 0x18, _qword(0))
        _put(reader, TRANSFER_FROM, _qword(int.from_bytes(foreign_two_ref, "little")))
        _put(reader, TRANSFER_FROM + 0x8, _i32(700))
        _put(reader, TRANSFER_FROM + 0x18, _qword(0))

    _set_entry(reader, old_income.TABLE_ONE, {0x2C: -1200, 0x28: 3813, 0x1C: 0, 0x40: 17}, pointers)
    _set_entry(reader, old_income.TABLE_TWO, {0x2C: 45, 0x28: 0, 0x1C: -5, 0x40: -1})


def _source(reader: old_income.Reader) -> dict:
    source = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert source["status"] == "observed"
    assert trade.validate_record(source)
    reader.reads.clear()
    return source


def _record(configured, *, include_dynamic: bool = True, include_transfer: bool = True):
    reader = old_income._build_reader()
    _install_details_memory(reader, include_dynamic=include_dynamic, include_transfer=include_transfer)
    source = _source(reader)
    record = details.read_fields(reader, MODULE_BASE, source)
    return reader, source, record


def test_v3_profile_is_pinned_with_native_tail_contract():
    profile = details._load_profile()
    assert profile["profile_id"] == "trade-details-memory-1374-v3"
    layout = details._profile_layout(profile)
    limits = details._profile_limits(profile)
    assert layout["transfer_to_head_offset"] == 0x60
    assert layout["transfer_from_head_offset"] == 0x78
    assert layout["transfer_element_next_offset"] == 0x18
    assert layout["transfer_max_country_slot"] == 4095
    assert limits["max_child_read_bytes"] == 128 * 1024
    assert limits["max_elements_per_node_across_three_chains"] == 64
    assert limits["max_elements_global_across_three_chains"] == 256
    assert limits["max_transfer_items_per_container"] == 64
    assert limits["max_transfer_items_total"] == 256


def test_capital_dynamic_and_transfer_are_bounded_and_keep_native_order(configured):
    reader, source, record = _record(configured)
    assert record["status"] == "observed"
    assert details.validate_record(record, source)
    assert record["capital_context"]["status"] == "observed"
    assert record["nodes"][0]["capital"] == {
        "status": "observed", "included": True, "raw": 2450,
        "raw_hex": "92090000", "reason": None,
    }
    dynamic = record["nodes"][0]["dynamic_sources"]
    assert dynamic["status"] == "observed"
    assert [item["name_pointer_kind"] for item in dynamic["items"]] == ["inline_object", "heap"]
    assert [item["value_raw"] for item in dynamic["items"]] == [-13, 2048]
    transfer = record["nodes"][0]["transfer_sources"]
    assert [item["direction"] for item in transfer["to"]["items"]] == ["to"]
    assert transfer["to"]["items"][0]["raw"] == -1200
    assert transfer["from"]["items"][0]["raw"] == 700
    assert transfer["to"]["items"][0]["country_fullref_matched"] is True
    assert transfer["to"]["items"][0]["country_tag"] == "ENG"
    labels = [label for _address, _size, label in reader.reads]
    assert "trade_details_v3.code.details_leaf" in labels
    assert "transfer.element.fullref" in labels


def test_transfer_direction_preserves_raw_sign_and_does_not_reclassify(configured):
    _reader, source, record = _record(configured, include_dynamic=False)
    assert details.validate_record(record, source)
    to_item = record["nodes"][0]["transfer_sources"]["to"]["items"][0]
    from_item = record["nodes"][0]["transfer_sources"]["from"]["items"][0]
    assert to_item["native_key"] == "TRANSFER_TRADE_POWER_TO"
    assert from_item["native_key"] == "TRANSFER_TRADE_POWER_FROM"
    assert to_item["raw"] == -1200 and to_item["raw_hex"] == "50fbffff"
    assert from_item["raw"] == 700 and from_item["raw_hex"] == "bc020000"

    changed = deepcopy(record)
    changed["nodes"][0]["transfer_sources"]["to"]["items"][0]["raw"] = 1200
    assert not details.validate_record(changed, source)


def test_capital_anchor_miss_is_observed_without_a_capital_row(configured):
    reader = old_income._build_reader()
    _install_details_memory(reader, include_dynamic=False, include_transfer=False)
    _put(reader, CAPITAL_ANCHOR + 0xE8, _qword(0x30000C000))
    source = _source(reader)
    record = details.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    assert record["capital_context"]["status"] == "observed"
    assert record["capital_context"]["included_node_id"] is None
    assert record["nodes"][0]["capital"]["included"] is False
    assert details.validate_record(record, source)


def test_capital_country_pointer_mismatch_is_explicit_and_rejected(configured):
    reader = old_income._build_reader()
    _install_details_memory(reader, include_dynamic=False, include_transfer=False)
    _put(reader, COUNTRY_TABLE + 7 * 8, _qword(FOREIGN_COUNTRY_ONE))
    source = _source(reader)
    record = details.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    assert record["capital_context"]["status"] == "unknown"
    assert "selected_country_mismatch" in record["capital_context"]["reason"]
    assert record["nodes"][0]["source_rows"]
    assert not details.validate_record(record, source)


@pytest.mark.parametrize("mode", ["dynamic_cycle", "dynamic_cap", "transfer_cycle", "transfer_cap"])
def test_detail_subdomain_failure_is_unknown_without_removing_base_rows(configured, mode, monkeypatch):
    reader = old_income._build_reader()
    _install_details_memory(reader, include_dynamic=True, include_transfer=True)
    source = _source(reader)
    if mode == "dynamic_cycle":
        _put(reader, DYNAMIC_LINK_HEAP + 0x10, _qword(DYNAMIC_LINK_INLINE))
    elif mode == "dynamic_cap":
        profile = _profile()
        profile["limits"]["max_dynamic_items_per_node"] = 1
        monkeypatch.setattr(details, "_active_profile", lambda: profile)
        real_limits = details._profile_limits
        def dynamic_limits(_profile):
            normalized = deepcopy(_profile)
            normalized["limits"]["max_dynamic_items_per_node"] = 64
            return {**real_limits(normalized), "max_dynamic_items_per_node": 1}
        monkeypatch.setattr(details, "_profile_limits", dynamic_limits)
    elif mode == "transfer_cycle":
        _put(reader, TRANSFER_TO + 0x18, _qword(TRANSFER_TO))
    else:
        profile = _profile()
        profile["limits"]["max_transfer_items_per_container"] = 0
        monkeypatch.setattr(details, "_active_profile", lambda: profile)
        real_limits = details._profile_limits
        def transfer_limits(_profile):
            normalized = deepcopy(_profile)
            normalized["limits"]["max_transfer_items_per_container"] = 64
            return {**real_limits(normalized), "max_transfer_items_per_container": 0}
        monkeypatch.setattr(details, "_profile_limits", transfer_limits)
    record = details.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    assert record["nodes"][0]["source_rows"]
    if mode.startswith("dynamic"):
        assert record["nodes"][0]["dynamic_sources"]["status"] == "unknown"
    else:
        assert record["nodes"][0]["transfer_sources"]["to"]["status"] == "unknown"


def test_transfer_fullref_mismatch_keeps_raw_item_but_withholds_country_tag(configured):
    reader, source, record = _record(configured, include_dynamic=False)
    assert details.validate_record(record, source)
    item = record["nodes"][0]["transfer_sources"]["to"]["items"][0]
    changed = deepcopy(record)
    changed_item = changed["nodes"][0]["transfer_sources"]["to"]["items"][0]
    changed_item["country_fullref_raw_hex"] = source["country_fullref_raw_hex"]
    changed_item["country_fullref_matched"] = False
    changed_item["country_tag_status"] = "fullref_mismatch"
    assert not details.validate_record(changed, source)
    assert item["country_tag"] == "ENG"


def test_retract_clears_transfer_lookup_and_nodes(configured):
    _reader, source, record = _record(configured)
    assert details.validate_record(record, source)
    retracted = details.retract_record(record, "test_cleanup")
    assert retracted["status"] == "unknown"
    assert retracted["nodes"] is None
    assert retracted["transfer_lookup"] == {"status": "unknown", "reason": "test_cleanup"}
    assert not details.validate_record(retracted, source)


@pytest.mark.parametrize(
    ("node_limit", "global_limit", "reason_part"),
    [(2, 256, "detail_elements_per_node_limit"), (3, 2, "detail_elements_global_limit")],
)
def test_dynamic_to_from_share_v3_element_limits(configured, monkeypatch, node_limit, global_limit, reason_part):
    reader = old_income._build_reader()
    _install_details_memory(reader, include_dynamic=True, include_transfer=True)
    # Keep exactly one dynamic element so the following TO and FROM heads
    # exercise the same per-node/global allowance.
    _put(reader, DYNAMIC_LINK_INLINE + 0x10, _qword(0))
    source = _source(reader)
    real_limits = details._profile_limits

    def shared_limits(profile):
        normalized = real_limits(profile)
        normalized["max_elements_per_node_across_three_chains"] = node_limit
        normalized["max_elements_global_across_three_chains"] = global_limit
        return normalized

    monkeypatch.setattr(details, "_profile_limits", shared_limits)
    record = details.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    node = record["nodes"][0]
    assert node["dynamic_sources"]["status"] == "observed"
    assert len(node["dynamic_sources"]["items"]) == 1
    assert node["transfer_sources"]["to"]["status"] == "observed"
    assert len(node["transfer_sources"]["to"]["items"]) == 1
    assert node["transfer_sources"]["from"]["status"] == "unknown"
    assert reason_part in node["transfer_sources"]["from"]["reason"]
    assert details.validate_record(record, source)


def test_budget_reserves_continuous_failed_reads_before_underlying_call():
    class FailingReader:
        def __init__(self):
            self.attempts = 0

        def read(self, _address, _size, _label):
            self.attempts += 1
            raise RuntimeError("synthetic_rpm_failure")

    failing = FailingReader()
    budget = details._Budget(failing, limit=8)
    with pytest.raises(RuntimeError, match="synthetic_rpm_failure"):
        budget.read(0x300010000, 4, "failed.first")
    assert (budget.bytes_requested, budget.calls, failing.attempts) == (4, 1, 1)
    with pytest.raises(RuntimeError, match="synthetic_rpm_failure"):
        budget.read(0x300010100, 4, "failed.second")
    assert (budget.bytes_requested, budget.calls, failing.attempts) == (8, 2, 2)
    with pytest.raises(details.ReadError, match="read_budget_exceeded"):
        budget.read(0x300010200, 1, "failed.third")
    assert (budget.bytes_requested, budget.calls, failing.attempts) == (8, 2, 2)
