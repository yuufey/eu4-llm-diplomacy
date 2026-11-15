from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import country_resources_memory as crm
from bridge.information import trade_details_memory as details
from bridge.information import trade_income_memory as trade
from bridge.tests import test_information_trade_income_memory as old_fixture


MODULE_BASE = old_fixture.MODULE_BASE
COUNTRY_POINTER = old_fixture.COUNTRY_POINTER
HANDLE = 0x7788


def _details_profile() -> dict:
    return {
        "profile_id": "trade-details-memory-1374-v3",
        "game_version": details.EXPECTED_VERSION,
        "executable": {"sha256": details.EXPECTED_EXE_SHA256},
        "source_index": {
            "source_index_id": "trade-details-source-index-002",
            "path": "work/runtime/trade-details-source-index.json",
            "sha256": "c" * 64,
        },
        "layout": {
            "entry_size_bytes": 192,
            "share_offset": "0x2c",
            "source_offsets": {
                "TP_PROVINCE_POWER": "0x28",
                "TP_SHIP_POWER": "0x1c",
                "MERCHANT_DOWNSTREAM_BONUS": "0x40",
            },
            "source_trade_profile_sha256": "b" * 64,
            "capital": {
                "database_global_rva": "0x233d8b0",
                "country_table_offset": "0x118",
                "country_fullref_offset": "0x20",
                "country_14c8_offset": "0x14c8",
                "anchor_node_offset": "0xe8",
                "scalar_rva": "0x233f2f0",
                "vector_stride": 8,
            },
            "dynamic": {
                "head_offset": "0x90",
                "link_item_offset": "0x0",
                "link_next_offset": "0x10",
                "item_value_offset": "0x34",
                "item_name_offset": "0x10",
                "name_capacity_offset": "0x18",
                "name_heap_pointer_offset": "0x0",
                "name_inline_capacity": 16,
                "name_object_size": 32,
            },
            "transfer": {
                "to_head_offset": "0x60",
                "from_head_offset": "0x78",
                "element_fullref_offset": "0x0",
                "element_value_offset": "0x8",
                "element_next_offset": "0x18",
                "max_country_slot": 4095,
                "vector_stride": 8,
            },
        },
        "semantics": {
            "basis": "native_trade_node_share_source_capital_dynamic_and_transfer_tail",
            "unit": "mixed",
            "scale": 1000,
            "period": "current",
            "value_origin": "copied_native_cache",
            "complete": False,
        },
        "limits": {
            "max_child_read_bytes": 131072,
            "max_single_read_bytes": 65536,
            "max_dynamic_items_per_node": 64,
            "max_dynamic_items_total": 256,
            "max_dynamic_name_bytes": 1024,
            "max_transfer_items_per_container": 64,
            "max_transfer_items_total": 256,
            "max_country_slot": 4095,
        },
        "code_guards": [{"name": "details_leaf", "rva": "0x600", "hex": "aabb"}],
    }


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    trade_profile = old_fixture._profile()
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(details, "EXPECTED_PROFILE_SHA256", "d" * 64)
    monkeypatch.setattr(details, "EXPECTED_TRADE_PROFILE_SHA256", "b" * 64)
    profile = _details_profile()
    monkeypatch.setattr(details, "_active_profile", lambda: profile)
    return profile


def _reader_with_details_guard() -> old_fixture.Reader:
    reader = old_fixture._build_reader()
    reader.data[(MODULE_BASE + 0x600, 2)] = bytes.fromhex("aabb")
    return reader


def _set_entry(reader: old_fixture.Reader, table: int, values: dict[int, int]) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    for offset, value in values.items():
        raw[offset:offset + 4] = old_fixture._i32(value)
    reader.data[(address, 0xC0)] = bytes(raw)


def _source(reader: old_fixture.Reader) -> dict:
    record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert trade.validate_record(record)
    return record


def _record(configured):
    reader = _reader_with_details_guard()
    _set_entry(reader, old_fixture.TABLE_ONE, {
        0x2C: -1200,
        0x28: 3813,
        0x1C: 0,
        0x40: 17,
    })
    _set_entry(reader, old_fixture.TABLE_TWO, {
        0x2C: 45,
        0x28: 0,
        0x1C: -5,
        0x40: -1,
    })
    source = _source(reader)
    reader.reads.clear()
    record = details.read_fields(reader, MODULE_BASE, source)
    return reader, source, record


def test_pinned_profile_and_real_validator_accept_bounded_fake_memory(monkeypatch):
    assert details.PROFILE_FILE.name.endswith("-v3.json")
    assert details.PROFILE_ID == "trade-details-memory-1374-v3"
    assert details.PROFILE is not None
    assert len(details.EXPECTED_PROFILE_SHA256) == 64
    trade_profile = old_fixture._profile()
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    details_profile = _details_profile()
    monkeypatch.setattr(details, "EXPECTED_PROFILE_SHA256", "d" * 64)
    monkeypatch.setattr(details, "EXPECTED_TRADE_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(details, "_active_profile", lambda: details_profile)
    reader = old_fixture._build_reader()
    for item in details_profile["code_guards"]:
        expected = bytes.fromhex(item["hex"])
        reader.data[(MODULE_BASE + int(item["rva"], 0), len(expected))] = expected
    source = _source(reader)
    record = details.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    assert details.validate_record(record, source)


def test_reads_share_and_source_rows_in_native_order_without_rereading_graph(configured):
    reader, source, record = _record(configured)

    assert record["status"] == "observed"
    assert record["share_offset"] == "0x2c"
    assert record["source_offsets"] == {
        "TP_PROVINCE_POWER": "0x28",
        "TP_SHIP_POWER": "0x1c",
        "MERCHANT_DOWNSTREAM_BONUS": "0x40",
    }
    assert [node["node_id"] for node in record["nodes"]] == ["alpha", "beta"]
    assert record["nodes"][0]["share_raw"] == -1200
    assert record["nodes"][0]["share_raw_hex"] == "50fbffff"
    assert record["nodes"][0]["source_rows"] == [
        {"native_key": "TP_PROVINCE_POWER", "raw": 3813, "raw_hex": "e50e0000", "unit": "trade_power", "scale": 1000},
        {"native_key": "MERCHANT_DOWNSTREAM_BONUS", "raw": 17, "raw_hex": "11000000", "unit": "trade_power", "scale": 1000},
    ]
    assert record["nodes"][1]["source_rows"] == [
        {"native_key": "TP_SHIP_POWER", "raw": -5, "raw_hex": "fbffffff", "unit": "trade_power", "scale": 1000},
    ]
    assert record["nodes"][0]["source_inputs"]["TP_SHIP_POWER"] == {
        "raw": 0, "raw_hex": "00000000", "included": False,
    }
    assert record["nodes"][1]["source_inputs"]["MERCHANT_DOWNSTREAM_BONUS"] == {
        "raw": -1, "raw_hex": "ffffffff", "included": False,
    }
    assert record["basis"] == "native_trade_node_share_source_capital_dynamic_and_transfer_tail"
    assert record["unit"] == "mixed"
    assert record["scale"] == 1000
    assert record["complete"] is False
    assert record["unimplemented_source_kinds"] == details.UNIMPLEMENTED_SOURCE_KINDS
    assert details.validate_record(record, source)
    assert [label for _address, _size, label in reader.reads] == ["trade_details_v3.code.details_leaf", "capital.database_global"]


def test_profile_or_parent_rejection_happens_before_child_rpm(monkeypatch, configured):
    reader, source, _record_value = _record(configured)

    class BombReader:
        def __init__(self):
            self.calls = 0

        def read(self, *_args):
            self.calls += 1
            raise AssertionError("trade details must not RPM")

    bomb = BombReader()
    monkeypatch.setattr(details, "_active_profile", lambda: (_ for _ in ()).throw(details.ProfileError("pending")))
    pending = details.read_fields(bomb, MODULE_BASE, source)
    assert pending["status"] == "unknown"
    assert pending["reason"].startswith("profile_unavailable:")
    assert bomb.calls == 0

    invalid = details.read_fields(bomb, MODULE_BASE, {"status": "unknown"})
    assert invalid["reason"] == "trade_income_record_invalid"
    assert bomb.calls == 0


def test_validation_rejects_share_source_condition_order_binding_and_guard_tampering(configured):
    _reader, source, record = _record(configured)
    assert details.validate_record(record, source)

    for mutate in (
        lambda value: value["nodes"][0].__setitem__("share_raw", value["nodes"][0]["share_raw"] + 1),
        lambda value: value["nodes"][0].__setitem__("share_raw_hex", "00000000"),
        lambda value: value["nodes"][0]["source_inputs"]["TP_PROVINCE_POWER"].__setitem__("raw", 3814),
        lambda value: value["nodes"][0]["source_inputs"]["TP_SHIP_POWER"].__setitem__("included", True),
        lambda value: value["nodes"][0]["source_rows"].reverse(),
        lambda value: value.__setitem__("source_trade_record_canonical_sha256", "0" * 64),
        lambda value: value["runtime_code_guard"]["checks"].__setitem__("details_leaf", False),
        lambda value: value.__setitem__("country_fullref_raw_hex", "504f5200" + value["country_fullref_raw_hex"][8:]),
        lambda value: value.__setitem__("module_base", "0x150000000"),
    ):
        changed = deepcopy(record)
        mutate(changed)
        assert not details.validate_record(changed, source)


def test_retract_and_parent_default_combo_and_cleanup(configured, monkeypatch):
    reader, source, record = _record(configured)
    assert details.validate_record(record, source)
    retracted = details.retract_record(record, "cleanup_failed")
    assert retracted["status"] == "unknown"
    assert retracted["nodes"] is None
    assert not details.validate_record(retracted, source)

    default = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_trade_details" not in default["request"]
    assert "trade_details" not in default

    report = crm._base_report(
        Path("C:/EU4"),
        "FRA",
        include_trade_income=True,
        include_home_trade_node=True,
        include_trade_power=True,
        include_trade_details=True,
    )
    assert report["request"]["include_trade_details"] is True
    report["trade_income"] = source
    report["trade_details"] = record
    report["before"] = {
        "status": "observed",
        "values": {"administrative": 1},
        "trade_income": source,
        "home_trade_node": {"status": "observed", "nodes": [{"node_id": "alpha"}], "derived_nodes": ["alpha"], "home_node": "alpha"},
        "trade_power": {"status": "observed", "nodes": [{"node_id": "alpha"}]},
        "trade_details": record,
    }
    report["after"] = deepcopy(report["before"])
    assert crm._compare_snapshot(report["before"])["trade_details"] == record
    crm._retract(report)
    for item in (report, report["before"], report["after"]):
        assert item["trade_details"]["nodes"] is None

    calls: list[tuple[object, ...]] = []

    def fake_snapshot(*args):
        calls.append(args[4:])
        return {"status": "observed", "values": {}, "trade_income": source, "trade_details": record}

    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})
    monkeypatch.setattr(crm, "_snapshot", fake_snapshot)
    reader.read_log = []
    passed = crm._pass(reader, MODULE_BASE, "FRA", {}, 0, False, True, True, True, True)
    assert calls == [(False, True, True, True, True)]
    assert passed["trade_details"] == record

    monkeypatch.setattr(crm, "_configure_kernel", lambda: (_ for _ in ()).throw(AssertionError("no RPM")))
    invalid = crm.capture(Path("fake-installation.json"), "FRA", include_trade_details=True)
    assert invalid["status"] == "invalid_request"
    assert any(
        item["error"] == "include_trade_details_requires_include_trade_income"
        for item in invalid["errors"]
    )


def test_parent_capture_rejects_non_boolean_details_flag(monkeypatch):
    invalid = crm.capture(Path("fake-installation.json"), "FRA", include_trade_details=1)
    assert invalid["status"] == "invalid_request"
    assert any(item["error"] == "include_trade_details_must_be_bool" for item in invalid["errors"])
