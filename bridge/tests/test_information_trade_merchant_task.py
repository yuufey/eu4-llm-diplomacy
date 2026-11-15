from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import trade_income_memory as trade_memory
from bridge.tests import test_information_trade_collection as collection_fixture


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PROFILE_SHA256 = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
MODULE_BASE = collection_fixture.old_income.MODULE_BASE
COUNTRY_POINTER = collection_fixture.old_income.COUNTRY_POINTER
TABLE_ONE = collection_fixture.old_income.TABLE_ONE
TABLE_TWO = collection_fixture.old_income.TABLE_TWO
ENTRY_STRIDE = 0xC0
ENTRY_FLAGS_OFFSET = 0xAC


def _query(object_: dict, fields: list[str]) -> dict:
    return {
        "topic": "T05",
        "object": object_,
        "fields": fields,
        "parameters": {},
    }


def _record_with_flags(flags_one=(0, 0, 1), flags_two=(1, 0, 1)):
    """Use the pinned production profile and the existing bounded graph fixture."""

    reader, profile = collection_fixture._build_real_profile_reader()
    assert profile["profile_id"] == "trade-income-memory-1374"
    for table, flags in ((TABLE_ONE, flags_one), (TABLE_TWO, flags_two)):
        key = (table + 7 * ENTRY_STRIDE, ENTRY_STRIDE)
        entry = bytearray(reader.data[key])
        entry[ENTRY_FLAGS_OFFSET:ENTRY_FLAGS_OFFSET + 3] = bytes(flags)
        reader.data[key] = bytes(entry)
    record = trade_memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert record["profile_sha256"] == PROFILE_SHA256
    assert trade_memory.validate_record(record)
    return record, reader, profile


def _source(tmp_path: Path, record: dict):
    source, base, capture_calls, report = collection_fixture._real_report_source(
        tmp_path, record,
    )
    return source, base, capture_calls, report


def test_real_profile_validator_and_catalog_contract(tmp_path: Path):
    record, _reader, _profile = _record_with_flags()
    source, base, _capture_calls, _report = _source(tmp_path, record)
    catalog = source.catalog()[0]["fields"]["merchant_task"]
    assert catalog == {
        "coverage": "partial",
        "runtime_validation": "validated_native_flags_and_aggregate_predicate",
        "source": "bridge.information.country_resources_memory.capture",
        "unit": "state",
        "scale": 1,
        "raw": False,
        "raw_semantics": (
            "trade_node: none when copied native flag_ae is zero; "
            "collect when flag_ae is nonzero and the copied native eligible "
            "predicate is true; transfer when flag_ae is nonzero and it is false; "
            "country: ordered active rows only"
        ),
        "paths": ["trade_income.nodes[].flag_ae", "trade_income.nodes[].eligible"],
        "supported_countries": ["FRA"],
        "period": "current",
        "basis": "native_trade_node_merchant_presence_and_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
        "gaps": [
            "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
            "TRANSIT_IDLE_TASK_LIFECYCLE_NOT_PROVEN",
        ],
    }
    normalized = source.validate_query(
        _query(
            {"type": "country", "country": "FRA"},
            ["income", "collection", "merchant_task"],
        ),
        base.context(),
    )
    assert normalized["fields"] == ["income", "collection", "merchant_task"]


def test_mixed_income_collection_merchant_task_is_one_capture_and_preserves_order(
    tmp_path: Path,
):
    record, _reader, _profile = _record_with_flags(
        flags_one=(0, 0, 1),  # eligible -> collect
        flags_two=(1, 0, 1),  # ineligible -> transfer
    )
    source, base, capture_calls, _report = _source(tmp_path, record)
    result = source.read(
        _query(
            {"type": "country", "country": "FRA"},
            ["income", "collection", "merchant_task"],
        ),
        base.context(),
    )
    assert result["fields"]["income"]["value"] == 3813
    assert result["fields"]["collection"]["value"] == ["alpha"]
    assert result["fields"]["merchant_task"] == {
        "status": "known",
        "value": [
            {"node_id": "alpha", "task": "collect"},
            {"node_id": "beta", "task": "transfer"},
        ],
        "unit": "state",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_merchant_presence_and_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
    }
    assert len(capture_calls) == 1
    audit_nodes = result["source"]["provenance"]["trade_income"]["nodes"]
    assert [(node["node_id"], node["eligible"]) for node in audit_nodes] == [
        ("alpha", True), ("beta", False),
    ]
    assert audit_nodes[0]["flags"]["flag_ae"] == 1
    assert audit_nodes[1]["flags"]["flag_ac"] == 1


@pytest.mark.parametrize(
    ("flags_two", "expected_collection", "expected_task"),
    [
        ((0, 1, 0), True, "none"),   # AD makes B58C70 eligible, but AE says no merchant.
        ((1, 0, 0), False, "none"),  # false collection is still not transfer when AE is zero.
        ((0, 0, 255), True, "collect"),  # any nonzero AE is active for this projection.
    ],
)
def test_node_task_uses_ae_presence_then_existing_eligible_predicate(
    tmp_path: Path,
    flags_two: tuple[int, int, int],
    expected_collection: bool,
    expected_task: str,
):
    record, _reader, _profile = _record_with_flags(
        flags_one=(0, 0, 0),
        flags_two=flags_two,
    )
    source, base, _capture_calls, _report = _source(tmp_path, record)
    result = source.read(
        _query({"type": "trade_node", "node_id": "beta"}, ["collection", "merchant_task"]),
        base.context(),
    )
    assert result["fields"]["collection"]["value"] is expected_collection
    assert result["fields"]["merchant_task"] == {
        "status": "known",
        "value": expected_task,
        "unit": "state",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_merchant_presence_and_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
    }


def test_country_empty_active_rows_and_unknown_node_are_distinct(tmp_path: Path):
    record, _reader, _profile = _record_with_flags(
        flags_one=(1, 0, 0),
        flags_two=(0, 1, 0),
    )
    source, base, _capture_calls, _report = _source(tmp_path, record)
    country = source.read(
        _query({"type": "country", "country": "FRA"}, ["merchant_task"]),
        base.context(),
    )
    assert country["fields"]["merchant_task"]["status"] == "known"
    assert country["fields"]["merchant_task"]["value"] == []

    missing = source.read(
        _query({"type": "trade_node", "node_id": "missing"}, ["merchant_task"]),
        base.context(),
    )
    assert missing["fields"]["merchant_task"] == {
        "status": "unknown", "reason": "NODE_NOT_FOUND",
    }


def test_real_record_tamper_and_context_change_retract_merchant_task(tmp_path: Path):
    record, _reader, _profile = _record_with_flags()
    changed = deepcopy(record)
    changed["nodes"][0]["flag_ae"] = 255
    assert not trade_memory.validate_record(changed)
    source, base, _capture_calls, _report = _source(tmp_path, changed)
    corrupt = source.read(
        _query({"type": "country", "country": "FRA"}, ["merchant_task"]),
        base.context(),
    )
    assert corrupt["fields"]["merchant_task"]["status"] == "unknown"

    source, base, _capture_calls, _report = _source(tmp_path, record)
    base.after_context = {
        "game_date": collection_fixture.GAME_DATE + 1,
        "game_date_raw": collection_fixture.GAME_DATE + 1,
    }
    stale = source.read(
        _query({"type": "country", "country": "FRA"}, ["merchant_task"]),
        base.context(),
    )
    assert stale["fields"]["merchant_task"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in stale["fields"]["merchant_task"]["reason"]
