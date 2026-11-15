from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information import country_resources_memory
from bridge.information.model import canonical
from bridge.information.trade_power import NativeTradePowerSource
from bridge.information.trade_scenario_baseline import TradeScenarioBaselineReader
from bridge.tests import test_information_trade_power as trade_power_fixture


# Reuse the existing strict native-profile fixture and its real memory reader,
# parent report, validators, and query helpers.
configured = trade_power_fixture.configured


def _real_report(
    configured_profiles,
    tmp_path: Path,
    *,
    alpha_income: int = 3813,
    alpha_total_power: int = 746110,
    beta_zero_power: bool = False,
) -> tuple[dict, dict, dict]:
    reader = trade_power_fixture._reader_with_power_guard(configured_profiles[1])
    alpha_entry_address = trade_power_fixture.trade_fixture.TABLE_ONE + 7 * 0xC0
    alpha_entry = bytearray(reader.data[(alpha_entry_address, 0xC0)])
    alpha_entry[0x34:0x38] = trade_power_fixture.trade_fixture._i32(alpha_income)
    reader.data[(alpha_entry_address, 0xC0)] = bytes(alpha_entry)

    trade_power_fixture._set_power_components(
        reader,
        trade_power_fixture.trade_fixture.TABLE_ONE,
        (1053, 123767, 117538, 0, 51131),
    )
    if beta_zero_power:
        trade_power_fixture._set_power_components(
            reader,
            trade_power_fixture.trade_fixture.TABLE_TWO,
            (0, 0, 0, 0, 0),
        )
        reader.data[(
            trade_power_fixture.trade_fixture.RUNTIME_TWO
            + trade_power_fixture.power.RUNTIME_TOTAL_POWER_OFFSET,
            4,
        )] = trade_power_fixture.trade_fixture._i32(0)
    reader.data[(
        trade_power_fixture.trade_fixture.RUNTIME_ONE
        + trade_power_fixture.power.RUNTIME_TOTAL_POWER_OFFSET,
        4,
    )] = trade_power_fixture.trade_fixture._i32(alpha_total_power)

    trade_record, power_record = trade_power_fixture._records(reader)
    report_base = trade_power_fixture._Base(tmp_path)
    report = trade_power_fixture._report(trade_record, power_record, report_base)
    return report, trade_record, power_record


def _reader(tmp_path: Path, report: dict):
    source, base, calls = trade_power_fixture._source(tmp_path, report)
    return TradeScenarioBaselineReader(source), source, base, calls


def test_baseline_projects_income_collection_and_power_from_one_validated_report(
    configured, tmp_path: Path,
):
    report, income_record, power_record = _real_report(configured, tmp_path)
    reader, power_source, base, calls = _reader(tmp_path, report)
    original_capture = power_source.capture

    result = reader.read("alpha", base.context())

    income_node = next(node for node in income_record["nodes"] if node["node_id"] == "alpha")
    power_node = next(node for node in power_record["nodes"] if node["node_id"] == "alpha")
    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["node_id"] == "alpha"
    assert result["fields"]["income"]["value"] == income_node["income_raw"]
    assert result["fields"]["income"]["eligible"] is True
    assert result["fields"]["collection"]["value"] is True
    assert result["fields"]["country_power"]["value"] == power_node["country_power_raw"]
    assert result["fields"]["total_power"]["value"] == power_node["total_power_raw"]
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]
    assert power_source.capture is original_capture
    assert set(power_source.__dict__) == {"base_source", "capture"}

    provenance = result["source"]["provenance"]
    assert provenance["context_guard"]["status"] == "passed"
    assert provenance["single_parent_capture"] is True
    assert provenance["atomic_snapshot"] is False
    assert provenance["report_canonical_sha256"] == hashlib.sha256(
        canonical(report).encode("utf-8")
    ).hexdigest()
    assert "report" not in provenance
    assert "trade_income" not in provenance


def test_zero_and_ineligible_node_values_remain_known(configured, tmp_path: Path):
    report, income_record, _power_record = _real_report(
        configured, tmp_path, beta_zero_power=True,
    )
    reader, _power_source, base, calls = _reader(tmp_path, report)

    result = reader.read("beta", base.context())

    beta = next(node for node in income_record["nodes"] if node["node_id"] == "beta")
    assert result["status"] == "known"
    assert result["fields"]["income"]["status"] == "known"
    assert result["fields"]["income"]["value"] == 0
    assert result["fields"]["income"]["cache_income_raw"] == beta["cache_income_raw"] == -17
    assert result["fields"]["income"]["eligible"] is False
    assert result["fields"]["collection"]["status"] == "known"
    assert result["fields"]["collection"]["value"] is False
    assert result["fields"]["country_power"]["status"] == "known"
    assert result["fields"]["country_power"]["value"] == 0
    assert result["fields"]["total_power"]["status"] == "known"
    assert result["fields"]["total_power"]["value"] == 0
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]


def test_invalid_parent_capture_retracts_all_baseline_values(configured, tmp_path: Path):
    report, _income_record, _power_record = _real_report(configured, tmp_path)
    report["doublepass"]["consistent"] = False
    reader, _power_source, base, calls = _reader(tmp_path, report)

    result = reader.read("alpha", base.context())

    assert result["status"] == "unknown"
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "DOUBLEPASS" in result["fields"]["income"]["reason"]
    assert result["source"]["provenance"]["context_guard"]["status"] == "capture_invalid"
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]


def test_missing_node_stays_unknown_after_parent_validation(configured, tmp_path: Path):
    report, _income_record, _power_record = _real_report(configured, tmp_path)
    reader, _power_source, base, calls = _reader(tmp_path, report)

    result = reader.read("not_a_native_node", base.context())

    assert result["status"] == "unknown"
    assert all(
        item == {"status": "unknown", "reason": "NODE_NOT_FOUND"}
        for item in result["fields"].values()
    )
    assert result["source"]["provenance"]["context_guard"]["status"] == "passed"
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]


def test_each_read_captures_again_and_does_not_patch_shared_source(configured, tmp_path: Path):
    first, _first_income, _first_power = _real_report(
        configured, tmp_path, alpha_income=3813, alpha_total_power=746110,
    )
    second, _second_income, _second_power = _real_report(
        configured, tmp_path, alpha_income=9123, alpha_total_power=0,
    )
    base = trade_power_fixture._Base(tmp_path)
    reports = [first, second]
    capture_calls = []

    def capture(installation, country, *, include_trade_income=False, include_trade_power=False):
        capture_calls.append((installation, country, include_trade_income, include_trade_power))
        return deepcopy(reports.pop(0))

    power_source = NativeTradePowerSource(base, capture=capture)
    before_capture = power_source.capture
    before_attributes = set(power_source.__dict__)
    reader = TradeScenarioBaselineReader(power_source)

    first_result = reader.read("alpha", base.context())
    second_result = reader.read("alpha", base.context())

    assert first_result["fields"]["income"]["value"] == 3813
    assert second_result["fields"]["income"]["value"] == 9123
    assert first_result["fields"]["total_power"]["value"] == 746110
    assert second_result["fields"]["total_power"]["value"] == 0
    assert len(capture_calls) == 2
    assert all(call[2:] == (True, True) for call in capture_calls)
    assert power_source.capture is before_capture
    assert set(power_source.__dict__) == before_attributes
    assert not reports


def test_default_capture_reader_is_used_without_explicit_capture(
    configured, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    report, _income_record, _power_record = _real_report(configured, tmp_path)
    base = trade_power_fixture._Base(tmp_path)
    calls = []

    def capture(installation, country, *, include_trade_income=False, include_trade_power=False):
        calls.append((installation, country, include_trade_income, include_trade_power))
        return deepcopy(report)

    monkeypatch.setattr(country_resources_memory, "capture", capture)
    power_source = NativeTradePowerSource(base)
    reader = TradeScenarioBaselineReader(power_source)

    result = reader.read("alpha", base.context())

    assert result["status"] == "known"
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]


def test_native_power_components_are_opt_in_and_project_from_one_strict_capture(
    configured, tmp_path: Path,
):
    report, _income_record, power_record = _real_report(configured, tmp_path)

    default_reader, _default_source, default_base, default_calls = _reader(tmp_path, report)
    default = default_reader.read("alpha", default_base.context())
    assert default["status"] == "known"
    assert set(default) == {"status", "node_id", "fields", "source", "complete"}
    assert "native_power_components" not in default
    assert default_calls == [(tmp_path / "installation.json", "FRA", True, True)]

    rich_reader, _rich_source, rich_base, rich_calls = _reader(tmp_path, report)
    rich = rich_reader.read("alpha", rich_base.context(), with_power_components=True)

    power_node = next(node for node in power_record["nodes"] if node["node_id"] == "alpha")
    components = power_node["entry_power_components_raw"]
    assert rich["status"] == "known"
    assert rich["native_power_components"] == {
        "status": "known",
        "value": {
            "multiplier_raw": components["0x44"],
            "cap_raw": components["0x48"],
            "base_raw": components["0x4c"],
            "subtract_raw": components["0x50"],
            "add_raw": components["0x54"],
        },
        "basis": "native_trade_node_power_caches",
        "scale": 1000,
        "period": "current",
        "complete": False,
    }
    assert rich["source"]["provenance"]["single_parent_capture"] is True
    assert rich_calls == [(tmp_path / "installation.json", "FRA", True, True)]


def test_opt_in_components_retract_with_invalid_parent_and_stay_node_local(
    configured, tmp_path: Path,
):
    invalid_report, _income_record, _power_record = _real_report(configured, tmp_path)
    invalid_report["doublepass"]["consistent"] = False
    reader, _source, base, calls = _reader(tmp_path, invalid_report)

    invalid = reader.read("alpha", base.context(), with_power_components=True)

    assert invalid["status"] == "unknown"
    assert invalid["native_power_components"]["status"] == "unknown"
    assert "value" not in invalid["native_power_components"]
    assert all(field["status"] == "unknown" for field in invalid["fields"].values())
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]

    missing_report, _income_record, _power_record = _real_report(configured, tmp_path)
    missing_reader, _source, missing_base, missing_calls = _reader(tmp_path, missing_report)
    missing = missing_reader.read(
        "not_a_native_node", missing_base.context(), with_power_components=True,
    )

    assert missing["status"] == "unknown"
    assert missing["fields"]["country_power"] == {
        "status": "unknown", "reason": "NODE_NOT_FOUND",
    }
    assert missing["native_power_components"]["status"] == "unknown"
    assert "value" not in missing["native_power_components"]
    assert missing_calls == [(tmp_path / "installation.json", "FRA", True, True)]

