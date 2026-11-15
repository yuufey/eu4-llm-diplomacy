"""Literal checks for the partial N01 war-income projection."""
from __future__ import annotations

import pytest

from bridge.information import monthly_economy_memory as memory
from bridge.information import war_income_projection as projection
from bridge.tests import test_information_monthly_economy_memory as memory_fixture


MODULE_BASE = memory_fixture.MODULE_BASE
COUNTRY_POINTER = memory_fixture.COUNTRY_POINTER
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    profile = memory_fixture._profile()
    monkeypatch.setattr(memory, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(memory, "_load_profile", lambda *args, **kwargs: profile)
    return profile


def _record(configured, income: list[int] | None = None) -> dict:
    return memory.read_fields(
        memory_fixture._reader(configured, income=income),
        MODULE_BASE,
        COUNTRY_POINTER,
    )


def _unknown_without_value(record: dict) -> None:
    result = projection.project(record)
    assert result["status"] == "unknown"
    assert "value" not in result


def test_projects_four_literal_slots_and_exact_unwrapped_subtotal(configured):
    income = [0] * memory.INCOME_COUNT
    income[8] = 1200
    income[12] = -300
    income[17] = 500
    income[18] = I32_MAX

    result = projection.project(_record(configured, income))

    assert result["status"] == "known"
    assert result["partial"] is True and result["complete"] is False
    assert result["unit"] == "war_income_information"
    assert result["basis"] == "native_previous_month_war_related_income_slots"
    value = result["value"]
    assert value["components"]["war_reparations"]["raw"] == 1200
    assert value["components"]["war_reparations"]["value"] == 1.2
    assert value["components"]["war_reparations"]["native_key"] == "INCOME_WAR_REPARATION"
    assert value["components"]["spoils_of_war"]["raw"] == -300
    assert value["components"]["spoils_of_war"]["value"] == -0.3
    assert value["components"]["blockades"]["raw"] == 500
    assert value["components"]["looting"]["raw"] == I32_MAX
    subtotal = value["observed_components_subtotal"]
    assert subtotal["raw"] == 2_147_485_047
    assert subtotal["raw"] > I32_MAX
    assert subtotal["value"] == pytest.approx(2_147_485.047)
    assert subtotal["native_total"] is False
    assert subtotal["four_components_only"] is True
    assert value["monthly_income_overlap"] == {
        "component_indices": [8], "additive": False,
    }
    assert value["total_war_income"]["status"] == "unknown"
    assert value["current_war_attribution"]["status"] == "unknown"
    assert value["current_payment_obligations"]["status"] == "unknown"
    assert "raw_ledger_hex" not in value


def test_zero_components_are_known_partial_values(configured):
    result = projection.project(_record(configured, [0] * memory.INCOME_COUNT))

    assert result["status"] == "known"
    assert set(result["value"]["components"]) == {
        "war_reparations", "spoils_of_war", "blockades", "looting",
    }
    assert all(
        item["status"] == "known" and item["raw"] == 0 and item["value"] == 0.0
        for item in result["value"]["components"].values()
    )
    assert result["value"]["observed_components_subtotal"]["raw"] == 0
    assert result["value"]["total_war_income"]["status"] == "unknown"


def test_signed_extremes_sum_without_i32_wrap(configured):
    income = [0] * memory.INCOME_COUNT
    income[8], income[12], income[17], income[18] = (
        I32_MIN, I32_MAX, I32_MIN, I32_MAX,
    )

    result = projection.project(_record(configured, income))

    assert result["status"] == "known"
    assert result["value"]["observed_components_subtotal"]["raw"] == -2
    assert result["value"]["observed_components_subtotal"]["value"] == -0.002


def test_income_slots_tampering_is_unknown_and_has_no_value(configured):
    record = _record(configured)
    record["income_slots"][8] = 1

    _unknown_without_value(record)


def test_ledger_bytes_tampering_is_unknown_and_has_no_value(configured):
    record = _record(configured)
    payload = bytearray.fromhex(record["raw_ledger_hex"])
    payload[8 * 4:9 * 4] = (123).to_bytes(4, "little", signed=True)
    record["raw_ledger_hex"] = bytes(payload).hex()
    record["raw_payload_hex"] = record["raw_ledger_hex"]
    record["observation"]["ledger"]["raw_payload_hex"] = record["raw_ledger_hex"]

    _unknown_without_value(record)


@pytest.mark.parametrize(
    ("path", "bad_value"),
    [
        (("basis",), "other_basis"),
        (("reference_period",), "current"),
        (("observation", "period"), "year"),
        (("profile_sha256",), "a" * 64),
    ],
)
def test_profile_period_or_basis_tampering_is_unknown(configured, path, bad_value):
    record = _record(configured)
    cursor = record
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = bad_value

    _unknown_without_value(record)


def test_retracted_capture_is_unknown_without_value(configured):
    record = memory.retract_record(_record(configured), "test_retraction")

    _unknown_without_value(record)
