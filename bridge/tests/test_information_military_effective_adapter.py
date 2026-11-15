from copy import deepcopy

import pytest

from bridge.information import military_effective_memory as effective
from bridge.information import military_morale_memory as morale
from bridge.information.military_quality import NativeMilitaryQualitySource
from bridge.tests import test_information_military_effective_memory as fixture
from bridge.tests import test_information_military_morale_memory as morale_fixture
from bridge.tests import test_information_military_quality as parent


def report_with_effective(tmp_path, **options):
    assert fixture.MODULE_BASE == parent.MODULE_BASE
    assert fixture.COUNTRY_POINTER == parent.COUNTRY_POINTER
    base = parent._Base(tmp_path)
    child = effective.read_fields(fixture._reader(**options), fixture.MODULE_BASE, fixture.COUNTRY_POINTER)
    assert morale_fixture.MODULE_BASE == fixture.MODULE_BASE
    assert morale_fixture.COUNTRY_POINTER == fixture.COUNTRY_POINTER
    morale_child = morale.read_fields(morale_fixture.provide_reader(army=3123, navy=2142),
                                     fixture.MODULE_BASE, fixture.COUNTRY_POINTER)
    assert morale.validate_record(morale_child) is True
    report = parent._report(base, tradition_child=parent._tradition_child())
    for snapshot in (report, report["before"], report["after"]):
        snapshot["military_effective"] = deepcopy(child)
        snapshot["military_morale"] = deepcopy(morale_child)
    calls = []

    def capture(installation, country, **kwargs):
        calls.append((installation, country, kwargs))
        return deepcopy(report)

    return NativeMilitaryQualitySource(base, capture=capture), base, calls, report, child


def test_partial_discipline_and_complete_caches_share_real_validation_and_one_capture(tmp_path):
    source, base, calls, _report, child = report_with_effective(tmp_path, modifier=27, processor=True)
    assert effective.validate_record(child) is True
    result = source.read(parent._query(["discipline", "military_technology", "army_tradition", "morale"]), base.context())
    values = result["fields"]
    assert values["discipline"] == child["fields"]["discipline"]
    assert values["discipline"]["value"] == 1027 and values["discipline"]["complete"] is False
    assert values["military_technology"]["value"] == 7 and values["military_technology"]["complete"] is True
    assert values["army_tradition"]["value"] == -1250 and values["army_tradition"]["complete"] is True
    assert values["morale"]["value"] == {"army": 3123, "navy": 2142}
    assert values["morale"]["complete"] is True
    assert result["complete"] is False
    assert len(calls) == 1 and calls[0][2] == {"include_military_quality": True}
    assert source.catalog()[0]["fields"]["discipline"]["coverage"] == "partial"


@pytest.mark.parametrize("location", ["top", "before", "after"])
def test_tampered_effective_child_retracts_discipline_but_preserves_stable_technology(tmp_path, location):
    source, base, _calls, report, _child = report_with_effective(tmp_path)
    snapshot = report if location == "top" else report[location]
    snapshot["military_effective"]["fields"]["discipline"]["value"] += 1
    result = source.read(parent._query(["discipline", "military_technology"]), base.context())
    assert result["fields"]["discipline"]["status"] == "unknown"
    assert "value" not in result["fields"]["discipline"]
    assert result["fields"]["military_technology"]["status"] == "known"
    assert result["complete"] is False


def test_unknown_thread_dependent_contribution_keeps_its_reason_and_other_cache(tmp_path):
    values = {key: 0 for key in effective.PROCESSOR_DENSE_OFFSETS}
    values[next(iter(values))] = 5000
    source, base, _calls, _report, child = report_with_effective(tmp_path, processor=True, processor_values=values)
    assert child["fields"]["discipline"]["status"] == "unknown"
    result = source.read(parent._query(["discipline", "military_technology"]), base.context())
    assert result["fields"]["discipline"] == {
        "status": "unknown", "reason": "MILITARY_PROCESSOR_THREAD_CONTEXT_UNAVAILABLE"
    }
    assert result["fields"]["military_technology"]["status"] == "known"


def test_context_change_retracts_both_partial_and_complete_fields(tmp_path):
    source, base, _calls, _report, _child = report_with_effective(tmp_path)
    base.after_context = {"game_date": parent.GAME_DATE + 24, "game_date_raw": parent.GAME_DATE + 24}
    result = source.read(parent._query(["discipline", "military_technology"]), base.context())
    assert all(value["status"] == "unknown" and "value" not in value for value in result["fields"].values())
    assert result["complete"] is False


def test_morale_cache_query_is_complete_for_both_services(tmp_path):
    source, base, calls, _report, _child = report_with_effective(tmp_path)
    result = source.read(parent._query(["morale"]), base.context())
    assert result["complete"] is True
    assert result["fields"]["morale"]["raw_hex"] == {"army": "330c0000", "navy": "5e080000"}
    assert len(calls) == 1


@pytest.mark.parametrize("service", ["army", "navy"])
def test_one_tampered_morale_side_retracts_entire_morale_field(tmp_path, service):
    source, base, _calls, report, _child = report_with_effective(tmp_path)
    report["military_morale"]["fields"]["morale"]["raw_hex"][service] = "00000000"
    result = source.read(parent._query(["morale", "military_technology"]), base.context())
    assert result["fields"]["morale"]["status"] == "unknown"
    assert "value" not in result["fields"]["morale"]
    assert result["fields"]["military_technology"]["status"] == "known"
