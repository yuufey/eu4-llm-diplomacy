from copy import deepcopy

import pytest

from bridge.information import military_professionalism_memory as memory
from bridge.tests import test_information_military_professionalism_memory as fixture
from bridge.tests import test_information_military_effective_adapter as siblings
from bridge.tests import test_information_military_quality as parent


def source_with_professionalism(tmp_path):
    source, base, calls, report, _effective = siblings.report_with_effective(tmp_path)
    assert fixture.MODULE_BASE == parent.MODULE_BASE and fixture.COUNTRY_POINTER == parent.COUNTRY_POINTER
    child = memory.read_fields(fixture.provide_reader(value=655), fixture.MODULE_BASE, fixture.COUNTRY_POINTER)
    assert memory.validate_record(child) is True
    for snapshot in (report, report["before"], report["after"]):
        snapshot["military_professionalism"] = deepcopy(child)
    return source, base, calls, report, child


def test_professionalism_uses_real_validator_and_preserves_qword_scale(tmp_path):
    source, base, calls, _report, child = source_with_professionalism(tmp_path)
    result = source.read(parent._query(["professionalism"]), base.context())
    assert result["complete"] is True
    assert result["fields"]["professionalism"] == child["fields"]["professionalism"]
    assert result["fields"]["professionalism"]["raw_hex"] == "8f02000000000000"
    assert result["fields"]["professionalism"]["scale"] == 32768
    assert result["fields"]["professionalism"]["value"] == 655
    assert len(calls) == 1 and calls[0][2] == {"include_military_quality": True}
    assert source.catalog()[0]["fields"]["professionalism"]["coverage"] == "available"


def test_five_military_fields_share_capture_and_keep_their_completeness(tmp_path):
    source, base, calls, _report, _child = source_with_professionalism(tmp_path)
    fields = ["professionalism", "military_technology", "army_tradition", "morale", "discipline"]
    result = source.read(parent._query(fields), base.context())
    assert result["complete"] is False
    assert len(calls) == 1
    for key in fields:
        assert result["fields"][key]["status"] == "known"
        assert result["fields"][key]["complete"] is (key != "discipline")


@pytest.mark.parametrize("location", ["top", "before", "after"])
def test_invalid_professionalism_child_does_not_erase_stable_sibling(tmp_path, location):
    source, base, _calls, report, _child = source_with_professionalism(tmp_path)
    snapshot = report if location == "top" else report[location]
    snapshot["military_professionalism"]["fields"]["professionalism"]["raw_hex"] = "0000000000000000"
    result = source.read(parent._query(["professionalism", "morale"]), base.context())
    assert result["fields"]["professionalism"]["status"] == "unknown"
    assert "value" not in result["fields"]["professionalism"]
    assert result["fields"]["morale"]["status"] == "known"


def test_parent_country_binding_is_required_even_for_internally_valid_qword(tmp_path):
    source, base, _calls, report, _child = source_with_professionalism(tmp_path)
    other = fixture.COUNTRY_POINTER + 0x10000
    reader = fixture.provide_reader(value=655)
    # Relocate the recorded eight bytes while retaining the same static guards.
    reader.put(other + 0x50, (655).to_bytes(8, "little", signed=True))
    child = memory.read_fields(reader, fixture.MODULE_BASE, other)
    assert memory.validate_record(child) is True
    for snapshot in (report, report["before"], report["after"]):
        snapshot["military_professionalism"] = deepcopy(child)
    result = source.read(parent._query(["professionalism", "military_technology"]), base.context())
    assert result["fields"]["professionalism"]["status"] == "unknown"
    assert result["fields"]["military_technology"]["status"] == "known"


def test_changed_context_retracts_professionalism_and_other_fields(tmp_path):
    source, base, _calls, _report, _child = source_with_professionalism(tmp_path)
    base.after_context = {"game_date": parent.GAME_DATE + 24, "game_date_raw": parent.GAME_DATE + 24}
    result = source.read(parent._query(["professionalism", "morale"]), base.context())
    assert all(item["status"] == "unknown" and "value" not in item for item in result["fields"].values())
