from copy import deepcopy

import pytest

from bridge.information import country_resources_memory as parent
from bridge.information import country_loans_memory as loans
from bridge.information import country_modifiers_memory as modifiers
from bridge.information.country_records import NativeCountryRecordsSource, _loan_summary, _modifier_projection
from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.sources import DiplomacySource
from bridge.tests import test_information_country_loans_memory as lf
from bridge.tests import test_information_country_modifiers_memory as mf
from bridge.tests.test_information_military_quality import _Base, _report, GAME_DATE


def query(topic, fields):
    return dict(topic=topic, object={"type": "country", "country": "FRA"}, fields=fields, parameters={})


def modifier_child(*, other_country=False):
    reader = mf._reader()
    country = reader.country_pointer
    head = int.from_bytes(reader.read(country+0x1F0, 8, "test.head"), "little")
    item = int.from_bytes(reader.read(head, 8, "test.item"), "little")
    definition = int.from_bytes(reader.read(item+0x30, 8, "test.definition"), "little")
    if other_country:
        country += 0x10000
        reader.put(country+0x1F0, head.to_bytes(8, "little"))
    reader.put(item+0x40, (0x29C77F8).to_bytes(4, "little") + (GAME_DATE+120).to_bytes(4, "little"))
    # The definition is a separate object: poison its date-looking bytes.
    reader.put(definition+0x40, b"\x01\x00\x00\x00\x02\x00\x00\x00")
    child = modifiers.read_fields(reader, reader.module_base, country)
    assert modifiers.validate_record(child)
    return child


def source(tmp_path, key, child):
    base = _Base(tmp_path)
    report = _report(base)
    report["module_base"] = {"va": child["module_base"], "rva": None}
    report["request"][f"include_{key}"] = True
    for snapshot in (report, report["before"], report["after"]):
        snapshot[key] = deepcopy(child)
    for snapshot in (report["before"], report["after"]):
        snapshot["country_scan"]["country_pointer"] = {"va": child["country_pointer"], "rva": None}
    calls = []
    def capture(installation, country, **options):
        calls.append((country, options))
        return deepcopy(report)
    class Definitions:
        def lookup(self, modifier_id):
            if modifier_id == "papal_sanction_for_church_taxes":
                return {"status": "known", "declarations": {
                    "global_tax_modifier": {"status": "declared", "value": "0.15"},
                    "build_cost": {"status": "declared", "value": "-0.1"},
                    "picture": {"status": "unknown", "reason": "NON_LITERAL_DECLARATION"},
                }}
            return {"status": "unknown", "reason": "OPINION_DEFINITION_NOT_FOUND"}
    return NativeCountryRecordsSource(base, capture=capture, modifier_definitions=Definitions()), base, report, calls


def test_empty_current_loans_are_known_and_share_the_n01_parameter_schema(tmp_path):
    child = loans.read_fields(lf._reader([]), lf.MODULE_BASE, lf.COUNTRY_POINTER)
    adapter, base, _report_value, calls = source(tmp_path, "country_loans", child)
    result = adapter.read(query("N01", ["loans"]), base.context())
    assert result["fields"]["loans"]["status"] == "known"
    assert result["fields"]["loans"]["value"] == []
    assert result["complete"] is False
    assert calls == [("FRA", {"include_country_loans": True})]
    composite = CompositeSource(DiplomacySource(), [NativeCountryStateSource(base), adapter])
    mixed = query("N01", ["loans", "treasury"])
    mixed["parameters"] = {"reference_recipient": "SAV"}
    assert composite.validate_query(mixed) == mixed


@pytest.mark.parametrize("principals", [[], [123, 131]])
def test_loan_summary_shares_validated_capture_and_preserves_records(tmp_path, principals):
    reader = lf._reader([{"principal": value} for value in principals])
    child = loans.read_fields(reader, lf.MODULE_BASE, lf.COUNTRY_POINTER)
    adapter, base, _report_value, calls = source(tmp_path, "country_loans", child)
    result = adapter.read(query("N01", ["loans", "loan_summary"]), base.context())
    assert calls == [("FRA", {"include_country_loans": True})]
    assert result["fields"]["loans"]["value"] == child["fields"]["loans"]["value"]
    catalog = next(item for item in adapter.catalog() if item["topic_id"] == "N01")
    assert catalog["fields"]["loan_summary"]["value_origin"] == result["fields"]["loan_summary"]["value_origin"]
    assert result["fields"]["loan_summary"]["value"] == {
        "loan_count": len(principals),
        "total_principal": {"status": "known", "value": sum(principals), "unit": "ducats", "scale": 1},
        "unknown_principal_count": 0,
    }
    assert "node_address" not in str(result["fields"]["loan_summary"])


@pytest.mark.parametrize("principal", [{}, {"status": "unknown"}, {"status": "known", "value": -1}])
def test_loan_summary_keeps_incomplete_principal_explicit(principal):
    summary = _loan_summary([
        {"principal": {"status": "known", "value": 100}}, {"principal": principal},
    ])
    assert summary["loan_count"] == 2
    assert summary["unknown_principal_count"] == 1
    assert summary["total_principal"]["status"] == "unknown"
    assert summary["total_principal"]["known_subtotal"] == 100
    assert "value" not in summary["total_principal"]


def test_modifier_ids_targets_and_definition_effects_use_one_validated_capture(tmp_path):
    adapter, base, _report_value, calls = source(tmp_path, "country_modifiers", modifier_child())
    result = adapter.read(query("N07", ["modifier_id", "target", "effects"]), base.context())
    assert result["fields"]["modifier_id"]["value"] == ["papal_sanction_for_church_taxes", "shady_people"]
    assert result["fields"]["target"]["value"][0]["country"] == "FRA"
    effect = result["fields"]["effects"]["value"][0]
    assert effect["effects"][0]["raw"] == 150
    assert effect["final_effective_value"] is False
    assert effect["named_effects"]["value"] == {
        "global_tax_modifier": {"status": "known", "value": 0.15},
        "build_cost": {"status": "known", "value": -0.1},
    }
    assert result["fields"]["effects"]["value"][1]["named_effects"]["status"] == "unknown"
    assert result["complete"] is False
    assert calls == [("FRA", {"include_country_modifiers": True})]


def test_modifier_targets_bind_to_the_configured_non_fra_observer(tmp_path, monkeypatch):
    adapter, base, report, calls = source(tmp_path, "country_modifiers", modifier_child())
    context = dict(base.context(), observer="TUR")
    monkeypatch.setattr(base, "context", lambda: deepcopy(context))
    report["country"] = "TUR"
    request = query("N07", ["target"])
    with pytest.raises(ValueError, match="configured observer country"):
        adapter.read(request, context)
    assert calls == []

    request["object"]["country"] = "TUR"
    result = adapter.read(request, context)
    assert calls == [("TUR", {"include_country_modifiers": True})]
    assert result["fields"]["target"]["value"][0]["country"] == "TUR"


def test_modifier_dates_come_from_instances_and_keep_default_start_unknown(tmp_path):
    adapter, base, _report_value, calls = source(tmp_path, "country_modifiers", modifier_child())
    result = adapter.read(query("N08", ["modifier_start_date", "modifier_end_date", "remaining_days", "duration_type"]), base.context())
    assert result["fields"]["modifier_start_date"]["value"][0]["status"] == "unknown"
    assert result["fields"]["modifier_end_date"]["value"][0]["raw"] == GAME_DATE+120
    assert result["fields"]["remaining_days"]["value"][0]["value"] == 120
    assert result["fields"]["remaining_days"]["scale"] == 24
    assert result["fields"]["duration_type"]["value"][0]["value"] == "fixed_term"
    assert len(calls) == 1


def test_ruler_modifier_type_preserves_its_separate_fixed_expiry():
    records = [{"key": "power_to_provinces", "start_date_raw": 43808760,
                "date_raw": 56773248, "flags": {"ruler_modifier": 1}}]
    assert _modifier_projection("duration_type", records, GAME_DATE, "FRA") == [
        {"modifier_id": "power_to_provinces", "status": "known", "value": "ruler_modifier"}]
    assert _modifier_projection("modifier_end_date", records, GAME_DATE, "FRA")[0]["value"] == 56773248


@pytest.mark.parametrize("where", ["top", "before", "after"])
def test_tampered_record_is_rejected_by_the_real_child_validator(tmp_path, where):
    adapter, base, report, _calls = source(tmp_path, "country_modifiers", modifier_child())
    target = report if where == "top" else report[where]
    target["country_modifiers"]["fields"]["modifiers"]["value"][0]["date_raw"] += 1
    result = adapter.read(query("N07", ["modifier_id"]), base.context())
    assert result["fields"]["modifier_id"]["status"] == "unknown"
    assert "value" not in result["fields"]["modifier_id"]


def test_internally_valid_other_country_child_is_not_bound_to_this_parent(tmp_path):
    good = modifier_child()
    adapter, base, report, _calls = source(tmp_path, "country_modifiers", good)
    different = modifier_child(other_country=True)
    assert modifiers.validate_record(different)
    report["country_modifiers"] = different
    result = adapter.read(query("N07", ["modifier_id"]), base.context())
    assert result["fields"]["modifier_id"]["status"] == "unknown"
    assert "CONTEXT_BINDING" in result["fields"]["modifier_id"]["reason"]


def test_parent_context_change_retracts_records(tmp_path):
    adapter, base, _report_value, _calls = source(tmp_path, "country_modifiers", modifier_child())
    base.after_context = {"game_date": GAME_DATE+24}
    result = adapter.read(query("N07", ["modifier_id"]), base.context())
    assert result["fields"]["modifier_id"]["status"] == "unknown"
    assert result["fields"]["modifier_id"]["reason"] == "COUNTRY_RECORDS_CONTEXT_CHANGED_DURING_CAPTURE"


def test_unbounded_and_overdue_dates_preserve_the_native_duration_distinction():
    records = [dict(key="unbounded", start_date_raw=0x29C77F8, date_raw=43800000, flags={}, effects=[]),
               dict(key="overdue", start_date_raw=0x29C77F8, date_raw=GAME_DATE-48, flags={}, effects=[])]
    assert _modifier_projection("remaining_days", records, GAME_DATE, "FRA")[0]["status"] == "not_applicable"
    assert _modifier_projection("duration_type", records, GAME_DATE, "FRA")[0]["value"] == "no_fixed_end_date"
    assert _modifier_projection("remaining_days", records, GAME_DATE, "FRA")[1]["raw"] == -48


@pytest.mark.parametrize("option", ["include_country_loans", "include_country_modifiers"])
@pytest.mark.parametrize("bad", [1, "true", None])
def test_parent_record_options_require_literal_booleans(tmp_path, option, bad):
    result = parent.capture(tmp_path/"installation.json", "FRA", **{option: bad})
    assert result["status"] == "invalid_request"
    assert result["completed"] is False
    assert result["errors"][0]["error"] == option+"_must_be_bool"


def test_parent_retraction_clears_top_and_both_record_snapshots(tmp_path):
    _adapter, _base, report, _calls = source(tmp_path, "country_modifiers", modifier_child())
    parent._retract(report)
    for snapshot in (report, report["before"], report["after"]):
        assert snapshot["country_modifiers"]["fields"]["modifiers"]["status"] == "unknown"
        assert snapshot["country_modifiers"]["values"] is None
