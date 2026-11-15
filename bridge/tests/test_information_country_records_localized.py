"""Country-record/localization integration using the real raw-record validator."""
from copy import deepcopy

from bridge.tests.test_information_country_records import modifier_child, query, source
from bridge.tests.test_information_military_quality import GAME_DATE


class _Literals:
    def __init__(self, *, dynamic=False, change_context=None):
        self.calls = []
        self.dynamic = dynamic
        self.change_context = change_context

    def localized_text(self, country, context, keys):
        self.calls.append((country, deepcopy(context), list(keys)))
        if self.change_context:
            self.change_context()
        return {
            "status": "known", "language": "l_english",
            "entries": {key: {"status": "known", "text": "$COUNTRY$" if self.dynamic else key + " literal"}
                        for key in keys},
            "provenance": {"codec": "utf8", "test_boundary": "normalized_literal_reader"},
        }


def test_names_and_native_ids_share_one_country_capture_and_literal_lookup(tmp_path):
    adapter, base, _report, calls = source(tmp_path, "country_modifiers", modifier_child())
    literals = _Literals()
    adapter.localization_reader = literals
    result = adapter.read(query("N07", ["modifier_id", "name", "description"]), base.context())
    assert len(calls) == len(literals.calls) == 1
    names = result["fields"]["name"]
    assert names["status"] == "known"
    assert names["value"][0]["modifier_id"] == "papal_sanction_for_church_taxes"
    assert names["value"][0]["value"] == "papal_sanction_for_church_taxes literal"
    assert result["fields"]["description"]["value"][0]["key"] == "desc_papal_sanction_for_church_taxes"
    assert result["complete"] is False
    assert names["complete"] is False and names["partial"] is True
    assert result["source"]["provenance"]["native_records_and_text_atomic"] is False


def test_id_only_query_does_not_read_localization(tmp_path):
    adapter, base, _report, _calls = source(tmp_path, "country_modifiers", modifier_child())
    literals = _Literals()
    adapter.localization_reader = literals
    assert adapter.read(query("N07", ["modifier_id"]), base.context())["fields"]["modifier_id"]["status"] == "known"
    assert literals.calls == []


def test_dynamic_literal_does_not_hide_validated_native_records(tmp_path):
    adapter, base, _report, _calls = source(tmp_path, "country_modifiers", modifier_child())
    adapter.localization_reader = _Literals(dynamic=True)
    result = adapter.read(query("N07", ["modifier_id", "name"]), base.context())
    assert result["fields"]["modifier_id"]["status"] == "known"
    assert result["fields"]["name"]["status"] == "unknown"
    assert all("value" not in row for row in result["fields"]["name"]["value"])


def test_context_change_during_text_capture_withdraws_native_siblings(tmp_path):
    adapter, base, _report, _calls = source(tmp_path, "country_modifiers", modifier_child())
    adapter.localization_reader = _Literals(change_context=lambda: setattr(base, "after_context", {"game_date": GAME_DATE + 24}))
    result = adapter.read(query("N07", ["modifier_id", "name"]), base.context())
    for field in result["fields"].values():
        assert field["status"] == "unknown"
        assert field["reason"] == "COUNTRY_RECORDS_CONTEXT_CHANGED_DURING_LOCALIZATION"
        assert "value" not in field
