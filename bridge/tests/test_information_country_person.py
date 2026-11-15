"""Public S04 DTO and route tests with a stubbed capture validator.

The validator stub exercises source projection and service routing only. These
tests do not prove that a raw country-person RPM trace is safe; that belongs to
country_person_capture.validate_capture and its dedicated capture tests.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_person import NativeCountryPersonSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
import bridge.information.country_person as person_module


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134376782534496994
FIELDS = ("ruler", "heir", "dynasty", "personal_union")


def make_context(*, physical_country="POR"):
    return {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "person-public-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56564448,
        "physical_client_country": physical_country,
    }


def name_component(text: str) -> dict:
    return {
        "status": "known",
        "value": {
            "text": text,
            "raw_hex": text.encode("ascii").hex(),
            "encoding": "eu4_escape",
        },
        "raw_inputs": {"pointer": "0x123456789abcdef0"},
    }


def age_component(value: int) -> dict:
    return {
        "status": "known",
        "value": value,
        "unit": "years",
        "raw_inputs": {"age_pointer": "0x2233445566778899"},
    }


def claim_component(raw: int, weak: int = 50, strong: int = 80) -> dict:
    category = "weak" if raw < weak else "average" if raw < strong else "strong"
    return {
        "status": "known",
        "value": {
            "raw": raw,
            "scale": 1000,
            "category": category,
            "weak_threshold_raw": weak,
            "strong_threshold_raw": strong,
            "private": "not public",
        },
        "raw_inputs": {"claim_pointer": "0x3344556677889900"},
    }


def dynasty_component(text: str | None, *, included: bool) -> dict:
    return {
        "status": "known",
        "value": {
            "included_in_name": included,
            "name": name_component(text)["value"] if included else None,
        },
        "raw_inputs": {"dynasty_pointer": "0x4455667788990011"},
    }


def make_private_fields(*, heir_mode="character") -> dict:
    heir_components = {
        "name": name_component("Henry"),
        "age": age_component(17),
        "claim": claim_component(80),
    }
    if heir_mode == "hidden":
        heir_value = {
            "mode": "hidden",
            "present": None,
            **heir_components,
            "full_ui_label_complete": False,
        }
    elif heir_mode == "no_heir":
        heir_value = {
            "mode": "no_heir",
            "present": False,
            "name": {"status": "not_applicable", "reason": "NO_HEIR"},
            "age": {"status": "not_applicable", "reason": "NO_HEIR"},
            "claim": {"status": "not_applicable", "reason": "NO_HEIR"},
            "full_ui_label_complete": False,
        }
    else:
        heir_value = {
            "mode": "character",
            "present": True,
            **heir_components,
            "full_ui_label_complete": False,
        }
    return {
        "S04.ruler": {
            "status": "known",
            "value": {
                "display_mode": "person",
                "name": name_component("Edward"),
                "skills": {
                    "status": "known",
                    "value": {
                        "administrative": 4,
                        "diplomatic": 3,
                        "military": 5,
                        "raw": "drop",
                    },
                    "raw_inputs": {"skills_pointer": "0x123456789abcdef0"},
                },
                "age": age_component(34),
                "full_ui_label_complete": False,
                "raw_inputs": {"person_pointer": "0x123456789abcdef0"},
            },
            "raw_inputs": {"field_pointer": "0x123456789abcdef0"},
        },
        "S04.heir": {
            "status": "known",
            "value": heir_value,
            "raw_inputs": {"field_pointer": "0x123456789abcdef0"},
        },
        "S04.dynasty": {
            "status": "known",
            "value": {
                "ruler": dynasty_component("Lancaster", included=True),
                "heir": dynasty_component(None, included=False),
            },
            "raw_inputs": {"field_pointer": "0x123456789abcdef0"},
        },
        "S04.personal_union": {
            "status": "known",
            "value": {"uses_senior_ruler": False, "senior_country": None},
            "raw_inputs": {"field_pointer": "0x123456789abcdef0"},
        },
    }


def make_report(target="ENG", *, private_fields=None, gate_status="known",
                admitted=True, gate_reason=None):
    if private_fields is None:
        private_fields = make_private_fields()
    pass_gate = {"status": gate_status, "admitted": admitted}
    if gate_reason is not None:
        pass_gate["reason"] = gate_reason
    return {
        "schema": "information.country_person_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "backend": {
                "observer": {"tag": "FRA", "private_pointer": "0x2233445566778899"},
                "targets": [{
                    "tag": target,
                    "fullref": "0x123456789abcdef0",
                    "admission_by_pass": {
                        "pass1": deepcopy(pass_gate),
                        "pass2": deepcopy(pass_gate),
                    },
                    "fields": private_fields,
                }],
            },
        },
        "raw_reads": [{"label": "private.trace", "address": "0x123456789abcdef0"}],
    }


class Base:
    event_types = ()

    def __init__(self, directory: Path, context: dict):
        self.current = deepcopy(context)
        self.session = SimpleNamespace(
            directory=directory,
            creation_filetime=CREATION,
            record={
                "session_id": context["session_id"],
                "creation_filetime": CREATION,
            },
        )
        self.on_capture = None

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {
            "fields": {
                field: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                for field in query["fields"]
            },
            "complete": False,
            "source": {"name": "fixture_primary", "mode": "live"},
        }


def make_query(target="ENG", fields=None, parameters=None):
    return {
        "topic": "S04",
        "object": {"type": "country", "country": target},
        "fields": list(fields if fields is not None else FIELDS),
        "parameters": parameters if parameters is not None else {},
    }


def make_source(tmp_path, monkeypatch, *, target="ENG", report=None,
                valid=True, after_capture=None):
    base = Base(tmp_path, make_context())
    if after_capture is not None:
        base.on_capture = after_capture
    report = deepcopy(report if report is not None else make_report(target))
    captures = []
    validations = []

    def capture(installation, *, country, observer):
        captures.append((installation, country, observer))
        if base.on_capture is not None:
            base.on_capture(base)
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((
            deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        return valid

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(
        person_module, "import_module", lambda _name, _package: validator_module)
    source = NativeCountryPersonSource(base, capture=capture)
    return source, base, report, captures, validations


@pytest.mark.parametrize("target", ["ENG", "FRA"])
def test_all_four_fields_are_sanitized_for_foreign_or_observer_country(
        tmp_path, monkeypatch, target):
    report = make_report(target)
    source, base, _, captures, validations = make_source(
        tmp_path, monkeypatch, target=target, report=report)

    result = source.read(make_query(target), base.context())

    assert set(result["fields"]) == set(FIELDS)
    assert result["fields"]["ruler"]["value"] == {
        "display_mode": "person",
        "name": {"status": "known", "value": {
            "text": "Edward", "raw_hex": "456477617264", "encoding": "eu4_escape",
        }},
        "skills": {"status": "known", "value": {
            "administrative": 4, "diplomatic": 3, "military": 5,
        }},
        "age": {"status": "known", "value": 34, "unit": "years"},
        "full_ui_label_complete": False,
    }
    assert result["fields"]["heir"]["value"]["present"] is True
    assert result["fields"]["heir"]["value"]["claim"]["value"]["category"] == "strong"
    assert result["fields"]["dynasty"]["value"]["ruler"]["value"] == {
        "included_in_name": True,
        "name": {"text": "Lancaster", "raw_hex": "4c616e636173746572",
                 "encoding": "eu4_escape"},
    }
    assert result["fields"]["personal_union"]["value"] == {
        "uses_senior_ruler": False,
        "senior_country": None,
    }
    assert all(item["partial"] is True and item["complete"] is False
               for item in result["fields"].values())
    assert result["complete"] is False
    assert result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["provenance"]["target"] == target
    assert result["source"]["provenance"]["actual_UI_observed"] is False
    assert result["source"]["provenance"]["full_ui_label_complete"] is False
    assert result["source"]["provenance"]["capture_report_sha256"]
    assert captures == [(tmp_path / "installation.json", target, "FRA")]
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, target)
    public = repr(result)
    for private in (
        "raw_inputs", "raw_reads", "private_pointer", "person_pointer",
        "skills_pointer", "claim_pointer", "field_pointer", "not public",
    ):
        assert private not in public


def test_arbitrary_nonempty_unique_field_subset_is_supported(tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)

    result = source.read(make_query("ENG", ["personal_union", "ruler"]), base.context())

    assert set(result["fields"]) == {"personal_union", "ruler"}
    assert captures == [(tmp_path / "installation.json", "ENG", "FRA")]


def test_catalog_is_partial_and_does_not_claim_succession_dispute(tmp_path, monkeypatch):
    source, _, _, _, _ = make_source(tmp_path, monkeypatch)

    topic = source.catalog()[0]

    assert topic["topic_id"] == "S04"
    assert set(topic["fields"]) == set(FIELDS)
    assert all(item["coverage"] == "partial" and item["complete"] is False
               for item in topic["fields"].values())
    assert topic["triggers"] == ["query", "periodic"]
    assert "succession_dispute" not in topic["fields"]
    assert "完整联统名单或继承预测" in topic["scope_note"]


@pytest.mark.parametrize("field_status", ["unknown", "invisible"])
def test_private_unknown_or_invisible_fields_never_export_private_payload(
        tmp_path, monkeypatch, field_status):
    fields = make_private_fields()
    fields["S04.ruler"] = {
        "status": field_status,
        "reason": "NATIVE_RULER_UNKNOWN_0x123456789abcdef0",
        "value": {"secret": "do not leak"},
        "raw_inputs": {"ptr": "0x123456789abcdef0"},
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["ruler"]), base.context())["fields"]["ruler"]

    expected = "invisible" if field_status == "invisible" else "unknown"
    assert field["status"] == expected
    assert "value" not in field
    assert "raw_inputs" not in repr(field)
    assert "0x123456789abcdef0" not in repr(field)
    assert "do not leak" not in repr(field)


def test_unknown_reason_is_bounded_and_pointer_like_text_is_retracted(tmp_path, monkeypatch):
    fields = make_private_fields()
    fields["S04.dynasty"] = {
        "status": "unknown",
        "reason": "PRIVATE_DYNASTY_UNKNOWN_0x123456789abcdef0",
        "raw_inputs": {"ptr": "0x123456789abcdef0"},
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["dynasty"]), base.context())["fields"]["dynasty"]

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_PERSON_DYNASTY_UNKNOWN"
    assert "0x123456789abcdef0" not in repr(field)


def test_hidden_heir_panel_is_not_applicable_not_no_heir(tmp_path, monkeypatch):
    fields = make_private_fields(heir_mode="hidden")
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["heir"]), base.context())["fields"]["heir"]

    assert field["status"] == "not_applicable"
    assert field["reason"] == "NATIVE_HEIR_CHARACTER_PANEL_HIDDEN"
    assert "value" not in field
    assert "present" not in repr(field)


def test_no_heir_mode_preserves_only_not_applicable_components(tmp_path, monkeypatch):
    fields = make_private_fields(heir_mode="no_heir")
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["heir"]), base.context())["fields"]["heir"]

    assert field["status"] == "known"
    assert field["value"]["mode"] == "no_heir"
    assert field["value"]["present"] is False
    for component in ("name", "age", "claim"):
        assert field["value"][component]["status"] == "not_applicable"
        assert "value" not in field["value"][component]


def test_unknown_component_does_not_discard_sibling_ruler_components(tmp_path, monkeypatch):
    fields = make_private_fields()
    ruler = fields["S04.ruler"]["value"]
    ruler["name"] = {
        "status": "unknown",
        "reason": "NATIVE_NAME_CACHE_UNAVAILABLE",
        "value": {"text": "secret"},
        "raw_inputs": {"pointer": "0x123456789abcdef0"},
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["ruler"]), base.context())["fields"]["ruler"]

    assert field["status"] == "known"
    assert field["value"]["name"] == {
        "status": "unknown",
        "reason": "NATIVE_NAME_CACHE_UNAVAILABLE",
    }
    assert field["value"]["skills"]["status"] == "known"
    assert field["value"]["age"]["value"] == 34
    assert "raw_inputs" not in repr(field)


@pytest.mark.parametrize("bad_name", [
    {"text": "wrong", "raw_hex": "456477617264", "encoding": "eu4_escape"},
    {"text": "x", "raw_hex": "0", "encoding": "eu4_escape"},
    {"text": "x", "raw_hex": "zz", "encoding": "eu4_escape"},
    {"text": "x", "raw_hex": "00", "encoding": "eu4_escape"},
    {"text": "x", "raw_hex": "61" * 514, "encoding": "eu4_escape"},
    {"text": "Edward", "raw_hex": "456477617264"},
])
def test_invalid_name_becomes_component_unknown_without_pointer_leak(
        tmp_path, monkeypatch, bad_name):
    fields = make_private_fields()
    fields["S04.ruler"]["value"]["name"] = {
        "status": "known", "value": bad_name,
        "raw_inputs": {"name_pointer": "0x123456789abcdef0"},
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["ruler"]), base.context())["fields"]["ruler"]

    assert field["status"] == "known"
    assert field["value"]["name"] == {
        "status": "unknown",
        "reason": "COUNTRY_PERSON_RULER_NAME_UNKNOWN",
    }
    assert field["value"]["skills"]["status"] == "known"
    assert "0x123456789abcdef0" not in repr(field)


def test_valid_empty_name_component_remains_an_empty_text_object(tmp_path, monkeypatch):
    fields = make_private_fields()
    fields["S04.ruler"]["value"]["name"] = {
        "status": "known",
        "value": {"text": "", "raw_hex": "", "encoding": "eu4_escape"},
    }
    fields["S04.dynasty"]["value"]["ruler"] = dynasty_component("", included=True)
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    result = source.read(make_query("ENG", ["ruler", "dynasty"]), base.context())["fields"]

    assert result["ruler"]["value"]["name"] == {
        "status": "known",
        "value": {"text": "", "raw_hex": "", "encoding": "eu4_escape"},
    }
    assert result["dynasty"]["value"]["ruler"]["value"] == {
        "included_in_name": True,
        "name": {"text": "", "raw_hex": "", "encoding": "eu4_escape"},
    }


@pytest.mark.parametrize(
    ("raw", "weak", "strong", "category"),
    [(49, 50, 80, "weak"), (50, 50, 80, "average"),
     (79, 50, 80, "average"), (80, 50, 80, "strong"),
     (5, 10, 3, "weak")],
)
def test_claim_projection_matches_exact_native_threshold_if_else(
        tmp_path, monkeypatch, raw, weak, strong, category):
    fields = make_private_fields()
    fields["S04.heir"]["value"]["claim"] = claim_component(raw, weak, strong)
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(make_query("ENG", ["heir"]), base.context())["fields"]["heir"]

    assert field["status"] == "known"
    claim = field["value"]["claim"]
    assert claim["status"] == "known"
    assert claim["value"]["category"] == category
    assert claim["value"]["weak_threshold_raw"] == weak
    assert claim["value"]["strong_threshold_raw"] == strong


def test_claim_category_mismatch_and_invalid_age_are_component_unknown(tmp_path, monkeypatch):
    fields = make_private_fields()
    fields["S04.heir"]["value"]["claim"]["value"]["category"] = "average"
    fields["S04.ruler"]["value"]["age"] = {
        "status": "known", "value": -1, "unit": "years",
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    result = source.read(make_query("ENG", ["heir", "ruler"]), base.context())["fields"]

    assert result["heir"]["status"] == "known"
    assert result["heir"]["value"]["claim"] == {
        "status": "unknown",
        "reason": "COUNTRY_PERSON_HEIR_CLAIM_UNKNOWN",
    }
    assert result["ruler"]["status"] == "known"
    assert result["ruler"]["value"]["age"] == {
        "status": "unknown",
        "reason": "COUNTRY_PERSON_RULER_AGE_UNKNOWN",
    }


def test_personal_union_is_only_the_senior_ruler_panel_branch(tmp_path, monkeypatch):
    fields = make_private_fields()
    fields["S04.personal_union"]["value"] = {
        "uses_senior_ruler": True,
        "senior_country": "ENG",
        "raw_inputs": {"fullref": "0x123456789abcdef0"},
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(private_fields=fields))

    field = source.read(
        make_query("ENG", ["personal_union"]), base.context())["fields"]["personal_union"]

    assert field["status"] == "known"
    assert field["value"] == {"uses_senior_ruler": True, "senior_country": "ENG"}
    assert "raw_inputs" not in repr(field)


@pytest.mark.parametrize("query", [
    {"topic": "S04", "object": {"type": "country", "country": "bad"}, "fields": ["ruler"]},
    {"topic": "S04", "object": {"type": "country", "country": "ENG", "pointer": 7}, "fields": ["ruler"]},
    {"topic": "S04", "object": {"type": "country", "country": "ENG"}, "fields": []},
    {"topic": "S04", "object": {"type": "country", "country": "ENG"}, "fields": ["ruler", "ruler"]},
    {"topic": "S04", "object": {"type": "country", "country": "ENG"}, "fields": ["succession_dispute"]},
    {"topic": "S04", "object": {"type": "country", "country": "ENG"}, "fields": ["ruler"], "parameters": {"detail": "full"}},
    {"topic": "S04", "object": {"type": "country", "country": "ENG"}, "fields": ["ruler"], "unexpected": 1},
])
def test_query_rejects_bad_selectors_duplicates_and_unimplemented_field(
        tmp_path, monkeypatch, query):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(query, base.context())
    assert captures == []


def test_context_and_session_are_rechecked_after_capture(tmp_path, monkeypatch):
    def change_session(base):
        base.current["session_id"] = "different-session"

    source, base, _, _, validations = make_source(
        tmp_path, monkeypatch, after_capture=change_session)

    result = source.read(make_query("ENG", ["ruler"]), base.context())

    assert result["fields"]["ruler"]["status"] == "unavailable"
    assert result["fields"]["ruler"]["reason"] == (
        "COUNTRY_PERSON_CONTEXT_CHANGED_DURING_CAPTURE")
    assert validations == []


def test_capture_validator_must_return_true_before_public_projection(tmp_path, monkeypatch):
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, valid=False)

    result = source.read(make_query("ENG"), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "COUNTRY_PERSON_CAPTURE_INVALID"
               for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())


def test_unknown_or_rejected_observer_admission_blocks_every_value(tmp_path, monkeypatch):
    report = make_report(
        "ENG", gate_status="unknown", admitted=None,
        gate_reason="PRIVATE_GATE_0x123456789abcdef0")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query("ENG"), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "COUNTRY_PERSON_VIEW_ADMISSION_UNKNOWN"
               for field in result["fields"].values())
    assert "0x123456789abcdef0" not in repr(result)

    report = make_report("ENG", admitted=False)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query("ENG"), base.context())
    assert all(field["status"] == "invisible" for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())


def test_query_report_and_periodic_routes_share_partial_projection(tmp_path, monkeypatch):
    report = make_report("ENG")
    context = make_context()
    base = Base(tmp_path, context)
    captures = []

    def capture(_installation, *, country, observer):
        captures.append((country, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(
        person_module, "import_module", lambda _name, _package: validator_module)
    person = NativeCountryPersonSource(base, capture=capture)
    now = [100]
    service = InformationService(
        CompositeSource(base, [person]),
        tmp_path / "person-information.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    query = make_query("ENG", ["ruler", "heir"])
    try:
        topic = next(
            item for item in service.source.catalog() if item["topic_id"] == "S04")
        assert all(topic["fields"][name]["coverage"] == "partial"
                   for name in ("ruler", "heir", "dynasty", "personal_union"))
        assert all(topic["fields"][name]["complete"] is False
                   for name in ("ruler", "heir", "dynasty", "personal_union"))
        assert topic["triggers"] == ["query", "periodic"]

        direct = tools.call("information_query", {
            "request_id": "person-public-query", "queries": [query], "view": "full",
        })
        saved = tools.call("information_manage_report", {
            "request_id": "person-public-report", "operation": "create",
            "config": {"name": "person partial", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "request_id": "person-public-report-query", "report_id": saved["id"], "view": "full",
        })
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["heir"]["value"]["mode"] == "character"
        assert direct["complete"] is False

        tools.call("information_manage_subscription", {
            "request_id": "person-public-subscription-create",
            "operation": "create",
            "config": {
                "name": "person periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": saved["id"],
                "schedule": {
                    "basis": "real", "unit": "seconds", "every": 1,
                    "missed": "coalesce",
                },
            },
        })
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["items"][0]["fields"] == direct["items"][0]["fields"]
        assert periodic["status"] == "partial"
        assert captures == [("ENG", "FRA")] * 3
    finally:
        service.close()
