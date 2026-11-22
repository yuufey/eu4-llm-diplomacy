"""F01 public projection tests with an explicit stub capture validator.

The fake validator tests adapter privacy, DTO validation and shared service
routes. They are not evidence that the country-scale raw RPM trace passed.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_scale import NativeCountryScaleSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
import bridge.information.country_scale as scale_module


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134376782534496994
SUBJECT_VALUE = {
    "reference_count": 3,
    "included_count": 2,
    "excluded_count": 1,
    "weighted_development_raw": 17000,
    "development_scale": 1000,
    "weight_raw": 750,
    "weight_scale": 1000,
}
FIELD_IDS = {
    "development": "F01.development",
    "territory": "F01.territory",
    "subject_scale": "F01.subject_scale",
    "major_power": "F01.major_power",
    "wars": "F01.wars",
}
ALL_FIELDS = ["development", "territory", "subject_scale", "major_power", "wars"]


def _territory_raw(city_count=123, **overrides):
    result = {
        "status": "known",
        "value": {"city_count": city_count},
        "unit": "native_city_count",
        "scale": 1,
        "basis": "bounded_country_num_of_cities_cache_i32",
        "partial": True,
        "complete": False,
        "raw_inputs": {"country_pointer": "0x1122334455667788", "cache_raw_hex": "7b000000"},
    }
    result.update(overrides)
    return result


def _wars_value(target="ENG"):
    opponent = "BUR" if target == "FRA" else "FRA"
    return {
        "at_war": True,
        "war_count": 1,
        "wars": [{
            "war_id": {
                "status": "known", "value": "war_1c5b10c9b19ce405_00000007",
                "identity_scope": "observer_session", "lifetime_verified": False,
            },
            "target_side": "side_a",
            "side_a": [{"status": "known", "country": target}],
            "side_b": [{"status": "known", "country": opponent}],
            "membership_complete": True,
            "identities_complete": True,
            "roles_verified": False,
        }],
        "enumeration_scope": "current_country_opponent_index",
        "global_membership_verified": False,
        "lifetime_verified": False,
    }


def _wars_raw(value=None, **overrides):
    result = {
        "status": "known",
        "value": deepcopy(_wars_value() if value is None else value),
        "unit": "native_country_wars",
        "scale": 1,
        "basis": "current_country_war_index_and_side_vector_projection",
        "partial": True,
        "complete": False,
        "raw_inputs": {"war_pointer": "0x1122334455667788", "private_index": "private"},
    }
    result.update(overrides)
    return result


def make_context(*, physical_country="POR"):
    return {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "country-scale-public-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56564448,
        "physical_client_country": physical_country,
    }


def _known_raw_fields(*, target="ENG", development=21347, subject=None, major_power=True):
    subject = deepcopy(SUBJECT_VALUE if subject is None else subject)
    return {
        FIELD_IDS["development"]: {
            "status": "known",
            "value": development,
            "unit": "development_raw",
            "scale": 1000,
            "raw_inputs": {"country_pointer": "0x1122334455667788", "raw_hex": "63530000"},
        },
        FIELD_IDS["territory"]: _territory_raw(),
        FIELD_IDS["subject_scale"]: {
            "status": "known",
            "value": subject,
            "raw_inputs": {"subject_fullref": "0x0100007a00415246", "items": ["private"]},
        },
        FIELD_IDS["major_power"]: {
            "status": "known",
            "value": major_power,
            "raw_inputs": {"country_pointer": "0x1122334455667788", "TLS": "unclosed"},
        },
        FIELD_IDS["wars"]: _wars_raw(_wars_value(target)),
    }


def make_report(target="ENG", *, admitted=True, gate_status="known",
                field_overrides=None, observer="FRA"):
    fields = _known_raw_fields(target=target)
    for name, value in (field_overrides or {}).items():
        fields[FIELD_IDS.get(name, name)] = deepcopy(value)
    return {
        "schema": "information.country_scale_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "backend": {
                "observer": {"tag": observer, "private_pointer": "0x2233445566778899"},
                "targets": [{
                    "tag": target,
                    "fullref": "0x0100007a00415246",
                    "admission_by_pass": {
                        "pass1": {"status": gate_status, "admitted": admitted},
                        "pass2": {"status": gate_status, "admitted": admitted},
                    },
                    "fields": fields,
                }],
            },
        },
        "raw_reads": [{"label": "private.trace", "address": "0x1122334455667788"}],
    }


class Base:
    event_types = ()

    def __init__(self, directory: Path, context: dict):
        self.current = deepcopy(context)
        self.session = SimpleNamespace(
            directory=directory,
            creation_filetime=CREATION,
            record={"session_id": context["session_id"], "creation_filetime": CREATION},
        )
        self.on_capture = None

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {
            "fields": {
                name: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                for name in query["fields"]
            },
            "complete": False,
            "source": {"name": "fixture_primary", "mode": "live"},
        }


def make_query(target="ENG", fields=None, parameters=None):
    return {
        "topic": "F01",
        "object": {"type": "country", "country": target},
        "fields": list(ALL_FIELDS if fields is None else fields),
        "parameters": {} if parameters is None else parameters,
    }


def make_source(tmp_path, monkeypatch, *, target="ENG", report=None, valid=True,
                after_capture=None, capture_error=None, validator_error=False):
    base = Base(tmp_path, make_context())
    base.on_capture = after_capture
    report = deepcopy(report if report is not None else make_report(target))
    captures = []
    validations = []

    def capture(installation, *, country, observer):
        captures.append((installation, country, observer))
        if base.on_capture is not None:
            base.on_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        if validator_error:
            raise RuntimeError("fixture validator error")
        return valid

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(scale_module, "import_module", lambda _name, _package: validator_module)
    source = NativeCountryScaleSource(base, capture=capture)
    return source, base, report, captures, validations


@pytest.mark.parametrize("target", ["ENG", "FRA"])
def test_known_values_are_strict_whitelisted_dtos_and_preserve_physical_por(
        tmp_path, monkeypatch, target):
    report = make_report(target, field_overrides={
        "development": {
            "status": "known", "value": -2147483648,
            "unit": "development_raw", "scale": 1000,
            "raw_inputs": {"country_pointer": "0x123456789abcdef0"},
        },
        "subject_scale": {"status": "known", "value": SUBJECT_VALUE,
                          "raw_inputs": {"private": "0x123456789abcdef0"}},
        "major_power": {"status": "known", "value": False,
                         "raw_inputs": {"private": "0x123456789abcdef0"}},
    })
    source, base, _, captures, validations = make_source(
        tmp_path, monkeypatch, target=target, report=report
    )
    result = source.read(make_query(target), base.context())

    assert result["complete"] is False
    assert set(result["fields"]) == set(ALL_FIELDS)
    assert result["fields"]["development"]["value"] == -2147483648
    assert result["fields"]["subject_scale"]["value"] == SUBJECT_VALUE
    assert set(result["fields"]["subject_scale"]["value"]) == {
        "reference_count", "included_count", "excluded_count", "weighted_development_raw",
        "development_scale", "weight_raw", "weight_scale",
    }
    assert result["fields"]["major_power"]["value"] is False
    territory = result["fields"]["territory"]
    assert territory["value"] == {"city_count": 123}
    assert territory["unit"] == "native_city_count" and type(territory["scale"]) is int
    assert territory["scale"] == 1 and territory["basis"] == "bounded_country_num_of_cities_cache_i32"
    assert territory["gaps"] and "COMPLETE_OWNED_PROVINCE_COUNT_AND_LIST_NOT_CONNECTED" in territory["gaps"]
    assert "raw_inputs" not in repr(territory)
    wars = result["fields"]["wars"]
    assert wars["status"] == "known"
    assert wars["value"] == _wars_value(target)
    assert set(wars["value"]) == {
        "at_war", "war_count", "wars", "enumeration_scope",
        "global_membership_verified", "lifetime_verified",
    }
    assert wars["unit"] == "native_country_wars" and type(wars["scale"]) is int
    assert wars["scale"] == 1
    assert wars["basis"] == "current_country_war_index_and_side_vector_projection"
    assert wars["partial"] is True and wars["complete"] is False
    assert wars["gaps"] and "CURRENT_OPPONENT_INDEX_IS_NOT_GLOBAL_WAR_MEMBERSHIP" in wars["gaps"]
    assert "raw_inputs" not in repr(wars)
    assert result["source"]["projection_version"] == 3
    for name in ("development", "subject_scale", "major_power"):
        assert "unit" not in result["fields"][name]
        assert "scale" not in result["fields"][name]
    assert all(field["partial"] is True and field["complete"] is False
               for field in result["fields"].values())
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA" and provenance["target"] == target
    assert provenance["physical_client_country"] == "POR"
    assert provenance["actual_UI_observed"] is False
    assert provenance["ranking_membership_observed"] is False
    assert provenance["capture_report_sha256"]
    assert captures == [(tmp_path / "installation.json", target, "FRA")]
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, target)
    public = repr(result)
    for private in ("raw_inputs", "raw_reads", "country_pointer", "private_pointer",
                    "subject_fullref", "0x123456789abcdef0", "private.trace"):
        assert private not in public


def test_catalog_marks_city_count_and_wars_partial(
        tmp_path, monkeypatch):
    source, base, _, _, _ = make_source(tmp_path, monkeypatch)
    composite = CompositeSource(base, [source])
    topic = next(entry for entry in composite.catalog() if entry["topic_id"] == "F01")
    assert topic["status"] == "available"
    assert set(topic["fields"]) == {
        "development", "territory", "subject_scale", "major_power", "wars"
    }
    for name in ALL_FIELDS:
        assert topic["fields"][name]["coverage"] == "partial"
        assert topic["fields"][name]["complete"] is False
    assert topic["fields"]["development"]["unit"] == "development_raw"
    assert topic["fields"]["development"]["scale"] == 1000
    assert topic["fields"]["development"]["paths"] == [
        "observation.backend.targets[0].fields['F01.development'].value"
    ]
    assert topic["fields"]["territory"]["coverage"] == "partial"
    assert topic["fields"]["territory"]["complete"] is False
    assert topic["fields"]["territory"]["unit"] == "native_city_count"
    assert topic["fields"]["territory"]["scale"] == 1
    assert topic["fields"]["territory"]["basis"] == "bounded_country_num_of_cities_cache_i32"
    assert topic["fields"]["territory"]["paths"] == [
        "observation.backend.targets[0].fields['F01.territory'].value.city_count"
    ]
    assert "COMPLETE_OWNED_PROVINCE_COUNT_AND_LIST_NOT_CONNECTED" in topic["fields"]["territory"]["gaps"]
    assert topic["fields"]["wars"]["coverage"] == "partial"
    assert topic["fields"]["wars"]["complete"] is False
    assert topic["fields"]["wars"]["unit"] == "native_country_wars"
    assert topic["fields"]["wars"]["scale"] == 1
    assert topic["fields"]["wars"]["basis"] == (
        "current_country_war_index_and_side_vector_projection"
    )
    assert topic["fields"]["wars"]["paths"] == [
        "observation.backend.targets[0].fields['F01.wars'].value.at_war",
        "observation.backend.targets[0].fields['F01.wars'].value.war_count",
        "observation.backend.targets[0].fields['F01.wars'].value.wars",
    ]
    for required_gap in (
        "CURRENT_OPPONENT_INDEX_IS_NOT_GLOBAL_WAR_MEMBERSHIP",
        "OBSERVER_SESSION_REGISTRY_POINTER_MATCH_DOES_NOT_VERIFY_LIFETIME",
        "SIDE_A_AND_SIDE_B_ARE_NOT_ATTACK_AND_DEFEND_ROLES",
        "COUNTRY_ADMISSION_REDACTS_UNVERIFIED_MEMBER_IDENTITIES",
        "ACTUAL_UI_AND_COMPLETE_VISIBILITY_NOT_OBSERVED",
    ):
        assert required_gap in topic["fields"]["wars"]["gaps"]
    assert topic["fields"]["major_power"]["paths"] == [
        "observation.backend.targets[0].fields['F01.major_power'].value"
    ]
    assert all("COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY"
               in topic["fields"][name]["gaps"] for name in ALL_FIELDS)
    assert topic["triggers"] == ["query", "periodic"]


@pytest.mark.parametrize("city_count", [0, 65535])
def test_territory_accepts_only_bounded_city_count_dto_and_keeps_scope_metadata(
        tmp_path, monkeypatch, city_count):
    raw = _territory_raw(city_count, raw_inputs={
        "country_pointer": "0x123456789abcdef0", "cache_raw_hex": "private",
    })
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"territory": raw})
    )

    result = source.read(make_query(fields=["territory"]), base.context())
    field = result["fields"]["territory"]

    assert field["status"] == "known"
    assert field["value"] == {"city_count": city_count}
    assert set(field["value"]) == {"city_count"}
    assert field["unit"] == "native_city_count" and type(field["scale"]) is int
    assert field["scale"] == 1
    assert field["basis"] == "bounded_country_num_of_cities_cache_i32"
    assert field["partial"] is True and field["complete"] is False
    assert result["source"]["projection_version"] == 3
    assert "raw_inputs" not in repr(field)
    assert "0x123456789abcdef0" not in repr(result)


@pytest.mark.parametrize("raw", [
    _territory_raw(True),
    _territory_raw(-1),
    _territory_raw(65536),
    _territory_raw(1, value={"city_count": 1, "pointer": "0x123456789abcdef0"}),
    _territory_raw(1, value={}),
    _territory_raw(1, value=[1]),
    _territory_raw(1, unit="wrong"),
    _territory_raw(1, scale=True),
    _territory_raw(1, scale=2),
    _territory_raw(1, partial=False),
    _territory_raw(1, complete=True),
    _territory_raw(1, basis="unverified_basis"),
])
def test_invalid_territory_dto_retracts_only_city_count(tmp_path, monkeypatch, raw):
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"territory": raw})
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["territory"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_SCALE_FIELD_INVALID"
    assert "value" not in field
    for name in ("development", "subject_scale", "major_power", "wars"):
        assert result["fields"][name]["status"] == "known"


def test_wars_zero_index_is_a_known_empty_result(tmp_path, monkeypatch):
    zero = {
        "at_war": False, "war_count": 0, "wars": [],
        "enumeration_scope": "current_country_opponent_index",
        "global_membership_verified": False, "lifetime_verified": False,
    }
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"wars": _wars_raw(zero)})
    )
    field = source.read(make_query(fields=["wars"]), base.context())["fields"]["wars"]
    assert field["status"] == "known"
    assert field["value"] == zero
    assert field["value"]["war_count"] == len(field["value"]["wars"]) == 0
    assert field["value"]["at_war"] is False


def test_wars_query_supports_single_and_mixed_field_selections(tmp_path, monkeypatch):
    for fields in (["wars"], ["territory", "wars"], list(ALL_FIELDS)):
        source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
        result = source.read(make_query(fields=fields), base.context())
        assert list(result["fields"]) == fields
        assert result["fields"]["wars"]["status"] == "known"
        assert result["fields"]["wars"]["value"]["war_count"] == 1
        assert len(captures) == 1


@pytest.mark.parametrize("redacted_status", ["unknown", "invisible"])
def test_wars_allow_unknown_id_and_redacted_members_without_leaking_tags(
        tmp_path, monkeypatch, redacted_status):
    value = _wars_value("ENG")
    war = value["wars"][0]
    war["war_id"] = {"status": "unknown", "reason": "WAR_ID_NOT_REGISTERED"}
    war["side_b"] = [{"status": redacted_status, "reason": "COUNTRY_VIEW_NOT_ADMITTED"}]
    war["identities_complete"] = False
    raw = _wars_raw(value, raw_inputs={
        "redacted_country_tag": "FRA", "private_pointer": "0x123456789abcdef0",
    })
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"wars": raw})
    )
    field = source.read(make_query(fields=["wars"]), base.context())["fields"]["wars"]
    assert field["status"] == "known"
    public_war = field["value"]["wars"][0]
    assert public_war["war_id"] == {"status": "unknown", "reason": "WAR_ID_NOT_REGISTERED"}
    assert public_war["side_b"] == [{
        "status": redacted_status, "reason": "COUNTRY_VIEW_NOT_ADMITTED",
    }]
    assert public_war["identities_complete"] is False
    assert "raw_inputs" not in repr(field)
    assert "0x123456789abcdef0" not in repr(field)
    assert "FRA" not in repr(field)


@pytest.mark.parametrize("case", [
    "top_extra", "at_war_type", "at_war_mismatch", "count_type", "count_mismatch",
    "too_many_wars", "bad_scope", "global_true", "lifetime_true", "war_extra",
    "bad_target_side", "empty_side", "too_many_members", "duplicate_tag",
    "membership_incomplete", "identities_complete_wrong", "roles_true",
    "member_extra", "member_bad_tag", "member_bad_reason", "id_extra",
    "id_bad_format", "id_bad_scope", "id_lifetime_true", "id_serial_zero",
    "id_serial_overflow", "duplicate_known_id",
])
def test_invalid_wars_dto_retracts_only_wars(tmp_path, monkeypatch, case):
    value = _wars_value("ENG")
    war = value["wars"][0]
    if case == "top_extra":
        value["private"] = "0x123456789abcdef0"
    elif case == "at_war_type":
        value["at_war"] = 1
    elif case == "at_war_mismatch":
        value["at_war"] = False
    elif case == "count_type":
        value["war_count"] = True
    elif case == "count_mismatch":
        value["war_count"] = 2
    elif case == "too_many_wars":
        value["war_count"] = 33
        value["wars"] = [{}] * 33
    elif case == "bad_scope":
        value["enumeration_scope"] = "global"
    elif case == "global_true":
        value["global_membership_verified"] = True
    elif case == "lifetime_true":
        value["lifetime_verified"] = True
    elif case == "war_extra":
        war["native_reference"] = "0x123456789abcdef0"
    elif case == "bad_target_side":
        war["target_side"] = "attacker"
    elif case == "empty_side":
        war["side_a"] = []
    elif case == "too_many_members":
        war["side_a"] = [{"status": "unknown", "reason": "REDACTED"}] * 257
        war["identities_complete"] = False
    elif case == "duplicate_tag":
        war["side_b"] = deepcopy(war["side_a"])
    elif case == "membership_incomplete":
        war["membership_complete"] = False
    elif case == "identities_complete_wrong":
        war["identities_complete"] = False
    elif case == "roles_true":
        war["roles_verified"] = True
    elif case == "member_extra":
        war["side_a"][0]["raw_inputs"] = {"pointer": "0x123456789abcdef0"}
    elif case == "member_bad_tag":
        war["side_a"][0]["country"] = "eng"
    elif case == "member_bad_reason":
        war["side_b"] = [{"status": "unknown", "reason": "pointer_0x123456"}]
        war["identities_complete"] = False
    elif case == "id_extra":
        war["war_id"]["native_reference"] = "0x123456789abcdef0"
    elif case == "id_bad_format":
        war["war_id"]["value"] = "war_BAD_00000007"
    elif case == "id_bad_scope":
        war["war_id"]["identity_scope"] = "global"
    elif case == "id_lifetime_true":
        war["war_id"]["lifetime_verified"] = True
    elif case == "id_serial_zero":
        war["war_id"]["value"] = "war_1c5b10c9b19ce405_00000000"
    elif case == "id_serial_overflow":
        war["war_id"]["value"] = "war_1c5b10c9b19ce405_00000101"
    elif case == "duplicate_known_id":
        value["wars"].append(deepcopy(war))
        value["war_count"] = 2

    raw = _wars_raw(value)
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"wars": raw})
    )
    result = source.read(make_query(), base.context())
    field = result["fields"]["wars"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_SCALE_FIELD_INVALID"
    assert "value" not in field
    for name in ("development", "territory", "subject_scale", "major_power"):
        assert result["fields"][name]["status"] == "known"


@pytest.mark.parametrize("value", [_I32_MIN := -(1 << 31), -1, 0, _I32_MAX := (1 << 31) - 1])
def test_development_signed_i32_boundaries_are_preserved(tmp_path, monkeypatch, value):
    report = make_report(field_overrides={"development": {
        "status": "known", "value": value, "unit": "development_raw", "scale": 1000,
        "raw_inputs": {"private": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    field = source.read(make_query(fields=["development"]), base.context())["fields"]["development"]
    assert field["status"] == "known" and field["value"] == value


@pytest.mark.parametrize("raw", [
    {"status": "known", "value": True, "unit": "development_raw", "scale": 1000},
    {"status": "known", "value": 1 << 31, "unit": "development_raw", "scale": 1000},
    {"status": "known", "value": -(1 << 31) - 1, "unit": "development_raw", "scale": 1000},
    {"status": "known", "value": 1, "unit": "wrong", "scale": 1000},
    {"status": "known", "value": 1, "unit": "development_raw", "scale": True},
    {"status": "known", "value": 1, "unit": "development_raw", "scale": 999},
])
def test_invalid_development_retracts_only_its_field(tmp_path, monkeypatch, raw):
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(field_overrides={"development": raw})
    )
    result = source.read(make_query(), base.context())
    assert result["fields"]["development"]["status"] == "unknown"
    assert result["fields"]["development"]["reason"] == "COUNTRY_SCALE_FIELD_INVALID"
    assert "value" not in result["fields"]["development"]
    assert result["fields"]["subject_scale"]["status"] == "known"
    assert result["fields"]["major_power"]["status"] == "known"


def _subject_mutation(**changes):
    result = deepcopy(SUBJECT_VALUE)
    result.update(changes)
    return result


@pytest.mark.parametrize("subject", [
    _subject_mutation(reference_count=0, included_count=0, excluded_count=0,
                      weighted_development_raw=-(1 << 31), weight_raw=(1 << 31) - 1),
    _subject_mutation(reference_count=256, included_count=256, excluded_count=0,
                      weighted_development_raw=(1 << 31) - 1, weight_raw=-(1 << 31)),
])
def test_subject_scale_accepts_count_and_signed_i32_boundaries(tmp_path, monkeypatch, subject):
    report = make_report(field_overrides={"subject_scale": {
        "status": "known", "value": subject, "raw_inputs": {"private": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(fields=["subject_scale"]), base.context())
    assert result["fields"]["subject_scale"]["status"] == "known"
    assert result["fields"]["subject_scale"]["value"] == subject


@pytest.mark.parametrize("subject", [
    _subject_mutation(extra="private"),
    {key: value for key, value in SUBJECT_VALUE.items() if key != "weight_raw"},
    _subject_mutation(reference_count=True),
    _subject_mutation(reference_count=-1),
    _subject_mutation(reference_count=257, included_count=257, excluded_count=0),
    _subject_mutation(included_count=1),
    _subject_mutation(weighted_development_raw=True),
    _subject_mutation(weighted_development_raw=1 << 31),
    _subject_mutation(weighted_development_raw=-(1 << 31) - 1),
    _subject_mutation(development_scale=True),
    _subject_mutation(development_scale=999),
    _subject_mutation(weight_raw=False),
    _subject_mutation(weight_raw=1 << 31),
    _subject_mutation(weight_scale=False),
    _subject_mutation(weight_scale=999),
])
def test_invalid_subject_scale_retracts_only_its_field(tmp_path, monkeypatch, subject):
    report = make_report(field_overrides={"subject_scale": {
        "status": "known", "value": subject, "raw_inputs": {"secret": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(), base.context())
    field = result["fields"]["subject_scale"]
    assert field["status"] == "unknown" and field["reason"] == "COUNTRY_SCALE_FIELD_INVALID"
    assert "value" not in field
    assert result["fields"]["development"]["status"] == "known"
    assert result["fields"]["major_power"]["status"] == "known"


@pytest.mark.parametrize("value", [True, False])
def test_major_power_requires_literal_bool_and_discloses_feature_scope(
        tmp_path, monkeypatch, value):
    report = make_report(field_overrides={"major_power": {
        "status": "known", "value": value, "raw_inputs": {"private": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(fields=["major_power"]), base.context())
    field = result["fields"]["major_power"]
    assert field["status"] == "known" and field["value"] is value
    assert "FEATURE_FLAG_IS_NOT_GREAT_POWER_RANK_MEMBERSHIP" in next(
        meta["gaps"] for topic in source.catalog() for meta in topic["fields"].values()
        if meta["basis"] == field["basis"]
    )


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_major_power_rejects_integer_and_non_boolean_values(tmp_path, monkeypatch, value):
    report = make_report(field_overrides={"major_power": {
        "status": "known", "value": value, "raw_inputs": {"private": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(fields=["major_power"]), base.context())
    field = result["fields"]["major_power"]
    assert field["status"] == "unknown" and field["reason"] == "COUNTRY_SCALE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("name", ALL_FIELDS)
@pytest.mark.parametrize("status", ["unknown", "invisible"])
def test_unknown_or_invisible_field_never_exports_backend_value(
        tmp_path, monkeypatch, name, status):
    report = make_report(field_overrides={name: {
        "status": status, "value": "private value must not escape",
        "reason": "NATIVE_SCALE_UNAVAILABLE",
        "raw_inputs": {"private_pointer": "0x123456789abcdef0"},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(fields=[name]), base.context())
    field = result["fields"][name]
    assert field["status"] == status
    assert "value" not in field and "raw_inputs" not in repr(field)
    assert "0x123456789abcdef0" not in repr(result)


@pytest.mark.parametrize(
    "gate_status,admitted,expected",
    [("known", False, "invisible"), ("unknown", None, "unknown"), ("known", 1, "unknown")],
)
def test_target_admission_gate_is_literal_and_never_exports_any_field_value(
        tmp_path, monkeypatch, gate_status, admitted, expected):
    report = make_report(admitted=admitted, gate_status=gate_status)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(), base.context())
    assert all(field["status"] == expected for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())
    assert "raw_inputs" not in repr(result) and "private_pointer" not in repr(result)


def test_unknown_reason_is_bounded_and_pointer_like_detail_is_replaced(tmp_path, monkeypatch):
    report = make_report(field_overrides={"major_power": {
        "status": "unknown", "reason": "GREAT_POWER_TLS_PREDICATE_UNRESOLVED:0x123456789abcdef0",
        "raw_inputs": {"private": True},
    }})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(fields=["major_power"]), base.context())
    field = result["fields"]["major_power"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_SCALE_BACKEND_UNKNOWN"
    assert "0x123456789abcdef0" not in repr(result)


@pytest.mark.parametrize("target,fields,parameters", [
    ("bad", ALL_FIELDS, {}),
    ("ENG", ["unknown_field"], {}),
    ("ENG", ["development", "development"], {}),
    ("ENG", [], {}),
    ("ENG", ALL_FIELDS + ["unknown_field"], {}),
    ("ENG", ALL_FIELDS, {"detail": "full"}),
])
def test_query_rejects_unimplemented_fields_and_unbounded_requests(
        tmp_path, monkeypatch, target, fields, parameters):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(make_query(target, fields=fields, parameters=parameters), base.context())
    assert captures == []


@pytest.mark.parametrize('observer', ['TUR', 'D01'])
def test_scale_fields_use_the_configured_observer_tag(tmp_path, monkeypatch, observer):
    source, base, _, captures, validations = make_source(
        tmp_path, monkeypatch, report=make_report(observer=observer))
    base.current['observer'] = observer
    result = source.read(make_query(fields=['development']), base.context())
    assert result['fields']['development']['status'] == 'known'
    assert captures == [(tmp_path / 'installation.json', 'ENG', observer)]
    assert validations[0][1]['observer'] == observer


def test_observer_mismatch_stale_context_and_session_changes_do_not_publish_values(
        tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
    wrong_observer = base.context()
    wrong_observer["observer"] = "POR"
    rejected = source.read(make_query(), wrong_observer)
    assert all(field['reason'] == 'COUNTRY_SCALE_CONTEXT_STALE' for field in rejected['fields'].values())
    assert captures == []

    stale = base.context()
    stale["game_date"] += 1
    stale_result = source.read(make_query(), stale)
    assert all(field["status"] == "unavailable" for field in stale_result["fields"].values())
    assert captures == []

    def change_context(base_source):
        base_source.current["game_date"] += 1

    source2, base2, _, captures2, _ = make_source(
        tmp_path, monkeypatch, after_capture=change_context
    )
    changed = source2.read(make_query(), base2.context())
    assert all(field["status"] == "unavailable" for field in changed["fields"].values())
    assert all("value" not in field for field in changed["fields"].values())
    assert len(captures2) == 1

    def change_session(base_source):
        base_source.session.creation_filetime += 1
        base_source.session.record["creation_filetime"] += 1

    source3, base3, _, _, _ = make_source(tmp_path, monkeypatch, after_capture=change_session)
    session_changed = source3.read(make_query(), base3.context())
    assert all(field["status"] == "unavailable" for field in session_changed["fields"].values())
    assert all("value" not in field for field in session_changed["fields"].values())


@pytest.mark.parametrize("validator_error,valid", [(False, False), (True, True), (False, 1)])
def test_capture_validation_must_return_literal_true_before_projection(
        tmp_path, monkeypatch, validator_error, valid):
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, valid=valid, validator_error=validator_error
    )
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "COUNTRY_SCALE_CAPTURE_INVALID" for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())


@pytest.mark.parametrize("bad_shape", ["observer", "schema", "target"])
def test_capture_exception_and_capture_shape_mismatch_fail_closed(
        tmp_path, monkeypatch, bad_shape):
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, capture_error=OSError("fixture"))
    failed = source.read(make_query(), base.context())
    assert all(field["status"] == "unknown" for field in failed["fields"].values())
    assert all(field["reason"] == "COUNTRY_SCALE_CAPTURE_FAILED:OSError"
               for field in failed["fields"].values())

    bad_report = make_report(observer="POR" if bad_shape == "observer" else "FRA")
    if bad_shape == "schema":
        bad_report["schema"] = "information.other.v1"
    if bad_shape == "target":
        bad_report["observation"]["backend"]["targets"][0]["tag"] = "FRA"
    source2, base2, _, _, _ = make_source(tmp_path, monkeypatch, report=bad_report)
    invalid = source2.read(make_query(), base2.context())
    assert all(field["status"] == "unknown" for field in invalid["fields"].values())
    assert all(field["reason"] == "COUNTRY_SCALE_CAPTURE_SHAPE_INVALID"
               for field in invalid["fields"].values())


def test_query_report_and_periodic_routes_share_the_same_partial_projection(tmp_path, monkeypatch):
    report = make_report("ENG")
    context = make_context()
    base = Base(tmp_path, context)
    captured = []

    def capture(_installation, *, country, observer):
        captured.append((country, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(scale_module, "import_module", lambda _name, _package: validator_module)
    adapter = NativeCountryScaleSource(base, capture=capture)
    service = InformationService(
        CompositeSource(base, [adapter]),
        tmp_path / "country-scale-information.sqlite3",
        clock=lambda: now[0],
    )
    now = [100]
    tools = InformationTools(service)
    query = make_query("ENG")
    try:
        topic = next(item for item in service.source.catalog() if item["topic_id"] == "F01")
        assert topic["fields"]["development"]["coverage"] == "partial"
        assert topic["fields"]["subject_scale"]["coverage"] == "partial"
        assert topic["fields"]["major_power"]["coverage"] == "partial"
        assert topic["fields"]["territory"]["coverage"] == "partial"
        assert topic["fields"]["wars"]["coverage"] == "partial"

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "country-scale-public-query", "queries": [query],
        })
        saved = tools.call("information_manage_report", {
            "request_id": "country-scale-public-report", "operation": "create",
            "config": {"name": "country scale partial", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "country-scale-public-report-query", "report_id": saved["id"],
        })
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["subject_scale"]["value"] == SUBJECT_VALUE
        assert direct["items"][0]["fields"]["territory"]["value"] == {"city_count": 123}
        assert direct["items"][0]["fields"]["wars"]["value"] == _wars_value("ENG")
        assert direct["complete"] is False

        tools.call("information_manage_subscription", {
            "request_id": "country-scale-public-subscription-create",
            "operation": "create",
            "config": {
                "name": "country scale periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": saved["id"],
                "schedule": {"basis": "real", "unit": "seconds", "every": 1,
                             "missed": "coalesce"},
            },
        })
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["items"][0]["fields"] == direct["items"][0]["fields"]
        assert periodic["status"] == "partial"
        assert captured == [("ENG", "FRA")] * 3
    finally:
        service.close()

