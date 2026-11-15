"""Public G02 projection and tool-contract tests for province state.

The capture validator used here is a stub. These tests cover the public DTO,
query/report/periodic routing, and fail-closed propagation; they do not prove
that a raw province RPM trace is safe. That belongs to the dedicated
province_state_capture validation tests.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.information.province_state import NativeProvinceStateSource
import bridge.information.province_state as province_state_module


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134376782534496994
PROVINCE_ID = 183
FIELDS = ("owner", "controller", "culture", "religion", "autonomy",
          "development", "resource", "center_of_trade")
DEFAULT_FIELDS = ("owner", "controller")
_REPORT_DEFAULT = object()


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "province-public-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56564448,
        "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


def private_field(value, *, status="known", reason="PRIVATE_FIELD_0x123456789abcdef0"):
    return {
        "status": status,
        "value": value,
        "reason": reason,
        "raw_inputs": {"country_pointer": "0x123456789abcdef0"},
    }


def make_report(*, province_id=PROVINCE_ID, observer="FRA", owner="FRA",
                controller="ENG", gate_status="known", admitted=True,
                gate_reason="PRIVATE_GATE_0x2233445566778899",
                discovery_status="known", discovery_value=True,
                discovery_reason=None, schema=None, culture=None,
                religion=None, autonomy=55_000, development=42_000,
                resource=_REPORT_DEFAULT, center_of_trade=_REPORT_DEFAULT):
    role_gate = {"status": gate_status, "admitted": admitted}
    if gate_reason is not None:
        role_gate["reason"] = gate_reason
    discovery = {"status": discovery_status, "value": discovery_value}
    if discovery_reason is not None:
        discovery["reason"] = discovery_reason
    return {
        "schema": schema or "information.province_state_capture.v1",
        "status": "observed",
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "observation": {
                "backend": {
                    "observer": {
                        "tag": observer,
                        "private_pointer": "0x3344556677889900",
                    },
                    "targets": [{
                        "province_id": province_id,
                        "admission_by_pass": {
                            "pass1": deepcopy(role_gate),
                            "pass2": deepcopy(role_gate),
                        },
                        "discovery_by_pass": {
                            "pass1": deepcopy(discovery),
                            "pass2": deepcopy(discovery),
                        },
                        "fields": {
                            "G02.owner": private_field(owner),
                            "G02.controller": private_field(controller),
                            "G02.culture": private_field(culture if culture is not None else {
                                "name": {"text": "French", "raw_hex": "4672656e6368",
                                         "encoding": "eu4_escape"},
                                "private_culture_id": "0x5566778899001122",
                            }),
                            "G02.religion": private_field(religion if religion is not None else {
                                "name": {"text": "Catholic", "raw_hex": "436174686f6c6963",
                                         "encoding": "eu4_escape"},
                                "icon_frame_request": 3,
                                "private_religion_id": "0x6677889900112233",
                            }),
                            "G02.autonomy": private_field(autonomy),
                            "G02.development": private_field(development),
                            "G02.resource": private_field({
                                "localization_key": "trade_goods.iron",
                                "icon_index": -3,
                                "name": {
                                    "status": "known",
                                    "raw_hex": "49726f6e",
                                    "language": "l_english",
                                },
                                "private_definition_pointer": "0x7788990011223344",
                                "private_resource_key": "secret_resource_key",
                            } if resource is _REPORT_DEFAULT else resource),
                            "G02.center_of_trade": private_field(
                                {
                                    "present": False,
                                    "level": 0,
                                    "private_source_flags": "0x9988776655443322",
                                } if center_of_trade is _REPORT_DEFAULT else center_of_trade),
                            "G02.unrequested": private_field("secret"),
                        },
                    }],
                },
            },
        },
        "raw_reads": [{"label": "private.province_trace", "address": "0x4455667788990011"}],
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


def make_query(province_id=PROVINCE_ID, fields=None, parameters=None):
    return {
        "topic": "G02",
        "object": {"type": "province", "province_id": province_id},
        "fields": list(fields if fields is not None else DEFAULT_FIELDS),
        "parameters": parameters if parameters is not None else {},
    }


def make_source(tmp_path, monkeypatch, *, report=None, valid=True,
                after_capture=None, capture_error=None, validator_error=None,
                context=None):
    base = Base(tmp_path, context or make_context())
    if after_capture is not None:
        base.on_capture = after_capture
    actual_report = deepcopy(report if report is not None else make_report())
    captures = []
    validations = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        if base.on_capture is not None:
            base.on_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(actual_report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        if validator_error is not None:
            raise validator_error
        return valid

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(
        province_state_module, "import_module", lambda _name, _package: validator_module)
    source = NativeProvinceStateSource(base, capture=capture)
    return source, base, actual_report, captures, validations


def assert_no_public_value(result):
    assert all("value" not in field for field in result["fields"].values())


def test_known_owner_and_controller_are_sanitized_for_logical_fra(tmp_path, monkeypatch):
    source, base, _, captures, validations = make_source(tmp_path, monkeypatch)

    result = source.read(make_query(), base.context())

    assert result["fields"]["owner"]["status"] == "known"
    assert result["fields"]["owner"]["value"] == "FRA"
    assert result["fields"]["controller"]["status"] == "known"
    assert result["fields"]["controller"]["value"] == "ENG"
    assert result["complete"] is False
    for field in result["fields"].values():
        assert field["period"] == "current"
        assert field["partial"] is True
        assert field["complete"] is False
        assert "unit" not in field
    assert result["source"]["context_scope"] == "visible_scope"
    assert result["source"]["projection_version"] == 4
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA"
    assert provenance["province_id"] == PROVINCE_ID
    assert provenance["native_function_invoked"] is False
    assert provenance["actual_UI_observed"] is False
    assert provenance["full_province_visibility_complete"] is False
    assert len(provenance["capture_report_sha256"]) == 64
    assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, PROVINCE_ID)
    public = repr(result)
    for private in ("raw_inputs", "raw_reads", "private_pointer", "private.province_trace",
                    "country_pointer", "unrequested", "0x123456789abcdef0",
                    "0x2233445566778899", "0x3344556677889900"):
        assert private not in public


def test_catalog_and_query_contract_keep_g02_partial_and_narrow(tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)

    topic = source.catalog()[0]

    assert topic["topic_id"] == "G02"
    assert topic["object_types"] == ["province"]
    assert topic["observer_scope"] == ["FRA"]
    assert topic["supported_versions"] == ["1.37.4"]
    assert topic["triggers"] == ["query", "periodic"]
    assert set(topic["fields"]) == set(FIELDS)
    assert all(topic["fields"][field]["coverage"] == "partial" for field in FIELDS)
    assert all(topic["fields"][field]["complete"] is False for field in FIELDS)
    assert {field: topic["fields"][field]["unit"] for field in FIELDS} == {
        "owner": "country_tag", "controller": "country_tag",
        "culture": "native_display_name",
        "religion": "native_display_name_and_icon_frame_request",
        "autonomy": "percent",
        "development": "development",
        "resource": "native_resource_definition",
        "center_of_trade": "native_center_of_trade",
    }
    assert {field: topic["fields"][field]["scale"] for field in FIELDS} == {
        "owner": 1, "controller": 1, "culture": 1, "religion": 1, "autonomy": 1000,
        "development": 1000, "resource": 1, "center_of_trade": 1,
    }
    assert "位为0返回unknown" in topic["scope_note"]
    assert "不按物理玩家切换视角" in topic["scope_note"]
    resource_gaps = topic["fields"]["resource"]["gaps"]
    assert "TRANSLATED_RESOURCE_NAME_NOT_CAPTURED" not in resource_gaps
    assert "NATIVE_FNV1_HASH_ONLY" in resource_gaps
    assert "LITERAL_KEY_COLLISION_NOT_EXCLUDED" in resource_gaps
    assert "FULL_UI_RESOURCE_VISIBILITY_UNVERIFIED" in resource_gaps

    validated = source.validate_query(
        make_query(fields=["controller", "owner"]), base.context())
    assert validated == {
        "topic": "G02",
        "object": {"type": "province", "province_id": PROVINCE_ID},
        "fields": ["controller", "owner"],
        "parameters": {},
    }
    assert captures == []


@pytest.mark.parametrize("query", [
    {"topic": "G01", "object": {"type": "province", "province_id": 183}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "country", "country": "FRA"}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": True}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 0}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 65536}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 183, "pointer": 7}, "fields": ["owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 183}, "fields": []},
    {"topic": "G02", "object": {"type": "province", "province_id": 183}, "fields": ["owner", "owner"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 183}, "fields": ["not_a_field"]},
    {"topic": "G02", "object": {"type": "province", "province_id": 183},
     "fields": ["owner"], "parameters": {"detail": "full"}},
    {"topic": "G02", "object": {"type": "province", "province_id": 183},
     "fields": ["owner"], "unexpected": 1},
])
def test_invalid_query_contract_never_dispatches_capture(tmp_path, monkeypatch, query):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)

    with pytest.raises(InformationError):
        source.read(query, base.context())

    assert captures == []


def test_observer_mismatch_and_unsupported_context_version_fail_closed(tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)

    wrong_observer = make_context(observer="ENG")
    with pytest.raises(InformationError):
        source.read(make_query(), wrong_observer)
    assert captures == []

    base.current["game_version"] = "1.37.5"
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert_no_public_value(result)
    assert captures == []


def test_stale_caller_context_and_unavailable_source_context_have_no_values(
        tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)

    stale = base.context()
    stale["game_date"] -= 1
    result = source.read(make_query(), stale)
    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CONTEXT_STALE"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert captures == []

    base.current["status"] = "stopped"
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert_no_public_value(result)
    assert captures == []


@pytest.mark.parametrize(("gate_status", "admitted"), [
    ("unknown", None),
    ("known", False),
    ("known", 1),
    ("unavailable", True),
])
def test_role_gate_unknown_false_and_integer_one_never_publish_owner_or_controller(
        tmp_path, monkeypatch, gate_status, admitted):
    report = make_report(
        gate_status=gate_status, admitted=admitted,
        gate_reason="PRIVATE_GATE_0x2233445566778899")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_DISCOVERY_NOT_ESTABLISHED"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert "invisible" not in repr(result)
    assert "0x2233445566778899" not in repr(result)


@pytest.mark.parametrize(("discovery_status", "discovery_value"), [
    ("unknown", None),
    ("known", False),
    ("known", 1),
    ("unavailable", True),
])
def test_fra_role_admission_does_not_substitute_for_discovery(
        tmp_path, monkeypatch, discovery_status, discovery_value):
    report = make_report(
        gate_status="known", admitted=True,
        discovery_status=discovery_status, discovery_value=discovery_value,
        discovery_reason="PRIVATE_DISCOVERY_0x5566778899001122")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert_no_public_value(result)
    assert "0x5566778899001122" not in repr(result)
    assert "invisible" not in repr(result)


def test_discovery_requires_both_passes_and_literal_true(tmp_path, monkeypatch):
    report = make_report()
    target = report["capture"]["observation"]["backend"]["targets"][0]
    target["discovery_by_pass"]["pass1"] = {"status": "known", "value": True}
    target["discovery_by_pass"]["pass2"] = {"status": "known", "value": False}
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert_no_public_value(result)


def test_missing_discovery_pass_fails_closed_even_when_role_gate_is_true(
        tmp_path, monkeypatch):
    report = make_report(gate_status="known", admitted=True)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    del target["discovery_by_pass"]["pass2"]
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert_no_public_value(result)


@pytest.mark.parametrize("bad_tag", [
    "fra", "FRAA", "F-1", "0x1", "éRA", 1, True, None,
])
def test_invalid_known_tags_become_unknown_without_private_payload(
        tmp_path, monkeypatch, bad_tag):
    report = make_report(owner=bad_tag)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["owner"]), base.context())["fields"]["owner"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field
    assert "raw_inputs" not in repr(field)
    assert "0x123456789abcdef0" not in repr(field)


def test_culture_religion_and_autonomy_project_strict_public_dtos(tmp_path, monkeypatch):
    report = make_report()
    private_fields = report["capture"]["observation"]["backend"]["targets"][0]["fields"]
    private_fields["G02.culture"]["value"]["name"]["raw_hex"] = "4672656E6368"
    private_fields["G02.culture"]["value"]["private_culture_id"] = "0x9988776655443322"
    private_fields["G02.religion"]["value"]["name"]["raw_hex"] = "436174686F6C6963"
    private_fields["G02.religion"]["value"]["private_religion_id"] = "0x8877665544332211"
    private_fields["G02.religion"]["raw_inputs"]["private_pointer"] = "0x7766554433221100"
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(fields=["culture", "religion", "autonomy"]), base.context())

    assert result["fields"]["culture"]["status"] == "known"
    assert result["fields"]["culture"]["value"] == {
        "name": {"text": "French", "raw_hex": "4672656e6368", "encoding": "eu4_escape"}}
    assert result["fields"]["religion"]["status"] == "known"
    assert result["fields"]["religion"]["value"] == {
        "name": {"text": "Catholic", "raw_hex": "436174686f6c6963", "encoding": "eu4_escape"},
        "icon_frame_request": 3,
    }
    assert result["fields"]["autonomy"]["status"] == "known"
    assert result["fields"]["autonomy"]["value"] == 55_000
    public = repr(result)
    for private in ("raw_inputs", "private_culture_id", "private_religion_id",
                    "0x9988776655443322", "0x8877665544332211", "0x7766554433221100"):
        assert private not in public


@pytest.mark.parametrize(("text", "raw_hex", "encoding"), [
    ("Faux", "4672656e6368", "eu4_escape"),
    ("French", "4g", "eu4_escape"),
    ("French", "4672656e6368", "utf8"),
    ("French", "467200656e6368", "eu4_escape"),
    ("", "4672656e6368", "eu4_escape"),
])
def test_culture_and_religion_require_matching_eu4_escape_name_payloads(
        tmp_path, monkeypatch, text, raw_hex, encoding):
    report = make_report()
    fields = report["capture"]["observation"]["backend"]["targets"][0]["fields"]
    fields["G02.culture"]["value"]["name"] = {
        "text": text, "raw_hex": raw_hex, "encoding": encoding,
        "private_name_key": "0x1122334455667788",
    }
    fields["G02.religion"]["value"]["name"] = {
        "text": text, "raw_hex": raw_hex, "encoding": encoding,
    }
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(fields=["culture", "religion"]), base.context())

    for name in ("culture", "religion"):
        assert result["fields"][name]["status"] == "unknown"
        assert result["fields"][name]["reason"] == "PROVINCE_STATE_FIELD_INVALID"
        assert "value" not in result["fields"][name]
    assert "0x1122334455667788" not in repr(result)


@pytest.mark.parametrize("frame", [True, False, -(1 << 31) - 1, 1 << 31, "3"])
def test_religion_icon_frame_requires_signed_i32_not_bool_or_out_of_range(
        tmp_path, monkeypatch, frame):
    report = make_report()
    report["capture"]["observation"]["backend"]["targets"][0][
        "fields"]["G02.religion"]["value"]["icon_frame_request"] = frame
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["religion"]), base.context())["fields"]["religion"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("frame", [-(1 << 31), (1 << 31) - 1])
def test_religion_icon_signed_i32_boundaries_are_preserved(
        tmp_path, monkeypatch, frame):
    report = make_report()
    report["capture"]["observation"]["backend"]["targets"][0][
        "fields"]["G02.religion"]["value"]["icon_frame_request"] = frame
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["religion"]), base.context())["fields"]["religion"]

    assert field["status"] == "known"
    assert field["value"]["icon_frame_request"] == frame


@pytest.mark.parametrize("autonomy", [True, -1, 1 << 31, 1.0])
def test_autonomy_requires_nonnegative_signed_i32(tmp_path, monkeypatch, autonomy):
    report = make_report(autonomy=autonomy)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["autonomy"]), base.context())["fields"]["autonomy"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("autonomy", [0, (1 << 31) - 1])
def test_autonomy_nonnegative_i32_boundaries_are_preserved(
        tmp_path, monkeypatch, autonomy):
    report = make_report(autonomy=autonomy)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["autonomy"]), base.context())["fields"]["autonomy"]

    assert field["status"] == "known"
    assert field["value"] == autonomy


@pytest.mark.parametrize("development", [True, -(1 << 31) - 1, 1 << 31, 1.0, "42000"])
def test_development_requires_signed_i32_not_bool(tmp_path, monkeypatch, development):
    report = make_report(development=development)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["development"]), base.context())[
        "fields"]["development"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("development", [-(1 << 31), (1 << 31) - 1])
def test_development_signed_i32_boundaries_are_preserved(tmp_path, monkeypatch, development):
    report = make_report(development=development)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["development"]), base.context())[
        "fields"]["development"]

    assert field["status"] == "known"
    assert field["value"] == development
    assert type(field["value"]) is int


def test_resource_projection_keeps_key_icon_and_decoded_cached_literal_name(
        tmp_path, monkeypatch):
    report = make_report()
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"] == {
        "localization_key": "trade_goods.iron",
        "icon_index": -3,
        "name": {
            "status": "known",
            "text": "Iron",
            "raw_hex": "49726f6e",
            "encoding": "eu4_escape",
            "language": "l_english",
            "lookup_semantics": "native_FNV1_hash_only",
            "literal_key_collision_excluded": False,
        },
    }
    assert "unit" not in field
    assert "private_definition_pointer" not in repr(field)
    assert "secret_resource_key" not in repr(field)


@pytest.mark.parametrize(("key", "text", "raw_hex"), [
    ("paper", "Paper", "5061706572"),
    ("grain", "Grain", "477261696e"),
    ("cloth", "Cloth", "436c6f7468"),
])
def test_actual_resource_keys_project_literal_fixture_without_translation_assumptions(
        tmp_path, monkeypatch, key, text, raw_hex):
    # Keys come from actual province captures. Names are synthetic ASCII payload
    # fixtures and make no claim about the game's localized translation.
    report = make_report(resource={
        "localization_key": key,
        "icon_index": 4,
        "name": {"status": "known", "raw_hex": raw_hex, "language": "l_english"},
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"]["localization_key"] == key
    assert field["value"]["icon_index"] == 4
    assert field["value"]["name"] == {
        "status": "known",
        "text": text,
        "raw_hex": raw_hex,
        "encoding": "eu4_escape",
        "language": "l_english",
        "lookup_semantics": "native_FNV1_hash_only",
        "literal_key_collision_excluded": False,
    }


def test_legacy_resource_capture_without_name_remains_known_with_name_unknown(
        tmp_path, monkeypatch):
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch,
        report=make_report(resource={"localization_key": "paper", "icon_index": 28}))

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"] == {
        "localization_key": "paper",
        "icon_index": 28,
        "name": {"status": "unknown", "reason": "RESOURCE_NAME_NOT_CAPTURED"},
    }


@pytest.mark.parametrize(("raw_text", "raw_hex"), [
    ("$NAME$", "244e414d4524"),
    ("[From.GetName]", "5b46726f6d2e4765744e616d655d"),
    ("Iron [plural]", "49726f6e205b706c7572616c5d"),
])
def test_dynamic_resource_templates_retract_only_nested_name(
        tmp_path, monkeypatch, raw_text, raw_hex):
    report = make_report(resource={
        "localization_key": "paper", "icon_index": 28,
        "name": {"status": "known", "raw_hex": raw_hex, "language": "l_english"},
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"]["localization_key"] == "paper"
    assert field["value"]["icon_index"] == 28
    assert field["value"]["name"] == {
        "status": "unknown", "reason": "DYNAMIC_LOCALIZATION_UNRESOLVED",
    }
    assert raw_text not in repr(field)
    assert raw_hex not in repr(field)


@pytest.mark.parametrize("name", [
    None,
    "not-a-map",
    {"status": "observed", "raw_hex": "49726f6e", "language": "l_english"},
    {"status": "known", "raw_hex": "zz", "language": "l_english"},
    {"status": "known", "raw_hex": "49726f6e", "language": "english"},
    {"status": "known", "raw_hex": "49726f6e00", "language": "l_english"},
    {"status": "known", "raw_hex": "41" * 8193, "language": "l_english"},
])
def test_malformed_resource_name_is_isolated_from_valid_base(
        tmp_path, monkeypatch, name):
    report = make_report(resource={
        "localization_key": "grain", "icon_index": 1, "name": name,
        "private_name_pointer": "0x7788990011223344",
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"]["localization_key"] == "grain"
    assert field["value"]["icon_index"] == 1
    assert field["value"]["name"] == {
        "status": "unknown", "reason": "RESOURCE_NAME_INVALID",
    }
    assert "private_name_pointer" not in repr(field)
    assert "7788990011223344" not in repr(field)


def test_helper_unknown_resource_name_keeps_only_safe_reason(
        tmp_path, monkeypatch):
    report = make_report(resource={
        "localization_key": "cloth", "icon_index": 4,
        "name": {"status": "unknown", "reason": "LOCALIZATION_NAME_NOT_CACHED",
                 "raw_hex": "SECRET"},
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"]["name"] == {
        "status": "unknown", "reason": "LOCALIZATION_NAME_NOT_CACHED",
    }
    assert "SECRET" not in repr(field)


def test_resource_name_unknown_reason_is_sanitized(
        tmp_path, monkeypatch):
    report = make_report(resource={
        "localization_key": "cloth", "icon_index": 4,
        "name": {"status": "unknown", "reason": "PRIVATE_0x123456789abcdef0"},
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())[
        "fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"]["name"] == {
        "status": "unknown", "reason": "RESOURCE_NAME_INVALID",
    }
    assert "0x123456789abcdef0" not in repr(field)


@pytest.mark.parametrize("resource", [
    {"localization_key": "", "icon_index": 1},
    {"localization_key": "bad key", "icon_index": 1},
    {"localization_key": "x" * 129, "icon_index": 1},
    {"localization_key": "é", "icon_index": 1},
    {"localization_key": 7, "icon_index": 1},
    {"localization_key": "trade_goods.iron", "icon_index": True},
    {"localization_key": "trade_goods.iron", "icon_index": -(1 << 31) - 1},
    {"localization_key": "trade_goods.iron", "icon_index": 1 << 31},
    {"localization_key": "trade_goods.iron", "icon_index": "3"},
    None,
    "not-a-map",
])
def test_invalid_resource_projection_fails_closed_per_field(tmp_path, monkeypatch, resource):
    report = make_report(resource=resource)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())["fields"]["resource"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("icon_index", [-(1 << 31), (1 << 31) - 1])
def test_resource_icon_index_signed_i32_boundaries_are_preserved(
        tmp_path, monkeypatch, icon_index):
    report = make_report(resource={"localization_key": "iron:ore-1", "icon_index": icon_index})
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["resource"]), base.context())["fields"]["resource"]

    assert field["status"] == "known"
    assert field["value"] == {
        "localization_key": "iron:ore-1", "icon_index": icon_index,
        "name": {"status": "unknown", "reason": "RESOURCE_NAME_NOT_CAPTURED"},
    }


def test_center_of_trade_absent_and_present_values_are_whitelisted(tmp_path, monkeypatch):
    absent_source, absent_base, _, _, _ = make_source(tmp_path, monkeypatch)
    absent = absent_source.read(make_query(fields=["center_of_trade"]), absent_base.context())[
        "fields"]["center_of_trade"]
    assert absent["status"] == "known"
    assert absent["value"] == {"present": False, "level": 0}

    present_source, present_base, _, _, _ = make_source(
        tmp_path, monkeypatch,
        report=make_report(center_of_trade={
            "present": True, "level": 3, "kind": "coastal",
            "sprite_key": "GFX_center_of_trade_coastal_3",
            "private_source_flags": "0x9988776655443322",
        }))
    present = present_source.read(
        make_query(fields=["center_of_trade"]), present_base.context())[
        "fields"]["center_of_trade"]
    assert present["status"] == "known"
    assert present["value"] == {
        "present": True, "level": 3, "kind": "coastal",
        "sprite_key": "GFX_center_of_trade_coastal_3",
    }
    assert "private_source_flags" not in repr(present)


@pytest.mark.parametrize(("kind", "level"), [("coastal", 1), ("inland", 4)])
def test_center_of_trade_computes_exact_sprite_key_for_known_kind_and_level(
        tmp_path, monkeypatch, kind, level):
    expected = f"GFX_center_of_trade_{kind}_{level}"
    report = make_report(center_of_trade={
        "present": True, "level": level, "kind": kind, "sprite_key": expected,
    })
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["center_of_trade"]), base.context())[
        "fields"]["center_of_trade"]

    assert field["status"] == "known"
    assert field["value"] == {
        "present": True, "level": level, "kind": kind, "sprite_key": expected,
    }


@pytest.mark.parametrize("center_of_trade", [
    {"present": 1, "level": 0},
    {"present": False, "level": True},
    {"present": False, "level": 1},
    {"present": True, "level": 0, "kind": "coastal",
     "sprite_key": "GFX_center_of_trade_coastal_0"},
    {"present": True, "level": 2, "kind": "ocean",
     "sprite_key": "GFX_center_of_trade_ocean_2"},
    {"present": True, "level": 2, "kind": "inland",
     "sprite_key": "wrong"},
    None,
    "not-a-map",
])
def test_invalid_center_of_trade_projection_fails_closed_per_field(
        tmp_path, monkeypatch, center_of_trade):
    report = make_report(center_of_trade=center_of_trade)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["center_of_trade"]), base.context())[
        "fields"]["center_of_trade"]

    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_STATE_FIELD_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("name", ["culture", "religion", "autonomy", "development",
                                   "resource", "center_of_trade"])
def test_unknown_new_fields_never_export_values_or_private_reasons(
        tmp_path, monkeypatch, name):
    report = make_report()
    report["capture"]["observation"]["backend"]["targets"][0]["fields"][
        f"G02.{name}"] = private_field({"secret": "hidden"}, status="unknown")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=[name]), base.context())["fields"][name]

    assert field["status"] == "unknown"
    assert "value" not in field
    assert "0x123456789abcdef0" not in repr(field)
    assert "hidden" not in repr(field)


def test_discovery_bit_zero_keeps_all_eight_fields_unknown(tmp_path, monkeypatch):
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report(discovery_value=False))

    result = source.read(make_query(fields=FIELDS), base.context())

    assert set(result["fields"]) == set(FIELDS)
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())
    assert "French" not in repr(result) and "Catholic" not in repr(result)
    assert "trade_goods.iron" not in repr(result)


def test_bad_one_new_field_does_not_retract_independent_known_fields(tmp_path, monkeypatch):
    report = make_report()
    report["capture"]["observation"]["backend"]["targets"][0][
        "fields"]["G02.religion"]["value"]["icon_frame_request"] = True
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(fields=FIELDS), base.context())

    assert result["fields"]["owner"]["status"] == "known"
    assert result["fields"]["controller"]["status"] == "known"
    assert result["fields"]["culture"]["status"] == "known"
    assert result["fields"]["autonomy"]["status"] == "known"
    assert result["fields"]["development"]["status"] == "known"
    assert result["fields"]["resource"]["status"] == "known"
    assert result["fields"]["center_of_trade"]["status"] == "known"
    assert result["fields"]["religion"]["status"] == "unknown"
    assert "value" not in result["fields"]["religion"]


@pytest.mark.parametrize(("name", "bad_value"), [
    ("development", True),
    ("resource", {"localization_key": "bad key", "icon_index": 0}),
    ("center_of_trade", {"present": True, "level": 1, "kind": "coastal",
                          "sprite_key": "wrong"}),
])
def test_each_new_field_validation_failure_isolated_to_that_field(
        tmp_path, monkeypatch, name, bad_value):
    report = make_report()
    private_fields = report["capture"]["observation"]["backend"]["targets"][0]["fields"]
    private_fields[f"G02.{name}"]["value"] = bad_value
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(fields=FIELDS), base.context())

    assert set(result["fields"]) == set(FIELDS)
    assert result["fields"][name]["status"] == "unknown"
    assert "value" not in result["fields"][name]
    assert all(result["fields"][other]["status"] == "known"
               for other in FIELDS if other != name)


@pytest.mark.parametrize("private_field_value", [
    {"status": "unknown", "reason": "NATIVE_0x123456789abcdef0", "value": "FRA",
     "raw_inputs": {"ptr": "0x123456789abcdef0"}},
    {"status": "unavailable", "value": "ENG", "raw_inputs": {"ptr": "0x123456789abcdef0"}},
    {"status": "invisible", "value": "ENG", "raw_inputs": {"ptr": "0x123456789abcdef0"}},
    None,
])
def test_unknown_unavailable_and_missing_private_fields_export_no_value(
        tmp_path, monkeypatch, private_field_value):
    report = make_report()
    if private_field_value is None:
        del report["capture"]["observation"]["backend"]["targets"][0]["fields"]["G02.owner"]
    else:
        report["capture"]["observation"]["backend"]["targets"][0]["fields"]["G02.owner"] = (
            private_field_value)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    field = source.read(make_query(fields=["owner"]), base.context())["fields"]["owner"]

    assert field["status"] == "unknown"
    assert "value" not in field
    assert "0x123456789abcdef0" not in repr(field)
    assert "FRA" not in field.get("value", "")


def test_unrequested_private_fields_are_not_projected(tmp_path, monkeypatch):
    report = make_report(controller="MYS")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(fields=["owner"]), base.context())

    assert set(result["fields"]) == {"owner"}
    assert result["fields"]["owner"]["value"] == "FRA"
    public = repr(result)
    for private in ("MYS", "secret", "raw_reads", "private.province_trace",
                    "0x4455667788990011"):
        assert private not in public


@pytest.mark.parametrize("mutate", [
    lambda report: report["object"].update(province_id=184),
    lambda report: report["capture"]["observation"]["backend"]["observer"].update(tag="ENG"),
    lambda report: report["capture"]["observation"]["backend"]["targets"].append(
        deepcopy(report["capture"]["observation"]["backend"]["targets"][0])),
    lambda report: report["capture"]["observation"]["backend"]["targets"][0].update(
        province_id=184),
    lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "admission_by_pass"].pop("pass2"),
    lambda report: report["capture"]["observation"]["backend"]["targets"][0].update(
        fields="not-a-map"),
])
def test_capture_shape_and_identity_mismatches_fail_closed(tmp_path, monkeypatch, mutate):
    report = make_report()
    mutate(report)
    source, base, _, _, validations = make_source(tmp_path, monkeypatch, report=report)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CAPTURE_SHAPE_INVALID"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert len(validations) == 1
    for private in ("0x123456789abcdef0", "0x3344556677889900", "raw_reads"):
        assert private not in repr(result)


def test_capture_schema_version_is_rejected_when_validator_does_not_accept_it(
        tmp_path, monkeypatch):
    report = make_report(schema="information.province_state_capture.v0")
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report, valid=False)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CAPTURE_INVALID"
               for field in result["fields"].values())
    assert_no_public_value(result)


@pytest.mark.parametrize("validator_result", [False, 1, None])
def test_validator_must_return_literal_true_before_projection(
        tmp_path, monkeypatch, validator_result):
    source, base, _, _, validations = make_source(
        tmp_path, monkeypatch, valid=validator_result)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CAPTURE_INVALID"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert len(validations) == 1


def test_validator_exception_capture_exception_and_capture_time_mutations_fail_closed(
        tmp_path, monkeypatch):
    source, base, _, _, validations = make_source(
        tmp_path, monkeypatch, validator_error=RuntimeError("validator failed"))
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CAPTURE_INVALID"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert len(validations) == 1

    source, base, _, _, validations = make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError("capture failed"))
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CAPTURE_FAILED:RuntimeError"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert validations == []

    def change_context(base_source):
        base_source.current["game_date"] += 24

    source, base, _, _, validations = make_source(
        tmp_path, monkeypatch, after_capture=change_context)
    result = source.read(make_query(), base.context())
    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_CONTEXT_CHANGED_DURING_CAPTURE"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert validations == []


def test_session_binding_change_during_capture_invalidates_values(tmp_path, monkeypatch):
    def change_session(base_source):
        base_source.session.creation_filetime += 1
        base_source.session.record["creation_filetime"] += 1

    source, base, _, captures, validations = make_source(
        tmp_path, monkeypatch, after_capture=change_session)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_STATE_SESSION_CHANGED_DURING_CAPTURE"
               for field in result["fields"].values())
    assert_no_public_value(result)
    assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    assert validations == []


def test_query_report_and_periodic_tools_share_the_same_partial_projection(
        tmp_path, monkeypatch):
    report = make_report(center_of_trade={
        "present": True, "level": 2, "kind": "inland",
        "sprite_key": "GFX_center_of_trade_inland_2",
        "private_source_flags": "0x3344556677889900",
    })
    context = make_context()
    base = Base(tmp_path, context)
    captures = []

    def capture(_installation, *, province_id, observer):
        captures.append((province_id, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(
        province_state_module, "import_module", lambda _name, _package: validator_module)
    province = NativeProvinceStateSource(base, capture=capture)
    now = [100]
    service = InformationService(
        CompositeSource(base, [province]),
        tmp_path / "province-information.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    query = make_query(fields=FIELDS)
    try:
        topic = next(item for item in service.source.catalog() if item["topic_id"] == "G02")
        planned_topic = next(item for item in list_topics() if item["topic_id"] == "G02")
        assert set(topic["fields"]) == set(planned_topic["fields"])
        assert len(topic["fields"]) == len(FIELDS) == 8
        assert all(topic["fields"][field]["coverage"] == "partial" for field in FIELDS)
        assert all(topic["fields"][field]["complete"] is False for field in FIELDS)
        planned_fields = set(topic["fields"]) - set(FIELDS)
        assert planned_fields == set()

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "province-public-query", "queries": [query],
        })
        saved = tools.call("information_manage_report", {
            "request_id": "province-public-report", "operation": "create",
            "config": {"name": "province partial", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "province-public-report-query", "report_id": saved["id"],
        })
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["owner"]["value"] == "FRA"
        assert direct["items"][0]["fields"]["controller"]["value"] == "ENG"
        assert direct["items"][0]["fields"]["culture"]["value"]["name"]["text"] == "French"
        assert direct["items"][0]["fields"]["religion"]["value"]["name"]["text"] == "Catholic"
        assert direct["items"][0]["fields"]["religion"]["value"]["icon_frame_request"] == 3
        assert direct["items"][0]["fields"]["autonomy"]["value"] == 55_000
        assert direct["items"][0]["fields"]["development"]["value"] == 42_000
        assert direct["items"][0]["fields"]["resource"]["value"] == {
            "localization_key": "trade_goods.iron", "icon_index": -3,
            "name": {
                "status": "known", "text": "Iron", "raw_hex": "49726f6e",
                "encoding": "eu4_escape", "language": "l_english",
                "lookup_semantics": "native_FNV1_hash_only",
                "literal_key_collision_excluded": False,
            },
        }
        assert direct["items"][0]["fields"]["center_of_trade"]["value"] == {
            "present": True, "level": 2, "kind": "inland",
            "sprite_key": "GFX_center_of_trade_inland_2",
        }
        assert set(direct["items"][0]["fields"]) == set(FIELDS)
        for private in ("private_definition_pointer", "secret_resource_key",
                        "private_source_flags", "0x3344556677889900"):
            assert private not in repr(direct["items"][0]["fields"])
        assert direct["complete"] is False

        tools.call("information_manage_subscription", {
            "request_id": "province-public-subscription-create",
            "operation": "create",
            "config": {
                "name": "province periodic",
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
        assert set(periodic["items"][0]["fields"]) == set(FIELDS)
        assert periodic["status"] == "partial"
        assert captures == [(PROVINCE_ID, "FRA")] * 3
    finally:
        service.close()
