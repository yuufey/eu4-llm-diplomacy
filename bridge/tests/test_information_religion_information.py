"""Public tests for the combined native S02 religion-information source."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.country_faith import NativeCountryFaithSource
from bridge.information.religion_group import NativeReligionGroupSource
from bridge.information.religion_information import NativeReligionInformationSource
from bridge.information.tools import InformationTools
from bridge.tests import test_information_country_faith as faith_fixture
from bridge.tests import test_information_religion_group_source as group_fixture
import bridge.information.country_faith as faith_module
import bridge.information.religion_group as group_module
import bridge.information.religion_information as religion_information_module


IDENTITY_PROFILE_SHA256 = "c" * 64
GROUP_PROFILE_SHA256 = "d" * 64
PRE_BINDING_JOIN_SOURCE_SHA256 = "6f311e04f8880ccac08cba0d48b911e25b50d9b92b83b8cac985cd21976be829"
RELIGION_BINDING_SHA256 = "a" * 64
RELIGION_GROUP_BINDING_SHA256 = "b" * 64
KNOWN_BINDINGS = {
    "religion_binding_sha256": RELIGION_BINDING_SHA256,
    "religion_group_binding_sha256": RELIGION_GROUP_BINDING_SHA256,
}
KNOWN_IDENTITY = {"religion_key": "catholic", "religion_group_key": "christian"}
IDENTITY_BASIS = "bounded_native_religion_and_group_configuration_keys"
SOURCE_PINS = {
    "configuration_sha256": "1" * 64,
    "definitions_sha256": "2" * 64,
    "parser_manifest_sha256": "3" * 64,
    "cwt_sha256": "4" * 64,
    "cwt_commit": "a" * 40,
}


def _identity_report(target="ENG", *, admitted=True, gate_status="known",
                     field_status="known", value=None):
    field = {
        "status": field_status,
        "complete": False,
        "basis": IDENTITY_BASIS,
        "raw_inputs": {"private_pointer": "0x123456789abcdef0"},
    }
    if field_status == "known":
        field["value"] = deepcopy(value if value is not None else KNOWN_IDENTITY)
    return {
        "schema": "information.religion_identity_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {"backend": {
            "observer": {"tag": "FRA", "private_pointer": "0x2233445566778899"},
            "targets": [{
                "tag": target,
                "fullref": "0x123456789abcdef0",
                "admission_by_pass": {
                    "pass1": {"status": gate_status, "admitted": admitted},
                    "pass2": {"status": gate_status, "admitted": admitted},
                },
                "fields": {"S02.religion_identity": field},
            }],
        }},
        "raw_reads": [{"label": "private.trace", "address": "0x123456789abcdef0"}],
    }


def _legacy_sample(child, query, context, name, *, value=None, bindings=None):
    if value is None and name == "faith":
        value = {
            "primary_religion_name": {
                "text": "Catholic", "raw_hex": "436174686f6c6963", "encoding": "eu4_escape",
            },
            "icon_frame_request": 4,
        }
    elif value is None:
        value = {"religion_group_name": {
            "text": "christian", "raw_hex": "63687269737469616e", "encoding": "eu4_escape",
        }}
    return {
        "topic": "S02",
        "objects": [deepcopy(query["object"])],
        "game_date": context["game_date"],
        "fields": {name: {"status": "known", "complete": False, "partial": True,
                          "value": deepcopy(value)}},
        "complete": False,
        "source": {
            "name": type(child).__name__,
            "mode": context["mode"],
            "status": "observed",
            "observer": "FRA",
            "session_id": context["session_id"],
            "complete": False,
            "provenance": {
                "capture_report_sha256": "e" * 64,
                "read_only": True,
                "native_function_invoked": False,
                **deepcopy(bindings if bindings is not None else KNOWN_BINDINGS),
            },
        },
    }


def _rule_node(key, *, line=1):
    return {"key": key, "assignment": "=", "kind": "block", "value": None,
            "children": [], "line": line, "end_line": line}


def _rule_record(key, *, group=False, group_key="christian", invalid_ast=False):
    definition = {
        "relative_file": "common/religions/00_religions.txt",
        "line": 2,
        "file_sha256": "5" * 64,
        "source_kind": "basegame",
    }
    record = {
        "status": "known",
        "definition": definition,
        "source": deepcopy(SOURCE_PINS),
        "source_pins": deepcopy(SOURCE_PINS),
        "syntax": {"not": "an AST"} if invalid_ast else _rule_node(key, line=2),
        "conditions_evaluated": False,
        "effects_executed": False,
        "runtime_state_observed": False,
    }
    if group:
        record["religion_group_key"] = key
    else:
        record["religion_key"] = key
        record["religion_group_key"] = group_key
    return record


class DefinitionIndex:
    def __init__(self, *, group_mismatch=False, invalid_group_ast=False):
        religion_group = "not_christian" if group_mismatch else "christian"
        self.religion_record = _rule_record("catholic", group_key=religion_group)
        self.group_record = _rule_record("christian", group=True,
                                         invalid_ast=invalid_group_ast)
        self.assert_calls = 0
        self.context_calls = 0
        self.definition_calls = []
        self.group_calls = []
        self.fail_assert = False

    def assert_current(self):
        self.assert_calls += 1
        if self.fail_assert:
            raise ValueError("definition pins changed")

    def context(self):
        self.context_calls += 1
        return {"status": "ready", "complete": False,
                "configuration_sha256": SOURCE_PINS["configuration_sha256"],
                "definitions_sha256": SOURCE_PINS["definitions_sha256"]}

    def definition(self, key):
        self.definition_calls.append(key)
        return deepcopy(self.religion_record)

    def group_definition(self, key):
        self.group_calls.append(key)
        return deepcopy(self.group_record)


def _make_source(tmp_path, monkeypatch, *, target="ENG", identity_report=None,
                 identity_valid=True, identity_validator_raises=False,
                 identity_error=None, after_identity=None, faith_report=None,
                 group_report=None, definitions=None, identity_bindings=None):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    report = deepcopy(identity_report if identity_report is not None
                      else _identity_report(target))
    identity_calls = []
    identity_validations = []

    def capture_identity(installation, *, country, observer):
        identity_calls.append((installation, country, observer))
        if after_identity is not None:
            after_identity(base)
        if identity_error is not None:
            raise identity_error
        return deepcopy(report)

    def validate_identity(actual_report, actual_context, creation, actual_target):
        identity_validations.append((deepcopy(actual_report), deepcopy(actual_context),
                                     creation, actual_target))
        if identity_validator_raises:
            raise ValueError("identity profile pin mismatch")
        return identity_valid

    identity_module = SimpleNamespace(validate_capture=validate_identity,
                                      PROFILE_SHA256=IDENTITY_PROFILE_SHA256)
    identity_binding_values = deepcopy(identity_bindings if identity_bindings is not None
                                        else KNOWN_BINDINGS)

    def binding_digests(_field, _country, *, require_group=False):
        result = {"religion_binding_sha256": identity_binding_values[
            "religion_binding_sha256"]}
        if require_group:
            result["religion_group_binding_sha256"] = identity_binding_values[
                "religion_group_binding_sha256"]
        return result

    monkeypatch.setattr(religion_information_module, "binding_digests", binding_digests)
    monkeypatch.setattr(faith_module, "binding_digests", binding_digests)
    monkeypatch.setattr(group_module, "binding_digests", binding_digests)
    monkeypatch.setattr(religion_information_module, "import_module",
                        lambda *_args: identity_module)

    faith_calls = []
    faith_capture_report = deepcopy(faith_report if faith_report is not None
                                    else faith_fixture.make_report(
                                        target, name_text="天主教", icon=6))

    def capture_faith(_installation, *, country, observer):
        faith_calls.append((country, observer))
        return deepcopy(faith_capture_report)

    monkeypatch.setattr(
        faith_module, "import_module",
        lambda *_args: SimpleNamespace(validate_capture=lambda *_args: True),
    )
    faith_source = NativeCountryFaithSource(base, capture=capture_faith)

    group_calls = []
    group_capture_report = deepcopy(group_report if group_report is not None
                                     else group_fixture._group_report(
                                         target, text="christian"))

    def capture_group(_installation, *, country, observer):
        group_calls.append((country, observer))
        return deepcopy(group_capture_report)

    monkeypatch.setattr(
        group_module, "import_module",
        lambda *_args: SimpleNamespace(validate_capture=lambda *_args: True,
                                        PROFILE_SHA256=GROUP_PROFILE_SHA256),
    )
    group_source = NativeReligionGroupSource(base, capture=capture_group)

    source = NativeReligionInformationSource(
        base, faith_source=faith_source, group_source=group_source,
        definitions=definitions, capture=capture_identity,
    )
    return source, base, identity_calls, identity_validations, faith_calls, group_calls


def _read(source, base, target="ENG", fields=None):
    query = faith_fixture.make_query(target, fields=fields or ["faith"])
    return source.read(query, base.context())


@pytest.mark.parametrize("target", ["FRA", "ENG"])
def test_catalog_and_mixed_query_preserve_legacy_names_and_add_canonical_identity(
        tmp_path, monkeypatch, target):
    definitions = DefinitionIndex()
    source, base, identity_calls, validations, faith_calls, group_calls = _make_source(
        tmp_path / target, monkeypatch, target=target, definitions=definitions)

    topic = source.catalog()[0]
    assert topic["topic_id"] == "S02"
    assert set(topic["fields"]) >= {"faith", "religion_group", "mechanics"}
    assert source.event_types == ()
    for field in ("faith", "religion_group", "mechanics"):
        assert topic["fields"][field]["coverage"] == "partial"
        assert topic["fields"][field]["complete"] is False
        assert topic["fields"][field]["triggers"] == ["query", "periodic"]

    result = _read(source, base, target, ["faith", "religion_group", "mechanics"])
    fields = result["fields"]
    expected_identity = {"status": "known", **KNOWN_IDENTITY}
    assert fields["faith"]["status"] == "known"
    assert fields["faith"]["value"] == {
        "primary_religion_name": {
            "text": "天主教", "raw_hex": "10295911494e105965", "encoding": "eu4_escape",
        },
        "icon_frame_request": 6,
        "identity": expected_identity,
    }
    assert fields["religion_group"]["status"] == "known"
    assert fields["religion_group"]["value"] == {
        "religion_group_name": {
            "text": "christian", "raw_hex": "63687269737469616e",
            "encoding": "eu4_escape",
        },
        "identity": expected_identity,
    }
    mechanics = fields["mechanics"]
    assert mechanics["status"] == "known"
    assert mechanics["value"]["identity"] == expected_identity
    assert mechanics["value"]["runtime_state"] == {
        "status": "unknown", "reason": "RELIGION_MECHANIC_STATE_NOT_READ",
    }
    assert mechanics["value"]["conditions_evaluated"] is False
    assert mechanics["value"]["effects_executed"] is False
    assert result["complete"] is False
    assert result["source"]["name"] == "NativeReligionInformationSource"
    assert result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["provenance"]["target"] == target
    assert identity_calls == [(base.session.directory / "installation.json", target, "FRA")]
    assert len(validations) == 1 and validations[0][2:] == (
        faith_fixture.CREATION, target)
    assert faith_calls == [(target, "FRA")]
    assert group_calls == [(target, "FRA")]
    public = repr(result)
    for private in ("raw_inputs", "raw_reads", "private_pointer", "native_bytes"):
        assert private not in public


def test_default_constructor_contains_legacy_faith_and_group_sources(tmp_path):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    source = NativeReligionInformationSource(base)

    assert isinstance(source.faith_source, NativeCountryFaithSource)
    assert isinstance(source.group_source, NativeReligionGroupSource)
    assert source.faith_source.base_source is base
    assert source.group_source.base_source is base
    assert source.event_types == ()


@pytest.mark.parametrize(("case", "expected_status", "expected_reason"), [
    ("validator", "unknown", "RELIGION_IDENTITY_CAPTURE_INVALID"),
    ("private_identity", "unknown", "RELIGION_IDENTITY_CAPTURE_INVALID"),
    ("invisible", "invisible", "RELIGION_IDENTITY_NOT_ADMITTED"),
    ("native_unknown", "unknown", "RELIGION_IDENTITY_INPUT_UNAVAILABLE"),
])
def test_identity_failure_or_invisibility_never_exports_keys(
        tmp_path, monkeypatch, case, expected_status, expected_reason):
    kwargs = {}
    if case == "validator":
        kwargs["identity_valid"] = False
    elif case == "private_identity":
        kwargs["identity_report"] = _identity_report(
            value={**KNOWN_IDENTITY, "private_pointer": "0x123456789abcdef0"})
    elif case == "invisible":
        kwargs["identity_report"] = _identity_report(admitted=False)
    else:
        kwargs["identity_report"] = _identity_report(field_status="unknown")
    source, base, *_ = _make_source(tmp_path / case, monkeypatch, **kwargs)

    result = _read(source, base, fields=["faith", "religion_group", "mechanics"])
    for name in ("faith", "religion_group"):
        identity = result["fields"][name]["value"]["identity"]
        assert identity == {"status": expected_status, "reason": expected_reason}
        assert "religion_key" not in identity and "religion_group_key" not in identity
    mechanic = result["fields"]["mechanics"]
    assert mechanic["status"] == expected_status
    assert mechanic["reason"] == expected_reason
    assert "value" not in mechanic
    assert "0x123456789abcdef0" not in repr(result)


def test_unknown_native_and_name_only_query_never_resolve_static_definitions(
        tmp_path, monkeypatch):
    class NoCallIndex:
        def __init__(self):
            self.calls = []

        def assert_current(self):
            self.calls.append("assert_current")
            raise AssertionError("definitions must not be queried")

        def context(self):
            self.calls.append("context")
            raise AssertionError("definitions must not be queried")

        def definition(self, key):
            self.calls.append(("definition", key))
            raise AssertionError("definitions must not be queried")

        def group_definition(self, key):
            self.calls.append(("group_definition", key))
            raise AssertionError("definitions must not be queried")

    no_call = NoCallIndex()
    source, base, *_ = _make_source(
        tmp_path / "unknown", monkeypatch,
        identity_report=_identity_report(field_status="unknown"), definitions=no_call)
    mechanic = _read(source, base, fields=["mechanics"])["fields"]["mechanics"]
    assert mechanic["status"] == "unknown"
    assert no_call.calls == []

    name_source, name_base, *_ = _make_source(
        tmp_path / "name-only", monkeypatch, definitions=None)
    faith = _read(name_source, name_base, fields=["faith"])["fields"]["faith"]
    assert faith["status"] == "known"
    assert name_source.definitions is None


@pytest.mark.parametrize(("name", "digest_key", "mutation", "expected_reason"), [
    ("faith", "religion_binding_sha256", "different", "RELIGION_NAME_IDENTITY_CHANGED"),
    ("faith", "religion_binding_sha256", "missing", "RELIGION_NAME_IDENTITY_UNVERIFIED"),
    ("religion_group", "religion_binding_sha256", "different", "RELIGION_NAME_IDENTITY_CHANGED"),
    ("religion_group", "religion_group_binding_sha256", "different",
     "RELIGION_NAME_IDENTITY_CHANGED"),
    ("religion_group", "religion_binding_sha256", "missing",
     "RELIGION_NAME_IDENTITY_UNVERIFIED"),
    ("religion_group", "religion_group_binding_sha256", "missing",
     "RELIGION_NAME_IDENTITY_UNVERIFIED"),
])
def test_name_and_identity_join_requires_matching_per_capture_binding_digest(
        tmp_path, monkeypatch, name, digest_key, mutation, expected_reason):
    source, base, *_ = _make_source(tmp_path, monkeypatch, definitions=DefinitionIndex())
    child = source.faith_source if name == "faith" else source.group_source
    other_name = "religion_group" if name == "faith" else "faith"

    matching = _read(source, base, fields=["faith", "religion_group", "mechanics"])["fields"]
    for name_field in ("faith", "religion_group"):
        assert matching[name_field]["status"] == "known"
        assert matching[name_field]["value"]["identity"] == {
            "status": "known", **KNOWN_IDENTITY,
        }

    received = deepcopy(KNOWN_BINDINGS)
    if mutation == "different":
        received[digest_key] = "f" * 64
    else:
        received.pop(digest_key)

    def child_read(query, context):
        return _legacy_sample(child, query, context, name, bindings=received)

    child.read = child_read
    fields = _read(source, base, fields=["faith", "religion_group", "mechanics"])["fields"]

    assert fields[name]["status"] == "unknown"
    assert fields[name]["reason"] == expected_reason
    assert "value" not in fields[name]
    assert fields[other_name]["status"] == "known"
    assert fields[other_name]["value"]["identity"] == {
        "status": "known", **KNOWN_IDENTITY,
    }
    assert fields["mechanics"]["status"] == "known"
    assert fields["mechanics"]["value"]["identity"] == {
        "status": "known", **KNOWN_IDENTITY,
    }


def test_legacy_name_stays_known_when_native_identity_is_unknown(tmp_path, monkeypatch):
    source, base, *_ = _make_source(
        tmp_path, monkeypatch,
        identity_report=_identity_report(field_status="unknown"),
    )

    fields = _read(source, base, fields=["faith", "mechanics"])["fields"]

    assert fields["faith"]["status"] == "known"
    assert fields["faith"]["value"]["identity"] == {
        "status": "unknown", "reason": "RELIGION_IDENTITY_INPUT_UNAVAILABLE",
    }
    assert fields["mechanics"]["status"] == "unknown"
    assert fields["mechanics"]["reason"] == "RELIGION_IDENTITY_INPUT_UNAVAILABLE"
    assert source.definitions is None


def test_binding_guard_closes_reproduced_pre_correction_same_tick_join(
        tmp_path, monkeypatch):
    snapshot = (Path(__file__).resolve().parents[2] / "work" / "runtime"
                / "information-religion-identity-20261104-167-001"
                / "before-binding-join-correction" / "religion_information.py")
    assert snapshot.stat().st_size <= 10 * 1024 * 1024
    snapshot_bytes = snapshot.read_bytes()
    assert hashlib.sha256(snapshot_bytes).hexdigest() == PRE_BINDING_JOIN_SOURCE_SHA256
    module_name = "bridge.information._religion_information_before_binding_join"
    spec = importlib.util.spec_from_file_location(module_name, snapshot)
    assert spec is not None and spec.loader is not None
    old_module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, old_module)
    spec.loader.exec_module(old_module)
    monkeypatch.setattr(
        old_module, "import_module",
        lambda *_args: SimpleNamespace(
            validate_capture=lambda *_args: True,
            PROFILE_SHA256=IDENTITY_PROFILE_SHA256,
        ),
    )

    current, base, *_ = _make_source(tmp_path, monkeypatch)
    child = current.faith_source
    received = deepcopy(KNOWN_BINDINGS)
    received["religion_binding_sha256"] = "f" * 64
    child.read = lambda query, context: _legacy_sample(
        child, query, context, "faith", bindings=received)
    old = old_module.NativeReligionInformationSource(
        base, faith_source=current.faith_source, group_source=current.group_source,
        definitions=current.definitions, capture=current.capture,
    )

    old_field = _read(old, base, fields=["faith"])["fields"]["faith"]
    corrected_field = _read(current, base, fields=["faith"])["fields"]["faith"]

    assert old_field["status"] == "known"
    assert old_field["value"]["identity"] == {"status": "known", **KNOWN_IDENTITY}
    assert corrected_field["status"] == "unknown"
    assert corrected_field["reason"] == "RELIGION_NAME_IDENTITY_CHANGED"
    assert "value" not in corrected_field


@pytest.mark.parametrize("mutation", ["private_value", "wrong_source", "wrong_session",
                                       "wrong_object"])
def test_invalid_legacy_child_dto_or_binding_retracts_its_field(
        tmp_path, monkeypatch, mutation):
    source, base, *_ = _make_source(tmp_path, monkeypatch)

    def child_read(query, context):
        sample = _legacy_sample(source.faith_source, query, context, "faith")
        if mutation == "private_value":
            sample["fields"]["faith"]["value"]["private_pointer"] = "0x123456789abcdef0"
        elif mutation == "wrong_source":
            sample["source"]["name"] = "UntrustedSource"
        elif mutation == "wrong_session":
            sample["source"]["session_id"] = "stale-session"
        else:
            sample["objects"] = [{"type": "country", "country": "FRA"}]
        return sample

    source.faith_source.read = child_read
    field = _read(source, base, fields=["faith"])["fields"]["faith"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_NAME_SOURCE_INVALID"
    assert "value" not in field
    assert "private_pointer" not in repr(field)


@pytest.mark.parametrize(("stage", "drift", "expected_reason"), [
    ("identity_capture", "context", "RELIGION_INFORMATION_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("identity_capture", "session", "RELIGION_INFORMATION_SESSION_CHANGED_DURING_CAPTURE"),
    ("child", "context", "RELIGION_INFORMATION_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("child", "session", "RELIGION_INFORMATION_SESSION_CHANGED_DURING_CAPTURE"),
])
def test_capture_or_child_exception_with_context_or_session_drift_withdraws_all_fields(
        tmp_path, monkeypatch, stage, drift, expected_reason):
    def mutate(base):
        if drift == "context":
            base.current["game_date"] += 1
        else:
            next_creation = base.session.record["creation_filetime"] + 1
            base.session.record["creation_filetime"] = next_creation
            base.session.creation_filetime = next_creation

    source, base, *_ = _make_source(
        tmp_path / f"{stage}-{drift}", monkeypatch,
        identity_error=RuntimeError("capture failed") if stage == "identity_capture" else None,
        after_identity=mutate if stage == "identity_capture" else None)

    def valid_faith(query, context):
        if stage == "child":
            mutate(base)
            raise RuntimeError("legacy child failed")
        return _legacy_sample(source.faith_source, query, context, "faith")

    source.faith_source.read = valid_faith
    source.group_source.read = lambda query, context: _legacy_sample(
        source.group_source, query, context, "religion_group")
    result = _read(source, base, fields=["faith", "religion_group"])

    assert set(result["fields"]) == {"faith", "religion_group"}
    for field in result["fields"].values():
        assert field["status"] == "unavailable"
        assert field["reason"] == expected_reason
        assert "value" not in field


@pytest.mark.parametrize("failure", ["group_mismatch", "invalid_ast"])
def test_mechanics_configuration_failure_does_not_claim_applied_effects(
        tmp_path, monkeypatch, failure):
    definitions = DefinitionIndex(
        group_mismatch=failure == "group_mismatch",
        invalid_group_ast=failure == "invalid_ast")
    source, base, *_ = _make_source(tmp_path, monkeypatch, definitions=definitions)
    field = _read(source, base, fields=["mechanics"])["fields"]["mechanics"]

    assert field["status"] == "known"
    value = field["value"]
    assert value["runtime_state"] == {
        "status": "unknown", "reason": "RELIGION_MECHANIC_STATE_NOT_READ",
    }
    assert value["conditions_evaluated"] is False
    assert value["effects_executed"] is False
    assert "applied_effects" not in value
    if failure == "group_mismatch":
        assert value["religion_rules"] == {
            "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
        }
        assert value["group_rules"] == {
            "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
        }
    else:
        assert value["religion_rules"]["status"] == "known"
        assert value["group_rules"] == {
            "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
        }


def test_static_rules_cache_once_and_failed_assert_current_does_not_reuse_cache(
        tmp_path, monkeypatch):
    definitions = DefinitionIndex()
    source, base, *_ = _make_source(tmp_path, monkeypatch, definitions=definitions)

    first = _read(source, base, fields=["mechanics"])["fields"]["mechanics"]
    second = _read(source, base, fields=["mechanics"])["fields"]["mechanics"]
    assert first["status"] == second["status"] == "known"
    assert definitions.definition_calls == ["catholic"]
    assert definitions.group_calls == ["christian"]
    assert len(source._rule_cache) == 1

    definitions.fail_assert = True
    after_drift = _read(source, base, fields=["mechanics"])["fields"]["mechanics"]
    assert after_drift["status"] == "known"
    assert after_drift["value"]["religion_rules"] == {
        "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
    }
    assert after_drift["value"]["group_rules"] == {
        "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
    }
    assert source._rule_cache == {}
    assert definitions.definition_calls == ["catholic"]
    assert definitions.group_calls == ["christian"]


def test_composite_service_report_periodic_and_cancel_use_only_combined_source(
        tmp_path, monkeypatch):
    definitions = DefinitionIndex()
    source, base, identity_calls, _, faith_calls, group_calls = _make_source(
        tmp_path, monkeypatch, definitions=definitions)
    composite = CompositeSource(base, [source])
    now = [100]
    service = InformationService(composite, tmp_path / "religion-information.sqlite3",
                                 clock=lambda: now[0])
    tools = InformationTools(service)
    query = faith_fixture.make_query(
        "ENG", fields=["faith", "religion_group", "mechanics"])
    try:
        assert source.event_types == ()
        topic = next(item for item in service.source.catalog() if item["topic_id"] == "S02")
        assert set(topic["fields"]) >= {"faith", "religion_group", "mechanics"}

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "religion-information-query", "queries": [query],
        })
        direct_fields = direct["items"][0]["fields"]
        assert set(direct_fields) == {"faith", "religion_group", "mechanics"}
        assert direct["complete"] is False

        report = tools.call("information_manage_report", {
            "request_id": "religion-information-report-create",
            "operation": "create",
            "config": {"name": "religion information", "detail": "raw",
                       "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "religion-information-report-query", "report_id": report["id"],
        })
        assert rendered["items"][0]["fields"] == direct_fields

        subscription = tools.call("information_manage_subscription", {
            "request_id": "religion-information-subscription-create",
            "operation": "create",
            "config": {
                "name": "religion information periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": report["id"],
                "schedule": {"basis": "real", "unit": "seconds", "every": 1,
                             "missed": "coalesce"},
            },
        })["subscription"]
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        assert tick["results"][0]["status"] == "partial"
        assert tick["results"][0]["items"][0]["fields"] == direct_fields
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
        assert definitions.definition_calls == ["catholic"]
        assert definitions.group_calls == ["christian"]

        tools.call("information_manage_subscription", {
            "request_id": "religion-information-subscription-cancel",
            "operation": "cancel", "subscription_id": subscription["id"],
            "expected_version": subscription["version"],
        })
        now[0] = 104
        tools.call("information_tick", {"view": "full"})
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
    finally:
        service.close()

