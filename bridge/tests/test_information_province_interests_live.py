"""Focused contracts for the live, read-only G01 province adapter.

The public-source tests use a fake session/capture.  They verify routing,
publication gates, and sanitization; the native memory reader remains covered
by its own tests and by the separately retained private capture.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import foreign_technology_capture as owner_capture
from bridge.information import province_interest_capture
from bridge.information import province_state_capture
from bridge.information.composite import CompositeSource
from bridge.information.province_interests_live import NativeProvinceInterestsSource
from bridge.information.service import InformationService
from bridge.information.sources import RecordedSource
from bridge.information.tools import InformationTools
from bridge.information.catalog import list_topics


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134380633247930565
PROVINCE_ID = 186
PROFILE_SHA = province_interest_capture.PROFILE_SHA256
_DEFAULT_VALIDATION = object()


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "province-interest-test-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56569464,
        "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


class FakeBase:
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
            "source": {"name": "fake_primary", "mode": "live"},
        }

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, province_id=PROVINCE_ID, fields=None, obj=None):
    return {
        "topic": "G01",
        "object": obj or {"type": "province", "province_id": province_id},
        "fields": list(fields if fields is not None else ("cores", "claims")),
        "parameters": {},
    }


def make_capture_report(*, province_id=PROVINCE_ID, observer="FRA",
                        cores=None, claims=None, admission=True,
                        role_verified=True, discovery_status="known",
                        discovered=True):
    if cores is None:
        cores = {"status": "known", "value": ["CHP", "FRA"],
                 "raw_inputs": {"record_pointer": "0x1111222233334444"}}
    if claims is None:
        claims = {"status": "known", "value": ["BUR", "NEV", "ORL"],
                  "raw_inputs": {"node_pointer": "0x5555666677778888"}}
    admission_record = {
        "status": "known" if admission else "unknown",
        "admitted": admission,
        "observer_nonplayer_role": {
            "verified": role_verified,
            "observer": observer,
            "human_count": 1,
            "controller_type": 0 if role_verified else 1,
        },
        "raw_inputs": {"country_pointer": "0x123456789abcdef0"},
    }
    discovery_record = {
        "status": discovery_status,
        "value": discovered,
        "raw_inputs": {"bitset_pointer": "0x0fedcba987654321"},
    }
    return {
        "schema": "information.province_interest_capture.v1",
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "observation": {
                "backend": {
                    "observer": {"tag": observer,
                                 "private_pointer": "0x9988776655443322"},
                    "targets": [{
                        "province_id": province_id,
                        "admission_by_pass": {
                            "pass1": deepcopy(admission_record),
                            "pass2": deepcopy(admission_record),
                        },
                        "discovery_by_pass": {
                            "pass1": deepcopy(discovery_record),
                            "pass2": deepcopy(discovery_record),
                        },
                        "fields": {
                            "G01.cores": deepcopy(cores),
                            "G01.claims": deepcopy(claims),
                        },
                    }],
                },
            },
            "raw_reads": [{"label": "private.province_interest",
                           "address": "0xabcdef0011223344"}],
        },
    }


def make_source(tmp_path, monkeypatch, *, report=None,
                validation_result=_DEFAULT_VALIDATION, after_capture=None,
                capture_error=None, context=None):
    base = FakeBase(tmp_path, context or make_context())
    captured = deepcopy(report if report is not None else make_capture_report())
    captures = []
    validations = []
    projections = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(captured)

    def validate_capture(report_arg, context_arg, creation, province_id):
        validations.append((deepcopy(report_arg), deepcopy(context_arg),
                            creation, province_id))
        structurally_valid = (
            isinstance(report_arg, dict)
            and report_arg.get("schema") == "information.province_interest_capture.v1"
            and report_arg.get("observer") == "FRA"
            and report_arg.get("object") == {
                "type": "province", "province_id": province_id,
            }
            and isinstance(context_arg, dict)
            and context_arg.get("observer") == "FRA"
            and context_arg.get("session_id") == base.current.get("session_id")
            and creation == CREATION
        )
        if validation_result is _DEFAULT_VALIDATION:
            return structurally_valid
        return validation_result

    def project_fields(report_arg):
        projections.append(deepcopy(report_arg))
        return province_interest_capture.project_fields(report_arg)

    module = SimpleNamespace(
        validate_capture=validate_capture,
        project_fields=project_fields,
        PROFILE_SHA256=PROFILE_SHA,
    )
    monkeypatch.setattr(
        province_interests_live_module, "import_module",
        lambda _name, _package: module,
    )
    source = NativeProvinceInterestsSource(base, capture=capture)
    return source, base, captured, captures, validations, projections


from bridge.information import province_interests_live as province_interests_live_module


def test_catalog_and_composite_keep_live_fields_partial_and_other_g01_fields_planned(
        tmp_path, monkeypatch):
    source, base, *_ = make_source(tmp_path, monkeypatch)
    own_topic = source.catalog()[0]
    assert own_topic["topic_id"] == "G01"
    assert set(own_topic["fields"]) == {"cores", "claims"}
    assert all(item["coverage"] == "partial" and item["complete"] is False
               for item in own_topic["fields"].values())
    assert own_topic["triggers"] == ["query", "periodic"]

    composite = CompositeSource(base, [source])
    merged = next(item for item in composite.catalog() if item["topic_id"] == "G01")
    planned = next(item for item in list_topics() if item["topic_id"] == "G01")
    assert set(merged["fields"]) == set(planned["fields"])
    assert {name for name, meta in merged["fields"].items()
            if meta["coverage"] == "partial"} == {"cores", "claims"}
    assert all(merged["fields"][name]["coverage"] == "planned"
               for name in set(merged["fields"]) - {"cores", "claims"})


def test_live_projection_is_partial_sorted_and_private_inputs_are_not_public(
        tmp_path, monkeypatch):
    source, base, report, captures, validations, projections = make_source(
        tmp_path, monkeypatch)
    result = source.read(make_query(), base.context())

    assert result["fields"]["cores"]["status"] == "known"
    assert result["fields"]["cores"]["value"] == ["CHP", "FRA"]
    assert result["fields"]["claims"]["status"] == "known"
    assert result["fields"]["claims"]["value"] == ["BUR", "NEV", "ORL"]
    assert all(field["complete"] is False and field["period"] == "current"
               and field["unit"] == "country_tag" and field["scale"] == 1
               for field in result["fields"].values())
    assert result["complete"] is False
    assert result["game_date"] == base.current["game_date"]
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA"
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is False
    assert provenance["actual_UI_observed"] is False
    assert provenance["full_province_visibility_complete"] is False
    assert provenance["province_id"] == PROVINCE_ID
    assert len(provenance["capture_report_sha256"]) == 64
    assert provenance["profile_sha256"] == PROFILE_SHA
    assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    assert len(validations) == len(projections) == 1
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, PROVINCE_ID)
    public = repr(result)
    for private in ("raw_inputs", "raw_reads", "private_pointer",
                    "0x1111222233334444", "0x5555666677778888",
                    "0xabcdef0011223344", "0x9988776655443322"):
        assert private not in public


def test_known_empty_is_distinct_from_unknown_and_fields_fail_independently(
        tmp_path, monkeypatch):
    report = make_capture_report(
        cores={"status": "known", "value": [], "raw_inputs": {"ptr": "0x1"}},
        claims={"status": "unknown", "reason": "CLAIM_NODE_POINTER_INVALID",
                "raw_inputs": {"ptr": "0x2"}},
    )
    source, base, *_ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(), base.context())

    assert result["fields"]["cores"]["status"] == "known"
    assert result["fields"]["cores"]["value"] == []
    assert result["fields"]["claims"]["status"] == "unknown"
    assert "value" not in result["fields"]["claims"]
    assert "0x2" not in repr(result)


@pytest.mark.parametrize("gate", ["admission", "discovery_clear", "discovery_unknown"])
def test_admission_or_discovery_gate_failure_publishes_no_membership(
        tmp_path, monkeypatch, gate):
    options = {}
    if gate == "admission":
        options["admission"] = False
    elif gate == "discovery_clear":
        options["discovered"] = False
    else:
        options["discovery_status"] = "unknown"
    source, base, report, captures, validations, projections = make_source(
        tmp_path, monkeypatch, report=make_capture_report(**options))

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" and "value" not in field
               for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_INTEREST_CAPTURE_SHAPE_INVALID"
               for field in result["fields"].values())
    assert len(captures) == len(validations) == len(projections) == 1
    for private in ("0x123456789abcdef0", "0x0fedcba987654321", "raw_inputs"):
        assert private not in repr(result)


def test_human_observer_with_positive_discovery_can_read_membership(tmp_path, monkeypatch):
    report = make_capture_report(role_verified=False)
    source, base, _, captures, validations, projections = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query(), base.context())
    assert all(field['status'] == 'known' for field in result['fields'].values())
    assert len(captures) == len(validations) == len(projections) == 1
    assert report['capture']['observation']['backend']['targets'][0]['admission_by_pass']['pass1']['observer_nonplayer_role']['verified'] is False


def test_capture_object_identity_mismatch_is_rejected_by_validator(
        tmp_path, monkeypatch):
    report = make_capture_report(province_id=187)
    source, base, _, captures, validations, projections = make_source(
        tmp_path, monkeypatch, report=report)

    result = source.read(make_query(province_id=PROVINCE_ID), base.context())

    assert all(field["status"] == "unknown" and "value" not in field
               for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_INTEREST_CAPTURE_NOT_VALIDATED"
               for field in result["fields"].values())
    assert len(captures) == len(validations) == 1
    assert projections == []


@pytest.mark.parametrize("validation_result", [False, 1, None])
def test_capture_validator_must_return_literal_true(
        tmp_path, monkeypatch, validation_result):
    source, base, _, _, validations, projections = make_source(
        tmp_path, monkeypatch, validation_result=validation_result)

    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unknown" and "value" not in field
               for field in result["fields"].values())
    assert all(field["reason"] == "PROVINCE_INTEREST_CAPTURE_NOT_VALIDATED"
               for field in result["fields"].values())
    assert len(validations) == 1
    assert projections == []


@pytest.mark.parametrize("change", ["game_date", "session_creation"])
def test_context_or_session_drift_during_capture_retracts_values(
        tmp_path, monkeypatch, change):
    def mutate(base):
        if change == "game_date":
            base.current["game_date"] += 24
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, captures, validations, projections = make_source(
        tmp_path, monkeypatch, after_capture=mutate)
    result = source.read(make_query(), base.context())

    assert all(field["status"] == "unavailable" and "value" not in field
               for field in result["fields"].values())
    assert all(field["reason"] in {
        "PROVINCE_INTEREST_CONTEXT_CHANGED_DURING_CAPTURE",
        "PROVINCE_INTEREST_SESSION_CHANGED_DURING_CAPTURE",
    } for field in result["fields"].values())
    assert len(captures) == 1
    assert validations == projections == []


def test_stale_context_wrong_observer_and_country_reverse_do_not_capture(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections = make_source(tmp_path, monkeypatch)
    stale = base.context()
    base.current["game_date"] += 24
    stale_result = source.read(make_query(), stale)
    assert all(field["status"] == "unavailable" and "value" not in field
               for field in stale_result["fields"].values())

    wrong_observer = base.context()
    wrong_observer["observer"] = "ENG"
    observer_result = source.read(make_query(), wrong_observer)
    assert all(field["status"] == "unavailable" and "value" not in field
               for field in observer_result["fields"].values())

    reverse_result = source.read(make_query(
        fields=["cores", "claims"], obj={"type": "country", "country": "ENG"}),
        base.context())
    assert all(field["status"] == "unknown" and "value" not in field
               for field in reverse_result["fields"].values())
    assert all(field["reason"] == "COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED"
               for field in reverse_result["fields"].values())
    assert captures == validations == projections == []


def test_planned_only_g01_query_stays_unsupported_without_capture(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections = make_source(tmp_path, monkeypatch)
    result = source.read(make_query(fields=["permanent_claims"]), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unsupported"
    assert "value" not in field
    assert captures == validations == projections == []


def test_query_report_and_periodic_share_partial_g01_projection(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections = make_source(tmp_path, monkeypatch)
    now = [100]
    service = InformationService(
        CompositeSource(base, [source]),
        tmp_path / "province-interest-service.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    query = make_query(fields=["cores", "claims", "permanent_claims",
                               "task_targets", "strategic_targets"])
    try:
        topic = next(item for item in service.source.catalog()
                     if item["topic_id"] == "G01")
        assert set(topic["fields"]) == set(query["fields"])
        assert all(topic["fields"][name]["coverage"] == "partial"
                   for name in ("cores", "claims"))
        assert all(topic["fields"][name]["coverage"] == "planned"
                   for name in ("permanent_claims", "task_targets", "strategic_targets"))

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "live-province-interest-direct",
            "queries": [query],
        })
        saved = tools.call("information_manage_report", {
            "request_id": "live-province-interest-report-create",
            "operation": "create",
            "config": {"name": "live G01 partial", "detail": "raw",
                       "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "live-province-interest-report-query",
            "report_id": saved["id"],
        })
        direct_fields = direct["items"][0]["fields"]
        assert direct_fields == rendered["items"][0]["fields"]
        assert direct_fields["cores"]["value"] == ["CHP", "FRA"]
        assert direct_fields["claims"]["value"] == ["BUR", "NEV", "ORL"]
        assert all(direct_fields[name]["status"] == "unsupported"
                   for name in ("permanent_claims", "task_targets", "strategic_targets"))
        assert direct["complete"] is False
        assert direct["items"][0]["source"]["provenance"]["native_function_invoked"] is False
        assert direct["items"][0]["source"]["provenance"]["actual_UI_observed"] is False
        for private in ("raw_inputs", "private_pointer", "raw_reads",
                        "0x1111222233334444", "0xabcdef0011223344"):
            assert private not in repr(direct["items"][0])

        tools.call("information_manage_subscription", {
            "request_id": "live-province-interest-subscription-create",
            "operation": "create",
            "config": {
                "name": "live G01 periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": saved["id"],
                "schedule": {"basis": "real", "unit": "seconds",
                             "every": 1, "missed": "coalesce"},
            },
        })
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["items"][0]["fields"] == direct_fields
        assert periodic["status"] == "partial"
        assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")] * 3
        assert len(validations) == len(projections) == 3
    finally:
        service.close()


def test_recorded_archive_factory_does_not_mount_live_province_adapter(tmp_path):
    from tools.serve_information import _build_runtime

    archive = tmp_path / "recorded.json"
    archive.write_text(json.dumps({"cases": []}), encoding="utf-8")
    args = SimpleNamespace(
        battle_stream=None,
        battle_ingest_installation=None,
        battle_manage_capture=False,
        province_interest_save=None,
        province_interest_parser_manifest=None,
        operator_session=None,
        recorded_manifest=archive,
        observer=None,
        mission_save=None,
        mission_game_data=False,
        static_game_data=False,
        static_game_root=None,
        static_user_data=None,
        database=tmp_path / "recorded-service.sqlite3",
        owner="province-test",
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert isinstance(service.source, RecordedSource)
        assert not isinstance(service.source, CompositeSource)
        assert not isinstance(service.source, NativeProvinceInterestsSource)
    finally:
        service.close()


class FakeByteReader:
    def __init__(self, contents):
        self.contents = dict(contents)
        self.calls = []

    def read(self, address, size, label):
        self.calls.append((address, size, label))
        value = self.contents.get(address, b"")
        if len(value) != size:
            return b""
        return value


def _synthetic_profile(guards):
    return {
        "profile_id": "province-interest-memory-1374",
        "profile_version": 1,
        "game_version": "1.37.4",
        "executable": {"sha256": owner_capture.EXE_SHA256},
        "source_evidence": [],
        "layout_dependencies": [],
        "code_guards": deepcopy(guards),
    }


def _write_synthetic_profile(tmp_path, monkeypatch, profile):
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = tmp_path / "synthetic-province-interest-profile.json"
    path.write_bytes(raw)
    monkeypatch.setattr(province_interest_capture, "PROFILE_FILE", path)
    monkeypatch.setattr(province_interest_capture, "PROFILE_SHA256",
                        hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(province_state_capture, "_load_profile", lambda: {})
    return raw


def test_capture_profile_loader_and_runtime_guards_keep_complete_rva_records(
        tmp_path, monkeypatch):
    guards = [
        {"name": "test_guard_a", "rva": "0x100", "end_rva_exclusive": "0x102",
         "bytes": "90c3", "sha256": hashlib.sha256(bytes.fromhex("90c3")).hexdigest()},
        {"name": "test_guard_b", "rva": "0x200", "end_rva_exclusive": "0x201",
         "bytes": "cc", "sha256": hashlib.sha256(bytes.fromhex("cc")).hexdigest()},
    ]
    _write_synthetic_profile(tmp_path, monkeypatch, _synthetic_profile(guards))
    profile = province_interest_capture._load_profile()
    base = 0x140000000
    reader = FakeByteReader({
        base + int(item["rva"], 0): bytes.fromhex(item["bytes"])
        for item in guards
    })

    records = owner_capture._guards(reader, base, profile)

    assert [item["name"] for item in records] == ["test_guard_a", "test_guard_b"]
    assert [item["rva"] for item in records] == ["0x100", "0x200"]
    assert all(item["matches"] is True for item in records)
    assert [item["actual_hex"] for item in records] == ["90c3", "cc"]
    assert len(reader.calls) == len(guards)


def test_capture_profile_guard_missing_end_rva_metadata_fails_before_read(
        tmp_path, monkeypatch):
    guard = {"name": "missing_end", "rva": "0x100", "bytes": "90c3",
             "sha256": hashlib.sha256(bytes.fromhex("90c3")).hexdigest()}
    _write_synthetic_profile(tmp_path, monkeypatch,
                             _synthetic_profile([guard]))
    profile = province_interest_capture._load_profile()
    reader = FakeByteReader({0x140000100: bytes.fromhex("90c3")})

    with pytest.raises((KeyError, ValueError)):
        owner_capture._guards(reader, 0x140000000, profile)

    assert reader.calls == []


def test_current_r2_profile_declares_ranges_without_opening_game_or_capture():
    profile = province_interest_capture._load_profile()
    guards = profile["code_guards"]
    assert guards
    assert all({"name", "rva", "end_rva_exclusive", "bytes", "sha256"} <= set(item)
               for item in guards)
    for item in guards:
        expected = bytes.fromhex(item["bytes"])
        assert int(item["end_rva_exclusive"], 0) == int(item["rva"], 0) + len(expected)
        assert hashlib.sha256(expected).hexdigest() == item["sha256"]


@pytest.mark.parametrize("module_name", [
    "province_interest_capture", "province_permanent_claim_capture",
    "node_cash_aggregate_capture", "province_fort_capture", "province_modifiers_capture",
    "province_port_capture", "province_trade_power_capture", "province_trade_power_inputs_capture",
])
@pytest.mark.parametrize('damage_frozen', [False, True])
def test_sampling_profiles_reuse_frozen_country_lookup_source(module_name, monkeypatch, damage_frozen):
    module = import_module(f"bridge.information.{module_name}")
    mutable_source = (module.ROOT / "work/native/peace-context-query.inc").resolve()
    frozen_path = "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/peace-context-query.inc"
    frozen_source = (module.ROOT / frozen_path).resolve()
    original_sha = owner_capture._sha

    def sha_without_mutable_source(path):
        if Path(path).resolve() == mutable_source:
            raise AssertionError("province capture depends on the mutable war-query source")
        if damage_frozen and Path(path).resolve() == frozen_source:
            return '0' * 64
        return original_sha(path)

    monkeypatch.setattr(owner_capture, "_sha", sha_without_mutable_source)
    if damage_frozen:
        with pytest.raises(ValueError):
            module._load_profile()
        return
    profile = module._load_profile()
    frozen = next(row for row in profile["layout_dependencies"] if row["path"] == frozen_path)
    assert frozen["bytes"] == 12121
    assert frozen["sha256"] == "ed24862974ead033a7ea2bccf3a68e40a14af8f6444190d24def634466d508f5"
    assert all(row["path"] != "work/native/peace-context-query.inc"
               for row in profile["layout_dependencies"])
