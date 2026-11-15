"""G01 task-target routing across the real composite and information service.

The province native owners use small validated capture fixtures.  Mission
analysis reuses the existing captured-task test fixture, so the G01 adapter
receives a real M05.linked_targets projection without touching the game.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationError
from bridge.information import province_interests_live as interests_module
from bridge.information import province_permanent_claims as permanent_module
from bridge.information.composite import CompositeSource
from bridge.information.mission_analysis import MissionAnalysisSource
from bridge.information.mission_read_scope import MissionReadSource, MissionScopedReader
from bridge.information.province_interests_live import NativeProvinceInterestsSource
from bridge.information.province_permanent_claims import (
    NativeProvincePermanentClaimsSource,
)
from bridge.information.province_task_targets import ProvinceTaskTargetsSource
from bridge.information.service import InformationService
from bridge.tests.test_information_mission_chain_targets import setup_source as setup_mission_fixture
from bridge.tests.test_information_mission_target_rules_v2 import (
    FakeScopeIndex,
    province_scope,
)


CREATION = 134380633247930565
PROVINCE_ID = 186
SELECTOR = {"root_id": "root_main", "task_id": "task_core"}
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _province_query(fields, *, parameters=None, object_=None):
    return {
        "topic": "G01",
        "object": deepcopy(object_ or {"type": "province", "province_id": PROVINCE_ID}),
        "fields": list(fields),
        "parameters": deepcopy(parameters or {}),
    }


def _task_query(*, parameters=None, country="FRA", object_type="country"):
    object_ = {"type": object_type, "country": country}
    if object_type == "province":
        object_ = {"type": "province", "province_id": PROVINCE_ID}
    return _province_query(["task_targets"], parameters=parameters, object_=object_)


def _make_service(tmp_path, monkeypatch, *, clock=None, mission_read_scope=False):
    # This existing fixture includes loaded-task membership, a selected task,
    # a prerequisite, a follow-up, and literal province rules in M03.
    _chain, missions, primary, mission_state, definitions = setup_mission_fixture()
    primary.state.current["game_sha256"] = GAME_SHA
    # MissionInformationSource binds a map scope index to the same effective
    # installation and mod stack as its definitions. The small existing M05
    # fixture omits those identity fields, so give both offline fixture sides
    # the same explicit paths and empty mod stack.
    game_root = Path(tmp_path) / "fixture-game-root"
    user_data = Path(tmp_path) / "fixture-user-data"
    definitions_context = definitions.context

    def bound_definitions_context():
        value = definitions_context()
        value.update(game_root=str(game_root), user_data=str(user_data), enabled_mods=[])
        return value

    definitions.context = bound_definitions_context
    scope_index = FakeScopeIndex({
        "183": province_scope("183", 183),
        "186": province_scope("186", 186),
    }, complete=True)
    scope_context = scope_index.context

    def bound_scope_context():
        value = scope_context()
        value.update(game_root=str(game_root), user_data=str(user_data), enabled_mods=[])
        return value

    scope_index.context = bound_scope_context
    missions.scope_index = scope_index
    captures = {"interests": [], "permanent_claims": [], "analysis": [],
                "original_reader": [], "rule_reader": []}
    missions.scheduling = True
    if mission_read_scope:
        original_reader = missions.reader

        def old_reader(country):
            captures["original_reader"].append(country)
            return original_reader(country)

        def rule_reader(country):
            captures["rule_reader"].append(country)
            return original_reader(country)

        scoped_reader = MissionScopedReader(old_reader, rule_reader)
        missions.reader = scoped_reader
    else:
        scoped_reader = None
    analysis = MissionAnalysisSource(missions)

    # Reuse the same live identity for the G01 adapters and bind their synthetic
    # native capture to a local installation path, as the existing source tests do.
    primary.session = SimpleNamespace(
        directory=Path(tmp_path),
        creation_filetime=CREATION,
        record={
            "session_id": primary.context()["session_id"],
            "creation_filetime": CREATION,
        },
    )

    def capture_interests(_installation, *, province_id, observer):
        captures["interests"].append((province_id, observer))
        return {"owner": "interests", "province_id": province_id, "observer": observer}

    def capture_permanent(_installation, *, province_id, observer):
        captures["permanent_claims"].append((province_id, observer))
        return {"owner": "permanent_claims", "province_id": province_id,
                "observer": observer}

    interests_capture = SimpleNamespace(
        PROFILE_SHA256="a" * 64,
        validate_capture=lambda report, context, creation, province_id: (
            report.get("owner") == "interests"
            and report.get("province_id") == province_id
            and report.get("observer") == "FRA"
            and context.get("observer") == "FRA"
            and creation == CREATION
        ),
        project_fields=lambda _report: {
            "cores": {"status": "known", "value": ["FRA"]},
            "claims": {"status": "known", "value": ["BUR"]},
        },
    )
    permanent_capture = SimpleNamespace(
        PROFILE_SHA256="b" * 64,
        validate_capture=lambda report, context, creation, province_id: (
            report.get("owner") == "permanent_claims"
            and report.get("province_id") == province_id
            and report.get("observer") == "FRA"
            and context.get("observer") == "FRA"
            and creation == CREATION
        ),
        project_fields=lambda _report: {
            "permanent_claims": {"status": "known", "value": ["ENG"]},
        },
    )
    monkeypatch.setattr(interests_module, "import_module",
                        lambda _name, _package: interests_capture)
    monkeypatch.setattr(permanent_module, "import_module",
                        lambda _name, _package: permanent_capture)

    original_analysis_read = analysis.read

    def record_analysis_read(query, context=None):
        captures["analysis"].append(deepcopy(query))
        return original_analysis_read(query, context)

    analysis.read = record_analysis_read

    interests = NativeProvinceInterestsSource(primary, capture=capture_interests)
    permanent_claims = NativeProvincePermanentClaimsSource(
        primary, capture=capture_permanent,
    )
    task_targets = ProvinceTaskTargetsSource(analysis)
    composite = CompositeSource(primary, [interests, permanent_claims, task_targets])
    service_source = (MissionReadSource(composite, scoped_reader)
                      if scoped_reader is not None else composite)
    service = InformationService(
        service_source,
        Path(tmp_path) / "g01-task-targets.sqlite3",
        clock=clock,
    )
    return service, composite, primary, mission_state, captures


def _task_field(result):
    return result["items"][0]["fields"]["task_targets"]


def _assert_real_task_projection(field):
    assert field["status"] == "known"
    assert field["complete"] is False
    value = field["value"]
    assert value["schema"] == "information.g01_task_targets.v1"
    assert value["selector"] == SELECTOR
    assert value["runtime_conditions_evaluated"] is False
    assert value["full_target_set_resolved"] is False
    assert value["actual_target_set"] == "unknown"

    core_rule = next(
        row for row in value["rules"]
        if row["root_id"] == "root_main"
        and row["task_id"] == "task_core"
        and row["target_field"] == "provinces"
    )
    assert core_rule["mission_role"] == "selected"
    assert 186 in core_rule["province_ids"]
    assert core_rule["rule"]["literal_value"] == 186


def test_three_live_g01_owners_share_optional_selector_and_keep_legacy_queries(
        tmp_path, monkeypatch):
    service, composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch,
    )
    try:
        schemas = [adapter.catalog()[0]["parameters"] for adapter in composite.adapters]
        assert schemas[0] == schemas[1] == schemas[2]
        assert {"root_id", "task_id"} <= set(schemas[0]["properties"])
        assert not schemas[0].get("required")
        assert schemas[0]["additionalProperties"] is False

        result = service.query(
            "g01-legacy-province-fields",
            queries=[_province_query(["cores", "claims", "permanent_claims"])],
        )
        fields = result["items"][0]["fields"]
        assert {name: field["status"] for name, field in fields.items()} == {
            "cores": "known", "claims": "known", "permanent_claims": "known",
        }
        assert result["items"][0]["query"]["parameters"] == {}
        assert captures["interests"] == [(PROVINCE_ID, "FRA")]
        assert captures["permanent_claims"] == [(PROVINCE_ID, "FRA")]
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_task_selector_is_required_and_invalid_or_unknown_input_never_becomes_targets(
        tmp_path, monkeypatch):
    service, _composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch,
    )
    try:
        for index, parameters in enumerate((
            {},
            {"root_id": "root_main"},
            {"task_id": "task_core"},
            {"root_id": "root_main", "task_id": "bad/task"},
            {"root_id": "root_main", "task_id": "task_core", "extra": True},
        )):
            with pytest.raises(InformationError):
                service.query(
                    f"g01-invalid-task-selector-{index}",
                    queries=[_task_query(parameters=parameters)],
                )

        assert captures["analysis"] == []
        assert mission_state.calls == 0

        unknown = service.query(
            "g01-unloaded-task-selector",
            queries=[_task_query(parameters={
                "root_id": "root_main", "task_id": "not_loaded",
            })],
        )
        field = _task_field(unknown)
        assert field["status"] == "unknown"
        assert "value" not in field
        # The selector is syntactically valid, so M05 checks captured membership
        # and returns an explicit unknown rather than creating an empty target set.
        assert len(captures["analysis"]) == 1
        assert mission_state.calls == 1
    finally:
        service.close()


def test_mixed_country_query_preserves_selector_across_all_g01_owners(
        tmp_path, monkeypatch):
    service, _composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch,
    )
    try:
        query = _province_query(
            ["cores", "claims", "permanent_claims", "task_targets"],
            parameters=SELECTOR,
            object_={"type": "country", "country": "FRA"},
        )
        result = service.query("g01-mixed-task-and-province-fields", queries=[query])
        item = result["items"][0]

        assert item["query"]["parameters"] == SELECTOR
        assert item["fields"]["cores"]["status"] == "unknown"
        assert item["fields"]["claims"]["status"] == "unknown"
        assert item["fields"]["permanent_claims"]["status"] == "unknown"
        _assert_real_task_projection(item["fields"]["task_targets"])
        assert captures["interests"] == []
        assert captures["permanent_claims"] == []
        assert captures["analysis"] == [{
            "topic": "M05",
            "object": {"type": "country", "country": "FRA"},
            "fields": ["linked_targets"],
            "parameters": SELECTOR,
        }]
        assert mission_state.calls == 1
    finally:
        service.close()


def test_province_task_targets_are_not_applicable_without_reading_missions(
        tmp_path, monkeypatch):
    service, _composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch,
    )
    try:
        result = service.query(
            "g01-province-task-targets",
            queries=[_task_query(parameters=SELECTOR, object_type="province")],
        )
        field = _task_field(result)
        assert field["status"] == "not_applicable"
        assert field["reason"] == "OBJECT_TYPE_NOT_SUPPORTED_BY_ADAPTER"
        assert "value" not in field
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_country_observer_mismatch_is_rejected_before_mission_read(
        tmp_path, monkeypatch):
    service, _composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch,
    )
    try:
        try:
            rejected = service.query(
                "g01-task-targets-wrong-country",
                queries=[_task_query(parameters=SELECTOR, country="ENG")],
            )
        except InformationError as error:
            assert error.code == "observer_scope_mismatch"
        else:
            # The service may reject at query normalization or return the
            # per-owner scope failure from CompositeSource; both must stop
            # before invoking MissionAnalysisSource.
            field = _task_field(rejected)
            assert field["status"] == "unavailable"
            assert field["reason"] == "observer_scope_mismatch"
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_mission_read_wrapper_opens_rule_capture_only_for_g01_task_targets(
        tmp_path, monkeypatch):
    service, _composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch, mission_read_scope=True,
    )
    try:
        legacy = service.query(
            "g01-core-does-not-open-mission-collection",
            queries=[_province_query(["cores"])],
        )
        assert legacy["items"][0]["fields"]["cores"]["status"] == "known"
        assert "mission_collection" not in legacy["items"][0]["source"]
        assert captures["original_reader"] == []
        assert captures["rule_reader"] == []
        assert captures["analysis"] == []

        task = service.query(
            "g01-task-targets-opens-rule-collection",
            queries=[_task_query(parameters=SELECTOR)],
        )
        _assert_real_task_projection(_task_field(task))
        collection = task["items"][0]["source"]["mission_collection"]
        assert collection["state_reader_calls"] == 1
        assert collection["shared_state_hits"] == 0
        assert collection["cross_request_cache"] is False
        assert captures["rule_reader"] == ["FRA"]
        assert captures["original_reader"] == []
        assert len(captures["analysis"]) == 1
        assert captures["analysis"][0]["fields"] == ["linked_targets"]
        assert mission_state.calls == 1
    finally:
        service.close()


def test_task_targets_work_in_manual_report_and_periodic_collection(
        tmp_path, monkeypatch):
    now = [100.0]
    service, composite, _primary, mission_state, captures = _make_service(
        tmp_path, monkeypatch, clock=lambda: now[0],
    )
    try:
        query = _task_query(parameters=SELECTOR)
        topic = next(entry for entry in composite.catalog() if entry["topic_id"] == "G01")
        assert {"cores", "claims", "permanent_claims", "task_targets"} <= set(topic["fields"])
        assert "query" in topic["triggers"]
        assert "periodic" in topic["triggers"]
        assert "periodic" in topic["fields"]["task_targets"]["triggers"]

        manual = service.query("g01-task-targets-manual", queries=[query])
        _assert_real_task_projection(_task_field(manual))

        report = service.manage_report(
            "g01-task-targets-report-create",
            "create",
            config={"name": "G01 task targets", "queries": [query], "detail": "full"},
        )["report"]
        report_result = service.query(
            "g01-task-targets-report-read", report_id=report["id"],
        )
        _assert_real_task_projection(_task_field(report_result))

        subscription = service.manage_subscription(
            "g01-task-targets-periodic-create",
            "create",
            config={
                "kind": "periodic",
                "report_id": report["id"],
                "enabled": True,
                "schedule": {
                    "basis": "real", "every": 1, "unit": "seconds",
                    "missed": "coalesce",
                },
            },
        )["subscription"]
        assert subscription["state"] == "active"

        # First tick establishes the due point. The next tick exercises the
        # periodic collection path through the same CompositeSource owner.
        assert service.tick()["results"] == []
        now[0] += 1.0
        tick = service.tick()
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["subscription_id"] == subscription["id"]
        _assert_real_task_projection(_task_field(periodic))

        assert len(captures["analysis"]) == 3
        assert all(call["fields"] == ["linked_targets"] for call in captures["analysis"])
        assert mission_state.calls == 3
    finally:
        service.close()
