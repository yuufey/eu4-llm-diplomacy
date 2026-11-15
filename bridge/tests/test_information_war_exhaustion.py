"""W04 war exhaustion is a narrow view over the N04 country reader."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.catalog import get_topic, list_topics, validate_query as validate_global_query
from bridge.information.composite import CompositeSource
from bridge.information.domestic_pressure import NativeDomesticPressureSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.war_exhaustion import NativeWarExhaustionSource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CAPTURE_SHA256 = "9f" * 32


def _context(**changes):
    value = {
        "status": "ready", "complete": True, "mode": "live",
        "observer": "FRA", "session_id": "war-exhaustion-session",
        "game_sha256": GAME_SHA256, "game_version": "1.37.4",
        "game_date": 56556984, "world_id": "world-001",
        "dll_sha256": "a1" * 32, "world_generation": 7,
        "physical_client_country": "POR",
    }
    value.update(changes)
    return value


def _field(raw=0):
    return {
        "status": "known", "value": raw, "raw": raw,
        "raw_hex": int(raw).to_bytes(4, "little", signed=True).hex(),
        "unit": "war_exhaustion", "scale": 1000,
    }


def _query(field="war_exhaustion", *, object_type="country", country="FRA"):
    obj = {"type": object_type}
    if object_type == "country":
        obj["country"] = country
    elif object_type == "war":
        obj["war_id"] = "war_0123456789abcdef_01234567"
    return {"topic": "W04", "object": obj, "fields": [field], "parameters": {}}


class _Pressure:
    """A small N04-shaped seam; values remain explicitly owned by this fake."""

    def __init__(self, *, context=None, field=None, extra_fields=None,
                 source_extra=None, context_after_read=None, upstream_complete=True,
                 sequence=None):
        self._context = _context() if context is None else deepcopy(context)
        self.field = deepcopy(_field() if field is None else field)
        self.extra_fields = deepcopy(extra_fields or {})
        self.source_extra = deepcopy(source_extra or {})
        self.context_after_read = deepcopy(context_after_read)
        self.upstream_complete = upstream_complete
        self.sequence = deepcopy(sequence)
        self.validate_calls = []
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def validate_query(self, query, context=None):
        normalized = validate_global_query(query, context)
        assert normalized["topic"] == "N04"
        if normalized["object"].get("country") != "FRA":
            raise InformationError("observer_scope_mismatch", "fake N04 reader only admits FRA")
        assert normalized["fields"] == ["war_exhaustion"]
        self.validate_calls.append(deepcopy(normalized))
        return normalized

    def read(self, query, context=None):
        normalized = self.validate_query(query, context)
        self.read_calls.append((deepcopy(normalized), deepcopy(context)))
        current = self._context if context is None else context
        if self.sequence:
            index = min(len(self.read_calls) - 1, len(self.sequence) - 1)
            field = deepcopy(self.sequence[index])
        else:
            field = deepcopy(self.field)
        fields = {"war_exhaustion": field, **deepcopy(self.extra_fields)}
        upstream = {
            "objects": [deepcopy(normalized["object"])],
            "game_date": current.get("game_date"),
            "fields": fields,
            "complete": self.upstream_complete,
            "source": {
                "name": "NativeDomesticPressureSource",
                "mode": current.get("mode"), "status": current.get("status"),
                "observer": current.get("observer"), "session_id": current.get("session_id"),
                "complete": self.upstream_complete,
                "provenance": {"capture_report_sha256": CAPTURE_SHA256,
                               "private_trace": "must not cross W04", **self.source_extra},
            },
        }
        if self.context_after_read is not None:
            self._context.update(deepcopy(self.context_after_read))
        return upstream

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class _Primary:
    event_types = ()

    def __init__(self, pressure):
        self.pressure = pressure

    def context(self):
        return self.pressure.context()

    def catalog(self):
        return list_topics()

    def validate_query(self, query):
        return validate_global_query(query, self.context())

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


def _build(*, field=None, **kwargs):
    pressure = _Pressure(field=field, **kwargs)
    adapter = NativeWarExhaustionSource(pressure)
    return adapter, pressure


def _assert_no_private(value):
    forbidden = {"private_trace", "stability", "corruption", "raw_payload", "module_base",
                 "country_pointer", "runtime_code_guard", "raw_reads"}
    if isinstance(value, dict):
        assert not (set(value) & forbidden)
        for child in value.values():
            _assert_no_private(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_private(child)


def test_catalog_is_one_partial_country_field_and_composite_preserves_global_w04():
    adapter, _ = _build()
    own = adapter.catalog()[0]
    assert own["topic_id"] == "W04"
    assert list(own["fields"]) == ["war_exhaustion"]
    assert own["fields"]["war_exhaustion"]["coverage"] == "partial"
    assert own["fields"]["war_exhaustion"]["complete"] is False
    assert own["fields"]["war_exhaustion"]["supported_object_types"] == ["country"]
    assert own["fields"]["war_exhaustion"]["complete"] is False
    assert own["object_types"] == ["war", "country"]
    assert own["triggers"] == ["query", "periodic", "change"]
    assert own["change_detection"] == "sampled_state_comparison_not_lossless_events"
    composite = CompositeSource(_Primary(adapter.domestic_pressure_source), [adapter])
    topic = next(item for item in composite.catalog() if item["topic_id"] == "W04")
    assert set(topic["fields"]) == {"war_exhaustion", "contribution", "land_commitment", "exit_risk"}
    assert topic["fields"]["war_exhaustion"]["coverage"] == "partial"


@pytest.mark.parametrize("raw", [0, -1250, 2400])
def test_country_query_delegates_one_n04_read_and_preserves_signed_raw(raw):
    adapter, pressure = _build(field=_field(raw))
    context = pressure.context()
    result = adapter.read(_query(), context)
    assert len(pressure.validate_calls) == 2  # W04 validation and delegated N04 validation only.
    assert len(pressure.read_calls) == 1
    mapped = pressure.read_calls[0][0]
    assert mapped == {"topic": "N04", "object": {"type": "country", "country": "FRA"},
                      "fields": ["war_exhaustion"], "parameters": {}}
    assert result["fields"]["war_exhaustion"] == {
        "status": "known", "value": raw, "raw": raw,
        "raw_hex": int(raw).to_bytes(4, "little", signed=True).hex(),
        "unit": "war_exhaustion", "scale": 1000, "period": "current", "complete": True,
    }
    assert result["complete"] is True
    assert result["source"]["provenance"]["capture_report_sha256"] == CAPTURE_SHA256
    assert result["source"]["provenance"]["upstream_source"]["name"] == "NativeDomesticPressureSource"
    _assert_no_private(result)


@pytest.mark.parametrize("status", ["unknown", "unavailable"])
def test_upstream_nonknown_status_and_safe_reason_are_preserved(status):
    adapter, pressure = _build(field={"status": status, "reason": "DOMESTIC_PRESSURE_CAPTURE_UNAVAILABLE"})
    result = adapter.read(_query(), pressure.context())
    assert result["fields"]["war_exhaustion"] == {
        "status": status, "reason": "DOMESTIC_PRESSURE_CAPTURE_UNAVAILABLE"}
    assert len(pressure.read_calls) == 1


@pytest.mark.parametrize("mutation", [
    {"raw_hex": "01020304"},
    {"raw": True},
    {"unit": "ducats"},
    {"scale": True},
])
def test_malformed_known_upstream_field_is_safely_retracted(mutation):
    bad = dict(_field(-25), **mutation)
    adapter, pressure = _build(field=bad)
    result = adapter.read(_query(), pressure.context())
    item = result["fields"]["war_exhaustion"]
    assert item["status"] == "unavailable"
    assert item["reason"] == "WAR_EXHAUSTION_UPSTREAM_READ_INVALID"
    assert "value" not in item


def test_war_view_and_planned_fields_never_capture_n04():
    adapter, pressure = _build()
    war = adapter.read(_query(object_type="war"), pressure.context())
    assert war["fields"]["war_exhaustion"] == {
        "status": "unsupported", "reason": "WAR_PARTICIPANT_WAR_EXHAUSTION_NOT_IMPLEMENTED"}
    planned = adapter.read({"topic": "W04", "object": {"type": "country", "country": "FRA"},
                            "fields": ["contribution"], "parameters": {}}, pressure.context())
    assert planned["fields"]["contribution"]["status"] == "unsupported"
    assert pressure.read_calls == []


def test_invalid_or_foreign_selectors_do_not_capture():
    adapter, pressure = _build()
    for query in (
        _query(country="ENG"),
        {"topic": "W04", "object": {"type": "war"}, "fields": ["war_exhaustion"], "parameters": {}},
        {**_query(), "parameters": {"recipient": "ENG"}},
        {"topic": "W04", "object": {"type": "country", "country": "FRA"},
         "fields": ["not_a_w04_field"], "parameters": {}},
    ):
        with pytest.raises(InformationError):
            adapter.validate_query(query, pressure.context())
    assert not pressure.read_calls


def test_context_mismatch_or_drift_retracts_field():
    adapter, pressure = _build()
    stale = pressure.context()
    pressure._context["game_date"] += 1
    mismatched = adapter.read(_query(), stale)
    assert mismatched["fields"]["war_exhaustion"]["status"] == "unavailable"
    assert not pressure.read_calls

    adapter, pressure = _build(context_after_read={"game_date": 56556985})
    result = adapter.read(_query(), pressure.context())
    assert result["fields"]["war_exhaustion"] == {
        "status": "unavailable", "reason": "WAR_EXHAUSTION_CONTEXT_CHANGED_DURING_READ"}


def test_known_upstream_scalar_without_complete_sample_stays_incomplete():
    adapter, pressure = _build(field=_field(125), upstream_complete=False)
    result = adapter.read(_query(), pressure.context())
    assert result["fields"]["war_exhaustion"]["status"] == "known"
    assert result["fields"]["war_exhaustion"]["complete"] is False
    assert result["complete"] is False


def test_upstream_extras_and_provenance_are_whitelisted():
    adapter, pressure = _build(extra_fields={"stability": _field(1)},
                               source_extra={"raw_reads": ["private"], "secret": "private"})
    result = adapter.read(_query(), pressure.context())
    _assert_no_private(result)
    assert result["fields"].keys() == {"war_exhaustion"}
    assert result["source"]["provenance"]["capture_report_sha256"] == CAPTURE_SHA256
    assert "secret" not in result["source"]["provenance"]


def test_direct_report_and_independent_two_and_five_second_periodics(tmp_path: Path):
    adapter, pressure = _build(field=_field(-1250))
    composite = CompositeSource(_Primary(pressure), [adapter])
    now = [100.0]
    service = InformationService(composite, tmp_path / "war-exhaustion.sqlite3", clock=lambda: now[0])
    query = _query()
    try:
        direct = service.query("war-exhaustion-direct", queries=[query])
        report = service.manage_report(
            "war-exhaustion-report-create", "create",
            config={"name": "current exhaustion", "queries": [query]},
        )["report"]
        rendered = service.query("war-exhaustion-report-read", report_id=report["id"])
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        expected = direct["items"][0]["fields"]["war_exhaustion"]
        assert expected["raw"] == -1250 and expected["complete"] is True
        ids = {}
        for seconds in (2, 5):
            created = service.manage_subscription(
                f"war-exhaustion-sub-{seconds}", "create",
                config={"name": f"{seconds}s exhaustion", "kind": "periodic",
                        "report_id": report["id"],
                        "schedule": {"basis": "real", "unit": "seconds", "every": seconds,
                                     "missed": "coalesce"}},
            )["subscription"]
            ids[seconds] = created["id"]
        now[0] = 102.0
        tick2 = service.tick()
        assert len(tick2["results"]) == 1
        assert tick2["results"][0]["items"][0]["fields"]["war_exhaustion"] == expected
        service.manage_subscription("war-exhaustion-cancel-2", "cancel",
                                    subscription_id=ids[2], expected_version=1)
        now[0] = 105.0
        tick5 = service.tick()
        assert len(tick5["results"]) == 1
        assert tick5["results"][0]["items"][0]["fields"]["war_exhaustion"] == expected
        service.manage_subscription("war-exhaustion-cancel-5", "cancel",
                                    subscription_id=ids[5], expected_version=1)
    finally:
        service.close()


def test_change_sampling_reports_only_complete_scalar_changes(tmp_path: Path):
    pressure = _Pressure(sequence=[_field(100), _field(250)])
    adapter = NativeWarExhaustionSource(pressure)
    now = [100.0]
    service = InformationService(CompositeSource(_Primary(pressure), [adapter]),
                                tmp_path / "war-exhaustion-change.sqlite3", clock=lambda: now[0])
    query = _query()
    try:
        report = service.manage_report(
            "war-exhaustion-change-report", "create",
            config={"name": "exhaustion change", "queries": [query]},
        )["report"]
        sub = service.manage_subscription(
            "war-exhaustion-change-sub", "create",
            config={"kind": "change", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds", "every": 2}},
        )["subscription"]
        now[0] = 102.0
        first = service.tick()
        assert first["results"] == []
        runtime = service._runtime(sub["id"])
        assert runtime["last_attempt"]["status"] == "baseline_created"
        now[0] = 104.0
        second = service.tick()
        assert len(second["results"]) == 1
        assert second["results"][0]["items"][0]["fields"]["war_exhaustion"]["raw"] == 250
        service.manage_subscription("war-exhaustion-change-cancel", "cancel",
                                    subscription_id=sub["id"], expected_version=1)
    finally:
        service.close()


def test_change_sampling_does_not_baseline_an_incomplete_upstream_sample(tmp_path: Path):
    pressure = _Pressure(field=_field(100), upstream_complete=False)
    adapter = NativeWarExhaustionSource(pressure)
    now = [100.0]
    service = InformationService(CompositeSource(_Primary(pressure), [adapter]),
                                tmp_path / "war-exhaustion-change-incomplete.sqlite3",
                                clock=lambda: now[0])
    query = _query()
    try:
        report = service.manage_report(
            "war-exhaustion-incomplete-report", "create",
            config={"name": "incomplete exhaustion", "queries": [query]},
        )["report"]
        sub = service.manage_subscription(
            "war-exhaustion-incomplete-sub", "create",
            config={"kind": "change", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds", "every": 2}},
        )["subscription"]
        now[0] = 102.0
        assert service.tick()["results"] == []
        assert service._runtime(sub["id"])["last_attempt"]["status"] == "read_failed_baseline_preserved"
        now[0] = 104.0
        assert service.tick()["results"] == []
        assert service._runtime(sub["id"])["last_attempt"]["status"] == "read_failed_baseline_preserved"
        service.manage_subscription("war-exhaustion-incomplete-cancel", "cancel",
                                    subscription_id=sub["id"], expected_version=1)
    finally:
        service.close()


def test_live_factory_shares_n04_reader_and_recorded_factory_does_not_add_w04(tmp_path: Path):
    from tools.serve_information import _build_runtime, build_parser

    args = build_parser().parse_args(["--observer", "FRA", "--database", str(tmp_path / "live.sqlite")])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        adapters = service.source.adapters
        pressure = next(item for item in adapters if isinstance(item, NativeDomesticPressureSource))
        war = next(item for item in adapters if isinstance(item, NativeWarExhaustionSource))
        assert war.domestic_pressure_source is pressure
    finally:
        service.close()

    archive = tmp_path / "recorded.json"
    archive.write_text("{}", encoding="utf-8")
    recorded_args = build_parser().parse_args([
        "--recorded-manifest", str(archive), "--database", str(tmp_path / "recorded.sqlite")])
    recorded, journal = _build_runtime(recorded_args)
    try:
        assert journal is None
        assert type(recorded.source).__name__ == "RecordedSource"
        assert not any(isinstance(item, NativeWarExhaustionSource)
                       for item in getattr(recorded.source, "adapters", ()))
    finally:
        recorded.close()


def test_opinion_empire_and_mission_save_factories_do_not_add_live_w04(tmp_path: Path, monkeypatch):
    from bridge.information import (
        cwtools_script, mission_definitions, mission_scope_index,
        missions, saved_empire_v2, saved_missions, saved_opinions,
    )
    from tools.serve_information import _build_runtime, build_parser

    class Snapshot:
        def context(self):
            return {
                "status": "ready", "complete": True, "mode": "recorded",
                "observer": "FRA", "country": "FRA", "session_id": None,
                "version": "1.37.4", "game_version": "1.37.4",
                "game_date": 56556984, "game_day": None,
                "archive": {"player": "POR", "sha256": "a" * 64},
                "parser": {"snapshot_schema": "test"},
            }

    class MissionCatalogAdapter:
        scheduling = False

        def catalog(self):
            topic = get_topic("M04")
            topic.update(
                status="available",
                source="MissionInformationSource",
                context_scope="country_scope",
                observer_roles=["country"],
                object_types=["country"],
                triggers=["query"],
                supported_versions=["1.37.4"],
            )
            return [topic]

        def read(self, *_args, **_kwargs):
            raise AssertionError("saved factory test must not read live mission state")

    dummy_snapshot = Snapshot()
    monkeypatch.setattr(saved_opinions, "SavedOpinionSnapshot",
                        lambda *args, **kwargs: dummy_snapshot)
    monkeypatch.setattr(saved_empire_v2, "SavedEmpireSnapshotV2",
                        lambda *args, **kwargs: dummy_snapshot)
    monkeypatch.setattr(saved_missions, "SavedMissionSnapshot",
                        lambda *args, **kwargs: dummy_snapshot)
    monkeypatch.setattr(cwtools_script, "CwtoolsScriptParser", lambda *args, **kwargs: object())
    monkeypatch.setattr(mission_definitions, "MissionDefinitionIndex",
                        lambda *args, **kwargs: object())
    monkeypatch.setattr(mission_scope_index, "StaticMissionScopeIndex",
                        lambda *args, **kwargs: object())
    monkeypatch.setattr(missions, "MissionInformationSource",
                        lambda *args, **kwargs: MissionCatalogAdapter())

    class ForbiddenNativeMissionReader:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("saved mission factory must not construct a live reader")

    monkeypatch.setattr(missions, "NativeMissionReader", ForbiddenNativeMissionReader)

    configurations = [
        ["--opinion-save", str(tmp_path / "opinion.eu4"), "--observer", "FRA"],
        ["--empire-save", str(tmp_path / "empire.eu4"), "--observer", "FRA"],
        ["--mission-game-data", "--mission-save", str(tmp_path / "missions.eu4"),
         "--observer", "FRA"],
    ]
    for index, values in enumerate(configurations):
        args = build_parser().parse_args(values + ["--database", str(tmp_path / f"saved-{index}.sqlite")])
        service, journal = _build_runtime(args)
        try:
            assert journal is None
            assert not any(isinstance(item, NativeWarExhaustionSource)
                           for item in getattr(service.source, "adapters", ()))
        finally:
            service.close()
