"""Recorded N06/R02 adapters wired through the information service."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import types
from types import SimpleNamespace

from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.service import InformationService
from bridge.information.subject_relations import NativeSubjectRelationSource
from tools.serve_information import _build_runtime, build_parser


FIXTURE = (Path(__file__).parent / "fixtures" /
           "information_country_relations_live_1374.json")
FIXTURE_DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))


def _context() -> dict:
    recorded = deepcopy(FIXTURE_DATA["original_context"])
    recorded.update({
        "status": "ready",
        "mode": "live",
        "complete": True,
        "game_date_raw": recorded["game_date"],
        "world_id": "world-a",
        "paused": True,
    })
    return recorded


class _RecordedInspector:
    """Replay only the public read projections in the recorded fixture."""

    def __init__(self, *, failures=()):
        self.failures = set(failures)
        self.calls: list[tuple] = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase, parameters):
        self.calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        if recipient in self.failures:
            raise RuntimeError("recorded source failure")
        capture = FIXTURE_DATA["captures"].get(recipient)
        if capture is None:
            raise AssertionError(f"fixture has no recorded pair for {recipient}")
        return deepcopy(capture["public"])


class _RecordedPrimary:
    """Minimal primary source; native adapters remain the real sources under test."""

    event_types: tuple[str, ...] = ()

    def __init__(self, *, failures=()):
        self.diplomacy_tools = _RecordedInspector(failures=failures)
        self._context = _context()

    def context(self) -> dict:
        return deepcopy(self._context)

    def catalog(self) -> list[dict]:
        return list_topics()

    def read(self, query, context):  # pragma: no cover - adapters own both routes
        raise AssertionError(f"primary should not receive routed query {query['topic']}")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor or {}, "complete": True, "gaps": []}


def _source(*, failures=()) -> tuple[CompositeSource, _RecordedPrimary]:
    primary = _RecordedPrimary(failures=failures)
    source = CompositeSource(primary, [
        NativeCountryStateSource(primary),
        NativeSubjectRelationSource(primary),
    ])
    return source, primary


def _n06(*, country="FRA", recipient="PAP", fields=None) -> dict:
    return {
        "topic": "N06",
        "object": {"type": "country", "country": country},
        "fields": fields or ["prestige"],
        "parameters": {"reference_recipient": recipient},
    }


def _r02(recipient, *, fields=None) -> dict:
    return {
        "topic": "R02",
        "object": {"type": "country_pair", "actor": "FRA", "recipient": recipient},
        "fields": fields or ["overlord", "subject", "subject_type"],
        "parameters": {},
    }


def test_recorded_fixture_provenance_and_discovery_keep_both_native_topics(tmp_path):
    assert FIXTURE_DATA["provenance"]["mode"] == "recorded"
    assert FIXTURE_DATA["provenance"]["original_mode"] == "live"
    assert FIXTURE_DATA["provenance"]["business_actions_submitted"] is False
    assert FIXTURE_DATA["provenance"]["date_advance"] is False
    assert FIXTURE_DATA["provenance"]["save_or_reload"] is False

    source, _ = _source()
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        topics = {item["topic_id"]: item for item in service.discover()["topics"]}
        assert topics["N06"]["status"] == "available"
        assert topics["R02"]["status"] == "available"
        assert topics["N06"]["fields"]["prestige"]["scale"] == 1000
        assert topics["R02"]["fields"]["permissions"]["coverage"] == "planned"
        assert topics["R02"]["fields"]["overlord"]["paths"] == [
            "actor", "recipient", "actor_is_overlord", "actor_is_subject"
        ]
        assert topics["R02"]["fields"]["overlord"]["derivation"] == (
            "selected_pair_endpoint_from_verified_role_flags"
        )
    finally:
        service.close()


def test_service_mixes_n06_raw_prestige_and_orl_appanage_with_partial_permissions(tmp_path):
    source, primary = _source()
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        result = service.query("n06-and-orl", queries=[
            _n06(recipient="ORL"),
            _r02("ORL", fields=["overlord", "subject", "subject_type", "permissions"]),
        ])
        assert result["status"] == "partial"
        n06, r02 = result["items"]
        assert n06["complete"] is True
        assert n06["fields"]["prestige"] == {
            "status": "known", "value": -11643, "unit": "prestige", "scale": 1000
        }
        assert r02["complete"] is False
        assert r02["fields"]["overlord"]["status"] == "known"
        assert r02["fields"]["overlord"]["value"] == "FRA"
        assert r02["fields"]["subject"]["status"] == "known"
        assert r02["fields"]["subject"]["value"] == "ORL"
        assert r02["fields"]["subject_type"]["status"] == "known"
        assert r02["fields"]["subject_type"]["value"] == "appanage"
        assert r02["fields"]["permissions"] == {
            "status": "unsupported", "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER"
        }
        assert primary.diplomacy_tools.calls == [
            ("offer_vassalization", "FRA", "ORL", "initiate", {}),
            ("offer_vassalization", "FRA", "ORL", "initiate", {}),
        ]
    finally:
        service.close()


def test_service_reports_pap_pair_not_applicable_as_complete(tmp_path):
    source, _ = _source()
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        result = service.query("pap-no-relation", queries=[_r02("PAP")])
        item = result["items"][0]
        assert result["status"] == "complete"
        assert result["complete"] is True
        assert item["complete"] is True
        assert set(item["fields"]) == {"overlord", "subject", "subject_type"}
        assert all(value["status"] == "not_applicable"
                   for value in item["fields"].values())
        assert all(value["reason"] == "SELECTED_PAIR_HAS_NO_VASSAL_RELATION"
                   for value in item["fields"].values())
    finally:
        service.close()


def test_one_native_source_failure_does_not_erase_other_adapter_result(tmp_path):
    source, primary = _source(failures={"PAP"})
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        result = service.query("country-fails-subject-survives", queries=[
            _n06(recipient="PAP"), _r02("ORL")
        ])
        assert result["status"] == "partial"
        country_item, relation_item = result["items"]
        assert country_item["complete"] is False
        assert country_item["fields"]["prestige"] == {
            "status": "unavailable", "reason": "INSPECT_CALL_FAILED:RuntimeError",
            "unit": "prestige", "scale": 1000,
        }
        assert relation_item["complete"] is True
        assert relation_item["fields"]["subject_type"]["status"] == "known"
        assert relation_item["fields"]["subject_type"]["value"] == "appanage"
        assert [call[2] for call in primary.diplomacy_tools.calls] == ["PAP", "ORL"]
    finally:
        service.close()


def test_scope_mismatch_keeps_in_scope_relation_and_does_not_read_foreign_country(tmp_path):
    source, primary = _source()
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        result = service.query("scope-isolation", queries=[
            _n06(country="ENG", recipient="PAP"), _r02("ORL")
        ])
        assert result["status"] == "partial"
        foreign_country, relation_item = result["items"]
        assert foreign_country["complete"] is False
        assert foreign_country["fields"]["prestige"] == {
            "status": "unavailable", "reason": "observer_scope_mismatch"
        }
        assert relation_item["complete"] is True
        assert relation_item["fields"]["overlord"]["status"] == "known"
        assert relation_item["fields"]["overlord"]["value"] == "FRA"
        assert [call[2] for call in primary.diplomacy_tools.calls] == ["ORL"]
    finally:
        service.close()


def test_serve_runtime_wires_both_native_adapters_without_game_access(tmp_path):
    args = SimpleNamespace(
        recorded_manifest=None,
        operator_session=None,
        observer=None,
        static_game_data=False,
        mission_game_data=False,
        static_game_root=None,
        static_user_data=None,
        mission_save=None,
        journal=None,
        database=tmp_path / "runtime.sqlite",
        owner="country-relations-test",
    )
    service, journal = _build_runtime(args)
    try:
        topics = {item["topic_id"]: item for item in service.discover()["topics"]}
        assert topics["N06"]["status"] == "available"
        assert topics["R02"]["status"] == "available"
        assert service.discover()["context"]["status"] == "unready"
        assert journal is None
    finally:
        service.close()


def test_serve_parser_exposes_explicit_battle_stream_opt_in(tmp_path):
    args = build_parser().parse_args(["--battle-stream", str(tmp_path / "battle.sqlite")])
    assert args.battle_stream == tmp_path / "battle.sqlite"


def test_serve_parser_exposes_explicit_battle_ingest_installation_opt_in(tmp_path):
    args = build_parser().parse_args([
        "--battle-stream", str(tmp_path / "battle-stream.json"),
        "--battle-ingest-installation", str(tmp_path / "installation.json"),
    ])
    assert args.battle_ingest_installation == tmp_path / "installation.json"


def test_serve_rejects_battle_ingest_without_battle_stream(tmp_path):
    args = build_parser().parse_args([
        "--battle-ingest-installation", str(tmp_path / "installation.json"),
    ])
    try:
        _build_runtime(args)
    except ValueError as error:
        assert str(error) == "--battle-ingest-installation requires --battle-stream"
    else:  # pragma: no cover - protects the CLI permission boundary
        raise AssertionError("battle ingestion must require the explicit source wrapper")


def test_serve_runtime_lazily_wraps_the_complete_source_when_opted_in(tmp_path, monkeypatch):
    calls = []

    class _BattleInformationSource:
        @classmethod
        def from_config(cls, primary, config_path):
            calls.append((primary, config_path))
            return primary

    module = types.ModuleType("bridge.information.battles")
    module.BattleInformationSource = _BattleInformationSource
    monkeypatch.setitem(sys.modules, "bridge.information.battles", module)

    args = SimpleNamespace(
        recorded_manifest=None,
        operator_session=None,
        observer=None,
        static_game_data=False,
        mission_game_data=False,
        static_game_root=None,
        static_user_data=None,
        mission_save=None,
        journal=None,
        database=tmp_path / "runtime.sqlite",
        owner="battle-stream-test",
        battle_stream=tmp_path / "battle.sqlite",
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert len(calls) == 1
        assert isinstance(calls[0][0], CompositeSource)
        assert calls[0][1] == args.battle_stream
    finally:
        service.close()


def test_serve_runtime_constructs_ingestor_only_after_battle_wrapper(tmp_path, monkeypatch):
    install = tmp_path / "installation.json"
    install.write_text("{}", encoding="utf-8")
    calls = []

    class _BattleInformationSource:
        @classmethod
        def from_config(cls, primary, config_path):
            primary.battles = types.SimpleNamespace(
                database=tmp_path / "stream.sqlite",
                binding={
                    "session_id": "battle-ingest-test",
                    "installation": "0000000000000001",
                    "generation": "0000000000000001",
                },
            )
            calls.append((primary, config_path))
            return primary

    module = types.ModuleType("bridge.information.battles")
    module.BattleInformationSource = _BattleInformationSource
    monkeypatch.setitem(sys.modules, "bridge.information.battles", module)

    args = SimpleNamespace(
        recorded_manifest=None,
        operator_session=None,
        observer=None,
        static_game_data=False,
        mission_game_data=False,
        static_game_root=None,
        static_user_data=None,
        mission_save=None,
        journal=None,
        database=tmp_path / "runtime.sqlite",
        owner="battle-ingest-test",
        battle_stream=tmp_path / "battle-stream.json",
        battle_ingest_installation=install,
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert len(calls) == 1
        assert service.battle_ingestor.database == (tmp_path / "stream.sqlite").resolve()
        assert service.battle_ingestor.installation == install.resolve()
        assert service.source.ingestor is service.battle_ingestor
    finally:
        service.battle_ingestor.close()
        service.close()

