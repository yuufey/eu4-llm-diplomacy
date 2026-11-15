"""Offline R01 adapter tests using self-contained archived inspections."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.relation_state import NativeRelationSource
from bridge.information.service import InformationError, InformationService


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "bridge/tests/fixtures/information_relation_state_live_1374.json"
DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))
GAME_SHA = DATA["identity"]["game_sha256"]
FIELDS = ["relation_type", "status", "grantor", "recipient"]


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


def _context(**overrides) -> dict:
    value = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "dll_sha256": "d" * 64,
        "session_id": "relation-session",
        "game_date": 56553384,
        "game_date_raw": 56553384,
        "world_id": "relation-world",
        "paused": True,
    }
    value.update(overrides)
    return value


def _query(recipient: str, families: list[str] | None = None,
           fields: list[str] | None = None) -> dict:
    parameters = {} if families is None else {"relation_types": list(families)}
    return {
        "topic": "R01",
        "object": {"type": "country_pair", "actor": "FRA", "recipient": recipient},
        "fields": list(fields or FIELDS),
        "parameters": parameters,
    }


class RecordedInspector:
    """Replay only the fixture's actual native inspection objects."""

    def __init__(self, *, failures=(), overrides=None, mutate=None, on_call=None):
        self.failures = set(failures)
        self.overrides = dict(overrides or {})
        self.mutate = mutate
        self.on_call = on_call
        self.calls: list[tuple] = []
        self._by_key = {}
        for capture in DATA["captures"].values():
            query = capture["query"]
            self._by_key[(query["action_id"], query["recipient"])] = capture["inspection"]

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase, parameters):
        self.calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        if self.on_call is not None:
            self.on_call(action_id, actor, recipient)
        if action_id in self.failures:
            raise RuntimeError("recorded inspection failure")
        value = self.overrides.get((action_id, recipient))
        if value is None:
            value = self._by_key.get((action_id, recipient))
        if value is None:
            raise RuntimeError("fixture has no inspection for selected pair")
        value = deepcopy(value)
        if self.mutate is not None:
            self.mutate(action_id, recipient, value)
        return value


class RecordedPrimary:
    event_types: tuple[str, ...] = ()

    def __init__(self, *, context=None, inspector=None):
        self._context = deepcopy(context or _context())
        self.diplomacy_tools = inspector or RecordedInspector()
        self.catalog_entries: list[dict] = []

    def context(self) -> dict:
        return deepcopy(self._context)

    def catalog(self) -> list[dict]:
        return deepcopy(self.catalog_entries)

    def read(self, query, context):  # pragma: no cover - the R01 adapter owns the route
        raise AssertionError(f"primary should not receive R01 query: {query}")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor or {}, "complete": True, "gaps": []}


def _source(*, context=None, inspector=None) -> tuple[CompositeSource, RecordedPrimary, RecordedInspector]:
    inspector = inspector or RecordedInspector()
    primary = RecordedPrimary(context=context, inspector=inspector)
    adapter = NativeRelationSource(primary)
    # CompositeSource expects the primary catalog to declare the routable
    # topic before an adapter contributes its fields.  This mirrors the real
    # runtime catalog merge without adding a second production owner.
    primary.catalog_entries = adapter.catalog()
    return CompositeSource(primary, [adapter]), primary, inspector


def _item(result: dict, index: int = 0) -> dict:
    return result["items"][index]


def _family_value(item: dict, field: str, family: str) -> dict:
    values = item["fields"][field]["value"]
    return next(value for value in values if value["relation_type"] == family)


def test_fixture_is_self_contained_and_retains_real_source_pins() -> None:
    assert DATA["schema"] == "information_relation_state_live_fixture.v1"
    assert DATA["provenance"]["business_actions_submitted"] is False
    assert DATA["provenance"]["date_advance"] is False
    assert DATA["provenance"]["save_or_reload"] is False
    assert set(DATA["captures"]) == {
        "vassalization_ORL", "guarantee_SAV", "support_independence_SWE",
        "military_access_ARA", "rival_BUR", "rival_HAB", "royal_marriage_LAN",
    }
    for capture in DATA["captures"].values():
        assert capture["source"]["path"]
        assert capture["source"]["json_pointer"].startswith("/")
        assert len(capture["source"]["sha256"]) == 64
        assert isinstance(capture["inspection"], dict)
    assert DATA["captures"]["royal_marriage_LAN"]["inspection"].get("relationship_state") is None
    assert DATA["captures"]["rival_BUR"]["inspection"]["relationship_state"] == {
        "rival_active": True,
        "rival_since_date_raw": DATA["captures"]["rival_BUR"]["inspection"]["relationship_state"]["rival_since_date_raw"],
        "complete": True,
    }


def test_catalog_and_composite_service_query_cover_all_real_family_samples(tmp_path) -> None:
    source, _primary, inspector = _source()
    service = InformationService(source, tmp_path / "relation-state.sqlite")
    try:
        topics = {entry["topic_id"]: entry for entry in service.discover()["topics"]}
        entry = topics["R01"]
        assert entry["status"] == "available"
        assert set(entry["fields"]) == set(FIELDS)
        assert entry["object_types"] == ["country_pair", "country"]
        assert entry["parameters"]["properties"]["relation_types"]["maxItems"] == 9
        assert entry["triggers"] == ["query", "periodic", "change"]

        queries = [
            _query("ORL", ["vassalization"]),
            _query("SAV", ["guarantee"]),
            _query("SWE", ["support_independence"]),
            _query("ARA", ["military_access"]),
            _query("BUR", ["rival"]),
        ]
        result = service.query("r01-real-family-samples", queries=queries)
        assert len(result["items"]) == len(queries)
        expected = {
            "ORL": ("vassalization", "active"),
            "SAV": ("guarantee", "inactive"),
            "SWE": ("support_independence", "inactive"),
            "ARA": ("military_access", "inactive"),
            "BUR": ("rival", "active"),
        }
        for item, recipient in zip(result["items"], expected):
            family, status = expected[recipient]
            assert _family_value(item, "relation_type", family) == {
                "relation_type": family, "status": "known", "value": family,
            }
            assert _family_value(item, "status", family) == {
                "relation_type": family, "status": "known", "value": status,
            }
            assert item["complete"] is False
            if family == "vassalization":
                assert _family_value(item, "grantor", family) == {
                    "relation_type": family, "status": "known", "value": "FRA",
                }
                assert _family_value(item, "recipient", family) == {
                    "relation_type": family, "status": "known", "value": "ORL",
                }
            else:
                assert _family_value(item, "grantor", family)["status"] == "not_applicable"
        assert [call[0] for call in inspector.calls] == [
            "offer_vassalization", "proclaim_guarantee", "support_independence",
            "ask_military_access", "set_rival",
        ]
    finally:
        service.close()


def test_default_relation_types_include_memory_families_without_promoting_missing_siblings(tmp_path) -> None:
    source, _primary, inspector = _source()
    service = InformationService(source, tmp_path / "relation-default.sqlite")
    try:
        result = service.query("r01-default-five", queries=[_query("ORL")])
        item = _item(result)
        values = item["fields"]["status"]["value"]
        assert [value["relation_type"] for value in values] == [
            "vassalization", "guarantee", "support_independence",
            "military_access", "rival",
            "alliance", "royal_marriage",
            "fleet_basing", "fleet_basing", "trade_league",
        ]
        assert _family_value(item, "status", "vassalization")["value"] == "active"
        assert all(
            _family_value(item, "status", family)["status"] == "unknown"
            for family in ("guarantee", "support_independence", "military_access", "rival", "alliance", "royal_marriage", "fleet_basing", "trade_league")
        )
        assert [call[0] for call in inspector.calls] == [
            "offer_vassalization", "proclaim_guarantee", "support_independence",
            "ask_military_access", "set_rival",
        ]
    finally:
        service.close()


def test_missing_state_and_legality_only_are_unknown(tmp_path) -> None:
    def remove_state(action_id, recipient, value):
        if action_id == "proclaim_guarantee":
            value.pop("relationship_state", None)

    inspector = RecordedInspector(mutate=remove_state)
    source, _primary, _ = _source(inspector=inspector)
    service = InformationService(source, tmp_path / "relation-unknown.sqlite")
    try:
        result = service.query("missing-state", queries=[_query("SAV", ["guarantee"])])
        row = _family_value(_item(result), "status", "guarantee")
        assert row["status"] == "unknown"
        assert row["reason"] in {"RELATIONSHIP_STATE_UNREAD", "RELATION_STATUS_UNVERIFIED"}

        royal = DATA["captures"]["royal_marriage_LAN"]["inspection"]
        inspector.overrides[("proclaim_guarantee", "LAN")] = royal
        legality_only = service.query(
            "legality-only", queries=[_query("LAN", ["guarantee"])])
        row = _family_value(_item(legality_only), "status", "guarantee")
        assert row["status"] == "unknown"
        assert row["reason"] == "PUBLIC_PROJECTION_IDENTITY_MISMATCH"
    finally:
        service.close()


def test_bad_context_does_not_call_inspector_and_endpoint_or_action_mismatch_retracts(tmp_path) -> None:
    inspector = RecordedInspector()
    source, primary, _ = _source(
        context=_context(status="unready", complete=False), inspector=inspector)
    service = InformationService(source, tmp_path / "relation-context.sqlite")
    try:
        unavailable = service.query("bad-context", queries=[_query("SAV", ["guarantee"])])
        assert inspector.calls == []
        assert _item(unavailable)["fields"]["status"]["status"] in {"unavailable", "unknown"}

        primary._context = _context()
        actual = DATA["captures"]["guarantee_SAV"]["inspection"]
        inspector.overrides[("proclaim_guarantee", "ORL")] = actual
        endpoint = service.query("endpoint-mismatch", queries=[_query("ORL", ["guarantee"])])
        endpoint_row = _family_value(_item(endpoint), "status", "guarantee")
        assert endpoint_row == {
            "relation_type": "guarantee", "status": "unknown",
            "reason": "PUBLIC_PROJECTION_IDENTITY_MISMATCH",
        }

        support = DATA["captures"]["support_independence_SWE"]["inspection"]
        inspector.overrides[("proclaim_guarantee", "LAN")] = support
        action = service.query("action-mismatch", queries=[_query("LAN", ["guarantee"])])
        action_row = _family_value(_item(action), "status", "guarantee")
        assert action_row["status"] == "unknown"
        assert action_row["reason"] == "PUBLIC_PROJECTION_IDENTITY_MISMATCH"
    finally:
        service.close()


def test_sibling_family_failure_keeps_other_known(tmp_path) -> None:
    inspector = RecordedInspector(failures={"support_independence"})
    source, _primary, _ = _source(inspector=inspector)
    service = InformationService(source, tmp_path / "relation-sibling.sqlite")
    try:
        result = service.query(
            "sibling-family-failure",
            queries=[_query("SAV", ["guarantee", "support_independence"])],
        )
        item = _item(result)
        guarantee = _family_value(item, "status", "guarantee")
        support = _family_value(item, "status", "support_independence")
        assert guarantee["status"] == "known"
        assert guarantee["value"] == "inactive"
        assert support["status"] == "unknown"
        assert support["reason"] == "INSPECT_CALL_FAILED:RuntimeError"
        assert result["complete"] is False
    finally:
        service.close()


def test_report_periodic_tick_and_cancellation_use_the_same_offline_contract(tmp_path) -> None:
    clock = FakeClock()
    source, _primary, inspector = _source()
    service = InformationService(source, tmp_path / "relation-periodic.sqlite", clock=clock)
    try:
        report = service.manage_report(
            "r01-report-create", "create",
            config={"name": "R01 selected pair", "detail": "full",
                    "queries": [_query("SAV", ["guarantee"], ["relation_type", "status"])]},
        )["report"]
        queried = service.query("r01-report-query", report_id=report["id"])
        assert _family_value(_item(queried), "status", "guarantee")["value"] == "inactive"

        binding = {"session_id": "relation-session", "observer": "FRA",
                   "game_version": "1.37.4", "game_sha256": GAME_SHA,
                   "world_id": "relation-world"}
        subscription = service.manage_subscription(
            "r01-periodic-create", "create",
            config={"name": "R01 periodic", "kind": "periodic",
                    "report_id": report["id"], "enabled": True, "binding": binding,
                    "schedule": {"basis": "real", "every": 1,
                                 "unit": "seconds", "missed": "coalesce"}},
        )["subscription"]
        assert subscription["state"] == "active"
        assert service.tick().get("results", []) == []
        clock.advance(1)
        tick = service.tick()
        assert tick.get("results")
        assert any("inactive" in json.dumps(item, ensure_ascii=False) for item in tick["results"])

        cancelled = service.manage_subscription(
            "r01-periodic-cancel", "cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        before = len(inspector.calls)
        clock.advance(10)
        assert service.tick().get("results", []) == []
        assert len(inspector.calls) == before
    finally:
        service.close()

