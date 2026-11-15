"""Integration contracts for subscription-managed battle capture.

These tests keep the native producer behind a tiny fake manager.  They use the
real durable :class:`InformationService`, and a small source implementing the
same capture hook as ``BattleInformationSource`` where a service-only
assertion is more useful than a recorded battle fixture.  The tests never
start the game, read native memory, or invoke the control bridge.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.battles import EVENT_TYPE
from bridge.tests.test_information_battles import make_source


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


class FakeCaptureManager:
    """A deterministic lease manager with no filesystem or native I/O."""

    def __init__(
        self,
        *,
        producer_state: str = "enabled",
        transaction_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.producer_state = producer_state
        self.transaction_probe = transaction_probe
        self.reconcile_calls: list[set[str]] = []
        self.reconcile_in_transaction: list[bool] = []
        self.snapshot_calls = 0
        self.close_calls = 0
        self.release_calls = 0
        self.enable_calls = 0
        self.disable_calls = 0
        self.consumers: set[str] = set()
        self.closed = False

    def _snapshot(self) -> dict[str, Any]:
        if self.closed:
            status = "closed"
        elif self.producer_state != "enabled":
            status = "unavailable"
        elif self.consumers:
            status = "active"
        else:
            status = "idle"
        return {
            "status": status,
            "producer_state": self.producer_state,
            # ``managed`` describes the configured lease manager.  It is not
            # an alias for consumer_count and must stay true while a manager
            # is installed, even after the last consumer is released.
            "managed": not self.closed,
            "owned": bool(self.consumers and self.producer_state == "enabled"),
            "consumer_count": len(self.consumers),
            "consumers": sorted(self.consumers),
            "reason": "producer_disabled" if self.producer_state != "enabled" else "ok",
            # This is producer-readiness metadata, not battle-report
            # completeness.
            "complete": False,
        }

    def snapshot(self) -> dict[str, Any]:
        self.snapshot_calls += 1
        return deepcopy(self._snapshot())

    def reconcile(self, consumers: set[str]) -> dict[str, Any]:
        if self.transaction_probe is not None:
            in_transaction = bool(self.transaction_probe())
            self.reconcile_in_transaction.append(in_transaction)
            assert in_transaction is False, "capture lease reconciliation must be outside SQLite transactions"
        requested = set(consumers)
        self.reconcile_calls.append(requested)
        previous = set(self.consumers)
        if requested and not previous:
            self.enable_calls += 1
        if previous and not requested:
            self.disable_calls += 1
            self.release_calls += 1
        self.consumers = requested
        return self.snapshot()

    def close(self) -> dict[str, Any]:
        self.close_calls += 1
        if not self.closed:
            if self.consumers:
                self.disable_calls += 1
                self.release_calls += 1
            self.consumers.clear()
            self.closed = True
        return self.snapshot()


class HookSource:
    """Small source exposing the same capture lifecycle as battle sources."""

    event_types = (EVENT_TYPE, "fixture_observation")

    def __init__(self, manager: FakeCaptureManager | None = None, *, world_id: str | None = "world-a") -> None:
        self.capture_manager = manager
        self.context_value = {
            "status": "ready",
            "session_id": "capture-session",
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "game_day": 100,
            "game_date": "1444.01.01",
            "mode": "live",
            "paused": True,
        }
        if world_id is not None:
            self.context_value["world_id"] = world_id
        self.events: list[dict[str, Any]] = []
        self.poll_calls: list[tuple[Any, Any]] = []
        self.read_calls: list[dict[str, Any]] = []
        self.read_event_calls: list[dict[str, Any]] = []
        self.sync_calls: list[tuple[list[str], dict[str, Any]]] = []

    def context(self) -> dict[str, Any]:
        return deepcopy(self.context_value)

    def capture_status(self) -> dict[str, Any]:
        if self.capture_manager is not None:
            result = self.capture_manager.snapshot()
            result["mode"] = "subscription_managed_live"
            return result
        return {
            "managed": False,
            "owned": False,
            "producer_state": "unverified",
            "mode": "retained_records_only",
            "future_capture_verified": False,
            "complete": False,
        }

    @staticmethod
    def requires_capture(subscription: dict[str, Any]) -> bool:
        return (subscription.get("kind") == "event"
                and EVENT_TYPE in subscription.get("event", {}).get("types", []))

    def sync_subscriptions(self, subscriptions: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any] | None:
        ids = [item["id"] for item in subscriptions if self.requires_capture(item)]
        self.sync_calls.append((ids, deepcopy(context)))
        if self.capture_manager is None:
            return None
        return self.capture_manager.reconcile(set(ids))

    def close_capture(self) -> dict[str, Any] | None:
        if self.capture_manager is None:
            return None
        return self.capture_manager.close()

    def catalog(self) -> list[dict[str, Any]]:
        return [
            {
                "topic_id": "B01",
                "status": "available",
                "fields": {"event_id": {"type": "string"}},
                "object_types": ["battle"],
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                "supported_versions": ["1.37.4"],
                "triggers": ["query", "event"],
                "context_scope": "event_scope",
                "observer_roles": [],
                "capture": self.capture_status(),
            },
            {
                "topic_id": "fixture_state",
                "status": "available",
                "fields": {"value": {"type": "integer", "unit": "fixture"}},
                "object_types": ["country"],
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                "supported_versions": ["1.37.4"],
                "triggers": ["query", "periodic", "change"],
                "context_scope": "game",
            },
        ]

    def validate_query(self, query: dict[str, Any]) -> dict[str, Any]:
        return deepcopy(query)

    def validate_event_filter(self, event_filter: dict[str, Any]) -> None:
        if not isinstance(event_filter.get("types"), list) or not event_filter["types"]:
            raise InformationError("invalid_event_filter", "types required")

    def read(self, query: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        self.read_calls.append(deepcopy(query))
        fields = {
            field: {"status": "known", "value": 7}
            for field in query.get("fields", [])
        }
        return {"fields": fields, "complete": True, "source": {"name": "HookSource"}}

    def read_event(self, query: dict[str, Any], context: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        self.read_event_calls.append(deepcopy(event))
        return {
            "fields": {field: {"status": "known", "value": event.get(field, event.get("event_id"))}
                       for field in query.get("fields", [])},
            "complete": True,
            "source": {"name": "HookSource", "event_id": event.get("event_id")},
        }

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        self.poll_calls.append((deepcopy(context), cursor))
        if (self.capture_manager is not None and self.capture_manager.consumers
                and self.capture_manager.producer_state != "enabled"):
            return {
                "events": [],
                "cursor": cursor,
                "complete": False,
                "gaps": [{"reason": "BATTLE_CAPTURE_UNAVAILABLE"}],
            }
        events = deepcopy(self.events)
        self.events.clear()
        return {"events": events, "cursor": "fixture-cursor", "complete": True, "gaps": []}


def _report(service: InformationService, request_id: str, query: dict[str, Any]) -> dict[str, Any]:
    return service.manage_report(
        request_id,
        "create",
        config={"name": request_id, "detail": "full", "queries": [query]},
    )["report"]


def _battle_query() -> dict[str, Any]:
    return {
        "topic": "B01",
        "object": {"type": "battle"},
        "fields": ["event_id"],
        "parameters": {},
    }


def _state_query() -> dict[str, Any]:
    return {
        "topic": "fixture_state",
        "object": {"type": "country", "id": "FRA"},
        "fields": ["value"],
        "parameters": {},
    }


def _battle_config(report_id: str, *, name: str = "battle") -> dict[str, Any]:
    return {
        "name": name,
        "kind": "event",
        "report_id": report_id,
        "enabled": True,
        "event": {"types": [EVENT_TYPE]},
    }


def _state_config(report_id: str) -> dict[str, Any]:
    return {
        "name": "state",
        "kind": "periodic",
        "report_id": report_id,
        "enabled": True,
        "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
    }


def _runtime(service: InformationService, subscription_id: str) -> dict[str, Any]:
    return service.status(subscription_id)["subscriptions"][0]["runtime"]


def test_battle_source_uses_event_constant_and_retains_read_only_mode(tmp_path: Path) -> None:
    """A source without a manager must never claim future producer readiness."""

    source, _primary, _fixture, _stream_db, _payload = make_source(tmp_path)
    battle_subscription = {"id": "retained-sub", **_battle_config("report")}

    assert source.requires_capture(battle_subscription) is True
    assert source.requires_capture({**battle_subscription, "event": {"types": ["other"]}}) is False
    assert source.requires_capture({**battle_subscription, "kind": "periodic"}) is False
    assert source.capture_manager is None
    status = source.capture_status()
    assert status["mode"] == "retained_records_only"
    assert status["producer_state"] == "unverified"
    assert source.sync_subscriptions([battle_subscription], source.context()) is None
    assert source.close_capture() is None

    b01 = next(item for item in source.catalog() if item["topic_id"] == "B01")
    assert b01["capture"]["mode"] == "retained_records_only"
    assert b01["capture"]["future_capture_verified"] is False


def test_two_battle_subscriptions_share_one_lease_and_resume_reopens(tmp_path: Path) -> None:
    manager = FakeCaptureManager()
    source = HookSource(manager)
    service = InformationService(source, tmp_path / "service.sqlite3")
    try:
        report = _report(service, "battle-report", _battle_query())
        first_response = service.manage_subscription(
            "battle-create-1", "create", config=_battle_config(report["id"], name="first")
        )
        first = first_response["subscription"]
        assert first_response["capture"]["consumer_count"] == 1
        assert first_response["runtime"]["state"] == "active"
        assert manager.reconcile_calls == [{first["id"]}]
        assert manager.enable_calls == 1

        fetched = service.manage_subscription(
            "battle-get-1", "get", subscription_id=first["id"]
        )
        assert fetched["capture"]["consumer_count"] == 1
        assert fetched["runtime"]["state"] == "active"

        second = service.manage_subscription(
            "battle-create-2", "create", config=_battle_config(report["id"], name="second")
        )["subscription"]
        assert manager.reconcile_calls[-1] == {first["id"], second["id"]}
        assert manager.enable_calls == 1

        paused = service.manage_subscription(
            "battle-pause-1", "pause", subscription_id=first["id"], expected_version=first["version"]
        )["subscription"]
        assert paused["state"] == "paused"
        assert manager.reconcile_calls[-1] == {second["id"]}
        assert manager.disable_calls == 0

        cancelled = service.manage_subscription(
            "battle-cancel-2", "cancel", subscription_id=second["id"], expected_version=second["version"]
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        assert manager.reconcile_calls[-1] == set()
        assert manager.disable_calls == 1

        resumed = service.manage_subscription(
            "battle-resume-1", "resume", subscription_id=first["id"], expected_version=paused["version"]
        )["subscription"]
        assert resumed["state"] == "active"
        assert manager.reconcile_calls[-1] == {first["id"]}
        assert manager.enable_calls == 2
    finally:
        service.close()


def test_invalid_conflict_and_duplicate_requests_never_reconcile_again(tmp_path: Path) -> None:
    manager = FakeCaptureManager()
    source = HookSource(manager)
    service = InformationService(source, tmp_path / "service.sqlite3")
    try:
        report = _report(service, "battle-report", _battle_query())
        config = _battle_config(report["id"])
        first_response = service.manage_subscription("same-request", "create", config=config)
        calls = deepcopy(manager.reconcile_calls)

        assert service.manage_subscription("same-request", "create", config=config) == first_response
        assert manager.reconcile_calls == calls

        with pytest.raises(InformationError) as conflict:
            service.manage_subscription(
                "same-request", "create", config={**config, "name": "different"}
            )
        assert conflict.value.code == "request_conflict"
        assert manager.reconcile_calls == calls

        with pytest.raises(InformationError):
            service.manage_subscription(
                "invalid-event", "create",
                config={**config, "event": {"types": ["unknown_event"]}},
            )
        assert manager.reconcile_calls == calls

        subscription = first_response["subscription"]
        with pytest.raises(InformationError) as version_error:
            service.manage_subscription(
                "wrong-version", "pause", subscription_id=subscription["id"], expected_version=99
            )
        assert version_error.value.code == "version_conflict"
        assert manager.reconcile_calls == calls
    finally:
        service.close()


def test_disabled_producer_marks_runtime_unavailable_without_consuming_battle_events(tmp_path: Path) -> None:
    """A failed producer cannot drain a future battle event from the source."""

    manager = FakeCaptureManager(producer_state="disabled")
    source, _primary, _fixture, _stream_db, _payload = make_source(tmp_path)
    source.capture_manager = manager
    battle_poll_calls: list[Any] = []

    def forbidden_battle_poll(context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        battle_poll_calls.append(cursor)
        raise AssertionError("disabled managed producer must not poll the battle adapter")

    source.battles.poll_events = forbidden_battle_poll
    service = InformationService(source, tmp_path / "service.sqlite3")
    try:
        report = _report(service, "battle-report", {
            "topic": "B01",
            "object": {"type": "battle"},
            "fields": ["event_id"],
            "parameters": {},
        })
        subscription_response = service.manage_subscription(
            "disabled-battle", "create", config=_battle_config(report["id"])
        )
        subscription = subscription_response["subscription"]
        assert subscription_response["capture"]["producer_state"] == "disabled"
        assert _runtime(service, subscription["id"])["state"] == "source_unavailable"

        tick = service.tick()
        assert tick["results"] == []
        assert battle_poll_calls == []
        assert _runtime(service, subscription["id"])["state"] == "source_unavailable"
    finally:
        service.close()


def test_non_battle_subscription_runs_when_battle_capture_is_unavailable(tmp_path: Path) -> None:
    manager = FakeCaptureManager(producer_state="disabled")
    source = HookSource(manager)
    now = [100.0]
    service = InformationService(source, tmp_path / "service.sqlite3", clock=lambda: now[0])
    try:
        battle_report = _report(service, "battle-report", _battle_query())
        state_report = _report(service, "state-report", _state_query())
        battle = service.manage_subscription(
            "mixed-battle", "create", config=_battle_config(battle_report["id"])
        )["subscription"]
        state = service.manage_subscription(
            "mixed-state", "create", config=_state_config(state_report["id"])
        )["subscription"]

        now[0] = 102.0
        tick = service.tick()
        assert [result["subscription_id"] for result in tick["results"]] == [state["id"]]
        assert _runtime(service, state["id"])["state"] == "active"
        assert _runtime(service, battle["id"])["state"] == "source_unavailable"
        assert manager.reconcile_calls[-1] == {battle["id"]}
    finally:
        service.close()


def test_read_only_battle_source_keeps_recorded_polling_without_implicit_capture(tmp_path: Path) -> None:
    source, _primary, _fixture, _stream_db, _payload = make_source(tmp_path)
    battle_poll_calls: list[Any] = []
    original_poll = source.battles.poll_events

    def tracked_poll(context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        battle_poll_calls.append(cursor)
        return original_poll(context, cursor)

    source.battles.poll_events = tracked_poll
    service = InformationService(source, tmp_path / "service.sqlite3")
    try:
        report = _report(service, "battle-report", {
            "topic": "B01",
            "object": {"type": "battle"},
            "fields": ["event_id"],
            "parameters": {},
        })
        subscription = service.manage_subscription(
            "retained-battle", "create", config=_battle_config(report["id"])
        )["subscription"]
        assert source.capture_manager is None
        assert service.status()["capture"]["mode"] == "retained_records_only"

        service.tick()
        assert battle_poll_calls == [None]
        assert _runtime(service, subscription["id"])["state"] == "active"
    finally:
        service.close()


def test_capture_close_is_idempotent_and_rebind_does_not_reuse_old_lease(tmp_path: Path) -> None:
    manager_one = FakeCaptureManager()
    source_one = HookSource(manager_one)
    database = tmp_path / "service.sqlite3"
    service_one = InformationService(source_one, database)
    try:
        report = _report(service_one, "battle-report", _battle_query())
        config = _battle_config(report["id"])
        config["binding"] = {
            "session_id": "capture-session",
            "observer": "FRA",
            "game_version": "1.37.4",
        }
        subscription = service_one.manage_subscription(
            "rebind-create", "create", config=config
        )["subscription"]
        assert manager_one.reconcile_calls == [{subscription["id"]}]
        assert source_one.close_capture()["status"] == "closed"
        assert source_one.close_capture()["status"] == "closed"
        assert manager_one.release_calls == 1
    finally:
        service_one.close()

    manager_two = FakeCaptureManager()
    source_two = HookSource(manager_two)
    service_two = InformationService(source_two, database)
    try:
        assert manager_two.reconcile_calls == []
        service_two.tick()
        # Restart reconciliation explicitly releases any stale demand; the
        # world-revalidation marker prevents the old subscription from being
        # rebound until the caller supplies a current binding.
        assert manager_two.reconcile_calls == [set()]
        assert _runtime(service_two, subscription["id"])["state"] == "world_revalidation_required"

        current = service_two.status(subscription["id"])["subscriptions"][0]["subscription"]
        rebound = _battle_config(report["id"], name="rebound")
        rebound["binding"] = {
            "session_id": "capture-session",
            "observer": "FRA",
            "game_version": "1.37.4",
            "world_id": "world-a",
        }
        service_two.manage_subscription(
            "rebind-update", "update", subscription_id=subscription["id"],
            expected_version=current["version"], config=rebound,
        )
        assert manager_two.reconcile_calls == [set(), {subscription["id"]}]
        assert manager_two.enable_calls == 1
    finally:
        service_two.close()


def test_capture_reconciliation_hook_runs_outside_sqlite_transaction(tmp_path: Path) -> None:
    service_ref: dict[str, InformationService] = {}
    manager = FakeCaptureManager(
        transaction_probe=lambda: service_ref["service"].db.in_transaction,
    )
    source = HookSource(manager)
    service = InformationService(source, tmp_path / "service.sqlite3")
    service_ref["service"] = service
    try:
        report = _report(service, "battle-report", _battle_query())
        subscription = service.manage_subscription(
            "outside-transaction", "create", config=_battle_config(report["id"])
        )["subscription"]
        service.tick()
        assert manager.reconcile_in_transaction
        assert all(value is False for value in manager.reconcile_in_transaction)
        assert _runtime(service, subscription["id"])["state"] == "active"
    finally:
        service.close()

