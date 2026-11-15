"""Contract tests for the information query and subscription service.

The source in these tests is deliberately a small, mutable source rather than
a mock of ``InformationService``. It supplies a catalog, state reads and event
pages so that the tests exercise catalog validation, scheduling, persistence
and failure propagation through the public service boundary.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from copy import deepcopy
import json
import multiprocessing
import sqlite3
import threading
from typing import Any

import pytest

from bridge.information import InformationError, InformationService


TOPIC = "fixture_state"
QUERY = {
    "topic": TOPIC,
    "object": {"type": "country", "id": "FRA"},
    "fields": ["value", "zero"],
    "parameters": {"tag": "FRA"},
}


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class DeliveryInterrupted(BaseException):
    """Model a process interruption after an external adapter is called."""


class MemoryDatabase(dict):
    """A restartable dict that also accepts common persistence method names."""

    _missing = object()

    def load(self, key: str | None = None, default: Any = None) -> Any:
        if key is None:
            return deepcopy(dict(self))
        return deepcopy(self.get(key, default))

    def save(self, key: Any, value: Any = _missing) -> None:
        if value is self._missing:
            if not isinstance(key, dict):
                raise TypeError("save(state) requires a mapping")
            self.clear()
            self.update(deepcopy(key))
            return
        self[key] = deepcopy(value)

    def read(self, key: str | None = None, default: Any = None) -> Any:
        return self.load(key, default)

    def write(self, key: Any, value: Any = _missing) -> None:
        self.save(key, value)


class FakeOutput:
    def __init__(self) -> None:
        self.fail = False
        self.crash = False
        self.before_deliver = None
        self.delivered: list[dict] = []
        self.calls = 0

    def deliver(self, result: dict) -> dict:
        self.calls += 1
        if self.before_deliver is not None:
            self.before_deliver(result)
        if self.crash:
            raise DeliveryInterrupted("process interrupted after delivery claim")
        if self.fail:
            raise RuntimeError("output sink unavailable")
        self.delivered.append(deepcopy(result))
        return {"status": "delivered", "result_id": result.get("result_id")}


class FakeSource:
    """Mutable source with a non-built-in topic to prove catalog-driven reads."""

    event_types = ["battle", "trade"]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.session_id = "session-a"
        self.game_version = "1.0"
        self.observer = "FRA"
        self.game_day = 100
        self.game_date = "1444.01.01"
        self.mode = "live"
        self.paused = False
        self.world_id = "world-a"
        self.observer_roles: list[str] | None = None
        self.values: dict[str, Any] = {"value": 7, "zero": 0}
        self.read_error: str | None = None
        self.partial = False
        self.context_change_on_read: dict[str, Any] | None = None
        self.read_calls: list[tuple[dict, dict]] = []
        self.event_pages: list[dict] = []
        self.repeat_event_batch = False
        self._repeated_event_page: dict | None = None
        self.poll_calls: list[Any] = []

    def context(self) -> dict:
        with self._lock:
            return {
                "status": "ready",
                "session_id": self.session_id,
                "game_version": self.game_version,
                "observer": self.observer,
                "game_day": self.game_day,
                "game_date": self.game_date,
                "mode": self.mode,
                "paused": self.paused,
                "world_id": self.world_id,
            }

    def catalog(self) -> list[dict]:
        entry = {
                "topic_id": TOPIC,
                "status": "available",
                "fields": {
                    "value": {"type": "integer", "unit": "fixture_units"},
                    "zero": {"type": "integer", "unit": "fixture_units"},
                },
                "object_types": ["country"],
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tag": {"type": "string", "pattern": "^[A-Z]{3}$"},
                        "actor": {"type": "string", "pattern": "^[A-Z]{3}$"},
                        "options": {
                            "type": "object",
                            "additionalProperties": True,
                        },
                    },
                    "required": ["tag"],
                },
                "supported_versions": [self.game_version],
                "triggers": ["query", "periodic", "event", "change"],
            }
        if self.observer_roles is not None:
            entry["observer_roles"] = list(self.observer_roles)
        return [entry]

    def read(self, query: dict, context: dict) -> dict:
        with self._lock:
            self.read_calls.append((deepcopy(query), deepcopy(context)))
            if self.read_error:
                raise RuntimeError(self.read_error)

            if self.context_change_on_read:
                for key, value in self.context_change_on_read.items():
                    setattr(self, key, value)
                self.context_change_on_read = None

            requested = query.get("fields", list(self.values))
            if isinstance(requested, dict):
                requested = list(requested)
            fields: dict[str, dict] = {}
            for field in requested:
                if self.partial and field == "zero":
                    fields[field] = {"status": "unavailable"}
                elif field in self.values:
                    fields[field] = {"status": "known", "value": self.values[field]}
                else:
                    fields[field] = {"status": "unknown"}
            complete = not self.partial and all(
                item.get("status") == "known" for item in fields.values()
            )
            return {"fields": fields, "complete": complete, "source": "fake-source"}

    def poll_events(self, context: dict, cursor: Any) -> dict:
        with self._lock:
            self.poll_calls.append(cursor)
            if self.repeat_event_batch:
                if self._repeated_event_page is None and self.event_pages:
                    self._repeated_event_page = deepcopy(self.event_pages[0])
                if self._repeated_event_page is not None:
                    return deepcopy(self._repeated_event_page)
            if self.event_pages:
                return deepcopy(self.event_pages.pop(0))
            return {"events": [], "cursor": cursor, "complete": True, "gaps": []}

    def set_session(self, session_id: str, *, game_version: str | None = None) -> None:
        with self._lock:
            self.session_id = session_id
            if game_version is not None:
                self.game_version = game_version

    def set_game_day(self, game_day: int, game_date: str | None = None) -> None:
        with self._lock:
            self.game_day = game_day
            if game_date is not None:
                self.game_date = game_date


class EventAwareSource(FakeSource):
    """Source whose event snapshot is distinct from its current state."""

    def __init__(self) -> None:
        super().__init__()
        self.read_event_calls: list[dict] = []

    def read_event(self, query: dict, context: dict, event: dict) -> dict:
        with self._lock:
            self.read_event_calls.append(deepcopy(event))
            payload = event.get("payload", {})
            fields = {}
            for field in query["fields"]:
                if field in payload:
                    fields[field] = {"status": "known", "value": deepcopy(payload[field])}
                else:
                    fields[field] = {"status": "unknown", "reason": "event_field_missing"}
            return {
                "fields": fields,
                "complete": all(item["status"] == "known" for item in fields.values()),
                "source": {"name": "event-aware-source", "event_id": event.get("event_id")},
            }


@pytest.fixture
def env(tmp_path):
    source = FakeSource()
    database = tmp_path / "information.sqlite3"
    output = FakeOutput()
    clock = FakeClock()
    service = InformationService(source, database, output=output, clock=clock)
    return service, source, database, output, clock


def report_config(*, detail: str = "full", query: dict | None = None) -> dict:
    return {
        "name": "fixture report",
        "queries": [deepcopy(query or QUERY)],
        "detail": detail,
    }


def create_report(service: InformationService, request_id: str = "report-create", **kwargs) -> dict:
    return service.manage_report(
        request_id,
        "create",
        config=report_config(**kwargs),
    )["report"]


def subscription_config(
    report_id: str,
    *,
    name: str = "fixture subscription",
    kind: str = "periodic",
    enabled: bool = True,
    binding: dict | None = None,
    every: int = 10,
    basis: str = "real",
    unit: str = "seconds",
    missed: str = "coalesce",
    event: dict | None = None,
) -> dict:
    return {
        "name": name,
        "kind": kind,
        "report_id": report_id,
        "enabled": enabled,
        **({"binding": deepcopy(binding)} if binding is not None else {}),
        **(
            {
                "schedule": {
                    "basis": basis,
                    "every": every,
                    "unit": unit,
                    "missed": missed,
                }
            }
            if kind != "event"
            else {}
        ),
        **({"event": deepcopy(event)} if event is not None else {}),
    }


def create_subscription(
    service: InformationService,
    report_id: str,
    request_id: str = "subscription-create",
    **kwargs,
) -> dict:
    return service.manage_subscription(
        request_id,
        "create",
        config=subscription_config(report_id, **kwargs),
    )["subscription"]


def tick_results(tick_response: dict | list) -> list[dict]:
    if isinstance(tick_response, list):
        return tick_response
    return tick_response.get("results", [])


def records(response: dict, key: str) -> list[dict]:
    value = response.get(key, [])
    return value if isinstance(value, list) else [value]


def subscription_record(service: InformationService, subscription_id: str) -> dict:
    response = service.manage_subscription(
        f"get-{subscription_id}", "get", subscription_id=subscription_id
    )
    return response["subscription"]


def result_text(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


def _process_query_worker(database: str, owner: str, request_id: str) -> tuple[str, str, int]:
    """Open an independent SQLite connection for the multi-process test."""
    source = FakeSource()
    service = InformationService(
        source, database, clock=FakeClock(), owner=owner
    )
    try:
        result = service.query(request_id, queries=[QUERY])
        return "ok", result["result_id"], len(source.read_calls)
    except Exception as exc:  # surfaced by the parent assertion
        return "error", f"{type(exc).__name__}:{exc}", len(source.read_calls)
    finally:
        service.close()


def test_discover_and_query_use_catalog_and_expose_context(env):
    service, source, _database, _output, _clock = env

    discovered = service.discover()
    catalog = discovered.get(
        "topics", discovered.get("catalog", discovered.get("entries", []))
    )
    assert any(entry["topic_id"] == TOPIC for entry in catalog)

    result = service.query("query-catalog", queries=[QUERY])
    assert result["request_id"] == "query-catalog"
    assert result["complete"] is True
    assert result["context"]["session_id"] == source.session_id
    assert result["context"]["game_version"] == source.game_version
    assert result["context"]["observer"] == source.observer
    assert result["context"]["game_day"] == source.game_day
    assert result.get("generated_at") or result.get("collected_at")
    assert "7" in result_text(result)
    assert len(source.read_calls) == 1


def test_query_request_id_is_idempotent_and_conflicts_are_atomic(env):
    service, source, _database, _output, _clock = env

    first = service.query("same-query", queries=[QUERY])
    source.values["value"] = 99
    second = service.query("same-query", queries=[QUERY])
    assert second == first
    assert len(source.read_calls) == 1

    with pytest.raises(InformationError):
        service.query(
            "same-query",
            queries=[{**QUERY, "parameters": {"tag": "BUR"}}],
        )
    result_ids = {item["result_id"] for item in records(service.list_results(), "results")}
    assert first["result_id"] in result_ids
    assert len(result_ids) == 1


def test_invalid_report_is_rejected_without_partial_configuration(env):
    service, _source, _database, _output, _clock = env

    bad = report_config(query={**QUERY, "topic": "not-in-catalog"})
    with pytest.raises(InformationError):
        service.manage_report("bad-report", "create", config=bad)
    listing = service.manage_report("reports", "list")
    assert records(listing, "reports") == []

    good = create_report(service)
    old = deepcopy(good)
    with pytest.raises(InformationError):
        service.manage_report(
            "bad-update",
            "update",
            report_id=good["id"],
            config={**report_config(), "detail": "invalid-detail"},
            expected_version=good["version"],
        )
    current = service.manage_report(
        "report-after-bad-update", "get", report_id=good["id"]
    )["report"]
    assert current == old


def test_multiple_periods_share_report_path_and_remain_independent(env):
    service, _source, _database, output, clock = env
    report = create_report(service)
    short = create_subscription(
        service, report["id"], "short-create", name="short", every=10
    )
    long = create_subscription(
        service, report["id"], "long-create", name="long", every=100
    )

    clock.advance(10)
    first = tick_results(service.tick())
    assert any(short["id"] in result_text(item) for item in first)
    assert not any(long["id"] in result_text(item) for item in first)

    clock.advance(90)
    second = tick_results(service.tick())
    assert any(long["id"] in result_text(item) for item in second)
    assert any(short["id"] in result_text(item) for item in second)
    assert len(output.delivered) == len(first) + len(second)


def test_subscription_update_versions_and_does_not_modify_sibling(env):
    service, _source, _database, _output, _clock = env
    report = create_report(service)
    first = create_subscription(service, report["id"], "sub-a", name="a", every=10)
    sibling = create_subscription(service, report["id"], "sub-b", name="b", every=20)

    changed = subscription_config(report["id"], name="a changed", every=30)
    updated = service.manage_subscription(
        "sub-a-update",
        "update",
        subscription_id=first["id"],
        config=changed,
        expected_version=first["version"],
    )["subscription"]
    assert updated["version"] == first["version"] + 1
    assert subscription_record(service, sibling["id"])["version"] == sibling["version"]
    with pytest.raises(InformationError):
        service.manage_subscription(
            "sub-a-stale",
            "update",
            subscription_id=first["id"],
            config=changed,
            expected_version=first["version"],
        )
    assert subscription_record(service, first["id"]) == updated


def test_pause_resume_cancel_control_future_ticks(env):
    service, _source, _database, _output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])

    paused = service.manage_subscription(
        "pause", "pause", subscription_id=subscription["id"],
        expected_version=subscription["version"],
    )["subscription"]
    assert paused["state"] in {"paused", "disabled"}
    clock.advance(10)
    assert tick_results(service.tick()) == []

    resumed = service.manage_subscription(
        "resume", "resume", subscription_id=subscription["id"],
        expected_version=paused["version"],
    )["subscription"]
    assert resumed["state"] in {"active", "enabled", "running"}
    clock.advance(10)
    assert tick_results(service.tick())

    cancelled = service.manage_subscription(
        "cancel", "cancel", subscription_id=subscription["id"],
        expected_version=resumed["version"],
    )["subscription"]
    assert cancelled["state"] == "cancelled"
    clock.advance(100)
    assert tick_results(service.tick()) == []


def test_game_schedule_waits_while_game_is_paused_and_handles_missed_periods(env):
    service, source, _database, _output, clock = env
    report = create_report(service)
    subscription = create_subscription(
        service,
        report["id"],
        kind="periodic",
        basis="game",
        every=2,
        unit="days",
        missed="coalesce",
    )

    source.paused = True
    clock.advance(100)
    assert tick_results(service.tick()) == []

    source.paused = False
    source.set_game_day(source.game_day + 10)
    result = tick_results(service.tick())
    assert len(result) == 1
    assert subscription["id"] in result_text(result[0])


def test_binding_defaults_to_context_and_old_session_is_not_reused(env):
    service, source, _database, _output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    saved = subscription_record(service, subscription["id"])
    assert saved["binding"]["session_id"] == "session-a"
    assert saved["binding"]["game_version"] == "1.0"

    source.set_session("session-b")
    clock.advance(10)
    assert tick_results(service.tick()) == []
    state = service.status(subscription["id"])["subscriptions"][0]["runtime"]
    state_text = result_text(state).lower()
    assert state.get("state") in {"scope_mismatch", "stale", "invalid", "expired"}
    assert any(word in state_text for word in ("mismatch", "stale", "invalid", "expired"))


def test_event_subscriptions_filter_and_deduplicate_event_ids(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    subscription = create_subscription(
        service,
        report["id"],
        kind="event",
        every=1,
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    event_one = {
        "event_id": "battle-1",
        "event_type": "battle",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "game_day": 100,
    }
    ignored = {
        "event_id": "trade-1",
        "event_type": "trade",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "game_day": 100,
    }
    event_two = {
        "event_id": "battle-2",
        "event_type": "battle",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "game_day": 101,
    }
    source.event_pages = [
        {"events": [event_one, ignored], "cursor": "cursor-1", "complete": True, "gaps": []},
        {
            "events": [event_one, event_two],
            "cursor": "cursor-2",
            "complete": True,
            "gaps": [],
        },
    ]

    first = tick_results(service.tick())
    assert len(first) == 1
    assert subscription["id"] in result_text(first[0])
    assert "battle-1" in result_text(first[0])

    second = tick_results(service.tick())
    assert len(second) == 1
    assert "battle-2" in result_text(second[0])
    assert "trade-1" not in result_text(second[0])
    # FakeSource has no read_event hook, so the legacy read path remains the
    # event-result fallback for both matching events.
    assert len(source.read_calls) == 2


def test_event_read_event_hook_uses_event_snapshot_instead_of_current_state(tmp_path):
    source = EventAwareSource()
    source.values.update(value=99, zero=101)
    event = {
        "event_id": "battle-event-snapshot",
        "event_type": "battle",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "payload": {"value": 17, "zero": 23},
    }
    source.event_pages = [{"events": [event], "cursor": "event-1", "complete": True, "gaps": []}]
    service = InformationService(source, tmp_path / "information.sqlite3", clock=FakeClock())
    try:
        report = create_report(service, request_id="event-hook-report")
        create_subscription(
            service,
            report["id"],
            request_id="event-hook-subscription",
            kind="event",
            event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
        )

        results = tick_results(service.tick())
        assert len(results) == 1
        fields = results[0]["items"][0]["fields"]
        assert fields["value"] == {"status": "known", "value": 17, "unit": "fixture_units"}
        assert fields["zero"] == {"status": "known", "value": 23, "unit": "fixture_units"}
        assert source.read_calls == []
        assert source.read_event_calls == [event]
    finally:
        service.close()


def test_change_subscription_emits_only_after_a_changed_snapshot(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    subscription = create_subscription(
        service,
        report["id"],
        kind="change",
        basis="game",
        every=1,
        unit="days",
    )

    source.set_game_day(101)
    assert tick_results(service.tick()) == []  # establish baseline
    source.values["value"] = 8
    source.set_game_day(102)
    changed = tick_results(service.tick())
    assert len(changed) == 1
    assert subscription["id"] in result_text(changed[0])
    assert "value" in result_text(changed[0])
    source.set_game_day(103)
    assert tick_results(service.tick()) == []


def test_partial_and_source_failure_results_remain_queryable(env):
    service, source, _database, _output, _clock = env
    source.partial = True
    partial = service.query("partial-query", queries=[QUERY])
    assert partial["complete"] is False
    assert "7" in result_text(partial)
    assert "unavailable" in result_text(partial)
    assert service.get_result(partial["result_id"])["result_id"] == partial["result_id"]

    source.partial = False
    source.read_error = "native read failed"
    failed = service.query("failed-query", queries=[QUERY])
    assert failed["complete"] is False
    assert failed.get("status") in {"failed", "partial", "error"}
    assert "native read failed" in result_text(failed)
    assert service.get_result(failed["result_id"])["complete"] is False


def test_incomplete_change_sample_preserves_baseline_and_reports_failure_without_export(env):
    service, source, _database, output, _clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"], kind="change",
                                       basis="game", every=1, unit="days")
    source.set_game_day(101)
    assert tick_results(service.tick()) == []
    before = service.status(subscription["id"])["subscriptions"][0]["runtime"]
    source.partial = True
    source.values["value"] = 9
    source.set_game_day(102)
    assert tick_results(service.tick()) == []
    failed = service.status(subscription["id"])["subscriptions"][0]["runtime"]
    assert failed["baseline"] == before["baseline"]
    assert failed.get("last_result_id") == before.get("last_result_id")
    assert failed["last_attempt"]["status"] == "read_failed_baseline_preserved"
    assert failed["last_attempt"]["incomplete_queries"][0]["complete"] is False
    assert output.calls == 0
    source.partial = False
    source.set_game_day(103)
    assert len(tick_results(service.tick())) == 1
    assert output.calls == 1
    source.set_game_day(104)
    assert tick_results(service.tick()) == []


def test_failed_first_change_sample_does_not_create_a_baseline_or_result(env):
    service, source, _database, output, _clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"], kind="change",
                                       basis="game", every=1, unit="days")
    source.read_error = "read unavailable during change sampling"
    source.set_game_day(101)
    assert tick_results(service.tick()) == []
    runtime = service.status(subscription["id"])["subscriptions"][0]["runtime"]
    assert runtime.get("baseline") is None and runtime.get("last_result_id") is None
    assert runtime["last_attempt"]["status"] == "read_failed_baseline_preserved"
    gaps = runtime["last_attempt"]["incomplete_queries"]
    assert "unavailable" in result_text(gaps)
    assert output.calls == 0
    source.read_error = None
    source.set_game_day(102)
    assert tick_results(service.tick()) == []
    assert service.status(subscription["id"])["subscriptions"][0]["runtime"].get("baseline")


def test_delivery_failure_is_recorded_without_claiming_success(env):
    service, _source, _database, output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    output.fail = True
    clock.advance(10)
    results = tick_results(service.tick())
    assert len(results) == 1
    failed = results[0]
    delivery_text = result_text(failed).lower()
    assert "delivery" in delivery_text
    assert any(word in delivery_text for word in ("failed", "error", "unavailable"))
    assert output.calls == 1
    state_text = result_text(
        service.status(subscription["id"])["subscriptions"][0]["runtime"]
    ).lower()
    assert "failed" in state_text or "error" in state_text


def test_restart_recovers_reports_subscriptions_and_results(env):
    service, source, database, output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    clock.advance(10)
    generated = tick_results(service.tick())
    assert len(generated) == 1
    result_id = generated[0]["result_id"]
    service.close()

    restarted = InformationService(
        source,
        database,
        output=output,
        clock=clock,
    )
    assert restarted.manage_report("reports-after-restart", "list")["reports"]
    restored = restarted.manage_subscription("subs-after-restart", "list")["subscriptions"]
    assert any(item["id"] == subscription["id"] for item in restored)
    assert restarted.get_result(result_id)["result_id"] == result_id


def test_concurrent_duplicate_queries_have_one_effective_request(env):
    service, source, _database, _output, _clock = env

    def call(_: int) -> dict:
        return service.query("concurrent-query", queries=[QUERY])

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(call, range(8)))
    assert all(response == responses[0] for response in responses)
    assert len(source.read_calls) == 1
    assert len(records(service.list_results(), "results")) == 1


def test_list_results_limit_and_configure_are_observable(env):
    service, source, _database, _output, _clock = env
    for index in range(3):
        service.query(f"list-query-{index}", queries=[QUERY])
        source.values["value"] += 1
    limited = service.list_results(limit=2)
    assert len(records(limited, "results")) == 2

    configured = service.configure(
        "configure-output", "update", values={"max_results_per_tick": 2},
        expected_version=0,
    )
    assert configured
    reread = service.configure("configure-read", "get")
    assert "max_results_per_tick" in result_text(reread)


def _event(source: FakeSource, event_id: str, game_day: int = 100) -> dict:
    return {
        "event_id": event_id,
        "event_type": "battle",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "game_day": game_day,
    }


def test_event_batch_over_tick_budget_is_drained_without_loss(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    create_subscription(
        service,
        report["id"],
        kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    service.configure(
        "budget-one", "update", values={"max_results_per_tick": 1}, expected_version=0
    )
    batch = [_event(source, f"battle-{index}") for index in range(1, 4)]
    source.event_pages = [{"events": batch, "cursor": "batch-1", "complete": True, "gaps": []}]
    source.repeat_event_batch = True

    for event_id in ("battle-1", "battle-2", "battle-3"):
        generated = tick_results(service.tick())
        assert len(generated) == 1
        assert event_id in result_text(generated[0])
    assert tick_results(service.tick()) == []


def test_delivery_claim_is_durable_and_unknown_receipt_is_never_resent(env):
    service, source, database, output, clock = env
    observed: list[str] = []

    def before_deliver(result: dict) -> None:
        observed.append(result["result_id"])
        with sqlite3.connect(str(database)) as connection:
            row = connection.execute(
                "SELECT body FROM info_results WHERE id=?", (result["result_id"],)
            ).fetchone()
        assert row is not None
        assert json.loads(row[0])["delivery"]["status"] == "delivering"

    output.before_deliver = before_deliver
    output.crash = True
    with pytest.raises(DeliveryInterrupted):
        service.query("unknown-receipt", queries=[QUERY])
    assert output.calls == 1
    assert len(observed) == 1
    result_id = observed[0]
    assert service.get_result(result_id)["delivery"]["status"] == "delivering"

    repeated = service.query("unknown-receipt", queries=[QUERY])
    assert repeated["result_id"] == result_id
    assert output.calls == 1
    assert len(source.read_calls) == 1

    service.close()
    restarted_output = FakeOutput()
    restarted = InformationService(
        source, database, output=restarted_output, clock=clock, owner="llm"
    )
    after_restart = restarted.query("unknown-receipt", queries=[QUERY])
    assert after_restart["result_id"] == result_id
    assert restarted_output.calls == 0
    assert restarted.get_result(result_id)["delivery"]["status"] == "delivering"
    restarted.close()


def test_game_date_rewind_clears_change_baseline_before_next_sample(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    subscription = create_subscription(
        service, report["id"], kind="change", basis="game", every=1, unit="days"
    )

    source.set_game_day(101, "1444.01.02")
    assert tick_results(service.tick()) == []
    source.values["value"] = 8
    source.set_game_day(102, "1444.01.03")
    assert len(tick_results(service.tick())) == 1

    source.values["value"] = 9
    source.set_game_day(101, "1444.01.02")
    assert tick_results(service.tick()) == []
    source.set_game_day(102, "1444.01.03")
    assert tick_results(service.tick()) == []

    source.values["value"] = 10
    source.set_game_day(103, "1444.01.04")
    generated = tick_results(service.tick())
    assert len(generated) == 1
    assert subscription["id"] in result_text(generated[0])


def test_game_date_rewind_clears_event_cursor(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    create_subscription(
        service,
        report["id"],
        kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    source.event_pages = [
        {"events": [_event(source, "rewind-1", 100)], "cursor": "cursor-1", "complete": True, "gaps": []}
    ]
    source.set_game_day(100, "1444.01.01")
    assert len(tick_results(service.tick())) == 1
    assert source.poll_calls[-1] is None

    source.set_game_day(99, "1443.12.31")
    source.event_pages = [
        {"events": [_event(source, "rewind-2", 99)], "cursor": "cursor-2", "complete": True, "gaps": []}
    ]
    generated = tick_results(service.tick())
    assert len(generated) == 1
    assert "rewind-2" in result_text(generated[0])
    assert source.poll_calls[-1] is None


def test_same_request_id_is_isolated_between_owners(tmp_path):
    source = FakeSource()
    database = tmp_path / "owners.sqlite3"
    clock = FakeClock()
    first_service = InformationService(source, database, clock=clock, owner="owner_a")
    second_service = InformationService(source, database, clock=clock, owner="owner_b")
    try:
        first = first_service.query("shared-request", queries=[QUERY])
        second = second_service.query("shared-request", queries=[QUERY])
        assert first["result_id"] != second["result_id"]
        assert first_service.get_result(first["result_id"])["owner"] == "owner_a"
        assert second_service.get_result(second["result_id"])["owner"] == "owner_b"
        assert first_service.query("shared-request", queries=[QUERY]) == first
    finally:
        first_service.close()
        second_service.close()


def test_resume_after_session_change_never_collects_old_binding(env):
    service, source, _database, _output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    paused = service.manage_subscription(
        "resume-scope-pause", "pause", subscription_id=subscription["id"],
        expected_version=subscription["version"],
    )["subscription"]

    source.set_session("session-b")
    resumed = service.manage_subscription(
        "resume-scope-resume", "resume", subscription_id=subscription["id"],
        expected_version=paused["version"],
    )["subscription"]
    assert resumed["state"] == "active"
    clock.advance(10)
    assert tick_results(service.tick()) == []
    runtime = service.status(subscription["id"])["subscriptions"][0]["runtime"]
    assert runtime["state"] == "scope_mismatch"


def test_one_event_is_delivered_to_each_matching_subscription_once(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    first = create_subscription(
        service, report["id"], "event-sub-a", kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    second = create_subscription(
        service, report["id"], "event-sub-b", kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    event = _event(source, "shared-event")
    source.event_pages = [
        {"events": [event], "cursor": "shared-1", "complete": True, "gaps": []},
        {"events": [event], "cursor": "shared-2", "complete": True, "gaps": []},
    ]

    generated = tick_results(service.tick())
    assert len(generated) == 2
    assert {item["subscription_id"] for item in generated} == {first["id"], second["id"]}
    assert tick_results(service.tick()) == []


def test_direct_query_output_failure_is_durable_and_not_retried(env):
    service, _source, _database, output, _clock = env
    output.fail = True
    first = service.query("direct-output-failure", queries=[QUERY])
    assert first["delivery"]["status"] == "failed"
    stored = service.get_result(first["result_id"])
    assert stored["delivery"]["status"] == "failed"

    repeated = service.query("direct-output-failure", queries=[QUERY])
    assert repeated["result_id"] == first["result_id"]
    assert repeated["delivery"]["status"] == "failed"
    assert output.calls == 1


def test_global_enabled_configuration_is_used_by_tick(env):
    service, _source, _database, _output, clock = env
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    disabled = service.configure(
        "disable-tick", "update", values={"enabled": False}, expected_version=0
    )
    assert disabled["config"]["effective"]["enabled"] is False
    clock.advance(10)
    tick = service.tick()
    assert tick["state"] == "disabled"
    assert tick_results(tick) == []

    enabled = service.configure(
        "enable-tick", "update", values={"enabled": True}, expected_version=1
    )
    assert enabled["config"]["effective"]["enabled"] is True
    clock.advance(10)
    assert subscription["id"] in result_text(tick_results(service.tick())[0])


def test_independent_processes_serialize_same_request_id(tmp_path):
    database = str(tmp_path / "multi-process.sqlite3")
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=context) as pool:
        futures = [
            pool.submit(_process_query_worker, database, "process-owner", "process-request")
            for _ in range(2)
        ]
        responses = [future.result(timeout=30) for future in futures]
    assert all(response[0] == "ok" for response in responses), responses
    assert len({response[1] for response in responses}) == 1
    assert sum(response[2] for response in responses) == 1


def test_context_change_during_collection_marks_result_stale(env):
    service, source, _database, _output, _clock = env
    source.context_change_on_read = {"session_id": "session-b", "game_day": 101}
    result = service.query("context-changes-during-read", queries=[QUERY])
    assert result["context"]["session_id"] == "session-a"
    assert result["complete"] is False
    assert all(
        field["status"] == "stale"
        for item in result["items"]
        for field in item["fields"].values()
    )


def test_restart_same_date_without_world_id_does_not_assume_same_world(tmp_path):
    database = tmp_path / "unknown-world.sqlite3"
    source = FakeSource()
    source.world_id = None
    clock = FakeClock()
    service = InformationService(source, database, clock=clock)
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    assert tick_results(service.tick()) == []  # persist the context checkpoint
    service.close()

    replacement = FakeSource()
    replacement.world_id = None
    replacement.values["value"] = 999
    restarted = InformationService(replacement, database, clock=clock)
    clock.advance(10)
    assert tick_results(restarted.tick()) == []
    runtime = restarted.status(subscription["id"])["subscriptions"][0]["runtime"]
    runtime_text = result_text(runtime).lower()
    assert any(
        marker in runtime_text for marker in ("world", "unknown", "stale", "scope")
    )
    restarted.close()


def test_unknown_world_revalidation_requires_explicit_resume(tmp_path):
    database = tmp_path / "unknown-world-resume.sqlite3"
    source = FakeSource()
    source.world_id = None
    clock = FakeClock()
    service = InformationService(source, database, clock=clock)
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    assert tick_results(service.tick()) == []
    service.close()

    replacement = FakeSource()
    replacement.world_id = None
    restarted = InformationService(replacement, database, clock=clock)
    runtime = restarted.status(subscription["id"])["subscriptions"][0]["runtime"]
    assert runtime["state"] == "world_revalidation_required"
    assert runtime["needs_rebind"] is True
    resumed = restarted.manage_subscription(
        "unknown-world-resume", "resume", subscription_id=subscription["id"],
        expected_version=subscription["version"],
    )["subscription"]
    assert resumed["version"] == subscription["version"] + 1
    clock.advance(10)
    generated = tick_results(restarted.tick())
    assert len(generated) == 1
    assert subscription["id"] in result_text(generated[0])
    restarted.close()


def test_stable_world_restart_keeps_existing_due_schedule(tmp_path):
    database = tmp_path / "stable-world.sqlite3"
    source = FakeSource()
    clock = FakeClock()
    service = InformationService(source, database, clock=clock)
    report = create_report(service)
    subscription = create_subscription(service, report["id"])
    assert tick_results(service.tick()) == []
    service.close()

    replacement = FakeSource()
    restarted = InformationService(replacement, database, clock=clock)
    clock.advance(10)
    generated = tick_results(restarted.tick())
    assert len(generated) == 1
    assert subscription["id"] in result_text(generated[0])
    restarted.close()


def test_object_actor_and_parameter_actor_conflict_is_rejected_before_read(env):
    service, source, _database, _output, _clock = env
    conflicting = deepcopy(QUERY)
    conflicting["object"] = {"type": "country", "id": "FRA", "actor": "FRA"}
    conflicting["parameters"] = {"tag": "FRA", "actor": "BUR"}
    with pytest.raises(InformationError) as exc_info:
        service.query("actor-conflict", queries=[conflicting])
    assert exc_info.value.code == "object_parameter_conflict"
    assert source.read_calls == []


def test_subscription_binding_unsupported_game_version_is_rejected(env):
    service, source, _database, _output, _clock = env
    report = create_report(service)
    config = subscription_config(
        report["id"],
        binding={
            "session_id": source.session_id,
            "observer": source.observer,
            "game_version": "9.9",
            "world_id": source.world_id,
        },
    )
    with pytest.raises(InformationError) as exc_info:
        service.manage_subscription("unsupported-binding", "create", config=config)
    assert exc_info.value.code == "unsupported_game_version"
    assert service.manage_subscription("list-after-binding-error", "list")["subscriptions"] == []


def test_query_object_from_another_session_is_rejected_without_source_read(env):
    service, source, _database, _output, _clock = env
    foreign = deepcopy(QUERY)
    foreign["object"] = {"type": "country", "id": "FRA", "session_id": "session-b"}
    result = service.query("foreign-session-object", queries=[foreign])
    assert result["complete"] is False
    assert result["status"] == "failed"
    assert "session_scope_mismatch" in result_text(result)
    assert source.read_calls == []


def _inbound_query() -> dict:
    return {
        "topic": TOPIC,
        "object": {
            "type": "country",
            "id": "SAV",
            "actor": "SAV",
            "recipient": "FRA",
        },
        "fields": ["value", "zero"],
        "parameters": {"tag": "SAV"},
    }


def test_recipient_observer_role_allows_inbound_query_and_default_actor_rejects(env):
    service, source, _database, _output, _clock = env
    inbound = _inbound_query()
    source.observer_roles = ["recipient"]
    allowed = service.query("recipient-role-query", queries=[inbound])
    assert allowed["complete"] is True
    assert len(source.read_calls) == 1

    source.observer_roles = None  # topic default is actor
    rejected = service.query("default-actor-query", queries=[inbound])
    assert rejected["complete"] is False
    assert rejected["status"] == "failed"
    assert "observer_scope_mismatch" in result_text(rejected)
    assert len(source.read_calls) == 1


def test_subscription_binding_uses_topic_observer_role(env):
    service, source, _database, _output, _clock = env
    inbound = _inbound_query()
    source.observer_roles = ["recipient"]
    recipient_report = create_report(
        service, "recipient-role-report", query=inbound
    )
    recipient_subscription = create_subscription(
        service, recipient_report["id"], "recipient-role-subscription"
    )
    assert recipient_subscription["state"] == "active"

    source.observer_roles = None
    actor_report = create_report(service, "actor-role-report", query=inbound)
    with pytest.raises(InformationError) as exc_info:
        create_subscription(service, actor_report["id"], "actor-role-subscription")
    assert exc_info.value.code == "observer_scope_mismatch"


def test_nested_additional_properties_parameters_are_preserved_and_accepted(env):
    service, source, _database, _output, _clock = env
    query = deepcopy(QUERY)
    query["parameters"] = {
        "tag": "FRA",
        "options": {
            "future_flag": True,
            "nested": {"counter": 2, "opaque": ["a", "b"]},
        },
    }
    result = service.query("nested-parameters", queries=[query])
    assert result["complete"] is True
    assert source.read_calls[0][0]["parameters"] == query["parameters"]



