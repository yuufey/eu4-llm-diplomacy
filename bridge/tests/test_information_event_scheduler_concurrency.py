"""Concurrency contracts for durable event polling and target projection."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import threading
from typing import Any, Callable

import pytest

from bridge.information import InformationService
from bridge.tests.test_information_service import (
    EventAwareSource,
    FakeClock,
    FakeOutput,
    QUERY,
    create_report,
    create_subscription,
    records,
    report_config,
    result_text,
    subscription_config,
    tick_results,
)


class EventGate:
    def __init__(self, operation: str, fields: tuple[str, ...] | None = None) -> None:
        self.operation = operation
        self.fields = fields
        self.entered = threading.Event()
        self.release = threading.Event()


class EventReadInterrupted(BaseException):
    """Simulate process interruption during one event projection."""


class GatedEventSource(EventAwareSource):
    """Gate poll/read_event outside FakeSource's internal RLock."""

    def __init__(self) -> None:
        super().__init__()
        self.context_status = "ready"
        self._gate_lock = threading.Lock()
        self._next_gate: EventGate | None = None
        self._active_gate: EventGate | None = None
        self.attempts = {"poll": 0, "read_event": 0}
        self.interrupt_read_event_attempt: int | None = None
        self.successful_read_fields: list[tuple[str, ...]] = []
        self.replay_fields: list[tuple[str, ...]] = []

    def context(self) -> dict:
        with self._lock:
            context = super().context()
            context["status"] = self.context_status
            return context

    def set_context_status(self, status: str) -> None:
        with self._lock:
            self.context_status = status

    def block_next(self, operation: str, fields: tuple[str, ...] | None = None) -> EventGate:
        if operation not in {"poll", "read_event"}:
            raise ValueError(operation)
        gate = EventGate(operation, fields)
        with self._gate_lock:
            if self._next_gate is not None or self._active_gate is not None:
                raise AssertionError("an event operation is already armed or blocked")
            self._next_gate = gate
        return gate

    def release_blocked(self) -> None:
        with self._gate_lock:
            gates = (self._next_gate, self._active_gate)
        for gate in gates:
            if gate is not None:
                gate.release.set()

    def _enter_operation(
        self, operation: str, fields: tuple[str, ...] | None = None
    ) -> tuple[EventGate | None, int]:
        with self._gate_lock:
            self.attempts[operation] += 1
            attempt = self.attempts[operation]
            gate = self._next_gate
            if gate is not None and gate.operation == operation:
                if gate.fields is None or gate.fields == fields:
                    self._next_gate = None
                    self._active_gate = gate
                else:
                    gate = None
            else:
                gate = None
        if gate is not None:
            gate.entered.set()
            if not gate.release.wait(timeout=5.0):
                raise RuntimeError("test did not release the blocked event operation")
            with self._gate_lock:
                self._active_gate = None
        return gate, attempt

    def poll_events(self, context: dict, cursor: Any) -> dict:
        self._enter_operation("poll")
        return super().poll_events(context, cursor)

    def read_event(self, query: dict, context: dict, event: dict) -> dict:
        fields = tuple(query.get("fields", ()))
        _gate, attempt = self._enter_operation("read_event", fields)
        if attempt == self.interrupt_read_event_attempt:
            raise EventReadInterrupted("interrupted during event projection")
        sample = super().read_event(query, context, event)
        self.successful_read_fields.append(fields)
        return sample

    def replay_event(self, query: dict, context: dict, event: dict) -> dict:
        """Project from the event archive without invoking the live read hook."""
        fields = tuple(query.get("fields", ()))
        self.replay_fields.append(fields)
        payload = event.get("payload", {})
        projected = {
            name: {"status": "known", "value": payload[name]}
            if name in payload
            else {"status": "unknown", "reason": "event_field_missing"}
            for name in fields
        }
        return {
            "fields": projected,
            "complete": all(item["status"] == "known" for item in projected.values()),
            "source": {"name": "durable-event-archive", "event_id": event.get("event_id")},
        }


@pytest.fixture
def event_env(tmp_path):
    source = GatedEventSource()
    database = tmp_path / "information-event-concurrency.sqlite3"
    output = FakeOutput()
    clock = FakeClock()
    service = InformationService(source, database, output=output, clock=clock)
    yield service, source, database, output, clock
    source.release_blocked()
    service.close()


def _event(
    source: GatedEventSource,
    event_id: str,
    *,
    value: int = 17,
    zero: int = 23,
) -> dict:
    return {
        "event_id": event_id,
        "event_type": "battle",
        "actor": "FRA",
        "recipient": "BUR",
        "session_id": source.session_id,
        "observer": source.observer,
        "game_day": source.game_day,
        "payload": {"value": value, "zero": zero},
    }


def _target(
    service: InformationService,
    fields: tuple[str, ...],
    request_prefix: str,
    *,
    report_id: str | None = None,
) -> tuple[dict, dict]:
    if report_id is None:
        query = {**QUERY, "fields": list(fields)}
        report = create_report(service, f"{request_prefix}-report", query=query)
        report_id = report["id"]
    else:
        report = service.manage_report(
            f"{request_prefix}-report-get", "get", report_id=report_id
        )["report"]
    subscription = create_subscription(
        service,
        report_id,
        f"{request_prefix}-subscription",
        kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )
    return report, subscription


def _page(*events: dict, cursor: str = "cursor-1") -> dict:
    return {"events": list(events), "cursor": cursor, "complete": True, "gaps": []}


def _start_blocked_tick(
    source: GatedEventSource,
    pool: ThreadPoolExecutor,
    service: InformationService,
    operation: str,
    fields: tuple[str, ...] | None = None,
) -> tuple[EventGate, Any]:
    gate = source.block_next(operation, fields)
    future = pool.submit(service.tick)
    if not gate.entered.wait(timeout=2.0):
        gate.release.set()
        raise AssertionError(f"{operation} did not reach its event gate")
    return gate, future


def _complete_before_release(pool: ThreadPoolExecutor, operation: Callable[[], Any]) -> Any:
    return pool.submit(operation).result(timeout=1.5)


def _event_target_rows(database, event_id: str) -> dict[str, tuple[str, dict]]:
    with sqlite3.connect(str(database)) as connection:
        rows = connection.execute(
            "SELECT subscription_id, status, body FROM info_event_targets WHERE event_id=?",
            (event_id,),
        ).fetchall()
    return {subscription_id: (status, json.loads(body)) for subscription_id, status, body in rows}


def _all_results(service: InformationService) -> list[dict]:
    return records(service.list_results(), "results")


@pytest.mark.parametrize("operation", ["poll", "read_event"])
def test_blocked_event_io_allows_status_and_cancel_while_sibling_delivers(
    event_env, operation: str
):
    service, source, _database, output, _clock = event_env
    _target_report, target = _target(service, ("value",), "cancel-target")
    _sibling_report, sibling = _target(service, ("zero",), "surviving-sibling")
    event = _event(source, f"blocked-{operation}")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        fields = ("value",) if operation == "read_event" else None
        gate, tick_future = _start_blocked_tick(source, pool, service, operation, fields)
        try:
            context = _complete_before_release(pool, source.context)
            assert context["session_id"] == "session-a"
            _complete_before_release(pool, lambda: service.status(target["id"]))
            cancelled = _complete_before_release(
                pool,
                lambda: service.manage_subscription(
                    "cancel-during-event-read",
                    "cancel",
                    subscription_id=target["id"],
                    expected_version=target["version"],
                ),
            )["subscription"]
            assert cancelled["state"] == "cancelled"
        finally:
            gate.release.set()
        tick = tick_future.result(timeout=2.0)

    generated = tick_results(tick)
    assert len(generated) == 1
    assert generated[0]["subscription_id"] == sibling["id"]
    assert all(item["subscription_id"] != target["id"] for item in generated)
    assert len(output.delivered) == 1
    assert service.get_result(output.delivered[0]["result_id"])["subscription_id"] == sibling["id"]


@pytest.mark.parametrize("mutation", ["report", "subscription"])
def test_staged_event_target_cas_discards_old_report_or_subscription_version(
    event_env, mutation: str
):
    service, source, database, output, _clock = event_env
    target_report, target = _target(service, ("value",), "cas-target")
    _sibling_report, sibling = _target(service, ("zero",), "cas-sibling")
    event = _event(source, f"cas-{mutation}")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        gate, tick_future = _start_blocked_tick(
            source, pool, service, "read_event", ("value",)
        )
        try:
            if mutation == "report":
                updated_report = _complete_before_release(
                    pool,
                    lambda: service.manage_report(
                        "report-update-during-event-read",
                        "update",
                        report_id=target_report["id"],
                        config={**report_config(query={**QUERY, "fields": ["value"]}),
                                "name": "updated target report"},
                        expected_version=target_report["version"],
                    ),
                )["report"]
                assert updated_report["version"] == target_report["version"] + 1
            else:
                updated_subscription = _complete_before_release(
                    pool,
                    lambda: service.manage_subscription(
                        "subscription-update-during-event-read",
                        "update",
                        subscription_id=target["id"],
                        config=subscription_config(
                            target_report["id"],
                            name="updated event subscription",
                            kind="event",
                            event={"types": ["battle"], "actors": ["FRA"],
                                   "recipients": ["BUR"]},
                        ),
                        expected_version=target["version"],
                    ),
                )["subscription"]
                assert updated_subscription["version"] == target["version"] + 1
        finally:
            gate.release.set()
        tick = tick_future.result(timeout=2.0)

    generated = tick_results(tick)
    assert [item["subscription_id"] for item in generated] == [sibling["id"]]
    assert output.calls == 1
    assert len(_all_results(service)) == 1
    rows = _event_target_rows(database, event["event_id"])
    assert rows[target["id"]][0] == "discarded"
    assert rows[sibling["id"]][0] == "committed"
    assert len([item for item in _all_results(service)
                if item.get("subscription_id") == target["id"]]) == 0


def test_disable_keeps_ready_projection_until_reenable_without_repoll_or_read(event_env):
    service, source, database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "disable-target")
    event = _event(source, "disable-ready-event")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=3) as pool:
        gate, tick_future = _start_blocked_tick(
            source, pool, service, "read_event", ("value",)
        )
        try:
            disabled = _complete_before_release(
                pool,
                lambda: service.configure(
                    "disable-during-event-projection",
                    "update",
                    values={"enabled": False},
                    expected_version=0,
                ),
            )
            assert disabled["config"]["effective"]["enabled"] is False
        finally:
            gate.release.set()
        first_tick = tick_future.result(timeout=2.0)

    assert tick_results(first_tick) == []
    assert output.calls == 0
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "ready"

    service.configure(
        "enable-after-event-projection",
        "update",
        values={"enabled": True},
        expected_version=1,
    )
    resumed = tick_results(service.tick())
    assert len(resumed) == 1
    assert resumed[0]["subscription_id"] == subscription["id"]
    assert output.calls == 1
    assert len(_all_results(service)) == 1
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "committed"


def test_budget_keeps_staged_batch_and_new_subscription_cannot_join_it(event_env):
    service, source, database, output, _clock = event_env
    _report, old_subscription = _target(service, ("value",), "budget-old")
    service.configure(
        "budget-one-event",
        "update",
        values={"max_results_per_tick": 1},
        expected_version=0,
    )
    events = [_event(source, f"budget-event-{index}", value=100 + index) for index in range(1, 4)]
    source.event_pages = [_page(*events, cursor="budget-cursor")]
    source.repeat_event_batch = True

    first = tick_results(service.tick())
    assert len(first) == 1 and "budget-event-1" in result_text(first[0])
    assert first[0]["subscription_id"] == old_subscription["id"]
    assert len(source.poll_calls) == 1

    new_subscription = create_subscription(
        service,
        old_subscription["report_id"],
        "budget-new-subscription",
        kind="event",
        event={"types": ["battle"], "actors": ["FRA"], "recipients": ["BUR"]},
    )

    second = tick_results(service.tick())
    third = tick_results(service.tick())
    assert len(second) == len(third) == 1
    assert "budget-event-2" in result_text(second[0])
    assert "budget-event-3" in result_text(third[0])
    assert all(item["subscription_id"] == old_subscription["id"] for item in second + third)
    assert all(item["subscription_id"] != new_subscription["id"] for item in first + second + third)
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 3
    for event in events:
        rows = _event_target_rows(database, event["event_id"])
        assert rows[old_subscription["id"]][0] == "committed"
        assert new_subscription["id"] not in rows
    assert output.calls == 3


@pytest.mark.parametrize("replay_available", [True, False])
def test_interrupted_target_recovery_preserves_committed_sibling_and_replays_only_pending(
    event_env, replay_available: bool
):
    service, source, database, _output, _clock = event_env
    _value_report, value_subscription = _target(service, ("value",), "recovery-value")
    _zero_report, zero_subscription = _target(service, ("zero",), "recovery-zero")
    event = _event(source, f"recovery-{replay_available}")
    source.event_pages = [_page(event)]
    source.interrupt_read_event_attempt = 2
    if not replay_available:
        source.replay_event = None

    with pytest.raises(EventReadInterrupted):
        service.tick()

    successful_fields = source.successful_read_fields
    assert len(successful_fields) == 1
    committed_subscription = (
        value_subscription["id"] if successful_fields[0] == ("value",)
        else zero_subscription["id"]
    )
    interrupted_subscription = (
        zero_subscription["id"] if committed_subscription == value_subscription["id"]
        else value_subscription["id"]
    )
    before_rows = _event_target_rows(database, event["event_id"])
    assert before_rows[committed_subscription][0] == "committed"
    assert before_rows[interrupted_subscription][0] == "collecting"
    committed_before = [item for item in _all_results(service)
                        if item.get("subscription_id") == committed_subscription]
    assert len(committed_before) == 1
    committed_result_id = committed_before[0]["result_id"]

    recovered = tick_results(service.tick())
    after_results = _all_results(service)
    by_subscription = {
        subscription_id: [item for item in after_results
                          if item.get("subscription_id") == subscription_id]
        for subscription_id in (value_subscription["id"], zero_subscription["id"])
    }
    assert len(by_subscription[committed_subscription]) == 1
    assert by_subscription[committed_subscription][0]["result_id"] == committed_result_id
    assert len(by_subscription[interrupted_subscription]) == 1
    assert all(item["subscription_id"] != committed_subscription for item in recovered)
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert len(source.successful_read_fields) == 1
    if replay_available:
        assert len(source.replay_fields) == 1
        assert source.replay_fields == [("zero",) if interrupted_subscription == zero_subscription["id"] else ("value",)]
        assert "EVENT_PROJECTION_INTERRUPTED_NOT_REPLAYED" not in result_text(
            by_subscription[interrupted_subscription][0]
        )
    else:
        assert source.replay_fields == []
        assert source.read_calls == []
        assert "EVENT_PROJECTION_INTERRUPTED_NOT_REPLAYED" in result_text(
            by_subscription[interrupted_subscription][0]
        )
    after_rows = _event_target_rows(database, event["event_id"])
    assert after_rows[committed_subscription][0] == "committed"
    assert after_rows[interrupted_subscription][0] == "committed"


def test_same_event_id_with_changed_payload_records_gap_without_second_notification(event_env):
    service, source, _database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "payload-conflict")
    source.event_pages = [
        _page(_event(source, "conflicting-event", value=1), cursor="conflict-1"),
        _page(_event(source, "conflicting-event", value=2), cursor="conflict-2"),
    ]

    first = tick_results(service.tick())
    second = tick_results(service.tick())
    assert len(first) == 1
    assert first[0]["subscription_id"] == subscription["id"]
    assert second == []
    assert output.calls == 1
    assert len(source.read_event_calls) == 1
    assert "event_identity_conflict" in result_text(service.status()["event_source"])


@pytest.mark.parametrize("operation", ["poll", "read_event"])
def test_source_scope_change_during_event_collection_discards_old_projection(
    event_env, operation: str
):
    service, source, _database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "scope-change")
    event = _event(source, f"scope-{operation}")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=2) as pool:
        fields = ("value",) if operation == "read_event" else None
        gate, tick_future = _start_blocked_tick(source, pool, service, operation, fields)
        try:
            source.set_session("session-b")
        finally:
            gate.release.set()
        tick = tick_future.result(timeout=2.0)

    assert tick_results(tick) == []
    assert output.calls == 0
    assert len(source.poll_calls) == 1
    status = service.status(subscription["id"])
    assert status["subscriptions"][0]["runtime"]["state"] == "scope_mismatch"
    assert not any(item.get("subscription_id") == subscription["id"] for item in _all_results(service))


def test_unready_after_blocked_event_read_keeps_raw_batch_and_replays_when_ready(event_env):
    service, source, database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "transient-read")
    event = _event(source, "transient-read-event")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=2) as pool:
        gate, tick_future = _start_blocked_tick(
            source, pool, service, "read_event", ("value",)
        )
        source.set_context_status("unready")
        gate.release.set()
        first_tick = tick_future.result(timeout=2.0)

    assert tick_results(first_tick) == []
    assert output.calls == 0
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    state = service.status()["event_source"]
    assert any(item["event_id"] == event["event_id"] for item in state["pending"])
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "collecting"

    source.set_context_status("ready")
    resumed = tick_results(service.tick())
    assert len(resumed) == 1
    assert resumed[0]["subscription_id"] == subscription["id"]
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert source.replay_fields == [("value",)]
    assert output.calls == 1
    assert len(_all_results(service)) == 1
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "committed"


def test_unready_ready_projection_waits_then_publishes_prepared_result(event_env):
    service, source, database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "transient-prepared")
    event = _event(source, "transient-prepared-event")
    source.event_pages = [_page(event)]

    with ThreadPoolExecutor(max_workers=3) as pool:
        gate, tick_future = _start_blocked_tick(
            source, pool, service, "read_event", ("value",)
        )
        try:
            disabled = _complete_before_release(
                pool,
                lambda: service.configure(
                    "disable-before-event-projection-commit",
                    "update",
                    values={"enabled": False},
                    expected_version=0,
                ),
            )
            assert disabled["config"]["effective"]["enabled"] is False
        finally:
            gate.release.set()
        first_tick = tick_future.result(timeout=2.0)

    assert tick_results(first_tick) == []
    assert output.calls == 0
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "ready"

    source.set_context_status("unready")
    service.configure(
        "enable-while-source-unready",
        "update",
        values={"enabled": True},
        expected_version=1,
    )
    waiting_tick = service.tick()
    assert tick_results(waiting_tick) == []
    assert output.calls == 0
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "ready"
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1

    source.set_context_status("ready")
    resumed = tick_results(service.tick())
    assert len(resumed) == 1
    assert resumed[0]["subscription_id"] == subscription["id"]
    assert output.calls == 1
    assert len(_all_results(service)) == 1
    assert len(source.poll_calls) == 1
    assert len(source.read_event_calls) == 1
    assert source.replay_fields == []
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "committed"


def test_poll_batch_survives_post_poll_unready_health_without_repoll(event_env):
    service, source, database, output, _clock = event_env
    _report, subscription = _target(service, ("value",), "poll-health")
    event = _event(source, "post-poll-unready-event")
    source.event_pages = [_page(event, cursor="post-poll-health-cursor")]

    with ThreadPoolExecutor(max_workers=2) as pool:
        gate, tick_future = _start_blocked_tick(source, pool, service, "poll")
        source.set_context_status("unready")
        gate.release.set()
        first_tick = tick_future.result(timeout=2.0)

    assert tick_results(first_tick) == []
    assert output.calls == 0
    assert source.poll_calls == [None]
    assert source.read_event_calls == []
    state = service.status()["event_source"]
    assert state["cursor"] == "post-poll-health-cursor"
    assert state["complete"] is False
    assert state["poll_health_unverified"] is True
    assert any(item["event_id"] == event["event_id"] for item in state["pending"])
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "pending"

    source.set_context_status("ready")
    resumed = tick_results(service.tick())
    assert len(resumed) == 1
    assert resumed[0]["subscription_id"] == subscription["id"]
    assert source.poll_calls == [None]
    assert len(source.read_event_calls) == 1
    assert source.replay_fields == []
    assert output.calls == 1
    assert len(_all_results(service)) == 1
    assert _event_target_rows(database, event["event_id"])[subscription["id"]][0] == "committed"
