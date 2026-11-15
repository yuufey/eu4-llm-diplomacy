"""Concurrency contracts for information collection and subscription ticks.

The blocked source waits outside ``FakeSource``'s internal lock so ordinary
context reads remain available while a collection is in flight.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
from typing import Any, Callable

import pytest

from bridge.information import InformationError, InformationService
from bridge.tests.test_information_service import (
    FakeClock,
    FakeOutput,
    FakeSource,
    QUERY,
    create_report,
    create_subscription,
    report_config,
    subscription_config,
    tick_results,
)


class ReadGate:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()


class BlockingSource(FakeSource):
    """Block one external read without holding FakeSource._lock."""

    def __init__(self) -> None:
        super().__init__()
        self._gate_lock = threading.Lock()
        self._next_gate: ReadGate | None = None
        self._active_gate: ReadGate | None = None
        self.read_attempts = 0

    def block_next_read(self) -> ReadGate:
        gate = ReadGate()
        with self._gate_lock:
            if self._next_gate is not None or self._active_gate is not None:
                raise AssertionError("a read is already armed or blocked")
            self._next_gate = gate
        return gate

    def release_reads(self) -> None:
        with self._gate_lock:
            gates = (self._next_gate, self._active_gate)
        for gate in gates:
            if gate is not None:
                gate.release.set()

    def read(self, query: dict, context: dict) -> dict:
        with self._gate_lock:
            gate = self._next_gate
            self._next_gate = None
            self._active_gate = gate
            self.read_attempts += 1
        if gate is not None:
            gate.entered.set()
            if not gate.release.wait(timeout=5.0):
                raise RuntimeError("test did not release the blocked source read")
            with self._gate_lock:
                self._active_gate = None
        return super().read(query, context)


class ReadInterrupted(BaseException):
    """Simulate interruption after a durable manual request claim."""


class InterruptingSource(FakeSource):
    def __init__(self) -> None:
        super().__init__()
        self.interrupt_next_read = True

    def read(self, query: dict, context: dict) -> dict:
        result = super().read(query, context)
        if self.interrupt_next_read:
            self.interrupt_next_read = False
            raise ReadInterrupted("interrupted after the source read")
        return result


@pytest.fixture
def concurrency_env(tmp_path):
    source = BlockingSource()
    database = tmp_path / "information-concurrency.sqlite3"
    output = FakeOutput()
    clock = FakeClock()
    service = InformationService(source, database, output=output, clock=clock)
    return service, source, database, output, clock


def _run_blocked_read(
    source: BlockingSource,
    pool: ThreadPoolExecutor,
    operation: Callable[[], Any],
) -> tuple[ReadGate, Any]:
    gate = source.block_next_read()
    future = pool.submit(operation)
    if not gate.entered.wait(timeout=2.0):
        gate.release.set()
        raise AssertionError("source read did not reach the gate")
    return gate, future


def _complete_before_release(pool: ThreadPoolExecutor, operation: Callable[[], Any]) -> Any:
    return pool.submit(operation).result(timeout=1.5)


def _runtime(service: InformationService, subscription_id: str) -> dict:
    return service.status(subscription_id)["subscriptions"][0]["runtime"]


def test_blocked_periodic_read_allows_status_cancel_and_sibling_progress(concurrency_env):
    service, source, _database, output, clock = concurrency_env
    report = create_report(service)
    target = create_subscription(service, report["id"], "target-create", every=10)
    sibling = create_subscription(
        service, report["id"], "sibling-create", name="sibling", every=20
    )
    clock.advance(10)

    with ThreadPoolExecutor(max_workers=5) as pool:
        gate, tick_future = _run_blocked_read(source, pool, service.tick)
        try:
            # The test source's context() uses the same internal RLock as read().
            assert source.context()["session_id"] == "session-a"
            _complete_before_release(pool, lambda: service.status(target["id"]))
            cancelled = _complete_before_release(
                pool,
                lambda: service.manage_subscription(
                    "cancel-in-flight",
                    "cancel",
                    subscription_id=target["id"],
                    expected_version=target["version"],
                ),
            )["subscription"]
            assert cancelled["state"] == "cancelled"
            _complete_before_release(pool, lambda: service.configure("get-config", "get"))
        finally:
            gate.release.set()

        assert tick_results(tick_future.result(timeout=2.0)) == []

    assert output.calls == 0
    clock.advance(10)
    sibling_results = tick_results(service.tick())
    assert any(sibling["id"] in str(item) for item in sibling_results)
    assert not any(target["id"] in str(item) for item in sibling_results)


@pytest.mark.parametrize("mutation", ["report", "subscription", "disable"])
def test_in_flight_periodic_snapshot_cannot_overwrite_concurrent_update(
    concurrency_env, mutation: str
):
    service, source, _database, output, clock = concurrency_env
    report = create_report(service)
    subscription = create_subscription(service, report["id"], "subscription-create")
    clock.advance(10)

    with ThreadPoolExecutor(max_workers=4) as pool:
        gate, tick_future = _run_blocked_read(source, pool, service.tick)
        try:
            if mutation == "report":
                _complete_before_release(
                    pool,
                    lambda: service.manage_report(
                        "report-update-during-read",
                        "update",
                        report_id=report["id"],
                        config={**report_config(), "name": "updated report"},
                        expected_version=report["version"],
                    ),
                )
            elif mutation == "subscription":
                _complete_before_release(
                    pool,
                    lambda: service.manage_subscription(
                        "subscription-update-during-read",
                        "update",
                        subscription_id=subscription["id"],
                        config=subscription_config(
                            report["id"], name="updated subscription", every=30
                        ),
                        expected_version=subscription["version"],
                    ),
                )
            else:
                _complete_before_release(
                    pool,
                    lambda: service.configure(
                        "disable-during-read",
                        "update",
                        values={"enabled": False},
                        expected_version=0,
                    ),
                )
            runtime_after_mutation = _complete_before_release(
                pool, lambda: _runtime(service, subscription["id"])
            )
        finally:
            gate.release.set()

        tick = tick_future.result(timeout=2.0)

    assert tick_results(tick) == []
    assert output.calls == 0
    runtime_after_tick = _runtime(service, subscription["id"])
    if mutation == "subscription":
        assert runtime_after_tick == runtime_after_mutation
    else:
        for key in ("next_due", "last_clock", "baseline", "baseline_scope"):
            assert runtime_after_tick.get(key) == runtime_after_mutation.get(key)
        assert "collection" not in runtime_after_tick
        assert runtime_after_tick["last_attempt"]["status"] == (
            "discarded_report_changed"
            if mutation == "report"
            else "discarded_configuration_changed"
        )
        current_subscription = service.manage_subscription(
            f"subscription-after-{mutation}",
            "get",
            subscription_id=subscription["id"],
        )["subscription"]
        assert current_subscription["version"] == subscription["version"]
        if mutation == "report":
            current_report = service.manage_report(
                "report-after-in-flight-read", "get", report_id=report["id"]
            )["report"]
            assert current_report["version"] == report["version"] + 1
        else:
            current_config = service.configure("config-after-in-flight-read", "get")["config"]
            assert current_config["effective"]["enabled"] is False


@pytest.mark.parametrize("second_tick", ["same_service", "independent_service"])
def test_collection_lock_makes_concurrent_tick_return_busy(
    concurrency_env, second_tick: str
):
    service, source, database, _output, clock = concurrency_env
    report = create_report(service)
    create_subscription(service, report["id"], "subscription-create")
    other_source = source if second_tick == "same_service" else FakeSource()
    other_service = (
        service
        if second_tick == "same_service"
        else InformationService(other_source, database, clock=clock)
    )
    clock.advance(10)

    with ThreadPoolExecutor(max_workers=2) as pool:
        gate, first_future = _run_blocked_read(source, pool, service.tick)
        try:
            busy = other_service.tick()
            assert busy.get("state") == "busy"
            assert tick_results(busy) == []
            assert source.read_attempts == 1
            if other_source is not source:
                assert other_source.read_calls == []
        finally:
            gate.release.set()
        assert len(tick_results(first_future.result(timeout=2.0))) == 1

    if other_service is not service:
        other_service.close()


def test_manual_query_is_claimed_once_and_does_not_hold_configuration_lock(
    concurrency_env,
):
    service, source, _database, _output, _clock = concurrency_env
    report = create_report(service)
    subscription = create_subscription(service, report["id"], "subscription-create")
    with ThreadPoolExecutor(max_workers=5) as pool:
        gate, first_future = _run_blocked_read(
            source, pool, lambda: service.query("blocked-manual-query", queries=[QUERY])
        )
        try:
            assert source.context()["session_id"] == "session-a"
            _complete_before_release(pool, lambda: service.status(subscription["id"]))
            _complete_before_release(
                pool,
                lambda: service.manage_subscription(
                    "cancel-during-manual-query",
                    "cancel",
                    subscription_id=subscription["id"],
                    expected_version=subscription["version"],
                ),
            )
            _complete_before_release(pool, lambda: service.configure("manual-config", "get"))
            duplicate_future = pool.submit(
                lambda: service.query("blocked-manual-query", queries=[QUERY])
            )
        finally:
            gate.release.set()

        first = first_future.result(timeout=2.0)
        try:
            duplicate = duplicate_future.result(timeout=2.0)
        except InformationError as exc:
            assert "request_outcome_unknown" in str(exc)
        else:
            assert duplicate["result_id"] == first["result_id"] or (
                "request_outcome_unknown" in str(duplicate)
            )

    assert source.read_attempts == 1
    assert len(source.read_calls) == 1


def test_interrupted_manual_claim_is_not_reread(concurrency_env):
    _unused, _blocking_source, database, output, clock = concurrency_env
    source = InterruptingSource()
    service = InformationService(source, database, output=output, clock=clock)

    with pytest.raises(ReadInterrupted):
        service.query("interrupted-manual-query", queries=[QUERY])

    try:
        repeated = service.query("interrupted-manual-query", queries=[QUERY])
    except InformationError as exc:
        assert exc.code == "request_outcome_unknown"
    else:
        assert "request_outcome_unknown" in str(repeated)
    assert len(source.read_calls) == 1


@pytest.mark.parametrize("failure", ["read_error", "context_change"])
def test_change_sample_failure_or_context_change_preserves_baseline(
    concurrency_env, failure: str
):
    service, source, _database, output, _clock = concurrency_env
    report = create_report(service)
    subscription = create_subscription(
        service,
        report["id"],
        "change-create",
        kind="change",
        basis="game",
        every=1,
        unit="days",
    )
    source.set_game_day(101)
    assert tick_results(service.tick()) == []
    before = _runtime(service, subscription["id"])
    source.values["value"] = 99
    source.set_game_day(102)
    if failure == "read_error":
        source.read_error = "blocked change read failed"
    else:
        source.context_change_on_read = {"session_id": "session-b"}

    with ThreadPoolExecutor(max_workers=4) as pool:
        gate, tick_future = _run_blocked_read(source, pool, service.tick)
        try:
            _complete_before_release(pool, lambda: service.status(subscription["id"]))
            _complete_before_release(pool, lambda: service.configure("change-config", "get"))
        finally:
            gate.release.set()
        assert tick_results(tick_future.result(timeout=2.0)) == []

    after = _runtime(service, subscription["id"])
    assert after["baseline"] == before["baseline"]
    assert after.get("last_result_id") == before.get("last_result_id")
    assert output.calls == 0


def test_close_waits_until_blocked_source_read_finishes(concurrency_env):
    service, source, _database, _output, clock = concurrency_env
    report = create_report(service)
    create_subscription(service, report["id"], "subscription-create")
    clock.advance(10)
    close_started = threading.Event()
    close_finished = threading.Event()

    def close_service() -> None:
        close_started.set()
        try:
            service.close()
        finally:
            close_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        gate, tick_future = _run_blocked_read(source, pool, service.tick)
        try:
            close_future = pool.submit(close_service)
            assert close_started.wait(timeout=1.0)
            assert not close_finished.wait(timeout=1.0)
        finally:
            gate.release.set()
        assert len(tick_results(tick_future.result(timeout=2.0))) == 1
        close_future.result(timeout=2.0)
        assert close_finished.is_set()
