"""Host-to-native country assignment file and acknowledgement protocol."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import time

import pytest

from bridge import country_control_runtime as runtime


class FakeSession:
    def __init__(self, directory: Path, *, session_id: str = "session-1",
                 capabilities=None, health_status: str = "ready"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id
        self._capabilities = frozenset(
            {runtime.CAPABILITY} if capabilities is None else capabilities
        )
        self._health_status = health_status
        self.health_calls = 0

    def installation_capabilities(self):
        return self._capabilities

    def health(self):
        self.health_calls += 1
        return {"status": self._health_status}


def _ack_for_request(request_line: bytes, *, accepted: bool = True) -> dict:
    header, session_id, revision, country_text = request_line.decode("ascii").strip().split("\t")
    assert header == "EU4CONTROL1"
    return {
        "event": runtime.ACK_EVENT,
        "session_id": session_id,
        "revision": int(revision),
        "countries": [] if country_text == "-" else country_text.split(","),
        "accepted": accepted,
    }


def _start_ack_writer(session: FakeSession, *, mutate=None, accepted: bool = True):
    request = session.directory / runtime.REQUEST_NAME
    log = session.directory / "control-probe.jsonl"
    baseline = request.read_bytes() if request.exists() else None
    finished = threading.Event()
    failures: list[BaseException] = []

    def write_ack():
        deadline = time.monotonic() + 2.0
        try:
            while time.monotonic() < deadline:
                if request.exists():
                    try:
                        content = request.read_bytes()
                    except PermissionError:
                        # Atomic replacement can briefly conflict with the
                        # native writer's Windows handle. Retry only this
                        # narrow sharing window inside the existing deadline.
                        time.sleep(0.002)
                        continue
                    if content and content != baseline:
                        ack = _ack_for_request(content, accepted=accepted)
                        if mutate is not None:
                            mutate(ack)
                        try:
                            with log.open("a", encoding="utf-8", newline="\n") as stream:
                                stream.write(json.dumps(ack, sort_keys=True) + "\n")
                            return
                        except PermissionError:
                            time.sleep(0.002)
                time.sleep(0.001)
            raise AssertionError("runtime did not publish the request file")
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=write_ack, daemon=True)
    thread.start()
    return thread, finished, failures


def _start_ack_server(session: FakeSession, request_count: int):
    request = session.directory / runtime.REQUEST_NAME
    log = session.directory / "control-probe.jsonl"
    seen: set[bytes] = set()
    captured: list[bytes] = []
    failures: list[BaseException] = []

    def serve():
        deadline = time.monotonic() + 3.0
        try:
            while len(seen) < request_count and time.monotonic() < deadline:
                if request.exists():
                    try:
                        content = request.read_bytes()
                    except PermissionError:
                        time.sleep(0.002)
                        continue
                    if content and content not in seen:
                        ack = _ack_for_request(content)
                        try:
                            with log.open("a", encoding="utf-8", newline="\n") as stream:
                                stream.write(json.dumps(ack, sort_keys=True) + "\n")
                        except PermissionError:
                            time.sleep(0.002)
                            continue
                        seen.add(content)
                        captured.append(content)
                time.sleep(0.001)
            if len(seen) != request_count:
                raise AssertionError(
                    f"runtime published {len(seen)} request(s), expected {request_count}"
                )
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread, captured, failures


def _join_responder(thread, failures):
    thread.join(timeout=3.0)
    assert not thread.is_alive(), "fake native responder did not finish"
    assert failures == []


def test_new_native_configuration_normalizes_tags_and_supports_empty_set(tmp_path):
    session = FakeSession(tmp_path)
    responder, finished, failures = _start_ack_writer(session)
    configured = runtime.configure_native_control(
        session, ["FRA", "K00", "9AB", "FRA"], timeout=1.0
    )
    _join_responder(responder, failures)
    assert finished.is_set()
    assert configured["mode"] == "configured"
    assert configured["countries"] == ["9AB", "FRA", "K00"]

    request = tmp_path / runtime.REQUEST_NAME
    first_fields = request.read_text(encoding="ascii").strip().split("\t")
    assert first_fields[0] == "EU4CONTROL1"
    assert first_fields[1] == session.session_id
    assert int(first_fields[2]) == configured["revision"]
    assert first_fields[3] == "9AB,FRA,K00"

    first_revision = configured["revision"]
    responder, finished, failures = _start_ack_writer(session)
    empty = runtime.configure_native_control(session, [], timeout=1.0)
    _join_responder(responder, failures)
    assert finished.is_set()
    assert empty["countries"] == []
    assert empty["revision"] > first_revision
    assert request.read_text(encoding="ascii").split("\t")[3].strip() == "-"


@pytest.mark.parametrize("field", ["session_id", "revision", "countries"])
def test_ack_with_wrong_binding_or_country_is_not_accepted(tmp_path, field):
    session = FakeSession(tmp_path)

    def mutate(ack):
        if field == "session_id":
            ack["session_id"] = "another-session"
        elif field == "revision":
            ack["revision"] += 1
        else:
            ack["countries"] = ["ENG"]

    responder, _finished, failures = _start_ack_writer(session, mutate=mutate)
    with pytest.raises(RuntimeError):
        runtime.configure_native_control(session, ["FRA"], timeout=0.12)
    _join_responder(responder, failures)


def test_matching_rejection_ack_fails_and_cleans_atomic_temp_file(tmp_path):
    session = FakeSession(tmp_path)
    responder, _finished, failures = _start_ack_writer(session, accepted=False)
    with pytest.raises(RuntimeError, match="REJECTED"):
        runtime.configure_native_control(session, ["ENG"], timeout=1.0)
    _join_responder(responder, failures)
    assert not list(tmp_path.glob(runtime.REQUEST_NAME + ".*.pending"))


def test_collection_lock_serializes_same_path_revisions(tmp_path):
    session = FakeSession(tmp_path)
    responder, captured, failures = _start_ack_server(session, request_count=2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda countries: runtime.configure_native_control(
                session, countries, timeout=1.5
            ),
            (["ENG"], ["SAV"]),
        ))
    _join_responder(responder, failures)

    assert {tuple(result["countries"]) for result in results} == {("ENG",), ("SAV",)}
    revisions = sorted(result["revision"] for result in results)
    assert revisions[1] > revisions[0]
    published_revisions = sorted(
        int(line.decode("ascii").strip().split("\t")[2]) for line in captured
    )
    assert published_revisions == revisions


def test_atomic_replace_failure_keeps_previous_file_and_removes_temp(tmp_path, monkeypatch):
    session = FakeSession(tmp_path)
    responder, _finished, failures = _start_ack_writer(session)
    runtime.configure_native_control(session, ["FRA"], timeout=1.0)
    _join_responder(responder, failures)

    request = tmp_path / runtime.REQUEST_NAME
    previous = request.read_bytes()

    def fail_replace(_source, _target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(runtime.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        runtime.configure_native_control(session, ["ENG"], timeout=0.1)

    assert request.read_bytes() == previous
    assert not list(tmp_path.glob(runtime.REQUEST_NAME + ".*.pending"))


def test_legacy_native_accepts_only_fra_and_unready_sessions_are_rejected(tmp_path):
    legacy = FakeSession(tmp_path / "legacy", capabilities=())
    result = runtime.configure_native_control(legacy, ["FRA", "FRA"])
    assert result["mode"] == "legacy"
    assert result["countries"] == ["FRA"]
    assert not (legacy.directory / runtime.REQUEST_NAME).exists()

    with pytest.raises(RuntimeError, match="UNAVAILABLE"):
        runtime.configure_native_control(legacy, ["ENG"])
    assert not (legacy.directory / runtime.REQUEST_NAME).exists()

    unready = FakeSession(tmp_path / "unready", health_status="unready")
    with pytest.raises(RuntimeError, match="UNREADY"):
        runtime.configure_native_control(unready, ["ENG"])
    assert not (unready.directory / runtime.REQUEST_NAME).exists()


def test_country_tags_are_validated_before_health_or_any_write(tmp_path):
    session = FakeSession(tmp_path)
    with pytest.raises(ValueError):
        runtime.configure_native_control(session, ["eng"])
    assert session.health_calls == 0
    assert not (tmp_path / runtime.REQUEST_NAME).exists()
