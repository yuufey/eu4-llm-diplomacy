"""Focused regressions for bounded inbound lifecycle/result cursors.

These tests keep the lifecycle fast path narrow: unrelated canonical lifecycle
rows may be skipped, while expiry/drop compatibility and the later response
submission cursor remain observable through their existing public contracts.
"""

import json
from pathlib import Path

import pytest

from bridge import diplomacy as diplomacy_module
from bridge.diplomacy import ObserverSession
from bridge.tests.test_information_proposal_expiry import (
    NOW,
    SESSION,
    append,
    expired,
    offer,
    session as expiry_session,
)


def _append_raw(observed, *lines, final_newline=True):
    """Append bytes without changing separators or leading whitespace."""

    path = observed.directory / "control-probe.jsonl"
    with path.open("ab") as stream:
        for index, line in enumerate(lines):
            if isinstance(line, dict):
                line = json.dumps(line, separators=(",", ":")).encode("utf-8")
            elif isinstance(line, str):
                line = line.encode("utf-8")
            stream.write(line)
            if final_newline or index + 1 < len(lines):
                stream.write(b"\n")


def _compact_offer():
    return json.dumps(offer(), separators=(",", ":")).encode("utf-8")


def _compact_expiry():
    return json.dumps(expired(), separators=(",", ":")).encode("utf-8")


def test_canonical_unrelated_lifecycle_row_skips_json_decode_but_cursor_advances(
        tmp_path, monkeypatch):
    observed = expiry_session(tmp_path)
    unrelated = (
        b'{"event":"native_alliance_lifecycle","session_id":"'
        + SESSION.encode("ascii")
        + b'","kind":"unrelated"}'
    )
    _append_raw(observed, unrelated)
    parsed_lifecycle = []
    original_loads = diplomacy_module.json.loads

    def counting_loads(value, *args, **kwargs):
        text = value.decode("utf-8") if isinstance(value, bytes) else value
        if isinstance(text, str) and '"event":"native_alliance_lifecycle"' in text:
            parsed_lifecycle.append(text)
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(diplomacy_module.json, "loads", counting_loads)
    assert observed.read_native_alliance_inbound_offers() == []
    assert parsed_lifecycle == []
    assert observed._inbound_log_offset == (
        observed.directory / "control-probe.jsonl").stat().st_size


def test_new_proposal_after_skipped_canonical_row_is_still_delivered(tmp_path):
    observed = expiry_session(tmp_path)
    unrelated = (
        b'{"event":"native_alliance_lifecycle","session_id":"'
        + SESSION.encode("ascii")
        + b'","kind":"unrelated"}'
    )
    _append_raw(observed, unrelated, _compact_offer())
    proposals = observed.read_native_alliance_inbound_offers()
    assert len(proposals) == 1
    assert proposals[0]["actor"] == "SAV"
    assert observed._inbound_log_offset == (
        observed.directory / "control-probe.jsonl").stat().st_size


def test_duplicate_event_key_retains_existing_json_last_value_behavior(tmp_path):
    observed = expiry_session(tmp_path)
    duplicated = b'{"event":"native_alliance_lifecycle",' + _compact_offer()[1:]
    _append_raw(observed, duplicated)
    proposals = observed.read_native_alliance_inbound_offers()
    assert len(proposals) == 1
    assert proposals[0]['actor'] == 'SAV'


def test_escaped_and_leading_whitespace_lifecycle_rows_keep_parser_compatibility(
        tmp_path, monkeypatch):
    observed = expiry_session(tmp_path)
    escaped = json.dumps(
        {"event": "native_alliance_lifecycle", "session_id": SESSION,
         "kind": "unrelated", "note": "line\nwith escape"},
        separators=(",", ":"),
    )
    whitespace = (
        ' {"event":"native_alliance_lifecycle","session_id":"'
        + SESSION
        + '","kind":"unrelated"}'
    )
    _append_raw(observed, escaped, whitespace)
    parsed_lifecycle = []
    original_loads = diplomacy_module.json.loads

    def counting_loads(value, *args, **kwargs):
        text = value.decode("utf-8") if isinstance(value, bytes) else value
        if isinstance(text, str) and "native_alliance_lifecycle" in text:
            parsed_lifecycle.append(text)
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(diplomacy_module.json, "loads", counting_loads)
    assert observed.read_native_alliance_inbound_offers() == []
    assert len(parsed_lifecycle) == 2


def test_compact_expiry_row_is_not_dropped_by_fast_path(tmp_path):
    observed = expiry_session(tmp_path)
    _append_raw(observed, _compact_offer(), _compact_expiry())
    assert len(observed.read_native_alliance_inbound_offers()) == 1
    events = observed.read_native_inbound_events()
    assert [item["payload"].get("observer_status") for item in events] == [
        "observed_pending", "expired"
    ]
    assert observed.read_native_inbound_capture_gaps() == []


def test_lifecycle_drop_remains_counted(tmp_path):
    observed = expiry_session(tmp_path)
    _append_raw(observed, {
        "event": "native_alliance_lifecycle_drop",
        "session_id": SESSION,
        "dropped": 3,
    })
    assert observed.read_native_alliance_inbound_offers() == []
    assert observed.read_native_inbound_capture_gaps() == [
        "LIFECYCLE_CAPTURE_DROPPED:3"
    ]


def test_partial_line_cursor_waits_for_newline_without_rollback(tmp_path, monkeypatch):
    observed = expiry_session(tmp_path)
    unrelated = (
        b'{"event":"native_alliance_lifecycle","session_id":"'
        + SESSION.encode("ascii")
        + b'","kind":"unrelated"}'
    )
    _append_raw(observed, unrelated, _compact_offer(), final_newline=False)
    monkeypatch.setattr(diplomacy_module, "_RESPONSE_LOG_CHUNK_BYTES", 7)
    first = observed.read_native_alliance_inbound_offers()
    first_offset = observed._inbound_log_offset
    full_size = (observed.directory / "control-probe.jsonl").stat().st_size
    assert first == []
    assert 0 < first_offset < full_size

    with (observed.directory / "control-probe.jsonl").open("ab") as stream:
        stream.write(b"\n")
    second = observed.read_native_alliance_inbound_offers()
    assert len(second) == 1
    assert observed._inbound_log_offset > first_offset
    assert observed._inbound_log_offset == (
        observed.directory / "control-probe.jsonl").stat().st_size


def _submission_session(tmp_path):
    installation = tmp_path / "installation.json"
    installation.write_text(json.dumps({
        "experiment_id": "submit-cursor",
        "session_id": "submit-cursor-session",
        "game_sha256": "a" * 64,
        "dll_sha256": "b" * 64,
    }), encoding="utf-8")
    log = tmp_path / "control-probe.jsonl"
    log.write_bytes(b"old-line\n")
    observed = ObserverSession(installation, tmp_path / "unused-game.exe")
    observed.installation_capabilities = lambda: frozenset({
        "native_inbound_alliance_response",
    })
    return observed, log


def _submission_receipt(request_id, *, date_raw=NOW):
    return {
        "event": "native_alliance_submission_result",
        "request_id": request_id,
        "session_id": "submit-cursor-session",
        "action_id": "offer_alliance",
        "actor": "SAV",
        "recipient": "FRA",
        "phase": "accept",
        "date_raw": date_raw,
        "submitted": True,
        "native_queue_verified": True,
        "transport_ring": {"receipt": True},
        "native_sequence": 7,
        "native_origin": 1,
        "native_flags": 0,
    }


def _submit(observed, request_id, *, timeout=0.2):
    return observed.submit_native_inbound_response(
        request_id, "SAV", "FRA", "accept", NOW, 17, timeout=timeout,
    )


def test_submit_success_reads_only_result_after_publish_boundary(tmp_path, monkeypatch):
    observed, log = _submission_session(tmp_path)
    request_id = "response-after-boundary"
    boundary = log.stat().st_size
    # This stale matching request would fail validation if the reader scanned
    # from zero. The valid receipt is appended only by publication.
    log.write_text(
        json.dumps(_submission_receipt(request_id, date_raw=NOW - 1)) + "\n",
        encoding="utf-8",
    )
    boundary = log.stat().st_size

    def publish(_wire, _request_id, _request_name):
        with log.open("ab") as stream:
            stream.write(json.dumps(_submission_receipt(request_id)).encode("utf-8"))
            stream.write(b"\n")
        return "published"

    monkeypatch.setattr(observed, "_publish_atomic_request", publish)
    result = _submit(observed, request_id)
    assert result["status"] == "submitted"
    assert observed._response_log_offsets[request_id] == boundary


def test_submit_timeout_keeps_publish_boundary_for_later_reader(tmp_path, monkeypatch):
    observed, log = _submission_session(tmp_path)
    request_id = "response-timeout"
    boundary = log.stat().st_size
    monkeypatch.setattr(observed, "_publish_atomic_request", lambda *_: "published")
    result = _submit(observed, request_id, timeout=0.0)
    assert result == {"status": "timeout", "reason_code": "NATIVE_SUBMISSION_TIMEOUT"}
    assert observed._response_log_offsets[request_id] == boundary
    assert observed.read_native_alliance_inbound_response(
        request_id, "SAV", "FRA", "accept", NOW, 17,
    ) is None
    assert observed._response_log_offsets[request_id] == boundary


@pytest.mark.parametrize(
    ("publish_status", "result_status"),
    [("busy", "busy"), ("failed", "failed")],
)
def test_submit_busy_or_write_failure_does_not_create_boundary(
        tmp_path, monkeypatch, publish_status, result_status):
    observed, _ = _submission_session(tmp_path)
    request_id = "response-" + publish_status
    monkeypatch.setattr(observed, "_publish_atomic_request", lambda *_: publish_status)
    result = _submit(observed, request_id, timeout=0.0)
    assert result["status"] == result_status
    assert request_id not in observed._response_log_offsets


def test_submit_does_not_move_existing_boundary_backward(tmp_path, monkeypatch):
    observed, log = _submission_session(tmp_path)
    request_id = "response-existing-boundary"
    existing = 3
    observed._response_log_offsets[request_id] = existing

    def publish(_wire, _request_id, _request_name):
        with log.open("ab") as stream:
            stream.write(json.dumps(_submission_receipt(request_id)).encode("utf-8"))
            stream.write(b"\n")
        return "published"

    monkeypatch.setattr(observed, "_publish_atomic_request", publish)
    assert _submit(observed, request_id)["status"] == "submitted"
    assert observed._response_log_offsets[request_id] == existing
