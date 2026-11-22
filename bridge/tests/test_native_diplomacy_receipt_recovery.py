import json
from pathlib import Path
import subprocess
import sys

import pytest

from bridge.diplomacy import DiplomacyTools, ObserverSession, _RESPONSE_LOG_SCAN_BYTES
from bridge.diplomacy_journal import DurableJournal


_EXPERIMENT = "receipt-recovery"
_SESSION = "receipt-session"
_REQUEST = "curry-bos"
_DATE_RAW = 56461080
_PAYLOAD = {
    "action_id": "curry_favors", "actor": "TUR", "recipient": "BOS",
    "phase": "initiate", "parameters": {},
}
_BINDING = {
    **{key: _PAYLOAD[key] for key in ("action_id", "actor", "recipient", "phase")},
    "request_id": _REQUEST, "session_id": _SESSION, "date_raw": _DATE_RAW,
    "family": "curry_favors", "native_variant": 1, "before_active": False,
}
_SUBMISSION = {
    **_BINDING, "event": "native_alliance_submission_result",
    "submitted": True, "native_queue_verified": True, "transport_ring": True,
    "native_origin": 65535, "native_flags": 0, "native_sequence": 6297,
}
_CONSEQUENCE = {
    **_BINDING, "event": "native_diplomacy_task_execution_result",
    "outcome": "executed", "native_state": 0, "after_active": True,
    "task_before": False, "task_after": True, "diplomat_required": True,
    "diplomat_context_verified": True, "available_diplomat_count": 1,
    "diplomat_assignment_verified": True, "execution_verified": True,
    "request_binding_verified": True,
}


@pytest.fixture
def installation(tmp_path):
    path = tmp_path / "installation.json"
    path.write_text(json.dumps({"experiment_id": _EXPERIMENT, "session_id": _SESSION}),
                    encoding="utf-8")
    return path


def _write_backlog(log):
    line = json.dumps({"event": "diagnostic", "padding": "x" * 8192}).encode() + b"\n"
    with log.open("wb") as stream:
        for _ in range(_RESPONSE_LOG_SCAN_BYTES // len(line) + 2):
            stream.write(line)
    assert log.stat().st_size > _RESPONSE_LOG_SCAN_BYTES


def _append_events(log, *events):
    with log.open("ab") as stream:
        for event in events:
            stream.write(json.dumps(event).encode() + b"\n")


def _cold_result(installation, database, *, repeat_execute=False):
    result = subprocess.run(
        [sys.executable, "-c", """
import json
from pathlib import Path
import sys

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal

installation, database, request_id, repeat_execute = sys.argv[1:]
session = ObserverSession(Path(installation), Path("unused-game.exe"))
session.controlled_country = "TUR"

def fail_if_published(*args):
    raise AssertionError("recovery cannot publish a native request")

session._publish_execute_request = fail_if_published
with DurableJournal(database, session.experiment_id, session.session_id) as journal:
    tools = DiplomacyTools(journal, session)
    if repeat_execute == "True":
        result = tools.execute_diplomatic_action(request_id, "curry_favors", "TUR", "BOS")
    else:
        result = tools.get_diplomatic_result(request_id)
    print(json.dumps(result))
""", str(installation), str(database), _REQUEST, str(repeat_execute)],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


def test_cold_result_uses_submission_boundary_beyond_eight_mib(installation, monkeypatch):
    database = installation.with_name("diplomacy.sqlite3")
    log = installation.with_name("control-probe.jsonl")
    _write_backlog(log)
    # An event with the same request id before publication cannot settle the request.
    _append_events(log, _CONSEQUENCE)
    publication_offset = log.stat().st_size
    session = ObserverSession(installation, installation.with_name("unused-game.exe"))
    session.controlled_country = "TUR"
    monkeypatch.setattr(session, "installation_capabilities",
                        lambda: frozenset({"native_curry_favors_submission"}))

    def append_submission(_wire, request_id):
        assert request_id == _REQUEST
        _append_events(log, _SUBMISSION)
        return "published"

    monkeypatch.setattr(session, "_publish_execute_request", append_submission)
    with DurableJournal(database, _EXPERIMENT, _SESSION) as journal:
        tools = DiplomacyTools(journal, session)
        monkeypatch.setattr(tools, "inspect_diplomatic_action", lambda *args, **kwargs: {
            "session": {"status": "ready", "date_raw": _DATE_RAW},
            "legality": {"status": "available"},
        })
        first = tools.execute_diplomatic_action(_REQUEST, "curry_favors", "TUR", "BOS")
        assert first["status"] == "submitted"
        record = journal.lookup_request(_REQUEST)
        assert record.response_log_cursor.offset >= publication_offset
        assert "response_log_cursor" not in record.native_receipt

    _append_events(log, {**_CONSEQUENCE, "session_id": "foreign-session"})
    assert _cold_result(installation, database)["status"] == "submitted"

    _append_events(log, {**_CONSEQUENCE, "outcome": "unknown"})
    unresolved = _cold_result(installation, database)
    assert unresolved["status"] == "submitted"
    assert unresolved["result"]["native_outcome"] == "unknown"
    assert _cold_result(installation, database) == unresolved

    _append_events(log, _CONSEQUENCE)
    session = ObserverSession(installation, installation.with_name("unused-game.exe"))
    session.controlled_country = "TUR"
    with DurableJournal(database, _EXPERIMENT, _SESSION) as journal:
        previous = journal.lookup_request(_REQUEST)

        def fail_persistence(*args, **kwargs):
            raise OSError("injected journal write failure")

        monkeypatch.setattr(journal, "mark_executed", fail_persistence)
        with pytest.raises(OSError, match="injected journal write failure"):
            DiplomacyTools(journal, session).get_diplomatic_result(_REQUEST)
        assert journal.lookup_request(_REQUEST) == previous

    recovered = _cold_result(installation, database)
    assert recovered["status"] == "executed"
    assert recovered["submitted"] is True
    assert recovered["result"]["actor"] == "TUR"
    assert recovered["result"]["recipient"] == "BOS"
    assert "response_log_cursor" not in recovered
    assert sum(item["type"] == "native_response" for item in recovered["evidence"]) == 1
    assert sum(item["type"] == "native_execution_consequence" for item in recovered["evidence"]) == 1
    assert _cold_result(installation, database, repeat_execute=True) == {
        **recovered, "idempotent": True,
    }


def test_existing_receipt_without_checkpoint_advances_between_cold_services(installation):
    database = installation.with_name("diplomacy.sqlite3")
    log = installation.with_name("control-probe.jsonl")
    _write_backlog(log)
    _append_events(log, _SUBMISSION, _CONSEQUENCE)
    with DurableJournal(database, _EXPERIMENT, _SESSION) as journal:
        journal.register(_REQUEST, _PAYLOAD)
        for status in ("queued", "consumed", "constructed"):
            journal.transition(_REQUEST, status)
        claim = journal.claim_submission(_REQUEST)
        receipt = ObserverSession._public_native_curry_favors_submission_receipt(
            _SUBMISSION, _REQUEST, "TUR", "BOS", "initiate", _DATE_RAW, "curry_favors",
            controlled_country="TUR",
        )
        journal.mark_submitted(_REQUEST, claim.claim_token, receipt)
        assert journal.lookup_request(_REQUEST).response_log_cursor is None

    first = _cold_result(installation, database)
    assert first["status"] == "submitted"
    with DurableJournal(database, _EXPERIMENT, _SESSION) as journal:
        record = journal.lookup_request(_REQUEST)
        assert 0 < record.response_log_cursor.offset <= _RESPONSE_LOG_SCAN_BYTES
        assert record.native_receipt == receipt
    recovered = _cold_result(installation, database)
    assert recovered["status"] == "executed"
    assert _cold_result(installation, database) == recovered
