"""Narrow tests for read-only DurableJournal review obligations."""

from __future__ import annotations

from types import SimpleNamespace
import hashlib
import json

import pytest

from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.pending_matters import JournalPendingMattersSource
from bridge.information.tools import InformationTools


EXPERIMENT = "pending-test-experiment"
SESSION = "pending-test-session"
OBSERVER = "FRA"
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _context(**changes):
    value = {
        "status": "ready",
        "mode": "live",
        "observer": OBSERVER,
        "session_id": SESSION,
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56554848,
        "complete": True,
    }
    value.update(changes)
    return value


class FakeBase:
    def __init__(self, journal, *, experiment=EXPERIMENT, contexts=None):
        self.diplomacy_tools = SimpleNamespace(
            journal=journal,
            session=SimpleNamespace(experiment_id=experiment),
        )
        self._contexts = list(contexts or [_context()])
        self.context_calls = 0

    def context(self):
        index = min(self.context_calls, len(self._contexts) - 1)
        self.context_calls += 1
        return dict(self._contexts[index])


def _source(journal, **kwargs):
    return JournalPendingMattersSource(FakeBase(journal, **kwargs))


def _query(*, fields=("pending_matters",), **parameters):
    return {
        "topic": "C03",
        "object": {"type": "session", "session_id": SESSION},
        "fields": list(fields),
        "parameters": parameters,
    }


def _payload(actor=OBSERVER, request_id="unused"):
    return {
        "request_id": request_id,
        "action_id": "offer_alliance",
        "actor": actor,
        "recipient": "PAP",
        "phase": "initiate",
        "submission_token": "payload-token-secret",
        "claim_token": "payload-claim-secret",
        "native_token": "payload-native-secret",
    }


def _register(journal, request_id, *, actor=OBSERVER):
    return journal.register(request_id, _payload(actor, request_id))


def _advance_to_constructed(journal, request_id):
    for status in ("queued", "consumed", "constructed"):
        journal.transition(request_id, status)


def _fixture_row(journal, experiment_id, session_id, request_id, *, actor=OBSERVER,
                 status="unknown", created_at="2026-01-01T00:00:00+00:00"):
    """Insert synthetic cross-scope rows into the temporary test journal only."""
    payload = _payload(actor, request_id)
    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    with journal._lock:
        journal._connection.execute(
            """INSERT INTO diplomacy_requests
               (experiment_id,session_id,request_id,payload_json,payload_sha256,status,
                result_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,NULL,?,?)""",
            (experiment_id, session_id, request_id, payload_json, digest, status,
             created_at, created_at),
        )


def _value(report):
    return report["fields"]["pending_matters"]["value"]


def test_normal_concise_pending_queries_preserve_unknown_request_and_page_cursor(tmp_path):
    with DurableJournal(tmp_path / 'journal.sqlite3', EXPERIMENT, SESSION) as journal:
        _register(journal, 'a-unknown')
        journal.transition('a-unknown', 'unknown')
        _register(journal, 'b-received')
        source = _source(journal)
        database = tmp_path / 'information.sqlite3'
        service = InformationService(source, database)
        try:
            api = InformationTools(service)
            result = api.call('information_query', {
                'request_id': 'concise-pending-first', 'queries': [_query(limit=1)],
            })
            pending = result['items'][0]['pending_matters']
            assert pending['requests'][0]['request_id'] == 'a-unknown'
            assert pending['requests'][0]['status'] == 'unknown'
            assert pending['requests'][0]['review_kind'] == 'requires_reconciliation'
            assert pending['proposals'] is None
            assert pending['next_after_request_id'] == 'a-unknown'
            assert 'claimed_at' not in pending['requests'][0]
            second = api.call('information_query', {
                'request_id': 'concise-pending-second',
                'queries': [_query(limit=1, after_request_id=pending['next_after_request_id'])],
            })['items'][0]['pending_matters']
            assert second['requests'][0]['request_id'] == 'b-received'
            assert 'next_after_request_id' not in second
            stored = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
            assert stored['items'][0]['fields']['pending_matters']['value']['journal_requests'][0]['status'] == 'unknown'
        finally:
            service.close()
        reopened = InformationService(source, database)
        try:
            assert InformationTools(reopened).call('information_get_result', {
                'result_id': result['result_id'],
            }) == result
        finally:
            reopened.close()


def test_pending_page_classifies_open_local_journal_states_and_filters_scope(tmp_path):
    journal = DurableJournal(tmp_path / "journal.sqlite3", EXPERIMENT, SESSION)
    try:
        # A real journal claim is only a local reservation; this test never calls a submitter.
        _register(journal, "a-claimed-constructed")
        _advance_to_constructed(journal, "a-claimed-constructed")
        claim = journal.claim_submission("a-claimed-constructed", submission_id="fixture-claim")
        assert claim.claimed is True

        _register(journal, "b-submitted")
        with journal._lock:
            # Synthetic state fixture in this temporary DB; no native API or business action.
            # The first real claim intentionally holds the journal's one-channel reservation.
            journal._connection.execute(
                "UPDATE diplomacy_requests SET status='submitted',submitted_at=?,"
                "native_receipt_json=? WHERE request_id=?",
                ("fixture-time", '{"receipt":"native-receipt-secret"}', "b-submitted"),
            )

        _register(journal, "c-waiting-response")
        with journal._lock:
            journal._connection.execute(
                "UPDATE diplomacy_requests SET status='waiting_response',submitted_at=? "
                "WHERE request_id=?", ("fixture-time", "c-waiting-response"),
            )

        _register(journal, "d-unknown")
        journal.transition("d-unknown", "unknown")
        _register(journal, "e-received")
        _register(journal, "f-queued")
        journal.transition("f-queued", "queued")
        _register(journal, "g-consumed")
        journal.transition("g-consumed", "queued")
        journal.transition("g-consumed", "consumed")

        _register(journal, "h-cancelled")
        journal.transition("h-cancelled", "cancelled")
        _register(journal, "i-expired")
        journal.transition("i-expired", "expired")
        _register(journal, "j-other-actor", actor="ENG")
        journal.transition("j-other-actor", "unknown")
        _fixture_row(journal, "other-experiment", SESSION, "k-other-experiment")
        _fixture_row(journal, EXPERIMENT, "other-session", "l-other-session")

        # The summary path must not enumerate records or load evidence.
        journal.list_requests = lambda *args, **kwargs: pytest.fail("unbounded list_requests used")
        journal.list_evidence_for_record = lambda *args, **kwargs: pytest.fail("evidence read used")

        result = _source(journal).read(_query())
        field = result["fields"]["pending_matters"]
        assert field["status"] == "known"
        assert field["complete"] is False and field["partial"] is True
        value = field["value"]
        items = value["journal_requests"]
        by_id = {item["request_id"]: item for item in items}
        assert set(by_id) == {
            "a-claimed-constructed", "b-submitted", "c-waiting-response",
            "d-unknown", "e-received", "f-queued", "g-consumed",
        }
        assert by_id["a-claimed-constructed"]["review_kind"] == "requires_reconciliation"
        assert by_id["a-claimed-constructed"]["has_submission_claim"] is True
        assert by_id["a-claimed-constructed"]["submitted"] is False
        assert by_id["b-submitted"]["review_kind"] == "requires_reconciliation"
        assert by_id["b-submitted"]["submitted"] is True
        assert by_id["c-waiting-response"]["review_kind"] == "recorded_waiting_response"
        assert by_id["d-unknown"]["review_kind"] == "requires_reconciliation"
        assert by_id["e-received"]["review_kind"] == "local_workflow_incomplete"
        assert by_id["f-queued"]["review_kind"] == "local_workflow_incomplete"
        assert by_id["g-consumed"]["review_kind"] == "local_workflow_incomplete"
        assert all(item["native_pending_confirmed"] is False for item in items)
        assert value["native_inbound_pending"]["status"] == "unknown"
        assert value["action_authorization"] == "none_from_information_query"

        serialized = json.dumps(value)
        for secret in ("payload-token-secret", "payload-claim-secret", "payload-native-secret",
                       "native-receipt-secret", "result_json", "submission_token"):
            assert secret not in serialized
    finally:
        journal.close()


def test_pending_page_keyset_pagination_is_bounded_and_advances(tmp_path):
    journal = DurableJournal(tmp_path / "journal.sqlite3", EXPERIMENT, SESSION)
    try:
        for index, request_id in enumerate(("page-a", "page-b", "page-c"), start=1):
            _register(journal, request_id)
            with journal._lock:
                journal._connection.execute(
                    "UPDATE diplomacy_requests SET created_at=?,updated_at=? WHERE request_id=?",
                    (f"2026-01-01T00:00:0{index}+00:00", f"2026-01-01T00:00:0{index}+00:00", request_id),
                )
        source = _source(journal)
        first = _value(source.read(_query(limit=2)))
        assert [item["request_id"] for item in first["journal_requests"]] == ["page-a", "page-b"]
        assert first["pagination"] == {
            "returned": 2, "has_more": True, "next_after_request_id": "page-b",
        }
        second = _value(source.read(_query(limit=2, after_request_id="page-b")))
        assert [item["request_id"] for item in second["journal_requests"]] == ["page-c"]
        assert second["pagination"] == {
            "returned": 1, "has_more": False, "next_after_request_id": None,
        }
    finally:
        journal.close()


def test_bad_payload_hash_is_unknown_not_a_partial_public_record(tmp_path):
    journal = DurableJournal(tmp_path / "journal.sqlite3", EXPERIMENT, SESSION)
    try:
        _register(journal, "hash-mismatch")
        with journal._lock:
            journal._connection.execute(
                "UPDATE diplomacy_requests SET payload_sha256=? WHERE request_id=?",
                ("0" * 64, "hash-mismatch"),
            )
        field = JournalPendingMattersSource(FakeBase(journal)).read(_query())["fields"]["pending_matters"]
        assert field == {"status": "unknown", "reason": "PENDING_JOURNAL_PAYLOAD_HASH_MISMATCH"}
    finally:
        journal.close()


def test_closed_journal_and_missing_scope_binding_fail_closed(tmp_path):
    closed = DurableJournal(tmp_path / "closed.sqlite3", EXPERIMENT, SESSION)
    source = _source(closed)
    closed.close()
    result = source.read(_query())
    assert result["fields"]["pending_matters"] == {
        "status": "unknown", "reason": "PENDING_JOURNAL_CLOSED",
    }

    journal = DurableJournal(tmp_path / "unbound.sqlite3", EXPERIMENT, SESSION)
    try:
        missing = JournalPendingMattersSource(FakeBase(journal, experiment=None))
        result = missing.read(_query())
        assert result["fields"]["pending_matters"] == {
            "status": "unknown", "reason": "PENDING_JOURNAL_BINDING_UNAVAILABLE",
        }
    finally:
        journal.close()


def test_context_drift_during_summary_withholds_page(tmp_path):
    journal = DurableJournal(tmp_path / "journal.sqlite3", EXPERIMENT, SESSION)
    try:
        _register(journal, "drift-request")
        base = FakeBase(journal, contexts=[_context(), _context(game_date=56554872)])
        result = JournalPendingMattersSource(base).read(_query(), _context())
        assert result["fields"]["pending_matters"] == {
            "status": "unavailable", "reason": "PENDING_CONTEXT_CHANGED",
        }
    finally:
        journal.close()


def test_unsupported_only_c03_query_does_not_touch_journal(tmp_path):
    class BombBase:
        def context(self):
            return _context()

        @property
        def diplomacy_tools(self):
            raise AssertionError("unsupported-only query touched journal binding")

    result = JournalPendingMattersSource(BombBase()).read(
        _query(fields=("strategic_goals",)),
    )
    assert result["fields"]["strategic_goals"] == {
        "status": "unsupported", "reason": "C03_FIELD_NOT_IMPLEMENTED",
    }


def test_catalog_and_query_bounds_are_explicit(tmp_path):
    journal = DurableJournal(tmp_path / "journal.sqlite3", EXPERIMENT, SESSION)
    try:
        source = _source(journal)
        topic = source.catalog()[0]
        assert topic["topic_id"] == "C03"
        assert topic["fields"]["pending_matters"]["coverage"] == "partial"
        assert topic["fields"]["pending_matters"]["complete"] is False
        assert topic["triggers"] == ["query", "periodic", "change"]
        assert source.validate_query(_query(limit=128))["parameters"]["limit"] == 128
        with pytest.raises(Exception):
            source.validate_query(_query(limit=129))
        with pytest.raises(Exception):
            source.validate_query(_query(after_request_id="bad cursor with spaces"))
    finally:
        journal.close()
