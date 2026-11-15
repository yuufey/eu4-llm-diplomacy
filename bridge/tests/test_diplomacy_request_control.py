"""Caller and country ownership metadata for durable diplomacy requests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3

import pytest

from bridge.diplomacy_journal import (
    DurableJournal,
    RequestPermissionError,
)


def _payload(actor: str = "FRA", recipient: str = "SAV", phase: str = "initiate"):
    return {
        "action_id": "offer_alliance",
        "actor": actor,
        "recipient": recipient,
        "phase": phase,
        "parameters": {},
    }


def _canonical_payload(payload: object) -> tuple[str, str]:
    payload_json = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )
    return payload_json, hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def test_metadata_is_persisted_idempotently_without_changing_payload_digest(tmp_path):
    path = tmp_path / "requests.sqlite3"
    payload = _payload()
    payload_json, expected_digest = _canonical_payload(payload)
    journal = DurableJournal(path, "exp", "session")
    try:
        first = journal.register(
            "same_request", payload,
            principal="llm:alice", decision_country="FRA",
        )
        assert first.payload_json == payload_json
        assert first.payload_sha256 == expected_digest
        assert first.principal == "llm:alice"
        assert first.decision_country == "FRA"

        journal.transition("same_request", "queued")
        replay = journal.register(
            "same_request", payload,
            principal="llm:alice", decision_country="FRA",
        )
        assert replay.status == "queued"
        assert replay.created_at == first.created_at
        assert replay.to_dict()["principal"] == "llm:alice"
        assert replay.to_dict()["decision_country"] == "FRA"
    finally:
        journal.close()


def test_metadata_conflicts_are_denied_before_payload_conflicts(tmp_path):
    journal = DurableJournal(tmp_path / "requests.sqlite3", "exp", "session")
    try:
        journal.register(
            "bound", _payload(), principal="llm:alice", decision_country="FRA"
        )

        with pytest.raises(RequestPermissionError):
            journal.register(
                "bound", _payload(actor="BUR"),
                principal="llm:bob", decision_country="SAV",
            )
        with pytest.raises(RequestPermissionError):
            journal.register(
                "bound", _payload(),
                principal="llm:alice", decision_country="SAV",
            )

        same_owner = journal.register("bound", _payload())
        assert same_owner.principal == "llm:alice"
        assert same_owner.decision_country == "FRA"
    finally:
        journal.close()


def _create_pre_metadata_database(path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE diplomacy_requests (
            experiment_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN (
                'received', 'queued', 'consumed', 'constructed',
                'submitted', 'executing', 'waiting_response',
                'accepted', 'rejected', 'cancelled', 'expired',
                'invalidated', 'unknown'
            )),
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            submission_id TEXT,
            submission_token TEXT,
            submitted_at TEXT,
            PRIMARY KEY (experiment_id, session_id, request_id)
        );
        CREATE TABLE diplomacy_evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            arrival_layer TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            content_text TEXT NOT NULL,
            content_format TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY (experiment_id, session_id, request_id)
                REFERENCES diplomacy_requests(experiment_id, session_id, request_id)
                ON DELETE CASCADE,
            UNIQUE (experiment_id, session_id, request_id, event_id)
        );
        CREATE INDEX diplomacy_evidence_request_idx
            ON diplomacy_evidence (experiment_id, session_id, request_id, evidence_id);
        """
    )
    requests = {
        "legacy_initiate": _payload(),
        "legacy_accept": _payload(actor="SAV", recipient="FRA", phase="accept"),
    }
    for request_id, payload in requests.items():
        payload_json, fingerprint = _canonical_payload(payload)
        connection.execute(
            """
            INSERT INTO diplomacy_requests (
                experiment_id, session_id, request_id, payload_json,
                payload_sha256, status, result_json, created_at, updated_at,
                submission_id, submission_token, submitted_at
            ) VALUES ('exp', 'session', ?, ?, ?, ?, NULL, 'created', 'updated',
                      NULL, NULL, NULL)
            """,
            (
                request_id,
                payload_json,
                fingerprint,
                "queued" if request_id == "legacy_initiate" else "accepted",
            ),
        )
    connection.execute(
        """
        INSERT INTO diplomacy_evidence (
            evidence_id, experiment_id, session_id, request_id, event_id,
            arrival_layer, evidence_type, content_text, content_format,
            content_sha256, observed_at, recorded_at
        ) VALUES (11, 'exp', 'session', 'legacy_initiate', 'legacy-event',
                  'bridge', 'request_received', '{"kept":true}', 'json',
                  'legacy-content-sha', 'observed', 'recorded')
        """
    )
    connection.commit()
    connection.close()


def test_legacy_schema_migrates_without_claiming_or_replaying_orphaned_rows(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    _create_pre_metadata_database(path)

    journal = DurableJournal(path, "exp", "session")
    try:
        initiate = journal.get_request("legacy_initiate")
        assert initiate.status == "queued"
        assert initiate.principal is None
        assert initiate.decision_country is None
        assert initiate.evidence_count == 1
        assert journal.list_evidence("legacy_initiate")[0].evidence_id == 11

        # A matching controller may continue to read/register an old request,
        # but the first modern caller does not take ownership of its NULL row.
        with pytest.raises(RequestPermissionError):
            journal.register(
                "legacy_initiate", _payload(), principal="llm:alice"
            )
        replay = journal.register(
            "legacy_initiate", _payload(),
            principal="llm:alice", decision_country="FRA",
        )
        assert replay.status == "queued"
        assert replay.principal is None
        assert replay.decision_country is None
        with pytest.raises(RequestPermissionError):
            journal.register(
                "legacy_initiate", _payload(),
                principal="llm:alice", decision_country="SAV",
            )

        # Inbound decisions belong to the payload recipient, not the sender.
        accepted = journal.register(
            "legacy_accept", _payload(actor="SAV", recipient="FRA", phase="accept"),
            principal="llm:bob", decision_country="FRA",
        )
        assert accepted.status == "accepted"
        assert accepted.principal is None
        with pytest.raises(RequestPermissionError):
            journal.register(
                "legacy_accept", _payload(actor="SAV", recipient="FRA", phase="accept"),
                principal="llm:bob", decision_country="SAV",
            )
    finally:
        journal.close()

    connection = sqlite3.connect(path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(diplomacy_requests)")}
        assert {"principal", "decision_country", "claimed_at", "native_receipt_json"} <= columns
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(diplomacy_evidence)"
        ).fetchall()
        assert any(row[2] == "diplomacy_requests" for row in foreign_keys)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT evidence_id, event_id FROM diplomacy_evidence"
        ).fetchall() == [(11, "legacy-event")]
        assert connection.execute(
            "SELECT status FROM diplomacy_requests WHERE request_id = 'legacy_initiate'"
        ).fetchone() == ("queued",)
    finally:
        connection.close()


def test_concurrent_registration_cannot_replace_another_principal(tmp_path):
    path = tmp_path / "concurrent.sqlite3"
    first_journal = DurableJournal(path, "exp", "session")
    second_journal = DurableJournal(path, "exp", "session")
    try:
        def register(journal, principal):
            try:
                return journal.register(
                    "race", _payload(), principal=principal, decision_country="FRA"
                )
            except RequestPermissionError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda args: register(*args),
                [(first_journal, "llm:alice"), (second_journal, "llm:bob")],
            ))

        assert sum(not isinstance(outcome, RequestPermissionError) for outcome in outcomes) == 1
        assert sum(isinstance(outcome, RequestPermissionError) for outcome in outcomes) == 1
        stored = first_journal.get_request("race")
        assert stored.principal in {"llm:alice", "llm:bob"}
        assert stored.decision_country == "FRA"
    finally:
        first_journal.close()
        second_journal.close()


def test_declare_war_reconciliation_uses_payload_country_instead_of_fra(tmp_path):
    journal = DurableJournal(tmp_path / "declare-war.sqlite3", "exp", "session")
    request_id = "declare_war_eng"
    payload = {
        "action_id": "declare_war",
        "actor": "ENG",
        "recipient": "SAV",
        "phase": "initiate",
        "parameters": {
            "casus_belli": "conquest",
            "war_goal": {"province_id": 42, "beneficiary": "ENG"},
        },
    }
    expected_reason = "NATIVE_DECLARE_WAR_SUBMISSION_RECEIPT_INVALID"
    try:
        journal.register(
            request_id, payload, principal="llm:alice", decision_country="ENG"
        )
        journal.transition(request_id, "queued")
        journal.transition(request_id, "consumed")
        journal.transition(request_id, "constructed")
        journal.claim_submission(request_id, submission_id="native-eng-1")
        journal.mark_invalidated(
            request_id,
            {"submitted": False, "reason": {"code": expected_reason}},
        )

        native_receipt = {
            "event": "native_declare_war_submission_result",
            "family": "declare_war",
            "submitted": True,
            "transport_verified": True,
            "request_binding_verified": True,
            "request_id": request_id,
            "action_id": "declare_war",
            "actor": "ENG",
            "recipient": "SAV",
            "phase": "initiate",
            "casus_belli": "conquest",
            "war_goal_province": 42,
            "war_goal_beneficiary": "ENG",
            "date_raw": 100,
        }
        result = {
            "event": "native_declare_war_execution_result",
            "family": "declare_war",
            "outcome": "executed",
            "native_outcome": "executed",
            "execution_verified": True,
            "request_binding_verified": True,
            "war_before": False,
            "war_after": True,
            "request_id": request_id,
            "action_id": "declare_war",
            "actor": "ENG",
            "recipient": "SAV",
            "phase": "initiate",
            "casus_belli": "conquest",
            "war_goal_province": 42,
            "war_goal_beneficiary": "ENG",
            "date_raw": 100,
            "war_identity_verified": False,
            "war_id": None,
            "stability_verified": False,
            "stability_before_raw": None,
            "stability_after_raw": None,
        }
        reconciled = journal.reconcile_declare_war_executed(
            request_id,
            result,
            native_receipt,
            expected_reason_code=expected_reason,
            expected_payload=payload,
        )
        assert reconciled.status == "executed"
        assert reconciled.principal == "llm:alice"
        assert reconciled.decision_country == "ENG"
    finally:
        journal.close()
