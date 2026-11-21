"""Submit one country-bound recall and reconcile its native consequence."""
from __future__ import annotations

import json
import os
import re
import time
import uuid

from .diplomacy_control import DiplomacyPermissionError
from .diplomacy_journal import ContextMismatchError, RequestConflictError, RequestPermissionError
from .information.collection_lock import CollectionLock
from .information.model import InformationError


TOOL_NAME = "recall_diplomat"
PROTOCOL = "EU4RECALL1"
REQUEST_NAME = "diplomat-recall-mcp.req"
RESULT_EVENT = "native_diplomat_recall_result"
CONSEQUENCE_EVENT = "native_diplomat_recall_postcondition"
MAX_DIPLOMAT_ID = (1 << 31) - 1
_FILETIME_EPOCH = 116444736000000000
_DELIVERY_SECONDS = 6
_RESULT_SECONDS = 10
_RECEIPT_WINDOW = 1024 * 1024


def recall_available(session, control) -> bool:
    if (session is None or control is None or control.controlled_country is None
            or control.controlled_country not in getattr(session, "managed_countries", ())):
        return False
    read_ack = getattr(session, "_installation_ack", None)
    ack = read_ack() if callable(read_ack) else None
    return (isinstance(ack, dict) and ack.get("native_diplomat_recall_by_id") is True
            and ack.get("native_diplomat_recall_protocol") == PROTOCOL)


def _publish(request, line: str) -> None:
    temporary = request.with_suffix(f".{uuid.uuid4().hex}.pending")
    try:
        with temporary.open("xb") as stream:
            stream.write(line.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            os.rename(temporary, request)
        else:
            os.link(temporary, request)
    finally:
        temporary.unlink(missing_ok=True)


def _events(session, *, offset: int, revision: int, actor: str, diplomat_id: int):
    log = session.directory / "control-probe.jsonl"
    try:
        with log.open("rb") as stream:
            stream.seek(offset)
            lines = stream.read(_RECEIPT_WINDOW).split(b"\n")[:-1]
    except OSError:
        return
    for raw in lines:
        if b'native_diplomat_recall_' not in raw:
            continue
        try:
            event = json.loads(raw)
        except (UnicodeError, ValueError):
            continue
        if (isinstance(event, dict) and event.get("session_id") == session.session_id
                and type(event.get("revision")) is int and event["revision"] == revision
                and event.get("actor") == actor and type(event.get("diplomat_id")) is int
                and event["diplomat_id"] == diplomat_id):
            yield event


def _reconcile(session, journal, record):
    if (session is None or record.session_id != session.session_id
            or record.status not in {"constructed", "submitted"} or record.submission_id is None):
        return record
    receipt = record.native_receipt or record.result
    if not isinstance(receipt, dict) or type(receipt.get("log_offset")) is not int:
        return record
    offset = receipt["log_offset"]
    revision = int(record.submission_id)
    actor = record.payload["actor"]
    diplomat_id = record.payload["parameters"]["diplomat_id"]
    public = {"actor": actor, "diplomat_id": diplomat_id}
    request_id = record.request_id
    for event in _events(session, offset=offset, revision=revision, actor=actor, diplomat_id=diplomat_id):
        kind, status = event.get("event"), event.get("status")
        if kind == RESULT_EVENT and status in ("queued", "rejected"):
            # A matching native receipt can recover the narrow crash window
            # between publishing the file and persisting its delivery.
            if record.status == "constructed":
                record = journal.mark_submitted(request_id, record.submission_token, receipt)
            if status == "rejected":
                return journal.mark_rejected(
                    request_id, event, event_id=f"recall-rejected:{revision}",
                    result={**public, "reason": event.get("reason")})
        if kind == CONSEQUENCE_EVENT and record.status == "submitted":
            state, date_raw = event.get("state"), event.get("date_raw")
            if (status == "executed" and state in ("returning", "idle")
                    and type(date_raw) is int and date_raw > 0):
                return journal.mark_executed(
                    request_id, event, evidence_type="native_recall_postcondition",
                    event_id=f"recall-executed:{revision}",
                    result={**public, "state": state, "game_date_raw": date_raw})
            if status == "unconfirmed":
                return journal.mark_expired(
                    request_id, {**public, "reason": "RECALL_UNCONFIRMED"},
                    evidence_type="native_recall_unconfirmed", arrival_layer="native_response",
                    event_id=f"recall-unconfirmed:{revision}")
    if time.time_ns() - revision >= _RESULT_SECONDS * 1_000_000_000:
        return journal.mark_expired(request_id, {**public, "reason": "RECALL_UNCONFIRMED"})
    return record


def reconcile_diplomat_recall(session, journal, record) -> None:
    """Refresh an existing recall after authorizing access to its journal row."""
    if session is None or record.terminal or record.session_id != session.session_id:
        return
    with CollectionLock(session.directory / REQUEST_NAME).acquire(blocking=False) as acquired:
        if acquired:
            _reconcile(session, journal, journal.get_request(record.request_id))


def submit_diplomat_recall(session, control, journal, request_id: str, diplomat_id: int) -> dict | None:
    if control is None or control.controlled_country is None:
        raise DiplomacyPermissionError("DIPLOMACY_COUNTRY_NOT_AUTHORIZED")
    if not isinstance(request_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request_id) is None:
        raise ValueError("INVALID_REQUEST_ID")
    if type(diplomat_id) is not int or not 0 <= diplomat_id <= MAX_DIPLOMAT_ID:
        raise ValueError("INVALID_DIPLOMAT_ID")
    if not recall_available(session, control):
        raise InformationError("source_unavailable", "The current session does not support diplomat recall by ID")

    actor = control.controlled_country
    payload = {"action_id": TOOL_NAME, "actor": actor, "recipient": actor,
               "phase": "initiate", "parameters": {"diplomat_id": diplomat_id}}
    request = session.directory / REQUEST_NAME
    with CollectionLock(request).acquire(blocking=False) as acquired:
        if not acquired:
            raise InformationError("diplomacy_busy", "A diplomat recall is already in progress")
        try:
            record = journal.register(request_id, payload, principal=control.principal, decision_country=actor)
        except RequestPermissionError as error:
            raise DiplomacyPermissionError(str(error)) from None
        except RequestConflictError:
            return {"request_id": request_id, "submitted": False, "status": "conflict"}
        except ContextMismatchError:
            return {"request_id": request_id, "submitted": False, "status": "invalidated",
                    "reason": "REQUEST_ID_SESSION_CONFLICT"}
        if (record.status not in {"received", "queued", "consumed", "constructed"}
                or record.submission_id is not None):
            return None

        if session.health().get("status") != "ready":
            journal.mark_invalidated(request_id, {"reason": "NATIVE_SESSION_UNREADY"})
            return None
        try:
            offset = (session.directory / "control-probe.jsonl").stat().st_size
        except OSError:
            journal.mark_invalidated(request_id, {"reason": "RECALL_CHANNEL_UNAVAILABLE"})
            return None
        receipt = {"protocol": PROTOCOL, "log_offset": offset}
        if record.status == "received":
            record = journal.transition(request_id, "queued")
        if record.status == "queued":
            record = journal.transition(request_id, "consumed")
        if record.status == "consumed":
            journal.transition(request_id, "constructed", result=receipt)
        else:
            receipt = record.result
        revision = time.time_ns()
        claim = journal.claim_submission(request_id, submission_id=str(revision))
        if not claim.acquired:
            journal.mark_invalidated(request_id, {"reason": "DIPLOMACY_CHANNEL_BUSY"})
            return None
        expires = _FILETIME_EPOCH + revision // 100 + _DELIVERY_SECONDS * 10_000_000
        line = f"{PROTOCOL}\t{session.session_id}\t{revision}\t{expires}\t{actor}\t{diplomat_id}\n"
        try:
            _publish(request, line)
        except OSError:
            journal.mark_invalidated(request_id, {"reason": "RECALL_CHANNEL_UNAVAILABLE"})
            return None
        record = journal.mark_submitted(request_id, claim.claim_token, receipt)
        deadline = time.monotonic() + _RESULT_SECONDS
        while True:
            record = _reconcile(session, journal, record)
            if record.terminal or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    return None
