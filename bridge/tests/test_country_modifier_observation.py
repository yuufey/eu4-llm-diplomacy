"""Bounded decoding and shared-log cursor tests for native modifier additions."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from bridge import country_modifier_observation as observation
from bridge.diplomacy import ObserverSession


GAME_SHA = observation.GAME_SHA256
SESSION_ID = "modifier-observation-316"


def native_event(sequence=1, *, session_id=SESSION_ID, **changes):
    event = {
        "event": observation.NATIVE_EVENT,
        "schema_version": 1,
        "session_id": session_id,
        "sequence": sequence,
        "country": "FRA",
        "country_fullref": "0x100415246",
        "modifier_id": "test_modifier",
        "date_raw": 56658312,
        "start_date_raw": 0,
        "end_date_raw": 0,
        "flags": [0, 0, 0, 0],
        "source": observation.SOURCE,
        "complete": True,
    }
    event.update(changes)
    return event


def native_ack(session_id=SESSION_ID, *, version=44, enabled=True, wire=1,
               scope=observation.SCOPE, caps=None):
    event = {
        "event": "diplomacy_observer_installed",
        "session_id": session_id,
        "observer": "FRA",
        "version": version,
        "native_country_modifier_add_wire": wire,
        "native_country_modifier_scope": scope,
    }
    if enabled:
        event[observation.CAPABILITY] = True
    if caps is not None:
        event["caps"] = caps
    return event


class LogSession(ObserverSession):
    observer = "FRA"

    def __init__(self, installation, game_exe):
        super().__init__(installation, game_exe)
        self.game_date = 56660000

    def health(self):
        return {
            "status": "ready",
            "date_raw": self.game_date,
            "complete": True,
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA,
            "world_id": "modifier-world-316",
            "reasons": [],
        }

    def information_health(self):
        return self.health()


def make_session(directory, events=(), *, session_id=SESSION_ID, game_sha=GAME_SHA,
                 ack=None, observer="FRA"):
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "experiment_id": "modifier-observation-316",
        "session_id": session_id,
        "game_sha256": game_sha,
        "game_version": "1.37.4",
        "dll_sha256": "a" * 64,
        "observer": observer,
        "world_id": "modifier-world-316",
    }
    installation = directory / "installation.json"
    installation.write_text(json.dumps(record), encoding="utf-8")
    rows = [ack or native_ack(session_id), *events]
    (directory / "control-probe.jsonl").write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    return LogSession(installation, directory / "unused-game.exe")


def test_literal_ack_requires_version_wire_scope_and_exact_game_hash():
    ack = native_ack()
    assert observation.supported_ack(ack, GAME_SHA)
    assert observation.supported_ack(native_ack(version=45), GAME_SHA)
    assert not observation.supported_ack(native_ack(enabled=False, caps=[observation.CAPABILITY]), GAME_SHA)
    assert not observation.supported_ack(ack, "0" * 64)
    assert not observation.supported_ack(native_ack(version=43), GAME_SHA)
    assert not observation.supported_ack(native_ack(version=44.0), GAME_SHA)
    assert not observation.supported_ack(native_ack(version=True), GAME_SHA)
    assert not observation.supported_ack(native_ack(wire=True), GAME_SHA)
    assert not observation.supported_ack(native_ack(wire=2), GAME_SHA)
    assert not observation.supported_ack(native_ack(scope="all_country_modifiers"), GAME_SHA)


def test_v56_modifier_add_remove_and_expiry_preserve_the_v55_contract():
    ack = native_ack(version=56)
    assert observation.supported_ack(ack, GAME_SHA)

    remove_ack = dict(ack)
    remove_ack.update({
        observation.REMOVE_CAPABILITY: True,
        "native_country_modifier_remove_wire": 1,
    })
    assert observation.supported_remove_ack(remove_ack, GAME_SHA)

    expiry_ack = dict(remove_ack)
    expiry_ack.update({
        observation.EXPIRY_CAPABILITY: True,
        "native_country_modifier_expiry_wire": 1,
    })
    assert observation.supported_expiry_ack(expiry_ack, GAME_SHA)

    for candidate in (native_ack(version=57), dict(remove_ack, version=57), dict(expiry_ack, version=57)):
        assert not observation.supported_ack(candidate, GAME_SHA)
        assert not observation.supported_remove_ack(candidate, GAME_SHA)
        assert not observation.supported_expiry_ack(candidate, GAME_SHA)


@pytest.mark.parametrize(
    "ack_changes,game_sha,enabled",
    [
        ({}, GAME_SHA, True),
        ({"version": 45}, GAME_SHA, True),
        ({"enabled": False, "caps": [observation.CAPABILITY]}, GAME_SHA, False),
        ({"version": 43}, GAME_SHA, False),
        ({"wire": 2}, GAME_SHA, False),
        ({}, "0" * 64, False),
    ],
)
def test_observer_capability_is_not_granted_by_fake_caps_or_wrong_build(
    tmp_path, ack_changes, game_sha, enabled
):
    session = make_session(
        tmp_path,
        game_sha=game_sha,
        ack=native_ack(**ack_changes),
    )
    assert (observation.CAPABILITY in session.installation_capabilities()) is enabled


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"sequence": 0},
        {"sequence": True},
        {"country": "POR"},
        {"country_fullref": "0x100415247"},
        {"modifier_id": "has space"},
        {"date_raw": -1},
        {"start_date_raw": True},
        {"end_date_raw": 2**31},
        {"flags": [0, 0, 0, True]},
        {"source": "country_modifier_container_scan"},
        {"complete": False},
        {"native_rva": "0x328ca0"},
    ],
)
def test_malformed_or_out_of_scope_native_rows_are_rejected(changes):
    event = native_event(**changes)
    assert observation.public_observation(event, SESSION_ID) is None


def test_configured_modifier_scope_validates_turkish_fullref_and_rejects_mismatched_tags():
    reference = (42 << 32) | int.from_bytes(b"TUR", "little")
    event = native_event(country="TUR", country_fullref=hex(reference), schema_version=2)
    assert observation.public_observation(event, SESSION_ID) is None
    public = observation.public_observation(event, SESSION_ID, allow_scoped=True)
    assert public["payload"]["country"] == "TUR"
    assert public["payload"]["scope"] == observation.CONFIGURED_SCOPE
    assert observation.public_observation(event | {"country": "ENG"}, SESSION_ID, allow_scoped=True) is None


def test_missing_fields_and_wrong_session_are_rejected_or_ignored():
    missing = native_event()
    del missing["flags"]
    assert observation.public_observation(missing, SESSION_ID) is None
    assert observation.public_observation(native_event(session_id="other"), SESSION_ID) is None

    collector = observation.Collector(SESSION_ID)
    collector.observe(native_event(session_id="other"))
    batch = collector.batch(0)
    assert batch["events"] == []
    assert batch["complete"] is True
    assert batch["gaps"] == []


def test_collector_deduplicates_conflicts_and_reports_sequence_gaps():
    collector = observation.Collector(SESSION_ID)
    first = native_event(1)
    collector.observe(first)
    collector.observe(dict(first))
    collector.observe(native_event(1, modifier_id="other_modifier"))
    collector.observe(native_event(3))

    batch = collector.batch(0)
    assert [event["native_sequence"] for event in batch["events"]] == [1, 3]
    assert "COUNTRY_MODIFIER_SEQUENCE_CONFLICT" in batch["gaps"]
    assert "COUNTRY_MODIFIER_SEQUENCE_GAP" in batch["gaps"]
    assert batch["complete"] is False


def test_health_rows_preserve_source_state_and_surface_fault_or_invalid_status():
    healthy = observation.Collector(SESSION_ID)
    healthy.observe({
        "event": "diplomacy_observer_health",
        "session_id": SESSION_ID,
        "country_modifier_source": {
            "installed": True,
            "transport_fault": False,
            "queue_readable": True,
            "total_dropped": 0,
            "queued": 2,
        },
    })
    assert healthy.last_status["queued"] == 2
    assert healthy.batch(0)["complete"] is True

    faulted = observation.Collector(SESSION_ID)
    faulted.observe({
        "event": "diplomacy_observer_health",
        "session_id": SESSION_ID,
        "country_modifier_source": {
            "installed": True,
            "transport_fault": True,
            "queue_readable": True,
            "total_dropped": 3,
            "queued": 0,
        },
    })
    assert set(faulted.batch(0)["gaps"]) == {
        "COUNTRY_MODIFIER_CAPTURE_DROPPED",
        "COUNTRY_MODIFIER_TRANSPORT_FAULT",
    }

    malformed = observation.Collector(SESSION_ID)
    malformed.observe({
        "event": "diplomacy_observer_health",
        "session_id": SESSION_ID,
        "country_modifier_source": {"installed": True},
    })
    assert "COUNTRY_MODIFIER_HEALTH_INVALID" in malformed.batch(0)["gaps"]

    unavailable = observation.Collector(SESSION_ID)
    unavailable.observe({
        "event": "diplomacy_observer_health",
        "session_id": SESSION_ID,
        "country_modifier_source": {
            "installed": False,
            "transport_fault": False,
            "queue_readable": True,
            "total_dropped": 0,
            "queued": 0,
        },
    })
    assert "COUNTRY_MODIFIER_SOURCE_UNAVAILABLE" in unavailable.batch(0)["gaps"]


def test_cache_eviction_marks_only_cursors_behind_the_eviction():
    collector = observation.Collector(SESSION_ID)
    for sequence in range(1, observation.MAX_EVENTS + 2):
        collector.observe(native_event(sequence))

    stale = collector.batch(0)
    current = collector.batch(1)
    assert "COUNTRY_MODIFIER_CACHE_EVICTED" in stale["gaps"]
    assert stale["complete"] is False
    assert "COUNTRY_MODIFIER_CACHE_EVICTED" not in current["gaps"]
    assert current["complete"] is True
    assert [event["native_sequence"] for event in current["events"]] == list(
        range(2, observation.MAX_EVENTS + 2)
    )


def test_standalone_native_fixture_decodes_bounded_additions_and_drop_gap():
    """The 315 stream is a standalone native fixture, not a live-game capture."""
    root = Path(__file__).resolve().parents[2]
    fixture = root / "work/runtime/information-macro-events-20261109-315-001/modifier-observer-regression/stream.jsonl"
    assert fixture.is_file()
    assert fixture.stat().st_size < 50_000

    collector = None
    native_rows = []
    with fixture.open("r", encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if collector is None:
                collector = observation.Collector(event["session_id"])
            if event.get("event") == observation.NATIVE_EVENT:
                native_rows.append(event)
            collector.observe(event)

    assert collector is not None
    assert len(native_rows) == 64
    assert [row["sequence"] for row in native_rows] == list(range(1, 65))
    batch = collector.batch(0)
    assert len(batch["events"]) == 64
    assert batch["complete"] is False
    assert "COUNTRY_MODIFIER_CAPTURE_DROPPED" in batch["gaps"]


def test_refresh_false_does_not_scan_the_shared_log_cursor(tmp_path):
    session = make_session(tmp_path, [native_event(1)])
    batch = session.read_native_country_modifier_events(refresh=False)
    assert batch["events"] == []
    assert session._inbound_log_offset == 0

    fresh = session.read_native_country_modifier_events(refresh=True)
    assert [item["native_sequence"] for item in fresh["events"]] == [1]
    assert session._inbound_log_offset == (tmp_path / "control-probe.jsonl").stat().st_size


def test_partial_line_waits_for_newline_before_advancing_or_observing(tmp_path):
    session = make_session(tmp_path)
    log = tmp_path / "control-probe.jsonl"
    ack_end = log.stat().st_size
    partial = json.dumps(native_event(1), separators=(",", ":")).encode("utf-8")
    with log.open("ab") as stream:
        stream.write(partial)

    first = session.read_native_country_modifier_events()
    assert first["events"] == []
    assert session._inbound_log_offset == ack_end

    with log.open("ab") as stream:
        stream.write(b"\n")
    second = session.read_native_country_modifier_events()
    assert [item["native_sequence"] for item in second["events"]] == [1]
    assert session._inbound_log_offset == log.stat().st_size


def test_truncated_log_resets_shared_cursor_and_reports_modifier_gap(tmp_path):
    session = make_session(tmp_path, [native_event(1), native_event(2)])
    log = tmp_path / "control-probe.jsonl"
    first = session.read_native_country_modifier_events()
    assert [item["native_sequence"] for item in first["events"]] == [1, 2]
    previous_size = session._inbound_log_offset

    replacement = [native_ack(), native_event(3)]
    log.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in replacement),
        encoding="utf-8",
    )
    assert log.stat().st_size < previous_size
    second = session.read_native_country_modifier_events(after_sequence=2)
    assert [item["native_sequence"] for item in second["events"]] == [3]
    assert "COUNTRY_MODIFIER_LOG_RESET" in second["gaps"]
    assert second["complete"] is False


def test_shared_reader_surfaces_log_read_failure(tmp_path, monkeypatch):
    session = make_session(tmp_path)
    (tmp_path / "control-probe.jsonl").unlink()
    monkeypatch.setattr(session, "installation_capabilities", lambda: frozenset({observation.CAPABILITY}))

    batch = session.read_native_country_modifier_events()
    assert batch["events"] == []
    assert "COUNTRY_MODIFIER_LOG_READ_FAILED" in batch["gaps"]
    assert batch["complete"] is False


def test_concurrent_consumers_share_one_log_cursor_without_losing_rows(tmp_path):
    count = 24
    session = make_session(tmp_path, [native_event(sequence) for sequence in range(1, count + 1)])

    def consume(index):
        if index % 2:
            return session.read_native_country_modifier_events(after_sequence=0)
        return session.read_native_alliance_inbound_offers()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(consume, range(16)))

    batch = session.read_native_country_modifier_events(after_sequence=0, refresh=False)
    assert [item["native_sequence"] for item in batch["events"]] == list(range(1, count + 1))
    assert batch["complete"] is True
    assert session._inbound_log_offset == (tmp_path / "control-probe.jsonl").stat().st_size
