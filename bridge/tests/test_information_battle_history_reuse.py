"""Narrow regression tests for the retained W03 battle-history projection.

These tests reuse the recorded battle fixtures and only rewrite the small
SQLite rows created for a test.  They do not start the game or inspect native
artifacts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import (
    RecordedPrimary,
    _history_query,
    _war_identity_fixture,
    battle_topic_query,
    event_id,
    make_source,
)
from work.information_battle_war_identity_wire import STATUS_ABSENT as WAR_IDENTITY_ABSENT


TARGET_WAR = "war_05a3310ae47dd2bb_00000001"
OTHER_WAR = "war_05a3310ae47dd2bb_00000002"


def _w03(source, obj: dict, **parameters) -> dict:
    return source.read(
        _history_query("W03", ["battle_losses"], obj, **parameters),
        source.context(),
    )


def _replace_payload(database: Path, group_id: int, fixture: dict) -> None:
    payload = bytes.fromhex(fixture["payload_hex"])
    digest = hashlib.sha256(payload).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE fragment_groups SET total_bytes=? WHERE group_id=?",
            (len(payload), group_id),
        )
        connection.execute(
            "UPDATE complete_messages SET payload=?, payload_sha256=?, total_bytes=? "
            "WHERE group_id=?",
            (sqlite3.Binary(payload), digest, len(payload), group_id),
        )


def _bound_war_fixture(suffix: int = 1) -> dict:
    return _war_identity_fixture(
        war_id=f"war_05a3310ae47dd2bb_{suffix:08x}".encode("ascii")
    )


def _unknown_war_fixture() -> dict:
    return _war_identity_fixture(
        status=WAR_IDENTITY_ABSENT, reason=2, flags=0, creation=0, pair=(0, 0)
    )


def _war_stream(tmp_path: Path, fixtures: list[dict]):
    target = fixtures[0]
    source, _primary, target, database, _payload = make_source(
        tmp_path,
        fixture=target,
        observer="FRA",
        message_ids=tuple(str(index) for index in range(1, len(fixtures) + 1)),
        process_creation_filetime=132456789,
    )
    for group_id, fixture in enumerate(fixtures, 1):
        _replace_payload(database, group_id, fixture)
    return source, target, database


class _MetadataPrimary(RecordedPrimary):
    """Ensure the battle wrapper does not overwrite primary-owned metadata."""

    def catalog(self) -> list[dict]:
        topics = super().catalog()
        for topic in topics:
            if topic["topic_id"] == "H01":
                topic["fields"]["snapshot_changes"].update(
                    coverage="available", unit="custom_snapshot_unit", source="CustomPrimary"
                )
        return topics


class _W03QueryOnlyPrimary(RecordedPrimary):
    """Primary-owned W03 field with a valid version but query-only trigger."""

    def catalog(self) -> list[dict]:
        topics = super().catalog()
        for topic in topics:
            if topic["topic_id"] == "W03":
                topic["supported_versions"] = ["1.37.4"]
                topic["triggers"] = ["query"]
                topic["fields"]["occupations"].update(
                    coverage="available", unit="primary_occupations", source="CustomPrimary"
                )
        return topics


def test_w03_catalog_advertises_session_paging_and_preserves_primary_metadata(tmp_path):
    source, _primary, _fixture, _database, _payload = make_source(
        tmp_path, primary_cls=_MetadataPrimary
    )
    topics = {item["topic_id"]: item for item in source.catalog()}
    w03 = topics["W03"]
    losses = w03["fields"]["battle_losses"]

    assert "session" in w03["object_types"]
    assert {"query", "periodic", "change"} <= set(w03["triggers"])
    assert losses["coverage"] == "partial"
    assert losses["complete"] is False
    assert losses["history_scope"] == "retained_direct_participant_records"
    assert losses["unit"] == "battle_loss_event_page"
    assert w03["parameters"]["properties"]["limit"]["maximum"] == 256
    assert "after_event_id" in w03["parameters"]["properties"]

    h01 = topics["H01"]["fields"]["snapshot_changes"]
    assert h01["coverage"] == "available"
    assert h01["unit"] == "custom_snapshot_unit"
    assert h01["source"] == "CustomPrimary"


def test_w03_session_query_can_page_and_wrong_session_is_rejected(tmp_path):
    source, _primary, fixture, _database, _payload = make_source(
        tmp_path, message_ids=("1", "2")
    )
    session = {"type": "session", "session_id": source.context()["session_id"]}
    first = _w03(source, session, limit=1)
    first_page = first["fields"]["battle_losses"]["value"]
    assert first["fields"]["battle_losses"]["status"] == "known"
    assert [item["event_id"] for item in first_page["event_refs"]] == [event_id(fixture, "1")]
    assert first_page["coverage"]["returned"] == 1
    assert first_page["next_cursor"]

    second = _w03(source, session, after_event_id=first_page["next_cursor"], limit=1)
    assert [item["event_id"] for item in second["fields"]["battle_losses"]["value"]["event_refs"]] == [
        event_id(fixture, "2")
    ]

    wrong = _w03(source, {"type": "session", "session_id": "wrong-session"}, limit=1)
    assert wrong["fields"]["battle_losses"] == {
        "status": "unavailable", "reason": "BATTLE_SESSION_SCOPE_MISMATCH"
    }


def test_w03_known_war_filter_skips_unknown_rows_and_reports_gap(tmp_path):
    target = _bound_war_fixture()
    source, target, _database = _war_stream(
        tmp_path, [target, _bound_war_fixture(2), _unknown_war_fixture()]
    )
    result = _w03(source, {"type": "war", "war_id": TARGET_WAR}, limit=64)
    page = result["fields"]["battle_losses"]["value"]
    refs = page["event_refs"]

    assert [item["event_id"] for item in refs] == [event_id(target, "1")]
    assert refs[0]["war_id"] == {"status": "known", "value": TARGET_WAR}
    assert page["coverage"]["war_id"] == TARGET_WAR
    assert page["coverage"]["complete"] is False
    assert any(gap["reason"] == "BATTLE_HISTORY_WAR_ID_UNKNOWN" for gap in page["coverage"]["gaps"])
    encoded = json.dumps(result, sort_keys=True)
    assert event_id(target, "2") not in encoded
    assert OTHER_WAR not in encoded


def test_w03_other_known_war_is_filtered_without_reference_leak(tmp_path):
    target = _bound_war_fixture()
    source, target, _database = _war_stream(
        tmp_path, [target, _bound_war_fixture(2), _unknown_war_fixture()]
    )
    result = _w03(source, {"type": "war", "war_id": OTHER_WAR}, limit=64)
    page = result["fields"]["battle_losses"]["value"]
    encoded = json.dumps(result, sort_keys=True)

    assert [item["event_id"] for item in page["event_refs"]] == [event_id(target, "2")]
    assert event_id(target, "1") not in encoded
    assert TARGET_WAR not in encoded
    assert page["coverage"]["war_id"] == OTHER_WAR


@pytest.mark.parametrize("serial", [257, 0xFFFFFFFF])
def test_w03_public_query_and_report_keep_losses_for_recycled_registry_ids(tmp_path, serial):
    war_id = f"war_05a3310ae47dd2bb_{serial:08x}"
    fixture = _bound_war_fixture(serial)
    source, fixture, _database = _war_stream(
        tmp_path, [fixture, _bound_war_fixture(2), fixture]
    )
    query = _history_query("W03", ["battle_losses"], {"type": "war", "war_id": war_id}, limit=1)
    service = InformationService(source, tmp_path / "recycled-war-history.sqlite3")
    tools = InformationTools(service)
    try:
        full = tools.call("information_query", {
            "request_id": "recycled-war-first", "queries": [query], "view": "full",
        })
        field = full["items"][0]["fields"]["battle_losses"]
        assert field["status"] == "known"
        page = field["value"]
        assert [ref["event_id"] for ref in page["event_refs"]] == [event_id(fixture, "1")]
        assert page["event_refs"][0]["war_id"] == {"status": "known", "value": war_id}
        assert page["next_cursor"]

        losses = tools.call("information_query", {
            "request_id": "recycled-war-b02", "view": "full",
            "queries": [battle_topic_query("B02", ["losses"], selected_event=event_id(fixture, "1"))],
        })["items"][0]["fields"]["losses"]
        assert losses["status"] == "known"
        assert page["event_refs"][0]["losses"]["status"] == "known"
        assert page["event_refs"][0]["losses"]["value"] == losses["value"]

        next_query = dict(query, parameters={"limit": 1, "after_event_id": page["next_cursor"]})
        report = tools.call("information_manage_report", {
            "request_id": "recycled-war-report", "operation": "create",
            "config": {"name": "war losses", "queries": [next_query], "detail": "full"},
        })["report"]
        concise = tools.call("information_query", {
            "request_id": "recycled-war-next", "report_id": report["id"],
        })["items"][0]
        assert concise["war_id"] == war_id
        refs = concise["battle_losses"]["event_refs"]
        assert [ref["event_id"] for ref in refs] == [event_id(fixture, "3")]
        assert refs[0]["war_id"] == war_id
        assert refs[0]["losses"]
        assert concise["battle_losses"]["next_cursor"] is None
    finally:
        service.close()


def test_w03_cursor_preserves_limit_advances_over_filtered_rows_and_is_war_bound(tmp_path):
    target = _bound_war_fixture()
    source, target, _database = _war_stream(
        tmp_path, [_bound_war_fixture(2), _unknown_war_fixture(), target, _bound_war_fixture()]
    )
    selected = {"type": "war", "war_id": TARGET_WAR}
    first = _w03(source, selected, limit=1)
    first_page = first["fields"]["battle_losses"]["value"]
    cursor = first_page["next_cursor"]
    assert len(first_page["event_refs"]) == 1
    assert first_page["event_refs"][0]["event_id"] == event_id(target, "3")
    assert cursor
    assert any(gap["reason"] == "BATTLE_HISTORY_WAR_ID_UNKNOWN" for gap in first_page["coverage"]["gaps"])

    second = _w03(source, selected, after_event_id=cursor, limit=1)
    second_page = second["fields"]["battle_losses"]["value"]
    assert len(second_page["event_refs"]) == 1
    assert second_page["event_refs"][0]["event_id"] == event_id(target, "4")
    assert len(second_page["event_refs"]) <= 1

    crossed = _w03(source, {"type": "war", "war_id": OTHER_WAR}, after_event_id=cursor, limit=1)
    assert crossed["fields"]["battle_losses"]["status"] == "unavailable"
    assert crossed["fields"]["battle_losses"]["reason"] in {
        "battle_history_cursor_war_mismatch", "battle_history_cursor_binding_mismatch"
    }


def test_w03_war_selectors_do_not_degrade_to_global_and_h01_stays_unavailable(tmp_path):
    source, _primary, _fixture, _database, _payload = make_source(tmp_path)
    pair_only = _w03(
        source, {"type": "war", "actor": "FRA", "recipient": "HSA"}, limit=4
    )
    assert pair_only["fields"]["battle_losses"] == {
        "status": "unavailable", "reason": "WAR_ID_UNRESOLVED"
    }

    paired_id = _w03(
        source,
        {"type": "war", "war_id": TARGET_WAR, "actor": "FRA", "recipient": "HSA"},
        limit=4,
    )
    assert paired_id["fields"]["battle_losses"] == {
        "status": "unavailable", "reason": "WAR_HISTORY_PAIR_SELECTION_UNSUPPORTED"
    }

    for war_id in ("war_05a3310ae47dd2bb_00000000", "war_0000000000000000_00000101"):
        invalid = _w03(source, {"type": "war", "war_id": war_id}, limit=4)
        assert invalid["fields"]["battle_losses"] == {
            "status": "unavailable", "reason": "WAR_ID_UNRESOLVED"
        }

    h01 = source.read(
        _history_query("H01", ["battle_sequence"], {"type": "war", "war_id": TARGET_WAR}, limit=4),
        source.context(),
    )
    assert h01["fields"]["battle_sequence"] == {
        "status": "unavailable", "reason": "WAR_ID_UNRESOLVED"
    }


def test_filtered_scan_limit_emits_an_opaque_cursor_bound_to_the_selected_war(tmp_path):
    # All 256 rows are outside the selection. A bounded scan must still make
    # progress, while its opaque storage cursor cannot be reused for another war.
    fixture = _bound_war_fixture(2)
    source, _, _, _, _ = make_source(tmp_path, fixture=fixture, observer='FRA',
        message_ids=tuple(str(index) for index in range(1, 257)),
        process_creation_filetime=132456789)
    selected = {'type': 'war', 'war_id': TARGET_WAR}
    page = _w03(source, selected, limit=1)['fields']['battle_losses']['value']
    assert page['event_refs'] == [] and page['coverage']['complete'] is False
    cursor = page['next_cursor']
    assert cursor.startswith('battle-page:')
    resumed = _w03(source, selected, limit=1, after_event_id=cursor)
    assert resumed['fields']['battle_losses']['value']['next_cursor'] is None
    crossed = _w03(source, {'type': 'war', 'war_id': OTHER_WAR}, limit=1, after_event_id=cursor)
    assert crossed['fields']['battle_losses'] == {
        'status': 'unavailable', 'reason': 'battle_history_cursor_binding_mismatch'}


def test_w03_rejects_parameter_selectors_instead_of_ignoring_them(tmp_path):
    source, _, _, _, _ = make_source(tmp_path)
    with pytest.raises(InformationError) as error:
        _w03(source, {'type': 'country', 'country': 'VIJ'}, war_id=TARGET_WAR)
    assert error.value.code == 'invalid_parameters'


def test_w03_service_periodic_ticks_twice_change_is_quiet_and_cancel_is_independent(tmp_path):
    source, _primary, _fixture, _database, _payload = make_source(tmp_path)
    now = [1000.0]
    service = InformationService(source, tmp_path / "w03-service.sqlite3", clock=lambda: now[0])
    query = _history_query(
        "W03", ["battle_losses"], {"type": "session", "session_id": source.context()["session_id"]}, limit=64
    )
    try:
        report = service.manage_report(
            "w03-report", "create", config={"name": "w03", "queries": [query], "detail": "full"}
        )["report"]
        periodic = service.manage_subscription(
            "w03-periodic", "create",
            config={
                "name": "w03 periodic", "kind": "periodic", "report_id": report["id"],
                "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        change = service.manage_subscription(
            "w03-change", "create",
            config={
                "name": "w03 change", "kind": "change", "report_id": report["id"],
                "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        now[0] += 1
        first = service.tick()
        assert [item["subscription_id"] for item in first["results"]] == [periodic["id"]]
        assert first["results"][0]["items"][0]["fields"]["battle_losses"]["complete"] is False

        now[0] += 1
        second = service.tick()
        assert [item["subscription_id"] for item in second["results"]] == [periodic["id"]]
        assert all(item["subscription_id"] != change["id"] for item in second["results"])

        cancelled = service.manage_subscription(
            "w03-periodic-cancel", "cancel", subscription_id=periodic["id"],
            expected_version=periodic["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        now[0] += 1
        third = service.tick()
        assert all(item["subscription_id"] != periodic["id"] for item in third["results"])
        assert all(item["subscription_id"] != change["id"] for item in third["results"])
    finally:
        service.close()


def test_w03_mixed_primary_field_does_not_inherit_history_periodic_trigger(tmp_path):
    source, _primary, _fixture, _database, _payload = make_source(
        tmp_path, primary_cls=_W03QueryOnlyPrimary
    )
    service = InformationService(source, tmp_path / "w03-mixed-service.sqlite3")
    query = _history_query(
        "W03",
        ["battle_losses", "occupations"],
        {"type": "session", "session_id": source.context()["session_id"]},
    )
    try:
        report = service.manage_report(
            "w03-mixed-report", "create", config={"name": "mixed", "queries": [query]}
        )["report"]
        with pytest.raises(InformationError) as error:
            service.manage_subscription(
                "w03-mixed-periodic", "create",
                config={
                    "kind": "periodic", "report_id": report["id"],
                    "schedule": {"basis": "real", "every": 1, "unit": "seconds"},
                },
            )
        assert error.value.code == "unsupported_trigger"
    finally:
        service.close()
