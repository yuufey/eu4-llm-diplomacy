"""Offline projection tests for the v6 copied native battle-text extension.

The v5 base is an existing recorded FRA v4 fixture wrapped with the already
accepted WARI envelope.  NTXT is synthetic value-only test data; it is clearly
marked as such and does not represent a new live capture.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.battle_native_text import project_native_text
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import (
    _war_identity_fixture,
    battle_topic_query,
    event_id,
    make_source,
)
from work.information_battle_native_text_wire import (
    decode,
    encode,
)
from work.information_battle_war_identity_wire import decode as decode_v5


def _native_snapshot(*, line_state: str = "absent", date_delta: int = 0,
                     bad_raw: bool = False) -> dict:
    definition_hex = "4c414e44424154544c454f564552"
    if bad_raw:
        definition_hex = "10e3"
    return {
        "definition_key": {
            "state": "observed", "source": "message_metadata",
            "raw_hex": definition_hex,
        },
        "auxiliary_text": {
            "state": "observed", "source": "message_metadata", "raw_hex": "",
        },
        "title_helper_candidate": {
            "state": "observed", "source": "title_helper_candidate",
            "raw_hex": "424154544c455f4f465f5041524953",
        },
        "line1_text": {
            "state": line_state, "source": "native_line1", "raw_hex": "",
        },
        "native_date": {"state": "observed", "value": None},
        "raw_flags": {
            "state": "observed", "raw_flag_8c": 0xa1, "raw_flag_8d": 0x5e,
        },
        "_date_delta": date_delta,
    }


def _v6_fixture(*, line_state: str = "absent", date_delta: int = 0,
                bad_raw: bool = False) -> tuple[dict, bytes, bytes]:
    fixture = _war_identity_fixture()
    base = bytes.fromhex(fixture["payload_hex"])
    base_decoded = decode_v5(base)
    raw_date = base_decoded["observation"]["result"]["raw_date"]
    snapshot = _native_snapshot(
        line_state=line_state, date_delta=date_delta, bad_raw=bad_raw,
    )
    snapshot["native_date"]["value"] = raw_date + date_delta
    snapshot.pop("_date_delta")
    payload = encode(base, snapshot)
    fixture = deepcopy(fixture)
    fixture["payload_hex"] = payload.hex()
    fixture["synthetic_native_text_extension"] = True
    fixture["synthetic_native_text_note"] = (
        "NTXT values are bounded contract data wrapped around the recorded "
        "FRA v4/WARI base; this is not a live text capture."
    )
    return fixture, base, payload


def _details_query(selected: str) -> dict:
    return battle_topic_query("B04", ["details"], selected_event=selected)


def test_v5_shape_is_unchanged_and_v6_native_text_projects_through_query(tmp_path):
    fixture, base, payload = _v6_fixture()

    # The new decoder is a strict compatibility wrapper for v1-v5.
    assert decode(base) == decode_v5(base)

    decoded = decode(payload)
    projected = project_native_text(decoded)
    assert projected["codec"] == "eu4_escape"
    assert projected["definition_key"] == {
        "status": "known",
        "raw_hex": "4c414e44424154544c454f564552",
        "source": "message_metadata",
        "codec": "eu4_escape",
        "decoded": {"status": "known", "value": "LANDBATTLEOVER"},
    }
    assert projected["auxiliary_text"] == {
        "status": "known", "raw_hex": "", "source": "message_metadata",
        "codec": "eu4_escape", "decoded": {"status": "known", "value": ""},
    }
    assert projected["title_helper_candidate"]["decoded"] == {
        "status": "known", "value": "BATTLE_OF_PARIS",
    }
    assert projected["line1_text"] == {
        "status": "absent", "raw_hex": None, "source": "native_line1",
        "codec": "eu4_escape",
        "decoded": {"status": "absent", "reason": "NATIVE_TEXT_FIELD_ABSENT"},
    }
    assert projected["metadata"]["native_date"]["status"] == "known"
    assert projected["metadata"]["raw_flags"]["raw_flag_8c"] == 0xa1
    assert projected["full_display_complete"] is False

    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("9",),
    )
    result = source.read(
        _details_query(event_id(fixture, "9")), source.context(),
    )
    assert result["fields"]["details"]["status"] == "known"
    assert result["fields"]["details"]["value"]["native_text"] == projected
    assert result["source"]["projection_version"] == 30
    assert "raw_text" not in result["fields"]["details"]["value"]


def test_unknown_text_field_is_preserved_without_cross_source_aliasing():
    fixture, _base, payload = _v6_fixture(line_state="unknown")
    projected = project_native_text(decode(payload))
    assert projected["line1_text"] == {
        "status": "unknown", "raw_hex": None, "source": "native_line1",
        "codec": "eu4_escape",
        "decoded": {"status": "unknown", "reason": "NATIVE_TEXT_FIELD_UNKNOWN"},
    }
    assert projected["title_helper_candidate"]["source"] == (
        "title_helper_candidate"
    )
    assert projected["auxiliary_text"]["source"] == "message_metadata"


@pytest.mark.parametrize(
    ("date_delta", "bad_raw"),
    [(1, False), (0, True)],
)
def test_date_mismatch_or_bad_raw_preserves_v5_and_localizes_unknown(
        tmp_path, date_delta, bad_raw):
    fixture, _base, _payload = _v6_fixture(
        date_delta=date_delta, bad_raw=bad_raw,
    )
    projected = project_native_text(decode(bytes.fromhex(fixture["payload_hex"])))
    if date_delta:
        assert projected["status"] == "unknown"
        assert projected["reason"] == "NATIVE_TEXT_DATE_MISMATCH"
        assert projected["codec"] == "eu4_escape"
        assert projected["metadata"]["native_date"]["status"] == "known"
        assert projected["metadata"]["raw_flags"]["raw_flag_8d"] == 0x5e
        assert projected["complete"] is False
        assert projected["full_display_complete"] is False
    else:
        assert projected["definition_key"] == {
            "status": "unknown",
            "raw_hex": "10e3",
            "source": "message_metadata",
            "codec": "eu4_escape",
            "decoded": {
                "status": "unknown",
                "reason": "NATIVE_TEXT_DECODE_FAILED",
            },
        }

    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("9",),
    )
    selected = event_id(fixture, "9")
    result = source.read(_details_query(selected), source.context())
    details = result["fields"]["details"]
    assert details["status"] == "known"
    assert details["value"]["native_text"] == projected
    assert result["source"]["projection_version"] == 30
    polled = source.poll_events(source.context(), None)
    assert len(polled["events"]) == 1
    assert polled["events"][0]["payload"]["battle_fields"]["details"][
        "value"]["native_text"] == projected


def test_information_service_report_and_subscription_keep_native_text_payload(tmp_path):
    fixture, _base, _payload = _v6_fixture()
    source, _primary, _fixture, _db, _raw = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("9",),
    )
    service = InformationService(source, tmp_path / "native-text-service.sqlite3")
    tools = InformationTools(service)
    selected = event_id(fixture, "9")
    query = _details_query(selected)
    provenance = fixture["provenance"]
    binding = {
        "session_id": provenance["session_id"],
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": provenance["game_sha256"],
    }
    try:
        direct = service.query("native-text-query", queries=[query])
        assert direct["items"][0]["fields"]["details"]["value"]["native_text"][
            "title_helper_candidate"]["decoded"] == {
                "status": "known", "value": "BATTLE_OF_PARIS",
            }

        report = tools.call("information_manage_report", {
            "request_id": "native-text-report",
            "operation": "create",
            "config": {"name": "native text", "queries": [query], "detail": "full"},
        })["report"]
        report_result = service.query("native-text-report-query",
                                      report_id=report["id"])
        assert report_result["items"][0]["fields"]["details"]["value"][
            "native_text"]["auxiliary_text"]["decoded"] == {
                "status": "known", "value": "",
            }

        subscription = tools.call("information_manage_subscription", {
            "request_id": "native-text-subscription",
            "operation": "create",
            "config": {
                "name": "native text events",
                "kind": "event",
                "report_id": report["id"],
                "enabled": True,
                "binding": binding,
                "event": {"types": ["battle_observation"]},
            },
        })["subscription"]
        assert subscription["state"] == "active"
        tick = tools.call("information_tick", {"view": "full"})
        item = tick["results"][0]["items"][0]
        assert item["fields"]["details"]["value"]["native_text"][
            "definition_key"]["raw_hex"] == "4c414e44424154544c454f564552"
    finally:
        service.close()
