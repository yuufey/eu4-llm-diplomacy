"""Fixed-build battle roles remain independent of result and observer order."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information import battles
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import battle_query, event_id, make_source


@pytest.fixture(params=[
    ("information_battle_FRA_live_container_v4_1374.json", "FRA", "3"),
    ("information_battle_naval_seq8_live_container_v4_1374.json", "KEL", "8"),
])
def real_battle_source(tmp_path, request):
    filename, observer, message_id = request.param
    fixture = json.loads((Path(__file__).parent / "fixtures" / filename).read_text(encoding="utf-8"))
    assert fixture["provenance"]["real_capture"] is True
    assert fixture["provenance"]["synthetic_extension"] is False
    source, _, _, _, _ = make_source(tmp_path, fixture, observer=observer, message_ids=(message_id,))
    return source, event_id(fixture, message_id)


def roles_from(item):
    return [side["role"] for side in item["fields"]["sides"]["value"]]


@pytest.mark.parametrize("reverse_results", [False, True])
def test_roles_follow_combat_side_after_result_order_changes(real_battle_source, monkeypatch, reverse_results):
    source, selected = real_battle_source
    original_decode = battles.decode

    def changed_result_order(payload):
        decoded = original_decode(payload)
        if reverse_results:
            decoded["observation"]["result"]["sides"].reverse()
        return decoded

    monkeypatch.setattr(battles, "decode", changed_result_order)
    query = battle_query(["sides"], selected_event=selected)
    result = source.read(query, source.context())
    expected = ["attacker", "defender"] if reverse_results else ["defender", "attacker"]
    assert roles_from(result) == [{"status": "known", "value": role} for role in expected]
    assert result["source"]["battle_role_basis"] == "fixed1374_combat_save_keys"
    assert result["source"]["projection_version"] == 30
    metadata = next(topic for topic in source.catalog() if topic["topic_id"] == "B01")
    assert metadata["fields"]["sides"]["combat_side_roles"] == {"0": "attacker", "1": "defender"}


@pytest.mark.parametrize("unmatched", [True, False], ids=["unmatched", "duplicate_result_side"])
def test_ambiguous_result_side_never_acquires_a_role(real_battle_source, monkeypatch, unmatched):
    source, selected = real_battle_source
    original_decode = battles.decode

    def ambiguous_result(payload):
        decoded = original_decode(payload)
        sides = decoded["observation"]["result"]["sides"]
        sides[0]["country"] = (int.from_bytes(b"ZZZ" + b"\0" * 5, "little")
                               if unmatched else sides[1]["country"])
        return decoded

    monkeypatch.setattr(battles, "decode", ambiguous_result)
    result = source.read(battle_query(["sides"], selected_event=selected), source.context())
    assert roles_from(result) == [
        {"status": "unknown", "reason": "RESULT_SIDE_MAPPING_UNRESOLVED"},
        {"status": "unknown", "reason": "RESULT_SIDE_MAPPING_UNRESOLVED"},
    ]
    gap_query = dict(battle_query(["gaps"], selected_event=selected), topic="B04")
    gaps = source.read(gap_query, source.context())["fields"]["gaps"]["value"]
    assert "RESULT_SIDE_MAPPING_UNRESOLVED" in gaps
    assert "ROLES_AND_FULL_DISPLAY_UNRESOLVED" not in gaps


def test_real_battle_roles_agree_in_query_report_event_and_reopen(tmp_path, real_battle_source):
    source, selected = real_battle_source
    query = battle_query(["sides", "winner"], selected_event=selected)
    database = tmp_path / "information.sqlite3"
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        direct = tools.call("information_query", {"view": "full", "request_id": "roles-direct", "queries": [query]})
        report = tools.call("information_manage_report", {
            "request_id": "roles-create", "operation": "create",
            "config": {"name": "battle roles", "queries": [query], "detail": "full"},
        })["report"]
        reported = tools.call("information_query", {"view": "full", "request_id": "roles-report", "report_id": report["id"]})
        assert reported["items"][0]["fields"] == direct["items"][0]["fields"]
        tools.call("information_manage_subscription", {
            "request_id": "roles-subscribe", "operation": "create", "config": {
                "name": "battle result", "kind": "event", "report_id": report["id"], "enabled": True,
                "event": {"types": ["battle_observation"]},
            },
        })
        delivered = tools.call("information_tick", {"view": "full"})["results"]
        assert len(delivered) == 1
        assert delivered[0]["items"][0]["fields"] == direct["items"][0]["fields"]
        assert roles_from(delivered[0]["items"][0]) == [
            {"status": "known", "value": "defender"}, {"status": "known", "value": "attacker"},
        ]
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        retained_id = delivered[0]["result_id"]
        retained_items = deepcopy(delivered[0]["items"])
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(retained_id)["items"] == retained_items
