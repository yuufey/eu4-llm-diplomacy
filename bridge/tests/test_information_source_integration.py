"""Production adapters through catalog routing and the external tool boundary."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource
from bridge.information.sources import DiplomacySource
from bridge.tests.test_information_country_state import _source, _query, _r73_case
from bridge.tests.test_information_static_data import _write_fixture


ROOT = Path(__file__).resolve().parents[2]


def test_country_resource_report_keeps_unimplemented_fields_and_zero_values(tmp_path):
    adapter, session = _source(_r73_case("men_FRA_SAV_no_diplomat"),
                               {"native_favor_men_query", "native_favor_men_submission"})
    service = InformationService(CompositeSource(adapter.base_source, [adapter]), tmp_path / "info.db")
    try:
        query = _query("N05", ["diplomats_available", "diplomats_total"], "SAV")
        result = service.query("resource-partial", queries=[query])
        assert result["status"] == "partial"
        assert result["items"][0]["fields"]["diplomats_available"]["value"] == 0
        assert result["items"][0]["fields"]["diplomats_total"]["status"] == "unsupported"
        assert session.submit_calls == []
        foreign = deepcopy(query)
        foreign["object"]["country"] = "ENG"
        rejected = service.query("resource-foreign", queries=[foreign])
        assert rejected["status"] == "failed"
        assert rejected["items"][0]["fields"]["diplomats_available"]["reason"] == "observer_scope_mismatch"
        report = service.manage_report("foreign-report", "create", config={"queries": [foreign]})["report"]
        with pytest.raises(InformationError) as error:
            service.manage_subscription("foreign-subscription", "create", config={
                "report_id": report["id"], "kind": "periodic",
                "schedule": {"basis": "real", "every": 1, "unit": "seconds"}})
        assert error.value.code == "observer_scope_mismatch"
    finally:
        service.close()


def test_cli_static_query_can_succeed_beside_an_unready_game_source(tmp_path):
    game = tmp_path / "game"
    user = tmp_path / "user"
    user.mkdir()
    (user / "dlc_load.json").write_text('{"enabled_mods":[]}', encoding="utf-8")
    _write_fixture(game, "east={members={1} outgoing={name=west}} west={members={2}}")
    request = {"tool": "information_query", "arguments": {"request_id": "static-cli", "view": "full", "queries": [
        {"topic": "T01", "object": {"type": "trade_node", "node_id": "west"}, "fields": ["upstream", "downstream"]},
        {"topic": "C01", "object": {"type": "session"}, "fields": ["game_day"]}]}}
    result = subprocess.run([sys.executable, "tools/serve_information.py", "--jsonl", "--database", str(tmp_path / "info.db"),
                             "--static-game-data", "--static-game-root", str(game), "--static-user-data", str(user)],
                            input=json.dumps(request) + "\n", capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=20)
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["status"] == "partial"
    assert body["context"]["session_id"] is None
    assert body["items"][0]["fields"]["upstream"]["value"] == ["east"]
    assert body["items"][0]["source"]["context_scope"] == "static_rules"
    assert body["items"][1]["fields"]["game_day"]["status"] == "unavailable"


def test_explicit_operator_observer_is_checked_against_existing_authority():
    adapter, session = _source(_r73_case("men_FRA_PAP"),
                               {"native_favor_men_query", "native_favor_men_submission"})
    context = DiplomacySource(adapter.base_source.diplomacy_tools, observer="FRA").context()
    assert context["status"] == "ready"
    assert context["observer"] == "FRA"
    assert context["observer_binding"] == "operator_configuration"
    mismatch = DiplomacySource(adapter.base_source.diplomacy_tools, observer="ENG").context()
    assert mismatch["status"] == "unready"
    assert mismatch["complete"] is False
    assert {r["code"] for r in mismatch["reasons"]} >= {"OBSERVER_AUTHORITY_SCOPE_MISMATCH"}
    assert session.submit_calls == []


@pytest.mark.parametrize(("topic", "field", "action", "capabilities", "expected"), [
    ("N01", "treasury", "send_gift", {"native_gift_query", "native_gift_submission"}, 16645),
    ("N02", "manpower", "trade_favors_for_men", {"native_favor_men_query", "native_favor_men_submission"}, 37927),
    ("N05", "diplomats_available", "trade_favors_for_men", {"native_favor_men_query", "native_favor_men_submission"}, 1),
])
def test_retained_live_country_capture_through_public_projection_and_service(
    tmp_path, topic, field, action, capabilities, expected
):
    fixture = json.loads((Path(__file__).parent / "fixtures" / "information_country_live_1374.json").read_text(encoding="utf-8"))
    assert fixture["provenance"]["mode"] == "recorded"
    assert fixture["provenance"]["original_mode"] == "live"
    adapter, session = _source(fixture["events"][action]["raw"], capabilities)
    service = InformationService(CompositeSource(adapter.base_source, [adapter]), tmp_path / "info.db")
    try:
        result = service.query("retained-country", queries=[_query(topic, [field])])
        assert result["complete"] is True
        assert result["items"][0]["fields"][field]["value"] == expected
        assert result["context"]["session_id"] == fixture["provenance"]["session_id"]
        assert result["context"]["game_date"] == fixture["provenance"]["date_raw"]
        assert session.submit_calls == []
    finally:
        service.close()
