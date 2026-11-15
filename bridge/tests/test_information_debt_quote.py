"""A normalized read-only quote follows all three information delivery paths."""
from copy import deepcopy
import json
from unittest.mock import Mock

from bridge.debt_quote_query import BASIS, QUERY_CAPABILITY
from bridge.diplomacy import DiplomacyTools
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource


class QuoteSession:
    session_id = "offline-debt-quote-information"
    observer = "FRA"
    record = {
        "controlled_countries": ["FRA"],
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "dll_sha256": "d" * 64,
    }

    def __init__(self):
        self.calls = []

    def health(self):
        return {"status": "ready", "date_raw": 56556984,
                "complete": True, "reasons": []}

    def installation_capabilities(self):
        return frozenset({QUERY_CAPABILITY})

    def inspect_take_on_debt(self, actor, recipient, phase):
        self.calls.append((actor, recipient, phase))
        return {
            "native_visibility": True,
            "debt_quote": {
                "status": "known", "complete": True, "total_raw_i32": 104000,
                "value": 104.0, "scale": 1000, "unit": "ducats", "basis": BASIS,
                "as_of_raw": 56556984,
                "floating_point": {"model_compatible": True, "controls_stable": True},
                "loans": ["PRIVATE_INPUT_MUST_NOT_ESCAPE"],
            },
        }


def test_quote_query_report_and_periodic_delivery_share_public_value(tmp_path):
    session = QuoteSession()
    journal = Mock()
    tools = DiplomacyTools(journal, session)
    source = DiplomacySource(tools, observer="FRA")
    now = [1000.0]
    service = InformationService(source, tmp_path / "information.sqlite3", clock=lambda: now[0])
    query = {
        "topic": "A03",
        "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
        "fields": ["costs"], "parameters": {"action_id": "take_on_debt"},
    }
    try:
        direct = service.query("quote_direct", queries=[deepcopy(query)])
        report = service.manage_report("quote_report", "create", config={
            "name": "debt quote", "queries": [deepcopy(query)], "detail": "full"})["report"]
        from_report = service.query("quote_from_report", report_id=report["id"])
        subscription = service.manage_subscription("quote_subscribe", "create", config={
            "name": "debt quote", "report_id": report["id"], "kind": "periodic",
            "enabled": True,
            "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"},
        })["subscription"]
        now[0] += 2
        tick = service.tick()
        assert len(tick["results"]) == 1
        delivered = tick["results"][0]
        for result in (direct, from_report, delivered):
            field = result["items"][0]["fields"]["costs"]
            assert field["status"] == "known"
            quote = field["value"]["items"][0]
            assert quote["total_raw_i32"] == 104000
            assert quote["value"] == 104.0
            assert quote["basis"] == BASIS
            assert "PRIVATE_INPUT_MUST_NOT_ESCAPE" not in json.dumps(result)
        assert session.calls == [("FRA", "ENG", "initiate")] * 3
        journal.register.assert_not_called()
        service.manage_subscription("quote_cancel", "cancel", subscription_id=subscription["id"],
                                    expected_version=subscription["version"])
        now[0] += 2
        assert service.tick()["results"] == []
    finally:
        service.close()
