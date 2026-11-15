"""Public reads use the selected field owner's observer scope."""
import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.information.war_relations import NativeWarRelationsSource
from bridge.tests.test_information_country_scale import _wars_raw, _wars_value
from bridge.tests.test_information_war_relations import Primary, Rivals, Scale, query


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("entry_point", ["manual", "report", "periodic"])
def test_foreign_wars_read_keeps_its_owner_scope_and_survives_reopen(tmp_path, reverse, entry_point):
    scale, rivals = Scale(), Rivals()
    scale.field = _wars_raw(_wars_value("ENG"))
    owners = [rivals, NativeWarRelationsSource(scale)]
    if reverse:
        owners.reverse()
    source = CompositeSource(Primary(), owners)
    database = tmp_path / "information.sqlite3"
    now = [1000.0]
    service = InformationService(source, database, clock=lambda: now[0])
    try:
        tools = InformationTools(service)
        arguments = {"request_id": "foreign-war-query", "queries": [query("ENG")]}
        if entry_point != "manual":
            report = tools.call("information_manage_report", {
                "request_id": "foreign-war-report", "operation": "create",
                "config": {"name": "Foreign current wars", "queries": [query("ENG")], "detail": "full"},
            })["report"]
            arguments = {"request_id": "foreign-war-query", "report_id": report["id"]}
        if entry_point == "periodic":
            tools.call("information_manage_subscription", {
                "request_id": "foreign-war-periodic", "operation": "create",
                "config": {"name": "Foreign current wars", "report_id": report["id"], "kind": "periodic", "enabled": True,
                           "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"}},
            })
            assert tools.call("information_tick", {})["results"] == []
            now[0] += 1
            concise = tools.call("information_tick", {})["results"][0]
        else:
            concise = tools.call("information_query", arguments)
            assert tools.call("information_query", arguments) == concise
        assert concise["items"][0]["country"] == "ENG"
        assert concise["items"][0]["wars"]["war_count"] == 1
        full = tools.call("information_get_result", {"result_id": concise["result_id"], "view": "full"})
        assert full["items"][0]["fields"]["wars"]["status"] == "known"
        assert full["items"][0]["fields"]["wars"]["value"] == _wars_value("ENG")
        assert len(scale.calls) == 1
        assert rivals.calls == []
        assert full["complete"] is False
    finally:
        service.close()

    service = InformationService(source, database)
    try:
        tools = InformationTools(service)
        assert tools.call("information_get_result", {"result_id": concise["result_id"]}) == concise
        assert len(scale.calls) == 1
        with pytest.raises(InformationError) as error:
            tools.call("information_query", {
                "request_id": "foreign-rivals-rejected", "queries": [query("ENG", ["rivals"])],
            })
        assert error.value.code == "observer_scope_mismatch"
        assert rivals.calls == []
    finally:
        service.close()
