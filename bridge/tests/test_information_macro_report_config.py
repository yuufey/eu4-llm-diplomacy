"""Keep the macro report usable through the existing public information tools."""
import json
from pathlib import Path

from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools, REPORT_CONFIG_SCHEMA, validate_schema
from tools.serve_information import _build_runtime, build_parser


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "docs" / "02-使用与接口" / "宏观战略报告配置.json"


def test_macro_report_public_create_query_and_reopen(tmp_path):
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    args = build_parser().parse_args([
        "--database", str(tmp_path / "information.sqlite3"), "--observer", "FRA",
    ])
    service, journal = _build_runtime(args)
    assert journal is None
    try:
        tools = InformationTools(service)
        created = tools.call("information_manage_report", {
            "request_id": "macro-report-create", "operation": "create", "config": config,
        })["report"]
        result = tools.call("information_query", {
            "view": "full",
            "request_id": "macro-report-query", "report_id": created["id"],
        })
        assert result["report_id"] == created["id"]
        assert len(result["items"]) == len(config["queries"])
        for query, item in zip(created["queries"], result["items"]):
            assert item["query"] == query
            assert set(item["fields"]) == set(query["fields"])
            # The unbound runtime must preserve missing-source states.
            assert all(value["status"] != "known" for value in item["fields"].values())
        assert result["context"]["status"] != "ready"
    finally:
        service.close()

    reopened, journal = _build_runtime(args)
    assert journal is None
    try:
        saved = InformationTools(reopened).call("information_manage_report", {
            "request_id": "macro-report-get", "operation": "get", "report_id": created["id"],
        })["report"]
        assert saved == created
    finally:
        reopened.close()


def test_macro_report_selects_decision_fields_and_explicit_example_objects():
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    queries = config["queries"]
    assert all(query["fields"] for query in queries)
    assert {query["topic"] for query in queries} >= {
        "C01", "C03", "N01", "N02", "N03", "N04", "N05", "N06", "R01", "R03", "R04",
        "R07",
    }
    forces = next(query for query in queries if query["topic"] == "N02")
    assert set(forces["fields"]) == {
        "army_size", "navy_size", "manpower", "max_manpower",
        "sailors", "max_sailors", "force_limits",
    }
    assert {query["object"]["country"] for query in queries
            if query["object"]["type"] == "country"} == {"FRA", "ENG"}
    identity = next(query for query in queries if query['topic'] == 'C01')
    assert identity['fields'] == ['observer', 'game_date']
    treasury = next(query for query in queries if query['topic'] == 'N01')
    assert treasury['parameters'] == {}
    relations = next(query for query in queries if query['topic'] == 'R03' and query['object']['type'] == 'country')
    assert {'coalition_members', 'targets'} <= set(relations['fields'])
    commitments = next(query for query in queries if query['topic'] == 'R07')
    assert commitments['object'] == {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'}
    assert set(commitments['fields']) == {'land_commitments', 'war_commitments', 'economic_support', 'expiry'}
    for query in queries:
        if "reference_recipient" in query["parameters"]:
            assert query["object"]["country"] == "FRA"
            assert query["parameters"]["reference_recipient"] == "ENG"


def test_macro_context_config_has_explicit_tasks_nodes_and_valid_selected_war():
    path = CONFIG_PATH.with_name("宏观战略任务与贸易情境配置.json")
    config = json.loads(path.read_text(encoding="utf-8"))
    validate_schema(config, REPORT_CONFIG_SCHEMA)
    source = DiplomacySource(observer="FRA")
    mission_state = next(query for query in config["queries"] if query["topic"] == "M02")
    assert set(mission_state["fields"]) == {
        "prerequisites", "completion_status", "currently_completable", "condition_progress",
    }
    for query in config["queries"]:
        if query["topic"].startswith("M"):
            assert query["parameters"]["task_id"] == "fra_liberate_norm"
        elif query["topic"].startswith("T"):
            assert query["object"]["node_id"] in {"champagne", "english_channel"}
        else:
            assert source.validate_query(query) == query
            assert query["parameters"]["selection"]["war_goal"] == {
                "province_id": -1, "beneficiary": "FRA",
            }
