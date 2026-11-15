"""Selected CB costs through effective definitions and normal information tools."""
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.declaration_cost_rules import DeclarationCostRules, declaration_allowed_terms
from bridge.declarewar_peace_options import project_native_peace_options
from bridge.tests import test_declarewar_peace_options as peace_option_fixtures
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_sources import _LiveSession, _LiveTools


CB = "cb_test = { war_goal = take_test }"
GOAL = """take_test = {
    attacker = {
        badboy_factor = 0.25 prestige_factor = 1 peace_cost_factor = 0.75
        peace_options = { po_demand_provinces po_return_cores }
        allowed_provinces = { is_core = ROOT }
    }
    defender = {
        badboy_factor = 1 prestige_factor = 2 peace_cost_factor = 1
        peace_options = { po_gold }
    }
}"""


def _file(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def rules(tmp_path):
    game = tmp_path / "game"
    _file(game, "launcher-settings.json", json.dumps({"rawVersion": "v1.37.4.0"}))
    _file(game, "common/cb_types/00.txt", CB)
    _file(game, "common/wargoal_types/00.txt", GOAL)
    return DeclarationCostRules(game_root=game, user_data=tmp_path / "user", enabled_mods=[])


def test_literal_multipliers_and_province_conditions_are_projected(rules):
    result = rules.read("cb_test")
    assert result["status"] == "known" and result["complete"]
    assert result["value"] == {
        "casus_belli": "cb_test", "war_goal": "take_test",
        "attacker": {"warscore_multiplier": 0.75, "aggressive_expansion_multiplier": 0.25,
                     "prestige_multiplier": 1, "applies_to": ["po_demand_provinces", "po_return_cores"],
                     "province_conditions": [{"is_core": "ROOT"}]},
        "defender": {"warscore_multiplier": 1, "aggressive_expansion_multiplier": 1,
                     "prestige_multiplier": 2, "applies_to": ["po_gold"]},
    }
    assert len(result["source"]["definition_files"]) == 2


def test_changed_effective_files_refresh_cache(rules):
    first = rules.read("cb_test")
    path = Path(rules._configuration["game_root"]) / "common/wargoal_types/00.txt"
    path.write_text(GOAL.replace("0.75", "0.5"), encoding="utf-8")
    second = rules.read("cb_test")
    assert first["value"]["attacker"]["warscore_multiplier"] == 0.75
    assert second["value"]["attacker"]["warscore_multiplier"] == 0.5
    assert second["value"]["attacker"]["province_conditions"] == [{"is_core": "ROOT"}]


def test_effective_mod_override_uses_existing_file_resolution(rules, tmp_path):
    mod = tmp_path / "mod"
    _file(mod, "common/wargoal_types/00.txt", GOAL.replace("0.75", "0.4"))
    descriptor = _file(tmp_path, "cost.mod", f'name="cost"\npath="{mod.as_posix()}"')
    selected = DeclarationCostRules(game_root=rules._configuration["game_root"],
                                    user_data=tmp_path / "user", enabled_mods=[descriptor])
    assert selected.read("cb_test")["value"]["attacker"]["warscore_multiplier"] == 0.4


@pytest.mark.parametrize("value", ["@factor", "yes"])
def test_uninterpreted_factor_preserves_other_literal_rules(rules, value):
    path = Path(rules._configuration["game_root"]) / "common/wargoal_types/00.txt"
    path.write_text(GOAL.replace("peace_cost_factor = 0.75", "peace_cost_factor = " + value), encoding="utf-8")
    result = rules.read("cb_test")
    assert result["status"] == "known" and result["complete"] is False
    assert result["value"]["attacker"]["warscore_multiplier"] is None
    assert result["value"]["attacker"]["aggressive_expansion_multiplier"] == 0.25


def test_unknown_cb_retains_unknown(rules):
    assert rules.read("cb_missing")["status"] == "unknown"


def test_other_terms_multiplier_and_tribal_condition_remain_separate(rules):
    path = Path(rules._configuration["game_root"]) / "common/wargoal_types/00.txt"
    path.write_text(GOAL.replace("badboy_factor = 0.25", """
        peace_cost_factor_non_allowed_treaty = 2
        allowed_tribal_provinces = { is_core = ROOT }
        badboy_factor = 0.25"""), encoding="utf-8")
    attacker = rules.read("cb_test")["value"]["attacker"]
    assert attacker["other_terms_warscore_multiplier"] == 2
    assert attacker["tribal_province_conditions"] == [{"is_core": "ROOT"}]
    assert attacker["warscore_multiplier"] == 0.75


def test_unparseable_cost_file_retains_unknown(rules):
    path = Path(rules._configuration["game_root"]) / "common/wargoal_types/00.txt"
    path.write_text(GOAL.replace("0.75", "-nan"), encoding="utf-8")
    assert rules.read("cb_test")["status"] == "unknown"


def test_cost_rules_reach_default_concise_query_and_full_readback(rules, tmp_path):
    class Backend:
        session = _LiveSession()
        journal = None

        def __init__(self):
            self.calls = 0

        def inspect_diplomatic_action(self, action, actor, recipient, phase, parameters):
            self.calls += 1
            return {"action_id": action, "actor": actor, "recipient": recipient,
                    "parameters": {"actual": deepcopy(parameters)}}

    backend = Backend()
    source = DiplomacySource(backend, declaration_rules=rules)
    with closing(InformationService(source, tmp_path / "information.sqlite3")) as service:
        api = InformationTools(service)
        result = api.call("information_query", {"request_id": "cb-cost-query", "queries": [{
            "topic": "D06", "object": {"type": "country_pair", "actor": "FRA", "recipient": "BUR"},
            "fields": ["cost_rules"], "parameters": {"selection": {"casus_belli": "cb_test",
                "war_goal": {"province_id": 88, "beneficiary": "FRA"}, "call_allies": []}},
        }]})
        assert backend.calls == 1
        value = result["items"][0]["cost_rules"]
        assert value["attacker"]["warscore_multiplier"] == 0.75
        assert "source" not in value and "basis" not in value
        full = api.call("information_get_result", {"result_id": result["result_id"], "view": "full"})
        assert full["items"][0]["fields"]["cost_rules"]["source"]["casus_belli"] == "cb_test"


def test_favor_rule_states_the_without_land_promise_condition(rules, tmp_path):
    _file(Path(rules._configuration["game_root"]), "common/defines.lua",
          "NDefines = { NDiplomacy = { CALL_TO_ARMS_COST = 10 } }")
    value = rules.favor_requirement()
    assert value["status"] == "known"
    assert value["value"] == {"without_land_promise": 10}
    source = DiplomacySource(_LiveTools(_LiveSession()), declaration_rules=rules)
    with closing(InformationService(source, tmp_path / "favor-information.sqlite3")) as service:
        result = InformationTools(service).call("information_query", {
            "request_id": "favor-rule-query", "queries": [{"topic": "D04",
                "object": {"type": "country_pair", "actor": "FRA", "recipient": "BUR"},
                "fields": ["favor_requirement"], "parameters": {}}]})
        assert result["items"][0]["favor_requirement"] == {"without_land_promise": 10}


def test_term_declarations_keep_conditions_without_inferring_other_legal_terms(rules):
    path = Path(rules._configuration["game_root"]) / "common/wargoal_types/00.txt"
    path.write_text(GOAL.replace("badboy_factor = 0.25", """
        required_treaty_to_take_provinces = po_independence
        deny_annex = yes
        badboy_factor = 0.25"""), encoding="utf-8")
    native = project_native_peace_options(peace_option_fixtures.DeclareWarPeaceOptionsTests._options())
    inspection = {"parameters": {"actual": {"casus_belli": "cb_test"}}, "peace_term_rules": native}
    result = declaration_allowed_terms(inspection, rules)
    attacker = result["value"]["attacker"]
    assert attacker["declared_justified"] == native["attacker_declared"]["declared_justified_actions"]
    assert attacker["allowed_provinces"] == [{"is_core": "ROOT"}]
    assert attacker["required_treaty_to_take_provinces"] == "po_independence"
    assert attacker["deny_annex"] is True
    assert "war_reparations" not in attacker["declared_justified"]
    assert result["target_legality_evaluated"] is False
    assert inspection["peace_term_rules"] == native


def test_native_declarations_survive_missing_configuration_conditions():
    native = project_native_peace_options(peace_option_fixtures.DeclareWarPeaceOptionsTests._options())
    result = declaration_allowed_terms({"peace_term_rules": native, "parameters": None})
    assert result["status"] == "known" and result["complete"] is False
    assert result["value"]["defender"]["declared_justified"] == ["war_reparations"]
