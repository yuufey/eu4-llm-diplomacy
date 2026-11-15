"""Read selected CB war-goal multipliers from the effective game files."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import math
from pathlib import Path
from threading import RLock

from .cwtools_script import CwtoolsScriptParser
from .peace_rule_defines import PeaceRuleIndex
from .peace_subject_rules import PeaceSubjectRules


_DIRECTORIES = ("common/cb_types", "common/wargoal_types")
_MULTIPLIERS = {
    "peace_cost_factor": "warscore_multiplier",
    "badboy_factor": "aggressive_expansion_multiplier",
    "prestige_factor": "prestige_multiplier",
}
_MAX_TOTAL_BYTES = 8 * 1024 * 1024
_TERM_CONDITIONS = (
    "allowed_provinces", "allowed_tribal_provinces", "allowed_countries",
    "required_treaty_to_take_provinces", "allowed_provinces_are_eligible",
    "allow_annex", "deny_annex",
)


def _child(node, key):
    matches = [child for child in node.children if child.key == key]
    return matches[-1] if matches else None


def _condition(node):
    if node.kind == "scalar":
        return node.value
    return [{child.key: _condition(child)} for child in node.children]


def _side_rules(node):
    values, gaps = {}, []
    for original, public in _MULTIPLIERS.items():
        entry = _child(node, original)
        value, error = PeaceSubjectRules._scalar(entry) if entry is not None else (None, "not declared")
        if error or type(value) not in (int, float) or not math.isfinite(value):
            values[public] = None
            gaps.append(original)
        else:
            values[public] = value
    other_terms = _child(node, "peace_cost_factor_non_allowed_treaty")
    if other_terms is not None:
        value, error = PeaceSubjectRules._scalar(other_terms)
        if error or type(value) not in (int, float) or not math.isfinite(value):
            value = None
            gaps.append("peace_cost_factor_non_allowed_treaty")
        values["other_terms_warscore_multiplier"] = value
    options = _child(node, "peace_options")
    values["applies_to"] = None
    if options is not None and options.kind == "block":
        terms = []
        for option in options.children:
            if option.kind == "bare" or option.value == "yes":
                terms.append(option.key)
            elif option.kind == "block":
                terms.append({option.key: _condition(option)})
            elif option.value != "no":
                gaps.append(option.key)
        values["applies_to"] = terms
    else:
        gaps.append("peace_options")
    provinces = _child(node, "allowed_provinces")
    if provinces is not None:
        values["province_conditions"] = _condition(provinces)
    tribal = _child(node, "allowed_tribal_provinces")
    if tribal is not None:
        values["tribal_province_conditions"] = _condition(tribal)
    return values, gaps


class DeclarationCostRules:
    """Cache syntax by effective input hash and project one selected CB."""

    def __init__(self, *, game_root=None, user_data=None, enabled_mods=None, parser=None):
        self._configuration = dict(game_root=game_root, user_data=user_data, enabled_mods=enabled_mods)
        self.parser = parser
        self._cache_key = None
        self._definitions = None
        self._lock = RLock()

    def _load(self, resolver):
        stack = resolver._stack
        errors = [*stack._state.errors, *stack._state.compatibility.errors]
        loaded, files, total = [], [], 0
        for directory in _DIRECTORIES:
            selected, failures = resolver._effective_files(
                directory_path=directory, suffix=".txt", root_path=None)
            errors.extend(failures)
            for item in selected:
                path = Path(item["path"]).resolve()
                raw = stack._read_bounded(path, stack.max_file_bytes)
                total += len(raw)
                if total > _MAX_TOTAL_BYTES:
                    raise ValueError("CB_RULE_INPUT_SIZE_LIMIT")
                files.append({"relative": item["relative"], "path": str(path),
                              "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
                loaded.append((directory, path))
        if errors:
            raise ValueError(errors[0]["code"])
        signature = tuple((item["path"], item["sha256"]) for item in files)
        if signature != self._cache_key:
            parser = self.parser or CwtoolsScriptParser()
            self.parser = parser
            parsed = parser.parse_files([path for _, path in loaded])
            definitions = {directory: {} for directory in _DIRECTORIES}
            for directory, path in loaded:
                document = parsed[str(path)]
                if "error" in document:
                    raise ValueError("CB_RULE_PARSE_FAILED")
                for node in document["nodes"]:
                    if node.kind != "block":
                        continue
                    # Ambiguous duplicate definitions retain an unknown value.
                    prior = definitions[directory]
                    prior[node.key] = None if node.key in prior else node
            self._definitions = definitions
            self._cache_key = signature
        return files

    def _selected_definition(self, casus_belli):
        resolver = PeaceRuleIndex(**self._configuration)
        files = self._load(resolver)
        cb = self._definitions["common/cb_types"].get(casus_belli)
        if cb is None:
            raise ValueError("CB_RULE_NOT_DECLARED_OR_AMBIGUOUS")
        goal = _child(cb, "war_goal")
        if goal is None or goal.kind != "scalar":
            raise ValueError("CB_WAR_GOAL_UNAVAILABLE")
        definition = self._definitions["common/wargoal_types"].get(goal.value)
        if definition is None:
            raise ValueError("CB_WAR_GOAL_NOT_DECLARED_OR_AMBIGUOUS")
        source = {"casus_belli": casus_belli, "war_goal": goal.value, "definition_files": files,
                  "configuration_files": deepcopy(resolver._stack._state.compatibility.configuration_files)}
        return definition, source

    def read(self, casus_belli):
        with self._lock:
            try:
                definition, source = self._selected_definition(casus_belli)
                values = {"casus_belli": casus_belli, "war_goal": source["war_goal"]}
                gaps = {}
                for side in ("attacker", "defender"):
                    entry = _child(definition, side)
                    if entry is None or entry.kind != "block":
                        values[side], gaps[side] = None, ["side_not_declared"]
                    else:
                        values[side], missing = _side_rules(entry)
                        if missing:
                            gaps[side] = missing
                return {"status": "known", "value": values, "complete": not gaps,
                        "partial": bool(gaps), "gaps": gaps,
                        "basis": "selected_cb_declared_multipliers",
                        "source": source}
            except (OSError, ValueError) as error:
                return {"status": "unknown", "reason": "CB_COST_RULES_UNAVAILABLE", "detail": str(error)}

    def term_conditions(self, casus_belli):
        with self._lock:
            try:
                definition, source = self._selected_definition(casus_belli)
                values = {}
                for side in ("attacker", "defender"):
                    entry = _child(definition, side)
                    values[side] = None if entry is None else {}
                    if entry is None:
                        continue
                    for key in _TERM_CONDITIONS:
                        condition = _child(entry, key)
                        if condition is not None:
                            value = _condition(condition)
                            if isinstance(value, str):
                                value = {"yes": True, "no": False}.get(value, value)
                            values[side][key] = value
                return {"status": "known", "value": values, "source": source}
            except (OSError, ValueError) as error:
                return {"status": "unknown", "reason": "CB_TERM_CONDITIONS_UNAVAILABLE", "detail": str(error)}

    def favor_requirement(self):
        configured = PeaceRuleIndex(**self._configuration, keys=("CALL_TO_ARMS_COST",)).read()
        value = configured["values"].get("CALL_TO_ARMS_COST")
        if type(value) not in (int, float) or value < 0:
            return {"status": "unknown", "reason": "CALL_TO_ARMS_COST_UNAVAILABLE",
                    "source": configured["source"], "gaps": configured["reasons"]}
        return {"status": "known", "value": {"without_land_promise": value},
                "unit": "favors", "scale": 1, "complete": True,
                "basis": "configured_call_to_arms_cost", "source": configured["source"]}


def declaration_allowed_terms(inspection, rules=None):
    """Expose native declarations and their configured conditions together."""
    native = inspection.get("peace_term_rules")
    if not isinstance(native, dict) or native.get("called") is not True:
        return {"status": "unknown", "reason": "CB_TERM_DECLARATIONS_UNAVAILABLE"}
    parameters = inspection.get("parameters")
    actual = parameters.get("actual") if isinstance(parameters, dict) else None
    cb = actual.get("casus_belli") if isinstance(actual, dict) else None
    configured = rules.term_conditions(cb) if rules is not None and isinstance(cb, str) else {}
    values, gaps = {}, []
    for side in ("attacker", "defender"):
        table = native.get(side + "_declared", {})
        declared = table.get("declared_justified_actions")
        values[side] = {"declared_justified": deepcopy(declared) if isinstance(declared, list) else None}
        conditions = configured.get("value", {}).get(side)
        if isinstance(conditions, dict):
            values[side].update(deepcopy(conditions))
        if (table.get("available") is not True or table.get("complete") is not True
                or table.get("unmapped") or not isinstance(declared, list)):
            gaps.append(side + "_declarations_incomplete")
    if configured.get("status") != "known":
        gaps.append("configured_conditions_unavailable")
    if all(row["declared_justified"] is None for row in values.values()):
        return {"status": "unknown", "reason": "CB_TERM_DECLARATIONS_UNAVAILABLE"}
    return {"status": "known", "value": values, "complete": not gaps,
            "partial": bool(gaps), "scope": "declared_cb_terms_and_conditions",
            "target_legality_evaluated": False, "gaps": gaps,
            "source": {"native_tables": deepcopy(native), "configuration": configured.get("source")}}


__all__ = ["DeclarationCostRules", "declaration_allowed_terms"]
