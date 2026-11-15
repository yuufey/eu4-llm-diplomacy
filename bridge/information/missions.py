"""Country mission membership, partial loaded conditions, and static rules.

State readers supply explicit loaded root IDs and completion records. Static
definitions supply the rules for those IDs. Supported loaded prerequisites
and trigger nodes are evaluated; unresolved nodes retain explicit unknowns.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from .catalog import get_topic
from .model import InformationError, digest
from .observation_time import dates_match
from .mission_definitions import MissionDefinitionError
from .mission_requirements import evaluate_prerequisites
from .native_localization import NativeLocalizationReader
from .dlc_short_circuit_bindings import SUPPORTED_DLC_NAMES

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
COUNTRY = re.compile(r"[A-Z0-9]{3}\Z")
FIELDS = {
    "M01": ("task_id", "name", "description", "branches"),
    "M02": ("prerequisites", "unlock_conditions", "completion_status", "currently_completable", "condition_progress"),
    "M03": ("provinces", "regions", "countries", "ownership", "control", "cores", "subjects"),
    "M04": ("rewards", "claims", "casus_belli", "trade_modifiers", "duration", "unlocks"),
}

_REWARD_RULE_FIELDS = frozenset({"claims", "casus_belli", "trade_modifiers", "duration", "unlocks"})
_TARGET_RULE_FIELDS = frozenset(FIELDS["M03"])


def known(value):
    return {"status": "known", "value": deepcopy(value)}


def gap(reason, status="unknown"):
    return {"status": status, "reason": reason}


def _project_target_rules(tasks, field, *, scope_index=None, prepared=None):
    try:
        from .mission_target_rules_v2 import project_target_rules
        result = project_target_rules(tasks, field, scope_index=scope_index, _prepared=prepared)
    except Exception as exc:
        return gap(getattr(exc, "code", "MISSION_TARGET_RULES_FAILED"), "unavailable")
    if isinstance(result, dict) and result.get("status") == "partial":
        result = dict(result, status="known")
    if not isinstance(result, dict) or result.get("status") not in {"known", "unknown", "unavailable"}:
        return gap("MISSION_TARGET_RULES_INVALID_RESULT", "unavailable")
    if result["status"] == "known":
        if not result.get("value") or result.get("complete") is not False:
            return gap("MISSION_TARGET_RULES_INVALID_RESULT", "unavailable")
    elif "value" in result:
        return gap("MISSION_TARGET_RULES_INVALID_RESULT", "unavailable")
    return deepcopy(result)


def _bound_scope_index(index, definitions, context):
    """Bind static namespaces to the same installation and ordered mod stack."""
    if index is None:
        return None, {"status": "unavailable", "reason": "MISSION_SCOPE_INDEX_NOT_CONFIGURED"}
    try:
        current = index.context()
        paths_match = all(definitions.get(key) is not None and current.get(key) is not None
                          and Path(definitions[key]).resolve() == Path(current[key]).resolve()
                          for key in ("game_root", "user_data"))

        def mods(value):
            rows = value.get("enabled_mods")
            if not isinstance(rows, list):
                raise ValueError("MOD_STACK_NOT_VERIFIED")
            return [(str(Path(row['descriptor']).resolve()) if row.get('descriptor') else None,
                     row.get('descriptor_sha256'),
                     str(Path(row['root']).resolve()) if row.get('root') else None)
                    for row in rows]

        matched = (paths_match and current.get("status") == "ready"
                   and current.get("game_version") == definitions.get("game_version") == context.get("game_version")
                   and mods(current) == mods(definitions))
        summary = {key: deepcopy(current.get(key)) for key in (
            "status", "complete", "game_version", "configuration_sha256", "definitions_sha256",
            "component_statuses", "script_parser", "reasons")}
        summary["configuration_binding_verified"] = matched
        if not matched:
            summary["reason"] = "MISSION_SCOPE_CONFIGURATION_NOT_BOUND"
        return index if matched else None, summary
    except Exception:
        return None, {"status": "unavailable", "reason": "MISSION_SCOPE_INDEX_UNAVAILABLE"}


def _project_reward_rules(tasks, field):
    """Call the narrow M04 rule projector without coupling import-time startup.

    The projector is deliberately a separate source-owned module.  Its public
    contract is ``project_reward_rules(tasks, field)`` returning a field
    envelope with ``status``, ``value`` (when known), and ``complete=False``.
    A missing or malformed projector is an explicit gap; it cannot make the
    existing raw ``rewards`` field disappear or affect other M04 fields.
    """
    try:
        if field == "duration":
            from .mission_reward_duration import project_reward_duration
            projector = lambda selected, _: project_reward_duration(selected)
        elif field == "unlocks":
            from .mission_reward_unlocks import project_reward_unlocks
            projector = lambda selected, _: project_reward_unlocks(selected)
        else:
            from .mission_reward_rules import project_reward_rules
            projector = project_reward_rules
    except (ImportError, AttributeError):
        return gap("MISSION_REWARD_RULES_UNAVAILABLE", "unavailable")
    try:
        envelope = projector(deepcopy(tasks), field)
    except Exception as exc:
        return gap(getattr(exc, "code", "MISSION_REWARD_RULES_FAILED"), "unavailable")
    if not isinstance(envelope, dict):
        return gap("MISSION_REWARD_RULES_INVALID_RESULT", "unavailable")
    envelope = deepcopy(envelope)
    # A partial projection is represented by a normal field result whose
    # complete flag is false.  Accept a helper's descriptive ``partial``
    # spelling at this boundary, but keep the public field contract used by
    # InformationService (known/unknown/... statuses).
    if envelope.get("status") == "partial":
        envelope["status"] = "known"
    if envelope.get("status") == "known":
        if "value" not in envelope or envelope.get("complete") is not False:
            return gap("MISSION_REWARD_RULES_INVALID_RESULT", "unavailable")
        return envelope
    if envelope.get("status") in {"unknown", "unavailable", "stale", "unsupported"}:
        if "value" in envelope:
            envelope.pop("value", None)
        if "reason" not in envelope:
            reasons = envelope.get("provenance", {}).get("unknown_reasons", {})
            if isinstance(reasons, dict) and reasons:
                envelope["reason"] = next(iter(reasons)) if len(reasons) == 1 else "MISSION_REWARD_RULES_UNKNOWN"
        return envelope
    return gap("MISSION_REWARD_RULES_INVALID_RESULT", "unavailable")


def _loaded_task_entries(state):
    """Validate explicit runtime membership; absence keeps saved/static semantics."""
    if "loaded_tasks" not in state:
        return None
    captured = state["loaded_tasks"]
    if not isinstance(captured, dict) or captured.get("status") != "known":
        return gap(captured.get("reason", "LOADED_TASKS_NOT_VERIFIED")
                   if isinstance(captured, dict) else "LOADED_TASKS_INVALID")
    roots = captured.get("roots")
    expected = {root for slot in state["mission_slots"] for root in slot["roots"]}
    if not isinstance(roots, list) or len(roots) > 8192:
        return gap("LOADED_TASKS_INVALID")
    by_root, entries = {}, []
    for root in roots:
        if not isinstance(root, dict):
            return gap("LOADED_TASKS_INVALID")
        name, ids = root.get("root_id"), root.get("task_ids")
        if (not isinstance(name, str) or name not in expected or not isinstance(ids, list)
                or len(ids) > 4096 or any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in ids)
                or len(set(ids)) != len(ids)):
            return gap("LOADED_TASKS_INVALID")
        if name in by_root:
            if ids != by_root[name]:
                return gap("LOADED_TASK_ROOT_CONFLICT")
            continue
        by_root[name] = ids
        entries.extend({"root_id": name, "task_id": value, "branch_visibility": "unknown"} for value in ids)
        if len(entries) > 4096:
            return gap("LOADED_TASKS_LIMIT_EXCEEDED")
    if set(by_root) != expected:
        return gap("LOADED_TASK_ROOTS_INCOMPLETE")
    return dict(known(entries), membership_source="captured_loaded_task_objects")


class MissionInformationSource:
    """Compose a country-scoped state reader with a mission definition index.

``reader(country)`` returns ``complete``, ``country``, ``mission_slots`` (a
list of ``slot``/``roots`` records), and ``completed_missions`` (``status``
and ``task_ids``). Its provenance must explicitly retain live vs saved mode.
The primary source remains responsible for the shared session context.
    """

    event_types = ()

    def __init__(self, base_source, definitions, reader, *, scheduling=True, scope_index=None):
        self.base_source = base_source
        self.definitions = definitions
        self.reader = reader
        self.scheduling = scheduling
        self.scope_index = scope_index

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        result = []
        for topic_id, fields in FIELDS.items():
            topic = get_topic(topic_id)
            topic.update(status="available", source="MissionInformationSource",
                         context_scope="country_scope", observer_roles=["country"],
                         object_types=["country"], triggers=["query", "periodic", "change"] if self.scheduling else ["query"],
                         supported_versions=["1.37.4"])
            topic["fields"] = {field: dict(deepcopy(topic["fields"][field]),
                                             coverage="partial", source="MissionInformationSource")
                               for field in fields}
            topic["parameters"] = {
                "type": "object", "properties": {
                    key: {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"}
                    for key in ("root_id", "task_id")}, "additionalProperties": False}
            if getattr(self.reader, "supported_countries", None):
                topic["supported_observers"] = list(self.reader.supported_countries)
            if topic_id == "M04":
                topic["fields"]["rewards"]["description"] = "当前根所定义的奖励规则；未求值，不证明奖励已执行"
                for field in _REWARD_RULE_FIELDS:
                    topic["fields"][field].update(
                        description=(
                            "当前已选任务定义中的字面效果规则；不求值运行时条件，"
                            "不证明奖励或后续效果已生效"
                        ),
                        coverage="partial",
                        declared_literal_effect_rules=True,
                        runtime_conditions_evaluated=False,
                        actual_reward_status="unknown",
                    )
                topic["fields"]["duration"].update(
                    description="已选任务奖励的显式期限参数及命令专属单位；生效、起始和实际到期未知",
                    period="static_rules", complete=False, units="per_term",
                    value_origin="declared_effect_timing_parameters",
                    runtime_conditions_evaluated=False, actual_expiry_evaluated=False,
                )
                topic["fields"]["unlocks"].update(
                    description="已选任务中显式解锁、完成任务与任务树重建的字面请求；实际解锁及条件满足状态未知",
                    period="static_rules", complete=False,
                    value_origin="declared_reward_unlock_requests",
                    actual_unlocks_evaluated=False, scope_targets_resolved=False,
                )
            if topic_id == "M03":
                for field in fields:
                    topic["fields"][field].update(
                        complete=False, period="static_rules", value_origin="mission_trigger_syntax",
                        description="已选任务trigger中的字面、静态作用域及符号条件引用；保留逻辑，不判断满足状态或完整目标集合",
                        projection_version=2,
                        reference_forms=["literal_reference", "scope_head_reference", "symbolic_condition_reference"],
                        runtime_conditions_evaluated=False, scope_targets_resolved=False,
                        full_target_set_resolved=False,
                    )
            if topic_id == "M01":
                topic["fields"]["task_id"]["description"] = "实时源读取加载根中的实际子任务ID；保存源对应当前静态定义，分支可见性未求值"
                for field in ("name", "description"):
                    topic["fields"][field].update(description="实际任务的原生缓存文字及限定单选项派生；其他动态文本保留未知",
                                                   supported_modes=["live"])
            if topic_id == "M02":
                topic['change_comparison'] = {
                    'basis': 'sampled_state_comparison_not_lossless_events',
                    'fields': ['completion_status', 'currently_completable', 'condition_progress'],
                    'requires_known_selected_conditions': True,
                    'unknown_samples_preserve_baseline': True,
                }
                topic["fields"]["prerequisites"].update(
                    description="实时源读取原生前置ID并按已解析定义指针核对完成记录；另列当前磁盘声明，条件树另见condition_progress",
                    loaded_native_lists_supported=True, task_trigger_evaluated=False,
                    canonical_prerequisite_lookup_supported=True,
                )
                topic['fields']['currently_completable'].update(
                    description='原生资格的已完成/前置检查与已支持的加载条件树求值；其他条件保持未知',
                    complete=False,period='current',supported_modes=['live'],task_trigger_evaluated=False,
                    branch_visibility_evaluated=False,known_true_supported=True,
                    known_true_scope='fully_known_supported_native_trigger_trees_only',partial_trigger_evaluation_supported=True)
                topic['fields']['condition_progress'].update(
                    description='已加载条件树的逐项真/假/未知，支持部分DLC、条件分支和国家/省份作用域；不提供完整进度百分比',
                    complete=False,period='current',supported_modes=['live'],full_condition_progress=False,
                    supported_scopes=['root_country','literal_province','literal_country','loaded_geographic_set',
                                      'emperor_country','current_country_capital'],
                    supported_geographic_quantifiers=['all','any'],
                    supported_counted_province_conditions=[
                        'num_of_owned_provinces_with',
                        'num_of_provinces_owned_or_owned_by_non_sovereign_subjects_with'],
                    counted_province_domain_limit=256, counted_province_sample_limit=4,
                    counted_province_results='lower_and_upper_bounds; unknown_and_unsampled_members_remain_possible',
                    counted_province_filter='single_unbound_template; not_recounted_in_leaf_summary',
                    counted_province_fully_evaluated='all_members_attempted_or_filter_universally_known; does_not_imply_all_member_results_known',
                    supported_stored_condition_values=['stored_boolean'],
                    supported_boolean_condition_wrappers=['boolean_match'],
                    node_metadata_sampling='shared_per_outer_snapshot_not_atomic',
                    supported_global_conditions=['has_dlc'],
                    supported_dlc_names=list(SUPPORTED_DLC_NAMES),
                    dlc_evaluation='positive_short_circuit_only',
                    province_state_target_limit=128, area_member_limit=64,
                    province_input_sampling='shared_common_inputs_per_inner_pass; province_specific_fields_per_target_pass',
                    foreign_private_country_conditions_evaluated=False,
                    supported_conditional_branches=['if','else_if','else'],
                    supported_country_conditions=['army_size_percentage','religious_unity','has_country_modifier'],
                    supported_province_conditions=['owned_by','controlled_by','country_or_non_sovereign_subject_holds',
                                                   'province_id_matches'],
                    supported_province_country_arguments={
                        'owned_by':['ROOT'], 'controlled_by':['ROOT'],
                        'country_or_non_sovereign_subject_holds':['ROOT','literal_country']},
                    supported_scalar_conditions=['num_of_galley','num_of_explorers','sailors_percentage'],
                    unknown_predicates_preserved=True,branch_visibility_evaluated=False)
            result.append(topic)
        return result

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get("topic") not in FIELDS:
            raise InformationError("unknown_topic", "Mission source supports M01, M02, M03 and M04")
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "country"}
                or obj["type"] != "country" or not isinstance(obj["country"], str)
                or not COUNTRY.fullmatch(obj["country"])):
            raise InformationError("invalid_object", "Mission queries require an explicit country")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or len(set(fields)) != len(fields)
                or any(field not in FIELDS[query["topic"]] for field in fields)):
            raise InformationError("invalid_fields", "Unsupported mission fields")
        params = query.get("parameters", {})
        if (not isinstance(params, dict) or set(params)-{"root_id", "task_id"}
                or any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in params.values())):
            raise InformationError("invalid_parameters", "Invalid mission root/task selector")
        if context and context.get("observer") != obj["country"]:
            raise InformationError("observer_scope_mismatch", "Mission state belongs to another country")
        return dict(deepcopy(query), parameters=deepcopy(params))

    def _state(self, country, context):
        state = self.reader(country)
        if not isinstance(state, dict) or state.get("country") != country:
            raise InformationError("mission_identity_mismatch", "Mission reader country mismatch")
        if state.get("complete") is not True:
            raise InformationError("mission_snapshot_incomplete", "Mission snapshot is incomplete")
        slots = state.get("mission_slots")
        if (not isinstance(slots, list) or len(slots) > 64
                or any(not isinstance(slot, dict) or type(slot.get("slot")) is not int
                       or not isinstance(slot.get("roots"), list) or len(slot["roots"]) > 128
                       or any(not isinstance(root, str) or not IDENTIFIER.fullmatch(root) for root in slot["roots"])
                       for slot in slots)):
            raise InformationError("mission_snapshot_invalid", "Malformed mission slot records")
        if state.get("mode") != context.get("mode"):
            raise InformationError("mission_mode_mismatch", "Mission state and session modes differ")
        if state.get("mode") == "live":
            if (state.get("session_id") != context.get("session_id")
                    or not dates_match(context.get("game_date"), state.get("game_date"))):
                raise InformationError("mission_context_changed", "Mission snapshot belongs to another context")
        return state

    def _localized_fields(self, country, context, entries, requested):
        fields = {}
        method = getattr(self.reader, "localized_text", None)
        if not callable(method):
            return {field: gap("NATIVE_LOCALIZATION_READER_UNAVAILABLE", "unavailable") for field in requested}, None
        keys = list(dict.fromkeys(entry["task_id"]+("_title" if field == "name" else "_desc")
                    for field in requested for entry in entries))
        try:
            localized = method(country, context, keys) if keys else {"status":"known", "entries":{}, "language":None, "provenance":{}}
            if (not isinstance(localized, dict) or localized.get("status") != "known"
                    or not isinstance(localized.get("entries"), dict) or set(localized["entries"]) != set(keys)):
                raise InformationError("localization_snapshot_incomplete", "Localization reader did not return the requested keys")
            for field in requested:
                values = []
                for entry in entries:
                    key = entry["task_id"]+("_title" if field == "name" else "_desc")
                    text = deepcopy(localized["entries"][key])
                    if (not isinstance(text, dict) or text.get("status") not in {"known","unknown","unavailable"}
                            or (text["status"] == "known" and not isinstance(text.get("text"), str))
                            or (text["status"] != "known" and "text" in text)):
                        raise InformationError("localization_snapshot_invalid", "Malformed localized task value")
                    values.append(dict(text, root_id=entry["root_id"], task_id=entry["task_id"], localization_key=key))
                resolved = sum(entry["status"] == "known" for entry in values)
                complete = resolved == len(values)
                fields[field] = dict(known({"entries":values, "language":localized.get("language"),
                    "resolved_count":resolved, "unresolved_count":len(values)-resolved, "resolution_complete":complete,
                    "custom_derived_count":sum(isinstance(value.get("custom_text_derivation"), dict) for value in values),
                    "text_format":"native_cached_localization", "dynamic_substitution_evaluated":False}), complete=complete)
            return fields, deepcopy(localized.get("provenance", {}))
        except Exception as exc:
            return {field:gap(getattr(exc,"code","localization_read_failed"),"unavailable") for field in requested}, None

    def read(self, query, context=None):
        context = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, context)
        country = query["object"]["country"]
        result = {"topic": query["topic"], "fields": {}, "complete": False,
                  "game_date": context.get("game_date"), "objects": [deepcopy(query["object"])],
                  "source": {"name": "MissionInformationSource", "mode": context.get("mode"),
                             "session_id": context.get("session_id"), "observer": country,
                             "complete": False, "status": "unavailable"}}
        try:
            if context.get("status") != "ready":
                raise InformationError("source_unavailable", "Mission session is not ready")
            state = self._state(country, context)
        except Exception as exc:
            result["fields"] = {field: gap(getattr(exc, "code", "mission_read_failed"), "unavailable")
                                for field in query["fields"]}
            return result
        slots = deepcopy(state["mission_slots"])
        root_ids = [root for slot in slots for root in slot["roots"]]
        captured_tasks = _loaded_task_entries(state)
        requested_root = query["parameters"].get("root_id")
        if requested_root is not None:
            if requested_root not in root_ids:
                result["fields"] = {field: gap("ROOT_NOT_IN_CAPTURED_MISSION_SLOTS") for field in query["fields"]}
                return result
            root_ids = [requested_root]
            slots = [dict(slot, roots=[root for root in slot["roots"] if root == requested_root])
                     for slot in slots if requested_root in slot["roots"]]
        source = result["source"]
        source.update(status="observed", provenance={"state": deepcopy(state.get("provenance", {})),
                      "state_kind": state.get("state_kind"),
                      "rule_semantics": "definitions_unevaluated_except_literal_prerequisite_completion"})
        if captured_tasks is not None:
            source["provenance"]["task_membership_source"] = "captured_loaded_task_objects"
            source["provenance"]["task_membership_status"] = captured_tasks["status"]
        else:
            source["provenance"]["task_membership_source"] = "current_definitions_for_captured_roots"
        definitions_context = self.definitions.context()
        source["provenance"]["definitions"] = {key: deepcopy(definitions_context.get(key))
            for key in ("status", "game_version", "configuration_sha256", "definitions_sha256", "reasons", "script_parser")}
        source["provenance"]["selector"] = deepcopy(query.get("parameters", {}))
        source["provenance"]["observer_scope"] = {
            "type": "country", "country": country, "context_observer": context.get("observer"),
            "game_version": context.get("game_version"), "mode": context.get("mode"),
        }
        source["provenance"]["reward_rule_projection"] = {
            "selected_captured_roots_only": True,
            "task_membership_source": source["provenance"]["task_membership_source"],
            "loaded_task_membership_verified": (
                captured_tasks is not None and captured_tasks["status"] == "known"
            ),
            "definition_rules_previously_loaded_verified": False,
            "declared_literal_effect_rules": True,
            "runtime_conditions_evaluated": False,
            "actual_reward_status": "unknown",
        }
        if query["topic"] == "M03":
            source["provenance"]["target_rule_projection"] = {
                "selected_captured_roots_only": True,
                "task_membership_source": source["provenance"]["task_membership_source"],
                "loaded_task_membership_verified": captured_tasks is not None and captured_tasks["status"] == "known",
                "definition_rules_previously_loaded_verified": False,
                "declared_literal_trigger_references": True,
                "runtime_conditions_evaluated": False, "scope_targets_resolved": False,
                "full_target_set_resolved": False,
            }
        definition_ready = (definitions_context.get("status") == "ready"
                            and definitions_context.get("game_version") == context.get("game_version"))
        roots, missing = [], []
        if definition_ready:
            unique_roots = list(dict.fromkeys(root_ids))
            try:
                roots = self.definitions.roots(unique_roots)
            except (KeyError, InformationError, MissionDefinitionError):
                for root_id in unique_roots:
                    try:
                        roots.append(self.definitions.root(root_id))
                    except (KeyError, InformationError, MissionDefinitionError):
                        missing.append(root_id)
        source["provenance"]["used_root_definitions"] = [
            {"root_id": root["root_id"], "source": deepcopy(root.get("source"))} for root in roots]
        tasks = [dict(deepcopy(task), root_id=root["root_id"]) for root in roots for task in root["tasks"]]
        loaded_entries = []
        missing_task_definitions = []
        if captured_tasks is not None and captured_tasks["status"] == "known":
            loaded_entries = [entry for entry in captured_tasks["value"] if entry["root_id"] in root_ids]
            loaded_pairs = {(entry["root_id"], entry["task_id"]) for entry in loaded_entries}
            defined_pairs = {(task["root_id"], task["task_id"]) for task in tasks}
            missing_task_definitions = sorted(loaded_pairs - defined_pairs)
            source["provenance"]["task_definition_comparison"] = {
                "loaded_without_current_definition": [dict(root_id=root, task_id=task) for root, task in missing_task_definitions],
                "current_definition_not_loaded": [dict(root_id=root, task_id=task) for root, task in sorted(defined_pairs-loaded_pairs)],
                "matching_rules_previously_loaded_not_proven": True}
            tasks = [task for task in tasks if (task["root_id"], task["task_id"]) in loaded_pairs]
        requested_task = query["parameters"].get("task_id")
        if requested_task is not None:
            tasks = [task for task in tasks if task["task_id"] == requested_task]
            loaded_entries = [entry for entry in loaded_entries if entry["task_id"] == requested_task]
            missing_task_definitions = [(root, task) for root, task in missing_task_definitions if task == requested_task]
            related_roots = ({entry["root_id"] for entry in loaded_entries}
                             if captured_tasks is not None and captured_tasks["status"] == "known"
                             else {task["root_id"] for task in tasks})
            roots = [root for root in roots if root["root_id"] in related_roots]
            slots = [dict(slot, roots=[root for root in slot["roots"] if root in related_roots])
                     for slot in slots if any(root in related_roots for root in slot["roots"])]
        rules_ready = (definition_ready and not missing and not missing_task_definitions
                       and (requested_task is None or bool(tasks)))
        rule_gap = ("MISSION_DEFINITIONS_UNAVAILABLE" if not definition_ready else
                    "LOADED_ROOT_DEFINITION_MISSING" if missing else
                    "LOADED_TASK_DEFINITION_MISSING" if missing_task_definitions else "TASK_NOT_IN_CAPTURED_MISSION_ROOTS")
        selector_gap = None
        if requested_task is not None:
            if captured_tasks is None:
                selector_gap = rule_gap if not rules_ready else None
            elif captured_tasks["status"] != "known":
                selector_gap = captured_tasks["reason"]
            elif not loaded_entries:
                selector_gap = "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
        text_fields = [field for field in query["fields"] if field in {"name", "description"}]
        localized_fields = {}
        if text_fields and not selector_gap:
            if captured_tasks is None or captured_tasks["status"] != "known":
                localized_fields = {field:gap("LOADED_TASK_MEMBERSHIP_REQUIRED_FOR_LOCALIZATION") for field in text_fields}
            else:
                localized_fields, provenance = self._localized_fields(country, context, loaded_entries, text_fields)
                if provenance is not None:
                    source["provenance"]["localization"] = provenance
        target_prepared, bound_scope_index, scope_before = None, None, None
        if query["topic"] == "M03":
            source["projection_version"] = 2
            bound_scope_index, scope_before = _bound_scope_index(self.scope_index, definitions_context, context)
            source["provenance"]["scope_definitions"] = scope_before
            source["provenance"]["target_rule_projection"].update(
                symbolic_condition_references_recorded=True,
                static_scope_definitions_are_not_current_targets=True,
            )
            if rules_ready and tasks:
                try:
                    from .mission_target_rules_v2 import prepare_scope_projection
                    target_prepared = prepare_scope_projection(tasks, bound_scope_index)
                except Exception:
                    pass  # The per-field boundary below reports the concrete gap.
        fields = result["fields"]
        from .mission_loaded_prerequisites import project_prerequisites
        native_prerequisites = project_prerequisites(
            state, loaded_entries if captured_tasks is not None and captured_tasks['status'] == 'known' else None,
            tasks, context.get('game_version')) if 'prerequisites' in query['fields'] else None
        for field in query["fields"]:
            if selector_gap:
                fields[field] = gap(selector_gap, "unavailable" if not definition_ready and captured_tasks is None else "unknown")
            elif field == "branches":
                fields[field] = known({"state_kind": state.get("state_kind"), "slots": slots})
            elif field == "completion_status":
                completed = state.get("completed_missions", {})
                values = completed.get("task_ids")
                if (completed.get("status") == "known" and isinstance(values, list)
                        and all(isinstance(value, str) and IDENTIFIER.fullmatch(value) for value in values)):
                    fields[field] = known({"completed_task_ids": values,
                        "scope": "captured_country_completion_records",
                        "selected_task": ({"task_id": requested_task, "completed": requested_task in values}
                                          if requested_task else None)})
                else:
                    fields[field] = gap(completed.get("reason", "COMPLETION_RECORDS_UNAVAILABLE"))
            elif field == "task_id" and captured_tasks is not None:
                fields[field] = (dict(known(loaded_entries), membership_source="captured_loaded_task_objects")
                                 if captured_tasks["status"] == "known" else deepcopy(captured_tasks))
            elif field in {"name", "description"}:
                fields[field] = localized_fields[field]
            elif field == 'prerequisites' and native_prerequisites is not None:
                fields[field] = native_prerequisites
            elif field == 'currently_completable':
                from .mission_condition_source import project_eligibility
                fields[field] = project_eligibility(
                    state,loaded_entries if captured_tasks is not None and captured_tasks['status']=='known' else None,
                    context.get('game_version'))
            elif field == 'condition_progress':
                from .mission_trigger_source import project_progress
                fields[field]=project_progress(
                    state,loaded_entries if captured_tasks is not None and captured_tasks['status']=='known' else None,
                    context.get('game_version'))
            elif not rules_ready:
                fields[field] = gap(rule_gap, "unavailable" if not definition_ready else "unknown")
            elif query["topic"] == "M03" and field in _TARGET_RULE_FIELDS:
                if captured_tasks is not None and captured_tasks["status"] != "known":
                    fields[field] = gap(captured_tasks.get("reason", "LOADED_TASKS_NOT_VERIFIED"))
                elif not tasks:
                    fields[field] = gap("NO_SELECTED_MISSION_TASKS")
                else:
                    fields[field] = _project_target_rules(tasks, field, scope_index=bound_scope_index,
                                                         prepared=target_prepared)
            elif field in _REWARD_RULE_FIELDS:
                if captured_tasks is not None and captured_tasks["status"] != "known":
                    fields[field] = gap(captured_tasks.get("reason", "LOADED_TASKS_NOT_VERIFIED"))
                elif not tasks:
                    # A valid root selector can still select no currently
                    # loaded task definitions.  Do not call the projector
                    # with an empty set and do not manufacture an empty rule.
                    fields[field] = gap("NO_SELECTED_MISSION_TASKS")
                else:
                    fields[field] = _project_reward_rules(tasks, field)
            elif field == "task_id":
                fields[field] = known([{"root_id": task["root_id"], "task_id": task["task_id"],
                                        "branch_visibility": "unknown"} for task in tasks])
            elif field == "prerequisites":
                entries = []
                for task in tasks:
                    evaluation = evaluate_prerequisites(task.get("required_missions"),
                        state.get("completed_missions"), game_version=context.get("game_version"))
                    entries.append({"root_id": task["root_id"], "task_id": task["task_id"],
                                    "declared_rules": deepcopy(task.get("required_missions")),
                                    "evaluated": evaluation["status"] == "known", "evaluation": evaluation})
                fields[field] = known(entries)
            elif field == "unlock_conditions":
                fields[field] = known({"evaluated": False, "roots": [
                    {"root_id": root["root_id"], "potential": deepcopy(root.get("potential")),
                     "potential_on_load": deepcopy(root.get("potential_on_load"))} for root in roots],
                    "task_prerequisites": [{"root_id": task["root_id"], "task_id": task["task_id"],
                                            "required_missions": deepcopy(task.get("required_missions"))}
                                           for task in tasks]})
                branch_reader = getattr(self.reader, "branch_inputs", None)
                inputs = gap("BRANCH_INPUT_READER_UNAVAILABLE")
                if callable(branch_reader):
                    try:
                        inputs = branch_reader(country, context)
                    except Exception as exc:
                        inputs = gap(getattr(exc, "code", "branch_input_read_failed"), "unavailable")
                fields[field]["value"]["captured_inputs"] = inputs
            elif field == "rewards":
                fields[field] = known({"evaluated": False, "applied": "unknown", "tasks": [
                    {"root_id": task["root_id"], "task_id": task["task_id"], "effect": deepcopy(task.get("effect"))}
                    for task in tasks]})
        if missing:
            source["provenance"]["unresolved_root_ids"] = missing
        if query["topic"] == "M03" and bound_scope_index is not None:
            _, scope_after = _bound_scope_index(bound_scope_index, definitions_context, context)
            source["provenance"]["scope_definitions_after"] = scope_after
            if scope_after != scope_before:
                # Re-project the already captured task rules without the changed
                # map snapshot. Existing literal evidence can survive separately.
                for field in fields:
                    if fields[field].get("status") == "known":
                        fields[field] = _project_target_rules(tasks, field)
                source["provenance"]["static_scope_extensions_withdrawn"] = "MISSION_SCOPE_INPUT_CHANGED_DURING_COLLECTION"
        after = self.definitions.context()
        source["provenance"]["definitions_after"] = {
            key: deepcopy(after.get(key))
            for key in ("status", "game_version", "configuration_sha256", "definitions_sha256", "reasons", "script_parser")
        }
        if (definition_ready and (after.get("status") != "ready"
                or any(after.get(key) != definitions_context.get(key)
                       for key in ("game_version", "configuration_sha256", "definitions_sha256")))):
            for field in fields:
                uses_runtime_membership = (field in {"task_id", "name", "description"} and captured_tasks is not None
                                           and captured_tasks["status"] == "known")
                if field not in {"branches", "completion_status"} and not uses_runtime_membership and fields[field]["status"] == "known":
                    fields[field] = gap("MISSION_DEFINITIONS_CHANGED_DURING_COLLECTION", "stale")
        result["complete"] = all(value["status"] == "known" and value.get("complete",True) is True for value in fields.values())
        source["complete"] = result["complete"]
        return result

    def change_comparison(self, query, sample, context):
        """Compare known selected native conditions while retaining partial visibility."""
        try:
            normalized = self.validate_query(query, context)
            supported = {'completion_status', 'currently_completable', 'condition_progress'}
            if (normalized['topic'] != 'M02' or not set(normalized['fields']) <= supported
                    or context.get('status') != 'ready' or context.get('mode') != 'live'
                    or context.get('game_version') != '1.37.4'):
                return None
            fields = sample.get('fields', {})
            source = sample.get('source', {})
            if (sample.get('topic') != 'M02' or sample.get('complete') is not False
                    or sample.get('objects') != [normalized['object']]
                    or set(fields) != set(normalized['fields'])
                    or not dates_match(sample.get('game_date'), context.get('game_date'))
                    or source.get('name') != 'MissionInformationSource'
                    or source.get('status') != 'observed' or source.get('mode') != 'live'
                    or source.get('session_id') != context.get('session_id')
                    or source.get('observer') != context.get('observer')
                    or any(field.get('status') != 'known' for field in fields.values())):
                return None
            provenance = source.get('provenance', {})
            if (provenance.get('task_membership_source') != 'captured_loaded_task_objects'
                    or provenance.get('task_membership_status') != 'known'
                    or provenance.get('selector') != normalized['parameters']
                    or not isinstance(provenance.get('definitions'), dict)
                    or provenance.get('definitions') != provenance.get('definitions_after')):
                return None
            task_pairs = None
            for name in ('condition_progress', 'currently_completable'):
                if name not in fields:
                    continue
                field = fields[name]
                value = field.get('value', {})
                unknown_key = 'unknown_leaf_count' if name == 'condition_progress' else 'unknown_count'
                origins = ({'loaded_native_trigger_tree_partial'} if name == 'condition_progress' else
                           {'derived_native_eligibility_with_partial_trigger_tree',
                            'derived_native_eligibility_short_circuit'})
                rows = value.get('tasks')
                if (field.get('complete') is not False or field.get('native_function_called') is not False
                        or field.get('value_origin') not in origins
                        or type(value.get(unknown_key)) is not int or value[unknown_key] != 0
                        or not isinstance(rows, list) or not rows or len(rows) > 4096
                        or type(value.get('task_count')) is not int or value['task_count'] != len(rows)):
                    return None
                pairs = []
                for row in rows:
                    pair = (row.get('root_id'), row.get('task_id'))
                    if any(not isinstance(key, str) or not IDENTIFIER.fullmatch(key) for key in pair):
                        return None
                    if name == 'condition_progress':
                        checks = row.get('checks', {})
                        evaluation = row.get('trigger', {}).get('evaluation', {})
                        if (any(type(checks.get(key)) is not bool for key in
                                ('already_completed', 'prerequisites_satisfied'))
                                or evaluation.get('status') != 'known'
                                or type(evaluation.get('satisfied')) is not bool):
                            return None
                    elif row.get('status') != 'known' or type(row.get('currently_completable')) is not bool:
                        return None
                    pairs.append(pair)
                pairs = sorted(pairs)
                if len(set(pairs)) != len(pairs) or (task_pairs is not None and pairs != task_pairs):
                    return None
                task_pairs = pairs
            if task_pairs is None:
                return None
            scope = digest({'query': normalized, 'tasks': task_pairs,
                            'session_id': context.get('session_id'), 'world_id': context.get('world_id'),
                            'game_sha256': context.get('game_sha256'), 'dll_sha256': context.get('dll_sha256'),
                            'definitions': provenance.get('definitions')})
            return {'schema': 'information.change_comparison.v1',
                    'scope': 'M02.known_native_conditions.' + scope, 'fields': deepcopy(fields)}
        except (InformationError, AttributeError, KeyError, TypeError, ValueError):
            return None

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class SavedMissionContextSource:
    """Explicit saved-file context, without a fabricated game session ID.

The snapshot has no reliable game-session clock or world generation. It is
queryable, while scheduling remains disabled for this archived state source.
    """

    event_types = ()

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def context(self):
        raw = self.snapshot.context()
        version = raw.get("version")
        version = ".".join(version.split(".")[:3]) if isinstance(version, str) else None
        return {"mode": "recorded", "status": "ready" if raw.get("complete") and version == "1.37.4" else "unready",
                "complete": bool(raw.get("complete")) and version == "1.37.4", "observer": raw.get("country"),
                "game_version": version, "game_date": raw.get("game_date"), "game_day": None,
                "game_date_kind": "saved_calendar_date", "session_id": None, "world_id": None,
                "game_sha256": None, "dll_sha256": None, "paused": None,
                "archive": {key: deepcopy(raw.get(key)) for key in ("sha256", "size_bytes", "mtime_ns", "player", "dlc_enabled")}}

    def catalog(self):
        from .catalog import list_topics
        topics = list_topics()
        for topic in topics:
            topic["triggers"] = ["query"]
            if topic["topic_id"] == "C01":
                topic["source"] = "SavedMissionSnapshot"
                for name, field in topic["fields"].items():
                    field["source"] = "SavedMissionSnapshot"
                    field["coverage"] = ("available" if name in {"observer", "game_date", "game_version", "status"}
                                         else "planned")
            else:
                topic["status"] = "planned"
                for field in topic["fields"].values():
                    field["coverage"] = "planned"
        return topics

    def read(self, query, context):
        from .sources import _field_result, _result, _source_info
        fields, complete = _field_result(query["fields"], context, get_topic(query["topic"]),
                                         unsupported=query["topic"] != "C01")
        return _result(query, context, fields, complete, _source_info("SavedMissionSnapshot", context))

    def capture(self, country):
        data = self.snapshot.as_dict()
        if data["country"] != country:
            raise InformationError("observer_scope_mismatch", "Save snapshot belongs to another country")
        saved = data["country_missions"]
        completed = data["completed_missions"]
        return {"complete": saved["present"], "country": country, "mode": "recorded",
                "game_date": data["date"], "session_id": None, "state_kind": "saved_country_mission_slots",
                "mission_slots": [{"slot": slot["index"], "roots": slot["root_ids"]} for slot in saved["mission_slots"]],
                "completed_missions": ({"status": "known", "task_ids": completed["values"]} if completed["present"]
                    else {"status": "unknown", "reason": "COMPLETION_FIELD_ABSENT_IN_SAVE"}),
                "provenance": {"file_sha256": data["file"]["sha256"], "file_bytes": data["file"]["size_bytes"],
                               "save_date": data["date"], "save_version": data["version"],
                               "target_block": data["target_block"], "completed_field_present": completed["present"]}}

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class NativeMissionReader:
    """Normalize a version-bound, double-pass RPM capture for one observer."""

    supported_countries = ("FRA",)

    def __init__(self, base_source, capture=None, *, localization_capture=None,
                 custom_localization_capture=None, localization_reader=None):
        self.base_source = base_source
        self.capture = capture
        self.supports_trigger_selection = capture is None
        self.localization_capture = localization_capture
        self.custom_localization_capture = custom_localization_capture
        self.localization_reader = (
            localization_reader
            if localization_reader is not None
            else NativeLocalizationReader(base_source, capture=localization_capture)
        )

    def __call__(self, country, *, trigger_selector=None):
        base_context = self.base_source.context()
        if country not in self.supported_countries or base_context.get("observer") != country:
            raise InformationError("observer_scope_mismatch", "Native mission reader supports the bound FRA observer")
        session = getattr(self.base_source, "session", None)
        if session is None or base_context.get("status") != "ready":
            raise InformationError("source_unavailable", "No ready native mission session")
        capture = self.capture
        if capture is None:
            from .mission_memory import capture
            selection_options = {} if trigger_selector is None else {'trigger_selector': trigger_selector}
            report = capture(session.directory / "installation.json", country, include_completed=True,
                             include_tasks=True, include_prerequisites=True, include_conditions=True,
                             include_triggers=True, **selection_options)
        else:
            report = capture(session.directory / "installation.json", country, include_completed=True, include_tasks=True)
        state = self.normalize(report, base_context)
        state.setdefault("loaded_tasks", gap("LOADED_TASKS_NOT_CAPTURED"))
        return state

    def branch_inputs(self, country, context):
        if country not in self.supported_countries or context.get("observer") != country:
            raise InformationError("observer_scope_mismatch", "Branch input reader supports the bound FRA observer")
        session = getattr(self.base_source, "session", None)
        if session is None or context.get("status") != "ready":
            raise InformationError("source_unavailable", "No ready native branch input session")
        from .mission_branch_memory import capture_inputs
        report = capture_inputs(session.directory / "installation.json", country)
        return self.normalize_branch_inputs(report, context)

    def localized_text(self, country, context, keys):
        """Read requested cache keys with the session's explicit native codec.

        Each bounded batch is independently identity/date guarded. The task
        membership and localization reads are not an atomic game snapshot.
        """
        if country not in self.supported_countries or context.get("observer") != country:
            raise InformationError("observer_scope_mismatch", "Localization reader supports the bound FRA observer")
        session = getattr(self.base_source, "session", None)
        if session is None or context.get("status") != "ready" or context.get("mode") != "live":
            raise InformationError("source_unavailable", "No ready native localization session")
        if isinstance(self.localization_reader, NativeLocalizationReader):
            # Keep the mission reader's historical order: literal cache,
            # optional Root-text derivation, then the final context check.
            literal = self.localization_reader._localized_text(
                country, context, keys, verify_context=False,
            )
        else:
            literal = self.localization_reader.localized_text(country, context, keys)
        values = literal["entries"]
        language = literal["language"]
        provenance = deepcopy(literal.get("provenance", {}))
        batches = provenance.get("batches", [])
        codec = provenance.get("codec")
        if codec is None:
            from bridge.native_text import validate_native_text_codec
            record = getattr(session, "record", {})
            try:
                codec = validate_native_text_codec(record.get("native_text_codec"))
            except ValueError as exc:
                raise InformationError(
                    "localization_codec_unconfigured",
                    "Native localization requires an explicit session codec",
                ) from exc
        cache_capture = self.localization_capture
        if cache_capture is None:
            cache_capture = getattr(self.localization_reader, "capture", None)
        if cache_capture is None:
            from .localization_memory import capture as cache_capture
        values, custom_provenance = self._resolve_custom_templates(
            session, country, context, values, language, codec, cache_capture, batches)
        # Health may have changed after a cache batch; never attach old text
        # to a different date, process session, executable or observer.
        refreshed = self.base_source.context()
        if any(refreshed.get(key) != context.get(key) for key in
               ("status", "mode", "session_id", "game_sha256", "observer", "game_date")):
            raise InformationError("localization_context_changed", "Localization context changed during capture")
        provenance["custom_text_resolution"] = custom_provenance
        return {"status": literal.get("status", "known"), "entries":values, "language":language,
                "provenance":provenance}

    def _resolve_custom_templates(self, session, country, context, values, language, codec, cache_capture, batches):
        """Derive one registered singleton placeholder for query Root.

        The method container and literal key cache are independent bounded
        snapshots. A failure here leaves the original literal values intact.
        """
        from .mission_custom_texts import match_single_template
        targets = {}
        for key, entry in values.items():
            matched = match_single_template(entry)
            if matched is not None:
                targets[key] = matched["method"]
        if not targets:
            return values, {"status":"not_requested", "derived_count":0}
        names = list(dict.fromkeys(targets.values()))
        try:
            from .mission_custom_texts import normalize_methods, apply_single_template
            capture = self.custom_localization_capture
            if capture is None:
                from .custom_localization_memory import capture
            report = capture(session.directory / "installation.json", country, names)
            normalized = normalize_methods(report, context, names)
            methods = normalized["methods"]
            text_keys = list(dict.fromkeys(methods[name]["text_key"] for name in names
                                          if methods[name].get("status") == "known"))
            selected_entries = {}
            if text_keys:
                cache = self.normalize_localization(
                    cache_capture(session.directory / "installation.json", country, text_keys), context, text_keys, codec)
                if cache["language"] != language:
                    raise InformationError("custom_localization_language_changed", "Custom text cache uses another language")
                selected_entries = cache["entries"]
                batches.append(dict(cache["provenance"], purpose="custom_selected_text_keys"))
            result = deepcopy(values)
            for key,name in targets.items():
                method = methods[name]
                selected = selected_entries.get(method.get("text_key"), gap("CUSTOM_TEXT_KEY_UNRESOLVED"))
                result[key] = apply_single_template(values[key], name, method, selected)
            derived = sum(result[key].get("status") == "known" for key in targets)
            return result, {"status":"known", "derived_count":derived, "target_count":len(targets),
                "methods":deepcopy(methods), "provenance":deepcopy(normalized.get("provenance", {})),
                "root_binding":"explicit_query_observer_country", "ui_root_scope_verified":False,
                "atomic_with_text_cache":False, "native_function_invoked":False}
        except Exception as exc:
            return values, {"status":"unknown", "derived_count":0, "target_count":len(targets),
                            "reason":getattr(exc, "code", "custom_localization_read_failed"),
                            "native_function_invoked":False}

    @staticmethod
    def normalize_localization(report, context, keys, codec):
        return NativeLocalizationReader.normalize_localization(report, context, keys, codec)

    @staticmethod
    def normalize_branch_inputs(report, context):
        identity = report.get("identity", {})
        if (report.get("status") != "observed" or report.get("read_only") is not True
                or identity.get("binding_verified") is not True
                or identity.get("installation_session_id") != context.get("session_id")
                or identity.get("process_path_sha256") != context.get("game_sha256")
                or report.get("request", {}).get("country") != context.get("observer")
                or report.get("doublepass", {}).get("consistent") is not True
                or any(report.get(key, {}).get("status") != "observed"
                       for key in ("static_contract_guard", "file_code_guard", "runtime_code_guard"))
                or report.get("cleanup", {}).get("handle_close", {}).get("closed") is not True):
            raise InformationError("branch_input_snapshot_incomplete", "Branch input identity, guard or cleanup check failed")
        before = report.get("before", {})
        if before.get("game_date", {}).get("raw") != context.get("game_date"):
            raise InformationError("branch_input_context_changed", "Branch inputs belong to another game date")
        inputs = report.get("inputs", {})
        flags = inputs.get("country_flags", {})
        target_names = {"fra_shed_the_blood_of_the_saxon_man_flag", "fra_fufujoni_flag",
                        "fra_chose_to_piss_off_pope_flag", "fra_papal_lap_dop_flag"}
        mode = inputs.get("map_setup", {})
        if (not isinstance(flags, dict) or set(flags) != target_names
                or any(not isinstance(value, dict) or value.get("known") is not True or type(value.get("value")) is not bool
                for value in flags.values()) or mode.get("known") is not True
                or type(mode.get("value")) is not int or mode["value"] not in range(4)):
            raise InformationError("branch_input_snapshot_incomplete", "Branch input values are incomplete")
        dlc = gap("DLC_RUNTIME_SOURCE_NOT_IMPLEMENTED")
        domination = inputs.get("has_domination")
        if isinstance(domination, dict):
            if domination.get("known") is True:
                if domination.get("value") is not True:
                    raise InformationError("branch_input_snapshot_incomplete", "Domination false requires unresolved thread-local state")
                dlc = dict(known({"Domination": True}), scope="Domination_condition_only", complete_inventory=False,
                           derivation="native_condition_short_circuit_without_TLS")
            else:
                dlc = gap(domination.get("reason") or domination.get("unknown_reason") or "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED")
        return {"status": "known", "country_flags": {name: known(value["value"]) for name, value in flags.items()},
                "map_setup": known({"raw": mode["value"], "name": mode.get("name")}),
                "dlc_loaded": dlc,
                "provenance": {"reader": "bounded_ReadProcessMemory", "game_date": context.get("game_date"),
                    "session_id": context.get("session_id"), "profile_sha256": report.get("profile", {}).get("sha256"),
                    "probe_sha256": report.get("probe_script_sha256"), "doublepass_consistent": True,
                    "atomic_with_mission_slots": False, "world_generation_verified": False,
                    "flag_name_table_length_known": False}}

    @staticmethod
    def normalize_loaded_tasks(report, slots):
        captured = report.get("loaded_tasks")
        if (not isinstance(captured, dict) or captured.get("status") != "observed"
                or captured.get("complete") is not True):
            reasons = captured.get("unknown_conditions") if isinstance(captured, dict) else None
            return gap(reasons[0] if isinstance(reasons, list) and reasons else "LOADED_TASKS_NOT_VERIFIED")
        if (report.get("request", {}).get("include_tasks") is not True
                or report.get("doublepass", {}).get("task_consistent") is not True
                or report.get("cleanup", {}).get("handle_close", {}).get("closed") is not True
                or any(report.get(key, {}).get("status") != "observed" for key in
                       ("task_static_contract_guard", "task_file_code_guard", "task_runtime_code_guard"))):
            return gap("LOADED_TASK_GUARD_OR_CONSISTENCY_FAILED")
        raw_roots = captured.get("roots")
        expected = [(slot["slot_index"], root["root_index"], root["definition_name"]["text"])
                    for slot in slots for root in slot["roots"]]
        if not isinstance(raw_roots, list) or len(raw_roots) != len(expected):
            return gap("LOADED_TASK_ROOTS_INCOMPLETE")
        normalized, total = [], 0
        for root, identity in zip(raw_roots, expected):
            if not isinstance(root, dict):
                return gap("LOADED_TASKS_INVALID")
            records, ids = root.get("tasks"), root.get("task_ids")
            vector = root.get("vector")
            if (root.get("status") != "observed" or root.get("complete") is not True
                    or (root.get("slot_index"), root.get("root_index"), root.get("root_id")) != identity
                    or not isinstance(records, list) or not isinstance(ids, list)
                    or not isinstance(vector, dict) or type(vector.get("count")) is not int
                    or vector["count"] != len(records) or len(ids) != len(records) or len(ids) > 4096
                    or any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in ids)
                    or len(set(ids)) != len(ids)):
                return gap("LOADED_TASKS_INVALID")
            for task, task_id in zip(records, ids):
                if (not isinstance(task, dict) or task.get("status") != "observed" or task.get("complete") is not True
                        or not isinstance(task.get("task_id"), dict) or task["task_id"].get("status") != "observed"
                        or task["task_id"].get("text") != task_id):
                    return gap("LOADED_TASKS_INVALID")
            total += len(ids)
            if total > 4096:
                return gap("LOADED_TASKS_LIMIT_EXCEEDED")
            normalized.append({"root_id": identity[2], "task_ids": deepcopy(ids)})
        if type(captured.get("total_task_count")) is not int or captured["total_task_count"] != total:
            return gap("LOADED_TASK_COUNT_MISMATCH")
        return {"status": "known", "roots": normalized}

    @staticmethod
    def normalize(report, context):
        if (not isinstance(report, dict)
                or any(not isinstance(report.get(key), dict) for key in
                       ('identity', 'request', 'static_contract_guard', 'doublepass', 'before'))):
            raise InformationError('mission_snapshot_incomplete', 'Native mission audit sections are incomplete')
        identity = report.get("identity", {})
        task_capture_requested = report.get("request", {}).get("include_tasks") is True
        # Earlier retained root-only fixtures omitted these audit sections.
        # The current task contract requires them; an explicit failed section
        # always rejects the whole snapshot, including legacy root records.
        base_guard_failed = any((task_capture_requested or key in report)
                                and (not isinstance(report.get(key), dict)
                                     or report[key].get("status") != "observed")
                                for key in ("file_code_guard", "runtime_code_guard"))
        cleanup = report.get('cleanup')
        handle_close = cleanup.get('handle_close') if isinstance(cleanup, dict) else None
        cleanup_failed = ((task_capture_requested or "cleanup" in report)
                          and (not isinstance(handle_close, dict) or handle_close.get('closed') is not True))
        if (report.get("status") != "observed" or identity.get("binding_verified") is not True
                or report.get("read_only") is not True
                or report.get("static_contract_guard", {}).get("status") != "observed"
                or base_guard_failed or cleanup_failed
                or report.get("doublepass", {}).get("consistent") is not True
                or identity.get("installation_session_id") != context.get("session_id")):
            raise InformationError("mission_snapshot_incomplete", "Native mission identity or double-pass verification failed")
        before = report.get("before", {})
        missions = before.get("missions", {})
        mission_contract = before.get('mission_contract')
        if (not isinstance(missions, dict) or not isinstance(mission_contract, dict)
                or missions.get("status") != "observed" or mission_contract.get("status") != "observed"
                or identity.get("process_path_sha256") != context.get("game_sha256")):
            raise InformationError("mission_snapshot_incomplete", "Native mission slots are incomplete")
        completed = missions.get("candidate_completed_missions") or {}
        result = {"complete": True, "country": report.get("request", {}).get("country"), "mode": "live",
                "session_id": context.get("session_id"), "game_date": before.get("game_date", {}).get("raw"),
                "state_kind": "captured_country_mission_slots",
                "mission_slots": [{"slot": slot["slot_index"]+1,
                                   "roots": [root["definition_name"]["text"] for root in slot["roots"]]}
                                  for slot in missions["slots"]],
                "completed_missions": ({"status": "known", "task_ids": [value["text"] for value in completed.get("rootstrings", [])]}
                    if completed.get("status") == "observed" else {"status": "unknown", "reason": "COMPLETION_LIST_NOT_VERIFIED"}),
                "provenance": {"reader": "bounded_ReadProcessMemory", "read_only": True,
                               "process_creation_filetime": identity.get("process_creation_filetime"),
                               "game_sha256": identity.get("process_path_sha256"),
                               "probe_sha256": report.get("probe_script_sha256"),
                               "doublepass_consistent": True, "atomic_main_thread_snapshot": False,
                               "world_generation_verified": False,
                               "branch_visibility_evaluated": False}}
        if report.get("request", {}).get("include_tasks") is True:
            result["loaded_tasks"] = NativeMissionReader.normalize_loaded_tasks(report, missions["slots"])
            result["provenance"]["task_reader"] = deepcopy(report.get("task_reader"))
            result["provenance"]["loaded_tasks_same_doublepass"] = report.get("doublepass", {}).get("task_consistent") is True
        if report.get('request', {}).get('include_prerequisites') is True:
            from .mission_loaded_prerequisites import normalize_prerequisites
            result['loaded_prerequisites'] = normalize_prerequisites(report, result.get('loaded_tasks', {}))
            result['provenance']['prerequisite_profile_sha256'] = report.get('prerequisite_profile_sha256')
            result['provenance']['prerequisite_reader'] = deepcopy(report.get('prerequisite_reader'))
            result['provenance']['loaded_prerequisites_same_doublepass'] = report.get('doublepass', {}).get('prerequisite_consistent') is True
        if report.get('request',{}).get('include_conditions') is True:
            from .mission_condition_source import normalize_conditions
            result['mission_conditions'] = normalize_conditions(report,result.get('loaded_prerequisites',{}))
            result['provenance']['condition_reader'] = deepcopy(report.get('condition_reader'))
            result['provenance']['condition_profile_sha256'] = report.get('condition_profile_sha256')
            result['provenance']['mission_conditions_same_doublepass'] = report.get('doublepass',{}).get('condition_consistent') is True
        if report.get('request',{}).get('include_triggers') is True:
            from .mission_trigger_source import normalize_triggers
            result['mission_triggers']=normalize_triggers(report,result.get('loaded_prerequisites',{}))
            result['provenance']['trigger_reader']=deepcopy(report.get('trigger_reader'))
            result['provenance']['trigger_profile_sha256']=report.get('trigger_profile_sha256')
            result['provenance']['loaded_trigger_binding_verified']=report.get('doublepass',{}).get('trigger_consistent') is True
        return result
