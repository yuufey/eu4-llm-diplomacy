"""Compact user-facing projection for selected mission fields."""

from collections import OrderedDict


_MISSION_TOPICS = frozenset({"M01", "M02", "M03", "M04"})
_TECHNICAL_WORDS = ("token", "index", "path", "source", "line", "sha", "raw",
                    "verify", "context_id", "address", "pointer")


def _technical_key(key):
    lowered = str(key).lower()
    return (any(word in lowered for word in _TECHNICAL_WORDS)
            or lowered == "count" or lowered.endswith(("_count", "_counts")))


def _field_value(fields, name):
    """Return a known field payload, keeping unknown and missing facts distinct."""
    wrapped = fields.get(name)
    if not isinstance(wrapped, dict):
        return None
    if wrapped.get("status") != "known" or "value" not in wrapped:
        return None
    return wrapped["value"]


def _task_key(value):
    if not isinstance(value, dict):
        return None
    task_id = value.get("task_id")
    root_id = value.get("root_id")
    if not isinstance(task_id, str) or not task_id:
        return None
    return (root_id if isinstance(root_id, str) else None, task_id)


def _task_row(tasks, key):
    if key in tasks:
        return tasks[key]
    matches = [existing for existing in tasks if existing[1] == key[1]]
    if key[0] is None and len(matches) == 1:
        return tasks[matches[0]]
    unknown = (None, key[1])
    if key[0] is not None and unknown in tasks and len(matches) == 1:
        row = tasks.pop(unknown)
        row["root_id"] = key[0]
        tasks[key] = row
        return row
    return tasks.setdefault(key, {"root_id": key[0], "task_id": key[1]})


def _task_rows(tasks, rows):
    for row in rows if isinstance(rows, list) else ():
        key = _task_key(row)
        if key is not None:
            _task_row(tasks, key)


def _task_fact(mapping, key):
    if key in mapping:
        return mapping[key]
    matches = [value for candidate, value in mapping.items() if candidate[1] == key[1]]
    return matches[0] if len(matches) == 1 else None


def _preserve_unprojected(result, fields, consumed):
    """Retain other selected business fields through the shared concise view."""
    from .presentation import _concise_value

    for name, value in fields.items():
        if name not in consumed:
            result[name] = _concise_value(value)
    return result


def _localization_entries(value):
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        return ()
    return (entry for entry in value["entries"] if isinstance(entry, dict))


def _clean_scalar_map(value):
    """Keep only plain metric facts; discard implementation and source metadata."""
    if not isinstance(value, dict):
        return None
    result = {}
    for key, child in value.items():
        if _technical_key(key):
            continue
        if child is None or type(child) in (str, int, float, bool):
            result[key] = child
    return result or None


def _satisfied(value):
    if not isinstance(value, dict):
        return None
    satisfied = value.get("satisfied")
    return satisfied if type(satisfied) is bool else None


def _condition_rows(tree, province_id=None):
    """Extract evaluated leaf facts without exposing the source expression tree."""
    output = []
    if not isinstance(tree, dict):
        return output
    metric = tree.get("metric")
    metric = metric if isinstance(metric, dict) else None
    leaf_name = tree.get("condition_name")
    if isinstance(leaf_name, str):
        facts = _clean_scalar_map(metric) or {}
        actual_province = facts.get("province_id", province_id)
        if actual_province is not None:
            facts["province_id"] = actual_province
        output.append({
            "condition_name": leaf_name,
            "satisfied": _satisfied(tree.get("evaluation")),
            "metric": facts or None,
        })
    for member in tree.get("members", []) if isinstance(tree.get("members"), list) else ():
        if not isinstance(member, dict):
            continue
        member_id = member.get("province_id")
        output.extend(_condition_rows(member.get("tree"),
                                      member_id if type(member_id) is int else province_id))
    for child in tree.get("children", []) if isinstance(tree.get("children"), list) else ():
        output.extend(_condition_rows(child, province_id))
    return output


def _m01(fields):
    tasks = OrderedDict()
    _task_rows(tasks, _field_value(fields, "task_id"))
    for field_name in ("name", "description"):
        for entry in _localization_entries(_field_value(fields, field_name)):
            key = _task_key(entry)
            if key is None:
                continue
            task = _task_row(tasks, key)
            text = entry.get("text")
            task[field_name] = text if isinstance(text, str) else None
    return {"tasks": list(tasks.values())}


def _m02(fields):
    tasks = OrderedDict()
    completed_value = _field_value(fields, "completion_status")
    completed_ids = None
    selected_completion = {}
    if isinstance(completed_value, dict):
        values = completed_value.get("completed_task_ids")
        if isinstance(values, list) and all(isinstance(value, str) for value in values):
            completed_ids = values
        selected = completed_value.get("selected_task")
        key = _task_key(selected)
        if key is not None:
            _task_rows(tasks, [selected])
            value = selected.get("completed")
            selected_completion[key] = value if type(value) is bool else None

    completable_value = _field_value(fields, "currently_completable")
    completable_known = isinstance(completable_value, dict)
    completable_rows = completable_value.get("tasks", []) if completable_known else []
    _task_rows(tasks, completable_rows)
    completable = {}
    for row in completable_rows if isinstance(completable_rows, list) else ():
        key = _task_key(row)
        if key is not None:
            value = row.get("currently_completable") if row.get("status") == "known" else None
            completable[key] = value if type(value) is bool else None

    progress_value = _field_value(fields, "condition_progress")
    progress_known = isinstance(progress_value, dict)
    progress_rows = progress_value.get("tasks", []) if progress_known else []
    _task_rows(tasks, progress_rows)
    conditions = {}
    for row in progress_rows if isinstance(progress_rows, list) else ():
        key = _task_key(row)
        if key is not None:
            conditions[key] = _condition_rows(row.get("trigger"))

    prerequisites_value = _field_value(fields, "prerequisites")
    prerequisites_known = isinstance(prerequisites_value, list)
    prerequisites = {}
    for row in prerequisites_value if prerequisites_known else ():
        key = _task_key(row)
        if key is None:
            continue
        _task_row(tasks, key)
        evaluation = row.get("evaluation")
        if not isinstance(evaluation, dict) or evaluation.get("status") != "known":
            evaluation = row.get("declared_rule_evaluation")
        evaluation = evaluation if isinstance(evaluation, dict) else {}
        required = evaluation.get("required_task_ids", row.get("required_task_ids"))
        missing = evaluation.get("missing_task_ids")
        prerequisites[key] = {
            "required_task_ids": required if isinstance(required, list) else None,
            "missing_task_ids": missing if isinstance(missing, list) else None,
            "satisfied": (evaluation.get("satisfied")
                          if type(evaluation.get("satisfied")) is bool else None),
        }

    output = []
    for key, task in tasks.items():
        selected = _task_fact(selected_completion, key)
        if completed_ids is not None:
            task["completed"] = task["task_id"] in completed_ids
        elif selected is not None:
            task["completed"] = selected
        else:
            task["completed"] = None
        task["currently_completable"] = _task_fact(completable, key) if completable_known else None
        task["conditions"] = _task_fact(conditions, key) if progress_known else None
        if "prerequisites" in fields:
            task["prerequisites"] = _task_fact(prerequisites, key) if prerequisites_known else None
        output.append(task)
    return {"tasks": output if tasks else None,
            "completed_task_ids": completed_ids}


def _m03(fields):
    tasks = OrderedDict()
    target_fields = ("provinces", "regions", "countries")
    condition_fields = ("ownership", "control", "cores", "subjects")
    target_unknown = any(name in fields and _field_value(fields, name) is None
                         for name in target_fields)
    condition_unknown = any(name in fields and _field_value(fields, name) is None
                            for name in condition_fields)
    any_target_rules = False
    any_condition_rules = False
    for field_name in target_fields + condition_fields:
        value = _field_value(fields, field_name)
        if not isinstance(value, dict) or not isinstance(value.get("rules"), list):
            continue
        for rule in value["rules"]:
            if not isinstance(rule, dict):
                continue
            key = _task_key(rule)
            if key is None:
                continue
            task = _task_row(tasks, key)
            if field_name in target_fields:
                any_target_rules = True
                scope = rule.get("static_scope")
                if isinstance(scope, dict):
                    members = scope.get("members")
                    province_ids = ([value for value in members if type(value) is int]
                                    if isinstance(members, list) else None)
                    target = {
                        "kind": scope.get("kind") if isinstance(scope.get("kind"), str) else None,
                        "identifier": scope.get("name") if isinstance(scope.get("name"), str) else None,
                        "province_ids": province_ids,
                        "basis": "static_definition",
                    }
                    targets = task.setdefault("targets", [])
                    if target not in targets:
                        targets.append(target)
            if field_name in condition_fields:
                any_condition_rules = True
                condition_name = rule.get("command_key")
                if isinstance(condition_name, str):
                    condition = {"condition_name": condition_name, "satisfied": None}
                    conditions = task.setdefault("conditions", [])
                    if condition not in conditions:
                        conditions.append(condition)
    for task in tasks.values():
        if "targets" not in task and (target_unknown or any_target_rules):
            task["targets"] = None
        elif "targets" not in task and not any_target_rules:
            task["targets"] = None
        if "conditions" not in task and (condition_unknown or any_condition_rules):
            task["conditions"] = None
        elif "conditions" not in task and not any_condition_rules:
            task["conditions"] = None
    return {"tasks": list(tasks.values()) if tasks else None}


def _claim_conditions(rule):
    rows = []
    seen = set()
    for source in (rule.get("condition_context"), rule.get("parent_scope")):
        if not isinstance(source, list):
            continue
        for entry in source:
            if not isinstance(entry, dict):
                continue
            key, kind = entry.get("key"), entry.get("kind")
            if not isinstance(key, str) or key == "effect":
                continue
            # Context headers may repeat the same scope through both arrays.
            row = {"scope": key, "kind": kind if isinstance(kind, str) else None}
            marker = row["scope"]
            if marker not in seen:
                seen.add(marker)
                rows.append(row)
    return rows


_CONDITION_KEYS = frozenset({
    "kind", "condition_name", "name", "scope", "operator", "comparison",
    "value", "expected", "actual", "country", "tag", "province_id",
    "province_ids", "area", "region", "identifier", "children", "conditions",
    "all", "any", "not", "left", "right",
})


def _clean_condition(value):
    """Retain a small logical condition shape while dropping parser metadata."""
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, list):
        return [cleaned for child in value
                if (cleaned := _clean_condition(child)) is not None]
    if isinstance(value, dict):
        return {key: cleaned for key, child in value.items()
                if key in _CONDITION_KEYS
                and (cleaned := _clean_condition(child)) is not None}
    return None


def _limit_summary(candidate):
    evaluation = candidate.get("current_limit_evaluation")
    if not isinstance(evaluation, dict):
        return None
    provinces = evaluation.get("provinces")
    rows = []
    for province in provinces if isinstance(provinces, list) else ():
        if not isinstance(province, dict) or type(province.get("province_id")) is not int:
            continue
        value = province.get("satisfies_limit")
        rows.append({"province_id": province["province_id"],
                     "satisfies_limit": value if type(value) is bool else None})
    status = evaluation.get("status")
    return {"status": status if status == "known" else None, "provinces": rows}


def _m04(fields):
    tasks = OrderedDict()
    if "claims" not in fields:
        return {}
    claims_field = fields.get("claims")
    claims_value = _field_value(fields, "claims")
    if isinstance(claims_value, dict) and isinstance(claims_value.get("rules"), list):
        for task_rule in claims_value["rules"]:
            if not isinstance(task_rule, dict):
                continue
            key = _task_key(task_rule)
            if key is None:
                continue
            task = _task_row(tasks, key)
            claims = []
            for rule in task_rule.get("rules", []) if isinstance(task_rule.get("rules"), list) else ():
                if not isinstance(rule, dict):
                    continue
                candidate = rule.get("declared_area_candidates")
                candidate = candidate if isinstance(candidate, dict) else None
                candidate_status = candidate.get("status") if candidate else None
                province_ids = candidate.get("candidate_province_ids") if candidate else None
                if isinstance(province_ids, list):
                    province_ids = [value for value in province_ids if type(value) is int]
                else:
                    province_ids = None
                condition_rows = _claim_conditions(rule)
                claim_type = {"add_claim": "temporary", "add_permanent_claim": "permanent"}.get(rule.get("command"))
                condition_tree = _clean_condition(rule.get("conditional"))
                if condition_tree is None:
                    condition_tree = _clean_condition(rule.get("limit"))
                if condition_tree is None and condition_rows:
                    condition_tree = {"contexts": condition_rows, "evaluated": False}
                applied = candidate.get("applied") if candidate else claims_value.get("applied")
                claims.append({
                    "claim_type": claim_type,
                    "target": ({
                        "kind": candidate.get("kind") if isinstance(candidate.get("kind"), str) else None,
                        "identifier": candidate.get("identifier") if isinstance(candidate.get("identifier"), str) else None,
                        "province_ids": province_ids,
                        "basis": "declared_static_target",
                    } if candidate is not None and candidate_status == "known" else None),
                    "conditions": condition_rows or None,
                    "conditional": (True if condition_rows else None),
                    "condition_tree": condition_tree,
                    "condition_status": (rule.get("context_status")
                                         if rule.get("context_status") in ("known", "unresolved") else None),
                    "limit_evaluation": _limit_summary(candidate) if candidate else None,
                    "granted": applied if type(applied) is bool else None,
                })
            task["claims"] = claims if task_rule.get("status") == "known" else None
    if not tasks and claims_field is not None and claims_value is None:
        return {"tasks": None}
    return {"tasks": list(tasks.values()) if tasks else []}


def project_mission_fields(topic, fields):
    """Return compact mission facts for M01-M04; return None for other topics.

    The input is the stored, wrapped ``item.fields`` mapping.  The projection
    deliberately describes static declarations and captured facts only; it
    never infers that a reward was granted or that an unevaluated condition is
    satisfied.
    """
    if topic not in _MISSION_TOPICS:
        return None
    if not isinstance(fields, dict):
        return {"tasks": None}
    if topic == "M01":
        return _preserve_unprojected(_m01(fields), fields, {"task_id", "name", "description"})
    if topic == "M02":
        return _preserve_unprojected(_m02(fields), fields, {
            "completion_status", "currently_completable", "condition_progress", "prerequisites"})
    if topic == "M03":
        return _preserve_unprojected(_m03(fields), fields, {
            "provinces", "regions", "countries", "ownership", "control", "cores", "subjects"})
    return _preserve_unprojected(_m04(fields), fields, {"claims"})
