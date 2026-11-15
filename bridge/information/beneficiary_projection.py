"""Project beneficiaries from bounded public declaration and peace previews."""
from __future__ import annotations

from copy import deepcopy

from ..declarewar_selection import COUNTRY_TAG_RE


def _tag(value):
    return isinstance(value, str) and COUNTRY_TAG_RE.fullmatch(value) is not None


def _field(value, source_path, scope, complete, **metadata):
    return {"status": "known", "value": value, "source_path": source_path,
            "scope": scope, "complete": complete, "partial": not complete, **metadata}


def declaration_beneficiaries(inspection):
    """Keep the queried CB's native goal candidates and its selected goal."""
    parameters = inspection.get("parameters", {})
    actual = parameters.get("actual")
    actual = actual if isinstance(actual, dict) else {}
    cb = actual.get("casus_belli") or inspection.get("requested_casus_belli")
    if not isinstance(cb, str) or not cb:
        return {"status": "unknown", "reason": "QUERIED_CASUS_BELLI_REQUIRED"}
    candidates = inspection.get("candidates")
    if not isinstance(candidates, list):
        return {"status": "unknown", "reason": "DECLARE_WAR_CANDIDATES_UNAVAILABLE"}
    values, raw, unresolved = [], [], 0
    for candidate in candidates:
        if candidate.get("casus_belli_key_verified") is not True:
            unresolved += 1
            continue
        if candidate.get("casus_belli_key") != cb:
            continue
        raw.append(deepcopy(candidate))
        country = candidate.get("beneficiary_tag")
        if country == "---":
            country = inspection.get("actor")
        elif candidate.get("beneficiary_identifier_verified") is not True:
            unresolved += 1
            continue
        province = candidate.get("target_province_id")
        if (not _tag(country) or type(province) is not int
                or (province != -1 and (province <= 0 or candidate.get("province_identifier_verified") is not True))):
            unresolved += 1
            continue
        row = {"country": country, "province_id": None if province == -1 else province}
        if row not in values:
            values.append(row)
    goal = actual.get("war_goal")
    selected = None
    selected_country = goal.get("beneficiary") if isinstance(goal, dict) else None
    if selected_country == "---":
        selected_country = inspection.get("actor")
    if (inspection.get("selection_matched") is True and isinstance(goal, dict)
            and _tag(selected_country) and type(goal.get("province_id")) is int):
        selected = {"country": selected_country,
                    "province_id": None if goal["province_id"] == -1 else goal["province_id"]}
    enumeration = inspection.get("candidate_enumeration", {})
    complete = enumeration.get("query_complete") is True and not unresolved
    return _field({"casus_belli": cb, "war_goal_candidates": values, "selected_war_goal": selected},
        "candidates", "queried_casus_belli_war_goal_candidates", complete,
        native_candidates=raw, unresolved_candidate_count=unresolved,
        candidate_enumeration=deepcopy(enumeration), native_selected_war_goal=deepcopy(goal))


def _peace_tables(inspection):
    candidates = inspection.get("parameters", {}).get("candidates")
    if isinstance(candidates, list):
        native = inspection.get("native_provinces", {})
        table = {"candidates": candidates, "candidate_count": native.get("candidate_count"),
                 "candidates_available": native.get("candidate_enumeration_complete"),
                 "candidates_complete": native.get("candidate_enumeration_complete"),
                 "candidates_truncated": native.get("candidate_capture_truncated")}
        return [(inspection.get("action_id"), table)]
    if not isinstance(candidates, dict):
        return []
    if isinstance(candidates.get("candidates"), list):
        return [(inspection.get("action_id"), candidates)]
    return [(action, table) for action, table in candidates.items()
            if isinstance(table, dict) and isinstance(table.get("candidates"), list)]


def _peace_rows(tables):
    rows = []
    for action, table in tables:
        for candidate in table["candidates"]:
            row = {key: deepcopy(candidate[key]) for key in
                   ("province_id", "beneficiary", "selected", "name", "country", "partner", "core_owner")
                   if key in candidate}
            row["action_id"] = action
            row["selectable"] = (candidate["native_selectable"]
                if candidate.get("native_selectability_checked") is True
                and type(candidate.get("native_selectable")) is bool else None)
            rows.append(row)
    return rows


def _plan_countries(context):
    terms = context.get("terms")
    if not isinstance(terms, list):
        return None
    countries = []
    for term in terms:
        country = term.get("beneficiary")
        if term.get("action_id") == "demand_ducats":
            country = term.get("claimant")
        if term.get("action_id") == "return_core":
            country = term.get("core_owner")
        if _tag(country) and country not in countries:
            countries.append(country)
    return countries


def _selected_plan(inspection, context):
    countries = _plan_countries(context)
    if countries is None:
        return None
    legality = inspection.get("legality", {})
    return {"countries": countries, "legality": legality.get("status", "unknown"),
            "legality_reasons": [reason["text"] for reason in legality.get("reasons", [])
                        if isinstance(reason.get("text"), str)]}


def _requested_plan(inspection, context):
    parameters = inspection.get("parameters", {})
    requested = parameters.get("requested", {}).get("peace_context", {})
    if context.get("terms") is not None or not requested.get("terms"):
        return None, None
    countries = _plan_countries(requested)
    if countries is None:
        return None, None
    candidates = parameters.get("candidates", {})
    code = candidates.get("reason_code") if isinstance(candidates, dict) else None
    if not code:
        code = inspection.get("native_provinces", {}).get("reason_code")
    text = {
        "NATIVE_PEACE_PROVINCE_CANDIDATE_ABSENT": "请求的省份和受益国组合不在当前原生候选中。",
        "NATIVE_PEACE_PROVINCE_SELECTION_UNAVAILABLE": "原生预览无法应用请求的省份选择。",
        "NATIVE_PEACE_PROVINCE_SELECTION_MISMATCH": "原生实际选择与请求的省份和受益国不一致。",
    }.get(code)
    if text is None:
        messages = [reason["text"] for reason in inspection.get("legality", {}).get("reasons", [])
                    if isinstance(reason.get("text"), str)]
        text = "\n".join(messages) or None
    return {"countries": countries, "applied": False, "selection_reason": text}, code


def _peace_beneficiaries(rows, selected_plan, complete, requested_plan, selection_reason_code):
    countries, unresolved = {}, 0
    for row in rows:
        country = row.get("beneficiary")
        if row.get("action_id") == "return_core":
            country = row.get("core_owner")
        if not _tag(country) or type(row.get("province_id")) is not int:
            unresolved += 1
            continue
        group = countries.setdefault(country, {"country": country, "province_ids": [],
            "selectable_province_ids": [], "blocked_province_ids": [], "unchecked_province_ids": []})
        province = row["province_id"]
        if province not in group["province_ids"]:
            group["province_ids"].append(province)
        key = ("unchecked_province_ids" if row["selectable"] is None else
               "selectable_province_ids" if row["selectable"] else "blocked_province_ids")
        if province not in group[key]:
            group[key].append(province)
    checked = all(not group["unchecked_province_ids"] for group in countries.values())
    value = {"candidates": list(countries.values()), "selected_plan": selected_plan}
    if requested_plan is not None:
        value["requested_plan"] = requested_plan
    return _field(value,
        "parameters.candidates", "current_peace_candidate_beneficiaries", complete and checked and not unresolved,
        unresolved_candidate_count=unresolved, requested_plan_reason_code=selection_reason_code)


def peace_fields(inspection, requested_fields):
    """Fill P01 fields from the same public native inspection already queried."""
    requested = set(requested_fields)
    result = {}
    parameters = inspection.get("parameters", {})
    actual = parameters.get("actual")
    context = actual.get("peace_context", {}) if isinstance(actual, dict) else {}
    native_provinces = inspection.get("native_provinces", {})
    if (inspection.get("peace_consequences", {}).get("requested_terms_applied") is False
            or (native_provinces.get("selection_requested") is True
                and native_provinces.get("parameters_matched") is False)):
        context = {}
    if "terms" in requested and isinstance(context.get("terms"), list):
        result["terms"] = _field(deepcopy(context["terms"]), "parameters.actual.peace_context.terms",
                                 "selected_peace_plan", True)
    native_context = inspection.get("peace_context", {})
    war_id = context.get("war_id") or native_context.get("war_id")
    if "war_id" in requested and isinstance(war_id, str):
        source = "parameters.actual.peace_context.war_id" if context.get("war_id") else "peace_context.war_id"
        result["war_id"] = _field(war_id, source, "selected_war", True)
    tables = _peace_tables(inspection)
    if not tables:
        return result
    rows = _peace_rows(tables)
    complete = all(table.get("candidates_complete") is True
                   and table.get("candidates_truncated") is not True for _, table in tables)
    if not rows and not any(table.get("candidates_available") is True for _, table in tables):
        return result
    if "candidates" in requested:
        result["candidates"] = _field(rows, "parameters.candidates", "current_peace_candidates", complete,
                                      candidate_tables=deepcopy(parameters["candidates"]))
    if "beneficiaries" in requested:
        requested_plan, reason_code = _requested_plan(inspection, context)
        result["beneficiaries"] = _peace_beneficiaries(
            rows, _selected_plan(inspection, context), complete, requested_plan, reason_code)
    if "scope" in requested:
        value = {"war_id": war_id, "direction": context.get("direction") or native_context.get("direction"),
                 "action_ids": [action for action, _ in tables]}
        result["scope"] = _field(value, "parameters.candidates", "current_peace_candidates", complete)
    return result
