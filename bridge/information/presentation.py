"""Present brief reports while preserving their complete stored results."""
from copy import deepcopy
from decimal import Decimal
import re

from .mission_concise import project_mission_fields
from .diplomat_tasks import concise_diplomat_tasks


_PUBLIC_REASON = re.compile(r"[A-Za-z0-9_:-]{1,128}\Z")
_UNAVAILABLE_STATUSES = frozenset({"unknown", "invisible", "unavailable", "unsupported", "not_applicable", "stale"})


# These describe collection and implementation, rather than game state.
_INTERNAL_KEYS = frozenset({
    "provenance", "source", "sources", "source_path", "source_paths",
    "raw", "raw_hex", "unit", "scale", "basis", "value_origin",
    "value_semantics", "reference_period", "period", "complete", "partial",
    "gaps", "reason", "reasons", "limitations", "diagnostics", "diagnostic",
    "session_id", "game_sha256", "dll_sha256", "schema_version",
    "observation_window", "field_context_scopes", "context_scope",
    "collected_at", "observed_at", "last_known", "status",
    "scope", "identity_scope", "experiment_id", "action_authorization",
    "canonical_pointer_keys_verified", "native_function_called",
    "context_table_status", "context_status", "total_raw",
    "native_ledger_total", "total_includes_additional_native_terms",
    "combat_side_index", "result_side_index", "classification_scope",
    "enumeration_scope", "native_overrun",
    "trigger_ast", "declared_rules", "parent_scope", "context_table", "context_refs",
    "ancestor_headers", "logical_ancestors", "trigger_source", "source_column",
    "end_column", "end_line", "line", "path", "path_text", "cwt_rule_lines",
    "token", "task_index", "projection_version", "codec", "localization_key",
    "observation_path", "command_state", "command_mode",
    "collected_game_date", "native_sequence", "sequence", "role_basis",
    "condition_node", "condition_index", "child_index", "child_count",
    "root_condition_count", "observed_condition_count", "completion_path",
    "native_return_before", "native_return_after", "previous_observed_date_raw",
    "native_date_fields", "date_raw", "expiry_comparison",
})


def _concise_value(value):
    if isinstance(value, list):
        return [_concise_value(child) for child in value]
    if not isinstance(value, dict):
        return value
    if value.get("event") == "native_diplomacy_task_execution_result":
        result = {key: value[key] for key in ("task_before", "task_after") if key in value}
        metadata = value.get("native_result_date", {})
        result["date"] = (_readable_game_date(metadata.get("game_date_raw"))
                          if metadata.get("status") == "known" else None)
        return result
    wrapped = isinstance(value.get("status"), str)
    if value.get("unit") == "game_date_raw" and (not wrapped or value["status"] == "known"):
        return _readable_game_date(value.get("value", value.get("raw", value.get("game_date_raw"))))
    if "value" in value and (wrapped or "unit" in value or "scale" in value):
        if wrapped and value["status"] != "known":
            return None
        number = value["value"]
        scale = value.get("scale", 1)
        if type(number) in (int, float) and type(scale) in (int, float) and scale > 0:
            # Some inner display values have already been converted by their
            # source, e.g. force limit value=56 alongside raw=56000.
            if not wrapped or (type(value.get("raw")) in (int, float) and value["raw"] != number):
                return number
            return number if scale == 1 else number / scale
        if isinstance(number, dict) and scale != 1 and value.get("unit") == "morale":
            return {key: child / scale if type(child) in (int, float) else _concise_value(child)
                    for key, child in number.items()}
        return _concise_value(number)
    if isinstance(value.get("status"), str) and value["status"] in _UNAVAILABLE_STATUSES:
        return None
    if type(value.get("raw")) in (int, float) and "unit" in value and "scale" in value:
        return value["raw"] / value["scale"]
    return {key: _concise_value(child) for key, child in value.items()
            if key not in _INTERNAL_KEYS
            and not key.endswith(("_rva", "_address", "_pointer", "_sha256", "_hex"))
            and not key.endswith(("_verified", "_complete"))
            and (not key.startswith("raw_") or key == "raw_text")}


def _declare_war_participants(fields):
    participant_fields = [field for name, field in fields.items()
                          if name in {'ally', 'willingness', 'reasons', 'land_promise_available'}]
    if not participant_fields or any(
            field.get('source_path') != 'participants.candidates' for field in participant_fields):
        return None
    values = {name: field.get('value') if field.get('status') == 'known' else None
              for name, field in fields.items()}
    allies = values.get('ally') or []
    countries = {ally['country']: dict(ally) for ally in allies}
    for name in ('willingness', 'reasons', 'land_promise_available'):
        for country in values.get(name) or {}:
            countries.setdefault(country, {'country': country})
    for country, ally in countries.items():
        for name in ('willingness', 'reasons', 'land_promise_available'):
            if name not in fields:
                continue
            value = (values.get(name) or {}).get(country)
            if name == 'reasons' and isinstance(value, list):
                value = [{key: reason.get(key) for key in ('value', 'text')} for reason in value]
            ally[name] = deepcopy(value)
    result = {'allies': list(countries.values())}
    if 'favor_requirement' in fields:
        result['favor_requirement'] = _concise_value(fields['favor_requirement'])
    return result


def _with_range(current, maximum, minimum=None):
    value = {"current": current, "max": maximum}
    if minimum is not None:
        value["min"] = minimum
    return value


def _readable_game_date(value):
    if isinstance(value, str) or value is None:
        return value
    from .truce_date_math import decode_date
    try:
        year, month, day, _hour = decode_date(value)
        return f"{year}.{month}.{day}"
    except (TypeError, ValueError):
        return None


def _trade_outgoing(field):
    if field.get("status") != "known" or not isinstance(field.get("value"), dict):
        return None
    value = field["value"]
    scale = field.get("scale")
    routes = value.get("routes")
    if type(scale) is not int or scale <= 0 or not isinstance(routes, list):
        return None

    def ducats(raw):
        return raw / scale if type(raw) is int else None

    return {"total_ducats": ducats(value.get("total_raw")), "routes": [
        {"node_id": route["node_id"], "ducats": ducats(route.get("raw"))}
        for route in routes if isinstance(route, dict) and isinstance(route.get("node_id"), str)
    ]}


def _loan_dates(loans, game_date):
    from .engine_dates import TICKS_PER_DAY

    current_date = _readable_game_date(game_date)
    for loan in loans:
        if not isinstance(loan, dict):
            continue
        due_raw = loan.get("due_raw", loan.get("due"))
        due_date = _readable_game_date(due_raw) if type(due_raw) is int else None
        loan["due_date"] = due_date
        loan["days_until_due"] = (
            due_raw // TICKS_PER_DAY - game_date // TICKS_PER_DAY
            if due_date is not None and current_date is not None and type(game_date) is int else None
        )


def _missing_fields(fields):
    missing = {}
    for name, field in fields.items():
        if not isinstance(field, dict) or field.get("status") not in _UNAVAILABLE_STATUSES:
            continue
        reason = field.get("reason")
        item = {"status": field["status"]}
        if isinstance(reason, str) and _PUBLIC_REASON.fullmatch(reason) and "0x" not in reason.lower():
            item["reason"] = reason
        missing[name] = item
    return missing


def _modifier_event_payload(payload):
    if (not isinstance(payload, dict) or "modifier_id" not in payload
            or payload.get("change") not in {"added", "removed", "expired"}):
        return payload
    payload.pop("flags_raw", None)
    for label in ("start", "end"):
        raw_key = label + "_date_raw"
        if raw_key in payload:
            raw = payload.pop(raw_key)
            # Native omitted-start and unbounded-duration sentinels.
            payload[label + "_date"] = None if raw in (0x29C77F8, 43800000) else _readable_game_date(raw)
    return payload


def _rival_event_payload(payload):
    if (not isinstance(payload, dict) or "old_rival" not in payload
            or payload.get("operation") not in {"set", "replace", "remove"}):
        return payload
    payload.pop("count_basis", None)
    has_old_rival = payload.get("old_rival") is not None
    if not has_old_rival:
        payload.pop("old_rival")
    for label in ("before", "after"):
        state = payload.get(label)
        if not isinstance(state, dict):
            continue
        for role in ("target", "old"):
            raw_key = role + "_since_date_raw"
            if raw_key in state:
                raw = state.pop(raw_key)
                state[role + "_since"] = None if raw == -1 else _readable_game_date(raw)
        if not has_old_rival:
            state.pop("old_active", None)
            state.pop("old_since", None)
    return payload


def _country_modifier_fields(fields):
    """Keep each modifier's selected values together, including unknown dates."""
    modifiers = {}
    unavailable = {}
    collection_known = False
    for name, field in fields.items():
        if not isinstance(field, dict) or field.get("status") != "known" or not isinstance(field.get("value"), list):
            unavailable[name] = None
            continue
        collection_known = True
        occurrences = {}
        for entry in field["value"]:
            modifier_id = entry if name == "modifier_id" else entry.get("modifier_id")
            occurrence = occurrences.get(modifier_id, 0)
            occurrences[modifier_id] = occurrence + 1
            row = modifiers.setdefault((modifier_id, occurrence), {"modifier_id": modifier_id})
            if name == "modifier_id":
                continue
            label = name.removeprefix("modifier_")
            if name == "effects":
                row[label] = _concise_value(entry.get("named_effects"))
            elif name in {"modifier_start_date", "modifier_end_date"}:
                row[label] = _readable_game_date(entry.get("value")) if entry.get("status") == "known" else None
            elif name == "target":
                row[label] = _concise_value({key: value for key, value in entry.items() if key != "modifier_id"})
            else:
                row[label] = _concise_value(entry)
    if not modifiers:
        return {"modifiers": [] if collection_known else None}
    unavailable.pop("modifier_id", None)
    for row in modifiers.values():
        row.update({name.removeprefix("modifier_"): value for name, value in unavailable.items()})
    return {"modifiers": list(modifiers.values())}


def _country_relation_fields(fields):
    """Join country-network values by relation identity before unwrapping them."""
    rows = {}
    collection_known = False
    unavailable = {}
    for name, field in fields.items():
        if field.get("status") != "known" or not isinstance(field.get("value"), list):
            unavailable[name] = None
            continue
        collection_known = True
        for entry in field["value"]:
            key = tuple(entry.get(label) for label in ("actor", "partner", "relation_type", "direction"))
            row = rows.setdefault(key, {label: entry[label] for label in
                                       ("partner", "relation_type", "direction") if label in entry})
            # Symmetric relations have no grantor/recipient role.
            if entry.get("status") == "not_applicable":
                continue
            row[name] = _concise_value(entry)
    for row in rows.values():
        row.update(unavailable)
    return {"relations": list(rows.values()) if collection_known else None}


def _pending_matters(field):
    if not isinstance(field, dict) or field.get("status") != "known" or not isinstance(field.get("value"), dict):
        return None
    pending = field["value"]
    request_fields = ("request_id", "action_id", "actor", "recipient", "phase", "status", "review_kind")
    native = _concise_value(pending.get("native_inbound_pending"))
    result = {
        "requests": [{key: request[key] for key in request_fields if key in request}
                     for request in pending.get("journal_requests", [])],
        "proposals": native.get("entries") if isinstance(native, dict) else None,
    }
    pagination = pending.get("pagination", {})
    if pagination.get("has_more"):
        result["next_after_request_id"] = pagination.get("next_after_request_id")
    return result


def _request_event_payload(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
        return _concise_value(payload)
    request = payload["request"]
    result = {key: payload[key] for key in ("actor", "recipient") if key in payload}
    result["request"] = {key: deepcopy(request[key]) for key in
                         ("request_id", "action_id", "status", "game_outcome") if key in request}
    if "result" in request:
        result["request"]["result"] = _concise_value(request["result"])
    return result


def _battle_text(details):
    """Select readable game text from the existing result composition."""
    if not isinstance(details, dict) or details.get("status") != "known":
        return None
    payload = details.get("value")
    if not isinstance(payload, dict):
        return None
    result_text = payload.get('result_text')
    if (isinstance(result_text, dict) and result_text.get('status') == 'known'
            and result_text.get('unknown_section_count') == 0
            and isinstance(result_text.get('text'), str)):
        return result_text['text'] or None
    composition = payload.get("display_composition") or {}
    if composition.get("status") != "known":
        return None
    from .battle_display_composition import project_readable_text
    return project_readable_text(composition, include_unknown=False).get('text') or None


def present_concise(result):
    """Project stored query data into the default LLM response.

    Money is in ducats. Monthly recurring income and expenses describe the
    previous month. Null means no available value. Full evidence remains in
    storage and can be requested with view=full.
    """
    if not isinstance(result, dict) or not isinstance(result.get("items"), list):
        return deepcopy(result)
    items = []
    for item in result["items"]:
        query = item.get("query", {})
        identity = query.get("object", {})
        data = {key: deepcopy(value) for key, value in identity.items()
                if key not in {"type", "session_id"}}
        topic = query.get("topic", item.get("topic"))
        if topic == 'P06':
            data['war_id'] = query.get('parameters', {}).get('peace_context', {}).get('war_id')
        if topic in {"W03", "W04", "R07"} and identity.get("type") == "war" and "war_id" not in data:
            wars = [obj for obj in item.get("objects", []) if obj.get("type") == "war"]
            if len(wars) == 1 and wars[0].get("war_id"):
                data["war_id"] = wars[0]["war_id"]
        if topic == "W01" and any(field.get("reason") == "WAR_SELECTION_REQUIRED"
                                  for field in item.get("fields", {}).values()):
            data["war_candidates"] = [
                {"type": "war", "war_id": obj["war_id"],
                 "actor": obj["actor"], "recipient": obj["recipient"]}
                for obj in item.get("objects", [])
                if obj.get("type") == "war" and obj.get("war_id")
            ]
        fields = (_country_modifier_fields(item.get("fields", {})) if topic in {"N07", "N08"}
                  else project_mission_fields(topic, item.get("fields", {})))
        if fields is None:
            fields = {name: _concise_value(value) for name, value in item.get("fields", {}).items()}
        if topic == "R01" and identity.get("type") == "country":
            fields = _country_relation_fields(item.get("fields", {}))
        if topic == "N05" and "diplomat_tasks" in fields:
            field = item["fields"]["diplomat_tasks"]
            fields["diplomat_tasks"] = concise_diplomat_tasks(
                field.get("value") if field.get("status") == "known" else None)
        if topic == "C01" and "game_date" in fields:
            fields["game_date"] = _readable_game_date(fields["game_date"])
        if topic == 'D04':
            participants = _declare_war_participants(item.get('fields', {}))
            if participants is not None:
                fields = participants
        if topic == "N02":
            limits = fields.get("force_limits") or {}
            for field, label, maximum in (("army_size", "army_regiments", limits.get("land")),
                                          ("navy_size", "navy_ships", limits.get("naval")),
                                          ("manpower", "manpower", fields.get("max_manpower")),
                                          ("sailors", "sailors", fields.get("max_sailors"))):
                if field in fields:
                    fields[label] = _with_range(fields.pop(field), maximum)
            if "army_size" in item.get("fields", {}) and "navy_size" in item.get("fields", {}):
                fields.pop("force_limits", None)
            if "manpower" in item.get("fields", {}):
                fields.pop("max_manpower", None)
            if "sailors" in item.get("fields", {}):
                fields.pop("max_sailors", None)
        if topic == "W03" and "reinforcement_change" in fields:
            fields['force_change'] = fields.pop('reinforcement_change')
        if topic == "W02" and isinstance(fields.get("war_score"), dict):
            score = fields["war_score"]
            fields["war_score"] = {key: score[key] for key in
                                   ("total", "max_score", "mode", "perspective") if key in score}
            if isinstance(score.get("goal"), dict):
                fields["war_score"]["goal"] = {
                    "cumulative": score["goal"].get("cumulative"),
                    "max_score": score.get("overview_goal_cap"),
                }
        if topic == 'R07' and isinstance(fields.get('economic_support'), dict):
            fields['economic_support'] = fields['economic_support'].get('active_payment_obligations')
        if topic == "N03" and type(fields.get("discipline")) in (int, float):
            fields["discipline_percent"] = float(Decimal(str(fields.pop("discipline"))) * 100)
        if topic == "N04":
            for field, maximum, minimum in (("stability", 3, -3), ("war_exhaustion", 20, 0),
                                             ("corruption", 100, 0)):
                if field in fields:
                    fields[field] = _with_range(fields[field], maximum, minimum)
            if "unrest" in fields:
                fields["average_unrest"] = fields.pop("unrest")
            for field in ("overextension", "religious_unity"):
                if field in fields:
                    number = fields.pop(field)
                    fields[field + "_percent"] = float(Decimal(str(number)) * 100) if type(number) in (int, float) else None
        if topic == "N06" and "prestige" in fields:
            fields["prestige"] = _with_range(fields["prestige"], 100, -100)
        if topic == "F04" and "unrest" in fields:
            fields["average_unrest"] = fields.pop("unrest")
        if topic == "F04" and "war_exhaustion" in fields:
            fields["war_exhaustion"] = _with_range(fields["war_exhaustion"], 20, 0)
        if topic == "W04" and "war_exhaustion" in fields:
            exhaustion = fields["war_exhaustion"]
            if isinstance(exhaustion, dict):
                fields["war_exhaustion"] = {
                    side: {country: _with_range(value, 20, 0) for country, value in countries.items()}
                    for side, countries in exhaustion.items()}
            else:
                fields["war_exhaustion"] = _with_range(exhaustion, 20, 0)
        if (topic == "R06" and "ai_attitude" in fields and "relationship_tendency" in fields
                and fields["ai_attitude"] == fields["relationship_tendency"]):
            fields.pop("relationship_tendency")
        if topic == "R05" and isinstance(fields.get("favor_tasks"), dict):
            fields["favor_tasks"] = {"task_active": fields["favor_tasks"].get("task_active")}
        if topic == "G05" and fields.get("country") == [data.get("actor"), data.get("recipient")]:
            fields.pop("country")
        if topic == "R01" and "recipient" in fields and "recipient" in data:
            fields["relation_recipient"] = fields.pop("recipient")
        if topic == "R03" and fields.get("truce_until") is not None:
            date = item["fields"]["truce_until"].get("date")
            if isinstance(date, str):
                fields["truce_until"] = date
        if topic == "S03" and "liberty_desire" in fields:
            fields["liberty_desire"] = _with_range(fields["liberty_desire"], 100, 0)
        if topic == "F04" and isinstance(fields.get("subject_loyalty"), dict):
            pressure = fields["subject_loyalty"]
            if "liberty_desire" in pressure:
                pressure["liberty_desire"] = _with_range(pressure["liberty_desire"], 100, 0)
        if topic == "T03" and "outgoing_value" in fields:
            fields["outgoing_value"] = _trade_outgoing(item["fields"]["outgoing_value"])
        if topic == "B01" and isinstance(fields.get("winner"), dict):
            winner = fields["winner"]
            fields["winner"] = {"countries": winner.get("participants"),
                                "observer_outcome": winner.get("observer_outcome")}
        if topic == "B04" and "details" in fields:
            fields["details"] = _battle_text(item["fields"]["details"])
        if (topic == "C04" and item.get("source", {}).get("name") == "NativeWarDeclarationObservation"
                and isinstance(fields.get("event_payload"), dict)
                and {"attackers", "defenders", "observer_role"} <= fields["event_payload"].keys()):
            fields["event_payload"].pop("participants", None)
            fields["event_payload"].pop("observer_side", None)
        if topic == "C04" and "event_date" in fields:
            fields["event_date"] = _readable_game_date(fields["event_date"])
        if topic == "C04" and "event_payload" in fields:
            raw = item["fields"]["event_payload"]
            if raw.get("status") == "known" and isinstance(raw.get("value"), dict) and "request" in raw["value"]:
                fields["event_payload"] = _request_event_payload(raw["value"])
            fields["event_payload"] = _modifier_event_payload(fields["event_payload"])
            fields["event_payload"] = _rival_event_payload(fields["event_payload"])
        if topic == "C03" and "pending_matters" in fields:
            fields["pending_matters"] = _pending_matters(item["fields"]["pending_matters"])
        if topic == "N01":
            if isinstance(fields.get("loans"), list):
                _loan_dates(fields["loans"], item.get("game_date", result.get("context", {}).get("game_date")))
            recurring = {name: fields.pop("monthly_" + name)
                         for name in ("income", "expenses", "balance")
                         if "monthly_" + name in fields}
            if recurring:
                fields["previous_month_recurring"] = recurring
            if "loan_summary" in fields:
                loans = fields.pop("loan_summary")
                summary = ({"count": loans.get("loan_count"), "principal": loans.get("total_principal")}
                           if isinstance(loans, dict) else loans)
                fields["loan_summary" if "loans" in fields else "loans"] = summary
        data.update(fields)
        if topic in {"F02", "G03", "G06", "W01", "W02", "W03", "T03", "T04", "T05", "R05"}:
            missing = _missing_fields(item.get("fields", {}))
            if missing:
                data["missing_fields"] = missing
        if topic == "B01":
            guidance = next((field["guidance"]["message"] for field in item.get("fields", {}).values()
                             if isinstance(field, dict) and isinstance(field.get("guidance"), dict)
                             and isinstance(field["guidance"].get("message"), str)), None)
            if guidance is not None:
                data["query_guidance"] = guidance
        if topic == 'H02':
            cursors = {name: field['next_cursor'] for name, field in item.get('fields', {}).items()
                       if isinstance(field, dict) and field.get('next_cursor')}
            if cursors:
                data['next_cursor'] = cursors
        items.append(data)
    concise = {"result_id": result.get("result_id"), "items": items}
    if result.get("event") is not None:
        event = result["event"]
        if isinstance(event, dict) and (event.get("event_type") in {"battle_observation", "war_declared"}
                or all(item.get('query', {}).get('topic', item.get('topic')) == 'H02'
                       for item in result['items'])):
            concise["event"] = {key: event[key] for key in (
                "event_id", "event_type", "game_date", "actor", "recipient") if key in event}
        else:
            concise["event"] = _concise_value(event)
        if isinstance(concise["event"], dict) and "game_date" in concise["event"]:
            concise["event"]["game_date"] = _readable_game_date(concise["event"]["game_date"])
        if isinstance(concise["event"], dict) and "payload" in concise["event"]:
            if isinstance(event.get("payload"), dict) and "request" in event["payload"]:
                concise["event"]["payload"] = _request_event_payload(event["payload"])
            concise["event"]["payload"] = _modifier_event_payload(concise["event"]["payload"])
            concise["event"]["payload"] = _rival_event_payload(concise["event"]["payload"])
    return concise


def present_discovery(result, topics=None):
    selected = set(topics) if topics is not None else None
    return {"topics": [
        {"topic_id": topic["topic_id"], "title": topic.get("title"),
         "status": topic.get("status"), "fields": list(topic.get("fields", {})),
         **({"query_guidance": topic["query_guidance"]["message"]} if "query_guidance" in topic else {})}
        for topic in result.get("topics", [])
        if selected is None or topic["topic_id"] in selected
    ]}


def _source_summary(value):
    if isinstance(value, dict):
        return {key: _source_summary(child) for key, child in value.items() if key != "provenance"}
    if isinstance(value, list):
        return [_source_summary(child) for child in value]
    return deepcopy(value)


def present_result(result):
    """Keep every business field and its value, status, units and limitations."""
    if not isinstance(result, dict) or result.get("detail") != "brief":
        return result
    if not isinstance(result.get("items"), list) or not result.get("result_id"):
        return result
    brief = deepcopy(result)
    has_last_known = False
    for item in brief["items"]:
        if not isinstance(item, dict):
            continue
        if "source" in item:
            item["source"] = _source_summary(item["source"])
        fields = item.get("fields", {})
        if isinstance(fields, dict):
            details = fields.get("details", {})
            details_value = details.get("value") if isinstance(details, dict) else None
            composition = details_value.get("display_composition") if isinstance(details_value, dict) else None
            query = item.get("query", {})
            topic = item.get("topic") or (query.get("topic") if isinstance(query, dict) else None)
            if topic == "B04" and isinstance(composition, dict) and composition.get("status") == "known":
                from .battle_display_composition import project_readable_text
                try:
                    battle_text = project_readable_text(composition)
                except (KeyError, TypeError, AttributeError, UnicodeError):
                    battle_text = {"status": "unknown", "reason": "BATTLE_TEXT_PRESENTATION_UNAVAILABLE"}
                item.setdefault("presentation", {})["battle_text"] = battle_text
            for field in fields.values():
                if isinstance(field, dict):
                    field.pop("provenance", None)
                    previous = field.get("last_known")
                    if isinstance(previous, dict) and isinstance(previous.get("field"), dict):
                        has_last_known = True
                        previous["field"].pop("provenance", None)
    brief["presentation"] = {
        "view": "brief",
        "omitted_metadata": ["source.provenance", "fields.*.provenance"],
        "full_result": {"tool": "information_get_result", "arguments": {"result_id": result["result_id"]}},
    }
    if has_last_known:
        brief["presentation"]["omitted_metadata"].append("fields.*.last_known.field.provenance")
    from .battle_brief import project_battle_briefs
    battle_briefs = project_battle_briefs(brief)
    if battle_briefs:
        brief['presentation']['battle_summaries'] = battle_briefs
    from .mission_brief import project_mission_claim_briefs
    mission_briefs = project_mission_claim_briefs(brief)
    if mission_briefs:
        brief['presentation']['mission_claim_summaries'] = mission_briefs
    return brief
