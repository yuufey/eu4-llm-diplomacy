"""Compare observed national force sizes using the existing result history."""
from copy import deepcopy
import json

from .engine_dates import project_engine_date


def previous_force_sample(database, owner, context, obj):
    """Read one matching sample without loading the stored result bodies."""
    if type(context.get('game_date')) is not int or not context.get('session_id'):
        return None
    identity_keys = ('mode', 'session_id', 'observer', 'game_version', 'world_id')
    identity_sql = ' AND '.join(
        "json_extract(r.body, '$.context." + key + "') IS ?" for key in identity_keys)
    if obj['type'] == 'country':
        object_sql = "json_extract(i.value, '$.query.object.country')=?"
        selected = obj['country']
    else:
        object_sql = ("COALESCE(json_extract(i.value, '$.objects[0].war_id'), "
                      "json_extract(i.value, '$.query.object.war_id'))=?")
        selected = obj['war_id']
    row = database.execute(
        "SELECT r.id, json_extract(r.body, '$.context'), "
        "COALESCE(json_extract(i.value, '$.force_snapshot'), "
        "json_extract(i.value, '$.fields.current_forces')) "
        "FROM info_results r, json_each(r.body, '$.items') i "
        "WHERE r.owner=? AND " + identity_sql +
        " AND json_extract(r.body, '$.context.status')='ready'"
        " AND json_extract(r.body, '$.context.game_date')<=?"
        " AND json_extract(r.body, '$.event') IS NULL"
        " AND json_extract(i.value, '$.query.topic')='W03'"
        " AND json_extract(i.value, '$.query.object.type')=? AND " + object_sql +
        " AND COALESCE(json_extract(i.value, '$.force_snapshot.status'), "
        "json_extract(i.value, '$.fields.current_forces.status'))='known' "
        "ORDER BY r.rowid DESC LIMIT 1",
        (owner, *(context.get(key) for key in identity_keys), context['game_date'],
         obj['type'], selected)).fetchone()
    if row is None:
        return None
    return {'result_id': row[0], 'context': json.loads(row[1]), 'field': json.loads(row[2])}


def _difference(current, previous):
    """Only subtract known values with the same metric name and structure."""
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return {'status': 'unknown', 'reason': 'FORCE_COMPARISON_VALUE_MISSING'}
    if 'status' in current:
        if current.get('status') != 'known':
            return deepcopy(current)
        if previous.get('status') != 'known':
            return {'status': 'unknown', 'reason': 'FORCE_COMPARISON_VALUE_MISSING'}
        now, before = current.get('value'), previous.get('value')
        if type(now) in (int, float) and type(before) in (int, float):
            return {'status': 'known', 'value': now - before}
        value = _difference(now, before)
        if 'status' in value:
            return value
        complete = (current.get('complete', True) and previous.get('complete', True)
                    and all(_complete(child) for child in value.values()))
        return {'status': 'known', 'value': value, 'complete': complete}
    return {name: _difference(value, previous.get(name)) for name, value in current.items()}


def _complete(value):
    if value.get('status') == 'known':
        return value.get('complete', True)
    return 'status' not in value and all(_complete(child) for child in value.values())


def project_force_change(current, previous, context):
    if not isinstance(current, dict):
        return {'status': 'unknown', 'reason': 'CURRENT_FORCES_UNAVAILABLE'}
    if current.get('status') != 'known':
        return deepcopy(current)
    if previous is None:
        return {'status': 'unknown', 'reason': 'FORCE_COMPARISON_BASELINE_MISSING'}
    change = _difference(current, previous['field'])
    if change.get('status') != 'known':
        return change
    return {'status': 'known', 'complete': change.get('complete', True), 'value': {
        'from_date': project_engine_date(previous['context']['game_date'])['date'],
        'to_date': project_engine_date(context['game_date'])['date'],
        'net_change': change['value']}, 'baseline_result_id': previous['result_id']}
