"""Associate current flags with accepted promises retained by the event ledger."""
from copy import deepcopy

from .. import land_promise_observation as observation
from .model import digest


def attach_observed_promisors(field, context, history_reader):
    """Add the latest observed sender while retaining the current flag's coverage."""
    result = deepcopy(field)
    proof = {'basis': 'observed_command_same_session_war_and_beneficiary',
             'complete': True, 'gaps': [], 'events': []}
    rows = result['value']
    for row in rows:
        row['observed_promisor'] = None
    if not rows:
        return result, proof
    if not callable(history_reader):
        proof.update(complete=False, gaps=['LAND_PROMISE_HISTORY_READER_NOT_BOUND'])
        return result, proof
    filters = {}
    for key in ('war_id', 'beneficiary'):
        values = {row.get(key) for row in rows}
        if len(values) == 1 and None not in values:
            filters[key] = next(iter(values))
    try:
        batch = history_reader(context, event_types=[observation.EVENT_TYPE], limit=1000,
                               payload_filters=filters)
        if (not isinstance(batch, dict) or not isinstance(batch.get('events'), list)
                or type(batch.get('complete')) is not bool or not isinstance(batch.get('gaps'), list)):
            raise ValueError('LAND_PROMISE_HISTORY_INVALID')
        proof.update(complete=batch['complete'], gaps=deepcopy(batch['gaps']),
                     history_sha256=digest(batch))
        if batch.get('next_cursor'):
            proof['complete'] = False
            proof['gaps'].append('LAND_PROMISE_HISTORY_PAGE_LIMIT')
        latest = {}
        for event in batch['events']:
            if (not observation.valid_event_snapshot(event, context)
                    or type(context.get('game_date')) is not int
                    or event['game_date'] > context['game_date']):
                raise ValueError('LAND_PROMISE_HISTORY_INVALID')
            payload = event['payload']
            key = payload['war_id'], payload['beneficiary']
            order = event['game_date'], event['source']['native_sequence']
            previous = latest.get(key)
            if previous is not None and previous[0] == order and previous[1] != event:
                raise ValueError('LAND_PROMISE_HISTORY_CONFLICT')
            if previous is None or previous[0] < order:
                latest[key] = order, event
        for row in rows:
            observed = latest.get((row.get('war_id'), row['beneficiary']))
            if observed is None:
                continue
            event = observed[1]
            row['observed_promisor'] = event['payload']['promisor']
            proof['events'].append({'event_id': event['event_id'], 'war_id': row['war_id'],
                                    'beneficiary': row['beneficiary'],
                                    'event_date': event['game_date']})
        if any(row['observed_promisor'] is None for row in rows):
            proof['complete'] = False
            proof['gaps'].append('LAND_PROMISE_SENDER_NOT_OBSERVED')
    except Exception:
        for row in rows:
            row['observed_promisor'] = None
        proof.update(complete=False, gaps=['LAND_PROMISE_HISTORY_READ_INVALID'], events=[])
    return result, proof
