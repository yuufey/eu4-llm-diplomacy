"""Expiry reminders for diplomatic-contact deadlines already observed through A01."""
from copy import deepcopy
import json
import re

from .engine_dates import REFERENCE_RAW, MONTH_LENGTHS, TICKS_PER_DAY, DAYS_PER_YEAR
from .model import digest

EVENT_TYPE = 'cooldown_expired'
SCOPE = 'observed_A01_diplomatic_contact_deadlines'
DATE_SEMANTICS = 'advertised_available_on'
PAGE_SIZE = 128
_MONTHS = {name.lower(): index for index, name in enumerate((
    'January', 'February', 'March', 'April', 'May', 'June', 'July',
    'August', 'September', 'October', 'November', 'December'), 1)}
_TAG = re.compile(r'[A-Z0-9]{3}')
_ENROUTE_PATTERNS = (
    re.compile(
        r'^(?:- )?最近已经派遣过外交官，所以直到(?P<date>\d+年\d+月\d+日)我们才能再次派遣。$',
        re.MULTILINE,
    ),
    re.compile(
        r'^(?:- )?We have recently sent a diplomat, so we cannot send another until '
        r'(?P<date>[^\n]{1,80})\.$',
        re.MULTILINE,
    ),
)


def parse_enroute_cooldown(text):
    """Return the preview-compatible relation cooldown from an ENROUTE tooltip."""
    if not isinstance(text, str):
        return None
    text = re.sub(r'§.', '', text[:4096]).replace('\r\n', '\n')
    for pattern in _ENROUTE_PATTERNS:
        match = pattern.search(text)
        if match:
            return {'blocked': True, 'available_on': match['date']}
    return None


def deadline_raw(text):
    """Invert the existing fixed-365 calendar for the A01 date spellings."""
    if not isinstance(text, str):
        return None
    numeric = re.fullmatch(r'(\d{1,6})[.](\d{1,2})[.](\d{1,2})', text)
    chinese = re.fullmatch(r'(\d{1,6})年(\d{1,2})月(\d{1,2})日', text)
    english = re.fullmatch(r'(\d{1,2}) ([A-Za-z]+) (\d{1,6})', text)
    if numeric or chinese:
        year, month, day = map(int, (numeric or chinese).groups())
    elif english:
        day, name, year = english.groups()
        year, month, day = int(year), _MONTHS.get(name.lower(), 0), int(day)
    else:
        return None
    if not 1 <= month <= 12 or not 1 <= day <= MONTH_LENGTHS[month - 1]:
        return None
    raw = REFERENCE_RAW + (year * DAYS_PER_YEAR + sum(MONTH_LENGTHS[:month - 1]) + day - 1) * TICKS_PER_DAY
    return raw if 0 <= raw <= 2**31 - 1 else None


def _same_scope(first, second):
    return all(first.get(key) == second.get(key)
               for key in ('session_id', 'observer', 'game_version', 'world_id'))


def event_for(context, actor, recipient, end):
    identity = {key: context.get(key) for key in ('session_id', 'observer', 'game_version', 'world_id')}
    identity.update(actor=actor, recipient=recipient, end=end, kind=EVENT_TYPE)
    event = {
        'event_id': 'cooldown-expired:' + digest(identity)[:32], 'event_type': EVENT_TYPE,
        'session_id': context['session_id'], 'observer': context['observer'], 'game_date': end,
        'payload': {'actor': actor, 'recipient': recipient, 'cooldown': 'diplomatic_contact',
                    'available_on_raw': end},
        'objects': [{'type': 'country_pair', 'actor': actor, 'recipient': recipient},
                    {'type': 'country', 'country': actor}, {'type': 'country', 'country': recipient}],
        'complete': True,
        'source': {'name': 'RecordedActionCooldownDeadline', 'mode': context['mode'],
                   'session_id': context['session_id'], 'scope': SCOPE, 'complete': True,
                   'date_semantics': DATE_SEMANTICS, 'basis': 'native_enroute_tooltip'},
    }
    if context.get('world_id') is not None:
        event['world_id'] = context['world_id']
    return event


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    if (context.get('mode') not in ('live', 'recorded')
            or not isinstance(context.get('session_id'), str) or not context['session_id']):
        return False
    payload = event.get('payload')
    source = event.get('source')
    if (not isinstance(payload, dict)
            or set(payload) != {'actor', 'recipient', 'cooldown', 'available_on_raw'}
            or any(not isinstance(payload.get(key), str) or _TAG.fullmatch(payload[key]) is None
                   for key in ('actor', 'recipient'))
            or payload['actor'] == payload['recipient']
            or context.get('observer') not in (payload['actor'], payload['recipient'])
            or payload['cooldown'] != 'diplomatic_contact'
            or type(payload['available_on_raw']) is not int
            or not 0 <= payload['available_on_raw'] <= 2**31 - 1
            or event.get('session_id') != context.get('session_id')
            or event.get('observer') != context.get('observer')
            or event.get('world_id') != context.get('world_id')
            or event.get('complete') is not True or type(event.get('game_date')) is not int
            or not isinstance(source, dict) or source.get('complete') is not True):
        return False
    expected = event_for(context, payload['actor'], payload['recipient'], payload['available_on_raw'])
    return all(event.get(key) == value for key, value in expected.items())


def _observe(result, context, waiting, expired):
    sampled = result.get('context', {})
    if (result.get('event') is not None or sampled.get('status') != 'ready'
            or not _same_scope(sampled, context)):
        return
    for item in result.get('items', []):
        query = item.get('query', {})
        obj = query.get('object', {})
        if (query.get('topic') != 'A01' or obj.get('type') != 'country_pair'
                or query.get('parameters', {}).get('phase', 'initiate') != 'initiate'):
            continue
        actor, recipient = obj.get('actor'), obj.get('recipient')
        if (any(not isinstance(tag, str) or _TAG.fullmatch(tag) is None for tag in (actor, recipient))
                or context['observer'] not in (actor, recipient) or actor == recipient):
            continue
        field = item.get('fields', {}).get('cooldown', {})
        value = field.get('value')
        if field.get('status') != 'known' or not isinstance(value, dict):
            continue
        key = actor + ':' + recipient
        if value.get('blocked') is False and field.get('basis') == 'native_common_action_gate_passed':
            waiting.pop(key, None)
            continue
        if field.get('basis') != 'native_enroute_tooltip' or value.get('blocked') is not True:
            continue
        end = deadline_raw(value.get('available_on'))
        date = item.get('game_date', sampled.get('game_date'))
        collected = sampled.get('game_date')
        if (end is None or type(date) is not int or type(collected) is not int
                or min(date, collected) < 0 or max(date, collected) > context['game_date']
                or end <= date or end <= expired.get(key, -1)):
            continue
        waiting[key] = {'actor': actor, 'recipient': recipient, 'end': end}


def poll(db, owner, context, cursor=None):
    """Read one incremental result page; retain pending deadlines in the event cursor."""
    state = deepcopy(cursor or {'rowid': 0, 'waiting': {}})
    state.setdefault('expired', {})
    if (context.get('status') != 'ready' or type(context.get('game_date')) is not int
            or not isinstance(context.get('session_id'), str) or not context.get('observer')):
        return {'events': [], 'cursor': state, 'complete': False, 'gaps': ['COOLDOWN_EXPIRY_SOURCE_UNAVAILABLE']}
    rows = db.execute('SELECT rowid,body FROM info_results WHERE owner=? AND rowid>? ORDER BY rowid LIMIT ?',
                      (owner, state['rowid'], PAGE_SIZE + 1)).fetchall()
    for row in rows[:PAGE_SIZE]:
        _observe(json.loads(row[1]), context, state['waiting'], state['expired'])
        state['rowid'] = row[0]
    # A later saved observation can renew a deadline. Finish the bounded backlog
    # before declaring an earlier observation due.
    if len(rows) > PAGE_SIZE:
        return {'events': [], 'cursor': state, 'complete': False, 'gaps': ['COOLDOWN_EXPIRY_HISTORY_BACKLOG']}
    events = []
    for key, value in list(state['waiting'].items()):
        if value['end'] <= context['game_date']:
            events.append(event_for(context, value['actor'], value['recipient'], value['end']))
            state['expired'][key] = value['end']
            del state['waiting'][key]
    events.sort(key=lambda event: (event['game_date'], event['event_id']))
    return {'events': events, 'cursor': state, 'complete': True, 'gaps': []}
