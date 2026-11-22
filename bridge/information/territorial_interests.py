"""Public interest-map categories for a selected country pair and provinces."""
from copy import deepcopy
from functools import partial
import json
import re
import time
import uuid

from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner
from .model import InformationError
from .observation_time import context_identity, dates_match
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _session_binding


SCHEMA = 'information.territorial_interest_admission.v1'
CAPABILITY = 'native_territorial_interest_query'
_WIRE = CAPABILITY + '_wire'
_CONTEXT_KEYS = ('status', 'mode', 'complete', 'observer', 'session_id', 'world_id',
                 'game_version', 'game_sha256', 'dll_sha256')
FIELDS = ('country', 'interests', 'conflicts', 'visibility')
_TAG = re.compile(r'[A-Z0-9]{3}\Z')


def _observe(reader, base, country, profile, *, observer):
    def backend(read, module_base, target):
        return _countries.read_two_pass(read, module_base, observer, [target],
            fields=['G05.country'], admission_reader=_owner._bound_admission,
            read_fields=lambda read, base, binding, fields: {
                'G05.country': {'status': 'known', 'value': target}})
    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation, country, observer):
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=_owner.PROFILE_SHA256, load_profile=_owner._load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(report, context, creation, country,
        schema=SCHEMA, profile_sha256=_owner.PROFILE_SHA256,
        load_profile=_owner._load_profile, observe=partial(_observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True)


def _valid_response(event, actor, recipient, observer, ids, date):
    if (not isinstance(event, dict) or event.get('event') != CAPABILITY
            or event.get('actor') != actor or event.get('recipient') != recipient
            or event.get('observer') != observer or event.get('submitted') is not False
            or type(event.get('date_raw')) is not int or event['date_raw'] != date
            or type(event.get('frame_thread')) is not int or event['frame_thread'] <= 0):
        return False
    rows = event.get('provinces')
    if not isinstance(rows, list) or len(rows) != len(ids):
        return False
    return all(isinstance(row, dict) and type(row.get('province_id')) is int
        and row['province_id'] == province and type(row.get('visible')) is bool
        and row.get('actor') in ('vital', 'strategic', 'none', 'unknown')
        and row.get('recipient') in ('vital', 'strategic', 'none', 'unknown')
        for province, row in zip(ids, rows))


def query_native(session, actor, recipient, ids, *, observer):
    """Use the existing exclusive query channel and its atomic publisher."""
    acknowledgement = session._installation_ack() or {}
    if acknowledgement.get(CAPABILITY) is not True:
        return {'error_code': 'QUERY_INTEREST_CAPABILITY_MISSING'}
    wire_version = acknowledgement.get(_WIRE, 23)
    if type(wire_version) is not int or wire_version not in (23, 24):
        return {'error_code': 'QUERY_INTEREST_WIRE_UNSUPPORTED'}
    if wire_version == 23 and observer != 'FRA':
        return {'error_code': 'QUERY_INTEREST_OBSERVER_WIRE_REQUIRED'}
    health = session.health()
    if health.get('status') != 'ready':
        return {'error_code': 'QUERY_SESSION_UNREADY'}
    query_id = 'interests_' + uuid.uuid4().hex
    expiry = time.time_ns() // 100 + 116444736000000000 + 30 * 10000000
    scope_argument = f' {observer}' if wire_version == 24 else ''
    wire = (f"EU4DIP_QUERY{wire_version} {session.record['creation_filetime']:x} {query_id} "
            f"territorial_interests {actor} {recipient}{scope_argument} {health['date_raw']} {expiry} "
            f"{','.join(str(province) for province in ids)}\n")
    log = session.directory / 'control-probe.jsonl'
    offset = log.stat().st_size
    published = session._publish_atomic_request(wire, query_id, 'diplomacy-query.request')
    if published != 'published':
        return {'error_code': 'QUERY_CHANNEL_BUSY' if published == 'busy' else 'QUERY_CHANNEL_WRITE_FAILED'}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with log.open('rb') as stream:
            if log.stat().st_size < offset:
                return {'error_code': 'QUERY_LOG_TRUNCATED'}
            stream.seek(offset)
            data = stream.read(262144)
        complete = data.rfind(b'\n')
        if complete >= 0:
            offset += complete + 1
            for line in data[:complete + 1].splitlines():
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if (not isinstance(event, dict) or event.get('query_id') != query_id
                        or event.get('session_id') != session.session_id):
                    continue
                if event.get('event') == 'native_alliance_inspection_failed':
                    return {'error_code': event.get('reason_code', 'QUERY_INTEREST_FAILED')}
                if _valid_response(event, actor, recipient, observer, ids, health['date_raw']):
                    return event
        time.sleep(0.05)
    return {'error_code': 'QUERY_TIMEOUT'}


def project(event):
    countries = [event['actor'], event['recipient']]
    interests = {country: {'vital': [], 'strategic': []} for country in countries}
    conflicts, visible, hidden, unavailable = [], [], [], []
    for row in event['provinces']:
        province = row['province_id']
        if not row['visible']:
            hidden.append(province)
            continue
        visible.append(province)
        if row['actor'] == 'unknown' or row['recipient'] == 'unknown':
            unavailable.append(province)
            continue
        for role, country in zip(('actor', 'recipient'), countries):
            if row[role] != 'none':
                interests[country][row[role]].append(province)
        if row['actor'] != 'none' and row['recipient'] != 'none':
            conflicts.append(province)
    visibility = {'visible': visible, 'hidden': hidden}
    if unavailable:
        visibility['unavailable'] = unavailable
    return {'country': {'status': 'known', 'value': countries},
        'interests': {'status': 'known', 'value': interests, 'complete': not (hidden or unavailable)},
        'conflicts': {'status': 'known', 'value': conflicts, 'complete': not (hidden or unavailable)},
        'visibility': {'status': 'known', 'value': visibility}}


class NativeTerritorialInterestsSource(NativeTradeIncomeSource):
    def __init__(self, base_source, *, capture=None, native_query=None):
        super().__init__(base_source, capture=capture)
        self.native_query = native_query or query_native

    def catalog(self):
        return [{'topic_id': 'G05', 'catalog_ids': ['G05'], 'title': '公开领土兴趣',
            'status': 'available', 'fields': {name: {'coverage': 'available', 'complete': True,
                'period': 'current', 'source': __name__, 'description': description}
                for name, description in zip(FIELDS, (
                    '所选国家对', '所选省份中的重要及战略利益',
                    '双方均有公开兴趣的候选省份', '候选省份的已发现与未发现列表'))},
            'object_types': ['country_pair', 'province'], 'observer_scope': [],
            'observer_roles': [], 'context_scope': 'visible_scope', 'visibility': 'visible_scope',
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'parameters': {'type': 'object', 'properties': {
                'province_ids': {'type': 'array', 'minItems': 1, 'maxItems': 32,
                    'uniqueItems': True, 'items': {'type': 'integer', 'minimum': 1, 'maximum': 65535}},
                'country': {'type': 'string', 'pattern': '^[A-Z0-9]{3}$'}},
                'additionalProperties': False,
                'oneOf': [{'required': ['province_ids']}, {'required': ['country']}]},
            'source': type(self).__name__}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'G05'
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected a G05 query')
        if context is None:
            context = self.context()
        observer = context.get('observer') if isinstance(context, dict) else None
        if not isinstance(observer, str) or not _TAG.fullmatch(observer):
            raise InformationError('observer_scope_mismatch', 'G05 requires a configured observer country')
        obj, params, fields = query.get('object'), query.get('parameters', {}), query.get('fields')
        if not isinstance(obj, dict) or not isinstance(params, dict):
            raise InformationError('invalid_object', 'G05 requires a country pair or province')
        if obj.get('type') == 'country_pair':
            tags = [obj.get('actor'), obj.get('recipient')]
            valid = set(obj) == {'type', 'actor', 'recipient'} and set(params) == {'province_ids'}
            ids = params.get('province_ids')
        elif obj.get('type') == 'province':
            tags = [observer, params.get('country')]
            valid = set(obj) == {'type', 'province_id'} and set(params) == {'country'}
            ids = [obj.get('province_id')]
        else:
            raise InformationError('invalid_object', 'G05 requires a country pair or province')
        if (not valid or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) for tag in tags)
                or tags[0] == tags[1]
                or not isinstance(ids, list) or not 1 <= len(ids) <= 32
                or any(type(province) is not int or not 1 <= province <= 65535 for province in ids)
                or len(set(ids)) != len(ids)):
            raise InformationError('invalid_parameters', 'G05 requires two distinct countries and 1–32 unique province IDs')
        if observer not in tags:
            raise InformationError('observer_scope_mismatch', 'The G05 country pair must include the configured observer')
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in FIELDS for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Unsupported G05 fields')
        return deepcopy(query) | {'parameters': deepcopy(params)}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        obj, params = query['object'], query['parameters']
        observer = current['observer']
        actor, recipient = ((obj['actor'], obj['recipient']) if obj['type'] == 'country_pair'
                            else (observer, params['country']))
        ids = params['province_ids'] if obj['type'] == 'country_pair' else [obj['province_id']]
        country = recipient if actor == observer else actor
        invoked = False

        def result(fields, complete=False):
            return _result(query, current, fields, complete,
                _source_info(type(self).__name__, current, complete=complete, provenance={
                    'basis': 'native_public_interest_map_predicates', 'read_only': True,
                    'native_function_invoked': invoked, 'observer_scope': observer, 'province_ids': ids}))

        def failure(reason):
            return result({name: {'status': 'unknown', 'reason': reason} for name in query['fields']})

        installation, creation, reason = _session_binding(self.base_source)
        reason = reason or _observer_context_reason(current)
        if reason:
            return failure(reason)
        try:
            report = (self.capture or capture)(installation, country, observer)
            if not validate_capture(report, current, creation, country):
                return failure('INTEREST_ADMISSION_CAPTURE_INVALID')
            admitted = report['observation']['backend']['targets'][0]['fields']['G05.country']
            if admitted.get('status') != 'known':
                return result({name: deepcopy(admitted) for name in query['fields']})
            session = getattr(getattr(self.base_source, 'diplomacy_tools', None), 'session', None)
            if session is None:
                return failure('INTEREST_NATIVE_SESSION_UNAVAILABLE')
            invoked = True
            event = self.native_query(session, actor, recipient, ids, observer=observer)
            if not isinstance(event, dict):
                return failure('INTEREST_NATIVE_RESULT_INVALID')
            date = event.get('date_raw')
            if not _valid_response(event, actor, recipient, observer, ids, date):
                return failure(event.get('error_code', 'INTEREST_NATIVE_RESULT_INVALID'))
            after = self.context()
            if (context_identity(current, _CONTEXT_KEYS) != context_identity(after, _CONTEXT_KEYS)
                    or not dates_match(current.get('game_date'), date, after.get('game_date'))):
                return failure('INTEREST_CONTEXT_CHANGED')
            values = project(event)
            selected = {name: values[name] for name in query['fields']}
            return result(selected, all(field.get('complete', True) for field in selected.values()))
        except Exception:
            return failure('INTEREST_CAPTURE_FAILED')
