"""W04 current land-promise flags through the existing R07 source."""
from copy import deepcopy
import re

from .catalog import get_topic, validate_query
from .model import InformationError, digest
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import _context_reason, _identity


FIELD = 'land_commitment'
_UPSTREAM_FIELD = 'land_commitments'
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_GAPS = ['PRE_CAPTURE_PROMISE_SENDER_UNKNOWN', 'PENDING_CALLS_NOT_INCLUDED']


class NativeWarLandCommitmentsSource:
    event_types = ()

    def __init__(self, commitments_source):
        self.commitments_source = commitments_source

    def context(self):
        return deepcopy(self.commitments_source.context())

    def catalog(self):
        topic = get_topic('W04')
        topic.update(source=type(self).__name__, status='available',
                     object_types=['war', 'country'], observer_roles=['actor'],
                     observer_scope=['FRA'], supported_versions=['1.37.4'],
                     context_scope='country_scope', visibility='visible_scope',
                     triggers=['query', 'periodic', 'change'],
                     change_detection='sampled_selected_beneficiary_or_complete_war_land_flags',
                     change_scope={'fields': [FIELD]},
                     scope_note='FRA当前战争，war按W01选择，country按受益国筛选。')
        topic['fields'] = {FIELD: {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'land_commitments', 'scale': 1, 'period': 'current',
            'supported_object_types': ['war', 'country'],
            'basis': 'existing_R07_current_war_participant_land_flags',
            'paths': ['R07.land_commitments'], 'gaps': list(_GAPS),
            'description': '当前土地标记、本方战争领袖及同战争中已观察的许诺发送方，范围为FRA当前战争。',
        }}
        return [topic]

    @staticmethod
    def _mapped(query):
        return {'topic': 'R07', 'object': deepcopy(query['object']),
                'fields': [_UPSTREAM_FIELD], 'parameters': {}}

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError('invalid_context', 'W04 context must be an object')
        normalized = validate_query(query, context)
        if normalized['topic'] != 'W04':
            raise InformationError('unsupported_topic', 'Land commitments source supports W04 only')
        if normalized['parameters']:
            raise InformationError('invalid_parameters', 'W04 land commitments take no extra parameters')
        obj = normalized['object']
        if obj['type'] == 'war':
            self.commitments_source.validate_query(self._mapped(normalized), context)
        elif obj['type'] == 'country':
            if not isinstance(obj.get('country'), str):
                raise InformationError('invalid_object', 'A beneficiary country is required')
        else:
            raise InformationError('invalid_object', 'Land commitments require a war or country')
        if context is not None and context.get('observer') != 'FRA':
            raise InformationError('observer_scope_mismatch', 'The supported observer is FRA')
        return normalized

    def _read_war(self, query, context):
        upstream = self.commitments_source.read(self._mapped(query), context)
        source = upstream.get('source', {})
        objects = upstream.get('objects')
        obj = query['object']
        if (source.get('name') != 'NativeCommitmentsSource'
                or any(source.get(key) != context.get(key) for key in ('mode', 'observer', 'session_id'))
                or not dates_match(context['game_date'], upstream.get('game_date'))
                or not isinstance(objects, list) or len(objects) != 1
                or not isinstance(objects[0], dict)
                or any(objects[0].get(key) != obj.get(key) for key in ('type', 'actor', 'recipient'))
                or ('war_id' in obj and objects[0].get('war_id') != obj['war_id'])):
            raise ValueError('WAR_LAND_COMMITMENTS_UPSTREAM_IDENTITY_INVALID')
        proof = source.get('provenance', {}).get(_UPSTREAM_FIELD, {})
        return upstream.get('fields', {}).get(_UPSTREAM_FIELD), proof, objects

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        objects = [deepcopy(query['object'])]
        fields = {name: {'status': 'unsupported', 'reason': 'W04_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'delegated_topic': 'R07', 'delegated_field': _UPSTREAM_FIELD,
                      'shared_reader': 'NativeCommitmentsSource', 'read_only': True,
                      'scope': 'FRA_current_wars', 'gaps': list(_GAPS)}
        if FIELD in fields:
            reason = _context_reason(before, 'FRA')
            if context is not None and (_identity(context) != _identity(before)
                    or not dates_match(context.get('game_date'), before.get('game_date'))):
                reason = 'WAR_LAND_COMMITMENTS_CONTEXT_MISMATCH'
            if reason:
                fields[FIELD] = {'status': 'unavailable', 'reason': reason}
            else:
                try:
                    if query['object']['type'] == 'country':
                        field, proof = self.commitments_source.read_land_for_country(
                            query['object']['country'], before)
                    else:
                        field, proof, objects = self._read_war(query, before)
                    if not isinstance(field, dict) or not isinstance(field.get('status'), str):
                        raise ValueError('WAR_LAND_COMMITMENTS_UPSTREAM_FIELD_INVALID')
                    if field['status'] == 'known':
                        capture_hash = proof.get('capture_report_sha256')
                        if not isinstance(capture_hash, str) or _SHA.fullmatch(capture_hash) is None:
                            raise ValueError('WAR_LAND_COMMITMENTS_UPSTREAM_EVIDENCE_MISSING')
                        if not isinstance(field.get('value'), list):
                            raise ValueError('WAR_LAND_COMMITMENTS_UPSTREAM_VALUE_INVALID')
                        if query['object']['type'] == 'war':
                            selected = objects[0].get('war_id')
                            if (not isinstance(selected, str) or not selected
                                    or any(row.get('war_id') != selected for row in field['value'])):
                                raise ValueError('WAR_LAND_COMMITMENTS_WAR_ID_MISMATCH')
                        elif any(row.get('beneficiary') != query['object']['country']
                                 for row in field['value']):
                            raise ValueError('WAR_LAND_COMMITMENTS_BENEFICIARY_MISMATCH')
                    projected = deepcopy(field)
                    projected.pop('raw_inputs', None)
                    projected.update(unit='land_commitments', scale=1, period='current')
                    fields[FIELD] = projected
                    provenance['land_commitments'] = deepcopy(proof)
                except Exception:
                    fields[FIELD] = {'status': 'unknown', 'reason': 'WAR_LAND_COMMITMENTS_UPSTREAM_READ_INVALID'}
            after = self.context()
            if (_identity(after) != _identity(before)
                    or not dates_match(before.get('game_date'), after.get('game_date'))):
                fields[FIELD] = {'status': 'unavailable', 'reason': 'WAR_LAND_COMMITMENTS_CONTEXT_CHANGED_DURING_READ'}
        complete = all(field.get('status') == 'known' and field.get('complete') is True
                       for field in fields.values())
        source = _source_info(type(self).__name__, before, complete=complete, provenance=provenance)
        source['context_scope'] = query['object']['type']
        return _result(query, before, fields, complete, source, objects)

    def change_comparison(self, query, sample, context):
        field = sample.get('fields', {}).get(FIELD, {})
        source = sample.get('source', {})
        proof = source.get('provenance', {}).get('land_commitments', {})
        capture_hash = proof.get('capture_report_sha256')
        if (query.get('topic') != 'W04' or query.get('fields') != [FIELD]
                or set(sample.get('fields', {})) != {FIELD}
                or field.get('status') != 'known'
                or (query.get('object', {}).get('type') == 'war' and field.get('complete') is not True)
                or source.get('name') != type(self).__name__
                or source.get('session_id') != context.get('session_id')
                or not isinstance(capture_hash, str) or _SHA.fullmatch(capture_hash) is None
                or _context_reason(context, 'FRA')):
            return None
        return {'schema': 'information.change_comparison.v1',
                'scope': 'W04.current_land_commitments.' + digest({
                    'query': query, 'objects': sample.get('objects')}),
                'fields': deepcopy(sample['fields'])}

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
