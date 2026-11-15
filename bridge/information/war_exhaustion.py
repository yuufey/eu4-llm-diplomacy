"""Reuse current country pressure readers for W04 countries and war participants."""
from __future__ import annotations

from copy import deepcopy
import re

from ..war_participants import project_war_participants
from .catalog import get_topic, validate_query
from .domestic_pressure import _identity_snapshot
from .model import InformationError
from .observation_time import dates_match
from .sources import _result, _source_info

FIELD = 'war_exhaustion'
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_HEX = re.compile(r'[0-9a-fA-F]{8}\Z')
_STATES = {'unknown', 'unavailable', 'invisible', 'not_applicable', 'stale', 'unsupported'}


def _identity(context):
    return (*_identity_snapshot(context), context.get('dll_sha256'),
            context.get('world_generation'), context.get('physical_client_country'))


class NativeWarExhaustionSource:
    event_types = ()

    def __init__(self, domestic_pressure_source, foreign_pressure_source=None, base_source=None):
        self.domestic_pressure_source = domestic_pressure_source
        self.foreign_pressure_source = foreign_pressure_source
        self.base_source = base_source

    def context(self):
        return deepcopy(self.domestic_pressure_source.context())

    def catalog(self):
        topic = get_topic('W04')
        topic.update(source=type(self).__name__, status='available',
                     supported_versions=['1.37.4'], context_scope='country_scope',
                     visibility='country_scope', observer_roles=['country'], observer_scope=['FRA'],
                     triggers=['query', 'periodic', 'change'],
                     change_detection='sampled_state_comparison_not_lossless_events',
                     object_semantics='country_wide_value_independent_of_individual_war')
        topic['fields'] = {FIELD: {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'war_exhaustion', 'scale': 1000, 'period': 'current',
            'supported_object_types': ['country'], 'supported_countries': ['FRA'],
            'basis': 'verified_N04_current_country_war_exhaustion',
            'value_origin': 'delegated_native_domestic_pressure_field',
            'description': '观察国当前厌战值，复用N04同一读器；不是单场战争贡献或退出风险。',
            'paths': ['NativeDomesticPressureSource.read(N04).fields.war_exhaustion'],
            'gaps': ['WAR_PARTICIPANT_VIEW_NOT_IMPLEMENTED', 'OTHER_W04_FIELDS_NOT_IMPLEMENTED'],
        }}
        if self.foreign_pressure_source is not None:
            topic.update(context_scope='visible_scope', visibility='visible_scope', observer_roles=['actor'])
            field = topic['fields'][FIELD]
            field.update(coverage='available', complete=True,
                         supported_object_types=['country', 'war'] if self.base_source is not None else ['country'],
                         basis='existing_N04_and_F04_current_country_war_exhaustion',
                         description='所选国家或战争双方参战国的当前国家厌战值，范围0到20',
                         gaps=[])
            field.pop('supported_countries', None)
            topic['object_semantics'] = 'current_national_values_grouped_by_selected_war_side'
        return [topic]

    @staticmethod
    def _mapped(query):
        return {'topic': 'N04', 'object': deepcopy(query['object']),
                'fields': [FIELD], 'parameters': {}}

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError('invalid_context', 'W04 context must be an object')
        normalized = validate_query(query, context)
        if normalized['topic'] != 'W04':
            raise InformationError('unsupported_topic', 'War exhaustion source supports W04 only')
        if normalized['object']['type'] == 'country':
            # Validation does not acquire the capture, including for a query
            # containing only planned W04 fields.
            if (normalized['object']['country'] == 'FRA'
                    or self.foreign_pressure_source is None):
                self.domestic_pressure_source.validate_query(self._mapped(normalized), context)
            else:
                mapped = dict(self._mapped(normalized), topic='F04')
                self.foreign_pressure_source.validate_query(mapped, context)
        elif self.base_source is not None:
            obj = normalized['object']
            if obj.get('actor') != 'FRA' or obj.get('recipient') == 'FRA':
                raise InformationError('invalid_object', 'W04 war requires FRA and an opposing country')
        return normalized

    def _foreign_country(self, query, context):
        mapped = dict(self._mapped(query), topic='F04')
        try:
            upstream = self.foreign_pressure_source.read(mapped, context)
            source = upstream['source']
            if (source.get('observer') != context.get('observer')
                    or source.get('session_id') != context.get('session_id')
                    or upstream['objects'] != [query['object']]
                    or not dates_match(context.get('game_date'), upstream.get('game_date'))):
                raise ValueError('WAR_EXHAUSTION_UPSTREAM_IDENTITY_INVALID')
            field = self._project(upstream['fields'][FIELD])
            if field['status'] == 'known':
                field['complete'] = upstream.get('complete') is True
            return field
        except Exception:
            return {'status': 'unavailable', 'reason': 'WAR_EXHAUSTION_UPSTREAM_READ_INVALID'}

    def _war(self, query, context):
        objects = [deepcopy(query['object'])]
        try:
            discovery = self.base_source.read({
                'topic': 'W01', 'object': deepcopy(query['object']),
                'fields': ['war_id', 'participants'], 'parameters': {}}, context)
            identity = discovery['fields']['war_id']
            participants = discovery['fields']['participants']
            if identity.get('status') != 'known' or participants.get('status') != 'known':
                field = identity if identity.get('status') != 'known' else participants
                return deepcopy(field), objects
            members = project_war_participants(
                participants['value'], query['object']['actor'], query['object']['recipient'])
            if members is None or members['status'] != 'available':
                raise ValueError('WAR_PARTICIPANTS_UNAVAILABLE')
            objects = [dict(query['object'], war_id=identity['value'])]
        except Exception:
            return {'status': 'unknown', 'reason': 'WAR_DISCOVERY_FAILED'}, objects
        sides = {'our_side': members[members['actor_side']],
                 'opposing_side': members[members['recipient_side']]}
        countries = list(dict.fromkeys(country for side in sides.values() for country in side))
        batch_reader = getattr(self.foreign_pressure_source, 'read_war_exhaustion_batch', None)
        foreign = [country for country in countries if country != 'FRA']
        foreign_values = None
        if callable(batch_reader):
            try:
                foreign_values = batch_reader(foreign, context)
            except Exception:
                foreign_values = None
        values = {}
        for side, countries in sides.items():
            values[side] = {}
            for country in countries:
                if country != 'FRA' and foreign_values is not None:
                    try:
                        field = self._project(foreign_values[country])
                        if field['status'] == 'known':
                            field['complete'] = foreign_values[country].get('complete', True)
                        values[side][country] = field
                    except Exception:
                        values[side][country] = {'status': 'unavailable', 'reason': 'WAR_EXHAUSTION_UPSTREAM_READ_INVALID'}
                    continue
                mapped = {'topic': 'W04', 'object': {'type': 'country', 'country': country},
                          'fields': [FIELD], 'parameters': {}}
                sample = self.read(mapped, context)
                values[side][country] = sample['fields'][FIELD]
        complete = all(field.get('status') == 'known' and field.get('complete', True)
                       for side in values.values() for field in side.values())
        return {'status': 'known', 'value': values, 'complete': complete}, objects

    @staticmethod
    def _project(field):
        if not isinstance(field, dict):
            raise ValueError('WAR_EXHAUSTION_UPSTREAM_FIELD_INVALID')
        status = field.get('status')
        if status != 'known':
            reason = field.get('reason')
            if (status not in _STATES or not isinstance(reason, str) or not 1 <= len(reason) <= 256
                    or any(ord(char) < 32 for char in reason)):
                raise ValueError('WAR_EXHAUSTION_UPSTREAM_STATE_INVALID')
            return {'status': status, 'reason': reason}
        raw, raw_hex = field.get('raw'), field.get('raw_hex')
        if (type(raw) is not int or not -(1 << 31) <= raw < (1 << 31)
                or type(field.get('value')) is not int or field['value'] != raw
                or not isinstance(raw_hex, str) or _HEX.fullmatch(raw_hex) is None
                or int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) != raw
                or field.get('unit') != 'war_exhaustion'
                or type(field.get('scale')) is not int or field['scale'] != 1000):
            raise ValueError('WAR_EXHAUSTION_UPSTREAM_VALUE_INVALID')
        return {'status': 'known', 'value': raw, 'raw': raw, 'raw_hex': raw_hex.lower(),
                'unit': 'war_exhaustion', 'scale': 1000, 'period': 'current', 'complete': True}

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        objects = [deepcopy(query['object'])]
        fields = {name: {'status': 'unsupported', 'reason': 'W04_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'delegated_topic': 'N04', 'delegated_field': FIELD,
                      'shared_reader': 'NativeDomesticPressureSource',
                      'read_only': True, 'war_specific_value': False}
        if FIELD in fields:
            if context is not None and _identity(context) != _identity(before):
                fields[FIELD] = {'status': 'unavailable', 'reason': 'WAR_EXHAUSTION_CONTEXT_MISMATCH'}
            elif (query['object']['type'] == 'war' and self.base_source is not None
                    and self.foreign_pressure_source is not None):
                fields[FIELD], objects = self._war(query, before)
                provenance.update(delegated_topic=['W01', 'N04', 'F04'],
                                  participants_source='W01.native_war_side_vectors')
            elif query['object']['type'] != 'country':
                fields[FIELD] = {'status': 'unsupported',
                                 'reason': 'WAR_PARTICIPANT_WAR_EXHAUSTION_NOT_IMPLEMENTED'}
            elif query['object']['country'] != 'FRA':
                fields[FIELD] = self._foreign_country(query, before)
                provenance.update(delegated_topic='F04', shared_reader='NativeForeignPressureSource')
            else:
                try:
                    upstream = self.domestic_pressure_source.read(self._mapped(query), context)
                    source = upstream.get('source')
                    if (not isinstance(source, dict) or source.get('name') != 'NativeDomesticPressureSource'
                            or source.get('mode') != before.get('mode')
                            or source.get('observer') != before.get('observer')
                            or source.get('session_id') != before.get('session_id')
                            or not dates_match(before.get('game_date'), upstream.get('game_date'))
                            or upstream.get('objects') != [query['object']]):
                        raise ValueError('WAR_EXHAUSTION_UPSTREAM_IDENTITY_INVALID')
                    projected = self._project(upstream.get('fields', {}).get(FIELD))
                    upstream_provenance = source.get('provenance', {})
                    report_hash = upstream_provenance.get('capture_report_sha256')
                    if projected['status'] == 'known':
                        projected['complete'] = upstream.get('complete') is True
                        if not isinstance(report_hash, str) or _SHA.fullmatch(report_hash) is None:
                            raise ValueError('WAR_EXHAUSTION_UPSTREAM_EVIDENCE_MISSING')
                        provenance['capture_report_sha256'] = report_hash
                    provenance['upstream_source'] = {key: deepcopy(source.get(key)) for key in
                                                     ('name', 'mode', 'status', 'session_id', 'observer', 'complete')}
                    fields[FIELD] = projected
                except Exception:
                    fields[FIELD] = {'status': 'unavailable', 'reason': 'WAR_EXHAUSTION_UPSTREAM_READ_INVALID'}
        if FIELD in fields and _identity(self.context()) != _identity(before):
            fields[FIELD] = {'status': 'unavailable', 'reason': 'WAR_EXHAUSTION_CONTEXT_CHANGED_DURING_READ'}
        complete = all(item.get('status') == 'known' and item.get('complete') is True
                       for item in fields.values())
        source = _source_info(type(self).__name__, before, complete=complete, provenance=provenance)
        source['context_scope'] = 'visible_scope' if self.foreign_pressure_source is not None else 'country_scope'
        return _result(query, before, fields, complete, source, objects)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['NativeWarExhaustionSource']
