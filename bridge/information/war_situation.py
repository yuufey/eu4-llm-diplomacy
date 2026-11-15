"""W03 national summaries and selected-war participant summaries."""
from copy import deepcopy

from ..war_participants import project_war_participants
from . import war_state_capture as _capture
from .catalog import validate_query
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _context_reason, _session_binding
from .war_force_change import project_force_change


FIELDS = (*_capture.FIELDS, 'reinforcement_change')


class NativeWarSituationSource(NativeTradeIncomeSource):
    def __init__(self, base_source, territory_source, forces_source, *, capture=None, force_history=None):
        super().__init__(base_source, capture=capture)
        self.territory_source = territory_source
        self.forces_source = forces_source
        self.force_history = force_history

    def catalog(self):
        territory = self.territory_source.catalog()[0]
        forces = self.forces_source.catalog()[0]
        topic = deepcopy(territory)
        topic.update(object_types=['country', 'war'], source=type(self).__name__)
        topic['fields'].update(deepcopy(forces['fields']))
        for field in topic['fields'].values():
            field['object_types'] = ['country', 'war']
            field['source'] = type(self).__name__
        topic['fields']['occupations']['description'] = '所选国家或战争双方成员的受占领省份及控制国汇总'
        topic['fields']['blockades']['description'] = '所选国家或战争双方成员的受封锁省份数量'
        topic['fields']['current_forces']['description'] = (
            '国家视图沿用N02/F02规模，战争视图提供双方成员的可见士兵数及舰船数')
        topic['fields']['reinforcement_change'] = dict(topic['fields']['current_forces'],
            description='与上次同国或同一战争观测相比的军力净变化，包含损失、新建、解散和补充等影响')
        topic['scope_note'] = 'war对象使用actor=FRA和recipient选择战争，可提供war_id；双方汇总成员的当前全国状态'
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'W03' or any(field not in FIELDS for field in normalized['fields']):
            raise InformationError('invalid_fields', 'Unsupported W03 situation fields')
        obj = normalized['object']
        if obj['type'] not in ('country', 'war'):
            raise InformationError('invalid_object', 'W03 situation requires a country or war')
        if (obj['type'] == 'war' and (obj.get('actor') != 'FRA'
                or not isinstance(obj.get('recipient'), str) or obj['recipient'] == 'FRA')):
            raise InformationError('invalid_object', 'W03 war requires actor FRA and an opposing recipient')
        if normalized['parameters']:
            raise InformationError('invalid_parameters', 'W03 situation has no extra parameters')
        if context is not None and (not isinstance(context, dict) or context.get('observer') != 'FRA'):
            raise InformationError('observer_scope_mismatch', 'The supported observer is FRA')
        return normalized

    def _country(self, query, context):
        fields = {}
        for source in (self.territory_source, self.forces_source):
            owned = source.catalog()[0]['fields']
            selected = [name for name in query['fields'] if name in owned]
            if not selected:
                continue
            try:
                sample = source.read(dict(query, fields=selected), context)
                fields.update({name: deepcopy(sample['fields'][name]) for name in selected})
            except Exception:
                fields.update({name: {'status': 'unknown', 'reason': 'WAR_COUNTRY_STATE_UNAVAILABLE'}
                               for name in selected})
        complete = all(field.get('status') == 'known' and field.get('complete', True)
                       for field in fields.values())
        return _result(query, context, fields, complete,
            _source_info(type(self).__name__, context, complete=complete, provenance={
                'basis': 'existing_national_territory_and_force_summaries', 'read_only': True}))

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        selected = query['fields']
        needs_change = 'reinforcement_change' in selected
        capture_fields = [name for name in selected if name != 'reinforcement_change']
        if needs_change and 'current_forces' not in capture_fields:
            capture_fields.append('current_forces')
        sample = self._read_current(dict(query, fields=capture_fields), current)
        forces = sample['fields'].get('current_forces')
        if needs_change:
            obj = sample['objects'][0]
            previous = None
            if self.force_history is not None and (obj['type'] == 'country' or obj.get('war_id')):
                previous = self.force_history(current, obj)
            sample['fields']['reinforcement_change'] = project_force_change(forces, previous, current)
            sample['force_snapshot'] = deepcopy(forces)
        sample['fields'] = {name: sample['fields'][name] for name in selected}
        sample['query'] = query
        sample['complete'] = all(field.get('status') in ('known', 'not_applicable')
                                 and field.get('complete', True) for field in sample['fields'].values())
        return sample

    def _read_current(self, query, current):
        if query['object']['type'] == 'country':
            return self._country(query, current)
        objects = [deepcopy(query['object'])]
        discovery_query_id = None

        def finish(fields, complete=False):
            return _result(query, current, fields, complete,
                _source_info(type(self).__name__, current, complete=complete, provenance={
                    'basis': 'national_states_of_selected_war_participants',
                    'participants_source': 'W01.native_war_side_vectors', 'read_only': True,
                    'context_query_id': discovery_query_id,
                    'profile_sha256': _capture.PROFILE_SHA256}), objects)

        def failure(reason, status='unknown'):
            return finish({name: {'status': status, 'reason': reason} for name in query['fields']},
                          status == 'not_applicable')

        installation, creation, reason = _session_binding(self.base_source)
        reason = reason or _context_reason(current)
        if reason:
            return failure(reason, 'unavailable')
        try:
            discovery = self.base_source.read({'topic': 'W01', 'object': deepcopy(query['object']),
                'fields': ['war_id', 'participants'], 'parameters': {}}, current)
            discovery_query_id = discovery.get('source', {}).get('provenance', {}).get('query_id')
            identity = discovery['fields']['war_id']
            participants = discovery['fields']['participants']
            if identity.get('status') != 'known' or participants.get('status') != 'known':
                field = identity if identity.get('status') != 'known' else participants
                return failure(field.get('reason', 'WAR_PARTICIPANTS_UNAVAILABLE'), field.get('status', 'unknown'))
            members = project_war_participants(participants['value'],
                query['object']['actor'], query['object']['recipient'])
            if members is None or members['status'] != 'available':
                return failure('WAR_PARTICIPANTS_UNAVAILABLE')
            objects[:] = [dict(query['object'], war_id=identity['value'])]
        except Exception:
            return failure('WAR_DISCOVERY_FAILED')
        sides = {'our_side': members[members['actor_side']],
                 'opposing_side': members[members['recipient_side']]}
        countries = [country for side in sides.values() for country in side]
        values = {}
        for start in range(0, len(countries), _capture._countries.MAX_TARGETS):
            batch = countries[start:start + _capture._countries.MAX_TARGETS]
            try:
                report = (self.capture or _capture.capture)(installation, batch, fields=query['fields'])
                if not _capture.validate_capture(report, current, creation, batch, query['fields']):
                    raise ValueError('WAR_STATE_CAPTURE_INVALID')
                for target in report['observation']['backend']['targets']:
                    values[target['tag']] = {name: deepcopy(target['fields']['W03.' + name])
                                             for name in query['fields']}
            except Exception:
                values.update({country: {name: {'status': 'unknown', 'reason': 'WAR_STATE_CAPTURE_FAILED'}
                                         for name in query['fields']} for country in batch})
        fields = {}
        for name in query['fields']:
            grouped = {side: {country: values[country][name] for country in countries}
                       for side, countries in sides.items()}
            complete = all(field.get('status') == 'known' and field.get('complete', True)
                           for side in grouped.values() for field in side.values())
            fields[name] = {'status': 'known', 'value': grouped, 'complete': complete}
        return finish(fields, all(field['complete'] for field in fields.values()))
