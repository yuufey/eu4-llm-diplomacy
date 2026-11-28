"""W03 current force sizes composed from the existing N02 and F02 adapters."""
from copy import deepcopy

from .catalog import validate_query
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource


def project_sizes(fields, army_name, navy_name, army_label):
    values = {}
    for name, label in ((army_name, army_label), (navy_name, 'navy_ships')):
        field = fields.get(name, {'status': 'unknown', 'reason': 'CURRENT_FORCES_UNAVAILABLE'})
        values[label] = {key: deepcopy(field[key]) for key in ('status', 'value', 'reason')
                         if key in field}
    complete = all(field.get('status') == 'known' for field in values.values())
    return {'status': 'known', 'value': values, 'complete': complete}


class NativeWarForcesSource(NativeTradeIncomeSource):
    def __init__(self, base_source, own_source, foreign_source):
        super().__init__(base_source)
        self.own_source = own_source
        self.foreign_source = foreign_source

    def catalog(self):
        return [{'topic_id': 'W03', 'catalog_ids': ['W03'], 'title': '占领、封锁与战损',
            'status': 'available', 'fields': {'current_forces': {
                'coverage': 'available', 'complete': True, 'period': 'current',
                'source': type(self).__name__,
                'description': '当前陆军团数或士兵数及舰船数，可见条件取当前观察国'}},
            'object_types': ['country'], 'observer_roles': [], 'observer_scope': [],
            'context_scope': 'visible_scope', 'visibility': 'visible_scope',
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
            'source': type(self).__name__}]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'W03' or normalized['fields'] != ['current_forces']:
            raise InformationError('invalid_fields', 'Expected W03.current_forces')
        if normalized['object']['type'] != 'country':
            raise InformationError('invalid_object', 'W03 current forces requires a country')
        if normalized['parameters']:
            raise InformationError('invalid_parameters', 'W03 current forces has no extra parameters')
        return normalized

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        country = query['object']['country']
        own = country == current.get('observer')
        upstream = self.own_source if own else self.foreign_source
        topic = 'N02' if own else 'F02'
        names = ['army_size', 'navy_size'] if own else ['visible_army', 'visible_navy']
        fields = {name: {'status': 'unknown', 'reason': 'CURRENT_FORCES_UNAVAILABLE'} for name in names}
        try:
            value = upstream.read({'topic': topic, 'object': deepcopy(query['object']),
                                   'fields': names, 'parameters': {}}, current)
            copied = value.get('fields', {})
            fields.update({name: deepcopy(copied.get(name, fields[name])) for name in names})
        except Exception:
            pass
        field = project_sizes(fields, names[0], names[1], 'army_regiments' if own else 'army_soldiers')
        complete = field['complete']
        return _result(query, current, {'current_forces': field}, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance={
                'delegated_topic': topic, 'delegated_fields': names,
                'basis': 'existing_country_force_size_projection', 'read_only': True}))
