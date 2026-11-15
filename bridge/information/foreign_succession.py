"""Current public succession indicators projected from the existing S04 source."""
from copy import deepcopy
import re

from .country_person import NativeCountryPersonSource
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource


_TAG = re.compile(r'[A-Z0-9]{3}\Z')
_PERSON_FIELDS = ['ruler', 'heir', 'personal_union']


def _unknown(reason):
    return {'status': 'unknown', 'reason': reason}


def _project(fields):
    ruler = fields.get('ruler', _unknown('RULER_UNAVAILABLE'))
    heir = fields.get('heir', _unknown('HEIR_UNAVAILABLE'))
    union = fields.get('personal_union', _unknown('UNION_STATE_UNAVAILABLE'))
    if all(field.get('status') == 'invisible' for field in (ruler, heir, union)):
        return {'status': 'invisible', 'reason': 'COUNTRY_PERSON_NOT_ADMITTED_FOR_OBSERVER'}
    values = {'ruler_age': deepcopy(ruler.get('value', {}).get('age',
                _unknown('RULER_AGE_UNAVAILABLE'))),
              'heir_present': _unknown('HEIR_PRESENCE_UNAVAILABLE'),
              'heir_age': _unknown('HEIR_AGE_UNAVAILABLE'),
              'heir_claim': _unknown('HEIR_CLAIM_UNAVAILABLE'),
              'senior_country': _unknown('UNION_STATE_UNAVAILABLE')}
    if heir.get('status') == 'not_applicable':
        for name in ('heir_present', 'heir_age', 'heir_claim'):
            values[name] = {'status': 'not_applicable', 'reason': 'HEIR_PANEL_NOT_APPLICABLE'}
    elif heir.get('status') == 'known':
        data = heir['value']
        if type(data.get('present')) is bool:
            values['heir_present'] = {'status': 'known', 'value': data['present']}
        values['heir_age'] = deepcopy(data.get('age', values['heir_age']))
        claim = data.get('claim', values['heir_claim'])
        if claim.get('status') == 'known':
            points = claim['value']
            values['heir_claim'] = {'status': 'known', 'value': {
                'current': points['raw'] / points['scale'], 'max': 100,
                'category': points['category']}}
        else:
            values['heir_claim'] = deepcopy(claim)
    if union.get('status') == 'known':
        values['senior_country'] = {'status': 'known', 'value': union['value']['senior_country']}
    complete = all(value.get('status') in ('known', 'not_applicable') for value in values.values())
    return {'status': 'known', 'value': values, 'complete': complete}


class NativeForeignSuccessionSource(NativeTradeIncomeSource):
    def __init__(self, base_source, person_source=None):
        super().__init__(base_source)
        self.person_source = person_source if person_source is not None else NativeCountryPersonSource(base_source)

    def catalog(self):
        return [{'topic_id': 'F04', 'catalog_ids': ['F04'], 'title': '外国压力与继承风险',
            'status': 'available', 'fields': {'succession_risk': {
                'coverage': 'available', 'complete': True, 'period': 'current',
                'source': 'S04', 'basis': 'current_public_succession_indicators',
                'description': '当前君主年龄、继承人有无和年龄、继承权强度及联统宗主'}},
            'object_types': ['country'], 'observer_roles': [], 'observer_scope': ['FRA'],
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'source': type(self).__name__, 'context_scope': 'visible_scope', 'visibility': 'visible_scope'}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'F04'
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected an F04 query')
        obj = query.get('object')
        if (not isinstance(obj, dict) or set(obj) != {'type', 'country'}
                or obj.get('type') != 'country' or not isinstance(obj.get('country'), str)
                or not _TAG.fullmatch(obj['country']) or obj['country'] == 'FRA'):
            raise InformationError('invalid_object', 'F04 requires a foreign country tag')
        if query.get('fields') != ['succession_risk']:
            raise InformationError('invalid_fields', 'Unsupported succession fields')
        if query.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'Succession risk has no extra parameters')
        if context is not None and (not isinstance(context, dict) or context.get('observer') != 'FRA'):
            raise InformationError('observer_scope_mismatch', 'The supported observer is FRA')
        return {'topic': 'F04', 'object': deepcopy(obj), 'fields': ['succession_risk'], 'parameters': {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        person = self.person_source.read({'topic': 'S04', 'object': query['object'],
            'fields': list(_PERSON_FIELDS), 'parameters': {}}, current)
        field = _project(person['fields'])
        current['game_date'] = person['game_date']
        complete = field.get('status') == 'known' and field.get('complete') is True
        return _result(query, current, {'succession_risk': field}, complete,
            _source_info(type(self).__name__, current, complete=complete,
                provenance={'read_only': True, 'native_function_invoked': False,
                            'basis': 'current_public_succession_indicators', 'component_source': 'S04'}))
