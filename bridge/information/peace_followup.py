"""Strategic obligations, integration rules and truce constraints of selected peace."""
from copy import deepcopy
from decimal import Decimal
from collections.abc import Mapping

from ..peace_execution import normalize_peace_execution_parameters
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason
from .peace_truce import project_new_truce
from .peace_followup_conditions import (
    SUBJECT_DEFAULTS, PeaceIntegrationConditions, future_subjects,
    project_integration_conditions, project_restart_conditions,
)


FIELDS = ('obligations', 'new_truce', 'integration_conditions', 'restart_conditions')


_ANNUL_RELATION_TYPES = ('alliance', 'royal_marriage')


def _unknown_annul_relationship(reason):
    return {'present': None, 'will_be_broken': None, 'unavailable_reason': reason}


def project_obligations(peace, rules, subjects=None, relations=None, annul_relations=None):
    obligations, gaps = [], []
    future_types = {(row['subject'], row['overlord']): row['subject_type']
                    for row in relations or []}

    def rule(name, *, percent=False):
        value = rules['values'].get(name)
        if type(value) not in (int, float) or value < 0:
            reason = rules.get('reasons', {}).get(name, name + '_UNAVAILABLE')
            gaps.append(reason.get('code', name + '_UNAVAILABLE') if isinstance(reason, dict) else reason)
            return None
        return float(Decimal(str(value)) * 100) if percent else value

    claimant = peace['claimant']
    for term in peace['terms']:
        action = term['action_id']
        if action == 'war_reparations':
            obligations.append({'type': action, 'payer': term['payer'],
                'recipient': term['claimant'],
                'income_percent': rule('WAR_REPARATIONS_FACTOR', percent=True),
                'duration_years': rule('WAR_REPARATIONS_YEARS')})
        elif action == 'transfer_trade_power':
            obligations.append({'type': action, 'country': term['source'],
                'recipient': term['beneficiary'],
                'trade_power_percent': rule('PO_TRADE_POWER_AMOUNT', percent=True),
                'duration_years': None, 'end_condition': 'truce_ends'})
        elif action == 'annul_treaties':
            duration = rule('ANNUL_TREATIES_YEARS')
            current_relationships = [dict(deepcopy((annul_relations or {}).get(
                (term['country'], partner), _unknown_annul_relationship('CURRENT_RELATIONSHIP_NOT_READ'))),
                partner=partner) for partner in term['treaty_partners']]
            obligations.append({'type': action, 'country': term['country'],
                'partners': deepcopy(term['treaty_partners']),
                'duration_years': duration,
                'current_relationships': current_relationships,
                'future_restriction': {
                    'duration_years': duration,
                    'rule': 'ANNUL_TREATIES_YEARS',
                    'effect': 'prevents_reestablishing_annulled_treaties',
                }})
            if any(row['present'] is None for row in current_relationships):
                gaps.append('CURRENT_ANNUL_TREATY_RELATIONSHIPS_UNREAD')
        elif action in ('force_vassalization', 'form_personal_union', 'transfer_subject'):
            countries = term.get('countries', [term.get('country')])
            subject_type = {'force_vassalization': 'vassal',
                            'form_personal_union': 'personal_union'}.get(action)
            for country in countries:
                overlord = term.get('beneficiary', claimant)
                kind = future_types.get((country, overlord), subject_type)
                properties = (subjects or {}).get('values', {}).get(kind, {})
                details = None
                if properties:
                    share = properties.get('forcelimit_to_overlord')
                    details = {'vassal_tax_multiplier': properties.get('pays_overlord'),
                        'annual_tribute': properties.get('can_send_tribute'),
                        'joins_overlord_wars': properties.get('joins_overlords_wars'),
                        'land_force_limit_share_percent': (
                            float(Decimal(str(share)) * 100) if type(share) in (int, float) else None),
                        'manpower_factor': properties.get('manpower_to_overlord'),
                        'sailors_factor': properties.get('sailors_to_overlord')}
                obligations.append({'type': 'subject_obligations', 'country': country,
                    'overlord': overlord, 'subject_type': kind, 'details': details})
                if details is None or any(value is None for value in details.values()):
                    gaps.append('POST_PEACE_SUBJECT_OBLIGATION_RULES_UNAVAILABLE')
    return {'status': 'known', 'value': obligations, 'complete': not gaps,
            'gaps': list(dict.fromkeys(gaps))}


class PeaceFollowupSource(NativeTradeIncomeSource):
    def __init__(self, base_source, *, rules=None, inspector=None,
                 subject_rules=None, action_conditions=None, subject_source=None,
                 relation_source=None):
        super().__init__(base_source)
        self.rules = rules
        self.inspector = inspector
        self.subject_rules = subject_rules
        self.action_conditions = action_conditions
        self.subject_source = subject_source
        self.relation_source = relation_source

    def catalog(self):
        topic = get_topic('P04')
        topic.update(topic_id='P06', catalog_ids=['P06'], title='和约持续义务与后续条件',
            status='available', source=type(self).__name__, observer_scope=[],
            supported_versions=['1.37.4'], triggers=['query', 'periodic'])
        topic['fields'] = {'obligations': {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'description': '实际选中和约的持续赔款、贸易转移、废约限制及属国义务；废约同时列出当前关系（已知存在、已知不存在或未知）与仅作用于未来关系的配置期限'}}
        topic['fields']['new_truce'] = {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'description': '按当前日期签订所选和约时，谈判双方直接停战的预计截止日期'}
        topic['fields']['integration_conditions'] = {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'description': '新属国的整合方式、等待年数、基础成本及当前配置的关键条件'}
        topic['fields']['restart_conditions'] = {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'description': '预计停战约束，以及谈判双方的存亡和新增宗属关系造成的战争类型限制'}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'P06'
                or not isinstance(query.get('fields'), list) or not query['fields']
                or any(name not in FIELDS for name in query['fields'])
                or len(set(query['fields'])) != len(query['fields'])):
            raise InformationError('invalid_fields', 'Unsupported P06 follow-up fields')
        normalized = validate_query(dict(query, topic='P04', fields=['consequences']), context)
        normalized.update(topic='P06', fields=query['fields'][:])
        obj, parameters = normalized['object'], normalized['parameters']
        if not obj.get('actor') or not obj.get('recipient'):
            raise InformationError('invalid_object', 'Peace follow-up requires an actor and a recipient')
        if context is not None and obj['actor'] != context.get('observer'):
            raise InformationError('observer_scope_mismatch', 'Peace follow-up requires the observer as actor')
        if set(parameters) - {'action_id', 'phase', 'peace_context'}:
            raise InformationError('invalid_parameters', 'Provide an explicit peace_context selection')
        peace = parameters.get('peace_context')
        terms = peace.get('terms') if isinstance(peace, dict) else None
        if not isinstance(terms, list):
            raise InformationError('invalid_parameters', 'Peace follow-up requires selected terms')
        first = terms[0] if terms and isinstance(terms[0], dict) else {}
        action = parameters.get('action_id', first.get('action_id', 'white_peace'))
        phase = parameters.get('phase', 'initiate')
        try:
            selected = normalize_peace_execution_parameters(action, obj['actor'], obj['recipient'],
                phase, {'peace_context': peace})
        except ValueError as exc:
            raise InformationError('invalid_parameters', str(exc)) from exc
        if obj.get('war_id', peace['war_id']) != peace['war_id']:
            raise InformationError('object_parameter_conflict', 'Conflicting war_id')
        normalized['parameters'] = dict(selected, action_id=action, phase=phase)
        return normalized

    @staticmethod
    def _annul_pair_evidence(result):
        """Reduce a real R01 selected-pair status read to one partner row."""
        field = result.get('fields', {}).get('status') if isinstance(result, Mapping) else None
        values = field.get('value') if isinstance(field, Mapping) and field.get('status') == 'known' else None
        checked = {item['relation_type']: item['value'] for item in values or []
                   if isinstance(item, Mapping) and item.get('relation_type') in _ANNUL_RELATION_TYPES
                   and item.get('status') == 'known' and item.get('value') in ('active', 'inactive')}
        if set(checked) != set(_ANNUL_RELATION_TYPES):
            return _unknown_annul_relationship('CURRENT_RELATIONSHIP_NOT_READ')
        active = [kind for kind, state in checked.items() if state == 'active']
        return {'present': bool(active), 'will_be_broken': bool(active),
                'relationship_types': active, 'checked_relationship_types': list(checked),
                'basis': 'R01.current_selected_country_pair'}

    def _annul_relation_snapshot(self, peace, context):
        """Read treaty partners only where R01 can prove the selected pair.

        R01 is observer-scoped; it cannot claim the relationship between two
        foreign countries.  Such partners are intentionally returned as
        unknown rather than inferred from the annulment candidate list.
        """
        terms = [term for term in peace.get('terms', [])
                 if isinstance(term, Mapping) and term.get('action_id') == 'annul_treaties']
        if not terms:
            return None
        observer = context.get('observer') if isinstance(context, Mapping) else None
        if self.relation_source is None:
            from .relation_state import NativeRelationSource
            self.relation_source = NativeRelationSource(self.base_source)
        evidence = {}
        for term in terms:
            country = term.get('country')
            for partner in term.get('treaty_partners', []):
                key = (country, partner)
                if key in evidence:
                    continue
                if observer not in (country, partner):
                    item = _unknown_annul_relationship('CURRENT_RELATIONSHIP_OUTSIDE_OBSERVER_SCOPE')
                else:
                    target = partner if country == observer else country
                    relation_query = {
                        'topic': 'R01',
                        'object': {'type': 'country_pair', 'actor': observer,
                                   'recipient': target},
                        'fields': ['status'],
                        'parameters': {'relation_types': list(_ANNUL_RELATION_TYPES)},
                    }
                    try:
                        item = self._annul_pair_evidence(
                            self.relation_source.read(relation_query, context))
                    except Exception:
                        item = _unknown_annul_relationship('CURRENT_RELATIONSHIP_READ_FAILED')
                evidence[key] = item
        return evidence

    def _subject_context(self, subjects, need_actions, context):
        names = {row['subject_type'] for row in subjects if row['subject_type'] is not None}
        current_types = {}
        transferred = [row for row in subjects if row['subject_type'] is None]
        if transferred:
            if self.subject_source is None:
                from .subject_pressure import NativeSubjectPressureSource
                self.subject_source = NativeSubjectPressureSource(self.base_source)
            for row in transferred:
                country = row['subject']
                if country in current_types:
                    continue
                result = self.subject_source.read({'topic': 'S03',
                    'object': {'type': 'country', 'country': country}, 'fields': ['tribute']}, context)
                value = result['fields']['tribute']
                name = value.get('subject_type') if value.get('status') == 'known' else None
                current_types[country] = name
                if name is not None:
                    names.add(name)
            names.update(('vassal', 'client_vassal'))
        types, actions = {'values': {}}, {'values': {}}
        if not names:
            return types, actions
        if self.subject_rules is None:
            from .peace_subject_rules import PeaceSubjectRules
            self.subject_rules = PeaceSubjectRules(self.rules, defaults=SUBJECT_DEFAULTS)
        types = self.subject_rules.read(sorted(names))
        for row in transferred:
            name = current_types.get(row['subject'])
            created = types['values'].get(name, {}).get('created_by_overlord')
            if type(created) is bool:
                row['subject_type'] = 'client_vassal' if created else 'vassal'
        if transferred:
            types.setdefault('source', {})['transferred_from_types'] = current_types
        future_names = {row['subject_type'] for row in subjects}
        eligible = any(row.get('can_be_annexed') is True or row.get('can_be_integrated') is True
                       for name, row in types.get('values', {}).items() if name in future_names)
        if need_actions and eligible:
            if self.action_conditions is None:
                self.action_conditions = PeaceIntegrationConditions(
                    self.rules, parser=getattr(self.subject_rules, 'parser', None))
            actions = self.action_conditions.read()
        return types, actions

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        fields = {name: {'status': 'unavailable', 'reason': 'PEACE_PREVIEW_UNAVAILABLE'}
                  for name in query['fields']}
        provenance = {'basis': 'native_selected_terms_and_configured_rules', 'read_only': True}
        obj, parameters = query['object'], query['parameters']
        peace = parameters['peace_context']
        objects = [dict(obj, war_id=peace['war_id'])]
        reason = _observer_context_reason(current)
        if reason:
            fields = {name: {'status': 'unavailable', 'reason': reason} for name in query['fields']}
        else:
            inspector = self.inspector
            if inspector is None:
                inspector = getattr(getattr(self.base_source, 'diplomacy_tools', None),
                                    'inspect_diplomatic_action', None)
            if callable(inspector):
                inspected = inspector(parameters['action_id'], obj['actor'], obj['recipient'],
                    parameters['phase'], {'peace_context': deepcopy(peace)})
                actual = inspected.get('parameters', {}).get('actual')
                applied = inspected.get('peace_consequences', {}).get('requested_terms_applied')
                if not isinstance(actual, dict) or applied is not True:
                    fields = {name: {'status': 'unknown', 'reason': 'PEACE_SELECTED_TERMS_NOT_APPLIED'}
                              for name in query['fields']}
                else:
                    provenance['selected_terms'] = deepcopy(actual['peace_context'])
                    provenance['requested_terms_applied'] = True
                    configured = {'values': {}, 'reasons': {}}
                    claimant = obj['actor'] if peace['direction'] == 'demand' else obj['recipient']
                    subjects = future_subjects(actual['peace_context'], claimant)
                    needs_subjects = bool(subjects) and any(name in query['fields'] for name in (
                        'obligations', 'integration_conditions', 'restart_conditions'))
                    needs_rules = any(name in query['fields'] for name in (
                        'new_truce', 'restart_conditions')) or (
                        bool(subjects) and 'integration_conditions' in query['fields']) or any(term['action_id'] in ('war_reparations',
                        'transfer_trade_power', 'annul_treaties') for term in peace['terms'])
                    if self.rules is None and (needs_rules or needs_subjects):
                        from .peace_rule_defines import PeaceRuleIndex
                        self.rules = PeaceRuleIndex()
                    if needs_rules:
                        try:
                            configured = self.rules.read()
                        except Exception:
                            configured = {'values': {}, 'reasons': {}}
                    types, actions = self._subject_context(subjects,
                        'integration_conditions' in query['fields'], current) if needs_subjects else ({'values': {}}, {'values': {}})
                    provenance['subject_rules'] = types.get('source', {})
                    provenance['integration_conditions'] = actions.get('source', {})
                    if 'obligations' in query['fields']:
                        annul_relations = self._annul_relation_snapshot(actual['peace_context'], current)
                        fields['obligations'] = project_obligations(
                            dict(actual['peace_context'], claimant=claimant), configured, types, subjects,
                            annul_relations=annul_relations)
                    truce = {'status': 'unknown'}
                    if any(name in query['fields'] for name in ('new_truce', 'restart_conditions')):
                        truce = project_new_truce(inspected, configured, current)
                    if 'new_truce' in query['fields']:
                        fields['new_truce'] = truce
                    if 'integration_conditions' in query['fields']:
                        fields['integration_conditions'] = project_integration_conditions(
                            subjects, configured, types, actions)
                    if 'restart_conditions' in query['fields']:
                        fields['restart_conditions'] = project_restart_conditions(
                            actual['peace_context'], obj, truce, subjects, types)
                    provenance['rules'] = configured.get('source', {})
                    provenance['rule_reasons'] = configured.get('reasons', {})
        complete = all(field['status'] == 'known' and field.get('complete', True) for field in fields.values())
        return _result(query, current, fields, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance=provenance), objects)
