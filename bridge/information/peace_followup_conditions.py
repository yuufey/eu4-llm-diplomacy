"""Strategic integration and renewed-war conditions of selected peace terms."""
from copy import deepcopy
import hashlib
from pathlib import Path

from .cwtools_script import CwtoolsScriptParser
from .mission_definitions import _scalar_value


# 1.37.4 b23ce0 initializes the property block at subject definition +b8.
SUBJECT_DEFAULTS = {
    'created_by_overlord': False,
    'can_be_annexed': False, 'can_be_integrated': False,
    'integration_requires_same_religion_group': True,
    'annex_cost_per_development': 0, 'pays_overlord': 0,
    'can_send_tribute': False, 'forcelimit_to_overlord': 0,
    'manpower_to_overlord': 0, 'sailors_to_overlord': 0,
}


def future_subjects(peace, claimant):
    result = []
    for term in peace['terms']:
        kind = {'force_vassalization': 'vassal', 'form_personal_union': 'personal_union'}.get(term['action_id'])
        if kind is not None or term['action_id'] == 'transfer_subject':
            for country in term.get('countries', [term.get('country')]):
                result.append({'subject': country, 'overlord': term.get('beneficiary', claimant),
                               'subject_type': kind})
    return result


def _conditions(nodes):
    """Keep ordered game predicates and make the two country scopes explicit."""
    scopes = {'ROOT': 'overlord', 'FROM': 'subject'}
    output = []
    for node in nodes:
        key = scopes.get(node.key, node.key)
        value = _conditions(node.children) if node.kind == 'block' else _scalar_value(node)
        if isinstance(value, str):
            value = scopes.get(value, value)
        if node.assignment != '=':
            value = {'operator': node.assignment, 'value': value}
        output.append({key: value})
    return output


class PeaceIntegrationConditions:
    def __init__(self, defines_index, *, parser=None):
        self.defines_index = defines_index
        self.parser = parser

    def read(self):
        source, values = {'definition_files': []}, {}
        files, errors = self.defines_index._effective_files(
            directory_path='common/diplomatic_actions', suffix='.txt', root_path=None)
        state = self.defines_index._stack._state
        errors = [*state.errors, *state.compatibility.errors, *errors]
        if errors:
            return {'values': values, 'source': source, 'reason': 'INTEGRATION_ACTION_FILES_UNAVAILABLE'}
        try:
            parser = self.parser or CwtoolsScriptParser()
            self.parser = parser
            parsed = parser.parse_files([Path(item['path']).resolve() for item in files])
            for item in files:
                path = Path(item['path']).resolve()
                result = parsed[str(path)]
                if result.get('error'):
                    raise ValueError('INTEGRATION_ACTION_PARSE_FAILED')
                source['definition_files'].append({'relative': item['relative'],
                    'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
                for action in result['nodes']:
                    if action.key not in ('annexationaction', 'integrationaction'):
                        continue
                    if action.kind != 'block' or action.assignment != '=':
                        raise ValueError('INTEGRATION_ACTION_DEFINITION_INVALID')
                    conditions = values.setdefault(action.key, [])
                    for child in action.children:
                        if child.key != 'condition':
                            continue
                        when = [node for part in child.children if part.key == 'potential' for node in part.children]
                        required = [node for part in child.children if part.key == 'allow' for node in part.children]
                        conditions.append({'when': _conditions(when), 'requires': _conditions(required)})
            source['parser'] = parser.context()
        except Exception:
            return {'values': {}, 'source': source, 'reason': 'INTEGRATION_ACTION_RULES_UNAVAILABLE'}
        return {'values': values, 'source': source}


def project_integration_conditions(subjects, rules, types, actions):
    output, gaps = [], []
    values = rules['values']
    for relation in subjects:
        row = dict(relation)
        kind = relation['subject_type']
        properties = types.get('values', {}).get(kind, {})
        if kind is None or not properties:
            output.append(dict(row, methods=None))
            gaps.append('POST_PEACE_SUBJECT_TYPE_UNAVAILABLE')
            continue
        methods = []
        for flag, method, years_key, action in (
                ('can_be_annexed', 'annex_vassal', 'INTEGRATE_VASSAL_MIN_YEARS', 'annexationaction'),
                ('can_be_integrated', 'integrate_union', 'INTEGRATE_UNION_MIN_YEARS', 'integrationaction')):
            permitted = properties.get(flag)
            if type(permitted) is not bool:
                gaps.append('POST_PEACE_TYPE_INTEGRATION_PERMISSION_UNAVAILABLE')
            if permitted is not True:
                continue
            item = {'method': method, 'minimum_subject_years': values.get(years_key),
                'base_diplomatic_cost_per_development': properties.get('annex_cost_per_development'),
                'progress_liberty_desire_below': values.get('DIPLOANNEX_LIBERTY_THRESHOLD'),
                'scripted_conditions': deepcopy(actions.get('values', {}).get(action))}
            if method == 'integrate_union':
                item['same_religion_group_required'] = properties.get('integration_requires_same_religion_group')
                item['overlord_provinces_at_least_subject'] = True
            if any(value is None for value in item.values()):
                gaps.append('POST_PEACE_INTEGRATION_REQUIREMENTS_INCOMPLETE')
            methods.append(item)
        unknown_permission = any(type(properties.get(flag)) is not bool
                                 for flag in ('can_be_annexed', 'can_be_integrated'))
        row['methods'] = None if not methods and unknown_permission else methods
        output.append(row)
    return {'status': 'known', 'value': output, 'complete': not gaps,
            'gaps': list(dict.fromkeys(gaps))}


def project_restart_conditions(peace, obj, truce, subjects, types):
    removed = [term['country'] for term in peace['terms'] if term['action_id'] == 'full_annexation']
    parties = {'actor': obj['actor'], 'recipient': obj['recipient']}
    gone = [country for country in parties.values() if country in removed]
    if gone:
        return {'status': 'known', 'complete': True, 'value': {'countries_removed': gone}}
    interval = truce.get('value', {})
    value = {'if_signed_on': interval.get('if_signed_on'),
             'without_truce_break_after': interval.get('estimated_until')}
    gaps = [] if truce.get('status') == 'known' else ['POST_PEACE_TRUCE_UNAVAILABLE']
    for relation in subjects:
        if {relation['subject'], relation['overlord']} != set(parties.values()):
            continue
        properties = types.get('values', {}).get(relation['subject_type'], {})
        if relation['subject'] == obj['actor']:
            value['actor_becomes_subject'] = True
            value['independence_war_allowed_by_type'] = properties.get('can_fight_independence_war')
        else:
            value['recipient_becomes_subject'] = True
            value['overlord_attack_allowed_by_type'] = properties.get('overlord_can_attack')
        if any(component is None for component in value.values()):
            gaps.append('POST_PEACE_SUBJECT_WAR_RULES_UNAVAILABLE')
    return {'status': 'known', 'value': value, 'complete': not gaps,
            'gaps': list(dict.fromkeys(gaps))}
