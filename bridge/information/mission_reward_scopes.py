"""Associate direct reward area keys with bound static map memberships."""
from copy import deepcopy
import json

from .missions import _bound_scope_index


MAX_RULES = 128
MAX_MEMBERS = 4096
MAX_OUTPUT_BYTES = 512 * 1024


def _area_key(rule):
    parents = rule.get('parent_scope')
    if (not isinstance(parents, list) or len(parents) != 2
            or not all(isinstance(parent, dict) for parent in parents)
            or parents[0].get('key') != 'effect'):
        return None
    key = parents[1].get('key')
    return key if isinstance(key, str) and 0 < len(key) <= 128 else None


def _unknown(reason):
    return {'status': 'unknown', 'reason': reason,
            'reward_limits_evaluated': False, 'applied': 'unknown'}


def project_claim_scope_candidates(field, scope_index, *, reason='REWARD_AREA_INDEX_UNAVAILABLE'):
    """Keep the original rule inventory and add candidate area membership only."""
    result = deepcopy(field)
    if (not isinstance(result, dict) or result.get('status') != 'known'
            or not isinstance(result.get('value'), dict)
            or result['value'].get('semantics') != 'declared_literal_effect_rules'):
        return result
    tasks = result['value'].get('rules')
    if not isinstance(tasks, list):
        return result
    rules = []
    for task in tasks:
        if (not isinstance(task, dict) or task.get('status') != 'known'
                or not isinstance(task.get('rules'), list)):
            continue
        rules.extend(rule for rule in task['rules'] if isinstance(rule, dict))
    selected = rules[:MAX_RULES]
    names = []
    for rule in selected:
        key = _area_key(rule)
        if key is not None and key not in names:
            names.append(key)
    lookups = {}
    if scope_index is not None and names:
        try:
            lookups = scope_index.lookup_scopes(names)
        except Exception:
            reason = 'REWARD_AREA_LOOKUP_FAILED'
    if not isinstance(lookups, dict):
        lookups = {}
    used_bytes = known_count = 0
    for rule in selected:
        key = _area_key(rule)
        row = lookups.get(key)
        candidate = _unknown(reason)
        if key is None:
            candidate = _unknown('REWARD_AREA_SCOPE_CHAIN_UNSUPPORTED')
        elif isinstance(row, dict) and row.get('status') == 'known':
            members = row.get('members')
            if row.get('kind') != 'areas' or row.get('name') != key:
                candidate = _unknown('REWARD_AREA_SCOPE_KIND_UNSUPPORTED')
            elif (not isinstance(members, list) or len(members) > MAX_MEMBERS
                    or any(type(value) is not int or not 1 <= value <= 65535 for value in members)
                    or len(set(members)) != len(members) or not isinstance(row.get('source'), dict)):
                candidate = _unknown('REWARD_AREA_MEMBERSHIP_INVALID')
            else:
                candidate = {'status': 'known', 'kind': 'area', 'identifier': key,
                             'candidate_province_ids': sorted(members),
                             'source': deepcopy(row['source']),
                             'reward_limits_evaluated': False, 'applied': 'unknown'}
                try:
                    size = len(json.dumps(candidate, ensure_ascii=False, allow_nan=False,
                                          separators=(',', ':')).encode('utf-8'))
                except (TypeError, ValueError, UnicodeError):
                    rule['declared_area_candidates'] = _unknown('REWARD_AREA_SOURCE_INVALID')
                    continue
                if used_bytes + size > MAX_OUTPUT_BYTES:
                    candidate = _unknown('REWARD_AREA_OUTPUT_LIMIT')
                else:
                    used_bytes += size
                    known_count += 1
        elif isinstance(row, dict):
            code = row.get('reason')
            candidate = _unknown(code if isinstance(code, str) and len(code) <= 160
                                 else 'REWARD_AREA_NOT_RESOLVED')
        rule['declared_area_candidates'] = candidate
    result['value']['declared_area_candidates'] = {
        'projection_version': 1, 'known_rule_count': known_count,
        'unknown_rule_count': len(selected) - known_count,
        'omitted_rule_count': len(rules) - len(selected),
        'reward_limits_evaluated': False, 'scope_targets_resolved': False,
    }
    return result


class MissionRewardAreaSource:
    """Add static area candidates around the pinned mission source."""
    event_types = ()

    def __init__(self, base_source, *, limit_reader=None):
        self.base_source = base_source
        self.limit_reader = limit_reader

    def __getattr__(self, name):
        return getattr(self.base_source, name)

    def catalog(self):
        topics = deepcopy(self.base_source.catalog())
        if getattr(self.base_source, 'scope_index', None) is not None:
            for topic in topics:
                if topic['topic_id'] == 'M04':
                    topic['fields']['claims']['declared_area_candidates'] = {
                        'requires_task_id': True, 'scope': 'direct_area_parent',
                        'reward_limits_evaluated': False,
                    }
                    if self.limit_reader is not None:
                        topic['fields']['claims']['current_limit_evaluation'] = {
                            'requires_task_id': True, 'scope': 'direct_area_parent',
                            'predicates': ['is_core', 'owned_by', 'country_or_non_sovereign_subject_holds'],
                            'country_expression': 'ROOT', 'max_provinces': 64,
                            'execution_observed': False,
                        }
        return topics

    def read(self, query, context=None):
        context = context or self.context()
        query = self.validate_query(query, context)
        result = self.base_source.read(query, context)
        if (query['topic'] != 'M04' or 'claims' not in query['fields']
                or not query['parameters'].get('task_id') or getattr(self.base_source, 'scope_index', None) is None
                or result['fields']['claims'].get('status') != 'known'):
            return result
        provenance = result['source']['provenance']
        definitions = self.base_source.definitions.context()
        captured = provenance['definitions']
        keys = ('status', 'game_version', 'configuration_sha256', 'definitions_sha256')
        index, before = _bound_scope_index(self.base_source.scope_index, definitions, context)
        if any(captured.get(key) != definitions.get(key) for key in keys):
            index = None
            before = dict(before, configuration_binding_verified=False,
                          reason='MISSION_DEFINITIONS_CHANGED_DURING_COLLECTION')
        provenance['scope_definitions'] = before
        original = result['fields']['claims']
        enriched = project_claim_scope_candidates(original, index)
        if index is not None:
            if self.limit_reader is not None:
                from .mission_reward_limits import project_current_limits
                enriched = project_current_limits(enriched, self.limit_reader, context)
            after_definitions = self.base_source.definitions.context()
            _, after = _bound_scope_index(index, after_definitions, context)
            provenance['scope_definitions_after'] = after
            if before != after or any(definitions.get(key) != after_definitions.get(key) for key in keys):
                enriched = project_claim_scope_candidates(
                    original, None, reason='MISSION_SCOPE_INPUT_CHANGED_DURING_COLLECTION')
                provenance['static_scope_extensions_withdrawn'] = 'MISSION_SCOPE_INPUT_CHANGED_DURING_COLLECTION'
        result['fields']['claims'] = enriched
        return result
