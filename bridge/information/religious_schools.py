"""Current admitted-country religious school identity and configured syntax."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .country_faith import NativeCountryFaithSource
from . import school_relations_values as relations_values
from .religious_school_definitions import ReligiousSchoolDefinitionIndex
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _session_binding

FIELD = 'schools'
BACKEND_FIELD = 'S02.schools'
BASIS = 'bounded_native_country_religious_school'
ORIGIN = 'copied_native_religious_school'
UNIT = 'religious_school_summary'
GAPS = [
    'THREAD_GATED_ACTIVATION_PATH_UNRESOLVED',
    'FOREIGN_SCHOLAR_VISIBILITY_NOT_VERIFIED',
    'SCHOLAR_MODIFIER_KEY_MEMBERSHIP_ONLY',
    'SCHOLAR_INVITATION_HISTORY_NOT_READ',
    'SCHOLAR_DATE_SEMANTICS_UNPROVEN',
    'SCHOOL_RELATION_TOOLTIP_NOT_READ',
    'FULL_TOOLTIP_NOT_READ',
    'CONFIGURED_CONDITIONS_AND_EFFECTS_NOT_EXECUTED',
    'MAIN_THREAD_ATOMICITY_AND_CACHE_FRESHNESS_NOT_PROVEN',
]
_CONFIG_UNKNOWN = {
    'status': 'unknown',
    'reason': 'RELIGIOUS_SCHOOL_DEFINITION_UNAVAILABLE',
}
_CONFIG_KEYS = {
    'status', 'religion_group_key', 'school_key', 'source', 'source_pins',
    'syntax', 'conditions_evaluated', 'effects_executed', 'active_effects_proven',
}
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')


class NativeReligiousSchoolsSource(NativeTradeIncomeSource):
    """Expose copied native school identity and an optional static declaration."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source, capture=None, definitions=None, scholar_definitions=None):
        super().__init__(base_source, capture=capture)
        self.definitions = definitions
        self.scholar_definitions = scholar_definitions

    def catalog(self):
        topic = deepcopy(NativeCountryFaithSource.catalog(self)[0])
        topic.update(source=type(self).__name__, fields={FIELD: {
            'coverage': 'partial', 'complete': False, 'unit': UNIT,
            'scale': 1, 'period': 'current', 'basis': BASIS, 'value_origin': ORIGIN,
            'source': 'bridge.information.school_relations_capture.capture',
            'triggers': ['query', 'periodic'],
            'component_scopes': {
                'invited_scholars': {
                    'scope': 'observer_country',
                    'foreign_status': 'unknown',
                    'foreign_reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
                },
            },
            'runtime_validation': 'school_relations_capture.validate_capture',
            'paths': ["observation.backend.targets[0].fields['S02.schools'].value"],
            'raw_semantics': (
                'native religion and religion-group keys, current school presence/key, '
                'and the effective group declaration syntax when a school is present; '
                'activation uses the proven default-false and global bypass count paths; '
                'own-country scholar modifier membership uses exact keys only; '
                'foreign scholar disclosure is unverified and withheld; invitation history, '
                'date lifecycle and the thread-gated path remain unknown; school-pair '
                'relations come from the native relation cache, with tooltip unknown'
            ),
            'gaps': list(GAPS),
        }})
        topic['scope_note'] = (
            '读取准入国家的原生宗教key、宗教组key与当前宗教学校；'
            '仅附加有效配置中的宗教组学校AST，不执行条件或效果。'
            '机制默认false与global bypass计数规则已有证明，线程门控分支仍未知；'
            '本国学者只报告原生modifier key的精确成员关系；外国学者可知范围未核实，'
            '邀请历史和日期生命周期未知，'
            '学派关系读取原生school-pair relation cache，完整tooltip仍未读取。'
        )
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get('fields') != [FIELD]:
            raise InformationError('invalid_fields', 'S02.schools requires its single field')
        projected = deepcopy(query)
        projected['fields'] = ['faith']
        normalized = NativeCountryFaithSource.validate_query(self, projected, context)
        normalized['fields'] = [FIELD]
        return normalized

    @staticmethod
    def _context_reason(context):
        reason = NativeCountryFaithSource._context_reason(context)
        return reason.replace('COUNTRY_FAITH_', 'RELIGIOUS_SCHOOLS_', 1) if reason else None

    @staticmethod
    def _field(status, reason=None, value=None):
        result = {
            'status': status, 'period': 'current', 'unit': UNIT, 'scale': 1,
            'partial': True, 'complete': False, 'basis': BASIS, 'value_origin': ORIGIN,
        }
        if reason is not None:
            result['reason'] = reason
        if status == 'known' and value is not None:
            result['value'] = value
        return result

    @staticmethod
    def _safe_reason(value, fallback):
        return NativeCountryFaithSource._safe_reason(value, fallback)

    def _configured_rules(self, religion_group_key, school_key):
        try:
            if self.definitions is None:
                self.definitions = ReligiousSchoolDefinitionIndex()
            index = self.definitions
            definition = index.definition(religion_group_key, school_key)
            if not isinstance(definition, dict):
                return dict(_CONFIG_UNKNOWN)
            if definition.get('status') == 'unknown':
                if (set(definition) == {'status', 'reason'}
                        and definition.get('reason') == _CONFIG_UNKNOWN['reason']):
                    return deepcopy(definition)
                return dict(_CONFIG_UNKNOWN)
            if (set(definition) != _CONFIG_KEYS
                    or definition.get('status') != 'known'
                    or definition.get('religion_group_key') != religion_group_key
                    or definition.get('school_key') != school_key
                    or definition.get('conditions_evaluated') is not False
                    or definition.get('effects_executed') is not False
                    or definition.get('active_effects_proven') is not False):
                return dict(_CONFIG_UNKNOWN)
            canonical(definition)
            return deepcopy(definition)
        except Exception:
            return dict(_CONFIG_UNKNOWN)

    def _scholar_mapping(self):
        try:
            if self.scholar_definitions is None:
                module = import_module('.religious_scholar_definitions', __package__)
                self.scholar_definitions = module.ReligiousScholarDefinitionIndex()
            index = self.scholar_definitions
            mapping = getattr(index, 'mapping', None)
            if not callable(mapping):
                return {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE'}
            return mapping()
        except Exception:
            return {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE'}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        target = normalized['object']['country']
        provenance = {
            'read_only': True, 'native_function_invoked': False,
            'observer': current.get('observer'), 'target': target, 'actual_UI_observed': False,
            'configured_rules_are_applied_effects': False,
        }

        def result(field, ctx):
            source = _source_info(type(self).__name__, ctx, complete=False,
                                  provenance=deepcopy(provenance))
            source.update(context_scope='visible_scope', projection_version=2)
            return _result(normalized, ctx, {FIELD: field}, False, source)

        def fail(reason, ctx, unavailable=False):
            status = 'unavailable' if unavailable else 'unknown'
            return result(self._field(status, reason), ctx)

        reason = self._context_reason(current)
        if reason:
            return fail(reason, current, True)
        try:
            before = self.context()
        except Exception:
            return fail('RELIGIOUS_SCHOOLS_CONTEXT_UNAVAILABLE', current, True)
        if self._context_reason(before) or _identity(current) != _identity(before):
            return fail('RELIGIOUS_SCHOOLS_CONTEXT_STALE', before, True)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return fail('RELIGIOUS_SCHOOLS_SESSION_UNAVAILABLE', before, True)

        module = None
        report = None
        error = None
        try:
            module = import_module('.school_relations_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=target, observer=before['observer'])
        except Exception as exc:
            error = 'RELIGIOUS_SCHOOLS_CAPTURE_FAILED:' + type(exc).__name__

        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return fail('RELIGIOUS_SCHOOLS_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        next_installation, next_creation, next_reason = _session_binding(self.base_source)
        if next_reason or next_installation != installation or next_creation != creation:
            return fail('RELIGIOUS_SCHOOLS_SESSION_CHANGED_DURING_CAPTURE', before, True)
        if error:
            return fail(error, before)

        try:
            if module.validate_capture(report, before, creation, target) is not True:
                raise ValueError('CAPTURE_INVALID')
            if target == before['observer']:
                provenance['capture_report_sha256'] = hashlib.sha256(
                    canonical(report).encode('utf-8')
                ).hexdigest()
            provenance['profile_sha256'] = module.PROFILE_SHA256
            item = report['observation']['backend']['targets'][0]
            if item.get('tag') != target:
                raise ValueError('TARGET_MISMATCH')
            admission = item['admission_by_pass']['pass2']
            if admission.get('status') != 'known' or type(admission.get('admitted')) is not bool:
                return fail('RELIGIOUS_SCHOOLS_VIEW_ADMISSION_UNKNOWN', before)
            if not admission['admitted']:
                return result(self._field('invisible', 'RELIGIOUS_SCHOOLS_NOT_ADMITTED'), before)
            field = item['fields'][BACKEND_FIELD]
            status = field.get('status')
            if status in ('unknown', 'invisible'):
                reason = self._safe_reason(field.get('reason'), 'RELIGIOUS_SCHOOLS_BACKEND_UNKNOWN')
                return result(self._field(status, reason), before)
            if status != 'known' or field.get('complete') is not False or field.get('basis') != BASIS:
                raise ValueError('FIELD_SHAPE')

            native_value = relations_values.native_value(field['value'], target)
            if set(native_value) != {
                    'has_school', 'religion_key', 'religion_group_key', 'current_school',
                    'uses_schools', 'invited_scholars', 'relations'}:
                raise ValueError('NATIVE_VALUE_SHAPE')
            own_scholars = target == before['observer']
            mapping = (self._scholar_mapping()
                       if own_scholars and native_value['invited_scholars']['status'] == 'known' else None)
            native_value = relations_values.public_value(native_value, target, mapping)
            if not own_scholars:
                native_value['invited_scholars'] = {
                    'status': 'unknown', 'reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
                }
                # A full capture fingerprint covers unprojected foreign data.
                # The public receipt instead identifies only the visible value.
                provenance.pop('capture_report_sha256', None)
                provenance['scholar_visibility'] = 'unverified_foreign_component_withheld'
            if native_value['has_school']:
                configured_rules = self._configured_rules(
                    native_value['religion_group_key'], native_value['current_school']['key'])
            else:
                configured_rules = {
                    'status': 'not_applicable', 'reason': 'NO_CURRENT_RELIGIOUS_SCHOOL'
                }
            public_value = deepcopy(native_value)
            public_value['configured_rules'] = configured_rules
            if not own_scholars:
                provenance['public_projection_sha256'] = hashlib.sha256(
                    canonical(public_value).encode('utf-8')
                ).hexdigest()
            return result(self._field('known', value=public_value), before)
        except Exception:
            return fail('RELIGIOUS_SCHOOLS_CAPTURE_INVALID', before)
