"""Expose supported final country attributes using the existing N03 reader."""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module
import re

from .catalog import get_topic, validate_query
from .military_quality import _context_reason
from .model import InformationError, digest
from .province_goods_sources import (
    BASIS as _PROVINCE_GOODS_BASIS,
    BASIS_V2 as _PROVINCE_GOODS_BASIS_V2,
    MODIFIER_KEY as _PROVINCE_GOODS_MODIFIER_KEY,
    validate_public_breakdown as _validate_province_breakdown,
)
from .sources import _result, _source_info
from .trade_income import _identity

_ATTRIBUTES = ('discipline', 'morale')
_STATES = {'unknown', 'unavailable', 'invisible', 'not_applicable', 'stale', 'unsupported'}
_HEX = re.compile(r'[0-9a-fA-F]{8}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
# These are final native aggregate attributes, not instance/source attribution.
_SCALAR_ATTRIBUTES = {
    'diplomatic_reputation': {
        'topic': 'N06', 'field': 'diplomatic_reputation', 'unit': 'diplomatic_reputation', 'scale': 1000,
        'source': 'NativeDiplomaticReputationSource', 'capture': 'diplomatic_reputation_capture',
        'basis': 'native_diplomatic_reputation_aggregate_cache', 'origin': 'copied_native_aggregate_modifier'},
    'diplomats_total': {
        'topic': 'N05', 'field': 'diplomats_total', 'unit': 'diplomats', 'scale': 1000,
        'source': 'NativeDiplomatsTotalSource', 'capture': 'diplomats_total_capture',
        'basis': 'native_diplomats_total_aggregate_cache', 'origin': 'copied_native_aggregate_modifier'},
    'relations_limit': {
        'topic': 'N05', 'field': 'relations_limit', 'unit': 'diplomatic_relation', 'scale': 1,
        'source': 'NativeRelationsCapacitySource', 'capture': 'relations_capacity_capture',
        'basis': 'native_diplomatic_relation_trigger_arithmetic',
        'origin': 'derived_from_copied_native_modifier_and_relation_caches'},
}
_SCALAR_KEYS = {'status', 'value', 'raw', 'raw_hex', 'unit', 'scale', 'period',
                'complete', 'partial', 'basis', 'value_origin'}


def _project_scalar_attribute(item, spec):
    if not isinstance(item, dict):
        raise ValueError('FINAL_ATTRIBUTE_SCALAR_FIELD_INVALID')
    if item.get('status') != 'known':
        reason = item.get('reason')
        if (item.get('status') not in _STATES or not isinstance(reason, str)
                or re.fullmatch(r'[A-Za-z][A-Za-z0-9_:-]{0,255}', reason) is None):
            raise ValueError('FINAL_ATTRIBUTE_SCALAR_STATE_INVALID')
        return {'status': item['status'], 'reason': reason}
    value = item.get('value')
    if (set(item) != _SCALAR_KEYS or not _scalar(value, item.get('raw_hex'))
            or type(item.get('raw')) is not int or item['raw'] != value
            or item.get('unit') != spec['unit'] or type(item.get('scale')) is not int
            or item['scale'] != spec['scale'] or item.get('period') != 'current'
            or item.get('complete') is not False or item.get('partial') is not True
            or item.get('basis') != spec['basis'] or item.get('value_origin') != spec['origin']):
        raise ValueError('FINAL_ATTRIBUTE_SCALAR_CONTRACT_INVALID')
    return {key: deepcopy(item[key]) for key in _SCALAR_KEYS}


def _scalar_profile_sha(spec):
    return import_module('.' + spec['capture'], __package__).PROFILE_SHA256


_MODIFIER_EFFECT_GAPS = [
    'DIRECT_COUNTRY_MODIFIER_LIST_ONLY',
    'EFFECT_BUSINESS_UNITS_UNRESOLVED',
    'ACTIVATION_AND_FINAL_CONTRIBUTIONS_NOT_PROVEN',
]


def _scalar(value, raw_hex):
    return (type(value) is int and -(1 << 31) <= value < (1 << 31)
            and isinstance(raw_hex, str) and _HEX.fullmatch(raw_hex) is not None
            and int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) == value)


def _project(item, attribute):
    if not isinstance(item, dict):
        raise ValueError('FINAL_ATTRIBUTE_UPSTREAM_FIELD_INVALID')
    if item.get('status') != 'known':
        reason = item.get('reason')
        if (item.get('status') not in _STATES or not isinstance(reason, str)
                or not 1 <= len(reason) <= 256):
            raise ValueError('FINAL_ATTRIBUTE_UPSTREAM_STATE_INVALID')
        return {'status': item['status'], 'reason': reason}
    value, raw, raw_hex = item.get('value'), item.get('raw'), item.get('raw_hex')
    if (item.get('unit') != ('ratio' if attribute == 'discipline' else 'morale')
            or type(item.get('scale')) is not int or item['scale'] != 1000
            or item.get('period') != 'current' or type(item.get('complete')) is not bool):
        raise ValueError('FINAL_ATTRIBUTE_UPSTREAM_UNIT_INVALID')
    if attribute == 'discipline':
        valid = type(raw) is int and raw == value and _scalar(value, raw_hex)
    else:
        valid = (isinstance(value, dict) and set(value) == {'army', 'navy'}
            and isinstance(raw, dict) and set(raw) == set(value)
            and isinstance(raw_hex, dict) and set(raw_hex) == set(value)
            and all(type(raw[key]) is int and raw[key] == value[key]
                    and _scalar(value[key], raw_hex[key]) for key in value))
    if not valid:
        raise ValueError('FINAL_ATTRIBUTE_UPSTREAM_VALUE_INVALID')
    return {key: deepcopy(item[key]) for key in (
        'status', 'value', 'raw', 'raw_hex', 'unit', 'scale', 'period', 'complete')}


def _project_breakdown(discipline, provenance):
    """Project the already verified N03 calculation without exposing addresses."""
    if discipline.get('status') != 'known':
        return deepcopy(discipline)
    from . import military_effective_memory as native
    try:
        compact = provenance['military_effective']
        obs = compact['observation']
        if (compact.get('status') != 'observed'
                or compact.get('profile_sha256') != native.EXPECTED_PROFILE_SHA256
                or obs.get('profile_sha256') != native.EXPECTED_PROFILE_SHA256
                or _project(compact.get('field'), 'discipline') != discipline):
            raise ValueError('FINAL_ATTRIBUTE_BREAKDOWN_BINDING_INVALID')
        base = int(compact['module_base'], 0)
        country = int(compact['country_pointer'], 0)
        if obs.get('module_base') != compact['module_base'] or obs.get('country_pointer') != compact['country_pointer']:
            raise ValueError('FINAL_ATTRIBUTE_BREAKDOWN_BINDING_INVALID')
        valid_modifier, modifier = native._validate_modifier(obs, country)
        valid_processor, callback = native._validate_processor(obs, base, modifier)
        processor = obs['processor']
        if (not valid_modifier or not valid_processor
                or processor.get('thread_context_status') not in {
                    'not_required_no_processor', 'not_required_zero_contribution'}):
            raise ValueError('FINAL_ATTRIBUTE_BREAKDOWN_INPUTS_UNVERIFIED')
        before = native._i32(1000 + callback)
        final = max(10, before)
        if (obs.get('effective_before_clamp') != before or obs.get('minimum_clamp') != 10
                or obs.get('effective_raw') != final or discipline['raw'] != final
                or obs.get('effective_raw_hex') != discipline['raw_hex']):
            raise ValueError('FINAL_ATTRIBUTE_BREAKDOWN_TOTAL_MISMATCH')
        contributions = processor.get('contributions', {}) if processor['status'] == 'recognized' else {}
        terms = [{'native_key': key, 'input_raw': item['raw'], 'enabled': item['enabled'],
                  'applied_raw': item['scaled'], 'denominator': item['denominator']}
                 for key, item in contributions.items()]
        value = {'base_raw': 1000, 'aggregate_modifier_raw': modifier,
            'processor_terms': terms, 'callback_raw': callback,
            'before_minimum_raw': before, 'minimum_raw': 10,
            'minimum_adjustment_raw': final-before, 'final_raw': final,
            'unit': 'ratio', 'scale': 1000,
            'arithmetic': 'signed32_addition_then_minimum',
            'processor_context': processor['thread_context_status']}
        return {'status': 'known', 'value': {'discipline': value},
            'unit': 'attribute_breakdown_map', 'scale': 1, 'period': 'current',
            'complete': False, 'partial': True,
            'gaps': ['NAMED_MODIFIER_INSTANCE_CONTRIBUTIONS_NOT_IMPLEMENTED',
                     'MORALE_SOURCE_BREAKDOWN_NOT_IMPLEMENTED']}
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return {'status': 'unknown', 'reason': str(exc) if isinstance(exc, ValueError)
                else 'FINAL_ATTRIBUTE_BREAKDOWN_EVIDENCE_MISSING'}


def _context_matches(left, right):
    """Check the shared live identity used by both delegated readers."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    if any(left.get(key) != right.get(key)
           for key in ('mode', 'observer', 'session_id', 'game_date')):
        return False
    try:
        return _identity(left) == _identity(right)
    except (TypeError, AttributeError):
        return False


def _check_upstream_identity(upstream, expected_name, before, query_object,
                             error_code):
    if not isinstance(upstream, dict):
        raise ValueError(error_code)
    source = upstream.get('source')
    if not isinstance(source, dict) or source.get('name') != expected_name:
        raise ValueError(error_code)
    if any(source.get(key) != before.get(key)
           for key in ('mode', 'observer', 'session_id')):
        raise ValueError(error_code)
    if (upstream.get('game_date') != before.get('game_date')
            or upstream.get('objects') != [query_object]):
        raise ValueError(error_code)
    return source


def _project_modifier_effects(item):
    """Validate and copy the N07 effects projection without deriving semantics."""
    if not isinstance(item, dict):
        raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECTS_INVALID')
    status = item.get('status')
    if status != 'known':
        reason = item.get('reason')
        if (status not in _STATES or not isinstance(reason, str)
                or not 1 <= len(reason) <= 256):
            raise ValueError('FINAL_ATTRIBUTE_MODIFIER_STATE_INVALID')
        # Preserve the upstream non-known state and its bounded reason exactly.
        return deepcopy(item)

    if (item.get('unit') != 'modifier_effect_records'
            or type(item.get('scale')) is not int or item['scale'] != 1
            or item.get('period') != 'current'
            or item.get('complete') is not False
            or item.get('partial') is not True):
        raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECTS_CONTRACT_INVALID')
    values = item.get('value')
    raw_values = item.get('raw')
    if (not isinstance(values, list) or not isinstance(raw_values, list)
            or len(values) != len(raw_values)):
        raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECTS_LIST_INVALID')

    # Keep the limits aligned with the already-verified N07 memory reader.
    from . import country_modifiers_memory as native
    if len(values) > native.MAX_INSTANCES:
        raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECTS_LIST_TOO_LARGE')
    if raw_values != values:
        raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECTS_RAW_MISMATCH')
    for row in values:
        if not isinstance(row, dict):
            raise ValueError('FINAL_ATTRIBUTE_MODIFIER_RECORD_INVALID')
        modifier_id = row.get('modifier_id')
        effects = row.get('effects')
        if (not isinstance(modifier_id, str) or not modifier_id.strip()
                or len(modifier_id.encode('utf-8')) > native.MAX_KEY_BYTES
                or row.get('basis') != 'native_modifier_definition_entries'
                or row.get('final_effective_value') is not False):
            raise ValueError('FINAL_ATTRIBUTE_MODIFIER_ID_INVALID')
        if not isinstance(effects, list) or len(effects) > native.MAX_EFFECTS:
            raise ValueError('FINAL_ATTRIBUTE_MODIFIER_EFFECT_LIST_INVALID')
        for effect in effects:
            if not isinstance(effect, dict):
                raise ValueError('FINAL_ATTRIBUTE_EFFECT_INVALID')
            raw = effect.get('raw')
            raw_hex = effect.get('raw_hex')
            if (type(raw) is not int or not -(1 << 31) <= raw < (1 << 31)
                    or not isinstance(raw_hex, str) or _HEX.fullmatch(raw_hex) is None
                    or int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) != raw
                    or type(effect.get('scale')) is not int or effect['scale'] != 1000
                    or effect.get('unit') != 'native_fixed_point'
                    or effect.get('business_unit') != 'unknown'):
                raise ValueError('FINAL_ATTRIBUTE_EFFECT_CONTRACT_INVALID')

    projected = deepcopy(item)
    projected['value'] = deepcopy(values)
    projected['raw'] = deepcopy(raw_values)
    projected['unit'] = 'modifier_effect_records'
    projected['scale'] = 1
    projected['period'] = 'current'
    projected['complete'] = False
    projected['partial'] = True
    projected['gaps'] = list(_MODIFIER_EFFECT_GAPS)
    return projected


class NativeFinalAttributesSource:
    event_types = ()

    def __init__(self, military_quality_source, country_records_source=None, *, scalar_sources=None,
                 province_breakdown_source=None):
        self.military_quality_source = military_quality_source
        self.country_records_source = country_records_source
        self.province_breakdown_source = province_breakdown_source
        if scalar_sources is None:
            scalar_sources = {}
        if (not isinstance(scalar_sources, dict) or set(scalar_sources) - set(_SCALAR_ATTRIBUTES)
                or any(not callable(getattr(source, 'read', None))
                       or not callable(getattr(source, 'context', None))
                       for source in scalar_sources.values())):
            raise ValueError('FINAL_ATTRIBUTES_SCALAR_SOURCES_INVALID')
        self.scalar_sources = dict(scalar_sources)
        if (province_breakdown_source is not None
                and (not callable(getattr(province_breakdown_source, 'read', None))
                     or not callable(getattr(province_breakdown_source, 'context', None)))):
            raise ValueError('FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_SOURCE_INVALID')

    def context(self):
        return deepcopy(self.military_quality_source.context())

    def catalog(self):
        topic = get_topic('N09')
        object_types = ['country']
        breakdown_object_types = ['country']
        if self.province_breakdown_source is not None:
            object_types.append('province')
            breakdown_object_types.append('province')
        topic.update(status='available', source=type(self).__name__,
            object_types=object_types, observer_scope=['FRA'], observer_roles=['country'],
            supported_versions=['1.37.4'], visibility='country_scope', context_scope='country_scope',
            triggers=['query', 'periodic', 'change'],
            change_detection='sampled_state_comparison_not_lossless_events')
        topic['fields'] = {'final_value': {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'attribute_map', 'scale': 1, 'period': 'current',
            'supported_object_types': ['country'], 'supported_countries': ['FRA'],
            'supported_attributes': ['discipline', 'morale.army', 'morale.navy'],
            'basis': 'existing_N03_verified_final_discipline_and_country_morale_caches',
            'description': '当前纪律计算值与陆海军国家士气缓存；各属性保留原单位、精度与缺项。',
            'gaps': ['OTHER_FINAL_ATTRIBUTES_NOT_IMPLEMENTED', 'NAMED_MODIFIER_SOURCE_BREAKDOWN_NOT_IMPLEMENTED',
                     'MODIFIER_EFFECTIVE_STATUS_NOT_IMPLEMENTED'],
        }}
        if self.scalar_sources:
            final = topic['fields']['final_value']
            final['supported_attributes'] += [name for name in _SCALAR_ATTRIBUTES if name in self.scalar_sources]
            final['basis'] = 'existing_verified_native_military_and_diplomatic_attributes'
            final['description'] = '汇总已验证的纪律、士气和已配置外交属性；各项保留独立单位、精度、未知状态与来源。'
        topic['fields']['source_breakdown'] = {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'attribute_breakdown_map', 'scale': 1, 'period': 'current',
            'supported_object_types': breakdown_object_types, 'supported_countries': ['FRA'],
            'supported_attributes': ['discipline'],
            'basis': 'existing_N03_validated_discipline_calculation_observation',
            'description': '纪律基础值、聚合修正、已验证处理器贡献及下限钳制；尚未映射到单个修正实例。',
            'gaps': ['NAMED_MODIFIER_INSTANCE_CONTRIBUTIONS_NOT_IMPLEMENTED',
                     'MORALE_SOURCE_BREAKDOWN_NOT_IMPLEMENTED'],
        }
        if self.province_breakdown_source is not None:
            topic.update(
                visibility='adapter_managed',
                context_scope='adapter_managed',
                scope_note=(
                    'N09国家属性只适用于逻辑FRA国家对象；省份source_breakdown使用逻辑FRA的准入与发现校验，'
                    '不要求省份由FRA持有。'
                ),
            )
            topic['fields']['final_value'].update(
                visibility='country_scope', context_scope='country_scope',
            )
            breakdown = topic['fields']['source_breakdown']
            breakdown.pop('supported_countries', None)
            breakdown['supported_observers'] = ['FRA']
            breakdown['supported_country_tags_by_object_type'] = {'country': ['FRA']}
            breakdown['supported_attributes'].append(_PROVINCE_GOODS_MODIFIER_KEY)
            breakdown.update(
                visibility='adapter_managed', context_scope='adapter_managed',
                scope_by_object_type={
                    'country': 'country_scope',
                    'province': 'visible_scope',
                },
                scope_note=(
                    'country分支限逻辑FRA；province分支要求逻辑FRA的非玩家准入与省份发现，'
                    '不按省份所有者过滤。'
                ),
            )
            breakdown['basis_by_object_type'] = {
                'country': 'existing_N03_validated_discipline_calculation_observation',
                'province': _PROVINCE_GOODS_BASIS,
            }
            breakdown['supported_province_id_range'] = [1, 0xFFFF]
            breakdown['description'] = (
                '国家对象提供纪律计算分解；省份对象只提供已验证的贸易商品大小修正缓存分量与算术残差，'
                '不表示完整来源归因。'
            )
            breakdown['gaps'].extend([
                'PROVINCE_OTHER_MODIFIER_CALLBACKS_NOT_CAPTURED',
                'PROVINCE_MODIFIER_CACHE_PHASE_UNRESOLVED',
                'PROVINCE_ACQUISITION_DELTA_NOT_CAPTURED',
            ])
            if getattr(self.province_breakdown_source, 'projection_version', 1) == 2:
                breakdown['projection_version'] = 2
                breakdown['basis_by_object_type']['province'] = _PROVINCE_GOODS_BASIS_V2
                breakdown['description'] = (
                    '国家对象提供纪律计算分解；省份对象提供23个贸易商品修正缓存槽与4个直接条件模型的当前部分分解，'
                    '繁荣只验证了必要门槛，'
                    '其他回调、缓存时相与取得省份变化仍未覆盖。'
                )
        if self.country_records_source is not None:
            topic['fields']['modifier_effects'] = {
                'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
                'unit': 'modifier_effect_records', 'scale': 1, 'period': 'current',
                'supported_object_types': ['country'], 'supported_countries': ['FRA'],
                'visibility': 'country_scope', 'context_scope': 'country_scope',
                'basis': 'native_direct_country_modifier_records',
                'value_origin': 'copied_native_country_records',
                'description': '当前国家直接修正实例的原生定义效果；不推断来源、激活或最终属性贡献。',
                'gaps': list(_MODIFIER_EFFECT_GAPS),
            }
        topic['change_scope'] = {'fields': ['final_value'],
            'attributes': deepcopy(topic['fields']['final_value']['supported_attributes']),
            'readiness': 'all_supported_attributes_known',
            'comparison': 'sampled_supported_values_not_full_attribute_coverage'}
        return [topic]

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError('invalid_context', 'N09 context must be an object')
        normalized = validate_query(query, context)
        if normalized['topic'] != 'N09':
            raise InformationError('unsupported_topic', 'Final attributes source supports N09')
        obj = normalized['object']
        if obj.get('type') == 'country':
            if obj.get('country') != 'FRA':
                raise InformationError('observer_scope_mismatch', 'N09 requires the logical FRA observer')
        elif obj.get('type') == 'province':
            if self.province_breakdown_source is None:
                raise InformationError('invalid_object', 'N09 province breakdown source is not configured')
            if (set(obj) != {'type', 'province_id'} or type(obj.get('province_id')) is not int
                    or not 1 <= obj['province_id'] <= 0xFFFF):
                raise InformationError('invalid_object', 'N09 province_id must be a positive bounded integer')
            if context is not None and context.get('observer') not in (None, 'FRA'):
                raise InformationError('observer_scope_mismatch', 'N09 province breakdown is verified for logical FRA')
        else:
            raise InformationError('invalid_object', 'N09 requires a country or supported province')
        if normalized['parameters']:
            raise InformationError('invalid_parameters', 'N09 parameters must be empty')
        return normalized

    def _read_province_breakdown(self, query, context):
        try:
            before = self.context()
        except Exception:
            before = {}
        fields = {name: {'status': 'unsupported', 'reason': 'N09_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {
            'delegated_topic': 'G02' if 'source_breakdown' in query['fields'] else None,
            'delegated_fields': [_PROVINCE_GOODS_MODIFIER_KEY] if 'source_breakdown' in query['fields'] else [],
            'shared_reader': type(self.province_breakdown_source).__name__,
            'read_only': True, 'native_function_invoked': False,
            'full_modifier_breakdown': False, 'delegations': {},
            'delegations_atomic': True, 'atomic_snapshot': False,
        }

        def result(ctx=before):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=provenance)
            source['context_scope'] = 'visible_scope'
            return _result(query, ctx, fields, False, source)

        if 'source_breakdown' not in query['fields']:
            return result()
        reason = _context_reason(before)
        if reason or (context is not None and _identity(context) != _identity(before)):
            fields['source_breakdown'] = {
                'status': 'unavailable',
                'reason': reason or 'FINAL_ATTRIBUTES_CONTEXT_MISMATCH',
            }
            return result()

        try:
            source_before = self.province_breakdown_source.context()
        except Exception:
            source_before = None
        if not _context_matches(source_before, before):
            fields['source_breakdown'] = {
                'status': 'unavailable', 'reason': 'FINAL_ATTRIBUTES_CONTEXT_CHANGED',
            }
            return result()

        child_query = {
            'topic': 'N09', 'object': deepcopy(query['object']),
            'fields': ['source_breakdown'], 'parameters': {},
        }
        upstream = None
        upstream_error = None
        try:
            upstream = self.province_breakdown_source.read(child_query, before)
        except Exception as exc:
            upstream_error = f'FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_FAILED:{type(exc).__name__}'

        try:
            after = self.context()
        except Exception:
            after = None
        try:
            source_after = self.province_breakdown_source.context()
        except Exception:
            source_after = None
        if (not isinstance(after, dict) or _context_reason(after)
                or not _context_matches(before, after)
                or not _context_matches(source_after, before)
                or not _context_matches(source_before, source_after)):
            fields['source_breakdown'] = {
                'status': 'unavailable', 'reason': 'FINAL_ATTRIBUTES_CONTEXT_CHANGED',
            }
            return result(after if isinstance(after, dict) else before)

        try:
            if upstream is None:
                raise ValueError(upstream_error or 'FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_UNAVAILABLE')
            source = _check_upstream_identity(
                upstream, type(self.province_breakdown_source).__name__, before,
                query['object'], 'FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_IDENTITY_INVALID')
            projected = _validate_province_breakdown(
                upstream.get('fields', {}).get('source_breakdown'),
                query['object']['province_id'])
            fields['source_breakdown'] = projected
            if projected.get('status') == 'known':
                evidence = source.get('provenance')
                report_hash = evidence.get('capture_report_sha256') if isinstance(evidence, dict) else None
                profile_hash = evidence.get('profile_sha256') if isinstance(evidence, dict) else None
                if (not isinstance(report_hash, str) or _SHA.fullmatch(report_hash) is None
                        or not isinstance(profile_hash, str) or _SHA.fullmatch(profile_hash) is None):
                    raise ValueError('FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_EVIDENCE_MISSING')
                result_hash = digest(upstream)
                provenance['capture_report_sha256'] = report_hash
                provenance['delegations']['G02.province_goods_modifier_source'] = {
                    'field': 'G02.province_goods_modifier_source',
                    'profile_sha256': profile_hash,
                    'capture_report_sha256': report_hash,
                    'result_sha256': result_hash,
                }
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            fields['source_breakdown'] = {
                'status': 'unknown',
                'reason': str(exc) if isinstance(exc, ValueError)
                else 'FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_INVALID',
            }
        return result()

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        if query['object']['type'] == 'province':
            return self._read_province_breakdown(query, context)
        try:
            before = self.context()
        except Exception:
            before = {}
        fields = {name: {'status': 'unsupported', 'reason': 'N09_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        final_selected = [name for name in query['fields']
                          if name in {'final_value', 'source_breakdown'}]
        modifier_selected = ('modifier_effects' in query['fields']
                             and self.country_records_source is not None)
        selected = list(final_selected)
        if modifier_selected:
            selected.append('modifier_effects')
        requested = (_ATTRIBUTES if 'final_value' in final_selected
                     else ('discipline',) if final_selected else ())
        provenance = {
            'delegated_topic': 'N03' if final_selected else 'N07' if modifier_selected else None,
            'delegated_fields': list(requested) if final_selected else (['effects'] if modifier_selected else []),
            'shared_reader': 'NativeMilitaryQualitySource' if final_selected else
                             'NativeCountryRecordsSource' if modifier_selected else None,
            'read_only': True, 'native_function_invoked': False,
            'full_modifier_breakdown': False, 'delegations': {},
            'delegations_atomic': not (final_selected and modifier_selected),
            'atomic_snapshot': False,
        }

        def result(ctx=before):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=provenance)
            source['context_scope'] = 'country_scope'
            return _result(query, ctx, fields, False, source)

        if not selected:
            return result()
        reason = _context_reason(before)
        if reason or (context is not None and _identity(context) != _identity(before)):
            for name in selected:
                fields[name] = {'status': 'unavailable', 'reason': reason or 'FINAL_ATTRIBUTES_CONTEXT_MISMATCH'}
            return result()

        records_before = None
        if modifier_selected:
            try:
                records_before = self.country_records_source.context()
            except Exception:
                records_before = None
            if not _context_matches(records_before, before):
                for name in selected:
                    fields[name] = {'status': 'unavailable',
                                    'reason': 'FINAL_ATTRIBUTES_CONTEXT_CHANGED'}
                return result()

        scalar_selected = ([name for name in _SCALAR_ATTRIBUTES if name in self.scalar_sources]
                           if 'final_value' in final_selected else [])
        scalar_before, scalar_upstreams, scalar_errors = {}, {}, {}
        for name in scalar_selected:
            try:
                scalar_before[name] = self.scalar_sources[name].context()
            except Exception:
                scalar_before[name] = None
            if not _context_matches(scalar_before[name], before):
                for selected_name in selected:
                    fields[selected_name] = {'status': 'unavailable', 'reason': 'FINAL_ATTRIBUTES_CONTEXT_CHANGED'}
                return result()
        upstream = None
        upstream_error = None
        if final_selected:
            try:
                upstream = self.military_quality_source.read({
                    'topic': 'N03', 'object': deepcopy(query['object']),
                    'fields': list(requested), 'parameters': {}}, before)
            except Exception as exc:
                upstream_error = f'FINAL_ATTRIBUTES_UPSTREAM_FAILED:{type(exc).__name__}'

        modifier_upstream = None
        modifier_error = None
        if modifier_selected:
            try:
                modifier_upstream = self.country_records_source.read({
                    'topic': 'N07', 'object': deepcopy(query['object']),
                    'fields': ['effects'], 'parameters': {}}, before)
            except Exception as exc:
                modifier_error = f'FINAL_ATTRIBUTES_MODIFIER_RECORDS_FAILED:{type(exc).__name__}'

        for name in scalar_selected:
            spec = _SCALAR_ATTRIBUTES[name]
            try:
                scalar_upstreams[name] = self.scalar_sources[name].read({
                    'topic': spec['topic'], 'object': deepcopy(query['object']),
                    'fields': [spec['field']], 'parameters': {}}, before)
            except Exception as exc:
                scalar_errors[name] = 'FINAL_ATTRIBUTE_SCALAR_READ_FAILED:' + type(exc).__name__
        scalar_after = {}
        for name in scalar_selected:
            try:
                scalar_after[name] = self.scalar_sources[name].context()
            except Exception:
                scalar_after[name] = None
        if scalar_selected:
            provenance['delegations_atomic'] = False
        try:
            after = self.context()
        except Exception:
            after = None
        records_after = None
        if modifier_selected:
            try:
                records_after = self.country_records_source.context()
            except Exception:
                records_after = None
        if (not isinstance(after, dict) or _context_reason(after)
                or not _context_matches(before, after)
                or any(not _context_matches(scalar_after[name], before)
                       or not _context_matches(scalar_before[name], scalar_after[name]) for name in scalar_selected)
                or (modifier_selected and
                    (not _context_matches(records_after, before)
                     or not _context_matches(records_before, records_after)))):
            for name in selected:
                fields[name] = {'status': 'unavailable', 'reason': 'FINAL_ATTRIBUTES_CONTEXT_CHANGED'}
            return result(after if isinstance(after, dict) else before)

        if final_selected:
            try:
                if upstream is None:
                    raise ValueError(upstream_error or 'FINAL_ATTRIBUTES_UPSTREAM_UNAVAILABLE')
                source = _check_upstream_identity(
                    upstream, 'NativeMilitaryQualitySource', before,
                    query['object'], 'FINAL_ATTRIBUTES_UPSTREAM_IDENTITY_INVALID')
                attributes = {}
                for name in requested:
                    try:
                        attributes[name] = _project(upstream.get('fields', {}).get(name), name)
                    except ValueError as exc:
                        attributes[name] = {'status': 'unknown', 'reason': str(exc)}
                if any(item['status'] == 'known' for item in attributes.values()):
                    report_hash = source.get('provenance', {}).get('capture_report_sha256')
                    if not isinstance(report_hash, str) or not _SHA.fullmatch(report_hash):
                        raise ValueError('FINAL_ATTRIBUTES_UPSTREAM_EVIDENCE_MISSING')
                    result_hash = digest(upstream)
                    provenance.update(capture_report_sha256=report_hash,
                                      upstream_result_sha256=result_hash)
                    provenance['delegations']['N03'] = {
                        'capture_report_sha256': report_hash,
                        'result_sha256': result_hash,
                        'fields': list(requested),
                    }
                    if 'final_value' in final_selected:
                        fields['final_value'] = {'status': 'known', 'value': attributes,
                            'unit': 'attribute_map', 'scale': 1, 'period': 'current',
                            'complete': False, 'partial': True,
                            'gaps': ['OTHER_FINAL_ATTRIBUTES_NOT_IMPLEMENTED', 'NAMED_MODIFIER_SOURCE_BREAKDOWN_NOT_IMPLEMENTED']}
                elif 'final_value' in final_selected:
                    fields['final_value'] = {'status': 'unknown', 'reason': 'FINAL_ATTRIBUTES_UNAVAILABLE',
                                             'attributes': attributes}
                if 'source_breakdown' in final_selected:
                    fields['source_breakdown'] = _project_breakdown(
                        attributes['discipline'], source.get('provenance', {}))
            except (ValueError, TypeError, AttributeError) as exc:
                for name in final_selected:
                    fields[name] = {'status': 'unknown', 'reason': str(exc)}

        if scalar_selected:
            current = fields['final_value']
            attributes = (deepcopy(current.get('value', {})) if current.get('status') == 'known'
                          else deepcopy(current.get('attributes', {})))
            # A rejected N03 result cannot erase independent valid scalar siblings.
            for key in _ATTRIBUTES:
                attributes.setdefault(key, {'status': 'unknown',
                    'reason': current.get('reason', 'FINAL_ATTRIBUTES_UPSTREAM_UNAVAILABLE')})
            for name in scalar_selected:
                spec = _SCALAR_ATTRIBUTES[name]
                try:
                    if name in scalar_errors:
                        raise ValueError(scalar_errors[name])
                    delegated = scalar_upstreams.get(name)
                    source = _check_upstream_identity(delegated, spec['source'], before, query['object'],
                                                       'FINAL_ATTRIBUTE_SCALAR_IDENTITY_INVALID')
                    projected = _project_scalar_attribute(delegated.get('fields', {}).get(spec['field']), spec)
                    if projected['status'] == 'known':
                        evidence = source.get('provenance')
                        if not isinstance(evidence, dict):
                            raise ValueError('FINAL_ATTRIBUTE_SCALAR_EVIDENCE_MISSING')
                        report_hash, profile_hash = evidence.get('capture_report_sha256'), evidence.get('profile_sha256')
                        if (not isinstance(report_hash, str) or _SHA.fullmatch(report_hash) is None
                                or not isinstance(profile_hash, str) or _SHA.fullmatch(profile_hash) is None
                                or profile_hash != _scalar_profile_sha(spec)):
                            raise ValueError('FINAL_ATTRIBUTE_SCALAR_EVIDENCE_INVALID')
                        provenance['delegations'][spec['topic'] + '.' + spec['field']] = {
                            'topic': spec['topic'], 'fields': [spec['field']], 'profile_sha256': profile_hash,
                            'capture_report_sha256': report_hash, 'result_sha256': digest(delegated)}
                    attributes[name] = projected
                except (ValueError, KeyError, TypeError, AttributeError):
                    attributes[name] = {'status': 'unknown', 'reason': 'FINAL_ATTRIBUTE_SCALAR_UPSTREAM_INVALID'}
            if any(item.get('status') == 'known' for item in attributes.values()):
                fields['final_value'] = {'status': 'known', 'value': attributes,
                    'unit': 'attribute_map', 'scale': 1, 'period': 'current', 'complete': False, 'partial': True,
                    'gaps': ['OTHER_FINAL_ATTRIBUTES_NOT_IMPLEMENTED', 'NAMED_MODIFIER_SOURCE_BREAKDOWN_NOT_IMPLEMENTED']}
            else:
                fields['final_value'] = {'status': 'unknown', 'reason': 'FINAL_ATTRIBUTES_UNAVAILABLE',
                                         'attributes': attributes}

        if modifier_selected:
            try:
                if modifier_upstream is None:
                    raise ValueError(modifier_error or 'FINAL_ATTRIBUTES_MODIFIER_RECORDS_UNAVAILABLE')
                source = _check_upstream_identity(
                    modifier_upstream, 'NativeCountryRecordsSource', before,
                    query['object'], 'FINAL_ATTRIBUTES_MODIFIER_RECORDS_IDENTITY_INVALID')
                item = modifier_upstream.get('fields', {}).get('effects')
                projected = _project_modifier_effects(item)
                if projected.get('status') == 'known':
                    source_provenance = source.get('provenance')
                    if not isinstance(source_provenance, dict):
                        raise ValueError('FINAL_ATTRIBUTES_MODIFIER_RECORDS_EVIDENCE_MISSING')
                    report_hash = source_provenance.get('capture_report_sha256')
                    profile_hash = source_provenance.get('profile_sha256')
                    from . import country_modifiers_memory as native
                    if (not isinstance(report_hash, str) or _SHA.fullmatch(report_hash) is None
                            or profile_hash != native.EXPECTED_PROFILE_SHA256):
                        raise ValueError('FINAL_ATTRIBUTES_MODIFIER_RECORDS_EVIDENCE_INVALID')
                    result_hash = digest(modifier_upstream)
                    modifier_provenance = {
                        'capture_report_sha256': report_hash,
                        'profile_sha256': profile_hash,
                        'result_sha256': result_hash,
                        'fields': ['effects'],
                    }
                    provenance['modifier_records'] = deepcopy(modifier_provenance)
                    provenance['delegations']['N07'] = deepcopy(modifier_provenance)
                fields['modifier_effects'] = projected
            except (ValueError, TypeError, AttributeError) as exc:
                fields['modifier_effects'] = {'status': 'unknown', 'reason': str(exc)}
        return result()

    def change_comparison(self, query, sample, context):
        """Compare only a fully known supported attribute map, without upgrading coverage."""
        try:
            normalized = self.validate_query(query, context)
            if (normalized['fields'] != ['final_value'] or sample.get('topic') != 'N09'
                    or ('query' in sample and sample['query'] != normalized)):
                return None
            if _context_reason(context):
                return None
            source = _check_upstream_identity(sample, type(self).__name__, context,
                normalized['object'], 'FINAL_ATTRIBUTES_CHANGE_IDENTITY_INVALID')
            if set(sample.get('fields', {})) != {'final_value'}:
                return None
            field = sample['fields']['final_value']
            if (field.get('status') != 'known' or field.get('unit') != 'attribute_map'
                    or type(field.get('scale')) is not int or field['scale'] != 1
                    or field.get('period') != 'current' or field.get('complete') is not False
                    or field.get('partial') is not True):
                return None
            attributes = field.get('value')
            expected = {*_ATTRIBUTES, *self.scalar_sources}
            if not isinstance(attributes, dict) or set(attributes) != expected:
                return None
            for name in _ATTRIBUTES:
                if attributes[name].get('status') != 'known' or _project(attributes[name], name) != attributes[name]:
                    return None
            evidence = source.get('provenance', {}).get('delegations', {})
            military = evidence.get('N03', {})
            if military.get('fields') != list(_ATTRIBUTES):
                return None
            for name in ('capture_report_sha256', 'result_sha256'):
                if not isinstance(military.get(name), str) or not _SHA.fullmatch(military[name]):
                    return None
            profile_scope = []
            for name in _SCALAR_ATTRIBUTES:
                if name not in self.scalar_sources:
                    continue
                spec = _SCALAR_ATTRIBUTES[name]
                item = attributes[name]
                if item.get('status') != 'known' or _project_scalar_attribute(item, spec) != item:
                    return None
                delegated = evidence.get(spec['topic'] + '.' + spec['field'], {})
                profile_hash = _scalar_profile_sha(spec)
                if delegated.get('profile_sha256') != profile_hash or delegated.get('fields') != [spec['field']]:
                    return None
                for key in ('capture_report_sha256', 'result_sha256', 'profile_sha256'):
                    if not isinstance(delegated.get(key), str) or not _SHA.fullmatch(delegated[key]):
                        return None
                profile_scope.append(profile_hash)
            names = self.catalog()[0]['fields']['final_value']['supported_attributes']
            scope = ('N09.final_value.supported_attributes.v1:' + ','.join(names)
                     + ':' + ','.join(profile_scope))
            return {'schema': 'information.change_comparison.v1', 'scope': scope,
                    'fields': deepcopy(sample['fields'])}
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
