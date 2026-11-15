"""Conditional trade-income sensitivity over a single validated native baseline.

This is an explicit mathematical model, not an engine forecast. It calibrates
income against the observed power ratio and holds the surrounding trade
environment fixed except for the caller's two stated power deltas.
"""
from copy import deepcopy
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
import re

from .catalog import get_topic
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_province_power_scenarios import POWER_INPUT_MODEL, TOTAL_POWER_INPUT_MODEL, derive_power_scenarios

FIELDS = ('expected_trade', 'assumptions')
_ID = r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
_NODE = r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'
_I32_MAX = (1 << 31) - 1
_I32_MIN = -(1 << 31)
_MODEL = 'calibrated_fixed_environment_power_ratio_v1'
_CONTEXT_KEYS = ('status', 'mode', 'observer', 'session_id', 'world_id', 'game_version', 'game_sha256', 'game_date')
_ASSUMPTIONS = [
    {'id': 'power_ratio_proxy', 'description': '用本国竞争力与总竞争力缓存的比值作为模型代理，不声称这是界面已核对的份额。'},
    {'id': 'calibrate_current_income', 'description': '从同份采集的当前可收取收入校准比例系数。'},
    {'id': 'fixed_trade_environment', 'description': '保持节点价值、流入流出、贸易效率和收取策略不变。'},
    {'id': 'explicit_power_deltas', 'description': '只应用调用者给定的本国与总竞争力变化，其他竞争行为固定。'},
    {'id': 'no_territorial_inference', 'description': '不推算取得省份、战争、任务奖励或外交行为能产生多少竞争力。'},
    {'id': 'cache_and_snapshot_limits', 'description': '沿用输入缓存的新鲜度和非原子快照限制，不证明实际未来收入。'},
]


def _schema(with_costs=False, with_targets=False):
    schema = {'type': 'object', 'required': ['scenarios'], 'additionalProperties': False,
            'properties': {'scenarios': {'type': 'array', 'minItems': 1, 'maxItems': 8,
                'items': {'type': 'object', 'required': ['id'],
                    'oneOf': [
                        {'required': ['country_power_delta_raw', 'total_power_delta_raw'],
                         'not': {'anyOf': [{'required': [key]} for key in
                            ('power_input_model', 'province_power_delta_raw', 'total_power_input_model')]}},
                        {'required': ['power_input_model', 'province_power_delta_raw', 'total_power_delta_raw'],
                         'not': {'anyOf': [{'required': [key]} for key in
                            ('country_power_delta_raw', 'total_power_input_model')]}},
                        {'required': ['power_input_model', 'province_power_delta_raw', 'total_power_input_model'],
                         'not': {'anyOf': [{'required': [key]} for key in
                            ('country_power_delta_raw', 'total_power_delta_raw')]}}],
                    'additionalProperties': False, 'properties': {
                        'id': {'type': 'string', 'pattern': _ID},
                        'country_power_delta_raw': {'type': 'integer', 'minimum': _I32_MIN, 'maximum': _I32_MAX},
                        'power_input_model': {'type': 'string', 'const': POWER_INPUT_MODEL, 'enum': [POWER_INPUT_MODEL]},
                        'total_power_input_model': {'type': 'string', 'const': TOTAL_POWER_INPUT_MODEL, 'enum': [TOTAL_POWER_INPUT_MODEL]},
                        'province_power_delta_raw': {'type': 'integer', 'minimum': _I32_MIN, 'maximum': _I32_MAX},
                        'total_power_delta_raw': {'type': 'integer', 'minimum': _I32_MIN, 'maximum': _I32_MAX},
                        'description': {'type': 'string', 'minLength': 1, 'maxLength': 512}}}}}}
    if with_costs:
        schema['properties']['scenarios']['items']['properties']['actions'] = {
            'type': 'array', 'minItems': 1, 'maxItems': 16,
            'items': {'type': 'object', 'required': ['id', 'action_id', 'recipient', 'parameters'],
                'additionalProperties': False, 'properties': {
                    'id': {'type': 'string', 'maxLength': 64},
                    'action_id': {'type': 'string', 'enum': ['declare_war', 'cede_province']},
                    'recipient': {'type': 'string', 'pattern': '^[A-Z]{3}$'},
                    'parameters': {'type': 'object', 'additionalProperties': True}}}}
    if with_targets:
        schema['required'] = []
        schema['properties']['target_page'] = {'type': 'object', 'additionalProperties': False,
            'required': ['offset', 'limit'], 'properties': {
                'offset': {'type': 'integer', 'minimum': 0, 'maximum': 4096},
                'limit': {'type': 'integer', 'minimum': 1, 'maximum': 16}}}
    return schema


def _failure(reason, status='unknown', **extra):
    return {'status': status, 'reason': reason, 'partial': True, 'complete': False,
            'game_fact': False, **deepcopy(extra)}


def _exact(value):
    value = Fraction(value)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def _money(raw, period):
    raw = Fraction(raw)
    with localcontext() as ctx:
        ctx.prec = 80
        decimal = (Decimal(raw.numerator) / Decimal(raw.denominator) / 1000).quantize(
            Decimal('0.000001'), rounding=ROUND_HALF_EVEN)
        if decimal.is_zero():
            decimal = decimal.copy_abs()
    return {'exact_raw': _exact(raw), 'decimal': format(decimal, 'f'), 'unit': 'ducats', 'scale': 1000,
            'period': period, 'decimal_rounding': 'half_even_6_places'}


def project_scenarios(baseline, scenarios):
    """Pure bounded calculation; exact fractions are the authoritative result."""
    if not isinstance(baseline, dict) or baseline.get('status') != 'known':
        reason = baseline.get('reason', 'TRADE_SCENARIO_BASELINE_UNAVAILABLE') if isinstance(baseline, dict) else 'TRADE_SCENARIO_BASELINE_INVALID'
        status = 'unavailable' if isinstance(baseline, dict) and baseline.get('status') == 'unavailable' else 'unknown'
        return {name: _failure(reason, status) for name in FIELDS}
    fields = baseline.get('fields', {})
    if not isinstance(fields, dict):
        return {name: _failure('TRADE_SCENARIO_BASELINE_INVALID') for name in FIELDS}
    reason = None
    for name, unit in (('income', 'ducats'), ('country_power', 'trade_power'), ('total_power', 'trade_power')):
        field = fields.get(name)
        if (not isinstance(field, dict) or field.get('status') != 'known' or field.get('unit') != unit
                or type(field.get('scale')) is not int or field['scale'] != 1000
                or type(field.get('raw')) is not int or not _I32_MIN <= field['raw'] <= _I32_MAX
                or type(field.get('value')) is not int or field['value'] != field['raw']):
            reason = 'TRADE_SCENARIO_BASELINE_UNITS_OR_VALUES_INVALID'
            break
    collection = fields.get('collection', {})
    if not reason and (not isinstance(collection, dict) or collection.get('status') != 'known'
                       or type(collection.get('value')) is not bool):
        reason = 'TRADE_SCENARIO_COLLECTION_UNKNOWN'
    if reason:
        return {name: _failure(reason) for name in FIELDS}
    income = fields['income']['raw']
    own = fields['country_power']['raw']
    total = fields['total_power']['raw']
    if collection['value'] is not True or fields['income'].get('eligible') is not True:
        reason = 'TRADE_SCENARIO_BASELINE_NOT_COLLECTING'
    elif income < 0:
        reason = 'TRADE_SCENARIO_NEGATIVE_INCOME_UNSUPPORTED'
    elif own <= 0 or total <= 0 or own > total:
        reason = 'TRADE_SCENARIO_BASELINE_POWER_OUTSIDE_MODEL_DOMAIN'
    assumptions = {'status': 'known', 'partial': True, 'complete': False, 'game_fact': False,
        'value': {'schema': 'information.trade_power_scenarios.assumptions.v1', 'model': _MODEL,
            'formula': 'I_new = I * (P_new / T_new) / (P / T)',
            'system_assumptions': deepcopy(_ASSUMPTIONS), 'caller_scenarios': deepcopy(scenarios),
            'power_delta_unit': 'trade_power', 'power_delta_scale': 1000,
            'baseline': deepcopy(fields), 'model_domain_status': 'unknown' if reason else 'satisfied',
            'collection_policy': deepcopy(collection),
            'unmeasured_fixed_components': [
                {'component': name, 'status': 'unknown', 'model_treatment': 'held_fixed_not_measured'}
                for name in ('node_value', 'inflows_outflows', 'trade_efficiency')],
            'calibrated_income_factor_raw': (
                {'status': 'unknown', 'reason': reason} if reason else
                {'status': 'known', 'exact_raw': _exact(Fraction(income * total, own)),
                 'unit': 'ducats', 'scale': 1000, 'basis': 'I_times_T_divided_by_P',
                 'native_node_value_or_efficiency': False}),
            'model_domain_reason': reason, 'game_fact': False, 'complete': False}}
    if reason:
        return {'expected_trade': _failure(reason, baseline=deepcopy(fields)), 'assumptions': assumptions}
    rows = []
    period = fields['income'].get('period', 'current')
    for scenario in scenarios:
        row = {'id': scenario['id'], 'inputs': deepcopy(scenario)}
        next_own = own + scenario['country_power_delta_raw']
        next_total = total + scenario['total_power_delta_raw']
        if not 0 <= next_own <= _I32_MAX or not 0 < next_total <= _I32_MAX or next_own > next_total:
            row.update(status='unknown', reason='SCENARIO_POWER_OUTSIDE_MODEL_DOMAIN')
        else:
            expected = Fraction(income * next_own * total, own * next_total)
            row.update(status='known', expected_income=_money(expected, period),
                income_delta=_money(expected - income, period),
                scenario_country_power_raw=next_own, scenario_total_power_raw=next_total,
                modeled_power_ratio=_exact(Fraction(next_own, next_total)))
        rows.append(row)
    value = {'schema': 'information.trade_power_scenarios.v1', 'model': _MODEL,
        'baseline': deepcopy(fields), 'baseline_modeled_power_ratio': _exact(Fraction(own, total)),
        'scenarios': rows, 'actual_future_income': 'unknown', 'game_fact': False, 'complete': False}
    if any(row['status'] == 'known' for row in rows):
        expected_field = {'status': 'known', 'partial': True, 'complete': False, 'game_fact': False, 'value': value}
    else:
        expected_field = _failure('NO_SCENARIO_WITHIN_MODEL_DOMAIN', value=value)
    return {'expected_trade': expected_field, 'assumptions': assumptions}


def project_native_power_scenarios(baseline, scenarios):
    """Compose native power arithmetic with the existing conditional income model."""
    if not any('power_input_model' in row for row in scenarios):
        return project_scenarios(baseline, scenarios)
    derived = derive_power_scenarios(baseline, scenarios)
    result = project_scenarios(baseline, derived['resolved_scenarios'])
    transitions = derived['transitions']
    expected = result['expected_trade']
    # Keep country-power results usable even when income cannot be calibrated.
    expected['native_power_scenarios'] = [
        {'id': row['id'], 'inputs': deepcopy(row), 'power_transition': deepcopy(transitions[row['id']])}
        for row in scenarios if row['id'] in transitions]
    value = expected.get('value')
    if isinstance(value, dict):
        resolved_rows = {row['id']: row for row in value['scenarios']}
        rows = []
        for scenario in scenarios:
            identifier = scenario['id']
            transition = transitions.get(identifier)
            row = resolved_rows.get(identifier)
            if row is None:
                row = {'id': identifier, 'status': 'unknown', 'reason': transition['reason']}
            row['inputs'] = deepcopy(scenario)
            if transition is not None:
                row['power_transition'] = deepcopy(transition)
            rows.append(row)
        value['scenarios'] = rows
    assumptions = result['assumptions'].get('value')
    if isinstance(assumptions, dict):
        automatic_total = any('total_power_input_model' in row for row in scenarios)
        assumptions['caller_scenarios'] = deepcopy(scenarios)
        assumptions['power_input_model'] = POWER_INPUT_MODEL
        assumptions['native_power_components'] = deepcopy(baseline.get('native_power_components'))
        if automatic_total:
            assumptions['native_power_sum_membership'] = deepcopy(baseline.get('native_power_sum_membership'))
            income_calculation = baseline.get('native_income_calculation')
            if not isinstance(income_calculation, dict):
                income_calculation = {'status': 'unknown',
                    'reason': 'NATIVE_INCOME_CALCULATION_UNAVAILABLE'}
            assumptions['native_income_calculation'] = deepcopy(income_calculation)
            assumptions['total_power_input_model'] = TOTAL_POWER_INPUT_MODEL
        for item in assumptions['system_assumptions']:
            if item['id'] == 'explicit_power_deltas':
                item['description'] = ('手工情景使用给定的本国变化；省份来源情景按原生整数规则推导本国变化。显式总量使用调用者给定值；选择固定其它国家模式时，须先核对求和成员再推导总量。'
                    if automatic_total else '手工情景使用给定的本国变化；省份来源情景按原生整数规则推导本国变化。总竞争力变化均由调用者给定。')
        assumptions['system_assumptions'].extend([
            {'id': 'fixed_native_power_inputs', 'description': '省份来源情景只改变本国节点基础项；倍率、减项和加项固定，限额按已确认的原生分支刷新。'},
            ({'id': 'total_power_input', 'description': '总量须明确给定或选择固定其它国家模式；后者要求法国在原生求和列表中恰好贡献一次，按32位求和规则计算。'} if automatic_total else
             {'id': 'explicit_total_power_delta', 'description': '总竞争力变化仍需明确提供，不从本国变化或各国合计推导。'}),
            {'id': 'conditional_refresh', 'description': '基线须与现有公式相符且刷新不改变当前值；计算不证明游戏何时刷新或实际发生了行动。'}])
        if automatic_total:
            assumptions['system_assumptions'].append({'id': 'fixed_other_country_power',
                'description': '法国只贡献一次，列表和其它国家贡献保持不变；把当前总量解释为该求和阶段基线，忽略后续调用和网络反应，不证明缓存刷新时点。'})
            assumptions['system_assumptions'].append({'id': 'native_current_income_calculation',
                'description': '附带当前收入缓存算术重建供核对；这不是未来收入预测，现有条件收入代理保持不变。'})
    return result


class TradeScenarioSource:
    event_types = ()

    def __init__(self, baseline_reader, cost_reader=None, target_reader=None):
        self.baseline_reader = baseline_reader
        self.cost_reader = cost_reader
        self.target_reader = target_reader

    def _fields(self):
        return (*FIELDS, *(['costs'] if self.cost_reader is not None else []),
                *(['targets'] if self.target_reader is not None else []))

    def context(self):
        return deepcopy(self.baseline_reader.context())

    def catalog(self):
        topic = get_topic('T06')
        topic.update(status='available', source=type(self).__name__, object_types=['trade_node'],
            observer_roles=[], supported_countries=['FRA'], supported_versions=['1.37.4'],
            context_scope='country_scope', visibility='conditional_analysis',
            parameters=_schema(self.cost_reader is not None, self.target_reader is not None), triggers=['query', 'periodic'])
        topic['fields'] = {name: {'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'game_fact': False, 'basis': _MODEL, 'period': 'conditional_current_cache_scenario',
            'description': ('固定环境假设下、显式竞争力变化的条件收入估算，不是实际未来收益'
                            if name == 'expected_trade' else '本次条件估算实际使用的系统假设、基线及调用者竞争力变化'),
            'gaps': ['ACTUAL_FUTURE_INCOME_UNKNOWN', 'TERRITORIAL_POWER_CHANGES_NOT_INFERRED',
                     'TRADE_NETWORK_REACTIONS_AND_COSTS_NOT_SIMULATED', 'NATIVE_CACHE_FRESHNESS_NOT_PROVEN']}
            for name in FIELDS}
        for name in FIELDS:
            topic['fields'][name]['power_input_models'] = ['explicit_country_power_delta', POWER_INPUT_MODEL]
            topic['fields'][name]['native_power_scenario_condition'] = 'validated native components; fixed multiplier/subtract/add; modeled cap refresh; explicit total delta or verified exactly-once sum membership with other country contributions fixed'
            topic['fields'][name]['total_power_input_models'] = ['explicit_total_power_delta', TOTAL_POWER_INPUT_MODEL]
        if self.cost_reader is not None:
            topic['fields']['costs'] = {'coverage': 'partial', 'source': type(self).__name__,
                'complete': False, 'game_fact': False, 'period': 'current_state_action_previews',
                'basis': 'native_selected_action_rule_preview',
                'description': '按显式情景编号关联的当前行动成本预览；不推算行动产生的竞争力变化或完整战争代价',
                'gaps': ['FUTURE_MULTISTEP_STATE_NOT_SIMULATED', 'COMPLETE_CAMPAIGN_COSTS_UNKNOWN',
                    'TRADE_DIPLOMATIC_OPPORTUNITY_COSTS_UNKNOWN', 'ACTION_POWER_DELTA_LINK_NOT_EVALUATED']}
        if self.target_reader is not None:
            topic['fields']['targets'] = {'coverage': 'partial', 'source': type(self).__name__,
                'complete': False, 'game_fact': False, 'period': 'static_members_and_current_province_page',
                'basis': 'effective_static_node_members_with_existing_G02_annotations',
                'description': '节点候选省份分页，提供当前归属、贸易中心、港口、河口与已接入的贸易力量注释；不证明可扩张或取得省份后的收益',
                'gaps': ['ENGINE_LOADED_MEMBERSHIP_NOT_VERIFIED', 'PORT_FACILITIES_AND_ENGINE_LOADED_ESTUARY_RULE_NOT_VERIFIED',
                    'STRATEGIC_PRIORITY_AND_ACTION_ELIGIBILITY_NOT_EVALUATED',
                    'TERRITORIAL_TRADE_BENEFIT_NOT_EVALUATED', 'DIPLOMATIC_TARGETS_NOT_EVALUATED']}
            power_reader = getattr(self.target_reader, 'power_reader', None)
            if power_reader is not None:
                topic['fields']['targets']['current_trade_power_annotation'] = {
                    'path': 'rows[].current_trade_power', 'unit': 'trade_power', 'scale': 1000,
                    'numeric_modifier_inputs': bool(getattr(power_reader, 'with_numeric_inputs', False)),
                    'numeric_input_units': {'province_trade_power_value': 'trade_power',
                        'province_trade_power_modifier': 'ratio',
                        'province_trade_power_further_modifier': 'ratio'},
                    'numeric_input_condition': 'per-read processor pointer must remain NULL',
                    'country_modifier_inputs': bool(getattr(power_reader, 'with_country_inputs', False)),
                    'country_input_path': 'rows[].current_trade_power.country_modifiers',
                    'country_input_roles': ['controller', 'observer'],
                    'country_input_unit': 'ratio',
                    'country_input_condition': 'canonical country binding, country-view admission, stable NPC observer; cache state 0 or 2 and processor NULL',
                    'current_power_calculation': bool(getattr(power_reader, 'with_calculation', False)),
                    'calculation_path': 'rows[].current_trade_power.calculation',
                    'calculation_mode': 'cache_writer_zero_additional_inputs',
                    'calculation_cache_freshness_proven': False,
                    'province_node_allocation': bool(getattr(power_reader, 'with_node_allocation', False)),
                    'node_allocation_path': 'rows[].current_trade_power.node_allocation',
                    'node_allocation_observer': 'FRA',
                    'node_allocation_component': 'TP_PROVINCE_POWER',
                    'province_value_calculation': bool(getattr(power_reader, 'with_value_calculation', False)),
                    'province_value_path': 'rows[].current_trade_power.value_calculation',
                    'node_cash_aggregate': bool(getattr(power_reader, 'with_node_cash', False)),
                    'node_cash_path': 'rows[].current_trade_power.node_cash_aggregate',
                    'node_cash_calculation_stage': 'province_member_sum_before_network_flow',
                    'node_cash_cache_comparison': 'current_node_total_cache',
                    'node_cash_includes_network_flow': False,
                    'node_cash_same_update_phase_verified': False,
                    'node_cash_identified_refresh_paths': ['calendar_month_change', 'initialization'],
                    'node_cash_refresh_path_basis': 'static_binary_paths_not_observed_refresh_time',
                    'node_cash_all_members_required_for_cache_comparison': True,
                    'node_cash_cache_refresh_verified': False,
                    'acquisition_delta_evaluated': False}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or not {'topic', 'object', 'fields'} <= set(query)
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'T06 query has missing or unknown keys')
        if query['topic'] != 'T06':
            raise InformationError('unsupported_topic', 'TradeScenarioSource supports T06')
        obj = query['object']
        if (not isinstance(obj, dict) or set(obj) != {'type', 'node_id'} or obj.get('type') != 'trade_node'
                or not isinstance(obj.get('node_id'), str) or re.fullmatch(_NODE, obj['node_id']) is None
                or obj['node_id'] == 'Null'):
            raise InformationError('invalid_object', 'T06 model requires an explicit trade_node')
        fields = query['fields']
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) or f not in self._fields() for f in fields)
                or len(fields) != len(set(fields))):
            raise InformationError('invalid_fields', 'Unsupported T06 scenario field')
        params = query.get('parameters', {})
        allowed_params = {'scenarios'} | ({'target_page'} if self.target_reader is not None else set())
        if (not isinstance(params, dict) or set(params) - allowed_params
                or (any(f != 'targets' for f in fields) and 'scenarios' not in params)):
            raise InformationError('invalid_parameters', 'T06 income and cost fields require scenarios')
        page = params.get('target_page')
        if 'target_page' in params and (not isinstance(page, dict) or set(page) != {'offset', 'limit'}
                or type(page['offset']) is not int or not 0 <= page['offset'] <= 4096
                or type(page['limit']) is not int or not 1 <= page['limit'] <= 16):
            raise InformationError('invalid_parameters', 'T06 target_page requires bounded offset and limit')
        scenarios = params.get('scenarios', [])
        if 'scenarios' in params and (not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 8):
            raise InformationError('invalid_parameters', 'T06 requires one to eight scenarios')
        ids = set()
        for row in scenarios:
            derived = isinstance(row, dict) and 'power_input_model' in row
            delta_key = 'province_power_delta_raw' if derived else 'country_power_delta_raw'
            automatic_total = derived and 'total_power_input_model' in row
            total_key = 'total_power_input_model' if automatic_total else 'total_power_delta_raw'
            required = {'id', delta_key, total_key} | ({'power_input_model'} if derived else set())
            if (not isinstance(row, dict) or not required <= set(row)
                    or (derived and row['power_input_model'] != POWER_INPUT_MODEL)
                    or (automatic_total and row[total_key] != TOTAL_POWER_INPUT_MODEL)
                    or set(row) - (required | {'description'}
                                  | ({'actions'} if self.cost_reader is not None else set()))
                    or not isinstance(row['id'], str) or re.fullmatch(_ID, row['id']) is None or row['id'] in ids
                    or any(type(row[k]) is not int or not _I32_MIN <= row[k] <= _I32_MAX
                           for k in ((delta_key,) if automatic_total else (delta_key, 'total_power_delta_raw')))
                    or ('description' in row and (not isinstance(row['description'], str)
                        or not row['description'].strip() or len(row['description']) > 512))):
                raise InformationError('invalid_parameters', 'T06 scenario shape, ID or raw power delta is invalid')
            ids.add(row['id'])
        try:
            if len(canonical(params).encode('utf-8')) > 65536:
                raise ValueError('input_limit')
        except (ValueError, TypeError, UnicodeError) as exc:
            raise InformationError('invalid_parameters', 'T06 parameters exceed JSON bounds') from exc
        if isinstance(context, dict) and context.get('observer') not in (None, 'FRA'):
            raise InformationError('observer_scope_mismatch', 'T06 baseline is verified for FRA')
        if (any(f in fields for f in ('costs', 'targets')) and isinstance(context, dict) and context.get('status') == 'ready'
                and context.get('observer') != 'FRA'):
            raise InformationError('observer_scope_mismatch', 'T06 cost previews require the FRA observer binding')
        normalized = deepcopy(query)
        normalized['parameters'] = deepcopy(params)
        if 'costs' in fields:
            from .candidate_action_costs import normalize_plans
            plans = normalize_plans([{'id': row['id'], 'actions': row.get('actions')}
                for row in scenarios], 'FRA', plan_id_pattern=re.compile(_ID))
            for row, plan in zip(normalized['parameters']['scenarios'], plans):
                row['actions'] = plan['actions']
        return normalized

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        baseline = None
        baseline_attempted = False
        if current.get('status') != 'ready':
            fields = {name: _failure('source_unavailable', 'unavailable') for name in normalized['fields']}
        else:
            try:
                fields = {}
                if any(name != 'targets' for name in normalized['fields']):
                    baseline_attempted = True
                    native_mode = any('power_input_model' in row for row in normalized['parameters']['scenarios'])
                    automatic_total = any(
                        'total_power_input_model' in row
                        for row in normalized['parameters']['scenarios']
                    )
                    options = ({'with_power_components': True} if native_mode
                        and getattr(self.baseline_reader, 'supports_native_power_components', False) is True else {})
                    if (automatic_total
                            and getattr(self.baseline_reader, 'supports_native_power_sum', False) is True):
                        options['with_sum_membership'] = True
                    if (automatic_total
                            and getattr(self.baseline_reader, 'supports_native_income_calculation', False) is True
                            and getattr(self.baseline_reader, 'supports_native_power_sum', False) is True):
                        options['with_income_calculation'] = True
                    baseline = self.baseline_reader.read(normalized['object']['node_id'], current, **options)
                    fields = project_native_power_scenarios(baseline, normalized['parameters']['scenarios'])
                if 'costs' in normalized['fields']:
                    plans = [{'id': row['id'], 'actions': row['actions']}
                             for row in normalized['parameters']['scenarios']]
                    fields['costs'] = self.cost_reader.read(plans, current.get('observer'), current)
                if 'targets' in normalized['fields']:
                    try:
                        fields['targets'] = self.target_reader.read(normalized['object']['node_id'], current,
                            normalized['parameters'].get('target_page'))
                    except Exception:
                        fields['targets'] = _failure('TRADE_TARGET_READ_FAILED', 'unavailable')
                after = self.context()
                if any(current.get(k) != after.get(k) for k in _CONTEXT_KEYS):
                    fields = {name: _failure('TRADE_SCENARIO_CONTEXT_CHANGED', 'unavailable') for name in normalized['fields']}
            except Exception as exc:
                fields = {name: _failure(getattr(exc, 'code', 'TRADE_SCENARIO_READ_FAILED'), 'unavailable') for name in normalized['fields']}
        selected = {name: deepcopy(fields[name]) for name in normalized['fields']}
        provenance = {'model': _MODEL, 'read_only': True, 'game_fact': False,
            'engine_forecast': False, 'baseline_source': deepcopy(baseline.get('source')) if isinstance(baseline, dict) else None,
            'baseline_reads': int(baseline_attempted), 'atomic_game_snapshot': False}
        if any('power_input_model' in row for row in normalized['parameters'].get('scenarios', [])):
            provenance['power_input_model'] = POWER_INPUT_MODEL
        if any('total_power_input_model' in row for row in normalized['parameters'].get('scenarios', [])):
            provenance['total_power_input_model'] = TOTAL_POWER_INPUT_MODEL
        source = _source_info(type(self).__name__, current, complete=False, provenance=provenance)
        source.update(context_scope='country_scope', projection_version=1)
        result = _result(normalized, current, selected, False, source)
        if len(canonical(result).encode('utf-8')) > 4 * 1024 * 1024:
            result = _result(normalized, current,
                {name: _failure('TRADE_SCENARIO_OUTPUT_LIMIT_EXCEEDED') for name in normalized['fields']}, False,
                _source_info(type(self).__name__, current, complete=False,
                             provenance={'model': _MODEL, 'game_fact': False, 'output_limit_exceeded': True}))
        return result

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
