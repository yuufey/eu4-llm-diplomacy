"""Page static node members and qualify current province annotations via G02."""
from copy import deepcopy
import re

ANNOTATION_FIELDS = ('owner', 'controller', 'center_of_trade')
_STATIC_KEYS = ('status', 'game_version', 'game_sha256', 'definitions_sha256',
    'trade_definitions_sha256', 'configuration_sha256', 'config_sha256',
    'static_config_sha256', 'definition_files', 'configuration_files', 'enabled_mods',
    'trade_directory_members')


def _failure(reason, status='unknown'):
    return {'status': status, 'reason': reason, 'partial': True, 'complete': False, 'game_fact': False}


class TradeTargetsReader:
    def __init__(self, graph_reader, province_source, port_source=None, estuary_reader=None,
                 power_reader=None):
        self.graph_reader = graph_reader
        self.province_source = province_source
        self.port_source = port_source
        self.estuary_reader = estuary_reader
        self.power_reader = power_reader

    def _power(self, province_id, context):
        try:
            result = self.power_reader.read(province_id, context)
        except Exception:
            return _failure('TRADE_TARGET_POWER_READ_FAILED', 'unavailable')
        if not isinstance(result, dict):
            return _failure('TRADE_TARGET_POWER_RESULT_INVALID')
        if result.get('status') != 'known':
            reason = result.get('reason')
            if (not isinstance(reason, str) or not re.fullmatch(r'[A-Z0-9_:-]{1,128}', reason)
                    or '0x' in reason.lower()):
                reason = 'TRADE_TARGET_POWER_UNKNOWN'
            return _failure(reason, 'unavailable' if result.get('status') == 'unavailable' else 'unknown')
        source = result.get('source')
        proof = source.get('provenance') if isinstance(source, dict) else None
        value = result.get('value')
        if (type(result.get('province_id')) is not int or result['province_id'] != province_id
                or result.get('partial') is not True or result.get('complete') is not False
                or result.get('period') != 'current'
                or result.get('basis') != 'native_province_trade_power_trigger_cache'
                or result.get('acquisition_delta_evaluated') is not False
                or result.get('cache_refresh_timing_verified') is not False
                or result.get('game_date') != context.get('game_date')
                or not isinstance(value, dict) or set(value) != {'raw', 'scale', 'unit'}
                or type(value.get('raw')) is not int or not -(1 << 31) <= value['raw'] < (1 << 31)
                or type(value.get('scale')) is not int or value['scale'] != 1000
                or value.get('unit') != 'trade_power'
                or not isinstance(source, dict) or source.get('mode') != 'live'
                or source.get('status') != 'observed' or source.get('observer') != context.get('observer')
                or source.get('session_id') != context.get('session_id')
                or not isinstance(proof, dict) or proof.get('observer') != context.get('observer')
                or type(proof.get('province_id')) is not int or proof['province_id'] != province_id
                or proof.get('read_only') is not True or proof.get('native_function_invoked') is not False
                or not isinstance(proof.get('capture_report_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', proof['capture_report_sha256'])):
            return _failure('TRADE_TARGET_POWER_BINDING_INVALID')
        projected = deepcopy(result)
        if getattr(self.power_reader, 'with_value_calculation', False) is True:
            try:
                from .province_trade_power import _validate_value_calculation_annotation
                projected['value_calculation'] = _validate_value_calculation_annotation(
                    result.get('value_calculation'), province_id)
            except Exception:
                projected['value_calculation'] = {
                    'status': 'unknown',
                    'reason': 'TRADE_TARGET_VALUE_CALCULATION_INVALID',
                    'basis': 'native_province_trade_value_processor_absent',
                    'period': 'current', 'partial': True, 'complete': False,
                    'native_function_invoked': False,
                }
        if getattr(self.power_reader, 'with_node_cash', False) is True:
            from .node_cash_aggregate import validate_annotation
            projected['node_cash_aggregate'] = validate_annotation(result.get('node_cash_aggregate'))
        return projected

    @staticmethod
    def _configuration_binding(value):
        if not isinstance(value, dict):
            return None
        proof = value.get('provenance', value)
        files = proof.get('configuration_files') if isinstance(proof, dict) else None
        mods = value.get('enabled_mods')
        if mods is None and isinstance(proof, dict):
            mods = proof.get('enabled_mods')
        if not isinstance(files, list) or not 1 <= len(files) <= 512 or not isinstance(mods, list) or len(mods) > 256:
            return None
        rows = []
        for item in files:
            if not isinstance(item, dict):
                return None
            kind, path, sha = (item.get(k) for k in ('kind', 'path', 'sha256'))
            if kind not in ('launcher_settings', 'enabled_mod_config', 'mod_descriptor'):
                continue
            if (not isinstance(path, str) or not 1 <= len(path) <= 2048
                    or not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha)):
                return None
            rows.append((kind, path.replace('\\', '/').casefold(), sha))
        if (not {'launcher_settings', 'enabled_mod_config'} <= {r[0] for r in rows}
                or len(rows) != len(set((r[0], r[1]) for r in rows))):
            return None
        layers = []
        for mod in mods:
            if not isinstance(mod, dict) or not isinstance(mod.get('replace_paths'), list):
                return None
            paths = mod['replace_paths']
            if any(not isinstance(p, str) for p in paths):
                return None
            root, descriptor = mod.get('root'), mod.get('descriptor')
            if not isinstance(root, str) or not root or (descriptor is not None and not isinstance(descriptor, str)):
                return None
            layers.append((root.replace('\\', '/').casefold(),
                descriptor.replace('\\', '/').casefold() if descriptor else None,
                mod.get('descriptor_sha256'), tuple(p.replace('\\', '/').casefold() for p in paths)))
        return tuple(sorted(rows)), tuple(layers)

    def _estuary(self, province_id, context, graph_source):
        try:
            result = self.estuary_reader.read(province_id, context)
        except Exception:
            return _failure('TRADE_TARGET_ESTUARY_READ_FAILED', 'unavailable')
        if not isinstance(result, dict):
            return _failure('TRADE_TARGET_ESTUARY_RESULT_INVALID')
        if result.get('status') != 'known':
            reason = result.get('reason')
            if not isinstance(reason, str) or not re.fullmatch(r'[A-Z0-9_:-]{1,128}', reason) or '0x' in reason.lower():
                reason = 'TRADE_TARGET_ESTUARY_UNKNOWN'
            return _failure(reason, 'unavailable' if result.get('status') == 'unavailable' else 'unknown')
        source = result.get('source')
        proof = source.get('provenance') if isinstance(source, dict) else None
        rule = result.get('rule_binding')
        if (type(result.get('value')) is not bool or result.get('partial') is not True
                or result.get('complete') is not False or result.get('game_fact') is not False
                or result.get('engine_loaded_rule_verified') is not False
                or result.get('basis') != 'native_province_modifiers_under_effective_disk_estuary_rule'
                or result.get('game_date') != context.get('game_date')
                or not isinstance(source, dict) or source.get('mode') != 'live'
                or source.get('status') != 'observed' or source.get('observer') != context.get('observer')
                or source.get('session_id') != context.get('session_id')
                or not isinstance(proof, dict) or proof.get('observer') != context.get('observer')
                or type(proof.get('province_id')) is not int or proof['province_id'] != province_id
                or proof.get('read_only') is not True or proof.get('native_function_invoked') is not False
                or not isinstance(proof.get('capture_report_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', proof['capture_report_sha256'])
                or not isinstance(rule, dict) or rule.get('status') != 'known'
                or rule.get('game_fact') is not False or rule.get('context_scope') != 'static_rules'):
            return _failure('TRADE_TARGET_ESTUARY_BINDING_INVALID')
        rule_config = self._configuration_binding(rule)
        if rule_config is None or rule_config != self._configuration_binding(graph_source):
            return _failure('TRADE_TARGET_ESTUARY_CONFIGURATION_MISMATCH', 'unavailable')
        return deepcopy(result)

    def _port(self, province_id, context):
        query = {'topic': 'G04', 'object': {'type': 'province', 'province_id': province_id},
                 'fields': ['ports'], 'parameters': {}}
        try:
            result = self.port_source.read(query, context)
        except Exception:
            return _failure('TRADE_TARGET_PORT_READ_FAILED', 'unavailable')
        source = result.get('source') if isinstance(result, dict) else None
        fields = result.get('fields') if isinstance(result, dict) else None
        field = fields.get('ports') if isinstance(fields, dict) else None
        if not isinstance(field, dict):
            return _failure('TRADE_TARGET_PORT_RESULT_INVALID')
        if field.get('status') != 'known':
            return _failure(field.get('reason', 'TRADE_TARGET_PORT_UNKNOWN'),
                'unavailable' if field.get('status') == 'unavailable' else 'unknown')
        value = field.get('value')
        proof = source.get('provenance') if isinstance(source, dict) else None
        if (not isinstance(source, dict) or source.get('mode') != 'live'
                or source.get('status') != 'observed' or source.get('observer') != context.get('observer')
                or source.get('session_id') != context.get('session_id')
                or result.get('game_date') != context.get('game_date')
                or result.get('objects') != [query['object']]
                or not isinstance(proof, dict) or type(proof.get('province_id')) is not int
                or proof['province_id'] != province_id or proof.get('read_only') is not True
                or not isinstance(value, dict) or type(value.get('province_id')) is not int
                or value['province_id'] != province_id or type(value.get('has_port')) is not bool):
            return _failure('TRADE_TARGET_PORT_BINDING_INVALID')
        return {'status': 'known', 'value': value['has_port'], 'source': deepcopy(source),
                'game_date': result['game_date'], 'basis': 'native_has_port_scope_predicate',
                'partial': True, 'complete': False}

    def _annotation(self, province_id, context):
        query = {'topic': 'G02', 'object': {'type': 'province', 'province_id': province_id},
                 'fields': list(ANNOTATION_FIELDS), 'parameters': {}}
        try:
            result = self.province_source.read(query, context)
        except Exception:
            return _failure('TRADE_TARGET_PROVINCE_READ_FAILED', 'unavailable')
        source = result.get('source') if isinstance(result, dict) else None
        fields = result.get('fields') if isinstance(result, dict) else None
        proof = source.get('provenance') if isinstance(source, dict) else None
        if (not isinstance(source, dict) or source.get('mode') != 'live'
                or source.get('status') != 'observed' or source.get('observer') != context.get('observer')
                or source.get('session_id') != context.get('session_id')
                or result.get('game_date') != context.get('game_date')
                or result.get('objects') != [query['object']]
                or not isinstance(proof, dict) or proof.get('province_id') != province_id
                or proof.get('observer') != context.get('observer') or proof.get('read_only') is not True
                or not isinstance(fields, dict) or set(fields) != set(ANNOTATION_FIELDS)
                or any(not isinstance(v, dict) for v in fields.values())):
            return _failure('TRADE_TARGET_PROVINCE_BINDING_INVALID')
        return {'status': 'known' if any(v.get('status') == 'known' for v in fields.values()) else 'unknown',
                'fields': deepcopy(fields), 'source': deepcopy(source),
                'game_date': result['game_date'], 'complete': False}

    def read(self, node_id, context, page=None):
        page = page or {'offset': 0, 'limit': 4}
        try:
            before = self.graph_reader.context()
            graph = self.graph_reader.read(node_id, context)
        except Exception:
            return _failure('TRADE_TARGET_GRAPH_READ_FAILED', 'unavailable')
        if not isinstance(graph, dict) or graph.get('status') != 'known':
            return _failure(graph.get('reason', 'TRADE_TARGET_GRAPH_UNKNOWN') if isinstance(graph, dict)
                            else 'TRADE_TARGET_GRAPH_INVALID',
                            'unavailable' if isinstance(graph, dict) and graph.get('status') == 'unavailable' else 'unknown')
        rows = graph.get('rows')
        if (not isinstance(rows, list) or len(rows) > 4096
                or any(not isinstance(row, dict) or type(row.get('province_id')) is not int
                    or not 1 <= row['province_id'] <= 65535 or row.get('node_id') != node_id
                    or row.get('membership_kind') != 'member' for row in rows)):
            return _failure('TRADE_TARGET_GRAPH_ROWS_INVALID')
        selected = deepcopy(rows[page['offset']:page['offset'] + page['limit']])
        cache = {}; port_cache = {}; estuary_cache = {}; power_cache = {}
        for row in selected:
            province = row['province_id']
            if province not in cache:
                cache[province] = self._annotation(province, context)
            row['current_annotations'] = deepcopy(cache[province])
            row['current_trade_power'] = _failure('PROVINCE_TRADE_POWER_NOT_CAPTURED')
            if self.power_reader is not None:
                if province not in power_cache:
                    power_cache[province] = self._power(province, context)
                row['current_trade_power'] = deepcopy(power_cache[province])
            row['classification'] = {name: {'status': 'unknown', 'reason': reason}
                for name, reason in (
                    ('key_center_of_trade', 'TRADE_TARGET_STRATEGIC_PRIORITY_NOT_EVALUATED'),
                    ('port', 'PROVINCE_PORT_NOT_CAPTURED'), ('estuary', 'PROVINCE_ESTUARY_NOT_CAPTURED'),
                    ('eligibility', 'TERRITORIAL_ACTION_ELIGIBILITY_NOT_EVALUATED'),
                    ('expected_benefit', 'TERRITORIAL_POWER_AND_INCOME_EFFECT_NOT_EVALUATED'))}
            if self.port_source is not None:
                if province not in port_cache:
                    port_cache[province] = self._port(province, context)
                row['classification']['port'] = deepcopy(port_cache[province])
            if self.estuary_reader is not None:
                if province not in estuary_cache:
                    estuary_cache[province] = self._estuary(province, context, graph.get('source'))
                row['classification']['estuary'] = deepcopy(estuary_cache[province])
        try:
            after = self.graph_reader.context()
        except Exception:
            after = {}
        if (before.get('status') != 'ready' or after.get('status') != 'ready'
                or any(before.get(k) != after.get(k) for k in _STATIC_KEYS)):
            return _failure('TRADE_TARGET_STATIC_CONTEXT_CHANGED', 'unavailable')
        next_offset = page['offset'] + len(selected)
        return {'status': 'known', 'partial': True, 'complete': False, 'game_fact': False,
            'value': {'schema': 'information.trade_targets.v1', 'node_id': node_id,
                'candidate_basis': 'effective_disk_node_members_not_engine_loaded_membership',
                'rows': selected, 'candidate_count': len(rows), 'page': deepcopy(page),
                'next_offset': next_offset if next_offset < len(rows) else None,
                'topology': deepcopy(graph.get('topology')), 'static_source': deepcopy(graph.get('source')),
                'province_reads': len(cache), 'port_reads': len(port_cache),
                'estuary_reads': len(estuary_cache),
                'power_reads': len(power_cache),
                'province_annotation_fields': list(ANNOTATION_FIELDS),
                'cross_request_cache': False, 'atomic_game_snapshot': False,
                'trade_diplomatic_relation_targets': {'status': 'unknown', 'reason': 'RELATION_TARGETS_NOT_EVALUATED'},
                'complete': False, 'game_fact': False}}
