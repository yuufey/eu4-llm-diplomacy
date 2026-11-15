"""Connect G04 territory/node selectors to the existing T05 transfer reader."""
from copy import deepcopy
import re

from .catalog import get_topic, validate_query as validate_catalog_query
from .model import InformationError
from .sources import _result, _source_info
from .trade_details import _details_context_reason

FIELD = 'transfer_relations'
_NODE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_STATIC_KEYS = ('game_version', 'configuration_sha256', 'definitions_sha256')
_GAPS = ['NATIVE_CACHE_FRESHNESS_NOT_PROVEN', 'OTHER_COUNTRIES_NOT_SUPPORTED',
         'TRANSFER_VALUES_ARE_NOT_INCOME_OR_ALL_DIPLOMATIC_RELATIONS']


def _field(status, reason=None, **values):
    item = {'status': status, 'partial': True, 'complete': False,
            'period': 'current', 'basis': 'existing_T05_transfer_for_selected_geographic_node'}
    if reason is not None:
        item['reason'] = reason
    item.update(deepcopy(values))
    return item


def _node(value):
    return isinstance(value, str) and _NODE.fullmatch(value) is not None and value != 'Null'


class GeographicTradeTransferSource:
    event_types = ()

    def __init__(self, primary, transfers, static_trade=None):
        self.primary = primary
        self.transfers = transfers
        self.static_trade = static_trade

    def context(self):
        return deepcopy(self.primary.context())

    def catalog(self):
        upstream = next(item for item in self.transfers.catalog() if item['topic_id'] == 'T05')
        topic = get_topic('G04')
        objtypes = ['trade_node'] + (['province'] if self.static_trade is not None else [])
        topic.update(status='available', source=type(self).__name__, context_scope='country_scope',
            visibility='observer_trade_node_cache', observer_roles=['country'],
            supported_versions=deepcopy(upstream['supported_versions']),
            triggers=deepcopy(upstream['triggers']), object_types=objtypes,
            parameters={'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False},
            fields={FIELD: {
                'coverage': 'partial', 'complete': False, 'source': type(self).__name__,
                'description': '指定节点，或省份按当前有效磁盘配置所属节点中，观察国的贸易权转出和转入来源记录',
                'supported_countries': ['FRA'], 'supported_object_types': objtypes,
                'unit': 'trade_power', 'scale': 1000, 'period': 'current',
                'basis': 'existing_T05_transfer_for_selected_geographic_node',
                'value_origin': 'NativeTradeTransferSource.T05.transfer',
                'province_membership_basis': 'effective_disk_trade_definition',
                'loaded_province_membership_verified': False,
                'gaps': _GAPS + ['DISK_PROVINCE_MEMBERSHIP_NOT_PROVEN_EQUAL_TO_LOADED_RULES'],
            }})
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or set(query) - {'topic', 'object', 'fields', 'parameters'}:
            raise InformationError('invalid_parameters', 'G04 requires declared query keys')
        normalized = validate_catalog_query(query, context)
        if normalized['topic'] != 'G04' or normalized['fields'] != [FIELD]:
            raise InformationError('invalid_fields', 'G04 transfer source supports transfer_relations only')
        obj = normalized['object']
        if obj['type'] == 'trade_node':
            proxy = {'topic': 'T05', 'object': deepcopy(obj), 'fields': ['transfer'], 'parameters': {}}
            validated = self.transfers.validate_query(proxy, context)
            normalized['object'] = deepcopy(validated['object'])
        elif obj['type'] == 'province' and self.static_trade is not None:
            proxy = {'topic': 'G04', 'object': deepcopy(obj), 'fields': ['trade_node'], 'parameters': {}}
            validated = self.static_trade.validate_query(proxy, context)
            normalized['object'] = deepcopy(validated['object'])
        else:
            raise InformationError('invalid_object', 'Province selection requires the static trade source')
        return normalized

    @staticmethod
    def _static_fingerprint(value):
        if not isinstance(value, dict) or value.get('status') != 'ready':
            return None
        if value.get('game_version') != '1.37.4':
            return None
        if any(not isinstance(value.get(key), str) or _SHA.fullmatch(value[key]) is None
               for key in _STATIC_KEYS[1:]):
            return None
        return {key: value[key] for key in _STATIC_KEYS}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        obj = normalized['object']
        provenance = {'delegate_topic': 'T05', 'delegate_field': 'transfer',
                      'requested_object': deepcopy(obj), 'native_reader_changed': False}

        def finish(field):
            source = _source_info(type(self).__name__, current, complete=False, provenance=provenance)
            source['context_scope'] = 'country_scope'
            if field.get('status') == 'unavailable':
                source['status'] = 'unavailable'
            return _result(normalized, current, {FIELD: field}, False, source)

        reason = _details_context_reason(current)
        if reason is not None:
            return finish(_field('unavailable', reason))

        selected = {'basis': 'explicit_trade_node', 'loaded_membership_verified': None}
        fingerprint = None
        if obj['type'] == 'province':
            before = self.static_trade.context()
            fingerprint = self._static_fingerprint(before)
            if fingerprint is None:
                return finish(_field('unavailable', 'GEOGRAPHIC_TRADE_STATIC_CONTEXT_UNAVAILABLE'))
            selected_result = self.static_trade.read({'topic': 'G04', 'object': deepcopy(obj),
                'fields': ['trade_node'], 'parameters': {}}, current)
            selected_fields = selected_result.get('fields') if isinstance(selected_result, dict) else None
            selected_field = selected_fields.get('trade_node') if isinstance(selected_fields, dict) else None
            if not isinstance(selected_field, dict):
                return finish(_field('unknown', 'GEOGRAPHIC_TRADE_MEMBERSHIP_INVALID'))
            if selected_field.get('status') != 'known':
                return finish(_field('unavailable' if selected_field.get('status') == 'unavailable' else 'unknown',
                    selected_field.get('reason') or 'GEOGRAPHIC_TRADE_MEMBERSHIP_UNKNOWN'))
            node_id = selected_field.get('value')
            selected = {'basis': 'effective_disk_trade_definition', 'province_id': obj['province_id'],
                'loaded_membership_verified': False, 'definition_fingerprint': deepcopy(fingerprint)}
            provenance['static_selection_source'] = deepcopy(selected_result.get('source'))
        else:
            node_id = obj['node_id']
        if not _node(node_id):
            return finish(_field('unknown', 'GEOGRAPHIC_TRADE_NODE_INVALID'))
        selected['node_id'] = node_id
        provenance['selection'] = deepcopy(selected)
        proxy = {'topic': 'T05', 'object': {'type': 'trade_node', 'node_id': node_id},
                 'fields': ['transfer'], 'parameters': {}}
        original = self.transfers.read(proxy, current)
        if not isinstance(original, dict):
            return finish(_field('unknown', 'GEOGRAPHIC_TRADE_TRANSFER_RESULT_INVALID'))
        provenance['delegate_source'] = deepcopy(original.get('source'))
        transferred_fields = original.get('fields')
        transferred = transferred_fields.get('transfer') if isinstance(transferred_fields, dict) else None
        if fingerprint is not None and fingerprint != self._static_fingerprint(self.static_trade.context()):
            return finish(_field('unavailable', 'GEOGRAPHIC_TRADE_STATIC_CONTEXT_CHANGED'))
        if not isinstance(transferred, dict):
            return finish(_field('unknown', 'GEOGRAPHIC_TRADE_TRANSFER_RESULT_INVALID'))
        status = transferred.get('status')
        if status != 'known':
            status = status if status in ('unknown', 'unavailable', 'unsupported', 'not_applicable', 'stale', 'not_visible') else 'unknown'
            return finish(_field(status, transferred.get('reason') or 'GEOGRAPHIC_TRADE_TRANSFER_UNKNOWN'))
        source = original.get('source')
        if (not isinstance(source, dict) or source.get('status') != 'observed' or source.get('mode') != 'live'
                or source.get('observer') != 'FRA' or source.get('session_id') != current.get('session_id')
                or current.get('mode') != 'live' or current.get('status') != 'ready'
                or current.get('observer') != 'FRA' or original.get('game_date') != current.get('game_date')):
            return finish(_field('unavailable', 'GEOGRAPHIC_TRADE_TRANSFER_CONTEXT_MISMATCH'))
        value = transferred.get('value')
        if (not isinstance(value, dict) or value.get('node_id') != node_id
                or not isinstance(value.get('to'), dict) or not isinstance(value.get('from'), dict)
                or transferred.get('unit') != 'trade_power' or type(transferred.get('scale')) is not int
                or transferred['scale'] != 1000 or transferred.get('complete') is not False):
            return finish(_field('unknown', 'GEOGRAPHIC_TRADE_TRANSFER_RESULT_INVALID'))
        result_value = deepcopy(value)
        result_value.update(observer='FRA', selection=deepcopy(selected),
            relation_scope='observer_trade_node_transfer_cache')
        return finish(_field('known', value=result_value, unit=transferred['unit'], scale=1000,
            value_origin='NativeTradeTransferSource.T05.transfer', gaps=deepcopy(_GAPS)))
