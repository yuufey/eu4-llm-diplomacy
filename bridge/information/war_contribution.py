"""W04 current participation shares for a selected war or participating country."""
from copy import deepcopy

from . import war_contribution_capture as _capture
from .catalog import get_topic, validate_query
from .model import InformationError, digest
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _session_binding


class NativeWarContributionSource(NativeTradeIncomeSource):
    def catalog(self):
        topic = get_topic('W04')
        topic.update(source=type(self).__name__, status='available',
                     object_types=['war', 'country'], observer_roles=['actor'], observer_scope=[],
                     supported_versions=['1.37.4'], context_scope='visible_scope', visibility='visible_scope',
                     triggers=['query', 'periodic', 'change'])
        topic['fields'] = {'contribution': {
            'coverage': 'available', 'complete': True, 'period': 'current', 'scale': 1,
            'unit': 'war_participation_percent', 'source': type(self).__name__,
            'description': '所选战争双方的当前参战贡献百分比，国家视图按观察国正在参与的战争分别列出。',
            'basis': 'native_war_overview_participationValue_d95820'}}
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'W04' or normalized['fields'] != ['contribution']:
            raise InformationError('invalid_fields', 'Expected W04.contribution')
        if normalized['parameters']:
            raise InformationError('invalid_parameters', 'War contribution takes no extra parameters')
        obj = normalized['object']
        if obj['type'] == 'war':
            if not obj.get('actor') or not obj.get('recipient') or obj['actor'] == obj['recipient']:
                raise InformationError('invalid_object', 'War contribution requires the observer and an opponent')
            if context is not None and obj['actor'] != context.get('observer'):
                raise InformationError('observer_scope_mismatch', 'W04 war actor must be the configured observer country')
        if obj['type'] == 'country' and not obj.get('country'):
            raise InformationError('invalid_object', 'War contribution requires a country tag')
        return normalized

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        objects = [deepcopy(query['object'])]
        field = {'status': 'unknown', 'reason': 'WAR_CONTRIBUTION_UNAVAILABLE'}
        proof = {'read_only': True, 'basis': 'native_war_overview_participationValue_d95820'}
        installation, creation, reason = _session_binding(self.base_source)
        reason = reason or _observer_context_reason(current)
        try:
            if reason:
                field = {'status': 'unavailable', 'reason': reason}
            else:
                selected = None
                if query['object']['type'] == 'war':
                    discovery = self.base_source.read({
                        'topic': 'W01', 'object': deepcopy(query['object']),
                        'fields': ['war_id'], 'parameters': {}}, current)
                    identity = discovery['fields']['war_id']
                    if identity.get('status') != 'known':
                        return _result(query, current, {'contribution': deepcopy(identity)}, False,
                                       _source_info(type(self).__name__, current, complete=False), objects)
                    selected = identity['value']
                    requested = query['object'].get('war_id')
                    if requested is not None and selected != requested:
                        raise ValueError('WAR_CONTRIBUTION_WAR_CHANGED')
                    objects = [dict(query['object'], war_id=selected)]
                report = (self.capture(installation) if self.capture is not None
                          else _capture.capture(installation, observer=current['observer']))
                if not _capture.validate_capture(report, current, creation):
                    raise ValueError('WAR_CONTRIBUTION_CAPTURE_INVALID')
                field = _capture.field_from_capture(report)
                proof['capture_report_sha256'] = digest(report)
                if field.get('status') == 'known':
                    wars = field['value']
                    if selected is not None:
                        war = next((war for war in wars if war['war_id'] == selected), None)
                        if war is None:
                            raise ValueError('WAR_CONTRIBUTION_WAR_CHANGED')
                        field['value'] = {side: war[side] for side in ('our_side', 'opposing_side')}
                        field['complete'] = war['complete']
                        field['gaps'] = deepcopy(war['gaps'])
                    else:
                        country = query['object']['country']
                        if country in field.get('raw_inputs', {}).get('unavailable_countries', []):
                            field = {'status': 'unknown', 'reason': 'WAR_CONTRIBUTION_COUNTRY_UNAVAILABLE'}
                        else:
                            field['value'] = [dict(war_id=war['war_id'], side=side,
                                                   **war[side][country]['value'])
                                for war in wars for side in ('our_side', 'opposing_side') if country in war[side]]
                            field['complete'] = all(row['war_id'] is not None for row in field['value'])
                    field.pop('raw_inputs', None)
        except Exception as exc:
            field = {'status': 'unknown', 'reason': 'WAR_CONTRIBUTION_READ_FAILED:' + type(exc).__name__}
        complete = field.get('status') == 'known' and field.get('complete', True) is True
        return _result(query, current, {'contribution': field}, complete,
                       _source_info(type(self).__name__, current, complete=complete, provenance=proof), objects)
