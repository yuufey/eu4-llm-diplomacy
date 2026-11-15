"""R04 yearly changes derived from copied native tooltip inputs."""
from copy import deepcopy
import re
from .opinion_modifiers import NativeOpinionModifiersSource, _decimal_i32
from .opinion_modifiers_memory import _same
from .opinion_decay_memory import FIELDS, UNIT, yearly_contribution
from .sources import _result, _source_info

GAPS=['NATIVE_TOOLTIP_YEARLY_CONTRIBUTION_ONLY','ACTUAL_YEARLY_SETTLEMENT_NOT_OBSERVED',
      'OTHER_PROCESSOR_TYPES_OR_NONZERO_SECONDARY_UNRESOLVED',
      'NONZERO_PAIR_EFFECT_RELATIONSHIP_UNRESOLVED',
      'MODIFIER_EXPIRY_NOT_PROVEN',
      'OTHER_COMPUTED_OPINION_SOURCES_NOT_COVERED']

class NativeOpinionDecaySource(NativeOpinionModifiersSource):
    """Reuse the same identity, pair validation, capture and result lifecycle."""
    field='decay'

    def catalog(self):
        topic=super().catalog()[0]
        topic['scope_note']='逻辑FRA参与的国家对；按原生提示路径推导逐记录年度变化，未知因子保留。'
        topic['fields']={self.field:{'source':type(self).__name__,'coverage':'partial',
            'complete':False,'unit':UNIT,'scale':1000,'period':'per_year_at_current_state',
            'basis':'native_opinion_tooltip_yearly_contribution',
            'value_origin':'derived_from_copied_native_yearly_inputs',
            'supported_object_types':['country_pair'],'gaps':list(GAPS),
            'description':'当前具名修正在原生提示路径中的年度变化贡献；正数恢复好感，负数降低好感。'}}
        return [topic]

    def _capture_functions(self):
        from . import opinion_decay_capture
        return self._capture or opinion_decay_capture.capture, self._validator or opinion_decay_capture.validate_capture

    @staticmethod
    def _project_record(row):
        if not isinstance(row,dict):raise ValueError('decay record shape')
        if row.get('status')=='unknown' and set(row)=={'status','reason'}:
            reason=row['reason']
            if not isinstance(reason,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',reason):
                raise ValueError('decay record reason')
            return deepcopy(row)
        expected={'status','modifier_id','current_opinion_raw','base_yearly_raw',
                  'suppress_yearly_raw','factor','yearly_change'}
        if set(row)!=expected or row['status']!='known':raise ValueError('decay record shape')
        key=row['modifier_id']
        if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',key):
            raise ValueError('decay key')
        projected=yearly_contribution(row['current_opinion_raw'],row['base_yearly_raw'],
                                      row['suppress_yearly_raw'],row['factor'])
        if not _same(row['yearly_change'],projected):raise ValueError('decay projection mismatch')
        if projected['status']!='known':
            return {'modifier_id':key,**deepcopy(projected)}
        value=projected['raw']
        return {'status':'known','modifier_id':key,'yearly_change_raw':value,
                'yearly_change_decimal':_decimal_i32(value),'unit':UNIT,'scale':1000,
                'basis':projected['basis']}

    def _project_backend(self,report,other,actor,recipient):
        try:
            backend=report['observation']['backend']
            if backend['status']!='observed' or backend['consistency']['status']!='stable':
                raise ValueError('unstable')
            targets=backend['targets']
            if len(targets)!=1 or targets[0]['tag']!=other:raise ValueError('target')
            fields=targets[0]['fields']
            if set(fields)!=set(FIELDS):raise ValueError('fields')
            directions=[]
            for holder,target in ((actor,recipient),(recipient,actor)):
                item=fields[FIELDS[0] if holder=='FRA' else FIELDS[1]]
                direction={'holder':holder,'target':target}
                if item.get('status') in ('unknown','invisible'):
                    direction.update(status=item['status'],reason='OPINION_DECAY_DIRECTION_UNKNOWN')
                else:
                    if (set(item)!={'status','value','unit','scale','complete'} or item['status']!='known'
                            or item['unit']!=UNIT or type(item['scale']) is not int or item['scale']!=1000
                            or item['complete'] is not False):raise ValueError('field shape')
                    value=item['value']
                    if (set(value)!={'holder','target','records'} or value['holder']!=holder
                            or value['target']!=target or not isinstance(value['records'],list)
                            or len(value['records'])>256):raise ValueError('direction shape')
                    direction.update(status='known',records=[self._project_record(r) for r in value['records']])
                directions.append(direction)
            result={'unit':UNIT,'scale':1000,'period':'per_year_at_current_state',
                    'complete':False,'partial':True,'basis':'native_opinion_tooltip_yearly_contribution',
                    'value_origin':'derived_from_copied_native_yearly_inputs','gaps':list(GAPS)}
            if any(d['status']=='known' for d in directions):return {**result,'status':'known','value':directions}
            state='invisible' if all(d['status']=='invisible' for d in directions) else 'unknown'
            return {**result,'status':state,'directions':directions,'reason':'OPINION_DECAY_DIRECTIONS_UNKNOWN'}
        except (KeyError,TypeError,ValueError,AttributeError):
            return {'status':'unknown','reason':'OPINION_DECAY_BACKEND_INVALID'}

    @staticmethod
    def _result(normalized,context,fields,*,reason=None,unavailable=False,target=None,capture_status='not_attempted'):
        provenance={'adapter':'NativeOpinionDecaySource','read_only':True,'native_function_invoked':False,
                    'scope':'selected_country_pair','observer':'FRA','target':target,
                    'capture_status':capture_status,'actual_settlement_evaluated':False,
                    'end_date_evaluated':False,'yearly_contribution_derived':True}
        if reason is not None:provenance['reason']=reason
        source=_source_info('NativeOpinionDecaySource',context,complete=False,provenance=provenance)
        source['context_scope']='selected_country_pair'
        if unavailable:source['status']='unavailable'
        return _result(normalized,context,fields,False,source)
