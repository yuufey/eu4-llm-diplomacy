"""Expose bounded province fields for provinces discovered by the configured observer."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from collections.abc import Mapping

from ..native_text import decode_native_text_hex
from . import mission_texts
from .model import InformationError,canonical
from .sources import _result,_source_info
from .trade_income import NativeTradeIncomeSource,_observer_context_reason as _base_reason,_identity,_session_binding

FIELDS=('owner','controller','culture','religion','autonomy','development','resource','center_of_trade')
BASIS='native_actor_discovery_bit_positive_and_canonical_province_country_references'
ORIGIN='copied_native_province_owner_controller_references'
TAG=re.compile(r'[A-Z0-9]{3}\Z')
REASON=re.compile(r'[A-Z0-9_:-]{1,128}\Z')
NAME_HEX=re.compile(r'[0-9a-fA-F]{2,256}\Z')
RESOURCE_NAME_HEX=re.compile(r'(?:[0-9a-fA-F]{2}){0,8192}\Z')
RESOURCE_LANGUAGE=re.compile(r'l_[A-Za-z0-9_]{1,32}\Z')
RESOURCE_KEY=re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')
_REPORT_NAME_MISSING=object()
UNITS={'owner':('country_tag',1),'controller':('country_tag',1),
    'culture':('native_display_name',1),'religion':('native_display_name_and_icon_frame_request',1),
    'autonomy':('percent',1000),'development':('development',1000),
    'resource':('native_resource_definition',1),'center_of_trade':('native_center_of_trade',1)}


def _basis(name):
    if name in ('owner','controller'):return BASIS,ORIGIN
    if name=='autonomy':return ('native_province_autonomy_display_clamp',
        'copied_native_autonomy_current_lower_and_upper_caches')
    if name=='development':return ('native_province_effective_development_total',
        'copied_native_base_components_and_conditional_owner_tribal_bonus')
    if name=='resource':return ('native_province_resource_definition_inputs',
        'copied_native_resource_localization_key_icon_index_and_cached_literal_name')
    if name=='center_of_trade':return ('native_province_center_of_trade_state',
        'copied_native_center_presence_level_kind_and_sprite_key')
    return ('native_province_'+name+'_display_inputs','copied_native_province_'+name+'_name_cache')


def _reason(value,fallback):
    if isinstance(value,str) and REASON.fullmatch(value) and '0x' not in value.lower():return value
    return fallback


def _field(status,reason=None,value=None,*,name='owner'):
    basis,origin=_basis(name)
    out={'status':status,'period':'current','basis':basis,'value_origin':origin,
        'partial':True,'complete':False}
    if reason is not None:out['reason']=reason
    if status=='known' and value is not None:out['value']=value
    return out


def _project_resource_name(value):
    def unknown(reason):
        return {'status':'unknown','reason':_reason(reason,'RESOURCE_NAME_INVALID')}

    if not isinstance(value,Mapping):
        return unknown('RESOURCE_NAME_INVALID')
    if value.get('status')=='unknown':
        return unknown(value.get('reason'))
    if value.get('status')!='known':
        return unknown('RESOURCE_NAME_INVALID')
    raw_hex=value.get('raw_hex')
    language=value.get('language')
    if (not isinstance(raw_hex,str) or not RESOURCE_NAME_HEX.fullmatch(raw_hex)
            or not isinstance(language,str) or not RESOURCE_LANGUAGE.fullmatch(language)):
        return unknown('RESOURCE_NAME_INVALID')
    try:
        raw=bytes.fromhex(raw_hex)
        if b'\0' in raw:
            return unknown('RESOURCE_NAME_INVALID')
        decoded=mission_texts.decode_template(raw_hex,'eu4_escape')
    except (TypeError,ValueError,UnicodeError):
        return unknown('RESOURCE_NAME_INVALID')
    if not isinstance(decoded,Mapping) or decoded.get('status')!='known':
        reason=decoded.get('reason') if isinstance(decoded,Mapping) else None
        return unknown(reason or 'RESOURCE_NAME_UNKNOWN')
    text=decoded.get('text')
    if not isinstance(text,str) or not text.strip():
        return unknown('RESOURCE_NAME_EMPTY')
    return {'status':'known','text':text,'raw_hex':raw_hex.lower(),
        'encoding':'eu4_escape','language':language,
        'lookup_semantics':'native_FNV1_hash_only',
        'literal_key_collision_excluded':False}


def _project(value,name):
    def invalid():return _field('unknown','PROVINCE_STATE_FIELD_INVALID',name=name)
    if not isinstance(value,Mapping):return invalid()
    if value.get('status')=='known':
        item=value.get('value')
        if name in ('owner','controller'):
            if isinstance(item,str) and TAG.fullmatch(item):return _field('known',value=item,name=name)
            return invalid()
        if name in ('autonomy','development'):
            minimum=0 if name=='autonomy' else -(1<<31)
            if type(item) is int and minimum<=item<1<<31:return _field('known',value=item,name=name)
            return invalid()
        if name=='resource':
            if not isinstance(item,Mapping):return invalid()
            key,index=item.get('localization_key'),item.get('icon_index')
            if (not isinstance(key,str) or not RESOURCE_KEY.fullmatch(key)
                    or type(index) is not int or not -(1<<31)<=index<1<<31):return invalid()
            captured_name=item.get('name',_REPORT_NAME_MISSING)
            projected_name=({'status':'unknown','reason':'RESOURCE_NAME_NOT_CAPTURED'}
                if captured_name is _REPORT_NAME_MISSING else _project_resource_name(captured_name))
            return _field('known',value={'localization_key':key,'icon_index':index,
                'name':projected_name},name=name)
        if name=='center_of_trade':
            if not isinstance(item,Mapping) or type(item.get('present')) is not bool:return invalid()
            present,level=item['present'],item.get('level')
            if type(level) is not int:return invalid()
            if present is False:
                if level!=0:return invalid()
                return _field('known',value={'present':False,'level':0},name=name)
            kind=item.get('kind')
            if not 1<=level<1<<31 or kind not in ('coastal','inland'):return invalid()
            sprite='GFX_center_of_trade_'+kind+'_'+str(level)
            if item.get('sprite_key')!=sprite:return invalid()
            return _field('known',value={'present':True,'level':level,'kind':kind,'sprite_key':sprite},name=name)
        try:
            if not isinstance(item,Mapping) or not isinstance(item.get('name'),Mapping):return invalid()
            text=item['name']['text'];raw_hex=item['name']['raw_hex'];encoding=item['name']['encoding']
            if (not isinstance(text,str) or not text or not isinstance(raw_hex,str)
                    or not NAME_HEX.fullmatch(raw_hex) or encoding!='eu4_escape'
                    or b'\0' in bytes.fromhex(raw_hex)):return invalid()
            decoded=decode_native_text_hex(raw_hex,codec='eu4_escape',max_bytes=128)
            if decoded!=text:return invalid()
            projected={'name':{'text':decoded,'raw_hex':raw_hex.lower(),'encoding':'eu4_escape'}}
            if name=='religion':
                frame=item['icon_frame_request']
                if type(frame) is not int or not -(1<<31)<=frame<1<<31:return invalid()
                projected['icon_frame_request']=frame
            elif name!='culture':return invalid()
            return _field('known',value=projected,name=name)
        except (KeyError,TypeError,ValueError):return invalid()
    return _field('unknown',_reason(value.get('reason'),'PROVINCE_STATE_FIELD_UNKNOWN'),name=name)


class NativeProvinceStateSource(NativeTradeIncomeSource):
    event_types=()

    def catalog(self):
        return [{'topic_id':'G02','catalog_ids':['G02'],'title':'省份状态与资源（部分）',
            'status':'available','object_types':['province'],'observer_roles':[],
            'observer_scope':[],'parameters':{'type':'object','properties':{},'required':[],
                'additionalProperties':False},'supported_versions':['1.37.4'],'triggers':['query','periodic'],
            'source':type(self).__name__,'context_scope':'visible_scope','visibility':'visible_scope',
            'scope_note':'按已配置观察国的省份发现位检查可见性。发现位为 0 时返回 unknown。八个字段均为部分证据。文化和宗教仅含名称。发展度包含已确认的所有者部落分量。资源和贸易中心字段可含缓存字面名称、图标或 sprite 键，界面渲染另需证据。',
            'fields':{name:{'coverage':'partial','complete':False,'unit':UNITS[name][0],'scale':UNITS[name][1],
                'period':'current','basis':_basis(name)[0],'value_origin':_basis(name)[1],
                'source':'bridge.information.province_state_capture.capture',
                'paths':["capture.observation.backend.targets[0].fields['G02."+name+"']"],
                'supported_observers':[],'supported_province_id_range':[1,65535],
                'runtime_validation':'province_state_capture.validate_capture',
                'gaps':['FULL_PROVINCE_VISIBILITY_NOT_COMPLETE','ZERO_DISCOVERY_BIT_NOT_CLASSIFIED',
                    'UNOWNED_AND_SPECIAL_REFERENCES_UNSUPPORTED','NONATOMIC_READ_AND_CACHE_FRESHNESS']+
                    {'resource':['CACHED_LITERAL_NAME_IS_NOT_UI_VISIBILITY_OR_RENDER_PROOF',
                        'NATIVE_FNV1_HASH_ONLY','LITERAL_KEY_COLLISION_NOT_EXCLUDED',
                        'FULL_UI_RESOURCE_VISIBILITY_UNVERIFIED','LATENT_RESOURCE_NOT_CAPTURED',
                        'ICON_INDEX_IS_NOT_A_RENDERED_OR_REQUESTED_FRAME'],
                     'development':['FULL_DEVELOPMENT_TOOLTIP_NOT_CAPTURED'],
                     'center_of_trade':['UPGRADE_COSTS_AND_PERMISSIONS_NOT_CAPTURED',
                        'SPRITE_KEY_IS_NOT_RENDERED']}.get(name,[])}
                for name in FIELDS}}]

    def validate_query(self,query,context=None):
        if not isinstance(query,dict):raise InformationError('invalid_parameters','query must be an object')
        if not {'topic','object','fields'}<=set(query) or set(query)-{'topic','object','fields','parameters'}:
            raise InformationError('invalid_parameters','G02 query has missing or unknown keys')
        if query['topic']!='G02':raise InformationError('unknown_topic','G02 source only')
        obj=query['object']
        if (not isinstance(obj,dict) or set(obj)!={'type','province_id'} or obj['type']!='province'
                or type(obj['province_id']) is not int or not 1<=obj['province_id']<65536):
            raise InformationError('invalid_object','G02 requires one supported positive province_id')
        fields=query['fields']
        if (not isinstance(fields,list) or not fields or len(fields)>len(FIELDS)
                or any(not isinstance(x,str) or x not in FIELDS for x in fields)
                or len(set(fields))!=len(fields)):
            raise InformationError('invalid_fields','G02 source supports '+', '.join(FIELDS))
        params=query.get('parameters',{})
        if not isinstance(params,dict) or params:raise InformationError('invalid_parameters','G02 has no extra parameters')
        if context is not None and not isinstance(context,dict):
            raise InformationError('invalid_context','Province context must be an object')
        return {'topic':'G02','object':deepcopy(obj),'fields':list(fields),'parameters':{}}

    @staticmethod
    def _context_reason(context):
        reason=_base_reason(context)
        return reason.replace('TRADE_INCOME_','PROVINCE_STATE_',1) if reason else None

    def read(self,query,context=None):
        current=deepcopy(context) if isinstance(context,dict) else self.context()
        query=self.validate_query(query,current);province_id=query['object']['province_id']
        provenance={'observer':current.get('observer'),'province_id':province_id,'read_only':True,
            'native_function_invoked':False,'actual_UI_observed':False,'basis':BASIS,
            'full_province_visibility_complete':False}
        def result(fields,ctx=current):
            source=_source_info(type(self).__name__,ctx,complete=False,provenance=deepcopy(provenance))
            source.update(context_scope='visible_scope',projection_version=4)
            return _result(query,ctx,fields,False,source)
        def failure(reason,ctx=current,unavailable=False):
            return result({name:_field('unavailable' if unavailable else 'unknown',reason,name=name)
                for name in query['fields']},ctx)
        reason=self._context_reason(current)
        if reason:return failure(reason,unavailable=True)
        try:before=self.context()
        except Exception:return failure('PROVINCE_STATE_CONTEXT_UNAVAILABLE',unavailable=True)
        reason=self._context_reason(before)
        if reason:return failure(reason,before,True)
        if _identity(current)!=_identity(before):return failure('PROVINCE_STATE_CONTEXT_STALE',before,True)
        installation,creation,binding_reason=_session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return failure(binding_reason or 'PROVINCE_STATE_INSTALLATION_UNAVAILABLE',before,True)
        try:module=import_module('.province_state_capture',__package__)
        except Exception:return failure('PROVINCE_STATE_CAPTURE_UNAVAILABLE',before,True)
        capture=self.capture if self.capture is not None else getattr(module,'capture',None)
        if not callable(capture):return failure('PROVINCE_STATE_CAPTURE_UNAVAILABLE',before,True)
        report=None;error=None
        try:report=capture(installation,province_id=province_id,observer=before['observer'])
        except Exception as exc:error='PROVINCE_STATE_CAPTURE_FAILED:'+type(exc).__name__
        try:after=self.context()
        except Exception:after={}
        if self._context_reason(after) or _identity(before)!=_identity(after):
            return failure('PROVINCE_STATE_CONTEXT_CHANGED_DURING_CAPTURE',before,True)
        final_installation,final_creation,final_reason=_session_binding(self.base_source)
        if final_reason or final_installation!=installation or final_creation!=creation:
            return failure('PROVINCE_STATE_SESSION_CHANGED_DURING_CAPTURE',before,True)
        if error:return failure(error,before)
        try:valid=module.validate_capture(report,before,creation,province_id)
        except Exception:valid=False
        if valid is not True:return failure('PROVINCE_STATE_CAPTURE_INVALID',before)
        try:
            if not isinstance(report,Mapping) or not isinstance(report.get('object'),Mapping):raise ValueError('object')
            if report.get('schema')!='information.province_state_capture.v1' or report.get('observer')!=before['observer']:
                raise ValueError('capture schema or observer')
            if (set(report['object'])!={'type','province_id'}
                    or report['object']['type']!='province'
                    or type(report['object']['province_id']) is not int
                    or report['object']['province_id']!=province_id):raise ValueError('object')
            backend=report['capture']['observation']['backend']
            if not isinstance(backend,Mapping):raise ValueError('backend')
            if not isinstance(backend.get('observer'),Mapping) or backend['observer'].get('tag')!=before['observer']:
                raise ValueError('observer')
            targets=backend['targets']
            if not isinstance(targets,list) or len(targets)!=1:raise ValueError('targets')
            item=targets[0]
            if not isinstance(item,Mapping):raise ValueError('target')
            if type(item.get('province_id')) is not int or item['province_id']!=province_id:raise ValueError('province')
            provenance['capture_report_sha256']=hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            gate=item['admission_by_pass']['pass2']
            if not isinstance(gate,Mapping) or gate.get('status')!='known' or gate.get('admitted') is not True:
                reason=_reason(gate.get('reason') if isinstance(gate,Mapping) else None,
                    'PROVINCE_DISCOVERY_NOT_ESTABLISHED')
                return result({name:_field('unknown',reason,name=name) for name in query['fields']},before)
            discoveries=item.get('discovery_by_pass')
            if (not isinstance(discoveries,Mapping) or any(
                    not isinstance(discoveries.get(phase),Mapping)
                    or discoveries[phase].get('status')!='known'
                    or discoveries[phase].get('value') is not True
                    for phase in ('pass1','pass2'))):
                return result({name:_field('unknown','PROVINCE_DISCOVERY_NOT_ESTABLISHED',name=name)
                    for name in query['fields']},before)
            fields=item['fields']
            if not isinstance(fields,Mapping):raise ValueError('fields')
            return result({name:_project(fields.get('G02.'+name),name) for name in query['fields']},before)
        except (KeyError,TypeError,ValueError,IndexError):
            return failure('PROVINCE_STATE_CAPTURE_SHAPE_INVALID',before)


__all__=['NativeProvinceStateSource']
