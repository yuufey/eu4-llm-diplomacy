"""Foreign F02 technology, manpower, and diplomacy force statistics."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any

from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _identity, _session_binding
from . import foreign_quality_projection as _quality_projection

_TAG=re.compile(r'[A-Z0-9]{3}\Z')
_SAFE_REASON=re.compile(r'[A-Z][A-Z0-9_]{0,95}\Z')
_FIELDS=('military_technology','manpower','visibility','visible_army','visible_navy','military_quality')
_TECH_BASIS='native_country_view_predicate_projected_to_observer'
_MANPOWER_BASIS='native_manpower_statistic'
_ARMY_BASIS='native_diplomacy_soldier_statistic'
_NAVY_BASIS='native_diplomacy_ship_statistic'
_STATS_BASIS='native_country_military_stats_visibility_permission'
_UNKNOWN='unknown'
_I32_MIN=-(1<<31)
_I32_MAX=(1<<31)-1
_FORCE_FIELDS={
    'visible_army':('F02.visible_army','soldiers',_ARMY_BASIS,True),
    'visible_navy':('F02.visible_navy','ships',_NAVY_BASIS,False),
}
_FORCE_GAPS=['ACTUAL_UI_RENDER_NOT_OBSERVED','CACHE_FRESHNESS_NOT_PROVEN',
             'MAIN_THREAD_ATOMICITY_NOT_PROVEN','ONLY_FIXED_VTABLE_PREDICATE_MAP_SUPPORTED',
             'FULL_MILITARY_VISIBILITY_NOT_PROVEN']


def _safe_reason(value: Any, fallback: str) -> str:
    return value if isinstance(value,str) and _SAFE_REASON.fullmatch(value) else fallback


def _i32(value: Any) -> bool:
    return type(value) is int and _I32_MIN<=value<=_I32_MAX


def _wrap_i32(value: int) -> int:
    value &= 0xffffffff
    return value-(1<<32) if value & (1<<31) else value


def _backend_item(report: Any, target: str) -> Mapping[str, Any]:
    if not isinstance(report,Mapping):
        raise ValueError('capture report shape')
    observation=report.get('observation')
    backend=observation.get('backend') if isinstance(observation,Mapping) else None
    targets=backend.get('targets') if isinstance(backend,Mapping) else None
    if (not isinstance(targets,list) or len(targets)!=1 or not isinstance(targets[0],Mapping)
            or targets[0].get('tag')!=target):
        raise ValueError('capture target shape')
    return targets[0]


def _country_view(item: Mapping[str, Any]) -> dict[str, Any]:
    passes=item.get('admission_by_pass')
    if not isinstance(passes,Mapping):
        return {'status':_UNKNOWN,'reason':'COUNTRY_VIEW_ADMISSION_UNKNOWN'}
    admitted=[]
    for name in ('pass1','pass2'):
        gate=passes.get(name)
        role=gate.get('observer_nonplayer_role') if isinstance(gate,Mapping) else None
        if (not isinstance(gate,Mapping) or gate.get('status')!='known'
                or type(gate.get('admitted')) is not bool
                or not isinstance(role,Mapping) or role.get('verified') is not True):
            return {'status':_UNKNOWN,'reason':'COUNTRY_VIEW_ADMISSION_UNKNOWN'}
        admitted.append(gate['admitted'])
    if admitted[0] is not admitted[1]:
        return {'status':_UNKNOWN,'reason':'COUNTRY_VIEW_ADMISSION_CHANGED'}
    return {'status':'known','admitted':admitted[1]}


def _public_technology(item: Mapping[str, Any], view: Mapping[str, Any]) -> dict[str, Any]:
    if view.get('status')!='known':
        return {'status':_UNKNOWN,'reason':view.get('reason','FOREIGN_TECH_COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    if view.get('admitted') is False:
        return {'status':'invisible','reason':'COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER',
                'visibility_basis':_TECH_BASIS}
    tech=item.get('technology')
    if not isinstance(tech,Mapping):
        raise ValueError('technology field shape')
    value=tech.get('value');raw=tech.get('raw_hex')
    if (not _i32(value) or not isinstance(raw,str)
            or raw!=(value&0xffffffff).to_bytes(4,'little').hex()):
        raise ValueError('technology raw contract')
    return {'status':'known','value':value,'raw':value,'raw_hex':raw,
            'unit':'technology_level','scale':1,'period':'current','complete':False,'partial':True,
            'basis':'native_country_technology_level_cache',
            'value_origin':'copied_native_country_technology_cache','visibility_basis':_TECH_BASIS}


def _public_manpower_value(value: Any) -> dict[str, Any]:
    if not isinstance(value,Mapping):
        raise ValueError('manpower value shape')
    reserve=value.get('reserve_raw')
    recruited=value.get('recruited_total_raw')
    total=value.get('total_raw')
    components=value.get('components')
    if not (_i32(reserve) and _i32(recruited) and _i32(total)
            and isinstance(components,list) and len(components)==3):
        raise ValueError('manpower value bounds')
    public_components=[]
    sum_contributions=0
    for component in components:
        if not isinstance(component,Mapping):
            raise ValueError('manpower component shape')
        count=component.get('count')
        contribution=component.get('contribution_raw')
        cost=component.get('definition_cost')
        if type(count) is not int or not 0<=count<=0xffff or not _i32(contribution) or not isinstance(cost,Mapping):
            raise ValueError('manpower component bounds')
        if cost.get('status')=='known' and _i32(cost.get('raw')):
            cost_public={'status':'known','raw':cost['raw']}
            expected=_wrap_i32(count*cost['raw'])
        elif cost.get('status')=='not_applicable' and count==0:
            cost_public={'status':'not_applicable'}
            expected=0
        else:
            raise ValueError('manpower definition cost shape')
        if contribution!=expected:
            raise ValueError('manpower contribution mismatch')
        sum_contributions=_wrap_i32(sum_contributions+contribution)
        public_components.append({'count':count,'definition_cost':cost_public,
                                  'contribution_raw':contribution})
    if recruited!=sum_contributions or total!=_wrap_i32(reserve+recruited):
        raise ValueError('manpower aggregate mismatch')
    return {'reserve_raw':reserve,'components':public_components,
            'recruited_total_raw':recruited,'total_raw':total}


def _field_value(item: Mapping[str, Any], field_id: str) -> Mapping[str, Any] | None:
    fields=item.get('fields')
    return fields.get(field_id) if isinstance(fields,Mapping) else None


def _public_manpower(item: Mapping[str, Any], view: Mapping[str, Any]) -> dict[str, Any]:
    if view.get('status')!='known':
        return {'status':_UNKNOWN,'reason':view.get('reason','FOREIGN_MANPOWER_COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    if view.get('admitted') is False:
        return {'status':'invisible','reason':'COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER',
                'visibility_basis':_TECH_BASIS}
    field=_field_value(item,'F02.manpower')
    consistency=item.get('field_consistency')
    stable=consistency.get('F02.manpower') if isinstance(consistency,Mapping) else None
    if not isinstance(field,Mapping):
        return {'status':_UNKNOWN,'reason':'FOREIGN_MANPOWER_FIELD_MISSING'}
    status=field.get('status')
    if status=='invisible':
        return {'status':'invisible','reason':_safe_reason(
            field.get('reason'),'MILITARY_STATS_PERMISSION_DENIED'),
            'visibility_basis':_STATS_BASIS}
    if status!='known' or not isinstance(stable,Mapping) or stable.get('status')!='stable':
        return {'status':_UNKNOWN,'reason':_safe_reason(
            field.get('reason'),'FOREIGN_MANPOWER_FIELD_UNKNOWN')}
    public_value=_public_manpower_value(field.get('value'))
    return {'status':'known','value':public_value,'unit':'native_manpower_statistic','scale':1,
            'period':'current','basis':_MANPOWER_BASIS,'complete':False,'partial':True}


def _public_stats_permission(item: Mapping[str, Any], view: Mapping[str, Any]) -> dict[str, Any]:
    if view.get('status')!='known':
        return {'status':_UNKNOWN,'reason':view.get('reason','COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    if view.get('admitted') is False:
        return {'status':_UNKNOWN,'reason':'NOT_EVALUATED_COUNTRY_VIEW_DENIED'}
    field=_field_value(item,'F02.military_resource_visibility')
    if not isinstance(field,Mapping) or field.get('status')!='known':
        return {'status':_UNKNOWN,'reason':_safe_reason(
            field.get('reason') if isinstance(field,Mapping) else None,
            'MILITARY_STATS_PERMISSION_UNKNOWN')}
    value=field.get('value')
    if not isinstance(value,Mapping) or type(value.get('admitted')) is not bool:
        return {'status':_UNKNOWN,'reason':'MILITARY_STATS_PERMISSION_INVALID'}
    mode=value.get('mode')
    if mode not in {'public_options','active_timed_entry','expired_timed_entry','no_timed_entry'}:
        return {'status':_UNKNOWN,'reason':'MILITARY_STATS_PERMISSION_MODE_INVALID'}
    return {'status':'known','admitted':value['admitted'],'mode':mode,'basis':_STATS_BASIS}


def _capture_gate_conflict(views: list[Mapping[str, Any] | None],
                           permissions: list[Mapping[str, Any] | None]) -> str | None:
    admitted_views=[item['admitted'] for item in views
        if isinstance(item,Mapping) and item.get('status')=='known'
        and type(item.get('admitted')) is bool]
    if admitted_views and any(value is not admitted_views[0] for value in admitted_views[1:]):
        return 'COUNTRY_VIEW_CAPTURE_DISAGREEMENT'
    known_permissions=[(item['admitted'],item['mode']) for item in permissions
        if isinstance(item,Mapping) and item.get('status')=='known'
        and type(item.get('admitted')) is bool and isinstance(item.get('mode'),str)]
    if known_permissions and any(value!=known_permissions[0] for value in known_permissions[1:]):
        return 'MILITARY_STATS_PERMISSION_CAPTURE_DISAGREEMENT'
    return None


def _public_force_value(field: Mapping[str, Any], *, unit: str, basis: str,
                        has_record_count: bool) -> dict[str, Any]:
    value=field.get('value');raw=field.get('raw')
    if (not _i32(value) or not _i32(raw) or raw!=value
            or field.get('unit')!=unit or type(field.get('scale')) is not int
            or field.get('scale')!=1 or field.get('basis')!=basis
            or field.get('partial') is not True or field.get('complete') is not False):
        raise ValueError('force statistic contract')
    output={'status':'known','value':value,'raw':raw,'unit':unit,'scale':1,
            'period':'current','basis':basis,'complete':False,'partial':True}
    if has_record_count:
        count=field.get('record_count')
        if type(count) is not int or not 0<=count<=_I32_MAX:
            raise ValueError('army record count contract')
        output['record_count']=count
    return output


def _public_force_field(item: Mapping[str, Any], public_name: str,
                        view: Mapping[str, Any],
                        stats_permission: Mapping[str, Any]) -> dict[str, Any]:
    field_id,unit,basis,has_record_count=_FORCE_FIELDS[public_name]
    if view.get('status')!='known':
        return {'status':_UNKNOWN,'reason':_safe_reason(
            view.get('reason'),'FORCE_COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    if view.get('admitted') is False:
        return {'status':'invisible','reason':'COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER',
                'visibility_basis':_TECH_BASIS}
    if stats_permission.get('status')!='known':
        return {'status':_UNKNOWN,'reason':_safe_reason(
            stats_permission.get('reason'),'MILITARY_STATS_PERMISSION_UNKNOWN')}
    if stats_permission.get('admitted') is False:
        return {'status':'invisible','reason':'MILITARY_STATS_PERMISSION_DENIED',
                'visibility_basis':_STATS_BASIS}
    field=_field_value(item,field_id)
    consistency=item.get('field_consistency')
    stable=consistency.get(field_id) if isinstance(consistency,Mapping) else None
    if not isinstance(field,Mapping):
        return {'status':_UNKNOWN,'reason':'FOREIGN_FORCE_FIELD_MISSING'}
    status=field.get('status')
    if status=='invisible':
        # A denial under a positive combined gate is inconsistent; a negative
        # gate was already projected above without reading any field value.
        return {'status':_UNKNOWN,'reason':'FORCE_FIELD_PERMISSION_CONFLICT'}
    if status!= 'known' or not isinstance(stable,Mapping) or stable.get('status')!='stable':
        return {'status':_UNKNOWN,'reason':_safe_reason(
            field.get('reason'),'FOREIGN_FORCE_FIELD_UNKNOWN')}
    try:
        return _public_force_value(field,unit=unit,basis=basis,
                                   has_record_count=has_record_count)
    except (TypeError,ValueError):
        return {'status':_UNKNOWN,'reason':'FOREIGN_FORCE_FIELD_INVALID'}


def _public_admission_details(country_view: Mapping[str, Any] | None,
                              stats_permission: Mapping[str, Any] | None,
                              observer: str) -> dict[str, Any]:
    if country_view is not None and country_view.get('status')=='known':
        cv={'status':'known','admitted':country_view['admitted'],
            'observer':observer,'projected_observer_view':True,'actual_UI_observed':False}
    else:
        cv={'status':_UNKNOWN,'reason':_safe_reason(
            (country_view or {}).get('reason'),'COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    stats=(deepcopy(dict(stats_permission)) if isinstance(stats_permission,Mapping)
           else {'status':_UNKNOWN,'reason':'MILITARY_STATS_PERMISSION_UNKNOWN'})
    if cv['status']=='known' and cv['admitted'] is False:
        effective={'status':'known','value':False,
                   'reason':'COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER'}
    elif cv['status']=='known' and stats.get('status')=='known':
        effective={'status':'known','value':bool(cv['admitted'] and stats['admitted'])}
    else:
        effective={'status':_UNKNOWN,'reason':'COMBINED_MILITARY_VISIBILITY_INCOMPLETE'}
    return {'country_view':cv,'military_stats_permission':stats,
            'effective_admitted':effective}


def _public_visibility(country_view: Mapping[str, Any] | None,
                       stats_permission: Mapping[str, Any] | None,
                       *, target: str, observer: str, view_conflict: bool=False,
                       conflict_reason: str='COUNTRY_VIEW_CAPTURE_DISAGREEMENT',
                       force_country_view: Mapping[str, Any] | None=None,
                       force_stats_permission: Mapping[str, Any] | None=None,
                       force_capture_used: bool=False,
                       quality_country_view: Mapping[str, Any] | None=None,
                       quality_permission: Mapping[str, Any] | None=None) -> dict[str, Any]:
    if view_conflict:
        return {'status':_UNKNOWN,'reason':_safe_reason(
                    conflict_reason,'COUNTRY_VIEW_CAPTURE_DISAGREEMENT'),
                'basis':'combined_country_view_and_military_stats_permission'}
    force_view=(force_country_view if force_capture_used else country_view)
    force_stats=(force_stats_permission if force_capture_used else stats_permission)
    available_gates=(country_view,stats_permission,force_view,force_stats,quality_country_view,quality_permission)
    if not any(isinstance(gate,Mapping) and gate.get('status')=='known'
               for gate in available_gates):
        reason=(country_view or {}).get('reason') or (stats_permission or {}).get('reason')
        return {'status':_UNKNOWN,'reason':_safe_reason(reason,'MILITARY_VISIBILITY_UNKNOWN'),
                'basis':'combined_country_view_and_military_stats_permission'}
    if country_view is None:
        tech_view={'status':_UNKNOWN,'reason':'COUNTRY_VIEW_ADMISSION_UNKNOWN'}
    elif country_view.get('status')=='known':
        admitted=country_view['admitted']
        tech_view={'admitted':admitted,'observer':observer,'target':target,'actual_UI_observed':False,
                   'projected_observer_view':True}
    else:
        tech_view={'status':_UNKNOWN,'reason':country_view.get('reason','COUNTRY_VIEW_ADMISSION_UNKNOWN')}
    manpower_admission=_public_admission_details(country_view,stats_permission,observer)
    force_admission=_public_admission_details(force_view,force_stats,observer)
    value={'military_technology':tech_view,
        'manpower':manpower_admission,
        'army':force_admission,
        'navy':deepcopy(force_admission),
        'military_quality':{'status':_UNKNOWN,'reason':'QUALITY_PERMISSION_NOT_EVALUATED'},
        'other_F02_fields':{'status':_UNKNOWN,'reason':'OTHER_F02_FIELDS_NOT_IMPLEMENTED'}}
    if quality_country_view is not None or quality_permission is not None:
        details=_public_admission_details(quality_country_view,quality_permission,observer)
        details['quality_page_permission']=details.pop('military_stats_permission')
        value['military_quality']=details
    return {'status':'known','unit':'field_admission','period':'current','complete':False,
            'partial':True,'basis':'combined_country_view_and_military_stats_permission',
            'value':value}


class NativeForeignTechnologySource(NativeTradeIncomeSource):
    event_types=()

    def __init__(self, base_source, *, capture=None, manpower_capture=None,
                 forces_capture=None, quality_capture=None):
        # Keep the historical `capture=` injection bound to technology only.
        super().__init__(base_source,capture=capture)
        self.manpower_capture=manpower_capture
        self.forces_capture=forces_capture
        self.quality_capture=quality_capture

    def catalog(self):
        common={'coverage':'partial','complete':False,'supported_versions':['1.37.4'],
            'source':'bridge.information.foreign_technology_capture.capture',
            'supported_object_types':['country'],
            'period':'current','runtime_validation':'native_cache_and_observer_projection_observed',
            'gaps':['OBSERVER_PREDICATE_PROJECTION_NOT_ACTUAL_UI_OBSERVATION',
                    'MAIN_THREAD_ATOMICITY_NOT_PROVEN','NATIVE_CACHE_FRESHNESS_NOT_PROVEN']}
        manpower={**deepcopy(common),'source':'bridge.information.foreign_manpower_capture.capture',
            'unit':'native_manpower_statistic','scale':1,'raw':True,
            'basis':_MANPOWER_BASIS,
            'description':'报告目标国家三项原生人力统计分量与储备值；不推断兵种名称、显示格式或UI文字',
            'value_origin':'copied_native_manpower_statistic','paths':[
                'observation.backend.targets[0].fields.F02.manpower.value'],
            'gaps':common['gaps']+['COMPONENT_CATEGORIES_NOT_IDENTIFIED','UI_FORMATTING_NOT_OBSERVED']}
        forces_common={**deepcopy(common),
            'source':'bridge.information.foreign_forces_capture.capture',
            'runtime_validation':'strict_native_capture_replay; actual UI rendering not observed',
            'gaps':list(_FORCE_GAPS)}
        army={**deepcopy(forces_common),'unit':'soldiers','scale':1,'raw':True,
            'basis':_ARMY_BASIS,'value_origin':'diplomacy_country_view_soldier_statistic',
            'description':'外交国家面板的士兵统计；值来自固定版本已验证的+0x80真分支，record_count仅为记录数元数据',
            'raw_semantics':'signed int32 diplomacy soldier statistic; unit soldiers; record_count is not soldiers',
            'paths':['observation.backend.targets[0].fields.F02.visible_army.value']}
        navy={**deepcopy(forces_common),'unit':'ships','scale':1,'raw':True,
            'basis':_NAVY_BASIS,'value_origin':'diplomacy_country_view_ship_statistic',
            'description':'外交国家面板的船只统计；值来自固定版本已验证的+0x88真分支',
            'raw_semantics':'signed int32 diplomacy ship count; unit ships',
            'paths':['observation.backend.targets[0].fields.F02.visible_navy.value']}
        visibility={**deepcopy(common),
            'source':'foreign_manpower_capture / foreign_forces_capture',
            'unit':'field_admission','basis':'combined_country_view_and_military_stats_permission',
            'description':'分别报告country-view投影及人力、士兵、船只统计准入；不表示数据已采集或实际UI已显示',
            'paths':['foreign_manpower_capture admission_by_pass and fields.F02.military_resource_visibility',
                     'foreign_forces_capture admission_by_pass and fields.F02.military_resource_visibility'],
            'gaps':common['gaps']+['ACTUAL_UI_RENDER_NOT_OBSERVED','FULL_MILITARY_VISIBILITY_NOT_PROVEN']}
        quality={**deepcopy(common),'source':'bridge.information.foreign_quality_capture.capture',
            'unit':'native_military_quality_components','scale':1,'raw':True,
            'basis':_quality_projection.BASIS,
            'description':'分别提供陆军和海军质量表的六项当前缓存；型号名称取当前语言缓存，未观察实际渲染',
            'paths':['observation.backend.targets[0].fields.F02.military_quality.value'],
            'gaps':common['gaps']+['PER_COMPONENT_UNKNOWN_PRESERVED','PROCESSOR_TLS_CONDITIONS_REMAIN',
                                   'MODEL_NAME_HASH_COLLISION_NOT_EXCLUDED']}
        visibility['source']+=' / foreign_quality_capture'
        visibility['description']='分别报告国家查看条件及人力、士兵、船只和质量字段的独立准入；不表示实际UI已显示'
        return [{'topic_id':'F02','catalog_ids':['F02'],'title':'外国军事技术、人力、陆海军统计和质量及字段准入',
            'status':'available','fields':{
                'military_technology':{**deepcopy(common),'unit':'technology_level','scale':1,'raw':True,
                    'basis':'native_country_technology_level_cache',
                    'value_origin':'copied_native_country_technology_cache',
                    'description':'以当前观察国核对原生外交国家查看条件，通过后读取目标军事科技缓存',
                    'raw_semantics':'signed int32 target technology cache; scale1; not the next-level preview',
                    'paths':['observation.backend.targets[0].technology.value']},
                'manpower':manpower,'visibility':visibility,
                'visible_army':army,'visible_navy':navy,'military_quality':quality},
            'object_types':['country'],'observer_roles':[],'observer_scope':[],
            'parameters':{'type':'object','properties':{},'additionalProperties':False},
            'supported_versions':['1.37.4'],'triggers':['query','periodic'],
            'source':type(self).__name__,'context_scope':'visible_scope','visibility':'visible_scope',
            'scope_note':'以会话配置的观察国核对字段准入，质量组件可单独返回未知'}]

    def validate_query(self,query,context=None):
        if (not isinstance(query,dict) or set(query)-{'topic','object','fields','parameters'}
                or query.get('topic')!='F02'):
            raise InformationError('invalid_parameters','Expected an F02 query')
        obj=query.get('object')
        if (not isinstance(obj,dict) or set(obj)!={'type','country'} or obj.get('type')!='country'
                or not isinstance(obj.get('country'),str) or not _TAG.fullmatch(obj['country'])):
            raise InformationError('invalid_object','F02 requires one three-letter country tag')
        observer = (context.get('observer') if isinstance(context, dict)
                    else getattr(self.base_source, 'operator_observer', None))
        if context is not None and (not isinstance(observer, str) or not _TAG.fullmatch(observer)):
            raise InformationError('observer_scope_mismatch','F02 requires a bound observer country')
        if obj['country']==observer:
            raise InformationError('invalid_object','F02 requires a country other than the observer')
        fields=query.get('fields')
        if (not isinstance(fields,list) or not fields or len(fields)>len(_FIELDS)
                or any(not isinstance(field,str) or field not in _FIELDS for field in fields)
                or len(set(fields))!=len(fields)):
            raise InformationError('invalid_fields','Unsupported F02 foreign fields')
        if not isinstance(query.get('parameters',{}),dict) or query.get('parameters',{}):
            raise InformationError('invalid_parameters','Foreign technology has no extra parameters')
        return {'topic':'F02','object':deepcopy(obj),'fields':list(fields),'parameters':{}}

    def read(self,query,context=None):
        current=deepcopy(context) if isinstance(context,dict) else self.context()
        normalized=self.validate_query(query,current)
        target=normalized['object']['country'];requested=normalized['fields']
        observer=current['observer']
        provenance={'read_only':True,'native_function_invoked':False,'observer':observer,'target':target,
                    'visibility_basis':'combined_country_view_and_military_stats_permission',
                    'actual_UI_observed':False,'capture_report_sha256_by_source':{}}

        def result(fields):
            source=_source_info(type(self).__name__,current,complete=False,provenance=deepcopy(provenance))
            source['context_scope']='visible_scope'
            source['projection_version']=4
            return _result(normalized,current,fields,False,source)

        def failure(reason,unavailable=False):
            state='unavailable' if unavailable else _UNKNOWN
            return result({field:{'status':state,'reason':reason} for field in requested})

        reason=_observer_context_reason(current)
        if reason:
            return failure(reason.replace('TRADE_INCOME','FOREIGN_TECH'),True)
        try:
            before=self.context()
        except Exception:
            return failure('FOREIGN_TECH_CONTEXT_UNAVAILABLE',True)
        if _observer_context_reason(before) or _identity(before)!=_identity(current):
            return failure('FOREIGN_TECH_CONTEXT_STALE',True)
        installation,creation,reason=_session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failure('FOREIGN_TECH_INSTALLATION_UNAVAILABLE',True)

        need_technology='military_technology' in requested
        need_forces=any(field in requested for field in ('visible_army','visible_navy'))
        need_quality='military_quality' in requested
        need_manpower=('manpower' in requested or
                       ('visibility' in requested and not need_forces and not need_quality))
        reports={};modules={};capture_failures={}
        context_changed=False

        def capture_one(source_name,module_path,injected):
            nonlocal context_changed
            try:
                module=import_module(module_path,__package__)
                capture=injected if injected is not None else module.capture
                if not callable(capture):
                    raise RuntimeError('capture unavailable')
            except Exception as exc:
                capture_failures[source_name]='CAPTURE_UNAVAILABLE:'+type(exc).__name__
                return
            try:
                call_before=self.context()
            except Exception:
                context_changed=True
                return
            if (_observer_context_reason(call_before) or _identity(call_before)!=_identity(before)):
                context_changed=True
                return
            report=None;call_error=None
            try:
                report=capture(installation,country=target,observer=observer)
            except Exception as exc:
                call_error='CAPTURE_FAILED:'+type(exc).__name__
            try:
                call_after=self.context()
            except Exception:
                context_changed=True
                return
            if (_observer_context_reason(call_after) or _identity(call_after)!=_identity(call_before)
                    or _identity(call_after)!=_identity(before)):
                context_changed=True
                return
            if call_error is not None:
                capture_failures[source_name]=call_error
                return
            try:
                if module.validate_capture(report,call_before,creation,target) is not True:
                    capture_failures[source_name]='CAPTURE_INVALID'
                    return
                digest=hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            except Exception:
                capture_failures[source_name]='CAPTURE_INVALID'
                return
            reports[source_name]=report;modules[source_name]=module
            provenance['capture_report_sha256_by_source'][source_name]=digest
            if source_name=='technology':
                # Retain the original provenance key for existing consumers.
                provenance['capture_report_sha256']=digest

        if need_technology:
            capture_one('technology','.foreign_technology_capture',self.capture)
        if need_manpower:
            # Legacy single-capture test/integration overrides must not silently
            # fall through to an unmocked live capture for the new source.
            if self.manpower_capture is None and self.capture is not None:
                capture_failures['manpower']='CAPTURE_OVERRIDE_NOT_PROVIDED'
            else:
                capture_one('manpower','.foreign_manpower_capture',self.manpower_capture)
        if need_forces:
            # Keep the legacy technology-only capture override isolated.
            if self.forces_capture is None and self.capture is not None:
                capture_failures['forces']='CAPTURE_OVERRIDE_NOT_PROVIDED'
            else:
                capture_one('forces','.foreign_forces_capture',self.forces_capture)
        if need_quality:
            if self.quality_capture is None and self.capture is not None:
                capture_failures['quality']='CAPTURE_OVERRIDE_NOT_PROVIDED'
            else:
                capture_one('quality','.foreign_quality_capture',self.quality_capture)

        try:
            after=self.context()
        except Exception:
            context_changed=True;after={}
        if (_observer_context_reason(after) or _identity(after)!=_identity(before)):
            context_changed=True
        if context_changed:
            provenance['capture_failures']=capture_failures
            return failure('FOREIGN_TECH_CONTEXT_CHANGED_DURING_CAPTURE')
        if capture_failures:
            provenance['capture_failures']=capture_failures

        tech_item=None;tech_view=None;technology_field=None
        if 'technology' in reports:
            try:
                tech_item=_backend_item(reports['technology'],target)
                tech_view=_country_view(tech_item)
                technology_field=_public_technology(tech_item,tech_view)
            except (KeyError,TypeError,ValueError,IndexError):
                technology_field={'status':_UNKNOWN,'reason':'FOREIGN_TECH_FIELD_INVALID'}
                tech_view={'status':_UNKNOWN,'reason':'FOREIGN_TECH_FIELD_INVALID'}
        elif need_technology:
            technology_field={'status':_UNKNOWN,'reason':'FOREIGN_TECH_'+
                              capture_failures.get('technology','CAPTURE_UNAVAILABLE')}

        manpower_item=None;manpower_view=None;stats_permission=None;manpower_field=None
        if 'manpower' in reports:
            try:
                manpower_item=_backend_item(reports['manpower'],target)
                manpower_view=_country_view(manpower_item)
                stats_permission=_public_stats_permission(manpower_item,manpower_view)
                if 'manpower' in requested:
                    manpower_field=_public_manpower(manpower_item,manpower_view)
            except (KeyError,TypeError,ValueError,IndexError):
                manpower_view={'status':_UNKNOWN,'reason':'FOREIGN_MANPOWER_CAPTURE_INVALID'}
                stats_permission={'status':_UNKNOWN,'reason':'FOREIGN_MANPOWER_CAPTURE_INVALID'}
                if 'manpower' in requested:
                    manpower_field={'status':_UNKNOWN,'reason':'FOREIGN_MANPOWER_FIELD_INVALID'}
        elif need_manpower:
            reason='FOREIGN_MANPOWER_'+capture_failures.get('manpower','CAPTURE_UNAVAILABLE')
            manpower_view={'status':_UNKNOWN,'reason':reason}
            stats_permission={'status':_UNKNOWN,'reason':'MILITARY_STATS_PERMISSION_UNKNOWN'}
            if 'manpower' in requested:
                manpower_field={'status':_UNKNOWN,'reason':reason}

        forces_item=None;forces_view=None;forces_stats=None;force_fields={}
        if 'forces' in reports:
            try:
                forces_item=_backend_item(reports['forces'],target)
                forces_view=_country_view(forces_item)
                forces_stats=_public_stats_permission(forces_item,forces_view)
            except (KeyError,TypeError,ValueError,IndexError):
                forces_view={'status':_UNKNOWN,'reason':'FOREIGN_FORCES_CAPTURE_INVALID'}
                forces_stats={'status':_UNKNOWN,'reason':'FOREIGN_FORCES_CAPTURE_INVALID'}
                for public_name in ('visible_army','visible_navy'):
                    if public_name in requested:
                        force_fields[public_name]={'status':_UNKNOWN,
                            'reason':'FOREIGN_FORCES_CAPTURE_INVALID'}
            if forces_item is not None:
                for public_name in ('visible_army','visible_navy'):
                    if public_name not in requested:
                        continue
                    try:
                        force_fields[public_name]=_public_force_field(
                            forces_item,public_name,forces_view,forces_stats)
                    except (KeyError,TypeError,ValueError,IndexError):
                        force_fields[public_name]={'status':_UNKNOWN,
                            'reason':'FOREIGN_FORCE_FIELD_INVALID'}
        elif need_forces:
            reason='FOREIGN_FORCES_'+capture_failures.get('forces','CAPTURE_UNAVAILABLE')
            for public_name in ('visible_army','visible_navy'):
                if public_name in requested:
                    force_fields[public_name]={'status':_UNKNOWN,'reason':reason}

        quality_item=None;quality_view=None;quality_permission=None;quality_field=None
        if 'quality' in reports:
            try:
                quality_item=_backend_item(reports['quality'],target)
                quality_view=_country_view(quality_item)
                quality_permission=_quality_projection.permission(quality_item,quality_view)
                quality_field=_quality_projection.project(quality_item,quality_view,quality_permission)
            except (KeyError,TypeError,ValueError,IndexError):
                quality_view={'status':_UNKNOWN,'reason':'FOREIGN_QUALITY_CAPTURE_INVALID'}
                quality_permission={'status':_UNKNOWN,'reason':'FOREIGN_QUALITY_CAPTURE_INVALID'}
                quality_field={'status':_UNKNOWN,'reason':'FOREIGN_QUALITY_FIELD_INVALID'}
        elif need_quality:
            reason='FOREIGN_QUALITY_'+capture_failures.get('quality','CAPTURE_UNAVAILABLE')
            quality_view={'status':_UNKNOWN,'reason':reason}
            quality_permission={'status':_UNKNOWN,'reason':'QUALITY_PERMISSION_UNKNOWN'}
            quality_field={'status':_UNKNOWN,'reason':reason}

        gate_conflict=_capture_gate_conflict(
            [tech_view,manpower_view,forces_view,quality_view],
            [stats_permission,forces_stats])
        if gate_conflict:
            provenance['visibility_conflict']=gate_conflict

        fields={}
        if 'military_technology' in requested:
            fields['military_technology']=technology_field or {
                'status':_UNKNOWN,'reason':'FOREIGN_TECH_CAPTURE_UNAVAILABLE'}
        if 'manpower' in requested:
            fields['manpower']=manpower_field or {
                'status':_UNKNOWN,'reason':'FOREIGN_MANPOWER_CAPTURE_UNAVAILABLE'}
        if 'military_quality' in requested:
            fields['military_quality']=quality_field or {
                'status':_UNKNOWN,'reason':'FOREIGN_QUALITY_CAPTURE_UNAVAILABLE'}
        for public_name in ('visible_army','visible_navy'):
            if public_name in requested:
                fields[public_name]=force_fields.get(public_name,{
                    'status':_UNKNOWN,'reason':'FOREIGN_FORCES_CAPTURE_UNAVAILABLE'})
        if 'visibility' in requested:
            # Keep the technology gate separate; army/navy admission prefers
            # the matching force capture and visibility-only uses the manpower
            # capture's independently validated shared stats permission.
            view_candidates=(tech_view,manpower_view,forces_view,quality_view)
            view_for_visibility=next((item for item in view_candidates
                                      if isinstance(item,Mapping) and item.get('status')=='known'),
                                     next((item for item in view_candidates if item is not None),None))
            fields['visibility']=_public_visibility(view_for_visibility,stats_permission,
                target=target,observer=observer,view_conflict=gate_conflict is not None,
                conflict_reason=gate_conflict or 'COUNTRY_VIEW_CAPTURE_DISAGREEMENT',
                force_country_view=forces_view,force_stats_permission=forces_stats,
                force_capture_used=('forces' in reports),quality_country_view=quality_view,
                quality_permission=quality_permission)
        return result(fields)


__all__=['NativeForeignTechnologySource']
