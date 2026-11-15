"""Collect independently known S04 components after country-view admission."""
from __future__ import annotations

from copy import deepcopy

from . import country_ruler_union_memory as union
from . import person_panel_conditions_memory as panels
from . import person_name_memory as names
from . import person_age_memory as ages
from . import person_claim_memory as claims
from .foreign_technology_capture import _pointer, _read

FIELDS=('S04.ruler','S04.heir','S04.dynasty','S04.personal_union')


def _unknown(reason):
    return {'status':'unknown','reason':reason}


def _na(reason):
    return {'status':'not_applicable','reason':reason}


def _component(result):
    if isinstance(result,dict) and result.get('status')=='known' and 'value' in result:
        value={'status':'known','value':deepcopy(result['value'])}
        if 'unit' in result:value['unit']=result['unit']
        return value
    return _unknown((result or {}).get('reason','PERSON_COMPONENT_UNKNOWN'))


def _dynasty(name):
    if isinstance(name,dict) and name.get('status')=='known' and 'value' in name:
        return {'status':'known','value':deepcopy(name['value'])}
    return _unknown('PERSON_DYNASTY_NAME_COMPONENT_UNKNOWN')


def _panel_evidence(result):
    """Keep only the property that controls the heir character panel."""
    inputs=result.get('raw_inputs',{})
    common={key:deepcopy(value) for key,value in inputs.items()
        if key not in ('field_inputs','read_calls','bytes_requested','reads')}
    common['heir_panel_inputs']=deepcopy(inputs.get('field_inputs',{}).get('heir_panel'))
    return {'heir_panel':deepcopy(result.get('heir_panel')), 'raw_inputs':common}


def _u64(reader,address,label):
    return int.from_bytes(_read(reader,address,8,label),'little')


def _identity(reader,base,country,offset,refs,label):
    person=_pointer(_u64(reader,country+offset,'person.'+label+'.pointer'))
    owner_raw=_read(reader,person+0x20,8,'person.'+label+'.owner_reference')
    owner=int.from_bytes(owner_raw,'little')
    if owner not in refs:raise ValueError('PERSON_OWNER_REFERENCE_MISMATCH')
    return person,owner


def _presence(reader,base,person,label):
    vtable=_pointer(_u64(reader,person,'person.'+label+'.vtable'))
    method=_u64(reader,vtable+0x58,'person.'+label+'.presence_method')
    if method==base+0x8f440:return True
    if method==base+0x8f450:return False
    raise ValueError('PERSON_PRESENCE_METHOD_UNSUPPORTED')


def read_fields(reader,base,binding,fields,*,name_layout='vanilla'):
    """Known values may contain explicitly unknown independent components."""
    results={field:_unknown('PERSON_FIELD_UNSUPPORTED') for field in fields}
    try:
        country=_pointer(int(binding['country_pointer'],0))
        target_ref=int(binding['fullref'],0)
        if _u64(reader,country+0x20,'person.country.reference')!=target_ref:
            raise ValueError('PERSON_COUNTRY_REFERENCE_CHANGED')
    except Exception as exc:
        return {field:_unknown(str(exc)[:160]) for field in fields}
    union_result=union.read_ruler_union_gate(reader,base,binding)
    panel_result=panels.read_person_panel_conditions(reader,base,binding)
    ruler_raw={'country_binding':deepcopy(binding),'ruler_display_condition':union_result,
               'name_layout':name_layout}
    heir_raw={'country_binding':deepcopy(binding),'heir_panel_condition':_panel_evidence(panel_result),
              'name_layout':name_layout}
    dynasty_raw={'country_binding':deepcopy(binding),'ruler_display_condition':union_result,
                 'heir_panel_condition':_panel_evidence(panel_result),'name_layout':name_layout}
    active=union_result.get('active') if union_result.get('status')=='known' else None
    if type(active) is bool and 'S04.personal_union' in fields:
        related=union_result.get('related_country') or {}
        results['S04.personal_union']={'status':'known','value':{'uses_senior_ruler':active,
            'senior_country':related.get('tag') if active else None},'raw_inputs':deepcopy(ruler_raw),
            'basis':'projected_native_ruler_label_personal_union_condition'}
    elif 'S04.personal_union' in fields:
        results['S04.personal_union']=_unknown('PERSON_RULER_UNION_CONDITION_UNKNOWN')
    ruler_dynasty=_unknown('RULER_DYNASTY_UNAVAILABLE')
    heir_dynasty=_unknown('HEIR_DYNASTY_UNAVAILABLE')
    if any(field in fields for field in ('S04.ruler','S04.dynasty')):
        value={'display_mode':'personal_union' if active is True else 'person' if active is False else 'unknown',
            'name':_unknown('RULER_DISPLAY_CONDITION_UNKNOWN'),'skills':_unknown('RULER_SKILLS_UNKNOWN'),
            'age':_unknown('RULER_AGE_UNKNOWN'),'full_ui_label_complete':False}
        try:
            allowed={target_ref}
            related=union_result.get('related_country') or {}
            if active is True and isinstance(related.get('fullref'),str):allowed.add(int(related['fullref'],0))
            person,owner=_identity(reader,base,country,0x1280,allowed,'ruler')
            ruler_raw['ruler_owner_reference']=hex(owner)
            try:
                skill_raw=_read(reader,person+0x48,12,'person.ruler.skills')
                ruler_raw['ruler_skills_raw_hex']=skill_raw.hex()
                value['skills']={'status':'known','value':{key:int.from_bytes(skill_raw[n:n+4],'little',signed=True)
                    for key,n in (('administrative',0),('diplomatic',4),('military',8))}}
            except Exception:
                value['skills']=_unknown('RULER_SKILL_READ_FAILED')
            age=ages.read_age(reader,base,person,label='ruler',require_known_birth=True)
            ruler_raw['ruler_age']=age;value['age']=_component(age)
            if active is False:
                name=(names.read_person_name(reader,base,person,expected_country_fullref=owner,
                    name_layout=name_layout) if name_layout in ('vanilla','plugin64')
                    else _unknown('PERSON_NAME_RUNTIME_UNSUPPORTED'))
                ruler_raw['ruler_name']=name;value['name']=_component(name)
                if 'S04.dynasty' in fields:
                    dynasty=(names.read_dynasty_component(reader,base,person,expected_country_fullref=owner,
                        name_layout=name_layout) if name_layout in ('vanilla','plugin64')
                        else _unknown('PERSON_NAME_RUNTIME_UNSUPPORTED'))
                    dynasty_raw['ruler_dynasty']=dynasty;ruler_dynasty=_dynasty(dynasty)
            elif active is True:
                value['name']={'status':'invisible','reason':'NATIVE_RULER_LABEL_USES_SENIOR_COUNTRY'}
                ruler_dynasty={'status':'invisible','reason':'NATIVE_RULER_LABEL_USES_SENIOR_COUNTRY'}
            if 'S04.ruler' in fields:
                results['S04.ruler']={'status':'known','value':value,'raw_inputs':deepcopy(ruler_raw),
                    'basis':'copied_ruler_fields_and_projected_name_components'}
        except Exception as exc:
            if 'S04.ruler' in fields:results['S04.ruler']=_unknown(str(exc)[:160])
    if any(field in fields for field in ('S04.heir','S04.dynasty')):
        condition=panel_result.get('heir_panel',{})
        if condition.get('status')!='known' or type(condition.get('value')) is not bool:
            if 'S04.heir' in fields:results['S04.heir']=_unknown('HEIR_CHARACTER_PANEL_CONDITION_UNKNOWN')
        elif condition['value'] is False:
            hidden=_na('NATIVE_HEIR_CHARACTER_PANEL_HIDDEN')
            heir_dynasty=deepcopy(hidden)
            if 'S04.heir' in fields:
                results['S04.heir']={'status':'known','value':{'mode':'hidden','present':None,
                    'name':deepcopy(hidden),'age':deepcopy(hidden),'claim':deepcopy(hidden),
                    'full_ui_label_complete':False},'raw_inputs':deepcopy(heir_raw),
                    'basis':'projected_native_heir_panel_condition'}
        else:
            try:
                person=_pointer(_u64(reader,country+0x1298,'person.heir.pointer'))
                present=_presence(reader,base,person,'heir')
                heir_raw['present']=present;dynasty_raw['heir_present']=present
                if present:
                    if _u64(reader,person+0x20,'person.heir.owner_reference')!=target_ref:
                        raise ValueError('HEIR_OWNER_REFERENCE_MISMATCH')
                    name=(names.read_person_name(reader,base,person,expected_country_fullref=target_ref,
                        name_layout=name_layout) if name_layout in ('vanilla','plugin64')
                        else _unknown('PERSON_NAME_RUNTIME_UNSUPPORTED'))
                    age=ages.read_age(reader,base,person,label='heir')
                    claim=claims.read_claim(reader,base,person)
                    heir_raw.update(heir_name=name,heir_age=age,heir_claim=claim)
                    if 'S04.dynasty' in fields:
                        dynasty=(names.read_dynasty_component(reader,base,person,expected_country_fullref=target_ref,
                            name_layout=name_layout) if name_layout in ('vanilla','plugin64')
                            else _unknown('PERSON_NAME_RUNTIME_UNSUPPORTED'))
                        dynasty_raw['heir_dynasty']=dynasty;heir_dynasty=_dynasty(dynasty)
                    value={'mode':'character','present':True,'name':_component(name),'age':_component(age),
                        'claim':_component(claim),'full_ui_label_complete':False}
                else:
                    none=_na('NATIVE_NO_HEIR_BRANCH')
                    heir_dynasty=deepcopy(none)
                    value={'mode':'no_heir','present':False,'name':deepcopy(none),'age':deepcopy(none),
                        'claim':deepcopy(none),'full_ui_label_complete':False}
                if 'S04.heir' in fields:
                    results['S04.heir']={'status':'known','value':value,'raw_inputs':deepcopy(heir_raw),
                        'basis':'copied_heir_fields_and_projected_name_and_claim'}
            except Exception as exc:
                if 'S04.heir' in fields:results['S04.heir']=_unknown(str(exc)[:160])
    if 'S04.dynasty' in fields:
        results['S04.dynasty']={'status':'known','value':{'ruler':ruler_dynasty,'heir':heir_dynasty},
            'raw_inputs':deepcopy(dynasty_raw),'basis':'dynasty_components_in_native_normal_person_name'}
    return results


__all__=['FIELDS','read_fields']
