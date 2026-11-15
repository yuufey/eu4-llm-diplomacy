"""Read inputs for the native opinion tooltip's yearly contribution, without calls."""
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path

from . import opinion_modifiers_memory as records
from . import opinion_capture as opinion
from . import foreign_country_memory as backend
from .foreign_quality_memory import _TraceReader
from .modifier_storage import read_raw_modifier

ROOT=Path(__file__).resolve().parents[2]
PROFILE_FILE=Path(__file__).with_name('profiles')/'opinion-decay-memory-1374-v5-sampling-r1.json'
PROFILE_SHA256='2fdcfa0ba0a9ffbbb2e1dba212317b0cf56b9773297f5f8ac76d0b2949a3ae14'
PROFILE_ID='opinion-decay-memory-1374-v5'
PROFILE_VERSION=5
SCHEMA='information.opinion_decay_capture.v4'
FIELDS=('R04.decay.outgoing','R04.decay.incoming')
UNIT='opinion_points_per_year'
SCALE=1000
MAX_PAIR_ENTRIES=128

def _load_profile():
    assert 0<PROFILE_FILE.stat().st_size<=65536
    raw=PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:
        raise ValueError('OPINION_DECAY_PROFILE_PIN')
    own=json.loads(raw)
    if (own['base_profile_sha256']!=records.PROFILE_SHA256
            or own['profile_id']!=PROFILE_ID
            or own['profile_version']!=PROFILE_VERSION):
        raise ValueError('OPINION_DECAY_BASE_PROFILE')
    for item in own['dependencies']:
        path=(ROOT/item['path']).resolve(strict=True);path.relative_to(ROOT)
        if not 0<path.stat().st_size<=16*1024*1024 or path.stat().st_size!=item['bytes']:
            raise ValueError('OPINION_DECAY_DEPENDENCY_SIZE')
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=item['sha256']:raise ValueError('OPINION_DECAY_DEPENDENCY_PIN')
    merged=deepcopy(records._load_profile())
    merged.update(profile_id=PROFILE_ID,profile_version=own['profile_version'])
    merged['code_guards'].extend(own['code_guards'])
    return merged

def _unknown(reason):return {'status':'unknown','reason':reason}

def _bytes(reader,ptr,offset,size,label):
    return records._read(reader,records._address(ptr,offset,size),size,'decay.'+label)

def _ptr(reader,ptr,offset,label):
    return int.from_bytes(_bytes(reader,ptr,offset,8,label),'little')

def _processed_value(reader,base,object_owner,object_offset,manager):
    trace=_TraceReader(reader.read)
    # This helper reads only raw storage and has no country-identity contract.
    # Rebase its fixed +28d0 origin to the already bound object's inline map;
    # include the real owner in alias rejection. Keep its pinned implementation
    # unchanged for existing diplomats/quality readers.
    storage_origin=records._address(object_owner,object_offset,0x68)-0x28d0
    value=read_raw_modifier(trace,storage_origin,0x94,'ratio_modifier',name='opinion_recovery',
                           forbidden_pointers=(manager,object_owner))
    if value.get('status')!='known' or type(value.get('raw')) is not int:
        return _unknown('OPINION_DECAY_COUNTRY_MODIFIER_UNKNOWN')
    processor=_ptr(reader,manager,0x37c0,'processor.pointer')
    if processor:
        vt=_ptr(reader,processor,0,'processor.vtable')
        if vt!=base+0x1cc93a0 or _ptr(reader,vt,8,'processor.method')!=base+0x8f9300:
            return _unknown('OPINION_DECAY_PROCESSOR_UNRESOLVED')
        secondary=read_raw_modifier(trace,storage_origin,0x1a9,'ratio_modifier',name='opinion_recovery_secondary',
                                   forbidden_pointers=(manager,object_owner))
        if secondary.get('status')!='known' or secondary.get('raw')!=0:
            return _unknown('OPINION_DECAY_PROCESSOR_BRANCH_UNRESOLVED')
        # The two evidenced TLS/predicate branches return raw or raw+2*secondary.
        # With secondary==0 the numeric result is equal in both; no TLS call.
    return {'status':'known','raw':value['raw']}

def _pair_factor(reader,target,*,base=None,target_slot=None,processor_manager=None):
    manager=records._parse_address(_ptr(reader,target,0x1480,'pair.manager'))
    view=records._parse_address(_ptr(reader,manager,8,'pair.view'))
    header=_bytes(reader,view,0x20,16,'pair.vector')
    begin=int.from_bytes(header[:8],'little');end=int.from_bytes(header[8:],'little')
    if end<begin or (end-begin)%8 or (end-begin)//8>MAX_PAIR_ENTRIES:
        return _unknown('OPINION_DECAY_PAIR_CONTAINER_INVALID')
    if begin==end:return {'status':'known','raw':0}
    records._parse_address(begin)
    for index in range((end-begin)//8):
        entry=_ptr(reader,begin,index*8,'pair.entry')
        if not entry:continue
        kind=_bytes(reader,entry,0x18,1,'pair.kind')[0]
        if kind!=2:continue
        definition=_ptr(reader,entry,0x10,'pair.definition')
        if not definition:continue
        effect=_ptr(reader,definition,0x38,'pair.effect')
        if not effect:continue
        candidate=_ptr(reader,effect,0xe8,'pair.conditional')
        if not candidate:continue
        if base is None or type(target_slot) is not int or not 0<=target_slot<4096:
            return _unknown('OPINION_DECAY_PAIR_EFFECT_UNRESOLVED')
        cache=records._parse_address(_ptr(reader,candidate,0x18,'pair.cache'))
        entry=records._address(cache,target_slot*0xc0,0xb8)
        active=_bytes(reader,entry,0xae,1,'pair.cache_active')[0]
        if not active:continue
        selected=_ptr(reader,entry,0xb0,'pair.cache_selected')
        if not selected:continue
        value=_processed_value(reader,base,selected,0x58,processor_manager)
        # b5c2f0 may return null in its TLS branch. Either that null path or a
        # cached definition with processed value zero makes b5c690 return zero.
        if value.get('status')=='known' and value['raw']==0:continue
        return _unknown('OPINION_DECAY_PAIR_EFFECT_UNRESOLVED')
    return {'status':'known','raw':0}

def _country_factor(reader,base,target,target_slot=None):
    state=int.from_bytes(_bytes(reader,target,0x28c8,4,'country.cache_state'),'little')
    if state not in (0,2):return _unknown('OPINION_DECAY_COUNTRY_CACHE_STATE')
    manager=records._parse_address(_ptr(reader,base,0x2358060,'processor.manager'))
    value=_processed_value(reader,base,target,0x28d0,manager)
    if value['status']!='known':return value
    pair=_pair_factor(reader,target,base=base,target_slot=target_slot,processor_manager=manager)
    if pair['status']!='known':return pair
    return {'status':'known','country_modifier_raw':value['raw'],'pair_modifier_raw':pair['raw']}

def _trunc(value,denominator):
    return (1 if value>=0 else -1)*(abs(value)//denominator)

def yearly_contribution(current,base_yearly,suppressed,factor):
    """Project the evidenced tooltip accumulator, not a future settlement."""
    if any(type(x) is not int or not -(1<<31)<=x<(1<<31) for x in (current,base_yearly)):
        return _unknown('OPINION_DECAY_INPUT_INVALID')
    if type(suppressed) is not int or not 0<=suppressed<=255:
        return _unknown('OPINION_DECAY_INPUT_INVALID')
    if abs(current)<SCALE:
        return {'status':'known','raw':0,'basis':'tooltip_current_value_truncated_to_zero'}
    if suppressed:return {'status':'known','raw':0,'basis':'tooltip_yearly_suppressed'}
    multiplier=1000
    if current<0:
        if not isinstance(factor,dict) or factor.get('status')!='known':
            reason=factor.get('reason') if isinstance(factor,dict) else None
            if not isinstance(reason,str) or not re.fullmatch(r'OPINION_DECAY_[A-Z0-9_]{1,100}',reason):
                reason='OPINION_DECAY_FACTOR_UNKNOWN'
            return _unknown(reason)
        components=[factor.get('country_modifier_raw'),factor.get('pair_modifier_raw')]
        if any(type(x) is not int or not -(1<<31)<=x<(1<<31) for x in components):
            return _unknown('OPINION_DECAY_FACTOR_INVALID')
        total=1000+sum(components)
        if not -(1<<31)<=total<(1<<31):return _unknown('OPINION_DECAY_ARITHMETIC_RANGE')
        multiplier=max(0,total)
    amount=_trunc(multiplier*base_yearly,1000)
    if not -(1<<31)<=amount<(1<<31):return _unknown('OPINION_DECAY_ARITHMETIC_RANGE')
    raw=0 if amount<1 else (-amount if _trunc(current,1000)>=1 else amount)
    return {'status':'known','raw':raw,'basis':'derived_native_tooltip_yearly_contribution'}

def _snapshot(reader,base,pointer,index,target,target_slot=None):
    value=records._record_snapshot(reader,base,pointer,f'decay.record[{index}]')
    if value['status']!='known':return value
    definition=int.from_bytes(value['header'][16:24],'little')
    yearly=int.from_bytes(_bytes(reader,definition,0x58,4,'definition.yearly'),'little',signed=True)
    suppressed=_bytes(reader,pointer,0x25,1,'record.suppressed')[0]
    current=records._i32(value['current_raw'])
    factor=(_country_factor(reader,base,target,target_slot) if current<=-SCALE and not suppressed
            else {'status':'not_required'})
    return {'status':'known','modifier_id':value['key']['key'],
            'current_opinion_raw':current,'base_yearly_raw':yearly,
            'suppress_yearly_raw':suppressed,'factor':factor,'_stability':value}

def _record(reader,base,pointer,index,target,target_slot=None):
    try:
        before=_snapshot(reader,base,pointer,index,target,target_slot)
        after=_snapshot(reader,base,pointer,index,target,target_slot)
    except Exception:
        return _unknown('OPINION_DECAY_RECORD_READ_FAILED')
    if not records._same(before,after):return _unknown('OPINION_DECAY_INPUT_CHANGED')
    if before['status']!='known':return _unknown('OPINION_MODIFIER_CLASS_UNSUPPORTED')
    before.pop('_stability')
    before['yearly_change']=yearly_contribution(before['current_opinion_raw'],before['base_yearly_raw'],
                                               before['suppress_yearly_raw'],before['factor'])
    return before

def _backend_read(reader,base,country):
    pair={}
    def admit(read,module_base,scan,observer,target):
        pair.clear();pair.update(deepcopy(scan['requested']))
        gate=opinion._admission(read,module_base,scan,observer,target)
        gate['field_scope']['field']='R04.decay'
        return gate
    def fields(read,module_base,binding,selected):
        if selected!=FIELDS or not records._same(binding,pair.get(country)):
            raise ValueError('OPINION_DECAY_BINDING_CHANGED')
        output={}
        for name,holder,target in [(FIELDS[0],pair['FRA'],pair[country]),
                                   (FIELDS[1],pair[country],pair['FRA'])]:
            target_pointer=int(target['country_pointer'],0)
            def record_reader(r,b,p,i):return _record(r,b,p,i,target_pointer,target['slot'])
            direction=records._direction(read,module_base,holder,target,record_reader=record_reader)
            item=records._field(holder['tag'],target['tag'],direction)
            if item['status']=='known':item['unit']=UNIT
            output[name]=item
        return output
    return backend.read_two_pass(reader,base,'FRA',[country],FIELDS,read_fields=fields,admission_reader=admit)

def _observe(reader,base,country,profile):
    return opinion._owner._observe(reader,base,country,profile,backend_reader=_backend_read)
