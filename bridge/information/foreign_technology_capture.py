"""Own one read-only, identity-bound foreign-technology observation.

The country-view condition is projected to the logical FRA observer. It does
not require FRA to be the physical client country and never opens a UI. The
pure backend keeps its own visibility unknown; this parent adds the pinned
predicate, ROM guards, process/session/date binding and trace replay contract.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import country_resources_memory as _parent
from . import country_view_admission_memory as _admission
from . import foreign_technology_memory as _backend
from . import localization_memory as _identity
from . import mission_memory as _mm
from . import observation_time as _time

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles')/'foreign-technology-memory-1374-v2.json'
PROFILE_SHA256 = 'fd663e01bdd46bda1c456d52cc83e579b2eb9c79d7a0b8404a98db4f1e192158'
EXE_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
_TAG = re.compile(r'[A-Z0-9]{3}\Z')
MAX_READ_BYTES = 512*1024


class RecordedReadError(RuntimeError):
    """A failed RPM operation with retained address/width/label and reason."""


def _failure_reason(row,address,size,label):
    if (not isinstance(row,dict) or row.get('address')!=hex(address)
            or type(row.get('size')) is not int or row['size']!=size
            or row.get('label')!=label or row.get('status')!='error'
            or 'raw_hex' in row or not isinstance(row.get('error'),str)
            or not 0<len(row['error'])<=512):
        return None
    return row['error']


class _FailureReplayReader:
    """Normalize only failures that the underlying RPM owner actually logged."""
    def __init__(self,reader):
        self.reader=reader
        self.read_failures=[]

    def read(self,address,size,label):
        prior_rows=getattr(self.reader,'read_log',None)
        prior_count=len(prior_rows) if isinstance(prior_rows,list) else None
        try:
            return self.reader.read(address,size,label)
        except Exception:
            rows=getattr(self.reader,'read_log',None)
            fresh=(prior_count is not None and rows is prior_rows and len(rows)==prior_count+1)
            reason=_failure_reason(rows[-1],address,size,label) if fresh else None
            if reason is not None:
                self.read_failures.append(deepcopy(rows[-1]))
                raise RecordedReadError(reason) from None
            raise


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024*1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 65536:
        raise ValueError('FOREIGN_TECH_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('FOREIGN_TECH_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'foreign-technology-memory-1374'
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable',{}).get('sha256') != EXE_SHA256):
        raise ValueError('FOREIGN_TECH_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT/item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _sha(path) != item['sha256']:
            raise ValueError('FOREIGN_TECH_PROFILE_DEPENDENCY')
    return profile


def _pointer(value):
    if type(value) is not int or not 0x10000 <= value < 0x800000000000:
        raise ValueError('FOREIGN_TECH_POINTER_INVALID')
    return value


def _read(reader,address,size,label):
    _pointer(address)
    _pointer(address+size-1)
    raw=reader.read(address,size,label)
    if not isinstance(raw,bytes) or len(raw)!=size:
        raise ValueError('FOREIGN_TECH_SHORT_READ')
    return raw


def _u64(reader,address,label):
    return int.from_bytes(_read(reader,address,8,label),'little')


def _same(left,right):
    """Trace replay must not equate booleans and integer observations."""
    if type(left) is not type(right):
        return False
    if isinstance(left,dict):
        return left.keys()==right.keys() and all(_same(value,right[key]) for key,value in left.items())
    if isinstance(left,(list,tuple)):
        return len(left)==len(right) and all(_same(a,b) for a,b in zip(left,right))
    return left==right


def _context(reader,module_base):
    world=_pointer(_u64(reader,module_base+0x233fe58,'foreign_tech.world_pointer'))
    date_raw=_read(reader,world+0x1dd0,4,'foreign_tech.date')
    date=int.from_bytes(date_raw,'little',signed=True)
    if date<0:
        raise ValueError('FOREIGN_TECH_DATE_INVALID')
    mode=_read(reader,world+0x1e66,1,'foreign_tech.client_mode')[0]
    override=_read(reader,world+0x1e6f,1,'foreign_tech.client_override')[0]
    offset=0x1e68 if mode==7 and override else 0x1e60
    ref_raw=_read(reader,world+offset,8,'foreign_tech.physical_client_reference')
    return {'world_pointer':hex(world),'game_date':date,'game_date_raw_hex':date_raw.hex(),
        'physical_client_reference_raw_hex':ref_raw.hex(),'client_mode':mode,
        'client_override':override,'physical_client_reference_offset':hex(offset)}


def _guards(reader,module_base,profile,verifier=None):
    records=[]
    for guard in profile['code_guards']:
        expected=bytes.fromhex(guard['bytes'])
        rva=int(guard['rva'],0)
        if (not 0<len(expected)<=65536 or int(guard['end_rva_exclusive'],0)!=rva+len(expected)
                or hashlib.sha256(expected).hexdigest()!=guard['sha256']):
            raise ValueError('FOREIGN_TECH_CODE_PROFILE_INVALID')
        actual=_read(reader,module_base+rva,len(expected),'foreign_tech.code.'+guard['name'])
        records.append({'name':guard['name'],'rva':guard['rva'],'actual_hex':actual.hex(),
                        'matches':actual==expected})
        if actual!=expected:
            proof=verifier(reader,module_base,rva,expected,actual) if verifier is not None else None
            if not proof:
                raise ValueError('FOREIGN_TECH_RUNTIME_CODE_MISMATCH')
            records[-1]['observer_patch']=proof
    if not records:
        raise ValueError('FOREIGN_TECH_CODE_GUARD_MISSING')
    return records


def _observe(reader,module_base,country,profile,*,backend_reader=None,guard_verifier=None):
    before_guard=_guards(reader,module_base,profile,guard_verifier)
    before_context=_context(reader,module_base)
    if backend_reader is None:
        backend=_backend.read_two_pass(reader,module_base,'FRA',[country],
            admission_reader=_bound_admission)
    else:
        backend=backend_reader(reader,module_base,country)
    after_context=_context(reader,module_base)
    after_guard=_guards(reader,module_base,profile,guard_verifier)
    role_verified=all(
        (item.get('admission_by_pass',{}).get(phase) or {}).get('observer_nonplayer_role',{}).get('verified') is True
        for item in backend.get('targets',[]) for phase in ('pass1','pass2'))
    stable=(_same(_time.without_clock(before_context), _time.without_clock(after_context))
            and _time.dates_match(before_context['game_date'], after_context['game_date'])
            and backend.get('status')=='observed'
            and backend.get('consistency',{}).get('status')=='stable'
            and bool(backend.get('targets')) and role_verified)
    result={'runtime_code_before':before_guard,'context_before':before_context,'backend':backend,
            'context_after':after_context,'runtime_code_after':after_guard,'stable':stable}
    failures=getattr(reader,'read_failures',None)
    if failures:
        result['read_failures']=deepcopy(failures)
    return result


def _bound_admission(read,module_base,bindings,observer,target):
    """Keep the logical observer non-player, independently of UI current-ref."""
    def raw(address,size,label):
        _pointer(address);_pointer(address+size-1)
        data=read(address,size,label)
        if not isinstance(data,bytes) or len(data)!=size:
            raise ValueError('FOREIGN_TECH_ROLE_SHORT_READ')
        return data
    world=int.from_bytes(raw(module_base+0x233fe58,8,'foreign_tech.role.world'),'little')
    _pointer(world)
    slot=bindings['requested'][observer]['slot']
    if type(slot) is not int or not 0<=slot<4096:
        raise ValueError('FOREIGN_TECH_ROLE_SLOT')
    count_raw=raw(world+0xa60,4,'foreign_tech.role.human_count')
    controllers_raw=raw(world+0x1d48,8,'foreign_tech.role.controllers_pointer')
    controllers=_pointer(int.from_bytes(controllers_raw,'little'))
    kind_raw=raw(controllers+slot*4,4,'foreign_tech.role.observer_controller')
    count=int.from_bytes(count_raw,'little',signed=True)
    kind=int.from_bytes(kind_raw,'little',signed=True)
    gate=_admission.read_country_view_admission(read,module_base,bindings,observer,target)
    gate['observer_nonplayer_role']={'observer':observer,'slot':slot,'human_count':count,
        'controller_type':kind,'human_count_raw_hex':count_raw.hex(),
        'controller_type_raw_hex':kind_raw.hex(),'controllers_pointer_raw_hex':controllers_raw.hex(),
        'verified':count==1 and kind==0,
        'basis':'copied_native_controller_array_not_UI_current_country'}
    return gate


def _capture_common(installation, country, *, observer, schema, profile_sha256,
                    load_profile, observe, allow_observer_target=False):
    """Own the shared identity, read-only handle, ROM and trace lifecycle."""
    report={'schema':schema,'status':'unknown','completed':False,
        'request':{'country':country,'observer':observer,'installation':str(installation)},
        'profile_sha256':profile_sha256,'identity':{},'observation':None,'raw_reads':[],
        'cleanup':{'status':'not_opened'},'errors':[],
        'collected_at':datetime.now(timezone.utc).isoformat(),
        'access':{'read_only':True,'native_function_invoked':False,'writes':False,'UI_control':False,
                  'date_advance':False,'save_or_reload':False,'limit_bytes':MAX_READ_BYTES}}
    kernel=handle=reader=None
    try:
        if (observer!='FRA' or not isinstance(country,str) or not _TAG.fullmatch(country)
                or (country==observer and not allow_observer_target)):
            raise ValueError('FOREIGN_TECH_REQUEST_SCOPE')
        profile=load_profile()
        document=_identity._load_installation(Path(installation))
        report['request'].update({'pid':document['pid'],'creation_filetime':document['creation_filetime'],
                                 'session_id':document['session_id']})
        kernel=_identity._configure_kernel()
        handle=kernel.OpenProcess(_mm.PROCESS_ACCESS,False,int(document['pid']))
        if not handle:
            raise OSError('FOREIGN_TECH_OPEN_PROCESS')
        base=_identity._capture_identity(report,document,kernel,handle)
        report['module_base']=hex(base)
        process_path=Path(report['identity']['process_path'])
        for guard in profile['code_guards']:
            expected=bytes.fromhex(guard['bytes'])
            if _mm._read_pe_rva_bytes(process_path,int(guard['rva'],0),len(expected))!=expected:
                raise ValueError('FOREIGN_TECH_FILE_CODE_MISMATCH')
        reader=_parent.AddressBoundedRPM(kernel,handle,base)
        report['observation']=observe(_FailureReplayReader(reader),base,country,profile)
        after_identity={'identity':{}}
        if _identity._capture_identity(after_identity,document,kernel,handle)!=base:
            raise ValueError('FOREIGN_TECH_MODULE_CHANGED')
        report['identity_after']=after_identity['identity']
        if not _same(report['identity'],report['identity_after']):
            raise ValueError('FOREIGN_TECH_PROCESS_IDENTITY_CHANGED')
        if not report['observation']['stable']:
            raise ValueError('FOREIGN_TECH_OBSERVATION_UNSTABLE')
        report['status']='observed'
    except Exception as exc:
        report['errors'].append({'type':type(exc).__name__,'reason':str(exc)})
    finally:
        if reader is not None:
            report['raw_reads']=deepcopy(reader.read_log)
            report['access'].update({'bytes_requested':reader.bytes_requested,'calls':reader.calls})
        report['cleanup']=_identity._close_process_handle(kernel,handle)
        report['completed']=(report['status']=='observed' and report['cleanup'].get('status')=='closed')
        if not report['completed']:
            report['status']='unknown'
    return report


def capture(installation:Path, country:str, *, observer:str='FRA')->dict:
    return _capture_common(installation,country,observer=observer,
        schema='information.foreign_technology_capture.v1',profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,observe=_observe)


class _Replay:
    def __init__(self,rows):
        if not isinstance(rows,list) or len(rows)>40000:
            raise ValueError('FOREIGN_TECH_TRACE_SHAPE')
        self.rows=rows;self.index=0;self.bytes=0;self.read_failures=[]

    def read(self,address,size,label):
        if self.index>=len(self.rows):
            raise ValueError('FOREIGN_TECH_TRACE_EXHAUSTED')
        row=self.rows[self.index];self.index+=1;self.bytes+=size
        if (self.bytes>MAX_READ_BYTES or not 0<size<=65536
                or row.get('address')!=hex(address) or type(row.get('size')) is not int or row['size']!=size
                or row.get('label')!=label):
            raise ValueError('FOREIGN_TECH_TRACE_MISMATCH')
        reason=_failure_reason(row,address,size,label)
        if reason is not None:
            self.read_failures.append(deepcopy(row))
            raise RecordedReadError(reason)
        if row.get('status')!='observed':
            raise ValueError('FOREIGN_TECH_TRACE_MISMATCH')
        raw=bytes.fromhex(row['raw_hex'])
        if len(raw)!=size:
            raise ValueError('FOREIGN_TECH_TRACE_WIDTH')
        return raw


def _validate_capture_common(report,context,creation,country,*,schema,profile_sha256,
                             load_profile,observe,allow_observer_target=False,require_access=False):
    """Recompute every observation from its ordered raw trace; never attach."""
    try:
        if (not isinstance(report,dict) or report.get('schema')!=schema
                or report.get('status')!='observed' or report.get('completed') is not True
                or report.get('profile_sha256')!=profile_sha256
                or report.get('cleanup',{}).get('status')!='closed'
                or report['cleanup'].get('closed') is not True
                or report['cleanup'].get('success') is not True):
            return False
        access=report.get('access')
        if require_access or access is not None:
            expected={'read_only':True,'native_function_invoked':False,'writes':False,
                'UI_control':False,'date_advance':False,'save_or_reload':False,'limit_bytes':MAX_READ_BYTES}
            if not isinstance(access,dict) or any(not _same(access.get(key),value) for key,value in expected.items()):
                return False
            rows=report['raw_reads']
            if (not isinstance(rows,list) or type(access.get('calls')) is not int
                    or type(access.get('bytes_requested')) is not int
                    or access['calls']!=len(rows)
                    or any(type(row.get('size')) is not int or not 0<row['size']<=65536 for row in rows)
                    or access['bytes_requested']!=sum(row['size'] for row in rows)
                    or not 0<access['bytes_requested']<=MAX_READ_BYTES):
                return False
        request=report['request'];identity=report['identity']
        if (request['country']!=country or request['observer']!='FRA' or context.get('observer')!='FRA'
                or not isinstance(country,str) or not _TAG.fullmatch(country)
                or (country=='FRA' and not allow_observer_target)
                or request['session_id']!=context.get('session_id')
                or int(request['creation_filetime'])!=int(creation)
                or identity.get('binding_verified') is not True
                or identity.get('process_creation_filetime')!=int(creation)
                or identity.get('process_path_sha256')!=EXE_SHA256
                or not _same(identity,report['identity_after'])):
            return False
        if context.get('game_version')!='1.37.4' or context.get('game_sha256')!=EXE_SHA256:
            return False
        base=int(report['module_base'],0);profile=load_profile();replay=_Replay(report['raw_reads'])
        rebuilt=observe(replay,base,country,profile)
        if (replay.index!=len(replay.rows) or not _same(rebuilt,report['observation']) or not rebuilt['stable']
                or not _time.dates_match(context.get('game_date'),
                    rebuilt['context_before']['game_date'], rebuilt['context_after']['game_date'])):
            return False
        return True
    except Exception:
        return False


def validate_capture(report:Any,context:Mapping[str,Any],creation:int,country:str)->bool:
    """Recompute the legacy F02 observation without changing its packet shape."""
    return _validate_capture_common(report,context,creation,country,
        schema='information.foreign_technology_capture.v1',profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,observe=_observe)


__all__=['capture','validate_capture']
