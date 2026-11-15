"""Own one readonly S04 observation using the shared identity/trace lifecycle."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import country_person_memory as _fields
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from . import person_name_runtime_memory as _name_runtime
from .country_faith_capture import _admission as _country_admission

ROOT=Path(__file__).resolve().parents[2]
PROFILE_FILE=Path(__file__).with_name('profiles')/'country-person-memory-1374-v3-sampling-r1.json'
PROFILE_SHA256='1cb0094f97526499425836ea409ed17ca06126a4d564c5f20fbeb55e5865bb2f'
SCHEMA='information.country_person_capture.v1'


def _load_profile():
    if not 0<PROFILE_FILE.stat().st_size<=256*1024:raise ValueError('PERSON_PROFILE_SIZE')
    raw=PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:raise ValueError('PERSON_PROFILE_PIN')
    profile=json.loads(raw)
    if (profile.get('profile_id')!='country-person-memory-1374'
            or profile.get('game_version')!='1.37.4'
            or profile.get('executable',{}).get('sha256')!=_owner.EXE_SHA256):
        raise ValueError('PERSON_PROFILE_BUILD')
    for item in profile['source_evidence']+profile['layout_dependencies']:
        path=(ROOT/item['path']).resolve();path.relative_to(ROOT)
        if path.stat().st_size!=item['bytes'] or _owner._sha(path)!=item['sha256']:
            raise ValueError('PERSON_PROFILE_DEPENDENCY')
    plugin=profile.get('name_runtime',{}).get('plugin')
    if plugin is not None:
        from work.local_config import game_exe
        path=game_exe().parent/'plugins'/'plugin64.dll'
        if path.stat().st_size!=plugin['file_bytes'] or _owner._sha(path)!=plugin['sha256']:
            raise ValueError('PERSON_PLUGIN_FILE_IDENTITY')
    return profile


def _observe(reader,base,country,profile):
    layouts={}
    def admission(read,module_base,scan,observer,target):
        result=_country_admission(read,module_base,scan,observer,target)
        if profile.get('name_runtime') is None:
            layouts[target]='vanilla'
        elif result.get('status')=='known' and result.get('admitted') is True:
            runtime=_name_runtime.read_person_name_layout(read,module_base,profile['name_runtime'])
            result['person_name_runtime']=runtime
            layouts[target]=runtime.get('layout') if runtime.get('status')=='known' else None
        else:
            layouts[target]=None
        return result
    def backend(read,module_base,target):
        def collect(limiter,module,target_binding,fields):
            return _fields.read_fields(limiter,module,target_binding,fields,
                name_layout=layouts.get(target))
        return _backend.read_two_pass(read,module_base,'FRA',[target],_fields.FIELDS,
            read_fields=collect,admission_reader=admission)
    return _owner._observe(reader,base,country,profile,backend_reader=backend)


def capture(installation:Path,country:str,*,observer:str='FRA')->dict:
    return _owner._capture_common(installation,country,observer=observer,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe,
        allow_observer_target=True)


def validate_capture(report,context,creation,country)->bool:
    return _owner._validate_capture_common(report,context,creation,country,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe,
        allow_observer_target=True,require_access=True)


__all__=['capture','validate_capture']
