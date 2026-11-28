"""Read a selected country’s primary religion through the observer’s view.

The shared owner binds process/session/date/ROM and closes the read-only handle.
This module supplies the faith-specific pinned layout and two-pass collector.
"""
from __future__ import annotations

from functools import partial
import hashlib
import json
from pathlib import Path

from . import country_faith_memory as _fields
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner

ROOT=Path(__file__).resolve().parents[2]
PROFILE_FILE=Path(__file__).with_name('profiles')/'country-faith-memory-1374-v2.json'
PROFILE_SHA256='10a6c0e8341056ecf21869bf849759a4e1f10016cac33efdadbcaa4c96d348f2'
SCHEMA='information.country_faith_capture.v1'
FIELDS=('S02.faith',)


def _load_profile():
    if not 0<PROFILE_FILE.stat().st_size<=65536:
        raise ValueError('COUNTRY_FAITH_PROFILE_SIZE')
    raw=PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:
        raise ValueError('COUNTRY_FAITH_PROFILE_PIN')
    profile=json.loads(raw)
    if (profile.get('profile_id')!='country-faith-memory-1374'
            or profile.get('game_version')!='1.37.4'
            or profile.get('executable',{}).get('sha256')!=_owner.EXE_SHA256):
        raise ValueError('COUNTRY_FAITH_PROFILE_BUILD')
    for item in profile['source_evidence']+profile['layout_dependencies']:
        path=(ROOT/item['path']).resolve();path.relative_to(ROOT)
        if path.stat().st_size!=item['bytes'] or _owner._sha(path)!=item['sha256']:
            raise ValueError('COUNTRY_FAITH_PROFILE_DEPENDENCY')
    return profile


def _admission(read,base,bindings,observer,target):
    gate=_owner._bound_admission(read,base,bindings,observer,target)
    return gate


def _observe(reader,base,country,profile, *, observer="FRA"):
    def backend(read,module_base,target):
        return _backend.read_two_pass(read,module_base,observer,[target],FIELDS,
            read_fields=_fields.read_fields,admission_reader=_admission)
    return _owner._observe(reader,base,country,profile,backend_reader=backend)


def capture(installation:Path,country:str,*,observer:str='FRA')->dict:
    return _owner._capture_common(installation,country,observer=observer,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,
        observe=partial(_observe, observer=observer),
        allow_observer_target=True, observer_scoped=True)


def validate_capture(report,context,creation,country)->bool:
    observer = context.get('observer') if isinstance(context, dict) else None
    return _owner._validate_capture_common(report,context,creation,country,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,
        observe=partial(_observe, observer=observer),
        allow_observer_target=True, observer_scoped=True, require_access=True)


__all__=['capture','validate_capture']
