"""Own a province observation using the existing readonly FRA session owner.

The inner owner snapshot binds FRA as the observer country. The outer object
and the observe closure independently bind the requested province ID; neither
is a request to select that province in the physical client's UI.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_memory as _fields
from . import province_detail_memory as _details

ROOT=Path(__file__).resolve().parents[2]
PROFILE_FILE=Path(__file__).with_name('profiles')/'province-state-memory-1374-v4-sampling-r1.json'
PROFILE_SHA256='2d0db63ab5ce363f0a1509d495ca1ba40d74b812f3a2778706049f9e3e285a7e'
SCHEMA='information.province_state_capture.v1'
INNER_SCHEMA='information.province_state_observer_snapshot.v1'


def _valid_id(value):
    return type(value) is int and 1<=value<65536


def _load_profile():
    if not 0<PROFILE_FILE.stat().st_size<=256*1024:raise ValueError('PROVINCE_PROFILE_SIZE')
    raw=PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:raise ValueError('PROVINCE_PROFILE_PIN')
    profile=json.loads(raw)
    if (profile.get('profile_id')!='province-state-memory-1374'
            or profile.get('profile_version')!=4
            or profile.get('game_version')!='1.37.4'
            or profile.get('executable',{}).get('sha256')!=_owner.EXE_SHA256):
        raise ValueError('PROVINCE_PROFILE_BUILD')
    dependencies = profile['source_evidence'] + profile['layout_dependencies']
    frozen_native = {
        (Path(item['path']).name, item['bytes'], item['sha256'])
        for item in dependencies
        if item['path'].startswith('work/runtime/')
        and Path(item['path']).suffix.lower() in {'.inc', '.h', '.cpp', '.s'}
    }
    for item in dependencies:
        path=(ROOT/item['path']).resolve();path.relative_to(ROOT)
        # Python pins identify the historical analysis implementation.
        # Runtime layout data and native instruction guards remain pinned.
        if path.suffix == '.py':
            continue
        # Use the pinned build copy for historical native layout evidence.
        if (path.is_relative_to(ROOT / 'work/native')
                and (path.name, item['bytes'], item['sha256']) in frozen_native):
            continue
        if path.stat().st_size!=item['bytes'] or _owner._sha(path)!=item['sha256']:
            raise ValueError('PROVINCE_PROFILE_DEPENDENCY')
    return profile


def _observe_for(province_id):
    def observe(reader,base,country,profile):
        if country!='FRA' or not _valid_id(province_id):raise ValueError('PROVINCE_OBSERVER_SCOPE')
        def backend(read,module_base,observer_country):
            if observer_country!='FRA':raise ValueError('PROVINCE_OBSERVER_SCOPE')
            observed = _fields.read_two_pass(read,module_base,province_id,observer='FRA',
                fields=_details.FIELDS,read_fields=_details.read_fields)
            return _details.reconcile_resource_name(observed)
        return _owner._observe(reader,base,country,profile,backend_reader=backend)
    return observe


def capture(installation:Path,province_id:int,*,observer='FRA'):
    if not _valid_id(province_id) or observer!='FRA':raise ValueError('PROVINCE_REQUEST_SCOPE')
    inner=_owner._capture_common(installation,'FRA',observer=observer,schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe_for(province_id),
        allow_observer_target=True)
    return {'schema':SCHEMA,'observer':'FRA',
        'object':{'type':'province','province_id':province_id},'capture':inner}


def validate_capture(report,context,creation,province_id):
    if not _valid_id(province_id) or not isinstance(report,dict):return False
    if set(report)!={'schema','observer','object','capture'}:return False
    if report['schema']!=SCHEMA or report['observer']!='FRA':return False
    expected={'type':'province','province_id':province_id}
    if not _owner._same(report['object'],expected):return False
    return _owner._validate_capture_common(report['capture'],context,creation,'FRA',schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe_for(province_id),
        allow_observer_target=True,require_access=True)


__all__=['capture','validate_capture']
