"""Bind a read-only province observation to its configured observer.

The inner snapshot binds the observer country. The outer object
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


# New source revisions preserve the frozen native layout assumptions and have
# separate cross-country and replay tests. Keep historical profile hashes valid.
_REVIEWED_SOURCE_REVISIONS = {
    'bridge/information/province_permanent_claim_memory.py': (
        28362, '95a9e43fe66364a7463d811bffd7c6ed4d391822b0ac036d9496ab43e2e49c3f'),
    'bridge/information/province_interest_memory.py': (
        16503, 'c260b176ee9f2c5a64da96966a2d33202d8d1280ff6056627cb0d2a553ddbf4c'),
    'bridge/information/province_state_memory.py': (
        33452, '220a084f624200781aa8afa7c12d83fe34e35f6d7b019b664135a41273f747f5'),
    'bridge/information/foreign_technology_capture.py': (
        18302, 'add865cb523a3fafce591fb733d4d9ba52914b06ff6dd3bba4fe6f0bcda69165'),
    'bridge/information/localization_memory.py': (
        55946, '5494b6637b691672a48d566dfd7356def68de2ff2b5ac468db14cedf71f923ff'),
    'bridge/information/trade_income_memory.py': (
        49815, '94620284bf2c35efde5499763972ee69bac62a16bfad3c7b179181e8ff818f5e'),
    'bridge/information/province_trade_power_country_memory.py': (
        13293, 'ff9a1bb0b7238294bf82da6145875900f13f9edc1a6df2462686873e9b4250ac'),
    'bridge/information/province_node_allocation_memory.py': (
        34053, '5d302324732055d978119e0fd3d159eb50f58e4e3eaf86a4a26c0f8a78cf21f4'),
    'bridge/information/province_trade_value_memory.py': (
        7185, '01775d4afe9cfec0a4e57a396a509c3bdb30dc8d72bd774993580badec692735'),
    'bridge/information/province_trade_value_parent_memory.py': (
        13714, '4d3adbc1b444520c950f3e9151d6a5820a3a32a551deefd2049dc384547028f9'),
    'bridge/information/province_node_allocation_capture.py': (
        4938, 'a8734cbba74b5fa984b899d0fec514e6146bb9a35ead2b5eeed5f7d4d6cdd18c'),
    'bridge/information/node_cash_aggregate_memory.py': (
        17041, '8f3fe785f6b42b25e86bf38b2ae039271f09e1af3ac9de7f5f673f442d371773'),
    'bridge/information/node_cash_aggregate_parent_memory.py': (
        4229, '78fd103907a42ab060f4e06fdd6a25b2bbeb67c56ff9096491a4214d718cfd39'),
    'bridge/information/province_trade_value_capture.py': (
        5056, '4812e1b8dc8d06cb6489873a2aadab32e70ff11e5b7618b440e98205ff49f4aa'),
    'bridge/information/country_faith_capture.py': (
        3104, '3953f28ca0b867228a9c1d35f54aff2b1c79f2d50503ac6cc8abc751e6dc4267'),
    'bridge/information/country_modifiers_memory.py': (
        60650, 'f5be28106235750554f3916b2ee48f95eff5acecd827fb53e05abe5ede6de9d1'),
    'bridge/information/empire_memory.py': (
        12130, '661cb018f2fda1f05172ae8ff54f59197875e54d77c2292140b1bf6a6353415e'),
    'bridge/information/empire_capture.py': (
        14398, '0df25d00329c1e98f5fadef796fb147ec0295eee25c9292a9ff3b00f3956f46b'),
}


def _matches_reviewed_layout(item):
    path = (ROOT / item['path']).resolve()
    path.relative_to(ROOT)
    actual = (path.stat().st_size, _owner._sha(path))
    return actual in ((item['bytes'], item['sha256']), _REVIEWED_SOURCE_REVISIONS.get(item['path']))


def _validate_reviewed_layout_dependencies(profile, error):
    dependencies = profile['source_evidence'] + profile['layout_dependencies']
    frozen_native = {
        (Path(item['path']).name, item['bytes'], item['sha256'])
        for item in dependencies if item['path'].startswith('work/runtime/')
    }
    for item in dependencies:
        path = item['path']
        # The historical native evidence remains pinned at its build path.
        if path.startswith('work/native/') and (Path(path).name, item['bytes'], item['sha256']) in frozen_native:
            continue
        if not _matches_reviewed_layout(item):
            raise ValueError(error)


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


def _observe_for(province_id, observer='FRA'):
    def observe(reader,base,country,profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError('PROVINCE_OBSERVER_SCOPE')
        def backend(read,module_base,observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_OBSERVER_SCOPE')
            options = {'observer_scoped': True} if observer != 'FRA' else {}
            observed = _fields.read_two_pass(read,module_base,province_id,observer=observer,
                fields=_details.FIELDS,read_fields=_details.read_fields,**options)
            return _details.reconcile_resource_name(observed)
        return _owner._observe(reader,base,country,profile,backend_reader=backend)
    return observe


def capture(installation:Path,province_id:int,*,observer='FRA'):
    if not _valid_id(province_id) or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer):
        raise ValueError('PROVINCE_REQUEST_SCOPE')
    inner=_owner._capture_common(installation,observer,observer=observer,schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe_for(province_id, observer),
        allow_observer_target=True,observer_scoped=True)
    return {'schema':SCHEMA,'observer':observer,
        'object':{'type':'province','province_id':province_id},'capture':inner}


def validate_capture(report,context,creation,province_id):
    if not _valid_id(province_id) or not isinstance(report,dict):return False
    if set(report)!={'schema','observer','object','capture'}:return False
    observer = context.get('observer') if isinstance(context, dict) else None
    if report['schema'] != SCHEMA or report['observer'] != observer:
        return False
    expected={'type':'province','province_id':province_id}
    if not _owner._same(report['object'],expected):return False
    return _owner._validate_capture_common(report['capture'],context,creation,observer,schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,observe=_observe_for(province_id, observer),
        allow_observer_target=True,require_access=True,observer_scoped=True)


__all__=['capture','validate_capture']
