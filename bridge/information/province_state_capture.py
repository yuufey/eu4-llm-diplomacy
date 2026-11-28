"""Bind a read-only province observation to its configured observer.

The inner snapshot binds the observer country. The outer object
and the observe closure independently bind the requested province ID; neither
is a request to select that province in the physical client's UI.
"""
from __future__ import annotations

import hashlib
import json
from functools import partial
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
        33250, '9b917749d07d210ba3554b643a4eafd526d78a0bbcdbc00c54290d5e5a3292b7'),
    'bridge/information/foreign_technology_capture.py': (
        18372, '800fe35f2466922fe4120e0ba90343ea076871ee1c590007e6846d9f09150510'),
    'bridge/information/localization_memory.py': (
        55946, '5494b6637b691672a48d566dfd7356def68de2ff2b5ac468db14cedf71f923ff'),
    'bridge/information/trade_income_memory.py': (
        49815, '94620284bf2c35efde5499763972ee69bac62a16bfad3c7b179181e8ff818f5e'),
    'bridge/information/province_trade_power_country_memory.py': (
        13050, '8a3f357ff0b6469cea82cf3bdeca43d5c163cacf15a5a6fb600b4b9a1cb4220f'),
    'bridge/information/province_node_allocation_memory.py': (
        34053, '5d302324732055d978119e0fd3d159eb50f58e4e3eaf86a4a26c0f8a78cf21f4'),
    'bridge/information/province_trade_value_memory.py': (
        7185, '01775d4afe9cfec0a4e57a396a509c3bdb30dc8d72bd774993580badec692735'),
    'bridge/information/province_trade_value_parent_memory.py': (
        13566, '5e1bad6496cb8eff34f0bbfd1bc7f188cdb02755db6128ad2c3fb10e2663bd3c'),
    'bridge/information/province_node_allocation_capture.py': (
        4938, 'a8734cbba74b5fa984b899d0fec514e6146bb9a35ead2b5eeed5f7d4d6cdd18c'),
    'bridge/information/node_cash_aggregate_memory.py': (
        16956, '6bf046d581c5040c773668851a5abe2d0beae9c55b3ae564e107732dc784bd5e'),
    'bridge/information/node_cash_aggregate_parent_memory.py': (
        4229, '78fd103907a42ab060f4e06fdd6a25b2bbeb67c56ff9096491a4214d718cfd39'),
    'bridge/information/province_trade_value_capture.py': (
        5056, '4812e1b8dc8d06cb6489873a2aadab32e70ff11e5b7618b440e98205ff49f4aa'),
    'bridge/information/country_faith_capture.py': (
        2933, '07573bfd12186b2ee46ce753fc08387b29d1687a4de5b06b6c2b349406444c8c'),
    'bridge/information/country_modifiers_memory.py': (
        60650, 'f5be28106235750554f3916b2ee48f95eff5acecd827fb53e05abe5ede6de9d1'),
    'bridge/information/empire_memory.py': (
        11954, '9428bbc7a9eef22a7f30e90b90d9876e682ebf55b149563f5206b4527fb47291'),
    'bridge/information/province_discovery_memory.py': (
        19882, '2db327f644f51d5b12c6da368fe8e6ffce89a1577f4abb65c996da55575abce2'),
    'bridge/information/trade_value_capture.py': (
        11470, '8a6fb66c4f54b17dcb4f9f51e174439926eb477a49388d01e59ababe09fb5d24'),
    'bridge/information/empire_capture.py': (
        14343, '2d241600d4c94c1676abfa885caf4dd8bb0065b9fab517f621b070089cacbb12'),
    'bridge/information/empire_capture_v2.py': (
        17824, '679aba57f2da9556d8ea27f224d528d91c97d56ca2412f6f18ff070f6ac4b543'),
    'bridge/information/mission_memory.py': (
        87935, '98862abbfb9941fe9f9553e8c3d63398fb8acba37b30e377b05979c46edda1ff'),
    'bridge/information/province_detail_memory.py': (
        8104, 'cd3cc5a0dff7c2d64fa5adf71d475a9c69cdaefd7ebd5300bd8d9c106899495c'),
    'bridge/information/province_resource_localization_memory.py': (
        9952, '89ab196be3b8ecd11508385446c03114bd855c33112c0fe1ee9337d4928a864b'),
    'bridge/information/foreign_quality_memory.py': (
        37284, '1aebcaae4a6ec612123263db62a8493760910a19fb6aba9c8c1a13fc3c61a14c'),
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
                fields=_details.FIELDS,read_fields=partial(_details.read_fields, observer=observer),**options)
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
