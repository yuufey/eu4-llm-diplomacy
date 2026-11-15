"""Capture current land-promise flags alongside the existing two-pass war index."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import country_scale_capture as _scale
from . import foreign_technology_capture as _owner
from . import observer_registry_layout as _registry_layout
from . import war_land_commitments_memory as _memory


SCHEMA = 'information.war_land_commitments_capture.v1'
PROFILE_FILE = Path(__file__).with_name('profiles') / 'war-land-commitments-memory-1374.json'
ASSET_SHA256 = 'cc7ac81980d4cae291a318f6008a9f2831194216e998b9b906693033fec47fc5'
PROFILE_SHA256 = hashlib.sha256((ASSET_SHA256 + _scale.PROFILE_SHA256).encode('ascii')).hexdigest()


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 16384:
        raise ValueError('LAND_COMMITMENTS_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != ASSET_SHA256:
        raise ValueError('LAND_COMMITMENTS_PROFILE_CHANGED')
    contract = json.loads(raw)
    profile = _scale._load_profile()
    profile['code_guards'].extend(deepcopy(contract['code_guards']))
    profile['war_land_commitments'] = contract['layout']
    return profile


def _details(reader, base, field, profile):
    return {'land_commitments': _memory.read_land_commitments(
        reader, base, field, profile['war_land_commitments'])}


def capture(installation):
    installation = Path(installation)
    document = _owner._identity._load_installation(installation)
    descriptor = _registry_layout.descriptor_for_installation(installation)

    def observe(reader, base, country, profile):
        return _scale._capture_observe(
            reader, base, country, profile, document['creation_filetime'], descriptor,
            war_details_reader=_details)

    return _owner._capture_common(
        installation, 'FRA', observer='FRA', schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=observe, allow_observer_target=True)


def field_from_capture(report):
    field = report['observation']['backend']['targets'][0]['fields']['F01.wars']
    if field.get('status') != 'known':
        return {'status': 'unknown', 'reason': field.get('reason', 'LAND_COMMITMENTS_WARS_UNAVAILABLE')}
    return deepcopy(field['value']['details']['land_commitments'])


def validate_capture(report, context, creation):
    try:
        metadata = report['observation']['observer_module_binding']
        profile = _load_profile()
        descriptor = None
        if metadata['before'].get('file') != profile['observer_registry']['module_file']:
            descriptor = _registry_layout.descriptor_for_installation(report['request']['installation'])
        layout = profile['observer_registry'] if descriptor is None else descriptor
        consistency, before, after = _scale._module_consistency(
            metadata['before'], metadata['after'], layout)
        if metadata['consistency'] != consistency:
            return False
    except (OSError, KeyError, TypeError, ValueError):
        return False

    def observe(reader, base, country, loaded_profile):
        return _scale._observe_with_metadata(
            reader, base, country, loaded_profile, module_before=before,
            module_after=after, expected_creation=creation,
            registry_descriptor=descriptor, war_details_reader=_details)

    return _owner._validate_capture_common(
        report, context, creation, 'FRA', schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=observe, allow_observer_target=True, require_access=True)
