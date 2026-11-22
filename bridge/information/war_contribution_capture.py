"""Capture participation values through the admitted two-pass current war index."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import country_scale_capture as _scale
from . import foreign_technology_capture as _owner
from . import observer_registry_layout as _registry_layout
from . import war_land_commitments_capture as _participants
from . import war_contribution_memory as _memory


SCHEMA = 'information.war_contribution_capture.v1'
PROFILE_FILE = Path(__file__).with_name('profiles') / 'war-contribution-memory-1374.json'
ASSET_SHA256 = '1abab3a5281ac88c313cc4d0e3aadd9468a98b65519fe2f22dcbd9ef93c9cf9a'
PROFILE_SHA256 = hashlib.sha256((ASSET_SHA256 + _participants.PROFILE_SHA256).encode('ascii')).hexdigest()


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != ASSET_SHA256:
        raise ValueError('WAR_CONTRIBUTION_PROFILE_CHANGED')
    contract = json.loads(raw)
    profile = _participants._load_profile()
    profile['code_guards'].extend(deepcopy(contract['code_guards']))
    profile['war_contribution'] = dict(profile['war_land_commitments'], **contract['layout'])
    return profile


def _details(reader, base, field, profile):
    return {'contribution': _memory.read_contribution(reader, base, field, profile['war_contribution'])}


def capture(installation, *, observer='FRA'):
    installation = Path(installation)
    document = _owner._identity._load_installation(installation)
    descriptor = _registry_layout.descriptor_for_installation(installation)

    def observe(reader, base, country, profile):
        return _scale._capture_observe(reader, base, country, profile, document['creation_filetime'],
                                      descriptor, war_details_reader=_details, observer=observer)

    return _owner._capture_common(installation, observer, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=observe,
        allow_observer_target=True, observer_scoped=True)


def field_from_capture(report):
    field = report['observation']['backend']['targets'][0]['fields']['F01.wars']
    if field.get('status') != 'known':
        return {'status': 'unknown', 'reason': field.get('reason', 'WAR_CONTRIBUTION_WARS_UNAVAILABLE')}
    return deepcopy(field['value']['details']['contribution'])


def validate_capture(report, context, creation):
    try:
        observer = context['observer']
        metadata = report['observation']['observer_module_binding']
        profile = _load_profile()
        descriptor = None
        if metadata['before'].get('file') != profile['observer_registry']['module_file']:
            descriptor = _registry_layout.descriptor_for_installation(report['request']['installation'])
        layout = profile['observer_registry'] if descriptor is None else descriptor
        consistency, before, after = _scale._module_consistency(metadata['before'], metadata['after'], layout)
        if metadata['consistency'] != consistency:
            return False
    except (OSError, KeyError, TypeError, ValueError):
        return False

    def observe(reader, base, country, loaded_profile):
        return _scale._observe_with_metadata(reader, base, country, loaded_profile,
            module_before=before, module_after=after, expected_creation=creation,
            registry_descriptor=descriptor, war_details_reader=_details, observer=observer)

    return _owner._validate_capture_common(report, context, creation, observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=observe,
        allow_observer_target=True, require_access=True, observer_scoped=True)
