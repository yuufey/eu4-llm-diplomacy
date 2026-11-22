"""Identity-bound, admitted read-only capture of canonical religion/group keys."""
from __future__ import annotations

from functools import partial
import hashlib
import json
from pathlib import Path

from . import country_faith_capture as _gate
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from .province_state_capture import _matches_reviewed_layout
from . import religion_identity_memory as _fields

PROFILE_FILE = Path(__file__).with_name('profiles') / 'religion-identity-memory-1374-v1.json'
PROFILE_SHA256 = '7d3eb8cccd55c5b996c5711f54d9b081dd4d0ee8bf66a32b9ff7668abb4061cb'
SCHEMA = 'information.religion_identity_capture.v1'
FIELDS = ('S02.religion_identity',)


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 65536:
        raise ValueError('RELIGION_IDENTITY_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('RELIGION_IDENTITY_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'religion-identity-memory-1374'
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256):
        raise ValueError('RELIGION_IDENTITY_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        if not _matches_reviewed_layout(item):
            raise ValueError('RELIGION_IDENTITY_PROFILE_DEPENDENCY')
    return profile


def _observe(reader, base, country, profile, *, observer="FRA"):
    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, observer, [target], FIELDS,
                                      read_fields=_fields.read_fields,
                                      admission_reader=_gate._admission)
    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation: Path, country: str, *, observer: str = 'FRA') -> dict:
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
                                 profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
                                 observe=partial(_observe, observer=observer),
                                 allow_observer_target=True, observer_scoped=True)


def validate_capture(report, context, creation, country) -> bool:
    observer = context.get("observer") if isinstance(context, dict) else None
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
                                         profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
                                         observe=partial(_observe, observer=observer),
                                         allow_observer_target=True, observer_scoped=True,
                                         require_access=True)
