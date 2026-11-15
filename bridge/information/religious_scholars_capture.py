"""Admitted read-only school state and both country-modifier lists."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from . import country_faith_capture as _gate
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from . import religious_scholars_memory as _fields

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'religious-scholars-memory-1374-v1.json'
PROFILE_SHA256 = '7fa94903bb1df3cb726f93ee4c0c1127b740886de38cb27342a00c0ca03aff55'
SCHEMA = 'information.religious_scholars_capture.v1'
FIELDS = ('S02.schools',)


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 65536:
        raise ValueError('SCHOLAR_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('SCHOLAR_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'religious-scholars-memory-1374'
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256):
        raise ValueError('SCHOLAR_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / item['path']).resolve(); path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('SCHOLAR_PROFILE_DEPENDENCY')
    return profile


def _observe(reader, base, country, profile):
    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, 'FRA', [target], FIELDS,
                                      read_fields=_fields.read_fields,
                                      admission_reader=_gate._admission)
    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation: Path, country: str, *, observer: str = 'FRA') -> dict:
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
                                 profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
                                 observe=_observe, allow_observer_target=True)


def validate_capture(report, context, creation, country) -> bool:
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
                                         profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
                                         observe=_observe, allow_observer_target=True,
                                         require_access=True)
