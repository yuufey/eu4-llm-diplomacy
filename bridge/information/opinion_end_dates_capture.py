"""Reuse the typed bilateral record capture with independent schedule guards."""
from copy import deepcopy
from collections.abc import Mapping
from functools import partial
from pathlib import Path
import hashlib
import json
import re
from . import opinion_modifiers_memory as records
from . import opinion_capture as opinion
from . import foreign_technology_capture as owner

ROOT=Path(__file__).resolve().parents[2]
PROFILE_FILE=Path(__file__).with_name('profiles')/'opinion-end-dates-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256='9c350566409d002a0e123b4f7b782874cfb921e2cddbde09106c4d56d58f8164'
PROFILE_ID='opinion-end-dates-memory-1374-v1'
SCHEMA='information.opinion_end_dates_capture.v1'
FIELDS=records.FIELDS

def _load_profile():
    if not 0<PROFILE_FILE.stat().st_size<=65536:raise ValueError('OPINION_END_DATES_PROFILE_SIZE')
    raw=PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:raise ValueError('OPINION_END_DATES_PROFILE_PIN')
    own=json.loads(raw)
    if own['profile_id']!=PROFILE_ID or own['base_profile_sha256']!=records.PROFILE_SHA256:
        raise ValueError('OPINION_END_DATES_PROFILE_BASE')
    for item in own['dependencies']:
        path=(ROOT/item['path']).resolve(strict=True);path.relative_to(ROOT)
        size = path.stat().st_size
        if not 0 < size <= 16 * 1024 * 1024:
            raise ValueError('OPINION_END_DATES_DEPENDENCY_SIZE')
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if not opinion._record_layout_matches(item, size, digest):
            raise ValueError('OPINION_END_DATES_DEPENDENCY_PIN')
    merged=deepcopy(records._load_profile())
    merged.update(profile_id=PROFILE_ID,profile_version=1)
    merged['code_guards'].extend(own['code_guards'])
    return merged

def capture(installation,country,*,observer='FRA'):
    if not isinstance(observer, str) or not owner._TAG.fullmatch(observer):
        raise ValueError('OPINION_OBSERVER_TAG_INVALID')
    if not isinstance(country,str) or not re.fullmatch(r'[A-Z0-9]{3}',country) or country==observer:
        raise ValueError('OPINION_END_DATES_REQUEST_SCOPE')
    return owner._capture_common(installation,country,observer=observer,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,
        observe=partial(records._observe, observer=observer), observer_scoped=True)

def validate_capture(report,context,creation,country):
    if not isinstance(report,Mapping) or report.get('schema')!=SCHEMA:return False
    return owner._validate_capture_common(report,context,creation,country,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=_load_profile,
        observe=partial(records._observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True)
