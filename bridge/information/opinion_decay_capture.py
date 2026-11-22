"""Identity-bound capture/replay for the R04 yearly-contribution reader."""
import re
from collections.abc import Mapping
from functools import partial
from . import foreign_technology_capture as owner
from . import opinion_decay_memory as memory

FIELDS=memory.FIELDS
SCHEMA=memory.SCHEMA
PROFILE_SHA256=memory.PROFILE_SHA256
PROFILE_FILE=memory.PROFILE_FILE
PROFILE_ID=memory.PROFILE_ID
PROFILE_VERSION=memory.PROFILE_VERSION

def capture(installation,country,*,observer='FRA'):
    if not isinstance(observer, str) or not owner._TAG.fullmatch(observer):
        raise ValueError('OPINION_OBSERVER_TAG_INVALID')
    if not isinstance(country,str) or not re.fullmatch(r'[A-Z0-9]{3}',country) or country==observer:
        raise ValueError('OPINION_DECAY_REQUEST_SCOPE')
    return owner._capture_common(installation,country,observer=observer,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=memory._load_profile,
        observe=partial(memory._observe, observer=observer), observer_scoped=True)

def validate_capture(report,context,creation,country):
    if not isinstance(report,Mapping) or report.get('schema')!=SCHEMA:return False
    return owner._validate_capture_common(report,context,creation,country,schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,load_profile=memory._load_profile,
        observe=partial(memory._observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True)
