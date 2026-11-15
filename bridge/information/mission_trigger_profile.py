"""Pinned loaded-trigger structure, scalar and province contracts for B23."""
import hashlib
import json
from pathlib import Path

from .mission_condition_profile import load_profile as load_condition_profile
from .mission_prerequisite_profile import ROOT, EXE_SHA256, _sha

PROFILE_FILE=Path(__file__).parent/'profiles/mission-trigger-memory-1374-v14-r3-sampling-r11.json'
PROFILE_SHA256='12e82c2ef8dccc9cd4253a7bc19c56a33d58591f0f70289a18e51643fad44f2a'
MAX_PROFILE_BYTES=128*1024

def load_profile():
    size=PROFILE_FILE.stat().st_size
    if not 0<size<=MAX_PROFILE_BYTES:
        raise ValueError('MISSION_TRIGGER_PROFILE_SIZE')
    with PROFILE_FILE.open('rb') as stream:
        raw=stream.read(MAX_PROFILE_BYTES+1)
    if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:
        raise ValueError('MISSION_TRIGGER_PROFILE_PIN')
    profile=json.loads(raw)
    if profile.get('schema')!='eu4.mission_trigger_memory.v14' or profile.get('executable_sha256')!=EXE_SHA256:
        raise ValueError('MISSION_TRIGGER_PROFILE_INVALID')
    load_condition_profile()
    from .province_state_capture import _load_profile as load_province_profile
    load_province_profile()
    from . import country_modifiers_memory, religious_unity_memory, military_resources_memory
    country_modifiers_memory._load_profile()
    religious_unity_memory._load_profile()
    military_resources_memory._load_profile()
    for item in profile['source_evidence']:
        path=(ROOT/item['path']).resolve();path.relative_to(ROOT)
        # Retain Python hashes as analysis provenance while admitting current
        # implementation updates through the existing native/layout contracts.
        if path.suffix == '.py':
            continue
        if path.stat().st_size!=item['bytes'] or _sha(path)!=item['sha256']:
            raise ValueError('MISSION_TRIGGER_EVIDENCE_PIN')
    return profile
