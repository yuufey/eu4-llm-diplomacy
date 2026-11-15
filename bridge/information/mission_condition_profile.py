"""B23 mission registry and completion-pointer membership evidence."""
import hashlib
import json
from pathlib import Path

from .mission_prerequisite_profile import load_profile as load_prerequisite_profile, EXE_SHA256, ROOT, _sha

PROFILE_FILE=Path(__file__).parent/'profiles/mission-condition-memory-1374-v1.json'
PROFILE_SHA256='0811bb731bb7bb84603fd7a97a83ec5b1c4cbb51857ba320dff9717c4ca788a8'
MAX_PROFILE_BYTES=32*1024

def load_profile():
    size=PROFILE_FILE.stat().st_size
    if not 0<size<=MAX_PROFILE_BYTES:
        raise ValueError('MISSION_CONDITION_PROFILE_SIZE')
    with PROFILE_FILE.open('rb') as stream:
        raw=stream.read(MAX_PROFILE_BYTES+1)
    if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:
        raise ValueError('MISSION_CONDITION_PROFILE_PIN')
    value=json.loads(raw)
    if (value.get('schema')!='eu4.mission_condition_memory.v1'
            or value.get('executable_sha256')!=EXE_SHA256):
        raise ValueError('MISSION_CONDITION_PROFILE_INVALID')
    load_prerequisite_profile()
    for source in value['source_evidence']:
        path=(ROOT/source['path']).resolve();path.relative_to(ROOT)
        if path.stat().st_size!=source['bytes'] or _sha(path)!=source['sha256']:
            raise ValueError('MISSION_CONDITION_EVIDENCE_PIN')
    return value
