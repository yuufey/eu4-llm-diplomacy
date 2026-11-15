"""Pinned native required_missions layout and retained static evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).parent / 'profiles/mission-prerequisite-memory-1374-v1.json'
PROFILE_SHA256 = '09bb44088353ce873863fa7e24c481964c0116fe4049e85fdb09fd86b231074d'
EXE_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
MAX_PROFILE_BYTES = 32 * 1024

def _sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def load_profile():
    stat_size = PROFILE_FILE.stat().st_size
    if not 0 < stat_size <= MAX_PROFILE_BYTES:
        raise ValueError('PREREQUISITE_PROFILE_PIN_MISMATCH')
    with PROFILE_FILE.open('rb') as stream:
        raw = stream.read(MAX_PROFILE_BYTES + 1)
    if (not 0 < len(raw) <= MAX_PROFILE_BYTES or len(raw) != stat_size
            or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256):
        raise ValueError('PREREQUISITE_PROFILE_PIN_MISMATCH')
    profile = json.loads(raw)
    if (profile.get('schema') != 'eu4.mission_prerequisite_memory.v1'
            or profile.get('executable_sha256') != EXE_SHA256
            or profile.get('layout') != {'data_offset': 0x128, 'capacity_offset': 0x130,
                                         'count_offset': 0x134, 'stride': 32}):
        raise ValueError('PREREQUISITE_PROFILE_INVALID')
    for record in profile['source_evidence']:
        path = (ROOT / record['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != record['bytes'] or _sha(path) != record['sha256']:
            raise ValueError('PREREQUISITE_EVIDENCE_PIN_MISMATCH')
    return profile
