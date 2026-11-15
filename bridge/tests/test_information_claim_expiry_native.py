"""Exercise shipping claim capture and trampoline ABI in bounded owned processes."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from bridge import claim_expiry_observation as observation


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('kind', ['observer', 'entry-plan'])
def test_claim_expiry_native(tmp_path, kind, record_testsuite_property):
    compiler = shutil.which('g++')
    assert compiler
    sources = [f'work/native/tests/information-claim-expiry-{kind}-test.cpp']
    if kind == 'entry-plan':
        sources.append('work/native/tests/information-claim-expiry-entry-plan-abi.S')
    executable = tmp_path / 'claim-expiry.exe'
    built = subprocess.run([compiler, '-std=c++17', '-O1', '-Wall', '-Wextra', '-Iwork/native',
                            *sources, '-o', str(executable)], cwd=ROOT, capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=90)
    assert built.returncode == 0, built.stdout + built.stderr
    event_path = tmp_path / 'events.jsonl'
    environment = dict(os.environ, CLAIM_EXPIRY_FIXTURE_LOG=str(event_path))
    result = subprocess.run([str(executable)], cwd=ROOT, env=environment, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    record_testsuite_property(kind + '.stdout', result.stdout.strip())
    if kind == 'observer':
        rows = [json.loads(line) for line in event_path.read_text().splitlines()]
        assert len(rows) == 66
        events = [row for row in rows if row['event'] == observation.NATIVE_EVENT]
        assert len(events) == 65
        for event in events:
            assert observation.public_observation(event, event['session_id'])
            assert event['province_id'] == 186 and event['date_raw'] == 56692920
        assert rows[-33]['event'] == observation.NATIVE_GAP
