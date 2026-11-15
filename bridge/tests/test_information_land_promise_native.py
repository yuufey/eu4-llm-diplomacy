"""Exercise the shipping land-promise observer with owned, bounded memory."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from bridge import land_promise_observation as observation


ROOT = Path(__file__).resolve().parents[2]


def test_land_promise_native_observer(tmp_path, record_testsuite_property):
    compiler = shutil.which('g++')
    assert compiler
    executable = tmp_path / 'land-promise.exe'
    built = subprocess.run([compiler, '-std=c++17', '-O1', '-Wall', '-Wextra', '-Iwork/native',
                            'work/native/tests/information-land-promise-observer-test.cpp', '-o', str(executable)],
                           cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
    assert built.returncode == 0, built.stdout + built.stderr
    event_path = tmp_path / 'events.jsonl'
    result = subprocess.run([str(executable)], cwd=ROOT, env=dict(os.environ, LAND_PROMISE_FIXTURE_LOG=str(event_path)),
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    record_testsuite_property('native.stdout', result.stdout.strip())
    rows = [json.loads(line) for line in event_path.read_text().splitlines()]
    assert len(rows) == 2
    for event in rows:
        assert observation.public_observation(event, event['session_id']) is not None
    assert {row['source'] for row in rows} == set(observation.SOURCES)
