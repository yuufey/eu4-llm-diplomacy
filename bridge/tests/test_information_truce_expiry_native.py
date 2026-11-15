"""Run shipping truce capture and trampoline ABI in bounded owned processes."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from bridge import truce_expiry_observation as observation
from bridge.information.truce_date_math import direct_truce_expiry


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('kind', ['observer', 'entry-plan'])
def test_truce_expiry_native(tmp_path, kind, record_testsuite_property):
    compiler = shutil.which('g++')
    assert compiler
    sources = [f'work/native/tests/information-truce-expiry-{kind}-test.cpp']
    if kind == 'entry-plan':
        sources.append('work/native/tests/information-truce-expiry-entry-plan-abi.S')
    executable = tmp_path / 'truce-expiry.exe'
    built = subprocess.run([compiler, '-std=c++17', '-O1', '-Wall', '-Wextra', '-Iwork/native',
                            *sources, '-o', str(executable)], cwd=ROOT, capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=90)
    assert built.returncode == 0, built.stdout + built.stderr
    event_path = tmp_path / 'events.jsonl'
    math_path = tmp_path / 'date-math.csv'
    environment = dict(os.environ, TRUCE_EXPIRY_FIXTURE_LOG=str(event_path),
                       TRUCE_EXPIRY_MATH_LOG=str(math_path))
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
            assert event['date_input_raw'] == 56064000
            assert event['end_date_raw'] == event['date_raw'] == 56108544
        assert rows[-33]['event'] == observation.NATIVE_GAP
        cases = math_path.read_text().splitlines()
        assert len(cases) == 500
        for line in cases:
            date, adjustment, first, second, supported, result = map(int, line.split(','))
            try:
                expected = direct_truce_expiry(date, adjustment, first, second)['raw']
            except ValueError:
                assert not supported, line
            else:
                assert supported and result == expected, line
