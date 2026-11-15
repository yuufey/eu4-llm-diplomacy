"""Exercise the shipping native subsidy capture and its ABI with bounded fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('kind', ['observer', 'entry-plan'])
def test_subsidy_expiry_native(tmp_path, kind, record_testsuite_property):
    compiler = shutil.which('g++')
    assert compiler
    sources = [f'work/native/tests/information-subsidy-expiry-{kind}-test.cpp']
    if kind == 'entry-plan':
        sources.append('work/native/tests/information-subsidy-expiry-entry-plan-abi.S')
    executable = tmp_path / 'subsidy-expiry.exe'
    built = subprocess.run([compiler, '-std=c++17', '-O1', '-Wall', '-Wextra', '-Iwork/native',
                            *sources, '-o', str(executable)], cwd=ROOT, capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=90)
    assert built.returncode == 0, built.stdout + built.stderr
    event_path = tmp_path / 'events.jsonl'
    environment = dict(os.environ, SUBSIDY_EXPIRY_FIXTURE_LOG=str(event_path))
    result = subprocess.run([str(executable)], cwd=ROOT, env=environment, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    record_testsuite_property(kind + '.stdout', result.stdout.strip())
    if kind == 'observer':
        from bridge.subsidy_expiry_observation import public_observation

        rows = [json.loads(line) for line in event_path.read_text().splitlines()]
        assert len(rows) == 66
        events = [row for row in rows if row['event'] == 'native_subsidy_expired']
        assert len(events) == 65
        assert set(events[0]) == {'event', 'session_id', 'sequence', 'date_raw', 'payer_ref',
                                  'recipient_ref', 'observer_ref', 'start_date_raw',
                                  'end_date_raw', 'monthly_amount_raw', 'source', 'wire'}
        assert events[0]['end_date_raw'] == 8860
        assert events[0]['monthly_amount_raw'] == 1250
        decoded = public_observation(events[0], events[0]['session_id'])
        assert decoded is not None
        assert decoded['payload']['payer'] == 'FRA'
        assert decoded['payload']['recipient'] == 'SAV'
        assert rows[-33]['event'] == 'native_subsidy_expiry_capture_gap'
