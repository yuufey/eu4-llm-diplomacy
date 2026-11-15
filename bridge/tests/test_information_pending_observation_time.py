"""C03 pending date progression remains scoped to one live query."""
from __future__ import annotations

from copy import deepcopy

from bridge.diplomacy_journal import DurableJournal
from bridge.information import native_pending_memory as native
from bridge.information.observation_time import sampled_read
from bridge.information.pending_matters import JournalPendingMattersSource
from bridge.tests.test_information_pending_matters import (
    EXPERIMENT, SESSION, FakeBase, _context, _query,
)


def _inventory(deadline: int | None = None) -> dict:
    entry = {'entry_id': 'pending-entry-' + 'a' * 32, 'recognition': 'recognized',
             'action_id': 'offer_alliance', 'actor': 'SAV', 'recipient': 'FRA',
             'phase': 'initiate'}
    if deadline is not None:
        entry['deadline'] = {'pending_created_game_date': deadline, 'value': deadline + 72,
                             'unit': 'game_hours', 'scale': 1}
    return {'scope': native.SCOPE, 'native_queue_count': 1,
            'recognized_entry_count': 1, 'unresolved_entry_count': 0,
            'entries': [entry], 'identity_scope': 'native_list_entry_observation',
            'list_traversal_complete': True, 'payload_details_complete': False,
            'response_contexts_available': False}


def _report(first_date: int, second_date: int,
            first_value: dict | None = None, second_value: dict | None = None) -> dict:
    first_value = _inventory() if first_value is None else deepcopy(first_value)
    second_value = deepcopy(first_value) if second_value is None else deepcopy(second_value)
    return {
        'schema': native.SCHEMA, 'status': 'observed', 'country': 'FRA',
        'game_sha256': native.GAME_SHA256, 'profile_sha256': native.PROFILE_SHA256,
        'read_only': True, 'native_function_invoked': False,
        'target_memory_written': False, 'consistent': True,
        'cleanup': {'closed': True},
        'identity': {'binding_verified': True,
                     'installation_session_id': SESSION},
        'before': {'game_date': first_date, 'value': first_value},
        'after': {'game_date': second_date, 'value': second_value},
        'game_date': first_date, 'player_country': 'POR', 'value': first_value,
    }


def _source(tmp_path, contexts, pending_capture):
    journal = DurableJournal(tmp_path / 'journal.sqlite3', EXPERIMENT, SESSION)
    base = FakeBase(journal, contexts=contexts)
    base.diplomacy_tools.session.directory = tmp_path
    source = JournalPendingMattersSource(base, native_pending=True,
                                         pending_capture=pending_capture)
    return source, base, journal


def test_active_c03_scope_accepts_forward_dates_and_records_report_window(tmp_path):
    dates = [56554848, 56554872, 56554896]
    report = _report(56554920, 56554944)
    source, base, journal = _source(
        tmp_path, [_context(game_date=date) for date in dates],
        lambda *_args: deepcopy(report))
    try:
        anchor = base.context()
        query = _query()
        with sampled_read(query, anchor) as window:
            result = source.read(query, anchor)
            metadata = window.metadata()
        field = result['fields']['pending_matters']
        assert field['status'] == 'known'
        assert field['value']['native_inbound_pending']['status'] == 'known'
        assert metadata['start_game_date'] == dates[0]
        assert metadata['end_game_date'] == report['after']['game_date']
        # The final heartbeat may lag behind the last RPM pass.
        assert dates[-1] < report['after']['game_date']
    finally:
        journal.close()


def test_c03_rejects_unscoped_backwards_or_identity_changes(tmp_path):
    scenarios = [
        ('unscoped_forward', [_context(game_date=100), _context(game_date=101),
                              _context(game_date=101)], False,
         'PENDING_CONTEXT_UNAVAILABLE_OR_MISMATCH'),
        ('backwards', [_context(game_date=100), _context(game_date=101),
                       _context(game_date=100)], True, 'PENDING_CONTEXT_CHANGED'),
        ('identity_change', [_context(game_date=100), _context(game_date=100),
                             _context(game_date=101, session_id='other-session')],
         True, 'PENDING_CONTEXT_CHANGED'),
    ]
    for name, contexts, active, expected in scenarios:
        case_dir = tmp_path / name
        case_dir.mkdir()
        source, base, journal = _source(case_dir, contexts,
                                        lambda *_args: _report(101, 102))
        try:
            anchor = base.context()
            query = _query()
            if active:
                with sampled_read(query, anchor):
                    result = source.read(query, anchor)
            else:
                result = source.read(query, anchor)
            assert result['fields']['pending_matters'] == {
                'status': 'unavailable', 'reason': expected,
            }
        finally:
            journal.close()


def test_native_capture_ignores_only_active_monotonic_dates(monkeypatch):
    def run_capture(scenario):
        first_date, second_date = ((101, 100) if scenario == 'backwards'
                                   else (100, 101))
        first_value = _inventory(deadline=200)
        second_value = deepcopy(first_value)
        if scenario == 'deadline_change':
            second_value['entries'][0]['deadline']['value'] += 24
        snapshots = [
            {'game_date': first_date, 'player_country': 'POR', 'value': first_value},
            {'game_date': second_date, 'player_country': 'POR', 'value': second_value},
        ]

        class Kernel:
            def OpenProcess(self, *_args):
                return object()

        query = _query()
        context = _context(game_date=100)
        with monkeypatch.context() as patch:
            patch.setattr(native, 'load_contract', lambda: {})
            patch.setattr(native.memory, '_load_profile', lambda: {})
            patch.setattr(native.memory, '_load_installation',
                          lambda _path: {'pid': 1, 'session_id': SESSION})
            patch.setattr(native.memory, '_configure_kernel', Kernel)
            patch.setattr(native.memory, '_capture_identity', lambda *_args: 0x140000000)
            patch.setattr(native.memory, 'AddressBoundedRPM', lambda *_args: object())
            iterator = iter(snapshots)
            patch.setattr(native, '_snapshot', lambda *_args: deepcopy(next(iterator)))
            patch.setattr(native, 'validate_value',
                          lambda value, _contract=None: deepcopy(value))
            patch.setattr(native.memory, '_close_process_handle',
                          lambda *_args: {'closed': True})
            if scenario == 'strict_forward':
                return native.capture('unused-installation.json')
            with sampled_read(query, context):
                return native.capture('unused-installation.json')

    forward = run_capture('forward')
    assert forward['status'] == 'observed'
    assert forward['before']['game_date'] == 100
    assert forward['after']['game_date'] == 101
    assert forward['game_date'] == 100
    for scenario in ('strict_forward', 'backwards', 'deadline_change'):
        report = run_capture(scenario)
        assert report['status'] == 'unknown'
        assert report['reason'] == 'NATIVE_PENDING_SNAPSHOT_CHANGED'
