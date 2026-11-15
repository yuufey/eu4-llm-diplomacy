"""R03/F01 date progression checks for a live multi-day observation window."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from bridge.information import country_rivals as rivals_module
from bridge.information import country_rivals_memory as rivals_memory
from bridge.information.country_rivals import NativeCountryRivalsSource
from bridge.information.observation_time import sampled_read
from bridge.information.war_relations import NativeWarRelationsSource
from bridge.tests.test_information_country_rivals_memory import (
    CONTEXT as RIVALS_CONTEXT, CREATION as RIVALS_CREATION,
    _install_capture as _install_rivals_capture, _reader as _rivals_reader,
)
from bridge.tests.test_information_country_scale import (
    make_context as _scale_context, make_query as _scale_query,
    make_source as _make_scale_source,
)
from bridge.tests.test_information_war_relations import (
    Scale as _WarScale, context as _war_context, query as _war_query,
)


def _macro_context(game_date: int, *, session_id: str = 'r03-window-session') -> dict:
    return {
        'status': 'ready', 'complete': True, 'mode': 'live', 'observer': 'FRA',
        'session_id': session_id,
        'game_version': '1.37.4',
        'game_sha256': 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77',
        'game_date': game_date,
    }


def test_war_relations_accepts_forward_upstream_date_only_in_active_scope():
    anchor = _war_context()
    day = 24

    scale = _WarScale()
    scale.current['game_date'] = anchor['game_date']
    scale.mutate = lambda sample: sample.update(game_date=anchor['game_date'] + day)
    query = _war_query()
    with sampled_read(query, anchor):
        result = NativeWarRelationsSource(scale).read(query, anchor)
    assert result['fields']['wars']['status'] == 'known'
    assert result['fields']['wars']['value']
    # The child F01 sample can carry a newer date than R03's final heartbeat.
    assert scale.current['game_date'] < anchor['game_date'] + day

    # The same date change remains strict without a sampling scope.
    stale = _WarScale()
    stale.current['game_date'] = anchor['game_date'] + day
    result = NativeWarRelationsSource(stale).read(query, anchor)
    assert result['fields']['wars']['status'] == 'unavailable'
    assert stale.calls == []


def test_country_scale_allows_forward_context_dates_but_keeps_default_strict(
        tmp_path, monkeypatch):
    anchor = _scale_context()
    query = _scale_query(fields=['development'])
    day = 24

    source, base, *_ = _make_scale_source(
        tmp_path, monkeypatch,
        after_capture=lambda current: current.current.update(
            game_date=anchor['game_date'] + 2 * day))
    base.current['game_date'] = anchor['game_date'] + day
    with sampled_read(query, anchor):
        result = source.read(query, anchor)
    assert result['fields']['development']['status'] == 'known'

    strict_source, strict_base, *_ = _make_scale_source(tmp_path, monkeypatch)
    strict_base.current['game_date'] = anchor['game_date'] + day
    result = strict_source.read(query, anchor)
    assert result['fields']['development']['status'] == 'unavailable'
    assert result['fields']['development']['reason'] == 'COUNTRY_SCALE_CONTEXT_STALE'


def test_country_rivals_keeps_identity_and_monotonic_context_guards(tmp_path, monkeypatch):
    query = {'topic': 'R03', 'object': {'type': 'country', 'country': 'FRA'},
             'fields': ['rivals'], 'parameters': {}}
    report = {'before': {'record': {'fields': {
        'rivals': {'status': 'known', 'value': []},
    }}}}

    class Base:
        def __init__(self, contexts):
            self.contexts = contexts
            self.index = 1
            self.session = SimpleNamespace(directory=tmp_path, record={})

        def context(self):
            item = self.contexts[min(self.index, len(self.contexts) - 1)]
            self.index += 1
            return deepcopy(item)

    monkeypatch.setattr(rivals_module, '_context_reason', lambda _context: None)
    monkeypatch.setattr(rivals_module, '_session_binding',
                        lambda _base: (tmp_path / 'installation.json', 1, None))
    monkeypatch.setattr(rivals_module, 'import_module', lambda *_args: SimpleNamespace(
        validate_capture=lambda *_args: True))

    anchor = _macro_context(100)
    contexts = [anchor, _macro_context(124), _macro_context(148)]
    source = NativeCountryRivalsSource(Base(contexts), capture=lambda *_args, **_kwargs: report)
    with sampled_read(query, anchor):
        result = source.read(query, anchor)
    assert result['fields']['rivals']['status'] == 'known'

    scenarios = [
        ([_macro_context(100), _macro_context(124), _macro_context(124)], False),
        ([_macro_context(100), _macro_context(124), _macro_context(100)], True),
        ([_macro_context(100), _macro_context(100),
          _macro_context(124, session_id='other-session')], True),
    ]
    for context_list, active in scenarios:
        test_source = NativeCountryRivalsSource(
            Base(context_list), capture=lambda *_args, **_kwargs: report)
        if active:
            with sampled_read(query, context_list[0]):
                checked = test_source.read(query, context_list[0])
        else:
            checked = test_source.read(query, context_list[0])
        assert checked['fields']['rivals']['status'] != 'known'


def test_rivals_memory_ignores_only_active_forward_date(monkeypatch):
    query = {'topic': 'R03', 'object': {'type': 'country', 'country': 'FRA'},
             'fields': ['rivals'], 'parameters': {}}
    for mode, active, expected in (('date', True, 'observed'),
                                   ('date', False, 'doublepass_mismatch'),
                                   ('node', True, 'doublepass_mismatch')):
        with monkeypatch.context() as patch:
            _install_rivals_capture(patch, _rivals_reader(mutating=mode))
            if active:
                with sampled_read(query, RIVALS_CONTEXT) as window:
                    report = rivals_memory.capture(Path('synthetic-installation.json'))
                    metadata = window.metadata()
                    valid = (rivals_memory.validate_capture(
                        report, RIVALS_CONTEXT, RIVALS_CREATION) if mode == 'date' else None)
            else:
                report = rivals_memory.capture(Path('synthetic-installation.json'))
                metadata = None
                valid = None
            assert report['status'] == expected
            if mode == 'date' and active:
                assert report['before']['game_date']['value'] == RIVALS_CONTEXT['game_date']
                assert report['after']['game_date']['value'] == RIVALS_CONTEXT['game_date'] + 1
                assert metadata['end_game_date'] == RIVALS_CONTEXT['game_date'] + 1
                assert valid is True
