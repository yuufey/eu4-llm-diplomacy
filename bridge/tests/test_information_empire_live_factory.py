"""The live HRE route must be lazy and isolated from explicit saved sources."""
from copy import deepcopy

from tools.serve_information import _build_runtime, build_parser


def test_unbound_factory_describes_live_hre_without_opening_a_process(tmp_path, monkeypatch):
    from bridge.information import empire_capture

    def forbidden(*args, **kwargs):
        raise AssertionError('unbound discovery must not read a game process')

    monkeypatch.setattr(empire_capture, 'capture', forbidden)
    default_args = build_parser().parse_args(
        ['--observer', 'FRA', '--database', str(tmp_path / 'default.sqlite3')])
    default_service, default_journal = _build_runtime(default_args)
    try:
        expected_fields = {topic['topic_id']: set(topic['fields'])
                           for topic in default_service.source.catalog()}
    finally:
        default_service.close()
        if default_journal is not None:
            default_journal.close()
    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path / 'info.sqlite3')])
    service, journal = _build_runtime(args)
    try:
        topics = service.source.catalog()
        assert journal is None and len(topics) == len(expected_fields)
        assert {topic['topic_id']: set(topic['fields']) for topic in topics} == expected_fields
        topic = next(topic for topic in topics if topic['topic_id'] == 'S01')
        assert topic['source'] == 'CompositeSource'
        assert topic['adapter_sources'] == [
            'NativeEmpireSource', 'NativeEmpirePassedReformsSource']
        assert topic['triggers'] == ['query', 'periodic']
        assert topic['fields']['emperor']['period'] == 'current'
        assert topic['fields']['emperor']['coverage'] == 'partial'
        assert topic['fields']['electors']['coverage'] == 'partial'
        assert topic['fields']['reforms']['coverage'] == 'partial'
        assert topic['fields']['reforms']['source'] == 'NativeEmpirePassedReformsSource'
        assert any(type(adapter).__name__ == 'NativeEmpirePassedReformsSource'
                   for adapter in service.source.adapters)
        result = service.source.read({'topic': 'S01', 'object': {'type': 'session'},
                                      'fields': ['emperor', 'electors', 'reforms']}, service.source.context())
        assert all(result['fields'][name]['status'] == 'unavailable'
                   for name in ('emperor', 'electors', 'reforms'))
    finally:
        service.close()
        if journal is not None:
            journal.close()


def test_saved_empire_factory_never_constructs_live_empire_adapter(tmp_path, monkeypatch):
    from bridge.information import empire_live, empire_snapshot_v2, saved_empire_v2

    def forbidden(*args, **kwargs):
        raise AssertionError('saved source must not acquire the live HRE adapter')

    monkeypatch.setattr(empire_live, 'NativeEmpireSource', forbidden)
    original = saved_empire_v2.SavedEmpireSnapshotV2
    payload = {
        'schema': 'eu4.save_empire_snapshot.v2', 'saved_date': '1456.4.12',
        'saved_version': {'first': 1, 'second': 37, 'third': 4, 'fourth': 0},
        'saved_player': 'POR', 'country_tags': ['FRA', 'POR', 'HAB', 'BOH'],
        'empire': {'emperor': 'HAB', 'electors': ['BOH'], 'passed_reforms': None},
    }
    monkeypatch.setattr(saved_empire_v2, 'SavedEmpireSnapshotV2',
                        lambda path, observer, *, parser_manifest:
                        original(path, observer, parser=lambda _: deepcopy(payload)))
    save = tmp_path / 'historical.eu4'
    save.write_bytes(b'historical HRE test snapshot')
    args = build_parser().parse_args(['--empire-save', str(save), '--observer', 'FRA',
                                     '--database', str(tmp_path / 'info.sqlite3')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert type(service.source) is empire_snapshot_v2.SavedEmpireSourceV2
        context = service.source.context()
        assert context['mode'] == 'recorded' and context['session_id'] is None
        result = service.source.read({'topic': 'S01', 'object': {'type': 'session'},
                                      'fields': ['emperor', 'electors']}, context)
        assert result['fields']['emperor']['value'] == 'HAB'
        assert result['fields']['emperor']['period'] == 'saved_snapshot'
    finally:
        service.close()
