"""The live discovery owner is lazy and separate from saved/recorded modes."""
from tools.serve_information import _build_runtime, build_parser


def test_default_live_factory_owns_one_current_partial_discovery_field(tmp_path, monkeypatch):
    from bridge.information import province_discovery_capture as capture
    from bridge.information.province_discovery import NativeProvinceDiscoverySource

    def forbidden(*args, **kwargs):
        raise AssertionError('factory/catalog must not open the process')

    monkeypatch.setattr(capture, 'capture', forbidden)
    monkeypatch.setattr(capture, '_load_profile', forbidden)
    default_args = build_parser().parse_args(
        ['--observer', 'FRA', '--database', str(tmp_path/'default.sqlite')])
    default_service, default_journal = _build_runtime(default_args)
    try:
        expected_fields = {topic['topic_id']: set(topic['fields'])
                           for topic in default_service.source.catalog()}
    finally:
        default_service.close()
        if default_journal is not None:
            default_journal.close()
    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path/'live.sqlite')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        owners = [x for x in service.source.adapters if isinstance(x, NativeProvinceDiscoverySource)]
        assert len(owners) == 1 and owners[0].base_source is service.source.primary
        topics = service.source.catalog()
        assert len(topics) == len(expected_fields)
        assert {topic['topic_id']: set(topic['fields']) for topic in topics} == expected_fields
        c02 = next(x for x in topics if x['topic_id'] == 'C02')
        field = c02['fields']['discovered_provinces']
        assert field['coverage'] == 'partial' and field['period'] == 'current'
        assert field['complete'] is False
        assert set(field['triggers']) == {'query', 'periodic'}
        assert c02['fields']['discovered_countries']['coverage'] == 'partial'
        assert c02['fields']['related_countries']['coverage'] == 'planned'
    finally:
        service.close()
        if journal is not None:
            journal.close()


def test_recorded_factory_does_not_construct_current_discovery_owner(tmp_path, monkeypatch):
    from bridge.information import province_discovery as source_module

    def forbidden(*args, **kwargs):
        raise AssertionError('recorded mode must not acquire a live observer')

    monkeypatch.setattr(source_module, 'NativeProvinceDiscoverySource', forbidden)
    archive = tmp_path/'recorded.json'
    archive.write_text('{}', encoding='utf-8')
    args = build_parser().parse_args(['--recorded-manifest', str(archive),
                                     '--database', str(tmp_path/'recorded.sqlite')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None and type(service.source).__name__ == 'RecordedSource'
    finally:
        service.close()
