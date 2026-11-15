from tools.serve_information import _build_runtime, build_parser


def test_default_live_factory_registers_only_current_opinion(tmp_path, monkeypatch):
    from bridge.information import opinion_capture
    def forbidden(*args, **kwargs):
        raise AssertionError('catalog construction must not capture game memory')
    monkeypatch.setattr(opinion_capture, 'capture', forbidden)
    args = build_parser().parse_args([
        '--observer','FRA','--database',str(tmp_path/'information.sqlite3')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        topic = next(row for row in service.source.catalog() if row['topic_id'] == 'R04')
        assert topic['fields']['opinion']['coverage'] == 'partial'
        assert topic['fields']['opinion_modifiers']['coverage'] == 'partial'
        assert topic['fields']['decay']['coverage'] == 'partial'
        assert topic['fields']['end_date']['coverage'] == 'partial'
        assert {'query','periodic'} <= set(topic['triggers'])
        assert topic['fields']['opinion_modifiers']['triggers'] == ['query','periodic']
    finally:
        service.close()


def test_numeric_change_scope_survives_four_r04_owners(tmp_path):
    from bridge.information.composite import CompositeSource
    from bridge.information.opinion_modifiers import NativeOpinionModifiersSource
    from bridge.tests.test_information_opinion import _source, _query
    numeric,primary,_harness = _source(tmp_path)
    def forbidden(*args,**kwargs):
        raise AssertionError('unrequested record fields must not be collected')
    records = NativeOpinionModifiersSource(primary,capture=forbidden,validator=lambda *args:False)
    from bridge.information.opinion_decay import NativeOpinionDecaySource
    decay = NativeOpinionDecaySource(primary,capture=forbidden,validator=lambda *args:False)
    from bridge.information.opinion_end_dates import NativeOpinionEndDatesSource
    dates = NativeOpinionEndDatesSource(primary,capture=forbidden,validator=lambda *args:False)
    combined = CompositeSource(primary,[numeric,records,decay,dates])
    query = _query()
    context = combined.context()
    sample = combined.read(query,context)
    assert sample['fields']['opinion']['status'] == 'known'
    assert combined.change_comparison(query,sample,context) is not None
