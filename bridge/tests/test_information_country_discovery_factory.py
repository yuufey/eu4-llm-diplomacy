"""Country/province discovery share a topic with separate lazy owners."""
from tools.serve_information import _build_runtime, build_parser


def test_default_factory_registers_country_owner_without_profile_or_process_reads(tmp_path, monkeypatch):
    from bridge.information import country_discovery_capture as capture
    from bridge.information.country_discovery import NativeCountryDiscoverySource
    from bridge.information.province_discovery import NativeProvinceDiscoverySource

    def forbidden(*args, **kwargs):
        raise AssertionError('factory and catalog must remain read-free')

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
        owners = [x for x in service.source.adapters if isinstance(x, NativeCountryDiscoverySource)]
        assert len(owners) == 1 and owners[0].base_source is service.source.primary
        assert sum(isinstance(x, NativeProvinceDiscoverySource) for x in service.source.adapters) == 1
        # N09 shares the exact N07/N03 owners, preserving their read contracts.
        from bridge.information.country_records import NativeCountryRecordsSource
        from bridge.information.final_attributes import NativeFinalAttributesSource
        from bridge.information.military_quality import NativeMilitaryQualitySource
        final = next(x for x in service.source.adapters if isinstance(x, NativeFinalAttributesSource))
        records = next(x for x in service.source.adapters if isinstance(x, NativeCountryRecordsSource))
        military = next(x for x in service.source.adapters if isinstance(x, NativeMilitaryQualitySource))
        assert final.country_records_source is records and final.military_quality_source is military
        from bridge.information.own_military_modifiers import NativeOwnMilitaryModifiersSource
        own_modifiers = next(x for x in service.source.adapters if type(x) is NativeOwnMilitaryModifiersSource)
        assert own_modifiers.base_source is service.source.primary
        from bridge.information.trade_collection import NativeTradeCollectionSource
        from bridge.information.trade_income import NativeTradeIncomeSource
        collection = next(x for x in service.source.adapters if isinstance(x, NativeTradeCollectionSource))
        income = next(x for x in service.source.adapters if type(x) is NativeTradeIncomeSource)
        assert collection.trade_income_source is income
        topics = service.source.catalog()
        assert len(topics) == len(expected_fields)
        assert {topic['topic_id']: set(topic['fields']) for topic in topics} == expected_fields
        n03 = next(topic for topic in topics if topic['topic_id'] == 'N03')
        assert n03['fields']['military_modifiers']['coverage'] == 'partial'
        assert set(n03['fields']['military_modifiers']['triggers']) == {'query', 'periodic'}
        assert n03['fields']['military_modifiers']['object_types'] == ['country']
        from bridge.information.relations_capacity import NativeRelationsCapacitySource
        capacity = next(x for x in service.source.adapters if type(x) is NativeRelationsCapacitySource)
        assert capacity.base_source is service.source.primary
        from bridge.information.diplomatic_reputation import NativeDiplomaticReputationSource
        from bridge.information.diplomats_total import NativeDiplomatsTotalSource
        reputation = next(x for x in service.source.adapters if type(x) is NativeDiplomaticReputationSource)
        diplomats = next(x for x in service.source.adapters if type(x) is NativeDiplomatsTotalSource)
        assert final.scalar_sources == {'relations_limit': capacity,
            'diplomatic_reputation': reputation, 'diplomats_total': diplomats}
        n05 = next(topic for topic in topics if topic['topic_id'] == 'N05')
        for name in ('relations_count', 'relations_limit'):
            assert n05['fields'][name]['coverage'] == 'partial'
            assert set(n05['fields'][name]['triggers']) == {'query', 'periodic'}
            assert n05['fields'][name]['object_types'] == ['country']
        c02 = next(topic for topic in topics if topic['topic_id'] == 'C02')
        for name in ('discovered_countries', 'discovered_provinces'):
            field = c02['fields'][name]
            assert field['coverage'] == 'partial' and field['complete'] is False
            assert field['period'] == 'current' and set(field['triggers']) == {'query', 'periodic'}
        assert c02['fields']['related_countries']['coverage'] == 'planned'
        t02 = next(topic for topic in topics if topic['topic_id'] == 'T02')
        assert t02['fields']['collect_node']['coverage'] == 'partial'
        assert set(t02['fields']['collect_node']['triggers']) == {'query', 'periodic'}
        assert t02['fields']['collect_node']['object_types'] == ['country']
        from bridge.information.province_permanent_claims import NativeProvincePermanentClaimsSource
        permanent = next(x for x in service.source.adapters if type(x) is NativeProvincePermanentClaimsSource)
        assert permanent.base_source is service.source.primary
        g01 = next(topic for topic in topics if topic['topic_id'] == 'G01')
        assert g01['fields']['permanent_claims']['coverage'] == 'partial'
        assert set(g01['fields']['permanent_claims']['triggers']) == {'query', 'periodic'}
        n09 = next(topic for topic in topics if topic['topic_id'] == 'N09')
        assert n09['fields']['modifier_effects']['coverage'] == 'partial'
        c03 = next(topic for topic in topics if topic['topic_id'] == 'C03')
        assert c03['fields']['pending_matters']['coverage'] == 'partial'
        assert c03['fields']['strategic_goals']['coverage'] == 'planned'
    finally:
        service.close()
        if journal is not None:
            journal.close()


def test_recorded_factory_never_constructs_country_live_owner(tmp_path, monkeypatch):
    from bridge.information import country_discovery as source_module

    def forbidden(*args, **kwargs):
        raise AssertionError('recorded mode must not acquire live country discovery')

    monkeypatch.setattr(source_module, 'NativeCountryDiscoverySource', forbidden)
    archive = tmp_path/'recorded.json'; archive.write_text('{}', encoding='utf-8')
    args = build_parser().parse_args(['--recorded-manifest', str(archive),
                                     '--database', str(tmp_path/'recorded.sqlite')])
    service, _ = _build_runtime(args)
    try:
        assert type(service.source).__name__ == 'RecordedSource'
    finally:
        service.close()


def test_declared_context_factory_is_lazy_and_combines_field_owners(tmp_path):
    # A missing operator file must not be read just to construct/discover.
    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path/'inputs.sqlite'),
                                     '--decision-context', str(tmp_path/'not-written.json')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        topic = next(t for t in service.source.catalog() if t['topic_id'] == 'C03')
        assert set(topic['fields']) == {'strategic_goals', 'diplomatic_constraints', 'pending_matters'}
        assert all(field['coverage'] == 'partial' for field in topic['fields'].values())
        assert set(topic['adapter_sources']) == {'DecisionContextInputsSource', 'JournalPendingMattersSource'}
        assert 'source_kind' not in topic
        assert topic['fields']['strategic_goals']['source_kind'] == 'operator_input'
    finally:
        service.close()


def test_n05_capacity_and_diplomat_owners_share_reference_selector_without_reads(tmp_path):
    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path/'n05.sqlite')])
    service, _ = _build_runtime(args)
    try:
        query = {'topic': 'N05', 'object': {'type': 'country', 'country': 'FRA'},
                 'fields': ['relations_count', 'relations_limit', 'diplomat_tasks', 'diplomats_available'],
                 'parameters': {'reference_recipient': 'PAP'}}
        normalized = service.source.validate_query(query)
        assert normalized == query
        own_only = dict(query, fields=['relations_count', 'relations_limit'], parameters={})
        assert service.source.validate_query(own_only) == own_only
    finally:
        service.close()
