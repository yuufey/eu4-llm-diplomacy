"""The province source stays behind the single N09 owner and loads lazily."""
from tools.serve_information import _build_runtime, build_parser

def test_single_n09_owner_delegates_province_without_loading_profile(tmp_path, monkeypatch):
    from bridge.information import province_goods_sources_capture as capture
    from bridge.information.final_attributes import NativeFinalAttributesSource
    from bridge.information.province_goods_sources import NativeProvinceGoodsSourceBreakdownSource
    def forbidden(*args, **kwargs):
        raise AssertionError('factory/discovery cannot read a profile or attach')
    monkeypatch.setattr(capture, 'capture', forbidden)
    monkeypatch.setattr(capture, '_load_profile', forbidden)
    default_args=build_parser().parse_args(['--observer','FRA','--database',str(tmp_path/'default.sqlite')])
    default_service,default_journal=_build_runtime(default_args)
    try:
        expected_fields={topic['topic_id']:set(topic['fields'])
                         for topic in default_service.source.catalog()}
    finally:
        default_service.close()
        if default_journal is not None:
            default_journal.close()
    args=build_parser().parse_args(['--observer','FRA','--database',str(tmp_path/'factory.sqlite')])
    service,journal=_build_runtime(args)
    try:
        assert journal is None
        owners=[a for a in service.source.adapters if isinstance(a,NativeFinalAttributesSource)]
        assert len(owners)==1
        delegated=owners[0].province_breakdown_source
        assert isinstance(delegated,NativeProvinceGoodsSourceBreakdownSource)
        assert delegated.base_source is service.source.primary
        assert delegated not in service.source.adapters
        topics=service.source.catalog()
        assert len(topics)==len(expected_fields)
        assert {t['topic_id']:set(t['fields']) for t in topics}==expected_fields
        topic=next(t for t in topics if t['topic_id']=='N09')
        assert set(topic['object_types'])=={'country','province'}
        source=topic['fields']['source_breakdown']
        assert source['coverage']=='partial' and source['complete'] is False
        assert set(source['supported_object_types'])=={'country','province'}
        for field in ('final_value','modifier_effects'):
            assert topic['fields'][field]['supported_object_types']==['country']
        query={'topic':'N09','object':{'type':'province','province_id':187},
            'fields':['source_breakdown'],'parameters':{}}
        assert service.source.validate_query(query)==query
    finally:
        service.close()
        if journal is not None:
            journal.close()
