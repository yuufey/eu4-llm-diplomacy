"""N09 keeps one public owner while delegating the v2 province source internally."""


def test_single_n09_owner_has_v2_delegate_without_profile_or_capture(tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import province_modifier_sources_capture as capture
    from bridge.information.final_attributes import NativeFinalAttributesSource
    from bridge.information.province_goods_sources import NativeProvinceGoodsSourceBreakdownSource

    def forbidden(*args, **kwargs):
        raise AssertionError("factory and catalog must not load a profile or capture a process")

    monkeypatch.setattr(capture, "capture", forbidden)
    monkeypatch.setattr(capture, "_load_profile", forbidden)
    default_args = build_parser().parse_args([
        "--observer", "FRA", "--database", str(tmp_path / "default.sqlite"),
    ])
    default_service, default_journal = _build_runtime(default_args)
    try:
        expected_fields = {topic["topic_id"]: set(topic["fields"])
                           for topic in default_service.source.catalog()}
    finally:
        default_service.close()
        if default_journal is not None:
            default_journal.close()
    args = build_parser().parse_args([
        "--observer", "FRA", "--database", str(tmp_path / "factory.sqlite"),
    ])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        owners = [item for item in service.source.adapters
                  if isinstance(item, NativeFinalAttributesSource)]
        assert len(owners) == 1

        delegated = owners[0].province_breakdown_source
        assert isinstance(delegated, NativeProvinceGoodsSourceBreakdownSource)
        assert delegated.projection_version == 2
        assert delegated.base_source is service.source.primary
        assert delegated not in service.source.adapters

        topics = service.source.catalog()
        assert len(topics) == len(expected_fields)
        assert {topic["topic_id"]: set(topic["fields"]) for topic in topics} == expected_fields
        topic = next(item for item in topics if item["topic_id"] == "N09")
        assert set(topic["object_types"]) == {"country", "province"}
        assert topic["visibility"] == "adapter_managed"

        breakdown = topic["fields"]["source_breakdown"]
        assert breakdown["coverage"] == "partial" and breakdown["complete"] is False
        assert set(breakdown["supported_object_types"]) == {"country", "province"}
        assert breakdown["context_scope"] == "adapter_managed"
        assert breakdown["scope_by_object_type"] == {
            "country": "country_scope", "province": "visible_scope",
        }
        assert breakdown["basis_by_object_type"]["province"] == (
            "native_cached_and_reconstructed_province_modifier_sources"
        )

        for name in ("final_value", "modifier_effects"):
            field = topic["fields"][name]
            assert field["supported_object_types"] == ["country"]
            assert field["context_scope"] == "country_scope"

        query = {
            "topic": "N09",
            "object": {"type": "province", "province_id": 187},
            "fields": ["source_breakdown"],
            "parameters": {},
        }
        assert service.source.validate_query(query) == query
    finally:
        service.close()
        if journal is not None:
            journal.close()
