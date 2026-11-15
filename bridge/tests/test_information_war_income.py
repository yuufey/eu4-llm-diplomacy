"""N01 war receipts reuse one validated monthly capture and its context guard."""
import pytest

from bridge.information import monthly_economy_memory
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.tests import test_information_monthly_economy as fixtures


def record(amounts=(1000, 2000, 3000, 4000)):
    payload = bytearray(228)
    # Tax and expense values make the existing recurring aggregation distinct
    # from the four-component projection. All amounts are literal milli-ducats.
    payload[:4] = (10_000).to_bytes(4, "little", signed=True)
    payload[76:80] = (500).to_bytes(4, "little", signed=True)
    for index, value in zip((8, 12, 17, 18), amounts):
        payload[index * 4:index * 4 + 4] = value.to_bytes(4, "little", signed=True)

    class Reader:
        def read(self, address, size, label):
            if address == fixtures.COUNTRY_POINTER + 0x770 and size == 228:
                return bytes(payload)
            for _, rva, expected in monthly_economy_memory._profile_code_guards(
                    monthly_economy_memory._active_profile()):
                if address == fixtures.MODULE_BASE + rva:
                    return expected[:size]
            raise AssertionError((address, size, label))

    result = monthly_economy_memory.read_fields(
        Reader(), fixtures.MODULE_BASE, fixtures.COUNTRY_POINTER)
    assert result["status"] == "observed"
    return result


def source(tmp_path, *, amounts=(1000, 2000, 3000, 4000), after=None, mutate=None):
    calls = []
    leaf = record(amounts)

    def capture(installation, actor, **kwargs):
        calls.append((installation, actor, kwargs))
        return fixtures._report(session, leaf, mutate=mutate)

    adapter, session, tools = fixtures._source(tmp_path, capture=capture, after=after)
    return adapter, session, tools, calls


def query(fields=("war_income",), parameters=None):
    return fixtures._query(list(fields), parameters)


def assert_no_capture_memory(value):
    forbidden = {"raw_ledger_hex", "income_slots", "expense_slots", "observation",
                 "module_base", "country_pointer", "runtime_code_guard", "raw_payload_hex"}
    if isinstance(value, dict):
        assert not (set(value) & forbidden)
        for item in value.values():
            assert_no_capture_memory(item)
    elif isinstance(value, list):
        for item in value:
            assert_no_capture_memory(item)


def test_catalog_marks_only_the_war_component_scope_partial(tmp_path):
    adapter, _, _, calls = source(tmp_path)
    topic = next(t for t in adapter.catalog() if t["topic_id"] == "N01")
    metadata = topic["fields"]["war_income"]
    assert metadata["coverage"] == "partial"
    assert metadata["complete"] is False
    assert metadata["reference_period"] == "previous_month"
    assert topic["fields"]["treasury"]["coverage"] == "available"
    assert calls == []


def test_war_only_has_no_pair_probe_and_exposes_literal_receipts(tmp_path):
    adapter, _, tools, calls = source(tmp_path)
    result = adapter.read(query())
    field = result["fields"]["war_income"]
    assert field["status"] == "known", field
    assert field["complete"] is False
    assert len(calls) == 1
    assert calls[0][1:] == ("FRA", {"include_monthly_economy": True})
    assert tools.inspect_calls == []
    components = field["value"]["components"]
    assert {key: item["raw"] for key, item in components.items()} == {
        "war_reparations": 1000, "spoils_of_war": 2000,
        "blockades": 3000, "looting": 4000,
    }
    assert field["value"]["observed_components_subtotal"]["raw"] == 10_000
    assert field["value"]["total_war_income"]["status"] == "unknown"


def test_mixed_monthly_fields_share_capture_and_keep_their_old_semantics(tmp_path):
    adapter, _, tools, calls = source(tmp_path)
    result = adapter.read(query(("war_income", "monthly_income", "monthly_balance")))
    assert len(calls) == 1
    assert tools.inspect_calls == []
    # Only the 1-ducat reparation component belongs to the recurring total.
    assert result["fields"]["monthly_income"]["raw"] == 11_000
    assert result["fields"]["monthly_balance"]["raw"] == 10_500
    assert result["fields"]["war_income"]["value"]["observed_components_subtotal"]["raw"] == 10_000


def test_zero_components_are_known_without_claiming_no_war_income(tmp_path):
    adapter, _, _, _ = source(tmp_path, amounts=(0, 0, 0, 0))
    field = adapter.read(query())["fields"]["war_income"]
    assert field["status"] == "known"
    assert field["value"]["observed_components_subtotal"]["raw"] == 0
    assert field["value"]["total_war_income"]["status"] == "unknown"


@pytest.mark.parametrize("fields", [("war_income",), ("war_income", "monthly_income")])
def test_new_war_queries_do_not_disclose_capture_memory_through_provenance(tmp_path, fields):
    adapter, _, _, _ = source(tmp_path)
    result = adapter.read(query(fields))
    assert_no_capture_memory(result)
    summary = result["source"]["provenance"]["monthly_economy"]
    assert summary["raw_record_disclosed"] is False
    assert len(summary["private_provenance_sha256"]) == 64


def test_invalid_parent_also_omits_raw_inputs_from_public_metadata(tmp_path):
    adapter, _, _, _ = source(tmp_path, mutate={"doublepass": {"consistent": False}})
    result = adapter.read(query())
    assert result["fields"]["war_income"]["status"] == "unknown"
    assert_no_capture_memory(result)


@pytest.mark.parametrize('parameters', [{}, {'reference_recipient': 'PAP'}])
def test_treasury_mixed_query_preserves_independent_fields_with_optional_pair_hint(tmp_path, parameters):
    adapter, _, tools, calls = source(tmp_path)
    request = query(("treasury", "war_income"), parameters)
    assert adapter.validate_query(request) == request
    assert not tools.inspect_calls and not calls
    result = adapter.read(request)
    if parameters:
        assert result["fields"]["treasury"]["value"] == 1234
        assert tools.inspect_calls == [
            ("send_gift", "FRA", "PAP", "initiate", {"ducats": 25})]
    else:
        assert result["fields"]["treasury"] == {
            "status": "unavailable", "reason": "COUNTRY_RESOURCE_CACHE_UNAVAILABLE"}
        assert tools.inspect_calls == []
    assert result["fields"]["war_income"]["status"] == "known"
    assert len(calls) == 1


def test_context_change_retracts_war_components_after_capture(tmp_path):
    adapter, _, tools, calls = source(tmp_path, after={"date_raw": fixtures.GAME_DATE + 24})
    field = adapter.read(query())["fields"]["war_income"]
    assert field["status"] in {"unknown", "unavailable"}
    assert "value" not in field
    assert len(calls) == 1
    assert not tools.inspect_calls


def test_parent_doublepass_failure_never_publishes_components(tmp_path):
    adapter, _, _, _ = source(tmp_path, mutate={"doublepass": {"consistent": False}})
    field = adapter.read(query())["fields"]["war_income"]
    assert field["status"] == "unknown"
    assert "value" not in field


def test_no_foreign_country_rebinding_or_capture(tmp_path):
    adapter, _, tools, calls = source(tmp_path)
    request = query()
    request["object"]["country"] = "ENG"
    with pytest.raises(InformationError):
        adapter.read(request)
    assert not calls and not tools.inspect_calls


def test_composite_and_report_keep_the_same_war_projection(tmp_path):
    adapter, _, tools, calls = source(tmp_path)
    service = InformationService(CompositeSource(adapter), tmp_path / "war-income.sqlite")
    try:
        result = service.query("war-income-direct", queries=[query()])
        report = service.manage_report(
            "war-income-report", "create",
            config={"name": "war receipts", "queries": [query()]},
        )["report"]
        from_report = service.query("war-income-from-report", report_id=report["id"])
        direct_field = result["items"][0]["fields"]["war_income"]
        report_field = from_report["items"][0]["fields"]["war_income"]
        assert direct_field["status"] == "known"
        assert direct_field == report_field
        assert len(calls) == 2
        assert not tools.inspect_calls
    finally:
        service.close()
