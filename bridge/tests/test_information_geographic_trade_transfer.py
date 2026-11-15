from copy import deepcopy

import pytest

from bridge.information.catalog import get_topic, validate_query as validate_catalog_query
from bridge.information.composite import CompositeSource
from bridge.information.geographic_trade_transfer import GeographicTradeTransferSource
from bridge.information.model import InformationError


NODE = "english_channel"
SESSION = "geo-182"


def live_context(**overrides):
    value = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "dll_sha256": "d" * 64,
        "session_id": SESSION,
        "game_date": 56560344,
        "world_id": "world-182",
    }
    value.update(overrides)
    return value


def static_context(**overrides):
    value = {
        "status": "ready",
        "mode": "static",
        "context_scope": "static_rules",
        "complete": True,
        "game_version": "1.37.4",
        "configuration_sha256": "a" * 64,
        "definitions_sha256": "b" * 64,
        "session_id": None,
        "observer": None,
        "game_date": None,
        "world_id": None,
    }
    value.update(overrides)
    return value


def transfer_value(node_id=NODE):
    return {
        "node_id": node_id,
        "to": {
            "status": "known",
            "items": [
                {"country": "ENG", "raw": 1250},
                {"country": "FRA", "raw": -275},
            ],
        },
        "from": {"status": "empty", "items": []},
    }


def transfer_result(context, *, field=None, node_id=NODE):
    field = field or {
        "status": "known",
        "value": transfer_value(node_id),
        "unit": "trade_power",
        "scale": 1000,
        "complete": False,
    }
    return {
        "topic": "T05",
        "fields": {"transfer": deepcopy(field)},
        "source": {
            "name": "FakeNativeTradeTransferSource",
            "mode": "live",
            "status": "observed",
            "observer": "FRA",
            "session_id": context["session_id"],
            "complete": False,
        },
        "complete": False,
        "game_date": context["game_date"],
        "objects": [{"type": "trade_node", "node_id": node_id}],
    }


class FakePrimary:
    def __init__(self, context=None):
        self._context = deepcopy(context or live_context())

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return [get_topic("G04")]


class FakeTransfers:
    def __init__(self, context=None, result=None):
        self._context = deepcopy(context or live_context())
        self.result = deepcopy(result or transfer_result(self._context))
        self.read_calls = []
        self.validate_calls = []

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        item = get_topic("T05")
        item["supported_versions"] = ["1.37.4"]
        item["triggers"] = ["query"]
        return [item]

    def validate_query(self, query, context=None):
        self.validate_calls.append(deepcopy(query))
        return validate_catalog_query(query, context)

    def read(self, query, context=None):
        self.read_calls.append((deepcopy(query), deepcopy(context)))
        return deepcopy(self.result)


class FakeStaticTrade:
    def __init__(self, field, contexts=None):
        self.field = deepcopy(field)
        self._contexts = [deepcopy(item) for item in (contexts or [static_context()])]
        self.context_calls = 0
        self.read_calls = []
        self.validate_calls = []

    def context(self):
        self.context_calls += 1
        if len(self._contexts) > 1:
            return deepcopy(self._contexts.pop(0))
        return deepcopy(self._contexts[0])

    def catalog(self):
        item = get_topic("G04")
        item.update(
            status="available",
            source=type(self).__name__,
            context_scope="static_rules",
            supported_versions=["1.37.4"],
            fields={"trade_node": {"coverage": "available", "complete": False}},
        )
        item["object_types"] = ["province", "trade_node"]
        return [item]

    def validate_query(self, query, context=None):
        self.validate_calls.append(deepcopy(query))
        return validate_catalog_query(query, context)

    def read(self, query, context=None):
        self.read_calls.append((deepcopy(query), deepcopy(context)))
        current = context or static_context()
        return {
            "topic": "G04",
            "fields": {"trade_node": deepcopy(self.field)},
            "source": {
                "name": type(self).__name__,
                "mode": "static",
                "status": "observed" if self.field.get("status") == "known" else "unavailable",
                "context_scope": "static_rules",
                "complete": False,
            },
            "complete": False,
            "game_date": current.get("game_date"),
            "objects": [deepcopy(query["object"])],
        }


class FakeMembershipAdapter:
    """A small G04 owner used only to exercise CompositeSource routing."""

    def catalog(self):
        item = get_topic("G04")
        item.update(
            status="available",
            source=type(self).__name__,
            context_scope="static_rules",
            supported_versions=["1.37.4"],
            parameters={
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": False,
            },
            fields={"trade_node": {"coverage": "available", "complete": False}},
        )
        item["object_types"] = ["province", "trade_node"]
        return [item]

    def validate_query(self, query, context=None):
        return validate_catalog_query(query, context)

    def read(self, query, context=None):
        return {
            "topic": "G04",
            "fields": {"trade_node": {"status": "known", "value": NODE}},
            "source": {
                "name": type(self).__name__, "mode": "static", "status": "observed",
                "context_scope": "static_rules", "complete": False,
            },
            "complete": False,
            "game_date": (context or {}).get("game_date"),
            "objects": [deepcopy(query["object"])],
        }


def make_source(*, transfers=None, static_trade=None, context=None):
    current = deepcopy(context or live_context())
    return GeographicTradeTransferSource(
        FakePrimary(current), transfers or FakeTransfers(current), static_trade,
    )


def node_query(node_id=NODE):
    return {
        "topic": "G04",
        "object": {"type": "trade_node", "node_id": node_id},
        "fields": ["transfer_relations"],
        "parameters": {},
    }


def province_query(province_id=1298):
    return {
        "topic": "G04",
        "object": {"type": "province", "province_id": province_id},
        "fields": ["transfer_relations"],
        "parameters": {},
    }


def test_trade_node_delegates_once_and_preserves_signed_and_known_empty_rows():
    context = live_context()
    transfers = FakeTransfers(context)
    source = make_source(transfers=transfers, context=context)
    query = node_query()
    query_before = deepcopy(query)
    upstream_before = deepcopy(transfers.result)

    result = source.read(query, context)

    field = result["fields"]["transfer_relations"]
    assert len(transfers.read_calls) == 1
    assert len(transfers.validate_calls) == 1
    assert field["status"] == "known"
    assert field["value"]["node_id"] == NODE
    assert field["value"]["to"] == upstream_before["fields"]["transfer"]["value"]["to"]
    assert field["value"]["to"]["items"][1]["raw"] == -275
    assert field["value"]["from"] == {"status": "empty", "items": []}
    assert field["value"]["selection"] == {
        "basis": "explicit_trade_node", "loaded_membership_verified": None,
        "node_id": NODE,
    }
    assert query == query_before
    assert transfers.result == upstream_before

    field["value"]["to"]["items"][0]["raw"] = 999999
    assert transfers.result == upstream_before


def test_province_uses_unique_static_node_once_and_exposes_disk_selection():
    context = live_context()
    transfers = FakeTransfers(context)
    static = FakeStaticTrade({"status": "known", "value": NODE})
    source = make_source(transfers=transfers, static_trade=static, context=context)

    result = source.read(province_query(), context)

    field = result["fields"]["transfer_relations"]
    selection = field["value"]["selection"]
    assert len(static.read_calls) == 1
    assert len(transfers.read_calls) == 1
    assert selection["basis"] == "effective_disk_trade_definition"
    assert selection["province_id"] == 1298
    assert selection["node_id"] == NODE
    assert selection["loaded_membership_verified"] is False
    assert field["value"]["relation_scope"] == "observer_trade_node_transfer_cache"
    assert result["source"]["provenance"]["static_selection_source"]["context_scope"] == "static_rules"


@pytest.mark.parametrize(
    ("field", "expected_status", "expected_reason"),
    [
        ({"status": "unknown", "reason": "AMBIGUOUS_PROVINCE_TRADE_NODE"},
         "unknown", "AMBIGUOUS_PROVINCE_TRADE_NODE"),
        ({"status": "unavailable", "reason": "STATIC_SOURCE_UNREADY"},
         "unavailable", "STATIC_SOURCE_UNREADY"),
    ],
)
def test_static_unknown_or_ambiguous_never_calls_native_transfer(
    field, expected_status, expected_reason,
):
    context = live_context()
    transfers = FakeTransfers(context)
    static = FakeStaticTrade(field)
    source = make_source(transfers=transfers, static_trade=static, context=context)

    result = source.read(province_query(), context)

    projected = result["fields"]["transfer_relations"]
    assert projected["status"] == expected_status
    assert projected["reason"] == expected_reason
    assert len(static.read_calls) == 1
    assert transfers.read_calls == []


def test_static_fingerprint_change_retracts_after_native_transfer():
    context = live_context()
    changed = static_context(configuration_sha256="c" * 64)
    static = FakeStaticTrade(
        {"status": "known", "value": NODE},
        contexts=[static_context(), changed],
    )
    transfers = FakeTransfers(context)
    source = make_source(transfers=transfers, static_trade=static, context=context)

    result = source.read(province_query(), context)

    field = result["fields"]["transfer_relations"]
    assert static.context_calls == 2
    assert len(transfers.read_calls) == 1
    assert field["status"] == "unavailable"
    assert field["reason"] == "GEOGRAPHIC_TRADE_STATIC_CONTEXT_CHANGED"
    assert "value" not in field


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("unknown", "T05_UPSTREAM_UNKNOWN"),
        ("unavailable", "T05_UPSTREAM_UNAVAILABLE"),
    ],
)
def test_upstream_status_and_reason_are_preserved(status, reason):
    context = live_context()
    transfers = FakeTransfers(
        context,
        result=transfer_result(context, field={"status": status, "reason": reason}),
    )
    source = make_source(transfers=transfers, context=context)

    field = source.read(node_query(), context)["fields"]["transfer_relations"]

    assert field["status"] == status
    assert field["reason"] == reason
    assert len(transfers.read_calls) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result["fields"]["transfer"]["value"].update(node_id="wrong_node"),
        lambda result: result["fields"]["transfer"].update(unit="ducats"),
        lambda result: result["fields"]["transfer"].update(scale=1),
        lambda result: result["fields"]["transfer"].update(complete=True),
        lambda result: result["fields"]["transfer"]["value"].update(to=None),
    ],
)
def test_invalid_node_unit_scale_or_shape_never_becomes_known(mutate):
    context = live_context()
    upstream = transfer_result(context)
    mutate(upstream)
    transfers = FakeTransfers(context, result=upstream)
    source = make_source(transfers=transfers, context=context)

    field = source.read(node_query(), context)["fields"]["transfer_relations"]

    assert field["status"] == "unknown"
    assert field["reason"] == "GEOGRAPHIC_TRADE_TRANSFER_RESULT_INVALID"
    assert len(transfers.read_calls) == 1


@pytest.mark.parametrize(
    ("result_context", "result_date"),
    [("other-session", 56560344), (SESSION, 56560345)],
)
def test_date_or_session_mismatch_never_becomes_known(result_context, result_date):
    context = live_context()
    upstream = transfer_result(context)
    upstream["source"]["session_id"] = result_context
    upstream["game_date"] = result_date
    transfers = FakeTransfers(context, result=upstream)
    source = make_source(transfers=transfers, context=context)

    field = source.read(node_query(), context)["fields"]["transfer_relations"]

    assert field["status"] == "unavailable"
    assert field["reason"] == "GEOGRAPHIC_TRADE_TRANSFER_CONTEXT_MISMATCH"


def test_invalid_selector_strict_contract_and_province_without_static_is_rejected():
    context = live_context()
    transfers = FakeTransfers(context)
    source = make_source(transfers=transfers, context=context)

    with pytest.raises(InformationError) as province_error:
        source.validate_query(province_query(), context)
    assert province_error.value.code == "invalid_object"

    with pytest.raises(InformationError) as field_error:
        source.validate_query({**node_query(), "fields": ["trade_node"]}, context)
    assert field_error.value.code == "invalid_fields"

    with pytest.raises(InformationError) as parameter_error:
        source.validate_query({**node_query(), "parameters": {"unexpected": True}}, context)
    assert parameter_error.value.code == "invalid_parameters"

    result = source.read(node_query("Null"), context)
    assert result["fields"]["transfer_relations"] == {
        "status": "unknown",
        "partial": True,
        "complete": False,
        "period": "current",
        "basis": "existing_T05_transfer_for_selected_geographic_node",
        "reason": "GEOGRAPHIC_TRADE_NODE_INVALID",
    }
    assert transfers.read_calls == []


def test_catalog_and_composite_route_g04_fields_with_identical_empty_parameters():
    context = live_context()
    transfers = FakeTransfers(context)
    geographic = make_source(transfers=transfers, context=context)
    composite = CompositeSource(FakePrimary(context), [
        FakeMembershipAdapter(), geographic,
    ])
    query = {
        "topic": "G04",
        "object": {"type": "trade_node", "node_id": NODE},
        "fields": ["trade_node", "transfer_relations"],
        "parameters": {},
    }

    catalog = composite.catalog()
    topic = next(item for item in catalog if item["topic_id"] == "G04")
    assert {"trade_node", "transfer_relations"}.issubset(topic["fields"])
    assert topic["parameters"]["additionalProperties"] is False
    assert "trade_node" in topic["object_types"]

    normalized = composite.validate_query(query)
    result = composite.read(normalized, context)

    assert normalized == query
    assert result["fields"]["trade_node"] == {"status": "known", "value": NODE}
    assert result["fields"]["transfer_relations"]["status"] == "known"
    assert len(transfers.read_calls) == 1
    assert len(result["source"]["sources"]) == 2
