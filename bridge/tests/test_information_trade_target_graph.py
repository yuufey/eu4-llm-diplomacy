"""Focused contract tests for the static T06 target graph projection."""

from __future__ import annotations

from copy import deepcopy

from bridge.information.trade_target_graph import TradeTargetGraphReader
from bridge.information.static_data import StaticTradeSource


def _context(**changes):
    value = {
        "status": "ready",
        "mode": "static",
        "context_scope": "static_rules",
        "session_id": "session-targets-1",
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": "c" * 64,
        "game_date": 1456,
        "game_day": 600000,
        "world_id": "world-1",
        "paused": True,
        "configuration_sha256": "b" * 64,
        "config_sha256": "b" * 64,
        "definitions_sha256": "a" * 64,
        "trade_definitions_sha256": "a" * 64,
        "trade_directory_members": [
            {"path": "common/tradenodes", "exists": True, "members": ["00_fixture.txt"]}
        ],
        "definition_files": [
            {"relative": "common/tradenodes/00_fixture.txt", "sha256": "d" * 64}
        ],
        "configuration_files": [],
        "enabled_mods": [],
    }
    value.update(changes)
    return value


def _source(context=None, **changes):
    context = context or _context()
    value = {
        "name": "StaticTradeSource",
        "mode": "static",
        "status": "observed",
        "session_id": context["session_id"],
        "observer": context["observer"],
        "complete": True,
        "game_version": context["game_version"],
        "definitions_sha256": context["definitions_sha256"],
        "configuration_sha256": context["configuration_sha256"],
        "provenance": {
            "game_version": context["game_version"],
            "game_sha256": context["game_sha256"],
            "config_sha256": context["configuration_sha256"],
            "definitions_sha256": context["definitions_sha256"],
            "definition_files": deepcopy(context["definition_files"]),
            "configuration_files": deepcopy(context["configuration_files"]),
            "trade_directory_members": deepcopy(context["trade_directory_members"]),
            "enabled_mods": deepcopy(context["enabled_mods"]),
        },
    }
    value.update(changes)
    return value


def _result(fields, *, context=None, source=None, objects=None):
    context = context or _context()
    return {
        "topic": "T01",
        "fields": {
            name: {"status": "known", "value": deepcopy(value)}
            if not isinstance(value, dict) or "status" not in value
            else deepcopy(value)
            for name, value in fields.items()
        },
        "source": deepcopy(source or _source(context)),
        "complete": True,
        "objects": objects if objects is not None else [{"type": "trade_node", "node_id": "alpha"}],
    }


class _FakeStaticTrade:
    def __init__(self, result, *, contexts=None):
        self.result = deepcopy(result)
        self.contexts = deepcopy(contexts or [_context()])
        self.context_calls = 0
        self.read_calls = []

    def context(self):
        index = min(self.context_calls, len(self.contexts) - 1)
        self.context_calls += 1
        return deepcopy(self.contexts[index])

    def read(self, query, context=None):
        self.read_calls.append((deepcopy(query), deepcopy(context)))
        return deepcopy(self.result)


def _valid_fields():
    return {
        "provinces": [3, 1, 65535],
        "routes": [
            {
                "source": "alpha",
                "target": "beta",
                "path": [1, "sea_ref", 2.5],
                "control": [3, 4],
            }
        ],
        "upstream": ["gamma"],
        "downstream": ["beta"],
    }


def test_member_rows_keep_order_and_routes_remain_opaque_topology():
    context = _context()
    source = _source(context)
    fake = _FakeStaticTrade(_result(_valid_fields(), context=context, source=source))
    reader = TradeTargetGraphReader(fake)

    result = reader.read("alpha", context)

    assert result["status"] == "known"
    assert result["rows"] == [
        {"province_id": 3, "membership_kind": "member", "node_id": "alpha"},
        {"province_id": 1, "membership_kind": "member", "node_id": "alpha"},
        {"province_id": 65535, "membership_kind": "member", "node_id": "alpha"},
    ]
    assert result["topology"]["routes"] == _valid_fields()["routes"]
    assert result["topology"]["route_path_semantics"] == (
        "configuration_path_not_territorial_target_classification"
    )
    assert result["source"] == source
    assert result["complete"] is False
    assert result["game_fact"] is False
    assert len(fake.read_calls) == 1
    assert fake.read_calls[0][0] == {
        "topic": "T01",
        "object": {"type": "trade_node", "node_id": "alpha"},
        "fields": ["provinces", "routes", "upstream", "downstream"],
        "parameters": {},
    }


def test_known_empty_members_is_not_rewritten_to_unknown():
    context = _context()
    fields = {"provinces": [], "routes": [], "upstream": [], "downstream": []}
    fake = _FakeStaticTrade(_result(fields, context=context))

    result = TradeTargetGraphReader(fake).read("alpha", context)

    assert result["status"] == "known"
    assert result["rows"] == []
    assert result["topology"]["routes"] == []


def test_invalid_node_does_not_call_static_reader_and_failures_have_no_fake_rows():
    fake = _FakeStaticTrade(_result(_valid_fields()))
    reader = TradeTargetGraphReader(fake)

    invalid = reader.read("bad node")
    assert invalid["status"] == "unknown"
    assert invalid["reason"] == "TRADE_TARGET_NODE_ID_INVALID"
    assert "rows" not in invalid
    assert fake.read_calls == []

    duplicate = _FakeStaticTrade(_result({**_valid_fields(), "provinces": [1, 1]}))
    duplicate_result = TradeTargetGraphReader(duplicate).read("alpha")
    assert duplicate_result["status"] == "unknown"
    assert duplicate_result["reason"] == "TRADE_TARGET_MEMBER_DUPLICATE"
    assert "rows" not in duplicate_result


def test_unknown_node_and_malformed_route_are_explicit_not_empty_known():
    context = _context()
    unknown_fields = {
        name: {"status": "unknown", "reason": "NODE_NOT_FOUND"}
        for name in ("provinces", "routes", "upstream", "downstream")
    }
    fake = _FakeStaticTrade(_result(
        unknown_fields,
        context=context,
        objects=[{"type": "trade_node", "node_id": "missing"}],
    ))
    unknown = TradeTargetGraphReader(fake).read("missing", context)
    assert unknown["status"] == "unknown"
    assert unknown["reason"] == "NODE_NOT_FOUND"
    assert "rows" not in unknown
    assert fake.read_calls[0][0]["object"] == {"type": "trade_node", "node_id": "missing"}

    malformed_fields = {**_valid_fields(), "routes": [{
        "source": "alpha", "target": "beta", "path": [{"not": "scalar"}], "control": []
    }]}
    malformed = _FakeStaticTrade(_result(malformed_fields, context=context))
    malformed_result = TradeTargetGraphReader(malformed).read("alpha", context)
    assert malformed_result["status"] == "unknown"
    assert malformed_result["reason"] == "TRADE_TARGET_ROUTE_PATH_VALUE_INVALID"
    assert "rows" not in malformed_result


def test_member_limit_and_context_identity_gate():
    context = _context()
    over_limit = _valid_fields()
    over_limit["provinces"] = list(range(1, 4098))
    fake = _FakeStaticTrade(_result(over_limit, context=context))
    result = TradeTargetGraphReader(fake).read("alpha", context)
    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_MEMBER_LIST_OVER_LIMIT"
    assert "rows" not in result

    mismatched = _context(game_sha256="e" * 64)
    gated = _FakeStaticTrade(_result(_valid_fields(), context=context))
    gated_result = TradeTargetGraphReader(gated).read("alpha", mismatched)
    assert gated_result["status"] == "unavailable"
    assert gated_result["reason"] == "TRADE_TARGET_CONTEXT_IDENTITY_MISMATCH"
    assert gated.read_calls == []


def test_static_hash_or_directory_drift_after_public_read_withdraws_result():
    before = _context()
    after = _context(definitions_sha256="f" * 64, trade_definitions_sha256="f" * 64)
    source = _source(before)
    fake = _FakeStaticTrade(
        _result(_valid_fields(), context=before, source=source),
        contexts=[before, after],
    )

    result = TradeTargetGraphReader(fake).read("alpha", before)

    assert result["status"] == "unavailable"
    assert result["reason"] == "TRADE_TARGET_STATIC_CONTEXT_CHANGED_DURING_READ"
    assert result["source"] == source
    assert "rows" not in result
    assert len(fake.read_calls) == 1


def test_wrong_t01_source_identity_is_unknown_not_promoted():
    context = _context()
    fake = _FakeStaticTrade(
        _result(_valid_fields(), context=context, source=_source(context, name="CallerStub"))
    )

    result = TradeTargetGraphReader(fake).read("alpha", context)

    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_T01_SOURCE_IDENTITY_INVALID"
    assert "rows" not in result


def test_missing_pin_or_unavailable_t01_source_is_not_promoted():
    context = _context()
    missing_pin = _source(context, definitions_sha256=None)
    missing_pin["provenance"].pop("definitions_sha256")
    fake = _FakeStaticTrade(_result(_valid_fields(), context=context, source=missing_pin))
    result = TradeTargetGraphReader(fake).read("alpha", context)
    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_T01_SOURCE_IDENTITY_INVALID"
    assert "rows" not in result

    unavailable = _FakeStaticTrade(
        _result(_valid_fields(), context=context, source=_source(context, status="unavailable"))
    )
    result = TradeTargetGraphReader(unavailable).read("alpha", context)
    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_T01_SOURCE_IDENTITY_INVALID"
    assert "rows" not in result


def test_t01_objects_and_route_source_are_bound_to_selected_node():
    context = _context()
    wrong_objects = _FakeStaticTrade(
        _result(
            _valid_fields(),
            context=context,
            objects=[{"type": "trade_node", "node_id": "other"}],
        )
    )
    result = TradeTargetGraphReader(wrong_objects).read("alpha", context)
    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_T01_OBJECTS_INVALID"
    assert "rows" not in result

    foreign_route_fields = _valid_fields()
    foreign_route_fields["routes"] = [{
        "source": "foreign", "target": "beta", "path": [1], "control": []
    }]
    foreign_route = _FakeStaticTrade(_result(foreign_route_fields, context=context))
    result = TradeTargetGraphReader(foreign_route).read("alpha", context)
    assert result["status"] == "unknown"
    assert result["reason"] == "TRADE_TARGET_ROUTE_SOURCE_MISMATCH"
    assert "rows" not in result


def test_actual_static_trade_source_fixture_preserves_pins_and_members(tmp_path):
    (tmp_path / "common" / "tradenodes").mkdir(parents=True)
    (tmp_path / "launcher-settings.json").write_text(
        '{"rawVersion":"v1.37.4.0"}', encoding="utf-8"
    )
    (tmp_path / "common" / "tradenodes" / "00_fixture.txt").write_text(
        "alpha={location=1 members={1 2} outgoing={name=beta path={3} control={4}}}\n"
        "beta={members={3}}\n",
        encoding="utf-8",
    )
    static = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    context = static.context()
    result = TradeTargetGraphReader(static).read("alpha", context)

    assert result["status"] == "known"
    assert [row["province_id"] for row in result["rows"]] == [1, 2]
    assert result["topology"]["downstream"] == ["beta"]
    assert result["source"]["name"] == "StaticTradeSource"
    assert result["source"]["provenance"]["definitions_sha256"] == context["definitions_sha256"]
