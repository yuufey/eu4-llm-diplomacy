"""Bounded tests for the optional native trade-node name adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.model import InformationError
from bridge.information.static_data import StaticTradeSource


def _write_fixture(root: Path, text: str = "english_channel={members={1}}") -> Path:
    (root / "common" / "tradenodes").mkdir(parents=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    path = root / "common" / "tradenodes" / "00_fixture.txt"
    path.write_text(text, encoding="utf-8")
    return path


def _query(fields: list[str], node_id: str = "english_channel") -> dict:
    return {
        "topic": "T01",
        "object": {"type": "trade_node", "node_id": node_id},
        "fields": fields,
        "parameters": {},
    }


def _live_context(**overrides: object) -> dict:
    context = {
        "status": "ready",
        "mode": "live",
        "observer": "FRA",
        "session_id": "strict-session",
        "game_date": "1456.1.1",
        "game_sha256": "game-sha",
    }
    context.update(overrides)
    return context


class StrictLocalizationReader:
    """A fake reader that exposes every request to the test."""

    def __init__(self, response=None, *, mutate: Path | None = None):
        self.response = response
        self.mutate = mutate
        self.calls: list[tuple[str, dict, list[str]]] = []

    def localized_text(self, country, context, keys):
        assert country == "FRA"
        assert context["mode"] == "live"
        assert isinstance(keys, list) and len(keys) == 1
        assert keys[0] == "english_channel"
        self.calls.append((country, context, keys))
        if self.mutate is not None:
            self.mutate.write_text("english_channel={members={2}}", encoding="utf-8")
        if isinstance(self.response, BaseException):
            raise self.response
        if callable(self.response):
            return self.response()
        return self.response or {
            "status": "known",
            "entries": {
                "english_channel": {
                    "status": "known",
                    "text": "英吉利海峡",
                    "codec": "utf8",
                    "raw_template_hex": "e88bb1e59089e588a9e6b5b7e5b3a1",
                }
            },
            "language": "l_english",
            "provenance": {
                "reader": "strict-fake",
                "lookup_semantics": "native_FNV1_hash_only",
            },
        }


def _source(tmp_path: Path, reader=None, text: str = "english_channel={members={1}}"):
    _write_fixture(tmp_path, text)
    return StaticTradeSource(
        game_root=tmp_path,
        user_data=tmp_path / "user",
        enabled_mods=[],
        localization_reader=reader,
    )


def test_name_uses_exact_node_key_only_when_explicitly_requested_and_preserves_provenance(tmp_path):
    reader = StrictLocalizationReader()
    source = _source(tmp_path, reader)
    live = _live_context()

    topology = source.read(_query(["provinces"]), live)
    assert topology["fields"]["provinces"]["status"] == "known"
    assert reader.calls == []

    result = source.read(_query(["name", "provinces"]), live)
    assert result["fields"]["name"] == {"status": "known", "value": "英吉利海峡"}
    assert result["fields"]["provinces"]["value"] == [1]
    assert result["source"]["mode"] == "mixed"
    assert result["source"]["context_scope"] == "static_rules_and_native_localization"
    assert result["source"]["name_localization"] == {
        "key": "english_channel",
        "language": "l_english",
        "codec": "utf8",
        "raw_template_hex": "e88bb1e59089e588a9e6b5b7e5b3a1",
        "reader_provenance": {
            "reader": "strict-fake",
            "lookup_semantics": "native_FNV1_hash_only",
        },
        "status": "known",
        "mode": "live",
        "context_scope": "live",
        "session_id": "strict-session",
        "game_date": "1456.1.1",
    }
    assert reader.calls[0][2] == ["english_channel"]
    assert "_name" not in reader.calls[0][2][0]
    assert ":0" not in reader.calls[0][2][0]


def test_static_or_non_live_context_never_reads_native_cache(tmp_path):
    reader = StrictLocalizationReader()
    source = _source(tmp_path, reader)
    contexts = [
        source.context(),
        _live_context(mode="offline"),
        _live_context(mode="recorded"),
        _live_context(mode="live", context_scope="saved"),
        _live_context(status="unready"),
    ]
    for context in contexts:
        result = source.read(_query(["name"]), context)
        assert result["fields"]["name"] == {
            "status": "unknown",
            "reason": "LOCALISATION_NOT_READ",
        }
    assert reader.calls == []


def test_unknown_node_is_rejected_before_reader_call(tmp_path):
    reader = StrictLocalizationReader()
    source = _source(tmp_path, reader)
    result = source.read(_query(["name"], "missing_node"), _live_context())
    assert result["fields"]["name"] == {"status": "unknown", "reason": "NODE_NOT_FOUND"}
    assert reader.calls == []


@pytest.mark.parametrize(
    ("response", "status", "reason"),
    [
        (
            {
                "status": "known",
                "entries": {},
                "language": "l_english",
                "provenance": {"reader": "fake"},
            },
            "unknown",
            "LOCALIZATION_KEY_UNRESOLVED",
        ),
        (
            {
                "status": "known",
                "entries": {
                    "english_channel": {
                        "status": "unknown",
                        "reason": "LOCALIZATION_KEY_UNRESOLVED",
                    }
                },
                "language": "l_english",
                "provenance": {"reader": "fake"},
            },
            "unknown",
            "LOCALIZATION_KEY_UNRESOLVED",
        ),
        (
            {
                "status": "known",
                "entries": {
                    "english_channel": {
                        "status": "unknown",
                        "reason": "DYNAMIC_LOCALIZATION_UNRESOLVED",
                        "template": "[Root.GetName]",
                        "raw_template_hex": "5b526f6f742e4765744e616d655d",
                    }
                },
                "language": "l_english",
                "provenance": {"reader": "fake"},
            },
            "unknown",
            "DYNAMIC_LOCALIZATION_UNRESOLVED",
        ),
        (
            {
                "status": "known",
                "entries": {
                    "english_channel": {
                        "status": "known",
                        "text": "bad",
                        "raw_template_hex": "not-hex",
                    }
                },
                "language": "l_english",
                "provenance": {"reader": "fake"},
            },
            "unknown",
            "LOCALIZATION_BYTES_INVALID",
        ),
        (
            {"status": "unavailable", "reason": "localization_context_changed", "entries": {}},
            "unavailable",
            "localization_context_changed",
        ),
    ],
)
def test_reader_gaps_never_fall_back_to_node_id(tmp_path, response, status, reason):
    source = _source(tmp_path, StrictLocalizationReader(response))
    result = source.read(_query(["name"]), _live_context())
    assert result["fields"]["name"]["status"] == status
    assert result["fields"]["name"]["reason"] == reason
    assert "value" not in result["fields"]["name"]
    assert result["fields"]["name"].get("value") != "english_channel"


def test_reader_exception_preserves_unavailable_guard_reason(tmp_path):
    source = _source(
        tmp_path,
        StrictLocalizationReader(InformationError("LOCALIZATION_GUARD_FAILED", "guard failed")),
    )
    result = source.read(_query(["name"]), _live_context())
    assert result["fields"]["name"] == {
        "status": "unavailable",
        "reason": "LOCALIZATION_GUARD_FAILED",
    }


def test_name_guard_recheck_discards_known_value_when_static_definition_changes(tmp_path):
    path = _write_fixture(tmp_path)
    reader = StrictLocalizationReader(mutate=path)
    source = StaticTradeSource(
        game_root=tmp_path,
        user_data=tmp_path / "user",
        enabled_mods=[],
        localization_reader=reader,
    )
    result = source.read(_query(["name"]), _live_context())
    assert result["fields"]["name"] == {
        "status": "unavailable",
        "reason": "STATIC_SOURCE_CHANGED_DURING_LOCALIZATION",
    }
    assert reader.calls


def test_name_guard_recheck_unmakes_mixed_topology_fields_when_definition_changes(tmp_path):
    path = _write_fixture(tmp_path)
    reader = StrictLocalizationReader(mutate=path)
    source = StaticTradeSource(
        game_root=tmp_path,
        user_data=tmp_path / "user",
        enabled_mods=[],
        localization_reader=reader,
    )
    result = source.read(_query(["name", "node_id", "routes"]), _live_context())

    assert result["fields"] == {
        "name": {
            "status": "unavailable",
            "reason": "STATIC_SOURCE_CHANGED_DURING_LOCALIZATION",
        },
        "node_id": {
            "status": "unavailable",
            "reason": "STATIC_SOURCE_CHANGED_DURING_LOCALIZATION",
        },
        "routes": {
            "status": "unavailable",
            "reason": "STATIC_SOURCE_CHANGED_DURING_LOCALIZATION",
        },
    }
    assert result["source"]["status"] == "unavailable"
    assert result["source"]["mode"] == "mixed"
    assert result["source"]["context_scope"] == "static_rules_and_native_localization"


def test_catalog_triggers_are_reader_scoped(tmp_path):
    no_reader = _source(tmp_path / "no_reader")
    no_reader_catalog = {item["topic_id"]: item for item in no_reader.catalog()}
    assert no_reader_catalog["T01"]["triggers"] == ["query"]
    assert no_reader_catalog["G04"]["triggers"] == ["query"]
    assert no_reader_catalog["T02"]["triggers"] == ["query"]

    reader = StrictLocalizationReader()
    with_reader = _source(tmp_path / "with_reader", reader)
    catalog = {item["topic_id"]: item for item in with_reader.catalog()}
    assert catalog["T01"]["triggers"] == ["query", "periodic"]
    assert catalog["G04"]["triggers"] == ["query"]
    assert catalog["T02"]["triggers"] == ["query"]
    assert "literal cache" in catalog["T01"]["fields"]["name"]["description"]


def test_reader_failure_does_not_erase_other_static_fields(tmp_path):
    reader = StrictLocalizationReader(
        {
            "status": "known",
            "entries": {
                "english_channel": {
                    "status": "unknown",
                    "reason": "LOCALIZATION_KEY_UNRESOLVED",
                }
            },
            "language": "l_english",
            "provenance": {"reader": "fake"},
        }
    )
    source = _source(tmp_path, reader)
    result = source.read(_query(["name", "node_id", "provinces", "routes"]), _live_context())
    assert result["fields"]["name"]["status"] == "unknown"
    assert result["fields"]["node_id"] == {"status": "known", "value": "english_channel"}
    assert result["fields"]["provinces"] == {"status": "known", "value": [1]}
    assert result["fields"]["routes"] == {"status": "known", "value": []}

