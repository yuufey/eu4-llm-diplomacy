"""Memory bounds and invalidation tests for configured religion rules."""
from __future__ import annotations

from bridge.information.model import canonical
import bridge.information.religion_information as religion_information
from bridge.tests import test_information_religion_information as fixture


class MultiDefinitionIndex(fixture.DefinitionIndex):
    def __init__(self):
        super().__init__()
        self.generation = 0
        self.groups = {
            "catholic": "christian",
            "sunni": "muslim",
            "reformed": "christian",
        }

    def context(self):
        self.context_calls += 1
        return {
            "status": "ready",
            "complete": False,
            "configuration_sha256": fixture.SOURCE_PINS["configuration_sha256"],
            "definitions_sha256": fixture.SOURCE_PINS["definitions_sha256"],
            "generation": self.generation,
        }

    def definition(self, key):
        self.definition_calls.append(key)
        return fixture._rule_record(key, group_key=self.groups[key])

    def group_definition(self, key):
        self.group_calls.append(key)
        return fixture._rule_record(key, group=True)


def _make_source(tmp_path, monkeypatch, index):
    source, *_ = fixture._make_source(
        tmp_path, monkeypatch, definitions=index,
    )
    return source


def _cache_size(source):
    return sum(len(canonical([key, rules]).encode("utf-8"))
               for key, rules in source._rule_cache.items())


def test_rule_cache_fifo_count_bound_hit_copy_and_size_accounting(
        tmp_path, monkeypatch):
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_ENTRIES", 2)
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_BYTES", 8 * 1024 * 1024)
    index = MultiDefinitionIndex()
    source = _make_source(tmp_path, monkeypatch, index)
    identities = [
        {"religion_key": "catholic", "religion_group_key": "christian"},
        {"religion_key": "sunni", "religion_group_key": "muslim"},
        {"religion_key": "reformed", "religion_group_key": "christian"},
    ]

    first = source._configured_rules(identities[0])
    first_key = next(iter(source._rule_cache))
    first[0]["syntax"]["children"].append({"caller_mutation": True})
    second_read = source._configured_rules(identities[0])
    assert second_read[0]["syntax"]["children"] == []
    assert index.definition_calls == ["catholic"]
    assert index.group_calls == ["christian"]

    source._configured_rules(identities[1])
    source._configured_rules(identities[2])
    assert len(source._rule_cache) == 2
    assert first_key not in source._rule_cache
    assert source._rule_cache_bytes == _cache_size(source)
    assert source._rule_cache_bytes <= religion_information.MAX_RULE_CACHE_BYTES

    source._configured_rules(identities[0])
    assert index.definition_calls == ["catholic", "sunni", "reformed", "catholic"]
    assert index.group_calls == ["christian", "muslim", "christian", "christian"]
    assert len(source._rule_cache) == 2
    assert source._rule_cache_bytes == _cache_size(source)


def test_rule_cache_evicts_fifo_to_fit_canonical_byte_budget(
        tmp_path, monkeypatch):
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_ENTRIES", 16)
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_BYTES", 8 * 1024 * 1024)
    index = MultiDefinitionIndex()
    source = _make_source(tmp_path, monkeypatch, index)
    identity = {"religion_key": "catholic", "religion_group_key": "christian"}

    source._configured_rules(identity)
    first_key = next(iter(source._rule_cache))
    one_entry_bytes = source._rule_cache_bytes
    assert one_entry_bytes == _cache_size(source)

    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_BYTES", one_entry_bytes * 2)
    index.generation = 1
    source._configured_rules(identity)
    index.generation = 2
    source._configured_rules(identity)

    assert len(source._rule_cache) == 2
    assert first_key not in source._rule_cache
    assert source._rule_cache_bytes == _cache_size(source)
    assert source._rule_cache_bytes <= religion_information.MAX_RULE_CACHE_BYTES


def test_oversized_rule_result_is_known_but_never_cached(
        tmp_path, monkeypatch):
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_ENTRIES", 16)
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_BYTES", 1)
    index = MultiDefinitionIndex()
    source = _make_source(tmp_path, monkeypatch, index)
    identity = {"religion_key": "catholic", "religion_group_key": "christian"}

    first = source._configured_rules(identity)
    second = source._configured_rules(identity)

    assert first == second
    assert first[0]["status"] == first[1]["status"] == "known"
    assert source._rule_cache == {}
    assert source._rule_cache_entry_bytes == {}
    assert source._rule_cache_bytes == 0
    assert index.definition_calls == ["catholic", "catholic"]
    assert index.group_calls == ["christian", "christian"]


def test_stale_index_clears_entries_and_byte_accounting_without_reuse(
        tmp_path, monkeypatch):
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_ENTRIES", 16)
    monkeypatch.setattr(religion_information, "MAX_RULE_CACHE_BYTES", 8 * 1024 * 1024)
    index = MultiDefinitionIndex()
    source = _make_source(tmp_path, monkeypatch, index)
    identity = {"religion_key": "catholic", "religion_group_key": "christian"}

    known = source._configured_rules(identity)
    assert known[0]["status"] == known[1]["status"] == "known"
    assert source._rule_cache_bytes > 0

    index.fail_assert = True
    unknown = source._configured_rules(identity)

    expected = {"status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE"}
    assert unknown == (expected, expected)
    assert source._rule_cache == {}
    assert source._rule_cache_entry_bytes == {}
    assert source._rule_cache_bytes == 0
    assert index.definition_calls == ["catholic"]
    assert index.group_calls == ["christian"]
