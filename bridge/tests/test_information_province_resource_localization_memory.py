from __future__ import annotations

import json

import pytest

from bridge.information import localization_memory as localization
from bridge.information import province_resource_localization_memory as resource_localization
from bridge.tests.test_information_localization_memory import localization_fixture


class ReaderProxy:
    def __init__(self, inner, *, fail_label: str | None = None,
                 short_label: str | None = None):
        self.inner = inner
        self.module_base = inner.module_base
        self.fail_label = fail_label
        self.short_label = short_label
        self.calls = 0
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls += 1
        self.bytes_requested += size
        if label == self.fail_label:
            raise OSError("fixture read failure")
        value = self.inner.read(address, size, label)
        if label == self.short_label:
            return value[:-1]
        return value


def _read(values: dict[str, bytes], key="paper", **reader_options):
    inner, base, _offsets = localization_fixture(values)
    reader = ReaderProxy(inner, **reader_options)
    result = resource_localization.read_cached_name(reader, base, key)
    return result, reader, base


def test_literal_value_uses_real_snapshot_lookup_and_preserves_language():
    result, reader, _base = _read({"paper": b"Paper"})

    assert result["status"] == "known"
    assert result["raw_hex"] == b"Paper".hex()
    assert result["language"] == "l_english"
    snapshot = result["raw_inputs"]["snapshot"]
    assert snapshot["status"] == "observed"
    assert snapshot["country_scan"]["scanned_entries"] == localization.COUNTRY_SCAN_ENTRIES
    assert snapshot["entries"]["paper"]["hash"] == hex(localization._fnv1_ascii("paper"))
    assert reader.calls > 0


def test_dynamic_template_and_empty_bytes_are_preserved_without_decoding():
    template = b"$NAME$ [Root.GetName]"
    dynamic, _reader, _base = _read({"paper": template})
    assert dynamic["status"] == "known"
    assert dynamic["raw_hex"] == template.hex()
    assert "text" not in dynamic
    assert dynamic["raw_inputs"]["snapshot"]["entries"]["paper"][
        "dynamic_tokens_not_substituted"
    ] is True

    empty, _reader, _base = _read({"paper": b""})
    assert empty["status"] == "known"
    assert empty["raw_hex"] == ""
    assert empty["raw_inputs"]["snapshot"]["entries"]["paper"]["byte_length"] == 0


def test_missing_key_is_unknown_with_full_snapshot():
    result, _reader, _base = _read({"other": b"Other"}, key="paper")

    assert result["status"] == "unknown"
    assert result["reason"] == "LOCALIZATION_KEY_NOT_FOUND"
    entry = result["raw_inputs"]["snapshot"]["entries"]["paper"]
    assert entry["status"] == "unknown"
    assert entry["unknown_reason"] == "localization_key_not_found"


def test_maximum_resource_key_and_value_boundaries_are_accepted():
    key = "r" * 128
    value = b"x" * localization.MAX_VALUE_BYTES
    result, _reader, _base = _read({key: value}, key=key)
    assert result["status"] == "known"
    assert len(result["raw_hex"]) == len(value) * 2
    assert result["raw_inputs"]["snapshot"]["entries"][key]["byte_length"] == 8192


@pytest.mark.parametrize("key", ["", "r" * 129, "bad/key", "bad key", "cafe\u00e9", None])
def test_invalid_key_is_rejected_before_any_read(key):
    inner, base, _offsets = localization_fixture({"paper": b"Paper"})
    reader = ReaderProxy(inner)

    result = resource_localization.read_cached_name(reader, base, key)

    assert result["status"] == "unknown"
    assert result["reason"] == "RESOURCE_LOCALIZATION_KEY_INVALID"
    assert reader.calls == 0


def test_module_base_mismatch_is_rejected_before_any_read():
    inner, base, _offsets = localization_fixture({"paper": b"Paper"})
    reader = ReaderProxy(inner)

    result = resource_localization.read_cached_name(reader, base + 8, "paper")

    assert result["status"] == "unknown"
    assert result["reason"] == "LOCALIZATION_MODULE_BASE_MISMATCH"
    assert reader.calls == 0


@pytest.mark.parametrize("failure", ["read_error", "short_read"])
def test_failed_or_short_read_returns_unknown_with_private_snapshot(failure):
    options = ({"fail_label": "localization.outer_header"} if failure == "read_error"
               else {"short_label": "localization.outer_header"})
    result, reader, _base = _read({"paper": b"Paper"}, **options)

    assert result["status"] == "unknown"
    assert result["reason"] == "LOCALIZATION_SNAPSHOT_INCOMPLETE"
    snapshot = result["raw_inputs"]["snapshot"]
    assert snapshot["status"] == "unknown"
    assert reader.calls > 0


@pytest.mark.parametrize(("budget_name", "budget_value"), [
    ("_MAX_READ_CALLS", 0),
    ("_MAX_TOTAL_READ_BYTES", 1),
    ("_MAX_SINGLE_READ_BYTES", 1),
])
def test_local_budget_limits_fail_closed_without_opening_or_unbounded_reads(
    monkeypatch, budget_name, budget_value,
):
    monkeypatch.setattr(resource_localization, budget_name, budget_value)
    inner, base, _offsets = localization_fixture({"paper": b"Paper"})
    reader = ReaderProxy(inner)

    result = resource_localization.read_cached_name(reader, base, "paper")

    assert result["status"] == "unknown"
    assert result["reason"] == "LOCALIZATION_SNAPSHOT_INCOMPLETE"
    assert result["raw_inputs"]["snapshot"]["status"] == "unknown"
    assert reader.calls == 0


def test_result_roundtrip_remains_json_safe():
    result, _reader, _base = _read({"paper": b"Paper"})

    restored = json.loads(json.dumps(result, ensure_ascii=False))
    assert restored == result
    assert restored["raw_inputs"]["snapshot"]["entries"]["paper"]["value_hex"] == b"Paper".hex()


def test_unknown_roundtrip_preserves_safe_reason_and_snapshot_types():
    result, _reader, _base = _read({"other": b"Other"}, key="paper")

    restored = json.loads(json.dumps(result, ensure_ascii=False))
    assert restored == result
    assert restored["status"] == "unknown"
    assert restored["reason"] == "LOCALIZATION_KEY_NOT_FOUND"
    assert isinstance(restored["raw_inputs"]["snapshot"]["localization"]["table"]["count"], int)
