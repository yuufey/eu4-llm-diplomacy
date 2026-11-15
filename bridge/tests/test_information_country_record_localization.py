from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import country_modifiers_memory as memory
from bridge.information.country_record_localization import (
    NativeCountryModifierLocalizationSource,
)
from bridge.information.native_localization import NativeLocalizationReader
from bridge.tests.test_information_country_modifiers_memory import _reader as archived_reader


ROOT = Path(__file__).resolve().parents[2]
SOURCE_REPORT = ROOT / "work" / "runtime" / "information-country-records-localization-20261027-001" / "modifier-localization-source-001.json"


def _context(*, mode: str = "live", status: str = "ready", observer: str = "FRA", date: int = 56557728) -> dict:
    return {
        "status": status,
        "mode": mode,
        "session_id": "31460-1dd653f69242d7b",
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "observer": observer,
        "game_date": date,
        "game_version": "1.37.4",
    }


class FakeBase:
    def __init__(self, context: dict):
        self.current = deepcopy(context)

    def context(self):
        return deepcopy(self.current)


class NormalizerCaptureBase(FakeBase):
    """A no-process base for the real neutral reader and capture seam."""

    def __init__(self, context: dict, *, codec: str = "utf8"):
        super().__init__(context)
        self.session = SimpleNamespace(
            directory=ROOT,
            record={"native_text_codec": codec},
        )


class StrictLocalizationReader:
    def __init__(self, entries=None, *, error=None, mutate=None):
        self.entries = entries or {}
        self.error = error
        self.mutate = mutate
        self.calls = []

    def localized_text(self, country, context, keys):
        self.calls.append((country, deepcopy(context), list(keys)))
        if self.error is not None:
            raise self.error
        if self.mutate is not None:
            self.mutate()
        return {
            "status": "known",
            "entries": {key: deepcopy(self.entries[key]) for key in self.entries},
            "language": "l_english",
            "provenance": {
                "reader": "strict_fake_native_localization",
                "codec": "utf8",
                "session_id": context.get("session_id"),
                "game_date": context.get("game_date"),
            },
        }


def _literal(text: str) -> dict:
    return {
        "status": "known",
        "text": text,
        "raw_template_hex": text.encode("utf-8").hex(),
        "codec": "utf8",
        "decoded_status": "decoded",
    }


def _native_cache_entry(key: str, *, text: str | None = None,
                        status: str = "observed",
                        unknown_reason: str = "LOCALIZATION_KEY_UNRESOLVED") -> dict:
    if status == "unknown":
        return {"key": key, "status": "unknown", "unknown_reason": unknown_reason}
    assert text is not None
    raw = text.encode("utf-8")
    return {
        "key": key,
        "status": "observed",
        "value_hex": raw.hex(),
        "byte_length": len(raw),
    }


def _native_cache_report(context: dict, keys: list[str], entries: dict[str, dict],
                         *, language: str) -> dict:
    date = context["game_date"]
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "normalizer-profile"},
        "probe_script_sha256": "normalizer-probe",
        "identity": {
            "binding_verified": True,
            "installation_session_id": context["session_id"],
            "process_path_sha256": context["game_sha256"],
        },
        "request": {"country": context["observer"], "keys": list(keys)},
        "static_contract_guard": {"status": "observed"},
        "file_code_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "doublepass": {"performed": True, "consistent": True},
        "before": {"status": "observed", "game_date": {"raw": date}},
        "after": {"status": "observed", "game_date": {"raw": date}},
        "language": {"status": "observed", "text": language},
        "entries": deepcopy(entries),
        "cleanup": {"handle_close": {"closed": True}},
    }


def _record():
    reader = archived_reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert memory.validate_record(record)
    return record


def _all_literal_entries(record):
    entries = {}
    for item in record["values"]["modifiers"]:
        key = item["key"]
        entries[key] = _literal({
            "papal_sanction_for_church_taxes": "Papal Sanction for Increased Taxes",
            "shady_people": "Shady People",
        }[key])
        entries[f"desc_{key}"] = _literal({
            "papal_sanction_for_church_taxes": "The papacy has sanctioned our right to tax the faithful of our nation for a period, boosting our tax income substantially.",
            "shady_people": "Some shady people have offered their services to your country.",
        }[key])
    return entries


def test_exact_name_description_keys_and_literal_metadata():
    context = _context()
    base = FakeBase(context)
    reader = StrictLocalizationReader(_all_literal_entries(_record()))
    result = NativeCountryModifierLocalizationSource(base, localization_reader=reader).localize_records(_record(), context)

    assert result["status"] == "known"
    assert result["complete"] is True
    assert reader.calls and reader.calls[0][0] == "FRA"
    assert reader.calls[0][2] == [
        "papal_sanction_for_church_taxes",
        "desc_papal_sanction_for_church_taxes",
        "shady_people",
        "desc_shady_people",
    ]
    first = result["records"][0]
    assert first["key"] == "papal_sanction_for_church_taxes"
    assert first["name"]["status"] == "known"
    assert first["name"]["value"] == "Papal Sanction for Increased Taxes"
    assert first["name"]["key"] == "papal_sanction_for_church_taxes"
    assert first["description"]["key"] == "desc_papal_sanction_for_church_taxes"
    assert first["description"]["value"].startswith("The papacy")
    assert first["name"]["language"] == "l_english"
    assert first["name"]["codec"] == "utf8"
    assert first["name"]["encoding"] == "utf8"
    assert first["name"]["source"] == "native_localization_cache"
    assert first["name"]["raw_template_hex"] == "506170616c2053616e6374696f6e20666f7220496e63726561736564205461786573"
    assert first["name"]["reader_provenance"]["reader"] == "strict_fake_native_localization"
    assert result["source"]["key_convention"]["description"] == "desc_<modifier_key>"


def test_real_neutral_reader_normalizer_preserves_language_and_unknown_siblings():
    """Exercise NativeLocalizationReader.normalize_localization, not a stub shape."""

    context = _context()
    base = NormalizerCaptureBase(context)
    record = _record()
    keys = [
        "papal_sanction_for_church_taxes",
        "desc_papal_sanction_for_church_taxes",
        "shady_people",
        "desc_shady_people",
    ]
    entries = {
        keys[0]: _native_cache_entry(keys[0], text="教会税特许"),
        keys[1]: _native_cache_entry(keys[1], text="忠实纳税者的特许说明"),
        keys[2]: _native_cache_entry(keys[2], text="[ROOT.dynamic_name]"),
        keys[3]: _native_cache_entry(keys[3], status="unknown"),
    }
    raw_reports = []

    def capture(_installation, _country, requested):
        raw_reports.append(list(requested))
        return _native_cache_report(
            context, requested,
            {key: entries[key] for key in requested},
            language="l_simp_chinese",
        )

    neutral_reader = NativeLocalizationReader(base, capture=capture)
    result = NativeCountryModifierLocalizationSource(
        base, localization_reader=neutral_reader,
    ).localize_records(record, context)

    assert raw_reports == [keys]
    first, second = result["records"]
    assert first["name"]["status"] == "known"
    assert first["name"]["value"] == "教会税特许"
    assert first["description"]["value"] == "忠实纳税者的特许说明"
    assert first["name"]["language"] == "l_simp_chinese"
    assert first["name"]["reader_provenance"]["batches"][0]["profile_sha256"] == "normalizer-profile"
    assert second["name"]["status"] == "unknown"
    assert second["name"]["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"
    assert second["name"]["raw_template_hex"] == "5b524f4f542e64796e616d69635f6e616d655d"
    assert "value" not in second["name"]
    assert second["description"]["status"] == "unknown"
    assert second["description"]["reason"] == "LOCALIZATION_KEY_UNRESOLVED"
    assert "value" not in second["description"]
    assert result["complete"] is False


def test_archived_native_cache_round_trips_through_real_neutral_reader():
    """The current four-key cache report uses the real EU4 escape codec shape."""

    cache_path = ROOT / "work" / "runtime" / "information-country-records-localization-20261027-001" / "literal-reference-001" / "native-cache.json"
    report = json.loads(cache_path.read_text(encoding="utf-8"))
    context = _context()
    base = NormalizerCaptureBase(context, codec="eu4_escape")
    keys = list(report["request"]["keys"])
    calls = []

    def capture(_installation, _country, requested):
        calls.append(list(requested))
        assert requested == keys
        return deepcopy(report)

    neutral_reader = NativeLocalizationReader(base, capture=capture)
    result = NativeCountryModifierLocalizationSource(
        base, localization_reader=neutral_reader,
    ).localize_records(_record(), context)

    assert calls == [keys]
    assert result["complete"] is True
    first, second = result["records"]
    assert first["name"]["value"] == "教宗特许加税"
    assert first["description"]["value"].startswith("教廷特许")
    assert second["name"]["value"] == "暗处的人"
    assert second["description"]["value"].endswith("国家。")
    assert first["name"]["language"] == "l_english"
    assert first["name"]["codec"] == "eu4_escape"
    assert first["name"]["raw_template_hex"] == report["entries"][keys[0]]["value_hex"]


@pytest.mark.parametrize(
    "context",
    [
        _context(mode="recorded", status="ready"),
        _context(mode="saved", status="ready"),
        _context(mode="unbound", status="unknown"),
        _context(observer="ENG"),
    ],
)
def test_non_live_or_unbound_context_never_reads_localization(context):
    reader = StrictLocalizationReader(_all_literal_entries(_record()))
    result = NativeCountryModifierLocalizationSource(FakeBase(context), localization_reader=reader).localize_records(_record(), context)

    assert reader.calls == []
    assert result["complete"] is False
    assert result["source"]["attempted"] is False
    assert result["source"]["reason"] in {"LOCALISATION_NOT_READ", "OBSERVER_SCOPE_MISMATCH"}
    assert all(item["status"] == "unknown" for item in result["fields"]["name"]["value"])
    assert all("value" not in item for item in result["fields"]["name"]["value"])


def test_unknown_missing_dynamic_bad_entry_never_falls_back_to_disk_text():
    record = _record()
    entries = _all_literal_entries(record)
    entries["desc_papal_sanction_for_church_taxes"] = {
        "status": "dynamic",
        "template": "The papacy has [ROOT.dynamic]",
        "raw_template_hex": "5b524f4f542e64796e616d69635d",
        "unresolved_tokens": ["ROOT.dynamic"],
    }
    entries.pop("shady_people")
    entries["desc_shady_people"] = {
        "status": "known",
        "text": "[bad dynamic]",
        "raw_template_hex": "5b6261642064796e616d69635d",
        "decoded_status": "decoded",
    }
    reader = StrictLocalizationReader(entries)
    result = NativeCountryModifierLocalizationSource(FakeBase(_context()), localization_reader=reader).localize_records(record, _context())
    first, second = result["records"]

    assert first["name"]["status"] == "known"
    assert first["description"]["status"] == "unknown"
    assert first["description"]["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"
    assert first["description"]["template"] == "The papacy has [ROOT.dynamic]"
    assert second["name"]["status"] == "unknown"
    assert second["name"]["reason"] == "LOCALIZATION_KEY_UNRESOLVED"
    assert second["description"]["status"] == "unknown"
    assert second["description"]["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"
    assert "value" not in second["name"]
    assert "Shady People" not in json.dumps(result, ensure_ascii=False)


def test_reader_exception_preserves_modifier_records_and_does_not_fallback():
    context = _context()
    reader = StrictLocalizationReader(error=RuntimeError("cache unavailable"))
    result = NativeCountryModifierLocalizationSource(FakeBase(context), localization_reader=reader).localize_records(_record(), context)

    assert reader.calls
    assert result["status"] == "known"
    assert [item["key"] for item in result["records"]] == [
        "papal_sanction_for_church_taxes", "shady_people",
    ]
    assert all(item["status"] == "unknown" for item in result["fields"]["name"]["value"])
    assert result["source"]["reason"] == "LOCALIZATION_READ_FAILED"


def test_invalid_modifier_record_rejects_keys_before_reader():
    record = _record()
    record["values"]["modifiers"][0]["key"] = "tampered"
    reader = StrictLocalizationReader(_all_literal_entries(_record()))
    result = NativeCountryModifierLocalizationSource(FakeBase(_context()), localization_reader=reader).localize_records(record, _context())

    assert reader.calls == []
    assert result["status"] == "unknown"
    assert result["source"]["reason"] == "MODIFIER_RECORD_INVALID"
    assert result["records"] == []


def test_context_change_after_reader_invalidates_all_localization_values():
    context = _context()
    base = FakeBase(context)
    reader = StrictLocalizationReader(
        _all_literal_entries(_record()),
        mutate=lambda: base.current.update(game_date=56557729),
    )
    result = NativeCountryModifierLocalizationSource(base, localization_reader=reader).localize_records(_record(), context)

    assert result["status"] == "known"
    assert result["source"]["status"] == "unavailable"
    assert result["source"]["reason"] == "LOCALIZATION_CONTEXT_CHANGED"
    assert all(item["status"] == "unavailable" for item in result["fields"]["name"]["value"])
    assert all("value" not in item for item in result["fields"]["description"]["value"])


def test_static_source_report_closes_exact_two_key_convention():
    report = json.loads(SOURCE_REPORT.read_text(encoding="utf-8"))
    assert report["schema"] == "information_country_modifier_localization_source.v1"
    assert report["resource"]["relative_path"] == "localisation/modifers_l_english.yml"
    assert report["resource"]["scan"]["missing_keys"] == []
    pairs = report["resource"]["scan"]["pairs"]
    assert [(pair["name_key"], pair["description_key"]) for pair in pairs] == [
        ("papal_sanction_for_church_taxes", "desc_papal_sanction_for_church_taxes"),
        ("shady_people", "desc_shady_people"),
    ]
