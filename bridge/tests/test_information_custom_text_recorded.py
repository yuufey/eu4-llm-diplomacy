"""Offline replay tests for the recorded dynamic mission-text capture.

The fixture is a bounded projection of the historical live-acceptance-003
reports.  These tests exercise the current normalizer and reader with those
records; they do not open a game process or claim a new live observation.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.mission_custom_texts import normalize_methods
from bridge.information.missions import NativeMissionReader
from bridge.information.model import InformationError


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_custom_texts_live_1374.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CONTEXT = FIXTURE["original_context"]
METHODS = ["GetSelectableMissionTitle", "GetSelectableMissionDescription"]
INITIAL_KEYS = list(FIXTURE["localization_capture"]["report"]["entries"])
SELECTED_KEYS = list(FIXTURE["selected_text_cache"]["report"]["entries"])
EXPECTED = FIXTURE["expected_texts"]["entries"]


class _RecordedSession:
    def __init__(self) -> None:
        self.directory = FIXTURE_PATH.parent
        self.record = {"native_text_codec": "eu4_escape"}


class _RecordedSource:
    event_types: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.session = _RecordedSession()
        self._context = deepcopy(CONTEXT)

    def context(self) -> dict:
        return deepcopy(self._context)


class _RecordedHarness:
    def __init__(self, *, custom_mutator=None) -> None:
        self.cache_calls: list[list[str]] = []
        self.custom_calls: list[list[str]] = []
        self.custom_mutator = custom_mutator

    def localization_capture(self, _installation: Path, country: str,
                             keys: list[str]) -> dict:
        self.cache_calls.append(list(keys))
        base = (FIXTURE["localization_capture"]["report"]
                if len(self.cache_calls) == 1
                else FIXTURE["selected_text_cache"]["report"])
        report = deepcopy(base)
        report["request"]["country"] = country
        report["request"]["keys"] = list(keys)
        report["entries"] = {
            key: deepcopy(base["entries"][key]) for key in keys
        }
        return report

    def custom_localization_capture(self, _installation: Path, country: str,
                                    methods: list[str]) -> dict:
        self.custom_calls.append(list(methods))
        report = deepcopy(FIXTURE["native_capture"])
        report["request"]["country"] = country
        report["request"]["methods"] = list(methods)
        report["methods"] = {
            method: deepcopy(FIXTURE["native_capture"]["methods"][method])
            for method in methods
        }
        if self.custom_mutator is not None:
            self.custom_mutator(report)
        return report


def _run(*, custom_mutator=None) -> tuple[dict, _RecordedHarness]:
    harness = _RecordedHarness(custom_mutator=custom_mutator)
    source = _RecordedSource()
    reader = NativeMissionReader(
        source,
        localization_capture=harness.localization_capture,
        custom_localization_capture=harness.custom_localization_capture,
    )
    return reader.localized_text("FRA", CONTEXT, INITIAL_KEYS), harness


def test_fixture_is_recorded_and_retains_source_hashes() -> None:
    provenance = FIXTURE["provenance"]
    assert provenance["mode"] == "recorded"
    assert provenance["original_mode"] == "live"
    assert provenance["source"].endswith("live-acceptance-003/custom-methods.json")
    assert provenance["source_sha256"] == (
        "b0608f11ba54c174dcb742bfeddbcfd77ddbc671802d27be834d786cd28c1e8f"
    )
    assert FIXTURE["acceptance_summary"]["record"]["custom_capture_sha256"] == provenance["source_sha256"]
    assert FIXTURE["acceptance_summary"]["record"]["native_function_invoked"] is False
    assert FIXTURE["native_capture"]["status"] == "observed"
    assert FIXTURE["native_capture"]["read_only"] is True
    assert FIXTURE["provenance"]["projection"]["kind"] == "bounded_shell_method_cache_projection"


def test_recorded_methods_normalize_with_both_singleton_selection_guards() -> None:
    normalized = normalize_methods(
        FIXTURE["native_capture"], CONTEXT, METHODS,
    )

    assert set(normalized["methods"]) == set(METHODS)
    assert normalized["status"] == "known"
    for method in METHODS:
        raw = FIXTURE["native_capture"]["methods"][method]
        selection = raw["selection"]
        assert raw["status"] == "observed"
        assert raw["definition"]["option_count"] == 1
        assert len(raw["definition"]["options"]) == 1
        assert selection["kind"] == "single_unconditional_positive_weight"
        assert selection["option_count"] == 1
        assert selection["predicate_count"] == 0
        assert selection["weight"] == 1000
        assert selection["modifiers_empty"] is True
        assert selection["random_flag"] == 1
        assert selection["builtin_name_absent"] is True
        assert selection["derived_for_query_country_root"] is True
        assert selection["root_promotion_enum"] == 3
        assert selection["ui_root_scope_verified"] is False
        assert normalized["methods"][method]["status"] == "known"


def test_recorded_122_entries_match_14_derived_116_known_and_6_unknown() -> None:
    result, harness = _run()
    expected_counts = Counter(entry.get("status") for entry in EXPECTED.values())
    actual_counts = Counter(entry.get("status") for entry in result["entries"].values())

    assert len(INITIAL_KEYS) == 122
    assert len(EXPECTED) == 122
    assert expected_counts == Counter({"known": 116, "unknown": 6})
    assert actual_counts == expected_counts
    assert sum(entry.get("expected_custom_method") is not None for entry in EXPECTED.values()) == 14
    assert sum(
        value.get("status") == "known" and key.endswith("_title")
        for key, value in result["entries"].items()
    ) == 60
    assert sum(
        value.get("status") == "known" and key.endswith("_desc")
        for key, value in result["entries"].items()
    ) == 56

    for key, expected in EXPECTED.items():
        actual = result["entries"][key]
        assert actual["status"] == expected["status"], key
        if expected["status"] == "known":
            assert actual["text"] == expected["text"], key
        else:
            assert actual["template"] == expected["template"], key
            assert "text" not in actual, key

    resolution = result["provenance"]["custom_text_resolution"]
    assert resolution["status"] == "known"
    assert resolution["derived_count"] == 14
    assert resolution["target_count"] == 14
    assert harness.custom_calls == [METHODS]
    assert harness.cache_calls == [INITIAL_KEYS, SELECTED_KEYS]


def _tamper_cleanup(report: dict) -> None:
    report["cleanup"]["handle_close"]["closed"] = False


def _tamper_root_scope(report: dict) -> None:
    report["query_scope"]["binding"] = "implicit_ui_root"


def _tamper_query(report: dict) -> None:
    report["request"]["country"] = "ENG"


def _tamper_weight(report: dict) -> None:
    report["methods"]["GetSelectableMissionTitle"]["selection"]["weight"] = 0


def _tamper_builtin_absence(report: dict) -> None:
    report["methods"]["GetSelectableMissionDescription"]["selection"]["builtin_name_absent"] = False


@pytest.mark.parametrize(
    ("label", "mutator", "expected_code"),
    [
        ("cleanup", _tamper_cleanup, "custom_localization_snapshot_incomplete"),
        ("root", _tamper_root_scope, "custom_localization_root_scope_unverified"),
        ("query", _tamper_query, "custom_localization_request_invalid"),
        ("weight", _tamper_weight, "custom_localization_method_invalid"),
        ("builtin_absence", _tamper_builtin_absence, "custom_localization_root_scope_unverified"),
    ],
)
def test_recorded_guard_tampering_rejects_derivation(
    label: str, mutator, expected_code: str,
) -> None:
    report = deepcopy(FIXTURE["native_capture"])
    mutator(report)
    with pytest.raises(InformationError) as caught:
        normalize_methods(report, CONTEXT, METHODS)
    assert caught.value.code == expected_code, label

    result, harness = _run(custom_mutator=mutator)
    dynamic_keys = [
        key for key, expected in EXPECTED.items()
        if expected.get("expected_custom_method") is not None
    ]
    assert all(result["entries"][key]["status"] == "unknown" for key in dynamic_keys)
    resolution = result["provenance"]["custom_text_resolution"]
    assert resolution["status"] == "unknown"
    assert resolution["derived_count"] == 0
    assert harness.custom_calls == [METHODS]
    assert harness.cache_calls == [INITIAL_KEYS]

