"""Integration contracts for native mission localization normalization.

These tests use the smallest complete capture shape consumed by
``NativeMissionReader.normalize_localization``.  They intentionally do not
reuse the runtime research capture: the production reader's identity, guard,
double-pass, language, and cleanup fields are the contract under test.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.mission_texts import decode_template
from bridge.information.model import InformationError
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.tests.test_information_missions import Definitions, State, query


CONTEXT = {
    "status": "ready",
    "mode": "live",
    "session_id": "session-localization-1",
    "game_sha256": "game-sha-1",
    "observer": "FRA",
    "game_date": "1444.01.01",
}

CN_ESCAPE_HEX = "10e389103e6510fa8b10fc6610955e"
RECORDED_SOURCE_SHA256 = "985d1b5b8bb839d6295f91e7b19f8ad369ca278a651164d4ed8f27b5b06ca3c1"
RECORDED_FIXTURE = Path(__file__).with_name("fixtures") / "information_localization_live_1374.json"


def _recorded_fixture() -> dict:
    return json.loads(RECORDED_FIXTURE.read_text(encoding="utf-8"))


def _entry(key: str, *, value_hex: str | None = None, status: str = "observed") -> dict:
    if status == "unknown":
        return {"key": key, "status": "unknown", "unknown_reason": "localization_key_not_found"}
    if value_hex is None:
        raw = key.encode("utf-8")
        value_hex = raw.hex()
    return {
        "key": key,
        "status": "observed",
        "value_hex": value_hex,
        "byte_length": len(bytes.fromhex(value_hex)),
    }


def _report(
    keys: list[str],
    *,
    context: dict = CONTEXT,
    language: str = "l_english",
    entries: dict[str, dict] | None = None,
) -> dict:
    values = {key: _entry(key) for key in keys} if entries is None else entries
    game_date = context["game_date"]
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "localization-profile-sha"},
        "probe_script_sha256": "localization-probe-sha",
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
        "before": {"status": "observed", "game_date": {"raw": game_date}},
        "after": {"status": "observed", "game_date": {"raw": game_date}},
        "language": {"status": "observed", "text": language},
        "entries": values,
        "cleanup": {"handle_close": {"closed": True}},
    }


def _assert_code(error: pytest.ExceptionInfo[InformationError], code: str) -> None:
    assert error.value.code == code


def test_literal_chinese_eu4_escape_is_decoded_without_guessing() -> None:
    report = _report(["first_title"], entries={
        "first_title": _entry("first_title", value_hex=CN_ESCAPE_HEX),
    })

    normalized = NativeMissionReader.normalize_localization(
        report, CONTEXT, ["first_title"], "eu4_escape"
    )

    assert normalized["status"] == "known"
    assert normalized["language"] == "l_english"
    assert normalized["entries"]["first_title"]["status"] == "known"
    assert normalized["entries"]["first_title"]["text"] == "解放诺曼底"


def test_dynamic_template_is_unknown_and_has_no_resolved_text() -> None:
    template = "[Root.GetSelectableMissionTitle]"
    report = _report(["dynamic_title"], entries={
        "dynamic_title": _entry("dynamic_title", value_hex=template.encode().hex()),
    })

    normalized = NativeMissionReader.normalize_localization(
        report, CONTEXT, ["dynamic_title"], "utf8"
    )
    value = normalized["entries"]["dynamic_title"]

    assert value["status"] == "unknown"
    assert value["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"
    assert value["template"] == template
    assert "text" not in value


def test_recorded_native_fixture_normalizes_literal_and_template_counts() -> None:
    fixture = _recorded_fixture()
    report = fixture["native_capture"]
    context = fixture["original_context"]
    keys = report["request"]["keys"]

    assert fixture["provenance"]["mode"] == "recorded"
    assert fixture["provenance"]["original_mode"] == "live"
    assert fixture["provenance"]["source_sha256"] == RECORDED_SOURCE_SHA256
    assert fixture["provenance"]["read_only"] is True
    normalized = NativeMissionReader.normalize_localization(
        report, context, keys, fixture["provenance"]["native_text_codec"]
    )

    values = normalized["entries"]
    assert len(values) == 122
    assert sum(value["status"] == "known" for value in values.values()) == 102
    assert sum(value["status"] == "unknown" for value in values.values()) == 20
    assert normalized["language"] == "l_english"
    assert values["fra_liberate_norm_title"]["text"] == "解放诺曼底"
    assert values["fra_branch_mission_1_5_title"]["status"] == "unknown"
    assert "text" not in values["fra_branch_mission_1_5_title"]
    assert normalized["provenance"]["session_id"] == fixture["provenance"]["session_id"]
    assert normalized["provenance"]["game_date"] == fixture["provenance"]["game_date"]


@pytest.mark.parametrize("guard", ["static_contract_guard", "file_code_guard", "runtime_code_guard"])
def test_recorded_native_fixture_rejects_mutated_guard(guard: str) -> None:
    fixture = _recorded_fixture()
    report = deepcopy(fixture["native_capture"])
    report[guard]["status"] = "unknown"

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(
            report,
            fixture["original_context"],
            report["request"]["keys"],
            fixture["provenance"]["native_text_codec"],
        )

    _assert_code(caught, "localization_snapshot_incomplete")


def test_missing_requested_key_is_rejected() -> None:
    report = _report(["present"], entries={})

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["present"], "utf8")

    _assert_code(caught, "localization_snapshot_incomplete")


def test_entry_key_identity_is_rejected() -> None:
    report = _report(["present"])
    report["entries"]["present"]["key"] = "other"

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["present"], "utf8")

    _assert_code(caught, "localization_snapshot_invalid")


@pytest.mark.parametrize(
    "label",
    ["status", "read_only", "binding", "session", "process_hash", "country"],
)
def test_identity_and_read_contract_fail_closed(label: str) -> None:
    report = _report(["key"])
    if label == "status":
        report["status"] = "unknown"
    elif label == "read_only":
        report["read_only"] = False
    elif label == "binding":
        report["identity"]["binding_verified"] = False
    elif label == "session":
        report["identity"]["installation_session_id"] = "other-session"
    elif label == "process_hash":
        report["identity"]["process_path_sha256"] = "other-game"
    else:
        report["request"]["country"] = "ENG"

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_incomplete")


@pytest.mark.parametrize("guard", ["static_contract_guard", "file_code_guard", "runtime_code_guard"])
def test_any_code_guard_failure_is_rejected(guard: str) -> None:
    report = _report(["key"])
    report[guard]["status"] = "unknown"

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_incomplete")


def test_cleanup_failure_is_rejected() -> None:
    report = _report(["key"])
    report["cleanup"]["handle_close"]["closed"] = False

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_incomplete")


@pytest.mark.parametrize("which", ["before", "after"])
def test_date_change_in_either_pass_is_rejected(which: str) -> None:
    report = _report(["key"])
    report[which]["game_date"]["raw"] = "1444.01.02"

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_context_changed")


@pytest.mark.parametrize("field", ["performed", "consistent"])
def test_double_pass_must_be_observed_and_consistent(field: str) -> None:
    report = _report(["key"])
    report["doublepass"][field] = False

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_incomplete")


def test_observed_value_byte_length_mismatch_is_rejected() -> None:
    report = _report(["key"])
    report["entries"]["key"]["byte_length"] += 1

    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_invalid")


def test_unknown_key_preserves_unknown_without_inventing_text() -> None:
    report = _report(["missing"], entries={
        "missing": _entry("missing", status="unknown"),
    })

    normalized = NativeMissionReader.normalize_localization(
        report, CONTEXT, ["missing"], "utf8"
    )

    assert normalized["entries"]["missing"] == {
        "status": "unknown",
        "reason": "localization_key_not_found",
    }
    assert "text" not in normalized["entries"]["missing"]


@pytest.mark.parametrize("codec", [None, "utf16", "guess"])
def test_normalize_requires_an_explicit_supported_codec(codec: object) -> None:
    report = _report(["key"])

    with pytest.raises(ValueError):
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], codec)


class _Session:
    def __init__(self, directory: Path, codec: object) -> None:
        self.directory = directory
        self.record = {"native_text_codec": codec}


class _Source:
    def __init__(self, directory: Path, *, codec: object, refreshed: dict | None = None) -> None:
        self.session = _Session(directory, codec)
        self._refreshed = deepcopy(refreshed or CONTEXT)

    def context(self) -> dict:
        return deepcopy(self._refreshed)


@pytest.mark.parametrize("codec", [None, "utf16"])
def test_localized_text_rejects_missing_or_invalid_session_codec(tmp_path: Path, codec: object) -> None:
    source = _Source(tmp_path, codec=codec)
    calls: list[list[str]] = []

    def capture(_installation: Path, _country: str, keys: list[str]) -> dict:
        calls.append(keys)
        return _report(keys)

    reader = NativeMissionReader(source, localization_capture=capture)
    with pytest.raises(InformationError) as caught:
        reader.localized_text("FRA", CONTEXT, ["key"])

    _assert_code(caught, "localization_codec_unconfigured")
    assert calls == []


def test_localized_text_splits_129_keys_into_bounded_batches(tmp_path: Path) -> None:
    source = _Source(tmp_path, codec="utf8")
    keys = [f"key_{index}" for index in range(129)]
    calls: list[list[str]] = []

    def capture(_installation: Path, _country: str, requested: list[str]) -> dict:
        calls.append(list(requested))
        return _report(requested)

    normalized = NativeMissionReader(source, localization_capture=capture).localized_text(
        "FRA", CONTEXT, keys
    )

    assert normalized["status"] == "known"
    assert list(normalized["entries"]) == keys
    assert [len(batch) for batch in calls] == [128, 1]
    assert len(normalized["provenance"]["batches"]) == 2


def test_localized_text_rejects_language_change_between_batches(tmp_path: Path) -> None:
    source = _Source(tmp_path, codec="utf8")
    keys = [f"key_{index}" for index in range(129)]
    calls = 0

    def capture(_installation: Path, _country: str, requested: list[str]) -> dict:
        nonlocal calls
        calls += 1
        return _report(requested, language="l_english" if calls == 1 else "l_french")

    with pytest.raises(InformationError) as caught:
        NativeMissionReader(source, localization_capture=capture).localized_text(
            "FRA", CONTEXT, keys
        )

    _assert_code(caught, "localization_language_changed")
    assert calls == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "paused"),
        ("mode", "recorded"),
        ("session_id", "other-session"),
        ("game_sha256", "other-game"),
        ("observer", "ENG"),
        ("game_date", "1444.01.02"),
    ],
)
def test_localized_text_rejects_context_change_after_capture(
    tmp_path: Path, field: str, value: str,
) -> None:
    refreshed = deepcopy(CONTEXT)
    refreshed[field] = value
    source = _Source(tmp_path, codec="utf8", refreshed=refreshed)

    def capture(_installation: Path, _country: str, requested: list[str]) -> dict:
        return _report(requested)

    with pytest.raises(InformationError) as caught:
        NativeMissionReader(source, localization_capture=capture).localized_text(
            "FRA", CONTEXT, ["key"]
        )

    _assert_code(caught, "localization_context_changed")


def test_template_decoder_still_reports_no_text_for_unresolved_marker() -> None:
    value = decode_template("Hello $NAME$".encode().hex(), "utf8")
    assert value["status"] == "unknown"
    assert "text" not in value


@pytest.mark.parametrize("keys", [[], [[]]])
def test_normalize_rejects_empty_or_non_string_key_batches(keys: list) -> None:
    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(_report(["key"]), CONTEXT, keys, "utf8")

    _assert_code(caught, "localization_keys_invalid")


def test_empty_batch_with_missing_codec_does_not_guess_a_codec() -> None:
    with pytest.raises(ValueError):
        NativeMissionReader.normalize_localization(_report(["key"]), CONTEXT, [], None)


@pytest.mark.parametrize("report", [None, {"identity": "not-an-object"}])
def test_missing_or_nested_malformed_report_is_rejected(report: object) -> None:
    with pytest.raises(InformationError) as caught:
        NativeMissionReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, "localization_snapshot_invalid")


class _BadLocalizedReader:
    def __init__(self, state: State) -> None:
        self.state = state

    def __call__(self, country: str) -> dict:
        return self.state.capture(country)

    def localized_text(self, _country: str, _context: dict, keys: list[str]) -> dict:
        return {
            "status": "known",
            "entries": {
                key: {"status": "unknown", "text": "must-not-survive"}
                for key in keys
            },
            "language": "l_english",
            "provenance": {"reader": "fake"},
        }


def test_mission_source_rejects_unknown_localized_entry_with_text() -> None:
    state, definitions = State(), Definitions()
    state.sample["loaded_tasks"] = {
        "status": "known",
        "roots": [{"root_id": "loaded", "task_ids": ["first"]}],
    }
    reader = _BadLocalizedReader(state)
    source = MissionInformationSource(state, definitions, reader)

    result = source.read(query("M01", ["name"]), state.context())

    assert result["fields"]["name"] == {
        "status": "unavailable",
        "reason": "localization_snapshot_invalid",
    }
