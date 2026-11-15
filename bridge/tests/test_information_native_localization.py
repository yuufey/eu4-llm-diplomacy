"""Narrow contracts for the mission-independent native localization reader."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.model import InformationError
from bridge.information.native_localization import NativeLocalizationReader


CONTEXT = {
    "status": "ready",
    "mode": "live",
    "session_id": "neutral-localization-1",
    "game_sha256": "game-sha-neutral-1",
    "observer": "FRA",
    "game_date": "1444.01.01",
}


class _Session:
    def __init__(self, directory: Path, codec: object = "utf8") -> None:
        self.directory = directory
        self.record = {"native_text_codec": codec}


class _Source:
    def __init__(self, directory: Path, *, codec: object = "utf8",
                 refreshed: dict | None = None) -> None:
        self.session = _Session(directory, codec)
        self._refreshed = deepcopy(refreshed or CONTEXT)
        self.context_calls = 0

    def context(self) -> dict:
        self.context_calls += 1
        return deepcopy(self._refreshed)


def _entry(key: str, *, text: str | None = None,
           status: str = "observed", unknown_reason: str | None = None) -> dict:
    if status == "unknown":
        return {
            "key": key,
            "status": "unknown",
            "unknown_reason": unknown_reason or "localization_key_not_found",
        }
    value_hex = (text if text is not None else key).encode("utf-8").hex()
    return {
        "key": key,
        "status": "observed",
        "value_hex": value_hex,
        "byte_length": len(bytes.fromhex(value_hex)),
    }


def _report(keys: list[str], *, language: str = "l_english",
            entries: dict[str, dict] | None = None,
            context: dict = CONTEXT) -> dict:
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "neutral-profile-sha"},
        "probe_script_sha256": "neutral-probe-sha",
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
        "before": {"status": "observed", "game_date": {"raw": context["game_date"]}},
        "after": {"status": "observed", "game_date": {"raw": context["game_date"]}},
        "language": {"status": "observed", "text": language},
        "entries": entries if entries is not None else {key: _entry(key) for key in keys},
        "cleanup": {"handle_close": {"closed": True}},
    }


def _capture_factory(*, language: str = "l_english", entries: dict[str, dict] | None = None,
                     calls: list[list[str]] | None = None):
    def capture(_installation: Path, country: str, keys: list[str]) -> dict:
        assert country == "FRA"
        if calls is not None:
            calls.append(list(keys))
        selected = {
            key: deepcopy(entries[key]) for key in keys
            if entries is not None and key in entries
        }
        for key in keys:
            selected.setdefault(key, _entry(key))
        return _report(keys, language=language, entries=selected)

    return capture


def _assert_code(caught: pytest.ExceptionInfo[InformationError], code: str) -> None:
    assert caught.value.code == code


def test_literal_decoder_preserves_known_missing_and_dynamic_entries(tmp_path: Path) -> None:
    entries = {
        "literal": _entry("literal", text="解放诺曼底"),
        "missing": _entry("missing", status="unknown"),
        "dynamic": _entry("dynamic", text="[Root.GetName]"),
    }
    reader = NativeLocalizationReader(
        _Source(tmp_path),
        capture=_capture_factory(entries=entries),
    )

    result = reader.localized_text("FRA", CONTEXT, ["literal", "missing", "dynamic"])

    assert result["status"] == "known"
    assert result["language"] == "l_english"
    assert result["entries"]["literal"]["text"] == "解放诺曼底"
    assert result["entries"]["missing"] == {
        "status": "unknown",
        "reason": "localization_key_not_found",
    }
    assert result["entries"]["dynamic"]["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"
    assert "text" not in result["entries"]["dynamic"]
    assert "custom_text_resolution" not in result["provenance"]


def test_neutral_reader_does_not_invoke_mission_capture_or_custom_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bridge.information.custom_localization_memory as custom_memory
    import bridge.information.mission_branch_memory as branch_memory
    import bridge.information.mission_memory as mission_memory

    def fail(*_args, **_kwargs):
        raise AssertionError("mission-specific capture must not run")

    monkeypatch.setattr(mission_memory, "capture", fail)
    monkeypatch.setattr(branch_memory, "capture_inputs", fail)
    monkeypatch.setattr(custom_memory, "capture", fail)
    reader = NativeLocalizationReader(
        _Source(tmp_path),
        capture=_capture_factory(entries={"dynamic": _entry("dynamic", text="[Root.GetName]")}),
    )

    result = reader.localized_text("FRA", CONTEXT, ["dynamic"])

    assert result["entries"]["dynamic"]["status"] == "unknown"
    assert result["entries"]["dynamic"]["reason"] == "DYNAMIC_LOCALIZATION_UNRESOLVED"


@pytest.mark.parametrize("mutation, code", [
    ({"identity": {"binding_verified": False}}, "localization_snapshot_incomplete"),
    ({"request": {"country": "ENG"}}, "localization_snapshot_incomplete"),
    ({"static_contract_guard": {"status": "unknown"}}, "localization_snapshot_incomplete"),
    ({"doublepass": {"performed": True, "consistent": False}}, "localization_snapshot_incomplete"),
    ({"cleanup": {"handle_close": {"closed": False}}}, "localization_snapshot_incomplete"),
    ({"before": {"status": "observed", "game_date": {"raw": "1444.01.02"}}}, "localization_context_changed"),
])
def test_normalizer_rejects_identity_guard_doublepass_cleanup_and_date_failures(
    mutation: dict, code: str,
) -> None:
    report = _report(["key"])
    for key, value in mutation.items():
        report[key] = value

    with pytest.raises(InformationError) as caught:
        NativeLocalizationReader.normalize_localization(report, CONTEXT, ["key"], "utf8")

    _assert_code(caught, code)


@pytest.mark.parametrize("codec", [None, "utf16", "guess"])
def test_codec_must_be_explicit_and_supported(codec: object) -> None:
    with pytest.raises(ValueError):
        NativeLocalizationReader.normalize_localization(_report(["key"]), CONTEXT, ["key"], codec)


def test_reader_splits_batches_and_requires_one_language(tmp_path: Path) -> None:
    keys = [f"key_{index}" for index in range(129)]
    calls: list[list[str]] = []
    reader = NativeLocalizationReader(
        _Source(tmp_path),
        capture=_capture_factory(calls=calls),
    )

    result = reader.localized_text("FRA", CONTEXT, keys)

    assert result["status"] == "known"
    assert list(result["entries"]) == keys
    assert [len(batch) for batch in calls] == [128, 1]
    assert len(result["provenance"]["batches"]) == 2

    calls.clear()
    languages = iter(("l_english", "l_french"))

    def changing_capture(_installation: Path, _country: str, requested: list[str]) -> dict:
        calls.append(list(requested))
        return _report(requested, language=next(languages))

    with pytest.raises(InformationError) as caught:
        NativeLocalizationReader(_Source(tmp_path), capture=changing_capture).localized_text(
            "FRA", CONTEXT, keys,
        )
    _assert_code(caught, "localization_language_changed")
    assert len(calls) == 2


def test_reader_enforces_key_bound_unique_ascii_contract(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    reader = NativeLocalizationReader(_Source(tmp_path), capture=_capture_factory(calls=calls))
    max_keys = [f"key_{index}" for index in range(8192)]

    result = reader.localized_text("FRA", CONTEXT, max_keys)

    assert result["status"] == "known"
    assert len(result["entries"]) == 8192
    assert len(calls) == 64

    for keys in ([], max_keys + ["too_many"], ["dup", "dup"], ["非ASCII"]):
        with pytest.raises(InformationError) as caught:
            reader.localized_text("FRA", CONTEXT, keys)
        _assert_code(caught, "localization_keys_invalid")


def test_reader_rechecks_main_context_after_read(tmp_path: Path) -> None:
    changed = deepcopy(CONTEXT)
    changed["game_date"] = "1444.01.02"
    source = _Source(tmp_path, refreshed=changed)
    reader = NativeLocalizationReader(source, capture=_capture_factory())

    with pytest.raises(InformationError) as caught:
        reader.localized_text("FRA", CONTEXT, ["key"])

    _assert_code(caught, "localization_context_changed")


def test_mission_static_normalizer_entry_remains_the_same_authority() -> None:
    from bridge.information.missions import NativeMissionReader

    report = _report(["key"])
    assert NativeMissionReader.normalize_localization(
        report, CONTEXT, ["key"], "utf8",
    ) == NativeLocalizationReader.normalize_localization(
        report, CONTEXT, ["key"], "utf8",
    )
