"""Integration tests for bounded custom mission-text derivation.

The captures in this module are deliberately injected.  They exercise the
real ``NativeMissionReader.localized_text`` path and the public mission
adapter without opening a game process or relying on the recorded research
reports.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.mission_custom_texts import WHOLE_TEMPLATES
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.information.model import InformationError
from bridge.tests.test_information_missions import Definitions, query


CONTEXT = {
    "status": "ready",
    "mode": "live",
    "session_id": "custom-integration-session",
    "game_sha256": "custom-integration-game",
    "observer": "FRA",
    "game_version": "1.37.4",
    "game_date": 56553384,
}


def _entry(key: str, *, text: str | None = None, value_hex: str | None = None,
           status: str = "observed", reason: str = "localization_key_not_found") -> dict:
    if status == "unknown":
        return {"key": key, "status": "unknown", "unknown_reason": reason}
    if value_hex is None:
        value_hex = (key if text is None else text).encode("utf-8").hex()
    return {
        "key": key,
        "status": "observed",
        "value_hex": value_hex,
        "byte_length": len(bytes.fromhex(value_hex)),
    }


def _cache_report(keys: list[str], context: dict, *, language: str = "l_english",
                  entries: dict[str, dict] | None = None) -> dict:
    values = {key: _entry(key) for key in keys} if entries is None else deepcopy(entries)
    game_date = context["game_date"]
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "custom-cache-profile"},
        "probe_script_sha256": "custom-cache-probe",
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


def _selection(**changes: object) -> dict:
    value = {
        "status": "observed",
        "kind": "single_unconditional_positive_weight",
        "option_count": 1,
        "predicate_count": 0,
        "weight": 1000,
        "modifiers_empty": True,
        "random_flag": 1,
        "builtin_name_absent": True,
        "root_promotion_enum": 3,
        "derived_for_query_country_root": True,
        "ui_root_scope_verified": False,
    }
    value.update(changes)
    return value


def _compiled_method(name: str, *, key: str | None = None, unknown: bool = False) -> dict:
    if unknown:
        return {
            "name": name,
            "status": "unknown",
            "text_key": None,
            "selection": {"status": "unknown", "unknown_reason": "predicate_unknown"},
            "unknown_reason": "predicate_unknown",
        }
    if key is None:
        key = "COMPILED_TITLE_KEY" if name.endswith("Title") else "COMPILED_DESCRIPTION_KEY"
    return {
        "name": name,
        "status": "observed",
        "text_key": {
            "status": "observed",
            "complete": True,
            "text": key,
            "raw_hex": key.encode("ascii").hex(),
        },
        "selection": _selection(),
    }


def _custom_report(methods: dict[str, dict], context: dict) -> dict:
    game_date = context["game_date"]
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "custom-method-profile"},
        "probe_script_sha256": "custom-method-probe",
        "identity": {
            "binding_verified": True,
            "installation_session_id": context["session_id"],
            "process_path_sha256": context["game_sha256"],
        },
        "request": {"country": "FRA", "methods": list(methods)},
        "query_scope": {
            "country": "FRA",
            "root_kind": "country",
            "binding": "explicit_query_observer",
            "ui_root_scope_verified": False,
        },
        "static_contract_guard": {"status": "observed"},
        "file_code_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "doublepass": {"performed": True, "consistent": True},
        "before": {"status": "observed", "game_date": {"raw": game_date}},
        "after": {"status": "observed", "game_date": {"raw": game_date}},
        "cleanup": {"handle_close": {"closed": True}},
        "methods": deepcopy(methods),
    }


def _dynamic(key: str, method: str, *, codec: str = "utf8",
             prefix: str = "", suffix: str = "") -> dict:
    template = f"{prefix}{WHOLE_TEMPLATES[method]}{suffix}"
    value = _entry(key, value_hex=template.encode("utf-8").hex())
    # ``_entry`` is an observed native record; decoding it produces the
    # unresolved value consumed by ``_resolve_custom_templates``.
    return value


class _Session:
    def __init__(self, directory: Path, codec: str = "utf8") -> None:
        self.directory = directory
        self.record = {"native_text_codec": codec}


class _Source:
    """Primary source shell with no process access."""

    event_types = ()

    def __init__(self, directory: Path, *, context: dict | None = None,
                 context_sequence: list[dict] | None = None) -> None:
        self.session = _Session(directory)
        self._context = deepcopy(context or CONTEXT)
        self._sequence = [deepcopy(item) for item in context_sequence] if context_sequence else None
        self._context_calls = 0

    def context(self) -> dict:
        if self._sequence:
            value = self._sequence[min(self._context_calls, len(self._sequence) - 1)]
            self._context_calls += 1
            return deepcopy(value)
        return deepcopy(self._context)

    def catalog(self) -> list[dict]:
        from bridge.information.catalog import list_topics
        return list_topics()

    def read(self, query_value: dict, context: dict) -> dict:
        raise AssertionError(f"unexpected primary read: {query_value!r} {context!r}")

    def poll_events(self, context: dict, cursor: dict | None) -> dict:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class _CaptureHarness:
    def __init__(self, context: dict, initial_entries: dict[str, dict],
                 selected_entries: dict[str, dict] | None = None,
                 methods: dict[str, dict] | None = None,
                 *, initial_language: str = "l_english",
                 selected_language: str = "l_english") -> None:
        self.context = deepcopy(context)
        self.initial_entries = deepcopy(initial_entries)
        self.selected_entries = deepcopy(selected_entries or {})
        self.methods = deepcopy(methods or {
            "GetSelectableMissionTitle": _compiled_method(
                "GetSelectableMissionTitle", key="COMPILED_TITLE_KEY"),
            "GetSelectableMissionDescription": _compiled_method(
                "GetSelectableMissionDescription", key="COMPILED_DESCRIPTION_KEY"),
        })
        self.initial_language = initial_language
        self.selected_language = selected_language
        self.cache_calls: list[list[str]] = []
        self.custom_calls: list[list[str]] = []
        self.custom_mutator = None
        self.selected_mutator = None

    def localization_capture(self, _installation: Path, _country: str,
                             keys: list[str]) -> dict:
        self.cache_calls.append(list(keys))
        is_initial = len(self.cache_calls) == 1
        source = self.initial_entries if is_initial else self.selected_entries
        entries = {key: deepcopy(source[key]) for key in keys if key in source}
        # Missing keys are intentionally represented as unknown native entries
        # so the reader can exercise its ordinary unknown-preservation path.
        for key in keys:
            entries.setdefault(key, _entry(key, status="unknown"))
        report = _cache_report(
            keys,
            self.context,
            language=self.initial_language if is_initial else self.selected_language,
            entries=entries,
        )
        if not is_initial and self.selected_mutator is not None:
            self.selected_mutator(report)
        return report

    def custom_localization_capture(self, _installation: Path, _country: str,
                                    methods: list[str]) -> dict:
        self.custom_calls.append(list(methods))
        report = _custom_report(
            {name: deepcopy(self.methods[name]) for name in methods}, self.context
        )
        if self.custom_mutator is not None:
            self.custom_mutator(report)
        return report


def _reader(tmp_path: Path, harness: _CaptureHarness, *, source: _Source | None = None) -> NativeMissionReader:
    return NativeMissionReader(
        source or _Source(tmp_path),
        localization_capture=harness.localization_capture,
        custom_localization_capture=harness.custom_localization_capture,
    )


def _run(tmp_path: Path, harness: _CaptureHarness, keys: list[str], *, source: _Source | None = None) -> dict:
    source = source or _Source(tmp_path)
    return _reader(tmp_path, harness, source=source).localized_text("FRA", CONTEXT, keys)


def test_literal_and_two_whole_custom_templates_merge_using_compiled_keys(tmp_path: Path) -> None:
    methods = {
        "GetSelectableMissionTitle": _compiled_method(
            "GetSelectableMissionTitle", key="FAKE_COMPILED_TITLE"),
        "GetSelectableMissionDescription": _compiled_method(
            "GetSelectableMissionDescription", key="FAKE_COMPILED_DESCRIPTION"),
    }
    initial = {
        "literal_title": _entry("literal_title", text="字面任务"),
        "dynamic_title": _dynamic("dynamic_title", "GetSelectableMissionTitle"),
        "dynamic_description": _dynamic("dynamic_description", "GetSelectableMissionDescription"),
    }
    selected = {
        "FAKE_COMPILED_TITLE": _entry("FAKE_COMPILED_TITLE", text="派生标题"),
        "FAKE_COMPILED_DESCRIPTION": _entry("FAKE_COMPILED_DESCRIPTION", text="派生说明"),
    }
    harness = _CaptureHarness(CONTEXT, initial, selected, methods)

    result = _run(tmp_path, harness, list(initial))

    assert result["status"] == "known"
    assert result["entries"]["literal_title"]["text"] == "字面任务"
    assert result["entries"]["dynamic_title"]["text"] == "派生标题"
    assert result["entries"]["dynamic_description"]["text"] == "派生说明"
    assert result["entries"]["dynamic_title"]["custom_text_derivation"]["text_key"] == "FAKE_COMPILED_TITLE"
    assert result["entries"]["dynamic_description"]["custom_text_derivation"]["text_key"] == "FAKE_COMPILED_DESCRIPTION"
    assert harness.custom_calls == [["GetSelectableMissionTitle", "GetSelectableMissionDescription"]]
    assert harness.cache_calls[1] == ["FAKE_COMPILED_TITLE", "FAKE_COMPILED_DESCRIPTION"]
    assert "SELECTABLE_MISSION_TITLE" not in harness.cache_calls[1]


def test_selected_cache_keys_are_deduplicated_and_keep_one_language(tmp_path: Path) -> None:
    methods = {
        "GetSelectableMissionTitle": _compiled_method(
            "GetSelectableMissionTitle", key="FAKE_SHARED_KEY"),
        "GetSelectableMissionDescription": _compiled_method(
            "GetSelectableMissionDescription", key="FAKE_SHARED_KEY"),
    }
    initial = {
        "title": _dynamic("title", "GetSelectableMissionTitle"),
        "description": _dynamic("description", "GetSelectableMissionDescription"),
    }
    selected = {"FAKE_SHARED_KEY": _entry("FAKE_SHARED_KEY", text="共享文字")}
    harness = _CaptureHarness(CONTEXT, initial, selected, methods)

    result = _run(tmp_path, harness, list(initial))

    assert harness.custom_calls == [["GetSelectableMissionTitle", "GetSelectableMissionDescription"]]
    assert harness.cache_calls[1] == ["FAKE_SHARED_KEY"]
    assert result["language"] == "l_english"
    assert all(result["entries"][key]["status"] == "known" for key in initial)


def test_fourteen_dynamic_templates_capture_methods_once_and_read_two_keys(tmp_path: Path) -> None:
    keys: list[str] = []
    initial: dict[str, dict] = {}
    for index in range(14):
        method = "GetSelectableMissionTitle" if index % 2 == 0 else "GetSelectableMissionDescription"
        key = f"task_{index}_{'title' if index % 2 == 0 else 'desc'}"
        keys.append(key)
        # The recorded description template has one literal ASCII space before
        # its supported Root token.  Derivation must retain that byte-for-byte.
        prefix = " " if method == "GetSelectableMissionDescription" else ""
        initial[key] = _dynamic(key, method, prefix=prefix)
    methods = {
        "GetSelectableMissionTitle": _compiled_method(
            "GetSelectableMissionTitle", key="COMPILED_T"),
        "GetSelectableMissionDescription": _compiled_method(
            "GetSelectableMissionDescription", key="COMPILED_D"),
    }
    selected = {
        "COMPILED_T": _entry("COMPILED_T", text="标题"),
        "COMPILED_D": _entry("COMPILED_D", text="说明"),
    }
    harness = _CaptureHarness(CONTEXT, initial, selected, methods)

    result = _run(tmp_path, harness, keys)

    assert harness.custom_calls == [["GetSelectableMissionTitle", "GetSelectableMissionDescription"]]
    assert harness.cache_calls == [keys, ["COMPILED_T", "COMPILED_D"]]
    assert all(result["entries"][key]["status"] == "known" for key in keys)
    assert all(
        result["entries"][key]["text"] == ("标题" if key.endswith("_title") else " 说明")
        for key in keys
    )
    assert all(
        result["entries"][key]["custom_text_derivation"]["literal_prefix"]
        == ("" if key.endswith("_title") else " ")
        for key in keys
    )
    assert result["provenance"]["custom_text_resolution"]["derived_count"] == 14
    assert result["provenance"]["custom_text_resolution"]["target_count"] == 14


def test_no_exact_target_template_does_not_capture_custom_methods(tmp_path: Path) -> None:
    initial = {"literal": _entry("literal", text="普通文字")}
    harness = _CaptureHarness(CONTEXT, initial)

    result = _run(tmp_path, harness, ["literal"])

    assert result["entries"]["literal"]["status"] == "known"
    assert harness.custom_calls == []
    assert harness.cache_calls == [["literal"]]
    assert result["provenance"]["custom_text_resolution"] == {"status": "not_requested", "derived_count": 0}


@pytest.mark.parametrize("failure", ["unknown_method", "guard_failure", "selected_cache_failure"])
def test_custom_failures_preserve_ordinary_known_text_and_dynamic_unknown(
    tmp_path: Path, failure: str,
) -> None:
    methods = {
        "GetSelectableMissionTitle": _compiled_method(
            "GetSelectableMissionTitle", key="FAKE_TITLE", unknown=failure == "unknown_method"),
        "GetSelectableMissionDescription": _compiled_method(
            "GetSelectableMissionDescription", key="FAKE_DESCRIPTION"),
    }
    initial = {
        "ordinary": _entry("ordinary", text="普通已知"),
        "dynamic": _dynamic("dynamic", "GetSelectableMissionTitle"),
    }
    selected = {"FAKE_TITLE": _entry("FAKE_TITLE", text="派生标题")}
    harness = _CaptureHarness(CONTEXT, initial, selected, methods)
    if failure == "guard_failure":
        harness.custom_mutator = lambda report: report["static_contract_guard"].update(status="unknown")
    elif failure == "selected_cache_failure":
        harness.selected_mutator = lambda report: report["runtime_code_guard"].update(status="unknown")

    result = _run(tmp_path, harness, list(initial))

    assert result["entries"]["ordinary"]["status"] == "known"
    assert result["entries"]["ordinary"]["text"] == "普通已知"
    assert result["entries"]["dynamic"]["status"] == "unknown"
    assert "text" not in result["entries"]["dynamic"]
    assert harness.custom_calls == [["GetSelectableMissionTitle"]]


def test_selected_cache_language_mismatch_keeps_original_dynamic_template_unknown(tmp_path: Path) -> None:
    initial = {
        "ordinary": _entry("ordinary", text="普通已知"),
        "dynamic": _dynamic("dynamic", "GetSelectableMissionTitle"),
    }
    selected = {"COMPILED_TITLE_KEY": _entry("COMPILED_TITLE_KEY", text="派生标题")}
    harness = _CaptureHarness(
        CONTEXT, initial, selected,
        {"GetSelectableMissionTitle": _compiled_method("GetSelectableMissionTitle")},
        selected_language="l_french",
    )

    result = _run(tmp_path, harness, list(initial))

    assert result["entries"]["ordinary"]["status"] == "known"
    assert result["entries"]["dynamic"]["status"] == "unknown"
    assert "text" not in result["entries"]["dynamic"]
    resolution = result["provenance"]["custom_text_resolution"]
    assert resolution["status"] == "unknown"
    assert resolution["reason"] == "custom_localization_language_changed"


def test_final_base_context_change_rejects_the_combined_result(tmp_path: Path) -> None:
    changed = deepcopy(CONTEXT)
    changed["game_date"] += 1
    # ``localized_text`` gets the caller's snapshot as its context argument;
    # the only base-source context read is the final health refresh.
    source = _Source(tmp_path, context_sequence=[changed])
    initial = {"dynamic": _dynamic("dynamic", "GetSelectableMissionTitle")}
    selected = {"COMPILED_TITLE_KEY": _entry("COMPILED_TITLE_KEY", text="派生标题")}
    harness = _CaptureHarness(
        CONTEXT, initial, selected,
        {"GetSelectableMissionTitle": _compiled_method("GetSelectableMissionTitle")},
    )

    with pytest.raises(InformationError) as caught:
        _run(tmp_path, harness, ["dynamic"], source=source)

    assert caught.value.code == "localization_context_changed"
    assert harness.custom_calls == [["GetSelectableMissionTitle"]]


def test_supported_root_placeholder_with_literal_prefix_suffix_is_derived(tmp_path: Path) -> None:
    initial = {
        "wrapped": _dynamic(
            "wrapped", "GetSelectableMissionTitle",
            prefix="prefix ", suffix=" suffix",
        ),
    }
    selected = {"COMPILED_TITLE_KEY": _entry("COMPILED_TITLE_KEY", text="派生标题")}
    harness = _CaptureHarness(
        CONTEXT, initial, selected,
        {"GetSelectableMissionTitle": _compiled_method("GetSelectableMissionTitle")},
    )

    result = _run(tmp_path, harness, ["wrapped"])

    entry = result["entries"]["wrapped"]
    assert entry["status"] == "known"
    assert entry["text"] == "prefix 派生标题 suffix"
    assert entry["custom_text_derivation"]["literal_prefix"] == "prefix "
    assert entry["custom_text_derivation"]["literal_suffix"] == " suffix"
    assert harness.custom_calls == [["GetSelectableMissionTitle"]]
    assert harness.cache_calls == [["wrapped"], ["COMPILED_TITLE_KEY"]]


def test_mixed_or_multiple_root_templates_are_not_derived(tmp_path: Path) -> None:
    mixed = "prefix [Root.GetSelectableMissionTitle] and [Root.GetName] suffix"
    multiple = "[Root.GetSelectableMissionTitle] / [Root.GetSelectableMissionTitle]"
    other = "[Root.GetName]"
    initial = {
        "mixed": _entry("mixed", value_hex=mixed.encode().hex()),
        "multiple": _entry("multiple", value_hex=multiple.encode().hex()),
        "other": _entry("other", value_hex=other.encode().hex()),
    }
    harness = _CaptureHarness(CONTEXT, initial)

    result = _run(tmp_path, harness, list(initial))

    assert harness.custom_calls == []
    assert harness.cache_calls == [list(initial)]
    for key, template in (("mixed", mixed), ("multiple", multiple), ("other", other)):
        assert result["entries"][key]["status"] == "unknown"
        assert result["entries"][key]["template"] == template
        assert "text" not in result["entries"][key]


def test_selected_text_with_dynamic_marker_does_not_become_known(tmp_path: Path) -> None:
    initial = {"dynamic": _dynamic("dynamic", "GetSelectableMissionTitle")}
    selected = {
        "COMPILED_TITLE_KEY": _entry(
            "COMPILED_TITLE_KEY", text="仍有 $NAME$ 标记"),
    }
    harness = _CaptureHarness(
        CONTEXT, initial, selected,
        {"GetSelectableMissionTitle": _compiled_method("GetSelectableMissionTitle")},
    )

    result = _run(tmp_path, harness, ["dynamic"])

    assert result["entries"]["dynamic"]["status"] == "unknown"
    assert "text" not in result["entries"]["dynamic"]
    assert result["provenance"]["custom_text_resolution"]["derived_count"] == 0


class _MembershipReader:
    supported_countries = ("FRA",)

    def __init__(self, native: NativeMissionReader, state: dict) -> None:
        self.native = native
        self.state = deepcopy(state)

    def __call__(self, country: str) -> dict:
        assert country == "FRA"
        return deepcopy(self.state)

    def localized_text(self, country: str, context: dict, keys: list[str]) -> dict:
        return self.native.localized_text(country, context, keys)


def test_information_service_reports_name_complete_description_partial_and_derived_counts(
    tmp_path: Path,
) -> None:
    initial = {
        "first_title": _entry("first_title", text="字面名称"),
        "second_title": _dynamic("second_title", "GetSelectableMissionTitle"),
        "first_desc": _dynamic("first_desc", "GetSelectableMissionDescription"),
        "second_desc": _entry("second_desc", status="unknown"),
    }
    selected = {
        "COMPILED_TITLE_KEY": _entry("COMPILED_TITLE_KEY", text="派生名称"),
        "COMPILED_DESCRIPTION_KEY": _entry("COMPILED_DESCRIPTION_KEY", text="派生说明"),
    }
    methods = {
        "GetSelectableMissionTitle": _compiled_method(
            "GetSelectableMissionTitle", key="COMPILED_TITLE_KEY"),
        "GetSelectableMissionDescription": _compiled_method(
            "GetSelectableMissionDescription", key="COMPILED_DESCRIPTION_KEY"),
    }
    primary = _Source(tmp_path)
    harness = _CaptureHarness(CONTEXT, initial, selected, methods)
    native = _reader(tmp_path, harness, source=primary)
    membership = _MembershipReader(native, {
        "complete": True,
        "country": "FRA",
        "mode": "live",
        "session_id": CONTEXT["session_id"],
        "game_date": CONTEXT["game_date"],
        "state_kind": "captured_country_mission_slots",
        "mission_slots": [{"slot": 1, "roots": ["loaded"]}],
        "loaded_tasks": {
            "status": "known",
            "roots": [{"root_id": "loaded", "task_ids": ["first", "second"]}],
        },
        "completed_missions": {"status": "known", "task_ids": []},
    })
    adapter = MissionInformationSource(primary, Definitions(), membership)
    service = InformationService(CompositeSource(primary, [adapter]), tmp_path / "custom.db")
    try:
        result = service.query(
            "custom-service",
            queries=[query("M01", ["name", "description"])],
        )
    finally:
        service.close()

    assert result["status"] == "partial"
    assert result["complete"] is False
    fields = result["items"][0]["fields"]
    assert fields["name"]["complete"] is True
    assert fields["name"]["value"]["resolved_count"] == 2
    assert fields["name"]["value"]["unresolved_count"] == 0
    assert fields["name"]["value"]["custom_derived_count"] == 1
    assert fields["description"]["complete"] is False
    assert fields["description"]["value"]["resolved_count"] == 1
    assert fields["description"]["value"]["unresolved_count"] == 1
    assert fields["description"]["value"]["custom_derived_count"] == 1
    assert harness.custom_calls == [["GetSelectableMissionTitle", "GetSelectableMissionDescription"]]
