"""Offline projection tests for the internally bound estuary reader."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import province_estuaries as estuary_module
from bridge.information.province_estuaries import (
    BASIS,
    FIELD_PREDICATES,
    NativeProvinceEstuaryReader,
)
from bridge.tests import test_information_province_state as g02


PROVINCE_ID = 183
GAME_DATE = g02.make_context()["game_date"]
KEYS = ("river_estuary_modifier", "tagus_estuary_modifier", "mng_bogue_modifier")


def _rule_context(keys=KEYS):
    identity_sha = "d" * 64
    return {
        "schema": "information.province_estuary_static_definition.v1",
        "status": "known",
        "complete": True,
        "game_fact": False,
        "context_scope": "static_rules",
        "rule_name": "has_river_estuary_trigger",
        "configuration_sha256": "a" * 64,
        "definitions_sha256": "b" * 64,
        "scriptedtrigger_ast_sha256": "c" * 64,
        "known_modifier_keys": list(keys),
        "candidate_modifier_keys": list(keys),
        "scriptedtrigger_ast": {"key": "has_river_estuary_trigger", "children": []},
        "configuration_files": [{"path": "game/launcher-settings.json", "sha256": "a" * 64}],
        "enabled_mods": [],
        "definition_files": [{"relative": "common/scripted_triggers/00.txt", "sha256": "b" * 64}],
        "identity": {
            "algorithm": "SHA-256",
            "before_sha256": identity_sha,
            "after_sha256": identity_sha,
            "current_sha256": identity_sha,
            "stable_before_after": True,
        },
        "script_parser": {"status": "ready", "semantics": "syntax_only"},
        "reasons": [],
    }


class _RuleSource:
    def __init__(self, context=None):
        self.current = deepcopy(context or _rule_context())

    def context(self):
        return deepcopy(self.current)

    def drift(self):
        self.current["configuration_sha256"] = "e" * 64
        self.current["identity"].update({
            "before_sha256": "f" * 64,
            "after_sha256": "f" * 64,
            "current_sha256": "f" * 64,
            "stable_before_after": True,
        })


def _predicate_field(predicates):
    known_count = sum(item.get("status") == "known" for item in predicates.values())
    status = "known" if known_count == len(predicates) else ("partial" if known_count else "unknown")
    return {
        "status": status,
        "complete": False,
        "basis": "native_has_province_modifier_predicates",
        "value": {"predicates": deepcopy(predicates)},
        "raw_inputs": {"private_marker": "RAW_MEMORY_MUST_NOT_ESCAPE", "address": "0x12345678"},
    }


def _gate(*, admitted=True, discovered=True, observer="FRA"):
    return {
        "admission": {
            "status": "known",
            "admitted": admitted,
            "observer_nonplayer_role": {"observer": observer, "verified": True},
        },
        "discovery": {"status": "known", "value": discovered},
    }


def _report(
    predicates=None,
    *,
    province_id=PROVINCE_ID,
    observer="FRA",
    backend_observer=None,
    admitted=True,
    discovered=True,
    consistency="stable",
    date_before=GAME_DATE,
    date_after=GAME_DATE,
    access=None,
):
    if predicates is None:
        predicates = {
            key: {"status": "known", "value": False}
            for key in KEYS
        }
    gates = _gate(admitted=admitted, discovered=discovered, observer=observer)
    target = {
        "province_id": province_id,
        "admission_by_pass": {phase: deepcopy(gates["admission"]) for phase in ("pass1", "pass2")},
        "discovery_by_pass": {phase: deepcopy(gates["discovery"]) for phase in ("pass1", "pass2")},
        "fields": {FIELD_PREDICATES: _predicate_field(predicates)},
        "field_consistency": {FIELD_PREDICATES: {"status": consistency}},
    }
    inner = {
        "schema": "information.province_modifiers_observer_snapshot.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "stable": True,
            "context_before": {"game_date": date_before},
            "context_after": {"game_date": date_after},
            "backend": {
                "status": "observed",
                "consistency": {"status": "stable"},
                "observer": {"tag": backend_observer or observer},
                "targets": [target],
            },
        },
        "access": access or {
            "read_only": True,
            "native_function_invoked": False,
            "writes": False,
            "UI_control": False,
            "date_advance": False,
            "save_or_reload": False,
            "limit_bytes": 262144,
            "calls": 1,
            "bytes_requested": 8,
        },
        "raw_reads": [{"size": 8, "address": "0x12345678", "raw_hex": "00" * 8}],
    }
    return {
        "schema": "information.province_modifiers_capture.v1",
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "modifier_keys": list(KEYS),
        "capture": inner,
    }


def _source(tmp_path, monkeypatch, *, rule=None, report=None, capture_error=None, after_capture=None,
            validator=True, observer="FRA"):
    base = g02.Base(tmp_path, g02.make_context(observer=observer))
    rules = rule or _RuleSource()
    result_report = deepcopy(report if report is not None else _report())
    calls = {"capture": [], "validate": []}

    def capture(installation, *, province_id, keys, observer):
        calls["capture"].append((installation, province_id, tuple(keys), observer))
        if after_capture is not None:
            after_capture(base, rules)
        if capture_error is not None:
            raise capture_error
        return deepcopy(result_report)

    def validate_capture(report_arg, context_arg, creation, province_id, keys):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id, tuple(keys)))
        return validator

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(estuary_module, "import_module", lambda _name, _package: validator_module)
    return NativeProvinceEstuaryReader(base, rules, capture=capture), base, rules, calls


@pytest.mark.parametrize(
    ("predicates", "expected_status", "expected_value", "matched", "unknown"),
    [
        (
            {
                KEYS[0]: {"status": "known", "value": True},
                KEYS[1]: {"status": "known", "value": False},
                KEYS[2]: {"status": "unknown", "reason": "leaf_failed"},
            },
            "known", True, [KEYS[0]], [KEYS[2]],
        ),
        (
            {key: {"status": "known", "value": False} for key in KEYS},
            "known", False, [], [],
        ),
        (
            {
                KEYS[0]: {"status": "known", "value": False},
                KEYS[1]: {"status": "unknown", "reason": "leaf_failed"},
                KEYS[2]: {"status": "known", "value": False},
            },
            "unknown", None, [], [KEYS[1]],
        ),
    ],
)
@pytest.mark.parametrize("observer", ("FRA", "TUR"))
def test_or_classification_preserves_unknowns_and_only_emits_typed_values(
    tmp_path, monkeypatch, predicates, expected_status, expected_value, matched, unknown, observer,
):
    report = _report(predicates, observer=observer)
    source, base, rules, calls = _source(tmp_path, monkeypatch, report=report, observer=observer)

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == expected_status
    if expected_value is not None:
        assert type(result["value"]) is bool
        assert result["value"] is expected_value
    else:
        assert "value" not in result
    assert result["matched_modifier_keys"] == matched
    assert result["unknown_modifier_keys"] == unknown
    assert result["basis"] == BASIS
    assert result["partial"] is True and result["complete"] is False
    assert result["game_fact"] is False
    assert result["engine_loaded_rule_verified"] is False
    assert result["rule_binding"] == rules.context()
    assert result["source"]["provenance"]["observer"] == observer
    assert result["source"]["provenance"]["session_id"] == base.current["session_id"]
    assert result["source"]["provenance"]["game_date"] == GAME_DATE
    assert result["source"]["provenance"]["province_id"] == PROVINCE_ID
    assert result["source"]["provenance"]["read_only"] is True
    assert result["source"]["provenance"]["native_function_invoked"] is False
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
    assert calls["capture"] == [
        (tmp_path / "installation.json", PROVINCE_ID, KEYS, observer)
    ]
    assert calls["validate"][0][2:] == (g02.CREATION, PROVINCE_ID, KEYS)
    assert "RAW_MEMORY_MUST_NOT_ESCAPE" not in repr(result)
    assert "0x12345678" not in repr(result)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda report: report["capture"]["observation"]["backend"]["targets"][0][
            "admission_by_pass"]["pass2"].update(admitted=False),
         "PROVINCE_ESTUARY_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
        (lambda report: report["capture"]["observation"]["backend"]["targets"][0][
            "discovery_by_pass"]["pass1"].update(value=False),
         "PROVINCE_ESTUARY_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
        (lambda report: report["capture"]["observation"]["backend"]["targets"][0][
            "field_consistency"][FIELD_PREDICATES].update(status="changed"),
         "PROVINCE_ESTUARY_FIELD_NOT_STABLE"),
        (lambda report: report["capture"]["access"].update(writes=True),
         "PROVINCE_ESTUARY_CAPTURE_UNVERIFIED"),
        (lambda report: report["object"].update(province_id=184),
         "PROVINCE_ESTUARY_CAPTURE_PROVINCE_MISMATCH"),
    ],
)
def test_strict_capture_admission_discovery_and_access_gates(
    tmp_path, monkeypatch, mutate, reason,
):
    report = _report()
    mutate(report)
    source, base, _rules, calls = _source(tmp_path, monkeypatch, report=report)

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "value" not in result
    assert "RAW_MEMORY_MUST_NOT_ESCAPE" not in repr(result)
    assert calls["validate"] == []


def test_integer_predicate_value_is_not_coerced_to_boolean(tmp_path, monkeypatch):
    predicates = {key: {"status": "known", "value": False} for key in KEYS}
    predicates[KEYS[0]] = {"status": "known", "value": 1}
    source, base, _rules, _calls = _source(tmp_path, monkeypatch, report=_report(predicates))

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["unknown_modifier_keys"] == list(KEYS)
    assert "0x12345678" not in repr(result)


def test_live_context_and_session_identity_changes_retract_capture(tmp_path, monkeypatch):
    stale_context = g02.make_context()
    source, base, _rules, calls = _source(tmp_path, monkeypatch)
    base.current["game_date"] += 1
    stale = source.read(PROVINCE_ID, stale_context)
    assert stale["status"] == "unavailable"
    assert stale["reason"] == "PROVINCE_ESTUARY_CONTEXT_STALE"
    assert calls["capture"] == []

    session_dir = tmp_path / "session-drift"
    session_dir.mkdir()

    def drift_session(base_source, _rules):
        base_source.session.record["creation_filetime"] += 1

    source, base, _rules, calls = _source(session_dir, monkeypatch, after_capture=drift_session)
    result = source.read(PROVINCE_ID, base.context())
    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_ESTUARY_SESSION_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == []


def test_live_context_date_change_during_capture_is_unavailable(tmp_path, monkeypatch):
    def drift_date(base_source, _rules):
        base_source.current["game_date"] += 1

    source, base, _rules, calls = _source(tmp_path, monkeypatch, after_capture=drift_date)
    result = source.read(PROVINCE_ID, base.context())
    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_ESTUARY_CONTEXT_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == []


def test_rule_binding_must_be_complete_and_stable_before_capture(tmp_path, monkeypatch):
    bad_rule = _rule_context()
    bad_rule["identity"]["current_sha256"] = "e" * 64
    source, base, _rules, calls = _source(tmp_path, monkeypatch, rule=_RuleSource(bad_rule))

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_ESTUARY_RULE_BINDING_INVALID"
    assert calls["capture"] == []


def test_rule_context_drift_during_capture_is_unavailable(tmp_path, monkeypatch):
    def drift_rule(_base, rules):
        rules.drift()

    source, base, _rules, calls = _source(tmp_path, monkeypatch, after_capture=drift_rule)
    result = source.read(PROVINCE_ID, base.context())
    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_ESTUARY_RULE_CHANGED_DURING_CAPTURE"
    assert result["rule_binding"]["configuration_sha256"] == "a" * 64
    assert calls["validate"] == []


def test_capture_exception_and_validator_rejection_do_not_leak_details(tmp_path, monkeypatch):
    source, base, _rules, _calls = _source(
        tmp_path, monkeypatch, capture_error=OSError("private address 0x12345678")
    )
    failed = source.read(PROVINCE_ID, base.context())
    assert failed["status"] == "unknown"
    assert failed["reason"] == "PROVINCE_ESTUARY_CAPTURE_FAILED"
    assert "0x12345678" not in repr(failed)

    reject_dir = tmp_path / "validator-reject"
    reject_dir.mkdir()
    source, base, _rules, calls = _source(reject_dir, monkeypatch, validator=False)
    rejected = source.read(PROVINCE_ID, base.context())
    assert rejected["status"] == "unknown"
    assert rejected["reason"] == "PROVINCE_ESTUARY_CAPTURE_INVALID"
    assert calls["validate"]
    assert "raw_inputs" not in repr(rejected)


def test_modifier_keys_and_report_keys_are_exactly_bound(tmp_path, monkeypatch):
    bad_rule = _rule_context(["river_estuary_modifier", "river_estuary_modifier"])
    source, base, _rules, calls = _source(tmp_path, monkeypatch, rule=_RuleSource(bad_rule))
    invalid_rule = source.read(PROVINCE_ID, base.context())
    assert invalid_rule["status"] == "unavailable"
    assert calls["capture"] == []

    report_dir = tmp_path / "report-keys"
    report_dir.mkdir()
    report = _report()
    report["modifier_keys"] = list(reversed(KEYS))
    source, base, _rules, _calls = _source(report_dir, monkeypatch, report=report)
    mismatched = source.read(PROVINCE_ID, base.context())
    assert mismatched["status"] == "unknown"
    assert mismatched["reason"] == "PROVINCE_ESTUARY_CAPTURE_KEYS_MISMATCH"


def test_source_header_matches_known_classification_and_provenance(tmp_path, monkeypatch):
    predicates = {key: {"status": "known", "value": False} for key in KEYS}
    predicates[KEYS[0]] = {"status": "known", "value": True}
    source, base, _rules, _calls = _source(tmp_path, monkeypatch, report=_report(predicates))

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == "known"
    assert result["source"]["status"] == "observed"
    assert result["source"]["observer"] == result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["session_id"] == result["source"]["provenance"]["session_id"]
    assert result["source"]["session_id"] == base.current["session_id"]


def test_unavailable_source_header_does_not_claim_observed(tmp_path, monkeypatch):
    bad_rule = _rule_context()
    bad_rule["identity"]["current_sha256"] = "e" * 64
    source, base, _rules, calls = _source(tmp_path, monkeypatch, rule=_RuleSource(bad_rule))

    result = source.read(PROVINCE_ID, base.context())

    assert result["status"] == "unavailable"
    assert result["source"]["status"] == "unavailable"
    assert result["source"]["observer"] == "FRA"
    assert result["source"]["session_id"] == base.current["session_id"]
    assert calls["capture"] == []
