"""Bounded adapter tests for the native N06 monarch-point projection."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information.country_state import NativeCountryStateSource
from bridge.information.model import InformationError, canonical
from bridge.information.sources import DiplomacySource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_DATE = 56553384
CREATION_FILETIME = 134373102720165920


class _Session:
    observer = "FRA"

    def __init__(self, directory: Path, *, game_sha256: str = GAME_SHA256,
                 after: dict | None = None):
        self.directory = directory
        self.session_id = "37376-1dd639fff00a820"
        self.after = deepcopy(after)
        self.health_calls = 0
        self.record = {
            "observer": "FRA",
            "controlled_countries": ["FRA"],
            "game_sha256": game_sha256,
            "game_version": "1.37.4",
            "session_id": self.session_id,
            "creation_filetime": CREATION_FILETIME,
        }

    def health(self) -> dict:
        self.health_calls += 1
        result = {
            "status": "ready",
            "complete": True,
            "date_raw": GAME_DATE,
            "game_version": "1.37.4",
            "game_sha256": self.record["game_sha256"],
            "observer": "FRA",
            "reasons": [],
        }
        if self.after and self.health_calls >= 2:
            result.update(self.after)
        return result


class _Tools:
    def __init__(self, session: _Session, public: dict | None = None):
        self.session = session
        self.public = public or {
            "actor": "FRA",
            "recipient": "PAP",
            "action_id": "offer_vassalization",
            "family": "vassalization",
            "phase": "initiate",
            "prestige_raw": -11643,
            "prestige_scale": 1000,
        }
        self.inspect_calls: list[tuple] = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase,
                                  parameters):
        self.inspect_calls.append(
            (action_id, actor, recipient, phase, deepcopy(parameters))
        )
        return deepcopy(self.public)


def _report(session: _Session, *, values: dict | None = None,
            mutate: dict | None = None) -> dict:
    values = values or {"administrative": 12, "diplomatic": 34, "military": 56}
    report = {
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "unit": "monarch_points",
        "scale": 1,
        "values": deepcopy(values),
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "installation_session_id": session.session_id,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
        },
        "static_contract_guard": {"status": "observed"},
        "file_code_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "doublepass": {"performed": True, "consistent": True},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": {
            "status": "observed",
            "game_date": {"value": GAME_DATE, "raw_hex": GAME_DATE.to_bytes(4, "little", signed=True).hex()},
        },
        "after": {
            "status": "observed",
            "game_date": {"value": GAME_DATE, "raw_hex": GAME_DATE.to_bytes(4, "little", signed=True).hex()},
        },
        "completed": True,
    }
    if mutate:
        for key, value in mutate.items():
            if isinstance(value, dict) and isinstance(report.get(key), dict):
                report[key].update(deepcopy(value))
            else:
                report[key] = deepcopy(value)
    return report


def _source(tmp_path: Path, *, capture=None, after: dict | None = None,
            game_sha256: str = GAME_SHA256, public: dict | None = None):
    session = _Session(tmp_path, game_sha256=game_sha256, after=after)
    tools = _Tools(session, public=public)
    source = NativeCountryStateSource(
        DiplomacySource(tools), capture=capture,
    )
    return source, session, tools


def _query(fields: list[str], parameters: dict | None = None) -> dict:
    return {
        "topic": "N06",
        "object": {"type": "country", "country": "FRA"},
        "fields": fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_catalog_puts_points_first_and_documents_native_metadata(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path, capture=lambda *_: {})
    topic = next(item for item in source.catalog() if item["topic_id"] == "N06")

    assert list(topic["fields"]) == ["monarch_points", "prestige"]
    assert topic["parameters"]["required"] == []
    assert topic["fields"]["monarch_points"] == {
        "coverage": "available",
        "source": "bridge.information.country_resources_memory.capture",
        "supported_countries": ["FRA"],
        "description": (
            "本国当前行政、外交、军事君主点数；只取固定版本的有界"
            "纯 RPM capture values"
        ),
        "unit": "monarch_points",
        "scale": 1,
        "raw": True,
        "raw_semantics": "values.administrative/diplomatic/military / 1",
        "paths": ["values"],
    }


def test_points_only_uses_installation_capture_and_never_inspect(tmp_path: Path) -> None:
    calls: list[tuple[Path, str]] = []
    source, session, tools = _source(tmp_path)

    def capture(installation: Path, country: str) -> dict:
        calls.append((installation, country))
        return _report(session)

    source.monarch_points_capture = capture
    result = source.read(_query(["monarch_points"]))

    assert result["fields"]["monarch_points"] == {
        "status": "known",
        "value": {"administrative": 12, "diplomatic": 34, "military": 56},
    }
    assert result["complete"] is True
    assert calls == [(tmp_path / "installation.json", "FRA")]
    assert tools.inspect_calls == []
    assert result["source"]["provenance"]["context_guard"]["status"] == "passed"
    assert result["source"]["provenance"]["capture"]["identity"][
        "installation_creation_filetime"
    ] == CREATION_FILETIME


def test_points_capture_provenance_is_compact_and_hashes_full_report(tmp_path: Path) -> None:
    source, session, _ = _source(tmp_path)
    report = _report(session)
    report["probe_script_sha256"] = "a" * 64
    report["profile"] = {
        "path": "country-resources-memory-1374.json",
        "sha256": "b" * 64,
        "max_bytes": 65536,
    }
    report["static_contract_guard"] = {
        "status": "observed", "profile": "profile.json",
        "profile_sha256": "b" * 64, "checks": {"profile": True},
        "source_dependencies": [{"path": "bridge/helper.py", "sha256": "c" * 64}],
        "dependency_hash_checks": {"bridge/helper.py": True},
    }
    report["file_code_guard"] = {
        "status": "observed", "checks": {"reader": True},
        "records": {"reader": {
            "rva": "0x1000", "expected_hex": "aabb", "actual_hex": "aabb",
        }},
    }
    report["runtime_code_guard"] = {
        "status": "observed", "checks": {"reader": True},
        "records": {"reader": {
            "address": {"va": "0x140001000", "rva": "0x1000"},
            "expected_hex": "aabb", "actual_hex": "aabb",
        }},
    }
    for snapshot in (report["before"], report["after"]):
        snapshot["country_scan"] = {
            "status": "observed", "requested_country": "FRA",
            "scanned_entries": 256,
            "country_pointer": {"va": "0x500000"},
            "country_handle": {"value": "0x7a5246", "slot": 122},
            "matches": [{"raw_hex": "deadbeef"}] * 1000,
        }
        snapshot["read_log"] = [{"raw_hex": "deadbeef"}] * 1000
    report["access"] = {
        "rpm_bytes_requested": 4096, "rpm_calls": 20,
        "rpm_total_limit": 524288, "rpm_single_read_limit": 65536,
        "read_log": [{"raw_hex": "deadbeef"}] * 1000,
    }
    expected_hash = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
    source.monarch_points_capture = lambda *_: report

    result = source.read(_query(["monarch_points"]))
    provenance = result["source"]["provenance"]
    compact = provenance["capture"]
    compact_json = canonical(compact)

    assert provenance["capture_report_sha256"] == expected_hash
    assert provenance["capture_report_hash_algorithm"] == (
        "sha256(canonical_json_utf8;information.model.canonical)"
    )
    assert len(compact_json.encode("utf-8")) < 20000
    assert "read_log" not in compact_json
    assert "expected_hex" not in compact_json
    assert "actual_hex" not in compact_json
    assert compact["file_code_guard"]["records"]["reader"][
        "expected_sha256"
    ] == hashlib.sha256(bytes.fromhex("aabb")).hexdigest()
    assert compact["runtime_code_guard"]["records"]["reader"]["rva"] == "0x1000"
    assert compact["before"]["country_scan"]["scanned_entries"] == 256
    assert set(compact["before"]) == {
        "status", "game_date", "country_scan", "values", "value_raw_hex",
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("read_only", False),
        ("native_function_invoked", True),
        ("scale", False),
        ("unit", "ducats"),
        ("completed", False),
        ("doublepass", {"performed": True, "consistent": False}),
        ("cleanup", {"handle_close": {"status": "open"}}),
        ("identity", {"binding_verified": False}),
        ("before", {"game_date": {"value": GAME_DATE + 1, "raw_hex": "0x35f"}}),
    ],
)
def test_points_capture_contract_fail_closed(tmp_path: Path, path: str, value) -> None:
    source, session, _ = _source(
        tmp_path, capture=lambda *_: _report(session, mutate={path: value})
    )
    result = source.read(_query(["monarch_points"]))

    assert result["fields"]["monarch_points"]["status"] == "unknown"
    assert result["complete"] is False


@pytest.mark.parametrize("values", [
    {"administrative": True, "diplomatic": 34, "military": 56},
    {"administrative": 12, "diplomatic": 34},
    {"administrative": 12, "diplomatic": 34, "military": 1 << 31},
])
def test_points_values_require_three_non_bool_ints(tmp_path: Path, values: dict) -> None:
    source, session, _ = _source(
        tmp_path, capture=lambda *_: _report(session, values=values)
    )
    result = source.read(_query(["monarch_points"]))

    assert result["fields"]["monarch_points"] == {
        "status": "unknown", "reason": "MONARCH_POINTS_VALUES_INVALID",
    }


def test_points_requires_live_1374_identity_before_capture(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path, game_sha256="0" * 64,
                           capture=lambda *_: pytest.fail("capture must not run"))

    result = source.read(_query(["monarch_points"]))

    assert result["fields"]["monarch_points"] == {
        "status": "unavailable", "reason": "MONARCH_POINTS_GAME_IDENTITY_MISMATCH",
    }


def test_points_rejects_context_change_after_capture(tmp_path: Path) -> None:
    source, session, _ = _source(tmp_path, after={"date_raw": GAME_DATE + 24})
    source.monarch_points_capture = lambda *_: _report(session)

    result = source.read(_query(["monarch_points"]))

    assert result["fields"]["monarch_points"] == {
        "status": "unknown", "reason": "MONARCH_POINTS_CONTEXT_CHANGED",
    }


def test_prestige_and_mixed_queries_keep_pair_parameter_boundary(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path, capture=lambda *_: {})

    source.validate_query(_query(["monarch_points"]))
    with pytest.raises(InformationError):
        source.validate_query(_query(["prestige"]))
    with pytest.raises(InformationError):
        source.validate_query(_query(["monarch_points", "prestige"]))


def test_mixed_query_keeps_public_prestige_when_native_points_fail(tmp_path: Path) -> None:
    source, session, tools = _source(tmp_path)

    def bad_capture(*_args):
        report = _report(session)
        report["identity"]["binding_verified"] = False
        return report

    source.monarch_points_capture = bad_capture
    result = source.read(_query(
        ["monarch_points", "prestige"], {"reference_recipient": "PAP"}
    ))

    assert result["fields"]["prestige"] == {"status": "known", "value": -11643}
    assert result["fields"]["monarch_points"]["status"] == "unknown"
    assert result["complete"] is False
    assert tools.inspect_calls == [
        ("offer_vassalization", "FRA", "PAP", "initiate", {})
    ]

