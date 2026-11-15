"""Verify the read-only country-relation evidence and offline information catalog.

This checker reads only bounded workspace files.  It validates the native query
report, the periodic adapter acceptance, and the separately typed historical
save cross-check without opening a game process or sending a query.  Catalog
construction is offline: it uses an unbound ``DiplomacySource`` and therefore
does not turn the recorded reports into current state.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import py_compile
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-country-relations-20261024-001"
PREVIOUS = ROOT / "work/runtime/information-dynamic-text-20261024-001/delivery/manifest.json"
PREVIOUS_SHA = "c2feea2e334fb1796541956d440c55237451cf32d49d486b34c7ce06b8b6aafe"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json"
NATIVE_REPORT = STAGE / "native-public-001/report.json"
LIVE_REPORT = STAGE / "live-acceptance-001/report.json"
SAVE_REPORT = STAGE / "save-crosscheck-002.json"
RELATIONS_FIXTURE = ROOT / "bridge/tests/fixtures/information_country_relations_live_1374.json"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024

EXPECTED_GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
EXPECTED_SESSION = "37376-1dd639fff00a820"
EXPECTED_INSTALLATION_SHA = "29bb274f8165d960c10c16ed4fb669c096fd2784b76704bd0876ac3fe4cd3a8c"
EXPECTED_DATE = 56553384
EXPECTED_NATIVE_REPORT_SHA = "a013c3bcdda5c6d1ed480667718138180ace4e0703986c301cb258a997af1686"
EXPECTED_LIVE_REPORT_SHA = "a6c6bdebc434b181a59b8d2ef86d377b30d4787699fd28f6b7d5a156c82357eb"
EXPECTED_SAVE_REPORT_SHA = "f0d29f6ca104389b041376f45740b1e3c5eba887bbb2851a89c85a5105485360"
EXPECTED_SAVE_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
EXPECTED_CONTRACT2_SHA = "ea13b783902b9a5410aa808ae7956e03732fe57376383cd0d4ea094ac9f1a5f7"
CONTRACT2_REL = "work/runtime/information-dynamic-text-20261024-001/dynamic-localization-contract-002.json"
CAPTURE_SCRIPT = ROOT / "work/capture_information_country_relations.py"

SOURCE_FINGERPRINTS = (
    ROOT / "bridge/information/country_state.py",
    ROOT / "bridge/information/subject_relations.py",
    ROOT / "tools/serve_information.py",
)

# These are the fields emitted by the public projection and the native query
# record.  They are deliberately explicit: extra native diagnostic fields do
# not become an unreviewed public contract merely because they happen to match.
PAIR_FIELDS = (
    "action_id", "family", "actor", "recipient", "phase",
    "vassal_state_verified", "vassal_active", "actor_is_overlord",
    "actor_is_subject", "subject_type", "prestige_raw",
    "cancel_prestige_delta_raw", "cancel_prestige_effect_allowed",
    "prestige_scale", "cancel_prestige_cost_verified",
)


def bounded_file(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Path:
    """Resolve a regular workspace file and check its size before any read."""

    candidate = Path(path)
    try:
        resolved = candidate.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Cannot resolve path: {candidate}") from exc
    if not resolved.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Path is outside workspace: {candidate}")
    if not resolved.is_file():
        raise ValueError(f"Expected regular file: {candidate}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise ValueError(f"File exceeds {max_bytes}-byte budget: {resolved}")
    return resolved


def digest(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    path = bounded_file(path, max_bytes=max_bytes)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def read_json(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Any:
    path = bounded_file(path, max_bytes=max_bytes)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON: {path}") from exc


def read_profile(path: Path | str) -> dict[str, Any]:
    value = read_json(path, max_bytes=MAX_PROFILE_BYTES)
    if not isinstance(value, dict):
        raise ValueError(f"Profile must be an object: {path}")
    return value


def write_json(path: Path | str, value: Any) -> Path:
    """Write a bounded audit artifact under this workspace."""

    destination = Path(path).expanduser().resolve()
    if not destination.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Output is outside workspace: {path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    if destination.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Audit output exceeds {MAX_ARCHIVE_BYTES}-byte budget: {destination}")
    return destination


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_equal(mapping: dict[str, Any], key: str, expected: Any, label: str) -> None:
    if mapping.get(key) != expected:
        raise ValueError(f"{label}.{key} does not match expected value")


def require_true(mapping: dict[str, Any], key: str, label: str) -> None:
    if mapping.get(key) is not True:
        raise ValueError(f"{label}.{key} must be true")


def _expected_report_hash(path: Path, expected: str, label: str) -> str:
    actual = digest(path)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 changed: {actual}")
    return actual


def _check_source_files(report: dict[str, Any], report_dir: Path) -> list[dict[str, Any]]:
    source_files = require_mapping(
        require_mapping(report.get("source_files"), "native report source_files"),
        "native report source_files",
    )
    checked: list[dict[str, Any]] = []
    for name, record in source_files.items():
        record = require_mapping(record, f"native source_files.{name}")
        relative = record.get("path")
        expected = record.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError(f"native source_files.{name} lacks path/SHA")
        source = bounded_file(ROOT / relative)
        actual = digest(source)
        if actual != expected:
            raise ValueError(f"native source file changed: {relative}")
        if record.get("bytes") != source.stat().st_size:
            raise ValueError(f"native source file size changed: {relative}")
        checked.append({"name": name, "path": source.relative_to(ROOT_RESOLVED).as_posix(),
                       "bytes": source.stat().st_size, "sha256": actual})
    return checked


def _check_native_source_contracts(report: dict[str, Any]) -> list[dict[str, Any]]:
    contracts = require_mapping(report.get("source_contracts"), "native report source_contracts")
    checked: list[dict[str, Any]] = []
    for relative, expected in contracts.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("native source contract has an invalid path/SHA")
        source = bounded_file(ROOT / relative)
        actual = digest(source)
        if actual != expected:
            raise ValueError(f"native source contract changed: {relative}")
        checked.append({"path": source.relative_to(ROOT_RESOLVED).as_posix(), "sha256": actual})
    return checked


def _compare_pair(country: str, public: dict[str, Any], native: dict[str, Any]) -> dict[str, Any]:
    mismatches: list[str] = []
    compared: list[str] = []
    for field in PAIR_FIELDS:
        compared.append(field)
        if field not in public or field not in native or public.get(field) != native.get(field):
            mismatches.append(field)
    public_session = require_mapping(public.get("session"), f"{country} public session")
    compared.append("session.date_raw/native.date_raw")
    if (public_session.get("date_raw") != native.get("date_raw")
            or public_session.get("date_raw") != EXPECTED_DATE
            or native.get("date_raw") != EXPECTED_DATE):
        mismatches.append("session.date_raw/native.date_raw")
    if public_session.get("status") != "ready" or public_session.get("complete") is not True:
        mismatches.append("public.session.ready_complete")
    if native.get("submitted") is not False:
        mismatches.append("native.submitted_false")
    if native.get("session_id") != EXPECTED_SESSION:
        mismatches.append("native.session_id")
    if mismatches:
        raise ValueError(f"{country} public/native identity or raw fields differ: {mismatches}")
    return {"country": country, "fields": compared, "consistent": True,
            "session_date_raw": native["date_raw"], "submitted": native["submitted"]}


def _validate_fixture(native_report: dict[str, Any], native_report_sha: str) -> dict[str, Any]:
    fixture = require_mapping(read_json(RELATIONS_FIXTURE), "recorded relations fixture")
    provenance = require_mapping(fixture.get("provenance"), "relations fixture provenance")
    require_equal(provenance, "mode", "recorded", "relations fixture provenance")
    require_equal(provenance, "original_mode", "live", "relations fixture provenance")
    require_equal(provenance, "source_sha256", native_report_sha, "relations fixture provenance")
    for field, expected in (("session_id", EXPECTED_SESSION), ("observer", "FRA"),
                            ("game_version", "1.37.4"), ("game_date", EXPECTED_DATE),
                            ("game_sha256", EXPECTED_GAME_SHA), ("dll_sha256", EXPECTED_DLL_SHA)):
        require_equal(provenance, field, expected, "relations fixture provenance")
    require_true(provenance, "read_only_native_query", "relations fixture provenance")
    require_true(provenance, "native_query_functions_invoked", "relations fixture provenance")
    for field in ("business_actions_submitted", "date_advance", "save_or_reload", "dll_installation"):
        if provenance.get(field) is not False:
            raise ValueError(f"relations fixture provenance.{field} is not false")
    source_files = require_mapping(provenance.get("source_files"), "relations fixture source_files")
    checked_files: list[dict[str, Any]] = []
    for name, record in source_files.items():
        record = require_mapping(record, f"relations fixture source_files.{name}")
        source = bounded_file(ROOT / record.get("path"))
        actual = digest(source)
        if actual != record.get("sha256") or source.stat().st_size != record.get("bytes"):
            raise ValueError(f"relations fixture source changed: {name}")
        checked_files.append({"name": name, "path": source.relative_to(ROOT_RESOLVED).as_posix(),
                              "bytes": source.stat().st_size, "sha256": actual})
    captures = require_mapping(fixture.get("captures"), "relations fixture captures")
    report_captures = require_mapping(native_report.get("captures"), "native report captures")
    for country in ("PAP", "ORL"):
        fixture_capture = require_mapping(captures.get(country), f"fixture capture {country}")
        report_capture = require_mapping(report_captures.get(country), f"report capture {country}")
        if fixture_capture.get("public") != report_capture.get("public"):
            raise ValueError(f"relations fixture {country} public projection changed")
        if fixture_capture.get("native") != report_capture.get("native"):
            raise ValueError(f"relations fixture {country} native projection changed")
    return {"path": RELATIONS_FIXTURE.relative_to(ROOT_RESOLVED).as_posix(),
            "sha256": digest(RELATIONS_FIXTURE), "source_files": checked_files}


def validate_reports() -> dict[str, Any]:
    """Validate reports and their immutable identity chain."""

    installation = require_mapping(read_json(INSTALLATION), "installation manifest")
    for field, expected in (("game_sha256", EXPECTED_GAME_SHA), ("dll_sha256", EXPECTED_DLL_SHA),
                            ("session_id", EXPECTED_SESSION)):
        require_equal(installation, field, expected, "installation")
    require_equal(installation, "creation_filetime", 134373102720165920, "installation")
    installation_sha = digest(INSTALLATION)
    if installation_sha != EXPECTED_INSTALLATION_SHA:
        raise ValueError("installation manifest SHA changed")

    native_sha = _expected_report_hash(NATIVE_REPORT, EXPECTED_NATIVE_REPORT_SHA, "native report")
    live_sha = _expected_report_hash(LIVE_REPORT, EXPECTED_LIVE_REPORT_SHA, "live acceptance report")
    save_sha = _expected_report_hash(SAVE_REPORT, EXPECTED_SAVE_REPORT_SHA, "save cross-check report")
    native = require_mapping(read_json(NATIVE_REPORT), "native report")
    live = require_mapping(read_json(LIVE_REPORT), "live acceptance report")
    save = require_mapping(read_json(SAVE_REPORT), "save cross-check report")

    for field, expected in (("status", "passed"), ("session_id", EXPECTED_SESSION),
                            ("game_sha256", EXPECTED_GAME_SHA), ("dll_sha256", EXPECTED_DLL_SHA),
                            ("installation_sha256", installation_sha)):
        require_equal(native, field, expected, "native report")
    for field in ("read_only_native_query", "native_query_functions_invoked"):
        require_true(native, field, "native report")
    if native.get("pure_RPM") is not False:
        raise ValueError("native report must retain native-query evidence type")
    for field in ("business_actions_submitted", "date_advance", "save_or_reload", "dll_installation"):
        if native.get(field) is not False:
            raise ValueError(f"native report.{field} is not false")
    source_contracts = _check_native_source_contracts(native)
    # The native report records source contracts at the top level; the
    # individual embedded public/native JSON files are checked below and the
    # complete source-file map is checked through the recorded fixture.
    native_source_files: list[dict[str, Any]] = []

    report_captures = require_mapping(native.get("captures"), "native report captures")
    pair_checks: list[dict[str, Any]] = []
    embedded_files: list[dict[str, Any]] = []
    for country in ("PAP", "ORL"):
        capture = require_mapping(report_captures.get(country), f"native report capture {country}")
        public_path = NATIVE_REPORT.parent / f"{country}-public.json"
        native_path = NATIVE_REPORT.parent / f"{country}-native.json"
        public = require_mapping(read_json(public_path), f"{country} public capture")
        native_projection = require_mapping(read_json(native_path), f"{country} native capture")
        if capture.get("public") != public or capture.get("native") != native_projection:
            raise ValueError(f"native report does not embed the immutable {country} captures")
        pair_checks.append(_compare_pair(country, public, native_projection))
        embedded_files.extend([
            {"country": country, "kind": "public", "path": public_path.relative_to(ROOT_RESOLVED).as_posix(),
             "sha256": digest(public_path)},
            {"country": country, "kind": "native", "path": native_path.relative_to(ROOT_RESOLVED).as_posix(),
             "sha256": digest(native_path)},
        ])

    source_sha = native.get("source_sha256")
    capture_script_sha = digest(CAPTURE_SCRIPT)
    if source_sha != capture_script_sha:
        raise ValueError("native report source SHA does not match its capture script")
    fixture_check = _validate_fixture(native, native_sha)

    for field, expected in (("status", "passed"), ("session_id", EXPECTED_SESSION)):
        require_equal(live, field, expected, "live acceptance report")
    for field in ("read_only_native_query",):
        require_true(live, field, "live acceptance report")
    if live.get("pure_RPM") is not False or live.get("business_actions_submitted") is not False:
        raise ValueError("live acceptance is not a read-only native-query result")
    if live.get("periodic_results") != 3 or live.get("prestige_raw") != -11643:
        raise ValueError("live acceptance period or prestige does not match the recorded result")
    checks = require_mapping(live.get("checks"), "live acceptance checks")
    if set(checks) != {"active_matches_independent_native_public_capture",
                       "mixed_unimplemented_fields_preserve_known_endpoints",
                       "periodic_same_fields_delivered", "pause_player_date_preserved"}:
        raise ValueError("live acceptance check set changed")
    if any(value is not True for value in checks.values()):
        raise ValueError("live acceptance has a failed check")
    require_equal(live, "native_reference_sha256", native_sha, "live acceptance report")
    if live.get("relation_pairs") != ["FRA/ORL", "FRA/PAP"]:
        raise ValueError("live acceptance relation pairs changed")
    configured = require_mapping(live.get("configured_field_counts"), "live configured field counts")
    if configured != {"partial": 104, "available": 50, "planned": 243}:
        raise ValueError("live configured field counts changed")

    require_equal(save, "status", "passed", "save cross-check report")
    require_true(save, "save_is_recorded", "save cross-check report")
    require_true(save, "not_a_live_state_fallback", "save cross-check report")
    if save.get("world_generation_verified") is not False:
        raise ValueError("save cross-check must retain world_generation_verified=false")
    require_equal(save, "native_capture_sha256", native_sha, "save cross-check report")
    save_info = require_mapping(save.get("save"), "save cross-check report.save")
    require_equal(save_info, "sha256", EXPECTED_SAVE_SHA, "save cross-check report.save")
    saved_relation = require_mapping(save.get("saved_relation"), "save cross-check saved_relation")
    if (saved_relation.get("first"), saved_relation.get("second"), saved_relation.get("subject_type")) != (
            "FRA", "ORL", "appanage"):
        raise ValueError("saved FRA/ORL relation changed")
    subject_scan = require_mapping(save.get("subject_scan"), "save cross-check subject_scan")
    for field in ("diplomacy_block_found", "diplomacy_block_complete", "brace_balance_ok"):
        require_true(subject_scan, field, "save cross-check subject_scan")
    if subject_scan.get("unknown") != []:
        raise ValueError("save cross-check has unresolved scan conditions")

    return {
        "identity": {
            "game_sha256": EXPECTED_GAME_SHA, "dll_sha256": EXPECTED_DLL_SHA,
            "session_id": EXPECTED_SESSION, "installation_sha256": installation_sha,
            "creation_filetime": installation["creation_filetime"], "game_date_raw": EXPECTED_DATE,
        },
        "report_sha256": {"native": native_sha, "live": live_sha, "save": save_sha},
        "source_contracts": source_contracts,
        "capture_script_sha256": capture_script_sha,
        "native_source_files": native_source_files,
        "embedded_captures": embedded_files,
        "pair_checks": pair_checks,
        "fixture": fixture_check,
        "native": native,
        "live": live,
        "save": save,
    }


def validate_profiles() -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    profiles_dir = ROOT / "bridge/information/profiles"
    profile_paths = sorted(profiles_dir.glob("*.json"))
    if not profile_paths:
        raise ValueError("No information profiles found")
    custom_contract_seen = False
    for profile_path in profile_paths:
        profile_path = bounded_file(profile_path, max_bytes=MAX_PROFILE_BYTES)
        profile = read_profile(profile_path)
        relative_profile = profile_path.relative_to(ROOT_RESOLVED).as_posix()
        if relative_profile == "bridge/information/profiles/custom-localization-memory-1374.json":
            require_equal(profile, "contract_sha256", EXPECTED_CONTRACT2_SHA, "custom profile")
            evidence = require_mapping(profile.get("source_evidence"), "custom profile source_evidence")
            contract = require_mapping(evidence.get("dynamic_localization_contract"),
                                       "custom profile dynamic contract")
            require_equal(contract, "path", CONTRACT2_REL, "custom profile dynamic contract")
            require_equal(contract, "sha256", EXPECTED_CONTRACT2_SHA, "custom profile dynamic contract")
            custom_contract_seen = True
        evidence = require_mapping(profile.get("source_evidence"), f"{profile_path.name} source_evidence")
        for name, record in evidence.items():
            if isinstance(record, str):
                source = ROOT / "work/runtime/information-missions-20261024-001" / name
                expected = record
            else:
                record = require_mapping(record, f"{profile_path.name} source_evidence.{name}")
                source = ROOT / str(record.get("path"))
                expected = record.get("sha256")
            if not isinstance(expected, str) or len(expected) != 64:
                raise ValueError(f"Invalid profile SHA: {profile_path.name}/{name}")
            source = bounded_file(source)
            actual = digest(source)
            if actual != expected:
                raise ValueError(f"Profile reference changed: {profile_path.name}/{name}")
            refs.append({"profile": relative_profile, "name": name,
                         "path": source.relative_to(ROOT_RESOLVED).as_posix(),
                         "sha256": actual})
    if len(refs) != 41:
        raise ValueError(f"Expected 41 profile source references, found {len(refs)}")
    if not custom_contract_seen:
        raise ValueError("dynamic localization contract2 pin was not found")
    return refs


def build_offline_catalog() -> dict[str, Any]:
    """Build the current catalog without an operator session or live process."""

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.mission_definitions import MissionDefinitionIndex
    from bridge.information.missions import MissionInformationSource, NativeMissionReader
    from bridge.information.sources import DiplomacySource
    from bridge.information.static_data import StaticTradeSource
    from bridge.information.subject_relations import NativeSubjectRelationSource

    primary = DiplomacySource(observer="FRA")
    adapters = [
        NativeCountryStateSource(primary),
        NativeSubjectRelationSource(primary),
        StaticTradeSource(context_provider=primary.context),
        MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary)),
    ]
    source = CompositeSource(primary, adapters)
    topics = source.catalog()
    counts = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    if (len(topics), sum(len(topic["fields"]) for topic in topics),
            sum(topic["status"] == "available" for topic in topics)) != (74, 397, 34):
        raise ValueError("Information catalog totals changed")
    if counts != Counter({"available": 50, "partial": 104, "planned": 243}):
        raise ValueError("Information catalog coverage classes changed")
    if not any(topic["topic_id"] == "R02" and topic["status"] == "available" for topic in topics):
        raise ValueError("R02 subject relation adapter is not in the catalog")
    return {
        "schema_version": 1,
        "topic_count": len(topics),
        "field_count": sum(len(topic["fields"]) for topic in topics),
        "available_topic_count": sum(topic["status"] == "available" for topic in topics),
        "field_counts": dict(counts),
        "topics": topics,
        "configuration": {
            "native_country_state": True,
            "native_subject_relations": True,
            "static_game_data": True,
            "mission_game_data": True,
            "live_session_opened": False,
            "implementation_coverage_is_not_full_live_acceptance": True,
        },
    }


def compile_fingerprints() -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in SOURCE_FINGERPRINTS:
        path = bounded_file(path)
        py_compile.compile(str(path), doraise=True)
        files.append({"path": path.relative_to(ROOT_RESOLVED).as_posix(),
                      "bytes": path.stat().st_size, "sha256": digest(path)})
    return {"status": "passed", "file_count": len(files), "files": files,
            "scope": ["N06 country_state", "R02 subject_relations", "MCP serve entry"]}


def validate_previous_manifest() -> dict[str, Any]:
    previous = bounded_file(PREVIOUS)
    actual = digest(previous)
    if actual != PREVIOUS_SHA:
        raise ValueError("Previous immutable delivery manifest changed")
    return {"path": previous.relative_to(ROOT_RESOLVED).as_posix(), "sha256": actual,
            "recursive_archive_copy": False}


def run_validation(*, write_artifacts: bool = True) -> dict[str, Any]:
    reports = validate_reports()
    refs = validate_profiles()
    coverage = build_offline_catalog()
    compile_audit = compile_fingerprints()
    previous = validate_previous_manifest()
    result = {"reports": reports, "profile_references": refs, "coverage": coverage,
              "compile_audit": compile_audit, "previous_manifest": previous}
    if write_artifacts:
        write_json(STAGE / "coverage.json", coverage)
        write_json(STAGE / "compile-audit.json", compile_audit)
        write_json(STAGE / "source-audit.json", {
            "status": "passed", "profile_reference_count": len(refs),
            "profile_references": refs, "current_source_fingerprints": compile_audit["files"],
            "native_reports": reports["report_sha256"], "pair_checks": reports["pair_checks"],
        })
    return result


def main() -> int:
    result = run_validation(write_artifacts=True)
    print(json.dumps({
        "status": "passed",
        "reports": result["reports"]["report_sha256"],
        "catalog": {
            "topics": result["coverage"]["topic_count"],
            "fields": result["coverage"]["field_count"],
            "available_topics": result["coverage"]["available_topic_count"],
            "field_counts": result["coverage"]["field_counts"],
        },
        "profile_references": len(result["profile_references"]),
        "compiled": result["compile_audit"]["file_count"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
