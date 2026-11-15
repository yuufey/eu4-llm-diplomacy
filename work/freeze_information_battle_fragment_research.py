"""Freeze the bounded static research for the battle-message fragments batch.

This verifier reads only saved reports and bounded selected readbacks.  The
32 MiB 14B33A0 evidence is hashed as a stream and is never JSON-loaded.  The
missing provider run receipt for that query is an expected, explicitly
represented gap; it is not converted into a successful process receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-fragments-20261025-001"
IMAGE_BASE = 0x140000000
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
PROCESS_MEMORY_LIMIT = 1024 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
REVISION_RE = re.compile(r"^[0-9]{3}$")

QUERY_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "message_setting_8c1ba0",
        "directory": "rea-message-setting-001",
        "rva": "0x8c1ba0",
        "procedure": "0x1408c1ba0",
        "evidence_id": "ev_078491e6b218b6e5505934dbb69ebb6640f0666201165b5733239466446646ff",
        "evidence_bytes": 177150,
        "evidence_sha256": "9aac86bd32b6586d3204d4c48dbd672da3f3d2d5c8bdda8cffd10d5d259be0ec",
        "request_bytes": 740,
        "request_sha256": "e6e7539d9020f2d97a5bf244be5ee70355ac410efb4ae077ff98a4a79760f126",
        "run_present": True,
        "run_bytes": 1105,
        "run_sha256": "eed02a173ec2fc2074ea0846ec828b60e8205a2d222e83422edb9b321cf967fc",
        "selected_bytes": 25000,
        "selected_sha256": "ae05c0b87d8c4a56acf6a386ede08af6bf85777839d80212f52dad8cdada20c5",
        "readback_bytes": 7311,
        "readback_sha256": "5582d55334f0255a6d0a266000502e81741b6fc918a30eca479052cadfcefab4",
        "body": {"ranges": [{"start": "0x1408c1ba0", "end": "0x1408c1ca0"}], "total_bytes": 257, "span_bytes": 257, "non_contiguous": False, "contains_entry": True},
    },
    {
        "name": "localized_format_14b33a0",
        "directory": "rea-localized-format-001",
        "rva": "0x14b33a0",
        "procedure": "0x1414b33a0",
        "evidence_id": "ev_48919e3903f355e10997c47979823883c122867db887ce13bc26cb04cf244167",
        "evidence_bytes": 32568212,
        "evidence_sha256": "12acdf06a8a12f9e09ef31448e19594a454819668c1c4de8d6dd5134f313d966",
        "request_bytes": 741,
        "request_sha256": "1437179f678631eacaf95f086d838f8da915bb0414631bbcbd67bfe1c81aa427",
        "run_present": False,
        "run_bytes": None,
        "run_sha256": None,
        "selected_bytes": 41944,
        "selected_sha256": "48dfd0dec340cf031b64fe5d7f08ad6958179af736093cd91e93ea56d41a7bdc",
        "readback_bytes": 6663,
        "readback_sha256": "a52a94b8761a40f1c92791adae91bd4d4f3369d7ebb7db2ac30786e0840312ae",
        "body": {"ranges": [{"start": "0x1414b33a0", "end": "0x1414b35b9"}], "total_bytes": 538, "span_bytes": 538, "non_contiguous": False, "contains_entry": True},
        "expected_receipt_gap": {
            "run_json_present": False,
            "provider_exit_code": None,
            "provider_peak_committed_bytes": None,
            "shell_id": 52519,
            "shell_exit_code": 1,
            "shell_phase": "postread",
        },
    },
    {
        "name": "message_membership_84c0b0",
        "directory": "rea-message-membership-001",
        "rva": "0x84c0b0",
        "procedure": "0x14084c0b0",
        "evidence_id": "ev_3aa6d4acac0eecef99822869664565c516af7255560f739e09d14a5879b3f05d",
        "evidence_bytes": 120024,
        "evidence_sha256": "d76890ae0b458d5cd3766bdb6b92d5d5709668b48866c9093944a63797093c85",
        "request_bytes": 740,
        "request_sha256": "31beef5829baca431f95f1a451bdc8816ae18be1f642803b71bd1b1695fab302",
        "run_present": True,
        "run_bytes": 1746,
        "run_sha256": "5b51e4563f234bf0f31d5a90bd2ae4d39f68b1ef2dd43bef60fc085aacb4b823",
        "selected_bytes": 18779,
        "selected_sha256": "c88c14912c80251cc3e55dcb4752c5ed03ccd5dce7d0d4af948e3e626fcd68e6",
        "readback_bytes": 7329,
        "readback_sha256": "0ae4cc49edae79c17a5cafc37101964627b5975d5e922feb733d8674440e0e0e",
        "body": {"ranges": [{"start": "0x14084c0b0", "end": "0x14084c100"}], "total_bytes": 81, "span_bytes": 81, "non_contiguous": False, "contains_entry": True},
    },
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _bounded_json(path: Path, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    path = path.resolve()
    _require(path.is_file(), f"missing_json:{path}")
    before = path.stat()
    _require(before.st_size <= limit, f"json_over_bound:{path}:{before.st_size}>{limit}")
    raw = path.read_bytes()
    after = path.stat()
    _require(len(raw) == before.st_size and (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), f"json_changed_during_read:{path}")
    value = json.loads(raw.decode("utf-8"))
    _require(isinstance(value, dict), f"json_object_required:{path}")
    return value, raw


def _file_pin(path: Path, expected_bytes: int | None, expected_sha: str | None) -> dict[str, Any]:
    _require(path.is_file(), f"missing_source:{path}")
    size = path.stat().st_size
    digest = _sha256_file(path)
    if expected_bytes is not None:
        _require(size == expected_bytes, f"source_size_changed:{path}")
    if expected_sha is not None:
        _require(digest == expected_sha, f"source_sha_changed:{path}")
    return {"path": _rel(path), "bytes": size, "sha256": digest}


def _check_profile_and_request(selected: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    _require(selected.get("status") == "observed", f"selected_status_changed:{spec['name']}")
    query = selected.get("query")
    _require(isinstance(query, dict), f"selected_query_missing:{spec['name']}")
    _require(query.get("authorised_rva") == spec["rva"] and query.get("authorised_procedure") == spec["procedure"], f"selected_query_identity_changed:{spec['name']}")
    _require(query.get("target_sha256") == EXPECTED_EXE_SHA256 and query.get("fixed_build") == "1.37.4", f"selected_target_changed:{spec['name']}")
    identity = selected.get("identity_audit")
    _require(isinstance(identity, dict) and identity.get("status") == "passed" and identity.get("evidence_id") == spec["evidence_id"], f"selected_identity_audit_failed:{spec['name']}")
    request = selected.get("request")
    _require(isinstance(request, dict) and request.get("all_fixed_checks_pass") is True, f"selected_request_audit_failed:{spec['name']}")
    profile = selected.get("profile_audit")
    _require(isinstance(profile, dict) and profile.get("status") == "observed", f"selected_profile_audit_failed:{spec['name']}")
    cache = selected.get("cache_audit")
    _require(isinstance(cache, dict) and cache.get("status") == "passed", f"selected_cache_audit_failed:{spec['name']}")
    comparison = selected.get("normalized_comparison")
    _require(isinstance(comparison, dict) and set(comparison) == {"procedure", "pseudocode", "assembly", "callees"}, f"normalized_comparison_fields_changed:{spec['name']}")
    _require(all(item.get("status") == "equal" for item in comparison.values()), f"raw_normalized_mismatch:{spec['name']}")
    procedure = selected.get("raw_result_value", {}).get("procedure", {}).get("value", {})
    _require(isinstance(procedure, dict) and procedure.get("address") == spec["procedure"], f"selected_procedure_changed:{spec['name']}")
    body = procedure.get("body")
    _require(isinstance(body, dict), f"selected_body_missing:{spec['name']}")
    _require(body.get("ranges") == spec["body"]["ranges"], f"selected_body_ranges_changed:{spec['name']}")
    for key in ("total_bytes", "span_bytes", "non_contiguous", "contains_entry"):
        _require(body.get(key) == spec["body"][key], f"selected_body_{key}_changed:{spec['name']}")
    return {
        "identity_audit": identity,
        "request_audit": request,
        "profile_audit": profile,
        "cache_audit": cache,
        "normalized_comparison": comparison,
        "body": body,
    }


def _query_descriptor(spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bool]]:
    query_dir = STAGE / spec["directory"]
    evidence_path = query_dir / "evidence.json"
    request_path = query_dir / "request.json"
    run_path = query_dir / "run.json"
    selected_path = query_dir / "selected-evidence-001.json"
    readback_path = query_dir / "readback-recovery-001.json"
    evidence_pin = _file_pin(evidence_path, spec["evidence_bytes"], spec["evidence_sha256"])
    request_pin = _file_pin(request_path, spec["request_bytes"], spec["request_sha256"])
    selected_pin = _file_pin(selected_path, spec["selected_bytes"], spec["selected_sha256"])
    readback_pin = _file_pin(readback_path, spec["readback_bytes"], spec["readback_sha256"])
    selected, _ = _bounded_json(selected_path)
    audit = _check_profile_and_request(selected, spec)
    readback, _ = _bounded_json(readback_path)
    if spec["run_present"]:
        run_pin = _file_pin(run_path, spec["run_bytes"], spec["run_sha256"])
        runtime = selected.get("provider_runtime")
        _require(isinstance(runtime, dict) and runtime.get("run_json_present") is True and runtime.get("status") == "passed", f"provider_receipt_failed:{spec['name']}")
        _require(runtime.get("provider_exit_code") == 0 and isinstance(runtime.get("provider_peak_committed_bytes"), int) and runtime["provider_peak_committed_bytes"] < PROCESS_MEMORY_LIMIT, f"provider_runtime_failed:{spec['name']}")
        _require(readback.get("status") == "observed", f"readback_status_changed:{spec['name']}")
        receipt = {"status": "passed", "run_json_present": True, "provider_exit_code": 0, "provider_peak_committed_bytes": runtime["provider_peak_committed_bytes"], "run": run_pin}
    else:
        _require(not run_path.exists(), f"unexpected_run_json:{spec['name']}")
        runtime = selected.get("provider_runtime")
        gap = spec["expected_receipt_gap"]
        _require(isinstance(runtime, dict) and runtime.get("run_json_present") is False and runtime.get("status") == "unknown", f"missing_receipt_not_preserved:{spec['name']}")
        _require(runtime.get("provider_exit_code") is None and runtime.get("provider_peak_committed_bytes") is None, f"unknown_receipt_promoted:{spec['name']}")
        shell = runtime.get("original_shell_postread")
        _require(isinstance(shell, dict) and shell.get("shell_id") == gap["shell_id"] and shell.get("exit_code") == gap["shell_exit_code"] and shell.get("phase") == gap["shell_phase"], f"postread_gap_changed:{spec['name']}")
        _require(readback.get("status") == "partial_readback", f"missing_receipt_readback_status_changed:{spec['name']}")
        receipt = {"status": "unknown_expected_gap", "run_json_present": False, "provider_exit_code": None, "provider_peak_committed_bytes": None, "original_shell_postread": shell}
    descriptor = {
        "name": spec["name"],
        "directory": spec["directory"],
        "rva": spec["rva"],
        "procedure": spec["procedure"],
        "evidence_id": spec["evidence_id"],
        "evidence": evidence_pin,
        "request": request_pin,
        "selected": selected_pin,
        "readback": readback_pin,
        "body": audit["body"],
        "raw_normalized_equal": True,
        "request_profile_cache": {"request": audit["request_audit"], "profile": audit["profile_audit"], "cache": audit["cache_audit"]},
        "provider_receipt": receipt,
        "static_only": True,
    }
    checks = {
        "evidence_pin": True,
        "request_pin": True,
        "selected_pin": True,
        "readback_pin": True,
        "identity_profile_cache": True,
        "raw_normalized_equal": True,
        "provider_receipt_or_expected_gap": True,
        "readback_status": True,
    }
    return descriptor, checks


def _survey_descriptor() -> dict[str, Any]:
    path = STAGE / "capture-gate-survey-001.json"
    survey, raw = _bounded_json(path)
    _require(survey.get("schema") == "information-battle-capture-gate-survey-001", "survey_schema_changed")
    _require(survey.get("status") == "observed_static_mechanical_only" and survey.get("read_only") is True, "survey_status_changed")
    _require(survey.get("evidence_boundary", {}).get("runtime_effects_observed") is False, "survey_runtime_boundary_changed")
    _require(survey.get("evidence_boundary", {}).get("visibility_contract_proven") is False, "survey_visibility_boundary_changed")
    return {"path": _rel(path), "bytes": len(raw), "sha256": _sha256_file(path), "schema": survey["schema"], "status": survey["status"], "sources": len(survey.get("sources", [])), "contexts": len(survey.get("contexts", []))}


def _extractor_descriptor() -> dict[str, Any]:
    path = ROOT / "work" / "extract_information_battle_fragment_evidence.py"
    _require(path.is_file(), "fragment_extractor_missing")
    digest = _sha256_file(path)
    return {"path": _rel(path), "bytes": path.stat().st_size, "sha256": digest, "readback_method": "mmap_bounded_json_span_scan", "max_selected_value_bytes": 2 * 1024 * 1024, "whole_document_json_loaded": False}


def _freeze_script_descriptor() -> dict[str, Any]:
    path = Path(__file__).resolve()
    return {"path": _rel(path), "bytes": path.stat().st_size, "sha256": _sha256_file(path)}


def _ledger_descriptor(ledger_arg: Path | None, ledger_script_arg: Path | None) -> dict[str, Any]:
    ledger_path = (ledger_arg or (STAGE / "capture-scope-text-ledger-001.json")).resolve()
    ledger, raw = _bounded_json(ledger_path)
    descriptor: dict[str, Any] = {
        "path": _rel(ledger_path),
        "bytes": len(raw),
        "sha256": _sha256_file(ledger_path),
        "schema": ledger.get("schema"),
        "status": ledger.get("status"),
        "static_only_fields_recorded": sorted(ledger.keys()),
    }
    script_path = ledger_script_arg
    if script_path is None:
        candidate = ROOT / "work" / "probe_information_battle_capture_scope.py"
        script_path = candidate if candidate.is_file() else None
    if script_path is not None:
        script_path = script_path.resolve()
        _require(script_path.is_file(), f"ledger_script_missing:{script_path}")
        descriptor["generator_script"] = {"path": _rel(script_path), "bytes": script_path.stat().st_size, "sha256": _sha256_file(script_path)}
    else:
        descriptor["generator_script"] = None
    return descriptor


def _write_new(path: Path, value: Mapping[str, Any]) -> tuple[int, str]:
    _require(not path.exists(), f"refusing_to_overwrite:{path}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _require(len(raw) <= MAX_OUTPUT_BYTES, f"output_over_bound:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def run(*, revision: str, ledger: Path | None, ledger_script: Path | None) -> tuple[Path, Path]:
    _require(REVISION_RE.fullmatch(revision) is not None, "revision_must_be_three_digits")
    query_descriptors: list[dict[str, Any]] = []
    query_checks: dict[str, dict[str, bool]] = {}
    for spec in QUERY_SPECS:
        descriptor, checks = _query_descriptor(spec)
        query_descriptors.append(descriptor)
        query_checks[spec["name"]] = checks

    survey = _survey_descriptor()
    extractor = _extractor_descriptor()
    freeze_script = _freeze_script_descriptor()
    ledger_descriptor = _ledger_descriptor(ledger, ledger_script)
    all_checks: dict[str, bool] = {
        "fixed_executable_sha256": True,
        "fixed_build": True,
        "three_queries_present": len(query_descriptors) == 3,
        "survey_pinned": True,
        "extractor_pinned": True,
        "capture_scope_ledger_pinned": True,
        "expected_receipt_gap_faithfully_represented": any(item["provider_receipt"]["status"] == "unknown_expected_gap" for item in query_descriptors),
        "no_query_claimed_provider_receipt_pass_without_run": all(item["provider_receipt"]["status"] != "passed" or item["provider_receipt"].get("run_json_present") is True for item in query_descriptors),
        "static_research_incomplete": True,
    }
    for checks in query_checks.values():
        all_checks.update({f"{checks_name}": value for checks_name, value in checks.items()})
    _require(all(all_checks.values()), f"static_audit_failed:{all_checks}")

    common = {
        "schema": "information-battle-fragment-research-v1",
        "revision": revision,
        "status": "passed_static_research_with_expected_receipt_gap",
        "goal_complete": False,
        "operational_metadata": "static_research_incomplete",
        "read_only": True,
        "script": freeze_script,
        "target": {"fixed_build": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256, "image_base": hex(IMAGE_BASE)},
        "queries": query_descriptors,
        "capture_gate_survey": survey,
        "extractor": extractor,
        "capture_scope_ledger": ledger_descriptor,
        "checks": all_checks,
        "limitations": [
            "All three query outputs are static saved-artifact evidence; no runtime battle message was captured.",
            "14B33A0 selected spans are readable, but run.json is absent after shell 52519 postread exit 1; provider exit and peak remain unknown.",
            "No visibility, allied/enemy/nonparticipant mapping, ABI, hook safety, lifetime, or player/root binding is promoted by this freeze.",
            "The research is incomplete operational metadata and does not authorize a capture hook or a game action.",
        ],
    }
    index = {**common, "schema": "information-battle-fragment-research-index-v1", "source_audit_path": f"work/runtime/information-battle-fragments-20261025-001/source-audit-{revision}.json"}
    audit_path = STAGE / f"source-audit-{revision}.json"
    index_path = STAGE / f"research-index-{revision}.json"
    _write_new(index_path, index)
    index_pin = {"path": _rel(index_path), "bytes": index_path.stat().st_size, "sha256": _sha256_file(index_path)}
    audit = {**common, "schema": "information-battle-fragment-source-audit-v1", "index_path": _rel(index_path), "research_index": index_pin, "query_checks": query_checks, "source_pins": [item["evidence"] for item in query_descriptors]}
    _write_new(audit_path, audit)
    return index_path, audit_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="001")
    parser.add_argument("--ledger", type=Path, default=None, help="capture-scope ledger; defaults to the stage ledger")
    parser.add_argument("--ledger-script", type=Path, default=None)
    args = parser.parse_args(argv)
    index, audit = run(revision=args.revision, ledger=args.ledger, ledger_script=args.ledger_script)
    print(json.dumps({"status": "passed", "index": str(index), "source_audit": str(audit)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
