"""Offline-preflight and narrowly guarded live acceptance for R03 rivals.

``--preflight-only`` verifies pinned inputs, the independent saved-checkpoint
oracle, and the real ``serve_information`` catalog/tool route without opening
an operator session, process, RPM reader, or MCP client.  ``--run`` is the only
live entry point; it requires the frozen preflight receipt and performs one
direct production capture, one R03 active query, and one first-result check
from a real two-second periodic subscription in the same MCP service.

The expected outgoing set is read from the independently streamed checkpoint
audit, never from the production projection.  Each tool request and response
is written before its acceptance assertions; a successful or unknown request
is never replayed.  The live flow does not send ``information_tick`` or any
game/business action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.tools import TOOL_DEFINITIONS, validate_schema  # noqa: E402
from work.validate_information_live import Client as _BaseClient  # noqa: E402


COUNTRY = "FRA"
EXPECTED_PID = 27716
EXPECTED_CREATION_FILETIME = 134376348223436218
EXPECTED_SESSION = "27716-1dd6693a61275ba"
EXPECTED_VERSION = "1.37.4"
EXPECTED_DATE = 56562768
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA256 = "92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce"
INSTALLATION_SHA256 = "8669d71cfcf351ba7b53b394414930886002afac217efdbffab2f1c4f951d21b"
MANIFEST_SHA256 = "753e456808fec521600a9ded95a6151e6a0e492a3577558d9c97e7ec139408a2"
PROFILE_SHA256 = "a40515fd3e19d59dd73bde7bde442f155c04fd91ef6c3cd786ddaa481690708c"
AUDIT_SHA256 = "6d1af31e9e9630b3de57edf22ae495dc93eab2ee336e819df1604e967533d4d5"
AUDIT_BYTES = 220971
ARCHIVE_SOURCE_SHA256 = "0922452c8eff6b74416754feffa1928aa51b2be045b391f2dcd8582f8aec53d9"
INSTALLATION_DEFAULT = Path(
    "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/installation.json"
)
AUDIT_DEFAULT = Path(
    "work/runtime/information-diplomacy-state-20261028-001/rivals-source-001/report-002.json"
)
ARCHIVE_SOURCE_DEFAULT = Path(
    "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/rival-query.inc"
)
REVIEW_ROOT = Path("stage/live-helper-review-001")
PREFLIGHT_DEFAULT = REVIEW_ROOT / "preflight-001.json"
DEPENDENCY_REPORT_DEFAULT = REVIEW_ROOT / "helper-dependencies-001.json"
LIVE_OUTPUT_DEFAULT = Path(
    "work/runtime/information-diplomacy-state-20261028-001/live-acceptance-001"
)
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_NATIVE_LOG_SUFFIX = 2 * 1024 * 1024
MAX_NATIVE_LOG_LINE = 256 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
FIELD_KEY = "rivals"
R03_QUERY = {
    "topic": "R03",
    "object": {"type": "country", "country": COUNTRY},
    "fields": [FIELD_KEY],
    "parameters": {},
}

# These are read-only dependencies of this helper's preflight/run protocol.
# The acceptance helper itself is pinned separately in each receipt.
PINNED_FILES: dict[str, str] = {
    "work/runtime/information-diplomacy-state-20261028-001/rivals-source-001/report-002.json": AUDIT_SHA256,
    "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/rival-query.inc": ARCHIVE_SOURCE_SHA256,
    "bridge/information/country_rivals.py": "4aa564ff4df2fc97dc1275bce1f0e685069927dab85cbc2f049000ff61eb41e0",
    "bridge/information/country_rivals_memory.py": "59030a8a24d651ed34f94e5effce075156fa353633957815652bca5aba5deaa6",
    "bridge/information/profiles/country-rivals-memory-1374.json": PROFILE_SHA256,
    "bridge/tests/test_information_country_rivals.py": "bba95bc4d65a96c35e049cb8751683c1068686e7c16ab177ad9b0a90c06d6725",
    "bridge/tests/test_information_country_rivals_memory.py": "68448c67500fe7bd9e58a49b5e0d0af766fc53ae2c187c688782906d663731f7",
    "bridge/information/catalog.py": "32be92d4026b08f3ff59852d3f041e557a8fa2094e3b760e51ea492b55a3f0fb",
    "bridge/information/composite.py": "902d3d7c7ecf4396a1e8c70d73dddaf9803a7e8844c6fab11e575b94b6917f0e",
    "bridge/information/service.py": "52a52e465b5c91a9cadd2c871fd81fa3497ceee928eba2d446caa39e5b9e3c29",
    "bridge/information/tools.py": "743c85798a9d38b2bef91e1f09e235061bffa0737b338c3d8d09c193aa2fed3b",
    "bridge/diplomacy.py": "c65e36cb6443cd34394cf12b2da471c688bafac5456a6773ba136e8db195205e",
    "bridge/diplomacy_journal.py": "0caa09ba065cfd2d544bf268cf664032cb28bb9a2359e0ae0101512ce0cc0c7f",
    "tools/serve_information.py": "f8b85063127826e4a8d4e44abfe8357adf3e0b73a35798c1e84865f8b8243ea5",
    "work/validate_information_live.py": "478938d2f709445ccf8f2b7228e1665659f0b75a82dea4944efed37974373b00",
    "work/run_alliance_inbound_response.py": "75cbe9f41460413c8f3aeb7116da32b51e54966419b19601ceff9920dd6bf48e",
    "work/local_config.py": "55a3bce5a2bf98f83c58e27884699c780456ea40b84d11bcac5fe78082262001",
}


class AcceptanceError(RuntimeError):
    """A pin, offline-route, live-read, or lifecycle check failed."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    _require(0 < size <= max_bytes, f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _file_pin(relative_path: str, expected_sha: str) -> dict[str, Any]:
    path = ROOT / relative_path
    _require(path.is_file(), f"pinned_file_missing:{relative_path}")
    size = path.stat().st_size
    actual = _sha256(path)
    _require(actual == expected_sha, f"pinned_file_sha_mismatch:{relative_path}")
    return {"path": relative_path, "bytes": size, "sha256": actual}


def _load_identity(installation: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    installation = installation.resolve(strict=True)
    identity = _read_json(installation)
    _require(isinstance(identity, dict), "installation_not_object")
    expected = {
        "pid": EXPECTED_PID,
        "creation_filetime": EXPECTED_CREATION_FILETIME,
        "session_id": EXPECTED_SESSION,
        "game_sha256": GAME_SHA256,
        "dll_sha256": DLL_SHA256,
    }
    for key, value in expected.items():
        actual = identity.get(key)
        if isinstance(value, str):
            _require(isinstance(actual, str) and actual.lower() == value.lower(),
                     f"installation_{key}_pin_mismatch")
        else:
            _require(actual == value, f"installation_{key}_pin_mismatch")
    _require(identity.get("installation_returncode") == 0
             and identity.get("runtime_verified") is False,
             "installation_contract_mismatch")
    installation_pin = {"path": str(installation), "bytes": installation.stat().st_size,
                        "sha256": _sha256(installation)}
    _require(installation_pin["sha256"] == INSTALLATION_SHA256,
             "installation_file_sha_mismatch")

    manifest_path = installation.parent / "build-manifest.json"
    manifest = _read_json(manifest_path)
    _require(isinstance(manifest, dict), "build_manifest_not_object")
    manifest_pin = {"path": str(manifest_path.resolve()),
                    "bytes": manifest_path.stat().st_size,
                    "sha256": _sha256(manifest_path)}
    _require(manifest_pin["sha256"] == MANIFEST_SHA256,
             "build_manifest_sha_mismatch")
    sources = manifest.get("sources")
    _require(manifest.get("version") == 30 and manifest.get("compiled") is True
             and manifest.get("runtime_verified") is False
             and manifest.get("game_sha256") == GAME_SHA256
             and manifest.get("dll_sha256") == DLL_SHA256
             and isinstance(sources, list) and len(sources) == 119,
             "build_manifest_contract_mismatch")
    modules = identity.get("modules_after_install")
    _require(isinstance(modules, list) and any(
        isinstance(module, Mapping)
        and str(module.get("sha256", "")).lower() == DLL_SHA256
        for module in modules), "installed_dll_pin_missing")
    identity["_acceptance_installation_pin"] = installation_pin
    return identity, manifest, manifest_pin


def _battle_status(installation: Path) -> dict[str, Any]:
    path = installation.resolve().parent / "information-battle-status.json"
    value = _read_json(path, max_bytes=256 * 1024)
    _require(isinstance(value, Mapping), "battle_status_not_object")
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": _sha256(path), "value": dict(value)}


def _assert_battle_status(snapshot: Mapping[str, Any]) -> None:
    value = snapshot.get("value")
    _require(isinstance(value, Mapping), "battle_status_not_object")
    creation = str(value.get("creation_filetime", ""))
    _require(value.get("schema") == "EU4-BATTLE-SOURCE/1"
             and value.get("state") == "ready"
             and value.get("pid") == EXPECTED_PID
             and creation == str(EXPECTED_CREATION_FILETIME)
             and value.get("exe_sha256") == GAME_SHA256
             and value.get("dll_sha256") == DLL_SHA256
             and value.get("code_patch_installed") is False
             and value.get("dll_pinned") is False
             and value.get("unwind_registered") is False
             and value.get("capture_complete") is False
             and value.get("captured") == "0"
             and value.get("last_sequence") == "0"
             and value.get("fragment_sink_pending") is False
             and value.get("business_export_available") is False,
             "battle_source_not_ready_zero_unpatched")


def _independent_expected(audit_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    audit_path = audit_path.resolve(strict=True)
    pin = {"path": str(audit_path), "bytes": audit_path.stat().st_size,
           "sha256": _sha256(audit_path)}
    _require(pin["bytes"] == AUDIT_BYTES and pin["sha256"] == AUDIT_SHA256,
             "rivals_source_audit_pin_mismatch")
    audit = _read_json(audit_path, max_bytes=512 * 1024)
    _require(isinstance(audit, Mapping)
             and audit.get("schema") == "information_diplomacy_rivals_source_audit.v1"
             and audit.get("status") == "passed"
             and audit.get("read_only") is True
             and audit.get("native_game_calls") is False
             and audit.get("rpm_calls") is False
             and audit.get("mcp_calls") is False,
             "rivals_source_audit_contract_invalid")
    checkpoint = audit.get("checkpoint")
    interpretation = audit.get("interpretation")
    contract = audit.get("field_contract")
    _require(isinstance(checkpoint, Mapping)
             and checkpoint.get("sha256") == "c65f8c991420338465888d8a55f9487da3eb6ab3aca65872ae1f58c6ff850a5d"
             and checkpoint.get("size_bytes") == 43393512
             and checkpoint.get("date") == "1456.12.9"
             and checkpoint.get("final_brace_depth") == 0
             and isinstance(checkpoint.get("countries"), Mapping)
             and checkpoint["countries"].get("complete") is True
             and checkpoint["countries"].get("country_blocks_seen") == 1379
             and checkpoint["countries"].get("country_blocks_complete") == 1379
             and isinstance(checkpoint.get("formal_country_rival_nodes"), Mapping)
             and checkpoint["formal_country_rival_nodes"].get("total") == 1043
             and checkpoint["formal_country_rival_nodes"].get("complete") == 1043,
             "rivals_checkpoint_audit_contract_invalid")
    _require(isinstance(interpretation, Mapping)
             and interpretation.get("outgoing_FRA") == []
             and interpretation.get("outgoing_FRA_targets") == []
             and interpretation.get("FRA_historical_rival_fields", {}).get("history.historical_rival") == '"HAB"'
             and isinstance(contract, Mapping)
             and contract.get("field") == "R03.rivals"
             and contract.get("owner") == "actor country only; directional, not symmetric",
             "rivals_independent_outgoing_or_semantics_mismatch")
    rows = checkpoint["formal_country_rival_nodes"].get("all_rows")
    _require(isinstance(rows, list)
             and not any(isinstance(row, Mapping) and row.get("owner") == COUNTRY for row in rows),
             "rivals_checkpoint_contains_fra_outgoing_rows")
    # The empty value is derived only from the independent checkpoint's full
    # owner->target scan. Remaining keys state the audited public R03 contract.
    public_field = {
        "status": "known", "value": [], "unit": "country_tags", "scale": 1,
        "period": "current", "direction": "outgoing_declared_by_country",
        "basis": "native_outgoing_rival_membership", "value_origin": "copied_native_cache",
        "complete": True, "partial": False,
    }
    return ({"outgoing_rivals": [], "public_field": public_field,
             "checkpoint_date": checkpoint["date"], "checkpoint_sha256": checkpoint["sha256"],
             "evidence_kind": "independent_saved_checkpoint_owner_to_target_scan"}, pin)


def _dependency_pins() -> list[dict[str, Any]]:
    pins = []
    for relative, expected in PINNED_FILES.items():
        _require(expected != "TO_BE_PINNED", f"dependency_pin_not_frozen:{relative}")
        pins.append(_file_pin(relative, expected))
    return pins


def _tool(name: str) -> Mapping[str, Any]:
    found = next((item for item in TOOL_DEFINITIONS if item.get("name") == name), None)
    _require(isinstance(found, Mapping), f"information_tool_missing:{name}")
    return found


def _validate_tool_arguments(name: str, arguments: Mapping[str, Any]) -> None:
    validate_schema(dict(arguments), _tool(name)["inputSchema"], "arguments")


def _catalog_contract() -> dict[str, Any]:
    """Use the real offline service factory and inspect the actual R03 route."""
    from tools import serve_information
    from bridge.information.country_rivals import NativeCountryRivalsSource

    with tempfile.TemporaryDirectory(prefix="r03-rivals-route-") as directory:
        database = Path(directory) / "route-check.sqlite3"
        args = serve_information.build_parser().parse_args([
            "--database", str(database), "--observer", COUNTRY,
        ])
        _require(args.operator_session is None and args.observer == COUNTRY,
                 "offline_service_factory_would_open_operator_session")
        service, journal = serve_information._build_runtime(args)
        try:
            source = service.source
            rows = source.catalog()
            topic = next((row for row in rows if row.get("topic_id") == "R03"), None)
            _require(isinstance(topic, Mapping), "real_r03_catalog_missing")
            fields = topic.get("fields")
            _require(isinstance(fields, Mapping)
                     and isinstance(fields.get(FIELD_KEY), Mapping)
                     and fields[FIELD_KEY].get("coverage") == "available"
                     and fields[FIELD_KEY].get("complete") is True,
                     "real_r03_rivals_not_available_complete")
            truce = fields.get("truce_until")
            _require(isinstance(truce, Mapping)
                     and truce.get("coverage") == "planned",
                     "real_r03_truce_until_should_remain_planned")
            _require("query" in topic.get("triggers", [])
                     and "periodic" in topic.get("triggers", [])
                     and "country" in topic.get("object_types", []),
                     "real_r03_query_periodic_country_scope_missing")

            query = json.loads(json.dumps(R03_QUERY))
            normalized = source.validate_query(query)
            _require(normalized == query, "real_r03_query_normalization_mismatch")
            capabilities = source.query_capabilities(query)
            _require(isinstance(capabilities, list) and len(capabilities) == 1
                     and capabilities[0][0].get("fields") == [FIELD_KEY],
                     "real_r03_field_route_not_unique")
            route_entry = capabilities[0][1]
            _require(isinstance(route_entry, Mapping)
                     and route_entry.get("source") == "NativeCountryRivalsSource"
                     and set(route_entry.get("fields", {})) == {FIELD_KEY},
                     "real_r03_field_owner_not_single_native_rivals_source")
            adapter_owners = []
            for adapter in getattr(source, "adapters", ()):
                for row in adapter.catalog():
                    if row.get("topic_id") == "R03" and FIELD_KEY in row.get("fields", {}):
                        adapter_owners.append(type(adapter).__name__)
            _require(adapter_owners == ["NativeCountryRivalsSource"],
                     "real_r03_adapter_owner_set_mismatch")

            query_args = {"request_id": "r03-offline-query", "queries": [query]}
            report_config = {"name": "R03 offline schema", "queries": [query], "detail": "raw"}
            subscription_config = {
                "name": "R03 rivals two-second periodic", "kind": "periodic",
                "report_id": "report_example", "enabled": True,
                "schedule": {"basis": "real", "every": 2,
                             "unit": "seconds", "missed": "coalesce"},
            }
            schema_args = {
                "information_query": query_args,
                "information_manage_report": {
                    "request_id": "r03-offline-report", "operation": "create",
                    "config": report_config,
                },
                "information_manage_subscription": {
                    "request_id": "r03-offline-subscribe", "operation": "create",
                    "config": subscription_config,
                },
                "information_manage_subscription.list": {
                    "request_id": "r03-offline-list", "operation": "list",
                },
                "information_manage_subscription.cancel": {
                    "request_id": "r03-offline-cancel", "operation": "cancel",
                    "subscription_id": "sub_example", "expected_version": 1,
                },
                "information_list_results": {"limit": 100},
                "information_status": {},
            }
            for name, arguments in schema_args.items():
                tool_name = name.split(".", 1)[0]
                _validate_tool_arguments(tool_name, arguments)
            _require(journal is None, "offline_factory_created_diplomacy_journal")
            return {
                "service_factory": "tools.serve_information._build_runtime",
                "offline_operator_session": False,
                "service_database_temporary_and_closed": True,
                "journal_created": False,
                "topic_id": "R03", "topic_status": topic.get("status"),
                "topic_source": topic.get("source"),
                "rivals_field_coverage": fields[FIELD_KEY].get("coverage"),
                "rivals_field_complete": fields[FIELD_KEY].get("complete"),
                "truce_until_coverage": truce.get("coverage"),
                "triggers": list(topic.get("triggers", [])),
                "query": query,
                "normalized_query": normalized,
                "field_route_count": len(capabilities),
                "field_route_source": route_entry.get("source"),
                "r03_adapter_field_owners": adapter_owners,
                "query_report_subscription_status_schemas_validated": True,
                "periodic_config": subscription_config,
                "native_query_performed": False,
                "mcp_started": False,
            }
        finally:
            service.close()
            if journal is not None:
                journal.close()


def _build_preflight(installation: Path, audit_path: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "information.country_rivals.live_helper_preflight.v1",
        "status": "running", "mode": "offline-preflight-only",
        "explicit_live_guard": "--run", "checks": {},
        "side_effects": {"mcp_started": False, "rpm_capture_performed": False,
                         "native_game_calls": False, "target_memory_writes": False,
                         "information_tick_sent": False, "diplomacy_dispatched": False},
    }
    try:
        identity, manifest, manifest_pin = _load_identity(installation)
        installation_pin = identity.pop("_acceptance_installation_pin")
        report["installation_identity"] = {
            "path": installation_pin["path"], "sha256": installation_pin["sha256"],
            "bytes": installation_pin["bytes"], "pid": identity["pid"],
            "creation_filetime": identity["creation_filetime"],
            "session_id": identity["session_id"], "game_sha256": identity["game_sha256"],
            "dll_sha256": identity["dll_sha256"], "experiment_id": identity["experiment_id"],
            "manifest": manifest_pin, "manifest_version": manifest.get("version"),
            "native_source_count": len(manifest["sources"]),
        }
        report["checks"]["v30_005_installation_and_manifest_identity"] = True
        report["battle_source"] = _battle_status(installation)
        _assert_battle_status(report["battle_source"])
        report["checks"]["battle_source_ready_zero_unpatched_never_enabled"] = True

        from work.local_config import game_exe
        exe = game_exe().resolve(strict=True)
        exe_pin = {"path": str(exe), "bytes": exe.stat().st_size, "sha256": _sha256(exe)}
        _require(exe_pin["sha256"] == GAME_SHA256,
                 "configured_game_executable_sha_mismatch")
        report["game_executable"] = exe_pin
        report["checks"]["configured_game_executable_sha"] = True

        expected, audit_pin = _independent_expected(audit_path)
        report["source_audit"] = audit_pin
        report["independent_expected"] = expected
        report["checks"]["checkpoint_fra_outgoing_is_independently_empty"] = True
        report["checks"]["checkpoint_owner_direction_and_complete_scan"] = True

        profile_pin = _file_pin(
            "bridge/information/profiles/country-rivals-memory-1374.json", PROFILE_SHA256)
        profile = _read_json(ROOT / profile_pin["path"], max_bytes=64 * 1024)
        _require(isinstance(profile, Mapping)
                 and profile.get("profile_id") == "country-rivals-memory-1374"
                 and profile.get("game_version") == EXPECTED_VERSION
                 and profile.get("executable", {}).get("sha256") == GAME_SHA256
                 and profile.get("semantics", {}).get("field") == FIELD_KEY
                 and profile.get("semantics", {}).get("scope") == "outgoing_active_rivals_only",
                 "rivals_profile_contract_invalid")
        report["profile"] = profile_pin
        report["checks"]["pinned_native_rivals_profile_contract"] = True

        report["catalog_route_schema"] = _catalog_contract()
        report["checks"]["actual_service_catalog_and_single_field_route"] = True
        report["checks"]["actual_tool_schemas_for_all_acceptance_steps"] = True

        dependencies = _dependency_pins()
        helper_path = Path(__file__).resolve()
        helper = {"path": helper_path.relative_to(ROOT).as_posix(),
                  "bytes": helper_path.stat().st_size, "sha256": _sha256(helper_path),
                  "live_cli": (
                      "python work/live_information_country_rivals.py "
                      "--installation work/runtime/diplomacy-observer-20261028-information-resources-v30-005/installation.json "
                      "--source-audit work/runtime/information-diplomacy-state-20261028-001/rivals-source-001/report-002.json "
                      "--preflight-receipt stage/live-helper-review-001/preflight-001.json "
                      "--output work/runtime/information-diplomacy-state-20261028-001/live-acceptance-001 --run"),
                  "explicit_live_guard": "--run"}
        report["helper"] = helper
        report["dependency_pins"] = dependencies
        report["checks"]["standalone_helper_and_dependency_pins"] = True
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    return report


def _assert_frozen_preflight(receipt_path: Path, current: Mapping[str, Any]) -> None:
    frozen = _read_json(receipt_path)
    _require(isinstance(frozen, Mapping)
             and frozen.get("schema") == "information.country_rivals.live_helper_preflight.v1"
             and frozen.get("status") == "passed"
             and frozen.get("mode") == "offline-preflight-only",
             "frozen_preflight_receipt_invalid")
    for key in ("installation_identity", "source_audit", "independent_expected", "profile",
                "catalog_route_schema", "helper", "dependency_pins"):
        _require(frozen.get(key) == current.get(key),
                 f"frozen_preflight_changed:{key}")


def _request_namespace(output: Path) -> str:
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return "r03-rivals-" + digest


class _ImmediateClient(_BaseClient):
    """Flush MCP frames after each I/O and clean up failed initialization."""

    def __init__(self, installation: Path, output: Path, *, tick: int = 2):
        try:
            super().__init__(installation, output, tick=tick)
        except BaseException:
            self._close_partial()
            raise

    def _flush(self) -> None:
        if not hasattr(self, "path") or not hasattr(self, "transcript"):
            return
        with self.path.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(self.transcript, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    def _close_partial(self) -> None:
        process = getattr(self, "process", None)
        if process is not None and process.poll() is None:
            try:
                if process.stdin is not None:
                    process.stdin.close()
                process.wait(timeout=15)
            except Exception:
                try:
                    process.terminate()
                    process.wait(timeout=10)
                except Exception:
                    pass
        reader = getattr(self, "reader", None)
        if reader is not None:
            reader.join(timeout=3)
        stderr = getattr(self, "stderr", None)
        if stderr is not None and not stderr.closed:
            stderr.close()
        try:
            self._flush()
        except Exception:
            pass

    def send(self, value):
        try:
            return super().send(value)
        finally:
            self._flush()

    def rpc(self, method, params):
        try:
            return super().rpc(method, params)
        finally:
            self._flush()

    def call(self, name: str, **arguments: Any) -> Any:
        _validate_tool_arguments(name, arguments)
        try:
            return super().call(name, **arguments)
        finally:
            self._flush()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._flush()


def _mcp_call(client: _ImmediateClient, output: Path, label: str, name: str,
              arguments: Mapping[str, Any], request_id: str | None = None) -> Any:
    _validate_tool_arguments(name, arguments)
    _write_exclusive(output / f"{label}-request.json",
                     {"name": name, "arguments": dict(arguments), "request_id": request_id})
    try:
        value = client.call(name, **dict(arguments))
    except Exception as exc:
        _write_exclusive(output / f"{label}-failure.json",
                         {"type": type(exc).__name__, "message": str(exc)})
        raise
    # Persist the complete parsed response before any acceptance assertion.
    _write_exclusive(output / f"{label}-response.json", value)
    return value


def _check_no_active_subscriptions(value: Mapping[str, Any], *, label: str) -> list[dict[str, Any]]:
    rows = value.get("subscriptions")
    _require(isinstance(rows, list), f"{label}_subscription_list_missing")
    result = []
    for row in rows:
        _require(isinstance(row, Mapping), f"{label}_subscription_row_invalid")
        subscription = row.get("subscription") if isinstance(row.get("subscription"), Mapping) else row
        _require(isinstance(subscription, Mapping), f"{label}_subscription_shape_invalid")
        state = subscription.get("state")
        _require(state != "active", f"{label}_active_subscription_present")
        result.append({"id": subscription.get("id"), "state": state})
    return result


def _check_information_result(value: Mapping[str, Any], expected: Mapping[str, Any],
                              identity: Mapping[str, Any], subscription_id: str | None = None
                              ) -> dict[str, Any]:
    _require(value.get("complete") is True, "rivals_result_not_complete")
    delivery = value.get("delivery")
    _require(isinstance(delivery, Mapping)
             and delivery.get("status") == "delivered"
             and delivery.get("llm_read") == "unknown",
             "rivals_delivery_or_llm_read_state_invalid")
    context = value.get("context")
    _require(isinstance(context, Mapping)
             and context.get("session_id") == EXPECTED_SESSION
             and context.get("observer") == COUNTRY
             and context.get("game_version") == EXPECTED_VERSION
             and context.get("game_sha256") == GAME_SHA256
             and context.get("game_date") == EXPECTED_DATE,
             "rivals_result_context_mismatch")
    _require(identity.get("session_id") == EXPECTED_SESSION,
             "rivals_context_identity_mismatch")
    items = value.get("items")
    _require(isinstance(items, list) and len(items) == 1
             and isinstance(items[0], Mapping), "rivals_result_items_invalid")
    item = items[0]
    _require(item.get("query") == R03_QUERY
             and item.get("objects") == [R03_QUERY["object"]],
             "rivals_query_echo_or_object_mismatch")
    fields = item.get("fields")
    _require(isinstance(fields, Mapping) and set(fields) == {FIELD_KEY}
             and fields.get(FIELD_KEY) == expected["public_field"],
             "rivals_field_differs_from_independent_checkpoint")
    source = item.get("source")
    _require(isinstance(source, Mapping)
             and source.get("name") == "NativeCountryRivalsSource",
             "rivals_result_not_from_single_native_rivals_source")
    if subscription_id is not None:
        _require(value.get("subscription_id") == subscription_id,
                 "rivals_periodic_subscription_id_mismatch")
    return {
        "result_id": value.get("result_id"),
        "subscription_id": value.get("subscription_id"),
        "field": fields[FIELD_KEY],
        "source_name": source.get("name"),
        "delivery": {"status": delivery.get("status"), "adapter": delivery.get("adapter"),
                     "llm_read": delivery.get("llm_read")},
        "independent_checkpoint_equal": True,
        "llm_read_claimed": False,
    }


def _read_native_event_suffix(path: Path, offset: int) -> dict[str, Any]:
    _require(path.is_file(), "observer_control_log_missing")
    size = path.stat().st_size
    _require(size >= offset, "observer_control_log_shrank")
    length = size - offset
    _require(length <= MAX_NATIVE_LOG_SUFFIX, "observer_control_log_suffix_too_large")
    with path.open("rb") as stream:
        stream.seek(offset)
        suffix = stream.read(length)
    events = []
    for line in suffix.splitlines():
        if len(line) > MAX_NATIVE_LOG_LINE:
            continue
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(row, dict):
            name = row.get("event")
            if isinstance(name, str) and (name.startswith("native_")
                                          or "query" in name.lower()
                                          or "inspection" in name.lower()):
                events.append(row)
    forbidden = [row.get("event") for row in events
                 if isinstance(row.get("event"), str)
                 and ("query" in row["event"].lower()
                      or "inspection" in row["event"].lower())]
    _require(not forbidden, "unexpected_native_query_or_inspection_event")
    return {"path": str(path), "offset": offset, "end": size, "bytes": length,
            "native_events": events, "query_or_inspection_event_count": len(forbidden)}


def _db_readonly_check(path: Path) -> dict[str, Any]:
    import sqlite3

    _require(path.is_file(), f"server_database_missing:{path.name}")
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=0.5)
    try:
        check = connection.execute("PRAGMA quick_check").fetchone()
        _require(check == ("ok",), f"server_database_quick_check_failed:{path.name}")
        return {"path": str(path), "bytes": path.stat().st_size,
                "quick_check": check[0], "verification_connection_closed": True}
    finally:
        connection.close()


def _run(args: argparse.Namespace) -> int:
    output = args.output
    runtime_root = (ROOT / "work/runtime").resolve()
    output_resolved = output.resolve()
    try:
        output_resolved.relative_to(runtime_root)
    except ValueError as exc:
        raise AcceptanceError("output_must_be_under_work_runtime") from exc
    output_resolved.mkdir(parents=True, exist_ok=False)

    report: dict[str, Any] = {
        "schema": "information.country_rivals.live_acceptance.v1",
        "status": "running", "mode": "test-only-live-read", "read_only": True,
        "run_guard": "--run", "game_calls": False, "information_tick_sent": False,
        "diplomacy_dispatched": False,
        "identity_pins": {"pid": EXPECTED_PID, "creation_filetime": EXPECTED_CREATION_FILETIME,
                           "session_id": EXPECTED_SESSION, "game_sha256": GAME_SHA256,
                           "dll_sha256": DLL_SHA256, "manifest_sha256": MANIFEST_SHA256,
                           "game_version": EXPECTED_VERSION, "game_date": EXPECTED_DATE},
        "inputs": {"installation": str(args.installation.resolve()),
                   "source_audit": str(args.source_audit.resolve()),
                   "preflight_receipt": str(args.preflight_receipt.resolve()),
                   "output": str(output_resolved)},
        "checks": {}, "rpc_steps": [], "cancel_started": False,
        "active_subscription_count_before": None, "active_subscription_count_after": None,
        "server_exit_code": None,
    }
    session = None
    client: _ImmediateClient | None = None
    memory = None
    identity: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    before_control: dict[str, Any] | None = None
    before_health: dict[str, Any] | None = None
    before_battle: dict[str, Any] | None = None
    subscription: dict[str, Any] | None = None
    subscription_name = "R03 rivals 2s " + hashlib.sha256(str(output_resolved).encode()).hexdigest()[:10]
    subscription_create_started = False
    cancel_started = False
    lifecycle_after_verified = False
    native_log_path = args.installation.resolve().parent / "control-probe.jsonl"
    native_log_offset: int | None = None
    rpc_counter = 0
    namespace = _request_namespace(output_resolved)

    def call(label: str, name: str, arguments: Mapping[str, Any]) -> Any:
        nonlocal rpc_counter
        rpc_counter += 1
        request_id = arguments.get("request_id") if isinstance(arguments.get("request_id"), str) else None
        value = _mcp_call(client, output_resolved, label, name, arguments, request_id)  # type: ignore[arg-type]
        report["rpc_steps"].append({"step": label, "tool": name, "request_id": request_id,
                                    "response_saved_before_assertions": True})
        return value

    def cancel_once(label: str) -> None:
        nonlocal cancel_started, subscription
        if cancel_started or not isinstance(subscription, Mapping) or subscription.get("state") != "active":
            return
        cancel_started = True
        report["cancel_started"] = True
        args_cancel = {"request_id": f"{namespace}-{label}", "operation": "cancel",
                       "subscription_id": subscription["id"],
                       "expected_version": subscription["version"]}
        cancelled = call(label, "information_manage_subscription", args_cancel)
        row = cancelled.get("subscription") if isinstance(cancelled, Mapping) else None
        _require(isinstance(row, Mapping) and row.get("state") == "cancelled",
                 "rivals_subscription_cancel_failed")
        subscription = dict(row)

    try:
        current_preflight = _build_preflight(args.installation, args.source_audit)
        _write_exclusive(output_resolved / "preflight-recheck.json", current_preflight)
        _require(current_preflight.get("status") == "passed",
                 "live_preflight_recheck_failed")
        _assert_frozen_preflight(args.preflight_receipt, current_preflight)
        report["preflight_status"] = "passed"
        report["dependency_pins"] = current_preflight["dependency_pins"]
        expected = current_preflight["independent_expected"]
        report["expected"] = expected
        report["checks"]["frozen_preflight_and_dependencies_unchanged"] = True

        identity, manifest, manifest_pin = _load_identity(args.installation)
        identity.pop("_acceptance_installation_pin", None)
        report["installation_identity"] = {
            "pid": identity["pid"], "creation_filetime": identity["creation_filetime"],
            "session_id": identity["session_id"], "game_sha256": identity["game_sha256"],
            "dll_sha256": identity["dll_sha256"], "manifest": manifest_pin,
            "native_source_count": len(manifest["sources"]),
        }
        report["build_manifest"] = {"version": manifest["version"],
                                     "source_count": len(manifest["sources"]),
                                     **manifest_pin}

        from bridge.diplomacy import ObserverSession
        from work.local_config import game_exe
        from work.run_alliance_inbound_response import control_snapshot
        session = ObserverSession(args.installation.resolve(), game_exe())
        before_health = session.health()
        _write_exclusive(output_resolved / "before-health.json", before_health)
        _require(before_health.get("status") == "ready"
                 and before_health.get("date_raw") == EXPECTED_DATE
                 and session.record.get("pid") == EXPECTED_PID
                 and session.record.get("creation_filetime") == EXPECTED_CREATION_FILETIME
                 and session.record.get("session_id") == EXPECTED_SESSION
                 and session.record.get("game_sha256") == GAME_SHA256
                 and session.record.get("dll_sha256") == DLL_SHA256,
                 "before_health_identity_or_date_mismatch")
        report["checks"]["before_health_ready_same_identity_date"] = True

        before_control = control_snapshot(EXPECTED_PID, output_resolved / "before-control.json")
        _require((before_control.get("player_slot"), before_control.get("date_raw"),
                  before_control.get("speed"), before_control.get("paused_flag"))
                 == (189, EXPECTED_DATE, 0, 1),
                 "before_control_not_paused_por_date")
        report["before_control"] = before_control
        report["checks"]["before_control_paused_por_date"] = True

        before_battle = _battle_status(args.installation)
        _write_exclusive(output_resolved / "before-battle-source-status.json", before_battle)
        report["before_battle_source"] = before_battle
        _assert_battle_status(before_battle)
        report["checks"]["before_battle_source_ready_zero_unpatched"] = True
        _require(native_log_path.is_file(), "observer_control_log_missing_before_live")
        native_log_offset = native_log_path.stat().st_size
        report["native_log_before_offset"] = native_log_offset

        # Exactly one helper-owned production capture. The adapter itself will
        # perform its own isolated captures only for the active and periodic
        # reads after this receipt is safely written.
        from bridge.information import country_rivals_memory as memory
        capture = memory.capture(args.installation.resolve(), country=COUNTRY)
        _write_exclusive(output_resolved / "production-memory-capture.json", capture)
        context = {"status": "ready", "mode": "live", "session_id": EXPECTED_SESSION,
                   "game_sha256": GAME_SHA256, "observer": COUNTRY,
                   "game_version": EXPECTED_VERSION, "game_date": EXPECTED_DATE}
        valid_capture = memory.validate_capture(
            capture, context, EXPECTED_CREATION_FILETIME, COUNTRY)
        _require(valid_capture is True, "production_capture_strict_validation_failed")
        _require(capture.get("status") == "observed" and capture.get("complete") is True
                 and capture.get("read_only") is True
                 and capture.get("access", {}).get("native_game_calls") is False
                 and capture.get("access", {}).get("target_memory_writes") is False
                 and capture.get("access", {}).get("mcp_query") is False
                 and capture.get("access", {}).get("control_or_business_dispatch") is False,
                 "production_capture_read_only_contract_invalid")
        passes = []
        for pass_name in ("before", "after"):
            outer = capture.get(pass_name)
            record = outer.get("record") if isinstance(outer, Mapping) else None
            field = record.get("fields", {}).get(FIELD_KEY) if isinstance(record, Mapping) else None
            private = record.get("private") if isinstance(record, Mapping) else None
            _require(isinstance(field, Mapping) and field.get("status") == "known"
                     and field.get("value") == expected["outgoing_rivals"]
                     and field.get("complete") is True and field.get("partial") is False,
                     f"production_capture_{pass_name}_rivals_differ_from_checkpoint")
            _require(isinstance(private, Mapping)
                     and private.get("native_entries") == []
                     and private.get("rival_count") == 0
                     and private.get("rival_list_head") is None,
                     f"production_capture_{pass_name}_native_list_not_empty")
            passes.append({"pass": pass_name, "rivals": field["value"],
                           "rival_count": private["rival_count"]})
        _require(capture.get("doublepass", {}).get("performed") is True
                 and capture.get("doublepass", {}).get("consistent") is True
                 and capture.get("doublepass", {}).get("mismatches") == [],
                 "production_capture_doublepass_not_consistent")
        report["production_capture"] = {
            "path": "production-memory-capture.json", "strict_validate_capture": True,
            "passes": passes, "direct_capture_calls": 1,
            "mcp_or_game_calls": False, "checkpoint_outgoing_equal": True,
        }
        report["checks"]["one_strict_production_capture_equals_checkpoint"] = True

        client = _ImmediateClient(args.installation.resolve(), output_resolved, tick=2)
        before_list = call(
            "rpc-01-subscriptions-before", "information_manage_subscription",
            {"request_id": f"{namespace}-subscriptions-before", "operation": "list"})
        report["subscriptions_before"] = _check_no_active_subscriptions(
            before_list, label="before")
        report["active_subscription_count_before"] = 0
        report["checks"]["no_preexisting_active_subscription"] = True

        active = call(
            "rpc-02-active-query", "information_query",
            {"request_id": f"{namespace}-active-query", "queries": [R03_QUERY]})
        active_summary = _check_information_result(active, expected, identity)
        report["active"] = active_summary
        report["checks"]["active_query_exact_independent_outgoing_set"] = True

        report_config = {"name": "R03 rivals live acceptance", "queries": [R03_QUERY], "detail": "raw"}
        configured = call(
            "rpc-03-report-create", "information_manage_report",
            {"request_id": f"{namespace}-report-create", "operation": "create",
             "config": report_config})
        report_value = configured.get("report") if isinstance(configured, Mapping) else None
        _require(isinstance(report_value, Mapping) and isinstance(report_value.get("id"), str)
                 and report_value.get("queries") == [R03_QUERY]
                 and report_value.get("detail") == "raw",
                 "rivals_report_configuration_not_preserved")
        report["report"] = {"id": report_value["id"], "queries": report_value["queries"],
                            "detail": report_value["detail"]}
        report["checks"]["periodic_report_uses_same_query"] = True

        schedule = {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}
        subscription_create_started = True
        created = call(
            "rpc-04-periodic-create", "information_manage_subscription",
            {"request_id": f"{namespace}-periodic-create", "operation": "create",
             "config": {"name": subscription_name, "kind": "periodic",
                        "report_id": report_value["id"], "enabled": True,
                        "schedule": schedule}})
        created_value = created.get("subscription") if isinstance(created, Mapping) else None
        _require(isinstance(created_value, Mapping)
                 and isinstance(created_value.get("id"), str)
                 and type(created_value.get("version")) is int
                 and created_value.get("state") == "active"
                 and created_value.get("report_id") == report_value["id"]
                 and created_value.get("schedule") == schedule,
                 "rivals_periodic_subscription_not_active_or_exact")
        subscription = dict(created_value)
        report["subscription"] = {"id": subscription["id"],
                                   "version": subscription["version"],
                                   "state": subscription["state"],
                                   "schedule": subscription["schedule"]}
        report["checks"]["real_two_second_periodic_subscription_active"] = True

        periodic_result = None
        periodic_summary = None
        attempts = []
        for index in range(60):
            listed = call(f"rpc-05-results-{index + 1:02d}",
                          "information_list_results", {"limit": 100})
            rows = listed.get("results") if isinstance(listed, Mapping) else None
            _require(isinstance(rows, list), "rivals_periodic_results_missing")
            candidate = next((row for row in rows if isinstance(row, Mapping)
                              and row.get("subscription_id") == subscription["id"]), None)
            attempts.append({"attempt": index + 1, "result_count": len(rows),
                             "matching_subscription_result": candidate is not None})
            if candidate is not None:
                periodic_result = candidate
                _write_exclusive(output_resolved / "periodic-first-result.json", candidate)
                periodic_summary = _check_information_result(
                    candidate, expected, identity, subscription_id=subscription["id"])
                break
            time.sleep(0.5)
        _require(periodic_result is not None and periodic_summary is not None,
                 "first_real_periodic_rivals_result_missing")
        _require(active.get("items", [{}])[0].get("fields")
                 == periodic_result.get("items", [{}])[0].get("fields"),
                 "active_and_periodic_rivals_fields_differ")
        report["periodic"] = {**periodic_summary, "attempts": attempts,
                              "interval": {"basis": "real", "every": 2, "unit": "seconds"},
                              "same_service_as_active_query": True}
        report["checks"]["first_real_periodic_result_exact_checkpoint"] = True
        report["checks"]["active_and_periodic_fields_equal"] = True

        cancel_once("rpc-06-cancel")
        after_list = call(
            "rpc-07-subscriptions-after", "information_manage_subscription",
            {"request_id": f"{namespace}-subscriptions-after", "operation": "list"})
        report["subscriptions_after"] = _check_no_active_subscriptions(
            after_list, label="after")
        report["active_subscription_count_after"] = 0
        status = call("rpc-08-status-after", "information_status", {})
        status_rows = status.get("subscriptions") if isinstance(status, Mapping) else None
        _require(isinstance(status_rows, list)
                 and all(isinstance(row, Mapping)
                         and isinstance(row.get("subscription"), Mapping)
                         and row["subscription"].get("state") != "active"
                         and row.get("runtime", {}).get("state") != "active"
                         for row in status_rows),
                 "rivals_status_reports_active_subscription")
        report["status_after"] = {"active_subscription_count": 0,
                                  "subscription_rows": len(status_rows)}
        lifecycle_after_verified = True
        report["checks"]["cancelled_once_no_active_subscription"] = True
        report["checks"]["status_reports_no_active_subscription"] = True
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        # If creation succeeded but a later assertion failed, clean up once.
        # An unknown cancel is never replayed; final list/status are new
        # read-only diagnostics when the service is still available.
        if client is not None and subscription is not None and not cancel_started:
            try:
                cancel_once("rpc-cleanup-cancel")
                report["cleanup_cancel"] = "cancelled_once"
            except Exception as exc:
                report["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
        if client is not None and subscription_create_started and not lifecycle_after_verified:
            try:
                if subscription is None:
                    diagnostic = call(
                        "rpc-cleanup-subscriptions-after-unknown-create",
                        "information_manage_subscription",
                        {"request_id": f"{namespace}-cleanup-subscriptions-after-create",
                         "operation": "list"})
                    rows = diagnostic.get("subscriptions") if isinstance(diagnostic, Mapping) else None
                    matches = []
                    if isinstance(rows, list):
                        for row in rows:
                            sub = row.get("subscription") if isinstance(row, Mapping) and isinstance(row.get("subscription"), Mapping) else row
                            if isinstance(sub, Mapping) and sub.get("name") == subscription_name and sub.get("state") == "active":
                                matches.append(dict(sub))
                    if len(matches) == 1:
                        subscription = matches[0]
                        cancel_once("rpc-cleanup-cancel-after-unknown-create")
                    elif len(matches) > 1:
                        raise AcceptanceError("multiple_active_subscriptions_after_unknown_create")
                if not lifecycle_after_verified:
                    final_rows = call(
                        "rpc-cleanup-subscriptions-final", "information_manage_subscription",
                        {"request_id": f"{namespace}-cleanup-subscriptions-final",
                         "operation": "list"})
                    report["subscriptions_after_cleanup"] = _check_no_active_subscriptions(
                        final_rows, label="cleanup")
                    report["active_subscription_count_after"] = 0
                    final_status = call("rpc-cleanup-status-final", "information_status", {})
                    final_subs = final_status.get("subscriptions") if isinstance(final_status, Mapping) else None
                    _require(isinstance(final_subs, list)
                             and all(isinstance(row, Mapping)
                                     and isinstance(row.get("subscription"), Mapping)
                                     and row["subscription"].get("state") != "active"
                                     and row.get("runtime", {}).get("state") != "active"
                                     for row in final_subs),
                             "cleanup_status_reports_active_subscription")
                    lifecycle_after_verified = True
                    report["checks"]["cleanup_final_state_no_active_subscription"] = True
            except Exception as exc:
                report["cleanup_lifecycle_error"] = {"type": type(exc).__name__,
                                                       "message": str(exc)}
                report["status"] = "failed"

        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report["close_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
            report["server_exit_code"] = client.process.returncode
            report["mcp_client_reader_stopped"] = not client.reader.is_alive()
            report["mcp_stderr_closed"] = client.stderr.closed
            report["checks"]["server_exit_zero"] = client.process.returncode == 0
            report["checks"]["mcp_reader_and_stderr_closed"] = (
                report["mcp_client_reader_stopped"] and report["mcp_stderr_closed"])
            if client.process.returncode != 0 or not report["checks"]["mcp_reader_and_stderr_closed"]:
                report["status"] = "failed"
            try:
                report["closed_databases"] = [
                    _db_readonly_check(output_resolved / "information.sqlite3"),
                    _db_readonly_check(output_resolved / "diplomacy.sqlite3"),
                ]
                report["checks"]["server_databases_closed_and_readable"] = True
            except Exception as exc:
                report["database_close_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"

        if session is not None:
            try:
                after_health = session.health()
                _write_exclusive(output_resolved / "after-health.json", after_health)
                _require(after_health.get("status") == "ready"
                         and after_health.get("date_raw") == EXPECTED_DATE,
                         "after_health_not_ready_same_date")
                report["after_health"] = {"status": after_health.get("status"),
                                           "date_raw": after_health.get("date_raw")}
                report["checks"]["after_health_ready_same_date"] = True
            except Exception as exc:
                report["after_health_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"

        if before_control is not None:
            try:
                from work.run_alliance_inbound_response import control_snapshot
                after_control = control_snapshot(EXPECTED_PID,
                                                 output_resolved / "after-control.json")
                keys = ("player_slot", "date_raw", "speed", "paused_flag")
                _require(all(before_control.get(key) == after_control.get(key) for key in keys),
                         "control_state_changed_during_acceptance")
                report["after_control"] = after_control
                report["checks"]["control_date_pause_player_preserved"] = True
            except Exception as exc:
                report["after_control_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"

        if before_battle is not None:
            try:
                after_battle = _battle_status(args.installation)
                _write_exclusive(output_resolved / "after-battle-source-status.json", after_battle)
                _assert_battle_status(after_battle)
                before_value = before_battle.get("value", {})
                after_value = after_battle.get("value", {})
                stable_keys = ("state", "pid", "creation_filetime", "exe_sha256", "dll_sha256",
                               "code_patch_installed", "dll_pinned", "unwind_registered",
                               "capture_complete", "captured", "last_sequence",
                               "fragment_sink_pending", "business_export_available")
                _require(all(before_value.get(key) == after_value.get(key) for key in stable_keys),
                         "battle_source_state_changed_during_acceptance")
                report["after_battle_source"] = after_battle
                report["checks"]["battle_source_ready_zero_unpatched_unchanged"] = True
            except Exception as exc:
                report["after_battle_source_error"] = {"type": type(exc).__name__,
                                                        "message": str(exc)}
                report["status"] = "failed"

        if native_log_offset is not None:
            try:
                suffix = _read_native_event_suffix(native_log_path, native_log_offset)
                _write_exclusive(output_resolved / "native-query-log-suffix.json", suffix)
                report["native_query_log_suffix"] = {"offset": suffix["offset"],
                                                     "end": suffix["end"],
                                                     "bytes": suffix["bytes"],
                                                     "query_or_inspection_event_count": 0}
                report["checks"]["no_native_query_or_inspection_events_added"] = True
            except Exception as exc:
                report["native_log_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"

        report["cancel_started"] = cancel_started
        report["information_tick_sent"] = any(
            row.get("tool") == "information_tick" for row in report["rpc_steps"])
        report["diplomacy_dispatched"] = False
        report["game_calls"] = False
        if report["information_tick_sent"] or report["diplomacy_dispatched"] or report["game_calls"]:
            report["status"] = "failed"
        _write_exclusive(output_resolved / "report.json", report)

    print(json.dumps({key: report.get(key) for key in
                      ("status", "checks", "error", "server_exit_code", "expected")},
                     ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def _preflight_only(args: argparse.Namespace) -> int:
    report = _build_preflight(args.installation, args.source_audit)
    _write_exclusive(args.preflight_report, report)
    _require(report.get("status") == "passed", "offline_preflight_failed")
    dependency_document = {
        "schema": "information.country_rivals.live_helper_dependencies.v1",
        "status": "passed", "helper": report["helper"],
        "dependencies": report["dependency_pins"],
        "preflight": {"path": str(args.preflight_report.resolve()),
                      "bytes": args.preflight_report.stat().st_size,
                      "sha256": _sha256(args.preflight_report)},
        "runtime_freeze_included": False,
    }
    _write_exclusive(args.dependency_report, dependency_document)
    print(json.dumps({"status": report["status"],
                      "preflight": str(args.preflight_report.resolve()),
                      "helper_dependencies": str(args.dependency_report.resolve()),
                      "checks": report["checks"]}, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=ROOT / INSTALLATION_DEFAULT,
                        help="pinned v30-005 installation.json")
    parser.add_argument("--source-audit", type=Path, default=ROOT / AUDIT_DEFAULT,
                        help="independent R03 source/checkpoint audit report-002.json")
    parser.add_argument("--preflight-only", action="store_true",
                        help="offline-only pins plus real service catalog/schema/route")
    parser.add_argument("--preflight-report", type=Path, default=ROOT / PREFLIGHT_DEFAULT,
                        help="new offline preflight receipt; existing files are never overwritten")
    parser.add_argument("--dependency-report", type=Path, default=ROOT / DEPENDENCY_REPORT_DEFAULT,
                        help="new standalone helper dependency pin receipt")
    parser.add_argument("--preflight-receipt", type=Path, default=ROOT / PREFLIGHT_DEFAULT,
                        help="passed frozen offline preflight required by --run")
    parser.add_argument("--output", type=Path, default=ROOT / LIVE_OUTPUT_DEFAULT,
                        help="new work/runtime live acceptance directory; required with --run")
    parser.add_argument("--run", action="store_true",
                        help="explicitly enable one production capture and R03 MCP acceptance")
    args = parser.parse_args(argv)
    _require(args.preflight_only != args.run,
             "choose_exactly_one_of_--preflight-only_or_--run")
    if args.preflight_only:
        return _preflight_only(args)
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
