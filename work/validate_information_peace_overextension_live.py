"""Single-query, paused-live acceptance for P05 overextension.

The run is deliberately narrow: one operator-only peace-context discovery
identifies the current FRA→BUR war, then one MCP ``information_query`` asks
for the selected province-88 demand.  Every request, returned MCP value, and
the matching bounded observer event is written before checking it.  A checker
failure never retries a native or MCP query.

This helper is inert unless the required ``--test-only`` guard is supplied.
It performs read-only observation only; it does not advance time, save,
reload, submit diplomacy, install a module, or start a game.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information.catalog import get_topic
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_trade_power_live import CheckedClient


EXPECTED_VERSION = "1.37.4"
EXPECTED_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
DEFAULT_INSTALLATION = (
    ROOT
    / "work/runtime/diplomacy-observer-20261027-information-battle-v30-003"
    / "installation.json"
)
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_LINE_BYTES = 256 * 1024
MAX_APPENDED_LOG_BYTES = 512 * 1024
WAR_ID_RE = re.compile(r"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")


class AcceptanceError(RuntimeError):
    """A bounded input, identity, source, or projection check failed."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise AcceptanceError(f"{label}_must_be_integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isdecimal():
        result = int(value, 10)
    else:
        raise AcceptanceError(f"{label}_must_be_decimal")
    _require(result > 0, f"{label}_must_be_positive")
    return result


def _load_identity(
        installation: Path, *, pid: int, creation: int,
        game_sha256: str, dll_sha256: str) -> dict[str, Any]:
    value = _read_json(installation)
    _require(isinstance(value, dict), "installation_not_object")
    _require(value.get("pid") == pid, "installation_pid_pin_mismatch")
    _require(value.get("creation_filetime") == creation,
             "installation_creation_pin_mismatch")
    _require(value.get("game_sha256") == game_sha256,
             "installation_game_sha_pin_mismatch")
    _require(value.get("dll_sha256") == dll_sha256,
             "installation_dll_sha_pin_mismatch")
    _require(isinstance(value.get("session_id"), str)
             and value["session_id"], "installation_session_missing")
    _require(value.get("experiment_id"), "installation_experiment_missing")
    return value


def _request_namespace(output: Path) -> str:
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"p05-oe-{digest}"


def _read_appended_events(path: Path, offset: int) -> list[dict[str, Any]]:
    """Read only the bounded suffix written by the one MCP query."""
    _require(path.is_file(), f"observer_log_missing:{path}")
    size = path.stat().st_size
    _require(size >= offset, "observer_log_went_backwards")
    length = size - offset
    _require(length <= MAX_APPENDED_LOG_BYTES,
             f"observer_log_suffix_too_large:{length}")
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    events: list[dict[str, Any]] = []
    for line in data.splitlines():
        if len(line) > MAX_RESPONSE_LINE_BYTES:
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _peace_discovery(
        installation: Path, output: Path, *, game_date: int,
        pid: int, creation: int) -> tuple[str, dict[str, Any]]:
    """Issue exactly one operator-only QUERY1 and select one current war."""
    request = {
        "method": "DiplomacyTools.inspect_peace_contexts",
        "arguments": {
            "action_id": "white_peace",
            "actor": "FRA",
            "recipient": "BUR",
            "phase": "initiate",
        },
    }
    _write_exclusive(output / "discovery-request.json", request)
    session = ObserverSession(installation, game_exe())
    journal_path = output / "discovery-journal.sqlite3"
    journal = DurableJournal(
        journal_path,
        experiment_id=session.experiment_id,
        session_id=session.session_id,
        global_request_ids=True,
    )
    try:
        health = session.health()
        _write_exclusive(output / "discovery-health.json", health)
        _require(health.get("status") == "ready", "discovery_session_unready")
        _require(health.get("date_raw") == game_date,
                 "discovery_date_pin_mismatch")
        _require(session.record.get("pid") == pid
                 and session.record.get("creation_filetime") == creation,
                 "discovery_identity_pin_mismatch")
        # QUERY1 is the public ObserverSession route.  DiplomacyTools wraps
        # this same route for information queries, but does not expose a
        # method named inspect_peace_contexts itself.
        response = session.inspect_peace_contexts(
            "white_peace", "FRA", "BUR", "initiate")
        _require(isinstance(response, dict), "discovery_response_not_object")
        _write_exclusive(output / "discovery-response.json", response)
    finally:
        journal.close()

    _require(response.get("event") == "native_peace_context_inspection",
             "discovery_event_type_mismatch")
    _require(response.get("context_discovery") is True
             and response.get("query_complete") is True,
             "discovery_not_complete")
    _require(response.get("war_context_enumeration_complete") is True,
             "war_enumeration_not_complete")
    rows = response.get("war_contexts")
    _require(isinstance(rows, list), "discovery_war_contexts_missing")
    matches = [row for row in rows if isinstance(row, dict)
               and row.get("war_id")
               and row.get("actor") == "FRA"
               and row.get("recipient") == "BUR"
               and row.get("pair_at_war") is True]
    _require(len(matches) == 1, f"current_fra_bur_war_not_unique:{len(matches)}")
    war_id = matches[0]["war_id"]
    _require(isinstance(war_id, str) and WAR_ID_RE.fullmatch(war_id),
             "current_war_id_invalid")
    _write_exclusive(output / "selected-war.json", {
        "war_id": war_id,
        "row": matches[0],
        "discovery": {
            "query_complete": response.get("query_complete"),
            "war_context_enumeration_complete": response.get(
                "war_context_enumeration_complete"),
            "context_complete": matches[0].get("context_complete"),
        },
    })
    return war_id, response


class _ImmediateClient(CheckedClient):
    """CheckedClient that flushes its complete wire transcript after each I/O."""

    def _flush_transcript(self) -> None:
        self.path.write_text(
            json.dumps(self.transcript, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def send(self, value):
        result = super().send(value)
        self._flush_transcript()
        return result

    def rpc(self, method, params):
        try:
            return super().rpc(method, params)
        finally:
            self._flush_transcript()


def _query(war_id: str) -> dict[str, Any]:
    return {
        "topic": "P05",
        "object": {
            "type": "war",
            "war_id": war_id,
            "actor": "FRA",
            "recipient": "BUR",
        },
        "fields": ["overextension"],
        "parameters": {
            "action_id": "cede_province",
            "phase": "initiate",
            "peace_context": {
                "war_id": war_id,
                "direction": "demand",
                "terms": [{
                    "action_id": "cede_province",
                    "beneficiary": "FRA",
                    "province_ids": [88],
                }],
            },
        },
    }


def _matching_observer_event(
        installation: Path, offset: int, *, war_id: str,
        game_date: int) -> dict[str, Any]:
    log = installation.resolve().parent / "control-probe.jsonl"
    events = _read_appended_events(log, offset)
    matches = []
    for event in events:
        if (event.get("event") == "native_peace_province_offer_inspection"
                and event.get("action_id") == "cede_province"
                and event.get("actor") == "FRA"
                and event.get("recipient") == "BUR"
                and event.get("phase") == "initiate"
                and event.get("war_id") == war_id
                and event.get("date_raw") == game_date
                and event.get("direction") == "demand"
                and isinstance(event.get("query_id"), str)
                and event.get("query_id")):
            matches.append(event)
    _require(len(matches) == 1,
             f"matching_observer_response_not_unique:{len(matches)}")
    return matches[0]


def _raw_overextension(observer_event: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """Prefer an exposed public consequence; otherwise use the same event's native rows.

    The current observer log normally contains ``native_consequences`` while
    ``DiplomacyTools`` constructs ``peace_consequences`` in memory.  The
    fallback is intentionally labelled native-source evidence and never
    claims that an absent public key was returned by the observer.
    """
    public = observer_event.get("peace_consequences")
    if isinstance(public, dict) and isinstance(public.get("overextension"), dict):
        return "peace_consequences.overextension", deepcopy(public["overextension"])
    native = observer_event.get("native_consequences")
    _require(isinstance(native, dict)
             and isinstance(native.get("overextension"), dict),
             "observer_overextension_missing")
    return "native_consequences.overextension", deepcopy(native["overextension"])


def _compare_projection(
        result: Mapping[str, Any], observer_event: Mapping[str, Any],
        query: Mapping[str, Any]) -> dict[str, Any]:
    topic = get_topic("P05")
    field_catalog = topic["fields"]["overextension"]
    _require(field_catalog.get("coverage") == "partial",
             "P05_overextension_coverage_was_upgraded")
    _require(field_catalog.get("paths", ())[-1]
             == "peace_consequences.overextension",
             "P05_public_path_missing")

    items = result.get("items")
    _require(isinstance(items, list) and len(items) == 1,
             "information_result_item_count")
    item = items[0]
    _require(isinstance(item, dict) and item.get("query") == query,
             "information_query_echo_mismatch")
    field = item.get("fields", {}).get("overextension")
    _require(isinstance(field, dict) and field.get("status") == "known",
             f"information_overextension_not_known:{field!r}")
    value = field.get("value")
    _require(isinstance(value, dict), "information_overextension_value_missing")
    _require(value.get("source") == "native_peace_overextension"
             and value.get("scope") == "selected_territorial_preview"
             and value.get("available") is True
             and value.get("complete") is True,
             "information_overextension_semantics_mismatch")
    _require(value.get("unsupported_territorial_terms") is False,
             "information_overextension_unsupported_terms_changed")
    rows = value.get("countries")
    _require(isinstance(rows, list) and {row.get("country") for row in rows}
             == {"BUR", "FRA"}, "information_country_rows_mismatch")
    by_country = {row["country"]: row for row in rows}
    _require(by_country["BUR"].get("lost_province_ids") == [88]
             and by_country["FRA"].get("gained_province_ids") == [88],
             "information_province_direction_mismatch")
    for row in by_country.values():
        _require(row.get("scale") == 1000 and row.get("unit") == "fraction"
                 and row.get("complete") is True,
                 "information_row_units_or_complete_mismatch")

    raw_path, raw_value = _raw_overextension(observer_event)
    raw_rows = raw_value.get("countries")
    _require(isinstance(raw_rows, list), "observer_overextension_rows_missing")
    raw_by_country = {row.get("country"): row for row in raw_rows
                      if isinstance(row, dict)}
    _require(set(raw_by_country) == {"BUR", "FRA"},
             "observer_overextension_country_rows_mismatch")
    compare_keys = (
        "current_raw", "current_recomputed_raw", "cache_matches_recomputed",
        "gained_raw", "lost_raw", "delta_raw", "projected_raw",
        "gained_province_ids", "lost_province_ids", "scale",
    )
    for country in ("BUR", "FRA"):
        for key in compare_keys:
            _require(by_country[country].get(key) == raw_by_country[country].get(key),
                     f"observer_information_mismatch:{country}:{key}")
    _require(result.get("complete") is True and item.get("complete") is True,
             "information_complete_contract_mismatch")
    nested_context_complete = (
        observer_event.get("native_war_context", {}).get("context_complete")
        if isinstance(observer_event.get("native_war_context"), dict) else None
    )
    _require(nested_context_complete is False,
             "nested_war_context_was_promoted")
    return {
        "field_status": field.get("status"),
        "catalog_coverage": field_catalog.get("coverage"),
        "catalog_paths": list(field_catalog.get("paths", ())),
        "value": deepcopy(value),
        "raw_observer_path": raw_path,
        "raw_observer_value": raw_value,
        "raw_matches_information_value": True,
        "nested_war_context_complete": nested_context_complete,
        "public_peace_consequences_exposed_in_observer_event": (
            raw_path == "peace_consequences.overextension"),
    }


def run(args: argparse.Namespace) -> int:
    installation = args.installation.resolve(strict=True)
    game_sha = args.game_sha256.lower()
    dll_sha = args.dll_sha256.lower()
    _require(SHA_RE.fullmatch(game_sha), "game_sha256_invalid")
    _require(SHA_RE.fullmatch(dll_sha), "dll_sha256_invalid")
    identity = _load_identity(
        installation, pid=args.pid, creation=args.creation_filetime,
        game_sha256=game_sha, dll_sha256=dll_sha)
    _require(args.game_date > 0, "game_date_must_be_positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    namespace = _request_namespace(output)
    report: dict[str, Any] = {
        "schema": "information_peace_overextension_live_acceptance.v1",
        "status": "running",
        "mode": "test-only",
        "read_only": True,
        "installation": str(installation),
        "installation_sha256": _sha256(installation),
        "identity_pins": {
            "pid": args.pid,
            "creation_filetime": args.creation_filetime,
            "game_sha256": game_sha,
            "dll_sha256": dll_sha,
            "game_version": EXPECTED_VERSION,
            "game_date": args.game_date,
        },
        "session_id": identity["session_id"],
        "request_namespace": namespace,
        "checks": {},
        "limitations": [
            "Only one context discovery and one P05 information_query are issued.",
            "A failed checker never retries either request.",
            "The MCP boundary exposes the public field projection; when the raw observer event lacks a separate peace_consequences key, the report labels native_consequences evidence explicitly.",
        ],
        "business_actions_submitted": False,
        "native_read_only_queries": True,
        "date_advance_save_reload": False,
    }
    client: _ImmediateClient | None = None
    before: dict[str, Any] | None = None
    observer_offset: int | None = None
    try:
        before = control_snapshot(args.pid, output / "before-control.json")
        _require(
            (before.get("player_slot"), before.get("paused_flag"),
             before.get("speed"), before.get("date_raw"))
            == (189, 1, 0, args.game_date),
            "paused_control_pin_mismatch",
        )
        _write_exclusive(output / "installation-identity.json", {
            "installation": identity,
            "installation_sha256": report["installation_sha256"],
        })

        war_id, discovery = _peace_discovery(
            installation, output, game_date=args.game_date,
            pid=args.pid, creation=args.creation_filetime)
        report["war_id"] = war_id
        report["checks"]["current_fra_bur_war_discovered_once"] = True
        report["discovery_summary"] = {
            "query_id": discovery.get("query_id"),
            "session_id": discovery.get("session_id"),
            "war_context_enumeration_complete": discovery.get(
                "war_context_enumeration_complete"),
        }

        client = _ImmediateClient(installation, output, tick=0)
        query = _query(war_id)
        request_id = f"{namespace}-information-query"
        request = {
            "name": "information_query",
            "arguments": {"request_id": request_id, "queries": [query]},
        }
        _write_exclusive(output / "information-query-request.json", request)
        log_path = installation.parent / "control-probe.jsonl"
        _require(log_path.is_file(), "observer_log_missing_before_query")
        observer_offset = log_path.stat().st_size
        response = client.call(
            "information_query", request_id=request_id, queries=[query])
        _write_exclusive(output / "information-query-response.json", response)
        report["request_id"] = request_id

        observer_event = _matching_observer_event(
            installation, observer_offset, war_id=war_id,
            game_date=args.game_date)
        _write_exclusive(output / "observer-response.json", observer_event)
        comparison = _compare_projection(response, observer_event, query)
        _write_exclusive(output / "comparison.json", comparison)
        report["checks"].update({
            "single_mcp_query_returned_known_overextension": True,
            "observer_rows_match_information_rows": True,
            "raw_units_and_partial_coverage_preserved": True,
        })
        report["comparison"] = comparison
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={
            "type": type(exc).__name__, "message": str(exc),
        })
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report.update(status="failed", close_error={
                    "type": type(exc).__name__, "message": str(exc),
                })
            report["server_exit_code"] = client.process.returncode
            report["checks"]["server_exit_zero"] = client.process.returncode == 0
        if before is not None:
            try:
                after = control_snapshot(args.pid, output / "after-control.json")
                preserved = all(
                    before.get(key) == after.get(key)
                    for key in ("date_raw", "paused_flag", "speed", "player_slot")
                )
                report["checks"]["paused_control_preserved"] = preserved
                if not preserved:
                    report["status"] = "failed"
            except Exception as exc:
                report.update(status="failed", after_control_error={
                    "type": type(exc).__name__, "message": str(exc),
                })
        _write_exclusive(output / "report.json", report)
    print(json.dumps({key: report.get(key) for key in
                      ("status", "checks", "error", "war_id", "server_exit_code")}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-only", action="store_true", required=True,
        help="required read-only guard; no action, save, or time advance is allowed",
    )
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--output", type=Path, required=True,
                        help="new, non-existing exclusive output directory")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--creation-filetime", type=int, required=True)
    parser.add_argument("--game-sha256", required=True)
    parser.add_argument("--dll-sha256", required=True)
    parser.add_argument(
        "--expected-date", "--game-date", dest="game_date", type=int,
        required=True, help="current paused raw EU4 date/hour tick",
    )
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
