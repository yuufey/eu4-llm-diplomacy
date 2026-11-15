"""Run the bounded R01 current-relation MCP acceptance when explicitly requested.

The default invocation and ``--help`` only print this command's help.  The
``--run`` switch is the sole path that starts the information server.  The
acceptance uses one paused, read-only session and checks the independently
decoded network/pair reference; it never submits diplomacy, saves, restarts,
or advances the game.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_trade_power_live import CheckedClient, write


STAGE = ROOT / "work/runtime/information-relation-current-20261027-001"
DEFAULT_INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"
DEFAULT_EXPECTED = STAGE / "independent-network-expected-002.json"
DEFAULT_OUTPUT = STAGE / "live-acceptance-001"
NETWORK_FAMILIES = ("alliance", "royal_marriage")
PAIR_FAMILIES = (
    "vassalization", "guarantee", "support_independence", "military_access", "rival",
    "alliance", "royal_marriage",
)
FIELDS = ("relation_type", "status", "grantor", "recipient")


def _read_json(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"reference_size_out_of_bound:{size}")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("reference_must_be_object")
    return value


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(expected: Mapping[str, Any], binding: Mapping[str, Any]) -> tuple[str, Any]:
    candidates = []
    for key in ("header", "identity", "context"):
        value = expected.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)
    candidates.append(expected)
    session = game_date = None
    for candidate in candidates:
        if session is None:
            session = candidate.get("session_id") or candidate.get("installation_session_id")
        if game_date is None:
            game_date = candidate.get("game_date")
            if isinstance(game_date, Mapping):
                game_date = game_date.get("value") or game_date.get("raw")
    session = session or binding.get("session_id")
    if session is None or game_date is None:
        raise ValueError("reference_identity_missing_session_or_game_date")
    return str(session), game_date


def _family_record(container: Any, family: str) -> Mapping[str, Any] | None:
    if not isinstance(container, Mapping):
        return None
    direct = container.get(family)
    if isinstance(direct, Mapping):
        return direct
    for key in ("fields", "families", "network", "country_network", "active_partners", "statuses"):
        nested = container.get(key)
        if isinstance(nested, Mapping):
            value = nested.get(family)
            if isinstance(value, Mapping):
                return value
            if key == "active_partners" and isinstance(value, list):
                return {"status": "known", "value": value}
            if key == "statuses" and isinstance(value, str):
                return {"status": value}
    return None


def _network_container(expected: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("network", "country_network", "active_partners"):
        value = expected.get(key)
        if isinstance(value, Mapping):
            return value
    request = expected.get("request")
    if isinstance(request, Mapping) and request.get("mode") == "network":
        return expected
    if isinstance(expected.get("fields"), Mapping):
        return expected
    raise AssertionError("network_reference_missing")


def _expected_status(record: Mapping[str, Any]) -> str:
    value = record.get("status")
    if isinstance(value, str):
        return value
    if isinstance(record.get("field"), Mapping) and isinstance(record["field"].get("status"), str):
        return record["field"]["status"]
    return "unknown"


def _active_partners(record: Mapping[str, Any]) -> set[str]:
    values = record.get("active_partners", record.get("value", record.get("partners", [])))
    if isinstance(values, Mapping):
        values = values.get("value", [])
    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    for row in values:
        if isinstance(row, str):
            result.add(row)
        elif isinstance(row, Mapping):
            active = row.get("active") is True or row.get("status") == "active"
            if active:
                partner = row.get("country") or row.get("partner")
                if isinstance(partner, str):
                    result.add(partner)
    return result


def _network_actual_partners(field: Mapping[str, Any], family: str) -> set[str]:
    values = field.get("value", [])
    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    for row in values:
        if not isinstance(row, Mapping):
            continue
        if row.get("relation_type") != family:
            continue
        partner = row.get("partner") or row.get("country")
        # relation_state publishes a flat row.  For example, status rows are
        # {relation_type, actor, partner, status:"known", value:"active"}
        # and role rows use status:"not_applicable".  Every such row is an
        # active partner row; unresolved rows carry partner=None.
        if isinstance(partner, str):
            result.add(partner)
    return result


def _check_network_item(item: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    fields = item.get("fields")
    if not isinstance(fields, Mapping):
        raise AssertionError("network_fields_missing")
    container = _network_container(expected)
    for family in NETWORK_FAMILIES:
        wanted = _family_record(container, family)
        if wanted is None:
            raise AssertionError(f"network_family_reference_missing:{family}")
        wanted_status = _expected_status(wanted)
        actual_status = fields["status"].get("status")
        if wanted_status == "known":
            assert actual_status == "known", (family, fields["status"])
        elif wanted_status in {"partial", "unknown"}:
            assert actual_status != "known", (family, wanted_status, fields["status"])
        wanted_partners = _active_partners(wanted)
        for field_name in FIELDS:
            field = fields.get(field_name)
            assert isinstance(field, Mapping), (family, field_name)
            if wanted_status == "known":
                assert field.get("status") == "known", (family, field_name, field)
            assert _network_actual_partners(field, family) == wanted_partners, (family, field_name, field, wanted_partners)


def _pair_rows(item: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    fields = item.get("fields")
    if not isinstance(fields, Mapping) or not isinstance(fields.get("status"), Mapping):
        raise AssertionError("pair_status_field_missing")
    rows = fields["status"].get("value")
    if not isinstance(rows, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        family = row.get("relation_type")
        if isinstance(family, str) and isinstance(row.get("status"), str):
            result[family] = row
    return result


def _field_rows(item: Mapping[str, Any], field_name: str) -> dict[str, Mapping[str, Any]]:
    field = item.get("fields", {}).get(field_name, {})
    values = field.get("value", []) if isinstance(field, Mapping) else []
    result: dict[str, Mapping[str, Any]] = {}
    if isinstance(values, list):
        for row in values:
            if isinstance(row, Mapping) and isinstance(row.get("relation_type"), str):
                result[row["relation_type"]] = row
    return result


def _check_pair_default_sav(item: Mapping[str, Any], expected: Mapping[str, Any], *, require_expiry: bool) -> None:
    fields = item.get("fields")
    assert isinstance(fields, Mapping), "pair_fields_missing"
    rows = _pair_rows(item)
    for family in PAIR_FAMILIES:
        row = rows.get(family)
        assert row is not None, (family, rows)
        assert row.get("status") == "known" and row.get("value") in {"active", "inactive"}, (family, row)
        if family in NETWORK_FAMILIES:
            wanted = _family_record(_network_container(expected), family)
            assert wanted is not None, f"network_family_reference_missing:{family}"
            wanted_active = "SAV" in _active_partners(wanted)
            assert row["value"] == ("active" if wanted_active else "inactive"), (family, row, wanted)
    assert set(rows) == set(PAIR_FAMILIES), rows
    if require_expiry:
        expiry = fields.get("expires_at")
        assert isinstance(expiry, Mapping), "expires_at_missing_from_default_pair"
        assert expiry.get("status") == "unsupported", expiry


def _check_orl_vassal(item: Mapping[str, Any]) -> None:
    rows = _pair_rows(item)
    row = rows.get("vassalization")
    assert row is not None and row.get("status") == "known" and row.get("value") == "active", row
    grantor = _field_rows(item, "grantor").get("vassalization")
    recipient = _field_rows(item, "recipient").get("vassalization")
    assert (grantor or {}).get("status") == "known" and (grantor or {}).get("value") == "FRA", grantor
    assert (recipient or {}).get("status") == "known" and (recipient or {}).get("value") == "ORL", recipient


def query_country(fields=FIELDS):
    return {"topic": "R01", "object": {"type": "country", "country": "FRA"},
            "fields": list(fields), "parameters": {"relation_types": list(NETWORK_FAMILIES)}}


def query_pair(recipient: str, fields=None, families=None):
    result = {"topic": "R01", "object": {"type": "country_pair", "actor": "FRA", "recipient": recipient}}
    if fields is not None:
        result["fields"] = list(fields)
    if families is not None:
        result["parameters"] = {"relation_types": list(families)}
    return result


def _check_result(result: Mapping[str, Any], expected: Mapping[str, Any], session_id: str,
                  game_date: Any, *, pair_sav: bool = True) -> None:
    assert result.get("delivery", {}).get("status") == "delivered", result
    context = result.get("context", {})
    assert context.get("session_id") == session_id
    assert context.get("game_date") == game_date
    items = result.get("items")
    assert isinstance(items, list) and len(items) == 3, result
    _check_network_item(items[0], expected)
    _check_pair_default_sav(items[1], expected, require_expiry=pair_sav)
    _check_orl_vassal(items[2])
    assert result.get("complete") is False


def run(installation: Path, expected_path: Path, output: Path) -> int:
    installation = installation.resolve(strict=True)
    expected_path = expected_path.resolve(strict=True)
    expected = _read_json(expected_path)
    binding = _read_json(installation)
    session_id, game_date = _identity(expected, binding)
    assert binding.get("session_id") == session_id
    output.mkdir(parents=True, exist_ok=False)
    before = None
    client = None
    subscription = None
    periodic_results: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": "information_relation_current_live_acceptance.v1",
        "stage": "information-relation-current-20261027-001",
        "status": "running", "reference": str(expected_path),
        "reference_sha256": _sha(expected_path), "session_id": session_id,
        "game_date": game_date,
        "configuration": "R01 native current relation source plus --static-game-data; mission and battle sources disabled",
        "checks": {}, "periodic_results": 0, "subscriptions_created": 0,
        "business_actions_submitted": 0, "game_functions_called": True,
        "game_function_scope": "existing read-only diplomacy inspections for selected pairs",
        "new_relation_memory_native_functions_called": False,
        "save_restart_or_date_advance": False, "outbox": "not_yet_verified", "llm_read": "unknown",
    }
    queries = [query_country(), query_pair("SAV"), query_pair("ORL", FIELDS, ("vassalization",))]
    try:
        before = control_snapshot(int(binding["pid"]), output / "before-control.json")
        assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, game_date), before
        client = CheckedClient(installation, output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "R01")
        assert topic["status"] == "available"
        assert all(topic["fields"][field]["coverage"] == "partial" for field in FIELDS)
        assert topic["fields"]["expires_at"]["coverage"] == "planned"
        report["checks"]["R01_country_pair_catalog_partial_and_expiry_declared"] = True

        result = client.call("information_query", request_id="relation-current-query-001", queries=queries)
        write(output / "query.json", result)
        _check_result(result, expected, session_id, game_date)
        report["checks"]["country_network_and_two_selected_pairs_match_reference"] = True

        saved = client.call("information_manage_report", request_id="relation-current-report-001", operation="create",
                            config={"name": "FRA当前外交关系", "queries": queries, "detail": "raw"})
        write(output / "report-config.json", saved)
        report_id = saved["report"]["id"]
        report_result = client.call("information_query", request_id="relation-current-report-query-001", report_id=report_id)
        write(output / "report-query.json", report_result)
        _check_result(report_result, expected, session_id, game_date)
        report["checks"]["saved_report_replays_same_relation_contract"] = True

        created = client.call(
            "information_manage_subscription", request_id="relation-current-subscribe-001", operation="create",
            config={"name": "relation-current-one-period", "kind": "periodic", "report_id": report_id,
                    "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}},
        )
        subscription = created["subscription"]
        report["subscriptions_created"] = 1
        write(output / "subscription-config.json", created)
        deadline = time.monotonic() + 35
        while not periodic_results and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=50)
            periodic_results = [value for value in listed.get("results", [])
                                if value.get("subscription_id") == subscription["id"]]
            if len(periodic_results) > 1:
                raise AssertionError("more_than_one_periodic_result_before_cancel")
            if not periodic_results:
                time.sleep(0.2)
        assert len(periodic_results) == 1
        write(output / "periodic-results.json", periodic_results)
        _check_result(periodic_results[0], expected, session_id, game_date)
        report["periodic_results"] = 1
        cancelled = client.call("information_manage_subscription", request_id="relation-current-cancel-001",
                                operation="cancel", subscription_id=subscription["id"],
                                expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="relation-current-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(value["state"] == "cancelled" for value in listed["subscriptions"])
        report["checks"]["exactly_one_periodic_delivered_then_cancelled_no_active"] = True
        report.update(status="passed", outbox="delivered")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="relation-current-cleanup-001",
                                operation="cancel", subscription_id=subscription["id"],
                                expected_version=subscription["version"])
                client.close()
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
            report["checks"]["server_exit_code_zero"] = report["server_exit_code"] == 0
            if not report["checks"]["server_exit_code_zero"]:
                report["status"] = "failed"
        if before is not None:
            after = control_snapshot(int(binding["pid"]), output / "after-control.json")
            preserved = all(before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
            report["checks"]["date_pause_player_preserved"] = preserved
            if not preserved:
                report["status"] = "failed"
        write(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly start the MCP acceptance")
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    return run(args.installation, args.expected, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
