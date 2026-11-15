"""Validate the read-only T05 trade-transfer projection against raw inputs.

This helper is deliberately lazy: without ``--run`` (including ``--help``)
it only prints the CLI contract.  A run uses one fixed FRA installation and
an independently produced raw reference.  ``--resume-query`` and
``--resume-report-query`` reuse saved successful responses and therefore do
not issue those corresponding reads again.  The script performs no business
action, save, restart, date advance, RPM, REA, or game operation of its own.
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
from work.validate_information_trade_power_live import CheckedClient


REFERENCE_BASIS = "independent_raw_RPM_transfer_lists_not_public_projection"
TOPIC = "T05"
T04_TOPIC = "T04"
COUNTRY = "FRA"
T05_FIELDS = ("income", "collection", "merchant_task", "transfer")
T04_FIELDS = ("sources",)
TRANSFER_BASIS = "native_trade_power_transfer_relations"
TRANSFER_UNIT = "trade_power"
TRANSFER_SCALE = 1000
TRANSFER_PERIOD = "current"
MAX_JSON_BYTES = 16 * 1024 * 1024


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _request_namespace(output: Path) -> str:
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"trade-transfer-{digest}"


def _request_id(namespace: str, operation: str) -> str:
    return f"{namespace}-{operation}"


def _query(object_: Mapping[str, Any], fields: tuple[str, ...] | list[str], *, topic: str = TOPIC) -> dict[str, Any]:
    return {
        "topic": topic,
        "object": dict(object_),
        "fields": list(fields),
        "parameters": {},
    }


def _country_query(fields: tuple[str, ...] = ("transfer",)) -> dict[str, Any]:
    return _query({"type": "country", "country": COUNTRY}, fields)


def _node_query(node_id: str, fields: tuple[str, ...] = ("transfer",)) -> dict[str, Any]:
    return _query({"type": "trade_node", "node_id": node_id}, fields)


def _source_query(node_id: str) -> dict[str, Any]:
    return _query({"type": "trade_node", "node_id": node_id}, T04_FIELDS, topic=T04_TOPIC)


def _reference_parts(value: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Normalize the agreed flat reference while accepting an optional header."""
    if not isinstance(value, Mapping):
        raise ValueError("reference_not_object")
    header = value.get("header")
    merged: dict[str, Any] = dict(header) if isinstance(header, Mapping) else {}
    merged.update({key: item for key, item in value.items() if key != "header"})
    if merged.get("basis") != REFERENCE_BASIS:
        raise ValueError(f"reference_basis_mismatch:{merged.get('basis')!r}")
    if merged.get("country") != COUNTRY:
        raise ValueError("reference_country_mismatch")
    if not isinstance(merged.get("session_id"), str) or not merged["session_id"]:
        raise ValueError("reference_session_id_missing")
    if type(merged.get("game_date")) is not int:
        raise ValueError("reference_game_date_missing")
    nodes = merged.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 80:
        raise ValueError("reference_nodes_must_contain_80_entries")
    normalized: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, Mapping) or not isinstance(node.get("node_id"), str):
            raise ValueError("reference_node_missing_node_id")
        node_copy = dict(node)
        node_id = node_copy["node_id"]
        if node_id in by_id:
            raise ValueError(f"reference_duplicate_node:{node_id}")
        for direction in ("to", "from"):
            side = node_copy.get(direction)
            if not isinstance(side, Mapping):
                raise ValueError(f"reference_node_side_missing:{node_id}:{direction}")
            status = side.get("status")
            if status not in {"known", "unknown"}:
                raise ValueError(f"reference_node_side_status:{node_id}:{direction}")
            if status == "known" and not isinstance(side.get("items"), list):
                raise ValueError(f"reference_node_side_items_missing:{node_id}:{direction}")
            if status == "unknown" and "items" in side:
                raise ValueError(f"reference_unknown_side_has_items:{node_id}:{direction}")
        normalized.append(node_copy)
        by_id[node_id] = node_copy
    return merged, normalized, by_id


def _side_value(value: Any, *, node_id: str, direction: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AssertionError(f"transfer_side_not_object:{node_id}:{direction}")
    return value


def _assert_item_row(actual: Any, expected: Mapping[str, Any], *, node_id: str, direction: str) -> None:
    if not isinstance(actual, Mapping):
        raise AssertionError(f"transfer_item_not_object:{node_id}:{direction}")
    for key in ("country", "fullref_raw_hex", "slot", "raw", "raw_hex", "unit", "scale", "native_key", "direction"):
        if actual.get(key) != expected.get(key):
            raise AssertionError(f"transfer_item_mismatch:{node_id}:{direction}:{key}:{actual.get(key)!r}!={expected.get(key)!r}")
    if actual.get("unit") != TRANSFER_UNIT or actual.get("scale") != TRANSFER_SCALE:
        raise AssertionError(f"transfer_item_unit_mismatch:{node_id}:{direction}")
    if actual.get("direction") != direction:
        raise AssertionError(f"transfer_item_direction_mismatch:{node_id}:{direction}")


def _assert_side(actual: Any, expected: Mapping[str, Any], *, node_id: str, direction: str) -> None:
    actual_side = _side_value(actual, node_id=node_id, direction=direction)
    expected_status = expected.get("status")
    if actual_side.get("status") != expected_status:
        raise AssertionError(f"transfer_side_status_mismatch:{node_id}:{direction}")
    if expected_status == "unknown":
        if actual_side.get("reason") != expected.get("reason"):
            raise AssertionError(f"transfer_side_reason_mismatch:{node_id}:{direction}")
        return
    actual_items = actual_side.get("items")
    expected_items = expected.get("items")
    if not isinstance(actual_items, list) or not isinstance(expected_items, list):
        raise AssertionError(f"transfer_side_items_not_list:{node_id}:{direction}")
    if len(actual_items) != len(expected_items):
        raise AssertionError(f"transfer_side_item_count_mismatch:{node_id}:{direction}")
    for actual_item, expected_item in zip(actual_items, expected_items):
        _assert_item_row(actual_item, expected_item, node_id=node_id, direction=direction)


def _assert_node_projection(actual: Any, expected: Mapping[str, Any]) -> None:
    if not isinstance(actual, Mapping) or actual.get("node_id") != expected.get("node_id"):
        raise AssertionError(f"transfer_node_projection_mismatch:{expected.get('node_id')!r}")
    node_id = str(expected["node_id"])
    _assert_side(actual.get("to"), expected["to"], node_id=node_id, direction="to")
    _assert_side(actual.get("from"), expected["from"], node_id=node_id, direction="from")


def _assert_transfer_field(field: Any, expected_nodes: list[dict[str, Any]], *, selected_node: str | None = None) -> None:
    if not isinstance(field, Mapping) or field.get("status") != "known":
        raise AssertionError(f"transfer_field_not_known:{field!r}")
    if (field.get("unit"), field.get("scale"), field.get("period"), field.get("basis"), field.get("complete")) != (
        TRANSFER_UNIT, TRANSFER_SCALE, TRANSFER_PERIOD, TRANSFER_BASIS, False,
    ):
        raise AssertionError("transfer_field_metadata_mismatch")
    actual_value = field.get("value")
    if selected_node is None:
        if not isinstance(actual_value, list) or len(actual_value) != len(expected_nodes):
            raise AssertionError("transfer_country_value_shape_mismatch")
        for actual_node, expected_node in zip(actual_value, expected_nodes):
            _assert_node_projection(actual_node, expected_node)
    else:
        expected = next((node for node in expected_nodes if node.get("node_id") == selected_node), None)
        if expected is None:
            raise AssertionError(f"selected_reference_node_missing:{selected_node}")
        _assert_node_projection(actual_value, expected)


def _assert_result_context(result: Mapping[str, Any], session_id: str, game_date: int) -> None:
    if result.get("delivery", {}).get("status") != "delivered":
        raise AssertionError("result_not_delivered")
    context = result.get("context")
    if not isinstance(context, Mapping) or context.get("session_id") != session_id or context.get("game_date") != game_date:
        raise AssertionError("result_context_mismatch")


def _assert_transfer_result(result: Mapping[str, Any], expected_nodes: list[dict[str, Any]], session_id: str,
                            game_date: int, *, selected_node: str | None = None) -> None:
    _assert_result_context(result, session_id, game_date)
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise AssertionError("transfer_result_item_count_mismatch")
    fields = items[0].get("fields") if isinstance(items[0], Mapping) else None
    if not isinstance(fields, Mapping):
        raise AssertionError("transfer_result_fields_missing")
    _assert_transfer_field(fields.get("transfer"), expected_nodes, selected_node=selected_node)
    if result.get("complete") is not False:
        raise AssertionError("transfer_result_complete_contract_mismatch")


def _assert_mixed_result(result: Mapping[str, Any], expected_nodes: list[dict[str, Any]], session_id: str,
                         game_date: int, *, selected_node: str) -> None:
    _assert_result_context(result, session_id, game_date)
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 2:
        raise AssertionError("mixed_result_item_count_mismatch")
    t05_item, t04_item = items
    t05_fields = t05_item.get("fields") if isinstance(t05_item, Mapping) else None
    t04_fields = t04_item.get("fields") if isinstance(t04_item, Mapping) else None
    if not isinstance(t05_fields, Mapping) or not isinstance(t04_fields, Mapping):
        raise AssertionError("mixed_result_fields_missing")
    for field in T05_FIELDS:
        value = t05_fields.get(field)
        if not isinstance(value, Mapping) or value.get("status") != "known":
            raise AssertionError(f"mixed_T05_field_not_known:{field}")
    _assert_transfer_field(t05_fields["transfer"], expected_nodes, selected_node=None)
    sources = t04_fields.get("sources")
    if not isinstance(sources, Mapping) or sources.get("status") != "known":
        raise AssertionError("mixed_T04_sources_not_known")
    old_transfer = sources.get("value", {}).get(COUNTRY, {}).get("transfer_sources")
    if not isinstance(old_transfer, Mapping):
        raise AssertionError("mixed_T04_transfer_sources_missing")
    selected = next(node for node in expected_nodes if node["node_id"] == selected_node)
    for direction in ("to", "from"):
        _assert_side(old_transfer.get(direction), selected[direction], node_id=selected_node, direction=direction)
    if result.get("complete") is not False:
        raise AssertionError("mixed_result_complete_contract_mismatch")


def _resume_response(path: Path, default_queries: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    value = _read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError("resume_query_not_object")
    response = value.get("response") if isinstance(value.get("response"), Mapping) else value
    request = value.get("request")
    request_id = request.get("request_id") if isinstance(request, Mapping) else None
    queries = request.get("queries") if isinstance(request, Mapping) else None
    if not isinstance(queries, list):
        companion = path.with_name("query-request.json")
        if companion.is_file():
            request_value = _read_json(companion)
            queries = request_value.get("queries") if isinstance(request_value, Mapping) else None
            request_id = request_value.get("request_id") if isinstance(request_value, Mapping) else request_id
    if not isinstance(response, Mapping) or not isinstance(response.get("items"), list):
        raise ValueError("resume_query_response_invalid")
    if not isinstance(queries, list):
        queries = default_queries
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("resume_query_request_id_missing")
    return dict(response), list(queries), request_id


def _resume_report_response(path: Path, default_queries: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
    value = _read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError("resume_report_query_not_object")
    response_value = value.get("response") if isinstance(value.get("response"), Mapping) else value
    if not isinstance(response_value, Mapping) or not isinstance(response_value.get("items"), list):
        raise ValueError("resume_report_query_response_invalid")
    response = dict(response_value)
    report_id = response.get("report_id")
    request_id = response.get("request_id")
    if not isinstance(report_id, str) or not report_id:
        raise ValueError("resume_report_query_report_id_missing")
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("resume_report_query_request_id_missing")
    queries: Any = None
    request = value.get("request")
    if isinstance(request, Mapping) and isinstance(request.get("queries"), list):
        queries = request["queries"]
    companion = path.with_name("report-config.json")
    if queries is None and companion.is_file():
        config = _read_json(companion)
        report = config.get("report") if isinstance(config, Mapping) else None
        if isinstance(report, Mapping):
            queries = report.get("queries")
            configured_id = report.get("id")
            if configured_id is not None and configured_id != report_id:
                raise ValueError("resume_report_query_report_id_mismatch")
    if queries is None:
        queries = default_queries
    if not isinstance(queries, list):
        raise ValueError("resume_report_query_queries_invalid")
    return response, list(queries), request_id, report_id


def _selected_node(nodes: list[dict[str, Any]]) -> str:
    ids = [str(node["node_id"]) for node in nodes]
    for node in nodes:
        if any(isinstance(node.get(direction), Mapping) and node[direction].get("status") == "known"
               and node[direction].get("items") for direction in ("to", "from")):
            return str(node["node_id"])
    if "champagne" in ids:
        return "champagne"
    if "rheinland" in ids:
        return "rheinland"
    return ids[0]


def _assert_report_result(result: Mapping[str, Any], expected_nodes: list[dict[str, Any]],
                          selected_nodes: list[str], session_id: str, game_date: int) -> None:
    _assert_result_context(result, session_id, game_date)
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 1 + len(selected_nodes):
        raise AssertionError("transfer_report_item_count_mismatch")
    country_fields = items[0].get("fields") if isinstance(items[0], Mapping) else None
    if not isinstance(country_fields, Mapping):
        raise AssertionError("transfer_report_country_fields_missing")
    _assert_transfer_field(country_fields.get("transfer"), expected_nodes)
    for item, node_id in zip(items[1:], selected_nodes):
        fields = item.get("fields") if isinstance(item, Mapping) else None
        if not isinstance(fields, Mapping):
            raise AssertionError(f"transfer_report_node_fields_missing:{node_id}")
        _assert_transfer_field(fields.get("transfer"), expected_nodes, selected_node=node_id)
    if result.get("complete") is not False:
        raise AssertionError("transfer_report_complete_contract_mismatch")


def run(installation: Path, reference: Path, output: Path,
        resume_query: Path | None = None, resume_report_query: Path | None = None) -> int:
    installation = installation.resolve(strict=True)
    reference = reference.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    reference_bytes = reference.read_bytes()
    reference_value, expected_nodes, expected_by_id = _reference_parts(json.loads(reference_bytes))
    binding = _read_json(installation)
    if binding.get("session_id") != reference_value["session_id"]:
        raise ValueError("installation_reference_session_mismatch")
    before: dict[str, Any] | None = None
    client: CheckedClient | None = None
    subscription: dict[str, Any] | None = None
    namespace = _request_namespace(output)
    chosen = _selected_node(expected_nodes)
    node_selection = [chosen]
    if "champagne" in expected_by_id and chosen != "champagne":
        node_selection.insert(0, "champagne")
    country_query = _country_query()
    mixed_queries = [
        _country_query(T05_FIELDS),
        _source_query(chosen),
    ]
    default_report_queries = [country_query] + [_node_query(node) for node in node_selection]
    report: dict[str, Any] = {
        "schema": "information_trade_transfer_live_acceptance.v1",
        "status": "running",
        "stage": "information-trade-transfer-20261027-001",
        "reference": str(reference),
        "reference_sha256": hashlib.sha256(reference_bytes).hexdigest(),
        "installation": str(installation),
        "session_id": reference_value["session_id"],
        "game_date": reference_value["game_date"],
        "observer": COUNTRY,
        "request_namespace": namespace,
        "selected_node": chosen,
        "selected_nodes": node_selection,
        "checks": {},
        "request_ids": {},
        "periodic_results": 0,
        "subscriptions_created": 0,
        "business_actions_submitted": 0,
        "read_only": True,
        "game_functions_called": False,
        "save_restart_or_date_advance": False,
        "original_query_reused_offline": resume_query is not None,
        "original_report_query_reused_offline": resume_report_query is not None,
        "outbox": "not_yet_verified",
        "llm_read": "unknown",
    }
    try:
        output.mkdir(parents=True, exist_ok=False)
        before = control_snapshot(int(binding["pid"]), output / "before-control.json")
        assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (
            189, 1, 0, reference_value["game_date"],
        ), before
        client = CheckedClient(installation, output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        _write_exclusive(output / "discovery.json", discovery)
        topics = {item["topic_id"]: item for item in discovery.get("topics", [])
                  if isinstance(item, Mapping) and isinstance(item.get("topic_id"), str)}
        t05 = topics[TOPIC]
        t04 = topics[T04_TOPIC]
        assert t05["fields"]["transfer"]["coverage"] == "partial"
        assert t05["fields"]["steering_direction"]["coverage"] == "planned"
        assert all(t05["fields"][field]["coverage"] == "partial" for field in ("income", "collection", "merchant_task"))
        assert t04["fields"]["sources"]["coverage"] == "partial"
        report["checks"]["transfer_partial_steering_planned_and_sources_partial"] = True

        request_ids: dict[str, str] = {}
        if resume_query is not None:
            query_result, saved_queries, saved_id = _resume_response(resume_query.resolve(strict=True), [country_query])
            assert saved_queries == [country_query], "resume_query_request_mismatch"
            query_request_id = saved_id
            report["checks"]["resumed_country_query_not_reissued"] = True
            report["original_query_path"] = str(resume_query.resolve())
        else:
            query_request_id = _request_id(namespace, "query")
            query_result = client.call("information_query", request_id=query_request_id, queries=[country_query])
        request_ids["query"] = query_request_id
        report["request_ids"] = request_ids
        _write_exclusive(output / "query-request.json", {"request_id": query_request_id, "queries": [country_query]})
        _write_exclusive(output / "query.json", query_result)
        _assert_transfer_result(query_result, expected_nodes, reference_value["session_id"], reference_value["game_date"])
        report["checks"]["country_transfer_all_nodes_match_independent_reference"] = True

        node_results: dict[str, Any] = {}
        for node_id in node_selection:
            node_request_id = _request_id(namespace, "node-" + node_id)
            node_result = client.call("information_query", request_id=node_request_id, queries=[_node_query(node_id)])
            _assert_transfer_result(node_result, expected_nodes, reference_value["session_id"], reference_value["game_date"], selected_node=node_id)
            node_results[node_id] = node_result
        _write_exclusive(output / "node-queries.json", node_results)
        report["checks"]["selected_node_projections_match_reference"] = True

        mixed_request_id = _request_id(namespace, "mixed")
        mixed_result = client.call("information_query", request_id=mixed_request_id, queries=mixed_queries)
        _write_exclusive(output / "mixed-query.json", mixed_result)
        _assert_mixed_result(mixed_result, expected_nodes, reference_value["session_id"], reference_value["game_date"], selected_node=chosen)
        report["checks"]["T05_existing_fields_and_T04_sources_share_query_without_swallowing_transfer"] = True

        report_config = client.call(
            "information_manage_report", request_id=_request_id(namespace, "report-create"), operation="create",
            config={"name": "FRA贸易权转移", "queries": default_report_queries, "detail": "raw"},
        )
        _write_exclusive(output / "report-config.json", report_config)
        report_id = report_config["report"]["id"]
        report["request_ids"]["report_create"] = _request_id(namespace, "report-create")
        if resume_report_query is not None:
            report_result, saved_queries, report_query_id, old_report_id = _resume_report_response(
                resume_report_query.resolve(strict=True), default_report_queries,
            )
            assert saved_queries == default_report_queries, "resume_report_query_request_mismatch"
            report["original_report_id"] = old_report_id
            report["original_report_query_path"] = str(resume_report_query.resolve())
            report["request_ids"]["report_query_source"] = "resumed_original"
        else:
            report_query_id = _request_id(namespace, "report-query")
            report_result = client.call("information_query", request_id=report_query_id, report_id=report_id)
            report["request_ids"]["report_query_source"] = "new_namespace"
        report["request_ids"]["report_query"] = report_query_id
        _write_exclusive(output / "report-query.json", report_result)
        _assert_report_result(report_result, expected_nodes, node_selection,
                              reference_value["session_id"], reference_value["game_date"])
        report["checks"]["report_query_context_matches_reference"] = True

        created = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "subscribe"), operation="create",
            config={"name": "trade-transfer-two-seconds", "kind": "periodic", "report_id": report_id,
                    "enabled": True, "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"}},
        )
        _write_exclusive(output / "subscription-config.json", created)
        subscription = created["subscription"]
        report["subscriptions_created"] = 1
        periodic: list[dict[str, Any]] = []
        deadline = time.monotonic() + 35
        while not periodic and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=100)
            periodic = [item for item in listed.get("results", [])
                        if item.get("subscription_id") == subscription["id"]]
            if not periodic:
                time.sleep(0.2)
        assert len(periodic) >= 1, "periodic_result_timeout"
        _write_exclusive(output / "periodic-results.json", periodic)
        for item in periodic:
            _assert_report_result(item, expected_nodes, node_selection,
                                  reference_value["session_id"], reference_value["game_date"])
        report["periodic_results"] = len(periodic)
        report["checks"]["one_two_second_periodic_matches_selected_node"] = True

        cancelled = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "cancel"), operation="cancel",
            subscription_id=subscription["id"], expected_version=subscription["version"],
        )
        subscription = cancelled["subscription"]
        _write_exclusive(output / "cancelled-subscription.json", cancelled)
        assert subscription.get("state") == "cancelled"
        listed = client.call("information_manage_subscription", request_id=_request_id(namespace, "list"), operation="list")
        _write_exclusive(output / "subscriptions-after.json", listed)
        assert all(item.get("state") == "cancelled" for item in listed.get("subscriptions", []))
        report["checks"]["subscription_cancelled_no_active_and_server_cleanup_requested"] = True
        report.update(status="passed", outbox="delivered")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call(
                        "information_manage_subscription", request_id=_request_id(namespace, "cleanup"), operation="cancel",
                        subscription_id=subscription["id"], expected_version=subscription["version"],
                    )
            except Exception as exc:
                report.update(status="failed", cleanup_error={"type": type(exc).__name__, "message": str(exc)})
            try:
                client.close()
            except Exception as exc:
                report.update(status="failed", close_error={"type": type(exc).__name__, "message": str(exc)})
            report["server_exit_code"] = client.process.returncode
            report["checks"]["server_exit_zero"] = client.process.returncode == 0
            if client.process.returncode != 0:
                report["status"] = "failed"
        if before is not None and output.exists():
            try:
                after = control_snapshot(int(binding["pid"]), output / "after-control.json")
                preserved = all(before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
                report["checks"]["date_pause_player_preserved"] = preserved
                if not preserved:
                    report["status"] = "failed"
            except Exception as exc:
                report.update(status="failed", after_control_error={"type": type(exc).__name__, "message": str(exc)})
        if output.exists():
            _write_exclusive(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly start the read-only MCP acceptance")
    parser.add_argument("--installation", type=Path, help="verified observer installation.json")
    parser.add_argument("--reference", type=Path, help="independent raw transfer reference JSON")
    parser.add_argument("--output", type=Path, help="new exclusive acceptance directory")
    parser.add_argument("--resume-query", type=Path, help="saved query.json; skip reissuing the successful country read")
    parser.add_argument("--resume-report-query", type=Path,
                        help="saved report-query.json plus report-config.json; skip the successful report read")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    missing = [name for name, value in (("--installation", args.installation),
                                        ("--reference", args.reference),
                                        ("--output", args.output)) if value is None]
    if missing:
        parser.error("--run requires " + ", ".join(missing))
    return run(args.installation, args.reference, args.output, args.resume_query, args.resume_report_query)


if __name__ == "__main__":
    raise SystemExit(main())
