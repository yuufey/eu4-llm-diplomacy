"""Prepare the bounded N05/R05 live acceptance.

The helper is inert unless ``--run`` is supplied (``--help`` is inert too).
An explicit run uses the existing read-only information client and control
probe.  It compares one combined N05 diplomat-task query and one selected
FRA-to-BUR Curry query with independent references, then repeats the same two
queries through a report and one two-second periodic subscription.  It never
submits diplomacy, saves, restarts, advances the date, or performs RPM/REA.
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


STAGE = ROOT / "work/runtime/information-diplomat-favor-tasks-20261027-001"
DEFAULT_INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v28-002/installation.json"
DEFAULT_N05_REFERENCE = STAGE / "independent-expected-001.json"
DEFAULT_R05_REFERENCE = STAGE / "independent-favor-expected-001.json"
DEFAULT_OUTPUT = STAGE / "live-acceptance-001"
N05_BASIS = "independent_RPM_not_production_reader"
R05_BASIS = "independent_RPM_not_public_query"
COUNTRY = "FRA"
RECIPIENT = "BUR"
GAME_DATE = 56559408
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
    return f"diplomat-favor-{digest}"


def _request_id(namespace: str, operation: str) -> str:
    return f"{namespace}-{operation}"


def _n05_query() -> dict[str, Any]:
    return {
        "topic": "N05",
        "object": {"type": "country", "country": COUNTRY},
        "fields": ["diplomat_tasks"],
        "parameters": {},
    }


def _r05_query() -> dict[str, Any]:
    return {
        "topic": "R05",
        "object": {"type": "country_pair", "actor": COUNTRY, "recipient": RECIPIENT},
        "fields": ["favor_tasks"],
        "parameters": {},
    }


def _identity(reference: Mapping[str, Any]) -> Mapping[str, Any]:
    value = reference.get("identity")
    if not isinstance(value, Mapping):
        raise ValueError("reference_identity_missing")
    return value


def _validate_raw_pin(reference: Mapping[str, Any]) -> None:
    raw = reference.get("raw_input")
    if not isinstance(raw, Mapping):
        raise ValueError("reference_raw_input_missing")
    relative = raw.get("path")
    expected_sha = raw.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected_sha, str):
        raise ValueError("reference_raw_pin_invalid")
    source = (ROOT / relative).resolve(strict=True)
    if _sha(source) != expected_sha:
        raise ValueError(f"reference_raw_sha_mismatch:{source}")


def _validate_identity(reference: Mapping[str, Any], binding: Mapping[str, Any], label: str) -> None:
    identity = _identity(reference)
    if identity.get("binding_verified") is not True:
        raise ValueError(f"{label}_identity_not_bound")
    if identity.get("installation_session_id") != binding.get("session_id"):
        raise ValueError(f"{label}_session_mismatch")
    if identity.get("installation_pid") != binding.get("pid"):
        raise ValueError(f"{label}_pid_mismatch")
    if identity.get("process_creation_filetime") != binding.get("creation_filetime"):
        raise ValueError(f"{label}_creation_mismatch")
    if identity.get("installation_creation_filetime") != binding.get("creation_filetime"):
        raise ValueError(f"{label}_installation_creation_mismatch")
    if identity.get("process_path_sha256") != binding.get("game_sha256"):
        raise ValueError(f"{label}_game_sha_mismatch")
    if identity.get("process_path_sha256_matches_expected") is not True:
        raise ValueError(f"{label}_game_sha_not_verified")


def _validate_n05_reference(reference: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    if reference.get("schema") != "information_diplomat_tasks_independent_reference.v1":
        raise ValueError("n05_reference_schema_mismatch")
    if reference.get("basis") != N05_BASIS:
        raise ValueError("n05_reference_basis_mismatch")
    _validate_raw_pin(reference)
    _validate_identity(reference, binding, "n05")
    date = reference.get("date")
    if not isinstance(date, Mapping) or date.get("value") != GAME_DATE:
        raise ValueError("n05_reference_date_mismatch")
    if reference.get("instance_count_observed") != 4:
        raise ValueError("n05_reference_instance_count_mismatch")
    if reference.get("available_count_observed") != 2:
        raise ValueError("n05_reference_available_count_mismatch")
    instances = reference.get("instances")
    if not isinstance(instances, list) or len(instances) != 4:
        raise ValueError("n05_reference_instances_invalid")
    if sum(item.get("state") == "active" for item in instances if isinstance(item, Mapping)) != 2:
        raise ValueError("n05_reference_active_count_mismatch")
    if sum(item.get("state") == "idle" for item in instances if isinstance(item, Mapping)) != 2:
        raise ValueError("n05_reference_idle_count_mismatch")


def _validate_r05_reference(reference: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    if reference.get("schema") != "information_favor_tasks_independent_reference.v1":
        raise ValueError("r05_reference_schema_mismatch")
    if reference.get("basis") != R05_BASIS:
        raise ValueError("r05_reference_basis_mismatch")
    _validate_raw_pin(reference)
    _validate_identity(reference, binding, "r05")
    date = reference.get("date")
    if not isinstance(date, Mapping) or date.get("value") != GAME_DATE:
        raise ValueError("r05_reference_date_mismatch")
    if reference.get("actor") != COUNTRY or reference.get("recipient") != RECIPIENT:
        raise ValueError("r05_reference_pair_mismatch")
    if reference.get("family") != "curry_favors":
        raise ValueError("r05_reference_family_mismatch")
    if reference.get("task_active") is not False or reference.get("vector_count") != 0:
        raise ValueError("r05_reference_not_verified_inactive")
    if reference.get("first_dwords") != []:
        raise ValueError("r05_reference_vector_not_empty")


def _assert_context(result: Mapping[str, Any], session_id: str) -> None:
    if result.get("delivery", {}).get("status") != "delivered":
        raise AssertionError("result_not_delivered")
    context = result.get("context")
    if not isinstance(context, Mapping):
        raise AssertionError("result_context_missing")
    if context.get("session_id") != session_id or context.get("game_date") != GAME_DATE:
        raise AssertionError("result_context_mismatch")
    if context.get("observer") not in (None, COUNTRY):
        raise AssertionError("result_observer_mismatch")


def _assert_diplomat_field(field: Any, expected: Mapping[str, Any]) -> None:
    if not isinstance(field, Mapping) or field.get("status") != "known":
        raise AssertionError(f"n05_field_not_known:{field!r}")
    if (field.get("unit"), field.get("scale"), field.get("period"),
            field.get("basis"), field.get("value_origin"), field.get("complete")) != (
                "diplomat_task_records", 1, "current",
                "native_country_diplomat_task_records",
                "copied_native_country_diplomat_task_records", False):
        raise AssertionError("n05_field_metadata_mismatch")
    value = field.get("value")
    if not isinstance(value, Mapping):
        raise AssertionError("n05_value_missing")
    for key in ("instance_count_observed", "available_count_observed"):
        if value.get(key) != expected.get(key):
            raise AssertionError(f"n05_{key}_mismatch")
    actual_rows = value.get("instances")
    expected_rows = expected.get("instances")
    if not isinstance(actual_rows, list) or not isinstance(expected_rows, list) or len(actual_rows) != 4:
        raise AssertionError("n05_instances_shape_mismatch")
    for actual, wanted in zip(actual_rows, expected_rows):
        if not isinstance(actual, Mapping) or not isinstance(wanted, Mapping):
            raise AssertionError("n05_instance_invalid")
        if actual.get("state_raw") != wanted.get("state_raw") or actual.get("state") != wanted.get("state"):
            raise AssertionError("n05_instance_state_mismatch")
        if "id" in wanted and actual.get("raw_id_44") != wanted["id"]:
            raise AssertionError("n05_instance_id_mismatch")
        if "action_token_raw" in wanted and actual.get("action_token_raw") != wanted["action_token_raw"]:
            raise AssertionError("n05_instance_token_mismatch")
        if "action_token_raw" in wanted and actual.get("task") != (
                "build_spy_network" if wanted["action_token_raw"] == 13176 else "unknown"):
            raise AssertionError("n05_task_family_mismatch")
        if "unknown_2c_raw" in wanted and actual.get("raw_2c") != wanted["unknown_2c_raw"]:
            raise AssertionError("n05_unknown_raw_2c_mismatch")
        if "actor" in wanted:
            actor = wanted["actor"]
            recipient = wanted["recipient"]
            if (actual.get("actor"), actual.get("recipient")) != (actor.get("country"), recipient.get("country")):
                raise AssertionError("n05_instance_target_mismatch")
            if (actual.get("actor_fullref_raw_hex"), actual.get("recipient_fullref_raw_hex")) != (
                    actor.get("raw_hex"), recipient.get("raw_hex")):
                raise AssertionError("n05_instance_fullref_mismatch")
            actor_resolution = actual.get("actor_resolution")
            recipient_resolution = actual.get("recipient_resolution")
            if isinstance(actor_resolution, Mapping) and actor_resolution.get("slot") != actor.get("slot"):
                raise AssertionError("n05_actor_slot_mismatch")
            if isinstance(recipient_resolution, Mapping) and recipient_resolution.get("slot") != recipient.get("slot"):
                raise AssertionError("n05_recipient_slot_mismatch")
            lifecycle = actual.get("lifecycle_date_raw")
            if not isinstance(lifecycle, Mapping):
                raise AssertionError("n05_lifecycle_missing")
            if (lifecycle.get("raw_20"), lifecycle.get("raw_24")) != (
                    wanted.get("lifecycle_date_20_raw"), wanted.get("lifecycle_date_24_raw")):
                raise AssertionError("n05_lifecycle_mismatch")


def _assert_favor_field(field: Any, expected: Mapping[str, Any]) -> None:
    if not isinstance(field, Mapping) or field.get("status") != "known":
        raise AssertionError(f"r05_field_not_known:{field!r}")
    if (field.get("unit"), field.get("scale"), field.get("period"),
            field.get("basis"), field.get("value_origin"), field.get("complete")) != (
                "task_state", 1, "current", "native_curry_favors_pair_state",
                "copied_native_pair_inspection", False):
        raise AssertionError("r05_field_metadata_mismatch")
    value = field.get("value")
    if not isinstance(value, Mapping):
        raise AssertionError("r05_value_missing")
    if (value.get("actor"), value.get("recipient"), value.get("family"),
            value.get("task_active"), value.get("direction")) != (
                COUNTRY, RECIPIENT, "curry_favors", False, "actor_to_recipient"):
        raise AssertionError("r05_pair_state_mismatch")
    if value.get("relationship_state") != {"task_active": False, "complete": True}:
        raise AssertionError("r05_relationship_state_mismatch")
    if expected.get("task_active") is not False or expected.get("vector_count") != 0:
        raise AssertionError("r05_independent_inactive_contract_mismatch")


def _assert_combined(result: Mapping[str, Any], n05: Mapping[str, Any], r05: Mapping[str, Any],
                     session_id: str) -> None:
    _assert_context(result, session_id)
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 2:
        raise AssertionError("combined_item_count_mismatch")
    by_topic: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise AssertionError("combined_item_invalid")
        topic = item.get("topic")
        if topic is None and isinstance(item.get("query"), Mapping):
            topic = item["query"].get("topic")
        if not isinstance(topic, str):
            raise AssertionError("combined_item_invalid")
        if topic in by_topic:
            raise AssertionError("combined_duplicate_topic")
        by_topic[topic] = item
    if set(by_topic) != {"N05", "R05"}:
        raise AssertionError(f"combined_topics_mismatch:{set(by_topic)}")
    n05_fields = by_topic["N05"].get("fields")
    r05_fields = by_topic["R05"].get("fields")
    if not isinstance(n05_fields, Mapping) or not isinstance(r05_fields, Mapping):
        raise AssertionError("combined_fields_missing")
    _assert_diplomat_field(n05_fields.get("diplomat_tasks"), n05)
    _assert_favor_field(r05_fields.get("favor_tasks"), r05)
    if result.get("complete") is not False:
        raise AssertionError("combined_result_complete_contract_mismatch")


def _resume_response(path: Path, default_queries: list[dict[str, Any]], *, report: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]], str, str | None]:
    value = _read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError("resume_response_not_object")
    response = value.get("response") if isinstance(value.get("response"), Mapping) else value
    request = value.get("request") if isinstance(value.get("request"), Mapping) else None
    companion_name = "report-query-request.json" if report else "query-request.json"
    if request is None and (path.parent / companion_name).is_file():
        candidate = _read_json(path.parent / companion_name)
        request = candidate if isinstance(candidate, Mapping) else None
    if not isinstance(response, Mapping) or not isinstance(response.get("items"), list):
        raise ValueError("resume_response_invalid")
    queries = request.get("queries") if isinstance(request, Mapping) else None
    if not isinstance(queries, list):
        queries = default_queries
    request_id = request.get("request_id") if isinstance(request, Mapping) else None
    if not isinstance(request_id, str) or not request_id:
        request_id = response.get("request_id") if isinstance(response.get("request_id"), str) else "resumed"
    report_id = None
    if report:
        report_id = value.get("report_id") if isinstance(value.get("report_id"), str) else None
        report_id = report_id or (response.get("report_id") if isinstance(response.get("report_id"), str) else None)
        config_path = path.parent / "report-config.json"
        if report_id is None and config_path.is_file():
            config = _read_json(config_path)
            report_data = config.get("report") if isinstance(config, Mapping) else None
            if isinstance(report_data, Mapping) and isinstance(report_data.get("id"), str):
                report_id = report_data["id"]
            if isinstance(report_data, Mapping) and isinstance(report_data.get("queries"), list) and request is None:
                queries = report_data["queries"]
        if report_id is None:
            raise ValueError("resume_report_id_missing")
    return dict(response), list(queries), request_id, report_id


def _check_discovery(discovery: Mapping[str, Any]) -> None:
    topics = discovery.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("discovery_topics_missing")
    by_id = {item.get("topic_id"): item for item in topics if isinstance(item, Mapping)}
    n05 = by_id.get("N05")
    r05 = by_id.get("R05")
    if not isinstance(n05, Mapping) or not isinstance(r05, Mapping):
        raise AssertionError("discovery_topics_missing_N05_R05")
    if n05.get("fields", {}).get("diplomat_tasks", {}).get("coverage") != "partial":
        raise AssertionError("discovery_N05_coverage_mismatch")
    if r05.get("fields", {}).get("favor_tasks", {}).get("coverage") != "partial":
        raise AssertionError("discovery_R05_coverage_mismatch")
    for topic, field in ((n05, "diplomat_tasks"), (r05, "favor_tasks")):
        triggers = set(topic.get("triggers", ()))
        if not {"query", "periodic"}.issubset(triggers):
            raise AssertionError(f"discovery_triggers_mismatch:{topic.get('topic_id')}:{field}")


def run(installation: Path, n05_path: Path, r05_path: Path, output: Path,
        resume_query: Path | None = None, resume_report_query: Path | None = None) -> int:
    installation = installation.resolve(strict=True)
    n05_path = n05_path.resolve(strict=True)
    r05_path = r05_path.resolve(strict=True)
    binding = _read_json(installation, max_bytes=4 * 1024 * 1024)
    if not isinstance(binding, Mapping):
        raise ValueError("installation_binding_invalid")
    n05_reference = _read_json(n05_path)
    r05_reference = _read_json(r05_path)
    if not isinstance(n05_reference, Mapping) or not isinstance(r05_reference, Mapping):
        raise ValueError("independent_reference_invalid")
    _validate_n05_reference(n05_reference, binding)
    _validate_r05_reference(r05_reference, binding)
    if _identity(n05_reference).get("installation_session_id") != _identity(r05_reference).get("installation_session_id"):
        raise ValueError("independent_reference_session_mismatch")
    expected_queries = [_n05_query(), _r05_query()]
    resumed_query = _resume_response(resume_query, expected_queries) if resume_query is not None else None
    resumed_report = _resume_response(resume_report_query, expected_queries, report=True) if resume_report_query is not None else None
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(exist_ok=False)
    namespace = _request_namespace(output)
    session_id = str(binding.get("session_id"))
    report: dict[str, Any] = {
        "schema": "information_diplomat_favor_tasks_live_acceptance.v1",
        "stage": STAGE.relative_to(ROOT).as_posix(),
        "status": "running",
        "references": {
            "n05": {"path": str(n05_path), "sha256": _sha(n05_path)},
            "r05": {"path": str(r05_path), "sha256": _sha(r05_path)},
        },
        "session_id": session_id,
        "game_date": GAME_DATE,
        "scopes": {"N05": "country_scope:FRA", "R05": "selected_country_pair:FRA->BUR"},
        "business_actions_submitted": 0,
        "read_only": True,
        # N05 performs bounded native memory reads and R05 invokes an existing
        # read-only inspection.  Do not claim that no game function ran.
        "game_functions_called": True,
        "game_function_scope": "R05 read-only diplomacy inspection; N05 uses pure RPM",
        "checks": {},
        "counts": {},
        "periodic_results": 0,
        "subscriptions_created": 0,
        "original_query_reused_offline": resume_query is not None,
        "original_report_query_reused_offline": resume_report_query is not None,
        "outbox": "not_yet_verified",
        "llm_read": "unknown",
    }
    client = None
    subscription: dict[str, Any] | None = None
    before: Mapping[str, Any] | None = None
    periodic_results: list[dict[str, Any]] = []
    try:
        before = control_snapshot(int(binding["pid"]), output / "before-control.json")
        if (before.get("player_slot"), before.get("paused_flag"), before.get("speed"), before.get("date_raw")) != (189, 1, 0, GAME_DATE):
            raise AssertionError(f"control_before_mismatch:{before}")
        report["checks"]["control_before_matches_por_paused_snapshot"] = True
        client = CheckedClient(installation, output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        _write_exclusive(output / "discovery.json", discovery)
        _check_discovery(discovery)
        report["checks"]["N05_and_R05_fields_discoverable_partial_query_periodic"] = True

        if resumed_query is None:
            query_request = {"request_id": _request_id(namespace, "query"), "queries": expected_queries}
            _write_exclusive(output / "query-request.json", query_request)
            query_result = client.call("information_query", **query_request)
        else:
            query_result, query_queries, query_request_id, _ = resumed_query
            if query_queries != expected_queries:
                raise AssertionError("resumed_query_contract_mismatch")
            query_request = {"request_id": query_request_id, "queries": query_queries, "reused": True}
            _write_exclusive(output / "query-request.json", query_request)
        _write_exclusive(output / "query.json", query_result)
        _assert_combined(query_result, n05_reference, r05_reference, session_id)
        report["checks"]["combined_N05_diplomat_tasks_and_R05_favor_tasks_match_references"] = True
        report["counts"].update({"diplomat_instances": 4, "diplomat_active": 2, "diplomat_idle": 2, "favor_task_active": False})

        report_config = {
            "name": "FRA外交官任务与BUR人情任务",
            "queries": expected_queries,
            "detail": "raw",
        }
        saved = client.call("information_manage_report", request_id=_request_id(namespace, "report-create"), operation="create", config=report_config)
        _write_exclusive(output / "report-config.json", saved)
        report_data = saved.get("report") if isinstance(saved, Mapping) else None
        if not isinstance(report_data, Mapping) or not isinstance(report_data.get("id"), str):
            raise AssertionError("report_config_invalid")
        report_id = report_data["id"]
        if resumed_report is None:
            report_request = {"request_id": _request_id(namespace, "report-query"), "report_id": report_id}
            report_result = client.call("information_query", **report_request)
        else:
            report_result, report_queries, report_request_id, old_report_id = resumed_report
            if report_queries != expected_queries:
                raise AssertionError("resumed_report_query_contract_mismatch")
            report_request = {"request_id": report_request_id, "report_id": old_report_id, "reused": True}
        _write_exclusive(output / "report-query-request.json", report_request)
        _write_exclusive(output / "report-query.json", report_result)
        _assert_combined(report_result, n05_reference, r05_reference, session_id)
        report["checks"]["report_query_matches_references"] = True
        report["report_query_reused_report_id"] = resumed_report[3] if resumed_report is not None else None

        created = client.call(
            "information_manage_subscription",
            request_id=_request_id(namespace, "subscribe"),
            operation="create",
            config={
                "name": "diplomat-favor-two-seconds",
                "kind": "periodic",
                "report_id": report_id,
                "enabled": True,
                "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"},
            },
        )
        _write_exclusive(output / "subscription-config.json", created)
        subscription = created.get("subscription") if isinstance(created, Mapping) else None
        if not isinstance(subscription, Mapping):
            raise AssertionError("subscription_config_invalid")
        report["subscriptions_created"] = 1
        deadline = time.monotonic() + 30
        while not periodic_results and time.monotonic() < deadline:
            listed = client.call("information_list_results", limit=100)
            candidates = [item for item in listed.get("results", [])
                          if isinstance(item, Mapping) and item.get("subscription_id") == subscription.get("id")]
            if len(candidates) > 1:
                raise AssertionError("more_than_one_periodic_result_before_cancel")
            if candidates:
                periodic_results = [dict(candidates[0])]
            else:
                time.sleep(0.2)
        _write_exclusive(output / "periodic-results.json", periodic_results)
        if len(periodic_results) != 1:
            raise AssertionError("periodic_result_count_mismatch")
        _assert_combined(periodic_results[0], n05_reference, r05_reference, session_id)
        report["periodic_results"] = 1
        report["checks"]["one_two_second_periodic_result_matches_references"] = True

        cancelled = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "cancel"),
            operation="cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )
        _write_exclusive(output / "cancelled-subscription.json", cancelled)
        cancelled_data = cancelled.get("subscription") if isinstance(cancelled, Mapping) else None
        if not isinstance(cancelled_data, Mapping) or cancelled_data.get("state") != "cancelled":
            raise AssertionError("subscription_cancel_failed")
        subscription = dict(cancelled_data)
        listed = client.call("information_manage_subscription", request_id=_request_id(namespace, "list"), operation="list")
        _write_exclusive(output / "subscriptions-after.json", listed)
        active = [item for item in listed.get("subscriptions", [])
                  if isinstance(item, Mapping) and item.get("state") not in {"cancelled", "completed"}]
        if active:
            raise AssertionError(f"active_subscriptions_remain:{active}")
        report["checks"]["subscription_cancelled_and_no_active_subscription"] = True
        report.update(status="passed", outbox="delivered")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") not in {"cancelled", "completed"}:
                    try:
                        cleanup = client.call(
                            "information_manage_subscription",
                            request_id=_request_id(namespace, "cleanup-cancel"), operation="cancel",
                            subscription_id=subscription["id"], expected_version=subscription["version"],
                        )
                        _write_exclusive(output / "cleanup-cancel.json", cleanup)
                    except Exception as exc:
                        report["cleanup_cancel_error"] = {"type": type(exc).__name__, "message": str(exc)}
                        report["status"] = "failed"
            finally:
                try:
                    client.close()
                except Exception as exc:
                    report["cleanup_close_error"] = {"type": type(exc).__name__, "message": str(exc)}
                    report["status"] = "failed"
                report["server_exit_code"] = client.process.returncode
                report["checks"]["server_exit_code_zero"] = report["server_exit_code"] == 0
                if not report["checks"]["server_exit_code_zero"]:
                    report["status"] = "failed"
        if before is not None:
            try:
                after = control_snapshot(int(binding["pid"]), output / "after-control.json")
                preserved = all(before.get(key) == after.get(key)
                                for key in ("date_raw", "paused_flag", "speed", "player_slot"))
                report["checks"]["date_pause_player_preserved"] = preserved
                if not preserved:
                    report["status"] = "failed"
            except Exception as exc:
                report["checks"]["date_pause_player_preserved"] = False
                report["after_control_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
        _write_exclusive(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report.get("status") == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly run the live acceptance")
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--n05-reference", "--n05-expected", dest="n05_reference", type=Path,
                        default=DEFAULT_N05_REFERENCE)
    parser.add_argument("--r05-reference", "--r05-expected", dest="r05_reference", type=Path,
                        default=DEFAULT_R05_REFERENCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--resume-query", type=Path,
                        help="reuse a previously saved combined query response offline")
    parser.add_argument("--resume-report-query", type=Path,
                        help="reuse a previously saved report query response offline")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    return run(args.installation, args.n05_reference, args.r05_reference, args.output,
               args.resume_query, args.resume_report_query)


if __name__ == "__main__":
    raise SystemExit(main())
