"""Prepare the bounded R01 remaining-relation live acceptance.

The helper is inert unless ``--run`` is supplied.  On an explicit run it
starts the existing read-only information server, checks the country network,
the complete selected-country-pair projection, one vassal pair, one report,
and exactly one five-second periodic delivery.  Independent references are
kept separate: the legacy network reference supplies only alliance and royal
marriage partners, while the trade-league and fleet-basing references supply
the two new current-state booleans.  Empty vectors are accepted only when the
corresponding capture provenance also says that the family is known.
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


STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
NETWORK_STAGE = ROOT / "work/runtime/information-relation-current-20261027-001"
DEFAULT_INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"
DEFAULT_NETWORK_EXPECTED = NETWORK_STAGE / "independent-network-expected-003.json"
DEFAULT_TRADE_EXPECTED = STAGE / "expected-trade-league-current-001.json"
DEFAULT_FLEET_EXPECTED = STAGE / "expected-fleet-basing-projection-001.json"
DEFAULT_OUTPUT = STAGE / "live-acceptance-001"

NETWORK_FAMILIES = ("alliance", "royal_marriage", "fleet_basing", "trade_league")
OLD_PAIR_FAMILIES = (
    "vassalization", "guarantee", "support_independence", "military_access", "rival",
)
PAIR_FAMILIES = (*OLD_PAIR_FAMILIES, "alliance", "royal_marriage", "fleet_basing", "trade_league")
FIELDS = ("relation_type", "status", "grantor", "recipient")


def _read_json(path: Path, *, max_bytes: int = 96 * 1024 * 1024) -> dict[str, Any]:
    """Read only bounded reference/configuration files.

    The fleet reference is generated from a streamed 76 MiB raw capture and
    can itself be larger than the ordinary 16 MiB acceptance references.  It
    is still capped well below the process resource limit and is never used
    to read the raw capture here.
    """
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"reference_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"reference_must_be_object:{path}")
    return value


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _date_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        for key in ("value", "raw", "date", "game_date"):
            if key in value:
                return _date_value(value[key])
    return value


def _reference_identity(reference: Mapping[str, Any]) -> tuple[str | None, Any, str | None, Any]:
    """Extract the identity shapes used by the three independent reports."""
    candidates: list[Mapping[str, Any]] = []
    for key in ("identity", "context", "header"):
        value = reference.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)
    candidates.append(reference)
    session = game_date = observer = creation = None
    for candidate in candidates:
        if session is None:
            session = candidate.get("session_id") or candidate.get("installation_session_id")
        if game_date is None:
            for key in ("game_date", "date", "current_game_date"):
                if key in candidate:
                    game_date = _date_value(candidate[key])
                    break
        if observer is None:
            observer = candidate.get("observer") or candidate.get("observer_tag")
        if creation is None:
            creation = (candidate.get("creation_filetime") or
                        candidate.get("process_creation_filetime") or
                        candidate.get("installation_creation_filetime"))
    return (str(session) if session is not None else None, game_date,
            str(observer) if observer is not None else None, creation)


def _assert_reference_identity(reference: Mapping[str, Any], binding: Mapping[str, Any], label: str,
                               expected_date: Any) -> None:
    session, game_date, observer, creation = _reference_identity(reference)
    assert session == binding.get("session_id"), (label, session, binding.get("session_id"))
    assert _date_value(game_date) == expected_date, (label, game_date, expected_date)
    if observer is not None:
        assert observer == "FRA", (label, observer)
    if creation is not None:
        assert int(creation) == int(binding["creation_filetime"]), (label, creation)
    build = reference.get("build")
    if isinstance(build, Mapping) and build.get("exe_sha256"):
        assert build["exe_sha256"] == binding.get("game_sha256"), label
    identity = reference.get("identity")
    if isinstance(identity, Mapping):
        if "process_path_sha256" in identity:
            assert identity["process_path_sha256"] == binding.get("game_sha256"), label


def _assert_independent_reference(reference: Mapping[str, Any], binding: Mapping[str, Any],
                                  label: str, expected_date: Any) -> None:
    assert reference.get("status") == "observed", (label, reference.get("status"))
    # The trade-league reference predates the common top-level metadata and
    # records these two guarantees under raw_replay instead.  Accept either
    # shape, but never silently accept an explicit contradictory marker.
    if "read_only" in reference:
        assert reference.get("read_only") is True, label
    if "native_game_calls" in reference:
        assert reference.get("native_game_calls") is False, label
    _assert_reference_identity(reference, binding, label, expected_date)


def _network_expected(reference: Mapping[str, Any]) -> dict[str, set[str]]:
    fields = reference.get("fields")
    assert isinstance(fields, Mapping), "network_reference_fields_missing"
    result: dict[str, set[str]] = {}
    for family in ("alliance", "royal_marriage"):
        item = fields.get(family)
        assert isinstance(item, Mapping) and item.get("status") == "known", family
        values = item.get("value")
        assert isinstance(values, list), family
        partners: set[str] = set()
        for row in values:
            assert isinstance(row, Mapping), (family, row)
            assert row.get("status", "known") in ("known", "active"), (family, row)
            if row.get("active") is True:
                country = row.get("country") or row.get("partner")
                assert isinstance(country, str) and country not in partners, (family, row)
                partners.add(country)
        result[family] = partners
    checks = reference.get("checks")
    if isinstance(checks, Mapping):
        for key, value in checks.items():
            if any(token in str(key) for token in ("identity", "handle", "two_pass", "raw")):
                assert value is True or isinstance(value, Mapping) and all(bool(v) for v in value.values()), (key, value)
    assert reference.get("raw_two_pass_consistent") is True
    assert reference.get("identity_binding_verified") is True
    assert reference.get("handle_closed") is True
    return result


def _trade_expected(reference: Mapping[str, Any]) -> set[str]:
    fields = reference.get("fields")
    assert isinstance(fields, Mapping) and isinstance(fields.get("FRA"), Mapping)
    actor = fields["FRA"]
    assert actor.get("status") == "known"
    predicate = actor.get("predicate")
    assert isinstance(predicate, Mapping) and predicate.get("status") == "known"
    members = actor.get("members")
    assert isinstance(members, Mapping) and members.get("status") == "known"
    values = members.get("value")
    assert isinstance(values, list)
    partners: set[str] = set()
    for row in values:
        assert isinstance(row, Mapping), row
        country = row.get("country")
        assert isinstance(country, str) and country not in partners, row
        partners.add(country)
    # The current FRA capture is the explicitly observed false/empty vector.
    assert predicate.get("value") is False and not partners
    assert actor.get("active_member", {}).get("status") == "not_applicable"
    checks = reference.get("checks")
    assert isinstance(checks, Mapping)
    for key, value in checks.items():
        if key.endswith(("two_pass_bytes_equal", "predicate_replayed_from_code",
                         "vector_replayed_from_raw", "no_duplicate_or_stale_member")):
            assert value is True, (key, value)
    replay = reference.get("raw_replay")
    assert isinstance(replay, Mapping)
    for key in ("no_game_access", "no_native_call", "no_new_capture"):
        assert replay.get(key) is True, (key, replay.get(key))
    return partners


def _fleet_expected(reference: Mapping[str, Any]) -> dict[str, set[str]]:
    actors = reference.get("actors")
    assert isinstance(actors, Mapping) and isinstance(actors.get("FRA"), Mapping)
    actor = actors["FRA"]
    assert actor.get("status") == "observed"
    assert actor.get("raw_two_pass_consistent") is True
    fields = actor.get("fields")
    assert isinstance(fields, Mapping)
    result: dict[str, set[str]] = {}
    for direction in ("received", "granted"):
        field = fields.get(direction)
        assert isinstance(field, Mapping) and field.get("status") == "known", direction
        values = field.get("value")
        assert isinstance(values, list), direction
        countries: set[str] = set()
        for row in values:
            assert isinstance(row, Mapping), (direction, row)
            country = row.get("country")
            assert isinstance(country, str) and country not in countries, (direction, row)
            countries.add(country)
        result[direction] = countries
    checks = reference.get("checks")
    if isinstance(checks, Mapping):
        for key in ("identity_binding_verified", "handle_closed"):
            if key in checks:
                assert checks[key] is True, (key, checks[key])
        per_actor = checks.get("per_actor_raw_two_pass_consistent")
        if isinstance(per_actor, Mapping):
            assert per_actor.get("FRA") is True, per_actor
    return result


def _assert_fleet_projection_pin(reference: Mapping[str, Any]) -> None:
    """Ensure the compact projection still names the immutable full replay."""
    descriptor = reference.get("reference")
    if not isinstance(descriptor, Mapping):
        # This also keeps the CLI useful with the full independent reference
        # when a maintainer explicitly supplies --fleet-expected.
        return
    relative = descriptor.get("source_reference")
    source_sha = descriptor.get("source_reference_sha256")
    assert isinstance(relative, str) and isinstance(source_sha, str), descriptor
    source_path = (ROOT / relative).resolve()
    assert source_path.exists() and source_path.is_file(), source_path
    assert _sha(source_path) == source_sha, (source_path, source_sha)
    source_raw = reference.get("source_raw")
    if isinstance(source_raw, Mapping):
        assert source_raw.get("sha256") == source_sha, source_raw
        assert source_raw.get("full_source_json_loaded") is False, source_raw


def _network_container_calls(item: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    source = item.get("source")
    if isinstance(source, Mapping):
        provenance = source.get("provenance")
        if isinstance(provenance, Mapping) and isinstance(provenance.get("inspection_calls"), list):
            return [call for call in provenance["inspection_calls"] if isinstance(call, Mapping)]
    return []


def _network_actual_partners(field: Mapping[str, Any], family: str, field_name: str,
                             direction: str | None = None) -> set[str]:
    values = field.get("value")
    assert isinstance(values, list), (family, field)
    result: set[str] = set()
    for row in values:
        assert isinstance(row, Mapping), (family, row)
        if row.get("relation_type") != family:
            continue
        if direction is not None and row.get("direction") != direction:
            continue
        partner = row.get("partner") or row.get("country")
        assert isinstance(partner, str) and partner not in result, (family, row)
        if field_name in ("relation_type", "status"):
            wanted = family if field_name == "relation_type" else "active"
            assert row.get("status") == "known" and row.get("value") == wanted, (field_name, family, row)
        elif family == "fleet_basing":
            received = row.get("direction") == "received"
            wanted = (partner if received else "FRA") if field_name == "grantor" else ("FRA" if received else partner)
            assert row.get("status") == "known" and row.get("value") == wanted, (field_name, family, row)
        else:
            assert row.get("status") == "not_applicable", (field_name, family, row)
        result.add(partner)
    return result


def _check_network_item(item: Mapping[str, Any], expected: Mapping[str, set[str]],
                        fleet_members: Mapping[str, set[str]]) -> None:
    fields = item.get("fields")
    assert isinstance(fields, Mapping), "network_fields_missing"
    for field_name in FIELDS:
        field = fields.get(field_name)
        assert isinstance(field, Mapping) and field.get("status") == "known", (field_name, field)
        for family, wanted in expected.items():
            if family == "fleet_basing":
                for direction in ("received", "granted"):
                    assert _network_actual_partners(field, family, field_name, direction) == fleet_members[direction], (field_name, family, direction)
            else:
                assert _network_actual_partners(field, family, field_name) == wanted, (field_name, family, field, wanted)
    calls = _network_container_calls(item)
    by_family: dict[str, Mapping[str, Any]] = {}
    for call in calls:
        families = call.get("families")
        assert isinstance(families, Mapping), call
        for family, summary in families.items():
            assert family in NETWORK_FAMILIES and family not in by_family, (family, calls)
            assert isinstance(summary, Mapping), (family, summary)
            by_family[family] = summary
    for family, wanted in expected.items():
        summary = by_family.get(family)
        assert isinstance(summary, Mapping), (family, calls)
        assert summary.get("status") == "known", (family, summary)
        count = sum(len(value) for value in fleet_members.values()) if family == "fleet_basing" else len(wanted)
        assert summary.get("active_partner_count") == count, (family, summary, wanted)
    source = item.get("source")
    assert isinstance(source, Mapping) and source.get("mode") == "live", source
    assert source.get("context_scope") == "country_relation_network", source


def _row_family(row: Mapping[str, Any]) -> str | None:
    value = row.get("relation_type")
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("value"), str):
        return value["value"]
    return None


def _row_direction(row: Mapping[str, Any]) -> str | None:
    direction = row.get("direction")
    if isinstance(direction, str):
        return direction
    return None


def _rows_for_field(item: Mapping[str, Any], field_name: str) -> dict[tuple[str, str | None], Mapping[str, Any]]:
    field = item.get("fields", {}).get(field_name)
    assert isinstance(field, Mapping), (field_name, field)
    values = field.get("value")
    assert isinstance(values, list), (field_name, field)
    result: dict[tuple[str, str | None], Mapping[str, Any]] = {}
    for row in values:
        assert isinstance(row, Mapping), (field_name, row)
        family = _row_family(row)
        assert family in PAIR_FAMILIES, (field_name, row)
        key = (family, _row_direction(row))
        assert key not in result, (field_name, key)
        result[key] = row
    return result


def _check_pair_default_sav(item: Mapping[str, Any], trade_members: set[str],
                            fleet_members: Mapping[str, set[str]],
                            legacy_network: Mapping[str, set[str]]) -> None:
    fields = item.get("fields")
    assert isinstance(fields, Mapping), "pair_fields_missing"
    expiry = fields.get("expires_at")
    assert isinstance(expiry, Mapping) and expiry.get("status") == "unsupported", expiry
    rows = _rows_for_field(item, "status")
    expected_keys = {(family, None) for family in OLD_PAIR_FAMILIES + ("alliance", "royal_marriage", "trade_league")}
    expected_keys.update({("fleet_basing", "received"), ("fleet_basing", "granted")})
    assert set(rows) == expected_keys, rows
    assert len(rows) == 10, rows
    for (family, direction), row in rows.items():
        assert row.get("status") == "known" and row.get("value") in {"active", "inactive"}, (family, direction, row)
        if family in ("alliance", "royal_marriage"):
            wanted = "active" if "SAV" in legacy_network[family] else "inactive"
        elif family == "trade_league":
            wanted = "active" if "SAV" in trade_members else "inactive"
        elif family == "fleet_basing":
            wanted = "active" if "SAV" in fleet_members[direction or ""] else "inactive"
        else:
            continue
        assert row.get("value") == wanted, (family, direction, row, wanted)

    # Every returned field must describe the same ten rows.  The role checks
    # preserve the source's direction contract for an active fleet row and do
    # not manufacture roles for an inactive/group relation.
    row_maps = {field_name: _rows_for_field(item, field_name) for field_name in FIELDS}
    for key in expected_keys:
        for field_name, mapping in row_maps.items():
            assert key in mapping, (field_name, key, mapping)
        status_row = row_maps["status"][key]
        active = status_row.get("value") == "active"
        family, direction = key
        assert row_maps["relation_type"][key].get("value") == family
        for role in ("grantor", "recipient"):
            role_row = row_maps[role][key]
            if not active:
                assert role_row.get("status") == "not_applicable", (role, key, role_row)
            elif family == "fleet_basing":
                assert role_row.get("status") == "known", (role, key, role_row)
                wanted = (("SAV" if direction == "received" else "FRA") if role == "grantor"
                          else ("FRA" if direction == "received" else "SAV"))
                assert role_row.get("value") == wanted, (role, key, role_row, wanted)
            elif family in ("alliance", "royal_marriage", "trade_league"):
                assert role_row.get("status") == "not_applicable", (role, key, role_row)
            else:
                # The legacy action inspectors can expose an active boolean
                # without proving its grantor/recipient role.  The live
                # acceptance checks the old five families' state shape only;
                # it must not turn that missing role proof into a claim.
                assert role_row.get("status") in {"known", "unknown", "not_applicable"}, (role, key, role_row)


def _check_orl_vassal(item: Mapping[str, Any]) -> None:
    rows = _rows_for_field(item, "status")
    key = ("vassalization", None)
    row = rows.get(key)
    assert row is not None and row.get("status") == "known" and row.get("value") == "active", row
    for field_name, wanted in (("grantor", "FRA"), ("recipient", "ORL")):
        field_rows = _rows_for_field(item, field_name)
        role = field_rows.get(key)
        assert isinstance(role, Mapping) and role.get("status") == "known" and role.get("value") == wanted, role


def query_country() -> dict[str, Any]:
    return {"topic": "R01", "object": {"type": "country", "country": "FRA"},
            "fields": list(FIELDS), "parameters": {"relation_types": list(NETWORK_FAMILIES)}}


def query_pair(recipient: str, fields: tuple[str, ...] | None = None,
               families: tuple[str, ...] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"topic": "R01", "object": {"type": "country_pair", "actor": "FRA", "recipient": recipient}}
    if fields is not None:
        result["fields"] = list(fields)
    if families is not None:
        result["parameters"] = {"relation_types": list(families)}
    return result


def _check_result(result: Mapping[str, Any], expected_network: Mapping[str, set[str]],
                  trade_members: set[str], fleet_members: Mapping[str, set[str]],
                  session_id: str, game_date: Any) -> None:
    assert result.get("delivery", {}).get("status") == "delivered", result
    context = result.get("context", {})
    assert context.get("session_id") == session_id
    assert context.get("game_date") == game_date
    items = result.get("items")
    assert isinstance(items, list) and len(items) == 3, result
    all_network = dict(expected_network, trade_league=trade_members,
                       fleet_basing=set().union(*fleet_members.values()))
    _check_network_item(items[0], all_network, fleet_members)
    _check_pair_default_sav(items[1], trade_members, fleet_members, expected_network)
    _check_orl_vassal(items[2])
    assert result.get("complete") is False


def _check_reference_set(network: Mapping[str, Any], trade: Mapping[str, Any],
                         fleet: Mapping[str, Any], binding: Mapping[str, Any], game_date: Any) -> tuple[dict[str, set[str]], set[str], dict[str, set[str]]]:
    _assert_independent_reference(network, binding, "network", game_date)
    _assert_independent_reference(trade, binding, "trade_league", game_date)
    _assert_independent_reference(fleet, binding, "fleet_basing", game_date)
    return _network_expected(network), _trade_expected(trade), _fleet_expected(fleet)


def run(installation: Path, network_path: Path, trade_path: Path, fleet_path: Path, output: Path,
        resume_query: Path | None = None) -> int:
    installation = installation.resolve(strict=True)
    network_path = network_path.resolve(strict=True)
    trade_path = trade_path.resolve(strict=True)
    fleet_path = fleet_path.resolve(strict=True)
    binding = _read_json(installation, max_bytes=4 * 1024 * 1024)
    before_date = None
    # Validate all three independent references before opening the service.
    network = _read_json(network_path)
    trade = _read_json(trade_path)
    fleet = _read_json(fleet_path)
    session_id, game_date, observer, _creation = _reference_identity(network)
    assert session_id == binding.get("session_id") and observer in (None, "FRA")
    _assert_fleet_projection_pin(fleet)
    expected_network, trade_members, fleet_members = _check_reference_set(network, trade, fleet, binding, game_date)
    original_result = _read_json(resume_query) if resume_query is not None else None
    if original_result is not None:
        _check_result(original_result, expected_network, trade_members, fleet_members, session_id, game_date)

    output.mkdir(parents=True, exist_ok=False)
    before = None
    client = None
    subscription = None
    periodic_results: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": "information_relation_remaining_live_acceptance.v1",
        "stage": "information-relation-remaining-20261027-001",
        "status": "running",
        "references": {
            "network": {"path": str(network_path), "sha256": _sha(network_path)},
            "trade_league": {"path": str(trade_path), "sha256": _sha(trade_path)},
            "fleet_basing": {"path": str(fleet_path), "sha256": _sha(fleet_path)},
        },
        "session_id": session_id, "game_date": game_date,
        "configuration": "live R01 native relation source plus --static-game-data; mission and battle sources disabled",
        "checks": {}, "periodic_results": 0, "subscriptions_created": 0,
        "business_actions_submitted": 0, "game_functions_called": True,
        "game_function_scope": "existing read-only diplomacy inspections for selected pairs",
        "new_relation_memory_native_functions_called": False,
        "save_restart_or_date_advance": False, "outbox": "not_yet_verified", "llm_read": "unknown",
        "original_query_reused_offline": resume_query is not None,
        "original_query": {"path": str(resume_query), "sha256": _sha(resume_query)} if resume_query is not None else None,
    }
    queries = [
        query_country(),
        query_pair("SAV"),
        query_pair("ORL", FIELDS, ("vassalization",)),
    ]
    try:
        before = control_snapshot(int(binding["pid"]), output / "before-control.json")
        before_date = before["date_raw"]
        assert (before["player_slot"], before["paused_flag"], before["speed"], before["date_raw"]) == (189, 1, 0, game_date), before
        client = CheckedClient(installation, output, extra_args=["--static-game-data"])
        discovery = client.call("information_discover")
        write(output / "discovery.json", discovery)
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "R01")
        assert topic["status"] == "available"
        assert all(topic["fields"][field]["coverage"] == "partial" for field in FIELDS)
        assert topic["fields"]["expires_at"]["coverage"] == "planned"
        assert set(topic["parameters"]["properties"]["relation_types"]["items"]["enum"]) >= set(PAIR_FAMILIES)
        report["checks"]["R01_remaining_families_and_expiry_catalogued"] = True

        result = original_result if original_result is not None else client.call(
            "information_query", request_id="relation-remaining-query-001", queries=queries)
        write(output / "query.json", result)
        _check_result(result, expected_network, trade_members, fleet_members, session_id, game_date)
        report["checks"]["country_network_and_trade_fleet_pair_match_references"] = True

        saved = client.call("information_manage_report", request_id="relation-remaining-report-001", operation="create",
                            config={"name": "FRA当前关系网与驻港贸易联盟", "queries": queries, "detail": "raw"})
        write(output / "report-config.json", saved)
        report_id = saved["report"]["id"]
        report_result = client.call("information_query", request_id="relation-remaining-report-query-001", report_id=report_id)
        write(output / "report-query.json", report_result)
        _check_result(report_result, expected_network, trade_members, fleet_members, session_id, game_date)
        report["checks"]["saved_report_replays_same_relation_contract"] = True

        created = client.call(
            "information_manage_subscription", request_id="relation-remaining-subscribe-001", operation="create",
            config={"name": "relation-remaining-one-period", "kind": "periodic", "report_id": report_id,
                    "enabled": True, "schedule": {"basis": "real", "every": 5, "unit": "seconds", "missed": "coalesce"}},
        )
        subscription = created["subscription"]
        report["subscriptions_created"] = 1
        write(output / "subscription-config.json", created)
        deadline = time.monotonic() + 40
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
        _check_result(periodic_results[0], expected_network, trade_members, fleet_members, session_id, game_date)
        report["periodic_results"] = 1
        cancelled = client.call("information_manage_subscription", request_id="relation-remaining-cancel-001",
                                operation="cancel", subscription_id=subscription["id"],
                                expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        write(output / "cancelled-subscription.json", cancelled)
        assert subscription["state"] == "cancelled"
        listed = client.call("information_manage_subscription", request_id="relation-remaining-list-001", operation="list")
        write(output / "subscriptions-after.json", listed)
        assert all(value["state"] == "cancelled" for value in listed["subscriptions"])
        report["checks"]["exactly_one_five_second_periodic_delivered_then_cancelled_no_active"] = True
        report.update(status="passed", outbox="delivered")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    client.call("information_manage_subscription", request_id="relation-remaining-cleanup-001",
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
    parser.add_argument("--network-expected", "--expected-network", dest="network_expected", type=Path,
                        default=DEFAULT_NETWORK_EXPECTED)
    parser.add_argument("--trade-expected", "--expected-trade", dest="trade_expected", type=Path,
                        default=DEFAULT_TRADE_EXPECTED)
    parser.add_argument("--fleet-expected", "--expected-fleet", dest="fleet_expected", type=Path,
                        default=DEFAULT_FLEET_EXPECTED)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--resume-query", type=Path, help="validate the original stored query offline; perform only remaining report/subscription work")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    return run(args.installation, args.network_expected, args.trade_expected, args.fleet_expected, args.output, args.resume_query)


if __name__ == "__main__":
    raise SystemExit(main())
