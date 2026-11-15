"""Bounded, read-only survey of existing EU4 battle business-field evidence.

This script deliberately consumes only small indexes/ledgers/reports and streams
hashes for referenced evidence files.  It does not dispatch REA, access a game
process, load a large evidence JSON document, or turn a static label into a
business-field claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable


REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    REPO
    / "work"
    / "runtime"
    / "information-battle-business-20261025-001"
    / "existing-business-fields-001.json"
)
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXE_VERSION = "1.37.4"
IMAGE_BASE = "0x140000000"
MAX_JSON_BYTES = 2 * 1024 * 1024
HASH_CHUNK = 1024 * 1024


class SurveyError(RuntimeError):
    pass


def _relative(path: str | Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        try:
            return p.relative_to(REPO)
        except ValueError as exc:
            raise SurveyError(f"path outside repository: {p}") from exc
    return p


def _sha256(path: Path) -> tuple[str, int, int]:
    """Stream a file hash and reject a file changing during the read."""
    try:
        before = path.stat()
    except OSError as exc:
        raise SurveyError(f"cannot stat {path}: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(HASH_CHUNK)
                if not block:
                    break
                digest.update(block)
                size += len(block)
    except OSError as exc:
        raise SurveyError(f"cannot hash {path}: {exc}") from exc
    try:
        after = path.stat()
    except OSError as exc:
        raise SurveyError(f"cannot restat {path}: {exc}") from exc
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise SurveyError(f"source changed while hashing: {path}")
    if size != before.st_size:
        raise SurveyError(f"short hash read for {path}: {size}/{before.st_size}")
    return digest.hexdigest(), size, before.st_mtime_ns


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    size = path.stat().st_size
    if size > limit:
        raise SurveyError(f"JSON exceeds bounded read limit ({size} > {limit}): {path}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise SurveyError(f"short JSON read: {path}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SurveyError(f"invalid bounded JSON: {path}: {exc}") from exc


def _pin(
    pins: list[dict[str, Any]],
    path: str,
    expected_sha256: str,
    *,
    layer: str,
    role: str,
    evidence_id: str | None = None,
    required: bool = True,
) -> dict[str, Any]:
    rel = _relative(path)
    full = REPO / rel
    item: dict[str, Any] = {
        "path": rel.as_posix(),
        "layer": layer,
        "role": role,
        "expected_sha256": expected_sha256,
        "required": required,
    }
    if evidence_id is not None:
        item["evidence_id"] = evidence_id
    try:
        actual, size, mtime_ns = _sha256(full)
        item.update(
            {
                "status": "matched" if actual == expected_sha256 else "mismatch",
                "actual_sha256": actual,
                "size_bytes": size,
                "mtime_ns": mtime_ns,
            }
        )
    except (OSError, SurveyError) as exc:
        item.update({"status": "missing_or_unreadable", "error": str(exc)})
    pins.append(item)
    return item


def _evidence(
    *,
    name: str,
    role: str,
    evidence_id: str,
    evidence_path: str,
    evidence_sha256: str,
    rva_start: str,
    rva_end_inclusive: str,
    span_bytes: int | None = None,
    range_count: int | None = None,
    selected_path: str | None = None,
    selected_sha256: str | None = None,
    receipt: str = "passed",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": name,
        "role": role,
        "evidence_id": evidence_id,
        "evidence_file": {
            "path": evidence_path,
            "sha256": evidence_sha256,
        },
        "fixed_build": {
            "version": EXE_VERSION,
            "executable_sha256": EXE_SHA256,
            "image_base": IMAGE_BASE,
        },
        "procedure_body_inclusive": {
            "rva_start": rva_start,
            "rva_end_inclusive": rva_end_inclusive,
        },
        "receipt": receipt,
    }
    if span_bytes is not None:
        value["procedure_body_inclusive"]["span_bytes"] = span_bytes
    if range_count is not None:
        value["procedure_body_inclusive"]["range_count"] = range_count
    if selected_path is not None:
        value["selected_file"] = {"path": selected_path, "sha256": selected_sha256}
    return value


def _runtime_summary(path: Path) -> dict[str, Any]:
    analysis = _read_json(path)
    messages = analysis.get("messages")
    if not isinstance(messages, list):
        raise SurveyError("runtime payload analysis has no messages list")
    sequences = [m.get("sequence") for m in messages if isinstance(m, dict)]
    threads = [m.get("thread") for m in messages if isinstance(m, dict)]
    routers = [m.get("known_router") for m in messages if isinstance(m, dict)]
    side_count = 0
    commander_slots = 0
    nonempty_commanders = 0
    raw_field_lengths: set[int] = set()
    flag_values: set[Any] = set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        sides = message.get("sides")
        if isinstance(sides, list):
            side_count += len(sides)
            commander_slots += sum(1 for side in sides if isinstance(side, dict) and "commander" in side)
            nonempty_commanders += sum(
                1
                for side in sides
                if isinstance(side, dict)
                and isinstance(side.get("commander"), dict)
                and side["commander"].get("length", 0) > 0
            )
        summary = message.get("summary")
        if isinstance(summary, dict):
            raw = summary.get("raw_i32")
            if isinstance(raw, list):
                raw_field_lengths.add(len(raw))
        if "flag108" in message:
            flag_values.add(message["flag108"])
    complete_flags = analysis.get("complete_flags", {})
    dates = analysis.get("dates", {})
    identity = analysis.get("source_identity", {})
    return {
        "status": "observed_raw_payload_only",
        "report": {
            "path": "work/runtime/information-battle-live-20261025-001/payload-analysis-001.json",
            "sha256": "17f55e7bde91f52a3a5cfaede933f3ea5db1cc87f25c25e6d5aa43223abcc3ce",
        },
        "input": analysis.get("input"),
        "source_identity": identity,
        "messages": {
            "count": len(messages),
            "sequence_first": min(sequences) if sequences else None,
            "sequence_last": max(sequences) if sequences else None,
            "sequence_values": sequences,
            "thread_values": sorted(set(threads)),
            "known_router_values": sorted(set(routers), key=str),
            "side_count": side_count,
            "country_ref_count": analysis.get("country_refs", {}).get("complete_raw_ref_count"),
            "commander_slot_count": commander_slots,
            "nonempty_commander_count": nonempty_commanders,
            "summary_raw_i32_lengths": sorted(raw_field_lengths),
            "flag108_values_observed": sorted(flag_values, key=str),
        },
        "date_range_raw": {
            "min": dates.get("raw_min"),
            "max": dates.get("raw_max"),
            "unique_count": dates.get("unique_raw_value_count"),
        },
        "transport": analysis.get("transport", {}).get("reported"),
        "message_page": analysis.get("message_page", {}).get("reported"),
        "complete_flags": complete_flags.get("top_level"),
        "business_semantics": {
            "kind": "unknown",
            "side_roles": "unknown",
            "winner_or_loser": "unknown",
            "units_and_scale": "unknown",
            "visibility": "unverified",
            "public_battle_id": "absent",
            "public_war_id": "absent",
        },
    }


def _check_runtime_shape(summary: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    messages = summary["messages"]
    expected = {
        "count": 18,
        "sequence_first": 1,
        "sequence_last": 18,
        "side_count": 36,
        "country_ref_count": 36,
        "commander_slot_count": 36,
        "summary_raw_i32_lengths": [11],
        "thread_values": [23696],
        "known_router_values": [True],
    }
    for key, value in expected.items():
        if messages.get(key) != value:
            errors.append(f"runtime {key}: expected {value!r}, got {messages.get(key)!r}")
    flags = summary.get("complete_flags") or {}
    for key in ("battle_complete", "business_complete", "overall_complete", "visibility_verified"):
        if flags.get(key) is not False:
            errors.append(f"runtime complete flag {key} is not false")
    if flags.get("public_identity", {}).get("status") != "absent":
        errors.append("runtime public identity is not explicitly absent")
    if summary.get("transport", {}).get("complete") is not False:
        errors.append("runtime transport stream unexpectedly complete")
    if summary.get("message_page", {}).get("truncated") is not False:
        errors.append("runtime message page unexpectedly truncated")
    return errors


def _make_report() -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    pins: list[dict[str, Any]] = []
    errors: list[str] = []

    # The indexes and ledgers are the small source-of-truth documents.  Raw
    # REA evidence below is only hashed by streaming; no raw JSON is loaded.
    small_pins = [
        ("docs/逐场战报原生来源.md", "14600d64d099a874bbf415bd5cda3d0cae3e5b173e67a622343003326fe3e5ea", "static_inference", "business-field boundary"),
        ("docs/逐场战报采集与交付边界.md", "1e94e51979d35079db842d32186b7058b6e551a95a8dc1918cd4e6f91078ca32", "static_inference", "identity and lifetime boundary"),
        ("docs/逐场战报自然入口与复制.md", "cdb746837a41f9ac1012812093391c870516b4bf520970e5c11542fb93d275e0", "static_inference", "owned raw-copy boundary"),
        ("docs/逐场战报历史读取与保留范围.md", "2a444dcc722f4fa8ca993a7979e41f1c6666852bb586feefb2be0fa9fce0a2be", "static_inference", "history/save boundary"),
        ("work/runtime/information-battles-20261025-001/research-index-001.json", "0afcbd8b928cffbd1acda34f1f7d19e2d5eef4901e15525e6b219ac0bd8580f9", "REA_index", "router/builder/result/effects evidence index"),
        ("work/runtime/information-battle-layout-20261025-001/research-index-001.json", "c3e958f623e86d9495c619ba4cd1dc1e20762e17b6e38bfc5b619eb7dca4eac4", "REA_index", "result postprocess and land formatter index"),
        ("work/runtime/information-battle-capture-contract-20261025-001/research-index-002.json", "5fbe175bcec6ea7e94ae1fbf023ff83969490f34f9a32e86530483d43f17a1aa", "REA_index", "side identity and cleanup index"),
        ("work/runtime/information-battle-message-20261025-001/research-index-001.json", "62e57ecfeaa4a5414165df3dbf6162298aca646cfab57da24f125ae16cab8e83", "REA_index", "formatter and message boundary index"),
        ("work/runtime/information-battle-scalar-writers-20261025-001/research-index-001.json", "b3a2c7003ad98a7ea5f0c52f8c262da8a10841883487afcc328e167569eae8ce", "REA_index", "numeric conversion/display boundary index"),
        ("work/runtime/information-battle-entry-20261025-001/payload-source-survey-001.json", "d9c40946a1d5df5df5b98951a9bfd13de627259c56626af8cb59a89fe357cce4", "static_survey", "entry payload field inventory"),
        ("work/runtime/information-battles-20261025-001/source-survey-001.json", "bca3ee3326c3b2bf637f49e7ed0467764d1c4571cfd5a86f0952d173596f5756", "static_survey", "bounded historical source survey"),
        ("work/runtime/information-battle-layout-20261025-001/land-message-field-ledger-001.json", "4ecf78cd675e82558ef4935659d0d49544c7d004c80f07971804be42ed16b9cc", "REA_selected", "land formatter field ledger"),
        ("work/runtime/information-battles-20261025-001/naval-message-field-ledger-001.json", "bb1c27a67ba29ae25ec20bc5bbfca86525a3ea6be08b32dc6bc15115fb4a0045", "REA_selected", "naval formatter field ledger"),
        ("work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json", "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41", "REA_selected", "land/naval unit display ledger"),
        ("work/runtime/information-battle-scalar-writers-20261025-001/scalar-field-writer-001.json", "3bd495ce9575b7f4a3134512f7fb27fd9ad6594632b1afd4026e9a419b574400", "REA_selected", "static writer field ledger"),
        ("work/runtime/information-battle-war-records-20261025-001/callback-entry-selected-001.json", "1d7114d3accb76b417b6a4a56135cc32e8ff8cb3640d1242ff4fe0c5b280a8f6", "REA_selected", "238620 selected callback values"),
        ("work/runtime/information-battle-live-20261025-001/payload-analysis-001.json", "17f55e7bde91f52a3a5cfaede933f3ea5db1cc87f25c25e6d5aa43223abcc3ce", "runtime_observed", "18-message payload analysis"),
        ("work/runtime/information-battle-live-20261025-001/raw-after-window-002.json", "06c674404eea9407900e438a86a71aae1e03b34986a0d562447f7e3383405318", "runtime_observed", "immutable natural-window raw ingest report"),
    ]
    for path, sha, layer, role in small_pins:
        _pin(pins, path, sha, layer=layer, role=role)

    evidence_pins = [
        ("work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json", "e90c41522700fba9add03336fc7224b8086c7d426dbdea1c409e968ed989d663", "ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3", "23A020 router"),
        ("work/runtime/information-battles-20261025-001/rea-battle-result-builder-001/evidence.json", "f89ae1a7ce86953b2ea6e85a0655401eec781ca8d8ecc59d86b2f5e85b4494fb", "ev_03446e6e905eb63817e10e5c2576bc2e15508075809ecf3cc13c60fb433b2ebe", "237D80 non-siege builder"),
        ("work/runtime/information-battles-20261025-001/rea-battle-result-object-001/evidence.json", "ca634bf7519e93e8ff9604d8600dc9b9041568ca080035f2939bd46d0a5c976a", "ev_5a34a1545032fa29696f022c0f7ce62107b4677dc9af13d095461271c051cce9", "237FC0 result object"),
        ("work/runtime/information-battles-20261025-001/rea-battle-loss-summary-001/evidence.json", "48a7678b09df72c56dbee7de6e05cc94987ea36416a3c16abae0ecf2a4006e06", "ev_ea8d6d45a9788d89cad3a26bf75ba9e34c2607e090e08fdb48a714869cf8dd76", "237950 aggregate candidate"),
        ("work/runtime/information-battles-20261025-001/rea-battle-result-effects-001/evidence.json", "0da43feb0120230fe0d9e99acb444a996dd5ad89462f3fd2e9dba2a798de6cde", "ev_dfbbdac096cca33b6fba9295ca0bc27f2f1424afa384392da678e5a0ee424358", "238620 callback"),
        ("work/runtime/information-battles-20261025-001/rea-message-dispatch-001/evidence.json", "017a28a7d4ded0ff1bc4668da53d7fdb72750045fa229a39c40a88a4d7177734", "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e", "22E6B0 naval formatter"),
        ("work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/evidence.json", "272c19c062bdb9ce628689e0bbe2fd93d2e2a54a5ff8b4af6d252ebb182a7921", "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89", "232A80 land formatter"),
        ("work/runtime/information-battle-capture-contract-20261025-001/rea-side-country-selector-001/evidence.json", "e548e13a5b2723e3a09eea0ce2870de31feddff0f66aba78ab5ca2db6a728c71", "ev_eb423943852560c33b8bf764a143cd8c925e88887656fb8f828bfd24719d719d", "21C7D0 side country selector"),
        ("work/runtime/information-battle-capture-contract-20261025-001/rea-side-commander-selector-001/evidence.json", "ebe2fd7b01f576cd5f6a291fe71a24bcf78ca1097f4375145a78f3dfbc12ea21", "ev_66949db89bae83ffb97d97534caf7313ed6692fd7db61ea141f6b78b1c40a973", "21FEB0 commander selector"),
        ("work/runtime/information-battle-capture-contract-20261025-001/rea-result-release-001/evidence.json", "5325ae0d79cb7fe3747dbc059111fe640bb2bdcd0c3f05d0757293979814d9b3", "ev_fb35b596d32c105001f1e50c620ff980139638757c9c71e8bd7674c591206154", "1DD090 cleanup"),
        ("work/runtime/information-battle-scalar-writers-20261025-001/rea-scalar-writer-001/evidence.json", "6263127a4a2ef2b87b9015237aa9ca11b9cbb9ebbc5ea26b9febdeebc508a152", "ev_aed48f3663f7c2a170398a4c4685fb3a7d5fab7a0d017d0fbda62c4f3eaae28c", "1707B30 numeric writer"),
        ("work/runtime/information-battle-scalar-writers-20261025-001/rea-count-conversion-001/evidence.json", "caf08f0283ae4f444be7f62a4cf5069102f970b82af0a57ba616b505527da429", "ev_4c3cd7bbb0db4a6ea25ed7678f09db838425668457a2234c38b8ab5f1f20c504", "CFCD0 conversion"),
        ("work/runtime/information-battle-scalar-writers-20261025-001/rea-count-display-001/evidence.json", "775d94f6ae640cf56009977daa42c59ce621d0af84617720a2db56eec924cb57", "ev_959dd5e56c1114bb51d5b23ab36d9685586c3bbf60f33296eb7a7cc7b361adb1", "AE8A80 display"),
    ]
    for path, sha, evidence_id, role in evidence_pins:
        _pin(pins, path, sha, layer="REA_raw_stream_hash", role=role, evidence_id=evidence_id)

    # Smaller selected reports for the result postprocessor and save-key names.
    selected_pins = [
        ("work/runtime/information-battle-layout-20261025-001/rea-result-postprocess-001/selected-evidence-001.json", "af2b2db2eb662e387f5c19972922bfa815d6206299b403dfd9013aa03226e7b8", "1DD930 selected postprocess"),
        ("work/runtime/information-battle-layout-20261025-001/rea-result-initializer-001/selected-evidence-001.json", "7e72e2197c96fbc5bd85fb9526ecb6d948024b0242a60e48e8025b0eeb7c584c", "1DD020 selected initializer"),
        ("work/runtime/information-battle-layout-20261025-001/result-save-keys-001.json", "02bf98a96cdc04d411d82fbca6c39b0d63b9a691d319bc485864a7c847985ba4", "result compiled save-key inventory"),
        ("work/runtime/information-battle-layout-20261025-001/side-save-keys-001.json", "75594b4629a05c647c767eea23fe95b0c04c852ee0113c573486c87f053a75d3", "side compiled save-key inventory"),
    ]
    for path, sha, role in selected_pins:
        _pin(pins, path, sha, layer="ordinary_or_selected", role=role)

    for item in pins:
        if item["status"] != "matched":
            errors.append(f"source pin {item['path']}: {item['status']}")

    router = _evidence(
        name="router_23a020",
        role="battle result router; static branch selector",
        evidence_id="ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3",
        evidence_path="work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json",
        evidence_sha256="e90c41522700fba9add03336fc7224b8086c7d426dbdea1c409e968ed989d663",
        rva_start="0x23a020",
        rva_end_inclusive="0x23a6b7",
        span_bytes=1688,
    )
    builder = _evidence(
        name="builder_237d80",
        role="non-siege result builder; direct calls to unqueried summary helpers",
        evidence_id="ev_03446e6e905eb63817e10e5c2576bc2e15508075809ecf3cc13c60fb433b2ebe",
        evidence_path="work/runtime/information-battles-20261025-001/rea-battle-result-builder-001/evidence.json",
        evidence_sha256="f89ae1a7ce86953b2ea6e85a0655401eec781ca8d8ecc59d86b2f5e85b4494fb",
        rva_start="0x237d80",
        rva_end_inclusive="0x237fbd",
        span_bytes=574,
    )
    result_object = _evidence(
        name="result_object_237fc0",
        role="result object construction candidate",
        evidence_id="ev_5a34a1545032fa29696f022c0f7ce62107b4677dc9af13d095461271c051cce9",
        evidence_path="work/runtime/information-battles-20261025-001/rea-battle-result-object-001/evidence.json",
        evidence_sha256="ca634bf7519e93e8ff9604d8600dc9b9041568ca080035f2939bd46d0a5c976a",
        rva_start="0x237fc0",
        rva_end_inclusive="0x23861a",
        span_bytes=1627,
    )
    aggregate = _evidence(
        name="aggregate_237950",
        role="auxiliary aggregate candidate; directory name is not semantic proof",
        evidence_id="ev_ea8d6d45a9788d89cad3a26bf75ba9e34c2607e090e08fdb48a714869cf8dd76",
        evidence_path="work/runtime/information-battles-20261025-001/rea-battle-loss-summary-001/evidence.json",
        evidence_sha256="48a7678b09df72c56dbee7de6e05cc94987ea36416a3c16abae0ecf2a4006e06",
        rva_start="0x237950",
        rva_end_inclusive="0x237d73",
        span_bytes=1060,
    )
    callback = _evidence(
        name="callback_238620",
        role="per-participant callback and variable writes",
        evidence_id="ev_dfbbdac096cca33b6fba9295ca0bc27f2f1424afa384392da678e5a0ee424358",
        evidence_path="work/runtime/information-battles-20261025-001/rea-battle-result-effects-001/evidence.json",
        evidence_sha256="0da43feb0120230fe0d9e99acb444a996dd5ad89462f3fd2e9dba2a798de6cde",
        rva_start="0x238620",
        rva_end_inclusive="0x23a013",
        span_bytes=6644,
        range_count=16,
        selected_path="work/runtime/information-battle-war-records-20261025-001/callback-entry-selected-001.json",
        selected_sha256="1d7114d3accb76b417b6a4a56135cc32e8ff8cb3640d1242ff4fe0c5b280a8f6",
    )
    land = _evidence(
        name="land_formatter_232a80",
        role="land result formatter; selected pseudocode only",
        evidence_id="ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89",
        evidence_path="work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/evidence.json",
        evidence_sha256="272c19c062bdb9ce628689e0bbe2fd93d2e2a54a5ff8b4af6d252ebb182a7921",
        rva_start="0x232a80",
        rva_end_inclusive="0x236796",
        span_bytes=15639,
        range_count=13,
        selected_path="work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/selected-evidence-001.json",
        selected_sha256="82455e0f1f9fe27bc3dba2e3bea176743ce21d89b076f5e789a8b7f5cef83242",
    )
    naval = _evidence(
        name="naval_formatter_22e6b0",
        role="naval result formatter; selected spans only",
        evidence_id="ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e",
        evidence_path="work/runtime/information-battles-20261025-001/rea-message-dispatch-001/evidence.json",
        evidence_sha256="017a28a7d4ded0ff1bc4668da53d7fdb72750045fa229a39c40a88a4d7177734",
        rva_start="0x22e6b0",
        rva_end_inclusive="0x232a76",
        span_bytes=17351,
        range_count=10,
        selected_path="work/runtime/information-battles-20261025-001/rea-battle-message-dispatch-001/selected-evidence-001.json",
        selected_sha256="ca5bf66fa2682e6e066d8ee75d6b5e56a325cbd67654c25b9a6d51509a576d6b",
        receipt="run.json absent; provider exit and peak unknown",
    )
    side_selector = _evidence(
        name="side_selector_21c7d0",
        role="representative country selector; not a stable public identity getter",
        evidence_id="ev_eb423943852560c33b8bf764a143cd8c925e88887656fb8f828bfd24719d719d",
        evidence_path="work/runtime/information-battle-capture-contract-20261025-001/rea-side-country-selector-001/evidence.json",
        evidence_sha256="e548e13a5b2723e3a09eea0ce2870de31feddff0f66aba78ab5ca2db6a728c71",
        rva_start="0x21c7d0",
        rva_end_inclusive="0x21c8e0",
        span_bytes=273,
    )
    postprocess = _evidence(
        name="result_postprocess_1dd930",
        role="auxiliary result-slot recomputation; selected evidence",
        evidence_id="ev_db9bc1d1c31a4a0d288d622dced59ae8201b8befe9a961060ba316b2a656d97d",
        evidence_path="work/runtime/information-battle-layout-20261025-001/rea-result-postprocess-001/selected-evidence-001.json",
        evidence_sha256="af2b2db2eb662e387f5c19972922bfa815d6206299b403dfd9013aa03226e7b8",
        rva_start="0x1dd930",
        rva_end_inclusive="0x1ddb32",
        span_bytes=515,
        receipt="selected report pin; original raw evidence is represented by its index metadata",
    )
    evidence_records = [router, builder, result_object, aggregate, callback, land, naval, side_selector, postprocess]

    runtime_path = REPO / "work/runtime/information-battle-live-20261025-001/payload-analysis-001.json"
    runtime = _runtime_summary(runtime_path)
    errors.extend(_check_runtime_shape(runtime))

    # No standalone dossier for these two helpers exists.  They are visible as
    # calls in the 237D80 REA body, which is the narrowest honest next hop.
    candidates = [
        {
            "rva": "0x2367a0",
            "static_va": "0x1402367a0",
            "status": "unqueried_standalone_function",
            "reason": "237D80 calls it after 237FC0/237950; no standalone REA record or selected evidence was found in the pinned indexes.",
            "caller_evidence": "ev_03446e6e905eb63817e10e5c2576bc2e15508075809ecf3cc13c60fb433b2ebe",
            "caller_rva": "0x237d80",
        },
        {
            "rva": "0x236dc0",
            "static_va": "0x140236dc0",
            "status": "unqueried_standalone_function",
            "reason": "237D80 calls it on the same result-construction path; no standalone REA record or selected evidence was found in the pinned indexes.",
            "caller_evidence": "ev_03446e6e905eb63817e10e5c2576bc2e15508075809ecf3cc13c60fb433b2ebe",
            "caller_rva": "0x237d80",
        },
    ]

    report: dict[str, Any] = {
        "schema": "information_battle_business_fields_survey_v1",
        "status": "passed_static_and_runtime_boundary_survey" if not errors else "failed_source_pin_or_shape_check",
        "generated_by": "work/survey_information_battle_business_fields.py",
        "scope": {
            "read_only": True,
            "game_access": False,
            "process_access": False,
            "control_command_sent": False,
            "rea_query_or_dispatch": False,
            "production_modified": False,
            "large_raw_json_loaded": False,
            "raw_evidence_policy": "stream-hash referenced evidence; use selected reports/ledgers; do not load >10MB evidence JSON",
        },
        "target_build": {
            "game_version": EXE_VERSION,
            "executable_sha256": EXE_SHA256,
            "image_base": IMAGE_BASE,
            "address_convention": "RVA findings; static VA=image_base+RVA; REA body endpoints inclusive",
        },
        "evidence_layers": {
            "rea_static": {
                "interpretation": "REA/Ghidra static function evidence; no native call and no runtime business semantics",
                "records": evidence_records,
            },
            "ordinary_pe_and_compiled_static": {
                "interpretation": "fixed-file bytes and compiled save-key/display ledgers; no runtime key-vector or field semantics",
                "reports": [
                    {"path": "work/runtime/information-battle-layout-20261025-001/result-save-keys-001.json", "sha256": "02bf98a96cdc04d411d82fbca6c39b0d63b9a691d319bc485864a7c847985ba4"},
                    {"path": "work/runtime/information-battle-layout-20261025-001/side-save-keys-001.json", "sha256": "75594b4629a05c647c767eea23fe95b0c04c852ee0113c573486c87f053a75d3"},
                    {"path": "work/runtime/information-battle-scalar-writers-20261025-001/scalar-field-writer-001.json", "sha256": "3bd495ce9575b7f4a3134512f7fb27fd9ad6594632b1afd4026e9a419b574400"},
                    {"path": "work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json", "sha256": "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41"},
                ],
            },
            "static_inference": {
                "reports": [
                    {"path": "docs/逐场战报原生来源.md", "sha256": "14600d64d099a874bbf415bd5cda3d0cae3e5b173e67a622343003326fe3e5ea", "lines": "14-25,29-55,61-89"},
                    {"path": "docs/逐场战报采集与交付边界.md", "sha256": "1e94e51979d35079db842d32186b7058b6e551a95a8dc1918cd4e6f91078ca32", "lines": "9-27,39-47"},
                    {"path": "docs/逐场战报自然入口与复制.md", "sha256": "cdb746837a41f9ac1012812093391c870516b4bf520970e5c11542fb93d275e0", "lines": "30-42"},
                    {"path": "docs/逐场战报历史读取与保留范围.md", "sha256": "2a444dcc722f4fa8ca993a7979e41f1c6666852bb586feefb2be0fa9fce0a2be", "lines": "19-25,42,52-56"},
                ],
            },
            "runtime_observed": runtime,
        },
        "fields": {
            "kind": {
                "status": "partial_static_branch_only",
                "known": [
                    "23A020 observes a virtual +0x60 return value of 1 or 2 and routes 1 to 232A80 and 2 to 22E6B0.",
                    "These are raw branch values and formatter targets, not a published enum or public event kind.",
                ],
                "evidence": ["ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3", "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89", "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e"],
                "unknown": ["business enum names", "other branch values", "per-message kind in the 18 runtime records", "visibility/observer semantics"],
            },
            "side_roles": {
                "status": "raw_structure_only_business_roles_unknown",
                "known": [
                    "237FC0/1DD020 construct two embedded side objects at result+0x10 and result+0x88.",
                    "21C7D0 selects a representative country reference through unit-chain/virtual checks; a war-member comparison can lead to result-side exchange.",
                    "Static default save labels attacker/defender and formatter labels OUR/ENEMY are retained as labels only.",
                ],
                "evidence": ["ev_5a34a1545032fa29696f022c0f7ce62107b4677dc9af13d095461271c051cce9", "ev_eb423943852560c33b8bf764a143cd8c925e88887656fb8f828bfd24719d719d", "ev_db9bc1d1c31a4a0d288d622dced59ae8201b8befe9a961060ba316b2a656d97d"],
                "unknown": ["attacker/defender business roles", "war-side versus original participant mapping", "OUR/ENEMY player or country view", "observer visibility"],
            },
            "winner_or_loser": {
                "status": "raw_flag_and_auxiliary_slots_observed_semantics_unknown",
                "known": [
                    "Compiled default names result, winner_alliance and loser_alliance are associated with result offsets +0x108, +0x104 and +0x100.",
                    "1DD930 resets/recomputes +0x100/+0x104 under country-reference, result-flag and war-membership branches; side exchange can reverse the flag.",
                ],
                "evidence": ["ev_db9bc1d1c31a4a0d288d622dced59ae8201b8befe9a961060ba316b2a656d97d", "ev_5a34a1545032fa29696f022c0f7ce62107b4677dc9af13d095461271c051cce9"],
                "unknown": ["which side won", "whether result=yes means attacker, defender, observer or another convention", "winner/loser numeric scale", "alliance slot semantics", "runtime save-key overrides"],
            },
            "units_and_losses": {
                "status": "formatter_inputs_and_script_names_observed_semantics_unknown",
                "known": [
                    "238620 contains writes/lookups for land_units_killed/lost and naval_units_killed/lost; these are cumulative/script variable names, not a per-battle public schema.",
                    "232A80 mechanically reads land side offsets +0x118/+0x11C/+0x120 and loss offsets +0x134/+0x138/+0x13C; the ledger records per-operand conversion before subtraction for land end rows.",
                    "22E6B0 has separate naval template/accumulator paths; CFCD0 and AE8A80 show integer conversion/display operations, not a universal runtime unit scale.",
                ],
                "evidence": ["ev_dfbbdac096cca33b6fba9295ca0bc27f2f1424afa384392da678e5a0ee424358", "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89", "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e", "ev_4c3cd7bbb0db4a6ea25ed7678f09db838425668457a2234c38b8ab5f1f20c504", "ev_959dd5e56c1114bb51d5b23ab36d9685586c3bbf60f33296eb7a7cc7b361adb1"],
                "unknown": ["initial/current/lost quantity semantics", "raw scale and rounding", "unit identities and side ownership", "captured ships/retreat/annihilation", "full payload coverage"],
            },
        },
        "runtime_18_boundary": {
            "status": "raw_observation_only",
            "claimable": ["18 complete wire payloads at transport-message level", "sequence 1..18 with no observed gap", "36 raw country references", "raw names/commander bytes/province/date/flag/aux/11-int summaries"],
            "not_claimable": ["kind", "attacker/defender or OUR/ENEMY roles", "winner/loser", "final quantity/unit scale", "visibility", "battle_id/war_id", "complete business battle"],
            "reason": "payload-analysis-001 explicitly keeps battle_complete, business_complete, overall_complete and visibility_verified false; public IDs are absent and transport_stream_complete is false.",
        },
        "next_minimal_unqueried_functions": candidates,
        "source_pins": pins,
        "errors": errors,
        "limitations": [
            "No field is promoted to a public business field by this survey.",
            "Raw runtime values are preserved as observations only; flag108, value shape, template labels and save-key names are not semantic guesses.",
            "The original 22E6B0 evidence has no run.json; provider exit and peak remain unknown.",
            "2367A0 and 236DC0 are recommended only as narrow next candidates because they are called by the already-pinned 237D80 path and lack standalone evidence.",
        ],
    }
    return report, pins, errors


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    output = args.output if args.output.is_absolute() else REPO / args.output
    output = output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    report, _pins, errors = _make_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "status": report["status"], "pin_count": len(report["source_pins"]), "error_count": len(errors)}, ensure_ascii=False))
    return 0 if not errors else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SurveyError as exc:
        print(f"survey failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2)
