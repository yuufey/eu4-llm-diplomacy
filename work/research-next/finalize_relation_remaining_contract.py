"""Pin batch55's accepted static sources and independent read-only observations."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def read(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("large artifacts are pin-only")
    return json.loads(path.read_text(encoding="utf-8"))


def pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest}


def finalize(output):
    if output.exists():
        raise FileExistsError(output)
    from work.local_config import game_exe

    binary = game_exe()
    with binary.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == SHA
    accepted = []
    for name in ("trade-league-validity", "fleet-access-validity", "fleet-current-predicate", "offer-fleet-access-validity"):
        directory = STAGE / ("rea-" + name + "-001")
        run = read(directory / "run.json")
        evidence = read(directory / "evidence.json")
        assert run["status"] == "completed" and run["provider_exit_code"] == 0
        assert run["postread_exit_code"] == 0 and run["database_unchanged"] is True
        assert run["query_reanalysis"] is False and run["cleanup"]["status"] == "complete"
        assert run["cleanup"]["closed_process_receipt"] is True
        assert run["evidence_id"] == evidence["evidence_id"]
        accepted.append({"evidence_id": evidence["evidence_id"], "procedure": run["procedure"],
                         "run": pin(directory / "run.json"), "evidence": pin(directory / "evidence.json"),
                         "database_unchanged": True, "no_reanalysis": True, "closed": True})
    fleet_receipt = read(STAGE / "fleet-basing-reference-receipt-001.json")
    assert fleet_receipt["status"] == "observed"
    assert all(item["raw_two_pass_consistent"] for item in fleet_receipt["per_actor"].values())
    trade = read(STAGE / "expected-trade-league-current-001.json")
    assert all(trade["checks"].values())
    sources = [STAGE / "fleet-basing-current-source-002.json",
               ROOT / "work/runtime/information-trade-league-current-20261027-001/trade-league-current-source-003.json",
               STAGE / "code-source004.json"]
    result = {
        "schema": "information_relation_remaining_contract.v1", "batch": 55,
        "target_binary": {"path": str(binary), "version": "1.37.4", "sha256": SHA,
                          "bytes": binary.stat().st_size, "static_image_base": "0x140000000"},
        "ordinary_static_sources": [pin(path) for path in sources], "accepted_REA": accepted,
        "common_relation_row": {"country_table_pointer_offset": "0x1510", "dereference_before_indexing": True,
                                "stride": "0x48", "owner_pointer_offset": "0x0", "partner_fullref_offset": "0x10",
                                "owner_equals_country_required": False},
        "fleet_basing": {
            "received": {"predicate_rva": "0xA69370", "body_end_exclusive_rva": "0xA693CA",
                         "owner_vector_begin": "0xE0", "owner_vector_count": "0xEC", "stride": 16,
                         "first_match": "element DWORD equals sign_extend_i16(partner.fullref.slot)",
                         "active": "first matching element+8 nonnull record; record+18 fullref slot equals partner slot",
                         "return_register": "AL only", "grantor": "partner", "beneficiary": "actor"},
            "granted": {"native_consumer_rva": "0x533FD0", "owner_vector_begin": "0xF8",
                        "owner_vector_count": "0x104", "stride": 16,
                        "active": "native inline membership compares element first DWORD with sign-extended partner slot",
                        "grantor": "actor", "beneficiary": "partner"},
            "role_binding_layer": "static operand and native text inference; no active runtime record observed",
            "role_binding_basis": ["ask checks partner port count and HAVE_FLEET_BASING against the received predicate",
                                   "offer checks actor port count and WE_GIVING_FLEET_ACCESS against the granted vector"],
            "runtime_positive_sample": False,
            "raw_reference": pin(STAGE / "fleet-basing-reference-receipt-001.json"),
            "uninterpreted": ["remaining vector element bytes", "record fields other than +18", "expiry"]},
        "trade_league": {
            "country_object_pointer": "0x1948", "active_virtual_slot": "0x40", "virtual_invoked": False,
            "active_type": {"vtable_rva": "0x1CE8948", "method_rva": "0x8F440", "method_bytes": "b001c3", "AL": True},
            "inactive_type": {"vtable_rva": "0x1C48508", "method_rva": "0x8F450", "method_bytes": "32c0c3", "AL": False},
            "members": {"begin": "0x20", "end": "0x28", "stride": 8,
                        "identity": "full eight-byte country reference bound against complete database table",
                        "first_member": "leader input in native LEADER text", "self_required_when_active": True},
            "pair": "both active, identical current object pointer, and identity-consistent membership",
            "grantor_and_beneficiary": "not applicable to shared group membership",
            "raw_reference": pin(STAGE / "expected-trade-league-current-001.json"),
            "runtime_positive_samples": ["HSA", "VEN", "GEN"], "runtime_FRA_active": False},
        "layers": {"ordinary_PE": "fixed bytes and addresses", "REA": "accepted cached decompilation, no reanalysis",
                   "RPM": "independent source bytes, before/after comparisons and closed handles",
                   "public_MCP": "not yet accepted for batch55"},
        "scope": {"goal_topics": 74, "goal_fields": 397, "goal_complete": False,
                  "pair_relation_types": 9, "country_network_families": 4,
                  "missing": ["expires_at", "guarantee and military-access country network", "remaining full development plan"]},
    }
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": "source_contract_pinned", "output": pin(output), "accepted_REA": len(accepted)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=STAGE / "relation-remaining-contract-005.json")
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return
    finalize(args.output)


if __name__ == "__main__":
    main()
