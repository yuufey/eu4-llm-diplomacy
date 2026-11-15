"""Bind the ordinary PE windows to two accepted cached REA leaf queries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "work/runtime/information-relation-current-20261027-001"
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path):
    data = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    source_path = STAGE / "relation-current-source-002.json"
    source = json.loads(source_path.read_bytes())
    assert source["target_binary"]["sha256"] == GAME_SHA
    rea = []
    for family, folder, rva, begin, count in (
        ("alliance", "rea-alliance-membership-001", 0xA68BC0, "0x80", "0x8c"),
        ("royal_marriage", "rea-marriage-membership-001", 0xA68A10, "0x68", "0x74"),
    ):
        path = STAGE / folder
        assert (path / "evidence.json").stat().st_size < 2 * 1024 * 1024
        run = json.loads((path / "run.json").read_bytes())
        evidence = json.loads((path / "evidence.json").read_bytes())
        assert run["target_sha256"] == GAME_SHA and run["status"] == "completed"
        assert run["provider_exit_code"] == run["exit_code"] == run["postread_exit_code"] == 0
        assert run["query_reanalysis"] is False and run["database_unchanged"] is True
        assert run["cleanup"]["status"] == "complete"
        assert evidence["evidence_id"] == run["evidence_id"]
        normalized = evidence["normalized_result"]
        pseudocode = normalized["pseudocode"]
        assert begin in pseudocode and count in pseudocode
        assert "(int)(short)" in pseudocode and "param_1[2] >> 0x20" in pseudocode
        assert "piVar1 = piVar1 + 4" in pseudocode
        rea.append({"family": family, "rva": hex(rva), "static_va": hex(0x140000000 + rva),
                    "evidence_id": evidence["evidence_id"], "provider": evidence["provider"],
                    "procedure": normalized["procedure"], "pseudocode": pseudocode,
                    "limitations": normalized.get("limitations", []),
                    "run": pin(path / "run.json"), "evidence": pin(path / "evidence.json"),
                    "query_reanalysis": False, "database_unchanged": True, "closed": True})
    result = {
        "schema": "information_relation_current_contract.v1", "report_id": "relation-current-contract-003",
        "target_binary": {"version": "1.37.4", "sha256": GAME_SHA, "image_base": "0x140000000"},
        "ordinary_pe_source": pin(source_path), "accepted_REA": rea,
        "predicate": {
            "relation_row_owner": "*(relation_row+0); distinct from actor country",
            "recipient_guard": "relation_row+0x10 must equal the resolved recipient's full 8-byte reference",
            "slot": "signed_i16(recipient_fullref >> 32)",
            "vectors": {"alliance": {"pointer": "owner+0x80", "count": "owner+0x8c"},
                        "royal_marriage": {"pointer": "owner+0x68", "count": "owner+0x74"}},
            "element_stride": 16, "compared_bytes": "element+0 signed32 slot only",
            "active": "at least one compared slot equals the signed recipient slot",
            "native_return": "AL only; other EAX bytes are not a bool",
            "remaining_element_bytes": "12 uninterpreted bytes; no date or fullref claim",
            "selector_offer_false": "case zero-extends AL and XORs false; membership retained",
        },
        "corrections": [{"source": "relation-current-source-001.json",
                         "field": "producer_contract.native_membership_helper.call_target_va",
                         "old": "0x14135a920", "correct": "0x14035a920",
                         "rva_unchanged": "0x35a920", "original_preserved": True}],
        "runtime": {"new_RPM": False, "native_function_invoked": False, "game_state_written": False},
        "unresolved": ["expires_at", "remaining 12 bytes in each member record", "complete R01 relation type coverage"],
    }
    target = STAGE / "relation-current-contract-003.json"
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(pin(target)))


if __name__ == "__main__":
    main()
