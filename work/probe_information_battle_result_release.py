"""Link the conditional result cleanup call to its fixed-build vtable target.

Only previously collected REA and ordinary PE evidence are consumed. Static
cleanup order does not prove callback reentrancy safety or runtime ownership.
"""
from __future__ import annotations

import argparse
import hashlib
import json

from probe_information_battle_side_identity import (
    IMAGE_BASE, ROOT, SPECS, STAGE, TARGET_SHA, excerpt, load,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "result-release-ledger-001.json"
    if output.exists() and not args.verify_existing:
        raise FileExistsError(output)
    SPECS["result_release"] = (
        STAGE / "rea-result-release-001/evidence.json",
        "ev_fb35b596d32c105001f1e50c620ff980139638757c9c71e8bd7674c591206154",
        0x1DD090,
    )
    SPECS["result_router"] = (
        ROOT / "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json",
        "ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3",
        0x23A020,
    )
    # Match the fixed router ID against the already frozen index as well.
    index_path = ROOT / "work/runtime/information-battles-20261025-001/research-index-001.json"
    # Do not let a copied or substituted report self-authorize its identity.
    index_raw = index_path.read_bytes()
    assert hashlib.sha256(index_raw).hexdigest() == "0afcbd8b928cffbd1acda34f1f7d19e2d5eef4901e15525e6b219ac0bd8580f9"
    assert SPECS["result_router"][1].encode("ascii") in index_raw
    release, release_record = load("result_release")
    router, router_record = load("result_router")
    vtable_path = ROOT / "work/runtime/information-battles-20261025-001/battle-stage/result-vtable-window-001.json"
    vtable_raw = vtable_path.read_bytes()
    assert hashlib.sha256(vtable_raw).hexdigest() == "6139e4ee994a3e303eb71c1eb7a0e119f8fca9ce626e10406aa3ef6727b7dbb3"
    vtable = json.loads(vtable_raw)
    assert vtable["target"]["sha256"] == TARGET_SHA
    assert vtable["slots"][0]["target"]["target_rva"] == "0x1dd090"
    assert vtable["window"]["rva"] == "0x1c448d0"
    report = {
        "schema": "information_battle_result_release_ledger_v1",
        "status": "bounded_static_cleanup_and_release_path",
        "target_exe_sha256": TARGET_SHA, "static_image_base": hex(IMAGE_BASE),
        "runtime_observed": False, "new_native_calls": 0, "new_hooks_installed": 0,
        "rea_sources": [release_record, router_record],
        "ordinary_pe_source": {"path": vtable_path.relative_to(ROOT).as_posix(),
            "bytes": len(vtable_raw), "sha256": hashlib.sha256(vtable_raw).hexdigest(),
            "vtable_rva": "0x1c448d0", "slot_0_target_rva": "0x1dd090",
            "type": "historical bounded ordinary PE bytes, not new runtime REA"},
        "observations": [
            {"meaning": "Router uses R12D=1 as EDX for the result's virtual slot0 call when SIL is zero. The land formatter CALL is RVA23a441; 23a43e is its MOV RCX setup instruction.",
             "proof": [excerpt(router, "0x14023a3cc:", assembly=True, after=2),
                       excerpt(router, "0x14023a437:", assembly=True, after=9)]},
            {"meaning": "Static vtable slot0 resolves to1dd090. This function calls095660 on result+118, +a0 and +28 in that order, then, for flag bit0 set, calls1739420(result,0x138). It returns the original result address without establishing that the storage remains valid.",
             "proof": [excerpt(release, "FUN_140095660(param_1 + 0x118)", after=12),
                       excerpt(release, "0x1401dd0c0:", assembly=True, after=6)]},
        ],
        "derived_interpretation": "This is the fixed-build deleting-destructor-like cleanup path for the result object's three string members and its 0x138 allocation. The names/allocator contracts of095660/1739420 are inferred here from call pattern and arguments, not independently reanalyzed in this batch.",
        "capture_consequences": [
            "Copy result name and commander strings before the conditional slot0 cleanup, even if their outer object addresses appear readable later.",
            "Do not use the cleanup function's returned object address as proof of retained lifetime.",
            "Formatter entry is a candidate synchronous copy boundary in the static order; actual ABI, callbacks, reentrancy, field stability and ownership remain to be verified.",
            "A nonzero SIL skips this cleanup in the router; it does not identify a retaining owner or prove an asynchronous read window.",
        ],
        "historical_report_caveat": "The callback-lifetime-survey's definitely-usable wording only describes expected static call order; no runtime pointer or field lifetime has been proved.",
        "catalog_promotion": False,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert output.read_text(encoding="utf-8") == encoded, "existing release ledger changed"
    else:
        output.write_text(encoded, encoding="utf-8")
    print(json.dumps({"path": output.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
