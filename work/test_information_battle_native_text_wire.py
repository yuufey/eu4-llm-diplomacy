"""Lazy native runner and Python cross-check for the IBOW v6 text wire.

The default invocation and --help are inert.  Only an explicit --run compiles
and runs the small value-only C++ fixture; it never opens EU4 or uses REA/RPM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-native-text-20261027-001" / "native-wire-test-001"
CPP = NATIVE / "tests" / "information-battle-native-text-wire-test.cpp"
HEADER = NATIVE / "information-battle-native-text-wire.h"
OWNED = NATIVE / "information-battle-owned-native-text.h"
MODULE = ROOT / "work" / "information_battle_native_text_wire.py"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _parse_wires(stdout: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if not line.startswith("WIRE "):
            continue
        _, name, text = line.split(" ", 2)
        if name in result:
            raise ValueError("duplicate_wire_name")
        result[name] = bytes.fromhex(text)
    if set(result) != {"observed", "empty", "absent"}:
        raise ValueError(f"wire_cases_mismatch:{sorted(result)}")
    return result


def run(output: Path | None = None) -> dict[str, Any]:
    compiler = shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        raise RuntimeError("no_cxx_compiler")
    STAGE.mkdir(parents=True, exist_ok=True)
    executable = STAGE / "test-information-battle-native-text-wire.exe"
    report = output or (STAGE / "report-001.json")
    if report.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report}")
    command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-pedantic",
               "-I", str(NATIVE), str(CPP), "-o", str(executable)]
    compile_result = subprocess.run(command, cwd=ROOT, check=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
    if compile_result.returncode != 0:
        raise RuntimeError(f"native_compile_failed:{compile_result.stderr[-4000:]}")
    native = subprocess.run([str(executable)], cwd=ROOT, check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if native.returncode != 0:
        raise RuntimeError(f"native_test_failed:{native.stderr.decode(errors='replace')[-4000:]}")
    wires = _parse_wires(native.stdout)
    # Import only after the explicit --run gate; normal help/default remains inert.
    from work.information_battle_native_text_wire import decode_envelope

    envelopes = {name: decode_envelope(value) for name, value in wires.items()}
    checks = {
        "native_result_pass": b"RESULT PASS" in native.stdout,
        "observed_wire_known": envelopes["observed"]["text_fields"]["title_helper_candidate"]["status"] == "known",
        "empty_wire_known_empty": envelopes["empty"]["text_fields"]["auxiliary_text"]["raw_hex"] == "",
        "absent_wire_absent": envelopes["absent"]["text_fields"]["auxiliary_text"]["status"] == "absent",
        # The bounded C++ fixture intentionally uses a framing-only fake v5;
        # semantic composition is covered by the Python real-v5 replay/tests.
        "all_embedded_v5_hex_present": all(
            envelopes[name]["base_v5_payload_hex"] for name in envelopes),
        "framing_only_fixture": all(
            envelopes[name]["schema"] == "information_battle_native_text_envelope_v6"
            for name in envelopes),
        "not_full_b04": all(
            envelopes[name]["full_display_complete"] is False
            for name in envelopes),
    }
    result = {
        "schema": "information_battle_native_text_wire_native_test.v1",
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "native_stdout": native.stdout.decode("ascii", errors="strict"),
        "native_stderr": native.stderr.decode("ascii", errors="replace"),
        "wire_bytes": {name: len(value) for name, value in wires.items()},
        "wire_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in wires.items()},
        "compiler": compiler,
        "sources": {
            str(path.relative_to(ROOT)).replace("\\", "/"): {
                "bytes": path.stat().st_size, "sha256": _sha256(path),
            }
            for path in (CPP, HEADER, OWNED, MODULE)
        },
        "scope": {"game": False, "rea": False, "rpm": False,
                  "native_call": False, "full_suite": False},
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="compile and run the bounded native fixture")
    parser.add_argument("--output", type=Path,
                        help="exclusive report path used with --run")
    args = parser.parse_args(argv)
    if not args.run:
        # Deliberately inert: discovery/help must not compile or run anything.
        return 0
    result = run(args.output)
    print(json.dumps({"status": result["status"], "checks": result["checks"]},
                     ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
