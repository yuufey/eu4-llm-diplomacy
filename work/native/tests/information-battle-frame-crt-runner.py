"""Compile and run fixed CRT reference cases only with explicit --test-only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from work.local_config import get_path

STAGE = ROOT / "work/runtime/information-battle-control-text-20261029-001"
CPP = Path(__file__).with_name("information-battle-frame-crt-test.cpp")
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": h.hexdigest()}


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-only", action="store_true")
    parser.add_argument("--attempt", type=int, default=1)
    args = parser.parse_args()
    if not args.test_only:
        print(json.dumps({"status": "not_run_test_only_required"}))
        return 2
    if not 1 <= args.attempt <= 999:
        parser.error("attempt must be 1..999")
    output = STAGE / "owned-crt-reference-001" / f"attempt-{args.attempt:03d}"
    output.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), CPP]
    for directory in ("rea-string-to-frame-001", "rea-native-atol-001", "rea-native-integer-parser-001"):
        run = STAGE / directory / "run.json"
        report = json.loads(run.read_text(encoding="utf-8"))
        if report.get("exit_code") != 0 or report.get("target_sha256") != SHA:
            raise ValueError("REA reference not complete or wrong target")
        sources.extend((run, STAGE / directory / "evidence.json"))
    pins = [pin(path) for path in sources]
    compiler = get_path("EU4_CXX")
    executable = output / "crt-reference.exe"
    command = [str(compiler), "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
               "-static-libgcc", "-static-libstdc++", str(CPP), "-o", str(executable)]
    write(output / "pre-execution-audit.json", {
        "at": datetime.now(timezone.utc).isoformat(), "test_only": True,
        "scope": "fixed owned-process Windows long32 C-locale strtol reference cases",
        "game_function_calls": 0, "process_attachment": False, "game_memory_writes": False,
        "does_not_execute_game_bytes_or_the_historical_59_byte_leaf": True,
        "not_proof_of_game_runtime_locale_or_actual_widget_state": True,
        "sources": pins, "compiler": pin(compiler), "command": command,
    })
    result = {"schema": "information.battle.frame_crt_reference.v1", "status": "failed",
              "test_only": True, "game_function_calls": 0, "sources": pins}
    with (output / "compile.log").open("xb") as log:
        compiled = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
    result["compile_exit"] = compiled.returncode
    if compiled.returncode == 0:
        with (output / "reference.tsv").open("xb") as stdout, (output / "runtime.stderr").open("xb") as stderr:
            ran = subprocess.run([str(executable)], cwd=ROOT, stdout=stdout, stderr=stderr,
                                 check=False, timeout=20)
        result["runtime_exit"] = ran.returncode
        lines = (output / "reference.tsv").read_text(encoding="ascii").splitlines()
        rows = []
        for line in lines:
            name, raw_hex, parsed, clamped, no_digits = line.split("\t")
            raw = bytes.fromhex(raw_hex)
            if len(raw) > 8192 or clamped not in ("0", "1") or no_digits not in ("0", "1"):
                raise ValueError("reference row invalid")
            rows.append({"name": name, "raw_hex": raw_hex, "signed_i32": int(parsed),
                         "range_clamped": clamped == "1", "no_digits": no_digits == "1"})
        if ran.returncode == 0 and len(rows) == 36:
            result["status"] = "passed_owned_crt_reference_only"
        write(output / "reference.json", {"rows": rows, "case_count": len(rows),
              "scope": "owned CRT reference, not an observed game call"})
        result.update(cases=len(rows), executable=pin(executable), reference=pin(output / "reference.json"))
    if [pin(path) for path in sources] != pins:
        result["status"] = "failed_source_changed"
    write(output / "receipt.json", result)
    print(json.dumps({"status": result["status"], "cases": result.get("cases"), "output": str(output)}))
    return 0 if result["status"] == "passed_owned_crt_reference_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
