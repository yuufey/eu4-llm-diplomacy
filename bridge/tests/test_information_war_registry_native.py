"""Compile bounded registry/constructor fixtures using the current native sources."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("source,standard", [
    ("work/native/tests/information-war-registry-recycling-test.cpp", "c++17"),
    ("work/native/tests/information-war-registry-recycling-test.cpp", "c++20"),
    ("work/native/test-peace-war-participants.cpp", "c++17"),
    ("work/native/test-peace-war-participants.cpp", "c++20"),
    ("work/native/test-peace-inbound-annex-proof.cpp", "c++17"),
    ("work/native/tests/information-war-declaration-observer-test.cpp", "c++20"),
    ("work/native/tests/information-war-declaration-test.cpp", "c++20"),
    ("work/native/tests/information-war-declaration-forward-test.cpp", "c++20"),
    ("work/native/tests/information-support-subject-record-entry-plan-test.cpp", "c++17"),
    ("work/native/tests/information-support-subject-record-entry-plan-test.cpp", "c++20"),
])
def test_native_registry_lifetime_paths(tmp_path, source, standard, record_testsuite_property):
    compiler = shutil.which("g++")
    assert compiler, "The existing native fixture compiler must be available"
    executable = tmp_path / "war-registry-fixture.exe"
    sources = [source]
    if "entry-plan-test" in source:
        sources.append("work/native/tests/information-support-subject-record-entry-plan-abi.S")
    definitions = []
    if source.endswith("information-war-declaration-forward-test.cpp"):
        definitions.append("-DBRIDGE_WAR_DECLARATION_OBSERVATION=1")
        body = (ROOT / "work/native/alliance-execution.inc").read_text(encoding="utf-8")
        start = body.index("static bool execution_call_original(")
        end = body.index("\n}", start) + 2
        assert end - start < 4096
        (tmp_path / "original-call-body.inc").write_text(body[start:end], encoding="utf-8")
        definitions.extend(["-I", str(tmp_path)])
    built = subprocess.run([compiler, "-std=" + standard, "-O1", "-Iwork/native", *definitions, *sources,
                            "-o", str(executable)], cwd=ROOT, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=90)
    assert built.returncode == 0, built.stdout + built.stderr
    environment = dict(os.environ)
    environment["WAR_DECLARATION_FIXTURE_LOG"] = str(tmp_path / "native-events.jsonl")
    result = subprocess.run([str(executable)], cwd=ROOT, env=environment,
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    record_testsuite_property(Path(source).stem + "." + standard + ".stdout", result.stdout.strip())
