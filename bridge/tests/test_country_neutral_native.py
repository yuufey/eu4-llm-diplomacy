"""Compile and run the native policy and response-contract fixtures."""
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(("source", "flags"), [
    ("test-control-country-policy.cpp", []),
    ("test-alliance-inbound-inspection-event.cpp", []),
    ("tests/information-mission-conditions-test.cpp", ["-DBRIDGE_NATIVE_COUNTRY_CONTROL=1"]),
])
def test_native_country_binding_fixtures(tmp_path, source, flags):
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("native fixture requires g++")
    executable = tmp_path / "country-neutral.exe"
    command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
               *flags, "-I", str(ROOT / "work/native"),
               str(ROOT / "work/native" / source), "-o", str(executable)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stderr
    tested = subprocess.run([str(executable)], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert tested.returncode == 0, tested.stdout + tested.stderr
