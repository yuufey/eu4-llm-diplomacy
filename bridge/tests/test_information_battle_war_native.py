"""Run the owned C++ war-binding and cross-language wire fixtures in regression."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("source,expected", [
    ("work/native/test-information-battle-war-binding.cpp", '"checks":8'),
    ("work/native/tests/information-battle-war-identity-wire-test.cpp", "RESULT PASS information-battle-war-identity-wire"),
])
def test_owned_war_native_fixture(source, expected, tmp_path):
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("owned native fixture requires g++")
    executable = tmp_path / "war-fixture.exe"
    compiled = subprocess.run(
        [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "work/native"),
         str(ROOT / source), "-o", str(executable)],
        cwd=ROOT, capture_output=True, text=True, timeout=45, check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert expected in result.stdout, result.stdout
