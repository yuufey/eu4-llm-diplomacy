"""Machine configuration works after relocation and from another cwd."""
import os
from pathlib import Path
import subprocess
import shutil
import sys

import pytest

from work import local_config


def test_relative_path_uses_repository_and_expands_environment(tmp_path, monkeypatch):
    monkeypatch.setattr(local_config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("EU4_PATH_TEST", "data/有空格的目录")
    monkeypatch.chdir(tmp_path.parent)
    assert local_config.get_path("EU4_PATH_TEST") == tmp_path / "data/有空格的目录"
    monkeypatch.setenv("EU4_CONFIG_PARENT", str(tmp_path))
    monkeypatch.setenv("EU4_PATH_TEST", "$EU4_CONFIG_PARENT/game")
    assert local_config.get_path("EU4_PATH_TEST") == tmp_path / "game"


def test_environment_overrides_bom_and_quoted_local_file(tmp_path, monkeypatch):
    config = tmp_path / "local.env"
    config.write_text('\ufeff# local config\nEU4_CONFIG_TEST="file value"\n', encoding="utf-8")
    monkeypatch.setenv("EU4_CONFIG_TEST", "environment value")
    local_config.load_local_env(config)
    assert os.environ["EU4_CONFIG_TEST"] == "environment value"
    assert local_config.read_local_env(config) == {"EU4_CONFIG_TEST": "file value"}


def test_powershell_uses_same_precedence_and_relative_base(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for its configuration reader")
    project = tmp_path / "relocated project"
    project.mkdir()
    (project / "local.env").write_text('EU4_PYTHON="tools/本地 python.exe"\nEU4_CONFIG_TEST=file\n', encoding="utf-8-sig")
    importer = Path(local_config.__file__).parent / "native/import-local-env.ps1"
    environment = dict(os.environ, EU4_CONFIG_TEST="environment")
    environment.pop("EU4_PYTHON", None)
    command = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new()\n. $env:TEST_IMPORTER\nImport-ProjectLocalEnv -ProjectRoot $env:TEST_PROJECT\nGet-ProjectLocalValue EU4_CONFIG_TEST\nGet-ProjectLocalValue EU4_PYTHON"
    environment.update(TEST_IMPORTER=str(importer), TEST_PROJECT=str(project))
    result = subprocess.run([shell, "-NoProfile", "-Command", command], env=environment,
                            cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", check=True)
    assert result.stdout.splitlines() == ["environment", str(project / "tools/本地 python.exe")]


def test_native_recorder_uses_configured_python_and_preserves_failure_code(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for its configuration reader")
    script = tmp_path / "recorder with spaces.py"
    script.write_text("raise SystemExit(7)\n", encoding="utf-8")
    importer = Path(local_config.__file__).parent / "native/import-local-env.ps1"
    result = subprocess.run([shell, "-NoProfile", "-File", str(importer), "-PythonScript", str(script)],
                            env=dict(os.environ, EU4_PYTHON=sys.executable), cwd=tmp_path,
                            capture_output=True, text=True)
    assert result.returncode == 7
