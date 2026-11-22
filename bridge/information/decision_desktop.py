"""Send a briefing to the Codex desktop client that owns the target chat."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from uuid import UUID


def desktop_thread_id(value: str) -> str:
    return str(UUID(value))


def desktop_prompt(brief: dict) -> str:
    payload = json.dumps(brief, ensure_ascii=False, indent=2)
    if len(payload.encode("utf-16-le")) > 40_000:
        payload = json.dumps({"result_id": brief["result_id"], "brief_size_limit": True},
                             ensure_ascii=False, indent=2)
    return f"非用户指令\n【EU4 自动简报】\n\n{payload}"


def _desktop_request(thread_id: str, message: str, flags: list[str]) -> dict:
    thread_id = desktop_thread_id(thread_id)
    shell = shutil.which("pwsh")
    if not shell:
        raise RuntimeError("Desktop briefing delivery requires PowerShell 7.4 or later")
    script = Path(__file__).resolve().parents[2] / "tools" / "send_codex_desktop_brief.ps1"
    command = [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script), "-ThreadId", thread_id, *flags]
    completed = subprocess.run(
        command, input=message, capture_output=True, encoding="utf-8", errors="replace",
        timeout=80, check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"Codex desktop delivery could not be confirmed: {detail[-1800:]}")
    try:
        outcome = json.loads(completed.stdout)
        if outcome["thread_id"] != thread_id:
            raise ValueError("unexpected target")
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("Codex desktop returned an invalid delivery receipt") from error
    return outcome


def verify_desktop_owner(thread_id: str) -> None:
    if _desktop_request(thread_id, "", ["-DiscoverOnly"]).get("method") != "discover":
        raise RuntimeError("Codex desktop did not confirm ownership of the target chat")


def send_desktop_brief(thread_id: str, brief: dict, *, active_only: bool = False) -> dict:
    """Steer the running turn, or start a turn when the owner confirms it is idle."""
    flags = ["-ActiveOnly"] if active_only else []
    outcome = _desktop_request(thread_id, desktop_prompt(brief), flags)
    try:
        expected = ("steer",) if active_only else ("steer", "start")
        if outcome["method"] not in expected:
            raise ValueError("unexpected delivery mode")
        UUID(outcome["message_id"])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("Codex desktop returned an invalid delivery receipt") from error
    return outcome
