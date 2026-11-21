"""Deliver a briefing as a visible follow-up in an existing local Codex chat."""
from __future__ import annotations

import json
import re
import subprocess
from uuid import UUID


def desktop_thread_id(value: str) -> str:
    return str(UUID(value))


def desktop_prompt(brief: dict, *, check_only: bool) -> str:
    action = (
        "这是同一对话的投递验收。请回复简报编号和日期，并给出一个只读的下一步建议。"
        if check_only else
        "请在本对话开始一轮外交决策。根据简报说明优先事项。若已连接本轮 EU4 MCP，"
        "先核对当前日期和待办，再使用已授权的游戏工具。"
    )
    payload = json.dumps(brief, ensure_ascii=False, indent=2)
    if len(payload.encode("utf-16-le")) > 40_000:
        payload = json.dumps({"result_id": brief["result_id"], "brief_size_limit": True},
                             ensure_ascii=False, indent=2)
    return f"【EU4 自动简报】\n\n{action}\n\n{payload}"


def enqueue_desktop_brief(executable: str, thread_id: str, brief: dict, *, check_only: bool) -> dict:
    """Queue one follow-up through the shared Codex app server."""
    thread_id = desktop_thread_id(thread_id)
    prompt = desktop_prompt(brief, check_only=check_only)
    completed = subprocess.run(
        [executable, "queue", "--thread", thread_id, "--message", prompt, "--resume"],
        capture_output=True, encoding="utf-8", errors="replace", timeout=60, check=False,
    )
    match = re.search(r"^Queued message ([0-9a-f-]+) for thread ([0-9a-f-]+)\.$",
                      completed.stdout, re.MULTILINE)
    if completed.returncode or not match or match.group(2) != thread_id:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"Codex follow-up queue could not be confirmed: {detail[-1000:]}")
    return {"message_id": match.group(1), "thread_id": thread_id,
            "warning": completed.stderr.strip() or None}
