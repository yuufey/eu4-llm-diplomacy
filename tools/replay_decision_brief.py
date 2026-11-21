"""Test desktop delivery using one previously captured, read-only EU4 brief."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge.information.decision_desktop import enqueue_desktop_brief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thread", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--codex-exe", default=os.environ.get("CODEX_APP_RUNTIME_CLI_PATH")
                        or shutil.which("codex.exe") or shutil.which("codex"))
    args = parser.parse_args()
    if not args.codex_exe:
        parser.error("A Codex executable with the queue command is required")
    captured = json.loads(args.receipt.read_text(encoding="utf-8-sig"))
    brief = captured["brief"]
    outcome = enqueue_desktop_brief(args.codex_exe, args.thread, brief, check_only=True)
    print(json.dumps({"event": "decision_desktop_queued", "result_id": brief["result_id"], **outcome},
                     ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
