"""Collect EU4 strategic briefs and dispatch them to a dedicated Codex thread."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.serve_information import _build_runtime, build_parser
from bridge.information.collection_lock import CollectionLock
from bridge.information.decision_codex import CodexDecisionClient, CodexRPCError
from bridge.information.decision_desktop import desktop_thread_id, send_desktop_brief, verify_desktop_owner
from bridge.information.decision_mcp import decision_mcp
from bridge.information.decision_queue import DecisionQueue, strategic_subscription
from bridge.game_tools import GameTools


_END_STATES = {"completed", "failed", "interrupted"}


def codex_command(executable: str, port: int, env: dict[str, str], *, check_only: bool) -> list[str]:
    relay = Path(__file__).with_name("relay_decision_mcp.py").resolve()
    args = ["-B", str(relay), str(port)]
    env_config = ",".join(f"{key}={json.dumps(value)}" for key, value in env.items())
    server = [
        "command=" + json.dumps(sys.executable),
        "args=" + json.dumps(args),
        "cwd=" + json.dumps(str(relay.parents[1])),
        "env={" + env_config + "}",
        "required=true",
        "startup_timeout_sec=90",
        "tool_timeout_sec=90",
    ]
    approved = ["information_query", "information_get_result", "information_discover",
                "render_political_map", "inspect_political_map"]
    if check_only:
        server.append("enabled_tools=" + json.dumps(approved))
    else:
        server.append('disabled_tools=["information_tick"]')
        approved.extend([
            "manage_political_map_export", "information_list_results", "information_status", "information_manage_report",
            "information_manage_subscription", "list_diplomatic_actions", "inspect_diplomatic_action",
            "execute_diplomatic_action", "get_diplomatic_result", "recall_diplomat", "set_game_speed",
        ])
    server.append("tools={" + ",".join(
        key + '={approval_mode="approve"}' for key in approved) + "}")
    settings = "mcp_servers={eu4_information={" + ",".join(server) + "}}"
    return [executable, "-c", settings, "-c", 'sandbox_mode="read-only"',
            "-c", 'approval_policy="never"', "app-server"]


def receipt(event: str, **fields):
    print(json.dumps({"event": event, **fields}, ensure_ascii=False), flush=True)


def due_brief(service, queue, subscription_id, *, turn_id=None):
    tick = service.tick()
    context = tick.get("context", {})
    if context.get("status") == "ready" and any(
            context.get(key) != value for key, value in queue.binding.items()):
        raise RuntimeError("The source changed away from the bound decision session")
    if subscription_id and tick.get("state") == "processed":
        brief = queue.claim_latest(subscription_id, context, active_turn_id=turn_id)
        map_service = getattr(service, "map_live", None)
        if brief and map_service is not None:
            map_service.invalidate()
            brief["political_map"] = {"tool": "render_political_map", "arguments": {}}
        return brief
    return None


def run_desktop(service, queue, options, subscription_id):
    if queue.unresolved():
        raise RuntimeError("The previous chat delivery is uncertain; check the target chat before continuing")
    if options.receipts:
        options.receipts.parent.mkdir(parents=True, exist_ok=True)
    receipt("decision_scheduler_ready", thread_id=options.desktop_thread,
            session_id=queue.binding["session_id"], country=queue.binding["observer"],
            subscription_id=subscription_id)
    deadline = time.monotonic() + 300 if options.check else math.inf
    while time.monotonic() < deadline:
        brief = due_brief(service, queue, subscription_id)
        if brief:
            result_id = brief["result_id"]
            try:
                outcome = send_desktop_brief(options.desktop_thread, brief)
                queue.mark(result_id, "delivered")
            except BaseException:
                queue.mark(result_id, "uncertain")
                raise
            event = {"event": "decision_desktop_delivered", "result_id": result_id, **outcome}
            print(json.dumps(event, ensure_ascii=False), flush=True)
            if options.receipts:
                with options.receipts.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            if options.check:
                return 0
        time.sleep(options.poll_seconds)
    raise RuntimeError("No due brief was delivered in five minutes")


def run_turns(service, queue, codex, thread_id, subscription_id, poll_seconds, check_only):
    deadline = time.monotonic() + 300 if check_only else math.inf
    active = queue.unresolved()
    if active:
        result_id, turn_id, state = active
        if state != "running" or not turn_id:
            raise RuntimeError(f"Decision receipt uncertain for {result_id}; inspect the Codex thread before continuing")
        recovered = codex.read_turn_status(thread_id, turn_id)
        if recovered in _END_STATES:
            queue.mark(result_id, recovered)
            receipt("decision_turn_recovered", result_id=result_id, turn_id=turn_id, status=recovered)
            if check_only:
                return 0 if recovered == "completed" else 1
            active = None
        elif recovered != "inProgress":
            queue.mark(result_id, "uncertain")
            raise RuntimeError(f"Cannot reconcile turn {turn_id} for {result_id}")

    while time.monotonic() < deadline:
        for event_thread, event_turn, state in codex.collect_turns():
            if event_thread != thread_id or not active or event_turn != active[1] or state not in _END_STATES:
                continue
            result_id, turn_id, _ = active
            queue.mark(result_id, state)
            receipt("decision_turn_finished", result_id=result_id, thread_id=thread_id,
                    turn_id=turn_id, status=state)
            active = None
            if check_only or state != "completed":
                return 0 if state == "completed" else 1

        brief = due_brief(service, queue, None if active and check_only else subscription_id,
                          turn_id=active[1] if active else None)
        if brief:
            result_id = brief["result_id"]
            try:
                if active:
                    try:
                        turn_id = codex.steer_turn(thread_id, active[1], brief)
                    except CodexRPCError as error:
                        if ("no active turn to steer" not in str(error).lower()
                                or codex.read_turn_status(thread_id, active[1]) != "completed"):
                            raise
                        queue.mark(active[0], "completed")
                        receipt("decision_turn_finished", result_id=active[0], thread_id=thread_id,
                                turn_id=active[1], status="completed")
                        active = None
                if active:
                    queue.mark(result_id, "steered", turn_id)
                else:
                    turn_id = codex.start_turn(thread_id, brief)
                    queue.mark(result_id, "running", turn_id)
            except BaseException:
                queue.mark(result_id, "uncertain")
                raise
            if active:
                receipt("decision_turn_steered", result_id=result_id, thread_id=thread_id, turn_id=turn_id)
            else:
                active = result_id, turn_id, "running"
                receipt("decision_turn_started", result_id=result_id, thread_id=thread_id, turn_id=turn_id)
        time.sleep(poll_seconds)
    raise RuntimeError("The read-only decision check did not finish in five minutes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--every-game-days", type=int, default=7)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--codex-exe", default=os.environ.get("CODEX_APP_RUNTIME_CLI_PATH")
                        or shutil.which("codex.exe") or shutil.which("codex"))
    parser.add_argument("--desktop-thread", type=desktop_thread_id, help="Deliver briefs to a local Codex chat UUID")
    parser.add_argument("--check", action="store_true",
                        help="Process one due brief (desktop delivery or read-only Codex turn)")
    parser.add_argument("--receipts", type=Path, help="Record this Codex App Server's protocol in JSONL")
    parser.add_argument("service_arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    if not options.workspace.is_dir() or (not options.desktop_thread and not options.codex_exe):
        parser.error("A decision workspace and Codex executable are required")
    if (not 1 <= options.every_game_days <= 3650 or not math.isfinite(options.poll_seconds)
            or options.poll_seconds <= 0):
        parser.error("Use a positive polling interval and 1 to 3650 game days")
    if not options.service_arguments or options.service_arguments[0] != "--":
        parser.error("Pass the information service options after --")
    service_arguments = options.service_arguments[1:]
    args = build_parser().parse_args(service_arguments)
    if (not args.operator_session or not args.observer or args.controlled_country != args.observer
            or args.jsonl or args.tick_seconds or args.recorded_manifest or args.battle_only):
        parser.error("Bind a live session observing the assigned country with MCP and no second scheduler")
    launch_guard = CollectionLock(args.database.with_suffix(".decision-run"))
    try:
        with launch_guard.acquire(blocking=False) as acquired, ExitStack() as stack:
            if not acquired:
                raise RuntimeError("A decision scheduler already owns this database")
            if options.desktop_thread:
                verify_desktop_owner(options.desktop_thread)
            service, journal = _build_runtime(args)
            if journal:
                stack.callback(journal.close)
            ingestor = getattr(service, "battle_ingestor", None)
            if ingestor:
                stack.callback(ingestor.close)
            stack.callback(service.close)
            context = service.discover()["context"]
            if context.get("status") != "ready" or not context.get("session_id"):
                raise RuntimeError("The operator-bound game session is unready")
            binding = {key: context[key] for key in ("session_id", "game_version", "observer")}
            if context.get("world_id"):
                binding["world_id"] = context["world_id"]
            queue = DecisionQueue(args.database, args.owner, binding, days=options.every_game_days,
                                  check_only=options.check, desktop_thread=options.desktop_thread)
            subscription = strategic_subscription(service, args.controlled_country,
                                                  options.every_game_days, queue.scope)
            if options.desktop_thread:
                return run_desktop(service, queue, options, subscription["id"])
            port, relay_env = stack.enter_context(decision_mcp(service, GameTools(service)))
            command = codex_command(options.codex_exe, port, relay_env, check_only=options.check)
            if options.check:
                instruction = (
                    "这是游戏简报推送验收。收到 information_brief 后，调用 EU4 MCP 的 information_query，"
                    "以简报 result_id 作为唯一 request_id。查询参数 queries 使用 "
                    '[{"topic":"C01","object":{"type":"session"},"fields":["game_date"]}]。'
                    "最终简短回报简报的 result_id、观察国、原始简报日期和查询到的日期，然后结束该轮。"
                )
            else:
                instruction = (
                    f"你负责 {args.controlled_country} 的 EU4 外交。每次收到 information_brief 就处理一轮。"
                    "依据简报制定当前行动，使用 EU4 MCP 获取补充证据。执行外交前重新核对日期、"
                    "本国待办和方案条件。跟踪每次行动的请求编号及结果。用简短决策记录结束这一轮。"
                )
            codex = stack.enter_context(CodexDecisionClient(command, options.workspace.resolve(),
                                                            receipts=options.receipts))
            previous_thread = queue.thread()
            try:
                thread_id = codex.open_thread(previous_thread, instruction)
            except CodexRPCError as error:
                # Codex may defer creating its rollout until the first turn.
                # Replace that empty thread only before any dispatch attempt.
                if (not previous_thread or queue.has_started() or error.code != -32600
                        or not str(error).endswith(f"no rollout found for thread id {previous_thread}")):
                    raise
                thread_id = codex.open_thread(None, instruction)
            queue.save_thread(thread_id)
            receipt("decision_scheduler_ready", thread_id=thread_id, session_id=binding["session_id"],
                    country=args.controlled_country, subscription_id=subscription["id"])
            return run_turns(service, queue, codex, thread_id, subscription["id"],
                             options.poll_seconds, options.check)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f"decision scheduler: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
