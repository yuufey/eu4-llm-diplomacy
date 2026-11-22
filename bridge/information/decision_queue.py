"""Persist which periodic information results have triggered a Codex turn."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .model import digest
from .presentation import present_concise


def strategic_subscription(service, country: str, days: int, scope: str) -> dict:
    context = service.discover()["context"]
    if context.get("status") != "ready" or context.get("observer") != country:
        raise RuntimeError("Strategic briefs require a ready session observing the decision country")
    binding = {key: context[key] for key in ("session_id", "game_version", "observer")}
    if context.get("world_id"):
        binding["world_id"] = context["world_id"]

    def query(topic, fields, **object_scope):
        return {"topic": topic, "object": object_scope, "fields": fields}

    report = service.manage_report(
        f"decision-report-{scope}", "create", config={
            "name": f"{country} 战略简报",
            "detail": "brief",
            "queries": [
                query("C01", ["game_date", "observer"], type="session"),
                query("C03", ["pending_matters"], type="session"),
                query("N01", ["treasury", "monthly_balance"], type="country", country=country),
                query("N05", ["diplomat_tasks"], type="country", country=country),
            ],
        },
    )["report"]
    created = service.manage_subscription(
        f"decision-periodic-{scope}", "create", config={
            "name": f"{country} 每 {days} 游戏日战略简报",
            "report_id": report["id"],
            "kind": "periodic",
            "binding": binding,
            "schedule": {"basis": "game", "every": days, "unit": "days", "missed": "coalesce"},
        },
    )["subscription"]
    current = service.status(created["id"])["subscriptions"][0]
    subscription = current["subscription"]
    if current["runtime"]["state"] == "world_revalidation_required":
        # The operator explicitly started this scheduler against a ready live
        # session. Resume its own report with a new cadence and no old cursor.
        return service.manage_subscription(
            f"decision-resume-{scope}-{subscription['version']}", "resume",
            subscription_id=subscription["id"], expected_version=subscription["version"],
        )["subscription"]
    return subscription


class DecisionQueue:
    def __init__(self, database, owner: str, binding: dict, *, days: int, check_only: bool,
                 desktop_thread: str | None = None):
        self.database = database
        self.owner = owner
        self.binding = binding
        identity = [owner, binding, days, check_only]
        if desktop_thread:
            identity.append(desktop_thread)
        self.scope = digest(identity)[:32]
        with closing(sqlite3.connect(database, timeout=15)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS decision_threads (
                    scope TEXT PRIMARY KEY, thread_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decision_turns (
                    scope TEXT NOT NULL, result_id TEXT NOT NULL, turn_id TEXT,
                    state TEXT NOT NULL, PRIMARY KEY(scope, result_id)
                );
            """)

    def connect(self):
        return closing(sqlite3.connect(self.database, timeout=15))

    def thread(self):
        with self.connect() as db:
            row = db.execute("SELECT thread_id FROM decision_threads WHERE scope=?", (self.scope,)).fetchone()
            return row[0] if row else None

    def save_thread(self, thread_id: str):
        with self.connect() as db, db:
            db.execute("INSERT INTO decision_threads VALUES (?, ?) "
                       "ON CONFLICT(scope) DO UPDATE SET thread_id=excluded.thread_id",
                       (self.scope, thread_id))

    def has_started(self) -> bool:
        with self.connect() as db:
            return db.execute("SELECT 1 FROM decision_turns WHERE scope=? LIMIT 1",
                              (self.scope,)).fetchone() is not None

    def unresolved(self):
        with self.connect() as db:
            return db.execute(
                "SELECT result_id,turn_id,state FROM decision_turns WHERE scope=? "
                "AND state IN ('starting','running','uncertain') ORDER BY rowid LIMIT 1",
                (self.scope,),
            ).fetchone()

    def claim_latest(self, subscription_id: str, context: dict, *,
                     active_turn_id: str | None = None) -> dict | None:
        with self.connect() as db, db:
            scope = self.scope
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                    "SELECT 1 FROM decision_turns WHERE scope=? "
                    "AND (state IN ('starting','uncertain') OR (state='running' AND "
                    "(? IS NULL OR turn_id IS NOT ?)))", (scope, active_turn_id, active_turn_id)).fetchone():
                return None
            sub_row = db.execute(
                "SELECT body FROM info_config WHERE owner=? AND kind='subscription' AND id=?",
                (self.owner, subscription_id),
            ).fetchone()
            if not sub_row:
                return None
            subscription = json.loads(sub_row[0])
            if subscription["state"] != "active" or subscription["binding"] != self.binding:
                return None
            runtime_row = db.execute(
                "SELECT body FROM info_runtime WHERE owner=? AND id=?",
                (self.owner, subscription_id),
            ).fetchone()
            if not runtime_row or json.loads(runtime_row[0]).get("state") != "active":
                return None
            report_row = db.execute(
                "SELECT version FROM info_config WHERE owner=? AND kind='report' AND id=?",
                (self.owner, subscription["report_id"]),
            ).fetchone()
            if not report_row:
                return None
            row = db.execute(
                """SELECT body FROM info_results WHERE owner=?
                   AND json_extract(body,'$.subscription_id')=?
                   AND json_extract(body,'$.subscription_version')=?
                   AND json_extract(body,'$.report_version')=?
                   AND json_extract(body,'$.trigger')='periodic'
                   ORDER BY rowid DESC LIMIT 1""",
                (self.owner, subscription_id, subscription["version"], report_row[0]),
            ).fetchone()
            if not row:
                return None
            result = json.loads(row[0])
            if result.get("status") not in ("complete", "partial") or any(
                    result["context"].get(key) != value for key, value in self.binding.items()):
                return None
            result_context = result["context"]
            if context.get("world_id") != result_context.get("world_id"):
                return None
            if type(result_context.get("game_day")) is not int or type(context.get("game_day")) is not int:
                return None
            if result_context["game_day"] > context["game_day"]:
                return None
            # Read only the newest result. Older periodic samples remain in the
            # information database and will never backfill another decision.
            brief = present_concise(result)
            brief.pop("delivery", None)
            if len(json.dumps(brief, ensure_ascii=False).encode("utf-8")) > 64_000:
                brief.pop("items", None)
                brief["read_via"] = "information_get_result"
            if db.execute(
                    "INSERT INTO decision_turns VALUES (?, ?, NULL, 'starting') ON CONFLICT DO NOTHING",
                    (scope, result["result_id"])).rowcount:
                return brief
            return None

    def mark(self, result_id: str, state: str, turn_id: str | None = None):
        with self.connect() as db, db:
            db.execute(
                "UPDATE decision_turns SET state=?,turn_id=COALESCE(?,turn_id) "
                "WHERE scope=? AND result_id=? AND state IN ('starting','running','uncertain')",
                (state, turn_id, self.scope, result_id),
            )
