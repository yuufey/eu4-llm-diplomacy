"""Development history tests use only temporary files and FakeRuntime."""
import copy
import json
from pathlib import Path
import threading
import types
import unittest
from unittest.mock import patch

from bridge import tag_command_backend as tag_command_backend_module
from bridge import tag_test_policy
from bridge.tag_command_backend import (PublicationUnknownError, SCHEMA, TagCommandBackend,
                                       decode, digest, encode, write_new)
from bridge.tag_test_policy import DevelopmentTestHistory, clean_rejection
from bridge.tests import test_tag_command_backend as fixtures


class DevelopmentTestPolicyTests(unittest.TestCase):
    event = fixtures.TagCommandTests.event

    def setUp(self):
        fixtures.TagCommandTests.setUp(self)
        self.history_dir = self.path/"isolated-development-history"
        self._install_synthetic_historical_policy()
        self.history = DevelopmentTestHistory(self.history_dir)
        self.first = self.new_session("2")

    def _install_synthetic_historical_policy(self):
        """Route test-only sessions through the real validator and temp evidence."""
        self.synthetic_policy_root = self.path/"synthetic-test-policy-root"
        self.historical_policy_root = self.synthetic_policy_root
        self.synthetic_historical_action = "trade_favors_for_war_prep"
        self.synthetic_blocked_actions = {self.synthetic_historical_action}
        self._historical_dispatch_validator = tag_test_policy.historical_dispatch_blocks

        source_name = "work/reports/diplomacy-corrective-20261013-r2/fixture-receipts.jsonl"
        source_rows = [
            {"sequence": 1, "fixture_id": "policy-fixture-133", "phase": "claim"},
            {"sequence": 1, "fixture_id": "policy-fixture-133", "phase": "result",
             "action": self.synthetic_historical_action, "outcome": "dispatch_recorded"},
        ]
        source_raw = b"".join(
            (json.dumps(row, sort_keys=True)+"\n").encode("ascii") for row in source_rows)
        source_path = self.historical_policy_root/source_name
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(source_raw)

        evidence = [{
            "action": self.synthetic_historical_action,
            "source": source_name,
            "claim_line": 1,
            "result_line": 2,
            "sequence": 1,
            "identity": {"fixture_id": "policy-fixture-133"},
            "claim_expected": {"phase": "claim"},
            "result_expected": {"action": self.synthetic_historical_action,
                                "outcome": "dispatch_recorded"},
        }]
        policy = {
            "schema": "EU4TAG-HISTORICAL-DISPATCH-EXCLUSIONS/1",
            "game_sha256": fixtures.GAME_SHA,
            "source_pins": {source_name: {"bytes": len(source_raw),
                                          "sha256": digest(source_raw)}},
            "evidence": evidence,
            "blocked_actions": sorted(self.synthetic_blocked_actions),
        }
        self.synthetic_policy_raw = encode(policy)
        policy_path = self.historical_policy_root/tag_test_policy.HISTORICAL_DISPATCH_POLICY
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_bytes(self.synthetic_policy_raw)

        self._install_synthetic_no_repeat_history()

        expected_sha_patch = patch.object(
            tag_test_policy, "HISTORICAL_DISPATCH_POLICY_SHA", digest(self.synthetic_policy_raw))
        expected_sha_patch.start()
        self.addCleanup(expected_sha_patch.stop)

        def validate_fixture_policy(root=None):
            return self._historical_dispatch_validator(
                self.historical_policy_root if root is None else root)

        source_patch = patch.object(tag_test_policy, "historical_dispatch_blocks",
                                    side_effect=validate_fixture_policy)
        source_patch.start()
        self.addCleanup(source_patch.stop)

        backend_root_patch = patch.object(tag_command_backend_module, "ROOT",
                                          self.synthetic_policy_root)
        backend_root_patch.start()
        self.addCleanup(backend_root_patch.stop)

    def _install_synthetic_no_repeat_history(self):
        """Provide a complete temporary no-repeat input chain for fixture publishes."""
        self.synthetic_no_repeat_action = "trade_favors_for_men"
        command = {"request_id": "synthetic-final-clean-rejection",
                   "action": "trade_favors_for_gold", "actor": "FRA", "target": "NAV"}
        native_result = {
            "status": 2, "reason": "full88_normal_false",
            "known_cleanup_complete": True, "ownership_closed": True,
            "submitted": False, "submit_attempted": False, "submit_returned": False,
            "submit_value": False, "slot_consumed": False,
            "owned_live": 0, "quarantined": 0, "adapter_fault": 0,
            "transfer_outcome": 0, "submit_exception": 0,
            "adapter_call_attempts": 4,
        }
        final_evidence = {
            "completed_without_unattempted_requests": True,
            "results": [{"command": command, "state": "native_rejected",
                         "native_result": native_result}],
        }
        self.synthetic_final_evidence_path = (
            "work/runtime/policy-fixture-133/final-integration-evidence.json")
        evidence_raw = encode(final_evidence)
        evidence_path = self.synthetic_policy_root/self.synthetic_final_evidence_path
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_bytes(evidence_raw)

        closed = {
            "schema": "EU4TAG-TEST-HISTORY/1",
            "game_sha256": fixtures.GAME_SHA,
            "final_integration_closed": True,
            "source": self.synthetic_final_evidence_path,
            "source_sha256": digest(evidence_raw),
            "effect_success_claimed": False,
            "scope": "Synthetic unit fixture only; not historical authority.",
            "requests": [{"command": command, "state": "native_rejected"}],
        }
        self.synthetic_closed_path = self.synthetic_policy_root/"bridge/tag_test_history_1375.json"
        self.synthetic_closed_path.parent.mkdir(parents=True, exist_ok=True)
        self.synthetic_closed_raw = encode(closed)
        self.synthetic_closed_path.write_bytes(self.synthetic_closed_raw)

        no_repeat = {
            "schema_version": 1,
            "purpose": "user_required_no_repeat_test_policy",
            "game_version": "1.37.5",
            "formal_capabilities_promoted": False,
            "policy": "Synthetic test fixture; never evidence about an actual action.",
            "source_pins": {self.synthetic_final_evidence_path: digest(evidence_raw)},
            "aliases": {},
            "blocked_count": 1,
            "blocked_actions": {self.synthetic_no_repeat_action: [{
                "source": self.synthetic_final_evidence_path,
                "experiment": "policy-fixture-133",
                "scope": "synthetic_guard_test_only",
            }]},
        }
        self.synthetic_no_repeat_path = (
            self.synthetic_policy_root/"work/reports/diplomacy-no-repeat-test-policy-1375.json")
        self.synthetic_no_repeat_path.parent.mkdir(parents=True, exist_ok=True)
        self.synthetic_no_repeat_raw = encode(no_repeat)
        self.synthetic_no_repeat_path.write_bytes(self.synthetic_no_repeat_raw)

        # verify() rereads the fixture's manifest source pins after publication
        # preflight. Keep that source available under the injected temporary ROOT.
        source = fixtures.ROOT/"bridge/tag_command_backend.py"
        backend_source = self.synthetic_policy_root/"bridge/tag_command_backend.py"
        backend_source.parent.mkdir(parents=True, exist_ok=True)
        backend_source.write_bytes(source.read_bytes())

    def new_session(self, marker, *, different_manifest=False):
        manifest = self.path/"build.json"
        if different_manifest:
            directory = self.path/("build-"+marker)
            directory.mkdir()
            data = decode(manifest.read_bytes())
            data["PE_timestamp"] += int(marker,16)
            (directory/data["DLL"]).write_bytes((self.path/data["DLL"]).read_bytes())
            manifest = directory/"build.json"
            manifest.write_bytes(encode(data))
        runtime = fixtures.FakeRuntime()
        backend = TagCommandBackend(manifest,runtime=runtime,test_history_dir=self.history_dir)
        identity = dict(self.identity,session=marker*32,manifest_sha256=backend.manifest_sha)
        directory = backend.session(identity)
        directory.mkdir()
        session = types.SimpleNamespace(backend=backend,identity=identity,directory=directory,
                                        runtime=runtime,rows=[])
        self.add_event(session,"bootstrap_verified",0)
        self.add_event(session,"hook_installed",0)
        return session

    def add_event(self, session, event, sequence, **fields):
        row = {"schema":SCHEMA,"event":event,**session.identity,"ordinal":len(session.rows)+1,
               "production_ready":False,"no_send":False,"owner_thread":12,"thread":12,
               "sequence":sequence,**fields}
        session.rows.append(row)
        self.rewrite_events(session)

    def rewrite_events(self, session):
        (session.directory/"events.jsonl").write_text("".join(json.dumps(row)+"\n" for row in session.rows))

    def make_command(self, request_id="development-first"):
        return dict(self.command_fixture,request_id=request_id)

    @property
    def command_fixture(self):
        return {"request_id":"fixture", "actor":"POR", "target":"BRI", "action":"trade_favors_for_gold"}

    def publish(self, session, request_id="development-first"):
        command = self.make_command(request_id)
        session.backend.publish(session.identity,[command],test_only=True)
        return command

    def assert_no_preflight_publication_side_effects(self, session):
        self.assertEqual(session.runtime.checks, [])
        self.assertFalse(list(session.directory.glob("*.request")))
        self.assertFalse(list(session.directory.glob("*.pending")))
        self.assertFalse(list(session.directory.glob("key-*.json")))
        self.assertFalse((session.directory/"publisher.lock").exists())
        self.assertFalse(self.history_dir.exists())

    def claim(self, session, command):
        (session.directory/"1.claim").write_bytes((session.directory/"1.request").read_bytes())
        self.add_event(session,"request_claimed",1,action=command["action"],actor=command["actor"],
                       target=command["target"],expires=60100)
        actor = (1<<56)|(189<<32)|int.from_bytes(command["actor"].encode("ascii"),"little")
        target = (1<<56)|(116<<32)|int.from_bytes(command["target"].encode("ascii"),"little")
        human = (1<<56)|(122<<32)|int.from_bytes(b"FRA","little")
        self.add_event(session,"pair_bound",1,actor_handle=actor,target_handle=target,
                       human_player_handle=human,actor_is_human_player=False)

    def reject(self, session, command, *, gate=False):
        self.claim(session,command)
        calls = [0,1,2,3,4,5,6] if gate else [0,1,2,5]
        for call in calls:
            self.add_event(session,"native_call_begin",1,call=call)
            self.add_event(session,"native_call_return",1,call=call,normal=True,exception=0,
                           boolean=call not in ([4] if gate else [2]))
        self.add_event(session,"request_result",1,status=3 if gate else 2,
                       reason="command_gate_normal_false" if gate else "full88_normal_false",
                       known_cleanup_complete=True,ownership_closed=True,owned_live=0,quarantined=0,
                       adapter_fault=0,submitted=False,submit_attempted=False,submit_returned=False,
                       submit_value=False,slot_consumed=False,transfer_outcome=0,submit_exception=0,
                       adapter_call_attempts=len(calls))

    def assert_blocked_in_new_session(self, marker="3"):
        second = self.new_session(marker,different_manifest=True)
        command = dict(self.make_command("development-blocked-next-"+marker),actor="ENG",target="POR")
        with self.assertRaisesRegex(ValueError,"Development action reserved, dispatched or uncertain"):
            second.backend.publish(second.identity,[command],test_only=True)
        self.assertEqual(second.runtime.checks,[])
        self.assertFalse(list(second.directory.glob("key-*.json")))
        self.assertFalse((second.directory/"publisher.lock").exists())

    def test_published_attempt_blocks_changed_session_manifest_tags_and_id(self):
        self.publish(self.first)
        self.assertEqual(len(list(self.history_dir.glob("attempt-*.json"))),1)
        self.assertFalse((self.history_dir/"test-policy.lock").exists())
        self.assert_blocked_in_new_session()

    def test_claimed_attempt_without_outcome_remains_blocked(self):
        command = self.publish(self.first)
        self.claim(self.first,command)
        self.assert_blocked_in_new_session()

    def test_dispatch_or_native_unknown_never_becomes_retestable(self):
        command = self.publish(self.first)
        self.claim(self.first,command)
        self.add_event(self.first,"dispatch_intent",1)
        self.add_event(self.first,"native_call_return",1,call=7,normal=True,boolean=True,
                       slot_consumed=True,exception=0)
        self.add_event(self.first,"request_result",1,submitted=True,status=4,
                       reason="normal_dispatch_slot_consumed",ownership_closed=True,
                       owned_live=0,quarantined=0,adapter_fault=0)
        self.assert_blocked_in_new_session()
        self.first.rows[-1].update(submitted=False,status=5,reason="dispatch_outcome_unknown_no_retry")
        self.rewrite_events(self.first)
        self.assert_blocked_in_new_session("4")

    def test_clean_rejection_allows_new_id_and_old_source_pins_need_not_be_runnable(self):
        command = self.publish(self.first)
        self.reject(self.first,command)
        second = self.new_session("3",different_manifest=True)
        # A file audit must not reconstruct the old runnable backend.
        with patch.object(TagCommandBackend,"verify",side_effect=AssertionError("No old execution check")):
            self.history.check([self.make_command("development-next")])
        result = second.backend.publish(second.identity,[self.make_command("development-next")],test_only=True)
        self.assertEqual(len(result["published"]),1)
        self.assertEqual(len(list(self.history_dir.glob("attempt-*.json"))),2)
        self.assert_blocked_in_new_session("4")

    def test_normal_gate_rejection_with_all_destructors_allows_another_attempt(self):
        command = self.publish(self.first)
        self.reject(self.first,command,gate=True)
        self.history.check([self.make_command("development-next")])

    def test_development_request_id_cannot_be_reused_even_after_clean_rejection(self):
        command = self.publish(self.first)
        self.reject(self.first,command)
        second = self.new_session("3")
        with self.assertRaisesRegex(ValueError,"Development request_id already reserved"):
            second.backend.publish(second.identity,[command],test_only=True)
        self.assertEqual(second.runtime.checks,[])

    def test_missing_cleanup_fields_or_unproven_calls_do_not_unlock(self):
        command = self.publish(self.first)
        self.reject(self.first,command)
        original = copy.deepcopy(self.first.rows)
        for field in ("ownership_closed","known_cleanup_complete","owned_live","quarantined",
                      "submit_attempted","transfer_outcome"):
            with self.subTest(field=field):
                self.first.rows = copy.deepcopy(original)
                self.first.rows[-1].pop(field)
                self.rewrite_events(self.first)
                with self.assertRaisesRegex(ValueError,"Development action reserved"):
                    self.history.check([self.make_command("development-next")])
        self.first.rows = copy.deepcopy(original)
        self.first.rows[-2]["normal"] = False
        self.rewrite_events(self.first)
        with self.assertRaisesRegex(ValueError,"Development action reserved"):
            self.history.check([self.make_command("development-next")])

    def test_partial_tail_changed_prefix_or_retained_publisher_lock_blocks_clean_receipt(self):
        command = self.publish(self.first)
        self.reject(self.first,command)
        audit = self.first.directory/"events.jsonl"
        complete = audit.read_bytes()
        audit.write_bytes(complete+b'{"event":"native_call_begin"')
        with self.assertRaisesRegex(ValueError,"Development action reserved"):
            self.history.check([self.make_command("development-next")])
        audit.write_bytes(complete)
        self.first.rows[0]["extra_field"] = "Changed old audit prefix"
        self.rewrite_events(self.first)
        with self.assertRaisesRegex(ValueError,"Development action reserved"):
            self.history.check([self.make_command("development-next")])
        audit.write_bytes(complete)
        (self.first.directory/"publisher.lock").write_bytes(b"Retain for audit")
        with self.assertRaisesRegex(ValueError,"Development action reserved"):
            self.history.check([self.make_command("development-next")])
        self.assertTrue((self.first.directory/"publisher.lock").exists())

    def test_publication_unknown_preserves_both_reservation_and_publisher_evidence(self):
        original_check = self.first.runtime.check
        def fail_second_check(*args):
            original_check(*args)
            if len(self.first.runtime.checks) == 2:
                raise ValueError("Manual pause changed")
        self.first.runtime.check = fail_second_check
        with self.assertRaises(PublicationUnknownError) as caught:
            self.publish(self.first)
        self.assertEqual(caught.exception.result["state"],"publication_unknown")
        self.assertEqual(caught.exception.result["results"][0]["publication_stage"],"pending_retained")
        self.assertFalse(caught.exception.result["automatic_retry"])
        self.assertTrue((self.first.directory/"publisher.lock").exists())
        self.assertEqual(len(list(self.history_dir.glob("attempt-*.json"))),1)
        self.assert_blocked_in_new_session()

    def test_synthetic_historical_exclusion_is_validated_and_blocks_before_runtime(self):
        self.assertEqual(self._historical_dispatch_validator(self.historical_policy_root),
                         self.synthetic_blocked_actions)
        command = self.make_command("synthetic-history-blocked-action")
        command["action"] = self.synthetic_historical_action
        with patch.object(self.first.backend, "verify",
                          side_effect=AssertionError("Historical policy must precede runtime")):
            with self.assertRaisesRegex(ValueError, "Historically dispatched action"):
                self.first.backend.publish(self.first.identity, [command], test_only=True)
        self.assert_no_preflight_publication_side_effects(self.first)

    def test_synthetic_no_repeat_exclusion_is_enforced_before_runtime(self):
        policy = decode(self.synthetic_no_repeat_raw)
        self.assertEqual(set(policy["blocked_actions"]), {self.synthetic_no_repeat_action})
        command = self.make_command("synthetic-no-repeat-blocked-action")
        command["action"] = self.synthetic_no_repeat_action
        with patch.object(self.first.backend, "verify",
                          side_effect=AssertionError("No-repeat policy must precede runtime")):
            with self.assertRaisesRegex(ValueError, "Previously successful action"):
                self.first.backend.publish(self.first.identity, [command], test_only=True)
        self.assert_no_preflight_publication_side_effects(self.first)

    def test_missing_or_tampered_historical_policy_blocks_before_publication(self):
        command = self.make_command("synthetic-history-policy-invalid")
        missing_root = self.path/"missing-historical-policy-root"
        tampered_root = self.path/"tampered-historical-policy-root"
        tampered_path = tampered_root/tag_test_policy.HISTORICAL_DISPATCH_POLICY
        tampered_path.parent.mkdir(parents=True)
        tampered_path.write_bytes(self.synthetic_policy_raw+b" ")

        for label, root, error_type in (("missing", missing_root, OSError),
                                        ("tampered", tampered_root, ValueError)):
            with self.subTest(policy=label):
                def validate_selected_policy(root_arg=None, selected_root=root):
                    return self._historical_dispatch_validator(
                        selected_root if root_arg is None else root_arg)

                with patch.object(tag_test_policy, "historical_dispatch_blocks",
                                  side_effect=validate_selected_policy):
                    with patch.object(self.first.backend, "verify",
                                      side_effect=AssertionError("Policy failure must precede runtime")):
                        with self.assertRaises(error_type):
                            self.first.backend.publish(self.first.identity, [command], test_only=True)
                self.assert_no_preflight_publication_side_effects(self.first)

    def test_missing_or_tampered_no_repeat_history_chain_blocks_before_publication(self):
        command = self.make_command("synthetic-no-repeat-chain-invalid")
        policy_original = self.synthetic_no_repeat_path.read_bytes()
        closed_original = self.synthetic_closed_path.read_bytes()
        evidence_path = self.synthetic_policy_root/self.synthetic_final_evidence_path
        evidence_original = evidence_path.read_bytes()

        cases = ("missing_no_repeat_policy", "tampered_no_repeat_policy",
                 "missing_closed_history", "tampered_closed_history",
                 "missing_closed_evidence", "tampered_closed_evidence")
        for label in cases:
            with self.subTest(dependency=label):
                try:
                    if label == "missing_no_repeat_policy":
                        self.synthetic_no_repeat_path.unlink()
                        error_type = OSError
                    elif label == "tampered_no_repeat_policy":
                        self.synthetic_no_repeat_path.write_bytes(b"{invalid policy")
                        error_type = ValueError
                    elif label == "missing_closed_history":
                        self.synthetic_closed_path.unlink()
                        error_type = OSError
                    elif label == "tampered_closed_history":
                        closed = decode(closed_original)
                        closed["source_sha256"] = "0"*64
                        self.synthetic_closed_path.write_bytes(encode(closed))
                        error_type = ValueError
                    elif label == "missing_closed_evidence":
                        closed = decode(closed_original)
                        closed["source"] = "work/runtime/policy-fixture-133/missing-evidence.json"
                        self.synthetic_closed_path.write_bytes(encode(closed))
                        error_type = OSError
                    else:
                        evidence_path.write_bytes(evidence_original+b" ")
                        error_type = ValueError

                    with patch.object(self.first.backend, "verify",
                                      side_effect=AssertionError("Policy chain must precede runtime")):
                        with self.assertRaises(error_type):
                            self.first.backend.publish(self.first.identity, [command], test_only=True)
                    self.assert_no_preflight_publication_side_effects(self.first)
                finally:
                    self.synthetic_no_repeat_path.write_bytes(policy_original)
                    self.synthetic_closed_path.write_bytes(closed_original)
                    evidence_path.write_bytes(evidence_original)

    def test_interrupted_development_reservation_retains_mutex_and_reports_unknown(self):
        def fail_after_record(path, data):
            write_new(path,data)
            if Path(path).name.startswith("attempt-"):
                raise OSError("Reservation fsync outcome unavailable")
        with patch("bridge.tag_test_policy.write_new",side_effect=fail_after_record):
            with self.assertRaises(PublicationUnknownError) as caught:
                self.publish(self.first)
        self.assertEqual(caught.exception.result["results"][0]["publication_stage"],
                         "development_reservation_started")
        self.assertTrue((self.history_dir/"test-policy.lock").exists())
        self.assertTrue((self.first.directory/"publisher.lock").exists())
        self.assertEqual(len(list(self.history_dir.glob("attempt-*.json"))),1)
        self.assertFalse(list(self.first.directory.glob("*.request")))

    def test_central_mutex_prevents_concurrent_same_action_reservations(self):
        second = self.new_session("3",different_manifest=True)
        winner_has_mutex = threading.Event()
        mutex_loser_seen = threading.Event()
        release_winner = threading.Event()
        thread_finished = {"winner": threading.Event(), "loser": threading.Event()}
        outcomes = {}
        original_acquire = DevelopmentTestHistory._acquire
        winner_paused = False

        def coordinated_acquire(history):
            nonlocal winner_paused
            name = threading.current_thread().name
            if name == "policy-mutex-winner" and not winner_paused:
                lock = original_acquire(history)
                winner_paused = True
                winner_has_mutex.set()
                if not release_winner.wait(3):
                    raise AssertionError("Timed out while holding the development mutex")
                return lock
            if name == "policy-mutex-loser":
                if not winner_has_mutex.wait(3):
                    raise AssertionError("Contender started before the mutex holder")
                try:
                    return original_acquire(history)
                except FileExistsError:
                    mutex_loser_seen.set()
                    raise
            return original_acquire(history)

        def attempt(label, session, request_id):
            try:
                self.publish(session,request_id)
                outcomes[label] = ("published",)
            except FileExistsError as error:
                outcomes[label] = ("mutex_blocked", type(error).__name__, str(error))
            except Exception as error:
                outcomes[label] = ("unexpected", type(error).__name__, str(error))
            finally:
                thread_finished[label].set()

        winner = threading.Thread(target=attempt,
                                  args=("winner",self.first,"concurrent-first"),
                                  name="policy-mutex-winner")
        loser = threading.Thread(target=attempt,
                                 args=("loser",second,"concurrent-second"),
                                 name="policy-mutex-loser")
        with patch.object(DevelopmentTestHistory, "_acquire", new=coordinated_acquire):
            winner.start()
            try:
                if not winner_has_mutex.wait(2):
                    if thread_finished["winner"].is_set():
                        self.fail("Winner raised before acquiring the development mutex: "
                                  f"{outcomes.get('winner')!r}")
                    self.fail("Timed out waiting for winner's mutex acquisition; "
                              f"current outcome={outcomes.get('winner')!r}")
                loser.start()
                if not mutex_loser_seen.wait(2):
                    self.fail("Contender did not lose on the development mutex; "
                              f"winner={outcomes.get('winner')!r}, loser={outcomes.get('loser')!r}")
            finally:
                release_winner.set()
                if winner.ident is not None:
                    winner.join(3)
                if loser.ident is not None:
                    loser.join(3)
        self.assertFalse(winner.is_alive())
        self.assertFalse(loser.is_alive())
        self.assertEqual(outcomes.get("winner"), ("published",))
        self.assertEqual(outcomes.get("loser", (None,))[0], "mutex_blocked")
        self.assertEqual(outcomes["loser"][1], "FileExistsError")
        self.assertIn("test-policy.lock", outcomes["loser"][2])
        self.assertEqual(len(list(self.history_dir.glob("attempt-*.json"))),1)
        self.assertEqual(sum(len(list(session.directory.glob("*.request")))
                             for session in (self.first,second)),1)
        self.assertEqual(len(self.first.runtime.checks),2)
        self.assertEqual(second.runtime.checks,[])

    def test_ordinary_commands_do_not_consult_or_clear_development_history(self):
        self.history_dir.mkdir()
        lock = self.history_dir/"test-policy.lock"
        lock.write_bytes(b"Unresolved development reservation")
        result = self.first.backend.publish(self.first.identity,[self.make_command()])
        self.assertEqual(len(result["published"]),1)
        self.assertEqual(lock.read_bytes(),b"Unresolved development reservation")
        self.assertFalse(list(self.history_dir.glob("attempt-*.json")))

    def test_sparse_lease_rejection_and_boolean_zero_are_not_clean_proofs(self):
        self.assertFalse(clean_rejection({"status":1,"reason":"lease_precondition_rejected",
                                          "adapter_call_attempts":0,"submitted":False}))
        command = self.publish(self.first)
        self.reject(self.first,command)
        result = dict(self.first.rows[-1])
        self.assertTrue(clean_rejection(result))
        result["owned_live"] = False
        self.assertFalse(clean_rejection(result))


if __name__ == "__main__":
    unittest.main()
