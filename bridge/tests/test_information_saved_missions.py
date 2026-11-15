from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from bridge.information.saved_missions import SavedMissionSnapshot


FIXTURE = b'''EU4txt
date=1455.11.13
player=POR
savegame_version={
 first=1
 second=37
 third=4
 forth=0
}
savegame_versions={
 "1.37.4.0"
}
dlc_enabled={
 "Domination" # comment with a closing brace }
 "Emperor"
}
countries={
 FRA={
  note="quoted { # this brace is inside a quote
still quoted }"
  country_missions={
   mission_slot={
    root_one root_duplicate # comment with {
   }
   mission_slot={
    root_duplicate "root { quoted"
   }
  }
  completed_missions={}
  flags={
   chose_branch=1455.1.1
   quoted_flag="yes # not a comment"
  }
  hidden_flags={
   hidden_branch=1455.2.2
  }
  nested_state={
   FRA={
    country_missions={
     mission_slot={ fake_nested_root }
    }
   }
  }
 }
 SWE={
  completed_missions={
   swe_one swe_two
  }
 }
}
'''


def _write(directory: Path, data: bytes = FIXTURE, name: str = "fixture.eu4") -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


class SavedMissionSnapshotTests(unittest.TestCase):
    def test_real_text_shape_preserves_slots_raw_data_and_explicit_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write(Path(temporary))
            snapshot = SavedMissionSnapshot(path, "FRA")
            result = snapshot.as_dict()
            context = snapshot.context()

        self.assertEqual("saved_mission_snapshot_v1", result["schema"])
        self.assertEqual("recorded", result["mode"])
        self.assertEqual("1455.11.13", result["date"])
        self.assertEqual("1.37.4.0", result["version"])
        self.assertEqual("POR", result["player"])
        self.assertEqual(["Domination", "Emperor"], result["dlc_enabled"])

        missions = result["country_missions"]
        self.assertTrue(missions["present"])
        self.assertEqual(2, len(missions["mission_slots"]))
        self.assertEqual(
            ["root_one", "root_duplicate"],
            missions["mission_slots"][0]["root_ids"],
        )
        self.assertEqual(
            ["root_duplicate", "root { quoted"],
            missions["mission_slots"][1]["root_ids"],
        )
        self.assertIn("country_missions={", missions["raw"]["text"])
        self.assertIn("mission_slot={", missions["mission_slots"][0]["raw"]["text"])
        for slot in missions["mission_slots"]:
            raw = slot["raw"]
            self.assertGreater(raw["line_end"], raw["line_start"])
            self.assertTrue(raw["text"].rstrip().endswith("}"))
            for root_id in slot["root_ids"]:
                self.assertIn(root_id, raw["text"])
            self.assertEqual(raw["bytes"], len(raw["text"].encode("utf-8")))
            self.assertEqual(
                raw["sha256"],
                hashlib.sha256(raw["text"].encode("utf-8")).hexdigest(),
            )

        completed = result["completed_missions"]
        self.assertTrue(completed["present"])
        self.assertEqual([], completed["values"])
        self.assertEqual([], completed["list"])
        self.assertTrue(result["flags"]["present"])
        self.assertEqual("1455.1.1", result["flags"]["entries"][0]["value"])
        self.assertEqual("yes # not a comment", result["flags"]["entries"][1]["value"])
        self.assertEqual("1455.2.2", result["hidden_flags"]["entries"][0]["value"])

        self.assertEqual("recorded", context["mode"])
        self.assertFalse(context["live"])
        self.assertEqual("1455.11.13", context["game_date"])
        self.assertIsNone(context["game_day"])
        self.assertEqual("saved_calendar_date", context["game_date_kind"])
        self.assertIsNone(context["world_id"])
        self.assertIsNone(context["session_id"])

    def test_absent_completed_missions_is_distinct_from_empty(self) -> None:
        data = FIXTURE.replace(b"  completed_missions={}\n", b"")
        with tempfile.TemporaryDirectory() as temporary:
            result = SavedMissionSnapshot(_write(Path(temporary), data), "FRA").as_dict()
        completed = result["completed_missions"]
        self.assertFalse(completed["present"])
        self.assertEqual([], completed["values"])
        self.assertEqual([], completed["list"])
        self.assertIsNone(completed["raw"])

    def test_nested_same_name_country_is_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = SavedMissionSnapshot(_write(Path(temporary)), "FRA").as_dict()
        roots = [slot["root_ids"] for slot in result["country_missions"]["mission_slots"]]
        self.assertNotIn(["fake_nested_root"], roots)
        self.assertEqual(2, len(roots))

    def test_duplicate_target_country_fails_closed(self) -> None:
        data = b"EU4txt\ncountries={\n FRA={}\n FRA={}\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(_write(Path(temporary), data), "FRA")

    def test_missing_target_country_fails_closed(self) -> None:
        data = b"EU4txt\ncountries={\n SWE={}\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(_write(Path(temporary), data), "FRA")

    def test_expected_hash_and_call_time_mutation_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write(Path(temporary))
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot = SavedMissionSnapshot(path, "FRA", expected)
            first = snapshot.as_dict()
            first["country_missions"]["mission_slots"].clear()
            self.assertEqual(2, len(snapshot.as_dict()["country_missions"]["mission_slots"]))

            path.write_bytes(FIXTURE + b"\n")
            with self.assertRaises(ValueError):
                snapshot.context()

    def test_bad_hash_zip_and_non_eu4txt_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = _write(directory)
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(path, "FRA", "0" * 64)

            zip_path = directory / "save.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("gamestate", FIXTURE)
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(zip_path, "FRA")

            bad_path = _write(directory, b"not an EU4 save\n", "bad.eu4")
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(bad_path, "FRA")

    def test_limits_and_country_validation_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write(Path(temporary))
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(path, "fra")
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(path, "FRA", max_line_bytes=8)
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(path, "FRA", max_target_bytes=12)
            with self.assertRaises(ValueError):
                SavedMissionSnapshot(path, "FRA", max_tokens=8)


if __name__ == "__main__":
    unittest.main()
