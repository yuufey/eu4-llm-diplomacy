from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest

import pytest

from bridge.declarewar_selection import (
    MAX_PARTICIPANTS,
    PARTICIPANT_FIELDS,
    country_csv,
    normalize_participant_selection,
    participant_selection_requested,
    validate_participant_selection,
)


def test_native_preview_and_execution_resolve_self_beneficiary(tmp_path):
    compiler = shutil.which("g++")
    if not compiler:
        pytest.skip("native Declare War fixture requires g++")
    directory = Path(__file__).resolve().parents[2] / "work" / "native"
    candidates = (directory / "declarewar-candidates.inc").read_text(encoding="utf-8")
    selection = candidates[candidates.index("struct DeclareWarCandidateSelection"):
                           candidates.index("struct DeclareWarCandidateNativeVector")]
    matching = candidates[candidates.index("enum class DeclareWarCandidateMatch"):
                          candidates.index("static bool declarewar_candidates_cleanup_vector")]
    for name in ("declarewar-query.inc", "declarewar-execution-preflight.inc"):
        assert "declarewar_candidates_resolve_beneficiary(" in (
            directory / name).read_text(encoding="utf-8")
    source, binary = tmp_path / "beneficiary.cpp", tmp_path / "beneficiary.exe"
    source.write_text(r'''
#include <cassert>
#include <cstdint>
#include <cstring>

static bool alliance_query_country(const char* tag,uint64_t& handle) {
    if (strcmp(tag,"BOS")) return false;
    handle=2;
    return true;
}
''' + selection + r'''
struct DeclareWarCandidateCapture {
    uintptr_t address=0;
    int candidate_index=0;
    int target_province_id=151;
    uint64_t beneficiary_handle=0;
    bool casus_belli_key_verified=true, target_province_id_verified=true;
    bool beneficiary_identifier_verified=true;
    const char* casus_belli_key="cb_conquest";
};
struct DeclareWarCandidateQueryResult {
    DeclareWarCandidateCapture items[3]{};
    unsigned captured_count=0, selection_match_count=0;
    uint64_t selected_beneficiary_handle=0;
    int32_t selected_candidate_index=-1;
};
''' + matching + r'''
int main() {
    DeclareWarCandidateSelection self{"cb_conquest",151};
    assert(declarewar_candidates_resolve_beneficiary(self,"TUR","TUR",1,false));
    DeclareWarCandidateQueryResult only_sentinel{};
    only_sentinel.captured_count=1;
    only_sentinel.items[0].address=10;
    assert(declarewar_candidates_select(self,only_sentinel)==10);
    assert(only_sentinel.selection_match_count==1 && !only_sentinel.selected_beneficiary_handle);

    DeclareWarCandidateQueryResult both{};
    both.captured_count=2;
    both.items[0].address=10;
    both.items[1].address=11;
    both.items[1].beneficiary_handle=1;
    assert(declarewar_candidates_select(self,both)==11);
    assert(both.selection_match_count==1 && both.selected_beneficiary_handle==1);

    DeclareWarCandidateQueryResult ambiguous=both;
    ambiguous.captured_count=3;
    ambiguous.items[2]=ambiguous.items[1];
    ambiguous.items[2].address=12;
    assert(declarewar_candidates_select(self,ambiguous)==0 && ambiguous.selection_match_count==2);

    DeclareWarCandidateSelection subject{"cb_conquest",151};
    assert(declarewar_candidates_resolve_beneficiary(subject,"BOS","TUR",1,false));
    assert(declarewar_candidates_selection_match(subject,only_sentinel.items[0])
        ==DeclareWarCandidateMatch::none);
    auto subject_candidate=only_sentinel.items[0];
    subject_candidate.beneficiary_handle=2;
    assert(declarewar_candidates_selection_match(subject,subject_candidate)
        ==DeclareWarCandidateMatch::exact);
    subject_candidate.beneficiary_identifier_verified=false;
    assert(declarewar_candidates_selection_match(subject,subject_candidate)
        ==DeclareWarCandidateMatch::none);

    DeclareWarCandidateSelection explicit_sentinel{"cb_conquest",151};
    assert(declarewar_candidates_resolve_beneficiary(explicit_sentinel,"---","TUR",1,false));
    assert(declarewar_candidates_select(explicit_sentinel,both)==10);
    DeclareWarCandidateSelection no_cb{"no_casus_belli",-1};
    assert(declarewar_candidates_resolve_beneficiary(no_cb,"TUR","TUR",1,true));
    assert(!no_cb.beneficiary_handle && !no_cb.allow_self_sentinel);
}
''', encoding="utf-8")
    built = subprocess.run([compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(binary)],
                           capture_output=True, text=True, timeout=45)
    assert built.returncode == 0, built.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stderr


class DeclareWarSelectionTests(unittest.TestCase):
    def test_missing_fields_default_and_valid_lists_are_sorted(self):
        self.assertEqual(
            normalize_participant_selection({}),
            {"call_allies": [], "promise_land_to": [],
             "co_belligerents": []},
        )
        parameters = {
            "casus_belli": "cb_conquest",
            "call_allies": ["ZZZ", "ENG", "SWE"],
            "promise_land_to": ["SWE", "ENG"],
            "co_belligerents": ["AUV", "POR"],
        }
        self.assertEqual(
            normalize_participant_selection(parameters, actor="FRA",
                                            recipient="GEN"),
            {"call_allies": ["ENG", "SWE", "ZZZ"],
             "promise_land_to": ["ENG", "SWE"],
             "co_belligerents": ["AUV", "POR"]},
        )
        self.assertEqual(
            validate_participant_selection(parameters, actor="FRA",
                                           recipient="GEN"),
            normalize_participant_selection(parameters, actor="FRA",
                                            recipient="GEN"),
        )

    def test_promise_is_subset_and_co_belligerents_are_disjoint(self):
        with self.assertRaisesRegex(
                ValueError, "DECLARE_WAR_PROMISE_LAND_TO_NOT_CALL_ALLY"):
            normalize_participant_selection({
                "call_allies": ["ENG"],
                "promise_land_to": ["SWE"],
            }, recipient="POR")
        with self.assertRaisesRegex(
                ValueError, "DECLARE_WAR_CO_BELLIGERENT_OVERLAP"):
            normalize_participant_selection({
                "call_allies": ["ENG"],
                "promise_land_to": ["ENG"],
                "co_belligerents": ["ENG"],
            }, recipient="POR")

    def test_each_field_has_type_tag_duplicate_and_bound_checks(self):
        for field in PARTICIPANT_FIELDS:
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_INVALID"):
                normalize_participant_selection({field: "ENG"}, recipient="POR")
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_TAG_INVALID"):
                normalize_participant_selection({field: ["eng"]}, recipient="POR")
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_DUPLICATE"):
                normalize_participant_selection({field: ["ENG", "ENG"]},
                                                recipient="POR")
            tags = [f"A{index:02d}" for index in range(MAX_PARTICIPANTS + 1)]
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_TOO_MANY"):
                normalize_participant_selection({field: tags}, recipient="POR")

    def test_actor_and_recipient_cannot_be_selected_participants(self):
        for field in PARTICIPANT_FIELDS:
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_MAIN_PARTY"):
                normalize_participant_selection({field: ["FRA"]},
                                                actor="FRA", recipient="POR")
            with self.assertRaisesRegex(
                    ValueError, f"DECLARE_WAR_{field.upper()}_MAIN_PARTY"):
                normalize_participant_selection({field: ["POR"]},
                                                actor="FRA", recipient="POR")
        with self.assertRaisesRegex(ValueError, "DECLARE_WAR_ACTOR_INVALID"):
            normalize_participant_selection({}, actor="fra")
        with self.assertRaisesRegex(ValueError, "DECLARE_WAR_RECIPIENT_INVALID"):
            normalize_participant_selection({}, recipient="eng")

    def test_csv_serialization_and_requested_marker(self):
        self.assertEqual("-", country_csv([]))
        self.assertEqual("ENG,SWE,ZZZ", country_csv(["ZZZ", "ENG", "SWE"]))
        with self.assertRaisesRegex(ValueError,
                                    "DECLARE_WAR_PARTICIPANTS_DUPLICATE"):
            country_csv(["ENG", "ENG"])
        self.assertFalse(participant_selection_requested({}))
        self.assertFalse(participant_selection_requested({
            "call_allies": [], "promise_land_to": [],
            "co_belligerents": [],
        }))
        self.assertTrue(participant_selection_requested({"promise_land_to": ["ENG"]}))
        self.assertTrue(participant_selection_requested({"co_belligerents": ["SWE"]}))
        with self.assertRaisesRegex(ValueError,
                                    "DECLARE_WAR_PARTICIPANT_SELECTION_INVALID"):
            participant_selection_requested(None)
        with self.assertRaisesRegex(ValueError, "DECLARE_WAR_CALL_ALLIES_INVALID"):
            participant_selection_requested({"call_allies": "ENG"})


if __name__ == "__main__":
    unittest.main()
