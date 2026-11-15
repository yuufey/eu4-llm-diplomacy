"""Validation and projection tests for bounded counted mission predicates."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import mission_trigger_memory as trigger
from bridge.information import mission_trigger_source as source
from bridge.information.mission_trigger_source import normalize_triggers, project_progress
from bridge.tests.test_information_mission_trigger_source import (
    _address,
    _group,
    _leaf,
    _prerequisites,
    _report,
    _task,
)


OWNED_TOKEN = 0x2BF9
SUBJECTS_TOKEN = 0x37FC


def _stored_leaf(value):
    return _leaf(value, token=0x2E20,
                 method=trigger.STORED_BOOLEAN_EVALUATE_RVA)


def _filter(value):
    return _group("and", [_stored_leaf(value)], token=OWNED_TOKEN,
                   method=trigger.COUNT_EVALUATE_RVA)


def _count_value(lower_bound, upper_bound, threshold):
    if lower_bound > 0 and lower_bound >= threshold:
        return True
    if upper_bound == 0 or upper_bound < threshold:
        return False
    return None


def _count_node(filter_tree, *, threshold, domain_count, lower_bound, upper_bound,
                samples=None, fully_evaluated=None, token=OWNED_TOKEN,
                mode="owned", value=...):
    samples = [] if samples is None else deepcopy(samples)
    sampled_count = len(samples)
    if fully_evaluated is None:
        fully_evaluated = sampled_count == domain_count
    if value is ...:
        value = _count_value(lower_bound, upper_bound, threshold)
    evaluation = {"status": "unknown" if value is None else "known",
                  "satisfied": value}
    return {
        "kind": "count",
        "token": token,
        "method_rva": trigger.COUNT_EVALUATE_RVA,
        "native_pointer": _address(),
        "scope": {"kind": "owned_provinces", "country": "FRA", "mode": mode},
        "metric": {
            "threshold": threshold,
            "domain_count": domain_count,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "sampled_count": sampled_count,
            "fully_evaluated": fully_evaluated,
        },
        "filter": deepcopy(filter_tree),
        "samples": samples,
        "evaluation": evaluation,
    }


def _normalize_tree(tree):
    rows = [_task("task_a", _group("and", [tree]))]
    return normalize_triggers(_report(rows), _prerequisites("task_a"))


def _valid_count_tree(node):
    return source._validate_tree(node, depth=0, counter=[0])


@pytest.mark.parametrize(
    "filter_value,threshold,lower,upper,expected",
    [(True, 4, 5, 5, True), (False, 0, 0, 0, False)],
)
def test_known_count_filter_short_circuits_bounds_and_samples(
        filter_value, threshold, lower, upper, expected):
    node = _count_node(
        _filter(filter_value), threshold=threshold, domain_count=5,
        lower_bound=lower, upper_bound=upper, samples=[], fully_evaluated=True,
        value=expected,
    )

    normalized = _normalize_tree(node)

    assert normalized["status"] == "known"
    accepted = normalized["tasks"][0]["tree"]["children"][0]
    assert accepted["evaluation"] == {"status": "known", "satisfied": expected}
    assert accepted["metric"]["sampled_count"] == 0
    assert accepted["metric"]["fully_evaluated"] is True
    assert accepted["samples"] == []


def test_unknown_count_filter_recomputes_bounds_from_true_false_and_unknown_samples():
    samples = [
        {"province_id": 17, "evaluation": {"status": "known", "satisfied": True}},
        {"province_id": 18, "evaluation": {"status": "known", "satisfied": False}},
        {"province_id": None, "evaluation": {
            "status": "unknown", "satisfied": None, "reason": "member_not_admitted",
        }},
    ]
    node = _count_node(
        _filter(None), threshold=2, domain_count=4,
        lower_bound=1, upper_bound=3, samples=samples, fully_evaluated=False,
        value=None,
    )

    normalized = _normalize_tree(node)

    assert normalized["status"] == "known"
    accepted = normalized["tasks"][0]["tree"]["children"][0]
    assert accepted["metric"]["lower_bound"] == 1
    assert accepted["metric"]["upper_bound"] == 3
    assert accepted["evaluation"] == {"status": "unknown", "satisfied": None}
    assert accepted["samples"][2]["province_id"] is None


@pytest.mark.parametrize(
    "samples,threshold,lower,upper,expected",
    [
        ([True, True, None], 2, 2, 4, True),
        ([False, False, False], 2, 0, 1, False),
        ([False, False, False, False], 0, 0, 0, False),
    ],
)
def test_count_result_uses_guaranteed_lower_and_upper_bounds(
        samples, threshold, lower, upper, expected):
    sample_rows = [
        {"province_id": index + 1 if value is not None else None,
         "evaluation": {"status": "unknown" if value is None else "known",
                        "satisfied": value}}
        for index, value in enumerate(samples)
    ]
    node = _count_node(
        _filter(None), threshold=threshold, domain_count=4,
        lower_bound=lower, upper_bound=upper, samples=sample_rows,
        fully_evaluated=len(samples) == 4, value=expected,
    )

    normalized = _normalize_tree(node)

    assert normalized["status"] == "known"
    assert normalized["tasks"][0]["tree"]["children"][0]["evaluation"] == {
        "status": "known", "satisfied": expected,
    }


def test_count_rejects_wrong_mode_token_and_forged_bounds():
    valid = _count_node(
        _filter(None), threshold=2, domain_count=4,
        lower_bound=1, upper_bound=3,
        samples=[{"province_id": 17,
                  "evaluation": {"status": "known", "satisfied": True}}],
        fully_evaluated=False, value=None,
    )
    invalid = []

    wrong_mode = deepcopy(valid)
    wrong_mode["token"] = SUBJECTS_TOKEN
    invalid.append(wrong_mode)

    wrong_token = deepcopy(valid)
    wrong_token["scope"]["mode"] = "non_sovereign_subjects"
    invalid.append(wrong_token)

    forged_bounds = deepcopy(valid)
    forged_bounds["metric"]["lower_bound"] = 2
    invalid.append(forged_bounds)

    known_filter_with_sample = _count_node(
        _filter(True), threshold=1, domain_count=4,
        lower_bound=4, upper_bound=4,
        samples=[{"province_id": 17,
                  "evaluation": {"status": "known", "satisfied": True}}],
        fully_evaluated=False, value=True,
    )
    invalid.append(known_filter_with_sample)

    for node in invalid:
        assert not _valid_count_tree(node)


def test_count_is_fra_country_scoped_and_filter_method_cannot_leak():
    node = _count_node(
        _filter(True), threshold=1, domain_count=2,
        lower_bound=2, upper_bound=2, fully_evaluated=True, value=True,
    )
    assert not source._validate_tree(
        node, depth=0, counter=[0], country_scope="ENG",
    )
    assert not source._validate_tree(
        node, depth=0, counter=[0], province_scope=True,
    )

    leaked_filter = _group("and", [_stored_leaf(True)],
                           method=trigger.COUNT_EVALUATE_RVA)
    leaked_root = _group("and", [leaked_filter])
    assert not source._validate_tree(leaked_root, depth=0, counter=[0], is_root=True)


def test_stored_boolean_is_an_ordinary_leaf_outside_count_nodes():
    normalized = _normalize_tree(_stored_leaf(True))

    assert normalized["status"] == "known"
    tree = normalized["tasks"][0]["tree"]
    assert tree["children"][0]["method_rva"] == trigger.STORED_BOOLEAN_EVALUATE_RVA
    assert tree["children"][0]["evaluation"]["satisfied"] is True


def test_public_projection_recurses_filter_strips_native_fields_and_counts_one_predicate():
    samples = [
        {"province_id": 17, "evaluation": {"status": "known", "satisfied": True}},
        {"province_id": None, "evaluation": {
            "status": "unknown", "satisfied": None, "reason": "member_not_admitted",
        }},
    ]
    node = _count_node(
        _filter(None), threshold=2, domain_count=3,
        lower_bound=1, upper_bound=3, samples=samples,
        fully_evaluated=False, value=None,
    )
    normalized = _normalize_tree(node)
    entries = _prerequisites("task_a")["tasks"]

    projected = project_progress({"mission_triggers": normalized}, entries, "1.37.4")

    assert projected["status"] == "known"
    value = projected["value"]
    assert (value["evaluated_leaf_count"], value["satisfied_leaf_count"],
            value["unsatisfied_leaf_count"], value["unknown_leaf_count"]) == (0, 0, 0, 1)
    public_count = value["tasks"][0]["trigger"]["children"][0]
    assert public_count["filter"]["kind"] == "and"
    assert public_count["filter"]["children"][0]["kind"] == "leaf"
    assert public_count["samples"][1]["province_id"] is None
    encoded = json.dumps(value)
    assert "native_pointer" not in encoded and "method_rva" not in encoded
    assert _all_keys(value).isdisjoint({"native_pointer", "method_rva"})


def _all_keys(value):
    if isinstance(value, dict):
        return set(value) | set().union(*(_all_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(child) for child in value)) if value else set()
    return set()
