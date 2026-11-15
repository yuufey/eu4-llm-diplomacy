"""Synthetic adapter tests; these fixtures do not establish native replay."""
from copy import deepcopy

import pytest

from bridge.information import foreign_quality_projection as projection
from bridge.information import foreign_technology as source_module
from bridge.tests import test_information_foreign_forces as fixtures


def quality_report():
    values = {"army": {}, "navy": {}}
    for (group, key), (unit, scale, bits) in projection.NUMBERS.items():
        number = 1000 if bits == 32 else 3276
        values[group][key] = {"status": "known", "value": number / scale if bits == 64 else number,
            "raw": str(number) if bits == 64 else number, "unit": unit, "scale": scale,
            "raw_inputs": {"private_pointer": "0xprivate-quality"}}
    for key in projection.MODELS:
        values["navy"][key] = {"status": "known", "value": {
            "localization_key": "early_carrack", "name": {"status": "known",
                "raw_hex": b"Early Carrack".hex(), "language": "l_english"}},
            "raw": "early_carrack", "unit": "ship_model", "scale": 1}
    report = fixtures.manpower_report()
    item = report["observation"]["backend"]["targets"][0]
    item["fields"] = {
        projection.FIELD: {"status": "known", "value": values,
            "basis": projection.BASIS, "unit": "native_military_quality_components",
            "scale": 1, "partial": True, "complete": False,
            "raw_inputs": {"private_pointer": "0xprivate-quality"}},
        projection.VISIBILITY_FIELD: {"status": "known", "value": {
            "admitted": True, "mode": "projected_quality_ledger_gate"}},
    }
    item["field_consistency"] = {projection.FIELD: {"status": "stable"}}
    return report


def setup(tmp_path, monkeypatch, report=None):
    source, base, calls, modules = fixtures.setup_source(tmp_path, monkeypatch)
    original_import = source_module.import_module
    module = fixtures.FakeCaptureModule(report or quality_report(), base.context(),
                                       base.session.creation_filetime)
    modules["quality"] = module

    def capture(installation, *, country, observer):
        calls.append(("quality", installation, country, observer))
        return module.capture(installation, country=country, observer=observer)

    source.quality_capture = capture
    monkeypatch.setattr(source_module, "import_module", lambda name, package:
        module if name == ".foreign_quality_capture" else original_import(name, package))
    return source, base, calls, modules


def field(report):
    return report["observation"]["backend"]["targets"][0]["fields"][projection.FIELD]


def test_quality_and_visibility_use_one_capture_and_strip_private_inputs(tmp_path, monkeypatch):
    source, base, calls, _ = setup(tmp_path, monkeypatch)
    result = source.read(fixtures.query(["military_quality", "visibility"]), base.context())
    assert [call[0] for call in calls] == ["quality"]
    quality = result["fields"]["military_quality"]
    assert quality["status"] == "known" and quality["known_component_count"] == 12
    assert quality["value"]["army"]["professionalism"]["raw"] == "3276"
    assert quality["value"]["navy"]["heavy_ship_model"]["value"]["name"]["text"] == "Early Carrack"
    assert "private" not in repr(result) and "raw_inputs" not in repr(result)
    admission = result["fields"]["visibility"]["value"]["military_quality"]
    assert admission["quality_page_permission"]["admitted"] is True
    assert admission["effective_admitted"]["value"] is True
    assert set(result["source"]["provenance"]["capture_report_sha256_by_source"]) == {"quality"}


def test_all_fields_keep_four_sources_and_independent_quality_gate(tmp_path, monkeypatch):
    source, base, calls, modules = setup(tmp_path, monkeypatch)
    modules["forces"].report = fixtures.force_report(stats_admitted=False)
    result = source.read(fixtures.query(["military_technology", "manpower", "visible_army",
        "visible_navy", "military_quality", "visibility"]), base.context())
    assert [call[0] for call in calls] == ["technology", "manpower", "forces", "quality"]
    assert result["fields"]["military_quality"]["status"] == "known"
    assert result["fields"]["visible_army"]["status"] == "invisible"
    assert set(result["source"]["provenance"]["capture_report_sha256_by_source"]) == set(modules)


@pytest.mark.parametrize("denial", ["country", "quality", "unknown", "invalid"])
def test_quality_gate_failures_do_not_expose_values(tmp_path, monkeypatch, denial):
    report = quality_report()
    item = report["observation"]["backend"]["targets"][0]
    expected = "unknown"
    if denial == "country":
        item["admission_by_pass"] = fixtures._admission(False)
        expected = "invisible"
    elif denial == "quality":
        item["fields"][projection.VISIBILITY_FIELD]["value"] = {"admitted": False, "mode": "denied"}
        expected = "invisible"
    elif denial == "unknown":
        item["fields"][projection.VISIBILITY_FIELD] = {"status": "unknown", "reason": "NO_GATE"}
    else:
        report["valid"] = False
    source, base, _, _ = setup(tmp_path, monkeypatch, report)
    result = source.read(fixtures.query(["military_quality"]), base.context())["fields"]["military_quality"]
    assert result["status"] == expected and "value" not in result


def test_bad_component_and_dynamic_name_keep_other_components(tmp_path, monkeypatch):
    report = quality_report()
    field(report)["value"]["army"]["morale"]["raw"] = True
    field(report)["value"]["navy"]["heavy_ship_model"]["value"]["name"]["raw_hex"] = b"$COUNTRY$".hex()
    source, base, _, _ = setup(tmp_path, monkeypatch, report)
    result = source.read(fixtures.query(["military_quality"]), base.context())["fields"]["military_quality"]
    assert result["value"]["army"]["morale"]["status"] == "unknown"
    assert result["value"]["army"]["discipline"]["status"] == "known"
    model = result["value"]["navy"]["heavy_ship_model"]
    assert model["value"]["localization_key"] == "early_carrack"
    assert model["value"]["name"]["status"] == "unknown"


def test_unprovided_quality_override_cannot_fall_through_to_live(tmp_path, monkeypatch):
    source, base, calls, _ = setup(tmp_path, monkeypatch)
    source.quality_capture = None
    result = source.read(fixtures.query(["military_quality"]), base.context())
    assert calls == []
    assert result["fields"]["military_quality"]["reason"] == "FOREIGN_QUALITY_CAPTURE_OVERRIDE_NOT_PROVIDED"


def test_i64_professionalism_preserves_exact_raw_decimal(tmp_path, monkeypatch):
    report = quality_report()
    component = field(report)["value"]["army"]["professionalism"]
    raw = (1 << 63) - 1
    component.update(raw=str(raw), value=raw / 32768)
    source, base, _, _ = setup(tmp_path, monkeypatch, report)
    result = source.read(fixtures.query(["military_quality"]), base.context())
    assert result["fields"]["military_quality"]["value"]["army"]["professionalism"]["raw"] == str(raw)


def test_real_permission_and_numeric_leaf_feed_public_projection(monkeypatch):
    from bridge.information import foreign_quality_capture as capture
    from bridge.information import military_effective_memory as discipline
    from bridge.tests import test_foreign_quality_memory as raw_fixture
    image, _, target, permission = raw_fixture._environment(cache_state=2)
    raw_fixture._set_dense(image)
    monkeypatch.setattr(discipline, "read_fields", lambda *_a, **_k:
                        {"status": "unknown", "reason": "fixture_not_mapped"})
    private = raw_fixture._run(image, target, permission)
    item = {"fields": {projection.FIELD: private,
                       projection.VISIBILITY_FIELD: capture._permission_field(permission)},
            "field_consistency": {projection.FIELD: {"status": "stable"}}}
    view = {"status": "known", "admitted": True}
    result = projection.project(item, view, projection.permission(item, view))
    assert result["known_component_count"] == 8
    assert result["value"]["army"]["morale"]["value"] == 1.011
    assert result["value"]["navy"]["morale"]["value"] == 0.75
    assert result["value"]["army"]["tradition"]["value"] == 25.125
    assert result["value"]["army"]["siege_ability"]["value"] == 0.225
    assert result["value"]["army"]["defensiveness"]["value"] == -0.07
