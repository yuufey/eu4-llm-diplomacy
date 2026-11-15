"""Identity-bound current bilateral war-reparations capture."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import foreign_country_memory as _backend
from . import foreign_economy_capture_v7 as _economy
from . import foreign_technology_capture as _owner
from . import reparations_commitments as _leaf


SCHEMA = "information.reparations_commitments_capture.v1"
PROFILE_FILE = Path(__file__).with_name("profiles") / "reparations-commitments-memory-1374.json"
PROFILE_SHA256 = "3c9fb5e412a55a79c6e19951ed17fa623ff3f052301197d1affa10091481431d"
FIELDS = _leaf.FIELDS


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 16384:
        raise ValueError("REPARATIONS_COMMITMENTS_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("REPARATIONS_COMMITMENTS_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "reparations-commitments-memory-1374"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256):
        raise ValueError("REPARATIONS_COMMITMENTS_PROFILE_BUILD")
    admission = _owner._load_profile()["code_guards"]
    reparations = [guard for guard in _economy._load_profile()["code_guards"]
                   if guard["name"].startswith("observer_reparations_")]
    if not reparations:
        raise ValueError("REPARATIONS_COMMITMENTS_RELATION_GUARDS_MISSING")
    profile["code_guards"] = deepcopy(admission + reparations) + profile["code_guards"]
    return profile


def _observe(reader, base, country, profile):
    current = {}

    def admission(read, module_base, scan, observer, target):
        current["observer"] = scan["requested"][observer]
        return _owner._bound_admission(read, module_base, scan, observer, target)

    def fields(limited, module_base, binding, requested):
        world = int.from_bytes(limited.read(module_base + 0x233FE58, 8,
                                            "reparations_commitments.world"), "little")
        now = int.from_bytes(limited.read(world + 0x1DD0, 4,
                                          "reparations_commitments.current_date"), "little", signed=True)
        return _leaf.read_fields(limited, module_base, current["observer"], binding,
                                 requested, observed_date=now)

    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, "FRA", [target], FIELDS,
                                      read_fields=fields, admission_reader=admission)

    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation, country, *, observer="FRA"):
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, require_access=True)


def project_fields(report):
    """Copy business fields after the caller validates this capture."""
    raw = report["observation"]["backend"]["targets"][0]["fields"]
    return {name.removeprefix("R07."): deepcopy(raw[name]) for name in FIELDS}
