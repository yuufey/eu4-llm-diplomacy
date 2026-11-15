"""Identity-bound, two-pass current coalition capture using shared RPM."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import coalition_memory as _leaf
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner


PROFILE_FILE = Path(__file__).with_name("profiles") / "coalitions-memory-1374.json"
PROFILE_SHA256 = "4e9f65793cd173abe31bf8b9adf434bc3096dd3dc0d6680a8d43c7234d3f1fe7"
SCHEMA = "information.coalition_capture.v1"


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 16384:
        raise ValueError("COALITION_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("COALITION_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "coalitions-memory-1374"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256):
        raise ValueError("COALITION_PROFILE_BUILD")
    parent = _owner._load_profile()
    profile["code_guards"] = deepcopy(parent["code_guards"]) + profile["code_guards"]
    return profile


def _observe(reader, base, country, profile):
    current = {}

    def admission(read, module_base, scan, observer, target):
        gate = _owner._bound_admission(read, module_base, scan, observer, target)
        current.update(scan=scan, gate=gate, target=target)
        return gate

    def fields(limited, module_base, binding, requested):
        scan = current["scan"]

        def admit(member):
            tag = member["tag"]
            if tag in ("FRA", current["target"]):
                return current["gate"].get("admitted") is True
            selected = dict(scan, requested={**scan["requested"], tag: member})
            gate = _owner._bound_admission(limited.read, module_base, selected, "FRA", tag)
            return gate.get("status") == "known" and gate.get("admitted") is True

        return _leaf.read_fields(limited, module_base, binding, requested,
                                 country_scan=scan, admit_country=admit)

    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, "FRA", [target], _leaf.FIELDS,
                                      read_fields=fields, admission_reader=admission)

    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation, country, *, observer="FRA"):
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, allow_observer_target=True)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, allow_observer_target=True, require_access=True)
