"""Own read-only F03 observations for nonplayer FRA with separate page scopes."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_country_memory as _backend
from . import foreign_economy_visibility_memory as _visibility
from . import foreign_income_memory as _income
from . import foreign_loans_memory as _loans
from . import observer_reparations_memory as _reparations
from . import observer_subsidies_memory as _subsidies
from . import target_debt_principal_memory as _principal
from . import foreign_technology_capture as _owner

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "foreign-economy-memory-1374-v6.json"
PROFILE_SHA256 = "3fbb65eadc9301765896bdde35d84e19f9e93e4b28f54a9820b30d5c2f213626"
PROFILE_ID = "foreign-economy-memory-1374"
SCHEMA = "information.foreign_economy_capture.v4"
EXE_SHA256 = _owner.EXE_SHA256
OBSERVER = "FRA"
PUBLIC_FIELDS = tuple("F03." + key for key in ("income", "debt", "bankruptcy_risk", "reparations", "subsidies"))
VISIBILITY_FIELD = "F03.economy_visibility"
REPARATIONS_FIELD = _reparations.FIELD
SUBSIDIES_FIELD = _subsidies.FIELD
DEBT_TOTAL_FIELD = _principal.FIELD
FIELDS = (*PUBLIC_FIELDS, VISIBILITY_FIELD, REPARATIONS_FIELD, SUBSIDIES_FIELD, DEBT_TOTAL_FIELD)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    if not 0 < PROFILE_FILE.stat().st_size <= 128 * 1024:
        raise ValueError("FOREIGN_ECONOMY_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("FOREIGN_ECONOMY_PROFILE_PIN")
    profile = json.loads(raw)
    reparations_profile = profile.get("observer_reparations", {})
    subsidies_profile = profile.get("observer_subsidies", {})
    principal_profile = profile.get("target_debt_principal", {})
    if (profile.get("profile_id") != PROFILE_ID or profile.get("profile_version") != 6
            or profile.get("semantics", {}).get("capture_schema") != SCHEMA
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256
            or profile.get("public_fields") != list(PUBLIC_FIELDS) or not profile.get("code_guards")
            or not isinstance(reparations_profile, Mapping)
            or reparations_profile.get("private_field") != REPARATIONS_FIELD
            or reparations_profile.get("scope") != _reparations.SCOPE
            or not isinstance(subsidies_profile, Mapping)
            or subsidies_profile.get("private_field") != SUBSIDIES_FIELD
            or subsidies_profile.get("scope") != _subsidies.SCOPE
            or not isinstance(principal_profile, Mapping)
            or principal_profile.get("private_field") != DEBT_TOTAL_FIELD
            or principal_profile.get("scope") != _principal.SCOPE):
        raise ValueError("FOREIGN_ECONOMY_PROFILE_CONTRACT")
    # These revisions add opt-in observer binding. The v6 replay still uses
    # the original FRA path and original evidence/guard profiles.
    reviewed_live_sources = {
        "bridge/information/bilateral_reparations_memory.py": (22458, "ad55d9c865d598d6c58efcf80d5563999dc205ae12158d4fa27f09ac56df44f2"),
        "bridge/information/observer_reparations_memory.py": (22469, "47d0350ab3aa3970512312ed8b2c647600e4441913e60de3ff941f5b699f6aa3"),
        "bridge/information/bilateral_subsidies_memory.py": (28799, "6ab7a540b93c05f9d05c15181ab237966e1d7f146a6d7349065b3151b69bc758"),
        "bridge/information/observer_subsidies_memory.py": (21864, "a93e35daa32ba437dea525e9e5473c37a10b964721a5800fd618d9cfd0ee282b"),
    }
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        actual = (path.stat().st_size, _sha(path))
        if actual != (item["bytes"], item["sha256"]) and actual != reviewed_live_sources.get(item["path"]):
            raise ValueError("FOREIGN_ECONOMY_PROFILE_DEPENDENCY")
    return profile


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "partial": True, "complete": False}


def _permission_field(permissions: dict[str, Any]) -> dict[str, Any]:
    values = {}
    for page, record in permissions.items():
        if _visibility.validate_permission(record, page=page):
            values[page] = {"status": "known", "admitted": record["admitted"], "mode": record["mode"]}
        else:
            values[page] = {"status": "unknown", "reason": "ECONOMY_PAGE_PERMISSION_UNKNOWN"}
    return {"status": "known", "value": values, "partial": True, "complete": False,
            "basis": _visibility.BASIS, "raw_inputs": {"permissions": deepcopy(permissions)}}


def _read_backend(reader: Any, base: int, country: str, profile: Mapping[str, Any]) -> dict[str, Any]:
    scans = {}

    def admission(read, module_base, scan, observer, target):
        scans[target] = scan
        gate = _owner._bound_admission(read, module_base, scan, observer, target)
        role = gate.get("observer_nonplayer_role") if isinstance(gate, Mapping) else None
        if not isinstance(role, Mapping) or role.get("verified") is not True:
            gate = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            gate.update(status="unknown", admitted=None, reason="OBSERVER_NONPLAYER_ROLE_UNVERIFIED")
        return gate

    def fields(read, module_base, target_binding, requested):
        scan = scans.get(country)
        observer = scan.get("requested", {}).get(OBSERVER) if isinstance(scan, Mapping) else None
        permissions = {}
        if isinstance(observer, Mapping):
            permissions = {page: _visibility.read_permission(read, module_base, observer, target_binding, page=page)
                           for page in _visibility.PAGES}
            reparations_permission = _reparations.read_permission(
                read, module_base, observer, target_binding)
            subsidies_permission = _subsidies.read_permission(
                read, module_base, observer, target_binding)
            principal_permission = _principal.read_permission(
                read, module_base, observer, target_binding)
        else:
            reparations_permission = None
            subsidies_permission = None
            principal_permission = None
        result = {}
        result.update(_income.read_fields(read, module_base, target_binding, requested,
                                         permission=permissions.get(_visibility.INCOME_PAGE)))
        result.update(_loans.read_fields(read, module_base, observer, target_binding, requested,
                                        permission=permissions.get(_visibility.LOANS_PAGE)))
        if REPARATIONS_FIELD in requested:
            result.update(_reparations.read_fields(
                read, module_base, observer, target_binding, requested,
                permission=reparations_permission))
        if SUBSIDIES_FIELD in requested:
            result.update(_subsidies.read_fields(
                read, module_base, observer, target_binding, requested,
                permission=subsidies_permission))
        if DEBT_TOTAL_FIELD in requested:
            result.update(_principal.read_fields(
                read, module_base, observer, target_binding, requested,
                permission=principal_permission))
        if "F03.bankruptcy_risk" in requested:
            result["F03.bankruptcy_risk"] = _unknown("NATIVE_BANKRUPTCY_RISK_AND_FOREIGN_VISIBILITY_NOT_ESTABLISHED")
        if VISIBILITY_FIELD in requested:
            result[VISIBILITY_FIELD] = _permission_field(permissions)
        return result

    return _backend.read_two_pass(reader, base, OBSERVER, [country], FIELDS,
                                  read_fields=fields, admission_reader=admission)


def _observe(reader, base, country, profile):
    guarded_profile = {**profile, "code_guards": [*profile["code_guards"],
                                                 *profile.get("data_guards", [])]}
    observation = _owner._observe(reader, base, country, guarded_profile,
        backend_reader=lambda read, module_base, target: _read_backend(read, module_base, target, profile))
    # Each private pair permission binds a fresh signed game date.  A mismatch
    # withdraws that child independently of the income cache or the other pair.
    context = observation.get("context_before") if isinstance(observation, Mapping) else None
    expected_date = context.get("game_date") if isinstance(context, Mapping) else None
    backend = observation.get("backend") if isinstance(observation, Mapping) else None
    targets = backend.get("targets") if isinstance(backend, Mapping) else None
    if type(expected_date) is int and isinstance(targets, list):
        for target in targets:
            if not isinstance(target, dict):
                continue
            fields = target.get("fields")
            for field, adapter, reason in (
                (REPARATIONS_FIELD, _reparations, "OBSERVER_REPARATIONS_CAPTURE_CONTEXT_DATE_MISMATCH"),
                (SUBSIDIES_FIELD, _subsidies, "OBSERVER_SUBSIDIES_CAPTURE_CONTEXT_DATE_MISMATCH"),
                (DEBT_TOTAL_FIELD, _principal, "TARGET_DEBT_CAPTURE_CONTEXT_DATE_MISMATCH"),
            ):
                record = fields.get(field) if isinstance(fields, Mapping) else None
                if not isinstance(record, Mapping) or record.get("status") != "known":
                    continue
                raw_inputs = record.get("raw_inputs")
                permission = raw_inputs.get("permission") if isinstance(raw_inputs, Mapping) else None
                permission_raw = permission.get("raw_inputs") if isinstance(permission, Mapping) else None
                world = permission_raw.get("world") if isinstance(permission_raw, Mapping) else None
                date_raw = world.get("date_raw_i32") if isinstance(world, Mapping) else None
                if (not adapter.validate_permission(permission)
                        or type(date_raw) is not int or date_raw != expected_date):
                    retracted = deepcopy(dict(record))
                    retracted.pop("value", None)
                    retracted.update(status="unknown", reason=reason, partial=True, complete=False)
                    fields[field] = retracted
                    consistency = target.get("field_consistency")
                    if isinstance(consistency, dict):
                        consistency[field] = {"status": "unknown", "reason": reason}
    return observation


def capture(installation: Path, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe)


def validate_capture(report: Any, context: Mapping[str, Any], creation: int, country: str) -> bool:
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe, require_access=True)


__all__ = ["capture", "validate_capture", "SCHEMA", "PROFILE_FILE", "PROFILE_SHA256",
           "PROFILE_ID", "PUBLIC_FIELDS", "VISIBILITY_FIELD", "REPARATIONS_FIELD", "SUBSIDIES_FIELD",
           "DEBT_TOTAL_FIELD", "FIELDS"]
