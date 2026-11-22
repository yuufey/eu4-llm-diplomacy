"""Identity-bound capture of current subsidy obligations and native expiry."""
from copy import deepcopy
import ctypes as C
from ctypes import wintypes as W
from functools import partial
import hashlib
import json
from pathlib import Path
import struct

from . import economic_commitments as _leaf
from . import foreign_country_memory as _backend
from . import foreign_economy_capture_v7 as _economy
from . import foreign_technology_capture as _owner
from . import mission_observer_guard as _observer_guard


SCHEMA = "information.economic_commitments_capture.v1"
PROFILE_FILE = Path(__file__).with_name("profiles") / "economic-commitments-memory-1374.json"
PROFILE_SHA256 = "cc6514b0e2ca3533383cc3429eb3339a2ce5aaa975de49a274757a78f587793c"
FIELDS = _leaf.FIELDS
_SUBSIDY_ENTRY_RVA = 0xA62DF0
# Fixed COFF subsidy_remove_observe RVA in the already admitted observer DLL.
_SUBSIDY_OBSERVER_HOOKS = {
    'f05d9eb9209e8d35f512bd1d066cf5fc6585d66f58786527a86ef27cbddd64e6': 0xBE260,
    '4238740233dbb3415c3151e5eace7f41b517a90d8b8843c9b6cff0e6c579dbc8': 0xBF260,
    '632e99535d85dce8b2a9e68ce0a1adcca9ccbb220dc30b8ead854fcc56632bd4': 0xC4030,
    '945d9ce8ecf6ac4f487ccc65f8a90554ef4c1e46b4e082fea454688eb68fe194': 0xC4130,
    '396f48c807b646eeed7786fcd7bd7a3ab6357f2357eebad2cf6538d0a31d8553': 0xC41F0,
}


def _bound_observer(reader, installation):
    underlying = getattr(reader, 'reader', reader)
    modules = (W.HMODULE * 1024)()
    needed = W.DWORD()
    if not underlying.kernel.K32EnumProcessModulesEx(
            underlying.handle, modules, C.sizeof(modules), C.byref(needed), 3):
        raise C.WinError(C.get_last_error())
    if not needed.value or needed.value > C.sizeof(modules) or needed.value % C.sizeof(W.HMODULE):
        raise ValueError('ECONOMIC_COMMITMENTS_MODULE_LIST_INVALID')
    _observer_guard.bind_loaded_observer(
        underlying, _owner._identity._load_installation(Path(installation)), Path(installation),
        modules, needed.value // C.sizeof(W.HMODULE))
    return deepcopy(underlying.mission_observer_binding)


def _verify_subsidy_entry(binding, game_base, rva, expected, actual):
    if rva != _SUBSIDY_ENTRY_RVA or not isinstance(binding, dict):
        return None
    hook_rva = _SUBSIDY_OBSERVER_HOOKS.get(binding.get('dll_sha256'))
    contract = _observer_guard._BUILDS.get(binding.get('dll_sha256'))
    dll_base = binding.get('dll_base')
    if (hook_rva is None or contract is None or type(dll_base) is not int
            or dll_base < 0x10000 or dll_base & 0xFFF
            or dll_base + hook_rva > _owner._mm.MAX_USER_ADDRESS
            or binding.get('build_manifest_sha256') != contract.get('manifest_sha256')):
        return None
    hook = dll_base + hook_rva
    if actual != b'\xff\x25\0\0\0\0' + struct.pack('<Q', hook) + expected[14:]:
        return None
    return dict(deepcopy(binding), kind='verified_installed_subsidy_expiry_entry',
                hook_rva=hex(hook_rva), hook_va=hex(hook), game_base=hex(game_base))


def _capture_binding(report):
    observation = report.get('observation') if isinstance(report, dict) else None
    return observation.get('observer_binding') if isinstance(observation, dict) else None


def _observe_guarded(reader, base, country, profile, *, backend_reader,
                     installation=None, observer_binding=None):
    binding = deepcopy(observer_binding)
    used_binding = False

    def verify(_reader, game_base, rva, expected, actual):
        nonlocal binding, used_binding
        if rva != _SUBSIDY_ENTRY_RVA:
            return None
        if binding is None and installation is not None:
            binding = _bound_observer(reader, installation)
        proof = _verify_subsidy_entry(binding, game_base, rva, expected, actual)
        used_binding = used_binding or proof is not None
        return proof

    observed = _owner._observe(reader, base, country, profile,
                               backend_reader=backend_reader, guard_verifier=verify)
    if used_binding:
        observed['observer_binding'] = binding
    return observed


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 16384:
        raise ValueError("ECONOMIC_COMMITMENTS_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("ECONOMIC_COMMITMENTS_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "economic-commitments-memory-1374"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256):
        raise ValueError("ECONOMIC_COMMITMENTS_PROFILE_BUILD")
    admission = _owner._load_profile()["code_guards"]
    subsidies = [guard for guard in _economy._load_profile()["code_guards"]
                 if guard["name"].startswith("subsidies_")]
    if not subsidies:
        raise ValueError("ECONOMIC_COMMITMENTS_SUBSIDY_GUARDS_MISSING")
    profile["code_guards"] = deepcopy(admission + subsidies) + profile["code_guards"]
    return profile


def _observe(reader, base, country, profile, *, observer="FRA", installation=None, observer_binding=None):
    current = {}

    def admission(read, module_base, scan, observer, target):
        current["observer"] = scan["requested"][observer]
        return _owner._bound_admission(read, module_base, scan, observer, target)

    def fields(limited, module_base, binding, requested):
        world = int.from_bytes(limited.read(module_base + 0x233FE58, 8,
                                            "economic_commitments.world"), "little")
        now = int.from_bytes(limited.read(world + 0x1DD0, 4,
                                          "economic_commitments.current_date"), "little", signed=True)
        return _leaf.read_fields(limited, module_base, current["observer"], binding,
                                 requested, observed_date=now)

    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, observer, [target], FIELDS,
                                      read_fields=fields, admission_reader=admission)

    return _observe_guarded(reader, base, country, profile, backend_reader=backend,
                            installation=installation, observer_binding=observer_binding)


def capture(installation, country, *, observer="FRA"):
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer, installation=installation), observer_scoped=True)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=context.get('observer'), observer_binding=_capture_binding(report)), require_access=True, observer_scoped=True)


def project_fields(report):
    """Copy business fields after the caller validates this capture."""
    raw = report["observation"]["backend"]["targets"][0]["fields"]
    return {name.removeprefix("R07."): deepcopy(raw[name]) for name in FIELDS}
