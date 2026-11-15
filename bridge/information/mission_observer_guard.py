"""Recognize pinned mission observers in an identity-bound RPM capture."""
from __future__ import annotations

import ctypes as C
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Mapping


DLL_NAME = "eu4_bridge_diplomacy_observer_v54.dll"
DLL_SHA256 = "8984b4da991e079d96ef25dc6009c865fcf38176656f11921c189e0756000ea8"
ASSET_FILE = Path(__file__).parent / "profiles/mission-observer-guard-v54.json"
ASSET_SHA256 = "6f111e5a650f518f2b1273346876c7fc2e2b4e17b024dd3635a7932411741fa9"
_BUILDS = {
    "3a9308690aa611b829ad38eb9680666f20f13baa1dd494cf4251c06f2caa705d": {
        "version": 64, "dll_name": "eu4_bridge_diplomacy_observer_v64.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v64-land-promise.json",
        "asset_sha256": "a87f8d51d382de76853acccbe97f662160c03410a5116278f213c9b491f6a5a3",
        "manifest_sha256": "8f31a31f2047f55dca591131b20a870da5b53bfe304970a3f7a56c962a7fefa9",
        "manifest_path": "work/runtime/diplomacy-observer-20261115-land-promise-v64-001/build-manifest.json",
        "source_count": 206, "build_version": 64,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "a09af4ed06abe7b9e15fd7db05d68d01171435a5ebe1fb223c3e86708221c2da",
    },
    "8db058b325bef33c2ee7fcd1bfa4418c9991ff2fdb0013893c94f97a069ac953": {
        "version": 64, "dll_name": "eu4_bridge_diplomacy_observer_v64.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v64-pending-clear.json",
        "asset_sha256": "4bfaf5662f1781d1b2ff11a0777640bfddcb99c620cf8027b40681916ce674e7",
        "manifest_sha256": "1c6f4c8aa42fd4ac3d52ae657e7fe625c57d0681e131804b4764048ca1f13ca2",
        "manifest_path": "work/runtime/diplomacy-observer-20261115-pending-clear-v64-001/build-manifest.json",
        "source_count": 206, "build_version": 64,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "03996255a13970a32a81e524344d706e1933e7df281ff57e978121acd142f23b",
    },
    "f05d9eb9209e8d35f512bd1d066cf5fc6585d66f58786527a86ef27cbddd64e6": {
        "version": 64, "dll_name": "eu4_bridge_diplomacy_observer_v64.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v64-subsidy-monthly.json",
        "asset_sha256": "a27df255707a99d3747a49105d5e69bef7ad7390e6056708bc8aac7c9f4131be",
        "manifest_sha256": "64c38d19e2a2decc2a0a039476a33e9f6c8295c7279bec590bdb50649c834f53",
        "manifest_path": "work/runtime/diplomacy-observer-20261115-subsidy-monthly-v64-001/build-manifest.json",
        "source_count": 206, "build_version": 64,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "4fc96b25e75df7f6dc2172386ce810fac43c9cc5b50fca242a12c5321f943620",
    },
    "a2711a11fe942c2fe129d47c1748b1502e7a275b98f2a5513f568cff1983d7b4": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-war-active-roster.json",
        "asset_sha256": "1a2a617bc6ec9efbd5e361856c7a21aafb254e9ce7f47f20bca19f283e0c8b02",
        "manifest_sha256": "6093fa86bc38b83b23a9e382f293b3325718cc74d6d9cc11113b0d89fd5c93f8",
        "manifest_path": "work/runtime/diplomacy-observer-20261115-war-active-roster-v61-001/build-manifest.json",
        "source_count": 191, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "11298a18b03f48324e47af4304b43c5f77a0bad868fcb38c7e0cc6c8f9137e01",
    },
    "d4de6ce15edd9040e1aaa7ff1bdc14f67a535e1460d8c7de703984e5aad507a5": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-war-recycling.json",
        "asset_sha256": "c328a4d63255f9007a24b300a30232158af975b00ac75a5b7b8a783417298e4f",
        "manifest_sha256": "ae8797da65c649611d5d7356d79d35d809c0a1b74d6b134089a218fe30c4b6a1",
        "manifest_path": "work/runtime/diplomacy-observer-20261115-war-recycling-v61-001/build-manifest.json",
        "source_count": 191, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "8c4247d7f242cb0d7df72635bb13a6cea72054e9f01e6825c39a20e76aeb7811",
    },
    "b6e0f879d99d84cd954315bdb8a9ecd880754c29df8b3ba7af7e0b22fe55a9fa": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-war-lifetime.json",
        "asset_sha256": "e3a0ba6af1f7ef47916462137e8c1d9ee7e04bf4b0d70b61eb6d62d643f3dd5e",
        "manifest_sha256": "155fa9d481746c3caab279bf0b11a5d166623771b4d4db319e79b1208ba67d05",
        "manifest_path": "work/runtime/diplomacy-observer-20261114-war-lifetime-v61-002/build-manifest.json",
        "source_count": 191, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "581e5e924ce1752ff2288048bc8c8730e03a939711bc160914261ccab9e4306c",
    },
    "d4fbf00818b3736d6494d11577b190164958257c35fb2c3c4fd538e87c3bf397": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-direct-declaration.json",
        "asset_sha256": "ed9b8c669ff86bee0310b84ae18b9cd3c3d5c5367b551d2ee2479bca4dc84b4b",
        "manifest_sha256": "697911d5886110bf6ff87ffcf59df52be214dd04c4b6e143eba2b34d9127938c",
        "manifest_path": "work/runtime/diplomacy-observer-20261113-direct-declaration-v61-001/build-manifest.json",
        "source_count": 190, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "e720184828d4fedcee7595c681978cfd60231c118405d2cbf6349b82be98976a",
    },
    "9bda79afaa5d0fe489e6c3a7a69b76ed73f516d7353c621d76dff9630a284481": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-inbound-clock.json",
        "asset_sha256": "10161d3c8f2dd2c95e0c563c840278e63fce2f7fb1dedb18a6190f3e3b0afd1f",
        "manifest_sha256": "d69134bb4a8560c2b046607f9d1d883d6fc0065cd527af4e0996620c1f6563a6",
        "manifest_path": "work/runtime/diplomacy-observer-20261113-inbound-clock-v61-001/build-manifest.json",
        "source_count": 190, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "cd35c0c7a7f194f2e40ce052620a54684d664791c56e79888f07943924138a34",
    },
    "968ee8e84e0426c86bd8e1e59b4b944cada8f06c90d01540a3c09846a2f14646": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-territorial-interest.json",
        "asset_sha256": "7b72cef04ed38f74d3d1c380b3d07569a8a06f34c7fca1ad529280774e303295",
        "manifest_sha256": "4e4a81ed12f2bf9766fa337802ab166b3f2800271c4a3c9d9ca6269875c4c3c6",
        "manifest_path": "work/runtime/diplomacy-observer-20261112-territorial-interest-v61-002/build-manifest.json",
        "source_count": 190, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "ffa38cf5fcb6320530c669fbcab93d149dcf803eb7b5837cc8371fbed2ac7ed9",
    },
    "5a165ed11e91fb9e64159f63954d40af68a19f26ccf0a20358f5bba231a711bd": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-p1-script.json",
        "asset_sha256": "e208d8336fec78067de6411e2d676fd83a216b9497ed29ace04a7906a352fb73", "manifest_sha256": "71f0e07828e5477cd4d02acc2b945e2af43a3c762a7bf4f41c3e20ba99540236",
        "manifest_path": "work/runtime/diplomacy-observer-20261113-p1-script-v61-002/build-manifest.json",
        "source_count": 190, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "0672f272b734c0eb27e2fcc0c657a6b4f2ccd8d3f08e2d848d948be60261ab21",
    },
    "b5cfbc0544ab0b6573504e4df13041ed6d1dcaf2ba32ecc345790c510f4addca": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-direct-support.json",
        "asset_sha256": "b48aca6abf3c9bb40f46ae8f6700571820a2265fb18d4a5d6eb4cc8c18fb5688",
        "manifest_sha256": "ec592112a84d744b9a4bbd2fa36b99460df41612edd3f9130d896a942e4cc14b",
        "manifest_path": "work/runtime/diplomacy-observer-20261113-direct-support-v61-001/build-manifest.json",
        "source_count": 190, "build_version": 61,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "fa05a3b4fe1b1d6cd01566ec0512bd4c03ed79d8359151df077e7fbaff365dfd",
    },
    "e019cedb4642901afd7c4edcf0fa97bc5e44ddb3013ed0e56ad918e139320293": {
        "version": 58, "dll_name": "eu4_bridge_diplomacy_observer_v58.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v58.json",
        "asset_sha256": "90fe354d2537474e8e158c8f1919fbef907dc1c9930c3d1dc2a4e1624cdb908e",
    },
    "807fdf34dfb96688e5e6eb42a738264b57be80d0a1ae4c28cc9ec8728b5aa573": {
        "version": 57, "dll_name": "eu4_bridge_diplomacy_observer_v57.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v57.json",
        "asset_sha256": "b71491986872adb42763cc46e0309bcf4a19c14ded883740799928c8fc01d442",
    },
    "175b1f1d598feb6af5877d8030b10da2da3b8a40bf0819ed480cae210ea64788": {
        "version": 56, "dll_name": "eu4_bridge_diplomacy_observer_v56.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v56.json",
        "asset_sha256": "8dc2e6c6cea8266e96a02a3c332f13fe904c1d59ef525945f86d0f64b4dd16ab",
    },
    "8144602f86e44e9bfb6c0f24313360d44b145362869825c1b4a44222c86badd4": {
        "version": 59, "dll_name": "eu4_bridge_diplomacy_observer_v59.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v59.json",
        "asset_sha256": "a7a0b33090fd50e8c2ecd6d128f4f39a49e704b73efac61b5d5d89ee1fcbbfc9", "manifest_sha256": "9b6ef8dc77762416a42bde1d3d6136a13e74773ba35b9a4f20267d0379065ed3",
        "manifest_path": "work/runtime/diplomacy-observer-20261110-directed-v59-351-001/build-manifest.json", "source_count": 185,
        "build_version": 59, "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "4e6802a5ead70ad92a16fa751e6c44b5efb2a2ff777481646bfd97e9cbf6c1cc",
    },
    "796c7af54c543d32dc5fe26770767f4b0ce3dfa1af9d1ea35219e159740c2ded": {
        "version": 60, "dll_name": "eu4_bridge_diplomacy_observer_v60.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v60.json",
        "asset_sha256": "a2cfbac67492c3a41ac1d2cb176de02c15bfaee7a711955a9092c7a5024dda15", "manifest_sha256": "4c4acfdfd8f2dcba68486191ca18a637ca65a9d2c2f30bf01d74eacfd2d0b90b",
        "manifest_path": "work/runtime/diplomacy-observer-20261110-support-subject-v60-354-001/build-manifest.json", "source_count": 187,
        "build_version": 60, "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "042f12818bc6b77d0937d792f32c2337f1a8e1336c6e0c3732a21e35a86fd818",
    },
    "41079eae93a825c48428defff2430aa0a17707c92bb020fb2f0e77952cd5efc1": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61.json",
        "asset_sha256": "a98288f911c74c63e2fb7e61b22641917635d1f4bf3e4ae896c4f103fd96a8db", "manifest_sha256": "2d6b73caeffa7f687b6c5aaf085e53d2996adbb30898b13a8bc06b299cdf8860",
        "manifest_path": "work/runtime/diplomacy-observer-20261110-rival-record-v61-360-001/build-manifest.json", "source_count": 189,
        "build_version": 61, "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "668eadf957e1e04ceb768caa4032bdb4fc2378378612b2d212c7e90fc0778364",
    },
    "5d3a679afde7a1069b69024e47210fd0841736877e0f63a1ee89f6a722513fb6": {
        "version": 61, "dll_name": "eu4_bridge_diplomacy_observer_v61.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v61-shared-entry.json",
        "asset_sha256": "15d9f1518aaccc372723d7bb0c7202e92c5bf35e01c2c8f8ba13d700f2fe67d4", "manifest_sha256": "5bfdd346d064f885d9f780c3a2a47ab1d3fd2a00adc6ed4b2f2891b1c0f2dd18",
        "manifest_path": "work/runtime/diplomacy-observer-20261110-rival-record-v61-360-003/build-manifest.json", "source_count": 189,
        "build_version": 61, "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "evidence_sha256": "b7ffde7cc70e59ce37db544bd9df60def55661ffc73c877afa6af06409784fae",
    },
    DLL_SHA256: {"version": 54, "dll_name": DLL_NAME, "asset_file": ASSET_FILE,
                 "asset_sha256": ASSET_SHA256},
    "f569c20465922e7f56b2fa45009da551501f690ea5549f3e13309b4ac8155ade": {
        "version": 55, "dll_name": "eu4_bridge_diplomacy_observer_v55.dll",
        "asset_file": Path(__file__).parent / "profiles/mission-observer-guard-v55.json",
        "asset_sha256": "e193ec565bb00483a578f82814abc3201ad1a719dbb1b10ee2f7b9667700998a",
    },
}
ENTRY_RVA = 0x8D4E00
CONDITION_RVA = 0xB98070
PROVINCE_RVA = 0xBE9300
PREFIX = bytes.fromhex("48895c2408488974241048897c2418")
PROJECTED_UNWIND = bytes.fromhex("010f06000f7403000a64020005340100")
PROVINCE_PREFIX = bytes.fromhex("48895c2408488974241848897c2420")
PROVINCE_UNWIND = bytes.fromhex("010f06000f7404000a64030005340100")


def bind_loaded_observer(reader: Any, document: Mapping[str, Any], installation: Path,
                         modules: Any, module_count: int) -> None:
    """Attach ownership only after the caller verifies the game's identity."""
    reader.mission_observer_binding = None
    dll_sha256 = document.get("dll_sha256")
    if not isinstance(dll_sha256, str):
        return
    contract = _BUILDS.get(dll_sha256)
    if contract is None:
        return
    dll_path = (installation.parent / contract["dll_name"]).resolve()
    matches = []
    for module in modules[:module_count]:
        name = C.create_unicode_buffer(32768)
        length = reader.kernel._probe_get_module_name(reader.handle, module, name, len(name))
        if length and Path(name.value).resolve() == dll_path:
            matches.append(int(getattr(module, "value", module)))
    if len(matches) != 1:
        return
    digest = hashlib.sha256()
    with dll_path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() == dll_sha256:
        reader.mission_observer_binding = {
            "dll_base": matches[0], "dll_path": str(dll_path), "dll_sha256": dll_sha256,
        }
        if contract.get("manifest_sha256"):
            reader.mission_observer_binding["build_manifest_sha256"] = contract["manifest_sha256"]
        if contract.get("manifest_sha256"):
            reader.mission_observer_binding["build_manifest_sha256"] = contract["manifest_sha256"]


def verify_entry(reader: Any, game_base: int, rva: int,
                 expected: bytes, actual: bytes) -> dict[str, Any] | None:
    """Return explicit patch proof, leaving all original runtime bytes intact."""
    if rva == ENTRY_RVA:
        if expected[:15] != PREFIX or len(expected) != 609:
            return None
    elif rva == PROVINCE_RVA:
        if expected[:15] != PROVINCE_PREFIX or len(expected) != 944:
            return None
    elif rva != CONDITION_RVA or len(expected) != 96:
        return None
    underlying = getattr(reader, "_reader", reader)
    binding = getattr(underlying, "mission_observer_binding", None)
    contract = _BUILDS.get(binding.get("dll_sha256")) if binding else None
    if contract is None:
        return None
    asset_file, asset_sha256 = contract["asset_file"], contract["asset_sha256"]
    if not 0 < asset_file.stat().st_size <= 32 * 1024:
        raise ValueError("mission_observer_asset_size_invalid")
    with asset_file.open("rb") as stream:
        raw_asset = stream.read(32 * 1024 + 1)
    if len(raw_asset) > 32 * 1024 or hashlib.sha256(raw_asset).hexdigest() != asset_sha256:
        raise ValueError("mission_observer_asset_pin_mismatch")
    asset = json.loads(raw_asset)
    if asset.get("dll_sha256") != binding["dll_sha256"]:
        raise ValueError("mission_observer_asset_dll_mismatch")
    for contract_key, asset_key in (
        ("build_version", "build_version"),
        ("manifest_sha256", "build_manifest_sha256"),
        ("manifest_path", "build_manifest_path"),
        ("source_count", "source_count"),
        ("game_sha256", "game_sha256"),
        ("evidence_sha256", "evidence_sha256"),
    ):
        contract_value = contract.get(contract_key)
        if contract_value is not None and asset.get(asset_key) != contract_value:
            raise ValueError("mission_observer_asset_release_mismatch")
    if contract.get("manifest_sha256") and binding.get("build_manifest_sha256") != contract["manifest_sha256"]:
        raise ValueError("mission_observer_manifest_binding_mismatch")
    for contract_key, asset_key in (
        ("build_version", "build_version"),
        ("manifest_sha256", "build_manifest_sha256"),
        ("manifest_path", "build_manifest_path"),
        ("source_count", "source_count"),
        ("game_sha256", "game_sha256"),
        ("evidence_sha256", "evidence_sha256"),
    ):
        contract_value = contract.get(contract_key)
        if contract_value is not None and asset.get(asset_key) != contract_value:
            raise ValueError("mission_observer_asset_release_mismatch")
    if contract.get("manifest_sha256") and binding.get("build_manifest_sha256") != contract["manifest_sha256"]:
        raise ValueError("mission_observer_manifest_binding_mismatch")
    for contract_key, asset_key in (
        ("build_version", "build_version"),
        ("manifest_sha256", "build_manifest_sha256"),
        ("manifest_path", "build_manifest_path"),
        ("source_count", "source_count"),
        ("game_sha256", "game_sha256"),
        ("evidence_sha256", "evidence_sha256"),
    ):
        contract_value = contract.get(contract_key)
        if contract_value is not None and asset.get(asset_key) != contract_value:
            raise ValueError("mission_observer_asset_release_mismatch")
    if contract.get("manifest_sha256") and binding.get("build_manifest_sha256") != contract["manifest_sha256"]:
        raise ValueError("mission_observer_manifest_binding_mismatch")
    dll_base = binding["dll_base"]
    reads = []

    def read(address: int, size: int, label: str) -> bytes:
        value = reader.read_code(address, size, "mission_observer." + label)
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError("mission_observer_short_read")
        reads.append({"address": hex(address), "raw_hex": value.hex()})
        return value

    if rva == CONDITION_RVA:
        condition = asset.get("condition")
        if not isinstance(condition, dict):
            return None
        return _verify_condition(read, game_base, expected, actual, condition,
                                 binding, asset_sha256, reads)
    prefix, projected_unwind, home_slot = PREFIX, PROJECTED_UNWIND, 0x20
    family = "mission_availability_entry"
    if rva == PROVINCE_RVA:
        asset = asset.get("province")
        if not isinstance(asset, dict) or contract["version"] not in (57, 58, 59, 60, 61, 64):
            return None
        prefix, projected_unwind, home_slot = PROVINCE_PREFIX, PROVINCE_UNWIND, 0x10
        family = "mission_province_condition_entry"
    if hashlib.sha256(expected).hexdigest() != asset["original_guard_sha256"]:
        raise ValueError("mission_observer_original_guard_mismatch")
    hook = dll_base + asset["observe_rva"]
    patch = b"\xff\x25\0\0\0\0" + struct.pack("<Q", hook) + b"\x90"
    if actual != patch + expected[15:]:
        raise ValueError("mission_observer_entry_mismatch")
    body = bytes.fromhex(asset["observe_hex"])
    if read(hook, len(body), "observe") != body:
        raise ValueError("mission_observer_body_mismatch")
    unwind = bytes.fromhex(asset["observe_unwind_hex"])
    if read(dll_base + asset["observe_unwind_rva"], len(unwind), "observe_unwind") != unwind:
        raise ValueError("mission_observer_unwind_mismatch")
    if read(dll_base + asset["game_base_rva"], 8, "game_base") != struct.pack("<Q", game_base):
        raise ValueError("mission_observer_game_base_mismatch")
    original = read(dll_base + asset["original_rva"], 8, "original")
    executable = read(dll_base + asset["executable_rva"], 8, "executable")
    trampoline = int.from_bytes(original, "little")
    if original != executable or trampoline < 0x10000 or trampoline & 0xFFF:
        raise ValueError("mission_observer_trampoline_pointer_invalid")
    continuation = game_base + rva + 15
    jump = (b"\xc7\x84\x24" + struct.pack("<II", home_slot, continuation & 0xFFFFFFFF)
            + b"\xc7\x84\x24" + struct.pack("<II", home_slot+4, continuation >> 32)
            + b"\xff\xa4\x24" + struct.pack("<I", home_slot))
    image = prefix + jump + bytes(20) + projected_unwind
    if read(trampoline, 80, "trampoline") != image:
        raise ValueError("mission_observer_trampoline_mismatch")
    if rva == PROVINCE_RVA:
        runtime_rows = b"".join(struct.pack("<III", *row) for row in asset["runtime_functions"])
        if read(dll_base+asset["runtime_functions_rva"], len(runtime_rows), "province.runtime_functions") != runtime_rows:
            raise ValueError("mission_province_runtime_functions_mismatch")
        if read(dll_base+asset["table_registered_rva"], 1, "province.table_registered") != b"\x01":
            raise ValueError("mission_province_table_registration_missing")
    return {
        "kind": f"verified_v{contract['version']}_{family}",
        **binding, "asset_sha256": asset_sha256, "hook_va": hex(hook),
        "trampoline_va": hex(trampoline), "reads": reads,
    }


def _verify_condition(read, game_base, expected, actual, asset, binding, asset_sha256, reads):
    if hashlib.sha256(expected).hexdigest() != asset["original_guard_sha256"]:
        raise ValueError("mission_condition_original_guard_mismatch")
    dll_base = binding["dll_base"]
    executable = int.from_bytes(read(dll_base + asset["executable_rva"], 8, "condition.executable"), "little")
    if executable < 0x10000 or executable & 0xFFF or executable + 224 > 0x7FFFFFFFFFFF:
        raise ValueError("mission_condition_executable_pointer_invalid")
    displacement = executable - (game_base + CONDITION_RVA + 47)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("mission_condition_patch_displacement_invalid")
    patch = b"\x90\xe8" + struct.pack("<i", displacement)
    if actual != expected[:41] + patch + expected[47:]:
        raise ValueError("mission_condition_callsite_mismatch")
    hook = dll_base + asset["observe_rva"]
    body = bytes.fromhex(asset["observe_hex"])
    if read(hook, len(body), "condition.observe") != body:
        raise ValueError("mission_condition_body_mismatch")
    unwind = bytes.fromhex(asset["observe_unwind_hex"])
    if read(dll_base + asset["observe_unwind_rva"], len(unwind), "condition.observe_unwind") != unwind:
        raise ValueError("mission_condition_observer_unwind_mismatch")
    if read(dll_base + asset["game_base_rva"], 8, "condition.game_base") != struct.pack("<Q", game_base):
        raise ValueError("mission_condition_game_base_mismatch")
    image = bytearray.fromhex(asset["image_hex"])
    image[asset["hook_immediate_offset"]:asset["hook_immediate_offset"] + 8] = struct.pack("<Q", hook)
    if read(executable, len(image), "condition.gateway_and_relay") != bytes(image):
        raise ValueError("mission_condition_dynamic_code_mismatch")
    runtime_rows = b"".join(struct.pack("<III", *row) for row in asset["runtime_functions"])
    if read(dll_base + asset["runtime_functions_rva"], len(runtime_rows), "condition.runtime_functions") != runtime_rows:
        raise ValueError("mission_condition_runtime_functions_mismatch")
    if read(dll_base + asset["table_registered_rva"], 1, "condition.table_registered") != b"\x01":
        raise ValueError("mission_condition_table_registration_missing")
    return {"kind": f"verified_v{_BUILDS[binding['dll_sha256']]['version']}_mission_condition_callsite", **binding,
            "asset_sha256": asset_sha256, "hook_va": hex(hook), "gateway_va": hex(executable),
            "reads": reads}
