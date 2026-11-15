"""Bounded proof of the B23 AI-choice predicate and pinned v34/v41/v42 hooks.

The proof accepts only the stock native-true stub or a pinned GUI
forwarding hook. It does not verify the whole loaded DLL and does not cover
the AI-turn hold path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_quality_visibility_memory as _common


SCHEMA = "information.native_ai_choice_mapping_memory.v2"
ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v34.json"
ASSET_SHA256 = "0c7431ff6aa035804950c142c38b905e91b5b6d672737aa8fc20c4c3a40c6413"
HOOK_DLL_SHA256 = "f1c0a589a9922bae5c395b564b3419748f5d6d789d565d5d78b0f86ab8358138"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
HOOK_POINTER_DELTA = 0x59690
V41_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v41.json"
V41_ASSET_SHA256 = "e509ba76c62ac46fe30d0dadc73cac70a27057f7fe0df014dfcf1ebc91c3df39"
V41_HOOK_DLL_SHA256 = "e04c770162562181274d0dbb5081a8b03c7e2b862f68625825748559121201dc"
V41_HOOK_POINTER_DELTA = 0x5bf50
V41_EXPIRY_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v41-expiry.json"
V41_EXPIRY_ASSET_SHA256 = "482f5ba299c88c553d927bc7d1ef267d5ec1d851b56eb6013d1c52e0b775ec47"
V41_EXPIRY_HOOK_DLL_SHA256 = "e4a3e1e391600c4881df6aca6202a4835a1c0cb19d6e4a45ea49dcdc4178ab29"
V41_EXPIRY_HOOK_POINTER_DELTA = 0x5bfa0
V41_PEACE_RETURN_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v41-peace-return.json"
V41_PEACE_RETURN_ASSET_SHA256 = "fe9c9b12e81c8756b7d3accca7abde647cf395097303181add89377a8fe8ef32"
V41_PEACE_RETURN_HOOK_DLL_SHA256 = "4d04150f079d9f5e5b0279d3ddca6694f2f0ac9e67fda3ee2b35f12e93b704a7"
V41_PEACE_RETURN_HOOK_POINTER_DELTA = 0x5bfa0
V41_RESULT_DATE_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v41-result-date.json"
V41_RESULT_DATE_ASSET_SHA256 = "b43c9fd874e614995cd106b95fa2777e486442870a2d691224ee34ac19fa06ab"
V41_RESULT_DATE_HOOK_DLL_SHA256 = "a053c253b39b59ad4073957b3ac60f882c6ae7be586b296823bb9b80740a4452"
V41_RESULT_DATE_HOOK_POINTER_DELTA = 0x5be50
V42_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v42-independent-line.json"
V42_ASSET_SHA256 = "de51d711ca64ea000f722497a4210a18af7c2e0a436cecaa694a05f87ef4db30"
V42_HOOK_DLL_SHA256 = "e991b124b1d16b7458230071a1d7ef6f665156942f2b3cb9eeb7ff5feefa77e8"
V42_HOOK_POINTER_DELTA = 0x5c0a0
V43_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v43-flag-inputs.json"
V43_ASSET_SHA256 = "25b4a5933ad0d24c6437eea85ff6cf54b68895d2b9ffe44b3f92fdbe4e147576"
V43_HOOK_DLL_SHA256 = "e682215beaf347154bbe06a45f8e4b39c39d14922b7febd568b538b7c027ecd1"
V43_HOOK_POINTER_DELTA = 0x5ae40
V44_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-support-roles.json"
V44_ASSET_SHA256 = "8d8e9aae72efd2981ede263a5b92c84bef39df287d65c72fb68be48172623364"
V44_HOOK_DLL_SHA256 = "113a63b4e6e47850fae763d20396e48bc9ae7829a770fd5f333b6d238bfb6ef1"
V44_HOOK_POINTER_DELTA = 0x5c5d0
V44_ROUTER_ORIGIN_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-router-origin.json"
V44_ROUTER_ORIGIN_ASSET_SHA256 = "bbc5efe5496b2466b1c0c9dba593ef56ff0e01b441d4c4d96d773f145f0a6ec3"
V44_ROUTER_ORIGIN_HOOK_DLL_SHA256 = "db8932a084c9693644c9a792e48c5a40c489bfd1829283b2426d9f997a6e6418"
V44_ROUTER_ORIGIN_HOOK_POINTER_DELTA = 0x5c620
V44_FRAGMENT_RETRY_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-fragment-retry.json"
V44_FRAGMENT_RETRY_ASSET_SHA256 = "4c7ff88102bb2e5360f6fd08b6473659c37b5f73bedfe01695521d6cd1692227"
V44_FRAGMENT_RETRY_HOOK_DLL_SHA256 = "adfb0171137c34fb31ced28a4de52199eec98c372307a04ddf7f959e162a53bd"
V44_FRAGMENT_RETRY_HOOK_POINTER_DELTA = 0x5c620
V44_UI_CLEANUP_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-ui-cleanup.json"
V44_UI_CLEANUP_ASSET_SHA256 = "410aeebc885d40cb05317b6cbafb7a4f8a47d21a368b6eeb4ed2bbc1b897ba9e"
V44_UI_CLEANUP_HOOK_DLL_SHA256 = "3985e5c32c5faf8e82d5e20efba6166ce0a5fde644dc10c29d7aabfa505e762f"
V44_UI_CLEANUP_HOOK_POINTER_DELTA = 0x5c620
V44_UNIT_REMOVAL_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-unit-removal-retreat.json"
V44_UNIT_REMOVAL_ASSET_SHA256 = "ae511bebdc290538015b3c1a0f362baf305ec6fc9e05f6bf734df9a97f499624"
V44_UNIT_REMOVAL_HOOK_DLL_SHA256 = "cdac40fbbeb984994c3b17b9f44f7fe7d467f79ef32b161d883b45acc98e845a"
V44_UNIT_REMOVAL_HOOK_POINTER_DELTA = 0x5cde0
V44_UNIT_REMOVAL_CAPACITY_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v44-unit-removal-retreat-capacity.json"
V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256 = "c4bc8aa8fe6acd89bc07af5a92846909d08b607dc118d24cf70bb584ccc1a4dc"
V44_UNIT_REMOVAL_CAPACITY_HOOK_DLL_SHA256 = "b861791f6c3ca1e97f125b3dd248a49b61bed8b6982e81e62b0cf8e51e53c627"
V44_UNIT_REMOVAL_CAPACITY_HOOK_POINTER_DELTA = 0x5cde0
V45_COUNTRY_MODIFIER_ADD_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v45-country-modifier-add.json"
V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256 = "12d195981492e956553fa1b066273d995878b6316f00091120d6a5f386083e0a"
V45_COUNTRY_MODIFIER_ADD_HOOK_DLL_SHA256 = "d79058b85bb30b172619bf81c8aa04bedc0d47515da71b87f77fcc756195a92e"
V45_COUNTRY_MODIFIER_ADD_HOOK_POINTER_DELTA = 0x5ced0
V46_COUNTRY_MODIFIER_REMOVE_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v46-country-modifier-remove.json"
V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256 = "1e3f04e3412873cf1597ab07e2f6e6f63fb7902c0dd9ab33a147fba1d9df7c29"
V46_COUNTRY_MODIFIER_REMOVE_HOOK_DLL_SHA256 = "2a5da4eb516dc33d6a8c08c0a0664645f82ebf029644c3ce45bde3f7746162e5"
V46_COUNTRY_MODIFIER_REMOVE_HOOK_POINTER_DELTA = 0x5d4e0
V47_COUNTRY_MODIFIER_EXPIRY_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v47-country-modifier-expiry.json"
V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256 = "32e39f1384312bff1889462e9e6bdf6ad614c5f81aee79329f8140fb57dcf367"
V47_COUNTRY_MODIFIER_EXPIRY_HOOK_DLL_SHA256 = "949825e9d962e28a2189c47cdceae3edb7d5e6504bac69d4a6d2ab4b3bb00788"
V47_COUNTRY_MODIFIER_EXPIRY_HOOK_POINTER_DELTA = 0x5d510
V48_RIVAL_CHANGE_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v48-rival-change.json"
V48_RIVAL_CHANGE_ASSET_SHA256 = "f7436fb13d6aabaf191d5021f1f246c9e252a6d63089dedb34474950797a62d8"
V48_RIVAL_CHANGE_HOOK_DLL_SHA256 = "55fa85e73a76de1dafffbeb6d2370b70e6d4880e7cfbe84117b3139121151b84"
V48_RIVAL_CHANGE_HOOK_POINTER_DELTA = 0x5de50
V51_MACRO_EVENTS_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v51-macro-events.json"
V51_MACRO_EVENTS_ASSET_SHA256 = "f5582c9efd4d620353c2064a99ca0f9a2b0b1f164406f8cfb440c6f9200a5f21"
V51_MACRO_EVENTS_HOOK_DLL_SHA256 = "6f50575ab19bf9ee465f939feae082466c2766bf6ed542e1504325217d6b94a9"
V51_MACRO_EVENTS_HOOK_POINTER_DELTA = 0x60b80
V54_MACRO_SOURCES_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v54-macro-sources.json"
V54_MACRO_SOURCES_ASSET_SHA256 = "da4c34d3a39f9f932f5d8292f9be2dfd863a4a0405888008beff2925718cf839"
V54_MACRO_SOURCES_HOOK_DLL_SHA256 = "8984b4da991e079d96ef25dc6009c865fcf38176656f11921c189e0756000ea8"
V54_MACRO_SOURCES_HOOK_POINTER_DELTA = 0x62460
V55_MACRO_REPAIR_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v55-macro-repair.json"
V55_MACRO_REPAIR_ASSET_SHA256 = "f658802b1d6249ca0d3b3d18dc0efc061cf32885d60fa3e3038ce4965b93fce2"
V55_MACRO_REPAIR_HOOK_DLL_SHA256 = "f569c20465922e7f56b2fa45009da551501f690ea5549f3e13309b4ac8155ade"
V55_MACRO_REPAIR_HOOK_POINTER_DELTA = 0x62B30
V56_CONDITION_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v56-condition.json"
V56_CONDITION_ASSET_SHA256 = "6ee80848c18489de915e4f2d9f6aeb588a7f35c677a4c593a6f388ee5d1cdd2f"
V56_CONDITION_HOOK_DLL_SHA256 = "175b1f1d598feb6af5877d8030b10da2da3b8a40bf0819ed480cae210ea64788"
V56_CONDITION_HOOK_POINTER_DELTA = 0x62DC0
V57_PROVINCE_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v57-province.json"
V57_PROVINCE_ASSET_SHA256 = "0482469647f678d2496ff23e56084186c0bb12630d228710f5934c456e3042fa"
V57_PROVINCE_HOOK_DLL_SHA256 = "807fdf34dfb96688e5e6eb42a738264b57be80d0a1ae4c28cc9ec8728b5aa573"
V57_PROVINCE_HOOK_POINTER_DELTA = 0x641F0
V58_ROYAL_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v58-royal.json"
V58_ROYAL_ASSET_SHA256 = "c4b590b13d29220a8ae0bb6dbf07560b648d70231cf737dc4f834fbee27adf10"
V58_ROYAL_HOOK_DLL_SHA256 = "e019cedb4642901afd7c4edcf0fa97bc5e44ddb3013ed0e56ad918e139320293"
V58_ROYAL_HOOK_POINTER_DELTA = 0x64BA0
V59_DIRECTED_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v59-directed.json"
V59_DIRECTED_ASSET_SHA256 = "52fc874862dc98030e9d0a9d6c68a80e4fa548d2de28c2e3c6b5b0fe82c7637d"
V59_DIRECTED_HOOK_DLL_SHA256 = "8144602f86e44e9bfb6c0f24313360d44b145362869825c1b4a44222c86badd4"
V59_DIRECTED_HOOK_POINTER_DELTA = 0x64E20
V60_SUPPORT_SUBJECT_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v60-support-subject.json"
V60_SUPPORT_SUBJECT_ASSET_SHA256 = "c9f04b6a7d00597ce6018a5870c8a847a35c1c4f7b53d86de8ec25f5123ad214"
V60_SUPPORT_SUBJECT_HOOK_DLL_SHA256 = "796c7af54c543d32dc5fe26770767f4b0ce3dfa1af9d1ea35219e159740c2ded"
V60_SUPPORT_SUBJECT_HOOK_POINTER_DELTA = 414272
V61_RIVAL_RECORD_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v61-rival-record.json"
V61_RIVAL_RECORD_ASSET_SHA256 = "97c9b4a50996c71b27483dc7b1452b0c079b8462a9816188c67036d096e6b4e1"
V61_RIVAL_RECORD_HOOK_DLL_SHA256 = "41079eae93a825c48428defff2430aa0a17707c92bb020fb2f0e77952cd5efc1"
V61_RIVAL_RECORD_HOOK_POINTER_DELTA = 415104
V61_RIVAL_SHARED_ENTRY_ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v61-rival-shared-entry.json"
V61_RIVAL_SHARED_ENTRY_ASSET_SHA256 = "a8a27a8759e048397c21ec7b1569792e2295f04abe77cde1199f87d8b72b8c71"
V61_RIVAL_SHARED_ENTRY_HOOK_DLL_SHA256 = "5d3a679afde7a1069b69024e47210fd0841736877e0f63a1ee89f6a722513fb6"
V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA = 414144
HOOK_DOS_PREFIX_SIZE = 64
HOOK_COFF_PREFIX_SIZE = 24
HOOK_MAGIC_SIZE = 2
HOOK_SIZE_OF_IMAGE_SIZE = 4
MAX_ASSET_BYTES = 8192


def _unknown(reason: str) -> None:
    raise _common._Unknown(reason)


def _asset(version=34) -> tuple[dict[str, Any], bytes]:
    relative, expected_sha, dll_sha, delta = ASSET_RELATIVE_PATH, ASSET_SHA256, HOOK_DLL_SHA256, HOOK_POINTER_DELTA
    if version == 44:
        relative, expected_sha = V44_ASSET_RELATIVE_PATH, V44_ASSET_SHA256
        dll_sha, delta = V44_HOOK_DLL_SHA256, V44_HOOK_POINTER_DELTA
    elif version == "44-router-origin":
        relative, expected_sha = (V44_ROUTER_ORIGIN_ASSET_RELATIVE_PATH,
                                  V44_ROUTER_ORIGIN_ASSET_SHA256)
        dll_sha, delta = (V44_ROUTER_ORIGIN_HOOK_DLL_SHA256,
                          V44_ROUTER_ORIGIN_HOOK_POINTER_DELTA)
    elif version == "44-fragment-retry":
        relative, expected_sha = (V44_FRAGMENT_RETRY_ASSET_RELATIVE_PATH,
                                  V44_FRAGMENT_RETRY_ASSET_SHA256)
        dll_sha, delta = (V44_FRAGMENT_RETRY_HOOK_DLL_SHA256,
                          V44_FRAGMENT_RETRY_HOOK_POINTER_DELTA)
    elif version == "44-ui-cleanup":
        relative, expected_sha = (V44_UI_CLEANUP_ASSET_RELATIVE_PATH,
                                  V44_UI_CLEANUP_ASSET_SHA256)
        dll_sha, delta = (V44_UI_CLEANUP_HOOK_DLL_SHA256,
                          V44_UI_CLEANUP_HOOK_POINTER_DELTA)
    elif version == "44-unit-removal-retreat":
        relative, expected_sha = (V44_UNIT_REMOVAL_ASSET_RELATIVE_PATH,
                                  V44_UNIT_REMOVAL_ASSET_SHA256)
        dll_sha, delta = (V44_UNIT_REMOVAL_HOOK_DLL_SHA256,
                          V44_UNIT_REMOVAL_HOOK_POINTER_DELTA)
    elif version == "44-unit-removal-retreat-capacity":
        relative, expected_sha = (V44_UNIT_REMOVAL_CAPACITY_ASSET_RELATIVE_PATH,
                                  V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256)
        dll_sha, delta = (V44_UNIT_REMOVAL_CAPACITY_HOOK_DLL_SHA256,
                          V44_UNIT_REMOVAL_CAPACITY_HOOK_POINTER_DELTA)
    elif version == "45-country-modifier-add":
        relative, expected_sha = (V45_COUNTRY_MODIFIER_ADD_ASSET_RELATIVE_PATH,
                                  V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256)
        dll_sha, delta = (V45_COUNTRY_MODIFIER_ADD_HOOK_DLL_SHA256,
                          V45_COUNTRY_MODIFIER_ADD_HOOK_POINTER_DELTA)
    elif version == "46-country-modifier-remove":
        relative, expected_sha = (V46_COUNTRY_MODIFIER_REMOVE_ASSET_RELATIVE_PATH,
                                  V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256)
        dll_sha, delta = (V46_COUNTRY_MODIFIER_REMOVE_HOOK_DLL_SHA256,
                          V46_COUNTRY_MODIFIER_REMOVE_HOOK_POINTER_DELTA)
    elif version == "47-country-modifier-expiry":
        relative, expected_sha = (V47_COUNTRY_MODIFIER_EXPIRY_ASSET_RELATIVE_PATH,
                                  V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256)
        dll_sha, delta = (V47_COUNTRY_MODIFIER_EXPIRY_HOOK_DLL_SHA256,
                          V47_COUNTRY_MODIFIER_EXPIRY_HOOK_POINTER_DELTA)
    elif version == "48-rival-change":
        relative, expected_sha = (V48_RIVAL_CHANGE_ASSET_RELATIVE_PATH,
                                  V48_RIVAL_CHANGE_ASSET_SHA256)
        dll_sha, delta = (V48_RIVAL_CHANGE_HOOK_DLL_SHA256,
                          V48_RIVAL_CHANGE_HOOK_POINTER_DELTA)
    elif version == "51-macro-events":
        relative, expected_sha = (V51_MACRO_EVENTS_ASSET_RELATIVE_PATH,
                                  V51_MACRO_EVENTS_ASSET_SHA256)
        dll_sha, delta = (V51_MACRO_EVENTS_HOOK_DLL_SHA256,
                          V51_MACRO_EVENTS_HOOK_POINTER_DELTA)
    elif version == "54-macro-sources":
        relative, expected_sha = (V54_MACRO_SOURCES_ASSET_RELATIVE_PATH,
                                  V54_MACRO_SOURCES_ASSET_SHA256)
        dll_sha, delta = (V54_MACRO_SOURCES_HOOK_DLL_SHA256,
                          V54_MACRO_SOURCES_HOOK_POINTER_DELTA)
    elif version == "55-macro-repair":
        relative, expected_sha = (V55_MACRO_REPAIR_ASSET_RELATIVE_PATH,
                                  V55_MACRO_REPAIR_ASSET_SHA256)
        dll_sha, delta = (V55_MACRO_REPAIR_HOOK_DLL_SHA256,
                          V55_MACRO_REPAIR_HOOK_POINTER_DELTA)
    elif version == "56-condition":
        relative, expected_sha = (V56_CONDITION_ASSET_RELATIVE_PATH,
                                  V56_CONDITION_ASSET_SHA256)
        dll_sha, delta = (V56_CONDITION_HOOK_DLL_SHA256,
                          V56_CONDITION_HOOK_POINTER_DELTA)
    elif version == "57-province":
        relative, expected_sha = (V57_PROVINCE_ASSET_RELATIVE_PATH,
                                  V57_PROVINCE_ASSET_SHA256)
        dll_sha, delta = (V57_PROVINCE_HOOK_DLL_SHA256,
                          V57_PROVINCE_HOOK_POINTER_DELTA)
    elif version == "58-royal":
        relative, expected_sha = (V58_ROYAL_ASSET_RELATIVE_PATH,
                                  V58_ROYAL_ASSET_SHA256)
        dll_sha, delta = (V58_ROYAL_HOOK_DLL_SHA256,
                          V58_ROYAL_HOOK_POINTER_DELTA)
    elif version == "59-directed":
        relative, expected_sha = (V59_DIRECTED_ASSET_RELATIVE_PATH,
                                  V59_DIRECTED_ASSET_SHA256)
        dll_sha, delta = (V59_DIRECTED_HOOK_DLL_SHA256,
                          V59_DIRECTED_HOOK_POINTER_DELTA)
    elif version == "60-support-subject":
        relative, expected_sha = (V60_SUPPORT_SUBJECT_ASSET_RELATIVE_PATH,
                                  V60_SUPPORT_SUBJECT_ASSET_SHA256)
        dll_sha, delta = (V60_SUPPORT_SUBJECT_HOOK_DLL_SHA256,
                          V60_SUPPORT_SUBJECT_HOOK_POINTER_DELTA)
    elif version == "61-rival-record":
        relative, expected_sha = (V61_RIVAL_RECORD_ASSET_RELATIVE_PATH,
                                  V61_RIVAL_RECORD_ASSET_SHA256)
        dll_sha, delta = (V61_RIVAL_RECORD_HOOK_DLL_SHA256,
                          V61_RIVAL_RECORD_HOOK_POINTER_DELTA)
    elif version == "61-rival-shared-entry":
        relative, expected_sha = (V61_RIVAL_SHARED_ENTRY_ASSET_RELATIVE_PATH,
                                  V61_RIVAL_SHARED_ENTRY_ASSET_SHA256)
        dll_sha, delta = (V61_RIVAL_SHARED_ENTRY_HOOK_DLL_SHA256,
                          V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA)
    elif version == 43:
        relative, expected_sha = V43_ASSET_RELATIVE_PATH, V43_ASSET_SHA256
        dll_sha, delta = V43_HOOK_DLL_SHA256, V43_HOOK_POINTER_DELTA
    elif version == 42:
        relative, expected_sha = V42_ASSET_RELATIVE_PATH, V42_ASSET_SHA256
        dll_sha, delta = V42_HOOK_DLL_SHA256, V42_HOOK_POINTER_DELTA
    elif version == "41-result-date":
        relative, expected_sha = V41_RESULT_DATE_ASSET_RELATIVE_PATH, V41_RESULT_DATE_ASSET_SHA256
        dll_sha, delta = V41_RESULT_DATE_HOOK_DLL_SHA256, V41_RESULT_DATE_HOOK_POINTER_DELTA
    elif version == "41-peace-return":
        relative, expected_sha = V41_PEACE_RETURN_ASSET_RELATIVE_PATH, V41_PEACE_RETURN_ASSET_SHA256
        dll_sha, delta = V41_PEACE_RETURN_HOOK_DLL_SHA256, V41_PEACE_RETURN_HOOK_POINTER_DELTA
    elif version == "41-expiry":
        relative, expected_sha = V41_EXPIRY_ASSET_RELATIVE_PATH, V41_EXPIRY_ASSET_SHA256
        dll_sha, delta = V41_EXPIRY_HOOK_DLL_SHA256, V41_EXPIRY_HOOK_POINTER_DELTA
    elif version == 41:
        relative, expected_sha = V41_ASSET_RELATIVE_PATH, V41_ASSET_SHA256
        dll_sha, delta = V41_HOOK_DLL_SHA256, V41_HOOK_POINTER_DELTA
    elif version != 34:
        _unknown("CHOICE_MAPPING_ASSET_VERSION_UNSUPPORTED")
    path = Path(__file__).resolve().parent / relative
    try:
        if path.stat().st_size > MAX_ASSET_BYTES:
            _unknown("CHOICE_MAPPING_ASSET_SIZE_INVALID")
        raw = path.read_bytes()
    except _common._Unknown:
        raise
    except Exception as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_UNAVAILABLE") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        _unknown("CHOICE_MAPPING_ASSET_PIN_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_INVALID") from exc
    if (type(value) is not dict
            or value.get("schema") != "information.native_ai_choice_hook_contract.v2"
            or value.get("dll_sha256") != dll_sha
            or value.get("game_executable_sha256") != EXPECTED_EXE_SHA256
            or value.get("body_rva") != delta):
        _unknown("CHOICE_MAPPING_ASSET_INVALID")
    return value, raw


def _asset_bytes(asset: dict[str, Any], key: str, expected_size: int) -> bytes:
    encoded = asset.get(key)
    if type(encoded) is not str:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    try:
        value = bytes.fromhex(encoded)
    except ValueError as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID") from exc
    if len(value) != expected_size or value.hex() != encoded.lower():
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    return value


def _asset_int(asset: dict[str, Any], key: str) -> int:
    value = asset.get(key)
    if type(value) is not int or value < 0:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    return value


def _normalized_evidence(trace: Any, start: int) -> list[dict[str, Any]]:
    ignored = {"ordinal", "label"}
    return [{key: value for key, value in row.items() if key not in ignored}
            for row in trace.reads[start:]]


def read_mapping(trace: Any, game_base: Any, actual_pointer: Any, *,
                 phase: str) -> dict[str, Any]:
    """Prove a stock or pinned-hook predicate mapping using the caller's trace.

    `trace` must be the shared `_common._Trace`, so every byte remains inside
    the permission's existing call and byte budgets. Phase-specific labels are
    omitted from the returned proof to allow strict before/after equality when
    the same bytes were observed in both passes.
    """
    if not isinstance(trace, _common._Trace):
        _unknown("CHOICE_MAPPING_TRACE_INVALID")
    if phase not in ("before", "after"):
        _unknown("CHOICE_MAPPING_PHASE_INVALID")
    base = _common._pointer(game_base, "GAME_BASE", alignment=0x1000)
    pointer = _common._pointer(actual_pointer, "CHOICE_POINTER", alignment=1)
    asset, _asset_raw = _asset()
    evidence_start = len(trace.reads)
    native_true_rva = _asset_int(asset, "native_true_predicate_rva")
    native_true_raw = _asset_bytes(asset, "native_true_predicate_hex", 3)
    expected_native_true = _common._checked_add(base, native_true_rva, len(native_true_raw))

    if pointer == expected_native_true:
        body = trace.exact(pointer, len(native_true_raw),
                           f"choice_mapping.native_true_body_{phase}")
        if body != native_true_raw:
            _unknown("NATIVE_TRUE_PREDICATE_BODY_MISMATCH")
        return {
            "schema": SCHEMA,
            "mode": "native_true",
            "game_base": hex(base),
            "actual_pointer": hex(pointer),
            "native_true_predicate_rva": hex(native_true_rva),
            "predicate_body_hex": body.hex(),
            "asset_sha256": ASSET_SHA256,
            "read_evidence": _normalized_evidence(trace, evidence_start),
        }

    asset_sha = ASSET_SHA256
    hook_delta = HOOK_POINTER_DELTA
    hook_version = 34
    mode = "installed_observer_gui_forwarding_v34"
    if (pointer > V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA
            and (pointer - V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("61-rival-shared-entry")
        asset_sha = V61_RIVAL_SHARED_ENTRY_ASSET_SHA256
        hook_delta = V61_RIVAL_SHARED_ENTRY_HOOK_POINTER_DELTA
        hook_version = 61
        mode = "installed_observer_gui_forwarding_v61"
    elif (pointer > V61_RIVAL_RECORD_HOOK_POINTER_DELTA
            and (pointer - V61_RIVAL_RECORD_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("61-rival-record")
        asset_sha = V61_RIVAL_RECORD_ASSET_SHA256
        hook_delta = V61_RIVAL_RECORD_HOOK_POINTER_DELTA
        hook_version = 61
        mode = "installed_observer_gui_forwarding_v61"
    elif (pointer > V60_SUPPORT_SUBJECT_HOOK_POINTER_DELTA
            and (pointer - V60_SUPPORT_SUBJECT_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("60-support-subject")
        asset_sha = V60_SUPPORT_SUBJECT_ASSET_SHA256
        hook_delta = V60_SUPPORT_SUBJECT_HOOK_POINTER_DELTA
        hook_version = 60
        mode = "installed_observer_gui_forwarding_v60"
    elif (pointer > V59_DIRECTED_HOOK_POINTER_DELTA
            and (pointer - V59_DIRECTED_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("59-directed")
        asset_sha = V59_DIRECTED_ASSET_SHA256
        hook_delta = V59_DIRECTED_HOOK_POINTER_DELTA
        hook_version = 59
        mode = "installed_observer_gui_forwarding_v59"
    elif (pointer > V58_ROYAL_HOOK_POINTER_DELTA
            and (pointer - V58_ROYAL_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("58-royal")
        asset_sha = V58_ROYAL_ASSET_SHA256
        hook_delta = V58_ROYAL_HOOK_POINTER_DELTA
        hook_version = 58
        mode = "installed_observer_gui_forwarding_v58"
    elif (pointer > V57_PROVINCE_HOOK_POINTER_DELTA
            and (pointer - V57_PROVINCE_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("57-province")
        asset_sha = V57_PROVINCE_ASSET_SHA256
        hook_delta = V57_PROVINCE_HOOK_POINTER_DELTA
        hook_version = 57
        mode = "installed_observer_gui_forwarding_v57"
    elif (pointer > V56_CONDITION_HOOK_POINTER_DELTA
            and (pointer - V56_CONDITION_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("56-condition")
        asset_sha = V56_CONDITION_ASSET_SHA256
        hook_delta = V56_CONDITION_HOOK_POINTER_DELTA
        hook_version = 56
        mode = "installed_observer_gui_forwarding_v56"
    elif (pointer > V55_MACRO_REPAIR_HOOK_POINTER_DELTA
            and (pointer - V55_MACRO_REPAIR_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("55-macro-repair")
        asset_sha = V55_MACRO_REPAIR_ASSET_SHA256
        hook_delta = V55_MACRO_REPAIR_HOOK_POINTER_DELTA
        hook_version = 55
        mode = "installed_observer_gui_forwarding_v55"
    elif (pointer > V54_MACRO_SOURCES_HOOK_POINTER_DELTA
            and (pointer - V54_MACRO_SOURCES_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("54-macro-sources")
        asset_sha = V54_MACRO_SOURCES_ASSET_SHA256
        hook_delta = V54_MACRO_SOURCES_HOOK_POINTER_DELTA
        hook_version = 54
        mode = "installed_observer_gui_forwarding_v54"
    elif (pointer > V51_MACRO_EVENTS_HOOK_POINTER_DELTA
            and (pointer - V51_MACRO_EVENTS_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("51-macro-events")
        asset_sha = V51_MACRO_EVENTS_ASSET_SHA256
        hook_delta = V51_MACRO_EVENTS_HOOK_POINTER_DELTA
        hook_version = 51
        mode = "installed_observer_gui_forwarding_v51"
    elif (pointer > V48_RIVAL_CHANGE_HOOK_POINTER_DELTA
            and (pointer - V48_RIVAL_CHANGE_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("48-rival-change")
        asset_sha = V48_RIVAL_CHANGE_ASSET_SHA256
        hook_delta = V48_RIVAL_CHANGE_HOOK_POINTER_DELTA
        hook_version = 48
        mode = "installed_observer_gui_forwarding_v48"
    elif (pointer > V47_COUNTRY_MODIFIER_EXPIRY_HOOK_POINTER_DELTA
            and (pointer - V47_COUNTRY_MODIFIER_EXPIRY_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("47-country-modifier-expiry")
        asset_sha = V47_COUNTRY_MODIFIER_EXPIRY_ASSET_SHA256
        hook_delta = V47_COUNTRY_MODIFIER_EXPIRY_HOOK_POINTER_DELTA
        hook_version = 47
        mode = "installed_observer_gui_forwarding_v47"
    elif (pointer > V46_COUNTRY_MODIFIER_REMOVE_HOOK_POINTER_DELTA
            and (pointer - V46_COUNTRY_MODIFIER_REMOVE_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("46-country-modifier-remove")
        asset_sha = V46_COUNTRY_MODIFIER_REMOVE_ASSET_SHA256
        hook_delta = V46_COUNTRY_MODIFIER_REMOVE_HOOK_POINTER_DELTA
        hook_version = 46
        mode = "installed_observer_gui_forwarding_v46"
    elif (pointer > V45_COUNTRY_MODIFIER_ADD_HOOK_POINTER_DELTA
            and (pointer - V45_COUNTRY_MODIFIER_ADD_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("45-country-modifier-add")
        asset_sha = V45_COUNTRY_MODIFIER_ADD_ASSET_SHA256
        hook_delta = V45_COUNTRY_MODIFIER_ADD_HOOK_POINTER_DELTA
        hook_version = 45
        mode = "installed_observer_gui_forwarding_v45"
    elif (pointer > V44_UNIT_REMOVAL_HOOK_POINTER_DELTA
            and (pointer - V44_UNIT_REMOVAL_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("44-unit-removal-retreat")
        asset_sha = V44_UNIT_REMOVAL_ASSET_SHA256
        hook_delta = V44_UNIT_REMOVAL_HOOK_POINTER_DELTA
        hook_version = 44
        mode = "installed_observer_gui_forwarding_v44"
    elif (pointer > V44_ROUTER_ORIGIN_HOOK_POINTER_DELTA
            and (pointer - V44_ROUTER_ORIGIN_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("44-router-origin")
        asset_sha = V44_ROUTER_ORIGIN_ASSET_SHA256
        hook_delta = V44_ROUTER_ORIGIN_HOOK_POINTER_DELTA
        hook_version = 44
        mode = "installed_observer_gui_forwarding_v44"
    elif (pointer > V44_HOOK_POINTER_DELTA
            and (pointer - V44_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset(44)
        asset_sha, hook_delta = V44_ASSET_SHA256, V44_HOOK_POINTER_DELTA
        hook_version = 44
        mode = "installed_observer_gui_forwarding_v44"
    elif (pointer > V43_HOOK_POINTER_DELTA
            and (pointer - V43_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset(43)
        asset_sha, hook_delta = V43_ASSET_SHA256, V43_HOOK_POINTER_DELTA
        hook_version = 43
        mode = "installed_observer_gui_forwarding_v43"
    elif (pointer > V42_HOOK_POINTER_DELTA
            and (pointer - V42_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset(42)
        asset_sha, hook_delta = V42_ASSET_SHA256, V42_HOOK_POINTER_DELTA
        hook_version = 42
        mode = "installed_observer_gui_forwarding_v42"
    elif (pointer > V41_RESULT_DATE_HOOK_POINTER_DELTA
            and (pointer - V41_RESULT_DATE_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("41-result-date")
        asset_sha, hook_delta = V41_RESULT_DATE_ASSET_SHA256, V41_RESULT_DATE_HOOK_POINTER_DELTA
        hook_version = 41
        mode = "installed_observer_gui_forwarding_v41"
    elif (pointer > V41_EXPIRY_HOOK_POINTER_DELTA
            and (pointer - V41_EXPIRY_HOOK_POINTER_DELTA) % 0x10000 == 0):
        asset, _asset_raw = _asset("41-expiry")
        asset_sha, hook_delta = V41_EXPIRY_ASSET_SHA256, V41_EXPIRY_HOOK_POINTER_DELTA
        hook_version = 41
        mode = "installed_observer_gui_forwarding_v41"
    elif pointer > V41_HOOK_POINTER_DELTA and (pointer - V41_HOOK_POINTER_DELTA) % 0x10000 == 0:
        asset, _asset_raw = _asset(41)
        asset_sha, hook_delta = V41_ASSET_SHA256, V41_HOOK_POINTER_DELTA
        hook_version = 41
        mode = "installed_observer_gui_forwarding_v41"
    if pointer <= hook_delta:
        _unknown("CHOICE_POINTER_NOT_SUPPORTED")
    module_base = pointer - hook_delta
    if (module_base < _common.MIN_USER_ADDRESS
            or module_base % 0x10000 != 0):
        _unknown("HOOK_MODULE_BASE_UNALIGNED")

    preferred_image_base = asset.get("preferred_image_base")
    if type(preferred_image_base) is not str:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    try:
        int(preferred_image_base, 16)
    except ValueError as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID") from exc

    pe_offset = _asset_int(asset, "pe_header_offset")
    size_of_image_expected = _asset_int(asset, "size_of_image")
    body_rva = _asset_int(asset, "body_rva")
    body_end_rva = _asset_int(asset, "body_end_rva_exclusive")
    body_expected = _asset_bytes(asset, "body_hex", body_end_rva - body_rva)
    body_expected_sha = asset.get("body_sha256")
    if (type(body_expected_sha) is not str
            or hashlib.sha256(body_expected).hexdigest() != body_expected_sha
            or pointer != _common._checked_add(module_base, body_rva, len(body_expected))):
        _unknown("HOOK_BODY_DESCRIPTOR_INVALID")
    image_end = _common._checked_add(module_base, size_of_image_expected, 1)
    if pointer + len(body_expected) > image_end:
        _unknown("HOOK_BODY_OUTSIDE_IMAGE")

    dos_expected = _asset_bytes(asset, "dos_prefix_hex", HOOK_DOS_PREFIX_SIZE)
    coff_expected = _asset_bytes(asset, "coff_prefix_hex", HOOK_COFF_PREFIX_SIZE)
    magic_expected = _asset_bytes(asset, "optional_header_magic_hex", HOOK_MAGIC_SIZE)
    if pe_offset != int.from_bytes(dos_expected[0x3C:0x40], "little"):
        _unknown("HOOK_PE_OFFSET_DESCRIPTOR_MISMATCH")

    dos_address = module_base
    coff_address = _common._checked_add(module_base, pe_offset, HOOK_COFF_PREFIX_SIZE)
    magic_address = _common._checked_add(module_base, pe_offset + HOOK_COFF_PREFIX_SIZE,
                                         HOOK_MAGIC_SIZE)
    size_image_offset = pe_offset + HOOK_COFF_PREFIX_SIZE + 56
    size_image_address = _common._checked_add(module_base, size_image_offset,
                                              HOOK_SIZE_OF_IMAGE_SIZE)
    dos = trace.exact(dos_address, HOOK_DOS_PREFIX_SIZE,
                      f"choice_mapping.hook_dos_header_{phase}")
    coff = trace.exact(coff_address, HOOK_COFF_PREFIX_SIZE,
                       f"choice_mapping.hook_coff_header_{phase}")
    magic = trace.exact(magic_address, HOOK_MAGIC_SIZE,
                        f"choice_mapping.hook_optional_magic_{phase}")
    size_image_raw = trace.exact(size_image_address, HOOK_SIZE_OF_IMAGE_SIZE,
                                 f"choice_mapping.hook_size_of_image_{phase}")
    size_of_image = int.from_bytes(size_image_raw, "little")
    old_header_match = (
        dos == dos_expected and coff == coff_expected and magic == magic_expected
        and size_of_image == size_of_image_expected)
    if not old_header_match and asset_sha == V44_ROUTER_ORIGIN_ASSET_SHA256:
        # These v44 variants share the hook RVA and global cells but have
        # distinct build headers and bodies. Select a variant only when every
        # bounded header read matches its pinned asset; router-origin bytes
        # remain accepted by the preceding exact comparison.
        candidate_version = "44-fragment-retry"
        candidate, _candidate_raw = _asset(candidate_version)
        candidate_dos = _asset_bytes(candidate, "dos_prefix_hex", HOOK_DOS_PREFIX_SIZE)
        candidate_coff = _asset_bytes(candidate, "coff_prefix_hex", HOOK_COFF_PREFIX_SIZE)
        candidate_magic = _asset_bytes(candidate, "optional_header_magic_hex", HOOK_MAGIC_SIZE)
        candidate_size_image = _asset_int(candidate, "size_of_image")
        candidate_header_match = (
            dos == candidate_dos and coff == candidate_coff
            and magic == candidate_magic and size_of_image == candidate_size_image)
        if not candidate_header_match:
            candidate_version = "44-ui-cleanup"
            candidate, _candidate_raw = _asset(candidate_version)
            candidate_dos = _asset_bytes(candidate, "dos_prefix_hex", HOOK_DOS_PREFIX_SIZE)
            candidate_coff = _asset_bytes(candidate, "coff_prefix_hex", HOOK_COFF_PREFIX_SIZE)
            candidate_magic = _asset_bytes(candidate, "optional_header_magic_hex", HOOK_MAGIC_SIZE)
            candidate_size_image = _asset_int(candidate, "size_of_image")
            candidate_header_match = (
                dos == candidate_dos and coff == candidate_coff
                and magic == candidate_magic and size_of_image == candidate_size_image)
        if candidate_header_match:
            variable_keys = {
                "dll_file_bytes", "dll_sha256", "body_hex", "body_sha256",
                "coff_prefix_hex", "preferred_image_base", "proof_scope",
            }
            if (set(candidate) != set(asset)
                    or any(candidate[key] != asset[key]
                           for key in set(asset) - variable_keys)):
                _unknown("HOOK_VARIANT_LAYOUT_MISMATCH")
            asset = candidate
            asset_sha = (V44_FRAGMENT_RETRY_ASSET_SHA256
                         if candidate_version == "44-fragment-retry"
                         else V44_UI_CLEANUP_ASSET_SHA256)
            preferred_image_base = asset["preferred_image_base"]
            pe_offset = _asset_int(asset, "pe_header_offset")
            size_of_image_expected = _asset_int(asset, "size_of_image")
            body_rva = _asset_int(asset, "body_rva")
            body_end_rva = _asset_int(asset, "body_end_rva_exclusive")
            body_expected = _asset_bytes(asset, "body_hex",
                                         body_end_rva - body_rva)
            body_expected_sha = asset.get("body_sha256")
            if (type(body_expected_sha) is not str
                    or hashlib.sha256(body_expected).hexdigest() != body_expected_sha
                    or pointer != _common._checked_add(
                        module_base, body_rva, len(body_expected))):
                _unknown("HOOK_BODY_DESCRIPTOR_INVALID")
            image_end = _common._checked_add(module_base, size_of_image_expected, 1)
        else:
            if dos != dos_expected:
                _unknown("HOOK_DOS_HEADER_MISMATCH")
            if coff != coff_expected:
                _unknown("HOOK_COFF_HEADER_MISMATCH")
            if magic != magic_expected:
                _unknown("HOOK_OPTIONAL_MAGIC_MISMATCH")
            if size_of_image != size_of_image_expected:
                _unknown("HOOK_SIZE_OF_IMAGE_MISMATCH")
    else:
        if dos != dos_expected:
            _unknown("HOOK_DOS_HEADER_MISMATCH")
        if coff != coff_expected:
            _unknown("HOOK_COFF_HEADER_MISMATCH")
        if magic != magic_expected:
            _unknown("HOOK_OPTIONAL_MAGIC_MISMATCH")
        if size_of_image != size_of_image_expected:
            _unknown("HOOK_SIZE_OF_IMAGE_MISMATCH")
    if (size_of_image == 0 or size_of_image % 0x1000 != 0
            or module_base + size_of_image > _common.MAX_USER_ADDRESS_EXCLUSIVE):
        _unknown("HOOK_SIZE_OF_IMAGE_RANGE_INVALID")

    body_address = _common._checked_add(module_base, body_rva, len(body_expected))
    body_first_size = min(1024, len(body_expected))
    body_first = trace.exact(body_address, body_first_size,
                             f"choice_mapping.hook_body_0_{phase}")
    body_second_size = len(body_expected) - body_first_size
    if body_second_size <= 0 or body_second_size > 1024:
        _unknown("HOOK_BODY_SPLIT_INVALID")
    body_second_address = _common._checked_add(body_address, body_first_size,
                                               body_second_size)
    body_second = trace.exact(body_second_address, body_second_size,
                              f"choice_mapping.hook_body_1_{phase}")
    body = body_first + body_second
    if body != body_expected and asset_sha in (
            V41_EXPIRY_ASSET_SHA256, V44_ROUTER_ORIGIN_ASSET_SHA256,
            V44_UNIT_REMOVAL_ASSET_SHA256):
        # These pinned variants share the guarded RVA/global layout. Select by
        # the already copied complete body, preserving historical replay reads.
        candidate_version = (
            "41-peace-return" if asset_sha == V41_EXPIRY_ASSET_SHA256
            else ("44-unit-removal-retreat-capacity"
                  if asset_sha == V44_UNIT_REMOVAL_ASSET_SHA256
                  else "44-fragment-retry"))
        candidate, _candidate_raw = _asset(candidate_version)
        variable_keys = {"dll_sha256", "body_hex", "body_sha256", "preferred_image_base"}
        if asset_sha == V44_ROUTER_ORIGIN_ASSET_SHA256:
            variable_keys |= {"dll_file_bytes", "coff_prefix_hex", "proof_scope"}
        elif asset_sha == V44_UNIT_REMOVAL_ASSET_SHA256:
            variable_keys |= {
                "dll_file_bytes", "coff_prefix_hex", "proof_scope",
                "game_module_base_global_rva", "favor_gold_original_global_rva",
            }
        if (set(candidate) != set(asset)
                or any(candidate[key] != asset[key] for key in set(asset) - variable_keys)):
            _unknown("HOOK_VARIANT_LAYOUT_MISMATCH")
        candidate_body = _asset_bytes(candidate, "body_hex", len(body_expected))
        if (body != candidate_body
                or hashlib.sha256(candidate_body).hexdigest() != candidate.get("body_sha256")):
            _unknown("HOOK_BODY_MISMATCH")
        asset = candidate
        asset_sha = (
            V41_PEACE_RETURN_ASSET_SHA256
            if candidate_version == "41-peace-return"
            else (V44_UNIT_REMOVAL_CAPACITY_ASSET_SHA256
                  if candidate_version == "44-unit-removal-retreat-capacity"
                  else V44_FRAGMENT_RETRY_ASSET_SHA256))
        body_expected = candidate_body
        preferred_image_base = asset["preferred_image_base"]
    if body != body_expected:
        _unknown("HOOK_BODY_MISMATCH")

    game_global_rva = _asset_int(asset, "game_module_base_global_rva")
    saved_original_rva = _asset_int(asset, "favor_gold_original_global_rva")
    game_global_address = _common._checked_add(module_base, game_global_rva, 8)
    saved_original_address = _common._checked_add(module_base, saved_original_rva, 8)
    observed_game_base = trace.u64(game_global_address,
                                   f"choice_mapping.hook_game_base_global_{phase}")
    saved_original = trace.u64(saved_original_address,
                               f"choice_mapping.hook_saved_original_global_{phase}")
    expected_original = expected_native_true
    if observed_game_base != base:
        _unknown("HOOK_GAME_BASE_GLOBAL_MISMATCH")
    if saved_original != expected_original:
        _unknown("HOOK_SAVED_ORIGINAL_MAPPING_MISMATCH")
    original_body = trace.exact(saved_original, len(native_true_raw),
                                f"choice_mapping.hook_saved_original_body_{phase}")
    if original_body != native_true_raw:
        _unknown("HOOK_SAVED_ORIGINAL_BODY_MISMATCH")

    return {
        "schema": SCHEMA,
        "mode": mode,
        "game_base": hex(base),
        "actual_pointer": hex(pointer),
        "module_base": hex(module_base),
        "module_size_of_image": size_of_image,
        "module_image_end_exclusive": hex(image_end),
        "preferred_image_base": preferred_image_base.lower(),
        "dll_sha256_from_asset": asset['dll_sha256'],
        "asset_sha256": asset_sha,
        "body_rva": hex(body_rva),
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_raw_hex": body.hex(),
        "body_matches_pinned_asset": True,
        "dos_header_matches_pinned_asset": True,
        "pe_header_offset": pe_offset,
        "coff_prefix_matches_pinned_asset": True,
        "optional_header_magic_matches_pinned_asset": True,
        "size_of_image_matches_pinned_asset": True,
        "game_module_base_global_rva": hex(game_global_rva),
        "observed_game_base": hex(observed_game_base),
        "saved_original_global_rva": hex(saved_original_rva),
        "saved_original_pointer": hex(saved_original),
        "saved_original_body_hex": original_body.hex(),
        "whole_loaded_dll_hash_verified": False,
        "proof_scope": f"guarded_EF2B00_GUI_caller_only; pinned_v{hook_version}_forwarder; AI_turn_hold_path_not_in_scope",
        "read_evidence": _normalized_evidence(trace, evidence_start),
    }


__all__ = ["SCHEMA", "ASSET_RELATIVE_PATH", "ASSET_SHA256", "read_mapping"]
