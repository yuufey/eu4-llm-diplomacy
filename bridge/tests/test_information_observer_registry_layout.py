"""Bounded PE fixtures for selecting the actually installed registry layout."""
from copy import deepcopy
import hashlib
import json
import struct

import pytest

from bridge.information import observer_registry_layout as layout
from tools import start_diplomacy_observer as installer


def _pe(modern):
    raw = bytearray(4096)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 128)
    raw[128:132] = b'PE\0\0'
    symbols = [
        (layout._static_symbol('peace_war_registry'), 16, 2),
        (layout._static_symbol('peace_war_registry_size'), 0, 2),
        (layout._static_symbol('observation_creation'), 0x3000, 2),
        ('_ZN11information12war_registry8Registry12register_warEyy', 0, 1),
    ]
    if modern:
        symbols.append((layout._static_symbol('peace_war_registry_revision'), 0x3010, 2))
    struct.pack_into('<HHIIIHH', raw, 132, 0x8664, 3, 0, 0x800, len(symbols), 240, 0x2022)
    optional = 152
    struct.pack_into('<H', raw, optional, 0x20b)
    struct.pack_into('<Q', raw, optional + 24, 0x180000000)
    struct.pack_into('<I', raw, optional + 56, 0x7000)
    struct.pack_into('<I', raw, optional + 108, 16)
    struct.pack_into('<II', raw, optional + 136, 0x6000, 12)
    sections = [
        (b'.text', 0x200, 0x1000, 0x200, 0x200, 0x60000020),
        (b'.bss', 0x4000, 0x2000, 0, 0, 0xc0000080),
        (b'.pdata', 12, 0x6000, 0x200, 0x400, 0x40000040),
    ]
    for index, (name, virtual_size, rva, size, offset, flags) in enumerate(sections):
        at = optional + 240 + index * 40
        raw[at:at + 8] = name.ljust(8, b'\0')
        struct.pack_into('<IIII', raw, at + 8, virtual_size, rva, size, offset)
        struct.pack_into('<I', raw, at + 36, flags)
    raw[0x200:0x210] = b'\x90' * 15 + b'\xc3'
    struct.pack_into('<III', raw, 0x400, 0x1000, 0x1010, 0x6010)
    strings = bytearray(4)
    for index, (name, value, section) in enumerate(symbols):
        at = 0x800 + index * 18
        struct.pack_into('<II', raw, at, 0, len(strings))
        strings.extend(name.encode() + b'\0')
        struct.pack_into('<IhHBB', raw, at + 8, value, section, 0, 3, 0)
    struct.pack_into('<I', strings, 0, len(strings))
    end = 0x800 + len(symbols) * 18
    raw[end:end + len(strings)] = strings
    return bytes(raw)


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(layout, 'ROOT', tmp_path)
    layout._layout.cache_clear()
    calls = []
    monkeypatch.setattr(installer, '_validate_information_battle_manifest',
                        lambda manifest, directory: calls.append((manifest, directory)))
    build = tmp_path / 'build'
    build.mkdir()
    dll = build / 'observer.dll'
    manifest_path = build / 'build-manifest.json'
    installation = build / 'installation.json'

    def write(raw, **changes):
        dll.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        manifest = {'dll': str(dll), 'dll_sha256': digest, 'game_sha256': layout.GAME_SHA256}
        manifest.update(changes)
        manifest_path.write_text(json.dumps(manifest))
        document = {'dll_sha256': digest, 'game_sha256': layout.GAME_SHA256,
                    'modules_after_install': [{'path': str(dll), 'sha256': digest}]}
        installation.write_text(json.dumps(document))
        return installation

    return write, dll, manifest_path, calls


@pytest.mark.parametrize('modern', [False, True])
def test_installed_artifact_supplies_current_rvas_and_format(artifact, modern):
    write, dll, _, calls = artifact
    descriptor = layout.descriptor_for_installation(write(_pe(modern)))
    assert descriptor['entries_rva'] == 0x2010
    assert descriptor['count_rva'] == 0x2000
    assert descriptor['creation_rva'] == 0x5000
    assert descriptor['module_file']['sha256'] == hashlib.sha256(dll.read_bytes()).hexdigest()
    assert descriptor.get('registry_format') == ('reusable_slots_v1' if modern else None)
    assert descriptor.get('revision_rva') == (0x5010 if modern else None)
    assert len(bytes.fromhex(descriptor['code_guards'][0]['bytes'])) == 16
    assert len(calls) == 1


@pytest.mark.parametrize('damage', ['dll', 'manifest_sha', 'game', 'coff_bounds', 'missing_symbol'])
def test_changed_or_unusable_artifact_keeps_registry_unbound(artifact, damage):
    write, dll, manifest_path, _ = artifact
    raw = bytearray(_pe(True))
    if damage == 'coff_bounds':
        struct.pack_into('<I', raw, 140, len(raw) + 1)
    if damage == 'missing_symbol':
        name = layout._static_symbol('peace_war_registry').encode()
        at = raw.index(name + b'\0')
        raw[at] = ord('X')
    installation = write(raw)
    if damage == 'dll':
        raw[0x201] ^= 1
        dll.write_bytes(raw)
    elif damage in {'manifest_sha', 'game'}:
        manifest = json.loads(manifest_path.read_text())
        manifest['dll_sha256' if damage == 'manifest_sha' else 'game_sha256'] = '0' * 64
        manifest_path.write_text(json.dumps(manifest))
    assert layout.descriptor_for_installation(installation) is None


def test_cache_is_artifact_scoped_and_returns_independent_data(artifact):
    write, _, _, calls = artifact
    installation = write(_pe(True))
    first = layout.descriptor_for_installation(installation)
    saved = deepcopy(first)
    first['entries_rva'] = 1
    assert layout.descriptor_for_installation(installation) == saved
    assert len(calls) == 1
    changed = bytearray(_pe(True))
    changed[0x201] ^= 1
    write(changed)
    second = layout.descriptor_for_installation(installation)
    assert second['code_guards'][0]['sha256'] != saved['code_guards'][0]['sha256']
    assert len(calls) == 2
