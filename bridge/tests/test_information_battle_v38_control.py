"""Exercise v38 admission and read-only status through the real controller."""
import hashlib
import json

import pytest

from bridge.tests.test_information_battle_v37_manifest import make_v37_manifest_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


def _fixture(directory):
    manifest, old_dll = make_v37_manifest_fixture(directory)
    old_dll.unlink()
    dll = directory / 'eu4_bridge_diplomacy_observer_v38.dll'
    dll.write_bytes(b'synthetic-v38-no-helper-invoke-dll')
    manifest.update(version=38, dll=str(dll.resolve()),
                    dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
                    information_battle_native_title_query=False,
                    information_battle_native_title_query_mode='cached_sources_no_helper_invoke',
                    information_battle_name_sources=True,
                    information_battle_name_sources_wire=11,
                    information_battle_name_sources_stage='entry_before_client_gate',
                    information_battle_name_sources_read_only=True,
                    information_battle_name_sources_complete=False)
    manifest['compiler_arguments'] += ['-DINFORMATION_BATTLE_NAME_SOURCES=1',
                                       '-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1']
    for name in start.INFORMATION_BATTLE_NAME_SOURCES_SOURCES:
        source = directory / name
        data = ('synthetic-v38:' + name).encode('ascii')
        source.write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    (directory / 'build-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    module = {'name': dll.name, 'path': str(dll.resolve()), 'sha256': manifest['dll_sha256']}
    identity = {'pid': 123, 'creation_filetime': 456, 'session_id': 'synthetic-123-456',
                'game_sha256': manifest['game_sha256'], 'modules': [module]}
    installation = {key: value for key, value in identity.items() if key != 'modules'}
    installation.update(dll_sha256=manifest['dll_sha256'], modules_after_install=[module])
    path = directory / 'installation.json'
    path.write_text(json.dumps(installation), encoding='utf-8')
    status = {'pid': 123, 'creation_filetime': '456', 'exe_sha256': manifest['game_sha256'],
              'dll_sha256': manifest['dll_sha256'], 'state': 'ready',
              'installation': '0', 'generation': '0', 'wire_version': 11,
              'native_title_query_enabled': False, 'name_sources_enabled': True}
    (directory / control.STATUS_NAME).write_text(json.dumps(status), encoding='utf-8')
    return manifest, path, identity


def test_v38_control_status_validates_full_manifest_without_publishing(monkeypatch, tmp_path):
    manifest, installation, identity = _fixture(tmp_path / 'valid')
    monkeypatch.setattr(control, 'probe_identity', lambda *_: identity)

    def no_write(*args, **kwargs):
        pytest.fail('read-only status must not create a binding or publish a request')

    monkeypatch.setattr(control, '_ensure_binding', no_write)
    monkeypatch.setattr(control, '_publish_request', no_write)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in installation.parent.iterdir()}
    result = control.run_control(installation, 'status')
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in installation.parent.iterdir()}
    assert result['status'] == 'observed' and result['fresh'] is True
    assert result['native']['wire_version'] == 11
    assert result['native']['native_title_query_enabled'] is False
    assert before == after


@pytest.mark.parametrize('mutation', ['missing_no_invoke', 'helper_invoke', 'wire10', 'missing_source'])
def test_v38_controller_keeps_strict_cached_source_contract(tmp_path, mutation):
    manifest, installation, _ = _fixture(tmp_path / mutation)
    if mutation == 'missing_no_invoke':
        manifest['compiler_arguments'].remove('-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1')
    elif mutation == 'helper_invoke':
        manifest['information_battle_native_title_query'] = True
    elif mutation == 'wire10':
        manifest['information_battle_name_sources_wire'] = 10
    else:
        manifest['sources'] = [item for item in manifest['sources']
                               if item['name'] != start.INFORMATION_BATTLE_NAME_SOURCES_SOURCES[0]]
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, installation.parent)
    assert caught.value.reason == 'BUILD_MANIFEST_MISMATCH'


@pytest.mark.parametrize('mutation,reason', [('session', 'SESSION_ID_MISMATCH'),
                                           ('module', 'MODULE_HASH_MISMATCH')])
def test_v38_controller_keeps_live_identity_binding(monkeypatch, tmp_path, mutation, reason):
    _, installation, identity = _fixture(tmp_path / mutation)
    if mutation == 'session':
        identity['session_id'] = 'different-session'
    else:
        identity['modules'][0]['sha256'] = 'f' * 64
    monkeypatch.setattr(control, 'probe_identity', lambda *_: identity)
    with pytest.raises(control.ControlError) as caught:
        control.run_control(installation, 'status')
    assert caught.value.reason == reason
