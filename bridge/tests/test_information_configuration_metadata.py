"""Configuration readers must not build unused mission ASTs."""
import json

import pytest

from bridge.information.localization import LocalizationIndex
from bridge.information.mission_definitions import MissionDefinitionError, MissionDefinitionIndex


def fixture(tmp_path):
    game, user = tmp_path / 'game', tmp_path / 'user'
    (game / 'missions').mkdir(parents=True)
    (game / 'localisation').mkdir()
    user.mkdir()
    (game / 'launcher-settings.json').write_text(json.dumps({'rawVersion': 'v1.37.4.0'}), encoding='utf-8')
    (game / 'missions/a.txt').write_text('root_a = { slot = 1 task_a = { position = 1 } }', encoding='utf-8')
    (game / 'localisation/a.yml').write_text('l_english:\n key_a:0 "Base"\n', encoding='utf-8')
    (user / 'dlc_load.json').write_text(json.dumps({'enabled_mods': []}), encoding='utf-8')
    return game, user


def test_configuration_mode_preserves_fingerprints_without_claiming_empty_missions(tmp_path):
    game, user = fixture(tmp_path)
    full = MissionDefinitionIndex(game, user)
    metadata = MissionDefinitionIndex(game, user, load_definitions=False)
    full_context, config_context = full.context(), metadata.context()
    assert full_context['status'] == config_context['status'] == 'ready'
    assert full.root('root_a')['tasks'][0]['task_id'] == 'task_a'
    assert config_context['definitions_loaded'] is False
    assert config_context['root_count'] is None
    assert config_context['script_parser']['semantics'] == 'configuration_only'
    for key in ('game_version', 'config_sha256', 'definitions_sha256', 'configuration_files', 'enabled_mods'):
        assert config_context[key] == full_context[key]
    for read in (lambda: metadata.roots(), lambda: metadata.root('root_a')):
        with pytest.raises(MissionDefinitionError) as error:
            read()
        assert error.value.code == 'MISSION_DEFINITIONS_NOT_LOADED'
    (user / 'dlc_load.json').write_text(json.dumps({'enabled_mods': ['changed.mod']}), encoding='utf-8')
    assert metadata.context()['status'] == 'unready'


def test_localisation_does_not_parse_missions_and_keeps_mod_order_and_invalidation(tmp_path, monkeypatch):
    game, user = fixture(tmp_path)
    mod = user / 'mod/overlay'
    (mod / 'localisation').mkdir(parents=True)
    (mod / 'localisation/overlay.yml').write_text('l_english:\n key_a:0 "Overlay"\n', encoding='utf-8')
    descriptor = user / 'mod/overlay.mod'
    descriptor.write_text('name="Overlay"\npath="' + mod.as_posix() + '"\n', encoding='utf-8')
    (user / 'dlc_load.json').write_text(json.dumps({'enabled_mods': ['mod/overlay.mod']}), encoding='utf-8')

    def forbidden(*args, **kwargs):
        raise AssertionError('localisation attempted to build a mission AST')

    monkeypatch.setattr(MissionDefinitionIndex, '_parse_definitions', forbidden)
    index = LocalizationIndex(game, user)
    result = index.lookup(['key_a'], language='l_english', encoding='utf8')
    assert result['entries']['key_a']['decoded_text'] == 'Overlay'
    assert result['entries']['key_a']['source']['layer'] == 'enabled_mod[0]'
    descriptor.write_text(descriptor.read_text(encoding='utf-8') + '# changed\n', encoding='utf-8')
    changed = index.lookup(['key_a'], language='l_english', encoding='utf8')
    assert changed['status'] == 'unavailable'


@pytest.mark.parametrize('value', [0, None, 'false'])
def test_configuration_mode_requires_explicit_boolean(tmp_path, value):
    game, user = fixture(tmp_path)
    with pytest.raises(ValueError, match='load_definitions must be a boolean'):
        MissionDefinitionIndex(game, user, load_definitions=value)
