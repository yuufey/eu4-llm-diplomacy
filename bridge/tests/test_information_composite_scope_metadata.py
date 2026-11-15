"""A live field must not inherit a static sibling owner's visibility or note."""
from copy import deepcopy
import pytest

from bridge.information.composite import CompositeSource


class Owner:
    def __init__(self, field, visibility, note):
        self.field = field
        self.visibility = visibility
        self.note = note

    def catalog(self):
        return [{"topic_id": "G03", "fields": {self.field: {"coverage": "partial"}},
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "object_types": ["province"], "supported_versions": ["1.37.4"],
            "triggers": ["query", "periodic"], "source": self.field,
            "visibility": self.visibility, "context_scope": self.visibility, "scope_note": self.note}]


class Primary:
    def catalog(self):
        return [{"topic_id": "G03", "fields": {"fort": {"coverage": "planned"},
                                                "straits": {"coverage": "planned"}}}]


@pytest.mark.parametrize('reverse', [False, True])
def test_disjoint_live_and_static_metadata_keeps_each_owners_scope(reverse):
    owners = [Owner('fort', 'visible_scope', 'Current discovered province level.'),
              Owner('straits', 'static_rules', 'Static sea adjacency only.')]
    if reverse:
        owners.reverse()
    entries = deepcopy([owner.catalog()[0] for owner in owners])
    result = CompositeSource(Primary(), owners).catalog()[0]
    assert result['visibility'] == 'adapter_managed'
    assert result['context_scope'] == 'adapter_managed'
    assert 'scope_note' not in result
    for owner in entries:
        field = next(iter(owner['fields']))
        for key in ('visibility', 'context_scope', 'scope_note'):
            assert result['fields'][field][key] == owner[key]
    assert [owner.catalog()[0] for owner in owners] == entries


def test_matching_owner_scope_can_keep_its_shared_topic_note():
    owners = [Owner('fort', 'visible_scope', 'Current province fields.'),
              Owner('straits', 'visible_scope', 'Current province fields.')]
    result = CompositeSource(Primary(), owners).catalog()[0]
    assert result['visibility'] == 'visible_scope'
    assert result['scope_note'] == 'Current province fields.'


def test_more_specific_field_note_is_preserved_over_owner_note():
    class SpecificOwner(Owner):
        def catalog(self):
            result = super().catalog()
            result[0]['fields'][self.field]['scope_note'] = 'Field-specific limitation.'
            return result
    owners = [SpecificOwner('fort', 'visible_scope', 'General province scope.'),
              Owner('straits', 'static_rules', 'Static sea adjacency only.')]
    result = CompositeSource(Primary(), owners).catalog()[0]
    assert result['fields']['fort']['scope_note'] == 'Field-specific limitation.'
    assert result['fields']['fort']['visibility'] == 'visible_scope'
