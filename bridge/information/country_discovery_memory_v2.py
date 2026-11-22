"""Existing ordinary-country candidates known to the logical observer.

This preserves the original private knowledge-only reader, adding the native
exists predicate before capital reads. Excluded table classes remain outside
the supported domain; this list does not claim complete map or UI visibility.
"""
from . import country_discovery_memory as _base
from .country_existence_memory import read_existence

SCHEMA = 'information.country_discovery_memory.v2'


def read_two_pass(reader, module_base, observer='FRA', *, observer_scoped=False):
    result = _base._read_two_pass(reader, module_base, observer, existence_reader=read_existence,
                                  observer_scoped=observer_scoped)
    result['schema'] = SCHEMA
    return result


__all__ = ['SCHEMA', 'read_two_pass']
