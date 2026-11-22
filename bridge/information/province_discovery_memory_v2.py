"""Private positive-domain sweep with typed, length-bounded native bitmaps.

Reuse the original observer/session admission, indexed record validation,
budgets and two-pass consistency checks. Domain completeness and zero's
public semantics remain unresolved, so this version is not a public Source.
"""
from . import province_discovery_memory as _base
from .province_discovery_bitmap_memory import read_discovery

SCHEMA = 'information.province_discovery_memory.v2'


def read_two_pass(reader, module_base, observer='FRA', *, observer_scoped=False):
    result = _base._read_two_pass(reader, module_base, observer,
        discovery_reader=read_discovery, candidate_bytes=32, use_observed_country_count=True,
        observer_scoped=observer_scoped)
    result['schema'] = SCHEMA
    result['scope']['bitmap_words_native_length_bounded'] = True
    if result['status'] == 'known':
        result['basis'] = 'stable_native_bounded_discovery_bits_for_indexed_positive_id_candidates'
    return result


__all__ = ['read_two_pass', 'SCHEMA']
