"""Dates captured across a returned native executor, separate from binding dates."""
from typing import Any


CAPABILITY = 'native_result_game_date_observation'
GAME_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
BASIS = 'original_executor_same_game_date'
OUTCOMES = frozenset({'accepted', 'rejected', 'executed'})


def _date(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**31


def attach(event: dict, result: dict, *, enabled: bool) -> dict:
    """Copy timing only after the caller has validated the native result."""
    date = event.get('native_result_game_date_raw')
    bound_date = result.get('date_raw')
    if (enabled is not True or result.get('native_outcome') not in OUTCOMES
            or event.get('native_result_game_date_verified') is not True
            or event.get('native_result_date_basis') != BASIS
            or not _date(date) or not _date(bound_date) or date < bound_date):
        return result
    return dict(result, native_result_date={
        'status': 'known', 'game_date_raw': date, 'unit': 'game_date_raw', 'basis': BASIS})


def for_record(record: Any) -> int | None:
    """Use a stored result date only for its matching terminal request snapshot."""
    result, payload = getattr(record, 'result', None), getattr(record, 'payload', None)
    status = getattr(record, 'status', None)
    if (status not in OUTCOMES or getattr(record, 'submitted_at', None) is None
            or not isinstance(result, dict) or not isinstance(payload, dict)
            or result.get('native_outcome') != status
            or result.get('request_id') != getattr(record, 'request_id', None)
            or any(result.get(key) != payload.get(key) for key in ('action_id', 'actor', 'recipient'))
            or result.get('phase') != payload.get('phase', 'initiate')):
        return None
    metadata = result.get('native_result_date')
    if (not isinstance(metadata, dict) or metadata.get('status') != 'known'
            or metadata.get('unit') != 'game_date_raw' or metadata.get('basis') != BASIS):
        return None
    date, bound_date = metadata.get('game_date_raw'), result.get('date_raw')
    return date if _date(date) and _date(bound_date) and date >= bound_date else None
