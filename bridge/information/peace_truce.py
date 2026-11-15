"""Rule-based direct truce prediction for a selected peace offer."""
from .engine_dates import project_engine_date
from .truce_date_math import adjustment_months, direct_truce_expiry


def project_new_truce(inspection, rules, context):
    cost = inspection.get('costs', {}).get('war_score', {})
    cap = inspection.get('war_context', {}).get('war_score', {}).get('max_score', {})
    for metric in (cost, cap):
        if (type(metric.get('value')) is not int or metric.get('unit') != 'war_score_point'
                or metric.get('scale') != 1 or metric.get('scale_verified') is not True):
            return {'status': 'unknown', 'reason': 'PEACE_WAR_SCORE_COST_OR_CAP_UNAVAILABLE'}
    values = rules['values']
    base, scaled = values.get('TRUCE_YEARS'), values.get('SCALED_TRUCE_YEARS')
    if type(base) is not int or type(scaled) is not int:
        return {'status': 'unknown', 'reason': 'PEACE_TRUCE_RULES_UNAVAILABLE'}
    # 9765a0 stores the clamped score in each direction's signed-byte input.
    clamped = min(max(cost['value'], 0), cap['value'])
    adjustment = (clamped + 128) % 256 - 128
    try:
        expiry = direct_truce_expiry(context['game_date'], adjustment, scaled, base)
        months = adjustment_months(adjustment, scaled, base)
    except (ValueError, KeyError):
        return {'status': 'unknown', 'reason': 'PEACE_TRUCE_DATE_PROJECTION_UNAVAILABLE'}
    return {'status': 'known', 'complete': True, 'value': {
        'if_signed_on': project_engine_date(context['game_date'])['date'],
        'estimated_until': expiry['date']}, 'calculation': {
            'aggregate_war_score': cost['value'], 'maximum_war_score': cap['value'],
            'adjustment_signed_i8': adjustment, 'base_years': base,
            'scaled_years': scaled, 'duration_months': months, 'raw_expiry': expiry['raw']},
        'basis': 'selected_offer_direct_truce_rules_at_current_date'}
