"""Current bilateral war-reparations obligations and their native deadline."""
from copy import deepcopy

from . import bilateral_reparations_memory as _relations
from . import observer_reparations_memory as _observer


SUPPORT_FIELD = "R07.economic_support"
EXPIRY_FIELD = "R07.expiry"
FIELDS = (SUPPORT_FIELD, EXPIRY_FIELD)
INCOME_FACTOR_RVA = 0x233E048


def _known(value, *, complete=True):
    return {"status": "known", "value": value, "scale": 1,
            "period": "current", "complete": complete, "partial": not complete}


def _date(raw):
    return {"status": "known", "value": raw, "unit": "game_date_raw"}


def _read(reader, address, size, label):
    method = getattr(reader, "read", reader)
    raw = method(address, size, label)
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
        raise ValueError("REPARATIONS_COMMITMENT_SHORT_READ")
    return bytes(raw)


def _registered(contract):
    contracts = []
    if contract["present"]:
        contracts.append({
            "payer": {"tag": contract["payer"]["tag"]},
            "claimant": {"tag": contract["claimant"]["tag"]},
            "start_date": {"calendar": deepcopy(contract["start_date"]["calendar"])},
            "end_date": {"calendar": deepcopy(contract["end_date"]["calendar"])},
        })
    return {
        "status": "known", "scope": "observer_target_pair_only",
        "unit": "bilateral_reparations_relation", "scale": 1, "period": "current",
        "complete_country_contracts": False,
        "pair_relation": {"status": "known", "present": contract["present"]},
        "contracts": contracts,
        "visibility": {"scope": _observer.SCOPE, "basis": _observer.BASIS,
                       "actual_UI_observed": False},
    }


def _income_percent(reader, module_base):
    try:
        raw = int.from_bytes(_read(reader, module_base + INCOME_FACTOR_RVA, 4,
                                   "reparations_commitments.income_factor"),
                             "little", signed=True)
        # The native factor uses thousandths. A percent uses ten raw units.
        return {"status": "known", "value": raw, "raw": raw,
                "unit": "percent", "scale": 10, "period": "month"}
    except Exception as exc:
        return {"status": "unknown", "reason": "REPARATIONS_INCOME_FACTOR_UNKNOWN:" + type(exc).__name__}


def read_fields(reader, module_base, observer, target, requested, *, observed_date):
    """Reuse the validated pair graph and evaluate its current native terms."""
    options = {'logical_observer': observer['tag']} if observer['tag'] != 'FRA' else {}
    state = _relations.read_state(reader, module_base, observer, target, observed_date, **options)
    reason = state.get("reason") if state["status"] != "known" else None
    if reason is None:
        directions = state["raw_inputs"]["pair_directions"]
        owners = tuple(hex(int(binding["country_pointer"], 0) + 0x14F8)
                       for binding in (observer, target))
        if tuple(row["owner"] for row in directions) != owners:
            reason = "PAIR_OWNER_NOT_ECONOMY_VECTOR"
    if reason:
        return {field: {"status": "unknown", "reason": reason} for field in requested}

    contract = state["contract"]
    obligations, expiries = [], []
    problem = None
    complete = True
    try:
        if contract["present"]:
            pointer = int(state["raw_inputs"]["pair_directions"][0]["target_pointer"], 0)
            removed = _read(reader, pointer + 0x28, 1,
                            "reparations_commitments.cancelled") != b"\0"
            if not removed and observed_date < contract["end_date"]["raw"]:
                percent = _income_percent(reader, module_base)
                complete = percent["status"] == "known"
                obligation = {
                    "kind": "war_reparations", "payer": contract["payer"]["tag"],
                    "recipient": contract["claimant"]["tag"], "income_percent": percent,
                    "start_date": _date(contract["start_date"]["raw"]),
                    "end_date": _date(contract["end_date"]["raw"]),
                    "expiry_comparison": "current_game_date >= end_date",
                }
                obligations.append(obligation)
                expiries.append({key: deepcopy(obligation[key]) for key in (
                    "kind", "payer", "recipient", "end_date", "expiry_comparison")})
    except Exception as exc:
        problem = "REPARATIONS_CURRENT_OBLIGATION_UNKNOWN:" + type(exc).__name__
    active = ({"status": "unknown", "reason": problem} if problem
              else _known(obligations, complete=complete))
    fields = {
        SUPPORT_FIELD: _known({"registered_reparations_evidence": _registered(contract),
                               "active_payment_obligations": active}, complete=False),
        EXPIRY_FIELD: ({"status": "unknown", "reason": problem} if problem else _known(expiries)),
    }
    return {field: fields[field] for field in requested}
