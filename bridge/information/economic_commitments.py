"""Current bilateral subsidy obligations from the existing native records.

The identity-bound parent owns executable guards, observer admission and
two-pass sampling. The current date only evaluates the native expiry rule.
"""
from copy import deepcopy
from types import SimpleNamespace

from . import bilateral_subsidies_memory as _subsidies
from . import foreign_economy_projection as _projection
from . import observer_subsidies_memory as _observer
from . import subject_type_memory as _subjects


SUPPORT_FIELD = "R07.economic_support"
EXPIRY_FIELD = "R07.expiry"
FIELDS = (SUPPORT_FIELD, EXPIRY_FIELD)
SUBJECT_SPEC = {"overlord_fullref_offset": 0x18F0, "relation_table_offset": 0x1510,
                "relation_row_stride": 0x48, "subject_types_offset": 0x128,
                "subject_definition_offset": 0x40, "max_subject_types": 4096}


def _known(value, *, complete=True):
    return {"status": "known", "value": value, "scale": 1,
            "period": "current", "complete": complete, "partial": not complete}


def _date(raw):
    return {"status": "known", "value": raw, "unit": "game_date_raw"}


def _registered(contract):
    contracts = []
    if contract["present"]:
        contracts.append({
            "payer": {"tag": contract["payer"]["tag"]},
            "recipient": {"tag": contract["recipient"]["tag"]},
            "observer_role": contract["observer_role"],
            "monthly_nominal_amount": {key: deepcopy(contract["monthly_nominal_amount"][key])
                                       for key in ("raw", "value", "unit", "scale", "period")},
            "start_date": {"calendar": deepcopy(contract["start_date"]["calendar"])},
            "duration_years": {**deepcopy(contract["duration_years"]),
                               "value": contract["duration_years"]["raw"]},
            "displayed_end_date": {"calendar": deepcopy(contract["displayed_end_date"]["calendar"])},
        })
    return _projection._subsidies_pair_result(
        present=contract["present"], contracts=contracts,
        scope=_observer.SCOPE, basis=_observer.BASIS)


def _payer_eligible(reader, payer):
    method = reader.read

    def exact(address, size, label):
        raw = method(address, size, label)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError("SUBSIDY_PAYER_STATE_SHORT_READ")
        return raw

    reader = SimpleNamespace(read=exact)
    pointer = int(payer["country_pointer"], 0)
    parent = int.from_bytes(reader.read(pointer + 0x18F0, 8,
                                       "economic_commitments.payer_overlord"), "little")
    if parent >> 56 == 0:
        return True
    rebound, definition = _subjects.read_definition(reader, pointer, SUBJECT_SPEC)
    if rebound != parent:
        raise ValueError("SUBSIDY_PAYER_SUBJECT_CHANGED")
    if definition == 0:
        return False
    flags = {offset: reader.read(definition + offset, 1,
                                f"economic_commitments.subject_flag_{offset:x}") != b"\0"
             for offset in (0x11B, 0x14B, 0x121, 0x13E, 0x151, 0x148)}
    return (flags[0x11B] and flags[0x14B] and not flags[0x121]
            and not flags[0x13E] and not flags[0x151] and flags[0x148])


def read_fields(reader, module_base, observer, target, requested, *, observed_date):
    """Read one observer/target pair and project active subsidy terms and expiry.

    Registered terms remain available when a subject-definition read fails.
    No contract is a known empty current obligation for this selected pair.
    """
    options = {'logical_observer': observer['tag']} if observer['tag'] != 'FRA' else {}
    state = _subsidies.read_state(reader, module_base, observer, target, **options)
    if state["status"] != "known":
        return {field: {"status": "unknown", "reason": state.get("reason", "SUBSIDY_STATE_UNKNOWN")}
                for field in requested}
    contract = state["contract"]
    registered = _registered(contract)
    obligations, expiries = [], []
    problem = None
    try:
        if contract["present"]:
            object_row = next(row for row in state["raw_inputs"]["ordered_read_trace"]
                              if row["label"] == "contract.relation_object")
            removed = bytes.fromhex(object_row["raw_hex"])[0x28] != 0
            end = contract["displayed_end_date"]["raw"]
            payer = observer if contract["payer"]["tag"] == observer["tag"] else target
            method = getattr(reader, "read", reader)
            if not removed and observed_date <= end and _payer_eligible(SimpleNamespace(read=method), payer):
                amount = contract["monthly_nominal_amount"]["raw"]
                obligation = {
                    "kind": "subsidy", "payer": contract["payer"]["tag"],
                    "recipient": contract["recipient"]["tag"],
                    "monthly_amount": {"status": "known", "value": amount, "raw": amount,
                                       "unit": "ducats", "scale": 1000, "period": "month"},
                    "start_date": _date(contract["start_date"]["raw"]), "end_date": _date(end),
                    "expiry_comparison": "current_game_date > end_date",
                }
                obligations.append(obligation)
                expiries.append({key: deepcopy(obligation[key]) for key in (
                    "kind", "payer", "recipient", "end_date", "expiry_comparison")})
    except Exception as exc:
        problem = "SUBSIDY_CURRENT_OBLIGATION_UNKNOWN:" + type(exc).__name__
    active = ({"status": "unknown", "reason": problem} if problem else _known(obligations))
    support = _known({"registered_subsidy_evidence": registered,
                      "active_payment_obligations": active,
                      "other_economic_support": {"status": "unsupported",
                                                 "reason": "OTHER_ECONOMIC_SUPPORT_NOT_IMPLEMENTED"}},
                     complete=False)
    expiry = {"status": "unknown", "reason": problem} if problem else _known(expiries)
    fields = {SUPPORT_FIELD: support, EXPIRY_FIELD: expiry}
    return {field: fields[field] for field in requested}
