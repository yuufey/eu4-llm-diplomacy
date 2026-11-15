from types import SimpleNamespace

from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.tests import test_information_trade_scenarios_integration as fixtures


def test_discovery_describes_bound_numeric_inputs_without_claiming_acquisition_gain():
    targets = SimpleNamespace(power_reader=SimpleNamespace(with_numeric_inputs=True))
    source = TradeScenarioSource(fixtures.FakeTradeBaseline(), target_reader=targets)
    field = source.catalog()[0]['fields']['targets']
    annotation = field['current_trade_power_annotation']
    assert annotation['numeric_modifier_inputs'] is True
    assert annotation['numeric_input_units']['province_trade_power_modifier'] == 'ratio'
    assert annotation['acquisition_delta_evaluated'] is False
    assert field['coverage'] == 'partial' and field['complete'] is False


def test_discovery_does_not_advertise_unbound_numeric_inputs():
    source = TradeScenarioSource(fixtures.FakeTradeBaseline(), target_reader=SimpleNamespace())
    assert 'current_trade_power_annotation' not in source.catalog()[0]['fields']['targets']
