"""Missing sealed sources have explicit errors through the public routes."""
from contextlib import contextmanager
from pathlib import Path
import threading
from unittest.mock import Mock, patch

import pytest

from bridge import diplomacy_contract_v2 as contracts
from bridge.diplomacy_api import DiplomacyAPI
from bridge.diplomacy_service import make_server
from bridge.tests.test_diplomacy_contract_v2 import connection


@contextmanager
def server():
    instance = make_server(None, port=0)
    thread = threading.Thread(target=instance.serve_forever)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_missing_source_is_explicit_without_creating_it(tmp_path):
    missing = tmp_path / 'absent.json'
    with pytest.raises(contracts.ContractError) as raised:
        contracts.read_bounded(missing, 64)
    assert raised.value.code == 'source_unavailable'
    assert raised.value.status == 503
    assert 'absent.json' in str(raised.value)
    assert isinstance(raised.value.__cause__, FileNotFoundError)
    assert not missing.exists()


@pytest.mark.parametrize('failure', [PermissionError('denied'), OSError('read failed')])
def test_source_open_and_read_errors_are_explicit(failure):
    with patch.object(Path, 'open', side_effect=failure):
        with pytest.raises(contracts.ContractError) as raised:
            contracts.read_bounded(Path('sealed.json'), 64)
    assert raised.value.code == 'source_unavailable'
    assert raised.value.status == 503
    assert raised.value.__cause__ is failure


def test_read_error_closes_the_open_source():
    failure = OSError('read failed')
    with patch.object(Path, 'open') as opening:
        opening.return_value.__enter__.return_value.read.side_effect = failure
        with pytest.raises(contracts.ContractError) as raised:
            contracts.read_bounded(Path('sealed.json'), 64)
    assert raised.value.code == 'source_unavailable'
    assert raised.value.__cause__ is failure
    opening.return_value.__exit__.assert_called_once()


def test_source_budget_still_rejects_oversized_file(tmp_path):
    source = tmp_path / 'source.json'
    source.write_bytes(b'12345')
    with pytest.raises(contracts.ContractError) as raised:
        contracts.read_bounded(source, 4)
    assert raised.value.code == 'input_budget'
    assert raised.value.status == 500


@pytest.mark.parametrize('version', [2, 3])
@pytest.mark.parametrize('method,suffix', [('GET', 'actions'), ('GET', 'actions/offer_alliance'),
                                          ('POST', 'validate'), ('POST', 'requests')])
def test_missing_catalog_source_reports_503_through_versioned_routes(tmp_path, version, method, suffix):
    with patch.object(contracts, 'ROOT', tmp_path), server() as instance:
        status, result = connection(instance, method, f'/v{version}/{suffix}', value={})
    assert status == 503
    assert result['error']['code'] == 'source_unavailable'
    assert 'diplomacy_catalog.json' in result['error']['message']
    assert list(tmp_path.iterdir()) == []


def test_tampered_present_catalog_keeps_source_mismatch(tmp_path):
    source = tmp_path / 'bridge' / 'diplomacy_catalog.json'
    source.parent.mkdir()
    source.write_bytes(b'{}')
    with pytest.raises(contracts.ContractError) as raised:
        contracts.ContractCatalog(root=tmp_path)
    assert raised.value.code == 'source_mismatch'
    assert raised.value.status == 500


def test_failed_contract_initialization_can_recover_without_caching_a_failure():
    available = Mock()
    available.describe.return_value = {'status': 'available'}
    failure = contracts.ContractError('source_unavailable', 'Pinned source is unavailable')
    with patch.object(DiplomacyAPI, 'contract', side_effect=[failure, available]) as factory:
        with server() as instance:
            first_status, first = connection(instance, 'GET', '/v2/actions')
            second_status, second = connection(instance, 'GET', '/v2/actions')
            third_status, third = connection(instance, 'GET', '/v2/actions')
    assert first_status == 503 and first['error']['code'] == 'source_unavailable'
    assert second_status == third_status == 200
    assert second == third == {'status': 'available'}
    assert factory.call_count == 2


@pytest.mark.parametrize('code,status', [('unknown_action', 404), ('request_budget', 413),
    ('source_mismatch', 500), ('input_budget', 500), ('invalid_contract', 500),
    ('invalid_parameters', 422), ('unsupported_schema', 422), ('invalid_protocol', 400)])
def test_existing_error_statuses_are_preserved(code, status):
    assert contracts.ContractError(code, 'fixture').status == status
