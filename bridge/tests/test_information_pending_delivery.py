"""A pending external output is revalidated before its irreversible claim."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from bridge.information import InformationService
from bridge.tests.test_information_service import (
    FakeClock,FakeOutput,FakeSource,create_report,create_subscription,tick_results,
)


@pytest.mark.parametrize('change',['cancel','report','disable','source_unready'])
def test_control_change_before_external_delivery_claim_is_not_published(tmp_path,monkeypatch,change):
    source=FakeSource();output=FakeOutput();clock=FakeClock()
    service=InformationService(source,tmp_path/'pending.sqlite3',output=output,clock=clock)
    entered=threading.Event();release=threading.Event();original=service._deliver
    def wait_before_claim(result):
        entered.set()
        assert release.wait(timeout=4),'delivery gate timed out'
        return original(result)
    monkeypatch.setattr(service,'_deliver',wait_before_claim)
    report=create_report(service)
    subscription=create_subscription(service,report['id'],'pending-create',every=10)
    clock.advance(10)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            future=pool.submit(service.tick)
            try:
                assert entered.wait(timeout=2),'result did not reach pending delivery'
                if change=='cancel':
                    service.manage_subscription('pending-cancel','cancel',subscription_id=subscription['id'],
                                                expected_version=subscription['version'])
                elif change=='report':
                    service.manage_report('pending-report','update',report_id=report['id'],
                        expected_version=report['version'],config={
                            'name':'replacement','detail':report['detail'],'queries':report['queries']})
                elif change=='disable':
                    version=service.configure(None,'get')['config']['version']
                    service.configure('pending-disable','update',values={'enabled':False},expected_version=version)
                else:
                    context=source.context()
                    monkeypatch.setattr(source,'context',lambda:dict(context,status='unready'))
            finally:
                release.set()
            rows=tick_results(future.result(timeout=2))
        assert len(rows)==1 and rows[0]['delivery']['status']=='failed'
        assert rows[0]['delivery']['error']['code']=='subscription_changed_before_delivery'
        assert output.calls==0
        assert service.get_result(rows[0]['result_id'])['delivery']==rows[0]['delivery']
    finally:
        release.set();service.close()
