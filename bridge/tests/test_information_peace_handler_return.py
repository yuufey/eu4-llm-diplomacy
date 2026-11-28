"""Run the production post-consumption boundary and peace formatter with stubs."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from bridge.tests.legacy_france_adapter import FixedFranceDiplomacyTools as DiplomacyTools, FixedFranceObserverSession as ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_native_results import ArchivedSession, result_query
from bridge.tests.test_peace_inbound_tools import inbound_response, inbound_submission


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def handler_fixture(tmp_path_factory):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('native peace handler fixture requires the existing C++ compiler')
    execution = (ROOT / 'work/native/alliance-execution.inc').read_text(encoding='utf-8')
    peace = (ROOT / 'work/native/peace-execution.inc').read_text(encoding='utf-8')
    start = execution.index('static bool execution_call_original(')
    original = execution[start:execution.index('static bool execution_consume_target(', start)]
    start = execution.index('struct ExecutionGameDate {')
    date_struct = execution[start:execution.index('struct ExecutionBinding {', start)]
    start = execution.index('static ExecutionGameDate execution_game_date(')
    date_helpers = execution[start:execution.index('static bool execution_set_inbound_response_paths(', start)]
    start = execution.index('        const ExecutionGameDate result_date_begin=execution_game_date();',
                            execution.index('extern "C" int bridge_execution_execute('))
    boundary = execution[start:execution.index('        if (binding.sender) {', start)]
    start = peace.index('static void execution_peace_inbound_unknown(')
    formatter = peace[start:peace.index('static ExecutionBinding execution_peace_deferred_binding(', start)]
    start = peace.index('struct ExecutionPeaceDeferredResult')
    spool = peace[start:peace.index('static bool execution_peace_seen_request_id(', start)]
    start = peace.index('static bool execution_peace_defer_result(')
    spool += peace[start:peace.index('static bool execution_peace_set_paths(', start)]
    start = peace.index('static ExecutionBinding execution_peace_deferred_binding(')
    spool += peace[start:peace.index('static void execution_peace_tick(', start)]
    preamble = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
enum class ActionFamily { peace, alliance };
struct Payload { ActionFamily family=ActionFamily::peace; int32_t state34=2; };
struct PeaceRequest {
    char request_id[65]="synthetic-peace-return";
    char action_id[25]="white_peace";
    char actor[4]="ENG",recipient[4]="FRA";
    int32_t date_raw=56566512;
    bool white_peace=true;
};
struct ResponseRequest {
    char session_id[28]="synthetic-peace-session";
    char request_id[65]="synthetic-peace-return";
    char original_actor[4]="ENG",decision[7]="accept";
    char decision_country[4]="FRA";
    int32_t date_raw=56566512;
};
struct ExecutionBinding {
    bool used=true,response_queued=false;
    bool sender=true,consumed=true,transport_verified=true,invalidated=false;
    bool inbound_response_request=true,alliance_before_verified=true,alliance_before=true;
    bool peace_handler_returned=false,peace_effects_supported=false;
    uint64_t pending_proposal_id=10,pending_generation=12;
    Payload payload{};
    PeaceRequest peace_request{};
    ResponseRequest response_request{};
    char peace_war_id[30]="war_0123456789abcdef_00000001";
    int peace_effects_before=0;
};
namespace bridge_alliance_inbound_detail { constexpr unsigned kQueueCapacity=64; }
using AlliancePayload=Payload;
using PeaceExecutionRequest=PeaceRequest;
using PeaceEffectState=int;
static bool pending_readable=false,pending_active=true,pending_retained=true,war_readable=false;
static bool inbound_pending_is_active(uint64_t id,uint64_t generation,bool& active,bool* retained) {
    assert(id==10 && generation==12);
    active=pending_active;
    *retained=pending_retained;
    return pending_readable;
}
static bool execution_peace_war_state(const Payload&,bool& active) {
    active=false;
    return war_readable;
}
struct ResponseScope { bool active=false;unsigned parent_slot=13; };
static ResponseScope execution_response_scope{};
static void* execution_entry_original=nullptr;
static void* bridge_response_original=nullptr;
static ExecutionBinding* active_binding=nullptr;
static unsigned entry_forwards=0,fallback_forwards=0,invalidations=0;
static uintptr_t base=0x140000000,game_address=0x300000;
static int32_t current_date=56566584;
static bool game_readable=true,date_readable=true;
static std::string selected_mode;
template<class T> static bool read(uintptr_t address,T& value) {
    if (address==base+0x233fe58) { value=static_cast<T>(game_address);return game_readable; }
    if (address==game_address+0x1dd0) { value=static_cast<T>(current_date);return date_readable; }
    return false;
}
static void native_body() {
    assert(active_binding && !active_binding->peace_handler_returned);
    assert(execution_response_scope.active && execution_response_scope.parent_slot==0);
    execution_response_scope={true,77};
    if (selected_mode=="date_changed") current_date+=24;
    if (selected_mode=="world_changed") game_address+=0x10000;
}
static void native_entry(void*) { ++entry_forwards;native_body(); }
static void native_fallback(void*) { ++fallback_forwards;native_body(); }
static void execution_mark_invalid(ExecutionBinding& binding) {
    binding.invalidated=true;++invalidations;
}
static void line(const char* value) { std::cout<<value; }
static unsigned GetCurrentProcessId() { return 1; }
static uint64_t observation_creation=1234;
struct InboundContext {
    bool complete=true,white=true;
    char json[512]=R"json({"war_id":"war_0123456789abcdef_00000001","direction":"demand","original_actor":"ENG","original_recipient":"FRA","terms":[],"white_peace":true,"complete":true,"selected_terms_complete":true,"reason":"none"})json";
};
static InboundContext execution_peace_inbound_context(const Payload&,const char*,void*,const PeaceRequest*) {
    return {};
}
static char effects_json[32]="null";
struct PeaceEffectSummary {
    char* json=effects_json;
    size_t capacity=sizeof(effects_json);
    bool terms_verified=true;
    const char* text() const { return json; }
};
static PeaceEffectSummary execution_peace_effects_json(int,const PeaceRequest&,bool) { return {}; }
struct PeaceExecutionEventBuffer {
    std::vector<char> storage;
    char* text;
    size_t capacity;
    explicit PeaceExecutionEventBuffer(size_t size):storage(size),text(storage.data()),capacity(size) {}
};
static void execution_peace_parameters_json(const PeaceRequest&,char* output) {
    std::strcpy(output,"\"parameters\":{}");
}
'''
    runner = r'''
static ExecutionGameDate saved_begin{};
static int run_target(ExecutionBinding& binding) {
    Payload payload=binding.payload;
    int target_slot=0;
    void* value=&binding;
BOUNDARY
    saved_begin=result_date_begin;
    return 1;
}
int main(int argc,char** argv) {
    const std::string mode=argc>1?argv[1]:"accept";
    selected_mode=mode;
    game_readable=mode!="game_failure";
    date_readable=mode!="date_failure";
    ExecutionBinding binding{};
    active_binding=&binding;
    execution_entry_original=reinterpret_cast<void*>(&native_entry);
    bridge_response_original=reinterpret_cast<void*>(&native_fallback);
    if (mode=="fallback") execution_entry_original=nullptr;
    if (mode=="missing") { execution_entry_original=nullptr;bridge_response_original=nullptr; }
    if (mode=="other_family") binding.payload.family=ActionFamily::alliance;
    if (mode=="reject") std::strcpy(binding.response_request.decision,"reject");
    const int returned=run_target(binding);
    assert(!execution_response_scope.active && execution_response_scope.parent_slot==13);
    if (mode=="unbound") binding.transport_verified=false;
    if (mode=="spool_reused" || mode=="spool_gone" || mode=="spool_removal_proven") {
        assert(execution_peace_defer_result(binding));
        std::strcpy(binding.response_request.request_id,"reused-by-another-request");
        execution_peace_pending_results(); // Locked or unreadable pending list.
        pending_readable=true;
        execution_peace_pending_results(); // Still present in the native list.
        if (mode=="spool_removal_proven") {
            pending_active=false;
            execution_peace_pending_results(); // Removal proven; war read unavailable.
        }
        const bool still_found=mode=="spool_reused";
        pending_readable=still_found;
        pending_retained=still_found;
        pending_active=false;
        war_readable=true;
        execution_peace_pending_results();
        execution_peace_pending_results(); // Results are emitted once.
    } else if (mode=="flush_later" || mode=="tight_buffer" || mode=="line_budget") {
        const int32_t captured=execution_result_game_date(&saved_begin);
        current_date+=240;
        char small[32]="{\"outcome\":\"accepted\"}\n";
        char large[512]="{\"outcome\":\"accepted\"}\n";
        if (mode=="line_budget") {
            const std::string text="{\"outcome\":\"accepted\",\"padding\":\""
                +std::string(256u*1024u-82u,'x')+"\"}\n";
            std::vector<char> buffer(256u*1024u+512u,0);
            assert(text.size()<buffer.size());
            std::memcpy(buffer.data(),text.data(),text.size());
            execution_result_line(buffer.data(),buffer.size(),captured);
        } else if (mode=="tight_buffer") execution_result_line(small,sizeof(small),captured);
        else execution_result_line(large,sizeof(large),captured);
    } else if (mode!="other_family")
        execution_peace_response(binding,mode=="reject"?1:2,mode=="reject",
            mode!="unverified",mode!="pending_active",mode=="deferred"?nullptr:&saved_begin);
    std::cout<<"{\"fixture_stats\":true,\"entry_forwards\":"<<entry_forwards
        <<",\"fallback_forwards\":"<<fallback_forwards<<",\"invalidations\":"<<invalidations
        <<",\"target_returned\":"<<returned<<",\"peace_handler_returned\":"
        <<(binding.peace_handler_returned?"true":"false")<<"}\n";
}
'''.replace('BOUNDARY', boundary)
    directory = tmp_path_factory.mktemp('peace-handler-return')
    source = directory / 'fixture.cpp'
    executable = directory / 'fixture.exe'
    source.write_text(preamble + date_struct + date_helpers + original + formatter + spool + runner,
                      encoding='utf-8')
    built = subprocess.run([compiler, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(executable)], capture_output=True, text=True,
                           cwd=ROOT, timeout=45)
    assert built.returncode == 0, built.stderr
    return executable


@pytest.mark.parametrize('mode,outcome', [
    ('spool_reused', 'accepted'),
    ('spool_gone', 'unknown'),
    ('spool_removal_proven', 'accepted'),
])
def test_pending_peace_result_keeps_evidence_after_slot_reuse(handler_fixture, mode, outcome):
    result = subprocess.run([str(handler_fixture), mode], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    response, stats = [json.loads(line) for line in result.stdout.splitlines()]
    assert response['request_id'] == 'synthetic-peace-return'
    assert response['outcome'] == outcome
    assert stats['entry_forwards'] == 1


@pytest.mark.parametrize('mode,outcome,forwards,returned,invalidations', [
    ('accept', 'accepted', (1, 0), True, 0),
    ('reject', 'rejected', (1, 0), True, 0),
    ('fallback', 'accepted', (0, 1), True, 0),
    ('missing', 'unknown', (0, 0), False, 1),
    ('pending_active', 'unknown', (1, 0), True, 0),
    ('unverified', 'unknown', (1, 0), True, 0),
    ('unbound', 'unknown', (1, 0), True, 0),
    ('other_family', None, (1, 0), False, 0),
])
def test_production_return_boundary_controls_native_peace_result(
        handler_fixture, mode, outcome, forwards, returned, invalidations):
    result = subprocess.run([str(handler_fixture), mode], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    stats = rows[-1]
    assert (stats['entry_forwards'], stats['fallback_forwards']) == forwards
    assert stats['invalidations'] == invalidations
    assert stats['peace_handler_returned'] is returned
    assert stats['target_returned'] == (0 if mode == 'missing' else 1)
    if outcome is None:
        assert len(rows) == 1
    else:
        event = rows[0]
        assert event['outcome'] == outcome
        assert event['response_verified'] is (outcome != 'unknown')
        assert event['execution_verified'] is (outcome != 'unknown')
        parsed = ObserverSession._public_native_inbound_response_result(
            event, event['request_id'], event['session_id'], event['actor'], event['phase'],
            event['date_raw'], 1, 'peace_offer')
        if outcome == 'unknown':
            assert parsed is None
        else:
            assert parsed['native_outcome'] == outcome


def white_response():
    event = inbound_response()
    event['peace_context'] = dict(event['peace_context'], terms=[], white_peace=True)
    return event


@pytest.mark.parametrize('field', ['response_verified', 'request_binding_verified', 'war_state_verified'])
@pytest.mark.parametrize('outcome', ['accepted', 'unknown'])
def test_false_verification_cannot_be_promoted_to_acceptance(field, outcome):
    event = white_response()
    event.update(outcome=outcome, terms_verified=False)
    event[field] = False
    assert ObserverSession._public_native_inbound_response_result(
        event, event['request_id'], event['session_id'], 'ENG', 'accept', event['date_raw'],
        1, 'peace_offer') is None


def test_verified_white_response_keeps_native_unknown():
    event = white_response()
    event.update(outcome='unknown', terms_verified=False)
    parsed = ObserverSession._public_native_inbound_response_result(
        event, event['request_id'], event['session_id'], 'ENG', 'accept', event['date_raw'],
        1, 'peace_offer')
    assert parsed['native_outcome'] == 'unknown' and parsed['terms_verified'] is False


def test_nonwhite_null_effects_still_require_term_evidence():
    event = inbound_response(effects=None)
    assert ObserverSession._public_native_inbound_response_result(
        event, event['request_id'], event['session_id'], 'ENG', 'accept', event['date_raw'],
        1, 'peace_offer') is None


@pytest.mark.parametrize('mode,expected', [
    ('accept', 'accepted'), ('reject', 'rejected'), ('missing', 'unknown'),
    ('pending_active', 'unknown'), ('unverified', 'unknown'), ('unbound', 'unknown'),
])
def test_native_formatter_output_reaches_journal_and_normal_event_tools(
        handler_fixture, tmp_path, monkeypatch, mode, expected):
    ran = subprocess.run([str(handler_fixture), mode], capture_output=True, text=True, timeout=10)
    assert ran.returncode == 0, ran.stderr
    event = json.loads(ran.stdout.splitlines()[0])
    archive = json.loads((ROOT / 'bridge/tests/fixtures/peace_inbound_r44d_real_accept.json').read_text())
    ack = deepcopy(archive['events'][0]['event'])
    ack.update(event='diplomacy_observer_installed', session_id=event['session_id'],
               version=41, native_inbound_alliance=True)
    fixture = {'source': {'session_id': event['session_id'], 'dll_sha256': 'a' * 64}}
    session = ArchivedSession(tmp_path, fixture)
    monkeypatch.setattr(session, 'health', lambda: {
        'status': 'ready', 'date_raw': event['date_raw'], 'complete': True, 'reasons': []})
    submission = inbound_submission(request_id=event['request_id'], session_id=session.session_id,
                                   phase=event['phase'], date_raw=event['date_raw'])
    (tmp_path / 'control-probe.jsonl').write_text(
        ''.join(json.dumps(row) + '\n' for row in (ack, submission, event)), encoding='utf-8')
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', session.experiment_id, session.session_id)) as journal:
        request_id = event['request_id']
        journal.register(request_id, {
            'action_id': 'peace_offer', 'actor': 'ENG', 'recipient': 'FRA', 'phase': event['phase'],
            'parameters': {'proposal_id': 'a' * 32}})
        for status in ('queued', 'consumed', 'constructed'):
            journal.transition(request_id, status)
        claim = journal.claim_submission(request_id)
        receipt = ObserverSession._public_native_inbound_submission_receipt(
            submission, request_id, 'ENG', event['phase'], event['date_raw'], 'peace_offer')
        journal.mark_submitted(request_id, claim.claim_token, receipt)
        source = DiplomacySource(DiplomacyTools(journal, session))
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            query = result_query(request_id)
            query['parameters'] = {}
            report = tools.call('information_manage_report', {
                'request_id': 'handler-report', 'operation': 'create',
                'config': {'name': 'native handler return', 'queries': [query], 'detail': 'full'},
            })['report']
            tools.call('information_manage_subscription', {
                'request_id': 'handler-subscription', 'operation': 'create', 'config': {
                    'name': 'native handler return', 'kind': 'event', 'report_id': report['id'],
                    'enabled': True, 'event': {'types': ['diplomatic_request_result']},
                },
            })
            delivered = tools.call('information_tick', {"view": "full"})['results']
            assert len(delivered) == 1
            fields = delivered[0]['items'][0]['fields']
            assert fields['game_outcome']['value'] == expected
            assert journal.lookup_request(request_id).status == (
                'submitted' if expected == 'unknown' else expected)
            assert delivered[0]['event']['game_date'] is None
            assert tools.call('information_tick', {"view": "full"})['results'] == []
            result_id = delivered[0]['result_id']
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(result_id)['items'] == delivered[0]['items']

