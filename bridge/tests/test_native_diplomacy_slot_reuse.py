"""Compile the production frame recycler and entry match with the actual ledger."""
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "work" / "native"


def test_frame_recycles_terminal_diplomacy_slots(tmp_path):
    compiler = shutil.which("g++")
    if not compiler:
        pytest.skip("native diplomacy fixture requires g++")
    execution = (NATIVE / "alliance-execution.inc").read_text(encoding="utf-8")
    match = execution[execution.index("static bool execution_binding_matches("):
                      execution.index("static int execution_find_target(")]
    release = execution[execution.index("static bool execution_release_pending("):
                        execution.index("static bool execution_commit_pending(")]
    reclaim = execution[execution.index("static void execution_reclaim_bindings("):
                        execution.index("static bool execution_preflight(")]
    source = tmp_path / "slot_reuse.cpp"
    binary = tmp_path / "slot_reuse.exe"
    source.write_text(r'''
#include <cassert>
#include <cstdio>
#include "alliance-authority-ledger.h"
using namespace bridge::alliance_authority;

constexpr unsigned kBindingCapacity=64;
struct ExecutionBinding {
    bool used=false, consumed=false, invalidated=false, response_queued=false;
    bool inbound_response_request=false, pending_reservation=false;
    uint64_t pending_proposal_id=0, pending_generation=0;
    SeedReceipt seed{};
    Phase phase=Phase::initiate;
    AlliancePayload payload{};
    ObjectRef target_wrapper{}, target_action{};
    NativeHeader final_entry_header{};
};
struct ProtocolWrapperShape {
    bool identity=true, readable=true;
    uintptr_t address=0, action=0;
    NativeHeader header{};
};
static NativeHeader execution_header(const ProtocolWrapperShape& shape) {
    return shape.header;
}
static AllianceAuthorityLedger execution_ledger(1);
static ExecutionBinding execution_bindings[kBindingCapacity]{};
static struct { bool active=false; } execution_sender_scope, execution_response_scope;
static bool execution_entry_in_progress=false;
static bool reservation_lock_available=true;
static unsigned released_reservations=0;
static bool inbound_pending_release(uint64_t id,uint64_t generation) {
    assert(id==17 && generation==19);
    if (!reservation_lock_available) return false;
    ++released_reservations;
    return true;
}
static void execution_peace_pending_results() {}
static bool execution_peace_defer_result(const ExecutionBinding&) { return false; }
''' + match + release + reclaim + r'''
static SeedReceipt seed(unsigned slot,const char* id,uint64_t now,uint64_t serial) {
    auto& binding=execution_bindings[slot];
    assert(!binding.used);
    binding.used=true;
    binding.payload=AlliancePayload{1,1,2,10,10,30,0,1,0};
    const auto seeded=execution_ledger.seed(Context{1,now},id,binding.payload,binding.phase,
        ObjectRef{0x10000u+slot*4,serial},ObjectRef{0x20000u+slot*4,serial},now+10);
    assert(seeded.result.ok());
    return binding.seed=seeded.receipt;
}

int main() {
    auto first=seed(0,"needs-release",1,1);
    auto& pending=execution_bindings[0];
    pending.inbound_response_request=true;
    pending.pending_reservation=true;
    pending.pending_proposal_id=17;
    pending.pending_generation=19;
    seed(1,"later",8,2);
    execution_reclaim_bindings(Context{1,9});
    assert(pending.used && execution_bindings[1].used);
    reservation_lock_available=false;
    execution_reclaim_bindings(Context{1,12});
    assert(pending.used && execution_bindings[1].used);
    reservation_lock_available=true;
    execution_entry_in_progress=true;
    execution_reclaim_bindings(Context{1,12});
    assert(pending.used && released_reservations==0);
    execution_entry_in_progress=false;
    execution_reclaim_bindings(Context{1,12});
    assert(!pending.used && released_reservations==1 && execution_bindings[1].used);
    execution_reclaim_bindings(Context{1,19});
    assert(!execution_bindings[1].used);

    for (unsigned i=0;i<160;++i) {
        char id[65]{};
        std::snprintf(id,sizeof(id),"completed-%u",i);
        const Context current{1,20u+i};
        auto serial=10u+i;
        const auto receipt=seed(0,id,current.current_tick,serial);
        auto& binding=execution_bindings[0];
        const ObjectRef source{0x10000u,serial}, action{0x20000u,serial};
        const ObjectRef incoming{0x30000u,serial}, loaded_action{0x40000u,serial};
        const NativeHeader header{0x1234,5,serial};
        assert(execution_ledger.serializer(current,receipt,binding.phase,source,action,
            binding.payload,header).ok());
        const auto claim=execution_ledger.incoming_preclone(current,receipt,binding.phase,
            incoming,loaded_action,header,binding.payload,true);
        assert(claim.result.ok());
        binding.target_wrapper={0x50000u,serial};
        binding.target_action={0x60000u,serial};
        binding.final_entry_header={0xffffu,0,serial};
        const CloneProof proof{incoming,loaded_action,binding.target_wrapper,binding.target_action,
            binding.payload,kTransferCloneHeader,binding.final_entry_header};
        assert(execution_ledger.postclone(current,claim.ticket,binding.phase,proof).ok());
        ProtocolWrapperShape entry{true,true,0x50000u,0x60000u,{0xffffu,0,serial-1u}};
        assert(!execution_binding_matches(binding,entry));
        entry.header.seq=serial;
        assert(execution_binding_matches(binding,entry));
        assert(execution_ledger.consume_entry(current,claim.ticket,binding.phase,
            binding.target_wrapper,binding.target_action,binding.payload,entry.header).ok());
        binding.consumed=true;

        execution_response_scope.active=true;
        execution_reclaim_bindings(current);
        assert(binding.used);
        execution_response_scope.active=false;
        execution_reclaim_bindings(current);
        assert(!binding.used && receipt.slot==first.slot);
        assert(execution_ledger.inspect(current,receipt).result.code==ErrorCode::claim_mismatch);
        assert(execution_ledger.seed(current,"completed-0",
            AlliancePayload{1,1,2,10,10,30,0,1,0},Phase::initiate,
            ObjectRef{0x10000u,serial},ObjectRef{0x20000u,serial},current.current_tick+10)
            .result.code==ErrorCode::duplicate_request);
    }
}
''', encoding="utf-8")
    build = subprocess.run(
        [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fno-exceptions", "-I", str(NATIVE), str(source), "-o", str(binary)],
        capture_output=True, text=True, timeout=45,
    )
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stderr
