#include "information-support-subject-record-entry-plan.h"

namespace support_subject_record_observer {
namespace plan = information::support_subject_record::entry;
namespace relation = relation_change_observer;
namespace owned = information::relation_change;
using Payload = bridge::alliance_authority::AlliancePayload;
using Original = uintptr_t(*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t);
struct Family final {
    owned::Kind kind;
    bridge::alliance_authority::ActionFamily family;
    uintptr_t table_rva;
    relation::Path enable, disable;
};
static constexpr Family families[] = {
    {owned::Kind::support_independence,bridge::alliance_authority::ActionFamily::support_independence,
     0x1c80570,relation::Path::support_record_enable,relation::Path::support_record_disable},
    {owned::Kind::subject,bridge::alliance_authority::ActionFamily::vassalization,
     0x1c81758,relation::Path::subject_record_enable,relation::Path::subject_record_disable}
};
struct Hook final {
    Original original = nullptr;
    plan::Plan image{};
    unsigned char* executable = nullptr;
    RUNTIME_FUNCTION unwind{};
    bool table_registered = false;
};
struct Pair final { owned::Kind kind{}; uint64_t actor = 0, recipient = 0; };
struct Pending final {
    relation::Value value{};
    uintptr_t actor_country = 0, recipient_country = 0;
    bool observed = false, ready = false;
};
static Hook hooks[5]{};
static bridge_entry_patch::PatchPlan patch{};
static bool published = false;
static std::atomic<bool> installed{false};
static thread_local Pair active_pairs[16]{};
static thread_local unsigned active_count = 0;

static bool snapshot(const Family& family,uint64_t actor,uint64_t recipient,
                     owned::Snapshot& output) noexcept {
    Payload payload{};
    payload.family = family.family;
    payload.actor10 = actor;
    payload.recipient20 = recipient;
    if (!relation::snapshot(payload,family.kind,output)) return false;
    if (family.kind == owned::Kind::subject) return true;
    owned::Snapshot reverse{};
    payload.actor10 = recipient;
    payload.recipient20 = actor;
    return relation::snapshot(payload,family.kind,reverse) && output.active == reverse.active
        && output.support_actor_is_subject == reverse.support_recipient_is_subject
        && output.support_recipient_is_subject == reverse.support_actor_is_subject;
}

static Pending begin(uintptr_t record,plan::Kind kind) noexcept {
    Pending pending{};
    const unsigned index = static_cast<unsigned>(kind);
    if (index >= 4) return pending;
    const auto& family = families[index/2];
    uintptr_t table = 0;
    if (!installed || relation::transport_fault || record < 0x10000
        || record > UINT64_C(0x00007fffffffffd0) || !read(record,table)
        || table != base+family.table_rva) return pending;
    auto& value = pending.value;
    value.kind = family.kind;
    value.path = index%2 == 0 ? family.enable : family.disable;
    if (!read(record+0x10,value.actor) || !read(record+0x18,value.recipient)) {
        relation::note_drop();
        return pending;
    }
    if (value.actor == value.recipient
        || ((value.actor & 0xffffffu) != 0x415246u && (value.recipient & 0xffffffu) != 0x415246u)) return pending;
    for (unsigned depth = 0; depth < active_count; ++depth) {
        const auto& active = active_pairs[depth];
        const bool forward = active.actor == value.actor && active.recipient == value.recipient;
        const bool reverse = active.actor == value.recipient && active.recipient == value.actor;
        if (active.kind == family.kind && (forward || reverse)) return pending;
    }
    if (active_count == 16) { relation::note_drop(); return pending; }
    active_pairs[active_count++] = {family.kind,value.actor,value.recipient};
    pending.observed = true;
    pending.ready = relation::date_now(value.date)
        && insult_query_country(value.actor,pending.actor_country)
        && insult_query_country(value.recipient,pending.recipient_country)
        && snapshot(family,value.actor,value.recipient,value.before);
    return pending;
}

static void finish(Pending& pending) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    --active_count;
    auto& value = pending.value;
    const auto& family = families[value.kind == owned::Kind::support_independence ? 0 : 1];
    uintptr_t actor = 0, recipient = 0;
    int32_t date = 0;
    // Disable can release the record. Read only owned endpoints and canonical
    // country rows after the original returns.
    if (!pending.ready || relation::transport_fault || !relation::date_now(date) || date != value.date
        || !insult_query_country(value.actor,actor) || actor != pending.actor_country
        || !insult_query_country(value.recipient,recipient) || recipient != pending.recipient_country
        || !snapshot(family,value.actor,value.recipient,value.after)) { relation::note_drop(); return; }
    const auto outcome = owned::classify(value.kind,value.before,value.after);
    if (outcome == owned::Outcome::unreadable) { relation::note_drop(); return; }
    relation::record_result(value);
    if (outcome != owned::Outcome::unchanged) relation::enqueue(value);
}
struct PendingCleanup final {
    Pending& pending;
    ~PendingCleanup() noexcept {
        if (pending.observed) { --active_count; pending.observed = false; relation::note_drop(); }
    }
};
static uintptr_t observe(plan::Kind kind,uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    const auto original = hooks[static_cast<unsigned>(kind)].original;
    if (!original) return 0;
    if (!installed || relation::transport_fault) return original(record,second,third,fourth);
    const DWORD incoming_error = GetLastError();
    auto pending = begin(record,kind);
    PendingCleanup cleanup{pending};
    SetLastError(incoming_error);
    const auto result = original(record,second,third,fourth);
    const DWORD returned_error = GetLastError();
    finish(pending);
    SetLastError(returned_error);
    return result;
}
static uintptr_t support_enable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::support_enable,record,second,third,fourth);
}
static uintptr_t support_disable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::support_disable,record,second,third,fourth);
}
static uintptr_t subject_enable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::subject_enable,record,second,third,fourth);
}
static uintptr_t subject_disable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::subject_disable,record,second,third,fourth);
}

struct ActionPendingCleanup final {
    relation::Pending& pending;
    ~ActionPendingCleanup() noexcept {
        if (pending.observed) {
            --relation::active_pair_count;
            pending.observed = false;
            relation::note_drop();
        }
    }
};
static uintptr_t support_action(uintptr_t action,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    const auto original = hooks[static_cast<unsigned>(plan::Kind::support_action)].original;
    if (!original) return 0;
    if (!installed || relation::transport_fault) return original(action,second,third,fourth);
    const DWORD incoming_error = GetLastError();
    uintptr_t table = 0;
    relation::Pending pending{};
    if (read(action,table) && table == base+lifecycle_support_vtable_rva) {
        AlliancePayload payload{};
        const auto shape = lifecycle_capture_shape(reinterpret_cast<void*>(action));
        if (shape.vtable == table && execution_payload(shape,payload))
            pending = relation::begin_payload(action,payload);
    }
    ActionPendingCleanup cleanup{pending};
    SetLastError(incoming_error);
    const auto result = original(action,second,third,fourth);
    const DWORD returned_error = GetLastError();
    relation::finish(pending);
    SetLastError(returned_error);
    return result;
}

static void release_unpublished() noexcept {
    if (published) return;
    for (auto& hook : hooks) {
        if (hook.table_registered && !RtlDeleteFunctionTable(&hook.unwind)) {
            lifecycle_rollback_incomplete = true;
            continue;
        }
        if (hook.executable) VirtualFree(hook.executable,0,MEM_RELEASE);
        hook = {};
    }
}
static bool prepare_hook(unsigned index,Original observer) noexcept {
    auto& hook = hooks[index];
    const auto& source = plan::kSpecs[index];
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+source.rva,&image_base,nullptr);
    std::array<unsigned char,17> prefix{};
    std::array<unsigned char,40> metadata{};
    SIZE_T copied = 0;
    if (!parent || image_base != base || parent->BeginAddress != source.rva
        || parent->EndAddress != source.end_rva || parent->UnwindData != source.unwind_rva
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.rva),
            prefix.data(),source.prefix_bytes,&copied) || copied != source.prefix_bytes
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.unwind_rva),
            metadata.data(),source.unwind_bytes,&copied) || copied != source.unwind_bytes
        || !plan::prepare(static_cast<plan::Kind>(index),prefix,metadata,base+source.rva,
            reinterpret_cast<uintptr_t>(observer),hook.image)) return false;
    hook.executable = static_cast<unsigned char*>(VirtualAlloc(nullptr,hook.image.image.size(),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!hook.executable) return false;
    std::memcpy(hook.executable,hook.image.image.data(),hook.image.image.size());
    DWORD old = 0;
    if (!VirtualProtect(hook.executable,hook.image.image.size(),PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),hook.executable,hook.image.image.size())) return false;
    hook.unwind = {hook.image.runtime.begin,hook.image.runtime.end,hook.image.runtime.unwind};
    hook.table_registered = RtlAddFunctionTable(&hook.unwind,1,reinterpret_cast<DWORD64>(hook.executable)) != FALSE;
    if (!hook.table_registered) return false;
    hook.original = reinterpret_cast<Original>(hook.executable);
    patch.targets[index] = {reinterpret_cast<void*>(base+source.rva),source.prefix_bytes,
        source.prefix.data(),hook.image.patch.data(),hook.executable,hook.image.runtime.end};
    return true;
}
static bool install() noexcept {
    if (published) return false;
    for (const auto& hook : hooks) if (hook.original) return false;
    const Original observers[] = {&support_enable,&support_disable,&subject_enable,&subject_disable,
                                  &support_action};
    for (unsigned index = 0; index < 5; ++index) {
        if (!prepare_hook(index,observers[index])) { release_unpublished(); return false; }
    }
    patch.count = 5;
    const auto result = bridge_entry_patch::guarded_patch_apply(patch);
    published = result.published;
    if (!published) release_unpublished();
    return result.success && result.threads_resumed && result.protection_restored;
}
static bool rollback() noexcept {
    installed = false;
    if (!published) return true;
    const auto result = bridge_entry_patch::guarded_patch_rollback(patch);
    return result.success && result.threads_resumed && result.protection_restored;
}
} // namespace support_subject_record_observer
