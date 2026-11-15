#include "information-royal-record-entry-plan.h"

namespace royal_record_observer {
namespace plan = information::royal_record::entry;
namespace relation = relation_change_observer;
namespace owned = information::relation_change;
using Payload = bridge::alliance_authority::AlliancePayload;
using Original = uintptr_t(*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t);
struct Hook final {
    Original original = nullptr;
    plan::Plan image{};
    unsigned char* executable = nullptr;
    RUNTIME_FUNCTION unwind{};
    bool table_registered = false;
};
struct Pair final { uint64_t actor = 0, recipient = 0; };
struct Pending final {
    relation::Value value{};
    uintptr_t actor_country = 0, recipient_country = 0;
    bool observed = false, ready = false;
};
static Hook hooks[2]{};
static bridge_entry_patch::PatchPlan patch{};
static bool published = false;
static std::atomic<bool> installed{false};
static thread_local Pair active_pairs[16]{};
static thread_local unsigned active_count = 0;

static bool snapshot(uint64_t actor, uint64_t recipient, owned::Snapshot& output) noexcept {
    Payload payload{};
    payload.family = bridge::alliance_authority::ActionFamily::royal_marriage;
    payload.actor10 = actor;
    payload.recipient20 = recipient;
    owned::Snapshot reverse{};
    if (!relation::snapshot(payload,owned::Kind::royal_marriage,output)) return false;
    payload.actor10 = recipient;
    payload.recipient20 = actor;
    return relation::snapshot(payload,owned::Kind::royal_marriage,reverse)
        && output.active == reverse.active;
}

static Pending begin(uintptr_t record, plan::Kind kind) noexcept {
    Pending pending{};
    uintptr_t table = 0;
    if (!installed || relation::transport_fault || record < 0x10000
        || record > UINT64_C(0x00007fffffffffd0) || !read(record,table)
        || table != base+0x1c80be0) return pending;
    auto& value = pending.value;
    value.kind = owned::Kind::royal_marriage;
    value.path = kind == plan::Kind::enable ? relation::Path::royal_record_enable
        : relation::Path::royal_record_disable;
    if (!read(record+0x10,value.actor) || !read(record+0x18,value.recipient)) {
        relation::note_drop();
        return pending;
    }
    if (value.actor == value.recipient
        || ((value.actor & 0xffffffu) != 0x415246u && (value.recipient & 0xffffffu) != 0x415246u)) return pending;
    for (unsigned index = 0; index < active_count; ++index) {
        const auto& active = active_pairs[index];
        if ((active.actor == value.actor && active.recipient == value.recipient)
            || (active.actor == value.recipient && active.recipient == value.actor)) return pending;
    }
    if (active_count == 16) { relation::note_drop(); return pending; }
    active_pairs[active_count++] = {value.actor,value.recipient};
    pending.observed = true;
    pending.ready = relation::date_now(value.date)
        && insult_query_country(value.actor,pending.actor_country)
        && insult_query_country(value.recipient,pending.recipient_country)
        && snapshot(value.actor,value.recipient,value.before);
    return pending;
}

static void finish(Pending& pending) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    --active_count;
    auto& value = pending.value;
    uintptr_t actor = 0, recipient = 0;
    int32_t date = 0;
    // The registry can release its record during disable. Only owned endpoint
    // values and the canonical country rows are read after the original call.
    if (!pending.ready || relation::transport_fault || !relation::date_now(date) || date != value.date
        || !insult_query_country(value.actor,actor) || actor != pending.actor_country
        || !insult_query_country(value.recipient,recipient) || recipient != pending.recipient_country
        || !snapshot(value.actor,value.recipient,value.after)) { relation::note_drop(); return; }
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
    const auto original = hooks[kind == plan::Kind::enable ? 0 : 1].original;
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
static uintptr_t observe_enable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::enable,record,second,third,fourth);
}
static uintptr_t observe_disable(uintptr_t record,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(plan::Kind::disable,record,second,third,fourth);
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
static bool prepare_hook(unsigned index,plan::Kind kind,Original observer) noexcept {
    auto& hook = hooks[index];
    const auto& source = plan::spec(kind);
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+source.rva,&image_base,nullptr);
    std::array<unsigned char,15> prefix{};
    std::array<unsigned char,32> metadata{};
    SIZE_T copied = 0;
    if (!parent || image_base != base || parent->BeginAddress != source.rva
        || parent->EndAddress != source.end_rva || parent->UnwindData != source.unwind_rva
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.rva),
            prefix.data(),source.prefix_bytes,&copied) || copied != source.prefix_bytes
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.unwind_rva),
            metadata.data(),source.unwind_bytes,&copied) || copied != source.unwind_bytes
        || !plan::prepare(kind,prefix,metadata,base+source.rva,reinterpret_cast<uintptr_t>(observer),hook.image)) return false;
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
    if (published || hooks[0].original || hooks[1].original) return false;
    if (!prepare_hook(0,plan::Kind::enable,&observe_enable)
        || !prepare_hook(1,plan::Kind::disable,&observe_disable)) { release_unpublished(); return false; }
    patch.count = 2;
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
} // namespace royal_record_observer
