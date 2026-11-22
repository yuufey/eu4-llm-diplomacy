// Record-level rival observations share the existing command event stream.
#include "information-rival-record-entry-plan.h"

#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
extern "C" void bridge_direct_break_observe(void*,uint64_t,unsigned char,uintptr_t);
#endif

namespace rival_record_observer {
namespace entry = information::rival_record::entry;
namespace legacy = rival_change_observer;
namespace owned = information::rival_change;

using Original = uintptr_t(*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t);
static Original originals[2]{};
static std::atomic<bool> installed{false};
struct RecordChange final {
    owned::Change value{};
    entry::Kind path = entry::Kind::add;
};
static int format(const RecordChange& record, uint64_t sequence, unsigned long pid,
                  uint64_t creation, char* output, size_t capacity, uint64_t observer = 0) noexcept {
    const auto& value = record.value;
    const bool add = record.path == entry::Kind::add;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    constexpr unsigned schema = 4;
#else
    constexpr unsigned schema = 2;
    if (!observer) observer = legacy::observes(value.actor) ? value.actor : value.target;
#endif
    if (!output || !capacity || !sequence || !pid || !creation
        || (record.path != entry::Kind::add && record.path != entry::Kind::remove)
        || value.kind != (add ? owned::Kind::set : owned::Kind::remove) || value.old_rival
        || !legacy::valid_tag(value.actor) || !legacy::valid_tag(value.target) || value.actor == value.target
        || (observer != value.actor && observer != value.target)
#ifndef BRIDGE_NATIVE_COUNTRY_CONTROL
        || !legacy::observes(observer)
#endif
        || owned::classify(value.kind,value.date,value.before,value.after) != owned::Outcome::changed
        || value.after.target.active != add) return 0;
    char actor[4]{}, target[4]{}, country[4]{};
    for (unsigned byte = 0; byte < 3; ++byte) {
        actor[byte] = static_cast<char>(value.actor >> (byte*8));
        target[byte] = static_cast<char>(value.target >> (byte*8));
        country[byte] = static_cast<char>(observer >> (byte*8));
    }
    const int bytes = snprintf(output,capacity,
        "{\"event\":\"native_rival_changed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
        "\"sequence\":%llu,\"country\":\"%.3s\",\"actor\":\"%s\",\"target\":\"%s\",\"old_rival\":\"---\","
        "\"actor_fullref\":\"0x%llx\",\"target_fullref\":\"0x%llx\",\"old_rival_fullref\":\"0x0\","
        "\"operation\":\"%s\",\"date_raw\":%d,\"before\":{\"count\":%d,\"target_active\":%s,"
        "\"target_since_date_raw\":%d,\"old_active\":false,\"old_since_date_raw\":-1},"
        "\"after\":{\"count\":%d,\"target_active\":%s,\"target_since_date_raw\":%d,"
        "\"old_active\":false,\"old_since_date_raw\":-1},\"source\":\"%s\","
        "\"observation_path\":\"%s\",\"count_basis\":\"active_nonretired_nodes\",\"complete\":true}\n",
        schema,pid,static_cast<unsigned long long>(creation),static_cast<unsigned long long>(sequence),country,actor,target,
        static_cast<unsigned long long>(value.actor),static_cast<unsigned long long>(value.target),
        add ? "set" : "remove",value.date,value.before.count,value.before.target.active ? "true" : "false",
        value.before.target.since_date,value.after.count,value.after.target.active ? "true" : "false",
        value.after.target.since_date,add ? "country_rival_add_return" : "country_rival_remove_return",
        add ? "country_rival_add" : "country_rival_remove");
    return bytes > 0 && static_cast<size_t>(bytes) < capacity ? bytes : 0;
}
// The host supplies a bounded sink. All event values belong to this record.
static bool publish(const RecordChange& record) noexcept {
    return legacy::enqueue(record.value,record.path == entry::Kind::add ? 1 : 2);
}

static int format_event(const owned::Change& value, unsigned char path, uint64_t sequence,
                        uint64_t observer, char* output, size_t capacity) noexcept {
    if (path != 1 && path != 2) return 0;
    return format({value,path == 1 ? entry::Kind::add : entry::Kind::remove},sequence,
                  static_cast<unsigned long>(GetCurrentProcessId()),observation_creation,output,capacity,observer);
}

struct Command final { owned::Kind kind{}; uint64_t actor = 0, target = 0, old_rival = 0; };
static thread_local Command commands[16]{};
static thread_local unsigned command_count = 0, command_overflow = 0;

class CommandScope final {
    bool registered = false, overflow = false;
public:
    explicit CommandScope(const legacy::Pending& pending) noexcept {
        if (!pending.relevant || !pending.ready) return;
        if (command_count == 16) {
            ++command_overflow;
            overflow = true;
            legacy::note_drop();
            return;
        }
        const auto& value = pending.value;
        commands[command_count++] = {value.kind,value.actor,value.target,value.old_rival};
        registered = true;
    }
    CommandScope(const CommandScope&) = delete;
    CommandScope& operator=(const CommandScope&) = delete;
    ~CommandScope() noexcept {
        if (registered) --command_count;
        if (overflow) --command_overflow;
    }
};

static bool covered(entry::Kind kind, uint64_t actor, uint64_t target) noexcept {
    if (command_overflow) return true;
    for (unsigned index = 0; index < command_count; ++index) {
        const auto& command = commands[index];
        if (command.actor != actor) continue;
        if (kind == entry::Kind::add && command.kind != owned::Kind::remove
            && command.target == target) return true;
        if (kind == entry::Kind::remove
            && ((command.kind == owned::Kind::remove && command.target == target)
                || (command.kind == owned::Kind::replace && command.old_rival == target))) return true;
    }
    return false;
}

// The stored list count includes nodes retired during native iteration.
// Notifications count active, nonretired nodes so a deferred unlink is observed
// at the actual removal return, while the node is still physically present.
static bool snapshot(uintptr_t owner, uint64_t target, int32_t date, owned::Snapshot& output) noexcept {
    uintptr_t node = 0;
    int32_t physical_count = -1;
    if (!read(owner+0x2248,node) || !read(owner+0x2258,physical_count)
        || physical_count < 0 || physical_count > 64) return false;
    uintptr_t visited[64]{};
    owned::Snapshot value{};
    value.count = 0;
    for (int32_t index = 0; index < physical_count; ++index) {
        if (node < 0x10000 || node > UINT64_C(0x00007fffffffffc8)) return false;
        for (int32_t prior = 0; prior < index; ++prior) if (visited[prior] == node) return false;
        visited[index] = node;
        uintptr_t table = 0, next = 0;
        uint64_t member = 0;
        int32_t since = -1;
        unsigned char retired = 0;
        if (!read(node,table) || table != base+0x1c56c18
            || !read(node+0x10,member) || !legacy::valid_tag(member)
            || !read(node+0x18,since) || !read(node+0x28,next)
            || !read(node+0x30,retired) || retired > 1) return false;
        if (!retired) {
            if (since < 0 || since > date) return false;
            ++value.count;
            if (static_cast<uint16_t>(member >> 32) == static_cast<uint16_t>(target >> 32)) {
                if (member != target || value.target.active) return false;
                value.target = {true,since};
            }
        }
        node = next;
    }
    if (node) return false;
    value.verified = true;
    output = value;
    return true;
}

struct Pending final {
    RecordChange record{};
    uintptr_t owner = 0;
    bool relevant = false, ready = false;
};

static bool command_snapshot(const owned::Change& value, uintptr_t owner, owned::Snapshot& output) noexcept {
    owned::Snapshot current{};
    if (!snapshot(owner,value.target,value.date,current)) return false;
    if (value.kind == owned::Kind::replace) {
        owned::Snapshot old{};
        if (!snapshot(owner,value.old_rival,value.date,old) || old.count != current.count) return false;
        current.old_rival = old.target;
    }
    output = current;
    return true;
}

static Pending begin(entry::Kind kind, uintptr_t owner, uint64_t target) noexcept {
    Pending pending{};
    if (!installed || legacy::transport_fault) return pending;
    uint64_t actor = 0;
    if (owner < 0x10000 || owner > UINT64_C(0x00007fffffffffdb)
        || !read(owner+0x20,actor)) { legacy::note_drop(); return pending; }
    pending.relevant = legacy::observes(actor) || legacy::observes(target);
    if (!pending.relevant) return pending;
    if (covered(kind,actor,target)) { pending.relevant = false; return pending; }
    auto& record = pending.record;
    record.path = kind;
    auto& value = record.value;
    value.kind = kind == entry::Kind::add ? owned::Kind::set : owned::Kind::remove;
    value.actor = actor;
    value.target = target;
    pending.owner = owner;
    uintptr_t current_owner = 0, recipient = 0;
    pending.ready = legacy::valid_tag(actor) && legacy::valid_tag(target) && actor != target
        && legacy::read_date(value.date) && insult_query_country(actor,current_owner) && current_owner == owner
        && insult_query_country(target,recipient) && snapshot(owner,target,value.date,value.before);
    return pending;
}

static void finish(Pending& pending) noexcept {
    if (!pending.relevant) return;
    pending.relevant = false;
    auto& value = pending.record.value;
    uintptr_t owner = 0, recipient = 0;
    int32_t date = 0;
    uint64_t actor = 0;
    if (!pending.ready || legacy::transport_fault || !legacy::read_date(date) || date != value.date
        || !read(pending.owner+0x20,actor) || actor != value.actor
        || !insult_query_country(actor,owner) || owner != pending.owner
        || !insult_query_country(value.target,recipient)
        || !snapshot(owner,value.target,date,value.after)) { legacy::note_drop(); return; }
    const auto outcome = owned::classify(value.kind,date,value.before,value.after);
    if (outcome == owned::Outcome::unchanged) return;
    if (outcome == owned::Outcome::unreadable
        || (value.kind == owned::Kind::set && !value.after.target.active)
        || (value.kind == owned::Kind::remove && value.after.target.active)) { legacy::note_drop(); return; }
    if (!publish(pending.record)) legacy::note_drop();
}

struct PendingCleanup final {
    Pending& pending;
    ~PendingCleanup() noexcept { if (pending.relevant) legacy::note_drop(); }
};

static uintptr_t observe(entry::Kind kind, uintptr_t owner, uintptr_t second, uintptr_t third, uintptr_t fourth) {
    const auto original = originals[kind == entry::Kind::add ? 0 : 1];
    if (!original) return 0;
    if (!installed || legacy::transport_fault) return original(owner,second,third,fourth);
    const DWORD incoming_error = GetLastError();
    auto pending = begin(kind,owner,second);
    PendingCleanup cleanup{pending};
    SetLastError(incoming_error);
    const auto result = original(owner,second,third,fourth);
    const DWORD returned_error = GetLastError();
    finish(pending);
    SetLastError(returned_error);
    return result;
}

struct Hook final {
    entry::Plan image{};
    unsigned char* executable = nullptr;
    RUNTIME_FUNCTION unwind{};
    bool table_registered = false;
};
static Hook hooks[2]{};
static bridge_entry_patch::PatchPlan patch{};
static bool published = false;

static uintptr_t observe_add(uintptr_t owner,uintptr_t second,uintptr_t third,uintptr_t fourth) {
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
    const DWORD incoming_error = GetLastError();
#ifdef _MSC_VER
    const auto caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
#else
    const auto caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#endif
    bridge_direct_break_observe(reinterpret_cast<void*>(owner),second,
                               static_cast<unsigned char>(third),caller);
    SetLastError(incoming_error);
#endif
    return observe(entry::Kind::add,owner,second,third,fourth);
}
static uintptr_t observe_remove(uintptr_t owner,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    return observe(entry::Kind::remove,owner,second,third,fourth);
}

static void release_unpublished() noexcept {
    if (published) return;
    for (unsigned index = 0; index < 2; ++index) {
        auto& hook = hooks[index];
        if (hook.table_registered && !RtlDeleteFunctionTable(&hook.unwind)) {
            lifecycle_rollback_incomplete = true;
            continue;
        }
        if (hook.executable) VirtualFree(hook.executable,0,MEM_RELEASE);
        hook = {};
        originals[index] = nullptr;
    }
}

static bool prepare_hook(unsigned index,entry::Kind kind,Original observer) noexcept {
    auto& hook = hooks[index];
    const auto& source = entry::spec(kind);
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+source.rva,&image_base,nullptr);
    std::array<unsigned char,15> prefix{};
    std::array<unsigned char,28> metadata{};
    SIZE_T copied = 0;
    if (!parent || image_base != base || parent->BeginAddress != source.rva
        || parent->EndAddress != source.end_rva || parent->UnwindData != source.unwind_rva
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.rva),
            prefix.data(),prefix.size(),&copied) || copied != prefix.size()
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+source.unwind_rva),
            metadata.data(),source.unwind_bytes,&copied) || copied != source.unwind_bytes
        || !entry::prepare(kind,prefix,metadata,base+source.rva,reinterpret_cast<uintptr_t>(observer),hook.image)) return false;
    hook.executable = static_cast<unsigned char*>(VirtualAlloc(nullptr,hook.image.image.size(),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!hook.executable) return false;
    std::memcpy(hook.executable,hook.image.image.data(),hook.image.image.size());
    DWORD old = 0;
    if (!VirtualProtect(hook.executable,hook.image.image.size(),PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),hook.executable,hook.image.image.size())) return false;
    hook.unwind = {hook.image.runtime.begin,hook.image.runtime.end,hook.image.runtime.unwind};
    hook.table_registered = RtlAddFunctionTable(&hook.unwind,1,reinterpret_cast<DWORD64>(hook.executable)) != FALSE;
    if (!hook.table_registered) return false;
    originals[index] = reinterpret_cast<Original>(hook.executable);
    patch.targets[index] = {reinterpret_cast<void*>(base+source.rva),prefix.size(),
        source.prefix.data(),hook.image.patch.data(),hook.executable,hook.image.runtime.end};
    return true;
}

static bool install() noexcept {
    if (published || originals[0] || originals[1]) return false;
    if (!prepare_hook(0,entry::Kind::add,&observe_add)
        || !prepare_hook(1,entry::Kind::remove,&observe_remove)) { release_unpublished(); return false; }
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
} // namespace rival_record_observer
