// Included in alliance_execution_detail after its payload helpers. The value
// header and standard-library headers are included at global scope first.
namespace war_declaration_observer {

namespace owned = ::information::war_declaration;
constexpr unsigned kCapacity = 64;
struct Value final {
    uint64_t actor = 0, recipient = 0, observer = 0;
    int32_t date = 0;
    unsigned actor_side = 0, recipient_side = 0, observer_side = 0;
    char war_id[30]{};
    char participants[4096]{};
};
struct Event final { Value value{}; uint64_t sequence = 0; };
struct Pending final {
    uint64_t actor = 0, recipient = 0;
    uintptr_t actor_country = 0, recipient_country = 0;
    owned::References before{};
    uint64_t birth_sequence_before = 0;
    int32_t date = 0;
    bool observed = false, ready = false;
};
static std::atomic<bool> installed{false}, transport_fault{false};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[kCapacity]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0, total_dropped = 0;

static void note_drop() noexcept {
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static bool date_now(int32_t& date) noexcept {
    uintptr_t game = 0;
    return !thread_changed && frame_thread == GetCurrentThreadId()
        && read(base + 0x233fe58, game) && read(game + 0x1dd0, date) && date > 0;
}

static bool pair_snapshot(uint64_t actor, uint64_t recipient, uintptr_t& left_country,
    uintptr_t& right_country, owned::References& result) noexcept {
    PeaceWarReferenceList left{}, right{};
    if (!peace_query_country_pointer(actor, left_country) || !peace_query_country_pointer(recipient, right_country)
        || !peace_query_pair_references(left_country, static_cast<unsigned>((recipient >> 32) & 0xffffu), left)
        || !peace_query_pair_references(right_country, static_cast<unsigned>((actor >> 32) & 0xffffu), right)
        || !peace_query_reference_sets_equal(left, right)
        || !peace_query_context_state_stable(actor, recipient, left_country, right_country, left, right)) return false;
    if (left.count > owned::kMaxReferences) return false;
    result.count = left.count;
    for (unsigned index = 0; index < left.count; ++index) {
        result.values[index] = left.references[index];
        result.births[index] = peace_war_registry_lifetimes.birth(left.references[index]).sequence;
    }
    result.complete = true;
    return owned::valid(result);
}

static void capture_payload(Pending& pending,const AlliancePayload& payload) noexcept {
    if (payload.family != ActionFamily::declare_war || payload.state34 != 0
        || payload.variant38 != 1 || payload.actor10 == payload.recipient20) return;
    pending.actor = payload.actor10;
    pending.recipient = payload.recipient20;
    pending.birth_sequence_before = peace_war_registry_lifetimes.sequence();
    pending.ready = pair_snapshot(pending.actor,pending.recipient,pending.actor_country,
                         pending.recipient_country,pending.before);
}

static Pending begin(void* wrapper) noexcept {
    Pending pending{};
    if (!installed || transport_fault) return pending;
    const auto address = reinterpret_cast<uintptr_t>(wrapper);
    uintptr_t action = 0, table = 0;
    // Only DeclareWar enters the larger payload and association readers.
    if (address < 0x10000 || address > UINT64_C(0x00007fffffffffa7)
        || !read(address + 0x50, action) || !read(action, table)
        || table != base + lifecycle_declarewar_vtable_rva) return pending;
    pending.observed = true;
    if (!date_now(pending.date)) return pending;
    const auto entry = protocol_capture(wrapper);
    AlliancePayload payload{};
    if (!entry.identity || !entry.readable || entry.action != action
        || !execution_payload(entry.payload,payload)) return pending;
    capture_payload(pending,payload);
    return pending;
}

static void finish(Pending& pending) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    owned::References after{};
    uintptr_t left = 0, right = 0;
    int32_t date = 0;
    if (!pending.ready || transport_fault || !date_now(date) || date != pending.date
        || !pair_snapshot(pending.actor, pending.recipient, left, right, after)
        || left != pending.actor_country || right != pending.recipient_country) { note_drop(); return; }
    const auto difference = owned::difference(pending.before, after);
    if (difference.outcome == owned::Outcome::unchanged) return;
    if (difference.outcome != owned::Outcome::single_added) { note_drop(); return; }
    const auto birth = peace_war_registry_lifetimes.birth(difference.reference);
    if (birth.sequence <= pending.birth_sequence_before || birth.sequence != difference.birth
        || birth.state != information::war_registry::BirthState::complete
        || birth.actor != pending.actor || birth.recipient != pending.recipient) { note_drop(); return; }
    PeaceWarSideMembers side_a{}, side_b{};
    const char* reason = nullptr;
    if (!peace_war_capture_participant_sides(difference.reference, pending.actor, pending.recipient,
        side_a, side_b, reason)) { note_drop(); return; }
    Value value{};
    value.actor = pending.actor;
    value.recipient = pending.recipient;
    value.date = date;
    value.actor_side = peace_war_side_for_handle(side_a, side_b, value.actor);
    value.recipient_side = peace_war_side_for_handle(side_a, side_b, value.recipient);
    uint64_t observers[32]{};
    unsigned observer_count=0;
    for (const auto* side : {&side_a, &side_b}) {
        for (unsigned index = 0; index < side->count; ++index) {
            const auto handle=side->handles[index];
            if (!observation_information_country_handle(handle)) continue;
            if (observer_count==32) { note_drop(); return; }
            observers[observer_count++]=handle;
        }
    }
    if (!observer_count) return;
    if (!peace_war_participants_json(side_a, side_b, value.actor, value.recipient,
        nullptr, value.participants, sizeof(value.participants))) { note_drop(); return; }
    const auto war = peace_query_register_war(difference.reference);
    if (!war) { note_drop(); return; }
    if (!peace_war_registry_lifetimes.current(*war)
        || peace_war_registry_lifetimes.birth(difference.reference).sequence!=birth.sequence) {
        note_drop(); return;
    }
    const auto announcement=peace_war_registry_lifetimes.claim_announcement(*war);
    if (announcement==information::war_registry::Announcement::stale) { note_drop(); return; }
    if (announcement==information::war_registry::Announcement::duplicate) return;
    memcpy(value.war_id, war->public_id, sizeof(value.war_id));
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    for (unsigned index=0;index<observer_count;++index) {
        value.observer=observers[index];
        value.observer_side=peace_war_side_for_handle(side_a, side_b, value.observer);
        Event event{value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
        if (size < kCapacity) { events[(head + size) % kCapacity] = event; ++size; }
        else note_drop();
    }
    ReleaseSRWLockExclusive(&queue_lock);
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) { transport_fault = true; return false; }
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) { transport_fault = true; return false; }
    return true;
}

static void tag(uint64_t reference, char (&value)[4]) noexcept {
    for (unsigned index = 0; index < 3; ++index) value[index] = static_cast<char>(reference >> (index * 8));
    value[3] = 0;
}

static void flush() noexcept {
    if (!installed) return;
    int32_t date=0;
    if (date_now(date)) peace_query_reconcile_war_registry();
    if (transport_fault) return;
    for (unsigned index = 0; index < 32; ++index) {
        Event event{};
        if (!TryAcquireSRWLockExclusive(&queue_lock)) return;
        if (!size) { ReleaseSRWLockExclusive(&queue_lock); break; }
        event = events[head];
        ReleaseSRWLockExclusive(&queue_lock);
        const auto& value = event.value;
        char actor[4]{}, recipient[4]{}, observer[4]{};
        tag(value.actor, actor);
        tag(value.recipient, recipient);
        tag(value.observer, observer);
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        constexpr unsigned schema=2;
#else
        constexpr unsigned schema=1;
#endif
        char message[8192]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_war_declared\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"%.3s\",\"actor\":\"%s\",\"recipient\":\"%s\","
            "\"actor_fullref\":\"0x%llx\",\"recipient_fullref\":\"0x%llx\",\"observer_fullref\":\"0x%llx\","
            "\"war_id\":\"%s\",\"date_raw\":%d,\"actor_side\":%u,\"recipient_side\":%u,\"observer_side\":%u,"
            "\"participants\":%s,"
            "\"source\":\"declare_war_command_return_new_pair_reference\",\"complete\":true}\n",
            schema,static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), observer, actor, recipient,
            static_cast<unsigned long long>(value.actor), static_cast<unsigned long long>(value.recipient),
            static_cast<unsigned long long>(value.observer), value.war_id, value.date,
            value.actor_side, value.recipient_side, value.observer_side, value.participants);
        if (bytes <= 0 || static_cast<size_t>(bytes) >= sizeof(message)) { transport_fault = true; return; }
        if (!append(message, static_cast<size_t>(bytes))) return;
        AcquireSRWLockExclusive(&queue_lock);
        head = (head + 1) % kCapacity;
        --size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    const LONG count = InterlockedCompareExchange(&dropped, 0, 0);
    if (count) {
        char message[256]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_war_declaration_capture_gap\",\"session_id\":\"%lu-%llx\","
            "\"dropped\":%ld,\"complete\":false}\n", static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation), static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes))
            InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    char* end = strrchr(message, '}');
    if (!end) return;
    unsigned queued = 0;
    const bool readable = TryAcquireSRWLockExclusive(&queue_lock) != FALSE;
    if (readable) { queued = size; ReleaseSRWLockExclusive(&queue_lock); }
    snprintf(end, capacity - static_cast<size_t>(end - message),
        ",\"war_declaration_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n", installed.load() ? "true" : "false",
        transport_fault.load() ? "true" : "false", static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        readable ? "true" : "false", queued);
}

#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
namespace plan = owned::entry;
using Original = uintptr_t(*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t);
struct EntryHook final {
    uintptr_t original = 0;
    plan::Plan image{};
    unsigned char* executable = nullptr;
    RUNTIME_FUNCTION unwind{};
    bool table_registered = false;
};
static EntryHook hooks[3]{};
static bool published = false;
static bridge_entry_patch::PatchPlan patch{};

struct PendingCleanup final {
    Pending& pending;
    ~PendingCleanup() noexcept {
        if (pending.observed) { pending.observed = false; note_drop(); }
    }
};
static uintptr_t direct_action(uintptr_t action,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    const auto original = reinterpret_cast<Original>(hooks[0].original);
    if (!original) return 0;
    if (!installed || transport_fault) return original(action,second,third,fourth);
    const DWORD incoming_error = GetLastError();
    Pending pending{};
    uintptr_t table = 0;
    if (read(action,table) && table == base+lifecycle_declarewar_vtable_rva) {
        pending.observed = true;
        if (date_now(pending.date)) {
            const auto shape = lifecycle_capture_shape(reinterpret_cast<void*>(action));
            AlliancePayload payload{};
            if (shape.vtable == table && execution_payload(shape,payload)) capture_payload(pending,payload);
        }
    }
    PendingCleanup cleanup{pending};
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    auto land_promise_pending = land_promise_observer::begin_action(action);
#endif
    SetLastError(incoming_error);
    const auto result = original(action,second,third,fourth);
    const DWORD returned_error = GetLastError();
    finish(pending);
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    land_promise_observer::finish(land_promise_pending);
#endif
    SetLastError(returned_error);
    return result;
}
struct BirthCleanup final {
    information::war_registry::Birth token{};
    bool finished = false;
    ~BirthCleanup() noexcept {
        if (!finished) {
            peace_war_registry_lifetimes.complete(token,false);
            note_drop();
        }
    }
};
static uintptr_t construct_war(uintptr_t object,uintptr_t actor,uintptr_t recipient,uintptr_t goal) {
    const auto original = reinterpret_cast<Original>(hooks[1].original);
    if (!original) return 0;
    const DWORD incoming_error = GetLastError();
    int32_t date = 0;
    const auto token = peace_war_registry_lifetimes.begin(object,actor,recipient,date_now(date));
    BirthCleanup cleanup{token};
    SetLastError(incoming_error);
    const auto result = original(object,actor,recipient,goal);
    const DWORD returned_error = GetLastError();
    int32_t current_date = 0, marker = 0;
    uintptr_t table = 0, history_table = 0;
    const bool verified = result == object && date_now(current_date) && current_date == date
        && read(object,table) && table == base+0x1d1f6f0
        && read(object+8,marker) && marker == 0x165
        && read(object+0x108,history_table) && history_table == base+0x1d20be0;
    if (!peace_war_registry_lifetimes.complete(token,verified)) note_drop();
    cleanup.finished = true;
    SetLastError(returned_error);
    return result;
}
static void destroy_war(uintptr_t object) {
    const auto original=reinterpret_cast<void(*)(uintptr_t)>(hooks[2].original);
    if (!original) return;
    const DWORD incoming_error=GetLastError();
    auto retirement=peace_war_registry_lifetimes.retire(object);
    SetLastError(incoming_error);
    original(object);
    const DWORD returned_error=GetLastError();
    peace_war_registry_lifetimes.complete_retirement(retirement);
    SetLastError(returned_error);
}
static void release_unpublished() noexcept {
    if (published) return;
    for (auto& hook : hooks) {
        if (hook.table_registered && !RtlDeleteFunctionTable(&hook.unwind)) {
            lifecycle_rollback_incomplete = true;
            continue;
        }
        hook.table_registered = false;
        if (hook.executable) VirtualFree(hook.executable,0,MEM_RELEASE);
        hook.executable = nullptr;
        hook.original = 0;
    }
}
static bool install() noexcept {
    if (published || hooks[0].original || hooks[1].original || hooks[2].original) return false;
    using Prepare = bool(*)(const std::array<unsigned char,17>&,
        const std::array<unsigned char,40>&,uintptr_t,uintptr_t,plan::Plan&);
    struct Spec final {
        uint32_t rva, end, unwind;
        unsigned prefix_bytes, unwind_bytes;
        const std::array<unsigned char,17>& prefix;
        const std::array<unsigned char,40>& metadata;
        Prepare prepare;
        uintptr_t target;
    };
    namespace birth = owned::birth_entry;
    namespace retirement = owned::retirement_entry;
    const Spec specs[] = {
        {plan::kRva,plan::kEndRva,plan::kUnwindRva,plan::kPrefixBytes,plan::kUnwindBytes,
         plan::kPrefix,plan::kUnwind,plan::prepare,reinterpret_cast<uintptr_t>(&direct_action)},
        {birth::kRva,birth::kEndRva,birth::kUnwindRva,birth::kPrefixBytes,birth::kUnwindBytes,
         birth::kPrefix,birth::kUnwind,birth::prepare,reinterpret_cast<uintptr_t>(&construct_war)},
        {retirement::kRva,retirement::kEndRva,retirement::kUnwindRva,
         retirement::kPrefixBytes,retirement::kUnwindBytes,retirement::kPrefix,
         retirement::kUnwind,retirement::prepare,reinterpret_cast<uintptr_t>(&destroy_war)},
    };
    for (unsigned index = 0; index < 3; ++index) {
        const auto& spec = specs[index];
        auto& hook = hooks[index];
        DWORD64 image_base = 0;
        const auto parent = RtlLookupFunctionEntry(base+spec.rva,&image_base,nullptr);
        std::array<unsigned char,17> prefix{};
        std::array<unsigned char,40> metadata{};
        SIZE_T copied = 0;
        if (!parent || image_base != base || parent->BeginAddress != spec.rva
            || parent->EndAddress != spec.end || parent->UnwindData != spec.unwind
            || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+spec.rva),
                prefix.data(),spec.prefix_bytes,&copied) || copied != spec.prefix_bytes
            || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+spec.unwind),
                metadata.data(),spec.unwind_bytes,&copied) || copied != spec.unwind_bytes
            || !spec.prepare(prefix,metadata,base+spec.rva,spec.target,hook.image)) {
            release_unpublished(); return false;
        }
        hook.executable = static_cast<unsigned char*>(VirtualAlloc(nullptr,hook.image.image.size(),
            MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
        if (!hook.executable) { release_unpublished(); return false; }
        std::memcpy(hook.executable,hook.image.image.data(),hook.image.image.size());
        DWORD old = 0;
        if (!VirtualProtect(hook.executable,hook.image.image.size(),PAGE_EXECUTE_READ,&old)
            || !FlushInstructionCache(GetCurrentProcess(),hook.executable,hook.image.image.size())) {
            release_unpublished(); return false;
        }
        hook.unwind = {hook.image.runtime.begin,hook.image.runtime.end,hook.image.runtime.unwind};
        hook.table_registered = RtlAddFunctionTable(&hook.unwind,1,
            reinterpret_cast<DWORD64>(hook.executable)) != FALSE;
        if (!hook.table_registered) { release_unpublished(); return false; }
        hook.original = reinterpret_cast<uintptr_t>(hook.executable);
        patch.targets[index] = {reinterpret_cast<void*>(base+spec.rva),spec.prefix_bytes,
            spec.prefix.data(),hook.image.patch.data(),hook.executable,hook.image.runtime.end};
    }
    patch.count = 3;
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
#endif

} // namespace war_declaration_observer
