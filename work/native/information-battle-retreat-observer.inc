// Included inside information_battle_source after Reader/code_guard/context.
// 22bed0 owns regular-end callbacks. The verified AddMovement call to
// 23b200 owns a separate state-before-removal snapshot. Neither path uses
// nearest-event or nearest-pointer matching.
namespace retreat_capture = battle::owned_retreat;
namespace retreat_plan = battle::retreat_entry;
namespace retreat_wire = battle::retreat_wire;

struct RetreatEntry final {
    retreat_plan::Plan plan{};
    unsigned char* trampoline = nullptr;
    RUNTIME_FUNCTION unwind{};
    uintptr_t source_row = 0;
    bool table_registered = false;
    bool patched = false;
};
static constexpr unsigned kRetreatEntryCount = 3;
static RetreatEntry retreat_entries[kRetreatEntryCount]{};
struct RetreatFrame final {
    retreat_capture::Scope units{};
    uintptr_t combat = 0;
    unsigned slot = 0;
    uint64_t sequence = 0;
    uint64_t drops_before = 0;
    bool has_record = false;
    bool router_complete = false;
    bool ambiguous = false;
    bool removal = false;
};
struct RetreatToken final { unsigned depth = 0; bool suppressed = false; };
static constexpr unsigned kRetreatScopeLimit = 8;
static RetreatFrame retreat_frames[kRetreatScopeLimit]{};
static unsigned retreat_depth = 0, retreat_suppressed = 0;
static std::atomic<uint64_t> retreat_drops{0};

static bool retreat_code_guard() noexcept {
    Reader reader;
    for (unsigned i = 0; i < kRetreatEntryCount; ++i) {
        const auto& spec = retreat_plan::spec(static_cast<retreat_plan::Kind>(i));
        const auto& owned = retreat_entries[i];
        unsigned char prefix[28]{}, metadata[32]{};
        if (!reader.read(base + spec.rva, prefix, spec.prefix_bytes)
            || !reader.read(base + spec.unwind_rva, metadata, sizeof(metadata))
            || memcmp(metadata, spec.unwind_expected.data(), sizeof(metadata))
            || memcmp(prefix, patched ? owned.plan.patch.data() : spec.prefix.data(), spec.prefix_bytes)) return false;
        if (owned.source_row) {
            RUNTIME_FUNCTION row{};
            if (!read_value(owned.source_row, row) || row.BeginAddress != spec.rva
                || row.EndAddress != spec.end_rva || row.UnwindData != spec.unwind_rva) return false;
        }
    }
    static constexpr unsigned char result_then_retreat[] = {
        0x41,0x0f,0xb6,0xd4,0x49,0x8b,0xce,0xe8,0x9f,0xdf,0x00,0x00,
        0x49,0x8b,0xcf,0xe8,0xd7,0x2a,0xff,0xff};
    static constexpr unsigned char assigned_before_callback[] = {
        0x66,0x41,0xc7,0x86,0x03,0x02,0x00,0x00,0x01,0x01,0x41,0xc6,0x86,0x01,0x02,0x00,
        0x00,0x00,0x49,0x8b,0x5e,0x58,0x48,0x85,0xdb,0x74,0x18,0x66,0x90,0x45,0x33,0xc0,
        0xb2,0x01,0x48,0x8b,0x0b,0xe8,0x13,0xb3,0xb2,0x00,0x48,0x8b,0x5b,0x10,0x48,0x85,
        0xdb,0x75,0xea,0x45,0x33,0xc0,0xb2,0x01,0x49,0x8b,0xce,0xe8,0xad,0x0c,0xb3,0x00};
    static constexpr unsigned char removal_call[] = {
        0x45,0x33,0xc0,0x49,0x8b,0xd7,0x49,0x8b,0xc9,0xe8,0x4e,
        0xae,0x4e,0xff,0x4d,0x89,0xaf,0xc0,0x00,0x00,0x00};
    unsigned char first[sizeof(result_then_retreat)]{}, second[sizeof(assigned_before_callback)]{},
        third[sizeof(removal_call)]{};
    return reader.read(base + 0x22c075, first, sizeof(first))
        && reader.read(base + 0x21ee33, second, sizeof(second))
        && !memcmp(first, result_then_retreat, sizeof(first))
        && !memcmp(second, assigned_before_callback, sizeof(second))
        && reader.read(base + 0xd503a4, third, sizeof(third))
        && !memcmp(third, removal_call, sizeof(third));
}

static bool prepare_retreat_entries() noexcept {
    Reader reader;
    if (patch.count + kRetreatEntryCount > bridge_entry_patch::kMaxTargets || !retreat_code_guard()) return false;
    const uintptr_t hooks[kRetreatEntryCount] = {
        reinterpret_cast<uintptr_t>(&information_battle_outcome_retreat_hook),
        reinterpret_cast<uintptr_t>(&information_battle_unit_retreat_hook),
        reinterpret_cast<uintptr_t>(&information_battle_unit_removal_retreat_hook)};
    void** originals[kRetreatEntryCount] = {
        &information_battle_outcome_retreat_original, &information_battle_unit_retreat_original,
        &information_battle_unit_removal_retreat_original};
    for (unsigned i = 0; i < kRetreatEntryCount; ++i) {
        auto& owned = retreat_entries[i];
        const auto kind = static_cast<retreat_plan::Kind>(i);
        const auto& spec = retreat_plan::spec(kind);
        if (owned.trampoline) return false;
        DWORD64 source_base = 0;
        const auto* source_row = RtlLookupFunctionEntry(base + spec.rva, &source_base, nullptr);
        if (!source_row || source_base != base) return false;
        RUNTIME_FUNCTION row{};
        owned.source_row = reinterpret_cast<uintptr_t>(source_row);
        if (!read_value(owned.source_row, row) || row.BeginAddress != spec.rva
            || row.EndAddress != spec.end_rva || row.UnwindData != spec.unwind_rva) return false;
        unsigned char prefix[28]{}, metadata[32]{};
        const auto hook = hooks[i];
        if (!reader.read(base + spec.rva, prefix, spec.prefix_bytes)
            || !reader.read(base + spec.unwind_rva, metadata, sizeof(metadata))
            || retreat_plan::prepare(kind, prefix, spec.prefix_bytes, metadata, sizeof(metadata),
                                    base + spec.rva, hook, owned.plan) != retreat_plan::Status::prepared) return false;
        owned.trampoline = static_cast<unsigned char*>(VirtualAlloc(nullptr, retreat_plan::kMaxImageBytes,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!owned.trampoline) return false;
        memcpy(owned.trampoline, owned.plan.image.data(), owned.plan.image_bytes);
        DWORD old = 0;
        if (!VirtualProtect(owned.trampoline, retreat_plan::kMaxImageBytes, PAGE_EXECUTE_READ, &old)
            || !FlushInstructionCache(GetCurrentProcess(), owned.trampoline, owned.plan.image_bytes)) return false;
        owned.unwind = {owned.plan.runtime.begin, owned.plan.runtime.end, owned.plan.runtime.unwind};
        owned.table_registered = RtlAddFunctionTable(&owned.unwind, 1, reinterpret_cast<DWORD64>(owned.trampoline)) != FALSE;
        DWORD64 owned_base = 0;
        if (!owned.table_registered || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(owned.trampoline + 1),
            &owned_base, nullptr) != &owned.unwind || owned_base != reinterpret_cast<DWORD64>(owned.trampoline)) return false;
        *originals[i] = owned.trampoline;
        patch.targets[patch.count++] = {reinterpret_cast<void*>(base + spec.rva),
            static_cast<unsigned>(owned.plan.patch_bytes), spec.prefix.data(), owned.plan.patch.data(),
            owned.trampoline, owned.plan.runtime.end};
    }
    return true;
}

static bool retreat_mark_patched() noexcept {
    Reader reader;
    bool complete = true;
    for (unsigned i = 0; i < kRetreatEntryCount; ++i) {
        auto& owned = retreat_entries[i];
        const auto& spec = retreat_plan::spec(static_cast<retreat_plan::Kind>(i));
        unsigned char prefix[28]{};
        owned.patched = reader.read(base + spec.rva, prefix, spec.prefix_bytes)
            && !memcmp(prefix, owned.plan.patch.data(), spec.prefix_bytes);
        complete = complete && owned.patched;
    }
    return complete;
}

static RetreatToken begin_retreat_scope(void* combat, void* losing_side,
    void* removing_unit = nullptr, uintptr_t removal_return_pc = 0) noexcept {
    if (removing_unit && removal_return_pc != base + retreat_capture::kRemovalReturnRva) return {};
    if (state.load(std::memory_order_acquire) != enabled || GetCurrentThreadId() != bound_thread) return {};
    if (!TryAcquireSRWLockExclusive(&capture_lock)) { retreat_drops.fetch_add(1); return {}; }
    RetreatToken token{};
    uintptr_t actual_game = 0; uint64_t actual_player = 0; int32_t date = 0;
    if (state.load(std::memory_order_acquire) == enabled && code_guard()
        && context(actual_game, actual_player, date) && actual_game == game && actual_player == player
        && date >= last_date) {
        if (retreat_depth == kRetreatScopeLimit || retreat_suppressed) {
            ++retreat_suppressed; token.suppressed = true; retreat_drops.fetch_add(1);
        } else {
            auto& frame = retreat_frames[retreat_depth++];
            frame.units.clear(); frame.combat = reinterpret_cast<uintptr_t>(combat);
            frame.has_record = false; frame.router_complete = false; frame.ambiguous = false;
            frame.removal = removing_unit != nullptr;
            frame.slot = 0; frame.sequence = 0; frame.drops_before = retreat_drops.load();
            Reader reader;
            bool copied = false;
            if (frame.removal) {
                const auto unit = reinterpret_cast<uintptr_t>(removing_unit);
                const auto return_rva = static_cast<uint32_t>(removal_return_pc - base);
                copied = frame.units.begin_removal(reader, frame.combat, unit, return_rva)
                    && frame.units.observe_removal(reader, unit, return_rva);
            } else {
                copied = frame.units.begin(reader, frame.combat, reinterpret_cast<uintptr_t>(losing_side));
            }
            if (!copied) frame.ambiguous = true;
            token.depth = retreat_depth;
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
    return token;
}

// Both helpers below are called while the existing capture owner holds its lock.
static void retreat_bind_record_locked(uintptr_t combat, unsigned slot, uint64_t seq, bool deferred) noexcept {
    if (!deferred || !retreat_depth || retreat_suppressed) return;
    auto& frame = retreat_frames[retreat_depth - 1];
    if (frame.combat != combat) return;
    if (frame.has_record) { frame.ambiguous = true; frame.units.invalidate(); return; }
    frame.has_record = true; frame.slot = slot; frame.sequence = seq;
}
static bool retreat_defer_ready_locked(unsigned slot, uint64_t seq) noexcept {
    for (unsigned i = retreat_depth; i; --i) {
        auto& frame = retreat_frames[i - 1];
        if (frame.has_record && frame.slot == slot && frame.sequence == seq) {
            frame.router_complete = true;
            return true;
        }
    }
    return false;
}

static void capture_retreat_unit(void* unit, uintptr_t return_pc) noexcept {
    if (state.load(std::memory_order_acquire) != enabled || GetCurrentThreadId() != bound_thread
        || return_pc != base + retreat_capture::kObserveReturnRva || !retreat_depth || retreat_suppressed) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) { retreat_drops.fetch_add(1); return; }
    auto& frame = retreat_frames[retreat_depth - 1];
    if (frame.removal) { ReleaseSRWLockExclusive(&capture_lock); return; }
    if (frame.has_record && frame.router_complete && !frame.ambiguous && code_guard()) {
        Reader reader;
        if (!frame.units.observe(reader, reinterpret_cast<uintptr_t>(unit), retreat_capture::kObserveReturnRva))
            frame.ambiguous = true;
    } else frame.ambiguous = true;
    ReleaseSRWLockExclusive(&capture_lock);
}

static void end_retreat_scope(RetreatToken token) noexcept {
    if (!token.depth && !token.suppressed) return;
    AcquireSRWLockExclusive(&capture_lock);
    const bool mismatched=token.suppressed ? retreat_suppressed==0
        : (token.depth!=retreat_depth || retreat_suppressed!=0);
    if (mismatched) {
        state.store(fault, std::memory_order_release);
        for (auto& frame : retreat_frames) {
            frame.units.clear(); frame.combat = 0; frame.has_record = false;
            frame.sequence = 0; frame.slot = 0; frame.router_complete = false; frame.ambiguous = false;
            frame.removal = false;
        }
        retreat_depth = 0; retreat_suppressed = 0;
    } else if (token.suppressed) --retreat_suppressed;
    else {
        auto& frame = retreat_frames[--retreat_depth];
        if (frame.has_record && frame.slot < kSlots && values(slots[frame.slot]).sequence == frame.sequence
            && !slot_ready[frame.slot] && frame.router_complete) {
            auto& record = slots[frame.slot];
            uintptr_t actual_game = 0; uint64_t actual_player = 0; int32_t date = 0;
            const bool guards = !frame.ambiguous && retreat_drops.load() == frame.drops_before
                && state.load(std::memory_order_acquire) == enabled && code_guard()
                && context(actual_game, actual_player, date) && actual_game == game && actual_player == player
                && date == values(record).result.raw_date;
            frame.units.finish(frame.sequence, values(record).result.raw_date,
                static_cast<uint8_t>(contexts(record).context.kind), guards, record.retreat);
            slot_ready[frame.slot] = true;
        } else if (frame.has_record) state.store(fault, std::memory_order_release);
        frame.units.clear(); frame.combat = 0; frame.has_record = false;
        frame.sequence = 0; frame.slot = 0; frame.router_complete = false; frame.ambiguous = false;
        frame.removal = false;
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
