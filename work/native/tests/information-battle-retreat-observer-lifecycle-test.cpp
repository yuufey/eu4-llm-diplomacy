#include "../information-battle-retreat-entry-plan.h"
#include "../information-battle-owned-retreat.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace harness {

namespace battle = information::battle;
namespace owned = battle::owned_retreat;

using Address = std::uintptr_t;
using DWORD = std::uint32_t;
using DWORD64 = std::uint64_t;
using BOOL = int;

struct RUNTIME_FUNCTION final {
    std::uint32_t BeginAddress = 0u;
    std::uint32_t EndAddress = 0u;
    std::uint32_t UnwindData = 0u;
};

struct SRWLOCK final {
    bool held = false;
};

#define SRWLOCK_INIT SRWLOCK{}
inline constexpr BOOL FALSE = 0;
inline constexpr DWORD MEM_COMMIT = 0x1000u;
inline constexpr DWORD MEM_RESERVE = 0x2000u;
inline constexpr DWORD PAGE_READWRITE = 0x04u;
inline constexpr DWORD PAGE_EXECUTE_READ = 0x20u;

struct FakeMemory final {
    static constexpr std::size_t kRegionBytes = 0x30000u;
    static constexpr std::size_t kRegionCount = 8u;
    struct Region final {
        Address base = 0u;
        std::size_t size = 0u;
        std::array<unsigned char, kRegionBytes> bytes{};
    };
    std::array<Region, kRegionCount> regions{};
    std::size_t count = 0u;
    std::size_t read_calls = 0u;
    std::size_t read_bytes = 0u;

    void reset() noexcept { *this = FakeMemory{}; }

    static bool range_end(Address base, std::size_t size,
                          Address& end) noexcept {
        if (size == 0u || base > UINT64_MAX - size) return false;
        end = base + static_cast<Address>(size);
        return end > base;
    }

    bool add(Address base, std::size_t size) noexcept {
        if (count >= regions.size() || size == 0u || size > kRegionBytes) {
            return false;
        }
        Address end = 0u;
        if (!range_end(base, size, end)) return false;
        for (std::size_t index = 0u; index < count; ++index) {
            Address old_end = 0u;
            if (!range_end(regions[index].base, regions[index].size,
                           old_end)
                    || (base < old_end && regions[index].base < end)) {
                return false;
            }
        }
        Region& region = regions[count++];
        region.base = base;
        region.size = size;
        std::fill(region.bytes.begin(), region.bytes.end(), 0u);
        return true;
    }

    Region* find(Address address, std::size_t size) noexcept {
        for (std::size_t index = 0u; index < count; ++index) {
            Region& region = regions[index];
            if (address < region.base
                    || address - region.base > region.size
                    || size > region.size - static_cast<std::size_t>(
                                   address - region.base)) continue;
            return &region;
        }
        return nullptr;
    }

    bool put(Address address, const void* source, std::size_t size) noexcept {
        if (source == nullptr || size == 0u) return false;
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(region->bytes.data() + static_cast<std::size_t>(
                         address - region->base), source, size);
        return true;
    }

    bool put_u64(Address address, std::uint64_t value) noexcept {
        return put(address, &value, sizeof(value));
    }

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        read_bytes += size;
        if (destination == nullptr || size == 0u) return false;
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(destination, region->bytes.data() + static_cast<std::size_t>(
                         address - region->base), size);
        return true;
    }
};

static FakeMemory fake_memory{};
static DWORD fake_thread = 77u;
static bool fake_code_guard = true;
static Address fake_game = UINT64_C(0x230000000);
static std::uint64_t fake_player = UINT64_C(0xabcdef0011223344);
static std::int32_t fake_date = 56563608;

struct Reader final {
    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        return fake_memory.read(address, destination, size);
    }
};

template <typename T>
bool read_value(Address address, T& output) noexcept {
    return fake_memory.read(address,
                            reinterpret_cast<unsigned char*>(&output),
                            sizeof(output));
}

bool code_guard() noexcept { return fake_code_guard; }

bool context(Address& game, std::uint64_t& player,
             std::int32_t& date) noexcept {
    game = fake_game;
    player = fake_player;
    date = fake_date;
    return true;
}

enum State : unsigned char {
    disabled = 0,
    enabled = 1,
    fault = 2,
    source_changed = 3,
};

static std::atomic<State> state{enabled};
static Address base = UINT64_C(0x140000000);
static Address game = fake_game;
static std::uint64_t player = fake_player;
static std::int32_t last_date = fake_date;
static DWORD bound_thread = fake_thread;
static SRWLOCK capture_lock = SRWLOCK_INIT;

struct Values final {
    std::uint64_t sequence = 0u;
    struct Result final {
        std::int32_t raw_date = 0;
    } result{};
};

struct Contexts final {
    struct Context final {
        std::uint8_t kind = 0u;
    } context{};
};

struct Record final {
    battle::retreat_wire::Snapshot retreat{};
    Values value{};
    Contexts context_value{};
};

inline Values& values(Record& record) noexcept { return record.value; }
inline const Values& values(const Record& record) noexcept {
    return record.value;
}
inline Contexts& contexts(Record& record) noexcept {
    return record.context_value;
}
inline const Contexts& contexts(const Record& record) noexcept {
    return record.context_value;
}

namespace bridge_entry_patch {

inline constexpr unsigned kMaxTargets = 64u;

struct PatchTarget final {
    void* target = nullptr;
    unsigned patch_bytes = 0u;
    const unsigned char* expected = nullptr;
    const unsigned char* replacement = nullptr;
    unsigned char* trampoline = nullptr;
    std::uint32_t continuation = 0u;
};

struct PatchPlan final {
    unsigned count = 0u;
    std::array<PatchTarget, kMaxTargets> targets{};
};

}  // namespace bridge_entry_patch

static bridge_entry_patch::PatchPlan patch{};
static bool patched = false;
static void* information_battle_outcome_retreat_original = nullptr;
static void* information_battle_unit_retreat_original = nullptr;
static void* information_battle_unit_removal_retreat_original = nullptr;

inline BOOL TryAcquireSRWLockExclusive(SRWLOCK* lock) noexcept {
    if (lock == nullptr || lock->held) return FALSE;
    lock->held = true;
    return 1;
}

inline void AcquireSRWLockExclusive(SRWLOCK* lock) noexcept {
    if (lock != nullptr) lock->held = true;
}

inline void ReleaseSRWLockExclusive(SRWLOCK* lock) noexcept {
    if (lock != nullptr) lock->held = false;
}

inline DWORD GetCurrentThreadId() noexcept { return fake_thread; }
inline void* GetCurrentProcess() noexcept { return nullptr; }
inline void* VirtualAlloc(void*, std::size_t, DWORD, DWORD) noexcept {
    return nullptr;
}
inline BOOL VirtualProtect(void*, std::size_t, DWORD, DWORD*) noexcept {
    return FALSE;
}
inline BOOL FlushInstructionCache(void*, const void*, std::size_t) noexcept {
    return FALSE;
}
inline BOOL RtlAddFunctionTable(RUNTIME_FUNCTION*, DWORD, DWORD64) noexcept {
    return FALSE;
}
inline const RUNTIME_FUNCTION* RtlLookupFunctionEntry(
    DWORD64, DWORD64*, void*) noexcept {
    return nullptr;
}

void information_battle_outcome_retreat_hook() noexcept {}
void information_battle_unit_retreat_hook() noexcept {}
void information_battle_unit_removal_retreat_hook() noexcept {}

constexpr unsigned kSlots = 8u;
static Record slots[kSlots]{};
static bool slot_ready[kSlots]{};

#include "../information-battle-retreat-observer.inc"

#undef SRWLOCK_INIT

struct Fixture final {
    static constexpr Address kCombat = UINT64_C(0x220000000);
    static constexpr Address kSide0 = UINT64_C(0x220001000);
    static constexpr Address kSide1 = UINT64_C(0x220002000);
    static constexpr Address kNodes = UINT64_C(0x220010000);
    static constexpr Address kUnits = UINT64_C(0x220020000);
    static constexpr std::size_t kNodeStride = 0x20u;
    static constexpr std::size_t kUnitStride = 0x300u;
    std::array<Address, owned::kMaxUnits> units{};
    std::array<Address, owned::kMaxUnits> nodes{};
    std::size_t count = 0u;

    bool build(std::size_t requested, bool all_side1 = false) noexcept {
        fake_memory.reset();
        units.fill(0u);
        nodes.fill(0u);
        count = requested;
        if (requested == 0u || requested > units.size()) return false;
        const std::size_t side0_count = all_side1
            ? 0u : (requested + 1u) / 2u;
        if (!fake_memory.add(kCombat, 0x100u)
                || !fake_memory.add(kSide0, 0x200u)
                || !fake_memory.add(kSide1, 0x200u)
                || !fake_memory.add(kNodes, requested * kNodeStride)
                || !fake_memory.add(kUnits, requested * kUnitStride)) {
            return false;
        }
        if (!fake_memory.put_u64(kCombat + battle::owned_retreat::kCombatSidesOffset,
                                 kSide0)
                || !fake_memory.put_u64(kCombat
                                             + battle::owned_retreat::kCombatSidesOffset
                                             + sizeof(Address), kSide1)
                || !fake_memory.put_u64(kSide0
                                             + battle::owned_retreat::kSideParentOffset,
                                        kCombat)
                || !fake_memory.put_u64(kSide1
                                             + battle::owned_retreat::kSideParentOffset,
                                        kCombat)) return false;
        Address side0_head = 0u;
        Address side1_head = 0u;
        std::size_t side0_index = 0u;
        std::size_t side1_index = side0_count;
        for (std::size_t index = 0u; index < requested; ++index) {
            nodes[index] = kNodes + index * kNodeStride;
            units[index] = kUnits + index * kUnitStride;
            const bool first_side = index < side0_count;
            const std::size_t side_position = first_side
                ? side0_index++ : side1_index++;
            const Address next = first_side
                ? (side_position + 1u < side0_count
                       ? kNodes + (index + 1u) * kNodeStride : 0u)
                : (side_position + 1u < requested
                       ? kNodes + (index + 1u) * kNodeStride : 0u);
            if (first_side && side0_head == 0u) side0_head = nodes[index];
            if (!first_side && side1_head == 0u) side1_head = nodes[index];
            const std::uint64_t owner = index == 0u
                ? UINT64_C(0xffffffffffffffff)
                : static_cast<std::uint64_t>(0x100u + index);
            const std::array<unsigned char, 5u> flags{{
                static_cast<unsigned char>(index + 1u),
                static_cast<unsigned char>(0xa0u + index),
                static_cast<unsigned char>(index + 2u),
                static_cast<unsigned char>(index + 3u),
                static_cast<unsigned char>(index + 4u),
            }};
            if (!fake_memory.put_u64(nodes[index]
                                         + battle::owned_retreat::kNodeUnitOffset,
                                     units[index])
                    || !fake_memory.put_u64(nodes[index]
                                                 + battle::owned_retreat::kNodeNextOffset,
                                            next)
                    || !fake_memory.put_u64(units[index] + owned::kUnitCombatOffset,
                                            kCombat)
                    || !fake_memory.put_u64(units[index]
                                                 + battle::owned_retreat::kUnitOwnerFullRefOffset,
                                            owner)
                    || !fake_memory.put(units[index]
                                             + battle::owned_retreat::kUnitRawFlagsOffset,
                                        flags.data(), flags.size())) return false;
        }
        return fake_memory.put_u64(kSide0
                                       + battle::owned_retreat::kSideLinkedHeadOffset,
                                   side0_head)
            && fake_memory.put_u64(kSide1
                                       + battle::owned_retreat::kSideLinkedHeadOffset,
                                   side1_head);
    }
};

struct Harness final {
    unsigned checks = 0u;
    unsigned failures = 0u;

    void check(bool value, const char* name) noexcept {
        ++checks;
        if (!value) {
            ++failures;
            std::printf("FAIL:%s\n", name);
        }
    }
};

void reset_parent() noexcept {
    state.store(enabled, std::memory_order_release);
    base = UINT64_C(0x140000000);
    game = fake_game;
    player = fake_player;
    last_date = fake_date;
    bound_thread = fake_thread;
    fake_code_guard = true;
    capture_lock.held = false;
    retreat_depth = 0u;
    retreat_suppressed = 0u;
    retreat_drops.store(0u, std::memory_order_release);
    for (auto& record : slots) record = Record{};
    std::fill(std::begin(slot_ready), std::end(slot_ready), false);
    for (auto& frame : retreat_frames) {
        frame.units.clear();
        frame.combat = 0u;
        frame.slot = 0u;
        frame.sequence = 0u;
        frame.drops_before = 0u;
        frame.has_record = false;
        frame.router_complete = false;
        frame.ambiguous = false;
        frame.removal = false;
    }
}

void bind_ready(Address combat, unsigned slot, std::uint64_t sequence,
                std::uint8_t kind, bool deferred = true) noexcept {
    values(slots[slot]).sequence = sequence;
    values(slots[slot]).result.raw_date = fake_date;
    contexts(slots[slot]).context.kind = kind;
    retreat_bind_record_locked(combat, slot, sequence, deferred);
    (void)retreat_defer_ready_locked(slot, sequence);
}

void retain_unused_inc_functions() noexcept {
    using Guard = bool (*)() noexcept;
    using Prepare = bool (*)() noexcept;
    const Guard guard = &retreat_code_guard;
    const Prepare prepare = &prepare_retreat_entries;
    const Guard mark = &retreat_mark_patched;
    (void)guard;
    (void)prepare;
    (void)mark;
}

void test_happy_lifecycle(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(4u), "happy fixture");
    owned::Scope direct_scope{};
    Reader direct_reader{};
    h.check(direct_scope.begin(direct_reader, fixture.kCombat, fixture.kSide0),
            "direct scope begin");
    h.check(!direct_scope.observe(direct_reader, fixture.units[0], 0x22bed0u),
            "direct wrong return false");
    h.check(direct_scope.observe(direct_reader, fixture.units[0],
                                owned::kObserveReturnRva),
            "direct observe true");
    h.check(!direct_scope.observe(direct_reader, fixture.units[0],
                                 owned::kObserveReturnRva),
            "direct duplicate observe false");
    owned::Scope direct_side1{};
    Reader direct_reader_side1{};
    h.check(direct_side1.begin(direct_reader_side1, fixture.kCombat,
                               fixture.kSide1), "direct side1 begin");
    h.check(direct_side1.observe(direct_reader_side1, fixture.units[2],
                                owned::kObserveReturnRva),
            "direct side1 observe true");
    h.check(direct_side1.observe(direct_reader_side1, fixture.units[3],
                                owned::kObserveReturnRva),
            "direct side1 second observe true");
    const RetreatToken token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide1));
    h.check(token.depth == 1u && !slot_ready[0], "begin not ready");
    bind_ready(fixture.kCombat, 0u, 42u, 1u);
    h.check(!slot_ready[0], "router bind not ready");
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[2]),
                         base + battle::owned_retreat::kObserveReturnRva);
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[3]),
                         base + battle::owned_retreat::kObserveReturnRva);
    end_retreat_scope(token);
    h.check(slot_ready[0], "end marks ready");
    h.check(slots[0].retreat.present
                && slots[0].retreat.sequence == 42u
                && slots[0].retreat.observed_count == 2u
                && slots[0].retreat.units[0].ordinal == 2u
                && slots[0].retreat.units[1].ordinal == 3u,
            "happy retreat values");
    h.check(slots[0].retreat.units[0].owner_full_ref
                == UINT64_C(0x102)
                && slots[0].retreat.units[0].raw_flags
                    == std::array<std::uint8_t, 4u>{{3u, 4u, 5u, 6u}},
            "happy owner and flags");
    h.check(retreat_depth == 0u && retreat_frames[0].combat == 0u
                && !retreat_frames[0].units.active(),
            "happy frame cleared");
}

void test_admission_and_ignored_callbacks(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(2u), "admission fixture");
    const std::size_t before_disabled = fake_memory.read_calls;
    state.store(disabled, std::memory_order_release);
    h.check(begin_retreat_scope(reinterpret_cast<void*>(fixture.kCombat),
                                reinterpret_cast<void*>(fixture.kSide0)).depth == 0u
                && fake_memory.read_calls == before_disabled,
            "disabled rejected");
    reset_parent();
    h.check(fixture.build(2u), "thread fixture");
    bound_thread = fake_thread + 1u;
    h.check(begin_retreat_scope(reinterpret_cast<void*>(fixture.kCombat),
                                reinterpret_cast<void*>(fixture.kSide0)).depth == 0u,
            "wrong thread rejected");
    reset_parent();
    h.check(fixture.build(2u), "return fixture");
    const RetreatToken token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    const std::size_t before_return = fake_memory.read_calls;
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[0]),
                         base + 0x22bed0u);
    h.check(fake_memory.read_calls == before_return
                && !retreat_frames[0].ambiguous,
            "wrong return ignored");
    end_retreat_scope(token);
}

void test_record_and_router_order_fail_closed(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(2u), "early callback fixture");
    const RetreatToken token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[0]),
                         base + battle::owned_retreat::kObserveReturnRva);
    bind_ready(fixture.kCombat, 0u, 42u, 1u);
    end_retreat_scope(token);
    h.check(slot_ready[0] && !slots[0].retreat.present,
            "early callback stays unknown");

    reset_parent();
    h.check(fixture.build(2u), "duplicate bind fixture");
    const RetreatToken duplicate_token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    bind_ready(fixture.kCombat, 0u, 43u, 1u);
    retreat_bind_record_locked(fixture.kCombat, 0u, 43u, true);
    (void)retreat_defer_ready_locked(0u, 43u);
    end_retreat_scope(duplicate_token);
    h.check(slot_ready[0] && !slots[0].retreat.present,
            "duplicate bind not complete");

    reset_parent();
    h.check(fixture.build(2u), "duplicate observe fixture");
    const RetreatToken observe_token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    bind_ready(fixture.kCombat, 0u, 44u, 1u);
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[0]),
                         base + battle::owned_retreat::kObserveReturnRva);
    capture_retreat_unit(reinterpret_cast<void*>(fixture.units[0]),
                         base + battle::owned_retreat::kObserveReturnRva);
    end_retreat_scope(observe_token);
    h.check(slot_ready[0] && !slots[0].retreat.present,
            "duplicate observe not complete");
}

void test_stale_sequence_guard_and_disabled_end(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(2u), "stale fixture");
    const RetreatToken stale = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    bind_ready(fixture.kCombat, 0u, 45u, 1u);
    values(slots[0]).sequence = 46u;
    end_retreat_scope(stale);
    h.check(state.load(std::memory_order_acquire) == fault
                && retreat_depth == 0u && retreat_frames[0].combat == 0u,
            "stale sequence faults and clears");

    reset_parent();
    h.check(fixture.build(2u), "disabled end fixture");
    const RetreatToken disabled_end = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    bind_ready(fixture.kCombat, 0u, 47u, 1u);
    state.store(disabled, std::memory_order_release);
    end_retreat_scope(disabled_end);
    h.check(slot_ready[0] && !slots[0].retreat.present,
            "disabled end keeps unknown retreat");
}

void test_nested_pairing_wrong_order_and_busy_lock(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(2u), "nested fixture");
    const RetreatToken outer = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    bind_ready(fixture.kCombat, 0u, 50u, 1u);
    const RetreatToken inner = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide1));
    bind_ready(fixture.kCombat, 1u, 51u, 2u);
    end_retreat_scope(inner);
    h.check(slot_ready[1] && !slot_ready[0], "inner closes own slot");
    end_retreat_scope(outer);
    h.check(slot_ready[0] && retreat_depth == 0u,
            "outer closes after inner");

    reset_parent();
    h.check(fixture.build(2u), "wrong order fixture");
    const RetreatToken first = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    const RetreatToken second = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide1));
    end_retreat_scope(first);
    h.check(state.load(std::memory_order_acquire) == fault
                && retreat_depth == 0u && retreat_frames[0].combat == 0u,
            "wrong token faults and clears all");
    end_retreat_scope(second);

    reset_parent();
    h.check(fixture.build(2u), "busy fixture");
    capture_lock.held = true;
    const std::size_t before_busy = fake_memory.read_calls;
    const RetreatToken busy = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    h.check(busy.depth == 0u && !busy.suppressed
                && retreat_drops.load() != 0u
                && fake_memory.read_calls == before_busy,
            "busy capture lock drops without blocking");
    capture_lock.held = false;
}

void test_orphan_suppressed_and_all_losing_boundary(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(1u), "orphan suppressed fixture");
    RetreatToken orphan{};
    orphan.suppressed = true;
    end_retreat_scope(orphan);
    h.check(state.load(std::memory_order_acquire) == fault
                && retreat_depth == 0u && retreat_suppressed == 0u
                && std::all_of(std::begin(retreat_frames),
                               std::end(retreat_frames),
                               [](const RetreatFrame& frame) {
                                   return frame.combat == 0u
                                       && !frame.units.active();
                               }),
            "orphan suppressed faults without underflow");

    reset_parent();
    h.check(fixture.build(owned::kMaxUnits, true),
            "all losing 128-unit fixture");
    const RetreatToken token = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide1));
    h.check(token.depth == 1u, "all losing 128 begin");
    bind_ready(fixture.kCombat, 0u, 128u, 1u);
    for (std::size_t index = 0u; index < owned::kMaxUnits; ++index) {
        capture_retreat_unit(reinterpret_cast<void*>(fixture.units[index]),
                             base + battle::owned_retreat::kObserveReturnRva);
    }
    end_retreat_scope(token);
    h.check(slot_ready[0] && slots[0].retreat.present
                && slots[0].retreat.initial_unit_count == owned::kMaxUnits
                && slots[0].retreat.observed_count == owned::kMaxUnits
                && slots[0].retreat.units[0].ordinal == 0u
                && slots[0].retreat.units[owned::kMaxUnits - 1u].ordinal
                    == owned::kMaxUnits - 1u
                && retreat_depth == 0u && retreat_frames[0].combat == 0u,
            "all losing 128 units complete");
}

void test_scope_overflow_suppresses_and_closes(Harness& h) {
    reset_parent();
    Fixture fixture{};
    h.check(fixture.build(1u), "overflow fixture");
    std::array<RetreatToken, kRetreatScopeLimit> tokens{};
    for (unsigned index = 0u; index < kRetreatScopeLimit; ++index) {
        tokens[index] = begin_retreat_scope(
            reinterpret_cast<void*>(fixture.kCombat),
            reinterpret_cast<void*>(fixture.kSide0));
        h.check(tokens[index].depth == index + 1u, "nested depth accepted");
    }
    const RetreatToken overflow = begin_retreat_scope(
        reinterpret_cast<void*>(fixture.kCombat),
        reinterpret_cast<void*>(fixture.kSide0));
    h.check(overflow.depth == 0u && overflow.suppressed
                && retreat_suppressed == 1u && retreat_drops.load() != 0u,
            "overflow suppressed and dropped");
    end_retreat_scope(overflow);
    for (unsigned index = kRetreatScopeLimit; index != 0u; --index) {
        end_retreat_scope(tokens[index - 1u]);
    }
    h.check(retreat_depth == 0u && retreat_suppressed == 0u
                && std::all_of(std::begin(slot_ready), std::end(slot_ready),
                               [](bool value) { return !value; }),
            "overflow scopes close without complete claim");
}

void test_removal_state_before_original(Harness& h) {
    for (unsigned variant = 0u; variant < 6u; ++variant) {
        reset_parent();
        Fixture fixture{};
        h.check(fixture.build(2u), "removal fixture");
        const Address unit = fixture.units[1];
        const std::array<unsigned char, 5u> flags{{0u, 0xa5u, 1u, 1u, 0u}};
        h.check(fake_memory.put(unit + owned::kUnitRawFlagsOffset,
                                flags.data(), flags.size()), "removal flags");
        const auto before = fake_memory.read_calls;
        const RetreatToken token = begin_retreat_scope(
            reinterpret_cast<void*>(fixture.kCombat), nullptr,
            reinterpret_cast<void*>(unit), base + owned::kRemovalReturnRva
                + (variant == 1u ? 1u : 0u));
        if (variant == 1u) {
            h.check(token.depth == 0u && fake_memory.read_calls == before,
                    "wrong removal caller has no scope or reads");
            continue;
        }
        h.check(token.depth == 1u && retreat_frames[0].removal,
                "removal scope captures before original");
        // The native original may clear membership and flags after it emits
        // the result. Closing the scope must only use the owned copy.
        h.check(fake_memory.put_u64(unit + owned::kUnitCombatOffset, 0u),
                "original clears unit combat");
        const std::array<unsigned char, 5u> cleared{};
        h.check(fake_memory.put(unit + owned::kUnitRawFlagsOffset,
                                cleared.data(), cleared.size()),
                "original changes flags");
        const auto after_original = fake_memory.read_calls;
        capture_retreat_unit(reinterpret_cast<void*>(unit),
                             base + owned::kObserveReturnRva);
        h.check(fake_memory.read_calls == after_original
                    && !retreat_frames[0].ambiguous,
                "regular callback cannot contaminate removal scope");
        if (variant != 2u) {
            bind_ready(fixture.kCombat + (variant == 3u ? 8u : 0u),
                       0u, 700u + variant, 2u);
        }
        if (variant == 4u) fake_code_guard = false;
        if (variant == 5u) values(slots[0]).sequence += 1u;
        end_retreat_scope(token);
        const auto& snapshot = slots[0].retreat;
        if (variant == 0u) {
            h.check(slot_ready[0] && snapshot.present
                        && snapshot.capture_source == owned::kRemovalCaptureSource
                        && snapshot.combat_side_index == 1u
                        && snapshot.sequence == 700u
                        && snapshot.observed_count == 1u
                        && snapshot.units[0].owner_full_ref == 0x101u
                        && snapshot.units[0].raw_flags
                            == std::array<std::uint8_t, 4u>{{0u, 1u, 1u, 0u}},
                    "removal result retains pre-original state and identity");
        } else {
            h.check(!snapshot.present, "unbound or stale removal has no evidence");
        }
        h.check(fake_memory.read_calls == after_original
                    && retreat_depth == 0u && !retreat_frames[0].removal
                    && !retreat_frames[0].units.active(),
                "removal closes without post-original unit reads");
    }
}

}  // namespace harness

int main() {
    harness::retain_unused_inc_functions();
    harness::Harness harness{};
    harness::test_happy_lifecycle(harness);
    harness::test_admission_and_ignored_callbacks(harness);
    harness::test_record_and_router_order_fail_closed(harness);
    harness::test_stale_sequence_guard_and_disabled_end(harness);
    harness::test_nested_pairing_wrong_order_and_busy_lock(harness);
    harness::test_orphan_suppressed_and_all_losing_boundary(harness);
    harness::test_scope_overflow_suppresses_and_closes(harness);
    harness::test_removal_state_before_original(harness);
    std::printf("CHECK_COUNT=%u FAILURES=%u\n",
                harness.checks, harness.failures);
    return harness.failures == 0u ? 0 : 1;
}
