#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../information-mission-availability.h"
#include "../information-mission-availability-entry-plan.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static constexpr uint64_t kFra = UINT64_C(0x1200000100415246);
static constexpr uint64_t kEng = UINT64_C(0x1200000100474e45);
static constexpr size_t kModuleBytes = 0x2400000;
static uintptr_t base = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static bool lifecycle_rollback_incomplete = false;
static thread_local bool fixture_date_read_failed = false;
static thread_local bool identity_shift_after_original = false;
static thread_local bool original_has_returned = false;
static bool fixture_fra_is_player = false;
static uint64_t observation_creation = UINT64_C(0x329002);
static HANDLE log_file = INVALID_HANDLE_VALUE;
static wchar_t diagnostic_log_path[32768]{};
static wchar_t native_log_path[32768]{};
static uintptr_t fra_country = 0;
static unsigned char* country_memory = nullptr;
static unsigned char* task_memory = nullptr;
static unsigned task_count = 0;
static int32_t* date_pointer = nullptr;
static std::atomic<unsigned> checks{0};
static std::atomic<unsigned> failures{0};
static unsigned scenarios = 0;
static bool fail_delete_function_table = false;

#define CHECK(condition, label) do { \
    ++checks; \
    if (!(condition)) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); } \
} while (0)

namespace bridge_entry_patch {
struct PatchTarget final {
    void* address = nullptr;
    unsigned size = 0;
    const unsigned char* expected = nullptr;
    const unsigned char* replacement = nullptr;
    const void* original_trampoline = nullptr;
    SIZE_T original_trampoline_size = 0;
};
struct PatchPlan final { unsigned count = 0; PatchTarget targets[1]{}; };
struct PatchResult final {
    bool published = false;
    bool success = false;
    bool threads_resumed = false;
    bool protection_restored = false;
};
static bool suppress_publish = false;
static unsigned apply_calls = 0;
static unsigned rollback_calls = 0;

static PatchResult guarded_patch_apply(const PatchPlan& plan) {
    ++apply_calls;
    if (plan.count != 1 || !plan.targets[0].address
            || !plan.targets[0].expected || !plan.targets[0].replacement)
        return {};
    if (suppress_publish) return {false, false, true, true};
    const auto& target = plan.targets[0];
    if (std::memcmp(target.address, target.expected, target.size) != 0) return {};
    std::memcpy(target.address, target.replacement, target.size);
    return {true, true, true, true};
}

static PatchResult guarded_patch_rollback(const PatchPlan& plan) {
    ++rollback_calls;
    if (plan.count != 1 || !plan.targets[0].address
            || !plan.targets[0].expected || !plan.targets[0].replacement)
        return {};
    const auto& target = plan.targets[0];
    if (std::memcmp(target.address, target.replacement, target.size) != 0) return {};
    std::memcpy(target.address, target.expected, target.size);
    return {true, true, true, true};
}
} // namespace bridge_entry_patch

static BOOLEAN NTAPI call_real_delete_function_table(PRUNTIME_FUNCTION table) {
    return ::RtlDeleteFunctionTable(table);
}

static BOOLEAN NTAPI fixture_delete_function_table(PRUNTIME_FUNCTION table) {
    if (fail_delete_function_table) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return call_real_delete_function_table(table);
}

static bool read(uintptr_t address, uintptr_t& value) noexcept {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &copied) != FALSE && copied == sizeof(value);
}

static bool read(uintptr_t address, int32_t& value) noexcept {
    if (fixture_date_read_failed && original_has_returned
            && date_pointer && address == reinterpret_cast<uintptr_t>(date_pointer)) return false;
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &copied) != FALSE && copied == sizeof(value);
}

template<class Value>
static bool read(uintptr_t address, Value& value) noexcept {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &copied) != FALSE && copied == sizeof(value);
}

static bool insult_query_country(uint64_t reference, uintptr_t& country) noexcept {
    if (reference == kFra && fra_country) {
        country = fra_country + ((identity_shift_after_original && original_has_returned) ? 0x20 : 0);
        return true;
    }
    if (reference == kEng) {
        country = fra_country + 0x100;
        return true;
    }
    return false;
}

#define RtlDeleteFunctionTable fixture_delete_function_table
#include "../information-mission-availability-observer.inc"
#undef RtlDeleteFunctionTable

namespace Observer = mission_availability_observer;
namespace Owned = information::mission_availability;
namespace Entry = information::mission_availability::entry;

static void put_u64(uintptr_t address, uint64_t value) noexcept {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static void put_string32(uintptr_t address, const std::string& text,
                         uintptr_t heap_address) noexcept {
    std::memset(reinterpret_cast<void*>(address), 0, 32);
    const uint64_t length = text.size();
    uint64_t capacity = 15;
    if (text.size() <= 15) {
        std::memcpy(reinterpret_cast<void*>(address), text.data(), text.size());
        reinterpret_cast<char*>(address)[text.size()] = 0;
    } else {
        capacity = text.size();
        std::memcpy(reinterpret_cast<void*>(heap_address), text.data(), text.size());
        reinterpret_cast<char*>(heap_address)[text.size()] = 0;
        put_u64(address, heap_address);
    }
    put_u64(address + 16, length);
    put_u64(address + 24, capacity);
}

static uintptr_t make_definition(const std::string& name) {
    constexpr unsigned kStride = 0x400;
    if (!task_memory || task_count >= 512) return 0;
    const uintptr_t definition = reinterpret_cast<uintptr_t>(task_memory + task_count++ * kStride);
    put_string32(definition + 0x10, name, definition + 0x210);
    return definition;
}

struct Call final {
    uintptr_t definition = 0;
    uint64_t country = kFra;
    uint64_t return_value = 0;
    DWORD expected_error = ERROR_SUCCESS;
    DWORD returned_error = ERROR_SUCCESS;
    bool validate_error = false;
    bool throw_cpp = false;
    bool advance_date = false;
    bool shift_identity = false;
    bool fail_date_after = false;
    std::string mutate_name_to;
    Call* nested = nullptr;
    bool nested_invoked = false;
    unsigned calls = 0;
};

struct FixtureException final {};
static thread_local Call* active_call = nullptr;

static uint64_t test_original(void* definition, uint64_t country);

static uint64_t invoke(Call& call) {
    struct Restore final {
        Call* previous;
        ~Restore() { active_call = previous; }
    } restore{active_call};
    active_call = &call;
    return Observer::observe(reinterpret_cast<void*>(call.definition), call.country);
}

static uint64_t test_original(void* definition, uint64_t country) {
    Call* call = active_call;
    CHECK(call != nullptr, "original stub has an active owned fixture call");
    if (!call) return 0;
    ++call->calls;
    CHECK(reinterpret_cast<uintptr_t>(definition) == call->definition,
        "original receives the exact mission definition pointer");
    CHECK(country == call->country, "original receives the exact 64-bit country reference");
    if (call->validate_error)
        CHECK(GetLastError() == call->expected_error,
            "observe restores incoming LastError before forwarding");

    if (call->nested && !call->nested_invoked) {
        call->nested_invoked = true;
        const uint64_t nested_result = invoke(*call->nested);
        CHECK(nested_result == call->nested->return_value,
            "nested original return value passes through unchanged");
    }
    if (!call->mutate_name_to.empty())
        put_string32(call->definition + 0x10, call->mutate_name_to, call->definition + 0x210);
    if (call->advance_date && date_pointer) ++*date_pointer;
    if (call->shift_identity) identity_shift_after_original = true;
    if (call->fail_date_after) fixture_date_read_failed = true;
    original_has_returned = true;
    SetLastError(call->returned_error);
    if (call->throw_cpp) throw FixtureException{};
    return call->return_value;
}

static Call make_call(uintptr_t definition, uint64_t returned,
                      uint64_t country = kFra) {
    Call result{};
    result.definition = definition;
    result.country = country;
    result.return_value = returned;
    return result;
}

struct WorkerCall final {
    Call call{};
    HANDLE start = nullptr;
    uint64_t returned = 0;
    DWORD returned_error = 0, thread = 0;
};

static DWORD WINAPI run_worker(void* argument) {
    auto& job = *static_cast<WorkerCall*>(argument);
    WaitForSingleObject(job.start, INFINITE);
    job.thread = GetCurrentThreadId();
    SetLastError(job.call.expected_error);
    job.returned = invoke(job.call);
    job.returned_error = GetLastError();
    return 0;
}

static void reset_call_environment() noexcept {
    original_has_returned = false;
    identity_shift_after_original = false;
    fixture_date_read_failed = false;
    thread_changed = false;
    frame_thread = GetCurrentThreadId();
}

static const Observer::Event& queued(unsigned offset) {
    return Observer::events[(Observer::head + offset) % 64];
}

static void test_entry_plan(const std::array<unsigned char, Entry::kPatchBytes>& prefix,
                            const std::array<unsigned char, 28>& unwind,
                            uint64_t pe_rva, uint64_t pe_va, uint64_t pe_end,
                            uint64_t pe_unwind, uint64_t pe_unwind_bytes,
                            uint64_t pe_prefix_bytes) {
    ++scenarios;
    CHECK(pe_rva == Entry::kEntryRva && pe_va == UINT64_C(0x140000000) + Entry::kEntryRva,
        "entry RVA and preferred VA match the 329 PE ledger");
    CHECK(pe_end == Entry::kSourceEndRva && pe_unwind == Entry::kUnwindRva
            && pe_unwind_bytes == unwind.size() && pe_prefix_bytes == 64,
        "source pdata end, unwind RVA and widths match the 329 PE ledger");
    CHECK(prefix == Entry::kPrefix && unwind == Entry::kSourceUnwind,
        "exact 15-byte hook prefix and all 28 original unwind bytes match the PE ledger");
    CHECK(Entry::kPatchBytes == 15 && Entry::kUnwindOffset == 64
            && information::battle::message_entry::kHomeSlotJumpBytes == 29,
        "entry patch and continuation layout have their fixed widths");

    const uintptr_t original_entry = information::battle::message_entry::kStaticImageBase
        + Entry::kEntryRva;
    const uintptr_t hook = reinterpret_cast<uintptr_t>(&Observer::observe);
    Entry::Plan output{};
    CHECK(Entry::prepare(prefix, unwind, original_entry, hook, output),
        "exact PE prefix and original unwind prepare an owned entry plan");
    CHECK(output.runtime.begin == 0 && output.runtime.end == 44
            && output.runtime.unwind == Entry::kUnwindOffset,
        "runtime range covers the 15-byte copied prefix and 29-byte home-slot jump");
    CHECK(std::memcmp(output.image.data(), prefix.data(), prefix.size()) == 0,
        "the trampoline starts with the exact 15-byte native prefix");
    uint32_t home_low = 0, home_high = 0, jump_slot = 0;
    std::memcpy(&home_low, output.image.data() + 15 + 3, sizeof(home_low));
    std::memcpy(&home_high, output.image.data() + 15 + 14, sizeof(home_high));
    std::memcpy(&jump_slot, output.image.data() + 15 + 25, sizeof(jump_slot));
    uint32_t target_low = 0, target_high = 0;
    std::memcpy(&target_low, output.image.data() + 15 + 7, sizeof(target_low));
    std::memcpy(&target_high, output.image.data() + 15 + 18, sizeof(target_high));
    const uint64_t continuation = (static_cast<uint64_t>(target_high) << 32) | target_low;
    CHECK(home_low == 0x20 && home_high == 0x24 && jump_slot == 0x20
            && continuation == original_entry + Entry::kPatchBytes,
        "home-slot jump uses the fourth home slot at RSP+0x20 and the exact continuation");
    CHECK(output.patch[0] == 0xff && output.patch[1] == 0x25
            && output.patch[14] == 0x90,
        "the 15-byte entry patch is an absolute jump followed by one NOP");
    CHECK(output.image[64] == 0x01 && ((output.image[64] >> 3) & 7) == 0
            && std::memcmp(output.image.data() + 64, Entry::kProjectedUnwind.data(),
                           Entry::kProjectedUnwind.size()) == 0,
        "projected unwind metadata retains version 1 and clears handler flags");
    CHECK(((Entry::kSourceUnwind[0] >> 3) & 7) != 0,
        "the original unwind metadata contains handler flags that are not copied");

    auto wrong_prefix = prefix;
    wrong_prefix[7] ^= 1;
    Entry::Plan rejected_prefix{};
    CHECK(!Entry::prepare(wrong_prefix, unwind, original_entry, hook, rejected_prefix),
        "a one-byte change to the native prefix is rejected");
    auto wrong_unwind = unwind;
    wrong_unwind[27] ^= 1;
    Entry::Plan rejected_unwind{};
    CHECK(!Entry::prepare(prefix, wrong_unwind, original_entry, hook, rejected_unwind),
        "a one-byte change to the original handler-bearing unwind metadata is rejected");
}

static bool open_log(const wchar_t* path, DWORD access, DWORD disposition) {
    log_file = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    return log_file != INVALID_HANDLE_VALUE;
}

static void test_install_guards(const std::array<unsigned char, Entry::kPatchBytes>& prefix,
                                const std::array<unsigned char, 28>& unwind,
                                RUNTIME_FUNCTION& source_runtime) {
    ++scenarios;
    auto* code = reinterpret_cast<unsigned char*>(base + Entry::kEntryRva);
    auto* source_unwind = reinterpret_cast<unsigned char*>(base + Entry::kUnwindRva);
    DWORD64 source_image_base = 0;
    CHECK(RtlLookupFunctionEntry(base + Entry::kEntryRva, &source_image_base, nullptr) != nullptr
            && source_image_base == base,
        "real Windows lookup finds the fixture's private source pdata record");

    code[5] ^= 1;
    CHECK(!Observer::install() && !Observer::original && !Observer::executable,
        "install refuses a changed 15-byte native entry prefix before allocating");
    std::memcpy(code, prefix.data(), prefix.size());

    source_unwind[27] ^= 1;
    CHECK(!Observer::install() && !Observer::original && !Observer::executable,
        "install refuses changed original UNWIND_INFO bytes before allocating");
    std::memcpy(source_unwind, unwind.data(), unwind.size());

    const uint32_t good_end = source_runtime.EndAddress;
    source_runtime.EndAddress = good_end - 1;
    CHECK(!Observer::install(), "install refuses a non-exact pdata end RVA");
    source_runtime.EndAddress = good_end;
    const uint32_t good_unwind = source_runtime.UnwindData;
    source_runtime.UnwindData = good_unwind + 1;
    CHECK(!Observer::install(), "install refuses a non-exact pdata unwind RVA");
    source_runtime.UnwindData = good_unwind;

    bridge_entry_patch::suppress_publish = true;
    fail_delete_function_table = true;
    CHECK(!Observer::install() && lifecycle_rollback_incomplete
            && Observer::table_registered && Observer::executable && Observer::original,
        "failed RtlDeleteFunctionTable retains the registered trampoline and marks incomplete rollback");
    DWORD64 lookup_base = 0;
    CHECK(RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(Observer::executable),
                                 &lookup_base, nullptr) == &Observer::unwind
            && lookup_base == reinterpret_cast<DWORD64>(Observer::executable),
        "a delete failure leaves the trampoline's runtime function registered");
    fail_delete_function_table = false;
    Observer::release_unpublished();
    lifecycle_rollback_incomplete = false;
    bridge_entry_patch::suppress_publish = false;
    CHECK(!Observer::table_registered && !Observer::executable && !Observer::original,
        "retrying unpublished cleanup deletes its table before freeing the trampoline");
}

static void test_baseline_updates_and_both_directions() {
    ++scenarios;
    reset_call_environment();
    *date_pointer = 14671210;
    const uintptr_t definition = make_definition("availability_toggle");
    const unsigned start = Observer::size;

    auto first = make_call(definition, 0);
    invoke(first);
    CHECK(first.calls == 1 && Observer::size == start,
        "the first successful native evaluation only establishes a baseline");
    *date_pointer = 14671220;
    auto same = make_call(definition, 0);
    invoke(same);
    CHECK(same.calls == 1 && Observer::size == start
            && Observer::baselines.values[0].date == 14671220,
        "an unchanged successful result updates only the last-observed date");

    *date_pointer = 14671230;
    auto became_eligible = make_call(definition, 1);
    became_eligible.expected_error = 0x1234;
    became_eligible.returned_error = 0x5678;
    became_eligible.validate_error = true;
    SetLastError(0x1234);
    const uint64_t one = invoke(became_eligible);
    CHECK(one == 1 && GetLastError() == 0x5678
            && became_eligible.calls == 1 && Observer::size == start + 1,
        "false-to-true preserves the native result, original call count and LastError");
    CHECK(queued(Observer::size - 1).change.before == false
            && queued(Observer::size - 1).change.after.eligible == true
            && queued(Observer::size - 1).change.previous_date == 14671220
            && queued(Observer::size - 1).change.after.date == 14671230,
        "false-to-true records the prior successful sample date and current observation date");

    *date_pointer = 14671240;
    auto became_ineligible = make_call(definition, 0);
    invoke(became_ineligible);
    CHECK(Observer::size == start + 2
            && queued(Observer::size - 1).change.before == true
            && queued(Observer::size - 1).change.after.eligible == false
            && queued(Observer::size - 1).change.previous_date == 14671230
            && queued(Observer::size - 1).change.after.date == 14671240,
        "true-to-false records the prior sample and current observation dates");
}

static void test_fra_npc_and_other_country_isolation() {
    ++scenarios;
    reset_call_environment();
    fixture_fra_is_player = false;
    *date_pointer = 14671250;
    const unsigned start = Observer::size;
    const LONG drops = Observer::total_dropped;
    const uintptr_t fra_definition = make_definition("npc_fra_task");
    auto baseline = make_call(fra_definition, 0);
    invoke(baseline);
    auto changed = make_call(fra_definition, 1);
    invoke(changed);
    CHECK(!fixture_fra_is_player && Observer::size == start + 1,
        "a FRA NPC predicate change is captured without requiring a player country");

    const uintptr_t other_definition = make_definition("other_country_task");
    const unsigned before_other = Observer::size;
    auto other = make_call(other_definition, 1, kEng);
    invoke(other);
    CHECK(other.calls == 1 && Observer::size == before_other
            && Observer::total_dropped == drops,
        "a non-FRA task evaluation is forwarded once and isolated without a gap");
}

static void test_nested_same_and_distinct_tasks() {
    ++scenarios;
    reset_call_environment();
    *date_pointer = 14671260;
    const uintptr_t same_definition = make_definition("nested_same_task");
    auto same_baseline = make_call(same_definition, 0);
    invoke(same_baseline);
    const unsigned before_same = Observer::size;
    Call inner_same = make_call(same_definition, 0);
    Call outer_same = make_call(same_definition, 1);
    outer_same.nested = &inner_same;
    invoke(outer_same);
    CHECK(outer_same.calls == 1 && inner_same.calls == 1
            && Observer::size == before_same + 1,
        "same-country same-task nested evaluation is suppressed while the outer change remains");

    const uintptr_t first_definition = make_definition("nested_task_a");
    const uintptr_t second_definition = make_definition("nested_task_b");
    auto first_baseline = make_call(first_definition, 0);
    auto second_baseline = make_call(second_definition, 0);
    invoke(first_baseline);
    invoke(second_baseline);
    const unsigned before_distinct = Observer::size;
    Call inner_other = make_call(second_definition, 1);
    Call outer_other = make_call(first_definition, 1);
    outer_other.nested = &inner_other;
    invoke(outer_other);
    CHECK(outer_other.calls == 1 && inner_other.calls == 1
            && Observer::size == before_distinct + 2,
        "nested evaluation of a different task retains both real changes");
}

static void test_date_identity_name_and_invalid_return_gaps() {
    ++scenarios;
    reset_call_environment();
    const LONG drops_start = Observer::total_dropped;
    const unsigned events_start = Observer::size;

    *date_pointer = 14671270;
    const uintptr_t date_definition = make_definition("date_crossing_task");
    auto date_base = make_call(date_definition, 0);
    invoke(date_base);
    auto crossing = make_call(date_definition, 1);
    crossing.advance_date = true;
    invoke(crossing);
    CHECK(Observer::size == events_start && Observer::total_dropped == drops_start + 1,
        "a date change during native evaluation is reported as a gap, not a transition");

    reset_call_environment();
    *date_pointer = 14671280;
    const uintptr_t identity_definition = make_definition("identity_shift_task");
    auto identity_base = make_call(identity_definition, 0);
    invoke(identity_base);
    auto identity_change = make_call(identity_definition, 1);
    identity_change.shift_identity = true;
    invoke(identity_change);
    CHECK(Observer::size == events_start && Observer::total_dropped == drops_start + 2,
        "a country object identity change during evaluation is a capture gap");

    reset_call_environment();
    *date_pointer = 14671290;
    const std::string stable_name = "name_mutation_task";
    const uintptr_t name_definition = make_definition(stable_name);
    auto name_base = make_call(name_definition, 0);
    invoke(name_base);
    auto name_mutation = make_call(name_definition, 1);
    name_mutation.mutate_name_to = "different_task_name";
    invoke(name_mutation);
    CHECK(Observer::size == events_start && Observer::total_dropped == drops_start + 3,
        "a mission definition name mutation during evaluation is rejected as a gap");
    put_string32(name_definition + 0x10, stable_name, name_definition + 0x210);
    *date_pointer = 14671300;
    auto name_recovered = make_call(name_definition, 1);
    invoke(name_recovered);
    CHECK(Observer::size == events_start + 1
            && std::string(queued(Observer::size - 1).change.after.mission.text,
                           queued(Observer::size - 1).change.after.mission.length) == stable_name,
        "restoring the original mission name permits a later real transition");

    reset_call_environment();
    *date_pointer = 14671310;
    const uintptr_t bad_return_definition = make_definition("invalid_wide_return");
    auto bad_return = make_call(bad_return_definition, UINT64_C(0x123456789abcdef0));
    bad_return.expected_error = 0x7788;
    bad_return.returned_error = 0x8899;
    bad_return.validate_error = true;
    SetLastError(0x7788);
    const unsigned before_invalid = Observer::size;
    const uint64_t wide = invoke(bad_return);
    CHECK(wide == UINT64_C(0x123456789abcdef0) && GetLastError() == 0x8899
            && Observer::size == before_invalid,
        "the complete 64-bit native return and LastError pass through while invalid returns create no event");

    reset_call_environment();
    *date_pointer = 14671320;
    const uintptr_t non_ascii_definition = make_definition(std::string("\x80", 1));
    auto non_ascii = make_call(non_ascii_definition, 1);
    const LONG before_non_ascii = Observer::total_dropped;
    const unsigned before_non_ascii_events = Observer::size;
    invoke(non_ascii);
    CHECK(Observer::size == before_non_ascii_events
            && Observer::total_dropped == before_non_ascii + 1,
        "non-printable mission IDs are rejected and retained as a capture gap");
}

static void test_cpp_exception_cleanup_and_recovery() {
    ++scenarios;
    reset_call_environment();
    *date_pointer = 14671330;
    const unsigned events_start = Observer::size;
    const LONG drops_start = Observer::total_dropped;
    const uintptr_t definition = make_definition("throw_then_recover");
    auto baseline = make_call(definition, 0);
    invoke(baseline);

    *date_pointer = 14671340;
    auto throwing = make_call(definition, 1);
    throwing.throw_cpp = true;
    bool propagated = false;
    try { (void)invoke(throwing); }
    catch (const FixtureException&) { propagated = true; }
    CHECK(propagated && Observer::depth == 0 && Observer::size == events_start
            && Observer::total_dropped == drops_start + 1,
        "a C++ original exception propagates, unwinds active depth and emits only a gap");

    *date_pointer = 14671350;
    auto recovered = make_call(definition, 1);
    invoke(recovered);
    CHECK(recovered.calls == 1 && Observer::depth == 0
            && Observer::size == events_start + 1
            && queued(Observer::size - 1).change.previous_date == 14671330,
        "the next successful evaluation works and uses the last successful baseline date");
}

static void test_baseline_capacity() {
    ++scenarios;
    static_assert(Owned::kMaxTasks == 4096, "mission eligibility baseline cap is fixed");
    Owned::Baselines baselines{};
    Owned::Change change{};
    for (unsigned index = 0; index < Owned::kMaxTasks; ++index) {
        Owned::Value value{};
        value.country = kFra;
        value.definition = index + 1;
        value.date = 1;
        std::snprintf(value.mission.text, sizeof(value.mission.text), "T%04u", index);
        value.mission.length = 5;
        CHECK(baselines.observe(value, change) == Owned::Result::baseline,
            "each slot through the 4096-task capacity stores its first baseline");
    }
    Owned::Value overflow{};
    overflow.country = kFra;
    overflow.definition = UINT64_C(0x12345678);
    overflow.date = 1;
    std::memcpy(overflow.mission.text, "OVERFLOW", 8);
    overflow.mission.length = 8;
    CHECK(baselines.count == 4096
            && baselines.observe(overflow, change) == Owned::Result::full
            && baselines.count == 4096,
        "a 4097th distinct task is rejected at the fixed baseline limit");
}

static void test_worker_evaluation_and_parallel_commit() {
    ++scenarios;
    reset_call_environment();
    *date_pointer = 14671355;
    const auto definition = make_definition("worker_task");
    auto baseline = make_call(definition, 0);
    invoke(baseline);
    const unsigned start = Observer::size;
    const auto worker_before = InterlockedCompareExchange64(&Observer::worker_evaluations, 0, 0);
    WorkerCall job{};
    job.call = make_call(definition, 1);
    job.call.expected_error = 0x1101;
    job.call.returned_error = 0x2202;
    job.call.validate_error = true;
    job.start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE thread = CreateThread(nullptr, 0, run_worker, &job, 0, nullptr);
    CHECK(job.start && thread, "create a genuine worker call and its start event");
    if (!job.start || !thread) std::exit(9);
    SetEvent(job.start);
    CHECK(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "worker task evaluation terminates");
    CHECK(CloseHandle(thread) && CloseHandle(job.start), "close worker handles");
    CHECK(job.thread != frame_thread && job.call.calls == 1 && job.returned == 1
            && job.returned_error == job.call.returned_error && Observer::size == start + 1,
        "a real non-frame worker preserves the native call and publishes the validated task change");
    CHECK(InterlockedCompareExchange64(&Observer::worker_evaluations, 0, 0) == worker_before + 1,
        "worker evaluations have an explicit diagnostic count");

    const auto shared_definition = make_definition("parallel_shared_task");
    auto shared_baseline = make_call(shared_definition, 0);
    invoke(shared_baseline);
    WorkerCall jobs[2]{};
    HANDLE threads[2]{};
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CHECK(ready != nullptr, "create a shared worker start event");
    if (!ready) std::exit(10);
    const unsigned parallel_start = Observer::size;
    for (unsigned index = 0; index < 2; ++index) {
        jobs[index].call = make_call(shared_definition, 1);
        jobs[index].call.expected_error = 0x3300 + index;
        jobs[index].call.returned_error = 0x4400 + index;
        jobs[index].call.validate_error = true;
        jobs[index].start = ready;
        threads[index] = CreateThread(nullptr, 0, run_worker, &jobs[index], 0, nullptr);
        CHECK(threads[index] != nullptr, "create a concurrent task worker");
        if (!threads[index]) std::exit(11);
    }
    SetEvent(ready);
    CHECK(WaitForMultipleObjects(2, threads, TRUE, 10000) == WAIT_OBJECT_0,
        "both concurrent native calls terminate");
    for (unsigned index = 0; index < 2; ++index) {
        CHECK(jobs[index].call.calls == 1 && jobs[index].returned == 1
                && jobs[index].returned_error == jobs[index].call.returned_error,
            "concurrent originals each preserve their result and thread-local LastError");
        CHECK(CloseHandle(threads[index]), "close a concurrent worker handle");
    }
    CHECK(CloseHandle(ready), "close the concurrent start event");
    CHECK(Observer::size == parallel_start + 1 && queued(parallel_start).change.before == false
            && queued(parallel_start).change.after.eligible == true,
        "concurrent identical native results commit exactly one baseline transition");
    char health[4096] = "{\"event\":\"diplomacy_observer_health\"}\n";
    Observer::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"drops_by_reason\":{") && std::strstr(health, "\"baseline_count\":")
            && std::strstr(health, "}}}\n"), "health includes bounded reason and worker diagnostics");
}

static void test_queue_limits_flush_and_write_fault() {
    ++scenarios;
    reset_call_environment();
    Observer::flush();
    CHECK(Observer::size == 0 && Observer::dropped == 0,
        "prior owned transitions and gaps are flushed before queue-capacity checks");
    const LONG drops_start = Observer::total_dropped;
    *date_pointer = 14671360;
    for (unsigned index = 0; index < 65; ++index) {
        char id[32]{};
        std::snprintf(id, sizeof(id), "queue_task_%02u", index);
        const uintptr_t definition = make_definition(id);
        auto baseline = make_call(definition, 0);
        auto change = make_call(definition, 1);
        invoke(baseline);
        invoke(change);
        CHECK(baseline.calls == 1 && change.calls == 1,
            "queue capacity samples forward each native evaluation once");
    }
    CHECK(Observer::size == 64 && Observer::total_dropped == drops_start + 1
            && Observer::dropped == 1,
        "the bounded native queue retains 64 events and counts one overflow");
    Observer::flush();
    CHECK(Observer::size == 32 && Observer::dropped == 0,
        "one flush writes at most 32 events and its drop gap");
    Observer::flush();
    CHECK(Observer::size == 0,
        "a second flush drains the remaining 32 queue entries");

    const uintptr_t fault_definition = make_definition("write_fault_head");
    auto fault_base = make_call(fault_definition, 0);
    auto fault_change = make_call(fault_definition, 1);
    invoke(fault_base);
    invoke(fault_change);
    const unsigned head = Observer::head;
    CHECK(CloseHandle(log_file) != FALSE, "close the writable native log before the write-fault case");
    log_file = INVALID_HANDLE_VALUE;
    CHECK(open_log(diagnostic_log_path, GENERIC_READ, OPEN_EXISTING),
        "reopen the fixture log read-only to force a genuine Windows WriteFile failure");
    Observer::flush();
    CHECK(Observer::transport_fault.load() && Observer::size == 1 && Observer::head == head,
        "a failed real file write latches transport fault and retains the uncommitted head");
    char health[640] = "{\"event\":\"fixture_health\"}";
    Observer::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"installed\":true") != nullptr
            && std::strstr(health, "\"transport_fault\":true") != nullptr
            && std::strstr(health, "\"queue_readable\":true") != nullptr
            && std::strstr(health, "\"queued\":1") != nullptr,
        "health reports the source fault and retained native queue head");
    std::printf("HEALTH_JSON:%s\n", health);
    CHECK(CloseHandle(log_file) != FALSE, "close the read-only fault handle");
    log_file = INVALID_HANDLE_VALUE;
}

static void reset_for_contract_log() {
    Observer::baselines = Owned::Baselines{};
    Observer::head = 0;
    Observer::size = 0;
    std::memset(Observer::events, 0, sizeof(Observer::events));
    InterlockedExchange64(&Observer::sequence, 0);
    InterlockedExchange(&Observer::dropped, 0);
    InterlockedExchange(&Observer::total_dropped, 0);
    Observer::transport_fault.store(false);
    Observer::installed.store(true);
    reset_call_environment();
}

static void write_contract_log() {
    ++scenarios;
    reset_for_contract_log();
    CHECK(open_log(native_log_path, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS),
        "open the isolated native contract JSONL as a real Windows file");
    if (log_file == INVALID_HANDLE_VALUE) return;

    const uintptr_t definition = make_definition("availability_delivery");
    *date_pointer = 14671001;
    auto baseline = make_call(definition, 0);
    invoke(baseline);
    *date_pointer = 14671025;
    auto forward = make_call(definition, 1);
    invoke(forward);
    *date_pointer = 14671049;
    auto reverse = make_call(definition, 0);
    invoke(reverse);

    std::string maximum(256, 'x');
    maximum[254] = '"';
    maximum[255] = '\\';
    const uintptr_t maximum_definition = make_definition(maximum);
    *date_pointer = 14671073;
    auto maximum_baseline = make_call(maximum_definition, 0);
    invoke(maximum_baseline);
    *date_pointer = 14671097;
    auto maximum_change = make_call(maximum_definition, 1);
    invoke(maximum_change);
    CHECK(Observer::size == 3 && Observer::sequence == 3,
        "isolated contract run has exactly three ordered native transitions and no gaps");
    Observer::flush();
    CHECK(Observer::size == 0 && Observer::dropped == 0,
        "all isolated contract rows are written without a capture gap");
    CHECK(CloseHandle(log_file) != FALSE, "close the native contract JSONL");
    log_file = INVALID_HANDLE_VALUE;
}

static bool env_path(const wchar_t* name, wchar_t* output, DWORD capacity) {
    const DWORD length = GetEnvironmentVariableW(name, output, capacity);
    return length > 0 && length < capacity;
}

static bool parse_bytes(const char* hex, unsigned char* output, size_t bytes) {
    if (!hex || std::strlen(hex) != bytes * 2) return false;
    for (size_t index = 0; index < bytes; ++index) {
        char pair[3]{hex[index * 2], hex[index * 2 + 1], 0};
        char* end = nullptr;
        const unsigned long value = std::strtoul(pair, &end, 16);
        if (!end || *end || value > 0xff) return false;
        output[index] = static_cast<unsigned char>(value);
    }
    return true;
}

static uint64_t parse_number(const char* text, int base_value) {
    return std::strtoull(text, nullptr, base_value);
}

int main(int argc, char** argv) {
    static_assert(sizeof(uintptr_t) == 8, "native mission availability fixture requires x64");
    if (argc != 9) return 2;
    std::array<unsigned char, Entry::kPatchBytes> prefix{};
    std::array<unsigned char, 28> unwind{};
    if (!parse_bytes(argv[1], prefix.data(), prefix.size())
            || !parse_bytes(argv[2], unwind.data(), unwind.size())) return 3;
    const auto pe_rva = parse_number(argv[3], 16);
    const auto pe_va = parse_number(argv[4], 16);
    const auto pe_end = parse_number(argv[5], 16);
    const auto pe_unwind = parse_number(argv[6], 16);
    const auto pe_unwind_bytes = parse_number(argv[7], 10);
    const auto pe_prefix_bytes = parse_number(argv[8], 10);
    std::fprintf(stderr, "STAGE entry-plan\n"); std::fflush(stderr);
    test_entry_plan(prefix, unwind, pe_rva, pe_va, pe_end, pe_unwind,
                    pe_unwind_bytes, pe_prefix_bytes);

    auto* module = static_cast<unsigned char*>(VirtualAlloc(nullptr, kModuleBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!module) return 4;
    std::fprintf(stderr, "STAGE private-module\n"); std::fflush(stderr);
    base = reinterpret_cast<uintptr_t>(module);
    const uintptr_t game = base + 0x2350000;
    date_pointer = reinterpret_cast<int32_t*>(game + 0x1dd0);
    *date_pointer = 14671200;
    put_u64(base + 0x233fe58, game);
    std::memcpy(reinterpret_cast<void*>(base + Entry::kEntryRva), prefix.data(), prefix.size());
    std::memcpy(reinterpret_cast<void*>(base + Entry::kUnwindRva), unwind.data(), unwind.size());

    RUNTIME_FUNCTION source_runtime{
        Entry::kEntryRva, Entry::kSourceEndRva, Entry::kUnwindRva,
    };
    std::fprintf(stderr, "STAGE source-function-table\n"); std::fflush(stderr);
    if (!RtlAddFunctionTable(&source_runtime, 1, base)) return 5;
    if (!env_path(L"INFORMATION_MISSION_AVAILABILITY_FIXTURE_LOG",
                  diagnostic_log_path, static_cast<DWORD>(std::size(diagnostic_log_path)))
            || !env_path(L"INFORMATION_MISSION_AVAILABILITY_NATIVE_LOG",
                         native_log_path, static_cast<DWORD>(std::size(native_log_path)))) return 6;
    if (!open_log(diagnostic_log_path, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS)) return 7;

    country_memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x50000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    task_memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x100000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!country_memory || !task_memory) return 8;
    fra_country = reinterpret_cast<uintptr_t>(country_memory);
    frame_thread = GetCurrentThreadId();

    std::fprintf(stderr, "STAGE install-guards\n"); std::fflush(stderr);
    test_install_guards(prefix, unwind, source_runtime);
    bridge_entry_patch::suppress_publish = false;
    CHECK(Observer::install(), "exact prefix and source metadata install the native observer");
    CHECK(bridge_entry_patch::apply_calls >= 2 && Observer::published
            && Observer::table_registered && Observer::executable,
        "the patch-manager stub receives the prepared original trampoline");
    Observer::installed.store(true); // Simulate the main family's atomic post-commit activation.
    Observer::original = &test_original;

    std::fprintf(stderr, "STAGE observer-behavior\n"); std::fflush(stderr);
    test_baseline_updates_and_both_directions();
    test_fra_npc_and_other_country_isolation();
    test_nested_same_and_distinct_tasks();
    test_date_identity_name_and_invalid_return_gaps();
    test_cpp_exception_cleanup_and_recovery();
    test_worker_evaluation_and_parallel_commit();
    test_baseline_capacity();
    std::fprintf(stderr, "STAGE queue-and-fault\n"); std::fflush(stderr);
    test_queue_limits_flush_and_write_fault();
    std::fprintf(stderr, "STAGE contract-log\n"); std::fflush(stderr);
    write_contract_log();

    CHECK(Observer::rollback(), "fixture rolls the entry patch back to the exact original prefix");
    CHECK(std::memcmp(reinterpret_cast<void*>(base + Entry::kEntryRva), prefix.data(), prefix.size()) == 0,
        "patch rollback restores the original 15-byte function prefix");
    Observer::published = false;
    Observer::release_unpublished();
    CHECK(!Observer::table_registered && !Observer::executable,
        "fixture releases its owned dynamic trampoline function table and memory");
    Observer::installed.store(false);
    if (log_file != INVALID_HANDLE_VALUE) {
        CHECK(CloseHandle(log_file) != FALSE, "close the final native fixture log handle");
        log_file = INVALID_HANDLE_VALUE;
    }
    CHECK(::RtlDeleteFunctionTable(&source_runtime) != FALSE,
        "unregister the fixture's private source pdata row");
    CHECK(VirtualFree(task_memory, 0, MEM_RELEASE) != FALSE,
        "release owned mission definition memory");
    CHECK(VirtualFree(country_memory, 0, MEM_RELEASE) != FALSE,
        "release owned FRA country memory");
    CHECK(VirtualFree(module, 0, MEM_RELEASE) != FALSE,
        "release the private module and date fixture memory");

    std::printf("FIXTURE_RESULT: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks.load(), scenarios);
    std::printf("RtlVirtualUnwind: delegated to separate entry ABI fixture; not run here\n");
    return failures ? 1 : 0;
}
