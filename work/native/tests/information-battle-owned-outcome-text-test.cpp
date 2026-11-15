#define main old_display_context_test_main
#include "information-battle-owned-display-context-test.cpp"
#undef main

#include "../information-battle-owned-outcome-text.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>

namespace outcome = information::battle::owned_outcome_text;
namespace outcome_model = information::battle::display_context;
namespace outcome_cache = information::battle::owned_display_context;

namespace {

struct OutcomeReader final {
    FakeReader* source = nullptr;
    std::size_t calls = 0u;
    std::size_t bytes = 0u;
    std::size_t fail_at = 0u;
    Address last_address = 0u;

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++calls;
        last_address = address;
        bytes += size;
        if (calls == fail_at) return false;
        return source != nullptr && source->read(address, destination, size);
    }
};

static_assert(information::battle::owned_name_sources::reader_contract<
                  OutcomeReader>::value);

struct OutcomeGuard final {
    int calls = 0;
    int fail_at = 0;
    bool guard() noexcept { return ++calls != fail_at; }
};

static_assert(information::battle::owned_name_sources::guard_contract<
                  OutcomeGuard>::value);

constexpr std::array<const char*, outcome::kOutcomeKeyCount> kOutcomeValues{{
    "allies won raw",
    "allies lost raw",
    "you won raw",
    "you lost raw",
    "result won raw",
    "result loss raw",
    "other result raw",
    "warscore raw",
    "military head raw",
    "messenger raw",
}};
constexpr std::array<const char*, outcome::kOutcomeKeyCount> kExpectedOutcomeKeys{{
    "ALLIES_WON", "ALLIES_LOST", "YOU_WON", "YOU_LOST", "RESULT_WON",
    "RESULT_LOSS", "OTHERRESULT", "WARSCORE_FROM_BATTLE",
    "MESSAGE_HEAD_MIL", "MESSENGER",
}};

int outcome_failures = 0;

void outcome_check(bool ok, const char* label) {
    std::printf("CHECK %s %s\n", label, ok ? "PASS" : "FAIL");
    if (!ok) ++outcome_failures;
}

struct OutcomeLocaleEntry final {
    const char* key = nullptr;
    const char* value = nullptr;
    std::uint32_t hash = 0u;
    std::uint32_t offset = 0u;
};

struct OutcomeFixture final {
    Fixture& source = fixture();
    OutcomeReader reader{};
    OutcomeGuard guard{};
    outcome::Workspace workspace{};
    outcome::Snapshot output{};
    outcome::Result result{};

    bool build(int absent_index = -1, int empty_index = -1,
               bool invalid_language = false) noexcept {
        if (!build_fixture(source, 1u, false, false, -1, false)) return false;
        reader = OutcomeReader{};
        reader.source = &source.reader;
        guard = OutcomeGuard{};
        workspace.clear();
        output = outcome::Snapshot{};
        result = outcome::Result{};

        Region* table = source.reader.find(kLocalizationTable, 1u);
        Region* pool = source.reader.find(kLocalizationPool, 1u);
        if (table == nullptr || pool == nullptr) return false;
        std::memset(table->bytes.data(), 0, table->bytes.size());
        std::memset(pool->bytes.data(), 0, pool->bytes.size());

        std::array<OutcomeLocaleEntry, outcome::kOutcomeKeyCount> entries{};
        std::size_t count = 0u;
        std::size_t pool_cursor = 0u;
        for (std::size_t index = 0u; index < outcome::kOutcomeKeyCount; ++index) {
            if (static_cast<int>(index) == absent_index) continue;
            const char* value = static_cast<int>(index) == empty_index
                ? "" : kOutcomeValues[index];
            const std::size_t length = std::strlen(value);
            if (pool_cursor > kLocalizationPoolRegionBytes
                    || length + 1u > kLocalizationPoolRegionBytes - pool_cursor) {
                return false;
            }
            OutcomeLocaleEntry& entry = entries[count++];
            entry.key = outcome::kLocalizationKeys[index];
            entry.value = value;
            entry.hash = owned::detail::localization_hash(entry.key);
            entry.offset = static_cast<std::uint32_t>(pool_cursor);
            if (length != 0u && !source.reader.put_bytes(
                    kLocalizationPool + pool_cursor,
                    reinterpret_cast<const unsigned char*>(value), length)) {
                return false;
            }
            const unsigned char nul = 0u;
            if (!source.reader.put_bytes(kLocalizationPool + pool_cursor + length,
                                         &nul, 1u)) {
                return false;
            }
            pool_cursor += length + 1u;
        }
        for (std::size_t index = 1u; index < count; ++index) {
            const OutcomeLocaleEntry current = entries[index];
            std::size_t insertion = index;
            while (insertion != 0u
                    && entries[insertion - 1u].hash > current.hash) {
                entries[insertion] = entries[insertion - 1u];
                --insertion;
            }
            if (insertion != 0u
                    && entries[insertion - 1u].hash == current.hash) {
                return false;
            }
            if (insertion < count && entries[insertion].hash == current.hash) {
                return false;
            }
            entries[insertion] = current;
        }

        table->size = count * owned::kLocalizationEntryStride;
        for (std::size_t index = 0u; index < count; ++index) {
            const Address entry_address = kLocalizationTable
                + index * owned::kLocalizationEntryStride;
            const std::uint64_t hash = entries[index].hash;
            const std::uint32_t offset = entries[index].offset;
            const std::array<unsigned char, 4u> padding{};
            if (!source.reader.put(entry_address + owned::kLocalizationEntryHashOffset,
                                   hash)
                    || !source.reader.put(entry_address + owned::kLocalizationEntryValueOffset,
                                          offset)
                    || !source.reader.put_bytes(entry_address + 12u,
                                                padding.data(), padding.size())) {
                return false;
            }
        }

        const std::uint64_t pool_begin = kLocalizationPool;
        const std::uint64_t pool_end = kLocalizationPool + pool_cursor;
        const std::uint64_t pool_capacity_end =
            kLocalizationPool + kLocalizationPoolRegionBytes;
        const std::uint64_t table_begin = kLocalizationTable;
        const std::uint64_t table_end = table_begin + table->size;
        const std::uint64_t table_capacity = count + 7u;
        if (!source.reader.put(kLocalizationOuter +
                                   owned::kLocalizationPoolBeginOffset,
                               pool_begin)
                || !source.reader.put(kLocalizationOuter +
                                          owned::kLocalizationPoolEndOffset,
                                      pool_end)
                || !source.reader.put(kLocalizationOuter +
                                          owned::kLocalizationPoolCapacityEndOffset,
                                      pool_capacity_end)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableBeginOffset,
                                      table_begin)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableEndOffset,
                                      table_end)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableCapacityOffset,
                                      table_capacity)) {
            return false;
        }
        return !invalid_language || put_string32(
            source.reader, kLocalizationInner + owned::kLocalizationLanguageOffset,
            "english", false, 0u);
    }

    bool capture(std::uint8_t kind = 1u, std::uint64_t sequence = 42u,
                 std::int32_t date = kDate) noexcept {
        return outcome::capture(reader, guard, kImageBase, kImageSize, kGame,
                                sequence, date, kind, workspace, output, result);
    }
};

OutcomeFixture& outcome_fixture() {
    static OutcomeFixture value{};
    return value;
}

template <std::size_t MaxBytes>
bool text_equals(const outcome::TextValue<MaxBytes>& text,
                 outcome_model::State expected_state,
                 const char* expected) noexcept {
    const std::size_t length = std::strlen(expected);
    return text.state == expected_state && text.length == length
        && text.length <= MaxBytes && text.bytes[length] == 0u
        && std::memcmp(text.bytes.data(), expected, length) == 0;
}

bool snapshot_unknown(const outcome::Snapshot& snapshot) noexcept {
    if (snapshot.sequence != 0u || snapshot.raw_date != 0
            || snapshot.kind != 0u
            || snapshot.language.state != outcome_model::State::unknown
            || snapshot.language.length != 0u) {
        return false;
    }
    for (unsigned char byte : snapshot.language.bytes)
        if (byte != 0u) return false;
    for (const outcome::OutcomeValue& field : snapshot.fields) {
        if (field.state != outcome_model::State::unknown || field.length != 0u)
            return false;
        for (unsigned char byte : field.bytes)
            if (byte != 0u) return false;
    }
    return true;
}

bool workspace_cleared(const outcome::Workspace& workspace) noexcept {
    if (!snapshot_unknown(workspace.first_snapshot)
            || !snapshot_unknown(workspace.second_snapshot)
            || workspace.temporary_snapshot.state != outcome_model::State::unknown
            || workspace.temporary_snapshot.identity.sequence != 0u
            || workspace.temporary_snapshot.identity.date != 0
            || workspace.temporary_snapshot.identity.kind != 0u
            || workspace.temporary_snapshot.identity.stage != 0u
            || workspace.temporary_snapshot.arena_used != 0u
            || workspace.first_pass.record_count != 0u
            || workspace.first_pass.bytes_used != 0u) {
        return false;
    }
    for (const model::Text& field : workspace.temporary_snapshot.fields)
        if (field.state != outcome_model::State::unknown || field.offset || field.length)
            return false;
    for (const unsigned char byte : workspace.temporary_snapshot.arena)
        if (byte != 0u) return false;
    for (const unsigned char byte : workspace.first_pass.bytes)
        if (byte != 0u) return false;
    for (const outcome_cache::detail::ReadRecord& record :
         workspace.first_pass.records) {
        if (record.address != 0u || record.offset != 0u || record.size != 0u)
            return false;
    }
    for (unsigned char byte : workspace.scratch)
        if (byte != 0u) return false;
    return true;
}

void test_all_ten_fixed_keys() {
    OutcomeFixture& f = outcome_fixture();
    const bool setup = f.build();
    const bool ok = setup && f.capture();
    bool key_order_matches = true;
    for (std::size_t index = 0u; index < outcome::kOutcomeKeyCount; ++index) {
        key_order_matches = key_order_matches
            && std::strcmp(outcome::kLocalizationKeys[index],
                           kExpectedOutcomeKeys[index]) == 0;
    }
    bool values_match = ok && key_order_matches && text_equals(f.output.language,
        outcome_model::State::observed, "l_english");
    for (std::size_t index = 0u; index < outcome::kOutcomeKeyCount; ++index) {
        values_match = values_match && outcome::kLocalizationKeys[index] != nullptr
            && text_equals(f.output.fields[index], outcome_model::State::observed,
                           kOutcomeValues[index]);
    }
    outcome_check(values_match
                      && f.output.sequence == 42u && f.output.raw_date == kDate
                      && f.output.kind == 1u,
                  "same_event_language_and_ten_fixed_cache_values_are_copied_in_order");
    outcome_check(ok && f.guard.calls == 3
                      && f.result.two_pass_consistent
                      && f.result.observed
                      && f.result.read_calls == f.reader.calls
                      && f.result.read_calls <= outcome_cache::kMaxTotalReadCalls
                      && f.result.bytes_read <= outcome_cache::kMaxTotalReadBytes
                      && f.result.pass_read_calls[0] <= outcome_cache::kMaxReadCallsPerPass
                      && f.result.pass_read_calls[1] <= outcome_cache::kMaxReadCallsPerPass
                      && f.result.pass_bytes_read[0] <= outcome_cache::kMaxReadBytesPerPass
                      && f.result.pass_bytes_read[1] <= outcome_cache::kMaxReadBytesPerPass
                      && f.result.largest_read <= outcome_cache::kMaxSingleReadBytes
                      && workspace_cleared(f.workspace),
                  "two_pass_capture_uses_existing_shared_512kib_4096call_budget_and_clears_workspace");
}

void test_absent_and_known_empty_are_distinct() {
    OutcomeFixture& f = outcome_fixture();
    bool setup = f.build(1, 0);
    bool ok = setup && f.capture();
    outcome_check(ok
                      && text_equals(f.output.fields[0], outcome_model::State::observed, "")
                      && text_equals(f.output.fields[1], outcome_model::State::absent, "")
                      && text_equals(f.output.fields[2], outcome_model::State::observed,
                                     kOutcomeValues[2]),
                  "known_empty_value_is_observed_while_missing_key_is_absent");
    setup = f.build(static_cast<int>(outcome::Key::messenger));
    ok = setup && f.capture();
    outcome_check(ok && f.output.fields[9].state == outcome_model::State::absent
                      && f.output.fields[9].length == 0u
                      && f.output.fields[8].state == outcome_model::State::observed,
                  "tenth_key_can_be_absent_without_changing_neighbor_state");
}

void test_invalid_language_and_read_failure_clear_everything() {
    OutcomeFixture& f = outcome_fixture();
    bool setup = f.build(-1, -1, true);
    bool ok = setup && f.capture();
    outcome_check(!ok && f.result.failure == outcome_model::Failure::cache_invalid
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace)
                      && !f.result.observed && !f.result.two_pass_consistent,
                  "invalid_language_rejects_bundle_and_clears_working_storage");

    setup = f.build();
    f.reader.fail_at = 3u;
    ok = setup && f.capture();
    outcome_check(!ok && f.result.failure == outcome_model::Failure::read_failed
                      && f.reader.calls == 3u && snapshot_unknown(f.output)
                      && workspace_cleared(f.workspace),
                  "mid_read_failure_returns_all_unknown_and_clears_workspace");
}

void test_each_guard_stage_clears_bundle() {
    OutcomeFixture& f = outcome_fixture();
    for (int stage = 1; stage <= 3; ++stage) {
        const bool setup = f.build();
        f.guard.fail_at = stage;
        const bool ok = setup && f.capture();
        outcome_check(!ok && f.guard.calls == stage
                          && f.result.failure == outcome_model::Failure::guard
                          && snapshot_unknown(f.output)
                          && workspace_cleared(f.workspace),
                      stage == 1 ? "guard_before_failure_clears_outcome_bundle"
                          : (stage == 2 ? "guard_between_passes_failure_clears_bundle"
                                        : "guard_after_second_pass_failure_clears_bundle"));
    }
}

void test_second_pass_byte_change_clears_bundle() {
    OutcomeFixture& f = outcome_fixture();
    const bool setup = f.build();
    const unsigned char changed[] = {'m','u','t','a','t','e','d',0u};
    f.source.reader.mutate_on_second_date = true;
    f.source.reader.mutation_address = kLocalizationPool;
    f.source.reader.mutation_size = sizeof(changed);
    std::memcpy(f.source.reader.mutation_bytes.data(), changed, sizeof(changed));
    const bool ok = setup && f.capture();
    outcome_check(!ok && f.result.failure == outcome_model::Failure::source_changed
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "same_address_second_pass_byte_change_rejects_all_ten_values");
}

void test_second_pass_address_change_is_rejected_by_replay() {
    OutcomeFixture& f = outcome_fixture();
    const bool setup = f.build();
    f.workspace.clear();
    f.output = outcome::Snapshot{};
    f.result = outcome::Result{};
    f.result.attempted = true;
    f.result.failure = outcome_model::Failure::none;
    outcome::Workspace& workspace = f.workspace;
    outcome::Snapshot& output = f.output;
    outcome::Result& result = f.result;
    outcome_cache::detail::AddressRange wr{}, out{}, rr{};
    const bool ranges = setup
        && outcome_cache::detail::object_range(&workspace, sizeof(workspace), wr)
        && outcome_cache::detail::object_range(&output, sizeof(output), out)
        && outcome_cache::detail::object_range(&result, sizeof(result), rr);
    if (!ranges) {
        outcome_check(false, "address_replay_fixture_ranges_available");
        return;
    }
    outcome_cache::detail::PassReader<OutcomeReader, outcome::Workspace> first(
        f.reader, workspace, result, 0u, wr, out, rr,
        &workspace.first_pass, nullptr);
    const Address address = kGame + owned::kGameDateOffset;
    const bool first_ok = first.read(address, sizeof(std::int32_t))
        && first.complete();
    const std::size_t calls_before_second = f.reader.calls;
    outcome_cache::detail::PassReader<OutcomeReader, outcome::Workspace> second(
        f.reader, workspace, result, 1u, wr, out, rr,
        nullptr, &workspace.first_pass);
    const bool second_ok = second.read(address + 1u, sizeof(std::int32_t));
    outcome_check(first_ok && !second_ok
                      && result.failure == outcome_model::Failure::source_changed
                      && f.reader.calls == calls_before_second,
                  "second_pass_address_change_is_rejected_before_reader_access");
}

void test_shared_call_and_byte_budget_limits() {
    OutcomeFixture& f = outcome_fixture();
    bool setup = f.build();
    const Address budget_region = UINT64_C(0x360000);
    setup = setup && f.source.reader.add_region(budget_region, 256u);
    if (!setup) {
        outcome_check(false, "budget_fixture_created");
        return;
    }
    std::array<unsigned char, 256u> bytes{};
    setup = f.source.reader.put_bytes(budget_region, bytes.data(), bytes.size());
    f.workspace.clear();
    f.output = outcome::Snapshot{};
    f.result = outcome::Result{};
    f.result.attempted = true;
    f.result.failure = outcome_model::Failure::none;
    outcome::Result& result = f.result;
    outcome::Snapshot& output = f.output;
    outcome::Workspace& workspace = f.workspace;
    outcome_cache::detail::AddressRange wr{}, out{}, rr{};
    const bool ranges = setup
        && outcome_cache::detail::object_range(&workspace, sizeof(workspace), wr)
        && outcome_cache::detail::object_range(&output, sizeof(output), out)
        && outcome_cache::detail::object_range(&result, sizeof(result), rr);
    if (!ranges) {
        outcome_check(false, "budget_storage_ranges_available");
        return;
    }
    outcome_cache::detail::PassReader<OutcomeReader, outcome::Workspace> pass(
        f.reader, workspace, result, 0u, wr, out, rr,
        &workspace.first_pass, nullptr);
    bool all_allowed = true;
    for (std::size_t index = 0u; index < outcome_cache::kMaxReadBytesPerPass / 256u;
         ++index) {
        all_allowed = all_allowed && pass.read(budget_region, 256u);
    }
    const bool rejected_over_budget = !pass.read(budget_region, 256u);
    outcome_check(all_allowed && rejected_over_budget
                      && result.failure == outcome_model::Failure::budget
                      && result.pass_bytes_read[0] == outcome_cache::kMaxReadBytesPerPass
                      && result.bytes_read == outcome_cache::kMaxReadBytesPerPass
                      && result.read_calls < outcome_cache::kMaxReadCallsPerPass,
                  "shared_reader_rejects_over_256kib_per_pass_without_expanding_budget");

    workspace.clear();
    output = outcome::Snapshot{};
    result = outcome::Result{};
    result.attempted = true;
    result.failure = outcome_model::Failure::none;
    outcome::Workspace& call_workspace = workspace;
    outcome::Result& call_result = result;
    outcome::Snapshot& call_output = output;
    outcome_cache::detail::AddressRange call_wr{}, call_out{}, call_rr{};
    const bool call_ranges = outcome_cache::detail::object_range(
            &call_workspace, sizeof(call_workspace), call_wr)
        && outcome_cache::detail::object_range(
            &call_output, sizeof(call_output), call_out)
        && outcome_cache::detail::object_range(
            &call_result, sizeof(call_result), call_rr);
    outcome_cache::detail::PassReader<OutcomeReader, outcome::Workspace> call_pass(
        f.reader, call_workspace, call_result, 0u, call_wr, call_out, call_rr,
        &call_workspace.first_pass, nullptr);
    bool all_calls_allowed = call_ranges;
    for (std::size_t index = 0u;
         all_calls_allowed && index < outcome_cache::kMaxReadCallsPerPass;
         ++index) {
        all_calls_allowed = call_pass.read(budget_region, 1u);
    }
    const bool extra_call_rejected = all_calls_allowed
        && !call_pass.read(budget_region, 1u);
    outcome_check(extra_call_rejected
                      && call_result.failure == outcome_model::Failure::budget
                      && call_result.pass_read_calls[0]
                          == outcome_cache::kMaxReadCallsPerPass
                      && call_result.read_calls
                          == outcome_cache::kMaxReadCallsPerPass
                      && outcome_cache::kMaxTotalReadCalls == 4096u
                      && outcome_cache::kMaxTotalReadBytes == 512u * 1024u,
                  "shared_reader_rejects_over_2048_calls_per_pass_without_expanding_4096_total");
}

union OutcomeWorkspaceOutput final {
    outcome::Workspace workspace;
    outcome::Snapshot output;
    OutcomeWorkspaceOutput() noexcept {}
    ~OutcomeWorkspaceOutput() {}
};
union OutcomeWorkspaceResult final {
    outcome::Workspace workspace;
    outcome::Result result;
    OutcomeWorkspaceResult() noexcept {}
    ~OutcomeWorkspaceResult() {}
};
union OutcomeSnapshotResult final {
    outcome::Snapshot output;
    outcome::Result result;
    OutcomeSnapshotResult() noexcept {}
    ~OutcomeSnapshotResult() {}
};

template <std::size_t N>
bool unchanged(const void* object,
               const std::array<unsigned char, N>& before) noexcept {
    return std::memcmp(object, before.data(), N) == 0;
}

void test_parameter_aliases_do_not_mutate_inputs() {
    OutcomeFixture& f = outcome_fixture();
    (void)f.build();
    static OutcomeWorkspaceOutput a{};
    new (&a.workspace) outcome::Workspace{};
    a.workspace.first_snapshot.sequence = 17u;
    static std::array<unsigned char, sizeof(a)> before_a{};
    std::memcpy(before_a.data(), &a, sizeof(a));
    const bool a_ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, a.workspace,
        *reinterpret_cast<outcome::Snapshot*>(&a), f.result);
    outcome_check(!a_ok && unchanged(&a, before_a)
                      && f.reader.calls == 0u && f.guard.calls == 0,
                  "workspace_output_alias_returns_without_mutation");

    (void)f.build();
    static OutcomeWorkspaceResult b{};
    new (&b.workspace) outcome::Workspace{};
    b.workspace.second_snapshot.sequence = 23u;
    static std::array<unsigned char, sizeof(b)> before_b{};
    std::memcpy(before_b.data(), &b, sizeof(b));
    const bool b_ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, b.workspace, f.output,
        *reinterpret_cast<outcome::Result*>(&b));
    outcome_check(!b_ok && unchanged(&b, before_b)
                      && f.reader.calls == 0u && f.guard.calls == 0,
                  "workspace_result_alias_returns_without_mutation");

    (void)f.build();
    static OutcomeSnapshotResult c{};
    new (&c.output) outcome::Snapshot{};
    c.output.sequence = 31u;
    static std::array<unsigned char, sizeof(c)> before_c{};
    std::memcpy(before_c.data(), &c, sizeof(c));
    const bool c_ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, f.workspace, c.output,
        *reinterpret_cast<outcome::Result*>(&c));
    outcome_check(!c_ok && unchanged(&c, before_c)
                      && f.reader.calls == 0u && f.guard.calls == 0,
                  "output_result_alias_returns_without_mutation");
}

void test_source_ranges_alias_storage_without_mutation() {
    OutcomeFixture& f = outcome_fixture();
    const bool setup = f.build();
    f.workspace.first_snapshot.sequence = 91u;
    f.output.sequence = 92u;
    f.result.read_calls = 93u;
    const Address bases[] = {
        reinterpret_cast<Address>(&f.workspace),
        reinterpret_cast<Address>(&f.output),
        reinterpret_cast<Address>(&f.result),
    };
    const std::uint64_t workspace_sequence = f.workspace.first_snapshot.sequence;
    const std::uint64_t output_sequence = f.output.sequence;
    const std::uint32_t result_calls = f.result.read_calls;
    bool all_rejected_untouched = setup;
    for (Address base : bases) {
        const bool ok = outcome::capture(f.reader, f.guard, base, 32u, kGame,
            42u, kDate, 1u, f.workspace, f.output, f.result);
        all_rejected_untouched = all_rejected_untouched && !ok
            && f.workspace.first_snapshot.sequence == workspace_sequence
            && f.output.sequence == output_sequence
            && f.result.read_calls == result_calls;
    }
    outcome_check(all_rejected_untouched && f.reader.calls == 0u
                      && f.guard.calls == 0,
                  "source_image_range_aliases_workspace_output_or_result_without_mutation");
}

void test_input_validation() {
    OutcomeFixture& f = outcome_fixture();
    bool setup = f.build();
    bool ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize, kGame,
        0u, kDate, 1u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace)
                      && f.reader.calls == 0u && f.guard.calls == 0,
                  "zero_sequence_is_rejected_before_reader_or_guard");

    setup = f.build();
    ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize, kGame,
        42u, -1, 1u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "negative_date_is_rejected");

    setup = f.build();
    ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize, kGame,
        42u, kDate, 3u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "kind_outside_land_or_naval_is_rejected");

    setup = f.build();
    ok = outcome::capture(f.reader, f.guard, kImageBase, 0x100u, kGame,
        42u, kDate, 1u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "image_range_must_include_localization_cache_cell");

    setup = f.build();
    ok = outcome::capture(f.reader, f.guard, 0u, kImageSize, kGame,
        42u, kDate, 1u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "noncanonical_image_base_is_rejected");

    setup = f.build();
    ok = outcome::capture(f.reader, f.guard, kImageBase, kImageSize, 0u,
        42u, kDate, 1u, f.workspace, f.output, f.result);
    outcome_check(setup && !ok
                      && f.result.failure == outcome_model::Failure::invalid_input
                      && snapshot_unknown(f.output) && workspace_cleared(f.workspace),
                  "invalid_game_pointer_is_rejected");

    setup = f.build();
    ok = f.capture(2u);
    outcome_check(setup && ok && f.output.kind == 2u
                      && f.result.two_pass_consistent,
                  "kind_two_is_accepted_with_the_same_fixed_key_set");
}

} // namespace

int main() {
    test_all_ten_fixed_keys();
    test_absent_and_known_empty_are_distinct();
    test_invalid_language_and_read_failure_clear_everything();
    test_each_guard_stage_clears_bundle();
    test_second_pass_byte_change_clears_bundle();
    test_second_pass_address_change_is_rejected_by_replay();
    test_shared_call_and_byte_budget_limits();
    test_parameter_aliases_do_not_mutate_inputs();
    test_source_ranges_alias_storage_without_mutation();
    test_input_validation();
    std::printf("OUTCOME TEXT RESULT %s failures=%d\n",
                outcome_failures == 0 ? "PASS" : "FAIL", outcome_failures);
    return outcome_failures == 0 ? 0 : 1;
}
