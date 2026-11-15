#define main previous_display_context_test_main
#include "information-battle-owned-display-context-test.cpp"
#undef main

#include "../information-battle-owned-outcome-tail.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>

namespace tail = information::battle::owned_outcome_tail;
namespace tail_model = information::battle::display_context;
namespace tail_cache = information::battle::owned_display_context;

namespace {

using Address = tail::Address;

constexpr std::array<const char*, tail::kOutcomeKeyCount> kTailValues{{
    "naval flee raw", "naval triumph raw",
    "our victory type raw", "their victory type raw",
}};
constexpr std::array<const char*, tail::kOutcomeKeyCount> kTailKeys{{
    "COMBAT_FLEE", "COMBAT_TRIUMPH",
    "COMBAT_WINNERTYPE_OUR", "COMBAT_WINNERTYPE_THEIR",
}};

struct TailReader final {
    FakeReader* source = nullptr;
    std::size_t calls = 0u;
    std::size_t fail_at = 0u;
    Address last_address = 0u;
    std::size_t last_size = 0u;
    std::array<Address, 256u> addresses{};
    std::array<std::size_t, 256u> sizes{};

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++calls;
        last_address = address;
        last_size = size;
        if (calls <= addresses.size()) {
            addresses[calls - 1u] = address;
            sizes[calls - 1u] = size;
        }
        if (calls == fail_at) return false;
        return source != nullptr && source->read(address, destination, size);
    }
};

static_assert(information::battle::owned_name_sources::reader_contract<
                  TailReader>::value);

struct TailGuard final {
    int calls = 0;
    int fail_at = 0;

    bool guard() noexcept { return ++calls != fail_at; }
};

static_assert(information::battle::owned_name_sources::guard_contract<
                  TailGuard>::value);

struct TailLocaleEntry final {
    const char* key = nullptr;
    const char* value = nullptr;
    std::uint32_t hash = 0u;
    std::uint32_t offset = 0u;
};

struct TailFixture final {
    Fixture& source = fixture();
    TailReader reader{};
    TailGuard guard{};
    tail::Workspace workspace{};
    tail::Snapshot output{};
    tail::Result result{};
    int setup_failure = 0;

    bool build(int absent_index = -1, int empty_index = -1) noexcept {
        setup_failure = 0;
        if (!build_fixture(source, 2u, false, false, -1, false)) {
            setup_failure = 1;
            return false;
        }
        reader = TailReader{};
        reader.source = &source.reader;
        guard = TailGuard{};
        workspace.clear();
        output = tail::Snapshot{};
        result = tail::Result{};

        for (std::size_t index = 0u; index < tail::kSpecialSlotRvas.size();
             ++index) {
            const Address address = kImageBase + tail::kSpecialSlotRvas[index];
            if (!source.reader.add_region(address, sizeof(std::int32_t))) {
                setup_failure = 2;
                return false;
            }
        }
        constexpr std::array<std::int32_t, 3u> slots{{-31, 7, -31}};
        for (std::size_t index = 0u; index < slots.size(); ++index) {
            if (!source.reader.put(
                    kImageBase + tail::kSpecialSlotRvas[index], slots[index])) {
                setup_failure = 3;
                return false;
            }
        }

        Region* table = source.reader.find(kLocalizationTable, 1u);
        Region* pool = source.reader.find(kLocalizationPool, 1u);
        if (table == nullptr || pool == nullptr) {
            setup_failure = 4;
            return false;
        }
        std::memset(table->bytes.data(), 0, table->bytes.size());
        std::memset(pool->bytes.data(), 0, pool->bytes.size());

        std::array<TailLocaleEntry, tail::kOutcomeKeyCount> entries{};
        std::size_t count = 0u;
        std::size_t pool_cursor = 0u;
        for (std::size_t index = 0u; index < tail::kOutcomeKeyCount; ++index) {
            if (static_cast<int>(index) == absent_index) continue;
            const char* value = static_cast<int>(index) == empty_index
                ? "" : kTailValues[index];
            const std::size_t length = std::strlen(value);
            if (pool_cursor > kLocalizationPoolRegionBytes
                    || length + 1u > kLocalizationPoolRegionBytes - pool_cursor) {
                setup_failure = 5;
                return false;
            }
            TailLocaleEntry& entry = entries[count++];
            entry.key = kTailKeys[index];
            entry.value = value;
            entry.hash = owned::detail::localization_hash(entry.key);
            entry.offset = static_cast<std::uint32_t>(pool_cursor);
            if (length != 0u && !source.reader.put_bytes(
                    kLocalizationPool + pool_cursor,
                    reinterpret_cast<const unsigned char*>(value), length)) {
                setup_failure = 6;
                return false;
            }
            const unsigned char nul = 0u;
            if (!source.reader.put_bytes(kLocalizationPool + pool_cursor
                                              + length,
                                          &nul, 1u)) {
                setup_failure = 7;
                return false;
            }
            pool_cursor += length + 1u;
        }
        for (std::size_t index = 1u; index < count; ++index) {
            const TailLocaleEntry current = entries[index];
            std::size_t insertion = index;
            while (insertion != 0u
                    && entries[insertion - 1u].hash > current.hash) {
                entries[insertion] = entries[insertion - 1u];
                --insertion;
            }
            if ((insertion != 0u
                    && entries[insertion - 1u].hash == current.hash)
                    || (insertion < index
                        && entries[insertion + 1u].hash == current.hash)) {
                setup_failure = 8;
                return false;
            }
            entries[insertion] = current;
        }

        table->size = count * owned::kLocalizationEntryStride;
        for (std::size_t index = 0u; index < count; ++index) {
            const Address address = kLocalizationTable
                + index * owned::kLocalizationEntryStride;
            const std::uint64_t hash = entries[index].hash;
            const std::uint32_t offset = entries[index].offset;
            const std::array<unsigned char, 4u> padding{};
            if (!source.reader.put(
                    address + owned::kLocalizationEntryHashOffset, hash)
                    || !source.reader.put(
                        address + owned::kLocalizationEntryValueOffset, offset)
                    || !source.reader.put_bytes(address + 12u, padding.data(),
                                                padding.size())) {
                setup_failure = 9;
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
        const bool headers_ok = source.reader.put(
                   kLocalizationOuter + owned::kLocalizationPoolBeginOffset,
                   pool_begin)
            && source.reader.put(
                   kLocalizationOuter + owned::kLocalizationPoolEndOffset,
                   pool_end)
            && source.reader.put(
                   kLocalizationOuter
                       + owned::kLocalizationPoolCapacityEndOffset,
                   pool_capacity_end)
            && source.reader.put(
                   kLocalizationInner + owned::kLocalizationTableBeginOffset,
                   table_begin)
            && source.reader.put(
                   kLocalizationInner + owned::kLocalizationTableEndOffset,
                   table_end)
            && source.reader.put(
                   kLocalizationInner
                       + owned::kLocalizationTableCapacityOffset,
                   table_capacity);
        if (!headers_ok) setup_failure = 10;
        return headers_ok;
    }

    bool capture(std::uint8_t kind = 2u, std::uint64_t sequence = 230u,
                 std::int32_t date = kDate,
                 std::size_t image_size = kImageSize) noexcept {
        return tail::capture(reader, guard, kImageBase, image_size, kGame,
                             sequence, date, kind, workspace, output, result);
    }
};

TailFixture& tail_fixture() {
    static TailFixture value{};
    return value;
}

int tail_failures = 0;

void tail_check(bool ok, const char* label) {
    std::printf("CHECK %s %s\n", label, ok ? "PASS" : "FAIL");
    if (!ok) ++tail_failures;
}

template <std::size_t MaxBytes>
bool text_equals(const tail::TextValue<MaxBytes>& value,
                 tail_model::State state, const char* expected) noexcept {
    const std::size_t length = std::strlen(expected);
    return value.state == state && value.length == length
        && length <= MaxBytes && value.bytes[length] == 0u
        && std::memcmp(value.bytes.data(), expected, length) == 0;
}

template <std::size_t MaxBytes>
bool text_is_unknown(const tail::TextValue<MaxBytes>& value) noexcept {
    if (value.state != tail_model::State::unknown || value.length != 0u)
        return false;
    for (unsigned char byte : value.bytes)
        if (byte != 0u) return false;
    return true;
}

bool snapshot_is_unknown(const tail::Snapshot& value) noexcept {
    if (value.sequence != 0u || value.raw_date != 0 || value.kind != 0u
            || value.reserved_slots != std::array<std::int32_t, 3u>{}
            || !text_is_unknown(value.language)) {
        return false;
    }
    for (const tail::OutcomeValue& field : value.fields)
        if (!text_is_unknown(field)) return false;
    return true;
}

bool workspace_is_clear(const tail::Workspace& value) noexcept {
    if (!snapshot_is_unknown(value.first_snapshot)
            || !snapshot_is_unknown(value.second_snapshot)
            || value.temporary_snapshot.state != tail_model::State::unknown
            || value.temporary_snapshot.failure
                != tail_model::Failure::not_captured
            || value.temporary_snapshot.identity.sequence != 0u
            || value.temporary_snapshot.identity.date != 0
            || value.temporary_snapshot.identity.kind != 0u
            || value.temporary_snapshot.identity.stage != 0u
            || value.temporary_snapshot.popup_kind_raw != 0
            || value.temporary_snapshot.layout_raw != 0
            || value.temporary_snapshot.button_flag_raw != 0u
            || value.temporary_snapshot.arena_used != 0u) {
        return false;
    }
    for (const tail_model::Text& field : value.temporary_snapshot.fields)
        if (field.state != tail_model::State::unknown || field.offset != 0u
                || field.length != 0u) return false;
    for (unsigned char byte : value.temporary_snapshot.arena)
        if (byte != 0u) return false;
    if (value.first_pass.bytes_used != 0u
            || value.first_pass.record_count != 0u) return false;
    for (unsigned char byte : value.first_pass.bytes)
        if (byte != 0u) return false;
    for (const tail_cache::detail::ReadRecord& record :
         value.first_pass.records) {
        if (record.address != 0u || record.offset != 0u || record.size != 0u)
            return false;
    }
    for (unsigned char byte : value.scratch)
        if (byte != 0u) return false;
    return true;
}

void seed_failure_storage(TailFixture& fixture) {
    fixture.output.sequence = 999u;
    fixture.output.reserved_slots[0] = 12345;
    fixture.output.language.state = tail_model::State::observed;
    fixture.output.language.length = 1u;
    fixture.output.language.bytes[0] = 'X';
    fixture.output.fields[0].state = tail_model::State::observed;
    fixture.output.fields[0].length = 1u;
    fixture.output.fields[0].bytes[0] = 'Y';
    fixture.workspace.first_snapshot.sequence = 888u;
    fixture.workspace.temporary_snapshot.arena[0] = 'Z';
    fixture.workspace.first_pass.bytes[0] = 'Q';
    fixture.workspace.first_pass.records[0] = {UINT64_C(0x12345000), 0u, 1u};
    fixture.workspace.first_pass.record_count = 1u;
    fixture.workspace.first_pass.bytes_used = 1u;
    fixture.workspace.scratch[0] = 'R';
}

void test_slots_order_negative_and_duplicate_values() {
    TailFixture& f = tail_fixture();
    const bool setup = f.build();
    if (!setup) {
        std::printf("DEBUG fixture_setup_failure=%d regions=%zu\n",
                    f.setup_failure, f.source.reader.region_count);
    }
    const bool captured = setup && f.capture();
    bool keys_ok = true;
    for (std::size_t index = 0u; index < tail::kOutcomeKeyCount; ++index) {
        keys_ok = keys_ok
            && std::strcmp(tail::kLocalizationKeys[index], kTailKeys[index]) == 0;
    }
    bool values_ok = captured
        && text_equals(f.output.language, tail_model::State::observed,
                       "l_english");
    for (std::size_t index = 0u; index < tail::kOutcomeKeyCount; ++index) {
        values_ok = values_ok
            && text_equals(f.output.fields[index], tail_model::State::observed,
                           kTailValues[index]);
    }
    const std::array<std::int32_t, 3u> expected_slots{{-31, 7, -31}};
    bool slot_reads_ordered = f.reader.calls >= 4u;
    for (std::size_t index = 0u; index < expected_slots.size(); ++index) {
        slot_reads_ordered = slot_reads_ordered
            && f.reader.addresses[index + 1u]
                == kImageBase + tail::kSpecialSlotRvas[index]
            && f.reader.sizes[index + 1u] == sizeof(std::int32_t);
    }
    tail_check(captured && keys_ok && values_ok
                   && f.output.reserved_slots == expected_slots
                   && f.output.sequence == 230u && f.output.raw_date == kDate
                   && f.output.kind == 2u && slot_reads_ordered,
               "three_special_slots_keep_declared_order_signed_values_and_duplicates");
    tail_check(captured && f.result.observed && f.result.two_pass_consistent
                   && f.guard.calls == 3
                   && f.result.read_calls == f.reader.calls
                   && f.result.read_calls <= tail_cache::kMaxTotalReadCalls
                   && f.result.bytes_read <= tail_cache::kMaxTotalReadBytes
                   && f.result.pass_bytes_read[0]
                       <= tail_cache::kMaxReadBytesPerPass
                   && f.result.pass_bytes_read[1]
                       <= tail_cache::kMaxReadBytesPerPass
                   && workspace_is_clear(f.workspace),
               "two_pass_capture_uses_shared_budget_and_clears_workspace_on_success");
}

void test_absent_and_empty_keys_remain_distinct() {
    TailFixture& f = tail_fixture();
    const bool setup = f.build(1, 2);
    const bool captured = setup && f.capture();
    tail_check(captured
                   && text_equals(f.output.fields[0],
                                  tail_model::State::observed, kTailValues[0])
                   && text_equals(f.output.fields[1],
                                  tail_model::State::absent, "")
                   && text_equals(f.output.fields[2],
                                  tail_model::State::observed, "")
                   && text_equals(f.output.fields[3],
                                  tail_model::State::observed, kTailValues[3]),
               "missing_key_is_absent_while_present_empty_key_is_observed");
}

void test_slot_mutation_and_date_change_clear_stale_output() {
    TailFixture& f = tail_fixture();
    bool setup = f.build();
    const std::int32_t changed_slot = -30;
    f.source.reader.mutate_on_second_date = true;
    f.source.reader.mutation_address =
        kImageBase + tail::kSpecialSlotRvas[1];
    f.source.reader.mutation_size = sizeof(changed_slot);
    std::memcpy(f.source.reader.mutation_bytes.data(), &changed_slot,
                sizeof(changed_slot));
    seed_failure_storage(f);
    bool captured = setup && f.capture();
    tail_check(!captured
                   && f.result.failure == tail_model::Failure::source_changed
                   && !f.result.observed && !f.result.two_pass_consistent
                   && snapshot_is_unknown(f.output)
                   && workspace_is_clear(f.workspace),
               "changed_special_slot_between_passes_rejects_bundle_and_clears_old_bytes");

    setup = f.build();
    const std::int32_t changed_date = kDate + 1;
    f.source.reader.mutate_on_second_date = true;
    f.source.reader.mutation_address = kGame + tail_cache::kGameDateOffset;
    f.source.reader.mutation_size = sizeof(changed_date);
    std::memcpy(f.source.reader.mutation_bytes.data(), &changed_date,
                sizeof(changed_date));
    seed_failure_storage(f);
    captured = setup && f.capture();
    tail_check(!captured
                   && f.result.failure == tail_model::Failure::source_changed
                   && snapshot_is_unknown(f.output)
                   && workspace_is_clear(f.workspace),
               "date_change_between_passes_rejects_bundle_and_clears_old_bytes");
}

void test_guard_and_mid_read_failures_clear_bundle() {
    TailFixture& f = tail_fixture();
    bool setup = f.build();
    f.guard.fail_at = 2;
    seed_failure_storage(f);
    bool captured = setup && f.capture();
    tail_check(!captured && f.guard.calls == 2
                   && f.result.failure == tail_model::Failure::guard
                   && snapshot_is_unknown(f.output)
                   && workspace_is_clear(f.workspace),
               "guard_failure_between_passes_clears_entire_bundle");

    setup = f.build();
    f.reader.fail_at = 3u;
    seed_failure_storage(f);
    captured = setup && f.capture();
    tail_check(!captured && f.reader.calls == 3u
                   && f.reader.last_address
                       == kImageBase + tail::kSpecialSlotRvas[1]
                   && f.reader.last_size == sizeof(std::int32_t)
                   && f.result.failure == tail_model::Failure::read_failed
                   && snapshot_is_unknown(f.output)
                   && workspace_is_clear(f.workspace),
               "failed_i32_slot_read_does_not_publish_default_zero_or_old_bytes");
}

void test_slot_rva_outside_image_is_rejected() {
    TailFixture& f = tail_fixture();
    const bool setup = f.build();
    const std::size_t short_image = tail::kSpecialSlotRvas[0];
    seed_failure_storage(f);
    const bool captured = setup && f.capture(2u, 230u, kDate, short_image);
    tail_check(!captured && f.result.failure == tail_model::Failure::invalid_input
                   && f.reader.calls == 1u
                   && snapshot_is_unknown(f.output)
                   && workspace_is_clear(f.workspace),
               "slot_cell_that_extends_past_image_size_fails_without_defaulting");
}

void test_second_pass_address_redirection_is_rejected() {
    TailFixture& f = tail_fixture();
    const bool setup = f.build();
    f.workspace.clear();
    f.output = tail::Snapshot{};
    f.result = tail::Result{};
    f.result.attempted = true;
    f.result.failure = tail_model::Failure::none;
    tail_cache::detail::AddressRange workspace_range{}, output_range{}, result_range{};
    const bool ranges = setup
        && tail_cache::detail::object_range(&f.workspace, sizeof(f.workspace),
                                            workspace_range)
        && tail_cache::detail::object_range(&f.output, sizeof(f.output),
                                            output_range)
        && tail_cache::detail::object_range(&f.result, sizeof(f.result),
                                            result_range);
    if (!ranges) {
        tail_check(false, "address_redirection_fixture_ranges_available");
        return;
    }
    tail_cache::detail::PassReader<TailReader, tail::Workspace> first(
        f.reader, f.workspace, f.result, 0u, workspace_range, output_range,
        result_range, &f.workspace.first_pass, nullptr);
    const Address date_address = kGame + tail_cache::kGameDateOffset;
    const bool first_ok = first.read(date_address, sizeof(std::int32_t))
        && first.complete();
    const std::size_t calls_before_second = f.reader.calls;
    tail_cache::detail::PassReader<TailReader, tail::Workspace> second(
        f.reader, f.workspace, f.result, 1u, workspace_range, output_range,
        result_range, nullptr, &f.workspace.first_pass);
    const bool second_ok = second.read(date_address + 1u,
                                       sizeof(std::int32_t));
    tail_check(first_ok && !second_ok
                   && f.result.failure == tail_model::Failure::source_changed
                   && f.reader.calls == calls_before_second
                   && f.workspace.first_pass.record_count == 1u
                   && f.workspace.first_pass.bytes_used == sizeof(std::int32_t),
               "second_pass_redirected_address_is_rejected_before_reader_call");
}

union TailWorkspaceOutput final {
    tail::Workspace workspace;
    tail::Snapshot output;
    TailWorkspaceOutput() noexcept {}
    ~TailWorkspaceOutput() {}
};

union TailWorkspaceResult final {
    tail::Workspace workspace;
    tail::Result result;
    TailWorkspaceResult() noexcept {}
    ~TailWorkspaceResult() {}
};

union TailSnapshotResult final {
    tail::Snapshot output;
    tail::Result result;
    TailSnapshotResult() noexcept {}
    ~TailSnapshotResult() {}
};

template <std::size_t N>
bool unchanged(const void* object,
               const std::array<unsigned char, N>& before) noexcept {
    return std::memcmp(object, before.data(), N) == 0;
}

void test_aliasing_parameters_and_source_do_not_mutate_storage() {
    TailFixture& f = tail_fixture();
    bool setup = f.build();
    static TailWorkspaceOutput a{};
    new (&a.workspace) tail::Workspace{};
    a.workspace.first_snapshot.sequence = 17u;
    static std::array<unsigned char, sizeof(a)> before_a{};
    std::memcpy(before_a.data(), &a, sizeof(a));
    const bool a_ok = tail::capture(
        f.reader, f.guard, kImageBase, kImageSize, kGame, 230u, kDate, 2u,
        a.workspace, *reinterpret_cast<tail::Snapshot*>(&a), f.result);
    tail_check(setup && !a_ok && unchanged(&a, before_a)
                   && f.reader.calls == 0u && f.guard.calls == 0,
               "workspace_output_parameter_alias_returns_without_mutation");

    setup = f.build();
    static TailWorkspaceResult b{};
    new (&b.workspace) tail::Workspace{};
    b.workspace.second_snapshot.sequence = 23u;
    static std::array<unsigned char, sizeof(b)> before_b{};
    std::memcpy(before_b.data(), &b, sizeof(b));
    const bool b_ok = tail::capture(
        f.reader, f.guard, kImageBase, kImageSize, kGame, 230u, kDate, 2u,
        b.workspace, f.output, *reinterpret_cast<tail::Result*>(&b));
    tail_check(setup && !b_ok && unchanged(&b, before_b)
                   && f.reader.calls == 0u && f.guard.calls == 0,
               "workspace_result_parameter_alias_returns_without_mutation");

    setup = f.build();
    static TailSnapshotResult c{};
    new (&c.output) tail::Snapshot{};
    c.output.sequence = 31u;
    static std::array<unsigned char, sizeof(c)> before_c{};
    std::memcpy(before_c.data(), &c, sizeof(c));
    const bool c_ok = tail::capture(
        f.reader, f.guard, kImageBase, kImageSize, kGame, 230u, kDate, 2u,
        f.workspace, c.output, *reinterpret_cast<tail::Result*>(&c));
    tail_check(setup && !c_ok && unchanged(&c, before_c)
                   && f.reader.calls == 0u && f.guard.calls == 0,
               "output_result_parameter_alias_returns_without_mutation");

    setup = f.build();
    f.output.sequence = 92u;
    f.result.read_calls = 93u;
    const std::uint64_t old_sequence = f.output.sequence;
    const std::uint32_t old_calls = f.result.read_calls;
    const Address aliased_image = reinterpret_cast<Address>(&f.output);
    const bool source_alias_ok = tail::capture(
        f.reader, f.guard, aliased_image, sizeof(f.output), kGame, 230u,
        kDate, 2u, f.workspace, f.output, f.result);
    tail_check(setup && !source_alias_ok
                   && f.output.sequence == old_sequence
                   && f.result.read_calls == old_calls
                   && f.reader.calls == 0u && f.guard.calls == 0,
               "source_image_overlap_with_output_is_rejected_without_mutation");
}

} // namespace

int main() {
    test_slots_order_negative_and_duplicate_values();
    test_absent_and_empty_keys_remain_distinct();
    test_slot_mutation_and_date_change_clear_stale_output();
    test_guard_and_mid_read_failures_clear_bundle();
    test_slot_rva_outside_image_is_rejected();
    test_second_pass_address_redirection_is_rejected();
    test_aliasing_parameters_and_source_do_not_mutate_storage();
    std::printf("OUTCOME TAIL RESULT %s failures=%d\n",
                tail_failures == 0 ? "PASS" : "FAIL", tail_failures);
    return tail_failures == 0 ? 0 : 1;
}
