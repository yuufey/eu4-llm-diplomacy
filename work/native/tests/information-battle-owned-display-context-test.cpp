#include "../information-battle-owned-display-context.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace owned = information::battle::owned_display_context;
namespace model = information::battle::display_context;

namespace {

using Address = owned::Address;

constexpr Address kImageBase = UINT64_C(0x140000000);
constexpr std::size_t kImageSize = 0x2500000u;
constexpr Address kGame = UINT64_C(0x200000);
constexpr std::int32_t kDate = 56563608;
constexpr Address kManager = UINT64_C(0x300000);
constexpr Address kBucketArray = UINT64_C(0x301000);
constexpr Address kNodeOther = UINT64_C(0x302000);
constexpr Address kNodeTarget = UINT64_C(0x302100);
constexpr Address kDefinitionOther = UINT64_C(0x310000);
constexpr Address kDefinition = UINT64_C(0x311000);
constexpr Address kDefinitionHeap = UINT64_C(0x312000);
constexpr Address kLocalizationOuter = UINT64_C(0x330000);
constexpr Address kLocalizationInner = UINT64_C(0x331000);
constexpr Address kLanguageHeap = UINT64_C(0x332000);
constexpr Address kLocalizationTable = UINT64_C(0x340000);
constexpr Address kLocalizationPool = UINT64_C(0x350000);
constexpr std::size_t kLocalizationPoolRegionBytes = 8192u;

int failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) ++failures;
}

struct Region final {
    Address base = 0u;
    std::size_t size = 0u;
    std::array<unsigned char, 32768u> bytes{};
};

struct FakeReader final {
    std::array<Region, 24u> regions{};
    std::size_t region_count = 0u;
    std::size_t read_calls = 0u;
    std::size_t bytes_requested = 0u;
    std::size_t largest_read = 0u;
    std::size_t date_reads = 0u;
    bool mutate_on_second_date = false;
    Address mutation_address = 0u;
    std::array<unsigned char, 8u> mutation_bytes{};
    std::size_t mutation_size = 0u;

    void reset() noexcept {
        for (Region& region : regions) {
            region.base = 0u;
            region.size = 0u;
        }
        region_count = 0u;
        read_calls = 0u;
        bytes_requested = 0u;
        largest_read = 0u;
        date_reads = 0u;
        mutate_on_second_date = false;
        mutation_address = 0u;
        mutation_bytes.fill(0u);
        mutation_size = 0u;
    }

    bool add_region(Address base, std::size_t size) noexcept {
        if (region_count >= regions.size() || size == 0u
                || size > regions[0].bytes.size()) {
            return false;
        }
        Address end = 0u;
        if (!range_end(base, size, end)) return false;
        for (std::size_t index = 0u; index < region_count; ++index) {
            Address old_end = 0u;
            if (!range_end(regions[index].base, regions[index].size, old_end)
                    || (base < old_end && regions[index].base < end)) {
                return false;
            }
        }
        Region& region = regions[region_count++];
        region.base = base;
        region.size = size;
        std::fill(region.bytes.begin(), region.bytes.end(), 0u);
        return true;
    }

    Region* find(Address address, std::size_t size) noexcept {
        for (std::size_t index = 0u; index < region_count; ++index) {
            Region& region = regions[index];
            if (address >= region.base
                    && address - region.base <= region.size
                    && size <= region.size - static_cast<std::size_t>(
                                   address - region.base)) {
                return &region;
            }
        }
        return nullptr;
    }

    static bool range_end(Address base, std::size_t size,
                          Address& end) noexcept {
        if (size == 0u || size > static_cast<std::size_t>(
                                     UINT64_MAX - base)) {
            return false;
        }
        end = base + static_cast<Address>(size);
        return end > base;
    }

    bool write(Address address, const unsigned char* source,
               std::size_t size) noexcept {
        Region* region = find(address, size);
        if (region == nullptr || source == nullptr || size == 0u) return false;
        std::memcpy(region->bytes.data() + static_cast<std::size_t>(
                        address - region->base), source, size);
        return true;
    }

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        bytes_requested += size;
        if (size > largest_read) largest_read = size;
        if (destination == nullptr || size == 0u
                || size > owned::kMaxSingleReadBytes) {
            return false;
        }
        if (address == kGame + owned::kGameDateOffset
                && size == sizeof(std::int32_t)) {
            ++date_reads;
            if (mutate_on_second_date && date_reads == 2u
                    && !write(mutation_address, mutation_bytes.data(),
                              mutation_size)) {
                return false;
            }
        }
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(destination, region->bytes.data() + static_cast<std::size_t>(
                        address - region->base), size);
        return true;
    }

    template <typename T>
    bool put(Address address, T value) noexcept {
        return write(address, reinterpret_cast<const unsigned char*>(&value),
                     sizeof(value));
    }

    bool put_bytes(Address address, const unsigned char* bytes,
                   std::size_t size) noexcept {
        return write(address, bytes, size);
    }
};

static_assert(owned::reader_contract<FakeReader>::value,
              "fake Reader matches the production noexcept interface");

struct Fixture final {
    FakeReader reader{};
    owned::Workspace workspace{};
    model::Snapshot snapshot{};
    owned::Result result{};
    Address pool_end = 0u;
};

Fixture& fixture() {
    static Fixture value{};
    return value;
}

bool put_string32(FakeReader& reader, Address object, const char* text,
                  bool heap, Address heap_address) noexcept {
    const std::size_t length = std::strlen(text);
    if (length > 15u && !heap) return false;
    std::array<unsigned char, owned::kString32Bytes> header{};
    const std::uint64_t length_raw = static_cast<std::uint64_t>(length);
    const std::uint64_t capacity = heap ? 32u : 15u;
    if (heap) {
        if (!reader.add_region(heap_address, length + 1u)) return false;
        std::memcpy(header.data(), &heap_address, sizeof(heap_address));
        if (!reader.put_bytes(heap_address,
                reinterpret_cast<const unsigned char*>(text), length)) {
            return false;
        }
        const unsigned char nul = 0u;
        if (!reader.put_bytes(heap_address + length, &nul, 1u)) return false;
    } else {
        std::memcpy(header.data(), text, length);
        header[length] = 0u;
    }
    std::memcpy(header.data() + owned::kString32LengthOffset,
                &length_raw, sizeof(length_raw));
    std::memcpy(header.data() + owned::kString32CapacityOffset,
                &capacity, sizeof(capacity));
    return reader.put_bytes(object, header.data(), header.size());
}

struct LocaleEntry final {
    const char* key = nullptr;
    const char* value = nullptr;
    std::uint32_t hash = 0u;
    std::uint32_t offset = 0u;
};

bool build_localization(FakeReader& reader, std::uint8_t kind,
                        bool heap_language, int missing_index,
                        Address& pool_end) noexcept {
    if (!reader.add_region(kLocalizationOuter,
                           owned::kLocalizationOuterHeaderBytes)
            || !reader.add_region(kLocalizationInner,
                                  owned::kLocalizationInnerHeaderBytes)
            || !reader.add_region(kLocalizationPool,
                                  kLocalizationPoolRegionBytes)) {
        return false;
    }
    const char* keys[5] = {
        kind == 1u ? "LANDBATTLEOVER_1" : "NAVALBATTLEOVER_1",
        kind == 1u ? "LANDBATTLEOVER_BTN1" : "NAVALBATTLEOVER_BTN1",
        kind == 1u ? "LANDBATTLEOVER_BTN2" : "NAVALBATTLEOVER_BTN2",
        kind == 1u ? "LANDBATTLEOVER_BTN3" : "NAVALBATTLEOVER_BTN3",
        "COMPACT_BATTLE_RESULT_LOSSES",
    };
    const char* values[5] = {
        kind == 1u ? "Land result" : "Naval result",
        "OK one", "OK two", "Go", "Losses",
    };
    std::array<LocaleEntry, 5u> entries{};
    std::size_t count = 0u;
    std::size_t pool_cursor = 0u;
    for (std::size_t index = 0u; index < 5u; ++index) {
        if (static_cast<int>(index) == missing_index) continue;
        const std::size_t length = std::strlen(values[index]);
        if (pool_cursor > kLocalizationPoolRegionBytes
                || length + 1u > kLocalizationPoolRegionBytes - pool_cursor) {
            return false;
        }
        LocaleEntry& entry = entries[count++];
        entry.key = keys[index];
        entry.value = values[index];
        entry.hash = owned::detail::localization_hash(keys[index]);
        entry.offset = static_cast<std::uint32_t>(pool_cursor);
        if (!reader.put_bytes(kLocalizationPool + pool_cursor,
                reinterpret_cast<const unsigned char*>(values[index]), length)) {
            return false;
        }
        const unsigned char nul = 0u;
        if (!reader.put_bytes(kLocalizationPool + pool_cursor + length,
                              &nul, 1u)) {
            return false;
        }
        pool_cursor += length + 1u;
    }
    for (std::size_t index = 1u; index < count; ++index) {
        LocaleEntry current = entries[index];
        std::size_t insertion = index;
        while (insertion != 0u
                && entries[insertion - 1u].hash > current.hash) {
            entries[insertion] = entries[insertion - 1u];
            --insertion;
        }
        entries[insertion] = current;
    }

    const std::uint64_t inner = kLocalizationInner;
    const std::uint64_t pool_begin = kLocalizationPool;
    const std::uint64_t pool_end_raw = kLocalizationPool + pool_cursor;
    const std::uint64_t pool_capacity_end =
        kLocalizationPool + kLocalizationPoolRegionBytes;
    if (!reader.put(kLocalizationOuter + owned::kLocalizationOuterInnerOffset,
                    inner)
            || !reader.put(kLocalizationOuter +
                               owned::kLocalizationPoolBeginOffset,
                           pool_begin)
            || !reader.put(kLocalizationOuter +
                               owned::kLocalizationPoolEndOffset,
                           pool_end_raw)
            || !reader.put(kLocalizationOuter +
                               owned::kLocalizationPoolCapacityEndOffset,
                           pool_capacity_end)) {
        return false;
    }
    pool_end = static_cast<Address>(pool_end_raw);

    if (!put_string32(reader, kLocalizationInner +
                          owned::kLocalizationLanguageOffset,
                      "l_english", heap_language, kLanguageHeap)) {
        return false;
    }

    Address table_begin = 0u;
    Address table_end = 0u;
    if (count != 0u) {
        const std::size_t table_bytes = count * owned::kLocalizationEntryStride;
        if (!reader.add_region(kLocalizationTable, table_bytes)) return false;
        table_begin = kLocalizationTable;
        table_end = table_begin + table_bytes;
        for (std::size_t index = 0u; index < count; ++index) {
            const Address entry_address = table_begin +
                index * owned::kLocalizationEntryStride;
            const std::uint64_t hash = entries[index].hash;
            const std::uint32_t offset = entries[index].offset;
            const std::array<unsigned char, 4u> padding{{0xa5u, 0x5au, 0xc3u, 0x3cu}};
            if (!reader.put(entry_address + owned::kLocalizationEntryHashOffset,
                            hash)
                    || !reader.put(entry_address +
                                       owned::kLocalizationEntryValueOffset,
                                   offset)
                    || !reader.put_bytes(entry_address + 12u, padding.data(),
                                         padding.size())) {
                return false;
            }
        }
    }
    const std::uint64_t table_begin_raw = table_begin;
    const std::uint64_t table_end_raw = table_end;
    const std::uint64_t raw_capacity = count + 7u;
    return reader.put(kLocalizationInner + owned::kLocalizationTableBeginOffset,
                      table_begin_raw)
        && reader.put(kLocalizationInner + owned::kLocalizationTableEndOffset,
                      table_end_raw)
        && reader.put(kLocalizationInner +
                          owned::kLocalizationTableCapacityOffset,
                      raw_capacity);
}

bool build_fixture(Fixture& value, std::uint8_t kind,
                   bool heap_definition_key, bool heap_language,
                   int missing_locale_index, bool bucket_collision) noexcept {
    value.reader.reset();
    value.workspace.clear();
    model::clear(value.snapshot);
    value.result = owned::Result{};
    value.pool_end = 0u;

    FakeReader& reader = value.reader;
    if (!reader.add_region(kGame + owned::kGameDateOffset,
                           sizeof(std::int32_t))
            || !reader.add_region(kImageBase + owned::kDefinitionManagerCellRva,
                                  sizeof(Address))
            || !reader.add_region(kImageBase + owned::kLocalizationCellRva,
                                  sizeof(Address))
            || !reader.add_region(kManager, owned::kManagerHeaderBytes)
            || !reader.add_region(kBucketArray, sizeof(Address))
            || !reader.add_region(kNodeTarget, owned::kNodeBytes)
            || !reader.add_region(kDefinition + owned::kDefinitionKeyOffset,
                                  owned::kDefinitionKeyHeaderBytes +
                                      owned::kDefinitionScalarsBytes)) {
        return false;
    }

    const std::uint32_t date = static_cast<std::uint32_t>(kDate);
    const std::uint64_t manager = kManager;
    const std::uint32_t bucket_count = 1u;
    const std::uint64_t bucket_array = kBucketArray;
    const std::uint64_t target_definition = kDefinition;
    const std::uint64_t no_next = 0u;
    if (!reader.put(kGame + owned::kGameDateOffset, date)
            || !reader.put(kImageBase + owned::kDefinitionManagerCellRva,
                           manager)
            || !reader.put(kImageBase + owned::kLocalizationCellRva,
                           static_cast<std::uint64_t>(kLocalizationOuter))
            || !reader.put(kManager + owned::kManagerBucketCountOffset,
                           bucket_count)
            || !reader.put(kManager + owned::kManagerBucketArrayOffset,
                           bucket_array)) {
        return false;
    }

    std::uint64_t head = kNodeTarget;
    if (bucket_collision) {
        if (!reader.add_region(kNodeOther, owned::kNodeBytes)
                || !reader.add_region(
                    kDefinitionOther + owned::kDefinitionKeyOffset,
                    owned::kDefinitionKeyHeaderBytes +
                        owned::kDefinitionScalarsBytes)) {
            return false;
        }
        if (!put_string32(reader,
                          kDefinitionOther + owned::kDefinitionKeyOffset,
                          "OTHER", false, 0u)) {
            return false;
        }
        const std::uint64_t other_definition = kDefinitionOther;
        const std::uint64_t target_node = kNodeTarget;
        if (!reader.put(kNodeOther + owned::kNodeDefinitionOffset,
                        other_definition)
                || !reader.put(kNodeOther + owned::kNodeNextOffset, target_node)) {
            return false;
        }
        head = kNodeOther;
    }
    const char* definition_key = kind == 1u
        ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    if (!put_string32(reader, kDefinition + owned::kDefinitionKeyOffset,
                      definition_key, heap_definition_key,
                      kDefinitionHeap)
            || !reader.put(kDefinition + owned::kDefinitionPopupKindOffset,
                           static_cast<std::int32_t>(kind == 1u ? 0 : -77))
            || !reader.put(kDefinition + owned::kDefinitionLayoutOffset,
                           static_cast<std::int32_t>(kind == 1u ? 1 : -4))
            || !reader.put(kDefinition + owned::kDefinitionButtonFlagOffset,
                           static_cast<unsigned char>(1u))
            || !reader.put(kNodeTarget + owned::kNodeDefinitionOffset,
                           target_definition)
            || !reader.put(kNodeTarget + owned::kNodeNextOffset, no_next)
            || !reader.put(kBucketArray, static_cast<std::uint64_t>(head))) {
        return false;
    }

    return build_localization(reader, kind, heap_language,
                              missing_locale_index, value.pool_end);
}

model::Identity identity_for(std::uint8_t kind, std::int32_t date = kDate) {
    model::Identity identity{};
    identity.sequence = 42u;
    identity.date = date;
    identity.kind = kind;
    identity.stage = model::kRouterScopeExit;
    return identity;
}

bool field_equals(const model::Snapshot& snapshot, std::size_t index,
                  std::string_view expected) noexcept {
    if (index >= model::kFieldCount) return false;
    const model::Text& field = snapshot.fields[index];
    return field.state == model::State::observed
        && field.length == expected.size()
        && field.offset <= snapshot.arena_used
        && field.length <= snapshot.arena_used - field.offset
        && std::memcmp(snapshot.arena.data() + field.offset,
                       expected.data(), expected.size()) == 0;
}

bool failure_is_cleared(const Fixture& value,
                        model::Failure failure) noexcept {
    return value.snapshot.state == model::State::unknown
        && value.snapshot.failure == failure
        && model::valid(value.snapshot)
        && value.snapshot.arena_used == 0u
        && value.snapshot.identity.sequence == 0u
        && value.workspace.first_pass.record_count == 0u
        && value.workspace.first_pass.bytes_used == 0u
        && value.result.failure == failure
        && !value.result.observed;
}

bool result_is_bounded(const Fixture& value) noexcept {
    return value.result.read_calls == value.reader.read_calls
        && value.result.bytes_read == value.reader.bytes_requested
        && value.result.largest_read == value.reader.largest_read
        && value.result.read_calls <= owned::kMaxTotalReadCalls
        && value.result.bytes_read <= owned::kMaxTotalReadBytes
        && value.result.largest_read <= owned::kMaxSingleReadBytes
        && value.result.pass_read_calls[0] == value.result.pass_read_calls[1]
        && value.result.pass_bytes_read[0] == value.result.pass_bytes_read[1];
}

void test_land_kind_zero_and_bucket_collision() {
    std::printf("TEST land_kind_zero_and_bucket_collision\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 1u, false, false, -1, true);
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(captured, "land_capture_succeeds");
    check(model::valid(value.snapshot)
              && value.snapshot.state == model::State::observed
              && value.snapshot.popup_kind_raw == 0
              && value.snapshot.layout_raw == 1
              && value.snapshot.button_flag_raw == 1u,
          "raw_popup_kind_zero_is_preserved");
    check(field_equals(value.snapshot, 0u, "LANDBATTLEOVER")
              && field_equals(value.snapshot, 1u, "l_english")
              && field_equals(value.snapshot, 2u, "Land result")
              && field_equals(value.snapshot, 3u, "OK one")
              && field_equals(value.snapshot, 4u, "OK two")
              && field_equals(value.snapshot, 5u, "Go")
              && field_equals(value.snapshot, 6u, "Losses"),
          "definition_bucket_collision_resolves_exact_key_and_locale_fields");
    check(value.result.observed && value.result.two_pass_consistent
              && result_is_bounded(value),
          "both_passes_match_exact_read_graph_within_budget");
}

void test_naval_heap_strings_and_optional_missing() {
    std::printf("TEST naval_heap_strings_and_optional_missing\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 2u, true, true, 2, false);
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(2u),
        value.workspace, value.snapshot, value.result);
    check(captured && model::valid(value.snapshot),
          "naval_heap_capture_succeeds");
    check(value.snapshot.popup_kind_raw == -77
              && value.snapshot.identity.kind == 2u
              && field_equals(value.snapshot, 0u, "NAVALBATTLEOVER")
              && field_equals(value.snapshot, 1u, "l_english")
              && field_equals(value.snapshot, 2u, "Naval result"),
          "heap_definition_language_and_naval_body_copied");
    check(value.snapshot.fields[4].state == model::State::absent
              && value.snapshot.fields[4].offset == 0u
              && value.snapshot.fields[4].length == 0u
              && model::valid(value.snapshot),
          "missing_optional_locale_key_is_absent_not_hidden");
    check(result_is_bounded(value), "naval_reads_respect_budgets");
}

void test_identity_date_mismatch_clears() {
    std::printf("TEST identity_date_mismatch_clears\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 1u, false, false, -1, false);
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame,
        identity_for(1u, kDate + 1), value.workspace, value.snapshot,
        value.result);
    check(!captured && failure_is_cleared(value, model::Failure::guard),
          "identity_date_mismatch_is_guarded_and_cleared");
}

void test_graph_mutation_between_passes_clears() {
    std::printf("TEST graph_mutation_between_passes_clears\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 1u, false, false, -1, false);
    value.reader.mutate_on_second_date = true;
    value.reader.mutation_address = kDefinition + owned::kDefinitionLayoutOffset;
    value.reader.mutation_size = sizeof(std::int32_t);
    const std::int32_t changed_layout = 99;
    std::memcpy(value.reader.mutation_bytes.data(), &changed_layout,
                sizeof(changed_layout));
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::source_changed),
          "definition_header_change_between_passes_is_detected");
}

void test_date_change_between_passes_clears() {
    std::printf("TEST date_change_between_passes_clears\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 1u, false, false, -1, false);
    value.reader.mutate_on_second_date = true;
    value.reader.mutation_address = kGame + owned::kGameDateOffset;
    value.reader.mutation_size = sizeof(std::int32_t);
    const std::int32_t changed_date = kDate + 1;
    std::memcpy(value.reader.mutation_bytes.data(), &changed_date,
                sizeof(changed_date));
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::source_changed),
          "date_change_between_passes_is_detected");
}

void test_cycle_invalid_pool_and_table_limit_clear() {
    std::printf("TEST cycle_invalid_pool_and_table_limit_clear\n");
    Fixture& value = fixture();
    bool setup = build_fixture(value, 1u, false, false, -1, false);
    if (setup) {
        (void)value.reader.put(kNodeTarget + owned::kNodeNextOffset,
                               static_cast<std::uint64_t>(kNodeTarget));
    }
    bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::cache_invalid),
          "definition_chain_cycle_rejected");

    setup = build_fixture(value, 1u, false, false, -1, false);
    if (setup) {
        (void)value.reader.put(kLocalizationOuter +
                                   owned::kLocalizationPoolCapacityEndOffset,
                               static_cast<std::uint64_t>(value.pool_end - 1u));
    }
    captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::cache_invalid),
          "invalid_pool_capacity_range_rejected");

    setup = build_fixture(value, 1u, false, false, -1, false);
    if (setup) {
        const std::uint64_t over_limit_capacity = kLocalizationPool +
            owned::kMaxLocalizationPoolBytes + 1u;
        (void)value.reader.put(kLocalizationOuter +
                                   owned::kLocalizationPoolCapacityEndOffset,
                               over_limit_capacity);
    }
    captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::cache_invalid),
          "oversized_pool_capacity_rejected");

    setup = build_fixture(value, 1u, false, false, -1, false);
    if (setup) {
        const std::uint64_t over_limit_end = kLocalizationTable +
            (owned::kMaxLocalizationTableEntries + 1u) *
                owned::kLocalizationEntryStride;
        (void)value.reader.put(kLocalizationInner +
                                   owned::kLocalizationTableEndOffset,
                               over_limit_end);
    }
    captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::cache_invalid),
          "oversized_localization_table_rejected");
}

void test_empty_locale_ranges_report_absent_fields() {
    std::printf("TEST empty_locale_ranges_report_absent_fields\n");
    Fixture& value = fixture();
    bool setup = build_fixture(value, 1u, false, false, -1, false);
    const std::uint64_t zero = 0u;
    if (setup) {
        setup = value.reader.put(kLocalizationOuter +
                                     owned::kLocalizationPoolBeginOffset, zero)
            && value.reader.put(kLocalizationOuter +
                                    owned::kLocalizationPoolEndOffset, zero)
            && value.reader.put(kLocalizationOuter +
                                    owned::kLocalizationPoolCapacityEndOffset,
                                zero)
            && value.reader.put(kLocalizationInner +
                                    owned::kLocalizationTableBeginOffset, zero)
            && value.reader.put(kLocalizationInner +
                                    owned::kLocalizationTableEndOffset, zero);
    }
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(captured && model::valid(value.snapshot)
              && value.snapshot.state == model::State::observed,
          "empty_cache_ranges_keep_context_observed");
    bool all_optional_absent = true;
    for (std::size_t index = 2u; index < model::kFieldCount; ++index) {
        all_optional_absent = all_optional_absent
            && value.snapshot.fields[index].state == model::State::absent
            && value.snapshot.fields[index].offset == 0u
            && value.snapshot.fields[index].length == 0u;
    }
    check(all_optional_absent && field_equals(value.snapshot, 0u, "LANDBATTLEOVER")
              && field_equals(value.snapshot, 1u, "l_english"),
          "zero_table_and_pool_do_not_claim_locale_text");
}

void test_embedded_nul_definition_key_clears() {
    std::printf("TEST embedded_nul_definition_key_clears\n");
    Fixture& value = fixture();
    const bool setup = build_fixture(value, 1u, false, false, -1, false);
    const unsigned char nul = 0u;
    if (setup) {
        (void)value.reader.put_bytes(kDefinition + owned::kDefinitionKeyOffset,
                                     &nul, 1u);
    }
    const bool captured = setup && owned::capture(
        value.reader, kImageBase, kImageSize, kGame, identity_for(1u),
        value.workspace, value.snapshot, value.result);
    check(!captured && failure_is_cleared(value, model::Failure::cache_invalid),
          "embedded_nul_inside_definition_key_rejected");
}

} // namespace

int main() {
    test_land_kind_zero_and_bucket_collision();
    test_naval_heap_strings_and_optional_missing();
    test_identity_date_mismatch_clears();
    test_graph_mutation_between_passes_clears();
    test_date_change_between_passes_clears();
    test_cycle_invalid_pool_and_table_limit_clear();
    test_empty_locale_ranges_report_absent_fields();
    test_embedded_nul_definition_key_clears();
    std::printf("RESULT %s failures=%d\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
