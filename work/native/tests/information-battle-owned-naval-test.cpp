#include "../information-battle-owned-naval.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <type_traits>

namespace {

namespace naval = information::battle::owned_naval;
namespace summary = information::battle::owned_summary;

struct TestReader {
    using Address = naval::Address;

    static constexpr Address kBase = UINT64_C(0x200000);
    static constexpr std::size_t kMemoryBytes = 0x20000u;
    static constexpr Address kCombat = kBase + 0x100u;
    static constexpr Address kSummary = kBase + 0x400u;
    static constexpr Address kSide0 = kBase + 0x800u;
    static constexpr Address kSide1 = kBase + 0xc00u;
    static constexpr Address kRows = kBase + 0x1000u;
    static constexpr Address kRowObjects = kBase + 0x5000u;
    static constexpr Address kDefinitions = kBase + 0xa000u;

    enum class Mutation : std::uint8_t {
        none,
        summary_header,
        side_pointer,
        side_gate,
        row_pointer,
    };

    std::array<unsigned char, kMemoryBytes> memory{};
    std::size_t call_count = 0;
    std::size_t bytes_read = 0;
    std::size_t fail_on_call = 0;
    std::size_t mutate_after_call = 0;
    Mutation mutation = Mutation::none;
    std::uint32_t configured_rows = 0;

    bool contains(Address address, std::size_t size) const noexcept {
        if (address < kBase) {
            return false;
        }
        const Address offset = address - kBase;
        return offset <= static_cast<Address>(memory.size())
            && size <= memory.size() - static_cast<std::size_t>(offset);
    }

    bool write(Address address, const void* source,
               std::size_t size) noexcept {
        if (source == nullptr || !contains(address, size)) {
            return false;
        }
        std::memcpy(memory.data() + static_cast<std::size_t>(address - kBase),
                    source, size);
        return true;
    }

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++call_count;
        if (destination == nullptr || size == 0u || fail_on_call == call_count
                || !contains(address, size)) {
            return false;
        }
        std::memcpy(destination,
                    memory.data() + static_cast<std::size_t>(address - kBase),
                    size);
        bytes_read += size;
        if (mutate_after_call == call_count) {
            mutate_source();
        }
        return true;
    }

    void mutate_source() noexcept {
        if (mutation == Mutation::summary_header) {
            const Address end = kRows + static_cast<Address>(2u * sizeof(Address));
            (void)write(kSummary + naval::kSummaryEndOffset,
                        &end, sizeof(end));
        } else if (mutation == Mutation::side_pointer) {
            const Address side = kSide1;
            (void)write(kCombat + naval::kCombatSidePointerOffset,
                        &side, sizeof(side));
        } else if (mutation == Mutation::side_gate) {
            const unsigned char gate = 0x7fu;
            (void)write(kSide0 + 0x169u, &gate, sizeof(gate));
        } else if (mutation == Mutation::row_pointer) {
            const Address row = kRowObjects + 0x40u;
            const Address definition = kDefinitions + 0x20u;
            const std::int32_t type = 0x6a6a6a6a;
            (void)write(kRows, &row, sizeof(row));
            (void)write(row + naval::kRowDefinitionOffset,
                        &definition, sizeof(definition));
            (void)write(definition + naval::kDefinitionTypeOffset,
                        &type, sizeof(type));
        }
    }
};

struct BadReader {
    bool read(naval::Address, unsigned char*, std::size_t) { return true; }
};

static_assert(naval::reader_contract<TestReader>::value,
              "the test seam must match the exact noexcept signature");
static_assert(!naval::reader_contract<BadReader>::value,
              "a throwing-capable seam must be rejected");
static_assert(std::is_trivially_copyable<naval::Snapshot>::value,
              "the output must remain a plain raw-value object");

unsigned g_failures = 0;
unsigned g_checks = 0;

void check(bool condition, const char* label) noexcept {
    ++g_checks;
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void write_u64(TestReader& reader, TestReader::Address address,
               TestReader::Address value) noexcept {
    (void)reader.write(address, &value, sizeof(value));
}

void write_i32(TestReader& reader, TestReader::Address address,
               std::int32_t value) noexcept {
    (void)reader.write(address, &value, sizeof(value));
}

summary::Snapshot make_base_summary() noexcept {
    summary::Snapshot value{};
    for (std::size_t index = 0; index < value.raw_i32.size(); ++index) {
        value.raw_i32[index] = static_cast<std::int32_t>(
            -9000 + static_cast<int>(index * 37u));
    }
    value.control_byte = 0x5au;
    return value;
}

void setup(TestReader& reader, std::uint32_t row_count,
           const summary::Snapshot& base_summary) noexcept {
    reader.memory.fill(0);
    reader.call_count = 0;
    reader.bytes_read = 0;
    reader.fail_on_call = 0;
    reader.mutate_after_call = 0;
    reader.mutation = TestReader::Mutation::none;
    reader.configured_rows = row_count;

    const TestReader::Address begin = row_count == 0u ? 0u : TestReader::kRows;
    const TestReader::Address end = row_count == 0u
        ? 0u
        : TestReader::kRows
            + static_cast<TestReader::Address>(row_count * sizeof(TestReader::Address));
    write_u64(reader, TestReader::kSummary + naval::kSummaryBeginOffset, begin);
    write_u64(reader, TestReader::kSummary + naval::kSummaryEndOffset, end);
    for (std::size_t index = 0; index < base_summary.raw_i32.size(); ++index) {
        write_i32(reader, TestReader::kSummary + naval::kSummaryBaseOffset
                      + index * sizeof(std::int32_t),
                  base_summary.raw_i32[index]);
    }
    (void)reader.write(TestReader::kSummary + naval::kSummaryBaseOffset
                       + naval::kSummaryBaseBytes - 1u,
                       &base_summary.control_byte, sizeof(base_summary.control_byte));

    write_u64(reader, TestReader::kCombat + naval::kCombatSidePointerOffset,
              TestReader::kSide0);
    write_u64(reader, TestReader::kCombat + naval::kCombatSidePointerOffset
              + sizeof(TestReader::Address), TestReader::kSide1);
    for (std::size_t side_index = 0; side_index < 2u; ++side_index) {
        const TestReader::Address side = side_index == 0u
            ? TestReader::kSide0 : TestReader::kSide1;
        for (std::size_t field = 0; field < 4u; ++field) {
            const std::int32_t value = static_cast<std::int32_t>(
                (side_index == 0u ? -1 : 1) *
                (1000 + static_cast<int>(field * 17u + side_index * 5u)));
            write_i32(reader, side + naval::kSideLossOffset
                      + field * sizeof(std::int32_t), value);
        }
        const unsigned char gate = static_cast<unsigned char>(0x20u + side_index);
        (void)reader.write(side + 0x169u, &gate, sizeof(gate));
    }

    for (std::uint32_t index = 0; index < row_count; ++index) {
        const TestReader::Address row = TestReader::kRowObjects
            + static_cast<TestReader::Address>(index) * 0x40u;
        const TestReader::Address definition = TestReader::kDefinitions
            + static_cast<TestReader::Address>(index) * 0x20u;
        write_u64(reader, TestReader::kRows
                  + static_cast<TestReader::Address>(index)
                      * sizeof(TestReader::Address), row);
        write_u64(reader, row + naval::kRowDefinitionOffset, definition);
        write_i32(reader, definition + naval::kDefinitionTypeOffset,
                  static_cast<std::int32_t>(-700 + static_cast<int>(index * 13u)));
    }
}

bool same_snapshot(const naval::Snapshot& left,
                   const naval::Snapshot& right) noexcept {
    if (left.row_count != right.row_count) {
        return false;
    }
    for (std::size_t side_index = 0; side_index < left.sides.size();
         ++side_index) {
        if (left.sides[side_index].raw_loss_i32
                != right.sides[side_index].raw_loss_i32
                || left.sides[side_index].raw_gate
                    != right.sides[side_index].raw_gate) {
            return false;
        }
    }
    return left.row_types == right.row_types;
}

naval::Snapshot sentinel() noexcept {
    naval::Snapshot value{};
    value.row_count = static_cast<std::uint32_t>(naval::kMaxRows);
    for (std::size_t side_index = 0; side_index < value.sides.size();
         ++side_index) {
        for (std::size_t field = 0;
             field < value.sides[side_index].raw_loss_i32.size(); ++field) {
            value.sides[side_index].raw_loss_i32[field] =
                static_cast<std::int32_t>(0x51510000
                    + static_cast<int>(side_index * 17u + field));
        }
        value.sides[side_index].raw_gate =
            static_cast<std::uint8_t>(0xa0u + side_index);
    }
    for (std::size_t index = 0; index < value.row_types.size(); ++index) {
        value.row_types[index] = static_cast<std::int32_t>(
            0x31310000 + static_cast<int>(index));
    }
    return value;
}

void test_empty_success() noexcept {
    std::printf("TEST empty_success\n");
    TestReader reader;
    const summary::Snapshot base = make_base_summary();
    setup(reader, 0u, base);
    naval::Snapshot output = sentinel();
    const bool copied = naval::capture(reader, TestReader::kCombat,
                                       TestReader::kSummary, base, output);
    check(copied, "empty_capture");
    check(output.row_count == 0u, "empty_row_count");
    check(output.sides[0].raw_loss_i32[0] == -1000
              && output.sides[1].raw_loss_i32[3] == 1056,
          "empty_keeps_raw_losses");
    check(output.sides[0].raw_gate == 0x20u
              && output.sides[1].raw_gate == 0x21u,
          "empty_keeps_raw_gate");
    check(reader.bytes_read <= naval::kMaxReadBudgetBytes,
          "empty_read_budget");
}

void test_nonempty_and_max_rows() noexcept {
    std::printf("TEST nonempty_and_max_rows\n");
    TestReader reader;
    const summary::Snapshot base = make_base_summary();
    setup(reader, 3u, base);
    naval::Snapshot output{};
    check(naval::capture(reader, TestReader::kCombat, TestReader::kSummary,
                         base, output), "nonempty_capture");
    check(output.row_count == 3u, "nonempty_row_count");
    check(output.row_types[0] == -700 && output.row_types[1] == -687
              && output.row_types[2] == -674,
          "row_type_order_preserved");
    setup(reader, static_cast<std::uint32_t>(naval::kMaxRows), base);
    output = naval::Snapshot{};
    check(naval::capture(reader, TestReader::kCombat, TestReader::kSummary,
                         base, output), "max_rows_capture");
    check(output.row_count == naval::kMaxRows
              && output.row_types[naval::kMaxRows - 1u] == 2615,
          "max_rows_and_last_type");
    check(reader.bytes_read <= naval::kMaxReadBudgetBytes,
          "max_rows_read_budget");
}

void test_failure_keeps_output() noexcept {
    std::printf("TEST failure_keeps_output\n");
    const summary::Snapshot base = make_base_summary();
    const std::array<TestReader::Mutation, 4> mutations{{
        TestReader::Mutation::none,
        TestReader::Mutation::side_pointer,
        TestReader::Mutation::side_gate,
        TestReader::Mutation::row_pointer,
    }};
    for (std::size_t index = 0; index < mutations.size(); ++index) {
        TestReader reader;
        setup(reader, index == 3u ? 1u : 1u, base);
        naval::Snapshot output = sentinel();
        const naval::Snapshot before = output;
        if (mutations[index] == TestReader::Mutation::none) {
            reader.fail_on_call = 6u;
        } else {
            reader.mutation = mutations[index];
            reader.mutate_after_call = 8u;  // first pass: 5 + 3 rows
        }
        check(!naval::capture(reader, TestReader::kCombat,
                              TestReader::kSummary, base, output),
              index == 0u ? "read_failure_rejected"
                          : (index == 1u ? "side_pointer_change_rejected"
                                         : (index == 2u ? "side_gate_change_rejected"
                                                        : "row_pointer_change_rejected")));
        check(same_snapshot(output, before),
              index == 0u ? "read_failure_output_unchanged"
                          : (index == 1u ? "side_pointer_output_unchanged"
                                         : (index == 2u ? "side_gate_output_unchanged"
                                                        : "row_pointer_output_unchanged")));
    }

    TestReader reader;
    setup(reader, 1u, base);
    naval::Snapshot output = sentinel();
    const naval::Snapshot before = output;
    summary::Snapshot mismatched = base;
    mismatched.raw_i32[4] += 1;
    check(!naval::capture(reader, TestReader::kCombat, TestReader::kSummary,
                          mismatched, output), "base_summary_mismatch_rejected");
    check(same_snapshot(output, before), "base_mismatch_output_unchanged");

    setup(reader, 1u, base);
    output = sentinel();
    const naval::Snapshot header_before = output;
    reader.mutation = TestReader::Mutation::summary_header;
    reader.mutate_after_call = 8u;
    check(!naval::capture(reader, TestReader::kCombat,
                          TestReader::kSummary, base, output),
          "summary_header_change_rejected");
    check(same_snapshot(output, header_before),
          "summary_header_output_unchanged");
}

void test_bounds_alias_and_invalid() noexcept {
    std::printf("TEST bounds_alias_and_invalid\n");
    const summary::Snapshot base = make_base_summary();
    TestReader reader;
    setup(reader, 1u, base);

    naval::Snapshot output = sentinel();
    const naval::Snapshot before = output;
    write_u64(reader, TestReader::kSummary + naval::kSummaryEndOffset,
              TestReader::kRows + static_cast<TestReader::Address>(257u * 8u));
    check(!naval::capture(reader, TestReader::kCombat, TestReader::kSummary,
                          base, output), "row_limit_rejected");
    check(same_snapshot(output, before), "row_limit_output_unchanged");

    setup(reader, 1u, base);
    output = sentinel();
    const naval::Snapshot alias_before = output;
    const naval::Address output_address =
        reinterpret_cast<naval::Address>(&output);
    const naval::Address alias_summary = output_address;
    check(!naval::capture(reader, TestReader::kCombat, alias_summary,
                          base, output), "source_output_alias_rejected");
    check(reader.call_count == 0u, "alias_no_reader_call");
    check(same_snapshot(output, alias_before), "alias_output_unchanged");

    setup(reader, 1u, base);
    output = sentinel();
    const naval::Snapshot invalid_before = output;
    write_u64(reader, TestReader::kRows + 0u, TestReader::kRowObjects + 1u);
    check(!naval::capture(reader, TestReader::kCombat, TestReader::kSummary,
                          base, output), "unaligned_row_rejected");
    check(same_snapshot(output, invalid_before), "unaligned_output_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-naval\n");
    test_empty_success();
    test_nonempty_and_max_rows();
    test_failure_keeps_output();
    test_bounds_alias_and_invalid();
    std::printf("SUMMARY checks=%u failures=%u status=%s\n", g_checks,
                g_failures, g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
