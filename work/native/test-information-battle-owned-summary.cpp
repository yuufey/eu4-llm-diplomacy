#include "information-battle-owned-summary.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <type_traits>

namespace summary = information::battle::owned_summary;

struct TestReader {
    summary::Address base = UINT64_C(0x20000);
    std::array<unsigned char, 0x100> bytes{};
    bool fail = false;
    std::size_t call_count = 0;
    std::size_t bytes_read = 0;

    bool read(summary::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++call_count;
        if (fail || destination == nullptr || size == 0u
                || address < base
                || address - base > bytes.size()
                || size > bytes.size() - (address - base)) {
            return false;
        }
        std::memcpy(destination, bytes.data() + (address - base), size);
        bytes_read += size;
        return true;
    }
};

struct BadReader {
    bool read(summary::Address, unsigned char*, std::size_t) {
        return true;
    }
};

static_assert(summary::reader_contract<TestReader>::value,
              "the test seam must match the exact noexcept signature");
static_assert(!summary::reader_contract<BadReader>::value,
              "a throwing-capable seam must be rejected");
static_assert(std::is_trivially_copyable<summary::Snapshot>::value,
              "the output must remain a plain raw-value object");

namespace {

int failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++failures;
    }
}

void write_i32(TestReader& reader, std::size_t offset, std::int32_t value) {
    std::memcpy(reader.bytes.data() + offset, &value, sizeof(value));
}

void fill_source(TestReader& reader,
                 const std::array<std::int32_t, 11>& values,
                 unsigned char control) {
    reader.bytes.fill(0);
    for (std::size_t index = 0; index < values.size(); ++index) {
        write_i32(reader, summary::kRawFieldOffsets[index], values[index]);
    }
    reader.bytes[summary::kSummaryControlOffset] = control;
    reader.call_count = 0;
    reader.bytes_read = 0;
    reader.fail = false;
}

bool equal_snapshot(const summary::Snapshot& left,
                    const summary::Snapshot& right) {
    if (left.control_byte != right.control_byte) {
        return false;
    }
    return left.raw_i32 == right.raw_i32;
}

summary::Snapshot sentinel() {
    summary::Snapshot output{};
    for (std::size_t index = 0; index < output.raw_i32.size(); ++index) {
        output.raw_i32[index] = static_cast<std::int32_t>(
            0x51510000 + static_cast<int>(index));
    }
    output.control_byte = 0xa5u;
    return output;
}

void check_unchanged(const summary::Snapshot& output,
                     const summary::Snapshot& before,
                     const char* label) {
    check(equal_snapshot(output, before), label);
}

void test_valid_copy_and_source_mutation() {
    std::printf("TEST valid_copy_and_source_mutation\n");
    TestReader reader;
    const std::array<std::int32_t, 11> values{{
        INT32_MIN, -2000000000, -123456, -1, 0, 1,
        42, 99999, 123456789, INT32_MAX, -7,
    }};
    fill_source(reader, values, 0x7fu);
    summary::Snapshot output{};
    const bool copied = summary::capture(reader, reader.base, output);
    check(copied, "valid_capture");
    check(reader.call_count == 1u, "single_reader_call");
    check(reader.bytes_read == summary::kSummaryReadBytes,
          "read_exact_surveyed_span");
    check(reader.bytes_read <= summary::kMaxReadBudgetBytes,
          "read_budget_256");
    check(output.raw_i32 == values, "all_signed_raw_values");
    check(output.control_byte == 0x7fu, "raw_control_byte");

    const summary::Snapshot preserved = output;
    const std::array<std::int32_t, 11> rewritten{{
        7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    }};
    fill_source(reader, rewritten, 0x01u);
    check(equal_snapshot(output, preserved), "copy_has_no_borrowed_source");
}

void test_failed_read_keeps_output() {
    std::printf("TEST failed_read_keeps_output\n");
    TestReader reader;
    fill_source(reader, std::array<std::int32_t, 11>{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, 0x44u);
    reader.fail = true;
    summary::Snapshot output = sentinel();
    const summary::Snapshot before = output;
    check(!summary::capture(reader, reader.base, output), "reader_failure_rejected");
    check_unchanged(output, before, "reader_failure_output_unchanged");
}

void test_address_guards() {
    std::printf("TEST address_guards\n");
    TestReader reader;
    fill_source(reader, std::array<std::int32_t, 11>{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, 0x11u);

    const std::array<summary::Address, 4> invalid{{
        UINT64_C(0xf000),
        UINT64_C(0xfff0),
        summary::kMaxCanonicalExclusive - UINT64_C(0x20),
        std::numeric_limits<summary::Address>::max() - UINT64_C(0x10),
    }};
    for (std::size_t index = 0; index < invalid.size(); ++index) {
        summary::Snapshot output = sentinel();
        const summary::Snapshot before = output;
        reader.call_count = 0;
        check(!summary::capture(reader, invalid[index], output),
              index < 2u ? "low_address_rejected"
                         : (index == 2u ? "high_address_rejected"
                                        : "address_overflow_rejected"));
        check(reader.call_count == 0u, "invalid_address_no_read");
        check_unchanged(output, before, "invalid_address_output_unchanged");
    }
}

void test_source_output_alias() {
    std::printf("TEST source_output_alias\n");
    TestReader reader;
    fill_source(reader, std::array<std::int32_t, 11>{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, 0x22u);
    summary::Snapshot output = sentinel();
    const summary::Snapshot before = output;
    const summary::Address output_address =
        reinterpret_cast<summary::Address>(&output);
    const summary::Address alias_base = output_address - summary::kSummaryBaseOffset;
    reader.base = alias_base;
    reader.call_count = 0;
    check(!summary::capture(reader, alias_base, output), "source_output_alias_rejected");
    check(reader.call_count == 0u, "alias_no_read");
    check_unchanged(output, before, "alias_output_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-summary\n");
    test_valid_copy_and_source_mutation();
    test_failed_read_keeps_output();
    test_address_guards();
    test_source_output_alias();
    std::printf("SUMMARY checks_failed=%d status=%s\n",
                failures, failures == 0 ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
