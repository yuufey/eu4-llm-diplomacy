#include "../information-battle-owned-end-state.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <type_traits>

namespace {

namespace end_state = information::battle::owned_end_state;
namespace context = information::battle::owned_context;

struct TestReader {
    using Address = end_state::Address;

    static constexpr Address kBase = UINT64_C(0x200000);
    static constexpr std::size_t kMemoryBytes = 0x4000u;
    static constexpr Address kCombat = kBase + 0x100u;
    static constexpr Address kSide0 = kBase + 0x800u;
    static constexpr Address kSide1 = kBase + 0xc00u;

    enum class Mutation : std::uint8_t {
        none,
        side_pointer,
        side0_gate,
        side1_gate,
    };

    std::array<unsigned char, kMemoryBytes> memory{};
    std::size_t call_count = 0u;
    std::size_t bytes_read = 0u;
    std::size_t max_single_read = 0u;
    std::size_t fail_on_call = 0u;
    std::size_t mutate_after_call = 0u;
    Mutation mutation = Mutation::none;

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
        if (size > max_single_read) {
            max_single_read = size;
        }
        if (mutate_after_call == call_count) {
            mutate_source();
        }
        return true;
    }

    void mutate_source() noexcept {
        if (mutation == Mutation::side_pointer) {
            const Address side = kSide1 + 0x40u;
            (void)write(kCombat + end_state::kCombatSidePointerOffset
                            + sizeof(Address),
                        &side, sizeof(side));
        } else if (mutation == Mutation::side0_gate) {
            const unsigned char gate = 0x7fu;
            (void)write(kSide0 + end_state::kSideRawGateOffset,
                        &gate, sizeof(gate));
        } else if (mutation == Mutation::side1_gate) {
            const unsigned char gate = 0x3fu;
            (void)write(kSide1 + end_state::kSideRawGateOffset,
                        &gate, sizeof(gate));
        }
    }
};

struct BadReader {
    bool read(end_state::Address, unsigned char*, std::size_t) { return true; }
};

static_assert(end_state::reader_contract<TestReader>::value,
              "test reader must match the no-throw seam");
static_assert(!end_state::reader_contract<BadReader>::value,
              "throwing-capable seams must be rejected");
static_assert(sizeof(end_state::Snapshot) == 2u,
              "the extension must retain exactly two bytes");
static_assert(std::is_trivially_copyable<end_state::Snapshot>::value,
              "the copied output must remain a plain value object");

unsigned g_checks = 0u;
unsigned g_failures = 0u;

void check(bool condition, const char* label) noexcept {
    ++g_checks;
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

end_state::Snapshot sentinel() noexcept {
    end_state::Snapshot value{};
    value.raw_gate = {{0xa1u, 0xb2u}};
    return value;
}

bool same_snapshot(const end_state::Snapshot& left,
                   const end_state::Snapshot& right) noexcept {
    return left.raw_gate == right.raw_gate;
}

context::Snapshot make_context(context::Kind kind) noexcept {
    context::Snapshot value{};
    value.known_router = true;
    value.raw_selector = static_cast<std::uint32_t>(kind);
    value.selector_code_verified = true;
    value.kind = kind;
    for (std::size_t index = 0u; index < value.sides.size(); ++index) {
        value.sides[index].present = true;
        value.sides[index].participants.complete = true;
        value.sides[index].participants.count = 1u;
        value.sides[index].participants.full_refs[0] =
            UINT64_C(0x1000000000000001) + index;
    }
    return value;
}

std::array<TestReader::Address, 2> verified_sides() noexcept {
    return {{TestReader::kSide0, TestReader::kSide1}};
}

void setup(TestReader& reader) noexcept {
    reader.memory.fill(0u);
    reader.call_count = 0u;
    reader.bytes_read = 0u;
    reader.max_single_read = 0u;
    reader.fail_on_call = 0u;
    reader.mutate_after_call = 0u;
    reader.mutation = TestReader::Mutation::none;

    const std::array<TestReader::Address, 2> sides = verified_sides();
    (void)reader.write(TestReader::kCombat + end_state::kCombatSidePointerOffset,
                       sides.data(), sizeof(sides));
    const unsigned char raw0 = 0x01u;
    const unsigned char raw1 = 0x00u;
    (void)reader.write(TestReader::kSide0 + end_state::kSideRawGateOffset,
                       &raw0, sizeof(raw0));
    (void)reader.write(TestReader::kSide1 + end_state::kSideRawGateOffset,
                       &raw1, sizeof(raw1));
}

void test_land_and_naval_success() noexcept {
    std::printf("TEST land_and_naval_success\n");
    const std::array<context::Kind, 2> kinds{{
        context::Kind::land, context::Kind::naval,
    }};
    for (std::size_t index = 0u; index < kinds.size(); ++index) {
        TestReader reader;
        setup(reader);
        end_state::Snapshot output = sentinel();
        const bool copied = end_state::capture(
            reader, TestReader::kCombat, make_context(kinds[index]),
            verified_sides(), output);
        check(copied, index == 0u ? "land_copy_known" : "naval_copy_known");
        check(output.raw_gate == std::array<std::uint8_t, 2>{{0x01u, 0x00u}},
              index == 0u ? "land_raw_pair" : "naval_raw_pair");
        check(reader.call_count == 6u, "two_pass_six_reads");
        check(reader.bytes_read == 36u, "two_pass_36_bytes");
        check(reader.max_single_read <= end_state::kMaxSingleReadBytes,
              "single_read_at_most_16");
        check(reader.bytes_read <= end_state::kMaxReadBudgetBytes,
              "total_read_within_budget");
    }
}

void test_context_and_side_gates() noexcept {
    std::printf("TEST context_and_side_gates\n");
    TestReader reader;
    setup(reader);
    end_state::Snapshot output = sentinel();
    const end_state::Snapshot before = output;
    context::Snapshot invalid = make_context(context::Kind::unknown);
    check(!end_state::capture(reader, TestReader::kCombat, invalid,
                              verified_sides(), output), "unknown_kind_rejected");
    check(same_snapshot(output, before), "unknown_kind_output_unchanged");
    check(reader.call_count == 0u, "unknown_kind_no_read");

    setup(reader);
    output = sentinel();
    context::Snapshot bad_selector = make_context(context::Kind::land);
    bad_selector.raw_selector = 2u;
    check(!end_state::capture(reader, TestReader::kCombat, bad_selector,
                              verified_sides(), output),
          "selector_kind_mismatch_rejected");
    check(same_snapshot(output, before), "selector_mismatch_output_unchanged");

    setup(reader);
    output = sentinel();
    context::Snapshot one_side = make_context(context::Kind::naval);
    one_side.sides[1].present = false;
    check(!end_state::capture(reader, TestReader::kCombat, one_side,
                              verified_sides(), output), "missing_side_rejected");
    check(same_snapshot(output, before), "missing_side_output_unchanged");

    setup(reader);
    output = sentinel();
    context::Snapshot empty_side = make_context(context::Kind::land);
    empty_side.sides[0].participants.count = 0u;
    check(!end_state::capture(reader, TestReader::kCombat, empty_side,
                              verified_sides(), output), "empty_side_rejected");
    check(same_snapshot(output, before), "empty_side_output_unchanged");
}

void test_bad_pointer_bindings() noexcept {
    std::printf("TEST bad_pointer_bindings\n");
    TestReader reader;
    setup(reader);
    end_state::Snapshot output = sentinel();
    const end_state::Snapshot before = output;
    const std::array<TestReader::Address, 2> aliased{{
        TestReader::kSide0, TestReader::kSide0,
    }};
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::land), aliased,
                              output), "aliased_verified_sides_rejected");
    check(reader.call_count == 0u, "aliased_sides_no_read");
    check(same_snapshot(output, before), "aliased_sides_output_unchanged");

    setup(reader);
    output = sentinel();
    const std::array<TestReader::Address, 2> mismatched{{
        TestReader::kSide0, TestReader::kSide1 + 0x40u,
    }};
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::naval), mismatched,
                              output), "current_side_pair_mismatch_rejected");
    check(reader.call_count == 1u, "pair_mismatch_stops_after_pair_read");
    check(same_snapshot(output, before), "pair_mismatch_output_unchanged");

    setup(reader);
    output = sentinel();
    const std::array<TestReader::Address, 2> null_side{{
        TestReader::kSide0, 0u,
    }};
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::land), null_side,
                              output), "null_verified_side_rejected");
    check(reader.call_count == 0u, "null_side_no_read");
    check(same_snapshot(output, before), "null_side_output_unchanged");
}

void test_two_pass_drift_and_read_failure() noexcept {
    std::printf("TEST two_pass_drift_and_read_failure\n");
    TestReader reader;
    setup(reader);
    reader.mutation = TestReader::Mutation::side_pointer;
    reader.mutate_after_call = 1u;
    end_state::Snapshot output = sentinel();
    const end_state::Snapshot before = output;
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::land),
                              verified_sides(), output),
          "side_pointer_drift_rejected");
    check(same_snapshot(output, before), "side_pointer_drift_output_unchanged");

    setup(reader);
    reader.mutation = TestReader::Mutation::side0_gate;
    reader.mutate_after_call = 2u;
    output = sentinel();
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::naval),
                              verified_sides(), output), "side0_gate_drift_rejected");
    check(same_snapshot(output, before), "side0_gate_drift_output_unchanged");

    setup(reader);
    reader.mutation = TestReader::Mutation::side1_gate;
    reader.mutate_after_call = 3u;
    output = sentinel();
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::land),
                              verified_sides(), output), "side1_gate_drift_rejected");
    check(same_snapshot(output, before), "side1_gate_drift_output_unchanged");

    setup(reader);
    reader.fail_on_call = 6u;
    output = sentinel();
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::naval),
                              verified_sides(), output), "second_pass_read_failure");
    check(same_snapshot(output, before), "read_failure_output_unchanged");
}

void test_address_and_output_bounds() noexcept {
    std::printf("TEST address_and_output_bounds\n");
    TestReader reader;
    setup(reader);
    end_state::Snapshot output = sentinel();
    const end_state::Snapshot before = output;
    const end_state::Address near_limit =
        end_state::kMaxCanonicalExclusive - 8u;
    check(!end_state::capture(reader, near_limit,
                              make_context(context::Kind::land),
                              verified_sides(), output),
          "combat_pair_address_overflow_rejected");
    check(reader.call_count == 0u, "invalid_combat_no_read");
    check(same_snapshot(output, before), "invalid_combat_output_unchanged");

    setup(reader);
    output = sentinel();
    const std::array<TestReader::Address, 2> noncanonical{{
        TestReader::kSide0, end_state::kMaxCanonicalExclusive + 0x1000u,
    }};
    check(!end_state::capture(reader, TestReader::kCombat,
                              make_context(context::Kind::naval), noncanonical,
                              output), "noncanonical_side_rejected");
    check(reader.call_count == 0u, "noncanonical_side_no_read");
    check(same_snapshot(output, before), "noncanonical_side_output_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-end-state\n");
    test_land_and_naval_success();
    test_context_and_side_gates();
    test_bad_pointer_bindings();
    test_two_pass_drift_and_read_failure();
    test_address_and_output_bounds();
    std::printf("SUMMARY checks=%u failures=%u status=%s\n", g_checks,
                g_failures, g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
