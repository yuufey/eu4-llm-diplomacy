#include "information-battle-observation-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace observation = information::battle::observation;
namespace owned = information::battle::owned_result;

namespace {

unsigned g_failures = 0;
unsigned g_checks = 0;

void check(bool condition, const char* label) noexcept {
    ++g_checks;
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void set_bytes(owned::OwnedBytes& target,
               const unsigned char* bytes,
               std::size_t length,
               std::uint32_t capacity) noexcept {
    target.bytes.fill(0);
    if (length != 0u) {
        std::memcpy(target.bytes.data(), bytes, length);
    }
    target.length = static_cast<std::uint32_t>(length);
    target.capacity = capacity;
}

observation::Observation make_observation() noexcept {
    observation::Observation value{};
    value.sequence = std::numeric_limits<std::uint64_t>::max();
    value.thread = std::numeric_limits<std::uint32_t>::max();
    value.known_router = true;
    value.result.raw_date = std::numeric_limits<std::int32_t>::min();
    value.result.flag108 = 0xa5u;
    value.result.aux100 = -2000000000;
    value.result.aux104 = std::numeric_limits<std::int32_t>::max();
    value.result.province_id = -1285;

    constexpr std::array<unsigned char, 5> kName{{0xffu, 0x00u, 0x80u,
                                                    0xc3u, 0x28u}};
    set_bytes(value.result.name, kName.data(), kName.size(), 128u);

    value.result.sides[0].country = UINT64_C(0x0100007a00415246);
    value.result.sides[1].country = std::numeric_limits<std::uint64_t>::max();
    for (std::size_t index = 0; index < value.result.sides[0].raw_fields.size(); ++index) {
        value.result.sides[0].raw_fields[index] =
            index % 2u == 0u ? std::numeric_limits<std::int32_t>::min()
                             : std::numeric_limits<std::int32_t>::max();
        value.result.sides[1].raw_fields[index] =
            static_cast<std::int32_t>(-1000 - static_cast<int>(index));
    }
    set_bytes(value.result.sides[0].commander, nullptr, 0u, 0u);
    constexpr std::array<unsigned char, 3> kCommander{{0xf1u, 0x9fu, 0x8eu}};
    set_bytes(value.result.sides[1].commander, kCommander.data(),
              kCommander.size(), 16u);

    for (std::size_t index = 0; index < value.summary.raw_i32.size(); ++index) {
        value.summary.raw_i32[index] =
            index == 0u ? std::numeric_limits<std::int32_t>::min()
                        : static_cast<std::int32_t>(index * 17 - 90);
    }
    value.summary.control_byte = 0xfeu;
    return value;
}

bool bytes_equal(const std::array<unsigned char, observation::kMaxWireBytes>& left,
                 const std::array<unsigned char, observation::kMaxWireBytes>& right) noexcept {
    return std::memcmp(left.data(), right.data(), left.size()) == 0;
}

void print_wire(const unsigned char* data, std::size_t size) noexcept {
    std::printf("WIRE_HEX ");
    for (std::size_t index = 0; index < size; ++index) {
        std::printf("%02x", static_cast<unsigned>(data[index]));
    }
    std::printf("\n");
}

void test_valid_and_capacity_omitted() noexcept {
    std::printf("TEST valid_and_capacity_omitted\n");
    observation::Observation input = make_observation();
    std::array<unsigned char, observation::kMaxWireBytes> wire{};
    wire.fill(0xa5u);
    const observation::EncodeResult encoded =
        observation::encode(input, wire.data(), wire.size());
    check(encoded.succeeded(), "valid_encode");
    check(encoded.written_bytes <= observation::kMaxWireBytes,
          "wire_bound");
    check(wire[0] == observation::kMagic[0]
              && wire[1] == observation::kMagic[1]
              && wire[2] == observation::kMagic[2]
              && wire[3] == observation::kMagic[3],
          "fixed_magic");
    check(wire[4] == 1u && wire[5] == 0u, "little_endian_version");
    print_wire(wire.data(), encoded.written_bytes);

    observation::Observation capacity_variant = input;
    capacity_variant.result.name.capacity = 4096u;
    capacity_variant.result.sides[1].commander.capacity = 4096u;
    std::array<unsigned char, observation::kMaxWireBytes> variant{};
    const observation::EncodeResult variant_result =
        observation::encode(capacity_variant, variant.data(), variant.size());
    check(variant_result.succeeded(), "capacity_variant_encode");
    check(variant_result.written_bytes == encoded.written_bytes,
          "capacity_not_on_wire_size");
    check(std::memcmp(wire.data(), variant.data(), encoded.written_bytes) == 0,
          "capacity_not_on_wire_bytes");
}

void check_failure_unchanged(const observation::Observation& input,
                             std::size_t capacity,
                             const char* label) noexcept {
    std::array<unsigned char, observation::kMaxWireBytes> output{};
    output.fill(0x5au);
    const auto before = output;
    const observation::EncodeResult result =
        observation::encode(input, output.data(), capacity);
    check(!result.succeeded() && result.written_bytes == 0u, label);
    check(bytes_equal(output, before), "failure_output_unchanged");
}

void test_failure_guards() noexcept {
    std::printf("TEST failure_guards\n");
    observation::Observation input = make_observation();

    observation::Observation sequence_zero = input;
    sequence_zero.sequence = 0u;
    check_failure_unchanged(sequence_zero, observation::kMaxWireBytes,
                            "zero_sequence_rejected");

    observation::Observation thread_zero = input;
    thread_zero.thread = 0u;
    check_failure_unchanged(thread_zero, observation::kMaxWireBytes,
                            "zero_thread_rejected");

    observation::Observation oversized = input;
    oversized.result.name.length =
        static_cast<std::uint32_t>(observation::kMaxStringBytes + 1u);
    check_failure_unchanged(oversized, observation::kMaxWireBytes,
                            "oversized_string_rejected");

    observation::Observation bad_capacity = input;
    bad_capacity.result.name.capacity = bad_capacity.result.name.length - 1u;
    check_failure_unchanged(bad_capacity, observation::kMaxWireBytes,
                            "capacity_below_length_rejected");

    check_failure_unchanged(input, 1u, "short_output_rejected");
    {
        std::array<unsigned char, observation::kMaxWireBytes> output{};
        output.fill(0x3cu);
        const auto before = output;
        const auto result = observation::encode(input, nullptr,
                                                observation::kMaxWireBytes);
        check(!result.succeeded() && bytes_equal(output, before),
              "null_output_rejected");
    }

    observation::Observation alias_input = input;
    const observation::Observation before_alias = alias_input;
    const auto alias_result = observation::encode(
        alias_input,
        reinterpret_cast<unsigned char*>(&alias_input),
        observation::kMaxWireBytes);
    check(!alias_result.succeeded(), "input_output_alias_rejected");
    check(std::memcmp(&alias_input, &before_alias, sizeof(alias_input)) == 0,
          "alias_input_unchanged");

    const auto overflow_result = observation::encode(
        input,
        reinterpret_cast<unsigned char*>(
            std::numeric_limits<observation::Address>::max() - 1u),
        observation::kMaxWireBytes);
    check(!overflow_result.succeeded(), "output_pointer_overflow_rejected");
}

}  // namespace

int main() {
    test_valid_and_capacity_omitted();
    test_failure_guards();
    std::printf("SUMMARY checks=%u failures=%u\n", g_checks, g_failures);
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
