#include "../information-battle-naval-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

namespace naval = information::battle::naval_wire;
namespace context = information::battle::context_wire;
namespace observation = information::battle::observation;
namespace owned_result = information::battle::owned_result;
namespace owned_context = information::battle::owned_context;
namespace owned_naval = information::battle::owned_naval;

constexpr char kHex[] = "0123456789abcdef";

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

std::uint64_t full_ref(unsigned index) {
    constexpr unsigned char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    constexpr unsigned size = 36u;
    return static_cast<std::uint64_t>(alphabet[index % size])
        | (static_cast<std::uint64_t>(alphabet[(index / size) % size]) << 8u)
        | (static_cast<std::uint64_t>(alphabet[(index / (size * size)) % size]) << 16u)
        | (UINT64_C(0x01) << 32u)
        | (UINT64_C(0x01) << 56u);
}

owned_result::OwnedBytes bytes(const char* value) {
    owned_result::OwnedBytes result{};
    const std::size_t length = std::strlen(value);
    result.length = static_cast<std::uint32_t>(length);
    result.capacity = static_cast<std::uint32_t>(length);
    for (std::size_t index = 0; index < length; ++index) {
        result.bytes[index] = static_cast<unsigned char>(value[index]);
    }
    return result;
}

observation::Observation inner() {
    observation::Observation result{};
    result.sequence = UINT64_C(0x1122334455667788);
    result.thread = UINT32_C(0x12345678);
    result.known_router = true;
    result.result.raw_date = -1455113;
    result.result.flag108 = 0xA5u;
    result.result.aux100 = -123456;
    result.result.aux104 = 654321;
    result.result.province_id = 1275;
    result.result.name = bytes("Naval");
    for (std::size_t side = 0; side < result.result.sides.size(); ++side) {
        auto& value = result.result.sides[side];
        value.country = full_ref(static_cast<unsigned>(side));
        value.commander = owned_result::OwnedBytes{};
        for (std::size_t field = 0; field < value.raw_fields.size(); ++field) {
            value.raw_fields[field] = static_cast<std::int32_t>(
                static_cast<int>(side) * 100 + static_cast<int>(field));
        }
    }
    for (std::size_t index = 0; index < result.summary.raw_i32.size(); ++index) {
        result.summary.raw_i32[index] = static_cast<std::int32_t>(index * 7u - 30);
    }
    result.summary.control_byte = 0x5Au;
    return result;
}

context::ContextObservation base(bool context_present,
                                 owned_context::Kind kind) {
    context::ContextObservation result{};
    result.inner = inner();
    result.context_present = context_present;
    if (!context_present) {
        return result;
    }
    result.context.known_router = true;
    result.context.raw_selector = kind == owned_context::Kind::naval ? 2u : 1u;
    result.context.selector_code = {{0xB8u,
        static_cast<unsigned char>(result.context.raw_selector & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 8u) & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 16u) & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 24u) & 0xffu),
        0xC3u}};
    result.context.selector_code_verified = true;
    result.context.kind = kind;
    result.context.physical_player_full_ref = full_ref(0u);
    for (std::size_t side = 0; side < result.context.sides.size(); ++side) {
        auto& value = result.context.sides[side];
        value.present = true;
        value.participants.complete = true;
        value.participants.count = 1u;
        value.participants.full_refs[0] = full_ref(static_cast<unsigned>(side + 2u));
        for (std::size_t field = 0; field < value.raw_fields.size(); ++field) {
            value.raw_fields[field] = static_cast<std::int32_t>(
                static_cast<int>(side) * 1000 + static_cast<int>(field));
        }
    }
    result.context.war_context_status = owned_context::WarContextStatus::absent;
    return result;
}

naval::NavalObservation observed_naval(std::uint32_t rows) {
    naval::NavalObservation result{};
    result.base = base(true, owned_context::Kind::naval);
    result.naval_present = true;
    result.naval.row_count = rows;
    for (std::size_t index = 0; index < rows && index < owned_naval::kMaxRows;
         ++index) {
        result.naval.row_types[index] = static_cast<std::int32_t>(
            static_cast<int>(index) * 3 - 500);
    }
    for (std::size_t side = 0; side < result.naval.sides.size(); ++side) {
        for (std::size_t lane = 0; lane < result.naval.sides[side].raw_loss_i32.size(); ++lane) {
            result.naval.sides[side].raw_loss_i32[lane] = static_cast<std::int32_t>(
                static_cast<int>(side) * 10000 + static_cast<int>(lane) * 101 - 200);
        }
        result.naval.sides[side].raw_gate =
            static_cast<std::uint8_t>(0x80u + side);
    }
    return result;
}

void write_hex(std::ostream& output, const unsigned char* bytes,
               std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        const unsigned char value = bytes[index];
        output << kHex[(value >> 4u) & 0x0fu] << kHex[value & 0x0fu];
    }
}

template <std::size_t N>
void print_wire(const char* name, const std::array<unsigned char, N>& bytes,
                std::size_t length) {
    std::cout << "WIRE " << name << ' ';
    write_hex(std::cout, bytes.data(), length);
    std::cout << '\n';
}

void test_absent_and_base_roundtrip() {
    naval::NavalObservation input{};
    input.base = base(false, owned_context::Kind::unknown);
    input.naval_present = false;
    std::array<unsigned char, naval::kMaxWireBytes> output{};
    const auto result = naval::encode(input, output.data(), output.size());
    require(result.succeeded(), "v3 absent frame encodes");
    require(result.written_bytes == naval::encoded_size(input),
            "absent encoded_size matches encode");
    const std::size_t base_bytes = static_cast<std::size_t>(
        output[6] | (static_cast<std::uint32_t>(output[7]) << 8u)
        | (static_cast<std::uint32_t>(output[8]) << 16u)
        | (static_cast<std::uint32_t>(output[9]) << 24u));
    require(base_bytes != 0u && 10u + base_bytes + 1u == result.written_bytes,
            "absent frame has exact base and marker length");
    std::array<unsigned char, context::kMaxWireBytes> base_wire{};
    const auto base_result = context::encode(input.base, base_wire.data(),
                                               base_wire.size());
    require(base_result.succeeded() && base_result.written_bytes == base_bytes,
            "base v2 bytes are independently encoded");
    require(std::memcmp(output.data() + 10u, base_wire.data(), base_bytes) == 0,
            "v3 embeds unchanged v2 bytes");
    print_wire("absent", output, result.written_bytes);
    print_wire("base_v2", base_wire, base_result.written_bytes);
    std::cout << "CHECK absent_and_base_roundtrip PASS\n";
}

void test_nonempty_and_maximum() {
    const naval::NavalObservation input = observed_naval(3u);
    std::array<unsigned char, naval::kMaxWireBytes> output{};
    const auto result = naval::encode(input, output.data(), output.size());
    require(result.succeeded(), "v3 naval frame encodes");
    require(result.written_bytes == naval::encoded_size(input),
            "nonempty encoded_size matches encode");
    require(output[0] == 'I' && output[1] == 'B' && output[2] == 'O'
                && output[3] == 'W' && output[4] == 3u,
            "v3 header is canonical");
    print_wire("naval", output, result.written_bytes);
    std::cout << "CHECK nonempty_roundtrip_source PASS\n";

    const naval::NavalObservation maximum = observed_naval(
        static_cast<std::uint32_t>(owned_naval::kMaxRows));
    const auto maximum_result = naval::encode(maximum, output.data(),
                                              output.size());
    require(maximum_result.succeeded(), "256-row frame encodes");
    require(maximum_result.written_bytes <= naval::kMaxWireBytes,
            "256-row frame remains within wire budget");
    print_wire("maximum", output, maximum_result.written_bytes);
    std::cout << "CHECK maximum_256_rows PASS\n";
}

void test_rejections_and_atomic_output() {
    std::array<unsigned char, naval::kMaxWireBytes> output{};
    output.fill(0xA5u);
    auto invalid = observed_naval(0u);
    invalid.base.context_present = false;
    require(naval::encoded_size(invalid) == 0u,
            "naval present without base context is rejected");
    require(!naval::encode(invalid, output.data(), output.size()).succeeded(),
            "invalid base does not encode");
    for (const auto byte : output) {
        require(byte == 0xA5u, "invalid encode leaves output untouched");
    }

    invalid = observed_naval(0u);
    invalid.base = base(true, owned_context::Kind::land);
    require(naval::encoded_size(invalid) == 0u,
            "land base rejects naval extension");

    invalid = observed_naval(0u);
    invalid.naval.row_count = static_cast<std::uint32_t>(owned_naval::kMaxRows + 1u);
    require(naval::encoded_size(invalid) == 0u,
            "row count over bound rejects");

    const auto valid = observed_naval(3u);
    std::array<unsigned char, naval::kMaxWireBytes> short_output{};
    short_output.fill(0x5Au);
    const std::size_t required = naval::encoded_size(valid);
    require(required > 0u, "valid frame reports required size");
    require(!naval::encode(valid, short_output.data(), required - 1u).succeeded(),
            "short output rejects");
    for (const auto byte : short_output) {
        require(byte == 0x5Au, "short output leaves destination untouched");
    }
    std::cout << "CHECK invalid_and_atomic_rejections PASS\n";
}

}  // namespace

int main() {
    test_absent_and_base_roundtrip();
    test_nonempty_and_maximum();
    test_rejections_and_atomic_output();
    std::cout << "RESULT native_naval_wire PASS\n";
    return 0;
}
