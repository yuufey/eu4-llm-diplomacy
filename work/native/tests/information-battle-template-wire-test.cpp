#include "../information-battle-template-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace {

namespace wire = information::battle::template_wire;
namespace naval = information::battle::naval_wire;
namespace context = information::battle::context_wire;
namespace observation = information::battle::observation;
namespace owned_result = information::battle::owned_result;
namespace owned_context = information::battle::owned_context;
namespace owned_template = information::battle::owned_template;

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
    for (std::size_t index = 0u; index < length; ++index) {
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
    result.result.flag108 = 1u;
    result.result.aux100 = -123456;
    result.result.aux104 = 654321;
    result.result.province_id = 1275;
    result.result.name = bytes("Template");
    for (std::size_t side = 0u; side < result.result.sides.size(); ++side) {
        auto& value = result.result.sides[side];
        value.country = full_ref(static_cast<unsigned>(side));
        value.commander = owned_result::OwnedBytes{};
        for (std::size_t field = 0u; field < value.raw_fields.size(); ++field) {
            value.raw_fields[field] = static_cast<std::int32_t>(
                static_cast<int>(side) * 100 + static_cast<int>(field));
        }
    }
    for (std::size_t index = 0u; index < result.summary.raw_i32.size(); ++index) {
        result.summary.raw_i32[index] = static_cast<std::int32_t>(index * 7u - 30);
    }
    result.summary.control_byte = 1u;
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
    result.context.selector_code = {{
        0xb8u,
        static_cast<unsigned char>(result.context.raw_selector & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 8u) & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 16u) & 0xffu),
        static_cast<unsigned char>((result.context.raw_selector >> 24u) & 0xffu),
        0xc3u,
    }};
    result.context.selector_code_verified = true;
    result.context.kind = kind;
    result.context.physical_player_full_ref = full_ref(0u);
    for (std::size_t side = 0u; side < result.context.sides.size(); ++side) {
        auto& value = result.context.sides[side];
        value.present = true;
        value.participants.complete = true;
        value.participants.count = 1u;
        value.participants.full_refs[0] = full_ref(
            static_cast<unsigned>(side + 2u));
        for (std::size_t field = 0u; field < value.raw_fields.size(); ++field) {
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
    for (std::size_t index = 0u;
         index < rows && index < result.naval.row_types.size(); ++index) {
        result.naval.row_types[index] = static_cast<std::int32_t>(
            static_cast<int>(index) * 3 - 500);
    }
    for (std::size_t side = 0u; side < result.naval.sides.size(); ++side) {
        for (std::size_t lane = 0u;
             lane < result.naval.sides[side].raw_loss_i32.size(); ++lane) {
            result.naval.sides[side].raw_loss_i32[lane] =
                static_cast<std::int32_t>(
                    static_cast<int>(side) * 10000
                    + static_cast<int>(lane) * 101 - 200);
        }
        result.naval.sides[side].raw_gate =
            static_cast<std::uint8_t>(0x80u + side);
    }
    return result;
}

void put_range(owned_template::Snapshot& message,
               owned_template::TextRange& range,
               const unsigned char* data, std::size_t length,
               std::size_t& cursor) {
    require(length <= owned_template::kMaxArenaBytes - cursor,
            "snapshot fixture fits arena");
    range.offset = static_cast<std::uint32_t>(cursor);
    range.length = static_cast<std::uint32_t>(length);
    if (length != 0u) {
        std::memcpy(message.arena.data() + cursor, data, length);
    }
    cursor += length;
}

void fill_message(owned_template::Snapshot& message) {
    message = owned_template::Snapshot{};
    message.native_date = -1455113;
    message.raw_flag_8c = 0xa1u;
    message.raw_flag_8d = 0x5eu;
    message.raw_header_word_20 = UINT32_C(0xfeedbeef);
    message.raw_header_flag_24 = 0x7au;
    std::size_t cursor = 0u;
    const unsigned char auxiliary[] = {0x00u, 0xffu, 0x80u, 0x41u};
    put_range(message, message.auxiliary_text, auxiliary,
              sizeof(auxiliary), cursor);

    const unsigned char duplicate_key[] = {0x6bu, 0x00u, 0x80u};
    const unsigned char first_value[] = {0x00u, 0x76u, 0xfeu};
    const unsigned char second_value[] = {0x6fu, 0x6eu, 0x65u, 0x00u};
    message.pair_count = 2u;
    put_range(message, message.pairs[0].key, duplicate_key,
              sizeof(duplicate_key), cursor);
    put_range(message, message.pairs[0].value, first_value,
              sizeof(first_value), cursor);
    put_range(message, message.pairs[1].key, duplicate_key,
              sizeof(duplicate_key), cursor);
    put_range(message, message.pairs[1].value, second_value,
              sizeof(second_value), cursor);
}

void fill_boundary_message(owned_template::Snapshot& message,
                           std::size_t pair_count) {
    message = owned_template::Snapshot{};
    message.native_date = 0x11223344;
    message.raw_flag_8c = 0x11u;
    message.raw_flag_8d = 0x22u;
    message.raw_header_word_20 = UINT32_C(0xaabbccdd);
    message.raw_header_flag_24 = 0x33u;
    std::size_t cursor = 0u;
    std::array<unsigned char, owned_template::kMaxAuxiliaryTextBytes> auxiliary{};
    auxiliary.fill(0x00u);
    put_range(message, message.auxiliary_text, auxiliary.data(),
              auxiliary.size(), cursor);
    message.pair_count = static_cast<std::uint32_t>(pair_count);
    for (std::size_t index = 0u; index < pair_count; ++index) {
        const unsigned char key = static_cast<unsigned char>('A' + index % 26u);
        const unsigned char value = static_cast<unsigned char>('0' + index % 10u);
        put_range(message, message.pairs[index].key, &key, 1u, cursor);
        put_range(message, message.pairs[index].value, &value, 1u, cursor);
    }
}

void fill_length_boundary_message(owned_template::Snapshot& message) {
    message = owned_template::Snapshot{};
    std::size_t cursor = 0u;
    std::array<unsigned char, owned_template::kMaxAuxiliaryTextBytes> auxiliary{};
    auxiliary.fill(0xa5u);
    put_range(message, message.auxiliary_text, auxiliary.data(),
              auxiliary.size(), cursor);
    std::array<unsigned char, owned_template::kMaxKeyBytes> key{};
    key.fill(0x00u);
    std::array<unsigned char, owned_template::kMaxValueBytes> value{};
    value.fill(0xffu);
    message.pair_count = 1u;
    put_range(message, message.pairs[0].key, key.data(), key.size(), cursor);
    put_range(message, message.pairs[0].value, value.data(), value.size(), cursor);
}

void fill_formatter_container(owned_template::Snapshot& message) {
    message = owned_template::Snapshot{};
    message.raw_header_word_20 = UINT32_C(0x10203040);
    message.raw_header_flag_24 = 0x91u;
    std::size_t cursor = 0u;
    const unsigned char duplicate_key[] = {0x63u, 0x00u, 0x80u};
    const unsigned char first_value[] = {0x76u, 0xfeu};
    const unsigned char second_value[] = {0x00u, 0x41u};
    message.pair_count = 2u;
    put_range(message, message.pairs[0].key, duplicate_key,
              sizeof(duplicate_key), cursor);
    put_range(message, message.pairs[0].value, first_value,
              sizeof(first_value), cursor);
    put_range(message, message.pairs[1].key, duplicate_key,
              sizeof(duplicate_key), cursor);
    put_range(message, message.pairs[1].value, second_value,
              sizeof(second_value), cursor);
}

void write_hex(std::ostream& output, const unsigned char* data,
               std::size_t size) {
    for (std::size_t index = 0u; index < size; ++index) {
        const unsigned char value = data[index];
        output << kHex[(value >> 4u) & 0x0fu] << kHex[value & 0x0fu];
    }
}

template <std::size_t N>
void print_wire(const char* name, const std::array<unsigned char, N>& data,
                std::size_t size) {
    std::cout << "WIRE " << name << ' ';
    write_hex(std::cout, data.data(), size);
    std::cout << '\n';
}

void test_encode_cases() {
    std::array<unsigned char, wire::kMaxWireBytes> output{};

    wire::TemplateObservation absent{};
    absent.base = observed_naval(0u);
    absent.base.naval_present = false;
    absent.template_present = false;
    const auto absent_result = wire::encode(absent, output.data(), output.size());
    require(absent_result.succeeded(), "absent template frame encodes");
    require(absent_result.written_bytes == wire::encoded_size(absent),
            "absent encoded_size matches encode");
    print_wire("absent", output, absent_result.written_bytes);

    wire::TemplateObservation populated{};
    populated.base = observed_naval(3u);
    populated.template_present = true;
    fill_message(populated.message);
    const auto populated_result = wire::encode(
        populated, output.data(), output.size());
    require(populated_result.succeeded(), "template frame encodes");
    require(populated_result.written_bytes == wire::encoded_size(populated),
            "template encoded_size matches encode");
    print_wire("template", output, populated_result.written_bytes);

    wire::TemplateObservation boundary = populated;
    fill_length_boundary_message(boundary.message);
    const auto boundary_result = wire::encode(
        boundary, output.data(), output.size());
    require(boundary_result.succeeded(), "length boundary frame encodes");
    print_wire("boundary", output, boundary_result.written_bytes);

    wire::TemplateObservation maximum = populated;
    fill_boundary_message(maximum.message, owned_template::kMaxPairs);
    const auto maximum_result = wire::encode(
        maximum, output.data(), output.size());
    require(maximum_result.succeeded(), "pair boundary frame encodes");
    print_wire("maximum", output, maximum_result.written_bytes);

    wire::TemplateObservation container{};
    container.base = observed_naval(2u);
    container.template_present = true;
    container.template_source_kind = wire::kFormatterContainerSource;
    fill_formatter_container(container.message);
    const auto container_result = wire::encode(
        container, output.data(), output.size());
    require(container_result.succeeded(), "formatter container frame encodes");
    require(container_result.written_bytes == wire::encoded_size(container),
            "formatter container encoded_size matches encode");
    print_wire("container", output, container_result.written_bytes);
    std::cout << "CHECK native_encode_cases PASS\n";
}

void test_rejections_and_atomic_output() {
    wire::TemplateObservation valid = [] {
        wire::TemplateObservation value{};
        value.base = observed_naval(1u);
        value.template_present = true;
        fill_message(value.message);
        return value;
    }();
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    output.fill(0xa5u);

    wire::TemplateObservation invalid = valid;
    invalid.message.pair_count = static_cast<std::uint32_t>(
        owned_template::kMaxPairs + 1u);
    require(wire::encoded_size(invalid) == 0u,
            "pair count over bound rejected");
    require(!wire::encode(invalid, output.data(), output.size()).succeeded(),
            "invalid snapshot does not encode");
    for (const auto byte : output) {
        require(byte == 0xa5u, "invalid encode leaves output untouched");
    }

    wire::TemplateObservation arena_overflow = valid;
    fill_length_boundary_message(arena_overflow.message);
    arena_overflow.message.pair_count = 8u;
    for (std::size_t index = 1u; index < arena_overflow.message.pair_count;
         ++index) {
        arena_overflow.message.pairs[index] = arena_overflow.message.pairs[0];
    }
    require(wire::encoded_size(arena_overflow) == 0u,
            "serialized snapshot arena over bound rejected");
    require(!wire::encode(arena_overflow, output.data(), output.size()).succeeded(),
            "arena overflow does not encode");
    for (const auto byte : output) {
        require(byte == 0xa5u, "arena overflow leaves output untouched");
    }

    output.fill(0x5au);
    const std::size_t required = wire::encoded_size(valid);
    require(required > 0u, "valid frame reports required size");
    require(!wire::encode(valid, output.data(), required - 1u).succeeded(),
            "short output rejects");
    for (const auto byte : output) {
        require(byte == 0x5au, "short output leaves destination untouched");
    }

    output.fill(0x3cu);
    require(!wire::encode(valid,
                          reinterpret_cast<unsigned char*>(&valid),
                          required).succeeded(),
            "input output overlap rejects");
    for (const auto byte : output) {
        require(byte == 0x3cu, "overlap check leaves separate output untouched");
    }

    wire::TemplateObservation container = valid;
    container.template_source_kind = wire::kFormatterContainerSource;
    fill_formatter_container(container.message);
    require(wire::encoded_size(container) > 0u,
            "formatter container valid snapshot encodes");
    container.message.native_date = 1;
    require(wire::encoded_size(container) == 0u,
            "formatter container rejects message date");
    fill_formatter_container(container.message);
    container.message.raw_flag_8c = 1u;
    require(wire::encoded_size(container) == 0u,
            "formatter container rejects message flags");
    fill_formatter_container(container.message);
    container.message.arena[0] = 0x7fu;
    container.message.auxiliary_text = owned_template::TextRange{0u, 1u};
    require(wire::encoded_size(container) == 0u,
            "formatter container rejects auxiliary text");
    fill_formatter_container(container.message);
    container.template_source_kind = 3u;
    require(wire::encoded_size(container) == 0u,
            "unknown template source kind rejected");
    std::cout << "CHECK atomic_rejections PASS\n";
}

}  // namespace

int main() {
    test_encode_cases();
    test_rejections_and_atomic_output();
    std::cout << "RESULT native_template_wire PASS\n";
    return 0;
}
