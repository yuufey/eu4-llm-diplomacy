#include "../information-battle-native-text-wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

namespace wire = information::battle::native_text_wire;
namespace owned = information::battle::owned_native_text;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

void put_u16(std::vector<unsigned char>& bytes, std::size_t offset,
             std::uint16_t value) {
    bytes[offset] = static_cast<unsigned char>(value & 0xffu);
    bytes[offset + 1u] = static_cast<unsigned char>((value >> 8u) & 0xffu);
}

void put_u32(std::vector<unsigned char>& bytes, std::size_t offset,
             std::uint32_t value) {
    for (unsigned index = 0u; index < 4u; ++index) {
        bytes[offset + index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
}

std::vector<unsigned char> base_v5() {
    // A bounded structural v5 envelope is sufficient here: the native v6
    // layer treats the v5 frame as opaque and preserves every byte.  Python
    // tests additionally wrap an archived v4 payload for decoder coverage.
    constexpr std::size_t base_v4_bytes = 10u;
    constexpr std::size_t total = 10u + base_v4_bytes + 4u + 35u;
    std::vector<unsigned char> result(total, 0u);
    std::memcpy(result.data(), "IBOW", 4u);
    put_u16(result, 4u, 5u);
    put_u32(result, 6u, static_cast<std::uint32_t>(base_v4_bytes));
    std::memcpy(result.data() + 10u, "IBOW", 4u);
    put_u16(result, 14u, 4u);
    std::memcpy(result.data() + 20u, "WARI", 4u);
    result[20u + 4u] = 0u;  // absent WARI status
    result[20u + 4u + 34u] = 0u;
    return result;
}

void put_range(owned::Snapshot& snapshot, owned::TextRange& range,
               const unsigned char* data, std::size_t length,
               std::size_t& cursor) {
    require(cursor <= owned::kMaxArenaBytes
                && length <= owned::kMaxArenaBytes - cursor,
            "snapshot arena range");
    range.offset = static_cast<std::uint32_t>(cursor);
    range.length = static_cast<std::uint32_t>(length);
    if (length != 0u) {
        std::memcpy(snapshot.arena.data() + cursor, data, length);
    }
    cursor += length;
}

owned::Snapshot observed_snapshot() {
    owned::Snapshot result{};
    result.definition_key.source_kind = owned::SourceKind::message_metadata;
    result.auxiliary_text.source_kind = owned::SourceKind::message_metadata;
    result.title_helper_candidate.source_kind =
        owned::SourceKind::title_helper_candidate;
    result.native_line1.source_kind = owned::SourceKind::native_line1;
    result.native_date_state = owned::FieldState::observed;
    result.native_date = -1455113;
    result.raw_flags_state = owned::FieldState::observed;
    result.raw_flag_8c = 0xa1u;
    result.raw_flag_8d = 0x5eu;
    std::size_t cursor = 0u;

    result.definition_key.state = owned::FieldState::observed;
    const unsigned char definition[] = {'b', 'a', 't', 't', 'l', 'e'};
    put_range(result, result.definition_key.bytes, definition,
              sizeof(definition), cursor);

    result.auxiliary_text.state = owned::FieldState::observed;
    put_range(result, result.auxiliary_text.bytes, nullptr, 0u, cursor);

    result.title_helper_candidate.state = owned::FieldState::observed;
    const unsigned char non_utf8[] = {0xffu, 0x80u, 0x01u};
    put_range(result, result.title_helper_candidate.bytes, non_utf8,
              sizeof(non_utf8), cursor);

    result.native_line1.state = owned::FieldState::observed;
    const unsigned char line1[] = {'L', 'i', 'n', 'e', '1'};
    put_range(result, result.native_line1.bytes, line1, sizeof(line1), cursor);
    return result;
}

owned::Snapshot absent_snapshot() {
    owned::Snapshot result{};
    result.definition_key.source_kind = owned::SourceKind::message_metadata;
    result.auxiliary_text.source_kind = owned::SourceKind::message_metadata;
    result.title_helper_candidate.source_kind =
        owned::SourceKind::title_helper_candidate;
    result.native_line1.source_kind = owned::SourceKind::native_line1;
    result.definition_key.state = owned::FieldState::absent;
    result.auxiliary_text.state = owned::FieldState::absent;
    result.title_helper_candidate.state = owned::FieldState::unknown;
    result.native_line1.state = owned::FieldState::absent;
    result.native_date_state = owned::FieldState::absent;
    result.raw_flags_state = owned::FieldState::absent;
    return result;
}

owned::Snapshot empty_snapshot() {
    owned::Snapshot result = observed_snapshot();
    result.definition_key.bytes = {};
    result.auxiliary_text.bytes = {};
    result.title_helper_candidate.bytes = {};
    result.native_line1.bytes = {};
    return result;
}

std::string hex(const unsigned char* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2u);
    for (std::size_t index = 0u; index < size; ++index) {
        result.push_back(digits[data[index] >> 4u]);
        result.push_back(digits[data[index] & 0x0fu]);
    }
    return result;
}

std::vector<unsigned char> encode(const std::vector<unsigned char>& base,
                                  const owned::Snapshot& snapshot) {
    const std::size_t size = wire::encoded_size(base.data(), base.size(),
                                                snapshot);
    require(size != 0u, "fixture has an encoded size");
    std::vector<unsigned char> output(size, 0xa5u);
    const auto result = wire::encode(base.data(), base.size(), snapshot,
                                     output.data(), output.size());
    require(result.succeeded() && result.written_bytes == size,
            "fixture encodes exactly once");
    require(wire::validate(output.data(), output.size()),
            "fixture validates after encoding");
    require(std::equal(base.begin(), base.end(), output.begin() + 10u),
            "embedded v5 bytes remain unchanged");
    return output;
}

void test_present_empty_and_raw_bytes() {
    const auto base = base_v5();
    const auto observed = encode(base, observed_snapshot());
    const auto empty = encode(base, empty_snapshot());
    const auto absent = encode(base, absent_snapshot());
    require(observed != empty && empty != absent,
            "presence variants have distinct wire bytes");
    const std::size_t extension = 10u + base.size();
    require(observed[0] == 'I' && observed[1] == 'B'
                && observed[4] == 6u && observed[5] == 0u,
            "v6 header is canonical");
    require(std::memcmp(observed.data() + extension, "NTXT", 4u) == 0,
            "NTXT follows complete v5 base");
    require(observed[extension + 4u] == 1u
                && observed[extension + 5u] == 0u,
            "NTXT version is canonical");
    std::cout << "WIRE observed " << hex(observed.data(), observed.size())
              << '\n';
    std::cout << "WIRE empty " << hex(empty.data(), empty.size()) << '\n';
    std::cout << "WIRE absent " << hex(absent.data(), absent.size()) << '\n';
}

void test_guards_and_aliases() {
    const auto base = base_v5();
    auto snapshot = observed_snapshot();
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    output.fill(0xa5u);
    require(wire::encoded_size(base.data(), base.size(), snapshot) != 0u,
            "valid size remains available");

    snapshot.title_helper_candidate.source_kind =
        owned::SourceKind::message_metadata;
    require(wire::encoded_size(base.data(), base.size(), snapshot) == 0u,
            "source mismatch is rejected");
    snapshot = observed_snapshot();
    snapshot.native_line1.bytes.offset =
        static_cast<std::uint32_t>(owned::kMaxArenaBytes);
    snapshot.native_line1.bytes.length = 1u;
    require(wire::encoded_size(base.data(), base.size(), snapshot) == 0u,
            "out of bound range is rejected");

    snapshot = observed_snapshot();
    auto malformed_base = base;
    malformed_base[0] = 'X';
    require(wire::encoded_size(malformed_base.data(), malformed_base.size(),
                               snapshot) == 0u,
            "malformed base is rejected");

    auto valid = encode(base, snapshot);
    const std::size_t extension = 10u + base.size();
    valid[extension + 4u] = 2u;
    require(!wire::validate(valid.data(), valid.size()),
            "extension version mismatch is rejected");
    valid = encode(base, snapshot);
    valid[extension + 10u] = 1u;
    require(!wire::validate(valid.data(), valid.size()),
            "reserved flags are rejected");
    valid = encode(base, snapshot);
    valid.push_back(0u);
    require(!wire::validate(valid.data(), valid.size()),
            "trailing bytes are rejected");

    std::vector<unsigned char> alias(wire::kMaxWireBytes, 0u);
    std::copy(base.begin(), base.end(), alias.begin());
    const auto alias_result = wire::encode(alias.data(), base.size(), snapshot,
                                           alias.data(), alias.size());
    require(!alias_result.succeeded(), "output/base alias is rejected");
    require(output.front() == 0xa5u && output.back() == 0xa5u,
            "invalid cases do not touch unrelated output");
}

}  // namespace

int main() {
    test_present_empty_and_raw_bytes();
    test_guards_and_aliases();
    std::cout << "RESULT PASS information-battle-native-text-wire\n";
    return 0;
}
