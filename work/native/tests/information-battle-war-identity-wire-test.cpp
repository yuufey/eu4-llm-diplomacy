#include "../information-battle-war-identity-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace {

namespace wire = information::battle::war_identity_wire;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

std::uint64_t full_ref(const char* tag, unsigned marker) {
    require(tag != nullptr && std::strlen(tag) == 3u,
            "full-ref tag has three bytes");
    return static_cast<std::uint64_t>(static_cast<unsigned char>(tag[0]))
        | (static_cast<std::uint64_t>(static_cast<unsigned char>(tag[1])) << 8u)
        | (static_cast<std::uint64_t>(static_cast<unsigned char>(tag[2])) << 16u)
        | (static_cast<std::uint64_t>(marker & 0xffu) << 24u)
        | (UINT64_C(1) << 32u);
}

wire::WarIdentityObservation base_observation() {
    wire::WarIdentityObservation value{};
    auto& inner = value.base.base.base.inner;
    inner.sequence = UINT64_C(0x1122334455667788);
    inner.thread = UINT32_C(0x12345678);
    inner.known_router = true;
    inner.result.raw_date = -1455113;
    return value;
}

void fill_bound_id(wire::Identity& identity) {
    const char prefix[] = "war_0123456789abcdef_01234567";
    require(std::strlen(prefix) == wire::kMaxWarIdBytes,
            "bound ID has 29 bytes");
    std::memcpy(identity.war_id.data(), prefix, wire::kMaxWarIdBytes);
    identity.war_id[wire::kMaxWarIdBytes] = '\0';
}

void test_bound_and_absent() {
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    auto value = base_observation();
    value.identity.status = wire::kStatusBound;
    value.identity.binding_flags = wire::kBindingFlags;
    value.identity.process_creation_filetime = UINT64_C(132456789);
    value.identity.raw_date = value.base.base.base.inner.result.raw_date;
    value.identity.pair_full_refs = {{full_ref("FRA", 1u), full_ref("ORL", 2u)}};
    fill_bound_id(value.identity);

    const auto encoded = wire::encode(value, output.data(), output.size());
    require(encoded.succeeded(), "bound identity encodes");
    require(encoded.written_bytes == wire::encoded_size(value),
            "encoded size matches bound frame");
    require(output[0] == 'I' && output[1] == 'B'
                && output[2] == 'O' && output[3] == 'W'
                && output[4] == 5u && output[5] == 0u,
            "v5 header is canonical");
    const std::size_t base_bytes = static_cast<std::size_t>(output[6])
        | (static_cast<std::size_t>(output[7]) << 8u)
        | (static_cast<std::size_t>(output[8]) << 16u)
        | (static_cast<std::size_t>(output[9]) << 24u);
    const std::size_t extension = 10u + base_bytes;
    require(output[extension] == 'W' && output[extension + 1u] == 'A'
                && output[extension + 2u] == 'R'
                && output[extension + 3u] == 'I',
            "WARI marker follows complete v4 base");
    require(output[extension + 4u] == wire::kStatusBound,
            "bound status is serialized");
    require(output[extension + 4u + wire::kIdentityFixedBytes - 1u]
                == wire::kMaxWarIdBytes,
            "bound ID length is 29");

    auto absent = base_observation();
    absent.identity.status = wire::kStatusAbsent;
    absent.identity.reason = 2u;
    const auto absent_result = wire::encode(
        absent, output.data(), output.size());
    require(absent_result.succeeded(), "absent identity encodes");
    require(absent_result.written_bytes == wire::encoded_size(absent),
            "encoded size matches absent frame");
}

void test_bound_guards_are_atomic() {
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    output.fill(0xa5u);
    auto value = base_observation();
    value.identity.status = wire::kStatusBound;
    value.identity.binding_flags = wire::kBindingFlags;
    value.identity.process_creation_filetime = 1u;
    value.identity.raw_date = value.base.base.base.inner.result.raw_date;
    value.identity.pair_full_refs = {{full_ref("FRA", 1u), full_ref("ORL", 2u)}};
    fill_bound_id(value.identity);

    value.identity.pair_full_refs[1] = value.identity.pair_full_refs[0];
    require(wire::encoded_size(value) == 0u,
            "duplicate bound pair is rejected by size calculation");
    const auto result = wire::encode(value, output.data(), output.size());
    require(!result.succeeded(), "duplicate bound pair is rejected by encode");
    require(output[0] == 0xa5u && output[wire::kMaxWireBytes - 1u] == 0xa5u,
            "invalid encode does not touch output");

    value.identity.pair_full_refs[1] = full_ref("ORL", 2u);
    value.identity.raw_date += 1;
    require(wire::encoded_size(value) == 0u,
            "date mismatch is rejected");
}

}  // namespace

int main() {
    test_bound_and_absent();
    test_bound_guards_are_atomic();
    std::cout << "RESULT PASS information-battle-war-identity-wire\n";
    return 0;
}
