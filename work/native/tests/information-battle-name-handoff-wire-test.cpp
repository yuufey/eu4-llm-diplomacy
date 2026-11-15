#include "../information-battle-name-handoff-wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>

namespace {

namespace owned = information::battle::owned_name_handoff;
namespace wire = information::battle::name_handoff_wire;

std::size_t g_checks = 0u;

void check(bool condition, const char* label) {
    ++g_checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", label);
        std::exit(1);
    }
}

std::uint16_t u16(const unsigned char* bytes) {
    return static_cast<std::uint16_t>(bytes[0])
        | static_cast<std::uint16_t>(bytes[1] << 8u);
}

std::uint32_t u32(const unsigned char* bytes) {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8u)
        | (static_cast<std::uint32_t>(bytes[2]) << 16u)
        | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

std::uint64_t u64(const unsigned char* bytes) {
    std::uint64_t value = 0u;
    for (unsigned index = 0u; index < 8u; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    }
    return value;
}

void set_u16(unsigned char* bytes, std::uint16_t value) {
    bytes[0] = static_cast<unsigned char>(value & 0xffu);
    bytes[1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
}

void set_u32(unsigned char* bytes, std::uint32_t value) {
    for (unsigned index = 0u; index < 4u; ++index) {
        bytes[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
}

void set_u64(unsigned char* bytes, std::uint64_t value) {
    for (unsigned index = 0u; index < 8u; ++index) {
        bytes[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
}

std::int64_t i32(const unsigned char* bytes) {
    return static_cast<std::int32_t>(u32(bytes));
}

std::vector<unsigned char> read_file(const char* path) {
    std::ifstream stream(path, std::ios::binary);
    check(stream.good(), "base v7 fixture opens");
    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());
    check(!bytes.empty(), "base v7 fixture is nonempty");
    return bytes;
}

owned::Snapshot known_snapshot(const std::vector<unsigned char>& base7) {
    const std::size_t base6_bytes = u32(base7.data() + 6u);
    const std::size_t body = 10u + base6_bytes + 10u;
    owned::Snapshot snapshot{};
    snapshot.state = owned::SnapshotState::known;
    snapshot.sequence = u64(base7.data() + body + 4u);
    snapshot.raw_date = i32(base7.data() + body + 12u);
    snapshot.kind = base7[body + 16u];
    const char value[] = "NAME";
    snapshot.length = 4u;
    std::memcpy(snapshot.bytes.data(), value, snapshot.length);
    snapshot.bytes[snapshot.length] = 0u;
    return snapshot;
}

owned::Snapshot unknown_snapshot() {
    return owned::Snapshot{};
}

std::vector<unsigned char> unknown_display_context(
        const std::vector<unsigned char>& base7) {
    const std::size_t base6_bytes = u32(base7.data() + 6u);
    const std::size_t extension = 10u + base6_bytes;
    const std::size_t body = extension + 10u;
    const std::size_t minimum_body = wire::display_wire::kFixedBodyBytes
        + wire::display_wire::kEntryHeaderBytes
            * wire::display_wire::kEntryCount;
    std::vector<unsigned char> result = base7;
    result.resize(body + minimum_body);
    set_u32(result.data() + extension + 6u,
            static_cast<std::uint32_t>(minimum_body));
    std::fill(result.begin() + body, result.end(), 0u);
    result[body + 26u] = static_cast<unsigned char>(
        wire::display_wire::kEntryCount);
    for (std::size_t index = 0u; index < wire::display_wire::kEntryCount;
         ++index) {
        result[body + wire::display_wire::kFixedBodyBytes
               + index * wire::display_wire::kEntryHeaderBytes]
            = static_cast<unsigned char>(index + 1u);
    }
    set_u16(result.data() + body + 2u, 1u);
    return result;
}

std::vector<unsigned char> encode_ok(const std::vector<unsigned char>& base7,
                                     const owned::Snapshot& snapshot) {
    const std::size_t required = wire::encoded_size(
        base7.data(), base7.size(), snapshot);
    check(required != 0u, "valid snapshot has encoded size");
    std::vector<unsigned char> result(required, 0xa5u);
    const wire::EncodeResult encoded = wire::encode(
        base7.data(), base7.size(), snapshot, result.data(), result.size());
    check(encoded.succeeded() && encoded.written_bytes == required,
          "valid snapshot encodes exactly");
    return result;
}

void verify_frame(const std::vector<unsigned char>& base7,
                  const owned::Snapshot& snapshot,
                  const std::vector<unsigned char>& frame) {
    check(frame.size() <= wire::kMaxWireBytes, "v8 frame respects wire bound");
    check(std::memcmp(frame.data(), "IBOW", 4u) == 0, "outer magic is IBOW");
    check(u16(frame.data() + 4u) == wire::kVersion, "outer version is v8");
    check(u32(frame.data() + 6u) == base7.size(), "base length is exact");
    check(std::memcmp(frame.data() + 10u, base7.data(), base7.size()) == 0,
          "complete v7 base is byte-identical");

    const std::size_t extension = 10u + base7.size();
    check(std::memcmp(frame.data() + extension, "NHND", 4u) == 0,
          "NHND extension marker");
    check(u16(frame.data() + extension + 4u) == wire::kExtensionVersion,
          "NHND extension version");
    const std::size_t body = extension + wire::kExtensionHeaderBytes;
    const std::size_t body_bytes = u32(frame.data() + extension + 6u);
    check(body_bytes == frame.size() - body, "NHND body ends at frame end");
    check(body_bytes == wire::kFixedBodyBytes + snapshot.length,
          "NHND body is fixed header plus value length");
    check(frame[body] == static_cast<unsigned char>(snapshot.state),
          "snapshot state byte");
    check(frame[body + 1u] == static_cast<unsigned char>(snapshot.kind),
          "snapshot kind byte");
    check(u16(frame.data() + body + 2u) == 0u, "reserved field is zero");
    check(u64(frame.data() + body + 4u) == snapshot.sequence,
          "sequence u64 is preserved");
    check(i32(frame.data() + body + 12u) == snapshot.raw_date,
          "date low i32 is preserved");
    check(u32(frame.data() + body + 20u) == snapshot.length,
          "value length is exact");
    if (snapshot.length != 0u) {
        check(std::memcmp(frame.data() + body + wire::kFixedBodyBytes,
                          snapshot.bytes.data(), snapshot.length) == 0,
              "value bytes are preserved");
    }
}

void test_known_unknown_and_limits(const std::vector<unsigned char>& base7) {
    const auto known = known_snapshot(base7);
    check(wire::validate(base7.data(), base7.size(), known),
          "known snapshot validates against embedded identity");
    const auto known_frame = encode_ok(base7, known);
    verify_frame(base7, known, known_frame);

    const auto unknown = unknown_snapshot();
    check(wire::validate(base7.data(), base7.size(), unknown),
          "canonical unknown snapshot validates");
    const auto unknown_frame = encode_ok(base7, unknown);
    verify_frame(base7, unknown, unknown_frame);

    auto maximum = known;
    maximum.length = static_cast<std::uint32_t>(owned::kMaxValueBytes);
    maximum.bytes.fill(static_cast<unsigned char>('x'));
    maximum.bytes[maximum.length] = 0u;
    check(wire::validate(base7.data(), base7.size(), maximum),
          "exact 8192-byte value validates");
    check(wire::encoded_size(base7.data(), base7.size(), maximum) != 0u,
          "exact 8192-byte value has encoded size");
}

void test_rejection_without_write(const std::vector<unsigned char>& base7) {
    const auto known = known_snapshot(base7);
    auto bad_identity = known;
    ++bad_identity.sequence;
    check(!wire::validate(base7.data(), base7.size(), bad_identity),
          "known identity mismatch rejects");

    auto bad_date = known;
    bad_date.raw_date = -1;
    check(!wire::validate(base7.data(), base7.size(), bad_date),
          "negative date rejects");

    auto bad_length = known;
    bad_length.length = static_cast<std::uint32_t>(owned::kMaxValueBytes + 1u);
    check(!wire::validate(base7.data(), base7.size(), bad_length),
          "value beyond 8192 bytes rejects");

    auto bad_unknown = unknown_snapshot();
    bad_unknown.sequence = 1u;
    check(!wire::validate(base7.data(), base7.size(), bad_unknown),
          "unknown snapshot with identity rejects");

    const std::size_t required = wire::encoded_size(
        base7.data(), base7.size(), known);
    std::vector<unsigned char> output(required, 0x5au);
    const auto before = output;
    check(!wire::encode(base7.data(), base7.size(), known, output.data(),
                        required - 1u).succeeded()
              && output == before,
          "short output rejects without partial write");

    auto base_copy = base7;
    const auto base_before = base_copy;
    check(!wire::encode(base_copy.data(), base_copy.size(), known,
                        base_copy.data(), base_copy.size()).succeeded()
              && base_copy == base_before,
          "base/output alias rejects without write");

    auto snapshot_copy = known;
    std::array<unsigned char, sizeof(snapshot_copy)> snapshot_before{};
    std::memcpy(snapshot_before.data(), &snapshot_copy, sizeof(snapshot_copy));
    check(!wire::encode(base7.data(), base7.size(), snapshot_copy,
                        reinterpret_cast<unsigned char*>(&snapshot_copy),
                        sizeof(snapshot_copy)).succeeded()
              && std::memcmp(snapshot_before.data(), &snapshot_copy,
                             sizeof(snapshot_copy)) == 0,
          "snapshot/output alias rejects without write");
}

void test_nested_identity_binding(const std::vector<unsigned char>& base7) {
    const auto known = known_snapshot(base7);
    const auto unknown_dctx = unknown_display_context(base7);
    check(wire::validate(unknown_dctx.data(), unknown_dctx.size(), known),
          "known NAME binds to nested observation when DCTX is unknown");
    const auto frame = encode_ok(unknown_dctx, known);
    verify_frame(unknown_dctx, known, frame);

    auto wrong_dctx = base7;
    const std::size_t base6_bytes = u32(wrong_dctx.data() + 6u);
    const std::size_t body = 10u + base6_bytes + 10u;
    set_u64(wrong_dctx.data() + body + 4u, known.sequence + 1u);
    check(!wire::validate(wrong_dctx.data(), wrong_dctx.size(), known),
          "DCTX identity mismatch with nested observation rejects");
    check(wire::encoded_size(wrong_dctx.data(), wrong_dctx.size(), known) == 0u,
          "mismatched v7 base has no encoded size");
}

}  // namespace

int main(int argc, char** argv) {
    check(argc == 3 && std::strcmp(argv[1], "--base7") == 0,
          "test receives strict-valid v7 fixture path");
    const auto base7 = read_file(argv[2]);
    check(wire::validate(base7.data(), base7.size(), known_snapshot(base7)),
          "external base7 fixture passes v8 base guard");
    test_known_unknown_and_limits(base7);
    test_nested_identity_binding(base7);
    test_rejection_without_write(base7);
    std::printf("CHECK_COUNT=%zu\n", g_checks);
    return 0;
}
