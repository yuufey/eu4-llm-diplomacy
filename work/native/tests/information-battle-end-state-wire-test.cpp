#include "../information-battle-end-state-wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

namespace {

namespace wire = information::battle::end_state_wire;
namespace name_wire = information::battle::name_handoff_wire;
namespace display_wire = information::battle::display_context_wire;
namespace display = information::battle::display_context;
namespace owned_name = information::battle::owned_name_handoff;

std::size_t g_checks = 0u;

void check(bool condition, const char* label) {
    ++g_checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", label);
        std::exit(1);
    }
}

std::uint16_t get_u16(const unsigned char* bytes) {
    return static_cast<std::uint16_t>(bytes[0])
        | static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8u);
}

std::uint32_t get_u32(const unsigned char* bytes) {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8u)
        | (static_cast<std::uint32_t>(bytes[2]) << 16u)
        | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

std::uint64_t get_u64(const unsigned char* bytes) {
    std::uint64_t value = 0u;
    for (unsigned index = 0u; index < 8u; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    }
    return value;
}

std::int32_t get_i32(const unsigned char* bytes) {
    const std::uint32_t value = get_u32(bytes);
    std::int32_t result = 0;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

std::vector<unsigned char> read_file(const char* path) {
    std::ifstream stream(path, std::ios::binary);
    check(stream.good(), "base6 fixture opens");
    std::vector<unsigned char> result(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());
    check(!result.empty(), "base6 fixture is nonempty");
    return result;
}

void write_file(const char* path, const std::vector<unsigned char>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    check(stream.good(), "cross-language output opens");
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    check(stream.good(), "cross-language output writes completely");
}

std::vector<unsigned char> make_base7(const std::vector<unsigned char>& base6) {
    const display::Snapshot snapshot{}; // canonical unknown DCTX
    const std::size_t bytes = display_wire::encoded_size(
        base6.data(), base6.size(), snapshot);
    check(bytes != 0u, "valid base6 has v7 encoded size");
    std::vector<unsigned char> result(bytes, 0xa5u);
    const auto encoded = display_wire::encode(
        base6.data(), base6.size(), snapshot, result.data(), result.size());
    check(encoded.succeeded() && encoded.written_bytes == bytes,
          "v7 base encodes");
    return result;
}

std::vector<unsigned char> make_base8(const std::vector<unsigned char>& base7) {
    const owned_name::Snapshot snapshot{}; // canonical unknown NHND
    const std::size_t bytes = name_wire::encoded_size(
        base7.data(), base7.size(), snapshot);
    check(bytes != 0u, "valid base7 has v8 encoded size");
    std::vector<unsigned char> result(bytes, 0xa5u);
    const auto encoded = name_wire::encode(
        base7.data(), base7.size(), snapshot, result.data(), result.size());
    check(encoded.succeeded() && encoded.written_bytes == bytes,
          "v8 base encodes");
    return result;
}

wire::Snapshot known_snapshot(const std::vector<unsigned char>& base6,
                              const std::array<std::uint8_t, 2u>& gates) {
    name_wire::detail::BaseIdentity identity{};
    check(name_wire::detail::nested_base_identity(
              base6.data(), base6.size(), identity),
          "base6 identity resolves");
    wire::Snapshot snapshot{};
    snapshot.sequence = identity.sequence;
    snapshot.raw_date = identity.raw_date;
    snapshot.kind = identity.kind;
    snapshot.present = true;
    snapshot.raw_gates = gates;
    return snapshot;
}

std::vector<unsigned char> encode_ok(const std::vector<unsigned char>& base,
                                    const wire::Snapshot& snapshot) {
    const std::size_t required = wire::encoded_size(
        base.data(), base.size(), snapshot);
    check(required != 0u, "valid end-state snapshot has encoded size");
    std::vector<unsigned char> output(required, 0xa5u);
    const auto encoded = wire::encode(base.data(), base.size(), snapshot,
                                      output.data(), output.size());
    check(encoded.succeeded() && encoded.written_bytes == required,
          "valid end-state frame encodes exactly");
    return output;
}

void verify_known(const std::vector<unsigned char>& base,
                  const wire::Snapshot& snapshot,
                  const std::vector<unsigned char>& frame,
                  std::uint16_t base_version) {
    check(frame.size() <= wire::kMaxWireBytes, "v9 respects shared wire bound");
    check(std::memcmp(frame.data(), "IBOW", 4u) == 0, "outer magic is IBOW");
    check(get_u16(frame.data() + 4u) == 9u, "outer version is v9");
    check(get_u32(frame.data() + 6u) == base.size(), "base length is exact");
    check(std::memcmp(frame.data() + wire::kOuterHeaderBytes,
                      base.data(), base.size()) == 0,
          "complete base is byte-identical");
    check(get_u16(frame.data() + wire::kOuterHeaderBytes + 4u) == base_version,
          "embedded base remains the requested v7/v8 version");

    const std::size_t extension = wire::kOuterHeaderBytes + base.size();
    check(std::memcmp(frame.data() + extension, "EOST", 4u) == 0,
          "EOST extension marker");
    check(get_u16(frame.data() + extension + 4u) == 1u,
          "EOST extension version is one");
    check(get_u32(frame.data() + extension + 6u) == wire::kBodyBytes,
          "EOST body length is 16");
    const unsigned char* body = frame.data() + extension
        + wire::kExtensionHeaderBytes;
    check(get_u64(body) == snapshot.sequence, "sequence is exact");
    check(get_i32(body + 8u) == snapshot.raw_date, "raw date i32 is exact");
    check(body[12u] == snapshot.kind, "kind byte is exact");
    check(body[13u] == 1u, "present state byte is one");
    check(body[14u] == snapshot.raw_gates[0]
              && body[15u] == snapshot.raw_gates[1],
          "raw gate bytes are not booleanized");
}

void test_v7_v8_roundtrip(const std::vector<unsigned char>& base6) {
    const auto base7 = make_base7(base6);
    const auto base8 = make_base8(base7);
    const auto snapshot = known_snapshot(base6, {{0u, 255u}});
    check(wire::validate(base7.data(), base7.size(), snapshot),
          "known identity validates against v7 base");
    check(wire::validate(base8.data(), base8.size(), snapshot),
          "known identity validates against v8 base");
    verify_known(base7, snapshot, encode_ok(base7, snapshot), 7u);
    verify_known(base8, snapshot, encode_ok(base8, snapshot), 8u);
}

void test_unknown_normalization_and_output_unchanged(
        const std::vector<unsigned char>& base6,
        const std::vector<unsigned char>& base7,
        const std::vector<unsigned char>& base8) {
    wire::Snapshot unknown{};
    unknown.sequence = 999u;
    unknown.raw_date = 777;
    unknown.kind = 2u;
    unknown.present = false;
    unknown.raw_gates = {{17u, 255u}};
    const auto frame = encode_ok(base7, unknown);
    const std::size_t body = wire::kOuterHeaderBytes + base7.size()
        + wire::kExtensionHeaderBytes;
    check(std::all_of(frame.begin() + static_cast<std::ptrdiff_t>(body),
                      frame.begin() + static_cast<std::ptrdiff_t>(body + wire::kBodyBytes),
                      [](unsigned char value) { return value == 0u; }),
          "unknown snapshot normalizes identity and gates to zero");
    const auto frame8 = encode_ok(base8, unknown);
    const std::size_t body8 = wire::kOuterHeaderBytes + base8.size()
        + wire::kExtensionHeaderBytes;
    check(std::all_of(frame8.begin() + static_cast<std::ptrdiff_t>(body8),
                      frame8.begin() + static_cast<std::ptrdiff_t>(body8 + wire::kBodyBytes),
                      [](unsigned char value) { return value == 0u; }),
          "unknown v8-base snapshot normalizes identity and gates to zero");

    auto mismatch = known_snapshot(base6, {{1u, 2u}});
    ++mismatch.sequence;
    const auto matching = known_snapshot(base6, {{1u, 2u}});
    const std::size_t required = wire::encoded_size(base7.data(), base7.size(), matching);
    std::vector<unsigned char> unchanged(required, 0x5au);
    const auto before = unchanged;
    check(!wire::encode(base7.data(), base7.size(), mismatch, unchanged.data(),
                        unchanged.size()).succeeded()
              && unchanged == before,
          "identity mismatch rejects without modifying output");
}

void test_invalid_bases_capacity_and_aliases(
        const std::vector<unsigned char>& base7) {
    wire::Snapshot unknown{};
    check(wire::encoded_size(nullptr, base7.size(), unknown) == 0u,
          "null base rejects");
    check(wire::encoded_size(base7.data(), base7.size(), unknown) != 0u,
          "v7 base is accepted");
    std::vector<unsigned char> output(
        wire::encoded_size(base7.data(), base7.size(), unknown), 0x5au);
    const auto before = output;
    check(!wire::encode(base7.data(), base7.size(), unknown, output.data(),
                        output.size() - 1u).succeeded()
              && output == before,
          "short capacity rejects without partial write");
    auto base_copy = base7;
    const auto base_before = base_copy;
    check(!wire::encode(base_copy.data(), base_copy.size(), unknown,
                        base_copy.data(), base_copy.size()).succeeded()
              && base_copy == base_before,
          "base/output alias rejects without write");

    const auto frame = encode_ok(base7, unknown);
    const std::size_t frame_bytes = frame.size();
    check(wire::encoded_size(frame.data(), frame_bytes, unknown) == 0u,
          "recursive v9 base rejects");
}

}  // namespace

int main(int argc, char** argv) {
    check((argc == 3 || argc == 7)
              && std::strcmp(argv[1], "--base6") == 0
              && (argc == 3
                  || (std::strcmp(argv[3], "--emit-v7") == 0
                      && std::strcmp(argv[5], "--emit-v8") == 0)),
          "test receives a strict-valid v6 fixture and optional output paths");
    const auto base6 = read_file(argv[2]);
    check(display_wire::native_text::validate(base6.data(), base6.size()),
          "base6 fixture passes original v6 validator");
    const auto base7 = make_base7(base6);
    const auto base8 = make_base8(base7);
    test_v7_v8_roundtrip(base6);
    test_unknown_normalization_and_output_unchanged(base6, base7, base8);
    test_invalid_bases_capacity_and_aliases(base7);
    if (argc == 7) {
        const auto snapshot = known_snapshot(base6, {{0u, 255u}});
        write_file(argv[4], encode_ok(base7, snapshot));
        write_file(argv[6], encode_ok(base8, snapshot));
    }
    std::printf("CHECK_COUNT=%zu\n", g_checks);
    return 0;
}
