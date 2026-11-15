#include "../information-battle-name-sources-wire.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

namespace wire = information::battle::name_sources_wire;
namespace retreat = information::battle::retreat_wire;
static unsigned checks = 0;
static void check(bool ok, const char* name) {
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL:%s\n", name); std::exit(1); }
}
static void put(wire::Text& text, wire::State state, const char* value, std::size_t n) {
    text = wire::Text{};
    text.state = state; text.length = static_cast<std::uint32_t>(n);
    if (n) std::memcpy(text.bytes.data(), value, n);
}
static void put_u16(std::vector<unsigned char>& data, std::size_t offset,
                    std::uint16_t value) {
    data[offset] = static_cast<unsigned char>(value & 0xffu);
    data[offset + 1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
}
static void put_u32(std::vector<unsigned char>& data, std::size_t offset,
                    std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        data[offset + i] = static_cast<unsigned char>((value >> (i * 8u)) & 0xffu);
}
static std::vector<unsigned char> encode_v10(
        const std::vector<unsigned char>& base9,
        const retreat::detail::BaseIdentity& id, bool present,
        std::uint8_t capture_source) {
    retreat::Snapshot snapshot{};
    snapshot.sequence = id.sequence;
    snapshot.raw_date = id.raw_date;
    snapshot.kind = id.kind;
    snapshot.present = present;
    snapshot.capture_source = capture_source;
    if (present) {
        snapshot.combat_side_index = 1;
        snapshot.initial_unit_count = 1;
        snapshot.observed_count = 1;
        snapshot.units[0] = {0, UINT64_C(0x0102030405060708), {{0, 1, 1, 1}}};
    }
    const auto required = retreat::encoded_size(base9.data(), base9.size(), snapshot);
    check(required != 0, "real RETR v10 encoder computes a bounded size");
    std::vector<unsigned char> output(required, 0xa5);
    const auto result = retreat::encode(base9.data(), base9.size(), snapshot,
                                        output.data(), output.size());
    check(result.succeeded() && result.written_bytes == required,
          "real RETR v10 encoder writes the complete frame");
    return output;
}
static std::size_t v10_extension_offset(const std::vector<unsigned char>& base) {
    return wire::kOuterHeaderBytes + wire::bytes::get_u32(base.data() + 6u);
}
static void write(const char* path, const std::vector<unsigned char>& data) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    check(out.good(), "complete cross-language fixture output");
}
int main(int argc, char** argv) {
    check(argc == 4, "base, known, and unknown fixture paths");
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<unsigned char> fixture_v10((std::istreambuf_iterator<char>(input)), {});
    wire::detail::BaseIdentity fixture_identity{};
    check(wire::detail::base_identity(fixture_v10.data(), fixture_v10.size(), fixture_identity),
          "complete retained v10 fixture validates");
    check(wire::bytes::get_u16(fixture_v10.data() + 4u) == retreat::kVersion,
          "retained fixture is wire v10");
    const auto base9_bytes = wire::bytes::get_u32(fixture_v10.data() + 6u);
    check(base9_bytes <= fixture_v10.size() - wire::kOuterHeaderBytes,
          "retained fixture embeds a bounded v9 frame");
    std::vector<unsigned char> base9(
        fixture_v10.begin() + static_cast<std::ptrdiff_t>(wire::kOuterHeaderBytes),
        fixture_v10.begin() + static_cast<std::ptrdiff_t>(wire::kOuterHeaderBytes + base9_bytes));
    retreat::detail::BaseIdentity id{};
    check(retreat::detail::base_identity(base9.data(), base9.size(), id),
          "embedded v9 frame validates for the native RETR encoder");

    const auto regular_v10 = encode_v10(base9, id, true, retreat::kCaptureSourceRegular);
    auto unit_removal_v10 = encode_v10(
        base9, id, true, retreat::kCaptureSourceUnitRemovalState);
    const auto absent_v10 = encode_v10(base9, id, false, retreat::kCaptureSourceRegular);
    check(wire::detail::base_identity(regular_v10.data(), regular_v10.size(), fixture_identity),
          "RETR v1 with marker zero remains a valid name-source base");
    check(wire::bytes::get_u16(regular_v10.data() + v10_extension_offset(regular_v10) + 4u)
              == retreat::kExtensionVersion
          && regular_v10[v10_extension_offset(regular_v10) + 10u + 15u] == 0u,
          "real regular retreat encoder emits v1 and marker zero");
    check(wire::detail::base_identity(unit_removal_v10.data(), unit_removal_v10.size(), fixture_identity),
          "RETR v2 with unit-removal marker one is a valid name-source base");
    check(wire::bytes::get_u16(unit_removal_v10.data() + v10_extension_offset(unit_removal_v10) + 4u)
              == retreat::kUnitRemovalExtensionVersion
          && unit_removal_v10[v10_extension_offset(unit_removal_v10) + 10u + 15u] == 1u,
          "real unit-removal encoder emits v2 and marker one");
    check(wire::detail::base_identity(absent_v10.data(), absent_v10.size(), fixture_identity),
          "canonical absent RETR v1 base remains valid");
    check(wire::bytes::get_u16(absent_v10.data() + v10_extension_offset(absent_v10) + 4u)
              == retreat::kExtensionVersion
          && std::all_of(absent_v10.begin() + static_cast<std::ptrdiff_t>(
                             v10_extension_offset(absent_v10) + 10u),
                         absent_v10.end(), [](auto byte) { return byte == 0u; }),
          "absent retreat is canonical v1 with an all-zero body");

    wire::Snapshot known{};
    known.sequence = id.sequence; known.raw_date = id.raw_date; known.kind = id.kind;
    known.raw_failure = 0; known.prefix_failure = 0; known.transform_mode = 1;
    put(known.fields[wire::owner_name], wire::State::known, "Paris", 5);
    put(known.fields[wire::global_name], wire::State::known, "", 0);
    put(known.fields[wire::battle_of_template], wire::State::known, "Battle of ", 10);
    put(known.fields[wire::language], wire::State::known, "l_english", 9);
    const auto sum = known.fields[0].length + known.fields[1].length
        + known.fields[2].length + known.fields[3].length;
    const auto required = wire::encoded_size(unit_removal_v10.data(), unit_removal_v10.size(), known);
    check(required == unit_removal_v10.size() + 20 + 29 + sum, "exact v11 frame size");
    std::vector<unsigned char> output(required, 0xa5);
    auto result = wire::encode(unit_removal_v10.data(), unit_removal_v10.size(),
                               known, output.data(), output.size());
    check(result.succeeded() && result.written_bytes == required, "known frame encodes");
    check(output[4] == 11 && output[5] == 0, "wire11 version");
    check(std::equal(unit_removal_v10.begin(), unit_removal_v10.end(), output.begin() + 10),
          "unit-removal v10 remains byte-identical inside v11");
    check(output[10 + unit_removal_v10.size()] == 'N'
          && output[11 + unit_removal_v10.size()] == 'S', "NSRC extension");
    write(argv[2], output);

    std::vector<unsigned char> regular_output(
        wire::encoded_size(regular_v10.data(), regular_v10.size(), known), 0xa5);
    auto regular_result = wire::encode(regular_v10.data(), regular_v10.size(), known,
                                       regular_output.data(), regular_output.size());
    check(regular_result.succeeded(), "v1 RETR base still encodes as v11");
    std::vector<unsigned char> absent_output(
        wire::encoded_size(absent_v10.data(), absent_v10.size(), known), 0xa5);
    auto absent_result = wire::encode(absent_v10.data(), absent_v10.size(), known,
                                      absent_output.data(), absent_output.size());
    check(absent_result.succeeded(), "canonical absent v1 RETR base encodes as v11");

    auto fails = [&](wire::Snapshot bad, const char* label) {
        std::fill(output.begin(), output.end(), 0xa5);
        check(wire::encoded_size(unit_removal_v10.data(), unit_removal_v10.size(), bad) == 0, label);
        check(!wire::encode(unit_removal_v10.data(), unit_removal_v10.size(), bad,
                            output.data(), output.size()).succeeded(), "invalid snapshot rejected");
        check(std::all_of(output.begin(), output.end(), [](auto b) { return b == 0xa5; }), "failure leaves output untouched");
    };
    auto bad = known; ++bad.sequence; fails(bad, "sequence mismatch");
    bad = known; ++bad.raw_date; fails(bad, "date mismatch");
    bad = known; bad.kind = bad.kind == 1 ? 2 : 1; fails(bad, "kind mismatch");
    bad = known; bad.transform_mode = 3; fails(bad, "transform mode range");
    bad = known; bad.raw_failure = 1; fails(bad, "raw group failure mismatch");
    bad = known; bad.prefix_failure = 1; fails(bad, "prefix group failure mismatch");
    bad = known; bad.fields[0].state = static_cast<wire::State>(3); fails(bad, "invalid state");
    bad = known; put(bad.fields[3], wire::State::known, "English", 7); fails(bad, "language prefix");
    bad = known; bad.fields[0].bytes[1] = 0; fails(bad, "known text NUL");
    bad = known; bad.fields[0].length = static_cast<std::uint32_t>(wire::kMaxTextBytes + 1); fails(bad, "text length bound");
    bad = known; bad.fields[0].bytes[5] = 'x'; fails(bad, "nonzero known tail");
    check(!wire::encode(unit_removal_v10.data(), unit_removal_v10.size(), known,
                        output.data(), required - 1).succeeded(), "short output rejected");
    check(std::all_of(output.begin(), output.end(), [](auto b) { return b == 0xa5; }), "short output untouched");
    const auto base_copy = unit_removal_v10;
    check(!wire::encode(unit_removal_v10.data(), unit_removal_v10.size(), known,
                        unit_removal_v10.data(), required).succeeded(),
          "base/output overlap rejected");
    check(unit_removal_v10 == base_copy, "overlap leaves base unchanged");
    auto extra = unit_removal_v10; extra.push_back(0);
    check(wire::encoded_size(extra.data(), extra.size(), known) == 0, "extra base byte rejected");
    auto truncated = unit_removal_v10; truncated.pop_back();
    check(wire::encoded_size(truncated.data(), truncated.size(), known) == 0, "truncated base rejected");

    auto rejects_base = [&](const std::vector<unsigned char>& bad, const char* label) {
        wire::detail::BaseIdentity ignored{};
        check(!wire::detail::base_identity(bad.data(), bad.size(), ignored), label);
        check(wire::encoded_size(bad.data(), bad.size(), known) == 0,
              "invalid v10 base has zero v11 encoded size");
        std::fill(output.begin(), output.end(), 0xa5);
        check(!wire::encode(bad.data(), bad.size(), known, output.data(), output.size()).succeeded(),
              "invalid v10 base rejected by v11 encoder");
        check(std::all_of(output.begin(), output.end(), [](auto b) { return b == 0xa5; }),
              "invalid v10 base leaves output untouched");
    };
    const auto regular_extension = v10_extension_offset(regular_v10);
    auto v1_marker_one = regular_v10;
    v1_marker_one[regular_extension + 10u + 15u] = 1u;
    rejects_base(v1_marker_one, "RETR v1 rejects unit-removal marker one");
    const auto unit_extension = v10_extension_offset(unit_removal_v10);
    auto v2_marker_zero = unit_removal_v10;
    v2_marker_zero[unit_extension + 10u + 15u] = 0u;
    rejects_base(v2_marker_zero, "RETR v2 rejects regular marker zero");
    auto unknown_version = unit_removal_v10;
    put_u16(unknown_version, unit_extension + 4u, 99u);
    rejects_base(unknown_version, "unknown RETR extension version rejected");
    auto v2_absent = unit_removal_v10;
    const auto v2_body = unit_extension + retreat::kExtensionHeaderBytes;
    v2_absent.resize(v2_body + retreat::kFixedBodyBytes);
    put_u32(v2_absent, unit_extension + 6u,
            static_cast<std::uint32_t>(retreat::kFixedBodyBytes));
    std::fill(v2_absent.begin() + static_cast<std::ptrdiff_t>(v2_body),
              v2_absent.end(), 0u);
    rejects_base(v2_absent, "RETR v2 absent snapshot rejected");
    auto noncanonical_v1_absent = absent_v10;
    noncanonical_v1_absent[v10_extension_offset(absent_v10)
                            + retreat::kExtensionHeaderBytes] = 1u;
    rejects_base(noncanonical_v1_absent,
                 "RETR v1 absent snapshot requires an all-zero body");

    wire::Snapshot unknown{};
    unknown.sequence = id.sequence; unknown.raw_date = id.raw_date; unknown.kind = id.kind;
    const auto unknown_size = wire::encoded_size(unit_removal_v10.data(), unit_removal_v10.size(), unknown);
    check(unknown_size == unit_removal_v10.size() + 20 + 29, "canonical unknown frame size");
    std::vector<unsigned char> blank(unknown_size, 0xa5);
    check(wire::encode(unit_removal_v10.data(), unit_removal_v10.size(), unknown,
                       blank.data(), blank.size()).succeeded(), "unknown frame encodes");
    check(blank[10 + unit_removal_v10.size() + 10 + 13] == 12, "unknown raw failure default");
    check(blank[10 + unit_removal_v10.size() + 10 + 14] == 1, "unknown prefix failure default");
    check(blank[10 + unit_removal_v10.size() + 10 + 16] == 0, "unknown transform default");
    write(argv[3], blank);
    std::printf("{\"checks\":%u,\"status\":\"ok\"}\n", checks);
    return 0;
}
