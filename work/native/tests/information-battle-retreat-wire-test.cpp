#include "../information-battle-retreat-wire.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <vector>

namespace wire = information::battle::retreat_wire;
static unsigned checks = 0;
static void check(bool value, const char* name) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL:%s\n", name); std::exit(1); }
}
static void write(const char* path, const std::vector<unsigned char>& value) {
    std::ofstream stream(path, std::ios::binary);
    stream.write(reinterpret_cast<const char*>(value.data()), static_cast<std::streamsize>(value.size()));
    check(stream.good(), "complete cross-language output");
}
int main(int argc, char** argv) {
    check(argc == 5, "four fixture paths");
    std::ifstream stream(argv[1], std::ios::binary);
    std::vector<unsigned char> base((std::istreambuf_iterator<char>(stream)), {});
    wire::detail::BaseIdentity identity{};
    check(wire::detail::base_identity(base.data(), base.size(), identity), "real retained v9 base validates");
    wire::Snapshot value{};
    value.sequence = identity.sequence; value.raw_date = static_cast<std::int32_t>(identity.raw_date);
    value.kind = identity.kind; value.present = true; value.combat_side_index = 1;
    value.initial_unit_count = 3; value.observed_count = 2;
    value.units[0] = {0, UINT64_C(0x0102030405060708), {{0, 1, 1, 1}}};
    value.units[1] = {2, UINT64_C(0xffffffffffffffff), {{255, 128, 2, 0}}};
    const auto required = wire::encoded_size(base.data(), base.size(), value);
    check(required == base.size() + 68, "exact variable frame size");
    std::vector<unsigned char> output(required, 0xa5);
    auto encoded = wire::encode(base.data(), base.size(), value, output.data(), output.size());
    check(encoded.succeeded() && encoded.written_bytes == required, "known frame encodes");
    check(output[4] == 10 && output[5] == 0, "wire10 version");
    check(std::equal(base.begin(), base.end(), output.begin() + 10), "embedded v9 unchanged");
    check(wire::bytes::get_u16(output.data() + base.size() + 14) == 1, "regular source keeps RETR v1");
    check(output[base.size() + 35] == 0, "regular source reserved byte stays zero");
    check(output[required - 4] == 255 && output[required - 3] == 128, "raw flags retained");
    check(wire::bytes::get_u64(output.data() + base.size() + 42) == UINT64_C(0x0102030405060708), "owner fullref little-endian");
    write(argv[2], output);
    value.capture_source = wire::kCaptureSourceUnitRemovalState;
    std::vector<unsigned char> removal(required, 0xa5);
    check(wire::encode(base.data(), base.size(), value, removal.data(), removal.size()).succeeded(), "unit-removal source encodes");
    check(wire::bytes::get_u16(removal.data() + base.size() + 14) == 2, "unit-removal source selects RETR v2");
    check(removal[base.size() + 35] == 1, "unit-removal source marker occupies former reserved byte");
    write(argv[4], removal);
    auto fails = [&](wire::Snapshot invalid, const char* name) {
        std::fill(output.begin(), output.end(), 0xa5);
        check(!wire::encode(base.data(), base.size(), invalid, output.data(), output.size()).succeeded(), name);
        check(std::all_of(output.begin(), output.end(), [](auto b) { return b == 0xa5; }), "failure leaves output untouched");
    };
    auto invalid = value; ++invalid.sequence; fails(invalid, "sequence mismatch");
    invalid = value; ++invalid.raw_date; fails(invalid, "date mismatch");
    invalid = value; invalid.kind = 2; fails(invalid, "kind mismatch");
    invalid = value; invalid.combat_side_index = 2; fails(invalid, "invalid side");
    invalid = value; invalid.capture_source = 2; fails(invalid, "invalid capture source");
    invalid = value; invalid.initial_unit_count = 129; fails(invalid, "initial count limit");
    invalid = value; invalid.observed_count = 4; fails(invalid, "observed exceeds initial");
    invalid = value; invalid.units[1].ordinal = 0; fails(invalid, "duplicate ordinal");
    invalid = value; invalid.units[0].ordinal = 2; invalid.units[1].ordinal = 1; fails(invalid, "unordered ordinals");
    invalid = value; invalid.units[1].ordinal = 3; fails(invalid, "ordinal outside initial set");
    check(!wire::encode(base.data(), base.size(), value, output.data(), required - 1).succeeded(), "short output");
    check(!wire::encode(nullptr, base.size(), value, output.data(), output.size()).succeeded(), "null base");
    check(!wire::encode(base.data(), base.size(), value, nullptr, output.size()).succeeded(), "null output");
    const auto original_base = base;
    check(!wire::encode(base.data(), base.size(), value, base.data(), base.size()).succeeded(), "overlap rejected");
    check(base == original_base, "overlap preserves base");
    for (std::size_t length = 0; length < 10; ++length)
        check(wire::encoded_size(base.data(), length, value) == 0, "truncated base header");
    auto bad_base = base; bad_base[4] = 10;
    check(wire::encoded_size(bad_base.data(), bad_base.size(), value) == 0, "recursive v10 base forbidden");
    bad_base = base; bad_base.pop_back();
    check(wire::encoded_size(bad_base.data(), bad_base.size(), value) == 0, "truncated EOST forbidden");
    bad_base = base; bad_base[bad_base.size() - 3] = 0;
    check(wire::encoded_size(bad_base.data(), bad_base.size(), value) == 0, "noncanonical unknown EOST forbidden");
    wire::Snapshot unknown = value; unknown.present = false; unknown.observed_count = 65535;
    unknown.capture_source = 255;
    const auto unknown_size = wire::encoded_size(base.data(), base.size(), unknown);
    check(unknown_size == base.size() + 40, "unknown ignores stale counters");
    std::vector<unsigned char> blank(unknown_size, 0xa5);
    check(wire::encode(base.data(), base.size(), unknown, blank.data(), blank.size()).succeeded(), "unknown encodes");
    check(wire::bytes::get_u16(blank.data() + base.size() + 14) == 1, "unknown forces RETR v1");
    check(std::all_of(blank.end() - 20, blank.end(), [](auto b) { return b == 0; }), "unknown canonical all zero");
    write(argv[3], blank);
    value.initial_unit_count = 128; value.observed_count = 128;
    for (std::size_t i = 0; i < 128; ++i) value.units[i].ordinal = static_cast<std::uint16_t>(i);
    std::vector<unsigned char> full(wire::encoded_size(base.data(), base.size(), value));
    check(!full.empty() && wire::encode(base.data(), base.size(), value, full.data(), full.size()).succeeded(), "128 unit boundary");
    value.observed_count = 0;
    check(wire::encoded_size(base.data(), base.size(), value) == base.size() + 40, "zero observed transports without false inference");
    std::printf("CHECK_COUNT=%u\n", checks);
    return 0;
}
