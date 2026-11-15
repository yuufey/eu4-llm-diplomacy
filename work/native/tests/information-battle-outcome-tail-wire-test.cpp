#include "../information-battle-outcome-tail-wire.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <vector>

namespace wire = information::battle::outcome_tail_wire;
static unsigned checks = 0;

static void check(bool ok, const char* name) {
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL:%s\n", name); std::exit(1); }
}

static void put(wire::Text& text, wire::State state,
                const char* value, std::size_t size) {
    text = wire::Text{};
    text.state = state;
    text.length = static_cast<std::uint32_t>(size);
    if (size != 0u) std::memcpy(text.bytes.data(), value, size);
}

static void write(const char* path, const std::vector<unsigned char>& data) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
    check(output.good(), "complete cross-language fixture output");
}

int main(int argc, char** argv) {
    check(argc == 4, "base, known, and unknown fixture paths");
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<unsigned char> base((std::istreambuf_iterator<char>(input)), {});
    check(input.good() || input.eof(), "complete fixed synthetic base read");
    wire::detail::BaseIdentity identity{};
    check(wire::detail::base_identity(base.data(), base.size(), identity),
          "complete v12 base validates");

    auto known = std::unique_ptr<wire::Snapshot>(new wire::Snapshot{});
    known->sequence = identity.sequence;
    known->raw_date = identity.raw_date;
    known->kind = identity.kind;
    known->failure = 0u;
    put(known->fields[wire::language], wire::State::known, "l_english", 9u);
    known->reserved_slots = {{-7, 0, -7}};
    put(known->fields[wire::COMBAT_FLEE], wire::State::known, "", 0u);
    put(known->fields[wire::COMBAT_TRIUMPH], wire::State::absent, "", 0u);
    put(known->fields[wire::COMBAT_WINNERTYPE_OUR], wire::State::known, "our", 3u);
    put(known->fields[wire::COMBAT_WINNERTYPE_THEIR], wire::State::known, "their", 5u);

    std::size_t text_bytes = 0u;
    for (const auto& field : known->fields) text_bytes += field.length;
    const auto known_size = wire::encoded_size(base.data(), base.size(), *known);
    check(known_size == base.size() + 20u + wire::kFixedBodyBytes
                            + wire::kFieldCount * wire::kTextHeaderBytes + text_bytes,
          "exact v13 frame size");
    std::vector<unsigned char> known_wire(known_size, 0xa5u);
    const auto known_result = wire::encode(base.data(), base.size(), *known,
                                           known_wire.data(), known_wire.size());
    check(known_result.succeeded() && known_result.written_bytes == known_size,
          "known frame encodes");
    check(wire::validate(known_wire.data(), known_wire.size()), "known frame validates");
    check(known_wire[4u] == 13u && known_wire[5u] == 0u, "wire13 version");
    check(std::equal(base.begin(), base.end(), known_wire.begin() + 10),
          "embedded complete v12 frame unchanged");
    const std::size_t extension = 10u + base.size();
    check(std::memcmp(known_wire.data() + extension, "SCTX", 4u) == 0,
          "SCTX extension magic");
    const std::size_t body = extension + wire::kExtensionHeaderBytes;
    check(known_wire[body + wire::kFixedBodyBytes] == 1u,
          "language starts the ordered fields");
    check(known_wire[body + 15u] == 0xf9u
              && known_wire[body + 16u] == 0xffu
              && known_wire[body + 17u] == 0xffu
              && known_wire[body + 18u] == 0xffu,
          "negative reserved slot uses little-endian signed i32");
    const std::size_t flee_header = body + wire::kFixedBodyBytes
        + wire::kTextHeaderBytes + 9u;
    check(known_wire[flee_header] == 1u
              && known_wire[flee_header + 1u] == 0u
              && known_wire[flee_header + 2u] == 0u,
          "known empty remains distinct");
    const std::size_t triumph_header = flee_header + wire::kTextHeaderBytes;
    check(known_wire[triumph_header] == 2u
              && known_wire[triumph_header + 1u] == 0u
              && known_wire[triumph_header + 2u] == 0u,
          "absent has its own state");
    write(argv[2], known_wire);

    std::vector<unsigned char> untouched(known_size, 0xa5u);
    auto bad = std::unique_ptr<wire::Snapshot>(new wire::Snapshot(*known));
    auto reject = [&](const char* label) {
        std::fill(untouched.begin(), untouched.end(), 0xa5u);
        check(wire::encoded_size(base.data(), base.size(), *bad) == 0u, label);
        check(!wire::encode(base.data(), base.size(), *bad, untouched.data(),
                            untouched.size()).succeeded(),
              "invalid snapshot rejected");
        check(std::all_of(untouched.begin(), untouched.end(),
                          [](unsigned char value) { return value == 0xa5u; }),
              "failed encode leaves output untouched");
    };
    ++bad->sequence; reject("sequence mismatch");
    bad.reset(new wire::Snapshot(*known)); ++bad->raw_date; reject("date mismatch");
    bad.reset(new wire::Snapshot(*known)); bad->kind = bad->kind == 1u ? 2u : 1u;
    reject("kind mismatch");
    bad.reset(new wire::Snapshot(*known)); bad->failure = 1u;
    reject("failure group mismatch");
    bad.reset(new wire::Snapshot(*known)); bad->failure = 1u;
    bad->reserved_slots = {{0, 0, 0}};
    reject("failure group requires unknown fields");
    bad.reset(new wire::Snapshot{});
    bad->sequence = identity.sequence; bad->raw_date = identity.raw_date;
    bad->kind = identity.kind; bad->failure = 1u;
    bad->reserved_slots = {{-1, 0, 0}};
    reject("failed group requires zero reserved slots");
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::language].bytes[0] = 'x';
    reject("invalid language");
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::COMBAT_FLEE].bytes[0] = 1u;
    reject("nonzero unused tail");
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::COMBAT_WINNERTYPE_OUR].bytes[0] = 0u;
    reject("known text NUL");
    bad.reset(new wire::Snapshot(*known));
    bad->fields[wire::language].state = wire::State::absent;
    reject("language cannot be absent");

    auto unknown = std::unique_ptr<wire::Snapshot>(new wire::Snapshot{});
    unknown->sequence = identity.sequence;
    unknown->raw_date = identity.raw_date;
    unknown->kind = identity.kind;
    unknown->failure = 8u;
    const auto unknown_size = wire::encoded_size(base.data(), base.size(), *unknown);
    check(unknown_size == base.size() + 20u + wire::kFixedBodyBytes
                              + wire::kFieldCount * wire::kTextHeaderBytes,
          "canonical failed frame size");
    std::vector<unsigned char> unknown_wire(unknown_size, 0xa5u);
    const auto unknown_result = wire::encode(base.data(), base.size(), *unknown,
                                              unknown_wire.data(), unknown_wire.size());
    check(unknown_result.succeeded(), "failed frame encodes");
    check(wire::validate(unknown_wire.data(), unknown_wire.size()),
          "failed frame validates");
    check(unknown_wire[body + 13u] == 8u && unknown_wire[body + 14u] == 0u,
          "u16 failure is serialized");
    check(std::all_of(unknown_wire.begin() + static_cast<std::ptrdiff_t>(body + 15u),
                      unknown_wire.begin() + static_cast<std::ptrdiff_t>(body + 27u),
                      [](unsigned char value) { return value == 0u; }),
          "failure group reserves zero i32 slots");
    check(unknown_wire[body + wire::kFixedBodyBytes] == 0u,
          "unknown field state is canonical");
    write(argv[3], unknown_wire);

    auto trailing = known_wire;
    trailing.push_back(0u);
    check(!wire::validate(trailing.data(), trailing.size()),
          "trailing bytes rejected");
    auto extra_base = base;
    extra_base.push_back(0u);
    check(wire::encoded_size(extra_base.data(), extra_base.size(), *known) == 0u,
          "embedded v12 extra byte rejected");
    std::fill(untouched.begin(), untouched.end(), 0xa5u);
    check(!wire::encode(base.data(), base.size(), *known, untouched.data(),
                        known_size - 1u).succeeded(), "short output rejected");
    check(std::all_of(untouched.begin(), untouched.end(),
                      [](unsigned char value) { return value == 0xa5u; }),
          "short output leaves destination untouched");

    std::printf("{\"checks\":%u,\"status\":\"ok\"}\n", checks);
    return 0;
}
