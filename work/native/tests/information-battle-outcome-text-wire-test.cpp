#include "../information-battle-outcome-text-wire.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <vector>

namespace wire = information::battle::outcome_text_wire;
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
          "complete v11 base validates");

    auto known = std::unique_ptr<wire::Snapshot>(new wire::Snapshot{});
    known->sequence = identity.sequence;
    known->raw_date = identity.raw_date;
    known->kind = identity.kind;
    known->failure = 0u;
    put(known->fields[wire::language], wire::State::known, "l_english", 9u);
    put(known->fields[wire::ALLIES_WON], wire::State::known, "", 0u);
    put(known->fields[wire::ALLIES_LOST], wire::State::absent, "", 0u);
    put(known->fields[wire::YOU_WON], wire::State::known, "$COUNTRY$ won", 13u);
    put(known->fields[wire::YOU_LOST], wire::State::known, "", 0u);
    put(known->fields[wire::RESULT_WON], wire::State::known, "won", 3u);
    put(known->fields[wire::RESULT_LOSS], wire::State::absent, "", 0u);
    put(known->fields[wire::OTHERRESULT], wire::State::known, "other", 5u);
    put(known->fields[wire::WARSCORE_FROM_BATTLE], wire::State::known, "+1.00", 5u);
    put(known->fields[wire::MESSAGE_HEAD_MIL], wire::State::known, "mil head", 8u);
    put(known->fields[wire::MESSENGER], wire::State::known, "messenger", 9u);

    std::size_t text_bytes = 0u;
    for (const auto& field : known->fields) text_bytes += field.length;
    const auto known_size = wire::encoded_size(base.data(), base.size(), *known);
    check(known_size == base.size() + 20u + wire::kFixedBodyBytes
                            + wire::kFieldCount * wire::kTextHeaderBytes + text_bytes,
          "exact v12 frame size");
    std::vector<unsigned char> known_wire(known_size, 0xa5u);
    const auto known_result = wire::encode(base.data(), base.size(), *known,
                                           known_wire.data(), known_wire.size());
    check(known_result.succeeded() && known_result.written_bytes == known_size,
          "known frame encodes");
    check(wire::validate(known_wire.data(), known_wire.size()), "known frame validates");
    check(known_wire[4u] == 12u && known_wire[5u] == 0u, "wire12 version");
    check(std::equal(base.begin(), base.end(), known_wire.begin() + 10),
          "embedded complete v11 frame unchanged");
    const std::size_t extension = 10u + base.size();
    check(std::memcmp(known_wire.data() + extension, "OCTX", 4u) == 0,
          "OCTX extension magic");
    const std::size_t body = extension + wire::kExtensionHeaderBytes;
    check(known_wire[body + wire::kFixedBodyBytes] == 1u,
          "language starts the ordered fields");
    const std::size_t allies_won_header = body + wire::kFixedBodyBytes
        + wire::kTextHeaderBytes + 9u;
    check(known_wire[allies_won_header] == 1u
              && known_wire[allies_won_header + 1u] == 0u
              && known_wire[allies_won_header + 2u] == 0u,
          "known empty remains distinct");
    const std::size_t allies_lost_header = allies_won_header + wire::kTextHeaderBytes;
    check(known_wire[allies_lost_header] == 2u
              && known_wire[allies_lost_header + 1u] == 0u
              && known_wire[allies_lost_header + 2u] == 0u,
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
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::language].bytes[0] = 'x';
    reject("invalid language");
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::ALLIES_WON].bytes[0] = 1u;
    reject("nonzero unused tail");
    bad.reset(new wire::Snapshot(*known)); bad->fields[wire::YOU_WON].bytes[0] = 0u;
    reject("known text NUL");
    bad.reset(new wire::Snapshot(*known));
    bad->fields[wire::language].state = wire::State::absent;
    reject("language cannot be absent");

    auto unknown = std::unique_ptr<wire::Snapshot>(new wire::Snapshot{});
    unknown->sequence = identity.sequence;
    unknown->raw_date = identity.raw_date;
    unknown->kind = identity.kind;
    unknown->failure = 9u;
    const auto unknown_size = wire::encoded_size(base.data(), base.size(), *unknown);
    check(unknown_size == base.size() + 20u + wire::kFixedBodyBytes
                              + wire::kFieldCount * wire::kTextHeaderBytes,
          "canonical unknown frame size");
    std::vector<unsigned char> unknown_wire(unknown_size, 0xa5u);
    const auto unknown_result = wire::encode(base.data(), base.size(), *unknown,
                                              unknown_wire.data(), unknown_wire.size());
    check(unknown_result.succeeded(), "unknown frame encodes");
    check(wire::validate(unknown_wire.data(), unknown_wire.size()),
          "unknown frame validates");
    check(unknown_wire[body + 13u] == 9u && unknown_wire[body + 14u] == 0u,
          "u16 failure is serialized");
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
          "embedded v11 extra byte rejected");
    std::fill(untouched.begin(), untouched.end(), 0xa5u);
    check(!wire::encode(base.data(), base.size(), *known, untouched.data(),
                        known_size - 1u).succeeded(), "short output rejected");
    check(std::all_of(untouched.begin(), untouched.end(),
                      [](unsigned char value) { return value == 0xa5u; }),
          "short output leaves destination untouched");

    std::printf("{\"checks\":%u,\"status\":\"ok\"}\n", checks);
    return 0;
}
