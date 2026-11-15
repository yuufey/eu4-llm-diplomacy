#include "../information-battle-display-context-wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace {

namespace wire = information::battle::display_context_wire;
namespace display = information::battle::display_context;
namespace native_wire = information::battle::native_text_wire;

std::size_t g_checks = 0u;

void check(bool condition, const char* name) {
    ++g_checks;
    if (!condition) {
        std::cerr << "FAIL: " << name << '\n';
        std::exit(1);
    }
    std::cout << "PASS: " << name << '\n';
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

std::uint16_t get_u16(const unsigned char* bytes) {
    return static_cast<std::uint16_t>(bytes[0])
        | (static_cast<std::uint16_t>(bytes[1]) << 8u);
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
    return static_cast<std::int32_t>(get_u32(bytes));
}

std::vector<unsigned char> read_base6(const char* path) {
    std::ifstream stream(path, std::ios::binary);
    check(stream.good(), "valid complete base6 fixture file opens");
    std::vector<unsigned char> result(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());
    check(!result.empty(), "complete base6 fixture is nonempty");
    return result;
}

void append_text(display::Snapshot& snapshot, std::size_t index,
                 display::State state, const unsigned char* bytes,
                 std::size_t length) {
    display::Text& field = snapshot.fields[index];
    field.state = state;
    field.offset = 0u;
    field.length = 0u;
    if (state != display::State::observed) {
        return;
    }
    check(index < display::kFieldCount, "append field index bounded");
    check(snapshot.arena_used <= display::kArenaBytes
              && length <= display::kArenaBytes - snapshot.arena_used,
          "append field fits arena");
    check(length <= display::field_limit(index), "append field fits per-field limit");
    field.offset = snapshot.arena_used;
    field.length = static_cast<std::uint32_t>(length);
    if (length != 0u) {
        check(bytes != nullptr, "observed nonempty field has source bytes");
        std::memcpy(snapshot.arena.data() + snapshot.arena_used, bytes, length);
    }
    snapshot.arena_used += static_cast<std::uint32_t>(length);
}

void append_ascii(display::Snapshot& snapshot, std::size_t index,
                  display::State state, const char* text) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(text);
    append_text(snapshot, index, state, bytes, std::strlen(text));
}

display::Snapshot known_snapshot(std::uint8_t kind = 1u,
                                 std::int32_t popup_kind = 0) {
    display::Snapshot result{};
    result.state = display::State::observed;
    result.failure = display::Failure::none;
    result.identity.sequence = 3u;
    result.identity.date = 56557272;
    result.identity.kind = kind;
    result.identity.stage = display::kRouterScopeExit;
    result.popup_kind_raw = popup_kind;
    result.layout_raw = 1;
    result.button_flag_raw = 1u;

    const char* key = kind == 1u ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    append_ascii(result, 0u, display::State::observed, key);
    append_ascii(result, 1u, display::State::observed, "l_english");
    append_ascii(result, 2u, display::State::observed, "$NAME$");
    const unsigned char button1[] = {0x11u, 0x8bu, 0x59u, 0x10u, 0x84u, 0x76u};
    append_text(result, 3u, display::State::observed, button1, sizeof(button1));
    append_text(result, 4u, display::State::observed, nullptr, 0u);
    append_text(result, 5u, display::State::absent, nullptr, 0u);
    append_text(result, 6u, display::State::unknown, nullptr, 0u);
    return result;
}

display::Snapshot unknown_snapshot(display::Failure failure) {
    display::Snapshot result{};
    result.state = display::State::unknown;
    result.failure = failure;
    return result;
}

std::vector<unsigned char> encode_ok(const std::vector<unsigned char>& base,
                                     const display::Snapshot& snapshot) {
    const std::size_t bytes = wire::encoded_size(
        base.data(), base.size(), snapshot);
    check(bytes != 0u, "valid sample has encoded size");
    std::vector<unsigned char> result(bytes, 0xa5u);
    const auto encoded = wire::encode(base.data(), base.size(), snapshot,
                                      result.data(), result.size());
    check(encoded.succeeded() && encoded.written_bytes == bytes,
          "valid sample encodes exactly");
    return result;
}

void verify_frame(const std::vector<unsigned char>& base,
                  const display::Snapshot& snapshot,
                  const std::vector<unsigned char>& frame,
                  const char* label) {
    check(frame.size() <= wire::kMaxWireBytes, label);
    check(frame.size() >= wire::kOuterHeaderBytes + base.size()
              + wire::kExtensionHeaderBytes + wire::kFixedBodyBytes,
          "frame has minimum full v7 shape");
    check(std::memcmp(frame.data(), "IBOW", 4u) == 0,
          "outer magic is IBOW");
    check(get_u16(frame.data() + 4u) == 7u, "outer version is v7");
    check(get_u32(frame.data() + 6u) == base.size(),
          "outer u32 is complete base6 length");
    check(std::memcmp(frame.data() + 10u, base.data(), base.size()) == 0,
          "complete v6 base is byte-identical");
    const std::size_t extension = 10u + base.size();
    check(std::memcmp(frame.data() + extension, "DCTX", 4u) == 0,
          "DCTX extension marker");
    check(get_u16(frame.data() + extension + 4u) == 1u,
          "DCTX extension version 1");
    const std::size_t body_bytes = get_u32(frame.data() + extension + 6u);
    const std::size_t body = extension + wire::kExtensionHeaderBytes;
    check(body_bytes == frame.size() - body, "body length ends at frame end");
    check(body_bytes == wire::kFixedBodyBytes + wire::kEntryHeaderBytes * 7u
              + snapshot.arena_used,
          "body length is fixed fields plus seven packed entries");
    check(frame[body] == static_cast<unsigned char>(snapshot.state),
          "context state byte");
    check(frame[body + 1u] == snapshot.identity.stage,
          "capture stage byte");
    check(get_u16(frame.data() + body + 2u)
              == static_cast<std::uint16_t>(snapshot.failure),
          "failure u16");
    check(get_u64(frame.data() + body + 4u) == snapshot.identity.sequence,
          "sequence u64");
    check(get_i32(frame.data() + body + 12u) == snapshot.identity.date,
          "date i32");
    check(frame[body + 16u] == snapshot.identity.kind, "battle kind byte");
    check(get_i32(frame.data() + body + 17u) == snapshot.popup_kind_raw,
          "raw popup kind i32");
    check(get_i32(frame.data() + body + 21u) == snapshot.layout_raw,
          "layout i32");
    check(frame[body + 25u] == snapshot.button_flag_raw,
          "button flag byte");
    check(frame[body + 26u] == 7u, "entry count is seven");

    std::size_t cursor = body + wire::kFixedBodyBytes;
    for (std::size_t index = 0u; index < display::kFieldCount; ++index) {
        const display::Text& field = snapshot.fields[index];
        check(frame[cursor] == static_cast<unsigned char>(index + 1u),
              "entry ids are strictly ordered");
        check(frame[cursor + 1u] == static_cast<unsigned char>(field.state),
              "entry state preserved");
        check(get_u16(frame.data() + cursor + 2u) == 0u,
              "entry reserved u16 is zero");
        check(get_u32(frame.data() + cursor + 4u) == field.length,
              "entry length is exact");
        cursor += wire::kEntryHeaderBytes;
        if (field.length != 0u) {
            check(std::memcmp(frame.data() + cursor,
                              snapshot.arena.data() + field.offset,
                              field.length) == 0,
                  "entry payload matches packed snapshot bytes");
            cursor += field.length;
        }
    }
    check(cursor == frame.size(), "no trailing bytes");
}

bool rejected_without_write(const unsigned char* base, std::size_t base_bytes,
                            const display::Snapshot& snapshot,
                            std::size_t capacity_adjustment = 0u) {
    const std::size_t required = wire::encoded_size(base, base_bytes, snapshot);
    const std::size_t buffer_bytes = required == 0u ? 512u : required;
    std::vector<unsigned char> output(buffer_bytes, 0x5au);
    const auto before = output;
    const std::size_t capacity = capacity_adjustment == 0u
        ? buffer_bytes : capacity_adjustment;
    const auto result = wire::encode(base, base_bytes, snapshot,
                                     output.data(), capacity);
    return !result.succeeded() && output == before;
}

std::string hex(const unsigned char* data, std::size_t bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes * 2u);
    for (std::size_t index = 0u; index < bytes; ++index) {
        result.push_back(digits[data[index] >> 4u]);
        result.push_back(digits[data[index] & 0x0fu]);
    }
    return result;
}

void test_known_v7_and_export_fixture(const std::vector<unsigned char>& base,
                                      std::vector<unsigned char>& base6_out,
                                      display::Snapshot& snapshot_out,
                                      std::vector<unsigned char>& frame_out) {
    const auto snapshot = known_snapshot(1u, 0);
    const auto frame = encode_ok(base, snapshot);
    verify_frame(base, snapshot, frame, "known v7 frame within global limit");
    check(native_wire::validate(base.data(), base.size()),
          "fixture embedded v6 still validates");
    base6_out = base;
    snapshot_out = snapshot;
    frame_out = frame;
}

void test_unknown_and_failure_range(const std::vector<unsigned char>& base) {
    for (std::uint16_t failure = 1u; failure <= 9u; failure += 8u) {
        const auto snapshot = unknown_snapshot(
            static_cast<display::Failure>(failure));
        const auto frame = encode_ok(base, snapshot);
        verify_frame(base, snapshot, frame,
                     "unknown context has empty seven-entry payload");
        check(frame[10u + base.size()
                    + wire::kExtensionHeaderBytes] == 0u,
              "unknown context state zero");
    }
}

void test_raw_kind_is_not_family_check(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot(1u, 99);
    const auto frame = encode_ok(base, snapshot);
    verify_frame(base, snapshot, frame,
                 "observed raw popup kind may differ from land family");
}

void test_full_arena_boundary(const std::vector<unsigned char>& base) {
    display::Snapshot snapshot{};
    snapshot.state = display::State::observed;
    snapshot.failure = display::Failure::none;
    snapshot.identity.sequence = 99u;
    snapshot.identity.date = -1;
    snapshot.identity.kind = 1u;
    snapshot.identity.stage = display::kRouterScopeExit;
    snapshot.popup_kind_raw = -17;
    snapshot.layout_raw = 1;
    snapshot.button_flag_raw = 1u;
    append_ascii(snapshot, 0u, display::State::observed, "LANDBATTLEOVER");
    append_ascii(snapshot, 1u, display::State::observed, "l_english");
    const std::size_t remaining = display::kArenaBytes
        - snapshot.arena_used;
    const std::array<std::size_t, 4> lengths{{8192u, 8192u, 8192u,
        remaining - 8192u * 3u}};
    for (std::size_t index = 0u; index < lengths.size(); ++index) {
        const std::vector<unsigned char> bytes(lengths[index],
                                                static_cast<unsigned char>('x'));
        append_text(snapshot, index + 2u, display::State::observed,
                    bytes.data(), bytes.size());
    }
    append_text(snapshot, 6u, display::State::unknown, nullptr, 0u);
    check(snapshot.arena_used == display::kArenaBytes,
          "snapshot fills exact 32768-byte extension arena");
    check(display::valid(snapshot), "exact arena boundary remains valid");
    const auto frame = encode_ok(base, snapshot);
    verify_frame(base, snapshot, frame,
                 "maximum extension arena serializes within frame cap");
}

void test_signed_and_u64_extremes(const std::vector<unsigned char>& base) {
    auto snapshot = known_snapshot(2u, (std::numeric_limits<std::int32_t>::max)());
    snapshot.identity.sequence = (std::numeric_limits<std::uint64_t>::max)();
    snapshot.identity.date = (std::numeric_limits<std::int32_t>::min)();
    snapshot.layout_raw = (std::numeric_limits<std::int32_t>::min)();
    const auto frame = encode_ok(base, snapshot);
    verify_frame(base, snapshot, frame,
                 "u64 and signed i32 extrema retain their raw values");
}

void test_short_buffer_unchanged(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot();
    const std::size_t required = wire::encoded_size(base.data(), base.size(), snapshot);
    check(required > 1u, "short-buffer test has nontrivial size");
    std::vector<unsigned char> output(required, 0x6bu);
    const auto before = output;
    const auto result = wire::encode(base.data(), base.size(), snapshot,
                                     output.data(), required - 1u);
    check(!result.succeeded() && output == before,
          "short output rejects without a partial write");
}

void test_invalid_v6_envelopes_unchanged(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot();
    std::vector<unsigned char> bad_version = base;
    put_u16(bad_version, 4u, 5u);
    check(rejected_without_write(bad_version.data(), bad_version.size(), snapshot),
          "rejects non-v6 base without writing");

    std::vector<unsigned char> bad_length = base;
    put_u32(bad_length, 6u, 0xffffffffu);
    check(rejected_without_write(bad_length.data(), bad_length.size(), snapshot),
          "rejects invalid base6 length without writing");

    std::vector<unsigned char> bad_extension = base;
    const std::size_t extension = 10u + get_u32(base.data() + 6u);
    bad_extension[extension] ^= 0x20u;
    check(rejected_without_write(bad_extension.data(), bad_extension.size(), snapshot),
          "rejects malformed v6 extension without writing");

    std::vector<unsigned char> too_large(wire::kMaxWireBytes + 1u, 0u);
    check(rejected_without_write(too_large.data(), too_large.size(), snapshot),
          "rejects v6 base beyond 512 KiB without writing");
}

void test_invalid_snapshot_headers_unchanged(const std::vector<unsigned char>& base) {
    auto bad_state = known_snapshot();
    bad_state.state = static_cast<display::State>(3u);
    check(rejected_without_write(base.data(), base.size(), bad_state),
          "rejects invalid context-state header without writing");

    auto bad_failure = known_snapshot();
    bad_failure.failure = display::Failure::guard;
    check(rejected_without_write(base.data(), base.size(), bad_failure),
          "observed context requires failure zero without writing");

    auto bad_stage = known_snapshot();
    bad_stage.identity.stage = 0u;
    check(rejected_without_write(base.data(), base.size(), bad_stage),
          "observed context requires stage 1 through 3");

    auto bad_kind = known_snapshot();
    bad_kind.identity.kind = 3u;
    check(rejected_without_write(base.data(), base.size(), bad_kind),
          "observed context kind is restricted to land or naval");

    auto bad_unknown = unknown_snapshot(display::Failure::guard);
    bad_unknown.identity.sequence = 1u;
    check(rejected_without_write(base.data(), base.size(), bad_unknown),
          "unknown context requires zero identity and scalars");

    auto bad_failure_id = unknown_snapshot(static_cast<display::Failure>(10u));
    check(rejected_without_write(base.data(), base.size(), bad_failure_id),
          "unknown context failure must be in 1 through 9");
}

void test_invalid_language_key_and_text_unchanged(
        const std::vector<unsigned char>& base) {
    auto bad_language = known_snapshot();
    bad_language.arena[bad_language.fields[1].offset] = 'e';
    check(rejected_without_write(base.data(), base.size(), bad_language),
          "language must use l_ prefix");

    auto bad_language_char = known_snapshot();
    bad_language_char.arena[bad_language_char.fields[1].offset + 2u] = '-';
    check(rejected_without_write(base.data(), base.size(), bad_language_char),
          "language suffix permits only ASCII alnum and underscore");

    auto bad_key = known_snapshot(1u);
    bad_key.arena[bad_key.fields[0].offset] = 'N';
    check(rejected_without_write(base.data(), base.size(), bad_key),
          "definition key must match battle kind");

    auto embedded_nul = known_snapshot();
    embedded_nul.arena[embedded_nul.fields[2].offset + 1u] = 0u;
    check(rejected_without_write(base.data(), base.size(), embedded_nul),
          "observed fields reject embedded NUL");

    auto bad_order = known_snapshot();
    ++bad_order.fields[2].offset;
    check(rejected_without_write(base.data(), base.size(), bad_order),
          "observed arena fields must be tightly packed in field order");

    auto bad_arena_used = known_snapshot();
    bad_arena_used.arena_used = static_cast<std::uint32_t>(display::kArenaBytes + 1u);
    check(rejected_without_write(base.data(), base.size(), bad_arena_used),
          "arena_used cannot exceed 32768 bytes");
}

void test_pointer_aliases_unchanged(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot();
    const std::size_t required = wire::encoded_size(base.data(), base.size(), snapshot);

    std::vector<unsigned char> base_output(required, 0x3cu);
    std::copy(base.begin(), base.end(), base_output.begin());
    const auto base_before = base_output;
    const auto base_alias = wire::encode(base_output.data(), base.size(), snapshot,
                                         base_output.data(), base_output.size());
    check(!base_alias.succeeded() && base_output == base_before,
          "base/output overlap rejects without a partial write");

    auto mutable_snapshot = snapshot;
    std::vector<unsigned char> snapshot_before(sizeof(mutable_snapshot));
    std::memcpy(snapshot_before.data(), &mutable_snapshot, sizeof(mutable_snapshot));
    auto* snapshot_output = reinterpret_cast<unsigned char*>(&mutable_snapshot);
    const auto snapshot_alias = wire::encode(
        base.data(), base.size(), mutable_snapshot,
        snapshot_output, sizeof(mutable_snapshot));
    check(!snapshot_alias.succeeded()
              && std::memcmp(snapshot_before.data(), &mutable_snapshot,
                             sizeof(mutable_snapshot)) == 0,
          "snapshot/output overlap rejects without modifying snapshot");

    auto embedded_base_snapshot = snapshot;
    check(base.size() <= display::kArenaBytes - embedded_base_snapshot.arena_used,
          "base/snapshot alias fixture fits unused arena suffix");
    unsigned char* embedded_base = embedded_base_snapshot.arena.data()
        + embedded_base_snapshot.arena_used;
    std::memcpy(embedded_base, base.data(), base.size());
    std::vector<unsigned char> output(required, 0x4du);
    const auto output_before = output;
    const auto base_snapshot_alias = wire::encode(
        embedded_base, base.size(), embedded_base_snapshot,
        output.data(), output.size());
    check(!base_snapshot_alias.succeeded() && output == output_before,
          "base/snapshot overlap rejects before output write");
}

void test_output_pointer_overflow(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot();
    const std::size_t required = wire::encoded_size(base.data(), base.size(), snapshot);
    const std::uintptr_t max_address =
        (std::numeric_limits<std::uintptr_t>::max)();
    auto* invalid_output = reinterpret_cast<unsigned char*>(max_address - 4u);
    const auto result = wire::encode(base.data(), base.size(), snapshot,
                                     invalid_output, required);
    check(!result.succeeded(), "overflowing output pointer range rejects");
}

void test_encoded_size_rejects_invalid_inputs(const std::vector<unsigned char>& base) {
    const auto snapshot = known_snapshot();
    check(wire::encoded_size(nullptr, base.size(), snapshot) == 0u,
          "encoded size rejects null base");
    auto invalid = snapshot;
    invalid.identity.sequence = 0u;
    check(wire::encoded_size(base.data(), base.size(), invalid) == 0u,
          "encoded size rejects invalid snapshot");
}

}  // namespace

int main(int argc, char** argv) {
    check(argc == 3 && std::strcmp(argv[1], "--base6") == 0,
          "test receives the strict-valid v6 fixture path");
    const std::vector<unsigned char> base6 = read_base6(argv[2]);
    check(native_wire::validate(base6.data(), base6.size()),
          "external base6 fixture passes complete v6 envelope guard");
    std::vector<unsigned char> fixture_base6;
    display::Snapshot fixture_snapshot{};
    std::vector<unsigned char> fixture_v7;
    test_known_v7_and_export_fixture(base6, fixture_base6, fixture_snapshot,
                                     fixture_v7);
    test_unknown_and_failure_range(fixture_base6);
    test_raw_kind_is_not_family_check(fixture_base6);
    test_full_arena_boundary(fixture_base6);
    test_signed_and_u64_extremes(fixture_base6);
    test_short_buffer_unchanged(fixture_base6);
    test_invalid_v6_envelopes_unchanged(fixture_base6);
    test_invalid_snapshot_headers_unchanged(fixture_base6);
    test_invalid_language_key_and_text_unchanged(fixture_base6);
    test_pointer_aliases_unchanged(fixture_base6);
    test_output_pointer_overflow(fixture_base6);
    test_encoded_size_rejects_invalid_inputs(fixture_base6);

    std::cout << "CHECK_COUNT=" << g_checks << '\n';
    std::cout << "FIXTURE_BASE6_HEX="
              << hex(fixture_base6.data(), fixture_base6.size()) << '\n';
    std::cout << "FIXTURE_V7_HEX="
              << hex(fixture_v7.data(), fixture_v7.size()) << '\n';
    return 0;
}
