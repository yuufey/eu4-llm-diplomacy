#include "information-battle-context-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace wire = information::battle::context_wire;
namespace observation = information::battle::observation;
namespace owned = information::battle::owned_result;
namespace context = information::battle::owned_context;

namespace {

unsigned g_checks = 0u;
unsigned g_failures = 0u;

void check(bool condition, const char* label) noexcept {
    ++g_checks;
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void set_bytes(owned::OwnedBytes& destination,
               const unsigned char* source,
               std::size_t length,
               std::uint32_t capacity) noexcept {
    destination.bytes.fill(0u);
    if (length != 0u) {
        std::memcpy(destination.bytes.data(), source, length);
    }
    destination.length = static_cast<std::uint32_t>(length);
    destination.capacity = capacity;
}

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

std::uint64_t full_ref(std::size_t index) noexcept {
    const std::size_t alphabet_size = sizeof(kAlphabet) - 1u;
    const unsigned char first = static_cast<unsigned char>(
        kAlphabet[index % alphabet_size]);
    const unsigned char second = static_cast<unsigned char>(
        kAlphabet[(index / alphabet_size) % alphabet_size]);
    const unsigned char third = static_cast<unsigned char>(
        kAlphabet[(index / (alphabet_size * alphabet_size)) % alphabet_size]);
    return static_cast<std::uint64_t>(first)
        | (static_cast<std::uint64_t>(second) << 8u)
        | (static_cast<std::uint64_t>(third) << 16u)
        | (static_cast<std::uint64_t>(index & 0xffu) << 32u)
        | UINT64_C(0x0100000000000000);
}

std::uint64_t opaque_variant_ref(std::size_t index) noexcept {
    return full_ref(index)
        | (UINT64_C(0x5a) << 24u)
        | (UINT64_C(0x02) << 56u);
}

constexpr context::Address kModuleBase = UINT64_C(0x140000000);
constexpr std::size_t kImageBytes = 0x1d30000u;
constexpr context::Address kCombat = UINT64_C(0x200000000);
constexpr context::Address kSideA = UINT64_C(0x210000000);
constexpr context::Address kSideB = UINT64_C(0x210001000);
constexpr context::Address kRowsA = UINT64_C(0x220000000);
constexpr context::Address kRowsB = UINT64_C(0x220001000);
constexpr context::Address kWar = UINT64_C(0x230000000);
constexpr context::Address kMembersA = UINT64_C(0x230001000);
constexpr context::Address kMembersB = UINT64_C(0x230002000);
constexpr std::size_t kFixtureSegmentBytes = 4096u;
constexpr std::size_t kFixtureMaxSegments = 16u;

struct FixtureSegment {
    context::Address address = 0u;
    std::size_t size = 0u;
    std::array<unsigned char, kFixtureSegmentBytes> bytes{};
};

struct CaptureReader {
    std::array<FixtureSegment, kFixtureMaxSegments> segments{};
    std::size_t count = 0u;

    bool add(context::Address address, const void* source,
             std::size_t size) noexcept {
        if (source == nullptr || size == 0u
                || size > kFixtureSegmentBytes || count >= segments.size()) {
            return false;
        }
        FixtureSegment& segment = segments[count++];
        segment.address = address;
        segment.size = size;
        std::memcpy(segment.bytes.data(), source, size);
        return true;
    }

    bool read(context::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        if (destination == nullptr || size == 0u) {
            return false;
        }
        for (std::size_t index = 0u; index < count; ++index) {
            const FixtureSegment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(destination,
                        segment.bytes.data() + (address - segment.address),
                        size);
            return true;
        }
        return false;
    }
};

static_assert(context::reader_contract<CaptureReader>::value,
              "capture fixture must use the exact noexcept reader contract");

void put_u64(std::array<unsigned char, kFixtureSegmentBytes>& bytes,
             std::size_t offset, std::uint64_t value) noexcept {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void put_i32(std::array<unsigned char, kFixtureSegmentBytes>& bytes,
             std::size_t offset, std::int32_t value) noexcept {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

bool build_capture_fixture(CaptureReader& reader) noexcept {
    reader = CaptureReader{};
    std::array<unsigned char, kFixtureSegmentBytes> module{};
    put_u64(module, 0x160u, kModuleBase + 0x300u);
    module[0x300u] = 0xb8u;
    module[0x301u] = 1u;
    module[0x302u] = 0u;
    module[0x303u] = 0u;
    module[0x304u] = 0u;
    module[0x305u] = 0xc3u;
    if (!reader.add(kModuleBase, module.data(), 0x400u)) return false;

    std::array<unsigned char, kFixtureSegmentBytes> combat{};
    put_u64(combat, context::kCombatVtableOffset, kModuleBase + 0x100u);
    put_u64(combat, context::kCombatSideAOffset, kSideA);
    put_u64(combat, context::kCombatSideBOffset, kSideB);
    if (!reader.add(kCombat, combat.data(), 0x100u)) return false;

    std::array<unsigned char, kFixtureSegmentBytes> side_a{};
    std::array<unsigned char, kFixtureSegmentBytes> side_b{};
    put_u64(side_a, context::kParticipantBeginOffset, kRowsA);
    put_u64(side_a, context::kParticipantEndOffset,
            kRowsA + 2u * context::kParticipantRowBytes);
    put_u64(side_b, context::kParticipantBeginOffset, kRowsB);
    put_u64(side_b, context::kParticipantEndOffset,
            kRowsB + context::kParticipantRowBytes);
    for (std::size_t index = 0u;
         index < context::kSideRawFieldOffsets.size(); ++index) {
        put_i32(side_a, context::kSideRawFieldOffsets[index],
                static_cast<std::int32_t>(100 + index));
        put_i32(side_b, context::kSideRawFieldOffsets[index],
                static_cast<std::int32_t>(-200 - index));
    }
    if (!reader.add(kSideA, side_a.data(), 0x200u)
            || !reader.add(kSideB, side_b.data(), 0x200u)) return false;

    std::array<unsigned char, kFixtureSegmentBytes> row_a{};
    std::array<unsigned char, kFixtureSegmentBytes> row_b{};
    put_u64(row_a, context::kParticipantFullRefOffset,
            opaque_variant_ref(0u));
    put_u64(row_a, context::kParticipantRowBytes
                + context::kParticipantFullRefOffset,
            full_ref(1u));
    put_u64(row_b, context::kParticipantFullRefOffset, full_ref(2u));
    if (!reader.add(kRowsA, row_a.data(), 2u * context::kParticipantRowBytes)
            || !reader.add(kRowsB, row_b.data(), context::kParticipantRowBytes)) {
        return false;
    }

    std::array<unsigned char, kFixtureSegmentBytes> war{};
    put_u64(war, context::kWarHistoryRootOffset,
            kModuleBase + context::kWarHistoryRootVtableRva);
    put_u64(war, context::kWarSideABounds[0], kMembersA);
    put_u64(war, context::kWarSideABounds[1], kMembersA + 16u);
    put_u64(war, context::kWarSideABounds[2], kMembersA + 16u);
    put_u64(war, context::kWarSideBBounds[0], kMembersB);
    put_u64(war, context::kWarSideBBounds[1], kMembersB + 8u);
    put_u64(war, context::kWarSideBBounds[2], kMembersB + 8u);
    if (!reader.add(kWar, war.data(), 0x200u)) return false;

    std::array<unsigned char, kFixtureSegmentBytes> members_a{};
    std::array<unsigned char, kFixtureSegmentBytes> members_b{};
    put_u64(members_a, 0u, opaque_variant_ref(0u));
    put_u64(members_a, 8u, full_ref(1u));
    put_u64(members_b, 0u, full_ref(2u));
    return reader.add(kMembersA, members_a.data(), 16u)
        && reader.add(kMembersB, members_b.data(), 8u);
}

observation::Observation make_inner(bool known_router = true) noexcept {
    observation::Observation value{};
    value.sequence = UINT64_C(0x1122334455667788);
    value.thread = 0x12345678u;
    value.known_router = known_router;
    value.result.raw_date = -1455113;
    value.result.flag108 = 0xa5u;
    value.result.aux100 = -123456;
    value.result.aux104 = 654321;
    value.result.province_id = 1275;
    constexpr std::array<unsigned char, 5> name{{'B', 'a', 't', 't', 'l'}};
    set_bytes(value.result.name, name.data(), name.size(), 16u);
    value.result.sides[0].country = full_ref(0u);
    value.result.sides[1].country = full_ref(1u);
    for (std::size_t side = 0u; side < value.result.sides.size(); ++side) {
        for (std::size_t index = 0u;
             index < value.result.sides[side].raw_fields.size(); ++index) {
            value.result.sides[side].raw_fields[index] =
                static_cast<std::int32_t>(
                    static_cast<int>(side * 100u + index));
        }
        value.result.sides[side].commander.capacity = 0u;
        value.result.sides[side].commander.length = 0u;
        value.result.sides[side].commander.bytes.fill(0u);
    }
    for (std::size_t index = 0u; index < value.summary.raw_i32.size(); ++index) {
        value.summary.raw_i32[index] =
            static_cast<std::int32_t>(static_cast<int>(index) * 7 - 30);
    }
    value.summary.control_byte = 0x5au;
    return value;
}

wire::ContextObservation make_observed() noexcept {
    wire::ContextObservation value{};
    value.inner = make_inner(true);
    value.context_present = true;
    value.context.known_router = true;
    value.context.raw_selector = 1u;
    value.context.selector_code = {{0xb8u, 1u, 0u, 0u, 0u, 0xc3u}};
    value.context.selector_code_verified = true;
    value.context.kind = context::Kind::land;
    value.context.physical_player_full_ref = opaque_variant_ref(0u);

    value.context.sides[0].present = true;
    value.context.sides[0].participants.complete = true;
    value.context.sides[0].participants.count = 2u;
    value.context.sides[0].participants.full_refs[0] =
        opaque_variant_ref(0u);
    value.context.sides[0].participants.full_refs[1] = full_ref(1u);
    value.context.sides[0].raw_fields = {{100, 101, 102, -10, -11, -12}};

    value.context.sides[1].present = true;
    value.context.sides[1].participants.complete = true;
    value.context.sides[1].participants.count = 1u;
    value.context.sides[1].participants.full_refs[0] = full_ref(2u);
    value.context.sides[1].raw_fields = {{200, 201, 202, -20, -21, -22}};

    value.context.war_context_status = context::WarContextStatus::observed;
    value.context.war_members.side_a_count = 2u;
    value.context.war_members.side_a_full_refs[0] = opaque_variant_ref(0u);
    value.context.war_members.side_a_full_refs[1] = full_ref(1u);
    value.context.war_members.side_b_count = 1u;
    value.context.war_members.side_b_full_refs[0] = full_ref(2u);
    value.context.war_members.vectors_complete = true;
    value.context.war_members.physical_player_membership_known = true;
    value.context.war_members.physical_player_is_war_member = true;
    return value;
}

wire::ContextObservation make_maximum() noexcept {
    wire::ContextObservation value = make_observed();
    for (std::size_t index = 0u; index < context::kMaxParticipants; ++index) {
        value.context.sides[0].participants.full_refs[index] = full_ref(index);
        value.context.sides[1].participants.full_refs[index] =
            full_ref(index + context::kMaxParticipants);
        value.context.sides[0].participants.count =
            static_cast<std::uint32_t>(context::kMaxParticipants);
        value.context.sides[1].participants.count =
            static_cast<std::uint32_t>(context::kMaxParticipants);
    }
    for (std::size_t index = 0u; index < context::kMaxWarMembers; ++index) {
        value.context.war_members.side_a_full_refs[index] = full_ref(index);
        value.context.war_members.side_b_full_refs[index] =
            full_ref(index + context::kMaxWarMembers);
    }
    value.context.sides[0].participants.full_refs[0] = opaque_variant_ref(0u);
    value.context.war_members.side_a_full_refs[0] = opaque_variant_ref(0u);
    value.context.war_members.side_a_count =
        static_cast<std::uint32_t>(context::kMaxWarMembers);
    value.context.war_members.side_b_count =
        static_cast<std::uint32_t>(context::kMaxWarMembers);
    return value;
}

bool bytes_equal(const std::array<unsigned char, wire::kMaxWireBytes>& left,
                 const std::array<unsigned char, wire::kMaxWireBytes>& right)
    noexcept {
    return std::memcmp(left.data(), right.data(), left.size()) == 0;
}

void print_wire(const char* label, const unsigned char* bytes,
                std::size_t length) noexcept {
    std::printf("WIRE %s ", label);
    for (std::size_t index = 0u; index < length; ++index) {
        std::printf("%02x", static_cast<unsigned>(bytes[index]));
    }
    std::printf("\n");
}

void check_failed_unchanged(const wire::ContextObservation& input,
                            std::size_t capacity,
                            const char* label) noexcept {
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    output.fill(0x5au);
    const auto before = output;
    const auto result = wire::encode(input, output.data(), capacity);
    check(!result.succeeded() && result.written_bytes == 0u, label);
    check(bytes_equal(output, before), "failed_output_unchanged");
}

void test_observed_and_no_context() noexcept {
    std::printf("TEST observed_and_no_context\n");
    wire::ContextObservation observed = make_observed();
    CaptureReader reader;
    check(build_capture_fixture(reader), "capture_fixture_build");
    context::Snapshot captured_context{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, opaque_variant_ref(0u), captured_context),
          "owned_context_capture_input");
    check(captured_context.war_context_status
              == context::WarContextStatus::observed
              && captured_context.kind == context::Kind::land,
          "captured_context_is_observed");
    observed.context = captured_context;
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    const auto result = wire::encode(observed, output.data(), output.size());
    check(result.succeeded(), "observed_encode");
    check(result.written_bytes <= wire::kMaxWireBytes, "observed_bound");
    check(output[0] == 'I' && output[1] == 'B' && output[2] == 'O'
              && output[3] == 'W', "v2_magic");
    check(output[4] == 2u && output[5] == 0u, "v2_version_little_endian");
    print_wire("observed", output.data(), result.written_bytes);

    wire::ContextObservation no_context = observed;
    no_context.context_present = false;
    const auto no_context_result = wire::encode(
        no_context, output.data(), output.size());
    check(no_context_result.succeeded(), "no_context_encode");
    check(no_context_result.written_bytes < result.written_bytes,
          "no_context_omits_context_bytes");
    const std::size_t inner_length = static_cast<std::size_t>(output[6])
        | (static_cast<std::size_t>(output[7]) << 8u)
        | (static_cast<std::size_t>(output[8]) << 16u)
        | (static_cast<std::size_t>(output[9]) << 24u);
    check(output[10u + inner_length] == 0u, "no_context_marker_zero");
    print_wire("no_context", output.data(), no_context_result.written_bytes);
}

void test_maximum_vectors() noexcept {
    std::printf("TEST maximum_vectors\n");
    wire::ContextObservation input = make_maximum();
    std::array<unsigned char, wire::kMaxWireBytes> output{};
    const auto result = wire::encode(input, output.data(), output.size());
    check(result.succeeded(), "maximum_vectors_encode");
    check(result.written_bytes < wire::kMaxWireBytes, "maximum_vectors_bound");
    print_wire("maximum", output.data(), result.written_bytes);
}

void test_invalid_context_and_flags() noexcept {
    std::printf("TEST invalid_context_and_flags\n");
    const wire::ContextObservation base = make_observed();

    wire::ContextObservation mismatch = base;
    mismatch.context.known_router = false;
    check_failed_unchanged(mismatch, wire::kMaxWireBytes,
                           "known_router_mismatch_rejected");

    wire::ContextObservation bad_selector = base;
    bad_selector.context.selector_code[1] = 2u;
    check_failed_unchanged(bad_selector, wire::kMaxWireBytes,
                           "selector_code_mismatch_rejected");

    wire::ContextObservation bad_kind = base;
    bad_kind.context.kind = context::Kind::naval;
    check_failed_unchanged(bad_kind, wire::kMaxWireBytes,
                           "kind_selector_mismatch_rejected");

    wire::ContextObservation bad_ref = base;
    bad_ref.context.sides[0].participants.full_refs[0] = UINT64_C(0x1234);
    check_failed_unchanged(bad_ref, wire::kMaxWireBytes,
                           "non_alphanumeric_ref_rejected");

    wire::ContextObservation lowercase_ref = base;
    lowercase_ref.context.sides[0].participants.full_refs[0] =
        UINT64_C(0x0100000000434261);
    check_failed_unchanged(lowercase_ref, wire::kMaxWireBytes,
                           "lowercase_ref_rejected");

    wire::ContextObservation duplicate = base;
    duplicate.context.war_members.side_b_full_refs[0] = full_ref(1u);
    check_failed_unchanged(duplicate, wire::kMaxWireBytes,
                           "war_cross_side_overlap_rejected");

    wire::ContextObservation membership = base;
    membership.context.war_members.physical_player_is_war_member = false;
    check_failed_unchanged(membership, wire::kMaxWireBytes,
                           "membership_flag_mismatch_rejected");

    wire::ContextObservation incomplete_vectors = base;
    incomplete_vectors.context.war_members.vectors_complete = false;
    check_failed_unchanged(incomplete_vectors, wire::kMaxWireBytes,
                           "observed_incomplete_vectors_rejected");

    wire::ContextObservation unknown_membership = base;
    unknown_membership.context.war_members.physical_player_membership_known =
        false;
    check_failed_unchanged(unknown_membership, wire::kMaxWireBytes,
                           "observed_unknown_membership_rejected");

    wire::ContextObservation incomplete_side = base;
    incomplete_side.context.sides[0].participants.complete = false;
    check_failed_unchanged(incomplete_side, wire::kMaxWireBytes,
                           "present_incomplete_side_rejected");

    wire::ContextObservation no_router_war = base;
    no_router_war.inner.known_router = false;
    no_router_war.context.known_router = false;
    check_failed_unchanged(no_router_war, wire::kMaxWireBytes,
                           "observed_war_without_router_rejected");

    wire::ContextObservation absent_side = base;
    absent_side.context.sides[1].present = false;
    absent_side.context.sides[1].participants.count = 0u;
    absent_side.context.sides[1].participants.complete = false;
    absent_side.context.sides[1].raw_fields.fill(0);
    absent_side.context.war_members.side_b_count = 0u;
    absent_side.context.war_members.side_b_full_refs.fill(0u);
    const auto absent_result = wire::encode(
        absent_side,
        reinterpret_cast<unsigned char*>(
            const_cast<wire::ContextObservation*>(&absent_side)),
        wire::kMaxWireBytes);
    check(!absent_result.succeeded(), "output_alias_rejected_after_validation");
}

void test_atomic_output_and_alias() noexcept {
    std::printf("TEST atomic_output_and_alias\n");
    const wire::ContextObservation input = make_observed();
    check_failed_unchanged(input, 1u, "short_output_rejected");

    std::array<unsigned char, wire::kMaxWireBytes> output{};
    output.fill(0x6cu);
    const auto before = output;
    const auto null_result = wire::encode(input, nullptr, output.size());
    check(!null_result.succeeded() && bytes_equal(output, before),
          "null_output_rejected");

    wire::ContextObservation alias = input;
    const wire::ContextObservation before_alias = alias;
    const auto alias_result = wire::encode(
        alias,
        reinterpret_cast<unsigned char*>(&alias),
        wire::kMaxWireBytes);
    check(!alias_result.succeeded(), "whole_observation_alias_rejected");
    check(std::memcmp(&alias, &before_alias, sizeof(alias)) == 0,
          "whole_observation_alias_unchanged");

    wire::ContextObservation context_alias = input;
    const wire::ContextObservation before_context_alias = context_alias;
    const auto context_alias_result = wire::encode(
        context_alias,
        reinterpret_cast<unsigned char*>(
            context_alias.context.sides[0].participants.full_refs.data()),
        wire::kMaxWireBytes);
    check(!context_alias_result.succeeded(), "context_member_alias_rejected");
    check(std::memcmp(&context_alias, &before_context_alias,
                      sizeof(context_alias)) == 0,
          "context_member_alias_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-context-wire-v2\n");
    test_observed_and_no_context();
    test_maximum_vectors();
    test_invalid_context_and_flags();
    test_atomic_output_and_alias();
    std::printf("SUMMARY checks=%u failures=%u\n", g_checks, g_failures);
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
