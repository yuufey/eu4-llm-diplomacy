#include "information-battle-owned-context.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace context = information::battle::owned_context;

namespace {

constexpr context::Address kModuleBase = UINT64_C(0x140000000);
constexpr std::size_t kImageBytes = 0x1d30000u;
constexpr context::Address kCombat = UINT64_C(0x200000000);
constexpr context::Address kSideA = UINT64_C(0x210000000);
constexpr context::Address kSideB = UINT64_C(0x210001000);
constexpr context::Address kRowsA = UINT64_C(0x220000000);
constexpr context::Address kRowsB = UINT64_C(0x220010000);
constexpr context::Address kWar = UINT64_C(0x230000000);
constexpr context::Address kMembersA = UINT64_C(0x230001000);
constexpr context::Address kMembersB = UINT64_C(0x230003000);
constexpr std::size_t kSegmentBytes = 16384u;
constexpr std::size_t kMaxSegments = 16u;
constexpr std::uint64_t kPhysicalPlayer = UINT64_C(0x0100007a00415246);
constexpr std::uint64_t kOtherCountry = UINT64_C(0x0100007500525542);
constexpr std::uint64_t kParticipantA = UINT64_C(0x0100007100474e45);
constexpr std::uint64_t kParticipantB = UINT64_C(0x0100007200474e45);

constexpr std::uint64_t with_serial(std::uint64_t base,
                                    std::size_t serial) noexcept {
    return (base & UINT64_C(0x0000000000ffffff))
        | ((base & UINT64_C(0xffffffff00000000))
           + (static_cast<std::uint64_t>(serial) << 32u));
}

struct Segment {
    context::Address address = 0;
    std::size_t size = 0;
    std::array<unsigned char, kSegmentBytes> bytes{};
};

struct SparseReader {
    std::array<Segment, kMaxSegments> segments{};
    std::size_t count = 0;
    std::size_t read_calls = 0;
    std::size_t bytes_requested = 0;
    std::size_t fail_after_bytes = std::numeric_limits<std::size_t>::max();
    std::size_t mutate_on_call = 0;
    context::Address mutate_address = 0;
    std::array<unsigned char, 8> mutate_bytes{};
    context::Address mutate_trigger_address = 0;
    std::size_t mutate_trigger_read_number = 0;
    std::size_t mutate_trigger_reads = 0;

    void clear() noexcept { *this = SparseReader{}; }

    bool add(context::Address address, const void* source,
             std::size_t size) noexcept {
        if (source == nullptr || size == 0u || size > kSegmentBytes
                || count >= segments.size()) {
            return false;
        }
        Segment& segment = segments[count++];
        segment.address = address;
        segment.size = size;
        std::memcpy(segment.bytes.data(), source, size);
        return true;
    }

    bool write(context::Address address, const void* source,
               std::size_t size) noexcept {
        if (source == nullptr || size == 0u) return false;
        for (std::size_t index = 0; index < count; ++index) {
            Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(segment.bytes.data() + (address - segment.address),
                        source, size);
            return true;
        }
        return false;
    }

    bool read(context::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        if (destination == nullptr || size == 0u
                || bytes_requested > fail_after_bytes
                || size > fail_after_bytes - bytes_requested) {
            return false;
        }
        if (mutate_on_call != 0u && read_calls == mutate_on_call) {
            write(mutate_address, mutate_bytes.data(), mutate_bytes.size());
        }
        if (mutate_trigger_address != 0u
                && address == mutate_trigger_address) {
            ++mutate_trigger_reads;
            if (mutate_trigger_read_number != 0u
                    && mutate_trigger_reads == mutate_trigger_read_number) {
                write(mutate_address, mutate_bytes.data(), mutate_bytes.size());
            }
        }
        for (std::size_t index = 0; index < count; ++index) {
            const Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(destination,
                        segment.bytes.data() + (address - segment.address),
                        size);
            bytes_requested += size;
            return true;
        }
        return false;
    }
};

static_assert(context::reader_contract<SparseReader>::value,
              "synthetic seam must match exact noexcept reader contract");

struct BadReader {
    bool read(context::Address, unsigned char*, std::size_t) { return true; }
};

static_assert(!context::reader_contract<BadReader>::value,
              "throwing-capable seam must be rejected");

unsigned checks = 0;
unsigned failures = 0;

void check(bool condition, const char* label) noexcept {
    ++checks;
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) ++failures;
}

void put_u64(std::array<unsigned char, kSegmentBytes>& bytes,
             std::size_t offset, std::uint64_t value) noexcept {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void put_i32(std::array<unsigned char, kSegmentBytes>& bytes,
             std::size_t offset, std::int32_t value) noexcept {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void put_u64_at(SparseReader& reader, context::Address address,
                std::uint64_t value) noexcept {
    reader.write(address, &value, sizeof(value));
}

bool build_fixture(SparseReader& reader, bool with_war,
                   std::size_t side_a_count = 2u,
                   std::size_t side_b_count = 1u,
                   std::size_t war_a_count = 2u,
                   std::size_t war_b_count = 1u) noexcept {
    reader.clear();
    if (side_a_count > context::kMaxParticipants
            || side_b_count > context::kMaxParticipants
            || war_a_count > context::kMaxWarMembers
            || war_b_count > context::kMaxWarMembers) return false;

    std::array<unsigned char, kSegmentBytes> module{};
    put_u64(module, 0x160u, kModuleBase + 0x300u);
    module[0x300u] = 0xb8u;
    module[0x301u] = 1u;
    module[0x302u] = 0u;
    module[0x303u] = 0u;
    module[0x304u] = 0u;
    module[0x305u] = 0xc3u;
    if (!reader.add(kModuleBase, module.data(), module.size())) return false;

    std::array<unsigned char, kSegmentBytes> combat{};
    put_u64(combat, 0u, kModuleBase + 0x100u);
    put_u64(combat, context::kCombatSideAOffset, side_a_count ? kSideA : 0u);
    put_u64(combat, context::kCombatSideBOffset, side_b_count ? kSideB : 0u);
    if (!reader.add(kCombat, combat.data(), 0x100u)) return false;

    std::array<unsigned char, kSegmentBytes> side_a{};
    std::array<unsigned char, kSegmentBytes> side_b{};
    const context::Address side_a_end = kRowsA
        + static_cast<context::Address>(side_a_count * context::kParticipantRowBytes);
    const context::Address side_b_end = kRowsB
        + static_cast<context::Address>(side_b_count * context::kParticipantRowBytes);
    put_u64(side_a, context::kParticipantBeginOffset,
            side_a_count ? kRowsA : 0u);
    put_u64(side_a, context::kParticipantEndOffset,
            side_a_count ? side_a_end : 0u);
    put_u64(side_b, context::kParticipantBeginOffset,
            side_b_count ? kRowsB : 0u);
    put_u64(side_b, context::kParticipantEndOffset,
            side_b_count ? side_b_end : 0u);
    for (std::size_t i = 0; i < context::kSideRawFieldOffsets.size(); ++i) {
        put_i32(side_a, context::kSideRawFieldOffsets[i],
                static_cast<std::int32_t>(100 + i));
        put_i32(side_b, context::kSideRawFieldOffsets[i],
                static_cast<std::int32_t>(-200 - static_cast<int>(i)));
    }
    if (!reader.add(kSideA, side_a.data(), 0x200u)
            || !reader.add(kSideB, side_b.data(), 0x200u)) return false;

    std::array<unsigned char, kSegmentBytes> rows_a{};
    std::array<unsigned char, kSegmentBytes> rows_b{};
    for (std::size_t i = 0; i < side_a_count; ++i) {
        const std::uint64_t value = i == 0u ? kPhysicalPlayer
            : with_serial(kParticipantA, i);
        put_u64(rows_a, i * context::kParticipantRowBytes
                            + context::kParticipantFullRefOffset, value);
    }
    for (std::size_t i = 0; i < side_b_count; ++i) {
        const std::uint64_t value = with_serial(kParticipantB, i);
        put_u64(rows_b, i * context::kParticipantRowBytes
                            + context::kParticipantFullRefOffset, value);
    }
    if ((side_a_count && !reader.add(kRowsA, rows_a.data(),
                                     side_a_count * context::kParticipantRowBytes))
            || (side_b_count && !reader.add(kRowsB, rows_b.data(),
                                             side_b_count * context::kParticipantRowBytes))) {
        return false;
    }

    if (with_war) {
        std::array<unsigned char, kSegmentBytes> war{};
        put_u64(war, context::kWarHistoryRootOffset,
                kModuleBase + context::kWarHistoryRootVtableRva);
        put_u64(war, 0x48u, war_a_count ? kMembersA : 0u);
        put_u64(war, 0x50u, war_a_count ? kMembersA + war_a_count * 8u : 0u);
        put_u64(war, 0x58u, war_a_count ? kMembersA + war_a_count * 8u : 0u);
        put_u64(war, 0x78u, war_b_count ? kMembersB : 0u);
        put_u64(war, 0x80u, war_b_count ? kMembersB + war_b_count * 8u : 0u);
        put_u64(war, 0x88u, war_b_count ? kMembersB + war_b_count * 8u : 0u);
        if (!reader.add(kWar, war.data(), 0x200u)) return false;

        std::array<unsigned char, kSegmentBytes> members_a{};
        std::array<unsigned char, kSegmentBytes> members_b{};
        for (std::size_t i = 0; i < war_a_count; ++i) {
            const std::uint64_t value = i == 0u ? kPhysicalPlayer
                : with_serial(kParticipantA, 100u + i);
            put_u64(members_a, i * 8u, value);
        }
        for (std::size_t i = 0; i < war_b_count; ++i) {
            put_u64(members_b, i * 8u,
                    with_serial(kOtherCountry, 100u + i));
        }
        if ((war_a_count && !reader.add(kMembersA, members_a.data(),
                                        war_a_count * 8u))
                || (war_b_count && !reader.add(kMembersB, members_b.data(),
                                                war_b_count * 8u))) return false;
    }
    return true;
}

bool same_snapshot(const context::Snapshot& left,
                   const context::Snapshot& right) noexcept {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

context::Snapshot sentinel() noexcept {
    context::Snapshot output{};
    std::array<unsigned char, sizeof(output)> bytes{};
    bytes.fill(0xa5u);
    std::memcpy(&output, bytes.data(), bytes.size());
    return output;
}

void test_valid_context() noexcept {
    std::printf("TEST valid_context\n");
    SparseReader reader;
    check(build_fixture(reader, true), "fixture_build");
    context::Snapshot output{};
    const bool copied = context::capture(reader, kModuleBase, kImageBytes,
                                         kCombat, true, kWar,
                                         kPhysicalPlayer, output);
    check(copied, "capture_land");
    check(output.kind == context::Kind::land, "kind_land");
    check(output.raw_selector == 1u && output.selector_code_verified,
          "leaf_selector_proof");
    check(output.sides[0].present && output.sides[1].present,
          "both_raw_sides_present");
    check(output.sides[0].participants.count == 2u
              && output.sides[1].participants.count == 1u,
          "participant_counts");
    check(output.sides[0].participants.full_refs[0] == kPhysicalPlayer,
          "row_plus_10_ref");
    check(output.sides[0].raw_fields[0] == 100
              && output.sides[0].raw_fields[5] == 105,
          "raw_initial_loss_fields");
    check(output.war_context_status == context::WarContextStatus::observed
              && output.war_members.vectors_complete
              && output.war_members.physical_player_membership_known
              && output.war_members.physical_player_is_war_member,
          "war_membership_observed");
    check(reader.bytes_requested <= context::kMaxReadBudgetBytes,
          "read_budget_bound");
    const context::Snapshot preserved = output;
    std::array<unsigned char, 1> changed{{0x7fu}};
    reader.write(kRowsA + context::kParticipantFullRefOffset,
                 changed.data(), changed.size());
    check(same_snapshot(output, preserved), "owned_copy_survives_source_change");
}

void test_naval_empty_and_invalid_war() noexcept {
    std::printf("TEST naval_empty_and_invalid_war\n");
    SparseReader reader;
    check(build_fixture(reader, false, 0u, 0u), "empty_fixture_build");
    std::array<unsigned char, 6> naval{{0xb8u, 2u, 0u, 0u, 0u, 0xc3u}};
    reader.write(kModuleBase + 0x300u, naval.data(), naval.size());
    context::Snapshot output{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                           0u, kPhysicalPlayer, output), "capture_naval_empty");
    check(output.kind == context::Kind::naval
              && !output.sides[0].present && !output.sides[1].present,
          "naval_empty_sides");
    check(output.war_context_status == context::WarContextStatus::absent,
          "war_not_requested_absent");

    check(build_fixture(reader, true, 1u, 1u), "invalid_war_fixture_build");
    std::array<unsigned char, 8> bad_root{};
    put_u64_at(reader, kWar + context::kWarHistoryRootOffset,
               kModuleBase + 0x999u);
    (void)bad_root;
    output = context::Snapshot{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output),
          "combat_survives_invalid_optional_war");
    check(output.war_context_status == context::WarContextStatus::invalid
              && !output.war_members.physical_player_membership_known,
          "invalid_war_is_unknown_not_false");
}

void test_leaf_and_vector_failures() noexcept {
    std::printf("TEST leaf_and_vector_failures\n");
    SparseReader reader;
    check(build_fixture(reader, false), "failure_fixture_build");
    context::Snapshot output = sentinel();
    const context::Snapshot before = output;
    std::array<unsigned char, 6> al_only{{0xb0u, 1u, 0xc3u, 0x90u, 0x90u, 0xc3u}};
    reader.write(kModuleBase + 0x300u, al_only.data(), al_only.size());
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output), "al_only_leaf_rejected");
    check(same_snapshot(output, before), "al_only_output_unchanged");

    check(build_fixture(reader, false), "unstable_fixture_build");
    output = sentinel();
    const context::Snapshot unstable_before = output;
    reader.mutate_on_call = 8u;
    reader.mutate_address = kModuleBase + 0x300u;
    reader.mutate_bytes = {{0xb8u, 2u, 0u, 0u, 0u, 0xc3u}};
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output), "unstable_leaf_rejected");
    check(same_snapshot(output, unstable_before), "unstable_output_unchanged");

    check(build_fixture(reader, false), "bad_vector_fixture_build");
    put_u64_at(reader, kSideA + context::kParticipantEndOffset,
                kRowsA + 0x10u);
    output = sentinel();
    const context::Snapshot bad_vector_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output), "bad_vector_rejected");
    check(same_snapshot(output, bad_vector_before), "bad_vector_output_unchanged");

    check(build_fixture(reader, false), "budget_fixture_build");
    reader.fail_after_bytes = 64u;
    output = sentinel();
    const context::Snapshot budget_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output), "reader_budget_failure");
    check(same_snapshot(output, budget_before), "budget_output_unchanged");
}

void test_reference_and_post_copy_guards() noexcept {
    std::printf("TEST reference_and_post_copy_guards\n");
    SparseReader reader;
    check(build_fixture(reader, false), "reference_fixture_build");

    context::Snapshot output = sentinel();
    const context::Snapshot before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, 0u, output), "invalid_physical_ref_rejected");
    check(same_snapshot(output, before), "invalid_physical_output_unchanged");

    check(build_fixture(reader, false), "invalid_participant_fixture_build");
    put_u64_at(reader, kRowsA + context::kParticipantFullRefOffset, 0u);
    output = sentinel();
    const context::Snapshot invalid_participant_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "invalid_participant_ref_rejected");
    check(same_snapshot(output, invalid_participant_before),
          "invalid_participant_output_unchanged");

    check(build_fixture(reader, false), "post_copy_code_fixture_build");
    reader.mutate_trigger_address = kModuleBase + 0x300u;
    reader.mutate_trigger_read_number = 2u;
    reader.mutate_address = kModuleBase + 0x300u;
    reader.mutate_bytes = {{0xb8u, 2u, 0u, 0u, 0u, 0xc3u}};
    output = sentinel();
    const context::Snapshot changed_code_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "post_copy_code_change_rejected");
    check(same_snapshot(output, changed_code_before),
          "post_copy_code_output_unchanged");

    check(build_fixture(reader, false), "post_copy_slot_fixture_build");
    std::array<unsigned char, 8> alternate_slot{};
    const std::uint64_t alternate_code = kModuleBase + 0x400u;
    std::memcpy(alternate_slot.data(), &alternate_code, sizeof(alternate_code));
    std::array<unsigned char, 6> alternate_body{{0xb8u, 2u, 0u, 0u, 0u, 0xc3u}};
    reader.write(kModuleBase + 0x400u, alternate_body.data(), alternate_body.size());
    reader.mutate_trigger_address = kModuleBase + 0x160u;
    reader.mutate_trigger_read_number = 2u;
    reader.mutate_address = kModuleBase + 0x160u;
    reader.mutate_bytes = alternate_slot;
    output = sentinel();
    const context::Snapshot changed_slot_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "post_copy_slot_change_rejected");
    check(same_snapshot(output, changed_slot_before),
          "post_copy_slot_output_unchanged");

    check(build_fixture(reader, false), "post_copy_vtable_fixture_build");
    std::array<unsigned char, 8> alternate_vtable{};
    const std::uint64_t alternate_vtable_address = kModuleBase + 0x200u;
    std::memcpy(alternate_vtable.data(), &alternate_vtable_address,
                sizeof(alternate_vtable_address));
    std::array<unsigned char, kSegmentBytes> alternate_module{};
    put_u64(alternate_module, 0x60u, kModuleBase + 0x300u);
    reader.write(kModuleBase + 0x200u, alternate_module.data(), 0x68u);
    reader.mutate_trigger_address = kCombat;
    reader.mutate_trigger_read_number = 3u;
    reader.mutate_address = kCombat;
    reader.mutate_bytes = alternate_vtable;
    output = sentinel();
    const context::Snapshot changed_vtable_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "post_copy_vtable_change_rejected");
    check(same_snapshot(output, changed_vtable_before),
          "post_copy_vtable_output_unchanged");

    check(build_fixture(reader, false), "stable_ref_fixture_build");
    reader.mutate_trigger_address = kRowsA + context::kParticipantFullRefOffset;
    reader.mutate_trigger_read_number = 1u;
    reader.mutate_address = kRowsA + context::kParticipantFullRefOffset;
    reader.mutate_bytes = {{0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};
    output = sentinel();
    const context::Snapshot changed_ref_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "post_copy_ref_change_rejected");
    check(same_snapshot(output, changed_ref_before),
          "post_copy_ref_output_unchanged");
}

void test_optional_war_guards() noexcept {
    std::printf("TEST optional_war_guards\n");
    SparseReader reader;
    check(build_fixture(reader, true), "war_guard_fixture_build");

    context::Snapshot output = sentinel();
    const context::Snapshot before = output;
    const context::Address output_address =
        reinterpret_cast<context::Address>(&output);
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                            output_address, kPhysicalPlayer, output),
          "optional_war_output_alias_fatal");
    check(same_snapshot(output, before), "optional_war_alias_output_unchanged");

    check(build_fixture(reader, true), "duplicate_war_fixture_build");
    put_u64_at(reader, kMembersB, kPhysicalPlayer);
    output = sentinel();
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output),
          "duplicate_war_downgrades_to_invalid");
    check(output.war_context_status == context::WarContextStatus::invalid
              && !output.war_members.physical_player_membership_known,
          "duplicate_war_is_not_membership_false");

    check(build_fixture(reader, true), "invalid_tag_war_fixture_build");
    put_u64_at(reader, kMembersB, UINT64_C(0x0100000000000001));
    output = sentinel();
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output),
          "invalid_tag_war_downgrades_to_invalid");
    check(output.war_context_status == context::WarContextStatus::invalid
              && !output.war_members.physical_player_membership_known,
          "invalid_tag_war_is_unknown");

    check(build_fixture(reader, true), "war_root_stability_fixture_build");
    reader.mutate_trigger_address = kWar + context::kWarHistoryRootOffset;
    reader.mutate_trigger_read_number = 2u;
    reader.mutate_address = kWar + context::kWarHistoryRootOffset;
    reader.mutate_bytes = {};
    const std::uint64_t changed_root = kModuleBase + 0x999u;
    std::memcpy(reader.mutate_bytes.data(), &changed_root, sizeof(changed_root));
    output = sentinel();
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output),
          "changed_war_root_downgrades_to_invalid");
    check(output.war_context_status == context::WarContextStatus::invalid,
          "changed_war_root_is_unknown");

    check(build_fixture(reader, false), "bounded_budget_fixture_build");
    std::array<unsigned char, kSegmentBytes> bytes{};
    std::array<unsigned char, kSegmentBytes> destination{};
    const context::Address output_begin =
        reinterpret_cast<context::Address>(&output);
    const context::Address output_end = output_begin + sizeof(output);
    context::detail::BoundedReader<SparseReader> bounded(
        reader, output_begin, output_end);
    bool all_reads = true;
    for (unsigned i = 0u; i < 5u; ++i) {
        all_reads = bounded.read(kModuleBase, destination.data(), bytes.size())
            && all_reads;
    }
    check(!all_reads && bounded.fatal(), "bounded_budget_fatal_latched");
}

void test_empty_vector_bounds() noexcept {
    std::printf("TEST empty_vector_bounds\n");
    SparseReader reader;
    check(build_fixture(reader, false, 0u, 0u), "empty_core_fixture_build");
    put_u64_at(reader, kCombat + context::kCombatSideAOffset, kSideA);
    put_u64_at(reader, kCombat + context::kCombatSideBOffset, kSideB);
    const context::Address empty_a = kRowsA + 0x100u;
    const context::Address empty_b = kRowsB + 0x100u;
    put_u64_at(reader, kSideA + context::kParticipantBeginOffset, empty_a);
    put_u64_at(reader, kSideA + context::kParticipantEndOffset, empty_a);
    put_u64_at(reader, kSideB + context::kParticipantBeginOffset, empty_b);
    put_u64_at(reader, kSideB + context::kParticipantEndOffset, empty_b);
    context::Snapshot output{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                           0u, kPhysicalPlayer, output),
          "allocated_empty_core_accepted");
    check(output.sides[0].present && output.sides[1].present
              && output.sides[0].participants.count == 0u
              && output.sides[1].participants.count == 0u,
          "allocated_empty_core_shape");

    check(build_fixture(reader, false, 0u, 0u), "noncanonical_empty_fixture_build");
    put_u64_at(reader, kCombat + context::kCombatSideAOffset, kSideA);
    put_u64_at(reader, kSideA + context::kParticipantBeginOffset, 1u);
    put_u64_at(reader, kSideA + context::kParticipantEndOffset, 1u);
    output = sentinel();
    const context::Snapshot noncanonical_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "noncanonical_empty_core_rejected");
    check(same_snapshot(output, noncanonical_before),
          "noncanonical_empty_core_unchanged");

    check(build_fixture(reader, false, 0u, 0u), "misaligned_empty_fixture_build");
    put_u64_at(reader, kCombat + context::kCombatSideAOffset, kSideA);
    put_u64_at(reader, kSideA + context::kParticipantBeginOffset, kRowsA + 1u);
    put_u64_at(reader, kSideA + context::kParticipantEndOffset, kRowsA + 1u);
    output = sentinel();
    const context::Snapshot misaligned_before = output;
    check(!context::capture(reader, kModuleBase, kImageBytes, kCombat, false,
                            0u, kPhysicalPlayer, output),
          "misaligned_empty_core_rejected");
    check(same_snapshot(output, misaligned_before),
          "misaligned_empty_core_unchanged");

    check(build_fixture(reader, true, 0u, 0u, 0u, 0u),
          "allocated_empty_war_fixture_build");
    put_u64_at(reader, kWar + 0x48u, kMembersA);
    put_u64_at(reader, kWar + 0x50u, kMembersA);
    put_u64_at(reader, kWar + 0x58u, kMembersA);
    put_u64_at(reader, kWar + 0x78u, kMembersB);
    put_u64_at(reader, kWar + 0x80u, kMembersB);
    put_u64_at(reader, kWar + 0x88u, kMembersB);
    output = context::Snapshot{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output),
          "allocated_empty_war_accepted");
    check(output.war_context_status == context::WarContextStatus::observed
              && output.war_members.side_a_count == 0u
              && output.war_members.side_b_count == 0u
              && output.war_members.physical_player_membership_known
              && !output.war_members.physical_player_is_war_member,
          "allocated_empty_war_shape");
}

void test_max_vectors_and_alias() noexcept {
    std::printf("TEST max_vectors_and_alias\n");
    SparseReader reader;
    check(build_fixture(reader, true, context::kMaxParticipants,
                        context::kMaxParticipants, context::kMaxWarMembers,
                        context::kMaxWarMembers), "max_vector_fixture_build");
    context::Snapshot output{};
    check(context::capture(reader, kModuleBase, kImageBytes, kCombat, true,
                           kWar, kPhysicalPlayer, output), "max_vectors_capture");
    check(output.sides[0].participants.count == context::kMaxParticipants
              && output.sides[1].participants.count == context::kMaxParticipants,
          "max_combat_vectors");
    check(output.war_members.side_a_count == context::kMaxWarMembers
              && output.war_members.side_b_count == context::kMaxWarMembers,
          "max_war_vectors");
    check(reader.bytes_requested <= context::kMaxReadBudgetBytes,
          "max_vectors_budget");

    check(build_fixture(reader, false), "alias_fixture_build");
    context::Snapshot aliased = sentinel();
    const context::Snapshot before = aliased;
    const context::Address output_address =
        reinterpret_cast<context::Address>(&aliased);
    std::array<unsigned char, 0x100u> source{};
    const std::uint64_t source_vtable = kModuleBase + 0x100u;
    std::memcpy(source.data(), &source_vtable, sizeof(source_vtable));
    reader.add(output_address, source.data(), source.size());
    check(!context::capture(reader, kModuleBase, kImageBytes, output_address,
                            false, 0u, kPhysicalPlayer, aliased),
          "source_output_alias_rejected");
    check(same_snapshot(aliased, before), "alias_output_unchanged");
}

void test_bad_module_and_address() noexcept {
    std::printf("TEST bad_module_and_address\n");
    SparseReader reader;
    check(build_fixture(reader, false), "address_fixture_build");
    context::Snapshot output = sentinel();
    const context::Snapshot before = output;
    check(!context::capture(reader, kModuleBase, 0x100u, kCombat, false,
                            0u, kPhysicalPlayer, output), "small_image_rejected");
    check(same_snapshot(output, before), "small_image_output_unchanged");
    check(!context::capture(reader, context::kMaxCanonicalExclusive - 0x100u,
                            0x200u, kCombat, false, 0u, kPhysicalPlayer,
                            output), "noncanonical_image_rejected");
    check(same_snapshot(output, before), "noncanonical_image_output_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-context\n");
    test_valid_context();
    test_naval_empty_and_invalid_war();
    test_leaf_and_vector_failures();
    test_reference_and_post_copy_guards();
    test_optional_war_guards();
    test_empty_vector_bounds();
    test_max_vectors_and_alias();
    test_bad_module_and_address();
    std::printf("SUMMARY checks=%u failures=%u\n", checks, failures);
    std::printf("RESULT %s\n", failures == 0u ? "PASS" : "FAIL");
    return failures == 0u ? 0 : 1;
}
