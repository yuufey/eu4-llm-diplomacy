#include "../information-battle-owned-retreat.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace owned = information::battle::owned_retreat;
namespace wire = information::battle::retreat_wire;

namespace {

using Address = owned::Address;

constexpr Address kCombat = UINT64_C(0x220000000);
constexpr Address kSide0 = UINT64_C(0x220001000);
constexpr Address kSide1 = UINT64_C(0x220002000);
constexpr Address kNodes = UINT64_C(0x220010000);
constexpr Address kUnits = UINT64_C(0x220020000);
constexpr std::size_t kNodeStride = 0x20u;
constexpr std::size_t kUnitStride = 0x300u;
constexpr std::size_t kRegionBytes = 0x30000u;
constexpr std::size_t kSegmentCount = 8u;
constexpr std::size_t kMaxFixtureUnits = owned::kMaxUnits + 1u;

struct Segment final {
    Address base = 0u;
    std::size_t size = 0u;
    std::array<unsigned char, kRegionBytes> bytes{};
};

struct FakeReader final {
    std::array<Segment, kSegmentCount> segments{};
    std::size_t segment_count = 0u;
    std::size_t read_calls = 0u;
    std::size_t read_bytes = 0u;
    std::size_t fail_call = 0u;
    Address mutate_trigger_address = 0u;
    std::size_t mutate_trigger_occurrence = 0u;
    std::size_t mutate_seen = 0u;
    Address mutate_address = 0u;
    std::array<unsigned char, 32u> mutate_value{};
    std::size_t mutate_size = 0u;
    bool mutated = false;

    void reset() noexcept { *this = FakeReader{}; }

    static bool range_end(Address base, std::size_t size,
                          Address& end) noexcept {
        if (size == 0u || base > UINT64_MAX - size) return false;
        end = base + static_cast<Address>(size);
        return end > base;
    }

    bool add_region(Address base, std::size_t size) noexcept {
        if (segment_count >= segments.size() || size == 0u
                || size > kRegionBytes) return false;
        Address end = 0u;
        if (!range_end(base, size, end)) return false;
        for (std::size_t index = 0u; index < segment_count; ++index) {
            Address old_end = 0u;
            if (!range_end(segments[index].base, segments[index].size,
                           old_end)) return false;
            if (base < old_end && segments[index].base < end) return false;
        }
        Segment& segment = segments[segment_count++];
        segment.base = base;
        segment.size = size;
        std::fill(segment.bytes.begin(), segment.bytes.end(), 0u);
        return true;
    }

    Segment* find(Address address, std::size_t size) noexcept {
        for (std::size_t index = 0u; index < segment_count; ++index) {
            Segment& segment = segments[index];
            if (address < segment.base
                    || address - segment.base > segment.size
                    || size > segment.size - static_cast<std::size_t>(
                                   address - segment.base)) continue;
            return &segment;
        }
        return nullptr;
    }

    bool put(Address address, const void* source, std::size_t size) noexcept {
        if (source == nullptr || size == 0u) return false;
        Segment* segment = find(address, size);
        if (segment == nullptr) return false;
        std::memcpy(segment->bytes.data() + static_cast<std::size_t>(
                         address - segment->base), source, size);
        return true;
    }

    bool put_u64(Address address, std::uint64_t value) noexcept {
        return put(address, &value, sizeof(value));
    }

    bool put_bytes(Address address, const unsigned char* source,
                   std::size_t size) noexcept {
        return put(address, source, size);
    }

    void mutate_before_read(Address trigger_address, std::size_t occurrence,
                            Address address, const void* value,
                            std::size_t size) noexcept {
        mutate_trigger_address = trigger_address;
        mutate_trigger_occurrence = occurrence;
        mutate_seen = 0u;
        mutate_address = address;
        mutate_size = size;
        std::fill(mutate_value.begin(), mutate_value.end(), 0u);
        if (size <= mutate_value.size()) {
            std::memcpy(mutate_value.data(), value, size);
        } else {
            mutate_size = 0u;
        }
        mutated = false;
    }

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        read_bytes += size;
        if (address == mutate_trigger_address) {
            ++mutate_seen;
            if (!mutated && mutate_trigger_occurrence != 0u
                    && mutate_seen == mutate_trigger_occurrence) {
                mutated = true;
                (void)put(mutate_address, mutate_value.data(), mutate_size);
            }
        }
        if (read_calls == fail_call || destination == nullptr || size == 0u) {
            return false;
        }
        Segment* segment = find(address, size);
        if (segment == nullptr) return false;
        std::memcpy(destination, segment->bytes.data() + static_cast<std::size_t>(
                         address - segment->base), size);
        return true;
    }
};

static_assert(owned::reader_contract<FakeReader>::value,
              "FakeReader must match the noexcept read seam");

struct Fixture final {
    FakeReader reader{};
    std::array<Address, kMaxFixtureUnits> units{};
    std::array<Address, kMaxFixtureUnits> nodes{};
    std::size_t count = 0u;
    std::size_t side0_count = 0u;

    Address node(std::size_t index) const noexcept { return nodes[index]; }
    Address unit(std::size_t index) const noexcept { return units[index]; }

    bool build(std::size_t requested) noexcept {
        reader.reset();
        units.fill(0u);
        nodes.fill(0u);
        count = requested;
        side0_count = (requested + 1u) / 2u;
        if (requested == 0u || requested > kMaxFixtureUnits) return false;
        const std::size_t node_bytes = requested * kNodeStride;
        const std::size_t unit_bytes = requested * kUnitStride;
        if (!reader.add_region(kCombat, 0x100u)
                || !reader.add_region(kSide0, 0x200u)
                || !reader.add_region(kSide1, 0x200u)
                || !reader.add_region(kNodes, node_bytes)
                || !reader.add_region(kUnits, unit_bytes)) return false;

        if (!reader.put_u64(kCombat + owned::kCombatSidesOffset, kSide0)
                || !reader.put_u64(kCombat + owned::kCombatSidesOffset
                                      + sizeof(Address), kSide1)
                || !reader.put_u64(kSide0 + owned::kSideParentOffset, kCombat)
                || !reader.put_u64(kSide1 + owned::kSideParentOffset, kCombat)) {
            return false;
        }

        std::size_t side0_index = 0u;
        std::size_t side1_index = side0_count;
        Address side0_head = 0u;
        Address side1_head = 0u;
        for (std::size_t index = 0u; index < requested; ++index) {
            nodes[index] = kNodes + index * kNodeStride;
            units[index] = kUnits + index * kUnitStride;
            const bool first_side = index < side0_count;
            const std::size_t side_position = first_side
                ? side0_index++ : side1_index++;
            const Address next = first_side
                ? (side_position + 1u < side0_count
                       ? kNodes + (index + 1u) * kNodeStride : 0u)
                : (side_position + 1u < requested
                       ? kNodes + (index + 1u) * kNodeStride : 0u);
            if (first_side && side0_head == 0u) side0_head = nodes[index];
            if (!first_side && side1_head == 0u) side1_head = nodes[index];
            const std::uint64_t owner = index == 0u
                ? UINT64_C(0xffffffffffffffff)
                : (index == 1u ? UINT64_C(0x0102030405060708)
                               : static_cast<std::uint64_t>(index + 0x100u));
            const std::array<unsigned char, 5u> flags{{
                static_cast<unsigned char>(index + 1u),
                static_cast<unsigned char>(0xa0u + index),
                static_cast<unsigned char>(index + 2u),
                static_cast<unsigned char>(index + 3u),
                static_cast<unsigned char>(index + 4u),
            }};
            if (!reader.put_u64(nodes[index] + owned::kNodeUnitOffset,
                                units[index])
                    || !reader.put_u64(nodes[index] + owned::kNodeNextOffset,
                                       next)
                    || !reader.put_u64(units[index]
                                           + owned::kUnitCombatOffset,
                                       kCombat)
                    || !reader.put_u64(units[index]
                                           + owned::kUnitOwnerFullRefOffset,
                                       owner)
                    || !reader.put_bytes(units[index]
                                             + owned::kUnitRawFlagsOffset,
                                         flags.data(), flags.size())) {
                return false;
            }
        }
        return reader.put_u64(kSide0 + owned::kSideLinkedHeadOffset,
                              side0_head)
            && reader.put_u64(kSide1 + owned::kSideLinkedHeadOffset,
                              side1_head);
    }
};

struct Harness final {
    unsigned checks = 0u;
    unsigned failures = 0u;

    void check(bool value, const char* name) noexcept {
        ++checks;
        if (!value) {
            ++failures;
            std::printf("FAIL:%s\n", name);
        }
    }
};

wire::Snapshot sentinel() noexcept {
    wire::Snapshot output{};
    output.sequence = 777u;
    output.raw_date = 56560000;
    output.kind = 2u;
    output.present = true;
    output.combat_side_index = 1u;
    output.initial_unit_count = 5u;
    output.observed_count = 1u;
    output.units[0] = {4u, UINT64_C(0x1122334455667788), {{9u, 8u, 7u, 6u}}};
    return output;
}

void test_known_owner_flags_wrong_return_and_finish_clear(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(4u), "fixture known build");

    owned::Scope winning_scope{};
    h.check(winning_scope.begin(fixture.reader, kCombat, kSide1),
            "begin winning-side rejection");
    wire::Snapshot winning_output = sentinel();
    const wire::Snapshot winning_before = winning_output;
    h.check(!winning_scope.observe(fixture.reader, fixture.unit(0u),
                                   owned::kObserveReturnRva),
            "winning-side observe rejected");
    h.check(!winning_scope.finish(42u, 56563608, 1u, true, winning_output),
            "winning-side finish rejected");
    h.check(std::memcmp(&winning_output, &winning_before,
                        sizeof(winning_output)) == 0,
            "winning-side output unchanged");

    owned::Scope scope{};
    h.check(scope.begin(fixture.reader, kCombat, kSide1), "begin known");
    const std::size_t before_wrong_return = fixture.reader.read_calls;
    h.check(!scope.observe(fixture.reader, fixture.unit(2u), 0x22bed0u),
            "wrong return false");
    h.check(scope.active() && fixture.reader.read_calls == before_wrong_return,
            "wrong return ignored");
    h.check(scope.observe(fixture.reader, fixture.unit(2u),
                          owned::kObserveReturnRva),
            "losing unit two observe true");
    h.check(scope.observe(fixture.reader, fixture.unit(3u),
                          owned::kObserveReturnRva),
            "losing unit three observe true");
    wire::Snapshot output{};
    const std::size_t before_finish = fixture.reader.read_calls;
    h.check(scope.finish(42u, 56563608, 1u, true, output), "finish known");
    h.check(fixture.reader.read_calls == before_finish,
            "finish performs no reads");
    h.check(!scope.active(), "finish clears active scope");
    h.check(output.present && output.capture_source == 0u
                && output.combat_side_index == 1u
                && output.initial_unit_count == 4u
                && output.observed_count == 2u,
            "known counts and losing side");
    h.check(output.units[0].ordinal == 2u
                && output.units[0].owner_full_ref == UINT64_C(0x102)
                && output.units[0].raw_flags == std::array<std::uint8_t, 4u>{{3u, 4u, 5u, 6u}},
            "first losing owner and raw flags");
    h.check(output.units[1].ordinal == 3u
                && output.units[1].owner_full_ref == UINT64_C(0x103)
                && output.units[1].raw_flags == std::array<std::uint8_t, 4u>{{4u, 5u, 6u, 7u}},
            "second losing owner and raw flags");
    const std::size_t after_finish = fixture.reader.read_calls;
    scope.observe(fixture.reader, fixture.unit(2u), owned::kObserveReturnRva);
    h.check(fixture.reader.read_calls == after_finish,
            "observe after finish does not read");
}

void test_removal_source_selects_unit_side_and_counts(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(4u), "removal side-zero fixture build");

    owned::Scope side_zero{};
    h.check(side_zero.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                    owned::kRemovalReturnRva),
            "removal begin selects side zero unit");
    const std::size_t before_regular_observe = fixture.reader.read_calls;
    h.check(!side_zero.observe(fixture.reader, fixture.unit(0u),
                              owned::kObserveReturnRva)
                && fixture.reader.read_calls == before_regular_observe
                && side_zero.active(),
            "removal scope rejects regular observer without reading");
    h.check(side_zero.observe_removal(fixture.reader, fixture.unit(0u),
                                      owned::kRemovalReturnRva),
            "removal observer captures side-zero unit");
    h.check(side_zero.observe_removal(fixture.reader, fixture.unit(1u),
                                      owned::kRemovalReturnRva),
            "removal observer captures second side-zero unit");

    wire::Snapshot side_zero_output{};
    h.check(side_zero.finish(43u, 56563608, 2u, true, side_zero_output),
            "side-zero removal finish");
    h.check(side_zero_output.present
                && side_zero_output.capture_source == owned::kRemovalCaptureSource
                && side_zero_output.combat_side_index == 0u
                && side_zero_output.initial_unit_count == 4u
                && side_zero_output.observed_count == 2u
                && side_zero_output.units[0].ordinal == 0u
                && side_zero_output.units[1].ordinal == 1u,
            "side-zero removal source and counts");

    h.check(fixture.build(4u), "removal side-one fixture build");
    owned::Scope side_one{};
    h.check(side_one.begin_removal(fixture.reader, kCombat, fixture.unit(2u),
                                   owned::kRemovalReturnRva),
            "removal begin selects side one unit");
    h.check(side_one.observe_removal(fixture.reader, fixture.unit(2u),
                                    owned::kRemovalReturnRva)
                && side_one.observe_removal(fixture.reader, fixture.unit(3u),
                                            owned::kRemovalReturnRva),
            "removal observer captures side-one units");
    wire::Snapshot side_one_output{};
    h.check(side_one.finish(44u, 56563608, 2u, true, side_one_output),
            "side-one removal finish");
    h.check(side_one_output.capture_source == owned::kRemovalCaptureSource
                && side_one_output.combat_side_index == 1u
                && side_one_output.initial_unit_count == 4u
                && side_one_output.observed_count == 2u
                && side_one_output.units[0].ordinal == 2u
                && side_one_output.units[1].ordinal == 3u,
            "side-one removal source and counts");
}

void test_removal_caller_membership_and_source_exclusion(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(4u), "removal caller fixture build");
    owned::Scope scope{};
    const std::size_t before_wrong_begin = fixture.reader.read_calls;
    h.check(!scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                 owned::kRegularEndingSourceRva)
                && !scope.active()
                && fixture.reader.read_calls == before_wrong_begin,
            "wrong removal begin caller rejected without reads");

    h.check(!scope.begin_removal(fixture.reader, kCombat,
                                 kUnits + 20u * kUnitStride,
                                 owned::kRemovalReturnRva)
                && !scope.active(),
            "removal begin rejects unit absent from either side");

    h.check(fixture.build(4u), "removal observe fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal observe scope begins");
    const std::size_t before_wrong_observer = fixture.reader.read_calls;
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kObserveReturnRva)
                && scope.active()
                && fixture.reader.read_calls == before_wrong_observer,
            "wrong removal observe caller ignored without reads");
    h.check(scope.observe_removal(fixture.reader, fixture.unit(0u),
                                  owned::kRemovalReturnRva),
            "valid removal observe after wrong caller");
    scope.clear();

    h.check(fixture.build(4u), "removal missing-observer fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal missing-observer scope begins");
    const std::size_t before_missing_observer = fixture.reader.read_calls;
    h.check(!scope.observe_removal(fixture.reader,
                                   kUnits + 20u * kUnitStride,
                                   owned::kRemovalReturnRva)
                && !scope.active()
                && fixture.reader.read_calls == before_missing_observer,
            "removal observer rejects nonmember without source read");

    h.check(fixture.build(2u), "removal duplicate membership fixture build");
    h.check(fixture.reader.put_u64(fixture.node(1u) + owned::kNodeUnitOffset,
                                   fixture.unit(0u)),
            "write duplicate removal member");
    h.check(!scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                 owned::kRemovalReturnRva)
                && !scope.active(),
            "removal begin rejects duplicate unit membership");
}

void test_removal_combat_and_two_read_drift_guards(Harness& h) {
    Fixture fixture{};
    owned::Scope scope{};
    h.check(fixture.build(2u), "removal combat fixture build");
    const Address other_combat = kCombat + 0x400u;
    h.check(fixture.reader.put_u64(fixture.unit(0u)
                                       + owned::kUnitCombatOffset,
                                   other_combat),
            "write cross-combat unit pointer");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "cross-combat observer scope begins from membership");
    const std::size_t before_cross_combat = fixture.reader.read_calls;
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && !scope.active()
                && fixture.reader.read_calls == before_cross_combat + 1u,
            "observer rejects unit whose combat pointer differs");

    h.check(fixture.build(2u), "removal side-drift fixture build");
    const Address changed_head = fixture.node(1u);
    fixture.reader.mutate_before_read(
        kCombat + owned::kCombatSidesOffset, 2u,
        kSide0 + owned::kSideLinkedHeadOffset,
        &changed_head, sizeof(changed_head));
    h.check(!scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                 owned::kRemovalReturnRva)
                && !scope.active() && fixture.reader.mutated,
            "removal begin rejects list drift between passes");

    h.check(fixture.build(2u), "removal owner-drift fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal owner-drift scope begins");
    const std::uint64_t changed_owner = UINT64_C(0xaabbccddeeff0011);
    fixture.reader.mutate_before_read(
        fixture.unit(0u) + owned::kUnitOwnerFullRefOffset, 2u,
        fixture.unit(0u) + owned::kUnitOwnerFullRefOffset,
        &changed_owner, sizeof(changed_owner));
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && !scope.active() && fixture.reader.mutated,
            "removal observer rejects owner drift between reads");

    h.check(fixture.build(2u), "removal flags-drift fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal flags-drift scope begins");
    const std::array<unsigned char, 5u> changed_flags{{9u, 8u, 7u, 6u, 5u}};
    fixture.reader.mutate_before_read(
        fixture.unit(0u) + owned::kUnitOwnerFullRefOffset, 2u,
        fixture.unit(0u) + owned::kUnitRawFlagsOffset,
        changed_flags.data(), changed_flags.size());
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && !scope.active() && fixture.reader.mutated,
            "removal observer rejects owner/flags drift between reads");

    h.check(fixture.build(2u), "removal combat-drift fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal combat-drift scope begins");
    h.check(fixture.reader.put_u64(fixture.unit(0u)
                                       + owned::kUnitCombatOffset,
                                   kCombat),
            "restore original combat before drift");
    fixture.reader.mutate_before_read(
        fixture.unit(0u) + owned::kUnitCombatOffset, 2u,
        fixture.unit(0u) + owned::kUnitCombatOffset,
        &other_combat, sizeof(other_combat));
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && !scope.active() && fixture.reader.mutated,
            "removal observer rejects combat pointer drift between reads");
}

void test_removal_duplicate_observe_finish_and_old_api_compatibility(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(2u), "removal duplicate-observe fixture build");
    owned::Scope scope{};
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(0u),
                                owned::kRemovalReturnRva),
            "removal duplicate-observe scope begins");
    h.check(scope.observe_removal(fixture.reader, fixture.unit(0u),
                                  owned::kRemovalReturnRva),
            "first removal observation succeeds");
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && !scope.active(),
            "duplicate removal observation invalidates scope");

    h.check(fixture.build(2u), "removal finish fixture build");
    h.check(scope.begin_removal(fixture.reader, kCombat, fixture.unit(1u),
                                owned::kRemovalReturnRva),
            "removal finish scope begins");
    wire::Snapshot output{};
    const std::size_t before_finish = fixture.reader.read_calls;
    h.check(scope.finish(45u, 56563608, 2u, true, output)
                && fixture.reader.read_calls == before_finish
                && output.capture_source == owned::kRemovalCaptureSource
                && output.combat_side_index == 1u
                && output.initial_unit_count == 2u
                && output.observed_count == 0u,
            "removal finish supports zero observations without further reads");
    const std::size_t after_finish = fixture.reader.read_calls;
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(1u),
                                   owned::kRemovalReturnRva)
                && fixture.reader.read_calls == after_finish,
            "removal observer after finish does not read");

    h.check(fixture.build(2u), "regular compatibility fixture build");
    h.check(scope.begin(fixture.reader, kCombat, kSide0),
            "regular API still begins with explicit losing side");
    const std::size_t before_removal_observe = fixture.reader.read_calls;
    h.check(!scope.observe_removal(fixture.reader, fixture.unit(0u),
                                   owned::kRemovalReturnRva)
                && scope.active()
                && fixture.reader.read_calls == before_removal_observe,
            "regular scope rejects removal observer without reading");
    h.check(scope.observe(fixture.reader, fixture.unit(0u),
                          owned::kObserveReturnRva),
            "regular observer API remains accepted");
    output = wire::Snapshot{};
    h.check(scope.finish(46u, 56563608, 1u, true, output)
                && output.capture_source == 0u
                && output.combat_side_index == 0u
                && output.initial_unit_count == 2u
                && output.observed_count == 1u,
            "regular source keeps source-zero snapshot behavior");
}

void test_begin_refuses_overlap_and_requires_stable_passes(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(4u), "fixture overlap build");
    owned::Scope scope{};
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "first begin");
    const std::size_t before_overlap = fixture.reader.read_calls;
    h.check(!scope.begin(fixture.reader, kCombat, kSide1),
            "active begin refused");
    h.check(fixture.reader.read_calls == before_overlap,
            "active begin performs no reads");
    scope.clear();

    h.check(fixture.build(4u), "fixture changed pass build");
    const Address changed_head = fixture.node(1u);
    fixture.reader.mutate_before_read(
        kCombat + owned::kCombatSidesOffset, 2u,
        kSide0 + owned::kSideLinkedHeadOffset,
        &changed_head, sizeof(changed_head));
    h.check(!scope.begin(fixture.reader, kCombat, kSide0),
            "changed list rejected");
    h.check(!scope.active(), "changed list clears scope");
}

void test_duplicate_nodes_units_and_overbound_list_fail_closed(Harness& h) {
    Fixture fixture{};
    owned::Scope scope{};
    h.check(fixture.build(4u), "fixture duplicate node build");
    h.check(fixture.reader.put_u64(fixture.node(1u) + owned::kNodeNextOffset,
                                  fixture.node(0u)), "write node cycle");
    h.check(!scope.begin(fixture.reader, kCombat, kSide0),
            "duplicate node rejected");
    h.check(!scope.active(), "duplicate node inactive");

    h.check(fixture.build(2u), "fixture duplicate unit build");
    h.check(fixture.reader.put_u64(fixture.node(1u) + owned::kNodeUnitOffset,
                                  fixture.unit(0u)), "write duplicate unit");
    h.check(!scope.begin(fixture.reader, kCombat, kSide0),
            "duplicate unit rejected");

    h.check(fixture.build(owned::kMaxUnits + 1u), "fixture overbound build");
    h.check(!scope.begin(fixture.reader, kCombat, kSide0),
            "129 units rejected");
}

void test_observe_mutation_duplicate_wrong_member_and_read_failure(Harness& h) {
    Fixture fixture{};
    owned::Scope scope{};
    h.check(fixture.build(2u), "fixture observe build");
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "observe begin");
    const std::array<unsigned char, 5u> changed{{9u, 9u, 9u, 9u, 9u}};
    fixture.reader.mutate_before_read(
        fixture.unit(0u) + owned::kUnitOwnerFullRefOffset, 2u,
        fixture.unit(0u) + owned::kUnitRawFlagsOffset,
        changed.data(), changed.size());
    scope.observe(fixture.reader, fixture.unit(0u), owned::kObserveReturnRva);
    h.check(!scope.active(), "changed unit invalidates");
    wire::Snapshot output = sentinel();
    const wire::Snapshot before = output;
    h.check(!scope.finish(42u, 56563608, 1u, true, output),
            "changed unit finish rejected");
    h.check(std::memcmp(&output, &before, sizeof(output)) == 0,
            "changed unit leaves output unchanged");

    h.check(fixture.build(2u), "fixture duplicate observe build");
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "duplicate observe begin");
    scope.observe(fixture.reader, fixture.unit(0u), owned::kObserveReturnRva);
    scope.observe(fixture.reader, fixture.unit(0u), owned::kObserveReturnRva);
    h.check(!scope.active(), "duplicate observe invalidates");

    h.check(fixture.build(2u), "fixture wrong member build");
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "wrong member begin");
    const std::size_t before_wrong_member = fixture.reader.read_calls;
    scope.observe(fixture.reader, kUnits + 0x10000u,
                  owned::kObserveReturnRva);
    h.check(!scope.active() && fixture.reader.read_calls == before_wrong_member,
            "wrong member invalidates without source read");

    h.check(fixture.build(2u), "fixture failed read build");
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "failed read begin");
    fixture.reader.fail_call = fixture.reader.read_calls + 1u;
    scope.observe(fixture.reader, fixture.unit(0u), owned::kObserveReturnRva);
    h.check(!scope.active(), "failed unit read invalidates");
}

void test_finish_guards_identity_output_and_zero_observation(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(3u), "fixture finish failure build");
    owned::Scope scope{};
    h.check(scope.begin(fixture.reader, kCombat, kSide1), "finish failure begin");
    wire::Snapshot output = sentinel();
    const wire::Snapshot before = output;
    const std::size_t before_finish = fixture.reader.read_calls;
    h.check(!scope.finish(42u, 56563608, 1u, false, output),
            "guards false rejected");
    h.check(std::memcmp(&output, &before, sizeof(output)) == 0
                && fixture.reader.read_calls == before_finish,
            "guards false preserves output and reads");

    h.check(fixture.build(3u), "fixture identity failure build");
    h.check(scope.begin(fixture.reader, kCombat, kSide1), "identity failure begin");
    output = sentinel();
    const wire::Snapshot identity_before = output;
    h.check(!scope.finish(0u, 56563608, 1u, true, output),
            "zero sequence rejected");
    h.check(std::memcmp(&output, &identity_before, sizeof(output)) == 0,
            "bad identity preserves output");

    h.check(fixture.build(3u), "fixture zero observation build");
    h.check(scope.begin(fixture.reader, kCombat, kSide1), "zero observation begin");
    output = wire::Snapshot{};
    h.check(scope.finish(42u, 56563608, 2u, true, output),
            "zero observation known");
    h.check(output.present && output.initial_unit_count == 3u
                && output.observed_count == 0u,
            "zero observation does not infer false");
}

void test_128_unit_boundary_and_scope_read_budget(Harness& h) {
    Fixture fixture{};
    h.check(fixture.build(owned::kMaxUnits), "fixture 128 build");
    owned::Scope scope{};
    h.check(scope.begin(fixture.reader, kCombat, kSide0), "128 begin");
    wire::Snapshot output{};
    h.check(scope.finish(42u, 56563608, 1u, true, output),
            "128 finish");
    h.check(output.initial_unit_count == owned::kMaxUnits
                && output.observed_count == 0u
                && fixture.reader.read_bytes <= owned::kMaxReadBudgetBytes
                && fixture.reader.read_calls <= owned::kMaxReadCalls,
            "128 counts and budget");
}

}  // namespace

int main() {
    Harness harness{};
    test_known_owner_flags_wrong_return_and_finish_clear(harness);
    test_begin_refuses_overlap_and_requires_stable_passes(harness);
    test_duplicate_nodes_units_and_overbound_list_fail_closed(harness);
    test_observe_mutation_duplicate_wrong_member_and_read_failure(harness);
    test_finish_guards_identity_output_and_zero_observation(harness);
    test_128_unit_boundary_and_scope_read_budget(harness);
    test_removal_source_selects_unit_side_and_counts(harness);
    test_removal_caller_membership_and_source_exclusion(harness);
    test_removal_combat_and_two_read_drift_guards(harness);
    test_removal_duplicate_observe_finish_and_old_api_compatibility(harness);
    std::printf("CHECK_COUNT=%u FAILURES=%u\n",
                harness.checks, harness.failures);
    return harness.failures == 0u ? 0 : 1;
}
