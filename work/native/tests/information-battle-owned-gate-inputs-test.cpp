#include "../information-battle-owned-gate-inputs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <type_traits>

namespace gate = information::battle::owned_gate_inputs;

namespace {

constexpr gate::Address kGame = 0x20000u;
constexpr gate::Address kRegistry = 0x30000u;
constexpr gate::Address kSlot = 0x40000u;
constexpr gate::Address kCombat = 0x50000u;
constexpr std::size_t kGameBytes = gate::kGameReadSpan;
constexpr std::size_t kRegistryBytes = gate::kRegistrySlotOffset + 8u;
constexpr std::size_t kSlotBytes = gate::kSlotCombatOffset + 8u;

struct alignas(std::uint64_t) MockReader final {
    std::array<unsigned char, kGameBytes> game{};
    std::array<unsigned char, kRegistryBytes> registry{};
    std::array<unsigned char, kSlotBytes> slot{};
    bool fail_enabled = false;
    gate::Address fail_address = 0u;
    std::size_t fail_size = 0u;
    std::size_t calls = 0u;
    std::size_t bytes = 0u;

    bool read(gate::Address address, unsigned char* output,
              std::size_t size) noexcept {
        ++calls;
        bytes += size;
        if (fail_enabled && address == fail_address && size == fail_size) {
            if (output != nullptr) std::memset(output, 0xee, size);
            return false;
        }
        if (copy_region(address, output, size, kGame, game.data(), game.size())
                || copy_region(address, output, size, kRegistry,
                               registry.data(), registry.size())
                || copy_region(address, output, size, kSlot, slot.data(),
                               slot.size())) {
            return true;
        }
        return false;
    }

private:
    static bool copy_region(gate::Address address, unsigned char* output,
                            std::size_t size, gate::Address base,
                            const unsigned char* source,
                            std::size_t capacity) noexcept {
        if (output == nullptr || address < base) return false;
        const gate::Address offset = address - base;
        if (offset > capacity || size > capacity - static_cast<std::size_t>(offset)) {
            return false;
        }
        std::memcpy(output, source + static_cast<std::size_t>(offset), size);
        return true;
    }
};

void put_u64(unsigned char* destination, std::uint64_t value) {
    for (std::size_t index = 0u; index < sizeof(value); ++index) {
        destination[index] = static_cast<unsigned char>(value >> (index * 8u));
    }
}

void set_game_pointer(MockReader& reader, std::size_t offset,
                      std::uint64_t value) {
    put_u64(reader.game.data() + offset, value);
}

void set_pointer(MockReader& reader, gate::Address base, std::size_t offset,
                 std::uint64_t value) {
    unsigned char* destination = nullptr;
    if (base == kRegistry) destination = reader.registry.data();
    if (base == kSlot) destination = reader.slot.data();
    put_u64(destination + offset, value);
}

void init_valid(MockReader& reader, bool land_enabled = true,
                gate::Address combat = kCombat, std::uint8_t mode = 0u,
                std::uint8_t alternate_flag = 0u) {
    const std::uint64_t default_ref = UINT64_C(0x0102030405060708);
    const std::uint64_t alternate_ref = UINT64_C(0x1112131415161718);
    set_game_pointer(reader, gate::kCurrentCountryOffset, default_ref);
    set_game_pointer(reader, gate::kCurrentCountryOffset + 8u, alternate_ref);
    reader.game[gate::kCurrentCountryOffset + 6u] = mode;
    reader.game[gate::kCurrentCountryOffset + 15u] = alternate_flag;
    reader.game[gate::kLandEnableOffset] = land_enabled ? 1u : 0u;
    set_game_pointer(reader, gate::kRegistryOffset, kRegistry);
    set_pointer(reader, kRegistry, gate::kRegistrySlotOffset, kSlot);
    set_pointer(reader, kSlot, gate::kSlotCombatOffset, combat);
}

struct Checks final {
    int assertions = 0;
    int failures = 0;

    void expect(bool condition, const char* label) {
        ++assertions;
        if (!condition) {
            ++failures;
            std::fprintf(stderr, "FAIL: %s\n", label);
        }
    }
};

void test_valid_and_selector(Checks& checks) {
    MockReader reader{};
    init_valid(reader, true, kCombat, 7u, 1u);
    gate::Snapshot snapshot{};
    const bool ok = gate::capture(reader, kGame, kCombat, gate::Kind::land,
                                  snapshot);
    checks.expect(ok, "valid land capture accepted");
    checks.expect(snapshot.status == gate::Status::complete,
                  "valid land snapshot complete");
    checks.expect(snapshot.current_country_state == gate::FieldState::observed,
                  "selector bytes observed");
    checks.expect(snapshot.mode == 7u && snapshot.alternate_flag == 1u,
                  "selector mode and alternate flag projected");
    checks.expect(snapshot.selected_ref == snapshot.alternate_ref,
                  "mode 7 with nonzero flag selects alternate reference");
    checks.expect(snapshot.ui_override_known && snapshot.ui_override_value,
                  "matching combat and enabled land override is true");
    checks.expect(snapshot.registry_state == gate::ObjectState::present
                      && snapshot.slot_state == gate::ObjectState::present
                      && snapshot.combat_state == gate::ObjectState::present,
                  "registry graph states present");
    checks.expect(snapshot.equals_current_combat_known
                      && snapshot.equals_current_combat,
                  "combat pointer compared with current combat");
    checks.expect(snapshot.read_calls == 5u && snapshot.read_bytes == 41u,
                  "capture stays within 5 calls and 41 bytes");
    checks.expect(snapshot.read_calls == reader.calls
                      && snapshot.read_bytes == reader.bytes,
                  "snapshot reports reader budget accurately");
    checks.expect(snapshot.read_calls <= gate::kMaxReadCalls
                      && snapshot.read_bytes <= gate::kMaxReadBytes,
                  "capture stays within documented hard budget");

    MockReader mode_not_seven{};
    init_valid(mode_not_seven, true, kCombat, 6u, 1u);
    gate::Snapshot default_selected{};
    checks.expect(gate::capture(mode_not_seven, kGame, kCombat,
                                gate::Kind::naval, default_selected)
                      && default_selected.selected_ref
                             == default_selected.default_ref,
                  "non-seven mode selects default even with flag set");

    MockReader flag_zero{};
    init_valid(flag_zero, true, kCombat, 7u, 0u);
    gate::Snapshot default_on_zero{};
    checks.expect(gate::capture(flag_zero, kGame, kCombat, gate::Kind::land,
                                default_on_zero)
                      && default_on_zero.selected_ref
                             == default_on_zero.default_ref,
                  "mode seven with zero flag selects default");
}

void test_land_naval_and_match(Checks& checks) {
    MockReader disabled{};
    init_valid(disabled, false);
    gate::Snapshot land{};
    checks.expect(gate::capture(disabled, kGame, kCombat, gate::Kind::land,
                                land)
                      && land.ui_override_known && !land.ui_override_value,
                  "disabled land gate is known false");
    checks.expect(land.land_enable_state == gate::FieldState::observed
                      && land.land_enable_raw == 0u,
                  "land enable raw zero is retained");

    MockReader naval_disabled{};
    init_valid(naval_disabled, false);
    gate::Snapshot naval{};
    checks.expect(gate::capture(naval_disabled, kGame, kCombat,
                                gate::Kind::naval, naval)
                      && naval.ui_override_known && naval.ui_override_value,
                  "naval gate ignores land enable byte");
    checks.expect(naval.land_enable_state == gate::FieldState::observed,
                  "naval snapshot still retains land enable observation");

    MockReader mismatch{};
    init_valid(mismatch, true, kCombat + 0x100u);
    gate::Snapshot mismatch_snapshot{};
    checks.expect(gate::capture(mismatch, kGame, kCombat, gate::Kind::naval,
                                mismatch_snapshot)
                      && mismatch_snapshot.equals_current_combat_known
                      && !mismatch_snapshot.equals_current_combat
                      && mismatch_snapshot.ui_override_known
                      && !mismatch_snapshot.ui_override_value,
                  "different nonnull combat is a known false override");
}

void test_nulls_and_unknowns(Checks& checks) {
    MockReader no_registry{};
    init_valid(no_registry);
    set_game_pointer(no_registry, gate::kRegistryOffset, 0u);
    gate::Snapshot no_registry_snapshot{};
    checks.expect(gate::capture(no_registry, kGame, kCombat, gate::Kind::land,
                                no_registry_snapshot)
                      && no_registry_snapshot.registry_state
                             == gate::ObjectState::absent
                      && no_registry_snapshot.slot_state
                             == gate::ObjectState::unknown
                      && no_registry_snapshot.ui_override_known
                      && !no_registry_snapshot.ui_override_value,
                  "null registry is known absent and short circuits false");
    checks.expect(no_registry_snapshot.read_calls == 3u,
                  "null registry avoids slot and combat reads");

    MockReader no_slot{};
    init_valid(no_slot);
    set_pointer(no_slot, kRegistry, gate::kRegistrySlotOffset, 0u);
    gate::Snapshot no_slot_snapshot{};
    checks.expect(gate::capture(no_slot, kGame, kCombat, gate::Kind::land,
                                no_slot_snapshot)
                      && no_slot_snapshot.registry_state
                             == gate::ObjectState::present
                      && no_slot_snapshot.slot_state == gate::ObjectState::absent
                      && no_slot_snapshot.combat_state
                             == gate::ObjectState::unknown
                      && no_slot_snapshot.ui_override_known
                      && !no_slot_snapshot.ui_override_value,
                  "null slot is known absent and combat stays unknown");

    MockReader no_combat{};
    init_valid(no_combat);
    set_pointer(no_combat, kSlot, gate::kSlotCombatOffset, 0u);
    gate::Snapshot no_combat_snapshot{};
    checks.expect(gate::capture(no_combat, kGame, kCombat, gate::Kind::naval,
                                no_combat_snapshot)
                      && no_combat_snapshot.combat_state
                             == gate::ObjectState::absent
                      && no_combat_snapshot.equals_current_combat_known
                      && !no_combat_snapshot.equals_current_combat
                      && no_combat_snapshot.ui_override_known
                      && !no_combat_snapshot.ui_override_value,
                  "null combat is known absent and false");

    struct FailureCase final {
        gate::Address address;
        std::size_t size;
        const char* label;
    };
    constexpr FailureCase failures[] = {
        {kGame + gate::kCurrentCountryOffset, 16u, "selector"},
        {kGame + gate::kLandEnableOffset, 1u, "land enable"},
        {kGame + gate::kRegistryOffset, 8u, "registry"},
        {kRegistry + gate::kRegistrySlotOffset, 8u, "slot"},
        {kSlot + gate::kSlotCombatOffset, 8u, "combat"},
    };
    for (const FailureCase& failure : failures) {
        MockReader reader{};
        init_valid(reader);
        reader.fail_enabled = true;
        reader.fail_address = failure.address;
        reader.fail_size = failure.size;
        gate::Snapshot snapshot{};
        const bool accepted = gate::capture(reader, kGame, kCombat,
                                            gate::Kind::land, snapshot);
        checks.expect(accepted, failure.label);
        checks.expect(snapshot.status == gate::Status::partial
                          && snapshot.failure == gate::Failure::reader_failed,
                      "read failure reports partial and reason");
        if (failure.address == kGame + gate::kCurrentCountryOffset) {
            checks.expect(snapshot.current_country_state
                              == gate::FieldState::unknown
                              && snapshot.mode == 0u
                              && snapshot.default_ref == 0u
                              && snapshot.current_country_raw[0] == 0u,
                          "failed selector output is cleared and unknown");
        }
        if (failure.address == kGame + gate::kLandEnableOffset) {
            checks.expect(snapshot.land_enable_state == gate::FieldState::unknown
                              && !snapshot.ui_override_known,
                          "failed enable is unknown, not false");
        }
        if (failure.address == kGame + gate::kRegistryOffset) {
            checks.expect(snapshot.registry_state == gate::ObjectState::unknown
                              && !snapshot.ui_override_known,
                          "failed registry is unknown, not false");
        }
        if (failure.address == kRegistry + gate::kRegistrySlotOffset) {
            checks.expect(snapshot.registry_state == gate::ObjectState::present
                              && snapshot.slot_state == gate::ObjectState::unknown
                              && !snapshot.ui_override_known,
                          "failed slot is unknown, not absent");
        }
        if (failure.address == kSlot + gate::kSlotCombatOffset) {
            checks.expect(snapshot.slot_state == gate::ObjectState::present
                              && snapshot.combat_state
                                     == gate::ObjectState::unknown
                              && !snapshot.equals_current_combat_known
                              && !snapshot.ui_override_known,
                          "failed combat is unknown, not mismatch");
        }
    }

    MockReader short_circuit{};
    init_valid(short_circuit, false);
    short_circuit.fail_enabled = true;
    short_circuit.fail_address = kGame + gate::kRegistryOffset;
    short_circuit.fail_size = 8u;
    gate::Snapshot short_circuit_snapshot{};
    checks.expect(gate::capture(short_circuit, kGame, kCombat,
                                gate::Kind::land, short_circuit_snapshot)
                      && short_circuit_snapshot.ui_override_known
                      && !short_circuit_snapshot.ui_override_value
                      && short_circuit_snapshot.registry_state
                             == gate::ObjectState::unknown,
                  "known land disable short circuits false but preserves unknown registry");
}

void test_invalid_and_alias(Checks& checks) {
    MockReader reader{};
    init_valid(reader);
    gate::Snapshot snapshot{};
    checks.expect(!gate::capture(reader, kGame, kCombat,
                                 static_cast<gate::Kind>(0u), snapshot)
                      && snapshot.status == gate::Status::invalid
                      && snapshot.failure == gate::Failure::invalid_kind
                      && reader.calls == 0u,
                  "invalid kind rejected before reads");

    MockReader bad_game_reader{};
    gate::Snapshot bad_game{};
    checks.expect(!gate::capture(bad_game_reader, 0x1234u, kCombat,
                                 gate::Kind::land, bad_game)
                      && bad_game.failure == gate::Failure::invalid_game_address,
                  "invalid game address rejected");

    MockReader bad_combat_reader{};
    gate::Snapshot bad_combat{};
    checks.expect(!gate::capture(bad_combat_reader, kGame, 0x1234u,
                                 gate::Kind::land, bad_combat)
                      && bad_combat.failure
                             == gate::Failure::invalid_combat_address,
                  "invalid current combat rejected");

    MockReader wrap_reader{};
    gate::Snapshot wrap{};
    checks.expect(!gate::capture(wrap_reader,
                                 gate::kMaxCanonicalExclusive - 8u, kCombat,
                                 gate::Kind::land, wrap)
                      && wrap.status == gate::Status::invalid
                      && wrap.failure == gate::Failure::address_overflow,
                  "canonical game range wrap is rejected explicitly");

    MockReader invalid_pointer_reader{};
    init_valid(invalid_pointer_reader);
    set_game_pointer(invalid_pointer_reader, gate::kRegistryOffset, 0x1234u);
    gate::Snapshot invalid_pointer{};
    checks.expect(gate::capture(invalid_pointer_reader, kGame, kCombat,
                                gate::Kind::land, invalid_pointer)
                      && invalid_pointer.status == gate::Status::partial
                      && invalid_pointer.failure
                             == gate::Failure::invalid_pointer_value
                      && invalid_pointer.registry_state
                             == gate::ObjectState::unknown,
                  "invalid graph pointer rejected without becoming absent");

    MockReader alias_reader{};
    gate::Snapshot alias_output{};
    alias_output.status = gate::Status::complete;
    alias_output.failure = gate::Failure::budget_exceeded;
    alias_output.kind = gate::Kind::naval;
    alias_output.ui_override_known = true;
    alias_output.ui_override_value = true;
    alias_output.read_calls = 9u;
    alias_output.read_bytes = 77u;
    const gate::Address output_address =
        reinterpret_cast<gate::Address>(&alias_output);
    checks.expect(!gate::capture(alias_reader, output_address, kCombat,
                                 gate::Kind::land, alias_output)
                      && alias_output.status == gate::Status::complete
                      && alias_output.failure == gate::Failure::budget_exceeded
                      && alias_output.kind == gate::Kind::naval
                      && alias_output.read_calls == 9u
                      && alias_output.read_bytes == 77u
                      && alias_reader.calls == 0u,
                  "game/output alias is rejected without changing output");

    MockReader reader_alias{};
    gate::Snapshot reader_alias_output{};
    reader_alias_output.status = gate::Status::complete;
    reader_alias_output.failure = gate::Failure::reader_failed;
    reader_alias_output.read_calls = 8u;
    const gate::Address reader_address =
        reinterpret_cast<gate::Address>(&reader_alias);
    checks.expect(!gate::capture(reader_alias, reader_address, kCombat,
                                 gate::Kind::land, reader_alias_output)
                      && reader_alias_output.status == gate::Status::complete
                      && reader_alias_output.failure
                             == gate::Failure::reader_failed
                      && reader_alias_output.read_calls == 8u
                      && reader_alias.calls == 0u,
                  "game/reader alias is rejected without reads or mutation");

    MockReader pointer_alias_reader{};
    init_valid(pointer_alias_reader);
    gate::Snapshot pointer_alias{};
    const gate::Address registry_field_hits_output =
        reinterpret_cast<gate::Address>(&pointer_alias)
        - gate::kRegistrySlotOffset;
    set_game_pointer(pointer_alias_reader, gate::kRegistryOffset,
                     registry_field_hits_output);
    checks.expect(!gate::capture(pointer_alias_reader, kGame, kCombat,
                                 gate::Kind::land, pointer_alias)
                      && pointer_alias.status == gate::Status::partial
                      && pointer_alias.failure == gate::Failure::address_alias
                      && pointer_alias.registry_state == gate::ObjectState::present
                      && pointer_alias.slot_state == gate::ObjectState::unknown,
                  "graph source overlapping result is rejected and remains unknown");

    MockReader target_alias_reader{};
    init_valid(target_alias_reader);
    gate::Snapshot target_alias{};
    set_game_pointer(target_alias_reader, gate::kRegistryOffset,
                     reinterpret_cast<gate::Address>(&target_alias));
    checks.expect(!gate::capture(target_alias_reader, kGame, kCombat,
                                 gate::Kind::land, target_alias)
                      && target_alias.status == gate::Status::partial
                      && target_alias.failure == gate::Failure::address_alias
                      && target_alias.registry_state == gate::ObjectState::unknown,
                  "graph pointer targeting result storage is rejected");
}

}  // namespace

int main() {
    static_assert(std::is_trivially_copyable<gate::Snapshot>::value,
                  "Snapshot must remain trivially copyable");
    Checks checks{};
    test_valid_and_selector(checks);
    test_land_naval_and_match(checks);
    test_nulls_and_unknowns(checks);
    test_invalid_and_alias(checks);
    std::printf("checks=%d failures=%d\n", checks.assertions, checks.failures);
    return checks.failures == 0 ? 0 : 1;
}
