#ifndef INFORMATION_BATTLE_OWNED_GATE_INPUTS_H
#define INFORMATION_BATTLE_OWNED_GATE_INPUTS_H

// Read-only, bounded projection of the native battle UI gate inputs.  This
// component preserves only sampled values and tri-state facts; it never calls
// an engine function, allocates, performs I/O, or retains graph pointers.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace information::battle::owned_gate_inputs {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);

constexpr std::size_t kCurrentCountryOffset = 0x1e60u;
constexpr std::size_t kCurrentCountryBytes = 16u;
constexpr std::size_t kRegistryOffset = 0x1e00u;
constexpr std::size_t kLandEnableOffset = 0x7484u;
constexpr std::size_t kLandEnableBytes = sizeof(std::uint8_t);
constexpr std::size_t kRegistrySlotOffset = 0x11b0u;
constexpr std::size_t kSlotCombatOffset = 0x30u;
constexpr std::size_t kPointerBytes = sizeof(std::uint64_t);
constexpr std::size_t kGameReadSpan = kLandEnableOffset + kLandEnableBytes;

constexpr std::size_t kMaxReadCalls = 16u;
constexpr std::size_t kMaxReadBytes = 128u;

static_assert(sizeof(Address) == 8u, "gate input addresses require x64");
static_assert(kCurrentCountryBytes + kLandEnableBytes
                  + 4u * kPointerBytes
                  <= kMaxReadBytes,
              "maximum gate input reads must stay within byte budget");

enum class Kind : std::uint8_t {
    land = 1u,
    naval = 2u,
};

enum class Status : std::uint8_t {
    invalid = 0u,
    partial = 1u,
    complete = 2u,
};

enum class Failure : std::uint8_t {
    none = 0u,
    invalid_kind = 1u,
    invalid_game_address = 2u,
    invalid_combat_address = 3u,
    address_overflow = 4u,
    address_alias = 5u,
    invalid_pointer_value = 6u,
    reader_failed = 7u,
    budget_exceeded = 8u,
};

enum class FieldState : std::uint8_t {
    unknown = 0u,
    observed = 1u,
};

enum class ObjectState : std::uint8_t {
    unknown = 0u,
    absent = 1u,
    present = 2u,
};

struct Snapshot final {
    Status status = Status::invalid;
    Failure failure = Failure::none;
    Kind kind = Kind::land;

    FieldState current_country_state = FieldState::unknown;
    std::array<unsigned char, kCurrentCountryBytes> current_country_raw{};
    std::uint8_t mode = 0u;
    std::uint8_t alternate_flag = 0u;
    FieldState default_ref_state = FieldState::unknown;
    std::uint64_t default_ref = 0u;
    FieldState alternate_ref_state = FieldState::unknown;
    std::uint64_t alternate_ref = 0u;
    FieldState selected_ref_state = FieldState::unknown;
    std::uint64_t selected_ref = 0u;

    FieldState land_enable_state = FieldState::unknown;
    std::uint8_t land_enable_raw = 0u;

    ObjectState registry_state = ObjectState::unknown;
    ObjectState slot_state = ObjectState::unknown;
    ObjectState combat_state = ObjectState::unknown;
    bool equals_current_combat_known = false;
    bool equals_current_combat = false;

    bool ui_override_known = false;
    bool ui_override_value = false;

    std::uint8_t read_calls = 0u;
    std::uint16_t read_bytes = 0u;
};

static_assert(std::is_trivially_copyable<Snapshot>::value,
              "gate snapshot must remain a value-only POD");

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                     std::size_t) noexcept> {};

namespace detail {

inline bool checked_add(Address base, std::size_t offset,
                        Address& address) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (base > max_value - static_cast<Address>(offset)) {
        return false;
    }
    address = base + static_cast<Address>(offset);
    return true;
}

inline bool checked_range(Address address, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u) return false;
    const Address amount = static_cast<Address>(size);
    const Address max_value = std::numeric_limits<Address>::max();
    if (address > max_value - amount) return false;
    end = address + amount;
    return address >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive && end > address;
}

inline bool canonical_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(std::uint64_t)) == 0u;
}

inline bool ranges_overlap(Address left, std::size_t left_size,
                           Address right, std::size_t right_size) noexcept {
    Address left_end = 0u;
    Address right_end = 0u;
    if (!checked_range(left, left_size, left_end)
            || !checked_range(right, right_size, right_end)) {
        return true;
    }
    return left < right_end && right < left_end;
}

inline bool graph_target_alias(Address target, Address game,
                               Address current_combat,
                               Address reader_address,
                               std::size_t reader_size,
                               Address output_address,
                               std::size_t output_size,
                               bool allow_current_combat) noexcept {
    Address target_end = 0u;
    if (!checked_range(target, kPointerBytes, target_end)) return true;
    if (ranges_overlap(target, kPointerBytes, game, kGameReadSpan)
            || ranges_overlap(target, kPointerBytes, reader_address,
                              reader_size)
            || ranges_overlap(target, kPointerBytes, output_address,
                              output_size)) {
        return true;
    }
    if (!allow_current_combat
            && ranges_overlap(target, kPointerBytes, current_combat,
                              kPointerBytes)) {
        return true;
    }
    return false;
}

inline void note_failure(Snapshot& output, Failure failure) noexcept {
    if (output.failure == Failure::none) output.failure = failure;
    output.status = Status::partial;
}

inline void invalidate(Snapshot& output, Failure failure) noexcept {
    output = Snapshot{};
    output.status = Status::invalid;
    output.failure = failure;
}

template <typename Reader>
inline bool read_bytes(Reader& reader, Address address,
                       unsigned char* destination, std::size_t size,
                       Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader.read must be bool read(Address, unsigned char*, size_t) noexcept");
    Address source_end = 0u;
    Address output_address = 0u;
    Address reader_address = 0u;
    const Address destination_address =
        reinterpret_cast<Address>(destination);
    if (destination == nullptr
            || !checked_range(address, size, source_end)
            || !checked_range(destination_address, size, output_address)
            || !checked_range(reinterpret_cast<Address>(&output),
                              sizeof(output), output_address)
            || !checked_range(reinterpret_cast<Address>(&reader),
                              sizeof(reader), reader_address)) {
        note_failure(output, Failure::address_alias);
        return false;
    }
    const Address output_begin = reinterpret_cast<Address>(&output);
    const Address reader_begin = reinterpret_cast<Address>(&reader);
    if (ranges_overlap(address, size, destination_address, size)
            || ranges_overlap(address, size, output_begin, sizeof(output))
            || ranges_overlap(address, size, reader_begin, sizeof(reader))
            || ranges_overlap(destination_address, size, output_begin,
                              sizeof(output))
            || ranges_overlap(destination_address, size, reader_begin,
                              sizeof(reader))) {
        note_failure(output, Failure::address_alias);
        return false;
    }
    if (output.read_calls >= kMaxReadCalls
            || size > kMaxReadBytes - output.read_bytes) {
        note_failure(output, Failure::budget_exceeded);
        return false;
    }
    ++output.read_calls;
    output.read_bytes = static_cast<std::uint16_t>(output.read_bytes + size);
    if (!reader.read(address, destination, size)) {
        std::memset(destination, 0, size);
        note_failure(output, Failure::reader_failed);
        return false;
    }
    return true;
}

template <typename Reader>
inline bool read_u64(Reader& reader, Address address, std::uint64_t& value,
                     Snapshot& output) noexcept {
    std::array<unsigned char, sizeof(std::uint64_t)> raw{};
    if (!read_bytes(reader, address, raw.data(), raw.size(), output)) {
        return false;
    }
    value = 0u;
    for (std::size_t index = 0u; index < raw.size(); ++index) {
        value |= static_cast<std::uint64_t>(raw[index]) << (index * 8u);
    }
    return true;
}

inline std::uint64_t load_u64_le(
        const std::array<unsigned char, kCurrentCountryBytes>& raw,
        std::size_t offset) noexcept {
    std::uint64_t value = 0u;
    for (std::size_t index = 0u; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(raw[offset + index])
                 << (index * 8u);
    }
    return value;
}

inline void derive_override(Snapshot& output) noexcept {
    bool known_false = false;
    if (output.kind == Kind::land
            && output.land_enable_state == FieldState::observed
            && output.land_enable_raw == 0u) {
        known_false = true;
    }
    if (output.registry_state == ObjectState::absent
            || output.slot_state == ObjectState::absent
            || output.combat_state == ObjectState::absent
            || (output.equals_current_combat_known
                && !output.equals_current_combat)) {
        known_false = true;
    }
    if (known_false) {
        output.ui_override_known = true;
        output.ui_override_value = false;
        return;
    }
    const bool enable_ok = output.kind == Kind::naval
        || (output.land_enable_state == FieldState::observed
            && output.land_enable_raw != 0u);
    if (enable_ok && output.registry_state == ObjectState::present
            && output.slot_state == ObjectState::present
            && output.combat_state == ObjectState::present
            && output.equals_current_combat_known
            && output.equals_current_combat) {
        output.ui_override_known = true;
        output.ui_override_value = true;
    }
}

}  // namespace detail

// Returns false for invalid outer inputs and aliasing. Read failures yield a
// partial snapshot with the failed fields left unknown; callers must consult
// each state and Status before treating an observed false as evidence.
template <typename Reader>
inline bool capture(Reader& reader, Address game, Address current_combat,
                    Kind kind, Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader.read must be bool read(Address, unsigned char*, size_t) noexcept");
    Address output_end = 0u;
    Address reader_end = 0u;
    const Address output_address = reinterpret_cast<Address>(&output);
    const Address reader_address = reinterpret_cast<Address>(&reader);
    Address game_end_before_write = 0u;
    Address combat_end_before_write = 0u;
    const bool game_range_before_write =
        detail::canonical_pointer(game)
        && detail::checked_range(game, kGameReadSpan,
                                 game_end_before_write);
    const bool combat_range_before_write =
        detail::canonical_pointer(current_combat)
        && detail::checked_range(current_combat, sizeof(std::uint64_t),
                                 combat_end_before_write);
    if (!detail::checked_range(output_address, sizeof(output), output_end)
            || !detail::checked_range(reader_address, sizeof(reader),
                                      reader_end)
            || detail::ranges_overlap(output_address, sizeof(output),
                                      reader_address, sizeof(reader))) {
        // Do not initialize output here: it aliases the reader and writing the
        // result would mutate the caller's reader object.
        return false;
    }
    if (game_range_before_write
            && (detail::ranges_overlap(game, kGameReadSpan, output_address,
                                       sizeof(output))
                || detail::ranges_overlap(game, kGameReadSpan, reader_address,
                                          sizeof(reader)))) {
        return false;
    }
    if (combat_range_before_write
            && (detail::ranges_overlap(current_combat, sizeof(std::uint64_t),
                                       output_address, sizeof(output))
                || detail::ranges_overlap(current_combat,
                                          sizeof(std::uint64_t), reader_address,
                                          sizeof(reader)))) {
        return false;
    }
    output = Snapshot{};

    if (kind != Kind::land && kind != Kind::naval) {
        detail::invalidate(output, Failure::invalid_kind);
        return false;
    }
    if (!detail::canonical_pointer(game)) {
        detail::invalidate(output, Failure::invalid_game_address);
        return false;
    }
    if (!detail::canonical_pointer(current_combat)) {
        detail::invalidate(output, Failure::invalid_combat_address);
        return false;
    }
    Address combat_end = 0u;
    if (!detail::checked_range(current_combat, sizeof(std::uint64_t),
                               combat_end)) {
        detail::invalidate(output, Failure::invalid_combat_address);
        return false;
    }

    Address game_end = 0u;
    Address game_selector = 0u;
    Address game_registry = 0u;
    Address game_land_enable = 0u;
    if (!detail::checked_range(game, kGameReadSpan, game_end)
            || !detail::checked_add(game, kCurrentCountryOffset, game_selector)
            || !detail::checked_add(game, kRegistryOffset, game_registry)
            || !detail::checked_add(game, kLandEnableOffset, game_land_enable)) {
        detail::invalidate(output, Failure::address_overflow);
        return false;
    }

    if (detail::ranges_overlap(game, kGameReadSpan, current_combat,
                               sizeof(std::uint64_t))
            || detail::ranges_overlap(reader_address, sizeof(reader),
                                      output_address, sizeof(output))
            || detail::ranges_overlap(reader_address, sizeof(reader), game,
                                      kGameReadSpan)
            || detail::ranges_overlap(reader_address, sizeof(reader),
                                      current_combat, sizeof(std::uint64_t))
            || detail::ranges_overlap(output_address, sizeof(output), game,
                                      kGameReadSpan)
            || detail::ranges_overlap(output_address, sizeof(output),
                                      current_combat, sizeof(std::uint64_t))) {
        detail::invalidate(output, Failure::address_alias);
        return false;
    }

    output.status = Status::partial;
    output.kind = kind;

    std::array<unsigned char, kCurrentCountryBytes> selector_raw{};
    if (detail::read_bytes(reader, game_selector, selector_raw.data(),
                           selector_raw.size(), output)) {
        output.current_country_raw = selector_raw;
        output.current_country_state = FieldState::observed;
        output.mode = output.current_country_raw[6u];
        output.alternate_flag = output.current_country_raw[15u];
        output.default_ref = detail::load_u64_le(output.current_country_raw, 0u);
        output.default_ref_state = FieldState::observed;
        output.alternate_ref = detail::load_u64_le(output.current_country_raw, 8u);
        output.alternate_ref_state = FieldState::observed;
        const bool use_alternate = output.mode == 7u
            && output.alternate_flag != 0u;
        output.selected_ref = use_alternate
            ? output.alternate_ref : output.default_ref;
        output.selected_ref_state = FieldState::observed;
    }

    std::array<unsigned char, kLandEnableBytes> land_enable{};
    if (detail::read_bytes(reader, game_land_enable, land_enable.data(),
                           land_enable.size(), output)) {
        output.land_enable_state = FieldState::observed;
        output.land_enable_raw = land_enable[0u];
    }

    Address registry_address = 0u;
    std::uint64_t registry_value = 0u;
    if (detail::read_u64(reader, game_registry, registry_value, output)) {
        if (registry_value == 0u) {
            output.registry_state = ObjectState::absent;
        } else if (!detail::canonical_pointer(
                       static_cast<Address>(registry_value))) {
            detail::note_failure(output, Failure::invalid_pointer_value);
        } else if (detail::graph_target_alias(
                       static_cast<Address>(registry_value), game,
                       current_combat, reader_address, sizeof(reader),
                       output_address, sizeof(output), false)) {
            detail::note_failure(output, Failure::address_alias);
        } else {
            registry_address = static_cast<Address>(registry_value);
            output.registry_state = ObjectState::present;
        }
    }

    Address slot_address = 0u;
    if (output.registry_state == ObjectState::present) {
        Address slot_pointer_address = 0u;
        std::uint64_t slot_value = 0u;
        if (!detail::checked_add(registry_address, kRegistrySlotOffset,
                                 slot_pointer_address)) {
            detail::note_failure(output, Failure::address_overflow);
        } else if (detail::read_u64(reader, slot_pointer_address, slot_value,
                                    output)) {
            if (slot_value == 0u) {
                output.slot_state = ObjectState::absent;
            } else if (!detail::canonical_pointer(
                           static_cast<Address>(slot_value))) {
                detail::note_failure(output, Failure::invalid_pointer_value);
            } else if (detail::graph_target_alias(
                           static_cast<Address>(slot_value), game,
                           current_combat, reader_address, sizeof(reader),
                           output_address, sizeof(output), false)
                    || detail::ranges_overlap(
                           static_cast<Address>(slot_value), kPointerBytes,
                           registry_address, kPointerBytes)) {
                detail::note_failure(output, Failure::address_alias);
            } else {
                slot_address = static_cast<Address>(slot_value);
                output.slot_state = ObjectState::present;
            }
        }
    }

    if (output.slot_state == ObjectState::present) {
        Address combat_pointer_address = 0u;
        std::uint64_t combat_value = 0u;
        if (!detail::checked_add(slot_address, kSlotCombatOffset,
                                 combat_pointer_address)) {
            detail::note_failure(output, Failure::address_overflow);
        } else if (detail::read_u64(reader, combat_pointer_address,
                                    combat_value, output)) {
            if (combat_value == 0u) {
                output.combat_state = ObjectState::absent;
                output.equals_current_combat_known = true;
                output.equals_current_combat = false;
            } else if (!detail::canonical_pointer(
                           static_cast<Address>(combat_value))) {
                detail::note_failure(output, Failure::invalid_pointer_value);
            } else if (detail::graph_target_alias(
                           static_cast<Address>(combat_value), game,
                           current_combat, reader_address, sizeof(reader),
                           output_address, sizeof(output), true)
                    || detail::ranges_overlap(
                           static_cast<Address>(combat_value), kPointerBytes,
                           registry_address, kPointerBytes)
                    || detail::ranges_overlap(
                           static_cast<Address>(combat_value), kPointerBytes,
                           slot_address, kPointerBytes)) {
                detail::note_failure(output, Failure::address_alias);
            } else {
                output.combat_state = ObjectState::present;
                output.equals_current_combat_known = true;
                output.equals_current_combat =
                    static_cast<Address>(combat_value) == current_combat;
            }
        }
    }

    detail::derive_override(output);
    output.status = output.failure == Failure::none
        ? Status::complete : Status::partial;
    return output.failure != Failure::address_alias;
}

}  // namespace information::battle::owned_gate_inputs

#endif  // INFORMATION_BATTLE_OWNED_GATE_INPUTS_H
