#ifndef INFORMATION_BATTLE_OWNED_RETREAT_H
#define INFORMATION_BATTLE_OWNED_RETREAT_H

// Bounded, pointer-free capture of the owned side's retreat evidence.  This
// component only copies values through the caller's read seam.  It does not
// call game code, allocate, perform I/O, retain source pointers after clear or
// assign meaning to owner references or the four copied flag bytes.
#include "information-battle-retreat-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_retreat {

namespace wire = information::battle::retreat_wire;
using Address = wire::Address;

inline constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
inline constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);

// Fixed-build layout and callback gates.  0x23fd10 is intentionally not an
// accepted source point: the newly observed point is a siege path, not a
// manual retreat source.
inline constexpr std::uint32_t kRegularEndingSourceRva = 0x22bed0u;
inline constexpr std::uint32_t kObserveReturnRva = 0x21ee73u;
inline constexpr std::uint32_t kRemovalReturnRva = 0xd503b2u;
inline constexpr std::uint8_t kRemovalCaptureSource = wire::kCaptureSourceUnitRemovalState;
inline constexpr std::size_t kCombatSidesOffset = 0x20u;
inline constexpr std::size_t kSideParentOffset = 0x10u;
inline constexpr std::size_t kSideLinkedHeadOffset = 0xe8u;
inline constexpr std::size_t kNodeUnitOffset = 0x0u;
inline constexpr std::size_t kNodeNextOffset = 0x10u;
inline constexpr std::size_t kUnitOwnerFullRefOffset = 0xd0u;
inline constexpr std::size_t kUnitCombatOffset = 0xc0u;
inline constexpr std::size_t kUnitRawFlagsOffset = 0x201u;

inline constexpr std::size_t kMaxUnits = wire::kMaxUnits;
inline constexpr std::size_t kMaxSingleReadBytes = 24u;
inline constexpr std::size_t kMaxReadBudgetBytes = 16384u;
// 128 list members in two passes plus 128 owner/flag observations take
// 1034 calls. Keep the declared maximum fully representable within 16 KiB.
inline constexpr std::size_t kMaxReadCalls = 1152u;

static_assert(sizeof(Address) == sizeof(std::uint64_t),
              "owned retreat requires 64-bit addresses");

namespace detail {

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                    std::size_t) noexcept> {};

inline bool checked_range(Address begin, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u || size > kMaxSingleReadBytes) return false;
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(size)) return false;
    end = begin + static_cast<Address>(size);
    return begin >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive && end > begin;
}

inline bool checked_add(Address left, Address right,
                        Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) return false;
    result = left + right;
    return true;
}

inline bool valid_pointer(Address value) noexcept {
    Address end = 0u;
    return value != 0u && value % alignof(Address) == 0u
        && checked_range(value, 1u, end);
}

inline std::uint64_t load_u64(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0u;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

struct Pass final {
    std::array<Address, 2u> side_ptrs{};
    std::array<Address, 2u> side_heads{};
    std::array<Address, kMaxUnits> nodes{};
    std::array<Address, kMaxUnits> units{};
    std::array<std::uint8_t, kMaxUnits> side_index{};
    std::size_t count = 0u;
    std::uint8_t losing_side_index = 0u;
};

inline bool contains(const std::array<Address, kMaxUnits>& values,
                     std::size_t count, Address candidate) noexcept {
    for (std::size_t index = 0u; index < count; ++index) {
        if (values[index] == candidate) return true;
    }
    return false;
}

inline bool same_pass(const Pass& left, const Pass& right) noexcept {
    if (left.side_ptrs != right.side_ptrs
            || left.side_heads != right.side_heads
            || left.count != right.count
            || left.losing_side_index != right.losing_side_index) {
        return false;
    }
    for (std::size_t index = 0u; index < left.count; ++index) {
        if (left.nodes[index] != right.nodes[index]
                || left.units[index] != right.units[index]
                || left.side_index[index] != right.side_index[index]) {
            return false;
        }
    }
    return true;
}

}  // namespace detail

using detail::reader_contract;

class Scope final {
public:
    Scope() noexcept = default;
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

    template <typename Reader>
    bool begin(Reader& reader, Address combat,
               Address losing_side) noexcept {
        return begin_owned(reader, combat, losing_side, 0u);
    }

    template <typename Reader>
    bool begin_removal(Reader& reader, Address combat, Address unit,
                       std::uint32_t original_return_rva) noexcept {
        if (original_return_rva != kRemovalReturnRva) return false;
        return begin_owned(reader, combat, 0u, unit);
    }

private:
    template <typename Reader>
    bool begin_owned(Reader& reader, Address combat, Address losing_side,
                     Address removing_unit) noexcept {
        static_assert(reader_contract<Reader>::value,
                      "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
        if (active_) return false;
        clear();
        if (!detail::valid_pointer(combat)
                || (removing_unit == 0u && !detail::valid_pointer(losing_side))
                || (removing_unit != 0u && !detail::valid_pointer(removing_unit))) {
            return false;
        }

        detail::Pass first{};
        detail::Pass second{};
        if (!read_pass(reader, combat, losing_side, removing_unit, first)
                || !read_pass(reader, combat, losing_side, removing_unit, second)
                || !detail::same_pass(first, second)) {
            clear();
            return false;
        }

        combat_ = combat;
        losing_side_ = first.side_ptrs[first.losing_side_index];
        losing_side_index_ = first.losing_side_index;
        capture_source_ = removing_unit == 0u ? 0u : kRemovalCaptureSource;
        unit_count_ = first.count;
        for (std::size_t index = 0u; index < unit_count_; ++index) {
            unit_ptrs_[index] = first.units[index];
            side_index_[index] = first.side_index[index];
        }
        active_ = true;
        return true;
    }

public:
    template <typename Reader>
    bool observe(Reader& reader, Address unit,
                 std::uint32_t original_return_rva) noexcept {
        if (original_return_rva != kObserveReturnRva || capture_source_ != 0u) return false;
        return observe_unit(reader, unit);
    }

    template <typename Reader>
    bool observe_removal(Reader& reader, Address unit,
                         std::uint32_t original_return_rva) noexcept {
        if (original_return_rva != kRemovalReturnRva
                || capture_source_ != kRemovalCaptureSource) return false;
        return observe_unit(reader, unit);
    }

private:
    template <typename Reader>
    bool observe_unit(Reader& reader, Address unit) noexcept {
        static_assert(reader_contract<Reader>::value,
                      "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
        if (!active_) return false;

        std::size_t index = 0u;
        if (!find_unit(unit, index) || observed_[index]
                || side_index_[index] != losing_side_index_) {
            invalidate();
            return false;
        }

        wire::Unit first{};
        wire::Unit second{};
        first.ordinal = static_cast<std::uint16_t>(index);
        second.ordinal = first.ordinal;
        if (!read_unit(reader, unit, first)
                || !read_unit(reader, unit, second)
                || !same_unit_value(first, second)) {
            invalidate();
            return false;
        }
        observed_units_[index] = first;
        observed_[index] = true;
        ++observed_count_;
        return true;
    }

public:
    bool finish(std::uint64_t sequence, std::int32_t raw_date,
                std::uint8_t kind, bool guards_after,
                wire::Snapshot& output) noexcept {
        const bool valid = active_ && guards_after
            && sequence != 0u && (kind == 1u || kind == 2u)
            && unit_count_ <= kMaxUnits && observed_count_ <= unit_count_;
        if (!valid) {
            clear();
            return false;
        }

        wire::Snapshot candidate{};
        candidate.sequence = sequence;
        candidate.raw_date = raw_date;
        candidate.kind = kind;
        candidate.present = true;
        candidate.combat_side_index = losing_side_index_;
        candidate.capture_source = capture_source_;
        candidate.initial_unit_count = static_cast<std::uint16_t>(unit_count_);
        candidate.observed_count = static_cast<std::uint16_t>(observed_count_);
        std::size_t copied = 0u;
        for (std::size_t index = 0u; index < unit_count_; ++index) {
            if (observed_[index]) {
                candidate.units[copied++] = observed_units_[index];
            }
        }

        // The member traversal order is not a wire-order promise.  Sort only
        // the copied values; no source address is read during finish.
        for (std::size_t index = 1u; index < copied; ++index) {
            wire::Unit value = candidate.units[index];
            std::size_t position = index;
            while (position > 0u
                    && candidate.units[position - 1u].ordinal > value.ordinal) {
                candidate.units[position] = candidate.units[position - 1u];
                --position;
            }
            candidate.units[position] = value;
        }
        output = candidate;
        clear();
        return true;
    }

    void invalidate() noexcept { clear(); }

    void clear() noexcept {
        combat_ = 0u;
        losing_side_ = 0u;
        losing_side_index_ = 0u;
        capture_source_ = 0u;
        unit_ptrs_.fill(0u);
        side_index_.fill(0u);
        observed_units_.fill(wire::Unit{});
        observed_.fill(false);
        unit_count_ = 0u;
        observed_count_ = 0u;
        read_bytes_ = 0u;
        read_calls_ = 0u;
        active_ = false;
    }

    bool active() const noexcept { return active_; }

private:
    template <typename Reader>
    bool read_bytes(Reader& reader, Address address, unsigned char* destination,
                    std::size_t size) noexcept {
        if (destination == nullptr || size == 0u
                || size > kMaxSingleReadBytes
                || read_calls_ >= kMaxReadCalls
                || read_bytes_ > kMaxReadBudgetBytes - size) {
            return false;
        }
        ++read_calls_;
        read_bytes_ += size;
        Address end = 0u;
        if (!detail::checked_range(address, size, end)) return false;
        return reader.read(address, destination, size);
    }

    template <typename Reader>
    bool read_pointer(Reader& reader, Address address,
                      Address& output) noexcept {
        std::array<unsigned char, sizeof(Address)> bytes{};
        if (!read_bytes(reader, address, bytes.data(), bytes.size())) return false;
        output = static_cast<Address>(detail::load_u64(bytes.data()));
        return true;
    }

    template <typename Reader>
    bool read_pass(Reader& reader, Address combat, Address losing_side, Address removing_unit,
                   detail::Pass& output) noexcept {
        Address pair_address = 0u;
        if (!detail::checked_add(combat,
                                 static_cast<Address>(kCombatSidesOffset),
                                 pair_address)) {
            return false;
        }
        std::array<unsigned char, 2u * sizeof(Address)> side_bytes{};
        if (!read_bytes(reader, pair_address, side_bytes.data(),
                        side_bytes.size())) {
            return false;
        }
        for (std::size_t index = 0u; index < 2u; ++index) {
            output.side_ptrs[index] = static_cast<Address>(detail::load_u64(
                side_bytes.data() + index * sizeof(Address)));
            if (!detail::valid_pointer(output.side_ptrs[index])) return false;
        }
        if (output.side_ptrs[0] == output.side_ptrs[1]) return false;
        if (losing_side == output.side_ptrs[0]) {
            output.losing_side_index = 0u;
        } else if (losing_side == output.side_ptrs[1]) {
            output.losing_side_index = 1u;
        } else if (removing_unit == 0u) {
            return false;
        }

        for (std::size_t side = 0u; side < 2u; ++side) {
            Address parent_address = 0u;
            Address parent_value = 0u;
            if (!detail::checked_add(output.side_ptrs[side],
                                     static_cast<Address>(kSideParentOffset),
                                     parent_address)
                    || !read_pointer(reader, parent_address, parent_value)
                    || parent_value != combat) {
                return false;
            }
            Address head_address = 0u;
            Address head_location = 0u;
            if (!detail::checked_add(output.side_ptrs[side],
                                     static_cast<Address>(kSideLinkedHeadOffset),
                                     head_location)
                    || !read_pointer(reader, head_location, head_address)) {
                return false;
            }
            output.side_heads[side] = head_address;
            Address node = head_address;
            while (node != 0u) {
                if (output.count >= kMaxUnits
                        || !detail::valid_pointer(node)
                        || detail::contains(output.nodes, output.count, node)) {
                    return false;
                }
                Address unit = 0u;
                Address next = 0u;
                Address unit_location = 0u;
                Address next_location = 0u;
                if (!detail::checked_add(node,
                                         static_cast<Address>(kNodeUnitOffset),
                                         unit_location)
                        || !read_pointer(reader, unit_location, unit)
                        || !detail::valid_pointer(unit)
                        || detail::contains(output.units, output.count, unit)
                        || !detail::checked_add(node,
                                         static_cast<Address>(kNodeNextOffset),
                                         next_location)
                        || !read_pointer(reader, next_location, next)) {
                    return false;
                }
                if (next != 0u && !detail::valid_pointer(next)) return false;
                output.nodes[output.count] = node;
                output.units[output.count] = unit;
                output.side_index[output.count] = static_cast<std::uint8_t>(side);
                ++output.count;
                node = next;
            }
        }
        if (removing_unit != 0u) {
            bool found = false;
            for (std::size_t index = 0u; index < output.count; ++index) {
                if (output.units[index] == removing_unit) {
                    output.losing_side_index = output.side_index[index];
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    template <typename Reader>
    bool read_unit(Reader& reader, Address unit,
                   wire::Unit& output) noexcept {
        if (capture_source_ == kRemovalCaptureSource) {
            Address combat_location = 0u;
            Address current_combat = 0u;
            if (!detail::checked_add(unit, static_cast<Address>(kUnitCombatOffset), combat_location)
                    || !read_pointer(reader, combat_location, current_combat)
                    || current_combat != combat_) return false;
        }
        Address owner_location = 0u;
        Address flags_location = 0u;
        if (!detail::checked_add(unit,
                                 static_cast<Address>(kUnitOwnerFullRefOffset),
                                 owner_location)
                || !detail::checked_add(unit,
                                 static_cast<Address>(kUnitRawFlagsOffset),
                                 flags_location)) {
            return false;
        }
        std::array<unsigned char, sizeof(std::uint64_t)> owner_bytes{};
        std::array<unsigned char, 5u> flag_bytes{};
        if (!read_bytes(reader, owner_location, owner_bytes.data(),
                        owner_bytes.size())
                || !read_bytes(reader, flags_location, flag_bytes.data(),
                               flag_bytes.size())) {
            return false;
        }
        output.owner_full_ref = detail::load_u64(owner_bytes.data());
        output.raw_flags = {{flag_bytes[0], flag_bytes[2],
                             flag_bytes[3], flag_bytes[4]}};
        return true;
    }

    static bool same_unit_value(const wire::Unit& left,
                                const wire::Unit& right) noexcept {
        return left.ordinal == right.ordinal
            && left.owner_full_ref == right.owner_full_ref
            && left.raw_flags == right.raw_flags;
    }

    bool find_unit(Address unit, std::size_t& index) const noexcept {
        for (std::size_t cursor = 0u; cursor < unit_count_; ++cursor) {
            if (unit_ptrs_[cursor] == unit) {
                index = cursor;
                return true;
            }
        }
        return false;
    }

    Address combat_ = 0u;
    Address losing_side_ = 0u;
    std::uint8_t losing_side_index_ = 0u;
    std::uint8_t capture_source_ = 0u;
    std::array<Address, kMaxUnits> unit_ptrs_{};
    std::array<std::uint8_t, kMaxUnits> side_index_{};
    std::array<wire::Unit, kMaxUnits> observed_units_{};
    std::array<bool, kMaxUnits> observed_{};
    std::size_t unit_count_ = 0u;
    std::size_t observed_count_ = 0u;
    std::size_t read_bytes_ = 0u;
    std::size_t read_calls_ = 0u;
    bool active_ = false;
};

}  // namespace information::battle::owned_retreat

#endif  // INFORMATION_BATTLE_OWNED_RETREAT_H
