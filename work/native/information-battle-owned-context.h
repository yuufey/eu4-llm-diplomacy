#ifndef INFORMATION_BATTLE_OWNED_CONTEXT_H
#define INFORMATION_BATTLE_OWNED_CONTEXT_H

// Research-only, pointer-free copy of the raw combat context used by the
// fixed 1.37.4 battle message path.  This header never calls a game function,
// allocates, performs I/O, or retains a source address.  The caller supplies
// a safe read seam and the audited main-module range.  No thread, lifetime,
// visibility, or world-atomicity guarantee is implied by this copy.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_context {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);
constexpr std::size_t kMaxImageBytes = 512u * 1024u * 1024u;
constexpr std::size_t kMaxSingleReadBytes = 64u * 1024u;
constexpr std::size_t kMaxReadBudgetBytes = 64u * 1024u;
constexpr std::size_t kMaxParticipants = 256u;
constexpr std::size_t kMaxWarMembers = 256u;

// These are fixed-build layout inputs.  They are raw-layout contracts only;
// the component does not assign attacker/defender or other business roles.
constexpr std::size_t kCombatVtableOffset = 0x0u;
constexpr std::size_t kCombatKindSlotOffset = 0x60u;
constexpr std::size_t kCombatSideAOffset = 0x20u;
constexpr std::size_t kCombatSideBOffset = 0x28u;
constexpr std::size_t kParticipantBeginOffset = 0x100u;
constexpr std::size_t kParticipantEndOffset = 0x108u;
constexpr std::size_t kParticipantRowBytes = 0x20u;
constexpr std::size_t kParticipantFullRefOffset = 0x10u;
constexpr std::size_t kSideHeaderOffset = 0x100u;
constexpr std::size_t kSideHeaderBytes = 0x40u;
constexpr std::array<std::size_t, 6> kSideRawFieldOffsets{{
    0x118u, 0x11cu, 0x120u, 0x134u, 0x138u, 0x13cu,
}};

constexpr std::size_t kWarHistoryRootOffset = 0x108u;
constexpr Address kWarHistoryRootVtableRva = UINT64_C(0x1d20be0);
constexpr std::array<std::size_t, 3> kWarSideABounds{{0x48u, 0x50u, 0x58u}};
constexpr std::array<std::size_t, 3> kWarSideBBounds{{0x78u, 0x80u, 0x88u}};

static_assert(kParticipantFullRefOffset + sizeof(std::uint64_t)
                  <= kParticipantRowBytes,
              "participant full reference must remain inside the surveyed row");
static_assert(kSideRawFieldOffsets.back() + sizeof(std::int32_t)
                  <= kSideHeaderOffset + kSideHeaderBytes,
              "side raw fields must remain inside the bounded side header");

enum class Kind : std::uint8_t {
    unknown = 0,
    land = 1,
    naval = 2,
};

// A null candidate is different from a non-null candidate whose root or
// vectors failed validation.  Neither state means "not a member".
enum class WarContextStatus : std::uint8_t {
    absent = 0,
    observed = 1,
    invalid = 2,
};

struct ParticipantVector {
    std::array<std::uint64_t, kMaxParticipants> full_refs;
    std::uint32_t count;
    bool complete;
};

struct CombatSide {
    bool present;
    ParticipantVector participants;
    // Six raw native slots at the fixed offsets.  Their initial/loss/business
    // meaning is intentionally unresolved, including for naval messages.
    std::array<std::int32_t, kSideRawFieldOffsets.size()> raw_fields;
};

struct WarMembers {
    std::array<std::uint64_t, kMaxWarMembers> side_a_full_refs;
    std::array<std::uint64_t, kMaxWarMembers> side_b_full_refs;
    std::uint32_t side_a_count;
    std::uint32_t side_b_count;
    bool vectors_complete;
    bool physical_player_membership_known;
    bool physical_player_is_war_member;
};

struct Snapshot {
    bool known_router;
    std::uint32_t raw_selector;
    std::array<unsigned char, 6> selector_code;
    bool selector_code_verified;
    Kind kind;
    std::uint64_t physical_player_full_ref;
    std::array<CombatSide, 2> sides;
    WarContextStatus war_context_status;
    WarMembers war_members;
};

static_assert(std::is_trivially_copyable<ParticipantVector>::value,
              "participant vectors must be plain value objects");
static_assert(std::is_trivially_copyable<CombatSide>::value,
              "combat sides must be plain value objects");
static_assert(std::is_trivially_copyable<WarMembers>::value,
              "war members must be plain value objects");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "context snapshot must be a plain value object");

namespace detail {

inline bool checked_range(Address begin, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u || size > kMaxSingleReadBytes) {
        return false;
    }
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return begin >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive
        && end > begin;
}

inline bool checked_add(Address left, Address right, Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool ranges_overlap(Address left_begin, Address left_end,
                           Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline std::uint64_t load_u64(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline std::uint32_t load_u32(const unsigned char* bytes) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline std::int32_t load_i32(const unsigned char* bytes) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline bool output_range(const Snapshot& output, Address& begin,
                         Address& end) noexcept {
    begin = reinterpret_cast<Address>(&output);
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(sizeof(output))) {
        return false;
    }
    end = begin + static_cast<Address>(sizeof(output));
    return end > begin;
}

inline bool image_range(Address base, std::size_t image_size,
                        Address& end) noexcept {
    if (image_size == 0u || image_size > kMaxImageBytes
            || base < kMinCanonicalAddress
            || base >= kMaxCanonicalExclusive) {
        return false;
    }
    const Address max_value = std::numeric_limits<Address>::max();
    if (base > max_value - static_cast<Address>(image_size)) {
        return false;
    }
    end = base + static_cast<Address>(image_size);
    // A full image range is bounded independently from the per-read limit.
    // The fixed PE image is far below this conservative upper bound.
    return end > base && end <= kMaxCanonicalExclusive;
}

inline bool in_image(Address address, std::size_t size, Address base,
                     Address image_end) noexcept {
    Address end = 0;
    return checked_range(address, size, end)
        && address >= base && end <= image_end;
}

template <typename Reader>
class BoundedReader {
public:
    BoundedReader(Reader& reader, Address output_begin,
                  Address output_end) noexcept
        : reader_(reader), output_begin_(output_begin),
          output_end_(output_end) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        Address end = 0;
        if (destination == nullptr || !checked_range(address, size, end)) {
            return false;
        }
        if (bytes_read_ > kMaxReadBudgetBytes - size) {
            fatal_ = true;
            return false;
        }
        if (ranges_overlap(address, end, output_begin_, output_end_)) {
            fatal_ = true;
            return false;
        }
        bytes_read_ += size;
        return reader_.read(address, destination, size);
    }

    std::size_t bytes_read() const noexcept { return bytes_read_; }
    bool fatal() const noexcept { return fatal_; }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    std::size_t bytes_read_ = 0;
    bool fatal_ = false;
};

inline bool valid_country_full_ref(std::uint64_t value) noexcept {
    if (value == 0u) return false;
    for (unsigned shift = 0u; shift < 24u; shift += 8u) {
        const unsigned char byte = static_cast<unsigned char>(
            (value >> shift) & UINT64_C(0xff));
        const bool uppercase = byte >= static_cast<unsigned char>('A')
            && byte <= static_cast<unsigned char>('Z');
        const bool digit = byte >= static_cast<unsigned char>('0')
            && byte <= static_cast<unsigned char>('9');
        if (!uppercase && !digit) return false;
    }
    return true;
}

}  // namespace detail

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*, std::size_t) noexcept> {};

// Copy a combat context and, when explicitly requested, its candidate war
// membership.  A false return leaves output byte-for-byte unchanged.  A null
// or invalid optional war candidate is represented in a successful snapshot
// by WarContextStatus::absent/invalid; it is never converted to false
// membership.  The fixed leaf is inspected, never called.
template <typename Reader>
bool capture(Reader& reader, Address module_base, std::size_t image_size,
             Address combat, bool known_router, Address war_candidate,
             std::uint64_t physical_player_full_ref,
             Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(uintptr_t,unsigned char*,size_t) noexcept");

    Address output_begin = 0;
    Address output_end = 0;
    Address image_end = 0;
    Address combat_probe_end = 0;
    if (!detail::output_range(output, output_begin, output_end)
            || !detail::image_range(module_base, image_size, image_end)
            || combat < kMinCanonicalAddress || combat % alignof(Address) != 0u
            || !detail::valid_country_full_ref(physical_player_full_ref)
            || !detail::checked_range(combat, sizeof(Address), combat_probe_end)) {
        return false;
    }
    Address combat_side_end = 0;
    if (!detail::checked_add(combat,
                             kCombatSideBOffset + sizeof(Address),
                             combat_side_end)
            || combat_side_end <= combat) {
        return false;
    }

    detail::BoundedReader<Reader> bounded(reader, output_begin, output_end);
    Snapshot candidate;
    std::memset(&candidate, 0, sizeof(candidate));
    candidate.known_router = known_router;
    candidate.physical_player_full_ref = physical_player_full_ref;

    std::array<unsigned char, sizeof(Address)> combat_vtable_raw{};
    std::array<unsigned char, sizeof(Address) * 2u> side_pointer_raw{};
    if (!bounded.read(combat + kCombatVtableOffset, combat_vtable_raw.data(),
                      combat_vtable_raw.size())
            || !bounded.read(combat + kCombatSideAOffset,
                             side_pointer_raw.data(), side_pointer_raw.size())) {
        return false;
    }
    const Address combat_vtable = detail::load_u64(combat_vtable_raw.data());
    if (combat_vtable % alignof(Address) != 0u
            || !detail::in_image(combat_vtable, kCombatKindSlotOffset
                               + sizeof(Address), module_base, image_end)) {
        return false;
    }

    struct KindProbe {
        Address vtable = 0;
        Address code = 0;
        std::array<unsigned char, 6> bytes{};
        std::uint32_t selector = 0;
    };

    const auto probe = [&](KindProbe& value) noexcept -> bool {
        value = KindProbe{};
        std::array<unsigned char, sizeof(Address)> slot_raw{};
        if (!bounded.read(combat, combat_vtable_raw.data(),
                          combat_vtable_raw.size())
                || !bounded.read(combat_vtable + kCombatKindSlotOffset,
                                 slot_raw.data(), slot_raw.size())) {
            return false;
        }
        value.vtable = detail::load_u64(combat_vtable_raw.data());
        value.code = detail::load_u64(slot_raw.data());
        if (value.vtable != combat_vtable
                || !detail::in_image(value.vtable,
                                      kCombatKindSlotOffset + sizeof(Address),
                                      module_base, image_end)
                || !detail::in_image(value.code, 6u, module_base, image_end)
                || !bounded.read(value.code, value.bytes.data(),
                                 value.bytes.size())) {
            return false;
        }
        if (value.bytes[0] != 0xb8u || value.bytes[5] != 0xc3u) {
            return false;
        }
        value.selector = static_cast<std::uint32_t>(value.bytes[1])
            | (static_cast<std::uint32_t>(value.bytes[2]) << 8u)
            | (static_cast<std::uint32_t>(value.bytes[3]) << 16u)
            | (static_cast<std::uint32_t>(value.bytes[4]) << 24u);
        if (value.selector != 1u && value.selector != 2u) {
            return false;
        }
        return true;
    };

    KindProbe first{};
    // This is the pre-copy proof.  The matching post-copy proof is deliberately
    // performed only after all core and optional-war values have been copied.
    if (!probe(first)) {
        return false;
    }

    candidate.raw_selector = first.selector;
    candidate.selector_code = first.bytes;
    candidate.selector_code_verified = true;
    candidate.kind = first.selector == 1u ? Kind::land : Kind::naval;

    std::array<std::array<unsigned char, kSideHeaderBytes>, 2u>
        saved_side_headers{};
    std::array<unsigned char, kParticipantRowBytes> participant_row{};
    const auto read_side = [&](Address side_address, CombatSide& side,
                               std::array<unsigned char, kSideHeaderBytes>&
                                   saved_header) noexcept -> bool {
        if (side_address == 0u) {
            side = CombatSide{};
            return true;
        }
        Address side_end = 0;
        if (side_address < kMinCanonicalAddress
                || side_address % alignof(Address) != 0u
                || !detail::checked_range(side_address, kSideHeaderOffset
                                              + kSideHeaderBytes, side_end)) {
            return false;
        }
        if (!bounded.read(side_address + kSideHeaderOffset, saved_header.data(),
                          saved_header.size())) {
            return false;
        }
        const Address begin = detail::load_u64(
            saved_header.data() + kParticipantBeginOffset - kSideHeaderOffset);
        const Address end = detail::load_u64(
            saved_header.data() + kParticipantEndOffset - kSideHeaderOffset);
        if (end < begin || (end - begin) % kParticipantRowBytes != 0u
                || end - begin > kMaxParticipants * kParticipantRowBytes) {
            return false;
        }
        const std::uint32_t count = static_cast<std::uint32_t>(
            (end - begin) / kParticipantRowBytes);
        if (count != 0u) {
            Address ignored = 0;
            if (begin % alignof(Address) != 0u
                    || end % alignof(Address) != 0u
                    || !detail::checked_range(begin,
                                       static_cast<std::size_t>(end - begin),
                                       ignored)) {
                return false;
            }
        } else if (begin != 0u || end != 0u) {
            if (begin != end || begin < kMinCanonicalAddress
                    || begin >= kMaxCanonicalExclusive
                    || begin % alignof(Address) != 0u) {
                return false;
            }
        }
        side = CombatSide{};
        side.present = true;
        side.participants.count = count;
        side.participants.complete = true;
        for (std::size_t i = 0; i < kSideRawFieldOffsets.size(); ++i) {
            side.raw_fields[i] = detail::load_i32(
                saved_header.data() + kSideRawFieldOffsets[i]
                    - kSideHeaderOffset);
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            Address row_address = 0;
            if (!detail::checked_add(begin,
                                     static_cast<Address>(i)
                                         * kParticipantRowBytes,
                                     row_address)
                    || !bounded.read(row_address, participant_row.data(),
                                     participant_row.size())) {
                return false;
            }
            side.participants.full_refs[i] = detail::load_u64(
                participant_row.data() + kParticipantFullRefOffset);
            if (!detail::valid_country_full_ref(side.participants.full_refs[i])) {
                return false;
            }
        }
        return true;
    };

    const Address side_a_address = detail::load_u64(side_pointer_raw.data());
    const Address side_b_address = detail::load_u64(
        side_pointer_raw.data() + sizeof(Address));
    if (!read_side(side_a_address, candidate.sides[0], saved_side_headers[0])
            || !read_side(side_b_address, candidate.sides[1], saved_side_headers[1])) {
        return false;
    }

    struct WarVectorBounds {
        Address begin = 0;
        Address end = 0;
        Address capacity = 0;
    };
    std::array<WarVectorBounds, 2u> saved_war_bounds{};
    Address saved_war_root = 0;

    const auto valid_vector_pointer = [](Address value) noexcept -> bool {
        return value >= kMinCanonicalAddress
            && value < kMaxCanonicalExclusive
            && value % alignof(Address) == 0u;
    };
    const auto valid_war_bounds = [&](const WarVectorBounds& bounds) noexcept {
        if (bounds.begin == 0u && bounds.end == 0u
                && bounds.capacity == 0u) {
            return true;
        }
        if (!valid_vector_pointer(bounds.begin)
                || !valid_vector_pointer(bounds.end)
                || !valid_vector_pointer(bounds.capacity)
                || bounds.end < bounds.begin
                || bounds.capacity < bounds.end
                || (bounds.end - bounds.begin) % sizeof(Address) != 0u
                || bounds.end - bounds.begin > kMaxWarMembers * sizeof(Address)) {
            return false;
        }
        if (bounds.end == bounds.begin) return true;
        Address ignored = 0;
        return detail::checked_range(bounds.begin,
                                     static_cast<std::size_t>(
                                         bounds.end - bounds.begin),
                                     ignored);
    };

    const auto war_refs_unique = [](const WarMembers& members) noexcept {
        for (std::uint32_t i = 0; i < members.side_a_count; ++i) {
            for (std::uint32_t j = 0; j < i; ++j) {
                if (members.side_a_full_refs[i] == members.side_a_full_refs[j]) {
                    return false;
                }
            }
            for (std::uint32_t j = 0; j < members.side_b_count; ++j) {
                if (members.side_a_full_refs[i] == members.side_b_full_refs[j]) {
                    return false;
                }
            }
        }
        for (std::uint32_t i = 0; i < members.side_b_count; ++i) {
            for (std::uint32_t j = 0; j < i; ++j) {
                if (members.side_b_full_refs[i] == members.side_b_full_refs[j]) {
                    return false;
                }
            }
        }
        return true;
    };

    candidate.war_context_status = WarContextStatus::absent;
    candidate.war_members = WarMembers{};
    if (known_router) {
        if (war_candidate == 0u) {
            candidate.war_context_status = WarContextStatus::absent;
        } else {
            Address war_root_field = 0;
            if (war_candidate < kMinCanonicalAddress
                    || war_candidate % alignof(Address) != 0u
                    || !detail::checked_add(war_candidate,
                                             kWarHistoryRootOffset,
                                             war_root_field)
                    || !detail::checked_range(war_root_field,
                                               sizeof(Address), combat_probe_end)
                    || !bounded.read(war_root_field,
                                     reinterpret_cast<unsigned char*>(&saved_war_root),
                                     sizeof(Address))) {
                candidate.war_context_status = WarContextStatus::invalid;
            } else {
                Address expected_root = 0;
                if (!detail::checked_add(module_base,
                                         kWarHistoryRootVtableRva,
                                         expected_root)
                        || expected_root % alignof(Address) != 0u
                        || saved_war_root != expected_root
                        || !detail::in_image(saved_war_root, sizeof(Address),
                                              module_base, image_end)) {
                    candidate.war_context_status = WarContextStatus::invalid;
                } else {
                    const auto read_war_side = [&](
                            const std::array<std::size_t, 3>& offsets,
                            std::array<std::uint64_t, kMaxWarMembers>& refs,
                            std::uint32_t& count,
                            WarVectorBounds& bounds) noexcept -> bool {
                        std::array<unsigned char, sizeof(Address) * 3u> header{};
                        Address address = 0;
                        if (!detail::checked_add(war_candidate, offsets[0], address)
                                || !bounded.read(address, header.data(), header.size())) {
                            return false;
                        }
                        bounds.begin = detail::load_u64(header.data());
                        bounds.end = detail::load_u64(
                            header.data() + sizeof(Address));
                        bounds.capacity = detail::load_u64(
                            header.data() + sizeof(Address) * 2u);
                        if (!valid_war_bounds(bounds)) return false;
                        count = static_cast<std::uint32_t>(
                            (bounds.end - bounds.begin) / sizeof(Address));
                        if (count != 0u) {
                            if (!bounded.read(bounds.begin,
                                              reinterpret_cast<unsigned char*>(refs.data()),
                                              static_cast<std::size_t>(
                                                  bounds.end - bounds.begin))) {
                                return false;
                            }
                            for (std::uint32_t i = 0; i < count; ++i) {
                                if (!detail::valid_country_full_ref(refs[i])) return false;
                            }
                        }
                        return true;
                    };
                    if (!read_war_side(kWarSideABounds,
                                       candidate.war_members.side_a_full_refs,
                                       candidate.war_members.side_a_count,
                                       saved_war_bounds[0])
                            || !read_war_side(kWarSideBBounds,
                                              candidate.war_members.side_b_full_refs,
                                              candidate.war_members.side_b_count,
                                              saved_war_bounds[1])
                            || !war_refs_unique(candidate.war_members)) {
                        if (bounded.fatal()) return false;
                        candidate.war_context_status = WarContextStatus::invalid;
                        candidate.war_members = WarMembers{};
                    } else {
                        candidate.war_context_status = WarContextStatus::observed;
                        candidate.war_members.vectors_complete = true;
                        const auto contains = [](const std::array<std::uint64_t,
                                                                  kMaxWarMembers>& refs,
                                                 std::uint32_t count,
                                                 std::uint64_t value) noexcept {
                            for (std::uint32_t i = 0; i < count; ++i) {
                                if (refs[i] == value) return true;
                            }
                            return false;
                        };
                        candidate.war_members.physical_player_is_war_member =
                            contains(candidate.war_members.side_a_full_refs,
                                     candidate.war_members.side_a_count,
                                     physical_player_full_ref)
                            || contains(candidate.war_members.side_b_full_refs,
                                        candidate.war_members.side_b_count,
                                        physical_player_full_ref);
                        candidate.war_members.physical_player_membership_known = true;
                    }
                }
            }
        }
    }

    if (bounded.fatal()) return false;

    // Re-read all core side pointers, headers, raw slots and participant refs.
    // A change in any required combat value invalidates the whole copy.
    std::array<unsigned char, sizeof(Address) * 2u> side_pointer_recheck{};
    if (!bounded.read(combat + kCombatSideAOffset,
                      side_pointer_recheck.data(), side_pointer_recheck.size())
            || side_pointer_recheck != side_pointer_raw) {
        return false;
    }
    const auto recheck_side = [&](Address side_address,
                                  const CombatSide& side,
                                  const std::array<unsigned char,
                                      kSideHeaderBytes>& saved_header) noexcept {
        if (side_address == 0u) return !side.present;
        std::array<unsigned char, kSideHeaderBytes> header{};
        if (!bounded.read(side_address + kSideHeaderOffset, header.data(),
                          header.size()) || header != saved_header) {
            return false;
        }
        const Address begin = detail::load_u64(
            header.data() + kParticipantBeginOffset - kSideHeaderOffset);
        for (std::uint32_t i = 0; i < side.participants.count; ++i) {
            Address row_address = 0;
            std::array<unsigned char, sizeof(Address)> raw_ref{};
            if (!detail::checked_add(begin,
                                     static_cast<Address>(i)
                                         * kParticipantRowBytes
                                         + kParticipantFullRefOffset,
                                     row_address)
                    || !bounded.read(row_address, raw_ref.data(), raw_ref.size())) {
                return false;
            }
            const std::uint64_t ref = detail::load_u64(raw_ref.data());
            if (!detail::valid_country_full_ref(ref)
                    || ref != side.participants.full_refs[i]) {
                return false;
            }
        }
        return true;
    };
    if (!recheck_side(side_a_address, candidate.sides[0], saved_side_headers[0])
            || !recheck_side(side_b_address, candidate.sides[1], saved_side_headers[1])) {
        return false;
    }

    if (candidate.war_context_status == WarContextStatus::observed) {
        Address war_root_field = 0;
        Address current_war_root = 0;
        if (!detail::checked_add(war_candidate, kWarHistoryRootOffset,
                                 war_root_field)
                || !bounded.read(war_root_field,
                                 reinterpret_cast<unsigned char*>(&current_war_root),
                                 sizeof(Address))) {
            if (bounded.fatal()) return false;
            candidate.war_context_status = WarContextStatus::invalid;
            candidate.war_members = WarMembers{};
        } else if (current_war_root != saved_war_root) {
            candidate.war_context_status = WarContextStatus::invalid;
            candidate.war_members = WarMembers{};
        } else {
            const auto recheck_war_side = [&](
                    const std::array<std::size_t, 3>& offsets,
                    const std::array<std::uint64_t, kMaxWarMembers>& refs,
                    std::uint32_t count,
                    const WarVectorBounds& saved_bounds) noexcept -> bool {
                std::array<unsigned char, sizeof(Address) * 3u> header{};
                Address address = 0;
                if (!detail::checked_add(war_candidate, offsets[0], address)
                        || !bounded.read(address, header.data(), header.size())) {
                    return false;
                }
                WarVectorBounds current{};
                current.begin = detail::load_u64(header.data());
                current.end = detail::load_u64(header.data() + sizeof(Address));
                current.capacity = detail::load_u64(
                    header.data() + sizeof(Address) * 2u);
                if (!valid_war_bounds(current)
                        || current.begin != saved_bounds.begin
                        || current.end != saved_bounds.end
                        || current.capacity != saved_bounds.capacity
                        || count != static_cast<std::uint32_t>(
                            current.end - current.begin) / sizeof(Address)) {
                    return false;
                }
                for (std::uint32_t i = 0; i < count; ++i) {
                    Address ref_address = 0;
                    std::array<unsigned char, sizeof(Address)> raw_ref{};
                    if (!detail::checked_add(current.begin,
                                             static_cast<Address>(i)
                                                 * sizeof(Address),
                                             ref_address)
                            || !bounded.read(ref_address, raw_ref.data(),
                                             raw_ref.size())) {
                        return false;
                    }
                    const std::uint64_t ref = detail::load_u64(raw_ref.data());
                    if (!detail::valid_country_full_ref(ref) || ref != refs[i]) return false;
                }
                return true;
            };
            if (!recheck_war_side(kWarSideABounds,
                                  candidate.war_members.side_a_full_refs,
                                  candidate.war_members.side_a_count,
                                  saved_war_bounds[0])
                    || !recheck_war_side(kWarSideBBounds,
                                         candidate.war_members.side_b_full_refs,
                                         candidate.war_members.side_b_count,
                                         saved_war_bounds[1])
                    || !war_refs_unique(candidate.war_members)) {
                if (bounded.fatal()) return false;
                candidate.war_context_status = WarContextStatus::invalid;
                candidate.war_members = WarMembers{};
            }
        }
    }

    if (bounded.fatal()) return false;

    // This post-copy proof catches a vtable, slot-pointer, or leaf change that
    // occurred while the side/war context was being copied.
    KindProbe second{};
    if (!probe(second)
            || first.vtable != second.vtable
            || first.code != second.code
            || first.bytes != second.bytes
            || first.selector != second.selector) {
        return false;
    }
    candidate.raw_selector = second.selector;
    candidate.selector_code = second.bytes;
    candidate.kind = second.selector == 1u ? Kind::land : Kind::naval;

    // Commit only after every required combat read, optional-war fatal guard,
    // stability recheck, and both kind proofs succeed.
    std::memcpy(&output, &candidate, sizeof(candidate));
    return true;
}

}  // namespace information::battle::owned_context

#endif  // INFORMATION_BATTLE_OWNED_CONTEXT_H
