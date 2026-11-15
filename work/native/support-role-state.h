#ifndef BRIDGE_SUPPORT_ROLE_STATE_H
#define BRIDGE_SUPPORT_ROLE_STATE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace bridge::support_role_state {

struct Snapshot {
    bool readable = false;
    bool actor_is_subject = false;
    bool recipient_is_subject = false;
};

namespace detail {

inline constexpr std::uintptr_t kMinimumUserPointer = 0x10000u;
inline constexpr std::uintptr_t kMaximumUserPointer = 0x800000000000u;
inline constexpr std::uintptr_t kCountryFullrefOffset = 0x20u;
inline constexpr std::uintptr_t kOverlordFullrefOffset = 0x18F0u;
inline constexpr unsigned kFullrefHighByteShift = 56u;

inline bool valid_fullref(std::uint64_t fullref) noexcept {
    return fullref != 0 && (fullref >> kFullrefHighByteShift) != 0;
}

inline bool has_overlord(std::uint64_t fullref) noexcept {
    return (fullref >> kFullrefHighByteShift) != 0;
}

inline bool valid_country_pointer(std::uintptr_t pointer) noexcept {
    return pointer >= kMinimumUserPointer
        && pointer < kMaximumUserPointer
        && (pointer & (sizeof(std::uint64_t) - 1u)) == 0;
}

inline bool field_address(std::uintptr_t country, std::uintptr_t offset,
                          std::uintptr_t& address) noexcept {
    if (!valid_country_pointer(country)) return false;

    constexpr auto maximum = std::numeric_limits<std::uintptr_t>::max();
    if (offset > maximum - country) return false;

    const auto field = country + offset;
    if (sizeof(std::uint64_t) > maximum - field) return false;
    if (field >= kMaximumUserPointer
            || sizeof(std::uint64_t) > kMaximumUserPointer - field) return false;

    address = field;
    return true;
}

template <typename Reader>
bool read_u64(Reader& reader, std::uintptr_t address,
              std::uint64_t& value) noexcept {
    std::array<unsigned char, sizeof(std::uint64_t)> bytes{};
    if (!reader.read(address, bytes.data(), bytes.size())) return false;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return true;
}

struct Fields {
    std::uint64_t actor_fullref = 0;
    std::uint64_t actor_overlord_fullref = 0;
    std::uint64_t recipient_fullref = 0;
    std::uint64_t recipient_overlord_fullref = 0;
};

template <typename Reader>
bool read_fields(Reader& reader, std::uintptr_t actor_country,
                 std::uintptr_t recipient_country, Fields& fields) noexcept {
    std::uintptr_t actor_fullref_address = 0;
    std::uintptr_t actor_overlord_address = 0;
    std::uintptr_t recipient_fullref_address = 0;
    std::uintptr_t recipient_overlord_address = 0;
    if (!field_address(actor_country, kCountryFullrefOffset, actor_fullref_address)
            || !field_address(actor_country, kOverlordFullrefOffset, actor_overlord_address)
            || !field_address(recipient_country, kCountryFullrefOffset, recipient_fullref_address)
            || !field_address(recipient_country, kOverlordFullrefOffset, recipient_overlord_address)) {
        return false;
    }

    return read_u64(reader, actor_fullref_address, fields.actor_fullref)
        && read_u64(reader, actor_overlord_address, fields.actor_overlord_fullref)
        && read_u64(reader, recipient_fullref_address, fields.recipient_fullref)
        && read_u64(reader, recipient_overlord_address, fields.recipient_overlord_fullref);
}

inline bool same_fields(const Fields& left, const Fields& right) noexcept {
    return left.actor_fullref == right.actor_fullref
        && left.actor_overlord_fullref == right.actor_overlord_fullref
        && left.recipient_fullref == right.recipient_fullref
        && left.recipient_overlord_fullref == right.recipient_overlord_fullref;
}

template <typename Reader>
bool validate_overlord(Reader& reader, std::uint64_t overlord_fullref,
                       std::uint64_t country_fullref, std::uintptr_t country) noexcept {
    if (!has_overlord(overlord_fullref)) return true;
    if (overlord_fullref == country_fullref) return false;

    std::uintptr_t overlord_country = 0;
    return reader.resolve(overlord_fullref, overlord_country)
        && valid_country_pointer(overlord_country)
        && overlord_country != country;
}

} // namespace detail

template <typename Reader>
bool capture(Reader& reader, std::uint64_t actor, std::uint64_t recipient,
             Snapshot& output) noexcept {
    output = Snapshot{};

    if (!detail::valid_fullref(actor) || !detail::valid_fullref(recipient)
            || actor == recipient) {
        return false;
    }

    std::uintptr_t actor_country = 0;
    std::uintptr_t recipient_country = 0;
    const bool actor_resolved = reader.resolve(actor, actor_country);
    const bool recipient_resolved = reader.resolve(recipient, recipient_country);
    if (!actor_resolved || !recipient_resolved
            || !detail::valid_country_pointer(actor_country)
            || !detail::valid_country_pointer(recipient_country)) {
        return false;
    }

    detail::Fields first{};
    if (!detail::read_fields(reader, actor_country, recipient_country, first)
            || first.actor_fullref != actor
            || first.recipient_fullref != recipient
            || !detail::validate_overlord(reader, first.actor_overlord_fullref, actor, actor_country)
            || !detail::validate_overlord(reader, first.recipient_overlord_fullref, recipient, recipient_country)) {
        return false;
    }

    std::uintptr_t actor_country_again = 0;
    std::uintptr_t recipient_country_again = 0;
    const bool actor_resolved_again = reader.resolve(actor, actor_country_again);
    const bool recipient_resolved_again = reader.resolve(recipient, recipient_country_again);
    if (!actor_resolved_again || !recipient_resolved_again
            || !detail::valid_country_pointer(actor_country_again)
            || !detail::valid_country_pointer(recipient_country_again)
            || actor_country_again != actor_country
            || recipient_country_again != recipient_country) {
        return false;
    }

    detail::Fields second{};
    if (!detail::read_fields(reader, actor_country_again, recipient_country_again, second)
            || !detail::same_fields(first, second)) {
        return false;
    }

    output.readable = true;
    output.actor_is_subject = detail::has_overlord(first.actor_overlord_fullref);
    output.recipient_is_subject = detail::has_overlord(first.recipient_overlord_fullref);
    return true;
}

} // namespace bridge::support_role_state

#endif
