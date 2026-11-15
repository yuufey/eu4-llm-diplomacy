#ifndef INFORMATION_CURRENT_COUNTRY_CONTROL_POLICY_H
#define INFORMATION_CURRENT_COUNTRY_CONTROL_POLICY_H

// Pure policy for a single, already-authorized current-country transition.
// This header deliberately has no process, engine, or platform calls. The host
// owns all durable reservation, memory reads, native invocation, and frame I/O.

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace information::current_country_control {

enum class Country : std::uint8_t { por, fra };

struct Request {
    std::array<char,65> id{};
    std::array<char,65> dll_sha{};
    std::uint32_t pid{};
    std::uint64_t creation{};
    std::int32_t date{};
    Country from{Country::por};
    Country to{Country::por};
};

struct Identity {
    std::uint32_t pid{};
    std::uint64_t creation{};
    std::array<char,65> dll_sha{};
};

struct Snapshot {
    std::uintptr_t game{};
    std::uintptr_t player_country{};
    std::uintptr_t target_country{};
    std::uint64_t player_ref{};
    std::uint64_t target_ref{};
    std::int32_t date{};
    std::int32_t speed{};
    std::int32_t province_count{};
    std::int32_t human_count{};
    bool paused{};
    bool alternate_current{};
    // The host sets this only after exact database membership and fullref checks.
    bool read_ok{};
};

enum class Reason : std::uint8_t {
    ok,
    invalid_request,
    identity_mismatch,
    direction_already_attempted,
    code_guard_failed,
    capture_not_idle,
    snapshot_read_failed,
    stale_date,
    game_not_paused,
    alternate_current_active,
    human_count_not_single_player,
    province_count_invalid,
    game_pointer_invalid,
    country_pointer_invalid,
    country_pointers_not_distinct,
    player_reference_invalid,
    target_reference_invalid,
    player_tag_mismatch,
    target_tag_mismatch,
};

inline constexpr const char* tag(Country country) noexcept {
    switch (country) {
    case Country::por: return "POR";
    case Country::fra: return "FRA";
    }
    return nullptr;
}

inline constexpr unsigned bit(Country country) noexcept {
    switch (country) {
    case Country::fra: return 1u;
    case Country::por: return 2u;
    }
    return 0u;
}

inline constexpr const char* reason_name(Reason reason) noexcept {
    switch (reason) {
    case Reason::ok: return "ok";
    case Reason::invalid_request: return "invalid_request";
    case Reason::identity_mismatch: return "identity_mismatch";
    case Reason::direction_already_attempted: return "direction_already_attempted";
    case Reason::code_guard_failed: return "code_guard_failed";
    case Reason::capture_not_idle: return "capture_not_idle";
    case Reason::snapshot_read_failed: return "snapshot_read_failed";
    case Reason::stale_date: return "stale_date";
    case Reason::game_not_paused: return "game_not_paused";
    case Reason::alternate_current_active: return "alternate_current_active";
    case Reason::human_count_not_single_player: return "human_count_not_single_player";
    case Reason::province_count_invalid: return "province_count_invalid";
    case Reason::game_pointer_invalid: return "game_pointer_invalid";
    case Reason::country_pointer_invalid: return "country_pointer_invalid";
    case Reason::country_pointers_not_distinct: return "country_pointers_not_distinct";
    case Reason::player_reference_invalid: return "player_reference_invalid";
    case Reason::target_reference_invalid: return "target_reference_invalid";
    case Reason::player_tag_mismatch: return "player_tag_mismatch";
    case Reason::target_tag_mismatch: return "target_tag_mismatch";
    }
    return "invalid_reason";
}

namespace detail {

inline constexpr std::size_t kMaxPacketBytes = 320u;
inline constexpr std::uint64_t kMaximumUserPointer = UINT64_C(0x00007fffffffffff);
inline constexpr std::uint64_t kMinimumUserPointer = UINT64_C(0x10000);

inline constexpr bool ascii_alpha(char value) noexcept {
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

inline constexpr bool ascii_digit(char value) noexcept {
    return value >= '0' && value <= '9';
}

inline constexpr bool id_character(char value) noexcept {
    return ascii_alpha(value) || ascii_digit(value) || value == '_' || value == '-';
}

inline constexpr bool lower_hex(char value) noexcept {
    return ascii_digit(value) || (value >= 'a' && value <= 'f');
}

inline bool valid_id(const std::array<char,65>& value) noexcept {
    std::size_t length = 0;
    while (length < value.size() && value[length] != '\0') ++length;
    if (length == 0 || length > 64u) return false;
    for (std::size_t index=0; index<length; ++index) {
        if (!id_character(value[index])) return false;
    }
    for (std::size_t index=length; index<value.size(); ++index) {
        if (value[index] != '\0') return false;
    }
    return true;
}

inline bool valid_sha(const std::array<char,65>& value) noexcept {
    for (std::size_t index=0; index<64u; ++index) {
        if (!lower_hex(value[index])) return false;
    }
    return value[64] == '\0';
}

template<class Integer>
inline bool parse_positive(std::string_view token, Integer& output) noexcept {
    if (token.empty()) return false;
    Integer parsed{};
    const char* const first = token.data();
    const char* const last = first + token.size();
    const auto result = std::from_chars(first,last,parsed,10);
    if (result.ec != std::errc{} || result.ptr != last || parsed <= 0) return false;
    output = parsed;
    return true;
}

inline bool parse_country(std::string_view token, Country& output) noexcept {
    if (token == "POR") {
        output = Country::por;
        return true;
    }
    if (token == "FRA") {
        output = Country::fra;
        return true;
    }
    return false;
}

inline bool valid_pair(Country from, Country to) noexcept {
    return ((from == Country::por && to == Country::fra)
            || (from == Country::fra && to == Country::por));
}

inline bool valid_request(const Request& request) noexcept {
    return valid_id(request.id) && request.pid != 0u && request.creation != 0u
        && request.date > 0 && valid_sha(request.dll_sha)
        && valid_pair(request.from,request.to);
}

inline constexpr std::uint32_t tag_value(Country country) noexcept {
    const char* const value = tag(country);
    if (value == nullptr) return 0u;
    return static_cast<std::uint32_t>(static_cast<unsigned char>(value[0]))
        | (static_cast<std::uint32_t>(static_cast<unsigned char>(value[1])) << 8u)
        | (static_cast<std::uint32_t>(static_cast<unsigned char>(value[2])) << 16u);
}

inline bool reference_valid(std::uint64_t reference) noexcept {
    return reference != 0u && ((reference >> 56u) & UINT64_C(0xff)) != 0u;
}

inline bool reference_has_tag(std::uint64_t reference, Country country) noexcept {
    return (reference & UINT64_C(0x00ffffff)) == tag_value(country);
}

inline bool canonical_pointer(std::uintptr_t pointer) noexcept {
    const auto value = static_cast<std::uint64_t>(pointer);
    return value >= kMinimumUserPointer && value <= kMaximumUserPointer;
}

} // namespace detail

inline bool parse_request(std::string_view packet, Request& output) noexcept {
    if (packet.empty() || packet.size() > detail::kMaxPacketBytes
        || packet.back() != '\n') return false;
    for (std::size_t index=0; index<packet.size(); ++index) {
        const char value = packet[index];
        if (value == '\0' || value == '\r' || (value == '\n' && index+1u != packet.size()))
            return false;
    }

    const std::string_view body(packet.data(),packet.size()-1u);
    std::array<std::string_view,9> tokens{};
    std::size_t begin = 0;
    for (std::size_t index=0; index<tokens.size(); ++index) {
        const std::size_t separator = body.find(' ',begin);
        if (index+1u == tokens.size()) {
            if (separator != std::string_view::npos || begin >= body.size()) return false;
            tokens[index] = body.substr(begin);
        } else {
            if (separator == std::string_view::npos || separator == begin) return false;
            tokens[index] = body.substr(begin,separator-begin);
            begin = separator+1u;
            if (begin >= body.size()) return false;
        }
    }

    if (tokens[0] != "EU4COUNTRY1" || tokens[1] != "TEST_ONLY"
        || tokens[2].empty() || tokens[2].size() > 64u
        || tokens[6].size() != 64u) return false;
    for (char value : tokens[2]) {
        if (!detail::id_character(value)) return false;
    }
    for (char value : tokens[6]) {
        if (!detail::lower_hex(value)) return false;
    }

    Request parsed{};
    for (std::size_t index=0; index<tokens[2].size(); ++index)
        parsed.id[index] = tokens[2][index];
    if (!detail::parse_positive(tokens[3],parsed.pid)
        || !detail::parse_positive(tokens[4],parsed.creation)
        || !detail::parse_positive(tokens[5],parsed.date)) return false;
    for (std::size_t index=0; index<tokens[6].size(); ++index)
        parsed.dll_sha[index] = tokens[6][index];
    if (!detail::parse_country(tokens[7],parsed.from)
        || !detail::parse_country(tokens[8],parsed.to)
        || !detail::valid_pair(parsed.from,parsed.to)) return false;
    output = parsed;
    return true;
}

inline Reason admit(const Request& request, const Identity& identity,
                    const Snapshot& snapshot, bool code_guard,
                    bool capture_idle, unsigned attempted_mask) noexcept {
    if (!detail::valid_request(request)) return Reason::invalid_request;
    if (request.pid != identity.pid || request.creation != identity.creation
        || request.dll_sha != identity.dll_sha) return Reason::identity_mismatch;
    // Attempt bits name the requested destination country, so each direction
    // has one stable bit: POR->FRA consumes FRA's bit, and FRA->POR consumes POR's.
    if ((attempted_mask & bit(request.to)) != 0u) return Reason::direction_already_attempted;
    if (!code_guard) return Reason::code_guard_failed;
    if (!capture_idle) return Reason::capture_not_idle;
    if (!snapshot.read_ok) return Reason::snapshot_read_failed;
    if (request.date != snapshot.date) return Reason::stale_date;
    if (!snapshot.paused || snapshot.speed != 0) return Reason::game_not_paused;
    if (snapshot.alternate_current) return Reason::alternate_current_active;
    // game+a60 is the Human-list size. This operator admits only the observed
    // single-human state; the zero-human bootstrap path is not authorized here.
    if (snapshot.human_count != 1) return Reason::human_count_not_single_player;
    if (snapshot.province_count <= 0) return Reason::province_count_invalid;
    if (!detail::canonical_pointer(snapshot.game)) return Reason::game_pointer_invalid;
    if (!detail::canonical_pointer(snapshot.player_country)
        || !detail::canonical_pointer(snapshot.target_country)) return Reason::country_pointer_invalid;
    if (snapshot.player_country == snapshot.target_country)
        return Reason::country_pointers_not_distinct;
    if (!detail::reference_valid(snapshot.player_ref)) return Reason::player_reference_invalid;
    if (!detail::reference_valid(snapshot.target_ref)) return Reason::target_reference_invalid;
    if (!detail::reference_has_tag(snapshot.player_ref,request.from)) return Reason::player_tag_mismatch;
    if (!detail::reference_has_tag(snapshot.target_ref,request.to)) return Reason::target_tag_mismatch;
    return Reason::ok;
}

inline bool same_precondition(Snapshot left, Snapshot right) noexcept {
    return left.game == right.game
        && left.player_country == right.player_country
        && left.target_country == right.target_country
        && left.player_ref == right.player_ref
        && left.target_ref == right.target_ref
        && left.date == right.date
        && left.speed == right.speed
        && left.province_count == right.province_count
        && left.human_count == right.human_count
        && left.paused == right.paused
        && left.alternate_current == right.alternate_current
        && left.read_ok == right.read_ok;
}

inline bool effect_confirmed(Request request, Snapshot before,
                             Snapshot after, std::uint64_t native_return) noexcept {
    return detail::valid_request(request) && native_return == 1u
        && before.read_ok && after.read_ok
        && before.game == after.game
        && before.date == request.date && after.date == request.date
        && before.human_count == 1 && after.human_count == 1
        && before.paused && after.paused && before.speed == 0 && after.speed == 0
        && detail::reference_valid(before.player_ref)
        && detail::reference_valid(before.target_ref)
        && detail::reference_has_tag(before.player_ref,request.from)
        && detail::reference_has_tag(before.target_ref,request.to)
        && after.player_ref == before.target_ref
        && after.target_ref == before.target_ref
        && detail::reference_has_tag(after.player_ref,request.to);
}

inline bool allow_automation(std::uint64_t reference,
                             std::uint64_t authorized_fra_ref) noexcept {
    if (reference == 0u) return false;
    if (detail::reference_has_tag(reference,Country::por)
        && ((reference >> 32u) & UINT64_C(0xffff)) == 189u) return true;
    return authorized_fra_ref != 0u && reference == authorized_fra_ref
        && detail::reference_has_tag(reference,Country::fra);
}

} // namespace information::current_country_control

#endif
