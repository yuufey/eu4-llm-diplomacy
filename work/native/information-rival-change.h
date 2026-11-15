#ifndef INFORMATION_RIVAL_CHANGE_H
#define INFORMATION_RIVAL_CHANGE_H

// Owned membership values around the existing B23 Set/Replace/Remove command
// trampolines. This layer performs no native call, allocation or memory access.
#include <cstdint>

namespace information::rival_change {

enum class Kind : unsigned char { set = 1, replace = 2, remove = 3 };
enum class Outcome : unsigned char { unreadable, unchanged, changed };
struct Membership final {
    bool active = false;
    std::int32_t since_date = -1;
};
struct Snapshot final {
    bool verified = false;
    std::int32_t count = -1;
    Membership target{};
    Membership old_rival{};
};
struct Change final {
    Kind kind = Kind::set;
    std::uint64_t actor = 0, target = 0, old_rival = 0;
    std::int32_t date = 0;
    Snapshot before{}, after{};
};

inline bool valid(const Membership& value, std::int32_t date) noexcept {
    return value.active ? value.since_date >= 0 && value.since_date <= date
                        : value.since_date == -1;
}

inline bool valid(const Snapshot& value, Kind kind, std::int32_t date) noexcept {
    const bool replace = kind == Kind::replace;
    const int observed = static_cast<int>(value.target.active)
        + static_cast<int>(replace && value.old_rival.active);
    return value.verified && value.count >= observed && value.count <= 64
        && valid(value.target, date) && valid(value.old_rival, date)
        && (replace || !value.old_rival.active);
}

inline Outcome classify(Kind kind, std::int32_t date,
    const Snapshot& before, const Snapshot& after) noexcept {
    if (date <= 0 || (kind != Kind::set && kind != Kind::replace && kind != Kind::remove)
        || !valid(before, kind, date) || !valid(after, kind, date)) return Outcome::unreadable;
    const bool replace = kind == Kind::replace;
    const int delta = static_cast<int>(after.target.active) - static_cast<int>(before.target.active)
        + (replace ? static_cast<int>(after.old_rival.active) - static_cast<int>(before.old_rival.active) : 0);
    if (after.count - before.count != delta) return Outcome::unreadable;
    if (before.target.active == after.target.active
        && (!replace || before.old_rival.active == after.old_rival.active)) return Outcome::unchanged;
    return Outcome::changed;
}

} // namespace information::rival_change
#endif
