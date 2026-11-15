#pragma once

#include <cstdint>
#include <cstring>

namespace information::relation_change {

enum class Kind : uint8_t {
    alliance, royal_marriage, military_access, guarantee, support_independence, subject
};

struct Snapshot final {
    bool complete = false;
    bool active = false;
    bool guarantee_actor_grants = false;
    bool guarantee_recipient_grants = false;
    bool support_actor_is_subject = false;
    bool support_recipient_is_subject = false;
    bool subject_actor_is_overlord = false;
    bool subject_actor_is_subject = false;
    char subject_type[65]{};
};

enum class Outcome : uint8_t { unreadable, unchanged, activated, deactivated, changed };

inline const char* name(Kind kind) noexcept {
    switch (kind) {
    case Kind::alliance: return "alliance";
    case Kind::royal_marriage: return "royal_marriage";
    case Kind::military_access: return "military_access";
    case Kind::guarantee: return "guarantee";
    case Kind::support_independence: return "support_independence";
    case Kind::subject: return "subject";
    }
    return nullptr;
}

inline bool valid(Kind kind, const Snapshot& value) noexcept {
    if (!name(kind) || !value.complete) return false;
    if (kind == Kind::guarantee) {
        if (value.active != (value.guarantee_actor_grants || value.guarantee_recipient_grants)) return false;
    } else if (value.guarantee_actor_grants || value.guarantee_recipient_grants) return false;
    if (kind != Kind::support_independence
        && (value.support_actor_is_subject || value.support_recipient_is_subject)) return false;
    if (kind != Kind::subject || !value.active)
        return !value.subject_actor_is_overlord && !value.subject_actor_is_subject && !value.subject_type[0];
    if (value.subject_actor_is_overlord == value.subject_actor_is_subject || !value.subject_type[0]) return false;
    for (unsigned index = 0; index < sizeof(value.subject_type); ++index) {
        const auto byte = static_cast<unsigned char>(value.subject_type[index]);
        if (!byte) return true;
        if (byte < 0x20 || byte > 0x7e || byte == '"' || byte == '\\') return false;
    }
    return false;
}

inline Outcome classify(Kind kind, const Snapshot& before, const Snapshot& after) noexcept {
    if (!valid(kind, before) || !valid(kind, after)) return Outcome::unreadable;
    if (before.active != after.active) return after.active ? Outcome::activated : Outcome::deactivated;
    if (kind == Kind::guarantee
        && (before.guarantee_actor_grants != after.guarantee_actor_grants
            || before.guarantee_recipient_grants != after.guarantee_recipient_grants)) return Outcome::changed;
    if (kind == Kind::support_independence && before.active
        && (before.support_actor_is_subject != after.support_actor_is_subject
            || before.support_recipient_is_subject != after.support_recipient_is_subject)) return Outcome::unreadable;
    if (kind == Kind::subject && before.active
        && (before.subject_actor_is_overlord != after.subject_actor_is_overlord
            || before.subject_actor_is_subject != after.subject_actor_is_subject
            || std::strcmp(before.subject_type, after.subject_type))) return Outcome::changed;
    return Outcome::unchanged;
}

} // namespace information::relation_change
