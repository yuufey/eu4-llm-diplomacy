#ifndef INFORMATION_LAND_PROMISE_H
#define INFORMATION_LAND_PROMISE_H

#include <array>
#include <cstdint>
#include <cstring>
#include "information-war-declaration.h"
#include "information-land-promise-native-guards.h"

namespace information::land_promise {

using References = war_declaration::References;
constexpr unsigned kCapacity = 64, kMaxPromises = 128;
enum class Kind : unsigned char { none, declaration, call };

inline bool contains(const References& references, std::uintptr_t pointer,
                     std::uint64_t birth) noexcept {
    for (unsigned index = 0; index < references.count; ++index)
        if (references.values[index] == pointer && references.births[index] == birth) return true;
    return false;
}

inline bool joined(const References& actor_before, const References& actor_after,
                   const References& beneficiary_before, const References& beneficiary_after,
                   unsigned index) noexcept {
    if (!war_declaration::valid(actor_before) || !war_declaration::valid(actor_after)
        || !war_declaration::valid(beneficiary_before) || !war_declaration::valid(beneficiary_after)
        || index >= beneficiary_after.count) return false;
    const auto pointer = beneficiary_after.values[index];
    const auto birth = beneficiary_after.births[index];
    return contains(actor_before, pointer, birth) && contains(actor_after, pointer, birth)
        && !contains(beneficiary_before, pointer, birth);
}

struct Value final {
    std::uint64_t promisor = 0, beneficiary = 0, observer = 0;
    std::int32_t date = 0;
    Kind kind = Kind::none;
    char war_id[30]{};
};

inline bool same(const Value& left, const Value& right) noexcept {
    return left.promisor == right.promisor && left.beneficiary == right.beneficiary
        && left.date == right.date && !std::strcmp(left.war_id, right.war_id);
}

} // namespace information::land_promise
#endif
