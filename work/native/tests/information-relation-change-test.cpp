#include "../information-relation-change.h"

#include <cstdio>
#include <cstring>

using information::relation_change::Kind;
using information::relation_change::Outcome;
using information::relation_change::Snapshot;

static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { \
        ++failures; \
        std::fprintf(stderr, "FAIL: %s\n", message); \
    } \
} while (0)

static Snapshot state(Kind kind, bool active) {
    Snapshot value{};
    value.complete = true;
    value.active = active;
    if (kind == Kind::guarantee && active)
        value.guarantee_actor_grants = true;
    if (kind == Kind::subject && active) {
        value.subject_actor_is_overlord = true;
        std::strcpy(value.subject_type, "vassal");
    }
    return value;
}

static void test_six_relation_classes() {
    ++scenarios;
    constexpr Kind kinds[] = {
        Kind::alliance,
        Kind::royal_marriage,
        Kind::military_access,
        Kind::guarantee,
        Kind::support_independence,
        Kind::subject,
    };

    for (const Kind kind : kinds) {
        const Snapshot inactive = state(kind, false);
        const Snapshot active = state(kind, true);
        CHECK(information::relation_change::valid(kind, inactive),
            "inactive snapshot is valid for every relation kind");
        CHECK(information::relation_change::valid(kind, active),
            "active snapshot is valid for every relation kind");
        CHECK(information::relation_change::classify(kind, inactive, active)
                == Outcome::activated,
            "inactive to active is classified as activation");
        CHECK(information::relation_change::classify(kind, active, inactive)
                == Outcome::deactivated,
            "active to inactive is classified as deactivation");
        CHECK(information::relation_change::classify(kind, inactive, inactive)
                == Outcome::unchanged,
            "identical inactive snapshots are a no-op");
        CHECK(information::relation_change::classify(kind, active, active)
                == Outcome::unchanged,
            "identical active snapshots are a no-op");
    }
}

static void test_subject_type_and_role_changes() {
    ++scenarios;
    Snapshot before{};
    before.complete = true;
    before.active = true;
    before.subject_actor_is_overlord = true;
    std::strcpy(before.subject_type, "vassal");

    Snapshot after = before;
    after.subject_actor_is_overlord = false;
    after.subject_actor_is_subject = true;
    std::strcpy(after.subject_type, "personal_union");
    CHECK(information::relation_change::valid(Kind::subject, before),
        "subject before snapshot has exactly one valid role");
    CHECK(information::relation_change::valid(Kind::subject, after),
        "subject after snapshot has exactly one valid role");
    CHECK(information::relation_change::classify(Kind::subject, before, after)
            == Outcome::changed,
        "subject type and role changes are preserved while active stays true");

    Snapshot role_only = before;
    role_only.subject_actor_is_overlord = false;
    role_only.subject_actor_is_subject = true;
    CHECK(information::relation_change::classify(Kind::subject, before, role_only)
            == Outcome::changed,
        "subject role change is observable without an active-bit change");

    Snapshot type_only = before;
    std::strcpy(type_only.subject_type, "personal_union");
    CHECK(information::relation_change::classify(Kind::subject, before, type_only)
            == Outcome::changed,
        "subject type change is observable without a role change");
}

static void test_guarantee_direction_change() {
    ++scenarios;
    Snapshot before{};
    before.complete = true;
    before.active = true;
    before.guarantee_actor_grants = true;

    Snapshot after{};
    after.complete = true;
    after.active = true;
    after.guarantee_recipient_grants = true;
    CHECK(information::relation_change::valid(Kind::guarantee, before),
        "guarantee actor-to-recipient direction is valid");
    CHECK(information::relation_change::valid(Kind::guarantee, after),
        "guarantee recipient-to-actor direction is valid");
    CHECK(information::relation_change::classify(Kind::guarantee, before, after)
            == Outcome::changed,
        "guarantee direction changes are visible while the relation remains active");
}

static void test_support_role_change_is_unreadable() {
    ++scenarios;
    Snapshot before{};
    before.complete = true;
    before.active = true;
    Snapshot after = before;
    after.support_actor_is_subject = true;
    CHECK(information::relation_change::valid(Kind::support_independence, before),
        "support-role before snapshot is valid");
    CHECK(information::relation_change::valid(Kind::support_independence, after),
        "support-role after snapshot is valid");
    CHECK(information::relation_change::classify(Kind::support_independence, before, after)
            == Outcome::unreadable,
        "support relation role drift with active unchanged is rejected as unreadable");
}

static void test_invalid_cross_kind_fields() {
    ++scenarios;
    Snapshot invalid{};
    invalid.complete = true;
    invalid.support_actor_is_subject = true;
    CHECK(!information::relation_change::valid(Kind::alliance, invalid),
        "support role fields are forbidden on non-support kinds");

    invalid = Snapshot{};
    invalid.complete = true;
    invalid.active = true;
    std::strcpy(invalid.subject_type, "vassal");
    CHECK(!information::relation_change::valid(Kind::subject, invalid),
        "active subject must identify exactly one endpoint role");

    invalid.subject_actor_is_overlord = true;
    invalid.subject_actor_is_subject = true;
    CHECK(!information::relation_change::valid(Kind::subject, invalid),
        "subject endpoints cannot both be the subject role");

    invalid = Snapshot{};
    invalid.complete = true;
    invalid.subject_actor_is_overlord = true;
    CHECK(!information::relation_change::valid(Kind::subject, invalid),
        "inactive subject must not retain role fields");

    Snapshot missing{};
    CHECK(information::relation_change::classify(Kind::alliance, missing, missing)
            == Outcome::unreadable,
        "incomplete snapshots cannot be classified as a no-op");
}

int main() {
    test_six_relation_classes();
    test_guarantee_direction_change();
    test_subject_type_and_role_changes();
    test_support_role_change_is_unreadable();
    test_invalid_cross_kind_fields();
    std::printf("information relation value classifier: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
