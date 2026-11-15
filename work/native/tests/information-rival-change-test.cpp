#include "../information-rival-change.h"

#include <cstdio>

namespace change = information::rival_change;

static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) {
        ++failures;
        std::printf("FAIL %s\n", name);
    }
}

#define CHECK(expression) check((expression), #expression)

static change::Snapshot snapshot(int count, bool target_active, int target_since,
    bool old_active = false, int old_since = -1) {
    change::Snapshot value{};
    value.verified = true;
    value.count = count;
    value.target = {target_active, target_since};
    value.old_rival = {old_active, old_since};
    return value;
}

static void test_set_and_remove() {
    ++scenarios;
    CHECK(change::classify(change::Kind::set, 100,
        snapshot(0, false, -1), snapshot(1, true, 100)) == change::Outcome::changed);
    CHECK(change::classify(change::Kind::set, 100,
        snapshot(1, true, 90), snapshot(1, true, 90)) == change::Outcome::unchanged);
    CHECK(change::classify(change::Kind::remove, 100,
        snapshot(1, true, 90), snapshot(0, false, -1)) == change::Outcome::changed);
    CHECK(change::classify(change::Kind::remove, 100,
        snapshot(1, true, 90), snapshot(1, true, 90)) == change::Outcome::unchanged);
}

static void test_replace_full_and_partial() {
    ++scenarios;
    CHECK(change::classify(change::Kind::replace, 100,
        snapshot(1, false, -1, true, 80), snapshot(1, true, 100, false, -1))
        == change::Outcome::changed);
    // A partial result still counts as changed when only the new rival is added.
    CHECK(change::classify(change::Kind::replace, 100,
        snapshot(1, false, -1, true, 80), snapshot(2, true, 100, true, 80))
        == change::Outcome::changed);
    // A partial result also counts as changed when only the old rival is removed.
    CHECK(change::classify(change::Kind::replace, 100,
        snapshot(2, true, 80, true, 70), snapshot(1, true, 80, false, -1))
        == change::Outcome::changed);
    CHECK(change::classify(change::Kind::replace, 100,
        snapshot(1, true, 80, false, -1), snapshot(1, true, 80, false, -1))
        == change::Outcome::unchanged);
}

static void test_invalid_or_unreadable_snapshots() {
    ++scenarios;
    auto before = snapshot(0, false, -1);
    auto after = snapshot(1, true, 100);
    before.verified = false;
    CHECK(change::classify(change::Kind::set, 100, before, after)
        == change::Outcome::unreadable);

    before = snapshot(-1, false, -1);
    CHECK(change::classify(change::Kind::set, 100, before, after)
        == change::Outcome::unreadable);
    before = snapshot(65, false, -1);
    CHECK(change::classify(change::Kind::set, 100, before, after)
        == change::Outcome::unreadable);

    before = snapshot(1, true, 101);
    CHECK(change::classify(change::Kind::remove, 100, before,
        snapshot(0, false, -1)) == change::Outcome::unreadable);
    before = snapshot(0, false, 0);
    CHECK(change::classify(change::Kind::set, 100, before, after)
        == change::Outcome::unreadable);

    before = snapshot(0, false, -1);
    CHECK(change::classify(change::Kind::set, 0, before, after)
        == change::Outcome::unreadable);
    CHECK(change::classify(static_cast<change::Kind>(0), 100, before, after)
        == change::Outcome::unreadable);

    CHECK(change::classify(change::Kind::set, 100,
        snapshot(0, false, -1, true, 80), after) == change::Outcome::unreadable);
    CHECK(change::classify(change::Kind::set, 100,
        snapshot(0, false, -1), snapshot(0, true, 100)) == change::Outcome::unreadable);
    CHECK(change::classify(change::Kind::replace, 100,
        snapshot(1, false, -1, true, 80), snapshot(1, true, 100, true, 80))
        == change::Outcome::unreadable);
}

int main() {
    test_set_and_remove();
    test_replace_full_and_partial();
    test_invalid_or_unreadable_snapshots();
    std::printf("rival change classifier: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
