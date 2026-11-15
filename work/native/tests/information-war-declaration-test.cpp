#include "../information-war-declaration.h"

#include <cstdio>
#include <initializer_list>

namespace declaration = information::war_declaration;

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

static declaration::References references(std::initializer_list<uintptr_t> values,
    bool complete = true) {
    declaration::References result{};
    result.complete = complete;
    for (const auto value : values) result.values[result.count++] = value;
    return result;
}

static void test_empty_and_one_new_reference() {
    ++scenarios;
    CHECK(declaration::difference(references({}), references({})).outcome
        == declaration::Outcome::unchanged);
    const auto added = declaration::difference(references({}), references({0x1000}));
    CHECK(added.outcome == declaration::Outcome::single_added);
    CHECK(added.reference == 0x1000);
}

static void test_existing_war_and_one_new_reference() {
    ++scenarios;
    const auto before = references({0x1000, 0x2000});
    const auto after = references({0x2000, 0x1000, 0x3000});
    const auto result = declaration::difference(before, after);
    CHECK(result.outcome == declaration::Outcome::single_added);
    CHECK(result.reference == 0x3000);
}

static void test_duplicate_and_incomplete_inputs() {
    ++scenarios;
    CHECK(!declaration::valid(references({0x1000, 0x1000})));
    CHECK(declaration::difference(references({0x1000, 0x1000}), references({0x1000})).outcome
        == declaration::Outcome::unreadable);
    CHECK(declaration::difference(references({}), references({0x1000}, false)).outcome
        == declaration::Outcome::unreadable);
    auto oversized = references({});
    oversized.count = static_cast<unsigned>(declaration::kMaxReferences + 1);
    CHECK(declaration::difference(references({}), oversized).outcome
        == declaration::Outcome::unreadable);
}

static void test_multiple_new_references_are_ambiguous() {
    ++scenarios;
    const auto result = declaration::difference(references({0x1000}),
        references({0x1000, 0x2000, 0x3000}));
    CHECK(result.outcome == declaration::Outcome::ambiguous);
    CHECK(result.reference == 0);
}

static void test_removal_without_addition_is_unchanged() {
    ++scenarios;
    const auto result = declaration::difference(references({0x1000, 0x2000}),
        references({0x2000}));
    CHECK(result.outcome == declaration::Outcome::unchanged);
    CHECK(result.reference == 0);
}

int main() {
    test_empty_and_one_new_reference();
    test_existing_war_and_one_new_reference();
    test_duplicate_and_incomplete_inputs();
    test_multiple_new_references_are_ambiguous();
    test_removal_without_addition_is_unchanged();
    std::printf("war declaration pair difference: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
