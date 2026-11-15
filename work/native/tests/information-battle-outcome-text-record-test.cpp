#include "../information-battle-outcome-text-record.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

namespace record = information::battle::outcome_text_record;
namespace owned = information::battle::owned_outcome_text;
namespace wire = information::battle::outcome_text_wire;
namespace model = information::battle::display_context;

static constexpr std::uint64_t kSequence = 226u;
static constexpr std::int32_t kDate = 56564904;
static constexpr std::uint8_t kKind = 1u;
static constexpr const char* kRawText[owned::kOutcomeKeyCount] = {
    "$ALLIES_WON$ <b>$COUNTRY$</b>",
    "$ALLIES_LOST$ : $COUNTRY$",
    "$YOU_WON$|$RESULT$",
    "$YOU_LOST$|$RESULT$",
    "$RESULT_WON$|$COUNTRY$",
    "$RESULT_LOSS$|$COUNTRY$",
    "$OTHERRESULT$|$COUNTRY$",
    "$WARSCORE_FROM_BATTLE$|$VALUE$",
    "$MESSAGE_HEAD_MIL$|$TITLE$",
    "$MESSENGER$|$SENDER$",
};

static owned::Snapshot g_source{};
static owned::Result g_result{};
static wire::Snapshot g_output{};
static unsigned g_checks = 0u;

constexpr std::size_t kOverlapBytes =
    sizeof(owned::Snapshot) > sizeof(wire::Snapshot)
        ? sizeof(owned::Snapshot) : sizeof(wire::Snapshot);
alignas(std::max_align_t) static unsigned char g_overlap[kOverlapBytes]{};
alignas(std::max_align_t) static unsigned char g_overlap_before[kOverlapBytes]{};

static void check(bool ok, const char* name) {
    ++g_checks;
    if (!ok) {
        std::fprintf(stderr, "FAIL:%s\n", name);
        std::exit(1);
    }
}

static void set_text(owned::OutcomeValue& value, const char* bytes,
                     std::size_t length) {
    value = owned::OutcomeValue{};
    value.state = model::State::observed;
    value.length = static_cast<std::uint32_t>(length);
    if (length != 0u) std::memcpy(value.bytes.data(), bytes, length);
    value.bytes[length] = 0u;
}

static void initialize(owned::Snapshot& source, owned::Result& result) {
    source = owned::Snapshot{};
    source.sequence = kSequence;
    source.raw_date = kDate;
    source.kind = kKind;

    source.language.state = model::State::observed;
    source.language.length = 9u;
    std::memcpy(source.language.bytes.data(), "l_english", 9u);
    source.language.bytes[9u] = 0u;

    for (std::size_t index = 0u; index < owned::kOutcomeKeyCount; ++index) {
        set_text(source.fields[index], kRawText[index], std::strlen(kRawText[index]));
    }

    result = owned::Result{};
    result.attempted = true;
    result.observed = true;
    result.two_pass_consistent = true;
    result.failure = model::Failure::none;
}

static bool assign_valid(bool captured = true) {
    return record::assign(kSequence, kDate, kKind, captured,
                          g_source, g_result, g_output);
}

static void set_stale_output() {
    g_output = wire::Snapshot{};
    g_output.sequence = 1u;
    g_output.raw_date = 2;
    g_output.kind = 2u;
    g_output.failure = 0u;
    g_output.fields[wire::language].state = wire::State::known;
    g_output.fields[wire::language].length = 8u;
    std::memcpy(g_output.fields[wire::language].bytes.data(), "l_oldest", 8u);
    g_output.fields[wire::MESSENGER].state = wire::State::known;
    g_output.fields[wire::MESSENGER].length = 3u;
    std::memcpy(g_output.fields[wire::MESSENGER].bytes.data(), "OLD", 3u);
}

static void check_unknown_group(const char* label) {
    for (std::size_t index = 0u; index < wire::kFieldCount; ++index) {
        const wire::Text& field = g_output.fields[index];
        check(field.state == wire::State::unknown, label);
        check(field.length == 0u, label);
        for (const unsigned char byte : field.bytes) check(byte == 0u, label);
    }
}

static void expect_invalid_success(const char* label) {
    set_stale_output();
    check(assign_valid(), "invalid-success returns a canonical failed group");
    check(g_output.sequence == kSequence && g_output.raw_date == kDate
              && g_output.kind == kKind,
          "invalid-success retains requested event identity");
    check(g_output.failure == static_cast<std::uint16_t>(model::Failure::invalid_input),
          "invalid-success maps to invalid_input");
    check_unknown_group(label);
}

static void test_order_raw_and_language() {
    initialize(g_source, g_result);
    set_stale_output();
    check(assign_valid(), "valid capture is accepted");
    check(g_output.sequence == kSequence && g_output.raw_date == kDate
              && g_output.kind == kKind && g_output.failure == 0u,
          "success preserves event identity and zero failure");

    const wire::Text& language = g_output.fields[wire::language];
    check(language.state == wire::State::known && language.length == 9u
              && std::memcmp(language.bytes.data(), "l_english", 9u) == 0,
          "language is copied to wire slot zero");
    for (std::size_t index = 0u; index < owned::kOutcomeKeyCount; ++index) {
        const wire::Text& field = g_output.fields[index + 1u];
        const std::size_t length = std::strlen(kRawText[index]);
        check(field.state == wire::State::known
                  && field.length == length
                  && std::memcmp(field.bytes.data(), kRawText[index], length) == 0,
              "ten raw localization values retain source order and bytes");
    }
}

static void test_empty_and_absent() {
    initialize(g_source, g_result);
    set_text(g_source.fields[0u], "", 0u);
    g_source.fields[1u] = owned::OutcomeValue{};
    g_source.fields[1u].state = model::State::absent;
    set_stale_output();
    check(assign_valid(), "empty and absent capture is accepted");
    check(g_output.fields[wire::ALLIES_WON].state == wire::State::known
              && g_output.fields[wire::ALLIES_WON].length == 0u,
          "observed empty value remains known empty");
    check(g_output.fields[wire::ALLIES_LOST].state == wire::State::absent
              && g_output.fields[wire::ALLIES_LOST].length == 0u,
          "absent value remains distinct from known empty");
}

static void test_uncaptured_failure_mapping() {
    initialize(g_source, g_result);
    g_result.failure = model::Failure::none;
    set_stale_output();
    check(record::assign(kSequence, kDate, kKind, false,
                         g_source, g_result, g_output),
          "uncaptured group with zero source failure is accepted as unknown");
    check(g_output.failure == static_cast<std::uint16_t>(model::Failure::not_captured),
          "zero failure falls back to not_captured");
    check_unknown_group("uncaptured zero failure clears every field");

    initialize(g_source, g_result);
    g_result.failure = model::Failure::guard;
    set_stale_output();
    check(record::assign(kSequence, kDate, kKind, false,
                         g_source, g_result, g_output),
          "uncaptured group with failure eight is accepted");
    check(g_output.failure == 8u, "failure eight is retained");
    check_unknown_group("uncaptured failure eight clears every field");
}

static void test_full_length_does_not_copy_terminator() {
    initialize(g_source, g_result);
    owned::OutcomeValue& full = g_source.fields[0u];
    full = owned::OutcomeValue{};
    full.state = model::State::observed;
    full.length = static_cast<std::uint32_t>(wire::kMaxTextBytes);
    for (std::size_t index = 0u; index < wire::kMaxTextBytes; ++index) {
        full.bytes[index] = static_cast<unsigned char>('Z');
    }
    full.bytes[wire::kMaxTextBytes] = 0u;
    set_stale_output();
    check(assign_valid(), "8192-byte source value is accepted");
    const wire::Text& copied = g_output.fields[wire::ALLIES_WON];
    check(copied.state == wire::State::known
              && copied.length == wire::kMaxTextBytes,
          "full wire field keeps exact 8192-byte length");
    bool exact = true;
    for (std::size_t index = 0u; index < wire::kMaxTextBytes; ++index) {
        exact = exact && copied.bytes[index] == static_cast<unsigned char>('Z');
    }
    check(exact, "full wire field copies only the 8192 source bytes");
    check(g_output.fields[wire::ALLIES_LOST].state == wire::State::known
              && g_output.fields[wire::ALLIES_LOST].length == std::strlen(kRawText[1u])
              && std::memcmp(g_output.fields[wire::ALLIES_LOST].bytes.data(),
                             kRawText[1u], std::strlen(kRawText[1u])) == 0,
          "source terminator does not overwrite the next wire field");
}

static void test_invalid_success_inputs() {
    initialize(g_source, g_result);
    g_source.sequence += 1u;
    expect_invalid_success("identity mismatch makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.raw_date += 1;
    expect_invalid_success("date mismatch makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.kind = 2u;
    expect_invalid_success("kind mismatch makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.language.bytes[0u] = static_cast<unsigned char>('x');
    expect_invalid_success("invalid language makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.fields[4u].state = model::State::unknown;
    expect_invalid_success("unknown input field makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.fields[3u].bytes[2u] = 0u;
    expect_invalid_success("embedded NUL makes the whole group unknown");

    initialize(g_source, g_result);
    g_source.fields[3u].length = static_cast<std::uint32_t>(wire::kMaxTextBytes + 1u);
    expect_invalid_success("over-limit length makes the whole group unknown");

    initialize(g_source, g_result);
    g_result.observed = false;
    expect_invalid_success("unobserved result makes the whole group unknown");

    initialize(g_source, g_result);
    g_result.two_pass_consistent = false;
    expect_invalid_success("inconsistent result makes the whole group unknown");
}

static void test_clear_removes_old_text() {
    initialize(g_source, g_result);
    check(assign_valid(), "precondition: a known group is assigned");
    record::clear(g_output, kSequence + 1u, kDate + 1, 2u,
                  model::Failure::invalid_input);
    check(g_output.sequence == kSequence + 1u && g_output.raw_date == kDate + 1
              && g_output.kind == 2u
              && g_output.failure == static_cast<std::uint16_t>(model::Failure::invalid_input),
          "clear installs only the new identity and failure");
    check_unknown_group("clear leaves no old text or state");
}

static void test_source_output_overlap_is_refused_unchanged() {
    owned::Snapshot* overlap_source = new (g_overlap) owned::Snapshot{};
    initialize(*overlap_source, g_result);
    std::memcpy(g_overlap_before, g_overlap, sizeof(*overlap_source));

    // assign returns from the address-range guard before reading either alias.
    wire::Snapshot& overlapping_output =
        *reinterpret_cast<wire::Snapshot*>(static_cast<void*>(g_overlap));
    check(!record::assign(kSequence, kDate, kKind, true,
                          *overlap_source, g_result, overlapping_output),
          "source/output overlap is refused");
    check(std::memcmp(g_overlap, g_overlap_before, sizeof(*overlap_source)) == 0,
          "source/output overlap leaves shared storage unchanged");
}

static void test_result_output_overlap_is_refused_unchanged() {
    initialize(g_source, g_result);
    check(assign_valid(), "precondition: shared output contains known text");
    wire::Snapshot* overlap_output = new (g_overlap) wire::Snapshot(g_output);
    std::memcpy(g_overlap_before, g_overlap, sizeof(*overlap_output));

    // assign returns from the address-range guard before reading either alias.
    const owned::Result& overlapping_result =
        *reinterpret_cast<const owned::Result*>(static_cast<const void*>(g_overlap));
    check(!record::assign(kSequence, kDate, kKind, true,
                          g_source, overlapping_result, *overlap_output),
          "result/output overlap is refused");
    check(std::memcmp(g_overlap, g_overlap_before, sizeof(*overlap_output)) == 0,
          "result/output overlap leaves shared storage unchanged");
}

int main() {
    test_order_raw_and_language();
    test_empty_and_absent();
    test_uncaptured_failure_mapping();
    test_full_length_does_not_copy_terminator();
    test_invalid_success_inputs();
    test_clear_removes_old_text();
    test_source_output_overlap_is_refused_unchanged();
    test_result_output_overlap_is_refused_unchanged();
    std::printf("{\"checks\":%u,\"status\":\"ok\"}\n", g_checks);
    return 0;
}
