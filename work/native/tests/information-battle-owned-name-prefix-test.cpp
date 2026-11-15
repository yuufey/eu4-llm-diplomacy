#define main old_display_context_test_main
#include "information-battle-owned-display-context-test.cpp"
#undef main

#include "../information-battle-owned-name-prefix.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>

namespace prefix = information::battle::owned_name_prefix;
namespace prefix_model = information::battle::display_context;

namespace {

constexpr char kBattleText[] = "battle text";
int prefix_failures = 0;

void prefix_check(bool ok, const char* label) {
    std::printf("CHECK %s %s\n", label, ok ? "PASS" : "FAIL");
    if (!ok) ++prefix_failures;
}

struct PrefixReader final {
    FakeReader* source = nullptr;
    std::size_t calls = 0u;
    std::size_t bytes = 0u;
    std::size_t fail_at = 0u;
    Address last_address = 0u;

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++calls;
        last_address = address;
        bytes += size;
        if (calls == fail_at) return false;
        return source != nullptr && source->read(address, destination, size);
    }
};

static_assert(information::battle::owned_name_sources::reader_contract<PrefixReader>::value);

struct PrefixGuard final {
    int calls = 0;
    int fail_at = 0;
    bool guard() noexcept { return ++calls != fail_at; }
};

struct PrefixFixture final {
    Fixture& source = fixture();
    PrefixReader reader{};
    PrefixGuard guard{};
    prefix::Workspace workspace{};
    prefix::Snapshot output{};
    prefix::Result result{};

    bool build(int mode, const char* language = "l_english") noexcept {
        if (!build_fixture(source, 1u, false, false, -1, false)) return false;
        reader = PrefixReader{};
        reader.source = &source.reader;
        guard = PrefixGuard{};
        workspace.clear();
        output = prefix::Snapshot{};
        result = prefix::Result{};

        const bool empty_table = mode == 3;
        const char* key = mode == 1 ? "OTHER" : "BATTLE_OF";
        const char* value = mode == 0 ? kBattleText : (mode == 1 ? "other" : "");
        const std::size_t value_length = empty_table ? 0u : std::strlen(value);
        const std::uint64_t pool_begin = empty_table ? 0u : kLocalizationPool;
        const std::uint64_t pool_end = empty_table ? 0u : kLocalizationPool + value_length + 1u;
        const std::uint64_t pool_capacity = empty_table
            ? 0u : kLocalizationPool + kLocalizationPoolRegionBytes;
        const std::uint64_t table_begin = empty_table ? 0u : kLocalizationTable;
        const std::uint64_t table_end = empty_table
            ? 0u : kLocalizationTable + owned::kLocalizationEntryStride;
        const std::uint64_t table_capacity = empty_table ? 0u : 8u;
        const std::uint64_t hash = owned::detail::localization_hash(key);
        const std::uint32_t offset = 0u;
        if (!put_string32(source.reader,
                kLocalizationInner + owned::kLocalizationLanguageOffset,
                language, false, 0u)
                || !source.reader.put(kLocalizationOuter +
                                          owned::kLocalizationPoolBeginOffset,
                                      pool_begin)
                || !source.reader.put(kLocalizationOuter +
                                          owned::kLocalizationPoolEndOffset,
                                      pool_end)
                || !source.reader.put(kLocalizationOuter +
                                          owned::kLocalizationPoolCapacityEndOffset,
                                      pool_capacity)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableBeginOffset,
                                      table_begin)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableEndOffset,
                                      table_end)
                || !source.reader.put(kLocalizationInner +
                                          owned::kLocalizationTableCapacityOffset,
                                      table_capacity)) return false;
        if (empty_table) return true;
        std::array<unsigned char, 64u> bytes{};
        if (value_length != 0u)
            std::memcpy(bytes.data(), value, value_length);
        return source.reader.put(kLocalizationTable +
                                     owned::kLocalizationEntryHashOffset, hash)
            && source.reader.put(kLocalizationTable +
                                     owned::kLocalizationEntryValueOffset, offset)
            && source.reader.put_bytes(kLocalizationPool, bytes.data(), value_length + 1u);
    }

    bool capture() noexcept {
        return prefix::capture(reader, guard, kImageBase, kImageSize, kGame,
                               42u, kDate, 1u, workspace, output, result);
    }
};

PrefixFixture& prefix_fixture() {
    static PrefixFixture value{};
    return value;
}

bool text_equals(const prefix::OwnedText& text, const char* expected) noexcept {
    const std::size_t length = std::strlen(expected);
    return text.length == length && text.bytes[length] == 0u
        && std::memcmp(text.bytes.data(), expected, length) == 0;
}

bool output_cleared(const PrefixFixture& value) noexcept {
    return value.output.state == prefix_model::State::unknown
        && value.output.template_state == prefix_model::State::unknown
        && value.output.language.length == 0u
        && value.output.template_text.length == 0u
        && value.workspace.first_pass.record_count == 0u
        && value.workspace.first_pass.bytes_used == 0u
        && !value.result.observed && !value.result.two_pass_consistent;
}

void test_cached_battle_of_states() {
    PrefixFixture& f = prefix_fixture();
    bool setup = f.build(0);
    bool ok = setup && f.capture();
    prefix_check(ok && f.output.state == prefix_model::State::observed
                     && f.output.template_state == prefix_model::State::observed
                     && text_equals(f.output.language, "l_english")
                     && text_equals(f.output.template_text, kBattleText),
                  "cached_BATTLE_OF_text_and_language_are_copied");
    prefix_check(ok && f.result.two_pass_consistent
                     && f.result.read_calls == f.reader.calls
                     && f.result.read_calls <= owned::kMaxTotalReadCalls
                     && f.result.bytes_read <= owned::kMaxTotalReadBytes,
                  "cache_copy_is_two_pass_and_within_existing_budget");

    setup = f.build(1);
    ok = setup && f.capture();
    prefix_check(ok && f.output.template_state == prefix_model::State::absent
                     && f.output.template_text.length == 0u,
                  "unrelated_nonempty_cache_marks_BATTLE_OF_absent");
    setup = f.build(2);
    ok = setup && f.capture();
    prefix_check(ok && f.output.template_state == prefix_model::State::observed
                     && f.output.template_text.length == 0u
                     && f.output.template_text.bytes[0] == 0u,
                  "present_empty_BATTLE_OF_value_remains_observed_empty");
    setup = f.build(3);
    ok = setup && f.capture();
    prefix_check(ok && f.output.state == prefix_model::State::observed
                     && f.output.template_state == prefix_model::State::absent,
                  "empty_localization_table_marks_template_absent");
}

void test_language_and_read_failure() {
    PrefixFixture& f = prefix_fixture();
    bool setup = f.build(0, "english");
    bool ok = setup && f.capture();
    prefix_check(!ok && f.result.failure == prefix_model::Failure::cache_invalid
                     && output_cleared(f),
                  "language_without_l__prefix_is_rejected");
    setup = f.build(0);
    f.reader.fail_at = 3u;
    ok = setup && f.capture();
    prefix_check(!ok && f.result.failure == prefix_model::Failure::read_failed
                     && f.reader.calls == 3u && output_cleared(f),
                  "cache_read_failure_clears_partial_result");
}

void expect_changed(Address address, const unsigned char* bytes, std::size_t size,
                    prefix_model::Failure failure, const char* label) {
    PrefixFixture& f = prefix_fixture();
    const bool setup = f.build(0);
    f.source.reader.mutate_on_second_date = true;
    f.source.reader.mutation_address = address;
    f.source.reader.mutation_size = size;
    std::memcpy(f.source.reader.mutation_bytes.data(), bytes, size);
    const bool ok = setup && f.capture();
    prefix_check(!ok && f.result.failure == failure && output_cleared(f), label);
}

void test_second_pass_changes() {
    const unsigned char changed_text[] = {'c','h','a','n','g','e','d',0u};
    expect_changed(kLocalizationPool, changed_text, sizeof(changed_text),
                   prefix_model::Failure::source_changed,
                   "cache_content_change_between_passes_withdraws_text");
    const std::uint64_t moved_inner = UINT64_C(0x332000);
    expect_changed(kLocalizationOuter + owned::kLocalizationOuterInnerOffset,
                   reinterpret_cast<const unsigned char*>(&moved_inner),
                   sizeof(moved_inner), prefix_model::Failure::source_changed,
                   "cache_path_change_between_passes_withdraws_text");
}

void test_date_change() {
    const std::int32_t next_date = kDate + 1;
    expect_changed(kGame + owned::kGameDateOffset,
                   reinterpret_cast<const unsigned char*>(&next_date),
                   sizeof(next_date), prefix_model::Failure::source_changed,
                   "date_change_between_passes_withdraws_text");
}

void test_each_guard_stage() {
    PrefixFixture& f = prefix_fixture();
    for (int stage = 1; stage <= 3; ++stage) {
        const bool setup = f.build(0);
        f.guard.fail_at = stage;
        const bool ok = setup && f.capture();
        prefix_check(!ok && f.guard.calls == stage
                         && f.result.failure == prefix_model::Failure::guard
                         && output_cleared(f),
                     stage == 1 ? "guard_before_failure_clears"
                         : (stage == 2 ? "guard_between_failure_clears"
                                       : "guard_after_failure_clears"));
    }
}

void test_source_alias_rejected_before_reader() {
    PrefixFixture& f = prefix_fixture();
    const bool setup = f.build(0);
    const Address alias = reinterpret_cast<Address>(&f.workspace);
    (void)f.source.reader.put(owned::kLocalizationCellRva + kImageBase,
                              static_cast<std::uint64_t>(alias));
    const bool ok = setup && f.capture();
    prefix_check(!ok && f.result.failure == prefix_model::Failure::invalid_input
                     && f.reader.calls == 2u && f.reader.last_address == kImageBase + owned::kLocalizationCellRva
                     && output_cleared(f),
                  "source_alias_is_rejected_before_reader_access");
}

union WorkspaceOutput final {
    prefix::Workspace workspace;
    prefix::Snapshot output;
    WorkspaceOutput() noexcept {}
    ~WorkspaceOutput() {}
};
union WorkspaceResult final {
    prefix::Workspace workspace;
    prefix::Result result;
    WorkspaceResult() noexcept {}
    ~WorkspaceResult() {}
};
union SnapshotResult final {
    prefix::Snapshot output;
    prefix::Result result;
    SnapshotResult() noexcept {}
    ~SnapshotResult() {}
};

template <std::size_t N>
bool unchanged(const void* object, const std::array<unsigned char, N>& before) {
    return std::memcmp(object, before.data(), N) == 0;
}

void test_parameter_aliases_are_untouched() {
    PrefixFixture& f = prefix_fixture();
    (void)f.build(0);
    WorkspaceOutput a{};
    new (&a.workspace) prefix::Workspace{};
    a.workspace.first_snapshot.identity.sequence = 17u;
    std::array<unsigned char, sizeof(a)> before_a{};
    std::memcpy(before_a.data(), &a, sizeof(a));
    const bool a_ok = prefix::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, a.workspace,
        *reinterpret_cast<prefix::Snapshot*>(&a), f.result);
    prefix_check(!a_ok && unchanged(&a, before_a)
                     && f.reader.calls == 0u && f.guard.calls == 0,
                  "workspace_output_alias_returns_without_mutation");

    (void)f.build(0);
    WorkspaceResult b{};
    new (&b.workspace) prefix::Workspace{};
    b.workspace.second_snapshot.identity.sequence = 23u;
    std::array<unsigned char, sizeof(b)> before_b{};
    std::memcpy(before_b.data(), &b, sizeof(b));
    const bool b_ok = prefix::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, b.workspace, f.output,
        *reinterpret_cast<prefix::Result*>(&b));
    prefix_check(!b_ok && unchanged(&b, before_b)
                     && f.reader.calls == 0u && f.guard.calls == 0,
                  "workspace_result_alias_returns_without_mutation");

    (void)f.build(0);
    SnapshotResult c{};
    new (&c.output) prefix::Snapshot{};
    c.output.sequence = 31u;
    std::array<unsigned char, sizeof(c)> before_c{};
    std::memcpy(before_c.data(), &c, sizeof(c));
    const bool c_ok = prefix::capture(f.reader, f.guard, kImageBase, kImageSize,
        kGame, 42u, kDate, 1u, f.workspace, c.output,
        *reinterpret_cast<prefix::Result*>(&c));
    prefix_check(!c_ok && unchanged(&c, before_c)
                     && f.reader.calls == 0u && f.guard.calls == 0,
                  "output_result_alias_returns_without_mutation");
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--date-change-only") == 0) {
        test_date_change();
    } else if (argc == 1) {
        test_cached_battle_of_states();
        test_language_and_read_failure();
        test_second_pass_changes();
        test_date_change();
        test_each_guard_stage();
        test_source_alias_rejected_before_reader();
        test_parameter_aliases_are_untouched();
    } else return 2;
    std::printf("PREFIX RESULT %s failures=%d\n",
                prefix_failures == 0 ? "PASS" : "FAIL", prefix_failures);
    return prefix_failures == 0 ? 0 : 1;
}
