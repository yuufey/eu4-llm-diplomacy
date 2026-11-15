#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "format_input_builder.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using battle_format_input::BuildStatus;
using battle_format_input::ExpansionStatus;
using battle_format_input::InputRow;
using battle_format_input::NativeArg104;
using battle_format_input::Workspace;

namespace {

constexpr std::array<std::uint8_t, 59> kPinnedLeafBytes{
    0x33, 0xc0, 0x48, 0x89, 0x11, 0x48, 0x89, 0x41, 0x08, 0x48,
    0x89, 0x41, 0x18, 0x48, 0x89, 0x41, 0x30, 0x48, 0x89, 0x41,
    0x40, 0x89, 0x41, 0x50, 0x48, 0x89, 0x41, 0x58, 0x48, 0x8b,
    0xc1, 0x48, 0xc7, 0x41, 0x20, 0x0f, 0x00, 0x00, 0x00, 0xc7,
    0x41, 0x28, 0x02, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x41, 0x48,
    0x0f, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x41, 0x60, 0xc3,
};

using NativeLeaf = NativeArg104* (*)(NativeArg104*, const char*, const char*);
static_assert(std::is_pointer_v<NativeLeaf>);
static_assert(sizeof(NativeLeaf) == sizeof(void*));

std::size_t g_check_count = 0;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
    ++g_check_count;
}

bool contains_only_zeroes(const NativeArg104& argument,
                          std::size_t offset, std::size_t count) {
    return std::all_of(argument.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                       argument.bytes.begin() + static_cast<std::ptrdiff_t>(offset + count),
                       [](std::uint8_t byte) { return byte == 0; });
}

class OwnedCodePage final {
public:
    OwnedCodePage() = default;
    OwnedCodePage(const OwnedCodePage&) = delete;
    OwnedCodePage& operator=(const OwnedCodePage&) = delete;
    ~OwnedCodePage() {
        if (base_ != nullptr) {
            VirtualFree(base_, 0, MEM_RELEASE);
        }
    }

    bool allocate_copy_seal(const std::uint8_t* bytes, std::size_t length) noexcept {
        if (base_ != nullptr || bytes == nullptr || length != kPinnedLeafBytes.size()) {
            return false;
        }
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        page_bytes_ = static_cast<std::size_t>(info.dwPageSize);
        if (page_bytes_ < length || page_bytes_ == 0) {
            return false;
        }
        base_ = static_cast<std::uint8_t*>(VirtualAlloc(
            nullptr, page_bytes_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (base_ == nullptr) {
            return false;
        }

        MEMORY_BASIC_INFORMATION before{};
        if (VirtualQuery(base_, &before, sizeof(before)) != sizeof(before) ||
            before.State != MEM_COMMIT || before.Type != MEM_PRIVATE ||
            before.AllocationBase != base_ || before.Protect != PAGE_READWRITE) {
            return false;
        }
        std::memcpy(base_, bytes, length);
        DWORD old_protection = 0;
        if (!VirtualProtect(base_, page_bytes_, PAGE_EXECUTE_READ, &old_protection) ||
            old_protection != PAGE_READWRITE) {
            return false;
        }
        if (!FlushInstructionCache(GetCurrentProcess(), base_, length)) {
            return false;
        }

        MEMORY_BASIC_INFORMATION after{};
        if (VirtualQuery(base_, &after, sizeof(after)) != sizeof(after) ||
            after.State != MEM_COMMIT || after.Type != MEM_PRIVATE ||
            after.AllocationBase != base_ || after.Protect != PAGE_EXECUTE_READ) {
            return false;
        }
        sealed_ = true;
        return true;
    }

    NativeLeaf function() const noexcept {
        return sealed_ ? reinterpret_cast<NativeLeaf>(base_) : nullptr;
    }

    bool release_and_verify_free() noexcept {
        if (base_ == nullptr || !sealed_) {
            return false;
        }
        const auto old_address = reinterpret_cast<std::uintptr_t>(base_);
        if (!VirtualFree(base_, 0, MEM_RELEASE)) {
            return false;
        }
        base_ = nullptr;
        sealed_ = false;
        MEMORY_BASIC_INFORMATION after_free{};
        if (VirtualQuery(reinterpret_cast<const void*>(old_address), &after_free,
                         sizeof(after_free)) != sizeof(after_free)) {
            return false;
        }
        return after_free.State == MEM_FREE;
    }

private:
    std::uint8_t* base_{};
    std::size_t page_bytes_{};
    bool sealed_{};
};

void test_builder_owned_strings_and_leaf() {
    std::string base = "battle.test.engagement";
    std::string row_key = "left_losses";
    std::string row_value = "47";
    std::string localization = "Losses: $left_losses$";
    std::vector<InputRow> rows;
    rows.push_back({row_key, row_value});

    Workspace workspace;
    require(workspace.build(base, rows, localization) == BuildStatus::ok,
            "build owned positive strings");
    require(workspace.body_key() != nullptr &&
                std::string_view(workspace.body_key()) == "battle.test.engagement_1",
            "body key receives literal _1 suffix");
    require(workspace.argument_count() == 1, "one contiguous argument entry");

    const auto* argument = workspace.argument(0);
    require(argument != nullptr, "argument entry exists");
    const auto* key = battle_format_input::cstr_pointer(*argument, 0x00);
    const auto* value = battle_format_input::cstr_pointer(*argument, 0x60);
    require(key != nullptr && value != nullptr, "C string fields are present");
    require(std::string_view(key) == "left_losses", "owned row key copied");
    require(std::string_view(value) == "47", "owned row value copied");
    require(workspace.owns_c_string(workspace.body_key(), 256),
            "body key pointer lies in owned arena");
    require(workspace.owns_c_string(key, 256), "row key pointer lies in owned arena");
    require(workspace.owns_c_string(value, 8192), "row value pointer lies in owned arena");
    require(workspace.expansion_status() == ExpansionStatus::below_limit &&
                workspace.expansion_below_limit(),
            "synthetic resolved template receives bounded expansion status");
    const auto localization_placeholders = static_cast<std::size_t>(
        std::count(localization.begin(), localization.end(), '$'));
    require(workspace.expansion_worst_case_bytes() ==
                localization.size() + localization_placeholders * 8200,
            "worst-case expansion formula uses max value plus overhead");

    // Prove that subsequent caller edits cannot change pointers owned by Workspace.
    base[0] = 'X';
    row_key[0] = 'X';
    row_value[0] = 'X';
    rows[0].key[1] = 'X';
    rows[0].value[1] = 'X';
    require(std::string_view(workspace.body_key()) == "battle.test.engagement_1",
            "body key remains stable after source mutation");
    require(std::string_view(key) == "left_losses" && std::string_view(value) == "47",
            "argument C strings remain stable after source mutation");

    // The exact pinned leaf executes once, from this fixture's own RW->RX page.
    OwnedCodePage code;
    require(code.allocate_copy_seal(kPinnedLeafBytes.data(), kPinnedLeafBytes.size()),
            "allocate private RW page, copy fixed 59 bytes, seal RX");
    auto leaf = code.function();
    require(leaf != nullptr, "owned fixed-byte leaf function pointer exists");

    // Both sides start from the same all-zero 104-byte state. The leaf leaves
    // padding bytes untouched, so comparing against a differently initialized
    // destination would not be a valid ABI check.
    NativeArg104 actual{};
    auto* returned = leaf(&actual, key, value);
    require(returned == &actual, "leaf returns RCX argument pointer");
    require(std::memcmp(actual.bytes.data(), argument->bytes.data(),
                        battle_format_input::kNativeArgBytes) == 0,
            "owned native leaf bytes match the 104-byte builder result");
    require(battle_format_input::cstr_pointer(actual, 0x00) == key,
            "leaf stores borrowed key pointer at offset 0");
    require(battle_format_input::cstr_pointer(actual, 0x60) == value,
            "leaf stores borrowed value C string at offset 0x60");
    require(battle_format_input::qword_at(actual, 0x20) == 15,
            "first empty String32 capacity is 15");
    require(battle_format_input::dword_at(actual, 0x28) == 2,
            "native kind is DWORD 2");
    require(battle_format_input::qword_at(actual, 0x48) == 15,
            "second empty String32 capacity is 15");
    require(contains_only_zeroes(actual, 0x08, 8) &&
                contains_only_zeroes(actual, 0x18, 8) &&
                contains_only_zeroes(actual, 0x30, 8) &&
                contains_only_zeroes(actual, 0x40, 8) &&
                contains_only_zeroes(actual, 0x50, 4) &&
                contains_only_zeroes(actual, 0x58, 8),
            "leaf clears pinned zero fields");
    require(code.release_and_verify_free(), "VirtualFree releases exact owned RX page");
}

void test_empty_and_zero_row_inputs() {
    std::vector<InputRow> one_empty_value{{"empty_value", ""}};
    Workspace with_empty;
    require(with_empty.build("battle.empty", one_empty_value, std::string_view{""}) ==
                BuildStatus::ok,
            "empty row value is accepted and owned");
    const auto* empty_argument = with_empty.argument(0);
    require(empty_argument != nullptr, "empty-value argument exists");
    const auto* empty_value = battle_format_input::cstr_pointer(*empty_argument, 0x60);
    require(empty_value != nullptr && *empty_value == '\0',
            "empty value has a stable owned NUL byte");
    require(with_empty.owns_c_string(empty_value, 0),
            "empty value pointer lies in workspace arena");

    Workspace zero_rows;
    require(zero_rows.build("battle.no.rows", std::span<const InputRow>{},
                            std::string_view{"literal"}) ==
                BuildStatus::ok,
            "zero rows are accepted");
    require(zero_rows.argument_count() == 0 && zero_rows.body_key() != nullptr,
            "zero-row output contains only owned body key");
}

void test_successive_builds_reset_workspace() {
    Workspace workspace;
    std::vector<InputRow> first_rows{{"old_a", std::string(512, 'a')},
                                     {"old_b", "stale"}};
    require(workspace.build("battle.first", first_rows,
                            std::string_view{"$old_a$/$old_b$"}) == BuildStatus::ok,
            "first successful workspace build");
    require(workspace.argument_count() == 2 && workspace.arena_used_bytes() > 500,
            "first build leaves two rows and a nontrivial arena footprint");

    std::vector<InputRow> second_rows{{"new_key", "new_value"}};
    require(workspace.build("battle.second", second_rows,
                            std::string_view{"literal"}) == BuildStatus::ok,
            "second successful build on the same Workspace");
    const auto* second_argument = workspace.argument(0);
    require(second_argument != nullptr && workspace.argument(1) == nullptr,
            "second build replaces old argument count");
    require(std::string_view(workspace.body_key()) == "battle.second_1" &&
                std::string_view(battle_format_input::cstr_pointer(*second_argument, 0x00)) ==
                    "new_key" &&
                std::string_view(battle_format_input::cstr_pointer(*second_argument, 0x60)) ==
                    "new_value",
            "second build contains only current body key and row text");

    const auto expected_arena_bytes = std::string_view("battle.second_1").size() + 1 +
                                      std::string_view("new_key").size() + 1 +
                                      std::string_view("new_value").size() + 1;
    require(workspace.arena_used_bytes() == expected_arena_bytes,
            "second arena size counts only its own copied strings");
}

void test_rejections_and_bounds() {
    Workspace workspace;
    std::vector<InputRow> no_rows;
    require(workspace.build("", no_rows) == BuildStatus::invalid_base_key,
            "empty base definition key rejected");

    std::string nul_base("bad\0base", 8);
    require(workspace.build(nul_base, no_rows) == BuildStatus::embedded_nul,
            "embedded NUL in base key rejected");
    std::vector<InputRow> nul_key{{std::string("bad\0key", 7), "v"}};
    require(workspace.build("battle.nul", nul_key) == BuildStatus::embedded_nul,
            "embedded NUL in row key rejected");
    std::vector<InputRow> nul_value{{"key", std::string("bad\0value", 9)}};
    require(workspace.build("battle.nul", nul_value) == BuildStatus::embedded_nul,
            "embedded NUL in row value rejected");
    const std::string nul_template("$bad\0template$", 14);
    require(workspace.build("battle.nul", no_rows, nul_template) ==
                BuildStatus::embedded_nul,
            "embedded NUL in resolved template rejected");

    std::vector<InputRow> duplicate{{"same", "1"}, {"same", "2"}};
    require(workspace.build("battle.duplicate", duplicate) == BuildStatus::duplicate_key,
            "duplicate row keys rejected");

    std::string overlapping{"battle.row.key"};
    std::vector<InputRow> alias_rows{{overlapping, "v"}};
    const std::string_view alias_base(alias_rows[0].key.data(), 6);
    require(workspace.build(alias_base, alias_rows) == BuildStatus::alias,
            "base key aliasing a row string is rejected");
    const auto* self = reinterpret_cast<const char*>(&workspace);
    require(workspace.build(std::string_view(self, 1), no_rows) == BuildStatus::alias,
            "input overlapping workspace storage is rejected");

    std::string too_long_base(battle_format_input::kMaxKeyBytes - 1, 'b');
    require(workspace.build(too_long_base, no_rows) == BuildStatus::key_too_long,
            "base plus suffix cannot exceed 256 bytes");
    std::vector<InputRow> long_key{{
        std::string(battle_format_input::kMaxKeyBytes + 1, 'k'), "v"}};
    require(workspace.build("battle.long", long_key) == BuildStatus::key_too_long,
            "row keys above 256 bytes rejected");
    std::vector<InputRow> long_value{{
        "k", std::string(battle_format_input::kMaxValueBytes + 1, 'v')}};
    require(workspace.build("battle.long", long_value) == BuildStatus::value_too_long,
            "values above 8192 bytes rejected");

    std::string max_base(battle_format_input::kMaxKeyBytes - 2, 'b');
    std::vector<InputRow> max_key{{
        std::string(battle_format_input::kMaxKeyBytes, 'k'), ""}};
    require(workspace.build(max_base, max_key, std::string_view{""}) == BuildStatus::ok,
            "256-byte row and suffixed body keys accepted at boundary");
    require(std::string_view(workspace.body_key()).size() ==
                battle_format_input::kMaxKeyBytes,
            "complete body key is exactly 256 bytes");

    std::vector<InputRow> max_value{{
        "k", std::string(battle_format_input::kMaxValueBytes, 'v')}};
    require(workspace.build("battle.max.value", max_value, std::string_view{"literal"}) ==
                BuildStatus::ok,
            "8192-byte value accepted at boundary");
    require(std::string_view(battle_format_input::cstr_pointer(*workspace.argument(0), 0x60))
                    .size() == battle_format_input::kMaxValueBytes,
            "max-sized value copied with a terminating NUL");

    std::vector<InputRow> max_rows;
    max_rows.reserve(battle_format_input::kMaxRows);
    for (std::size_t i = 0; i < battle_format_input::kMaxRows; ++i) {
        max_rows.push_back({"row" + std::to_string(i), "v"});
    }
    require(workspace.build("battle.max.count", max_rows, std::string_view{"literal"}) ==
                BuildStatus::ok,
            "64-row count accepted at boundary");
    require(workspace.argument_count() == battle_format_input::kMaxRows,
            "all 64 contiguous entries are present");

    std::vector<InputRow> exact_arena;
    exact_arena.reserve(4);
    for (std::size_t i = 0; i < 3; ++i) {
        exact_arena.push_back({"k" + std::to_string(i),
                               std::string(battle_format_input::kMaxValueBytes, 'v')});
    }
    exact_arena.push_back({"k3", ""});
    std::size_t bytes_before_last_value = 4;  // "b_1" and its NUL byte.
    for (std::size_t i = 0; i < 3; ++i) {
        bytes_before_last_value += exact_arena[i].key.size() + 1;
        bytes_before_last_value += exact_arena[i].value.size() + 1;
    }
    bytes_before_last_value += exact_arena.back().key.size() + 1;
    const auto exact_arena_final_value =
        battle_format_input::kArenaBytes - bytes_before_last_value - 1;
    exact_arena.back().value.assign(exact_arena_final_value, 'v');
    const auto exact_arena_status =
        workspace.build("b", exact_arena, std::string_view{""});
    if (exact_arena_status != BuildStatus::ok) {
        std::fprintf(stderr,
                     "exact_arena_build_status=%u arena_used=%zu bytes_before_last=%zu final_value_bytes=%zu\n",
                     static_cast<unsigned>(exact_arena_status),
                     workspace.arena_used_bytes(), bytes_before_last_value,
                     exact_arena_final_value);
        throw std::runtime_error("exact_arena_build_status_not_ok");
    }
    require(exact_arena_status == BuildStatus::ok,
            "arena filled exactly to its 32 KiB boundary");
    require(workspace.arena_used_bytes() == battle_format_input::kArenaBytes,
            "exact arena boundary uses precisely 32 KiB");

    std::vector<InputRow> many_rows;
    many_rows.reserve(battle_format_input::kMaxRows + 1);
    for (std::size_t i = 0; i <= battle_format_input::kMaxRows; ++i) {
        many_rows.push_back({"k" + std::to_string(i), "v"});
    }
    require(workspace.build("battle.count", many_rows) == BuildStatus::too_many_rows,
            "row count above 64 rejected");

    std::vector<InputRow> arena_rows;
    arena_rows.reserve(4);
    for (std::size_t i = 0; i < 4; ++i) {
        arena_rows.push_back({"k" + std::to_string(i),
                              std::string(battle_format_input::kMaxValueBytes, 'v')});
    }
    require(workspace.build("battle.arena", arena_rows) == BuildStatus::arena_overflow,
            "cumulative owned strings above 32 KiB rejected");

    const auto below = battle_format_input::estimate_expansion(0, 7);
    require(below.status == ExpansionStatus::below_limit &&
                below.worst_case_bytes == 7 * 8200,
            "seven worst-case placeholders remain below 60 KiB");
    const auto at_or_above = battle_format_input::estimate_expansion(0, 8);
    require(at_or_above.status == ExpansionStatus::limit_reached &&
                at_or_above.worst_case_bytes == 8 * 8200,
            "eight worst-case placeholders exceed 60 KiB");
    const auto overflow = battle_format_input::estimate_expansion(
        std::numeric_limits<std::size_t>::max() - 100, 1);
    require(overflow.status == ExpansionStatus::overflow,
            "expansion addition overflow checked before multiplication");

    std::string eight_dollars(8, '$');
    require(workspace.build("battle.expansion", no_rows, eight_dollars) ==
                BuildStatus::expansion_limit_reached,
            "unsafe provided template rejected and workspace cleared");
    require(workspace.body_key() == nullptr && workspace.argument_count() == 0,
            "unsafe expansion leaves no usable input view");
    std::string oversized_template(battle_format_input::kExpansionLimitBytes, 'x');
    require(workspace.build("battle.expansion", no_rows, oversized_template) ==
                BuildStatus::expansion_limit_reached,
            "template at the 60 KiB limit rejected before scanning placeholders");

    Workspace unknown_template;
    require(unknown_template.build("battle.unknown", no_rows) == BuildStatus::ok &&
                unknown_template.expansion_status() == ExpansionStatus::unknown &&
                !unknown_template.expansion_below_limit(),
            "missing resolved localization remains unknown and not callable");
}

}  // namespace

int main() {
    try {
        test_builder_owned_strings_and_leaf();
        test_empty_and_zero_row_inputs();
        test_successive_builds_reset_workspace();
        test_rejections_and_bounds();
        std::printf(
            "{\"status\":\"passed\",\"evidence_kind\":\"owned fixture replay of native leaf bytes\","
            "\"leaf_rva\":\"0x6fbfa0\",\"leaf_bytes\":59,\"leaf_calls\":1,"
            "\"builder_layout_bytes\":104,\"checks\":%zu,\"virtual_alloc_rw_to_rx\":true,"
            "\"virtual_free_verified\":true,\"eu4_process_called\":false,"
            "\"formatter_called\":false,\"game_or_native_helper_called\":false}\n",
            g_check_count);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "fixture_failure:%s\n", error.what());
        return 1;
    }
}
