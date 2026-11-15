#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include "format_expansion_plan.h"

namespace battle_format_input {

inline constexpr std::size_t kNativeArgBytes = 0x68;
inline constexpr std::size_t kNativeArgAlignment = 8;
inline constexpr std::size_t kMaxRows = 64;
inline constexpr std::size_t kMaxKeyBytes = 256;
inline constexpr std::size_t kMaxValueBytes = 8192;
inline constexpr std::size_t kArenaBytes = 32 * 1024;
inline constexpr std::size_t kExpansionLimitBytes = 60 * 1024;
inline constexpr std::size_t kValueExpansionOverhead = 8;

struct alignas(kNativeArgAlignment) NativeArg104 final {
    std::array<std::uint8_t, kNativeArgBytes> bytes{};
};

static_assert(sizeof(void*) == 8, "the pinned native layout is x64 only");
static_assert(sizeof(NativeArg104) == kNativeArgBytes);
static_assert(alignof(NativeArg104) == kNativeArgAlignment);
static_assert(std::is_standard_layout_v<NativeArg104>);

struct InputRow final {
    std::string key;
    std::string value;
};

enum class ExpansionStatus {
    unknown,
    below_limit,
    overflow,
    limit_reached,
};

struct ExpansionBound final {
    ExpansionStatus status{ExpansionStatus::unknown};
    std::size_t worst_case_bytes{};
};

inline ExpansionBound estimate_expansion(std::size_t template_bytes,
                                         std::size_t placeholder_count) noexcept {
    constexpr auto per_placeholder = kMaxValueBytes + kValueExpansionOverhead;
    if (placeholder_count >
        (std::numeric_limits<std::size_t>::max() - template_bytes) / per_placeholder) {
        return {ExpansionStatus::overflow, 0};
    }
    const auto bound = template_bytes + placeholder_count * per_placeholder;
    if (bound >= kExpansionLimitBytes) {
        return {ExpansionStatus::limit_reached, bound};
    }
    return {ExpansionStatus::below_limit, bound};
}

enum class BuildStatus {
    ok,
    too_many_rows,
    invalid_base_key,
    key_too_long,
    invalid_row_key,
    value_too_long,
    embedded_nul,
    alias,
    invalid_input_range,
    duplicate_key,
    arena_overflow,
    expansion_overflow,
    expansion_limit_reached,
    missing_template_argument,
    invalid_resolved_template,
};

struct AddressRange final {
    std::uintptr_t begin{};
    std::uintptr_t end{};
    bool empty{true};
};

inline bool make_range(const void* data, std::size_t bytes,
                       AddressRange& output) noexcept {
    if (bytes == 0) {
        output = {};
        return true;
    }
    if (data == nullptr) {
        return false;
    }
    const auto begin = reinterpret_cast<std::uintptr_t>(data);
    if (bytes > std::numeric_limits<std::uintptr_t>::max() - begin) {
        return false;
    }
    output = {begin, begin + bytes, false};
    return true;
}

inline bool overlaps(const AddressRange& left,
                     const AddressRange& right) noexcept {
    return !left.empty && !right.empty && left.begin < right.end &&
           right.begin < left.end;
}

inline const char* cstr_pointer(const NativeArg104& argument,
                                std::size_t offset) noexcept {
    const char* value = nullptr;
    std::memcpy(&value, argument.bytes.data() + offset, sizeof(value));
    return value;
}

inline std::uint64_t qword_at(const NativeArg104& argument,
                              std::size_t offset) noexcept {
    std::uint64_t value{};
    std::memcpy(&value, argument.bytes.data() + offset, sizeof(value));
    return value;
}

inline std::uint32_t dword_at(const NativeArg104& argument,
                              std::size_t offset) noexcept {
    std::uint32_t value{};
    std::memcpy(&value, argument.bytes.data() + offset, sizeof(value));
    return value;
}

class Workspace final {
public:
    Workspace() = default;
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;
    Workspace(Workspace&&) = delete;
    Workspace& operator=(Workspace&&) = delete;

    BuildStatus build(std::string_view base_definition_key,
                      std::span<const InputRow> rows,
                      std::optional<std::string_view> resolved_template = std::nullopt) noexcept {
        if (rows.size() > kMaxRows) {
            reset();
            return BuildStatus::too_many_rows;
        }

        AddressRange workspace_range{};
        if (!make_range(this, sizeof(*this), workspace_range)) {
            reset();
            return BuildStatus::invalid_input_range;
        }
        AddressRange rows_range{};
        if (!make_range(rows.data(), rows.size_bytes(), rows_range)) {
            reset();
            return BuildStatus::invalid_input_range;
        }
        if (overlaps(workspace_range, rows_range)) {
            reset();
            return BuildStatus::alias;
        }

        std::array<AddressRange, 2 + 2 * kMaxRows> input_ranges{};
        std::size_t input_range_count = 0;
        const auto register_input = [&](const void* data, std::size_t bytes) noexcept {
            AddressRange range{};
            if (!make_range(data, bytes, range)) {
                return BuildStatus::invalid_input_range;
            }
            if (range.empty) {
                return BuildStatus::ok;
            }
            // Short std::strings may keep their bytes inside InputRow itself;
            // that is ordinary caller-owned storage. Pairwise text overlap and
            // overlap with this Workspace are rejected below.
            if (overlaps(workspace_range, range)) {
                return BuildStatus::alias;
            }
            for (std::size_t i = 0; i < input_range_count; ++i) {
                if (overlaps(input_ranges[i], range)) {
                    return BuildStatus::alias;
                }
            }
            input_ranges[input_range_count++] = range;
            return BuildStatus::ok;
        };

        auto input_status = register_input(base_definition_key.data(),
                                           base_definition_key.size());
        if (input_status != BuildStatus::ok) {
            reset();
            return input_status;
        }
        if (resolved_template.has_value()) {
            input_status = register_input(resolved_template->data(),
                                          resolved_template->size());
            if (input_status != BuildStatus::ok) {
                reset();
                return input_status;
            }
        }
        for (const auto& row : rows) {
            input_status = register_input(row.key.data(), row.key.size());
            if (input_status != BuildStatus::ok) {
                reset();
                return input_status;
            }
            input_status = register_input(row.value.data(), row.value.size());
            if (input_status != BuildStatus::ok) {
                reset();
                return input_status;
            }
        }

        if (base_definition_key.empty()) {
            reset();
            return BuildStatus::invalid_base_key;
        }
        if (base_definition_key.size() > kMaxKeyBytes - 2) {
            reset();
            return BuildStatus::key_too_long;
        }
        if (contains_nul(base_definition_key)) {
            reset();
            return BuildStatus::embedded_nul;
        }
        if (resolved_template.has_value() &&
            resolved_template->size() >= kExpansionLimitBytes) {
            reset();
            return BuildStatus::expansion_limit_reached;
        }
        if (resolved_template.has_value() && contains_nul(*resolved_template)) {
            reset();
            return BuildStatus::embedded_nul;
        }

        std::size_t required_arena_bytes = base_definition_key.size() + 2 + 1;
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const auto& row = rows[i];
            if (row.key.empty()) {
                reset();
                return BuildStatus::invalid_row_key;
            }
            if (row.key.size() > kMaxKeyBytes) {
                reset();
                return BuildStatus::key_too_long;
            }
            if (row.value.size() > kMaxValueBytes) {
                reset();
                return BuildStatus::value_too_long;
            }
            if (contains_nul(row.key) || contains_nul(row.value)) {
                reset();
                return BuildStatus::embedded_nul;
            }
            for (std::size_t j = 0; j < i; ++j) {
                if (row.key == rows[j].key) {
                    reset();
                    return BuildStatus::duplicate_key;
                }
            }
            if (!checked_add(required_arena_bytes, row.key.size() + 1) ||
                !checked_add(required_arena_bytes, row.value.size() + 1)) {
                reset();
                return BuildStatus::arena_overflow;
            }
        }
        if (required_arena_bytes > kArenaBytes) {
            reset();
            return BuildStatus::arena_overflow;
        }

        // Alias and all input/capacity checks must precede reset so a view into
        // the current workspace is detected. Once inputs are proven external
        // and usable, discard old output before assigning the new expansion
        // state or appending any bytes.
        reset();
        if (resolved_template.has_value()) {
            const auto placeholder_count = static_cast<std::size_t>(
                std::count(resolved_template->begin(), resolved_template->end(), '$'));
            const auto estimate = estimate_expansion(resolved_template->size(),
                                                     placeholder_count);
            expansion_status_ = estimate.status;
            expansion_worst_case_bytes_ = estimate.worst_case_bytes;
            if (estimate.status == ExpansionStatus::overflow) {
                reset();
                return BuildStatus::expansion_overflow;
            }
            if (estimate.status == ExpansionStatus::limit_reached) {
                reset();
                return BuildStatus::expansion_limit_reached;
            }
        } else {
            expansion_status_ = ExpansionStatus::unknown;
            expansion_worst_case_bytes_ = 0;
        }

        body_key_ = append_body_key(base_definition_key);
        if (body_key_ == nullptr) {
            reset();
            return BuildStatus::arena_overflow;
        }
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const char* key = append(rows[i].key);
            const char* value = append(rows[i].value);
            if (key == nullptr || value == nullptr) {
                reset();
                return BuildStatus::arena_overflow;
            }
            initialize_argument(arguments_[i], key, value);
        }
        argument_count_ = rows.size();
        return BuildStatus::ok;
    }

    BuildStatus build_for_bound_template(
        std::string_view base_definition_key,
        std::span<const InputRow> rows,
        std::string_view resolved_template) noexcept {
        const auto fail = [&](BuildStatus status) noexcept {
            reset();
            return status;
        };

        if (rows.size() > kMaxRows) {
            return fail(BuildStatus::too_many_rows);
        }

        AddressRange workspace_range{};
        if (!make_range(this, sizeof(*this), workspace_range)) {
            return fail(BuildStatus::invalid_input_range);
        }
        AddressRange rows_range{};
        if (!make_range(rows.data(), rows.size_bytes(), rows_range)) {
            return fail(BuildStatus::invalid_input_range);
        }
        if (overlaps(workspace_range, rows_range)) {
            return fail(BuildStatus::alias);
        }

        std::array<AddressRange, 2 + 2 * kMaxRows> input_ranges{};
        std::size_t input_range_count = 0;
        const auto register_input = [&](const void* data,
                                        std::size_t bytes) noexcept {
            AddressRange range{};
            if (!make_range(data, bytes, range)) {
                return BuildStatus::invalid_input_range;
            }
            if (range.empty) {
                return BuildStatus::ok;
            }
            if (overlaps(workspace_range, range)) {
                return BuildStatus::alias;
            }
            for (std::size_t i = 0; i < input_range_count; ++i) {
                if (overlaps(input_ranges[i], range)) {
                    return BuildStatus::alias;
                }
            }
            input_ranges[input_range_count++] = range;
            return BuildStatus::ok;
        };

        auto input_status = register_input(base_definition_key.data(),
                                           base_definition_key.size());
        if (input_status != BuildStatus::ok) {
            return fail(input_status);
        }
        input_status = register_input(resolved_template.data(),
                                      resolved_template.size());
        if (input_status != BuildStatus::ok) {
            return fail(input_status);
        }
        for (const auto& row : rows) {
            input_status = register_input(row.key.data(), row.key.size());
            if (input_status != BuildStatus::ok) {
                return fail(input_status);
            }
            input_status = register_input(row.value.data(), row.value.size());
            if (input_status != BuildStatus::ok) {
                return fail(input_status);
            }
        }

        if (base_definition_key.empty()) {
            return fail(BuildStatus::invalid_base_key);
        }
        if (base_definition_key.size() > kMaxKeyBytes - 2) {
            return fail(BuildStatus::key_too_long);
        }
        if (contains_nul(base_definition_key)) {
            return fail(BuildStatus::embedded_nul);
        }
        if (resolved_template.size() >
                information::battle::format_expansion_plan::kMaximumTemplateBytes) {
            return fail(BuildStatus::invalid_resolved_template);
        }
        if (contains_nul(resolved_template)) {
            return fail(BuildStatus::embedded_nul);
        }

        std::array<information::battle::format_expansion_plan::Type2Row,
                   kMaxRows> type2_rows{};
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const auto& row = rows[i];
            if (row.key.empty()) {
                return fail(BuildStatus::invalid_row_key);
            }
            if (row.key.size() > kMaxKeyBytes) {
                return fail(BuildStatus::key_too_long);
            }
            if (row.value.size() > kMaxValueBytes) {
                return fail(BuildStatus::value_too_long);
            }
            if (contains_nul(row.key) || contains_nul(row.value)) {
                return fail(BuildStatus::embedded_nul);
            }
            for (std::size_t j = 0; j < i; ++j) {
                if (row.key == rows[j].key) {
                    return fail(BuildStatus::duplicate_key);
                }
            }
            type2_rows[i] = {
                std::string_view(row.key.data(), row.key.size()),
                std::string_view(row.value.data(), row.value.size()),
            };
        }

        information::battle::format_expansion_plan::Plan expansion_plan{};
        if (!information::battle::format_expansion_plan::make_plan(
                resolved_template,
                std::span(type2_rows).first(rows.size()), expansion_plan)) {
            return fail(BuildStatus::invalid_resolved_template);
        }
        if (!expansion_plan.all_placeholders_bound) {
            return fail(BuildStatus::missing_template_argument);
        }
        if (!expansion_plan.below_60_kib) {
            return fail(BuildStatus::expansion_limit_reached);
        }

        const auto build_status = build(base_definition_key, rows, std::nullopt);
        if (build_status != BuildStatus::ok) {
            reset();
            return build_status;
        }
        expansion_status_ = ExpansionStatus::below_limit;
        expansion_worst_case_bytes_ = expansion_plan.upper_bound;
        return BuildStatus::ok;
    }

    const char* body_key() const noexcept { return body_key_; }
    std::size_t argument_count() const noexcept { return argument_count_; }
    std::size_t arena_used_bytes() const noexcept { return arena_used_; }
    const NativeArg104* argument(std::size_t index) const noexcept {
        return index < argument_count_ ? &arguments_[index] : nullptr;
    }
    ExpansionStatus expansion_status() const noexcept { return expansion_status_; }
    std::size_t expansion_worst_case_bytes() const noexcept {
        return expansion_worst_case_bytes_;
    }
    bool expansion_below_limit() const noexcept {
        return expansion_status_ == ExpansionStatus::below_limit;
    }

    bool owns_c_string(const char* value, std::size_t max_content_bytes) const noexcept {
        if (value == nullptr) {
            return false;
        }
        const auto begin = reinterpret_cast<std::uintptr_t>(arena_.data());
        const auto end = begin + arena_.size();
        const auto address = reinterpret_cast<std::uintptr_t>(value);
        if (address < begin || address >= end) {
            return false;
        }
        const auto available = static_cast<std::size_t>(end - address);
        const auto scan_bytes = std::min(available, max_content_bytes + 1);
        return std::memchr(value, '\0', scan_bytes) != nullptr;
    }

private:
    static bool contains_nul(std::string_view value) noexcept {
        return value.find('\0') != std::string_view::npos;
    }

    static bool checked_add(std::size_t& total, std::size_t value) noexcept {
        if (value > std::numeric_limits<std::size_t>::max() - total) {
            return false;
        }
        total += value;
        return true;
    }

    void reset() noexcept {
        arena_.fill('\0');
        for (auto& argument : arguments_) {
            argument.bytes.fill(0);
        }
        arena_used_ = 0;
        argument_count_ = 0;
        body_key_ = nullptr;
        expansion_status_ = ExpansionStatus::unknown;
        expansion_worst_case_bytes_ = 0;
    }

    const char* append(std::string_view value) noexcept {
        if (arena_used_ >= arena_.size() ||
            value.size() > arena_.size() - arena_used_ - 1) {
            return nullptr;
        }
        auto* destination = arena_.data() + arena_used_;
        if (!value.empty()) {
            std::memcpy(destination, value.data(), value.size());
        }
        destination[value.size()] = '\0';
        arena_used_ += value.size() + 1;
        return destination;
    }

    const char* append_body_key(std::string_view base) noexcept {
        constexpr std::string_view suffix{"_1"};
        const auto bytes = base.size() + suffix.size();
        if (arena_used_ >= arena_.size() ||
            bytes > arena_.size() - arena_used_ - 1) {
            return nullptr;
        }
        auto* destination = arena_.data() + arena_used_;
        std::memcpy(destination, base.data(), base.size());
        std::memcpy(destination + base.size(), suffix.data(), suffix.size());
        destination[bytes] = '\0';
        arena_used_ += bytes + 1;
        return destination;
    }

    static void write_pointer(NativeArg104& argument, std::size_t offset,
                              const char* value) noexcept {
        std::memcpy(argument.bytes.data() + offset, &value, sizeof(value));
    }

    static void write_qword(NativeArg104& argument, std::size_t offset,
                            std::uint64_t value) noexcept {
        std::memcpy(argument.bytes.data() + offset, &value, sizeof(value));
    }

    static void write_dword(NativeArg104& argument, std::size_t offset,
                            std::uint32_t value) noexcept {
        std::memcpy(argument.bytes.data() + offset, &value, sizeof(value));
    }

    static void initialize_argument(NativeArg104& argument, const char* key,
                                    const char* value) noexcept {
        argument.bytes.fill(0);
        write_pointer(argument, 0x00, key);
        write_qword(argument, 0x20, 15);
        write_dword(argument, 0x28, 2);
        write_qword(argument, 0x48, 15);
        write_pointer(argument, 0x60, value);
    }

    std::array<char, kArenaBytes> arena_{};
    std::array<NativeArg104, kMaxRows> arguments_{};
    std::size_t arena_used_{};
    std::size_t argument_count_{};
    const char* body_key_{};
    ExpansionStatus expansion_status_{ExpansionStatus::unknown};
    std::size_t expansion_worst_case_bytes_{};
};

}  // namespace battle_format_input
