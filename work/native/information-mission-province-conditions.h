#pragma once

#include "information-mission-conditions.h"

// Direct province-holding child of a task's area condition. Parent task
// evaluation and transport remain owned by the existing source.
namespace information::mission_province_condition {

namespace root = mission_conditions;
namespace names = mission_completion;
constexpr uintptr_t kAreaMethodRva = 0xc1bcf0;
constexpr uintptr_t kHeldMethodRva = 0xbe9300;
constexpr uintptr_t kAreaChildReturnRva = 0xc1bf0e;
constexpr unsigned kMaxBaselines = 16384;

inline bool supported_country(uint64_t country) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    // The enclosing task was admitted by the configured observer and its
    // canonical country reference was checked before this code is reached.
    return country != 0;
#else
    return (country & 0xffffffu) == 0x415246u;
#endif
}

struct Binding final {
    uintptr_t group = 0, slots = 0, child = 0, context = 0, root_context = 0;
    unsigned root_index = 0, child_index = 0, child_count = 0, province = 0;
    uint64_t country = 0;
};

inline bool same(const Binding& left, const Binding& right) noexcept {
    return left.group == right.group && left.slots == right.slots && left.child == right.child
        && left.context == right.context && left.root_context == right.root_context
        && left.root_index == right.root_index && left.child_index == right.child_index
        && left.child_count == right.child_count && left.province == right.province
        && left.country == right.country;
}

template <typename Reader>
root::CaptureResult bind(Reader& reader, uintptr_t base, const root::Evaluation& task,
                         uintptr_t child, uintptr_t context, uintptr_t caller, Binding& output) noexcept {
    if (caller != base+kAreaChildReturnRva || !task.valid || !supported_country(task.country)
        || task.root.count > root::kMaxConditions) return root::CaptureResult::ignored;
    Binding binding{};
    unsigned matches = 0;
    for (unsigned index = 0; index < task.root.count; ++index) {
        const auto& parent = task.root.nodes[index];
        if (parent.callee != base+kAreaMethodRva) continue;
        uintptr_t group_table = 0, group_method = 0;
        uintptr_t slots = 0;
        int32_t count = 0;
        if (!names::range(parent.child, 24) || !reader.read(parent.child, &group_table, 8)
            || !names::range(group_table+0x30, 8) || !reader.read(group_table+0x30, &group_method, 8)
            || group_method != base+kAreaMethodRva
            || !reader.read(parent.child+8, &slots, 8) || !reader.read(parent.child+20, &count, 4)
            || count < 0 || count > static_cast<int32_t>(root::kMaxConditions)
            || (count && !names::range(slots, static_cast<unsigned>(count)*8)))
            return root::CaptureResult::invalid;
        uintptr_t children[root::kMaxConditions]{};
        if (count && !reader.read(slots, children, static_cast<unsigned>(count)*8))
            return root::CaptureResult::invalid;
        for (unsigned nested = 0; nested < static_cast<unsigned>(count); ++nested) {
            if (children[nested] != child) continue;
            ++matches;
            binding.group = parent.child;
            binding.slots = slots;
            binding.child = child;
            binding.root_index = index;
            binding.child_index = nested;
            binding.child_count = static_cast<unsigned>(count);
        }
    }
    if (!matches) return root::CaptureResult::ignored;
    if (matches != 1) return root::CaptureResult::invalid;
    uintptr_t table = 0, method = 0;
    uint32_t token = 0, flags = 0;
    unsigned char literal = 0;
    if (!names::range(child, 0x64) || !reader.read(child, &table, 8)
        || !names::range(table+0x30, 8) || !reader.read(table+0x30, &method, 8)
        || !reader.read(child+0x50, &token, 4) || !reader.read(child+0x4f, &literal, 1)
        || !reader.read(child+0x60, &flags, 4)) return root::CaptureResult::invalid;
    if (method != base+kHeldMethodRva || token != 0x3643 || literal || flags != 0x4002)
        return root::CaptureResult::ignored;
    unsigned char bytes[56]{};
    uintptr_t context_table = 0, anchor = 0;
    uint32_t discriminator = 0, mode = 0;
    uint64_t current_country = 0;
    if (!names::range(context, sizeof(bytes)) || !reader.read(context, bytes, sizeof(bytes)))
        return root::CaptureResult::invalid;
    std::memcpy(&context_table, bytes, 8);
    std::memcpy(&discriminator, bytes+8, 4);
    std::memcpy(&binding.root_context, bytes+0x10, 8);
    std::memcpy(&binding.province, bytes+0x28, 4);
    std::memcpy(&current_country, bytes+0x2c, 8);
    std::memcpy(&mode, bytes+0x34, 4);
    if (context_table != base+root::kContextVtableRva || discriminator != 0x165
        || !binding.province || binding.province > 65535 || current_country != 0x2d2d2d
        || mode != 1 || binding.root_context == context
        || !root::root_context(reader, base, binding.root_context, task.country))
        return root::CaptureResult::invalid;
    // In this direct area constructor, both copied anchor and PREV refer to
    // the mission root. No semantic FROM interpretation is assigned here.
    for (unsigned offset : {0x18u, 0x20u}) {
        std::memcpy(&anchor, bytes+offset, 8);
        if (anchor != binding.root_context) return root::CaptureResult::invalid;
    }
    binding.country = task.country;
    binding.context = context;
    output = binding;
    return root::CaptureResult::observed;
}

struct Value final {
    Binding binding{};
    names::Name mission{};
    int32_t date = 0;
    uint64_t returned = 0;
};
template <typename Reader>
bool still_member(Reader& reader, uintptr_t base, const root::Root& task, const Binding& value) noexcept {
    if (task.count > root::kMaxConditions || value.root_index >= task.count
        || value.child_index >= value.child_count || value.child_count > root::kMaxConditions) return false;
    const auto& parent = task.nodes[value.root_index];
    uintptr_t table = 0, method = 0, slots = 0, child = 0;
    int32_t count = 0;
    uint32_t token = 0, flags = 0;
    unsigned char literal = 0;
    return parent.child == value.group && parent.callee == base+kAreaMethodRva
        && reader.read(value.group, &table, 8) && names::range(table+0x30, 8)
        && reader.read(table+0x30, &method, 8) && method == base+kAreaMethodRva
        && reader.read(value.group+8, &slots, 8) && slots == value.slots
        && reader.read(value.group+20, &count, 4) && count == static_cast<int32_t>(value.child_count)
        && names::range(slots, value.child_count*8)
        && reader.read(slots+value.child_index*8, &child, 8) && child == value.child
        && reader.read(child, &table, 8) && names::range(table+0x30, 8)
        && reader.read(table+0x30, &method, 8) && method == base+kHeldMethodRva
        && reader.read(child+0x50, &token, 4) && token == 0x3643
        && reader.read(child+0x4f, &literal, 1) && !literal
        && reader.read(child+0x60, &flags, 4) && flags == 0x4002;
}
struct Change final { Value before{}, after{}; };
enum class Result { baseline, unchanged, changed, reset, invalid, full };

struct Baselines final {
    std::array<Value, kMaxBaselines> entries{};
    unsigned count = 0;

    Result observe(const Value& value, Change& change) noexcept {
        change = {};
        if (!names::valid(value.mission) || value.date <= 0 || !value.binding.province
            || !supported_country(value.binding.country)
            || value.binding.root_index >= root::kMaxConditions
            || !value.binding.child_count || value.binding.child_count > root::kMaxConditions
            || value.binding.child_index >= value.binding.child_count) return Result::invalid;
        unsigned index = 0;
        for (; index < count; ++index) {
            const auto& previous = entries[index];
            if (previous.binding.country == value.binding.country && names::equal(previous.mission, value.mission)
                && previous.binding.root_index == value.binding.root_index
                && previous.binding.child_index == value.binding.child_index
                && previous.binding.province == value.binding.province) break;
        }
        if (index == count) {
            if (count == kMaxBaselines) return Result::full;
            entries[count++] = value;
            return Result::baseline;
        }
        const auto previous = entries[index];
        entries[index] = value;
        // Stack-context addresses may vary between observations. Only the
        // loaded condition structure participates in the persistent identity.
        if (value.date < previous.date || previous.binding.group != value.binding.group
            || previous.binding.slots != value.binding.slots || previous.binding.child != value.binding.child
            || previous.binding.child_count != value.binding.child_count) return Result::reset;
        if (bool(previous.returned&0xff) == bool(value.returned&0xff)) return Result::unchanged;
        change = {previous, value};
        return Result::changed;
    }
};

} // namespace information::mission_province_condition
