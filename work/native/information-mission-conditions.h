#pragma once

#include "information-mission-completion.h"
#include <array>

namespace information::mission_conditions {

namespace names = mission_completion;
constexpr unsigned kMaxConditions = 128;
constexpr unsigned kMaxTasks = 4096;
constexpr uintptr_t kRootOffset = 0x70;
constexpr uintptr_t kRootVtableRva = 0x1c38010;
constexpr uintptr_t kContextVtableRva = 0x1c38158;
constexpr uintptr_t kEvaluateRva = 0xb98070;

struct Node final { uintptr_t child = 0, callee = 0; };
struct Root final {
    uintptr_t definition = 0, slots = 0;
    unsigned count = 0;
    std::array<Node, kMaxConditions> nodes{};
};

inline bool same(const Root& left, const Root& right) noexcept {
    if (left.count > kMaxConditions || left.definition != right.definition
        || left.slots != right.slots || left.count != right.count) return false;
    for (unsigned index = 0; index < left.count; ++index) {
        if (left.nodes[index].child != right.nodes[index].child
            || left.nodes[index].callee != right.nodes[index].callee) return false;
    }
    return true;
}

template <typename Reader>
bool read_root(Reader& reader, uintptr_t base, uintptr_t definition, Root& output) noexcept {
    Root root{};
    unsigned char bytes[24]{};
    uintptr_t vtable = 0, method = 0;
    int32_t count = 0;
    if (!names::range(definition, kRootOffset+sizeof(bytes))
        || !reader.read(definition+kRootOffset, bytes, sizeof(bytes))) return false;
    std::memcpy(&vtable, bytes, 8);
    std::memcpy(&root.slots, bytes+8, 8);
    std::memcpy(&count, bytes+20, 4);
    if (vtable != base+kRootVtableRva || count < 0 || count > static_cast<int32_t>(kMaxConditions)
        || !reader.read(vtable+0x30, &method, 8) || method != base+kEvaluateRva) return false;
    root.definition = definition;
    root.count = static_cast<unsigned>(count);
    if (root.count && !names::range(root.slots, root.count*8)) return false;
    for (unsigned index = 0; index < root.count; ++index) {
        auto& node = root.nodes[index];
        if (!names::range(root.slots+index*8, 8)
            || !reader.read(root.slots+index*8, &node.child, 8)
            || !names::range(node.child, 8) || !reader.read(node.child, &vtable, 8)
            || !names::range(vtable+0x30, 8) || !reader.read(vtable+0x30, &node.callee, 8)
            || node.callee < base+0x1000 || node.callee >= base+0x1c00000) return false;
    }
    output = root;
    return true;
}

template <typename Reader>
bool root_context(Reader& reader, uintptr_t base, uintptr_t context, uint64_t country) noexcept {
    unsigned char bytes[56]{};
    if (!names::range(context, sizeof(bytes)) || !reader.read(context, bytes, sizeof(bytes))) return false;
    uintptr_t vtable = 0, anchor = 0;
    uint64_t current = 0;
    uint32_t discriminator = 0, province = 0, mode = 0;
    std::memcpy(&vtable, bytes, 8);
    std::memcpy(&discriminator, bytes+8, 4);
    std::memcpy(&province, bytes+0x28, 4);
    std::memcpy(&current, bytes+0x2c, 8);
    std::memcpy(&mode, bytes+0x34, 4);
    if (vtable != base+kContextVtableRva || discriminator != 0x165
        || province || current != country || mode != 1) return false;
    for (unsigned offset : {0x10u, 0x18u, 0x20u}) {
        std::memcpy(&anchor, bytes+offset, 8);
        if (anchor != context) return false;
    }
    return true;
}

enum class CaptureResult { ignored, observed, invalid };
struct Evaluation final {
    Root root{};
    uint64_t country = 0;
    names::Name mission{};
    int32_t date = 0;
    unsigned seen = 0;
    std::array<uint64_t, kMaxConditions> returns{};
    bool valid = false;

    template <typename Reader>
    CaptureResult observe(Reader& reader, uintptr_t base, uintptr_t child, uintptr_t context,
                          uint64_t returned, uintptr_t slot, uintptr_t callee) noexcept {
        if (root.count > kMaxConditions || seen > root.count) {
            valid = false;
            return CaptureResult::invalid;
        }
        if (!valid || slot < root.slots || slot-root.slots >= root.count*8
            || (slot-root.slots)%8) return CaptureResult::ignored;
        const unsigned index = static_cast<unsigned>((slot-root.slots)/8);
        if (index != seen || (seen && !(returns[seen-1]&0xff))
            || child != root.nodes[index].child || callee != root.nodes[index].callee
            || !root_context(reader, base, context, country)) {
            valid = false;
            return CaptureResult::invalid;
        }
        returns[seen++] = returned;
        return CaptureResult::observed;
    }

    bool complete() const noexcept {
        return valid && root.count <= kMaxConditions && seen && seen <= root.count
            && (seen == root.count || !(returns[seen-1]&0xff));
    }
};

struct NodeChange final { unsigned index = 0; int32_t previous_date = 0; uint64_t before = 0, after = 0; };
struct Changes final { std::array<NodeChange, kMaxConditions> nodes{}; unsigned count = 0; };
struct Task final {
    Root root{};
    names::Name mission{};
    uint64_t country = 0;
    int32_t date = 0;
    std::array<uint64_t, kMaxConditions> returns{};
    std::array<int32_t, kMaxConditions> dates{};
};
enum class Result { baseline, unchanged, changed, reset, invalid, full };

// The owning source serializes this store and event publication with one lock.
struct Baselines final {
    std::array<Task, kMaxTasks> tasks{};
    unsigned count = 0;

    Result observe(const Evaluation& value, Changes& changes) noexcept {
        changes = {};
        if (!value.complete() || !value.country || value.date <= 0 || !names::valid(value.mission)) return Result::invalid;
        unsigned index = 0;
        for (; index < count; ++index) {
            if (tasks[index].country == value.country && names::equal(tasks[index].mission, value.mission)) break;
        }
        const bool created = index == count;
        if (created && count == kMaxTasks) return Result::full;
        auto& task = tasks[index];
        const bool reset = !created && (!same(task.root, value.root) || value.date < task.date);
        if (created || reset) {
            task = {};
            task.root = value.root;
            task.mission = value.mission;
            task.country = value.country;
            if (created) ++count;
        }
        task.date = value.date;
        for (unsigned node = 0; node < value.seen; ++node) {
            // Native TEST compares AL with zero, not the exact nonzero byte.
            if (task.dates[node] && bool(task.returns[node]&0xff) != bool(value.returns[node]&0xff))
                changes.nodes[changes.count++] = {node, task.dates[node], task.returns[node], value.returns[node]};
            task.returns[node] = value.returns[node];
            task.dates[node] = value.date;
        }
        if (created) return Result::baseline;
        if (reset) return Result::reset;
        return changes.count ? Result::changed : Result::unchanged;
    }
};

} // namespace information::mission_conditions
