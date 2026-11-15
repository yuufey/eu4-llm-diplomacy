#ifndef INFORMATION_BATTLE_OWNED_TITLE_QUERY_H
#define INFORMATION_BATTLE_OWNED_TITLE_QUERY_H

// Bounded, value-only title-helper observation.  This component does not
// invoke an engine function itself.  The caller supplies an Invoker seam for
// the one external call and a read-only Reader for all source/value reads.

#include "information-battle-owned-native-text.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace information::battle::owned_title_query {

using Address = owned_native_text::Address;

constexpr Address kMinCanonicalAddress =
    owned_native_text::kMinCanonicalAddress;
constexpr Address kMaxCanonicalExclusive =
    owned_native_text::kMaxCanonicalExclusive;
constexpr std::size_t kSelectorOffset = 0x60u;
constexpr std::size_t kSelectorBytes = 6u;
constexpr std::size_t kProvinceOffset = 0x30u;
constexpr std::size_t kNameOwnerOffset = 0x28u;
constexpr std::size_t kNameOffset = 0x10u;
constexpr std::size_t kGlobalStringRva = 0x23266b8u;
constexpr std::size_t kStringObjectBytes = 0x20u;
constexpr std::size_t kInlineCapacity =
    owned_native_text::kInlineCapacity;
constexpr std::size_t kHeapThreshold = owned_native_text::kHeapThreshold;
constexpr std::size_t kMaxTextBytes = owned_native_text::kMaxTextBytes;
constexpr std::size_t kMaxReadBytes = 128u * 1024u;

static_assert(kSelectorBytes == 1u + sizeof(std::uint32_t) + 1u,
              "selector shape must remain b8-kind-c3");

// The native helper uses the same 32-byte SSO object as the existing text
// reader.  The first 16 bytes are inline storage or a heap pointer, followed
// by size and capacity at +0x10/+0x18.
struct alignas(8) String32 final {
    std::array<unsigned char, 16u> storage{};
    std::uint64_t size = 0u;
    std::uint64_t capacity = kInlineCapacity;
};

static_assert(alignof(String32) == 8u, "String32 alignment must be 8");
static_assert(sizeof(String32) == 32u, "String32 must remain 32 bytes");
static_assert(offsetof(String32, size) == 0x10u,
              "String32 size offset must remain native");
static_assert(offsetof(String32, capacity) == 0x18u,
              "String32 capacity offset must remain native");

enum class FailureStage : std::uint8_t {
    none = 0u,
    invalid_kind = 1u,
    invalid_base_or_image = 2u,
    invalid_combat = 3u,
    guard_before = 4u,
    source_before = 5u,
    selector = 6u,
    source_before_string = 7u,
    guard_before_invoke = 8u,
    invoke = 9u,
    returned_pointer = 10u,
    guard_after_invoke = 11u,
    source_after = 12u,
    source_changed = 13u,
    output_capture = 14u,
    destroy = 15u,
    guard_after_destroy = 16u,
    source_too_short = 17u,
};

struct Result final {
    bool attempted = false;
    bool returned_same = false;
    bool destroyed = false;
    bool source_unchanged = false;
    bool observed = false;
    bool guard_before = false;
    bool guard_after_invoke = false;
    bool guard_after_destroy = false;
    FailureStage failed_stage = FailureStage::none;
};

struct StringFingerprint final {
    Address object_address = 0u;
    String32 header{};
    Address payload_address = 0u;
    std::uint32_t length = 0u;
    std::array<unsigned char, kMaxTextBytes + 1u> bytes{};
};

struct GraphFingerprint final {
    Address combat_vtable = 0u;
    Address selector_slot = 0u;
    Address selector_address = 0u;
    Address province = 0u;
    Address name_owner = 0u;
    Address global_string = 0u;
    std::uint32_t kind = 0u;
    std::array<unsigned char, kSelectorBytes> selector{};
    StringFingerprint owner_name{};
    StringFingerprint global_name{};
};

// This is intended to be static or long-lived storage owned by the caller.
// It keeps the two source passes and the Invoker's local output off the native
// call frame while remaining bounded (two graphs, two strings each, and one
// 32-byte output object).
struct Workspace final {
    GraphFingerprint before{};
    GraphFingerprint after{};
    String32 output{};
};

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                     std::size_t) noexcept> {};

template <typename Invoker, typename = void>
struct invoker_contract : std::false_type {};

template <typename Invoker>
struct invoker_contract<
    Invoker,
    std::void_t<decltype(std::declval<Invoker&>().guard()),
                decltype(std::declval<Invoker&>().invoke(
                    std::declval<Address>(), std::declval<String32*>())),
                decltype(std::declval<Invoker&>().destroy(
                    std::declval<String32*>()))>>
    : std::bool_constant<
          std::is_same<decltype(std::declval<Invoker&>().guard()),
                      bool>::value
          && std::is_same<decltype(std::declval<Invoker&>().invoke(
                                 std::declval<Address>(),
                                 std::declval<String32*>())),
                          String32*>::value
          && std::is_same<decltype(std::declval<Invoker&>().destroy(
                                 std::declval<String32*>())),
                          void>::value
          && noexcept(std::declval<Invoker&>().guard())
          && noexcept(std::declval<Invoker&>().invoke(
              std::declval<Address>(), std::declval<String32*>()))
          && noexcept(std::declval<Invoker&>().destroy(
              std::declval<String32*>()))> {};

namespace detail {

inline void reset_string(String32& value) noexcept {
    value = String32{};
    value.capacity = kInlineCapacity;
}

inline void clear_result(Result& result) noexcept {
    result = Result{};
}

inline void fail(Result& result, FailureStage stage) noexcept {
    if (result.failed_stage == FailureStage::none) {
        result.failed_stage = stage;
    }
}

inline bool checked_range(Address address, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u) return false;
    const Address max_value = std::numeric_limits<Address>::max();
    if (address > max_value - static_cast<Address>(size)) return false;
    end = address + static_cast<Address>(size);
    return address >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive && end > address;
}

inline bool checked_add(Address left, Address right, Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) return false;
    result = left + right;
    return true;
}

inline bool valid_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(Address)) == 0u;
}

inline bool valid_canonical_address(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive;
}

inline bool image_address(Address base, std::size_t image_size,
                          std::size_t offset, std::size_t size,
                          Address& address) noexcept {
    if (image_size == 0u || offset > image_size
            || size > image_size - offset
            || !checked_add(base, static_cast<Address>(offset), address)) {
        return false;
    }
    Address end = 0u;
    return checked_range(address, size, end);
}

inline bool image_range(Address base, std::size_t image_size,
                        Address address, std::size_t size) noexcept {
    Address image_end = 0u;
    Address range_end = 0u;
    if (!checked_range(base, image_size, image_end)
            || !checked_range(address, size, range_end)) {
        return false;
    }
    return address >= base && range_end <= image_end;
}

inline std::uint64_t load_u64(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0u;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline std::uint32_t load_u32(const unsigned char* bytes) noexcept {
    std::uint32_t value = 0u;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline bool same_bytes(const unsigned char* left, const unsigned char* right,
                       std::size_t size) noexcept {
    return size == 0u || std::memcmp(left, right, size) == 0;
}

template <typename Reader>
class BudgetReader final {
public:
    explicit BudgetReader(Reader& reader) noexcept : reader_(reader) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        Address end = 0u;
        if (destination == nullptr || !checked_range(address, size, end)
                || size > remaining_) {
            return false;
        }
        // Reserve before touching the source reader.  This prevents a failed
        // source read from consuming a later budget slot.
        remaining_ -= size;
        return reader_.read(address, destination, size);
    }

    std::size_t remaining() const noexcept { return remaining_; }

private:
    Reader& reader_;
    std::size_t remaining_ = kMaxReadBytes;
};

inline bool valid_text_header(const String32& header,
                              std::size_t& text_length) noexcept {
    if (header.size > kMaxTextBytes || header.capacity < header.size
            || header.capacity > owned_native_text::kMaxStringCapacity
            || header.size > static_cast<std::uint64_t>(
                                  std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    text_length = static_cast<std::size_t>(header.size);
    if (header.capacity < kHeapThreshold) {
        return header.capacity <= kInlineCapacity
            && text_length <= kInlineCapacity;
    }
    return valid_pointer(load_u64(header.storage.data()));
}

template <typename Pass>
bool read_string_fingerprint(Pass& pass, Address object,
                             StringFingerprint& output) noexcept {
    output = StringFingerprint{};
    if (!valid_pointer(object)) return false;

    unsigned char raw[kStringObjectBytes]{};
    if (!pass.read(object, raw, sizeof(raw))) return false;
    std::memcpy(&output.header, raw, sizeof(output.header));
    output.object_address = object;

    std::size_t length = 0u;
    if (!valid_text_header(output.header, length)) return false;
    output.length = static_cast<std::uint32_t>(length);
    if (output.header.capacity < kHeapThreshold) {
        output.payload_address = object;
        if (length > kInlineCapacity || raw[length] != 0u) return false;
        for (std::size_t index = 0u; index < length; ++index) {
            if (raw[index] == 0u) return false;
        }
        std::memcpy(output.bytes.data(), raw, length + 1u);
        return true;
    }

    output.payload_address = load_u64(output.header.storage.data());
    if (!valid_pointer(output.payload_address)
            || !pass.read(output.payload_address, output.bytes.data(),
                          length + 1u)
            || output.bytes[length] != 0u) {
        return false;
    }
    for (std::size_t index = 0u; index < length; ++index) {
        if (output.bytes[index] == 0u) return false;
    }
    return true;
}

inline bool same_string(const StringFingerprint& left,
                        const StringFingerprint& right) noexcept {
    return left.object_address == right.object_address
        && std::memcmp(&left.header, &right.header, sizeof(String32)) == 0
        && left.payload_address == right.payload_address
        && left.length == right.length
        && same_bytes(left.bytes.data(), right.bytes.data(),
                      static_cast<std::size_t>(left.length) + 1u);
}

inline bool same_graph(const GraphFingerprint& left,
                       const GraphFingerprint& right) noexcept {
    return left.combat_vtable == right.combat_vtable
        && left.selector_slot == right.selector_slot
        && left.selector_address == right.selector_address
        && left.province == right.province
        && left.name_owner == right.name_owner
        && left.global_string == right.global_string
        && left.kind == right.kind
        && std::memcmp(left.selector.data(), right.selector.data(),
                       left.selector.size()) == 0
        && same_string(left.owner_name, right.owner_name)
        && same_string(left.global_name, right.global_name);
}

template <typename Pass>
bool read_graph(Pass& pass, Address base, std::size_t image_size,
                Address combat, std::uint32_t expected_kind,
                GraphFingerprint& output) noexcept {
    output = GraphFingerprint{};
    if (expected_kind != 1u && expected_kind != 2u) return false;
    if (!valid_pointer(combat)) return false;

    unsigned char pointer_bytes[sizeof(Address)]{};
    if (!pass.read(combat, pointer_bytes, sizeof(pointer_bytes))) return false;
    output.combat_vtable = load_u64(pointer_bytes);
    if (!valid_pointer(output.combat_vtable)
            || !image_range(base, image_size, output.combat_vtable,
                            kSelectorOffset + sizeof(Address))) {
        return false;
    }

    if (!checked_add(combat, kProvinceOffset, output.province)
            || !valid_pointer(output.province)
            || !pass.read(output.province, pointer_bytes,
                          sizeof(pointer_bytes))) {
        // The first read above is the vtable; the second read below is the
        // combat+0x30 province pointer.  Keep the addresses canonical before
        // following the object graph.
        return false;
    }
    output.province = load_u64(pointer_bytes);
    if (!valid_pointer(output.province)
            || !checked_add(output.combat_vtable, kSelectorOffset,
                            output.selector_slot)
            || !image_range(base, image_size, output.selector_slot,
                            sizeof(Address))
            || !pass.read(output.selector_slot, pointer_bytes,
                          sizeof(pointer_bytes))) {
        return false;
    }
    output.selector_address = load_u64(pointer_bytes);
    if (!valid_canonical_address(output.selector_address)
            || !image_range(base, image_size, output.selector_address,
                            output.selector.size())
            || !pass.read(output.selector_address, output.selector.data(),
                   output.selector.size())
            || output.selector[0] != 0xb8u
            || load_u32(output.selector.data() + 1u) != expected_kind
            || output.selector[5] != 0xc3u) {
        return false;
    }
    output.kind = expected_kind;

    if (!checked_add(output.province, kNameOwnerOffset, output.name_owner)
            || !valid_pointer(output.name_owner)
            || !pass.read(output.name_owner, pointer_bytes,
                          sizeof(pointer_bytes))) {
        return false;
    }
    output.name_owner = load_u64(pointer_bytes);
    if (!valid_pointer(output.name_owner)) return false;

    Address owner_string = 0u;
    if (!checked_add(output.name_owner, kNameOffset, owner_string)
            || !image_address(base, image_size, kGlobalStringRva,
                              kStringObjectBytes, output.global_string)) {
        return false;
    }
    // The global source address is an image-relative String32.  Reuse the
    // field only for that address after selector validation; the vtable+60
    // selector itself remains in the selector array.
    const Address global_string = output.global_string;
    if (!read_string_fingerprint(pass, owner_string, output.owner_name)
            || !read_string_fingerprint(pass, global_string,
                                        output.global_name)) {
        return false;
    }
    return true;
}

}  // namespace detail

template <typename Reader, typename Invoker>
bool capture(Reader& reader, Invoker& invoker, Address base,
             std::size_t image_size, Address combat,
             std::uint32_t expected_kind, Workspace& workspace,
             owned_native_text::Snapshot& output, Result& result,
             std::size_t minimum_combined_source_bytes = 0u) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
    static_assert(invoker_contract<Invoker>::value,
                  "Invoker must expose noexcept guard/invoke/destroy methods");

    detail::clear_result(result);
    owned_native_text::clear(output);
    detail::reset_string(workspace.output);
    workspace.before = GraphFingerprint{};
    workspace.after = GraphFingerprint{};

    if (expected_kind != 1u && expected_kind != 2u) {
        detail::fail(result, FailureStage::invalid_kind);
        return false;
    }
    Address image_end = 0u;
    if (!detail::checked_range(base, image_size, image_end)
            || !detail::image_address(base, image_size, kGlobalStringRva,
                                      kStringObjectBytes, image_end)) {
        detail::fail(result, FailureStage::invalid_base_or_image);
        return false;
    }
    if (!detail::valid_pointer(combat)) {
        detail::fail(result, FailureStage::invalid_combat);
        return false;
    }

    if (!invoker.guard()) {
        detail::fail(result, FailureStage::guard_before);
        return false;
    }
    result.guard_before = true;

    detail::BudgetReader<Reader> budget_reader(reader);
    if (!detail::read_graph(budget_reader, base, image_size, combat,
                            expected_kind, workspace.before)) {
        detail::fail(result, FailureStage::source_before);
        return false;
    }

    // The accepted plugin's replacement consumes a NUL-terminated temporary
    // formed from these two strings and rejects lengths below two.
    if (static_cast<std::size_t>(workspace.before.owner_name.length)
            + workspace.before.global_name.length < minimum_combined_source_bytes) {
        detail::fail(result, FailureStage::source_too_short);
        return false;
    }

    if (!invoker.guard()) {
        detail::fail(result, FailureStage::guard_before_invoke);
        return false;
    }

    result.attempted = true;
    String32* returned = invoker.invoke(combat, &workspace.output);
    result.returned_same = returned == &workspace.output;
    if (!result.returned_same) detail::fail(result, FailureStage::returned_pointer);

    result.guard_after_invoke = invoker.guard();
    if (!result.guard_after_invoke) {
        detail::fail(result, FailureStage::guard_after_invoke);
    }

    if (!detail::read_graph(budget_reader, base, image_size, combat,
                            expected_kind, workspace.after)) {
        detail::fail(result, FailureStage::source_after);
    } else {
        result.source_unchanged = detail::same_graph(workspace.before,
                                                     workspace.after);
        if (!result.source_unchanged) {
            detail::fail(result, FailureStage::source_changed);
        }
    }

    bool output_captured = false;
    if (result.returned_same && result.guard_after_invoke
            && result.source_unchanged) {
        output_captured = owned_native_text::capture_string(
            budget_reader, reinterpret_cast<Address>(returned),
            owned_native_text::SourceKind::title_helper_candidate, output);
        if (!output_captured) detail::fail(result, FailureStage::output_capture);
    }

    // invoke() is a no-exception seam.  Once it returned, destroy exactly the
    // local output object, even if the return pointer, copy, or source guard
    // failed.  A mismatched foreign pointer is never passed to destroy().
    invoker.destroy(&workspace.output);
    result.destroyed = true;
    result.guard_after_destroy = invoker.guard();
    if (!result.guard_after_destroy) {
        detail::fail(result, FailureStage::guard_after_destroy);
    }

    const bool success = result.attempted && result.returned_same
        && result.destroyed && result.source_unchanged
        && result.guard_before && result.guard_after_invoke
        && result.guard_after_destroy && output_captured;
    if (!success) {
        owned_native_text::clear(output);
        return false;
    }
    result.observed = true;
    return true;
}

}  // namespace information::battle::owned_title_query

#endif  // INFORMATION_BATTLE_OWNED_TITLE_QUERY_H
