#ifndef INFORMATION_BATTLE_OWNED_NAME_HANDOFF_H
#define INFORMATION_BATTLE_OWNED_NAME_HANDOFF_H

// Bounded, value-only observation of the two String32 values handed to the
// NAME pair constructor.  This is deliberately a reader seam, not a native
// caller: the caller must copy the source values before the constructor's
// move clears their headers.  The result is the logical constructor input,
// not the popup +0x1d0 node, final Line1, or a complete B04 explanation.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_name_handoff {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = 0x10000u;
constexpr Address kMaxCanonicalExclusive = 0x800000000000ull;

constexpr std::uint32_t kLandKind = 1u;
constexpr std::uint32_t kNavalKind = 2u;

constexpr std::size_t kLandReturnRva = 0x235493u;
constexpr std::size_t kNavalReturnRva = 0x230c08u;
constexpr std::size_t kLandValueOffset = 0xe0u;
constexpr std::size_t kNavalValueOffset = 0x68u;
constexpr std::size_t kLandDestinationBackOffset = 0x40u;
constexpr std::size_t kNavalDestinationBackOffset = 0x50u;
constexpr std::size_t kLandKeyEntryOffset = 0x60u;
constexpr std::size_t kNavalKeyEntryOffset = 0x58u;
constexpr std::size_t kLandFormatterCallerOffset = 0x1d8u;
constexpr std::size_t kNavalFormatterCallerOffset = 0x198u;
constexpr std::size_t kLandFormatterCallerRva = 0x23a446u;
constexpr std::size_t kNavalFormatterCallerRva = 0x23a42au;
constexpr std::size_t kFormatterOwnerBackOffset = 0x20u;

constexpr std::size_t kStringObjectBytes = 0x20u;
constexpr std::size_t kInlineCapacity = 0x0fu;
constexpr std::size_t kHeapThreshold = 0x10u;
constexpr std::size_t kMaxValueBytes = 8192u;
constexpr std::size_t kMaxStringCapacity = 128u * 1024u;
constexpr std::size_t kDestinationBytes = 0x58u;
constexpr std::size_t kMaxCalls = 20u;
constexpr std::size_t kMaxTotalBytes = 20u * 1024u;

// This is the native 32-byte string object.  For an inline value storage is
// the first 16 bytes; for a heap value storage[0..7] is a pointer.  The source
// object itself is never returned or retained in the public Snapshot.
struct alignas(8) String32 final {
    std::array<unsigned char, 16u> storage{};
    std::uint64_t length = 0u;
    std::uint64_t capacity = kInlineCapacity;
};

static_assert(alignof(String32) == 8u, "String32 alignment must be 8");
static_assert(sizeof(String32) == 0x20u, "String32 must remain 32 bytes");
static_assert(offsetof(String32, length) == 0x10u,
              "String32 length offset must remain native");
static_assert(offsetof(String32, capacity) == 0x18u,
              "String32 capacity offset must remain native");

struct Request final {
    Address module_base = 0u;
    std::size_t image_size = 0u;
    Address entry_rsp = 0u;
    Address original_rbp = 0u;
    Address destination = 0u;
    Address key = 0u;
    Address value = 0u;
    Address return_pc = 0u;
};

struct ScopeIdentity final {
    std::uint64_t sequence = 0u;
    std::int64_t raw_date = 0;
    Address combat = 0u;
    std::uint32_t kind = 0u;
    bool parent_guards_verified = false;
};

enum class SnapshotState : std::uint8_t {
    unknown = 0u,
    known = 1u,
};

// Public value-only output.  It intentionally contains no source, heap,
// frame, module, or destination pointer.
struct Snapshot final {
    SnapshotState state = SnapshotState::unknown;
    std::uint64_t sequence = 0u;
    std::int64_t raw_date = 0;
    std::uint32_t kind = 0u;
    std::uint32_t length = 0u;
    std::array<unsigned char, kMaxValueBytes + 1u> bytes{};
};

enum class FailureStage : std::uint8_t {
    none = 0u,
    alias = 1u,
    scope = 2u,
    request = 3u,
    frame = 4u,
    return_pc = 5u,
    formatter = 6u,
    key = 7u,
    value = 8u,
    budget_or_read = 9u,
    source_changed = 10u,
};

struct Result final {
    bool observed = false;
    bool before_complete = false;
    bool after_complete = false;
    bool source_unchanged = false;
    std::size_t calls = 0u;
    std::size_t total_bytes = 0u;
    FailureStage failed_stage = FailureStage::none;
};

struct StringFingerprint final {
    Address object_address = 0u;
    String32 header{};
    Address payload_address = 0u;
    std::uint32_t length = 0u;
    std::array<unsigned char, kMaxValueBytes + 1u> bytes{};
};

struct PassFingerprint final {
    Address return_pc = 0u;
    Address formatter_caller = 0u;
    Address combat_owner = 0u;
    StringFingerprint key{};
    StringFingerprint value{};
};

// Caller-owned, off-frame storage for the two bounded source passes.  It has
// no effect on native execution and is never exposed in Snapshot.
struct Workspace final {
    PassFingerprint before{};
    PassFingerprint after{};
};

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                     std::size_t) noexcept> {};

namespace detail {

inline void clear_snapshot(Snapshot& output) noexcept {
    output = Snapshot{};
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

inline bool checked_sub(Address left, Address right, Address& result) noexcept {
    if (left < right) return false;
    result = left - right;
    return true;
}

inline bool valid_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(Address)) == 0u;
}

inline bool valid_canonical(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive;
}

inline bool ranges_overlap(Address left, std::size_t left_size,
                           Address right, std::size_t right_size) noexcept {
    Address left_end = 0u;
    Address right_end = 0u;
    if (!checked_range(left, left_size, left_end)
            || !checked_range(right, right_size, right_end)) {
        return false;
    }
    return left < right_end && right < left_end;
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
                || calls_ >= kMaxCalls || size > kMaxTotalBytes - total_bytes_) {
            return false;
        }
        ++calls_;
        total_bytes_ += size;
        return reader_.read(address, destination, size);
    }

    std::size_t calls() const noexcept { return calls_; }
    std::size_t total_bytes() const noexcept { return total_bytes_; }

private:
    Reader& reader_;
    std::size_t calls_ = 0u;
    std::size_t total_bytes_ = 0u;
};

struct PassScratch final {
    Address return_pc = 0u;
    Address formatter_caller = 0u;
    Address combat_owner = 0u;
    String32 key{};
    String32 value{};
    Address value_payload = 0u;
    std::size_t value_length = 0u;
};

inline bool expected_layout(const Request& request,
                            const ScopeIdentity& scope,
                            Address expected_return,
                            Address expected_caller,
                            std::size_t caller_offset,
                            std::size_t owner_back_offset,
                            std::size_t key_offset,
                            std::size_t value_offset,
                            std::size_t destination_back_offset) noexcept {
    Address expected_destination = 0u;
    Address expected_key = 0u;
    Address expected_value = 0u;
    Address caller_slot = 0u;
    Address owner_slot = 0u;
    if (!checked_sub(request.original_rbp, destination_back_offset,
                     expected_destination)
            || !checked_add(request.entry_rsp, key_offset, expected_key)
            || !checked_add(request.original_rbp, value_offset,
                            expected_value)
            || !checked_add(request.original_rbp, caller_offset,
                            caller_slot)
            || !checked_sub(caller_slot, owner_back_offset, owner_slot)) {
        return false;
    }
    (void)scope;
    return valid_canonical(expected_caller)
        && request.destination == expected_destination
        && request.key == expected_key && request.value == expected_value
        && request.return_pc == expected_return
        && checked_range(caller_slot, sizeof(Address), caller_slot)
        && checked_range(owner_slot, sizeof(Address), owner_slot);
}

inline bool direct_aliases(const Request& request,
                           const Workspace& workspace,
                           const Snapshot& output,
                           std::size_t caller_offset,
                           Address expected_caller) noexcept {
    (void)expected_caller;
    const Address workspace_address =
        reinterpret_cast<Address>(&workspace);
    const Address output_address = reinterpret_cast<Address>(&output);
    const Address caller_slot = [&]() noexcept -> Address {
        Address value = 0u;
        if (!checked_add(request.original_rbp, caller_offset, value)) return 0u;
        return value;
    }();
    const Address owner_slot = [&]() noexcept -> Address {
        Address value = 0u;
        if (!checked_sub(caller_slot, kFormatterOwnerBackOffset, value)) {
            return 0u;
        }
        return value;
    }();

    if (ranges_overlap(workspace_address, sizeof(Workspace),
                       output_address, sizeof(Snapshot))) {
        return true;
    }

    const Address sources[] = {
        request.key, request.value, request.destination,
        request.entry_rsp, caller_slot, owner_slot,
    };
    const std::size_t sizes[] = {
        kStringObjectBytes, kStringObjectBytes, kDestinationBytes,
        sizeof(Address), sizeof(Address), sizeof(Address),
    };
    for (std::size_t index = 0u; index < sizeof(sources) / sizeof(sources[0]);
         ++index) {
        if (ranges_overlap(workspace_address, sizeof(Workspace),
                           sources[index], sizes[index])
                || ranges_overlap(output_address, sizeof(Snapshot),
                                  sources[index], sizes[index])) {
            return true;
        }
    }
    return false;
}

inline bool valid_value_header(const String32& header,
                               std::size_t& length,
                               Address& payload) noexcept {
    if (header.length > kMaxValueBytes
            || header.capacity < header.length
            || header.capacity > kMaxStringCapacity) {
        return false;
    }
    length = static_cast<std::size_t>(header.length);
    if (header.capacity <= kInlineCapacity) {
        if (header.capacity != kInlineCapacity) return false;
        if (length > kInlineCapacity) return false;
        payload = 0u;
        return true;
    }
    payload = load_u64(header.storage.data());
    return valid_pointer(payload);
}

inline bool valid_key_header(const String32& header) noexcept {
    static constexpr unsigned char expected[] = {'N', 'A', 'M', 'E', 0u};
    return header.capacity == kInlineCapacity && header.length == 4u
        && std::memcmp(header.storage.data(), expected, sizeof(expected)) == 0;
}

inline bool no_embedded_nul(const unsigned char* bytes,
                            std::size_t length) noexcept {
    for (std::size_t index = 0u; index < length; ++index) {
        if (bytes[index] == 0u) return false;
    }
    return true;
}

inline bool copy_inline(const String32& header, StringFingerprint& output,
                        std::size_t length) noexcept {
    if (length > kInlineCapacity || header.storage[length] != 0u
            || !no_embedded_nul(header.storage.data(), length)) {
        return false;
    }
    output.payload_address = output.object_address;
    output.length = static_cast<std::uint32_t>(length);
    std::memcpy(output.bytes.data(), header.storage.data(), length + 1u);
    return true;
}

inline bool source_range_is_clean(const PassScratch& scratch,
                                  const Request& request,
                                  Address workspace_address,
                                  Address output_address) noexcept {
    Address payload_end = 0u;
    if (scratch.value.capacity >= kHeapThreshold
            && !checked_range(scratch.value_payload,
                              scratch.value_length + 1u, payload_end)) {
        return false;
    }
    if (scratch.value.capacity < kHeapThreshold) return true;

    const Address ranges[] = {
        request.key, request.value, request.destination,
        workspace_address, output_address,
    };
    const std::size_t sizes[] = {
        kStringObjectBytes, kStringObjectBytes, kDestinationBytes,
        sizeof(Workspace), sizeof(Snapshot),
    };
    for (std::size_t index = 0u; index < sizeof(ranges) / sizeof(ranges[0]);
         ++index) {
        if (ranges_overlap(scratch.value_payload, scratch.value_length + 1u,
                           ranges[index], sizes[index])) {
            return false;
        }
    }
    return true;
}

template <typename Pass>
bool read_headers(Pass& pass, const Request& request,
                  const ScopeIdentity& scope,
                  Address expected_return, Address expected_caller,
                  std::size_t caller_offset,
                  std::size_t owner_back_offset,
                  PassScratch& scratch) noexcept {
    scratch = PassScratch{};
    unsigned char raw_pointer[sizeof(Address)]{};

    if (!pass.read(request.entry_rsp, raw_pointer, sizeof(raw_pointer))) {
        return false;
    }
    scratch.return_pc = load_u64(raw_pointer);
    if (scratch.return_pc != expected_return) return false;

    Address caller_slot = 0u;
    if (!checked_add(request.original_rbp, caller_offset, caller_slot)
            || !pass.read(caller_slot, raw_pointer, sizeof(raw_pointer))) {
        return false;
    }
    scratch.formatter_caller = load_u64(raw_pointer);
    if (scratch.formatter_caller != expected_caller
            || !valid_canonical(scratch.formatter_caller)) {
        return false;
    }

    Address owner_slot = 0u;
    if (!checked_sub(caller_slot, owner_back_offset, owner_slot)
            || !pass.read(owner_slot, raw_pointer, sizeof(raw_pointer))) {
        return false;
    }
    scratch.combat_owner = load_u64(raw_pointer);
    if (scratch.combat_owner != scope.combat) return false;

    unsigned char raw_string[kStringObjectBytes]{};
    if (!pass.read(request.key, raw_string, sizeof(raw_string))) return false;
    std::memcpy(&scratch.key, raw_string, sizeof(scratch.key));
    if (!valid_key_header(scratch.key)) return false;

    if (!pass.read(request.value, raw_string, sizeof(raw_string))) {
        return false;
    }
    std::memcpy(&scratch.value, raw_string, sizeof(scratch.value));
    if (!valid_value_header(scratch.value, scratch.value_length,
                            scratch.value_payload)) {
        return false;
    }
    return true;
}

template <typename Pass>
bool materialize(Pass& pass, const Request& request,
                 const PassScratch& scratch,
                 PassFingerprint& output) noexcept {
    output = PassFingerprint{};
    output.return_pc = scratch.return_pc;
    output.formatter_caller = scratch.formatter_caller;
    output.combat_owner = scratch.combat_owner;

    output.key.object_address = request.key;
    output.key.header = scratch.key;
    if (!copy_inline(scratch.key, output.key, 4u)) return false;

    output.value.object_address = request.value;
    output.value.header = scratch.value;
    output.value.length = static_cast<std::uint32_t>(scratch.value_length);
    if (scratch.value.capacity < kHeapThreshold) {
        if (!copy_inline(scratch.value, output.value, scratch.value_length)) {
            return false;
        }
        return true;
    }

    output.value.payload_address = scratch.value_payload;
    if (!pass.read(scratch.value_payload, output.value.bytes.data(),
                   scratch.value_length + 1u)
            || output.value.bytes[scratch.value_length] != 0u
            || !no_embedded_nul(output.value.bytes.data(),
                                scratch.value_length)) {
        return false;
    }
    return true;
}

inline bool same_string(const StringFingerprint& left,
                        const StringFingerprint& right) noexcept {
    const std::size_t bytes = static_cast<std::size_t>(left.length) + 1u;
    return left.object_address == right.object_address
        && std::memcmp(&left.header, &right.header, sizeof(String32)) == 0
        && left.payload_address == right.payload_address
        && left.length == right.length
        && same_bytes(left.bytes.data(), right.bytes.data(), bytes);
}

inline bool same_pass(const PassFingerprint& left,
                      const PassFingerprint& right) noexcept {
    return left.return_pc == right.return_pc
        && left.formatter_caller == right.formatter_caller
        && left.combat_owner == right.combat_owner
        && same_string(left.key, right.key)
        && same_string(left.value, right.value);
}

}  // namespace detail

template <typename Reader>
bool capture(Reader& reader, const Request& request,
             const ScopeIdentity& scope, Workspace& workspace,
             Snapshot& output, Result& result) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    result = Result{};

    const bool land = scope.kind == kLandKind;
    const bool naval = scope.kind == kNavalKind;
    const std::size_t return_rva =
        land ? kLandReturnRva : kNavalReturnRva;
    const std::size_t caller_rva =
        land ? kLandFormatterCallerRva : kNavalFormatterCallerRva;
    const std::size_t caller_offset =
        land ? kLandFormatterCallerOffset : kNavalFormatterCallerOffset;
    const std::size_t key_offset =
        land ? kLandKeyEntryOffset : kNavalKeyEntryOffset;
    const std::size_t value_offset =
        land ? kLandValueOffset : kNavalValueOffset;
    const std::size_t destination_back_offset =
        land ? kLandDestinationBackOffset : kNavalDestinationBackOffset;

    // Reject direct aliases before any output clear, including failures in
    // module-address arithmetic. Result is a separate caller-owned status.
    if (detail::direct_aliases(request, workspace, output, caller_offset, 0u)) {
        detail::fail(result, FailureStage::alias);
        return false;
    }
    Address expected_return = 0u;
    Address expected_caller = 0u;
    if (detail::checked_add(request.module_base,
                            static_cast<Address>(return_rva), expected_return)
            && detail::checked_add(request.module_base,
                                   static_cast<Address>(caller_rva),
                                   expected_caller)) {
        // Continue with the bounded static checks below.
    } else {
        detail::fail(result, FailureStage::request);
        return false;
    }

    // Alias checks precede every clear so a caller cannot accidentally erase
    // a live source/destination object by passing overlapping Workspace or
    // Snapshot storage.
    if (detail::direct_aliases(request, workspace, output, caller_offset,
                               expected_caller)) {
        detail::fail(result, FailureStage::alias);
        return false;
    }

    if (!scope.parent_guards_verified || scope.sequence == 0u
            || scope.raw_date < 0 || !detail::valid_pointer(scope.combat)
            || (!land && !naval)) {
        detail::fail(result, FailureStage::scope);
        return false;
    }

    Address image_end = 0u;
    if (!detail::checked_range(request.module_base, request.image_size,
                              image_end)
            || !detail::image_range(request.module_base, request.image_size,
                                    expected_return, 1u)
            || !detail::image_range(request.module_base, request.image_size,
                                    expected_caller, 1u)
            || !detail::valid_pointer(request.entry_rsp)
            || !detail::valid_pointer(request.original_rbp)
            || !detail::valid_pointer(request.destination)
            || !detail::valid_pointer(request.key)
            || !detail::valid_pointer(request.value)
            || !detail::valid_canonical(request.return_pc)
            || !detail::expected_layout(
                request, scope, expected_return, expected_caller,
                caller_offset, kFormatterOwnerBackOffset, key_offset,
                value_offset, destination_back_offset)) {
        detail::fail(result, FailureStage::request);
        return false;
    }

    Address destination_end = 0u;
    if (!detail::checked_range(request.destination, kDestinationBytes,
                              destination_end)
            || !detail::checked_range(request.key, kStringObjectBytes,
                                      destination_end)
            || !detail::checked_range(request.value, kStringObjectBytes,
                                      destination_end)
            || detail::ranges_overlap(request.destination, kDestinationBytes,
                                      request.key, kStringObjectBytes)
            || detail::ranges_overlap(request.destination, kDestinationBytes,
                                      request.value, kStringObjectBytes)
            || detail::ranges_overlap(request.key, kStringObjectBytes,
                                      request.value, kStringObjectBytes)) {
        detail::fail(result, FailureStage::request);
        return false;
    }

    detail::BudgetReader<Reader> budget(reader);
    detail::PassScratch first_scratch{};
    if (!detail::read_headers(
            budget, request, scope, expected_return, expected_caller,
            caller_offset, kFormatterOwnerBackOffset, first_scratch)) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::return_pc);
        return false;
    }
    if (!detail::source_range_is_clean(
            first_scratch, request, reinterpret_cast<Address>(&workspace),
            reinterpret_cast<Address>(&output))) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::alias);
        return false;
    }
    // The heap payload is discovered only by reading the source headers.
    // Do not clear owned buffers before proving those payloads disjoint.
    // Pre-admission/alias failures leave Snapshot/Workspace untouched; the
    // returned bool and Result.observed are the publication authority.
    detail::clear_snapshot(output);
    workspace = Workspace{};
    if (!detail::materialize(budget, request, first_scratch,
                             workspace.before)) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::budget_or_read);
        detail::clear_snapshot(output);
        return false;
    }
    result.before_complete = true;

    detail::PassScratch second_scratch{};
    if (!detail::read_headers(
            budget, request, scope, expected_return, expected_caller,
            caller_offset, kFormatterOwnerBackOffset, second_scratch)) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::budget_or_read);
        detail::clear_snapshot(output);
        return false;
    }
    if (!detail::source_range_is_clean(
            second_scratch, request, reinterpret_cast<Address>(&workspace),
            reinterpret_cast<Address>(&output))) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::alias);
        return false;
    }
    if (!detail::materialize(budget, request, second_scratch,
                             workspace.after)) {
        result.calls = budget.calls();
        result.total_bytes = budget.total_bytes();
        detail::fail(result, FailureStage::budget_or_read);
        detail::clear_snapshot(output);
        return false;
    }
    result.after_complete = true;
    result.calls = budget.calls();
    result.total_bytes = budget.total_bytes();

    if (!detail::same_pass(workspace.before, workspace.after)) {
        detail::fail(result, FailureStage::source_changed);
        detail::clear_snapshot(output);
        return false;
    }
    result.source_unchanged = true;

    output.state = SnapshotState::known;
    output.sequence = scope.sequence;
    output.raw_date = scope.raw_date;
    output.kind = scope.kind;
    output.length = workspace.before.value.length;
    std::memcpy(output.bytes.data(), workspace.before.value.bytes.data(),
                static_cast<std::size_t>(output.length) + 1u);
    result.observed = true;
    return true;
}

}  // namespace information::battle::owned_name_handoff

#endif  // INFORMATION_BATTLE_OWNED_NAME_HANDOFF_H
