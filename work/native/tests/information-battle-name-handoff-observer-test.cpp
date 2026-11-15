#define INFORMATION_BATTLE_TEMPLATE 1
#define INFORMATION_BATTLE_NAVAL 1
#define INFORMATION_BATTLE_CONTAINER 1
#define INFORMATION_BATTLE_WAR_IDENTITY 1
#define INFORMATION_BATTLE_NATIVE_TEXT 1
#define INFORMATION_BATTLE_GATE_TRACE 1
#define INFORMATION_BATTLE_DISPLAY_CONTEXT 1
#define INFORMATION_BATTLE_NAME_HANDOFF 1

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

static bool observation_register_battle_war(std::uintptr_t, char* output,
                                            std::size_t capacity) noexcept {
    if (output == nullptr || capacity < 30u) return false;
    constexpr char value[] = "war_0123456789abcdef_01234567";
    if (sizeof(value) != 30u) return false;
    std::memcpy(output, value, sizeof(value));
    return true;
}

std::uint64_t observation_creation = 0u;

#define main legacy_name_handoff_context_fixture_main
#include "../test-information-battle-observer-context.cpp"
#undef main

#include "information-battle-name-handoff-synthetic-guards.h"

// The observer translation unit retains hook addresses in its install-plan
// code. This fixture never installs or calls those entry points; the separate
// ABI tests own executable stub coverage, so inert matching symbols are enough
// to link the direct capture/flush integration path.
extern "C" void information_battle_entry_stub() {}
extern "C" void information_battle_message_hook(void*, void*, void*, void*) {}
extern "C" void information_battle_container_hook(void*) {}
extern "C" void information_battle_line1_hook(void*, void*, unsigned char) {}
extern "C" void information_battle_gate_marker_hook() {}
extern "C" void information_battle_name_handoff_hook() {}

namespace {

namespace handoff = information::battle::owned_name_handoff;
namespace name_wire = information::battle::name_handoff_wire;

constexpr std::size_t kNameStackOffset = 0x1900000u;
constexpr std::uint64_t kOtherOwnerDelta = 8u;
// The gate-trace identity requires a valid digest shape. This value is only
// synthetic fixture data; it does not identify the installed game DLL.
constexpr char kSyntheticFixtureDllSha256[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static_assert(sizeof(kSyntheticFixtureDllSha256) == 65u,
              "fixture digest must contain 64 hex characters and NUL");

enum class Case : std::uint8_t {
    land_known,
    naval_known,
    no_scope,
    wrong_owner,
    wrong_key,
    wrong_date,
    duplicate_same,
    conflicting_duplicate,
    scope_exit_guard_failure,
};

struct NameObjects final {
    std::uintptr_t entry_rsp = 0u;
    std::uintptr_t rbp = 0u;
    std::uintptr_t destination = 0u;
    std::uintptr_t key = 0u;
    std::uintptr_t value = 0u;
    std::uintptr_t return_pc = 0u;
    std::uint32_t kind = 0u;
};

LONG CALLBACK fixture_exception_diagnostic(EXCEPTION_POINTERS* info) noexcept {
    const DWORD code = info != nullptr && info->ExceptionRecord != nullptr
        ? info->ExceptionRecord->ExceptionCode : 0u;
    const std::uintptr_t rip = info != nullptr && info->ContextRecord != nullptr
        ? static_cast<std::uintptr_t>(info->ContextRecord->Rip) : 0u;
    const std::uintptr_t address = code == EXCEPTION_ACCESS_VIOLATION
            && info != nullptr && info->ExceptionRecord != nullptr
            && info->ExceptionRecord->NumberParameters >= 2u
        ? static_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionInformation[1])
        : 0u;
    char line[192]{};
    const int length = std::snprintf(
        line, sizeof(line),
        "FIXTURE_EXCEPTION code=0x%08lx rip=0x%llx address=0x%llx\n",
        static_cast<unsigned long>(code),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(address));
    if (length > 0 && static_cast<std::size_t>(length) < sizeof(line)) {
        DWORD written = 0u;
        (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line,
                        static_cast<DWORD>(length), &written, nullptr);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

std::uint32_t u32_at(const unsigned char* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8u)
        | (static_cast<std::uint32_t>(bytes[2]) << 16u)
        | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

std::uint64_t u64_at(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0u;
    for (unsigned index = 0u; index < 8u; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    }
    return value;
}

bool seed_range(const char* label, std::uintptr_t rva, const void* bytes,
                std::size_t size) noexcept {
    if (g_region == nullptr || bytes == nullptr || size == 0u
            || rva > kRegionBytes || size > kRegionBytes - rva) {
        std::printf("SEED_RANGE_FAIL %s rva=0x%llx size=%llu limit=0x%llx\n",
                    label == nullptr ? "unknown" : label,
                    static_cast<unsigned long long>(rva),
                    static_cast<unsigned long long>(size),
                    static_cast<unsigned long long>(kRegionBytes));
        return false;
    }
    std::printf("SEED_RANGE_BEGIN %s rva=0x%llx size=%llu\n",
                label == nullptr ? "unknown" : label,
                static_cast<unsigned long long>(rva),
                static_cast<unsigned long long>(size));
    std::memcpy(g_region + rva, bytes, size);
    std::printf("SEED_RANGE_DONE %s\n", label == nullptr ? "unknown" : label);
    return true;
}

bool seed_guard_bytes() noexcept {
    // These bytes are copied into a private VirtualAlloc image. The fixture
    // never executes the game function, entry prefix, callsites, or helpers.
    std::printf("PHASE seed_guard_bytes_begin\n");
    if (!seed_range("observer_entry", source::kEntryRva,
                    entry::kOriginalPrologue.data(),
                    entry::kOriginalPrologue.size())
            || !seed_range("observer_unwind", source::kUnwindRva,
                           entry::kOriginalUnwind.data(),
                           entry::kOriginalUnwind.size())) {
        return false;
    }

    for (unsigned index = 0u; index < source::kMessageEntryCount; ++index) {
        const auto kind = static_cast<source::message_entry::EntryKind>(index);
        const auto& spec = source::message_entry::spec(kind);
        if (!seed_range("message_entry_prefix", spec.rva, spec.prefix.data(),
                        spec.prefix_bytes)
                || !seed_range("message_entry_unwind", spec.unwind_rva,
                               spec.unwind_expected.data(), spec.unwind_bytes)) {
            return false;
        }
    }

    const auto& line1 = source::line1_entry_plan::spec();
    if (!seed_range("line1_entry_prefix", line1.entry_rva, line1.prefix.data(),
                    line1.prefix_bytes)
            || !seed_range("line1_entry_unwind", line1.unwind_rva,
                           line1.unwind_expected.data(), line1.unwind_bytes)) {
        return false;
    }

    const auto& gate = source::gate_marker_plan::spec();
    if (!seed_range("gate_marker_prefix", gate.entry_rva, gate.prefix.data(),
                    gate.prefix.size())
            || !seed_range("gate_marker_unwind", gate.unwind_rva,
                           gate.unwind_expected.data(),
                           gate.unwind_expected.size())
            || !seed_range("land_gate_callsite",
                           source::gate_marker_plan::kLandGateRva,
                           source::gate_marker_plan::kLandGateBytes.data(),
                           source::gate_marker_plan::kLandGateBytes.size())
            || !seed_range("naval_gate_callsite",
                           source::gate_marker_plan::kNavalGateRva,
                           source::gate_marker_plan::kNavalGateBytes.data(),
                           source::gate_marker_plan::kNavalGateBytes.size())
            || !seed_range("name_entry",
                           source::name_entry_plan::kEntryRva,
                           source::name_entry_plan::kExpectedFunction.data(),
                           source::name_entry_plan::kExpectedFunction.size())
            || !seed_range("name_land_callsite", 0x23545eu,
                           source::kNameLandCallsite,
                           sizeof(source::kNameLandCallsite))
            || !seed_range("name_naval_callsite", 0x230bd6u,
                           source::kNameNavalCallsite,
                           sizeof(source::kNameNavalCallsite))
            || !seed_range("name_literal", 0x1c43becu, "NAME", 5u)) {
        return false;
    }

    for (const auto& range :
         synthetic_name_handoff_guards::kDisplayContextRanges) {
        if (!seed_range("display_context_guard", range.rva,
                        range.bytes, range.size)) {
            return false;
        }
    }
    std::printf("PHASE seed_guard_bytes_complete\n");
    return true;
}

bool reset_case_state(std::uint32_t kind) noexcept {
    std::printf("PHASE reset_case_begin kind=%u\n", kind);
    if (g_region == nullptr || kRegionBytes == 0u
            || source::kEntryRva > kRegionBytes
            || kSourceCodeBytes > kRegionBytes - source::kEntryRva) {
        std::printf("RESET_RANGE_FAIL region_or_source_code\n");
        return false;
    }
    DWORD old_protection = 0u;
    SetLastError(ERROR_SUCCESS);
    if (!VirtualProtect(g_region, kRegionBytes, PAGE_READWRITE,
                        &old_protection)) {
        const DWORD error = GetLastError();
        std::printf("RESET_PROTECTION_FAIL error=0x%08lx bytes=0x%llx\n",
                    static_cast<unsigned long>(error),
                    static_cast<unsigned long long>(kRegionBytes));
        return false;
    }
    std::printf("PHASE region_protection_restored old=0x%08lx\n",
                static_cast<unsigned long>(old_protection));
    initialize_context();
    initialize_observed_objects();
    initialize_context_objects(kind, true);
    build_source_body(g_region + source::kEntryRva);
    if (!seed_guard_bytes()) return false;

    for (auto& record : source::slots) record = source::Record{};
    source::pending = source::Record{};
    for (bool& ready : source::slot_ready) ready = false;
    source::head = 0u;
    source::count = 0u;
    source::has_pending = false;
    source::fragment_plan = information::battle::fragment::FragmentPlan{};
    source::fragment_index = 0u;
    source::encoded_bytes = 0u;
    source::sequence.store(0u, std::memory_order_relaxed);
    source::trace_observation_drops.store(0u, std::memory_order_relaxed);
    source::scope_depth = 0u;
    source::suppressed_scopes = 0u;
    source::game = g_game;
    source::player = kPlayer;
    source::last_date = static_cast<std::int32_t>(kDate);
    source::state.store(source::enabled, std::memory_order_release);
    std::printf("PHASE reset_case_complete kind=%u\n", kind);
    return true;
}

bool prepare_fixture() noexcept {
    self_module = GetModuleHandleW(nullptr);
    std::uint64_t creation = 0u;
    if (self_module == nullptr || !process_creation(creation)
            || !make_directory_and_paths()) {
        return false;
    }
    g_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kRegionBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (g_region == nullptr) return false;
    base = reinterpret_cast<std::uintptr_t>(g_region);
    g_source_code = g_region + source::kEntryRva;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;

    source::identity = {kInstallation, creation};
    source::creation = creation;
    source::game_image_size = kRegionBytes;
    source::bound_thread = frame_thread;
    std::memcpy(source::dll_sha, kSyntheticFixtureDllSha256,
                sizeof(kSyntheticFixtureDllSha256));
    std::printf("FIXTURE_IDENTITY dll_sha_synthetic=true\n");
    observation_creation = creation;
    source::state.store(source::enabled, std::memory_order_release);
    if (!source::drain.reset(source::identity).succeeded()) return false;

    std::memcpy(source::directory, g_fixture_directory.data(),
                sizeof(source::directory));
    if (swprintf(source::log_path, MAX_PATH, L"%ls\\name-handoff.jsonl",
                 g_fixture_directory.data()) <= 0
            || swprintf(source::trace_log_path, MAX_PATH,
                        L"%ls\\name-handoff-gate-trace.jsonl",
                        g_fixture_directory.data()) <= 0) {
        return false;
    }
    source::trace_file_created = false;
    if (!source::writer.open(source::log_path, source::identity)) return false;

    if (!reset_case_state(1u)) return false;
    const bool guarded = source::code_guard();
    std::printf("PHASE initial_code_guard %s\n", guarded ? "PASS" : "FAIL");
    return guarded;
}

NameObjects make_name_objects(std::uint32_t kind) noexcept {
    NameObjects objects{};
    objects.kind = kind;
    objects.entry_rsp = base + kNameStackOffset;
    objects.rbp = base + kNameStackOffset + 0x2000u;
    objects.return_pc = base + (kind == handoff::kLandKind
        ? handoff::kLandReturnRva : handoff::kNavalReturnRva);
    if (kind == handoff::kLandKind) {
        objects.destination = objects.rbp - handoff::kLandDestinationBackOffset;
        objects.key = objects.entry_rsp + handoff::kLandKeyEntryOffset;
        objects.value = objects.rbp + handoff::kLandValueOffset;
    } else {
        objects.destination = objects.rbp - handoff::kNavalDestinationBackOffset;
        objects.key = objects.entry_rsp + handoff::kNavalKeyEntryOffset;
        objects.value = objects.rbp + handoff::kNavalValueOffset;
    }
    return objects;
}

void write_string(std::uintptr_t address, const char* text) noexcept {
    handoff::String32 value{};
    const std::size_t length = std::strlen(text);
    value.length = static_cast<std::uint64_t>(length);
    value.capacity = handoff::kInlineCapacity;
    std::memcpy(value.storage.data(), text, length);
    value.storage[length] = 0u;
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

void prepare_name_sources(const NameObjects& objects, const char* key,
                          const char* value, bool wrong_owner = false) noexcept {
    const std::uintptr_t caller_slot = objects.rbp
        + (objects.kind == handoff::kLandKind
            ? handoff::kLandFormatterCallerOffset
            : handoff::kNavalFormatterCallerOffset);
    const std::uintptr_t caller_pc = base
        + (objects.kind == handoff::kLandKind
            ? handoff::kLandFormatterCallerRva
            : handoff::kNavalFormatterCallerRva);
    std::memcpy(reinterpret_cast<void*>(objects.entry_rsp),
                &objects.return_pc, sizeof(objects.return_pc));
    std::memcpy(reinterpret_cast<void*>(caller_slot), &caller_pc,
                sizeof(caller_pc));
    const std::uintptr_t owner = g_combat
        + (wrong_owner ? kOtherOwnerDelta : 0u);
    std::memcpy(reinterpret_cast<void*>(caller_slot
                    - handoff::kFormatterOwnerBackOffset),
                &owner, sizeof(owner));
    std::memset(reinterpret_cast<void*>(objects.destination), 0,
                handoff::kDestinationBytes);
    write_string(objects.key, key);
    write_string(objects.value, value);
}

void invoke_name_capture(const NameObjects& objects) noexcept {
    information_battle_name_handoff_capture(
        reinterpret_cast<void*>(objects.destination),
        reinterpret_cast<void*>(objects.key),
        reinterpret_cast<void*>(objects.value),
        reinterpret_cast<void*>(objects.return_pc), objects.rbp,
        objects.entry_rsp);
}

void set_up_battle_scope(std::uint32_t kind,
                         source::ScopeToken& token) noexcept {
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + 0x23a40du), g_war);
    if (token.depth != 0u && source::scope_depth != 0u) {
        auto& scope = source::scopes[source::scope_depth - 1u];
        if (scope.has_record && scope.slot < source::kSlots) {
            auto& context = source::contexts(source::slots[scope.slot]);
            if (!context.context_present
                    || static_cast<std::uint32_t>(context.context.kind) != kind) {
                scope.ambiguous = true;
            }
        }
    }
}

bool frame_has_name(std::uint32_t expected_state, std::uint32_t expected_kind,
                    std::uint64_t expected_sequence, const char* expected_value,
                    const char* label) noexcept {
    const unsigned char* bytes = source::encoded;
    const std::size_t size = source::encoded_bytes;
    bool good = size >= name_wire::kOuterHeaderBytes
        && std::memcmp(bytes, name_wire::kMagic.data(), name_wire::kMagic.size()) == 0
        && bytes[4] == 8u && bytes[5] == 0u;
    if (!good) {
        check(false, label);
        return false;
    }
    const std::size_t base7_bytes = u32_at(bytes + 6u);
    const std::size_t extension = name_wire::kOuterHeaderBytes + base7_bytes;
    const std::size_t body = extension + name_wire::kExtensionHeaderBytes;
    good = extension + name_wire::kExtensionHeaderBytes +
            name_wire::kFixedBodyBytes <= size
        && base7_bytes <= size - name_wire::kOuterHeaderBytes
        && std::memcmp(bytes + extension, name_wire::kExtensionMagic.data(),
                       name_wire::kExtensionMagic.size()) == 0
        && name_wire::validate(bytes + name_wire::kOuterHeaderBytes,
                               base7_bytes, source::pending.name_handoff);
    if (good) {
        const std::uint32_t length = u32_at(bytes + body + 20u);
        good = bytes[body] == expected_state
            && (expected_state == 0u || bytes[body + 1u] == expected_kind)
            && (expected_state == 0u || u64_at(bytes + body + 4u) == expected_sequence)
            && (expected_state != 1u || (length == std::strlen(expected_value)
                && std::memcmp(bytes + body + name_wire::kFixedBodyBytes,
                               expected_value, length) == 0));
    }
    check(good, label);
    return good;
}

void emit_frame(const char* label) noexcept {
    std::printf("FRAME_HEX %s ", label);
    for (std::size_t index = 0u; index < source::encoded_bytes; ++index) {
        std::printf("%02x", static_cast<unsigned>(source::encoded[index]));
    }
    std::printf("\n");
}

void print_name_state(const char* label, const char* stage,
                      const source::Record* record) noexcept {
    const unsigned state = record == nullptr ? 0xffu
        : static_cast<unsigned>(record->name_handoff.state);
    const unsigned invalid = record != nullptr && record->name_handoff_invalid
        ? 1u : 0u;
    std::printf("NAME_STATE case=%s stage=%s state=%u invalid=%u\n",
                label, stage, state, invalid);
}

void run_case(Case selected, const char* label) noexcept {
    const std::uint32_t kind = selected == Case::naval_known ? 2u : 1u;
    if (!reset_case_state(kind)) {
        check(false, "synthetic_case_reset_succeeds");
        return;
    }
    source::name_entry = source::NameEntry{};
    const auto objects = make_name_objects(kind);
    const char* value = selected == Case::naval_known ? "naval-result" : "land-result";
    const char* key = selected == Case::wrong_key ? "OTHER" : "NAME";
    prepare_name_sources(objects, key, value,
                         selected == Case::wrong_owner);

    source::ScopeToken token{};
    set_up_battle_scope(kind, token);
    check(token.depth == 1u && source::scope_depth == 1u,
          "synthetic_battle_scope_opened");
    const bool has_owner = token.depth != 0u
        && source::scopes[token.depth - 1u].has_record;
    check(has_owner, "synthetic_result_and_context_bound_to_scope");
    const std::uint64_t expected_sequence = has_owner
        ? source::scopes[token.depth - 1u].sequence : 0u;
    source::Record* case_record = has_owner
        ? &source::slots[source::scopes[token.depth - 1u].slot] : nullptr;

    if (selected != Case::no_scope) {
        if (selected == Case::wrong_date) {
            write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
                      static_cast<std::int32_t>(kDate + 1));
        }
        invoke_name_capture(objects);
        if (selected == Case::duplicate_same) invoke_name_capture(objects);
        if (selected == Case::conflicting_duplicate) {
            write_string(objects.value, "other-result");
            invoke_name_capture(objects);
            write_string(objects.value, value);
            invoke_name_capture(objects);
        }
        if (selected == Case::land_known || selected == Case::naval_known) {
            // Native move happens after the callback. The observer must keep
            // the copied value even after both source String32 objects clear.
            std::memset(reinterpret_cast<void*>(objects.key), 0,
                        sizeof(handoff::String32));
            std::memset(reinterpret_cast<void*>(objects.value), 0,
                        sizeof(handoff::String32));
        }
        if (selected == Case::scope_exit_guard_failure) {
            g_region[source::name_entry_plan::kEntryRva + 154u] ^= 0xffu;
        }
    }
    print_name_state(label, "after_capture", case_record);

    source::end_scope(token);
    if (selected == Case::scope_exit_guard_failure) {
        // Restore the synthetic code after end_scope has observed the failed
        // code guard; final wire encoding still uses an intact fixture image.
        g_region[source::name_entry_plan::kEntryRva + 154u] =
            source::name_entry_plan::kExpectedFunction[154u];
    }
    if (selected == Case::no_scope) invoke_name_capture(objects);
    print_name_state(label, "after_scope_finalize", case_record);

    const auto trace_records_before =
        source::trace_records_written.load(std::memory_order_relaxed);
    source::trace_write_error = ERROR_SUCCESS;
    std::printf("FLUSH_BEGIN case=%s state=%ld trace_write_error=%lu encoded_bytes=%zu\n",
                label, source::state.load(std::memory_order_acquire),
                static_cast<unsigned long>(source::trace_write_error),
                source::encoded_bytes);
    source::flush();
    const auto trace_records_after =
        source::trace_records_written.load(std::memory_order_relaxed);
    std::printf("FLUSH_END case=%s state=%ld trace_write_error=%lu trace_records=%llu trace_failures=%llu encoded_bytes=%zu name_state=%u name_invalid=%u\n",
                label, source::state.load(std::memory_order_acquire),
                static_cast<unsigned long>(source::trace_write_error),
                static_cast<unsigned long long>(trace_records_after),
                static_cast<unsigned long long>(source::trace_write_failures.load(
                    std::memory_order_relaxed)),
                source::encoded_bytes,
                case_record == nullptr ? 0xffu
                    : static_cast<unsigned>(case_record->name_handoff.state),
                case_record != nullptr && case_record->name_handoff_invalid ? 1u : 0u);
    check(source::trace_write_error == ERROR_SUCCESS,
          "synthetic_gate_trace_write_succeeds");
    check(trace_records_after == trace_records_before + 1u,
          "synthetic_gate_trace_record_appended");
    check(source::encoded_bytes != 0u,
          "synthetic_v8_frame_encoded_after_trace");
    check(source::state.load(std::memory_order_acquire) != source::fault,
          "synthetic_flush_does_not_fault");
    emit_frame(label);

    const bool known = selected == Case::land_known
        || selected == Case::naval_known || selected == Case::duplicate_same;
    check(case_record != nullptr
              && (case_record->name_handoff.state
                  == (known ? handoff::SnapshotState::known
                            : handoff::SnapshotState::unknown)),
          "synthetic_name_state_matches_case");
    const std::uint32_t expected_kind = kind;
    const char* expected_value = value;
    frame_has_name(known ? 1u : 0u, expected_kind,
                   known ? expected_sequence : 0u,
                   known ? expected_value : "", label);
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
                       | SEM_NOOPENFILEERRORBOX);
    PVOID exception_handler = AddVectoredExceptionHandler(
        1u, &fixture_exception_diagnostic);
    std::printf("TEST information-battle-name-handoff-observer\n");
    if (!prepare_fixture()) {
        std::printf("RESULT FAIL synthetic_setup\n");
        if (exception_handler != nullptr) {
            (void)RemoveVectoredExceptionHandler(exception_handler);
        }
        return 1;
    }

    run_case(Case::land_known, "land_name_copied_before_move_and_flushed_v8");
    run_case(Case::naval_known, "naval_name_copied_before_move_and_flushed_v8");
    run_case(Case::no_scope, "callback_without_scope_remains_unknown");
    run_case(Case::wrong_owner, "wrong_combat_owner_remains_unknown");
    run_case(Case::wrong_key, "wrong_key_remains_unknown");
    run_case(Case::wrong_date, "date_drift_remains_unknown");
    run_case(Case::duplicate_same, "identical_duplicate_preserves_name");
    run_case(Case::conflicting_duplicate,
             "conflict_latches_unknown_after_original_value_returns");
    run_case(Case::scope_exit_guard_failure,
             "scope_exit_guard_failure_withdraws_name");

    const bool passed = g_failures == 0u;
    std::printf("RESULT %s failures=%u\n", passed ? "PASS" : "FAIL",
                g_failures);
    if (exception_handler != nullptr) {
        (void)RemoveVectoredExceptionHandler(exception_handler);
    }
    return passed ? 0 : 1;
}
