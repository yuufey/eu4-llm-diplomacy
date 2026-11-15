#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "information-battle-entry-plan.h"
#include "entry-patch-transaction.inc"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

// These are the host-owned seams required by the production include.  The
// fixture fills them with addresses in its private VirtualAlloc region; no
// EU4 process or game function is involved.
std::uintptr_t base = 0;
HMODULE self_module = nullptr;
DWORD frame_thread = 0;
bool thread_changed = false;

#include "information-battle-observer.inc"

namespace {

namespace entry = information::battle::entry;
namespace owned = information::battle::owned_result;
namespace summary = information::battle::owned_summary;
namespace source = information_battle_source;

constexpr std::size_t kRegionBytes = 0x2800000u;  // 40 MiB
constexpr std::size_t kSourceBytes = 0x1000u;
constexpr std::size_t kSourceUnwindOffset = 0x100u;
constexpr std::size_t kSourceCodeBytes = 72u;
constexpr std::size_t kResultOffset = 0x800000u;
constexpr std::size_t kSummaryOffset = 0x900000u;
constexpr std::size_t kNameHeapOffset = 0xa00000u;
constexpr std::size_t kCommanderHeapOffset = 0xa01000u;
constexpr std::size_t kGameOffset = 0x2300000u;
constexpr std::size_t kDatabaseOffset = 0x2400000u;
constexpr std::size_t kRowsOffset = 0x2500000u;
constexpr std::size_t kCountryOffset = 0x2600000u;
constexpr std::uint32_t kDate = 56553384u;
constexpr std::uint64_t kPlayer = UINT64_C(0x0000000100000042);
constexpr std::uint64_t kInstallation = UINT64_C(0x42328a11);
constexpr std::uintptr_t kCombat = UINT64_C(0x1111222233334444);
constexpr std::uintptr_t kNativeReturn = UINT64_C(0x13579bdf2468ace0);
constexpr DWORD kInitialLastError = 0x13572468u;
constexpr std::size_t kResultObjectBytes = owned::kResultObjectBytes;

using NativeFunction = std::uintptr_t (*)(void*, void*, void*, void*,
                                           std::uintptr_t, std::uintptr_t);

unsigned g_failures = 0;
unsigned g_body_calls = 0;
unsigned char* g_region = nullptr;
unsigned char* g_source_code = nullptr;
std::uintptr_t g_result = 0;
std::uintptr_t g_summary = 0;
std::uintptr_t g_game = 0;
std::uintptr_t g_database = 0;
std::uintptr_t g_rows = 0;
std::uintptr_t g_country = 0;
char g_fixture_dll_sha[65]{};
std::array<wchar_t, MAX_PATH> g_fixture_directory{};
bool g_startup_hash_guard_rejected = false;
bool g_startup_leases_closed = false;
bool g_source_changed_observed = false;
bool g_date_regression_observed = false;
bool g_source_changed_flush_preserved = false;
bool g_disabled_flush_drained = false;
bool g_nonce_receipt_observed = false;
bool g_final_response_observed = false;
bool g_unbound_disable_rejected = false;
bool g_unknown_nonce_rejected = false;
bool g_duplicate_request_observed = false;
bool g_wrong_player_rejected = false;
bool g_status_fields_observed = false;
bool g_terminal_quarantine_observed = false;
bool g_terminal_disable_rejected = false;
bool g_terminal_latch_observed = false;
bool g_sequence_exhaustion_fault = false;
bool g_writer_rejection_fault = false;
bool g_checked_log_written = false;

void check(bool condition, const char* name) noexcept {
    std::printf("CHECK %s %s\n", name, condition ? "PASS" : "FAIL");
    if (!condition) ++g_failures;
}

void write_u64(unsigned char* destination, std::uint64_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void write_i32(unsigned char* destination, std::int32_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void set_inline_string(unsigned char* destination, const char* text,
                       std::size_t length) noexcept {
    std::memset(destination, 0, owned::kStringObjectBytes);
    std::memcpy(destination, text, length);
    destination[length] = 0;
    write_u64(destination + 0x10u, static_cast<std::uint64_t>(length));
    write_u64(destination + 0x18u, static_cast<std::uint64_t>(length));
}

void set_heap_string(unsigned char* destination, unsigned char* heap,
                     const char* text, std::size_t length,
                     std::size_t capacity) noexcept {
    std::memset(destination, 0, owned::kStringObjectBytes);
    std::memcpy(heap, text, length);
    heap[length] = 0;
    write_u64(destination, reinterpret_cast<std::uintptr_t>(heap));
    write_u64(destination + 0x10u, static_cast<std::uint64_t>(length));
    write_u64(destination + 0x18u, static_cast<std::uint64_t>(capacity));
}

void initialize_context() noexcept {
    std::memset(g_region, 0, kRegionBytes);
    g_game = reinterpret_cast<std::uintptr_t>(g_region + kGameOffset);
    g_database = reinterpret_cast<std::uintptr_t>(g_region + kDatabaseOffset);
    g_rows = reinterpret_cast<std::uintptr_t>(g_region + kRowsOffset);
    g_country = reinterpret_cast<std::uintptr_t>(g_region + kCountryOffset);

    write_u64(g_region + 0x233fe58u, g_game);
    write_u64(reinterpret_cast<unsigned char*>(g_game) + 0x1e60u, kPlayer);
    write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
              static_cast<std::int32_t>(kDate));
    write_u64(g_region + 0x233d8b0u, g_database);
    write_u64(reinterpret_cast<unsigned char*>(g_database) + 0x118u, g_rows);
    write_u64(reinterpret_cast<unsigned char*>(g_rows) + 8u, g_country);
    write_u64(reinterpret_cast<unsigned char*>(g_country) + 0x20u, kPlayer);

    g_result = reinterpret_cast<std::uintptr_t>(g_region + kResultOffset);
    g_summary = reinterpret_cast<std::uintptr_t>(g_region + kSummaryOffset);
}

void initialize_observed_objects() noexcept {
    unsigned char* result = reinterpret_cast<unsigned char*>(g_result);
    std::memset(result, 0, kResultObjectBytes);
    const std::uintptr_t result_vtable = base + owned::kResultVtableRva;
    const std::uintptr_t side_vtable = base + owned::kSideVtableRva;
    write_u64(result, result_vtable);
    write_u64(result + owned::kResultSideAOffset, side_vtable);
    write_u64(result + owned::kResultSideBOffset, side_vtable);

    unsigned char* side_a = result + owned::kResultSideAOffset;
    unsigned char* side_b = result + owned::kResultSideBOffset;
    write_u64(side_a + owned::kSideCountryOffset, UINT64_C(0x465241));
    write_u64(side_b + owned::kSideCountryOffset, UINT64_C(0x454e47));
    set_inline_string(side_a + owned::kSideCommanderOffset, "A-CMD", 5u);
    set_heap_string(side_b + owned::kSideCommanderOffset,
                    g_region + kCommanderHeapOffset,
                    "B-HEAP-COMMANDER", 16u, 32u);
    for (std::size_t i = 0; i < owned::kSideRawFieldOffsets.size(); ++i) {
        write_i32(side_a + owned::kSideRawFieldOffsets[i],
                  static_cast<std::int32_t>(100 + i));
        write_i32(side_b + owned::kSideRawFieldOffsets[i],
                  static_cast<std::int32_t>(200 + i));
    }
    write_i32(result + owned::kResultAux100Offset, -17);
    write_i32(result + owned::kResultAux104Offset, 23);
    result[owned::kResultFlag108Offset] = 1u;
    write_u64(result + owned::kResultProvincePointerOffset,
              reinterpret_cast<std::uintptr_t>(g_region + 0xb00000u));
    write_i32(g_region + 0xb00000u + owned::kProvinceIdOffset, 1285);
    set_heap_string(result + owned::kResultNameOffset,
                    g_region + kNameHeapOffset,
                    "synthetic-battle-name", 21u, 32u);

    unsigned char* summary_object = reinterpret_cast<unsigned char*>(g_summary);
    std::memset(summary_object, 0, 0x80u);
    for (std::size_t i = 0; i < summary::kRawFieldOffsets.size(); ++i) {
        write_i32(summary_object + summary::kRawFieldOffsets[i],
                  static_cast<std::int32_t>(-300 + static_cast<int>(i)));
    }
    summary_object[summary::kSummaryControlOffset] = 0xfeu;
}

void append_u64(unsigned char* destination, std::size_t& cursor,
                std::uint64_t value) noexcept {
    std::memcpy(destination + cursor, &value, sizeof(value));
    cursor += sizeof(value);
}

extern "C" std::uintptr_t fixture_native_body(
    void*, void*, void* result, std::uintptr_t, std::uintptr_t) noexcept {
    ++g_body_calls;
    // The observer runs before this body.  Destroying the source objects here
    // proves that accepted slots and the encoded frame own their bytes.
    std::memset(result, 0xa5, kResultObjectBytes);
    std::memset(g_region + kNameHeapOffset, 0xdd, 64u);
    std::memset(g_region + kCommanderHeapOffset, 0xee, 64u);
    return kNativeReturn;
}

void build_source_body(unsigned char* destination) noexcept {
    std::memcpy(destination, entry::kOriginalPrologue.data(),
                entry::kOriginalPrologue.size());
    // The patched prefix is only 21 bytes, but the synthetic continuation
    // starts after the complete fixed 36-byte prologue.
    std::size_t cursor = entry::kOriginalPrologue.size();
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xb8u;
    append_u64(destination, cursor,
               reinterpret_cast<std::uintptr_t>(&fixture_native_body));
    destination[cursor++] = 0xffu;
    destination[cursor++] = 0xd0u;
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0x81u;
    destination[cursor++] = 0xc4u;
    destination[cursor++] = 0xa0u;
    destination[cursor++] = 0x05u;
    destination[cursor++] = 0x00u;
    destination[cursor++] = 0x00u;
    destination[cursor++] = 0x41u;
    destination[cursor++] = 0x5fu;
    destination[cursor++] = 0x41u;
    destination[cursor++] = 0x5eu;
    destination[cursor++] = 0x41u;
    destination[cursor++] = 0x5du;
    destination[cursor++] = 0x41u;
    destination[cursor++] = 0x5cu;
    destination[cursor++] = 0x5fu;
    destination[cursor++] = 0x5eu;
    destination[cursor++] = 0x5du;
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0x8bu;
    destination[cursor++] = 0x5cu;
    destination[cursor++] = 0x24u;
    destination[cursor++] = 0x10u;
    destination[cursor++] = 0xc3u;
    check(cursor == kSourceCodeBytes, "source_body_size");
}

bool make_directory_and_paths() noexcept {
    wchar_t temporary[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temporary);
    if (!length || length >= MAX_PATH) return false;
    if (swprintf(g_fixture_directory.data(),
                 MAX_PATH, L"%lsinformation-battle-manager-%lu", temporary,
                 static_cast<unsigned long>(GetCurrentProcessId())) < 0) {
        return false;
    }
    if (!CreateDirectoryW(g_fixture_directory.data(), nullptr)
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return false;
    }
    return true;
}

bool read_status_contract() noexcept {
    wchar_t path[MAX_PATH]{};
    if (swprintf(path, MAX_PATH, L"%ls\\information-battle-status.json",
                 source::directory) < 0) {
        return false;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    char bytes[8192]{};
    DWORD actual = 0;
    const bool readable = GetFileSizeEx(file, &size) && size.QuadPart > 0
        && size.QuadPart < static_cast<LONGLONG>(sizeof(bytes))
        && ReadFile(file, bytes, static_cast<DWORD>(size.QuadPart), &actual,
                    nullptr)
        && actual == static_cast<DWORD>(size.QuadPart);
    const bool closed = CloseHandle(file) != FALSE;
    if (!readable || !closed) return false;
    return std::strstr(bytes, "\"stats_consistent\":false") != nullptr
        && std::strstr(bytes, "\"same_address_reload_verified\":false") != nullptr
        && std::strstr(bytes, "\"publication_stage\":7") != nullptr
        && std::strstr(bytes, "\"patch_attempt_published\":true") != nullptr;
}

bool log_file_nonempty() noexcept {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(source::log_path, GetFileExInfoStandard,
                              &data)) {
        return false;
    }
    const std::uint64_t size =
        (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32u)
        | data.nFileSizeLow;
    return size > 0u;
}

bool process_creation(std::uint64_t& output) noexcept {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel,
                         &user)) {
        return false;
    }
    output = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32u)
        | created.dwLowDateTime;
    return output != 0;
}

bool protect_source() noexcept {
    DWORD old_protection = 0;
    return VirtualProtect(g_source_code, kSourceBytes, PAGE_EXECUTE_READ,
                          &old_protection) != FALSE
        && FlushInstructionCache(GetCurrentProcess(), g_source_code,
                                 kSourceBytes) != FALSE;
}

__attribute__((noinline)) std::uintptr_t call_source() noexcept {
    const NativeFunction target = reinterpret_cast<NativeFunction>(
        g_source_code);
    const std::uintptr_t result = target(
        reinterpret_cast<void*>(kCombat),
        reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(UINT64_C(0x4444555566667777)),
        UINT64_C(0x5555666677778888), UINT64_C(0x6666777788889999));
    asm volatile("" : : "a"(result) : "memory");
    return result;
}

bool command_line(char (&buffer)[512], const char* nonce,
                  const char* verb, std::uint64_t creation,
                  std::uint64_t expected_player = kPlayer) noexcept {
    return snprintf(buffer, sizeof(buffer),
                    "EU4BATTLE1 %s %s %lu %llu %llu %s %016llx\n", nonce,
                    verb, static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long long>(creation),
                    static_cast<unsigned long long>(kInstallation),
                    source::dll_sha,
                    static_cast<unsigned long long>(expected_player)) > 0;
}

bool encoded_has_expected_values() noexcept {
    return source::encoded_bytes > 0u
        && source::fragment_plan.fragment_count > 0u
        && source::fragment_index == source::fragment_plan.fragment_count
        && source::writer.ready()
        && source::encoded_bytes <= information::battle::observation::kMaxWireBytes;
}

void print_encoded() noexcept {
    std::printf("ENCODED_HEX ");
    for (std::size_t i = 0; i < source::encoded_bytes; ++i) {
        std::printf("%02x", static_cast<unsigned>(source::encoded[i]));
    }
    std::printf("\n");
    std::printf("SOURCE_POINTER_HEX %llx\n",
                static_cast<unsigned long long>(g_result));
}

DWORD WINAPI foreign_capture_thread(void*) {
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat),
        reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result), 0, 0);
    return 0;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-observer-manager\n");
    // Keep the complete include/transaction surface compiled in this TU.  The
    // manager deliberately never rolls back a published production patch;
    // taking the address of that cleanup helper is only to keep -Werror from
    // hiding the included implementation.
    (void)&bridge_entry_patch::guarded_patch_rollback;
    (void)&information_battle_tick;

    self_module = GetModuleHandleW(nullptr);
    std::uint64_t creation = 0;
    check(self_module != nullptr && process_creation(creation),
          "fixture_identity_available");
    check(make_directory_and_paths(), "fixture_directory_created");
    wchar_t fixture_exe[MAX_PATH]{};
    const DWORD fixture_exe_length = GetModuleFileNameW(
        nullptr, fixture_exe, MAX_PATH);
    check(fixture_exe_length > 0 && fixture_exe_length < MAX_PATH
              && information_battle_source::hash_file(fixture_exe,
                                                       g_fixture_dll_sha),
          "fixture_hash_helper_callable");

    g_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kRegionBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(g_region != nullptr, "private_40mb_region_allocated");
    if (!g_region || !self_module) {
        std::printf("RESULT FAIL allocation\n");
        return 1;
    }
    base = reinterpret_cast<std::uintptr_t>(g_region);
    g_source_code = g_region + source::kEntryRva;
    initialize_context();
    initialize_observed_objects();
    build_source_body(g_source_code);
    std::memset(g_region + source::kUnwindRva, 0,
                entry::kOriginalUnwind.size());
    std::memcpy(g_region + source::kUnwindRva, entry::kOriginalUnwind.data(),
                entry::kOriginalUnwind.size());
    check(std::memcmp(g_source_code, entry::kOriginalPrologue.data(),
                      entry::kOriginalPrologue.size()) == 0,
          "source_prefix_matches_fixed_36_bytes");
    check(protect_source(), "source_fixture_rx");

    std::uint64_t actual_creation = creation;
    const bool start_result = information_battle_start(
        g_fixture_directory.data(), actual_creation);
    g_startup_hash_guard_rejected = !start_result
        && source::state.load() == source::fault;
    check(!start_result && source::state.load() == source::fault,
          "startup_fixed_exe_hash_guard_rejects_fixture_and_faults");
    check(std::strcmp(source::kExeSha, g_fixture_dll_sha) != 0,
          "fixture_exe_sha_differs_from_fixed_build");
    g_startup_leases_closed = source::exe_lease == INVALID_HANDLE_VALUE
        && source::dll_lease == INVALID_HANDLE_VALUE;
    check(g_startup_leases_closed,
          "startup_hash_failure_closes_read_only_file_leases");

    // A failed startup is still unbound.  A disable request must be rejected
    // without changing the ready state; its durable started receipt is kept as
    // the audit record for the rejected request.
    // The real startup failure is terminal.  The following state reset is
    // fixture-only so the unbound command rejection can be exercised without
    // pretending that production can recover in place.
    source::state.store(source::ready, std::memory_order_release);
    check(!source::identity.valid(), "fixture_starts_unbound_after_guard_failure");
    char unbound_disable_command[512]{};
    check(command_line(unbound_disable_command,
                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "disable",
                       actual_creation),
          "unbound_disable_command_built");
    char unbound_nonce[33]{}, unbound_verb[9]{};
    const char* unbound_reason = nullptr;
    check(!source::command(unbound_disable_command, unbound_nonce,
                           unbound_verb, unbound_reason)
              && std::strcmp(unbound_reason, "unbound_source") == 0
              && source::state.load() == source::ready,
          "unbound_disable_rejected_without_state_change");
    g_unbound_disable_rejected = unbound_reason != nullptr
        && std::strcmp(unbound_reason, "unbound_source") == 0
        && source::state.load() == source::ready;

    // The following is the explicitly bounded fixture-only initialization
    // allowed by the source contract after the real startup guard rejects it.
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    source::identity = {kInstallation, actual_creation};
    source::creation = actual_creation;
    source::game = g_game;
    source::player = kPlayer;
    source::bound_thread = frame_thread;
    source::last_date = static_cast<std::int32_t>(kDate);
    source::state.store(source::ready, std::memory_order_release);
    check(source::drain.reset(source::identity).succeeded(),
          "fixture_transport_identity_initialized");
    check(source::identity.generation == actual_creation
              && source::identity.generation != 1u,
          "stream_generation_uses_process_creation");

    wchar_t log_path[MAX_PATH]{};
    check(swprintf(log_path, MAX_PATH, L"%ls\\battle-manager.jsonl",
                   g_fixture_directory.data())
              > 0,
          "fixture_log_path_built");
    std::memcpy(source::log_path, log_path, sizeof(log_path));
    check(source::writer.open(source::log_path, source::identity),
          "checked_log_opened");

    // A started-only receipt is an unknown outcome.  Retrying the same nonce
    // must not execute the command or mutate the manager state.
    const char unknown_nonce_literal[] =
        "77777777777777777777777777777777";
    wchar_t unknown_receipt[MAX_PATH]{};
    check(swprintf(unknown_receipt, MAX_PATH,
                   L"%ls\\information-battle-started-%hs.json",
                   source::directory, unknown_nonce_literal) > 0,
          "unknown_nonce_receipt_path_built");
    DeleteFileW(unknown_receipt);
    const char unknown_receipt_body[] =
        "{\"result\":\"started_outcome_requires_response\"}\n";
    check(source::write_json(unknown_receipt, unknown_receipt_body,
                             sizeof(unknown_receipt_body) - 1u,
                             CREATE_NEW),
          "unknown_nonce_started_receipt_created");
    source::state.store(source::enabled, std::memory_order_release);
    char unknown_command[512]{};
    check(command_line(unknown_command, unknown_nonce_literal, "disable",
                       actual_creation),
          "unknown_nonce_retry_command_built");
    char unknown_nonce[33]{}, unknown_verb[9]{};
    const char* unknown_reason = nullptr;
    check(!source::command(unknown_command, unknown_nonce, unknown_verb,
                           unknown_reason)
              && std::strcmp(unknown_reason,
                             "prior_outcome_unknown_no_retry") == 0
              && source::state.load() == source::enabled,
          "started_only_nonce_rejected_without_retry_mutation");
    g_unknown_nonce_rejected = unknown_reason != nullptr
        && std::strcmp(unknown_reason, "prior_outcome_unknown_no_retry") == 0
        && source::state.load() == source::enabled;

    check(source::install(), "actual_install_private_source");
    const bridge_entry_patch::PatchResult pending_retry =
        bridge_entry_patch::guarded_patch_retry_pending();
    check(pending_retry.pending_count == 0u,
          "patch_pending_retry_empty_after_install");
    check(source::patched && source::dll_pinned && source::table_registered
              && source::trampoline != nullptr && source::code_guard(),
          "install_pinned_unwind_patch_and_guard");
    check(source::publication_stage == 7u && source::last_patch_result.success
              && source::last_patch_result.threads_resumed
              && source::last_patch_result.protection_restored,
          "publication_stage_and_patch_receipt_complete");
    check(source::status("", "manager", true, "observed", false),
          "status_file_written_after_install");
    g_status_fields_observed = read_status_contract();
    check(g_status_fields_observed,
          "status_reports_nonatomic_stats_and_unverified_reload");
    source::transition(source::enabled);

    initialize_observed_objects();
    SetLastError(kInitialLastError);
    const std::uintptr_t first_return = call_source();
    check(first_return == kNativeReturn, "patched_source_returns_native_body");
    check(g_body_calls == 1u && source::accepted.load() == 1u
              && source::count == 1u && source::sequence.load() == 1u,
          "capture_accepts_one_owned_slot_body_once");
    check(GetLastError() == kInitialLastError,
          "stub_preserves_last_error_after_capture");
    check(*g_source_code == source::plan.patch[0],
          "entry_patch_remains_published_before_disable");

    char disable_command[512]{};
    check(command_line(disable_command,
                       "11111111111111111111111111111111", "disable",
                       actual_creation),
          "disable_command_built");
    char disable_nonce[33]{}, disable_verb[9]{};
    const char* disable_reason = nullptr;
    const bool disable_ok = source::command(disable_command, disable_nonce,
                                            disable_verb, disable_reason);
    check(disable_ok && std::strcmp(disable_reason, "capture_disabled_resources_retained") == 0
              && source::state.load() == source::disabled,
          "disable_changes_state_without_unpatching");
    wchar_t disable_receipt[MAX_PATH]{};
    check(swprintf(disable_receipt, MAX_PATH,
                   L"%ls\\information-battle-started-%hs.json",
                   source::directory,
                   "11111111111111111111111111111111") > 0
              && GetFileAttributesW(disable_receipt) != INVALID_FILE_ATTRIBUTES,
          "disable_nonce_has_durable_started_receipt");
    g_nonce_receipt_observed = GetFileAttributesW(disable_receipt)
        != INVALID_FILE_ATTRIBUTES;
    wchar_t disable_response[MAX_PATH]{};
    check(swprintf(disable_response, MAX_PATH,
                   L"%ls\\information-battle-response-%hs.json",
                   source::directory,
                   "11111111111111111111111111111111") > 0
              && source::status(disable_nonce, disable_verb, true,
                                disable_reason, true)
              && GetFileAttributesW(disable_receipt) != INVALID_FILE_ATTRIBUTES
              && GetFileAttributesW(disable_response) != INVALID_FILE_ATTRIBUTES,
          "successful_command_writes_separate_final_response");
    g_final_response_observed = GetFileAttributesW(disable_receipt)
        != INVALID_FILE_ATTRIBUTES
        && GetFileAttributesW(disable_response) != INVALID_FILE_ATTRIBUTES;
    char duplicate_command[512]{};
    check(command_line(duplicate_command,
                       "11111111111111111111111111111111", "disable",
                       actual_creation),
          "duplicate_command_built");
    char duplicate_nonce[33]{}, duplicate_verb[9]{};
    const char* duplicate_reason = nullptr;
    check(!source::command(duplicate_command, duplicate_nonce, duplicate_verb,
                           duplicate_reason)
              && std::strcmp(duplicate_reason, "duplicate_request") == 0,
          "duplicate_nonce_rejected_before_mutation");
    g_duplicate_request_observed = duplicate_reason != nullptr
        && std::strcmp(duplicate_reason, "duplicate_request") == 0;
    char wrong_player_command[512]{};
    check(command_line(wrong_player_command,
                       "44444444444444444444444444444444", "status",
                       actual_creation, kPlayer + 1u),
          "wrong_player_command_built");
    char wrong_player_nonce[33]{}, wrong_player_verb[9]{};
    const char* wrong_player_reason = nullptr;
    check(!source::command(wrong_player_command, wrong_player_nonce,
                           wrong_player_verb, wrong_player_reason)
              && std::strcmp(wrong_player_reason, "identity_mismatch") == 0,
          "wrong_player_binding_rejected");
    g_wrong_player_rejected = wrong_player_reason != nullptr
        && std::strcmp(wrong_player_reason, "identity_mismatch") == 0;
    check(source::patched && source::trampoline != nullptr
              && source::table_registered && *g_source_code == source::plan.patch[0],
          "disable_retains_published_resources_and_patch");

    source::flush();
    g_checked_log_written = log_file_nonempty();
    check(source::count == 0u && !source::has_pending
              && source::drain.stats().queued == 0u && encoded_has_expected_values(),
          "disabled_state_flushes_captured_record_to_checked_log");
    check(g_checked_log_written, "checked_log_file_has_persisted_bytes");
    print_encoded();

    // Resume is intentionally fixture-private: command enable must remain
    // rejected by the production fixed-EXE hash guard for this synthetic EXE.
    char enable_command[512]{};
    check(command_line(enable_command,
                       "22222222222222222222222222222222", "enable",
                       actual_creation),
          "enable_command_built");
    char enable_nonce[33]{}, enable_verb[9]{};
    const char* enable_reason = nullptr;
    const bool enable_ok = source::command(enable_command, enable_nonce,
                                           enable_verb, enable_reason);
    check(!enable_ok && std::strcmp(enable_reason, "source_guard") == 0
              && source::state.load() == source::disabled,
          "enable_rejects_fixture_hash_after_disable");
    source::transition(source::enabled);
    initialize_observed_objects();
    check(call_source() == kNativeReturn && g_body_calls == 2u
              && source::sequence.load() == 2u && source::accepted.load() == 2u,
          "fixture_resume_preserves_identity_and_sequence");

    const std::uint64_t accepted_before_source_copy_failure =
        source::accepted.load();
    const std::uint64_t copy_failures_before_source =
        source::copy_failed.load();
    const unsigned body_before_source_copy_failure = g_body_calls;
    initialize_observed_objects();
    write_u64(reinterpret_cast<unsigned char*>(g_result), 0u);
    check(call_source() == kNativeReturn
              && g_body_calls == body_before_source_copy_failure + 1u
              && source::copy_failed.load() == copy_failures_before_source + 1u
              && source::accepted.load() == accepted_before_source_copy_failure,
          "source_copy_failure_still_runs_native_body_once");
    initialize_observed_objects();

    HANDLE foreign = CreateThread(nullptr, 0, &foreign_capture_thread, nullptr,
                                  0, nullptr);
    check(foreign != nullptr && WaitForSingleObject(foreign, INFINITE) == WAIT_OBJECT_0,
          "foreign_thread_fixture_completed");
    if (foreign) CloseHandle(foreign);
    check(source::foreign_thread.load() == 1u && source::accepted.load() == 2u,
          "foreign_thread_dropped_without_capture");

    const std::uint64_t copy_failures_before = source::copy_failed.load();
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(0x10000u), 0, 0);
    check(source::copy_failed.load() == copy_failures_before + 1u
              && source::accepted.load() == 2u,
          "copy_failure_drops_slot_without_body_side_effect");

    // Fill the real eight-slot ring through the production callback, then
    // exercise the production full-ring branch and drain all accepted values.
    source::flush();
    const std::uint64_t accepted_before_fill = source::accepted.load();
    for (unsigned i = 0; i < source::kSlots; ++i) {
        initialize_observed_objects();
        information_battle_entry_capture(
            reinterpret_cast<void*>(kCombat),
            reinterpret_cast<void*>(g_summary),
            reinterpret_cast<void*>(g_result), 0, 0);
    }
    initialize_observed_objects();
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result), 0, 0);
    check(source::accepted.load() == accepted_before_fill + source::kSlots
              && source::full.load() >= 1u && source::count == source::kSlots,
          "full_ring_drops_without_overwriting_owned_slots");
    for (unsigned i = 0; i < source::kSlots + 1u; ++i) source::flush();
    check(source::count == 0u && source::drain.stats().queued == 0u,
          "full_ring_records_drain_after_disable_resume");

    const std::uint64_t accepted_before_change = source::accepted.load();
    write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
              static_cast<std::int32_t>(kDate - 1u));
    source::transition(source::enabled);
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result), 0, 0);
    g_date_regression_observed = source::state.load() == source::source_changed;
    g_source_changed_observed = source::state.load() == source::source_changed;
    check(g_source_changed_observed && g_date_regression_observed
              && source::accepted.load() == accepted_before_change
              && source::guard_failed.load() >= 1u,
          "date_regression_fails_closed_before_copy");
    write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
              static_cast<std::int32_t>(kDate));

    // A valid pending slot is retained while source_changed and only drains
    // after the manager is explicitly in the disabled state.  Resetting the
    // fixture after the intentional source_changed terminal state is private
    // setup; production keeps that terminal state latched.
    source::state.store(source::enabled, std::memory_order_release);
    initialize_observed_objects();
    const std::uint64_t accepted_before_pending = source::accepted.load();
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result), 0, 0);
    const unsigned pending_count = source::count;
    source::transition(source::source_changed);
    source::flush();
    g_source_changed_flush_preserved = source::count == pending_count
        && source::accepted.load() == accepted_before_pending + 1u;
    check(g_source_changed_flush_preserved,
          "source_changed_flush_stops_and_preserves_pending_slot");
    source::state.store(source::disabled, std::memory_order_release);
    source::flush();
    g_disabled_flush_drained = source::count == 0u && !source::has_pending;
    check(g_disabled_flush_drained,
          "disabled_flush_drains_preserved_pending_slot");

    source::transition(source::source_changed);
    char terminal_enable_command[512]{};
    check(command_line(terminal_enable_command,
                       "55555555555555555555555555555555", "enable",
                       actual_creation),
          "terminal_enable_command_built");
    char terminal_nonce[33]{}, terminal_verb[9]{};
    const char* terminal_reason = nullptr;
    check(!source::command(terminal_enable_command, terminal_nonce,
                           terminal_verb, terminal_reason)
              && std::strcmp(terminal_reason, "terminal_source_state") == 0,
          "source_changed_terminal_quarantine_rejects_enable");
    g_terminal_quarantine_observed = terminal_reason != nullptr
        && std::strcmp(terminal_reason, "terminal_source_state") == 0;
    char terminal_disable_command[512]{};
    check(command_line(terminal_disable_command,
                       "66666666666666666666666666666666", "disable",
                       actual_creation),
          "terminal_disable_command_built");
    char terminal_disable_nonce[33]{}, terminal_disable_verb[9]{};
    const char* terminal_disable_reason = nullptr;
    check(!source::command(terminal_disable_command, terminal_disable_nonce,
                           terminal_disable_verb, terminal_disable_reason)
              && std::strcmp(terminal_disable_reason,
                             "terminal_source_state") == 0
              && source::state.load() == source::source_changed,
          "terminal_disable_rejected_without_state_change");
    g_terminal_disable_rejected = terminal_disable_reason != nullptr
        && std::strcmp(terminal_disable_reason, "terminal_source_state") == 0
        && source::state.load() == source::source_changed;

    // Command parser/status is tested directly without writing a production
    // status file; the command still validates process, creation, DLL, and
    // installation identity using the include's real parser.
    source::state.store(source::disabled, std::memory_order_release);
    char status_command[512]{};
    check(command_line(status_command,
                       "33333333333333333333333333333333", "status",
                       actual_creation),
          "status_command_built");
    char status_nonce[33]{}, status_verb[9]{};
    const char* status_reason = nullptr;
    check(source::command(status_command, status_nonce, status_verb,
                          status_reason)
              && std::strcmp(status_reason, "observed") == 0,
          "status_command_identity_path");
    char malformed[] = "EU4BATTLE1 bad status\n";
    char malformed_nonce[33]{}, malformed_verb[9]{};
    const char* malformed_reason = nullptr;
    check(!source::command(malformed, malformed_nonce, malformed_verb,
                           malformed_reason)
              && std::strcmp(malformed_reason, "syntax") == 0,
          "command_parser_rejects_malformed_request");

    unsigned char rejected_payload[1] = {0x7au};
    check(source::drain.push(source::identity, rejected_payload,
                             sizeof(rejected_payload)).accepted(),
          "writer_rejection_record_queued");
    check(source::writer.close(), "checked_writer_closed_for_rejection");
    source::transition(source::enabled);
    source::flush();
    g_writer_rejection_fault = source::state.load() == source::fault
        && source::drain.has_pending();
    check(g_writer_rejection_fault,
          "drain_rejection_latches_fault_and_retains_pending_record");

    // The first terminal type is diagnostic state.  A later fault or source
    // change must not overwrite restart_required once it was published.
    source::state.store(source::enabled, std::memory_order_release);
    source::transition(source::restart_required);
    const bool restart_required_published =
        source::state.load(std::memory_order_acquire) == source::restart_required;
    source::transition(source::fault);
    source::transition(source::source_changed);
    g_terminal_latch_observed = restart_required_published
        && source::state.load(std::memory_order_acquire) == source::restart_required;
    check(g_terminal_latch_observed,
          "restart_required_terminal_latch_preserves_first_failure");

    // Sequence exhaustion can only fault an enabled stream through the CAS;
    // it must not change an already-terminal state or wrap the sequence.
    source::state.store(source::enabled, std::memory_order_release);
    source::sequence.store(UINT64_MAX, std::memory_order_release);
    information_battle_entry_capture(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result), 0, 0);
    g_sequence_exhaustion_fault =
        source::state.load(std::memory_order_acquire) == source::fault
        && source::sequence.load(std::memory_order_acquire) == UINT64_MAX;
    check(g_sequence_exhaustion_fault,
          "sequence_exhaustion_faults_enabled_stream_without_wrap");

    const auto log_stats = source::drain.stats();
    check(log_stats.identity == source::identity && g_checked_log_written,
          "transport_identity_remains_stable");
    check(g_body_calls == 3u,
          "direct_capture_paths_do_not_call_native_body");
    std::printf("LOG_PATH %ls\n", source::log_path);

    std::printf(
        "RESULT %s\n{\"passed\":%s,\"startup_hash_guard_rejected\":%s,"
        "\"install_success\":%s,\"patched\":%s,\"dll_pinned\":%s,"
        "\"unwind_registered\":%s,\"disable_retained_patch\":%s,"
        "\"resume_sequence\":%llu,\"accepted\":%llu,\"full_drops\":%llu,"
        "\"foreign_thread_drops\":%llu,\"copy_failures\":%llu,"
        "\"source_changed\":%s,\"date_regression\":%s,"
        "\"source_changed_flush_preserved\":%s,"
        "\"disabled_flush_drained\":%s,"
        "\"terminal_quarantine\":%s,\"terminal_disable_rejected\":%s,"
        "\"nonce_receipt\":%s,\"final_response\":%s,"
        "\"unbound_disable_rejected\":%s,\"unknown_nonce_rejected\":%s,"
        "\"duplicate_request\":%s,\"startup_leases_closed\":%s,"
        "\"wrong_player_rejected\":%s,\"status_fields\":%s,"
        "\"terminal_latch\":%s,\"sequence_exhaustion_fault\":%s,"
        "\"writer_rejection_fault\":%s,"
        "\"native_body_calls\":%u,\"checked_log_written\":%s,"
        "\"wire_bytes\":%zu,"
        "\"production_modified\":false,\"game_access\":false,"
        "\"fixture_private_initialization\":true}\n",
        g_failures == 0u ? "PASS" : "FAIL", g_failures == 0u ? "true" : "false",
        g_startup_hash_guard_rejected ? "true" : "false",
        source::patched ? "true" : "false", source::patched ? "true" : "false",
        source::dll_pinned ? "true" : "false", source::table_registered ? "true" : "false",
        source::patched && source::trampoline != nullptr ? "true" : "false",
        static_cast<unsigned long long>(source::sequence.load()),
        static_cast<unsigned long long>(source::accepted.load()),
        static_cast<unsigned long long>(source::full.load()),
        static_cast<unsigned long long>(source::foreign_thread.load()),
        static_cast<unsigned long long>(source::copy_failed.load()),
        g_source_changed_observed ? "true" : "false",
        g_date_regression_observed ? "true" : "false",
        g_source_changed_flush_preserved ? "true" : "false",
        g_disabled_flush_drained ? "true" : "false",
        g_terminal_quarantine_observed ? "true" : "false",
        g_terminal_disable_rejected ? "true" : "false",
        g_nonce_receipt_observed ? "true" : "false",
        g_final_response_observed ? "true" : "false",
        g_unbound_disable_rejected ? "true" : "false",
        g_unknown_nonce_rejected ? "true" : "false",
        g_duplicate_request_observed ? "true" : "false",
        g_startup_leases_closed ? "true" : "false",
        g_wrong_player_rejected ? "true" : "false",
        g_status_fields_observed ? "true" : "false",
        g_terminal_latch_observed ? "true" : "false",
        g_sequence_exhaustion_fault ? "true" : "false",
        g_writer_rejection_fault ? "true" : "false",
        g_body_calls, g_checked_log_written ? "true" : "false",
        source::encoded_bytes);
    return g_failures == 0u ? 0 : 1;
}
