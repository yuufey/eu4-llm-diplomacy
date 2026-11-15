#define INFORMATION_BATTLE_CONTAINER 1
#define INFORMATION_BATTLE_SCOPE_TEST_MAIN legacy_template_scope_fixture_main
#include "information-battle-message-scope-test.cpp"
#undef INFORMATION_BATTLE_SCOPE_TEST_MAIN

// This fixture reuses the private 40 MiB context/message fixture above.  It
// drives the real cleanup-entry patch and production container capture seam;
// all objects, code, and original bodies remain inside this process-owned
// synthetic image.

namespace {

constexpr std::size_t kCleanupContinuationOffset = 0x1af750u;
constexpr std::uintptr_t kLandCleanupReturnRva = 0x236736u;
constexpr std::uintptr_t kNavalCleanupReturnRva = 0x232a28u;
constexpr std::uintptr_t kUnknownCleanupReturnRva = 0x236720u;
constexpr std::size_t kLandContainerOffset = 0x60u;
constexpr std::size_t kNavalContainerOffset = 0x68u;
constexpr std::uint32_t kContainerRawWord = 0x10203040u;
constexpr unsigned char kContainerRawFlag = 0x91u;

std::uintptr_t g_land_container = 0u;
std::uintptr_t g_naval_container = 0u;
std::uintptr_t g_current_container = 0u;
std::uintptr_t g_observed_container = 0u;
unsigned g_container_original_calls = 0u;
bool g_message_first = false;
bool g_double_cleanup = false;
bool g_change_date_before_cleanup = false;
bool g_invalid_head = false;
bool g_wrong_container = false;

std::uintptr_t container_for(MessageSite site) noexcept {
    return site == MessageSite::land ? g_land_container : g_naval_container;
}

std::uintptr_t cleanup_return_for(MessageSite site) noexcept {
    return site == MessageSite::land ? kLandCleanupReturnRva
                                     : kNavalCleanupReturnRva;
}

std::size_t wrapper_offset_for(MessageSite site) noexcept {
    return site == MessageSite::land ? kLandMessageWrapperOffset
                                     : kNavalMessageWrapperOffset;
}

void write_container_header(MessageSite site, bool invalid_head = false) noexcept {
    g_current_container = container_for(site);
    unsigned char* container = reinterpret_cast<unsigned char*>(
        g_current_container);
    std::memset(container, 0, 0x18u);
    write_u64(container + 0x00u, invalid_head ? UINT64_C(0x1234)
                                              : g_message_node_a);
    write_u64(container + 0x08u, invalid_head ? 0u : g_message_node_b);
    write_u32(container + 0x10u, kContainerRawWord);
    container[0x14u] = kContainerRawFlag;
}

void initialize_container_addresses() noexcept {
    g_land_container = g_land_formatter_frame - kLandContainerOffset;
    g_naval_container = g_naval_formatter_frame - kNavalContainerOffset;
    write_container_header(MessageSite::land);
    write_container_header(MessageSite::naval);
}

extern "C" void fixture_cleanup_original(void* container) noexcept {
    ++g_container_original_calls;
    g_observed_container = reinterpret_cast<std::uintptr_t>(container);
    unsigned char* bytes = reinterpret_cast<unsigned char*>(container);
    // The native cleanup body destroys the temporary list before returning.
    // Keep the raw lanes untouched so the capture contract can be checked
    // against the bytes observed before this continuation runs.
    write_u64(bytes + 0x00u, 0u);
    write_u64(bytes + 0x08u, 0u);
}

void build_cleanup_original_body() noexcept {
    unsigned char* destination = g_region + kCleanupContinuationOffset;
    std::memset(destination, 0x90, 0x40u);
    std::size_t cursor = 0u;
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xb8u;                 // mov rax, original
    append_u64(destination, cursor,
               reinterpret_cast<std::uintptr_t>(&fixture_cleanup_original));
    destination[cursor++] = 0xffu;
    destination[cursor++] = 0xd0u;                 // call rax
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0x8bu;
    destination[cursor++] = 0x5cu;
    destination[cursor++] = 0x24u;
    destination[cursor++] = 0x38u;                 // mov rbx,[rsp+38h]
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0x83u;
    destination[cursor++] = 0xc4u;
    destination[cursor++] = 0x20u;                 // add rsp,20h
    destination[cursor++] = 0x5eu;                 // pop rsi
    destination[cursor++] = 0xc3u;                 // ret
    check(cursor <= 0x40u, "cleanup_original_body_bounded");
}

bool make_wrapper_writable(MessageSite site) noexcept {
    const std::uintptr_t page =
        (base + wrapper_offset_for(site)) & ~UINT64_C(0xfff);
    DWORD old = 0u;
    return VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                          PAGE_READWRITE, &old) != FALSE;
}

bool protect_wrapper_page(MessageSite site, const char* check_name) noexcept {
    const std::uintptr_t page =
        (base + wrapper_offset_for(site)) & ~UINT64_C(0xfff);
    DWORD old = 0u;
    const bool protected_page = VirtualProtect(
        reinterpret_cast<void*>(page), 0x1000u, PAGE_EXECUTE_READ, &old)
        != FALSE;
    check(protected_page, check_name);
    const bool flushed = FlushInstructionCache(
        GetCurrentProcess(), reinterpret_cast<void*>(page), 0x1000u) != FALSE;
    check(flushed, "cleanup_wrapper_icache_flush");
    return protected_page && flushed;
}

bool build_cleanup_call_site(MessageSite site,
                             std::uintptr_t return_rva) noexcept {
    if (!make_wrapper_writable(site)) return false;
    unsigned char* destination = g_region + wrapper_offset_for(site);
    std::memset(destination, 0x90, 0x100u);
    const std::uintptr_t formatter_frame = formatter_frame_for(site);
    std::size_t cursor = 0u;
    destination[cursor++] = 0x55u;                 // push rbp
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xbdu;                 // mov rbp, frame
    append_u64(destination, cursor, formatter_frame);
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0x83u;
    destination[cursor++] = 0xecu;
    destination[cursor++] = 0x20u;                 // sub rsp,20h
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xb8u;                 // mov rax, cleanup entry
    append_u64(destination, cursor, base + 0x1af740u);
    const std::size_t call_offset = static_cast<std::size_t>(return_rva - 2u)
        - wrapper_offset_for(site);
    check(cursor < call_offset, "cleanup_wrapper_call_offset_ordered");
    while (cursor < call_offset) destination[cursor++] = 0x90u;
    destination[cursor++] = 0xffu;                 // call rax
    destination[cursor++] = 0xd0u;
    const unsigned char epilogue[] = {
        0x48u, 0x83u, 0xc4u, 0x20u, 0x5du, 0xc3u,
    };
    std::memcpy(destination + cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    check(base + wrapper_offset_for(site) + call_offset + 2u
              == base + return_rva,
          "cleanup_wrapper_exact_return_pc");
    check(cursor <= 0x100u, "cleanup_wrapper_bounded");
    return protect_wrapper_page(site, "cleanup_wrapper_rx");
}

bool prepare_cleanup_site(MessageSite site, bool unrelated = false) noexcept {
    return build_cleanup_call_site(
        site, unrelated ? kUnknownCleanupReturnRva
                        : cleanup_return_for(site));
}

bool prepare_message_site(MessageSite site) noexcept {
    if (!make_wrapper_writable(site)) return false;
    build_message_call_site(wrapper_offset_for(site),
                            site == MessageSite::land ? kLandReturnRva
                                                      : kNavalReturnRva);
    return true;
}

void call_cleanup_site(MessageSite site, bool wrong_container = false) noexcept {
    const MessageCaller target = reinterpret_cast<MessageCaller>(
        g_region + wrapper_offset_for(site));
    const std::uintptr_t argument = wrong_container
        ? g_message : container_for(site);
    target(reinterpret_cast<void*>(argument), nullptr, nullptr, nullptr);
}

void reset_container_case(std::uint32_t selector = 1u,
                          std::int32_t message_date =
                              static_cast<std::int32_t>(kDate)) noexcept {
    g_message_first = false;
    g_double_cleanup = false;
    g_change_date_before_cleanup = false;
    g_invalid_head = false;
    g_wrong_container = false;
    reset_case(selector, message_date);
    initialize_container_addresses();
    write_container_header(g_current_site);
}

extern "C" void fixture_container_router_original(
    void* combat, unsigned char direction) noexcept {
    ++g_router_original_calls;
    g_last_direction = direction;
    const DWORD before = GetLastError();
    information_battle_entry_capture(
        combat, reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);

    if (g_message_first) {
        if (prepare_message_site(g_current_site)) {
            call_message_site(g_current_site);
            // The two native calls occupy the same private RX page.  Restore
            // the cleanup call after the message has returned.
            (void)prepare_cleanup_site(g_current_site);
        }
    }
    if (g_change_date_before_cleanup) {
        write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
                  static_cast<std::int32_t>(kDate + 1u));
    }
    call_cleanup_site(g_current_site, g_wrong_container);
    if (g_double_cleanup) {
        write_container_header(g_current_site);
        call_cleanup_site(g_current_site);
    }
    if (g_change_date_before_cleanup) {
        write_i32(reinterpret_cast<unsigned char*>(g_game) + 0x1dd0u,
                  static_cast<std::int32_t>(kDate));
    }
    SetLastError(before);
}

void check_router_case(const char* frame_prefix, MessageSite site,
                       bool expect_template, unsigned expected_original_delta,
                       unsigned expected_candidates_delta = 1u) noexcept {
    const unsigned router_before = g_router_original_calls;
    const unsigned original_before = g_container_original_calls;
    const auto candidate_before = source::container_candidates.load();
    const DWORD before = kInitialLastError;
    SetLastError(before);
    information_battle_router_hook(reinterpret_cast<void*>(g_combat),
                                   site == MessageSite::land ? 7u : 9u);
    check(g_router_original_calls == router_before + 1u,
          "container_router_original_once");
    check(g_container_original_calls == original_before
              + expected_original_delta,
          "container_cleanup_original_expected_count");
    check(g_observed_container == (g_wrong_container
              ? g_message : container_for(site)),
          "container_cleanup_original_observed_argument");
    check(source::container_candidates.load() == candidate_before
              + expected_candidates_delta,
          "container_candidate_counter_expected");
    check(source::scope_depth == 0u && source::count == 1u,
          "container_scope_committed_base_record");
    check(GetLastError() == before
              && g_last_direction == (site == MessageSite::land ? 7u : 9u),
          "container_router_preserves_last_error_and_direction");
    if (!g_wrong_container && !g_invalid_head) {
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(
            container_for(site));
        std::uint64_t head = 1u, tail = 1u;
        std::memcpy(&head, bytes + 0x00u, sizeof(head));
        std::memcpy(&tail, bytes + 0x08u, sizeof(tail));
        check(head == 0u && tail == 0u,
              "container_cleanup_body_clears_head_and_tail");
    }
    check(drain_frames(frame_prefix) == 1u,
          expect_template ? "container_template_one_frame"
                           : "container_rejected_one_base_frame");
}

void test_valid_land_and_naval() noexcept {
    reset_container_case(1u);
    check(prepare_cleanup_site(MessageSite::land),
          "land_cleanup_site_prepared");
    check_router_case("land_container", MessageSite::land, true, 1u);

    reset_container_case(2u);
    check(prepare_cleanup_site(MessageSite::naval),
          "naval_cleanup_site_prepared");
    check_router_case("naval_container", MessageSite::naval, true, 1u);
}

void test_wrong_owner() noexcept {
    reset_container_case(1u);
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1b8u,
              g_result);
    check(prepare_cleanup_site(MessageSite::land),
          "wrong_owner_cleanup_site_prepared");
    check_router_case("wrong_owner", MessageSite::land, false, 1u);
    initialize_formatter_frames();
}

void test_wrong_formatter_caller() noexcept {
    reset_container_case(1u);
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1d8u,
              base + kNavalFormatterCallerRva);
    check(prepare_cleanup_site(MessageSite::land),
          "wrong_caller_cleanup_site_prepared");
    check_router_case("wrong_formatter_caller", MessageSite::land, false, 1u);
    initialize_formatter_frames();
}

void test_wrong_container_address() noexcept {
    reset_container_case(1u);
    g_wrong_container = true;
    check(prepare_cleanup_site(MessageSite::land),
          "wrong_container_cleanup_site_prepared");
    check_router_case("wrong_container", MessageSite::land, false, 1u);
}

void test_date_change() noexcept {
    reset_container_case(1u);
    g_change_date_before_cleanup = true;
    check(prepare_cleanup_site(MessageSite::land),
          "date_change_cleanup_site_prepared");
    check_router_case("date_changed", MessageSite::land, false, 1u);
}

void test_invalid_head() noexcept {
    reset_container_case(1u);
    g_invalid_head = true;
    write_container_header(g_current_site, true);
    check(prepare_cleanup_site(MessageSite::land),
          "invalid_head_cleanup_site_prepared");
    check_router_case("invalid_head", MessageSite::land, false, 1u);
}

void test_double_cleanup() noexcept {
    reset_container_case(1u);
    g_double_cleanup = true;
    check(prepare_cleanup_site(MessageSite::land),
          "double_cleanup_site_prepared");
    const unsigned original_before = g_container_original_calls;
    information_battle_router_hook(reinterpret_cast<void*>(g_combat), 7u);
    check(g_container_original_calls == original_before + 2u,
          "double_cleanup_original_runs_twice");
    check(source::scope_depth == 0u && source::count == 1u,
          "double_cleanup_scope_committed_base_record");
    check(drain_frames("double_cleanup") == 1u,
          "double_cleanup_keeps_one_base_frame");
}

void test_message_priority() noexcept {
    reset_container_case(1u);
    g_message_first = true;
    check(prepare_cleanup_site(MessageSite::land),
          "message_priority_cleanup_site_prepared");
    const unsigned message_before = g_message_original_calls;
    const unsigned container_before = g_container_original_calls;
    information_battle_router_hook(reinterpret_cast<void*>(g_combat), 7u);
    check(g_message_original_calls == message_before + 1u,
          "message_priority_original_runs_once");
    check(g_container_original_calls == container_before + 1u,
          "message_priority_cleanup_original_runs_once");
    check(source::scope_depth == 0u && source::count == 1u,
          "message_priority_scope_committed_base_record");
    check(drain_frames("message_priority") == 1u,
          "message_priority_keeps_one_message_frame");
}

void test_missing_scope_and_unrelated() noexcept {
    reset_container_case(1u);
    check(prepare_cleanup_site(MessageSite::land),
          "missing_scope_cleanup_site_prepared");
    const unsigned original_before = g_container_original_calls;
    const auto candidate_before = source::container_candidates.load();
    call_cleanup_site(MessageSite::land);
    check(g_container_original_calls == original_before + 1u,
          "missing_scope_original_runs_once");
    check(source::container_candidates.load() == candidate_before + 1u,
          "missing_scope_candidate_observed");
    check(source::count == 0u && !source::has_pending,
          "missing_scope_emits_no_frame");

    write_container_header(MessageSite::land);
    check(build_cleanup_call_site(MessageSite::land,
                                  kUnknownCleanupReturnRva),
          "unrelated_cleanup_site_prepared");
    const unsigned unrelated_before = g_container_original_calls;
    const auto unrelated_candidates = source::container_candidates.load();
    call_cleanup_site(MessageSite::land);
    check(g_container_original_calls == unrelated_before + 1u,
          "unrelated_cleanup_original_runs_once");
    check(source::container_candidates.load() == unrelated_candidates,
          "unknown_cleanup_return_early_no_candidate");
    check(source::count == 0u && !source::has_pending,
          "unrelated_cleanup_emits_no_frame");
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-container-scope-manager\n");
    (void)&legacy_template_scope_fixture_main;
    (void)&bridge_entry_patch::guarded_patch_rollback;
    (void)&information_battle_tick;
    if (!prepare_manager(&build_cleanup_original_body)) {
        std::printf("RESULT FAIL prepare_manager\n");
        return 1;
    }
    information_battle_router_original = reinterpret_cast<void*>(
        &fixture_container_router_original);
    test_valid_land_and_naval();
    test_wrong_owner();
    test_wrong_formatter_caller();
    test_wrong_container_address();
    test_date_change();
    test_invalid_head();
    test_double_cleanup();
    test_message_priority();
    test_missing_scope_and_unrelated();
    const bool passed = g_failures == 0u;
    std::printf(
        "RESULT %s\n{\"passed\":%s,\"router_original_calls\":%u,"
        "\"message_original_calls\":%u,\"container_original_calls\":%u,"
        "\"container_candidates\":%llu,\"container_copied\":%llu,"
        "\"container_copy_failures\":%llu,\"template_copied\":%llu,"
        "\"template_copy_failures\":%llu,\"template_ambiguous\":%llu,"
        "\"scope_overflow\":%llu,\"production_modified\":false,"
        "\"game_access\":false,\"rea_access\":false,"
        "\"network_access\":false,\"full_dll_build\":false,"
        "\"native_game_function_invoked\":false,"
        "\"fixture_private_initialization\":true}\n",
        passed ? "PASS" : "FAIL", passed ? "true" : "false",
        g_router_original_calls, g_message_original_calls,
        g_container_original_calls,
        static_cast<unsigned long long>(source::container_candidates.load()),
        static_cast<unsigned long long>(source::container_copied.load()),
        static_cast<unsigned long long>(source::container_copy_failed.load()),
        static_cast<unsigned long long>(source::template_copied.load()),
        static_cast<unsigned long long>(source::template_copy_failed.load()),
        static_cast<unsigned long long>(source::template_ambiguous.load()),
        static_cast<unsigned long long>(source::scope_overflow.load()));
    return passed ? 0 : 1;
}
