#define INFORMATION_BATTLE_TEMPLATE 1
#define INFORMATION_BATTLE_NAVAL 1
#define main legacy_context_fixture_main
#include "test-information-battle-observer-context.cpp"
#undef main

// This TU intentionally reuses the closed private 40 MiB fixture above.  The
// test below exercises the real template-enabled observer manager and its two
// typed production wrappers; it never installs into EU4 or calls a game body.

namespace {

namespace template_owned = information::battle::owned_template;

constexpr std::size_t kMessageOffset = 0x190000u;
constexpr std::size_t kMessageNodeAOffset = 0x191000u;
constexpr std::size_t kMessageNodeBOffset = 0x192000u;
constexpr std::size_t kMessageManagerOffset = 0x193000u;
constexpr std::size_t kLandMessageWrapperOffset = 0x2366e0u;
constexpr std::size_t kNavalMessageWrapperOffset = 0x2329b0u;
// The production message stub passes the formatter's original RBP to the
// capture seam.  These two private pages stand in for the formatter frames:
// their saved caller-RDI and caller-PC fields are populated exactly where the
// native prologue would have left them.  They remain inside the private image
// so the production code-address guard is exercised as well.
constexpr std::size_t kLandFormatterFrameOffset = 0x2700000u;
constexpr std::size_t kNavalFormatterFrameOffset = 0x2710000u;
constexpr std::uintptr_t kLandReturnRva = 0x236721u;
constexpr std::uintptr_t kNavalReturnRva = 0x232a13u;
constexpr std::uintptr_t kLandFormatterCallerRva = 0x23a446u;
constexpr std::uintptr_t kNavalFormatterCallerRva = 0x23a42au;
constexpr std::uintptr_t kKnownRouterReturnRva = 0x23a40du;
constexpr std::uintptr_t kMessageCallbackRva = 0x2ec0a0u;

using MessageCaller = void (*)(void*, void*, void*, void*);

enum class MessageSite : unsigned { land, naval };

std::uintptr_t g_message = 0;
std::uintptr_t g_message_node_a = 0;
std::uintptr_t g_message_node_b = 0;
std::uintptr_t g_message_manager = 0;
std::uintptr_t g_current_message = 0;
std::uintptr_t g_land_formatter_frame = 0;
std::uintptr_t g_naval_formatter_frame = 0;
MessageSite g_current_site = MessageSite::land;
unsigned g_router_original_calls = 0;
unsigned g_message_original_calls = 0;
std::uintptr_t g_observed_message_return_pc = 0;
unsigned g_deferred_base_seen = 0;
unsigned g_deferred_message_seen = 0;
unsigned char g_last_direction = 0;

void write_u32(unsigned char* destination, std::uint32_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void set_message_node(std::uintptr_t node_address, std::uintptr_t next,
                      const char* key, const char* value) noexcept {
    unsigned char* node = reinterpret_cast<unsigned char*>(node_address);
    std::memset(node, 0, template_owned::kNodeBytes);
    set_inline_string(node + template_owned::kKeyOffset, key, std::strlen(key));
    set_inline_string(node + template_owned::kValueOffset, value, std::strlen(value));
    write_u64(node + template_owned::kNodeNextOffset, next);
}

void set_template_message(std::int32_t date = static_cast<std::int32_t>(kDate),
                          const char* first_key = "KEY_ONE",
                          const char* first_value = "VALUE_ONE",
                          const char* second_key = "KEY_TWO",
                          const char* second_value = "VALUE_TWO") noexcept {
    unsigned char* message = reinterpret_cast<unsigned char*>(g_message);
    std::memset(message, 0, template_owned::kMessageHeaderBytes);
    write_u64(message + template_owned::kContainerHeadOffset, g_message_node_a);
    write_u64(message + template_owned::kContainerTailOffset, g_message_node_b);
    write_u32(message + template_owned::kContainerRawWord20Offset, 0xa1b2c3d4u);
    message[template_owned::kContainerRawFlag24Offset] = 0x5au;
    set_inline_string(message + template_owned::kAuxiliaryTextOffset, "AUX", 3u);
    write_i32(message + template_owned::kNativeDateOffset, date);
    message[template_owned::kRawFlag8COffset] = 0x11u;
    message[template_owned::kRawFlag8DOffset] = 0x22u;
    set_message_node(g_message_node_a, g_message_node_b,
                     first_key, first_value);
    set_message_node(g_message_node_b, 0u, second_key, second_value);
}

std::uintptr_t formatter_frame_for(MessageSite site) noexcept {
    return site == MessageSite::land ? g_land_formatter_frame
                                     : g_naval_formatter_frame;
}

void initialize_formatter_frames() noexcept {
    g_land_formatter_frame = base + kLandFormatterFrameOffset;
    g_naval_formatter_frame = base + kNavalFormatterFrameOffset;
    std::memset(reinterpret_cast<void*>(g_land_formatter_frame), 0, 0x200u);
    std::memset(reinterpret_cast<void*>(g_naval_formatter_frame), 0, 0x200u);
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1b8u,
              g_combat);
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1d8u,
              base + kLandFormatterCallerRva);
    write_u64(reinterpret_cast<unsigned char*>(g_naval_formatter_frame) + 0x178u,
              g_combat);
    write_u64(reinterpret_cast<unsigned char*>(g_naval_formatter_frame) + 0x198u,
              base + kNavalFormatterCallerRva);
}

void build_message_call_site(std::size_t wrapper_offset,
                             std::uintptr_t return_rva) noexcept {
    unsigned char* destination = g_region + wrapper_offset;
    std::memset(destination, 0x90, 0x100u);
    const bool land = return_rva == kLandReturnRva;
    const std::uintptr_t formatter_frame = land ? g_land_formatter_frame
                                                : g_naval_formatter_frame;
    std::size_t cursor = 0u;
    const unsigned char prologue[] = {
        0x55u,                                      // save caller's RBP
        0x48u, 0xbdu,                               // mov rbp, fake frame
    };
    std::memcpy(destination + cursor, prologue, sizeof(prologue));
    cursor += sizeof(prologue);
    std::memcpy(destination + cursor, &formatter_frame,
                sizeof(formatter_frame));
    cursor += sizeof(formatter_frame);
    const unsigned char shadow_space[] = {
        0x48u, 0x83u, 0xecu, 0x20u,                // Win64 shadow space
        0x48u, 0xb8u,
    };
    std::memcpy(destination + cursor, shadow_space, sizeof(shadow_space));
    cursor += sizeof(shadow_space);
    const std::uintptr_t hook = reinterpret_cast<std::uintptr_t>(
        &information_battle_message_hook);
    std::memcpy(destination + cursor, &hook, sizeof(hook));
    cursor += sizeof(hook);
    // The production guard compares the return PC after the two-byte
    // `call rax`, so the synthetic call instruction begins two bytes earlier.
    const std::uintptr_t call_rva = return_rva - 2u;
    const std::size_t call_offset = static_cast<std::size_t>(call_rva)
        - wrapper_offset;
    check(cursor < call_offset, "message_wrapper_call_offset_ordered");
    while (cursor < call_offset) destination[cursor++] = 0x90u;
    destination[cursor++] = 0xffu;  // call rax; two-byte return address
    destination[cursor++] = 0xd0u;
    const unsigned char epilogue[] = {
        0x48u, 0x83u, 0xc4u, 0x20u,
        0x5du,                                      // restore caller's RBP
        0xc3u,
    };
    std::memcpy(destination + cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    check(base + wrapper_offset + call_offset + 2u == base + return_rva,
          "message_wrapper_exact_return_pc");
    check(cursor <= 0x100u, "message_wrapper_bounded");
    DWORD old = 0;
    const std::uintptr_t page = (base + wrapper_offset) & ~UINT64_C(0xfff);
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_EXECUTE_READ, &old) != FALSE,
          "message_wrapper_rx");
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(page), 0x1000u)
              != FALSE,
          "message_wrapper_icache_flush");
}

void build_message_call_sites() noexcept {
    build_message_call_site(kLandMessageWrapperOffset, kLandReturnRva);
    build_message_call_site(kNavalMessageWrapperOffset, kNavalReturnRva);
}

void initialize_message_entry_bytes() noexcept {
    for (unsigned index = 0u; index != source::kMessageEntryCount; ++index) {
        const auto kind = static_cast<information::battle::message_entry::EntryKind>(
            index);
        const auto& spec = information::battle::message_entry::spec(kind);
        std::memcpy(g_region + spec.rva, spec.prefix.data(), spec.prefix_bytes);
        std::memcpy(g_region + spec.unwind_rva, spec.unwind_expected.data(),
                    spec.unwind_bytes);
    }
}

void protect_message_entry_pages() noexcept {
    // The router entry shares the page that the legacy context fixture writes
    // for its private caller wrappers; build_caller_wrappers() makes that
    // page executable after its bytes are complete.  The message entry lives
    // on a separate page and is protected here.
    for (unsigned index = 1u; index != source::kMessageEntryCount; ++index) {
        const auto kind = static_cast<information::battle::message_entry::EntryKind>(
            index);
        const auto& spec = information::battle::message_entry::spec(kind);
        const std::uintptr_t page = (base + spec.rva) & ~UINT64_C(0xfff);
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                             PAGE_EXECUTE_READ, &old) != FALSE,
              "message_entry_fixture_rx");
        check(FlushInstructionCache(GetCurrentProcess(),
                                    reinterpret_cast<void*>(page), 0x1000u)
                  != FALSE,
              "message_entry_fixture_icache_flush");
    }
}

void call_message_site(MessageSite site) noexcept {
    const std::size_t offset = site == MessageSite::land
        ? kLandMessageWrapperOffset : kNavalMessageWrapperOffset;
    const MessageCaller target = reinterpret_cast<MessageCaller>(
        g_region + offset);
    target(reinterpret_cast<void*>(g_message_manager),
           reinterpret_cast<void*>(g_current_message), nullptr,
           reinterpret_cast<void*>(base + kMessageCallbackRva));
}

extern "C" void fixture_message_original(void*, void*, void*, void*) noexcept {
    ++g_message_original_calls;
    g_observed_message_return_pc = reinterpret_cast<std::uintptr_t>(
        __builtin_return_address(0));
    // The typed original is self-owned and deliberately preserves the caller's
    // last-error value so the production wrapper's observable contract can be
    // checked without introducing a second native operation.
    const DWORD before = GetLastError();
    SetLastError(before);
}

extern "C" void fixture_router_original(void* combat,
                                         unsigned char direction) noexcept {
    ++g_router_original_calls;
    g_last_direction = direction;
    const DWORD before = GetLastError();
    information_battle_entry_capture(
        combat, reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    const auto& active_scope = source::scopes[source::scope_depth - 1u];
    g_deferred_base_seen = source::scope_depth == 1u
        && active_scope.has_record
        && active_scope.slot < source::kSlots
        && !source::slot_ready[active_scope.slot]
        ? 1u : 0u;
    call_message_site(g_current_site);
    g_deferred_message_seen = source::scope_depth == 1u
        && active_scope.message_seen
        && active_scope.slot < source::kSlots
        && !source::slot_ready[active_scope.slot]
        && source::slots[active_scope.slot].template_present
        ? 1u : 0u;
    SetLastError(before);
}

void reset_case(std::uint32_t selector = 1u,
                std::int32_t message_date = static_cast<std::int32_t>(kDate)) noexcept {
    initialize_observed_objects();
    initialize_context_objects(selector, true);
    initialize_formatter_frames();
    set_template_message(message_date);
    g_current_message = g_message;
    g_current_site = selector == 2u ? MessageSite::naval : MessageSite::land;
    source::encoded_bytes = 0u;
    source::fragment_index = 0u;
}

unsigned drain_frames(const char* prefix) noexcept {
    unsigned frame_index = 0u;
    while ((source::count != 0u || source::has_pending) && frame_index < 16u) {
        source::encoded_bytes = 0u;
        source::flush();
        if (source::encoded_bytes == 0u) {
            check(false, "template_frame_written");
            break;
        }
        char name[96]{};
        if (snprintf(name, sizeof(name), "%s_%u", prefix, frame_index)
                <= 0) {
            check(false, "template_frame_name_built");
            break;
        }
        std::printf("FRAME_HEX %s ", name);
        for (std::size_t index = 0u; index < source::encoded_bytes; ++index)
            std::printf("%02x", static_cast<unsigned>(source::encoded[index]));
        std::printf("\n");
        ++frame_index;
    }
    check(frame_index < 16u, "template_frame_drain_bounded");
    return frame_index;
}

bool prepare_manager(void (*extra_body)() noexcept = nullptr) noexcept {
    self_module = GetModuleHandleW(nullptr);
    std::uint64_t creation = 0u;
    if (!self_module || !process_creation(creation)
            || !make_directory_and_paths()) {
        return false;
    }
    g_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kRegionBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_region) return false;
    base = reinterpret_cast<std::uintptr_t>(g_region);
    g_source_code = g_region + source::kEntryRva;
    initialize_context();
    initialize_observed_objects();
    initialize_context_objects();
    initialize_formatter_frames();
    build_source_body(g_source_code);
    initialize_message_entry_bytes();
    if (extra_body != nullptr) extra_body();
    protect_message_entry_pages();
    build_caller_wrappers();
    std::memset(g_region + source::kUnwindRva, 0,
                entry::kOriginalUnwind.size());
    std::memcpy(g_region + source::kUnwindRva, entry::kOriginalUnwind.data(),
                entry::kOriginalUnwind.size());
    if (!protect_source()) return false;
    g_message = reinterpret_cast<std::uintptr_t>(g_region + kMessageOffset);
    g_message_node_a = reinterpret_cast<std::uintptr_t>(
        g_region + kMessageNodeAOffset);
    g_message_node_b = reinterpret_cast<std::uintptr_t>(
        g_region + kMessageNodeBOffset);
    g_message_manager = reinterpret_cast<std::uintptr_t>(
        g_region + kMessageManagerOffset);
    build_message_call_sites();
    set_template_message();

    // Keep the real startup guard in the fixture: it must reject this private
    // executable.  The following binding is fixture-only, as in the context
    // manager test, and does not claim a live installation.
    const bool startup = information_battle_start(
        g_fixture_directory.data(), creation);
    check(!startup && source::state.load() == source::fault,
          "template_fixture_startup_hash_guard_rejects_private_exe");
    check(source::exe_lease == INVALID_HANDLE_VALUE
              && source::dll_lease == INVALID_HANDLE_VALUE,
          "template_fixture_startup_leases_closed");
    frame_thread = GetCurrentThreadId();
    source::identity = {kInstallation, creation};
    source::creation = creation;
    source::game_image_size = kRegionBytes;
    source::game = g_game;
    source::player = kPlayer;
    source::bound_thread = frame_thread;
    source::last_date = static_cast<std::int32_t>(kDate);
    source::state.store(source::ready, std::memory_order_release);
    if (!source::drain.reset(source::identity).succeeded()) return false;
    wchar_t log_path[MAX_PATH]{};
    if (swprintf(log_path, MAX_PATH, L"%ls\\message-scope.jsonl",
                 g_fixture_directory.data()) <= 0) return false;
    std::memcpy(source::log_path, log_path, sizeof(log_path));
    if (!source::writer.open(source::log_path, source::identity)) return false;
    check(source::code_guard(), "message_fixture_pre_install_code_guard");
    if (!source::install()) {
        std::printf("INSTALL_STATE state=%ld patched=%d table=%d trampoline=%p "
                    "router_trampoline=%p message_trampoline=%p stage=%u "
                    "error=%lu errors=%u\\n",
                    source::state.load(), source::patched ? 1 : 0,
                    source::table_registered ? 1 : 0,
                    static_cast<void*>(source::trampoline),
                    static_cast<void*>(source::message_entries[0].trampoline),
                    static_cast<void*>(source::message_entries[1].trampoline),
                    static_cast<unsigned>(source::last_patch_result.failure_stage),
                    static_cast<unsigned long>(source::last_patch_result.error),
                    source::last_patch_result.error_records);
        return false;
    }
    source::state.store(source::enabled, std::memory_order_release);
    information_battle_router_original = reinterpret_cast<void*>(
        &fixture_router_original);
    information_battle_message_original = reinterpret_cast<void*>(
        &fixture_message_original);
    return source::patched && source::code_guard()
        && source::table_registered && source::trampoline != nullptr;
}

void test_deferred_template() noexcept {
    reset_case(1u);
    const unsigned router_before = g_router_original_calls;
    const unsigned message_before = g_message_original_calls;
    const DWORD before = kInitialLastError;
    g_deferred_base_seen = 0u;
    g_deferred_message_seen = 0u;
    SetLastError(before);
    information_battle_router_hook(reinterpret_cast<void*>(g_combat), 7u);
    check(g_router_original_calls == router_before + 1u
              && g_message_original_calls == message_before + 1u,
          "deferred_typed_router_and_message_original_each_once");
    check(g_deferred_base_seen == 1u && g_deferred_message_seen == 1u
              && source::scope_depth == 0u && source::count == 1u,
          "message_deferred_until_router_scope_exit");
    check(g_observed_message_return_pc == base + kLandReturnRva,
          "typed_message_wrapper_observes_exact_return_pc");
    check(g_last_direction == 7u && GetLastError() == before,
          "typed_router_wrapper_preserves_last_error_and_direction");
    check(drain_frames("deferred") == 1u,
          "deferred_template_one_frame");
}

void test_nested_scope_isolation() noexcept {
    reset_case(1u);
    const auto outer = source::begin_scope(reinterpret_cast<void*>(g_combat));
    check(outer.depth == 1u, "nested_outer_scope_started");
    // Capture the outer record before entering the inner scope.  The manager
    // must reserve its FIFO slot immediately, then attach the inner record to
    // the next slot; otherwise a deferred outer record can be emitted after
    // the later inner sequence.
    set_template_message(static_cast<std::int32_t>(kDate),
                         "OUTER_A", "OUTER_VALUE_A", "OUTER_B", "OUTER_VALUE_B");
    g_current_message = g_message;
    g_current_site = MessageSite::land;
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    check(source::scope_depth == 1u && source::count == 1u
              && source::scopes[0].has_record,
          "nested_outer_record_reserved_before_inner");

    // Rebuild a second complete message at the node address; its ordered keys
    // differ from the outer message and therefore reveal cross-scope pairing.
    set_template_message(static_cast<std::int32_t>(kDate),
                         "INNER_A", "INNER_VALUE_A", "INNER_B", "INNER_VALUE_B");
    g_current_message = g_message;
    g_current_site = MessageSite::land;
    information_battle_router_hook(reinterpret_cast<void*>(g_combat), 1u);
    check(source::scope_depth == 1u && source::count == 2u
              && source::scopes[0].has_record,
          "nested_inner_scope_committed_without_outer_cross_talk");
    set_template_message(static_cast<std::int32_t>(kDate),
                         "OUTER_A", "OUTER_VALUE_A", "OUTER_B", "OUTER_VALUE_B");
    g_current_message = g_message;
    source::capture_message(reinterpret_cast<void*>(g_current_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(outer);
    check(source::scope_depth == 0u && source::count == 2u,
          "nested_outer_scope_committed_after_inner");
    check(drain_frames("nested") == 2u,
          "nested_scope_two_ordered_frames");
}

void test_double_base() noexcept {
    reset_case(1u);
    const auto token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(source::template_ambiguous.load() > 0u,
          "same_scope_double_base_marks_ambiguous");
    check(drain_frames("double_base") == 2u,
          "same_scope_double_base_keeps_two_raw_base_frames");
}

void test_double_message() noexcept {
    reset_case(1u);
    const auto token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(source::template_ambiguous.load() > 0u,
          "same_scope_double_message_marks_ambiguous");
    check(drain_frames("double_message") == 1u,
          "same_scope_double_message_keeps_base_frame");
}

void test_rejection_cases() noexcept {
    reset_case(1u);
    auto token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + 0x999999u,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("unknown_return") == 1u,
          "unknown_return_keeps_base_without_template");

    reset_case(1u);
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva + 8u),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("wrong_callback") == 1u,
          "wrong_callback_keeps_base_without_template");

    reset_case(1u);
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    // The formatter frame is structurally valid but belongs to another
    // object.  The owner check must reject the template and retain the base.
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1b8u,
              g_result);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("wrong_owner") == 1u,
          "wrong_formatter_owner_keeps_base_without_template");

    reset_case(1u);
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    // A valid frame with the other formatter's router return is rejected.
    write_u64(reinterpret_cast<unsigned char*>(g_land_formatter_frame) + 0x1d8u,
              base + kNavalFormatterCallerRva);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("wrong_formatter_caller") == 1u,
          "wrong_formatter_caller_keeps_base_without_template");

    reset_case(2u);
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("kind_mismatch") == 1u,
          "kind_mismatch_keeps_base_without_template");

    reset_case(1u, static_cast<std::int32_t>(kDate - 1u));
    token = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(token);
    check(drain_frames("date_mismatch") == 1u,
          "date_mismatch_keeps_base_without_template");

    reset_case(1u);
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    check(drain_frames("missing_scope") == 1u,
          "missing_scope_keeps_base_without_template");
}

void test_scope_overflow() noexcept {
    reset_case(1u);
    const auto outer = source::begin_scope(reinterpret_cast<void*>(g_combat));
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    std::array<source::ScopeToken, source::kScopeLimit> nested{};
    for (unsigned index = 0u; index + 1u < source::kScopeLimit; ++index) {
        nested[index] = source::begin_scope(reinterpret_cast<void*>(g_combat));
    }
    const auto suppressed = source::begin_scope(reinterpret_cast<void*>(g_combat));
    check(suppressed.suppressed && source::suppressed_scopes != 0u,
          "scope_overflow_enters_suppressed_guard");
    source::capture_message(reinterpret_cast<void*>(g_message),
                            reinterpret_cast<void*>(base + kMessageCallbackRva),
                            base + kLandReturnRva,
                            formatter_frame_for(MessageSite::land));
    source::end_scope(suppressed);
    for (unsigned index = source::kScopeLimit - 1u; index > 0u; --index)
        source::end_scope(nested[index - 1u]);
    source::end_scope(outer);
    check(source::scope_overflow.load() > 0u && source::count == 1u,
          "scope_overflow_does_not_attach_outer_message");
    check(drain_frames("overflow") == 1u,
          "scope_overflow_keeps_outer_base_frame");
}

}  // namespace

#ifndef INFORMATION_BATTLE_SCOPE_TEST_MAIN
#define INFORMATION_BATTLE_SCOPE_TEST_MAIN main
#endif

int INFORMATION_BATTLE_SCOPE_TEST_MAIN() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-message-scope-manager\n");
    (void)&legacy_context_fixture_main;
    (void)&bridge_entry_patch::guarded_patch_rollback;
    (void)&information_battle_tick;
    if (!prepare_manager()) {
        std::printf("RESULT FAIL prepare_manager\n");
        return 1;
    }
    test_deferred_template();
    test_nested_scope_isolation();
    test_double_base();
    test_double_message();
    test_rejection_cases();
    test_scope_overflow();
    const bool passed = g_failures == 0u;
    std::printf(
        "RESULT %s\n{\"passed\":%s,\"router_original_calls\":%u,"
        "\"message_original_calls\":%u,\"template_copied\":%llu,"
        "\"template_copy_failures\":%llu,\"template_ambiguous\":%llu,"
        "\"scope_overflow\":%llu,\"production_modified\":false,"
        "\"game_access\":false,\"fixture_private_initialization\":true}\n",
        passed ? "PASS" : "FAIL", passed ? "true" : "false",
        g_router_original_calls, g_message_original_calls,
        static_cast<unsigned long long>(source::template_copied.load()),
        static_cast<unsigned long long>(source::template_copy_failed.load()),
        static_cast<unsigned long long>(source::template_ambiguous.load()),
        static_cast<unsigned long long>(source::scope_overflow.load()));
    return passed ? 0 : 1;
}

