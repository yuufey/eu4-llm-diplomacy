// Included inside mission_condition_observer after the shared queue writer.
namespace province {

namespace values = information::mission_province_condition;
namespace entry = values::entry;
using Original = uint64_t(*)(void*, void*);
static Original original = nullptr;
static entry::Plan entry_image{};
static unsigned char* trampoline = nullptr;
static RUNTIME_FUNCTION entry_unwind{};
static bridge_entry_patch::PatchPlan entry_patch{};
static bool entry_table_registered = false, entry_published = false;
static values::Baselines province_baselines{};

static unsigned baseline_count_locked() noexcept { return province_baselines.count; }

static uint64_t observe(void* child, void* context) {
    const auto call = original;
    if (!call) return 0;
    // The common unowned path performs no memory reads or Windows API call.
    if (!active_scopes.load(std::memory_order_relaxed) || !installed || transport_fault || !depth)
        return call(child, context);
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (caller != base+values::kAreaChildReturnRva) return call(child, context);
    const DWORD incoming_error = GetLastError();
    const uint64_t token = scopes[depth-1].token;
    values::Binding before{};
    Reader reader;
    const auto captured = values::bind(reader, base, scopes[depth-1].value,
        reinterpret_cast<uintptr_t>(child), reinterpret_cast<uintptr_t>(context), caller, before);
    SetLastError(incoming_error);
    const uint64_t returned = call(child, context);
    const DWORD returned_error = GetLastError();
    auto* scope = current(token);
    if (scope && captured != owned::CaptureResult::ignored) {
        values::Binding after{};
        if (captured != owned::CaptureResult::observed
            || values::bind(reader, base, scope->value, reinterpret_cast<uintptr_t>(child),
                reinterpret_cast<uintptr_t>(context), caller, after) != owned::CaptureResult::observed
            || !values::same(before, after)) {
            scope->province_valid = false;
            note_drop("province_binding_changed_or_invalid");
        } else if (scope->province_count == 128) {
            scope->province_valid = false;
            note_drop("province_evaluation_limit");
        } else {
            scope->province_samples[scope->province_count++] = {before, returned};
        }
    }
    SetLastError(returned_error);
    return returned;
}

static void commit(const Scope& scope, Reader& reader) noexcept {
    if (!scope.province_valid || !scope.province_count) return;
    // The caller has checked the parent country, mission, date and root walk,
    // and holds queue_lock. Never read a finished area's old stack context.
    for (unsigned index = 0; index < scope.province_count; ++index) {
        const auto& binding = scope.province_samples[index].binding;
        if (binding.root_index >= scope.value.seen
            || !values::still_member(reader, base, scope.value.root, binding)) {
            note_drop("province_parent_or_membership_rejected");
            return;
        }
        for (unsigned earlier = 0; earlier < index; ++earlier) {
            const auto& previous = scope.province_samples[earlier].binding;
            if (binding.root_index == previous.root_index && binding.child_index == previous.child_index
                && binding.province == previous.province) {
                note_drop("province_duplicate_evaluation");
                return;
            }
        }
    }
    for (unsigned index = 0; index < scope.province_count; ++index) {
        const auto& sample = scope.province_samples[index];
        values::Value value{sample.binding, scope.value.mission, scope.value.date, sample.returned};
        values::Change change{};
        const auto result = province_baselines.observe(value, change);
        if (result == values::Result::invalid || result == values::Result::reset || result == values::Result::full) {
            note_drop("province_baseline_invalid_full_or_reset");
            continue;
        }
        if (result != values::Result::changed) continue;
        Event event{};
        event.mission = value.mission;
        event.node = {value.binding.child, base+values::kHeldMethodRva};
        event.change = {value.binding.root_index, change.before.date, change.before.returned, value.returned};
        event.country = value.binding.country;
        event.sequence = ++sequence;
        event.date = value.date;
        event.root_count = scope.value.root.count;
        event.observed_count = scope.value.seen;
        event.child_index = value.binding.child_index;
        event.child_count = value.binding.child_count;
        event.province_id = value.binding.province;
        if (size < 64) { events[(head+size)%64] = event; ++size; }
        else note_drop("queue_full");
    }
}

static void release_unpublished() noexcept {
    if (entry_published) return;
    if (entry_table_registered && !RtlDeleteFunctionTable(&entry_unwind)) {
        lifecycle_rollback_incomplete = true;
        return;
    }
    if (trampoline) VirtualFree(trampoline, 0, MEM_RELEASE);
    trampoline = nullptr;
    original = nullptr;
    entry_table_registered = false;
}

static bool install() noexcept {
    if (original || trampoline || entry_published) return false;
    Reader reader;
    std::array<unsigned char, entry::kPatchBytes> source{};
    std::array<unsigned char, 28> metadata{};
    DWORD64 image_base = 0;
    const auto* parent = RtlLookupFunctionEntry(base+entry::kEntryRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != entry::kEntryRva || parent->EndAddress != entry::kSourceEndRva
        || parent->UnwindData != entry::kUnwindRva
        || !reader.read(base+entry::kEntryRva, source.data(), source.size())
        || !reader.read(base+entry::kUnwindRva, metadata.data(), metadata.size())
        || !entry::prepare(source, metadata, base+entry::kEntryRva,
            reinterpret_cast<uintptr_t>(&observe), entry_image)) return false;
    trampoline = static_cast<unsigned char*>(VirtualAlloc(nullptr, entry_image.image.size(),
        MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    if (!trampoline) return false;
    std::memcpy(trampoline, entry_image.image.data(), entry_image.image.size());
    DWORD previous = 0;
    if (!VirtualProtect(trampoline, entry_image.image.size(), PAGE_EXECUTE_READ, &previous)
        || !FlushInstructionCache(GetCurrentProcess(), trampoline, entry_image.image.size())) {
        release_unpublished(); return false;
    }
    entry_unwind = {entry_image.runtime.begin, entry_image.runtime.end, entry_image.runtime.unwind};
    entry_table_registered = RtlAddFunctionTable(&entry_unwind, 1, reinterpret_cast<DWORD64>(trampoline)) != FALSE;
    if (!entry_table_registered) { release_unpublished(); return false; }
    original = reinterpret_cast<Original>(trampoline);
    entry_patch.count = 1;
    entry_patch.targets[0] = {reinterpret_cast<void*>(base+entry::kEntryRva), entry::kPatchBytes,
        entry::kPrefix.data(), entry_image.patch.data(), trampoline, entry_image.runtime.end};
    const auto result = bridge_entry_patch::guarded_patch_apply(entry_patch);
    entry_published = result.published;
    if (!entry_published) release_unpublished();
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool rollback() noexcept {
    if (!entry_published) return true;
    const auto result = bridge_entry_patch::guarded_patch_rollback(entry_patch);
    // Published trampolines remain available to an already dispatched caller.
    return result.success && result.threads_resumed && result.protection_restored;
}

} // namespace province
