.text

// Offline ABI fixture for a future passive natural-battle entry.  This shim
// never calls the original.  It preserves the caller's entry frame, observes
// through the C callback, and tail-jumps to the caller-owned original pointer.
// The caller must publish a non-null, immutable original pointer before use.

.extern GetLastError
.extern SetLastError
.extern information_battle_entry_capture
.extern information_battle_entry_original

.globl information_battle_entry_stub
.globl information_battle_entry_unwind_entry
.globl information_battle_entry_unwind_after_push
.globl information_battle_entry_unwind_after_sub
.globl information_battle_entry_unwind_before_call
.globl information_battle_entry_unwind_before_add
.globl information_battle_entry_unwind_after_add
.globl information_battle_entry_unwind_after_popfq
.def information_battle_entry_stub; .scl 2; .type 32; .endef
.seh_proc information_battle_entry_stub
information_battle_entry_stub:
information_battle_entry_unwind_entry:
    // Entry RSP is 8 mod 16.  Keep RFLAGS in the one-word slot immediately
    // below the original return address, then allocate 0x1e0 (0 mod 16), so
    // the callback call sees an aligned RSP and its 32-byte home area at
    // [rsp..+1f].  The original return address remains at [rsp+0x1e8].
    pushfq
    .seh_stackalloc 8
information_battle_entry_unwind_after_push:
    subq $0x1e0, %rsp
    .seh_stackalloc 0x1e0
information_battle_entry_unwind_after_sub:
    .seh_endprologue

    // Save every volatile GPR before calling GetLastError.  These slots are
    // after the callback's 32-byte shadow area.
    // Keep incoming RAX away from the fifth callback argument slot.
    movq %rax, 0xd8(%rsp)
    movq %rbx, 0xe0(%rsp)
    movq %rcx, 0x28(%rsp)
    movq %rdx, 0x30(%rsp)
    movq %r8,  0x38(%rsp)
    movq %r9,  0x40(%rsp)
    movq %r10, 0x48(%rsp)
    movq %r11, 0x50(%rsp)

    // Save volatile vector state and the two floating-point control words.
    movdqu %xmm0, 0x60(%rsp)
    movdqu %xmm1, 0x70(%rsp)
    movdqu %xmm2, 0x80(%rsp)
    movdqu %xmm3, 0x90(%rsp)
    movdqu %xmm4, 0xa0(%rsp)
    movdqu %xmm5, 0xb0(%rsp)
    stmxcsr 0xc8(%rsp)
    fnstcw 0xcc(%rsp)

    // The API call is made only after all incoming volatile state is saved.
    call GetLastError
    movl %eax, 0xd0(%rsp)

    // The callback receives combat/summary/result, the original CALL return
    // address, and the incoming RBX as its fifth Win64 argument.  The fifth
    // argument is written into the caller shadow/argument slot only after all
    // incoming volatile state has been copied elsewhere.  The incoming native
    // R9 is restored below before the tail-jump to the original.
    movq 0x28(%rsp), %rcx
    movq 0x30(%rsp), %rdx
    movq 0x38(%rsp), %r8
    movq 0x1e8(%rsp), %r9
    movq 0xe0(%rsp), %rax
    movq %rax, 0x20(%rsp)
information_battle_entry_unwind_before_call:
    call information_battle_entry_capture

    // Restore the native thread error slot before restoring flags/registers.
    movl 0xd0(%rsp), %ecx
    call SetLastError
    ldmxcsr 0xc8(%rsp)
    fldcw 0xcc(%rsp)

    movdqu 0x60(%rsp), %xmm0
    movdqu 0x70(%rsp), %xmm1
    movdqu 0x80(%rsp), %xmm2
    movdqu 0x90(%rsp), %xmm3
    movdqu 0xa0(%rsp), %xmm4
    movdqu 0xb0(%rsp), %xmm5
    movq 0x50(%rsp), %r11
    movq 0x48(%rsp), %r10
    movq 0x40(%rsp), %r9
    movq 0x38(%rsp), %r8
    movq 0x30(%rsp), %rdx
    movq 0x28(%rsp), %rcx
    movq 0xd8(%rsp), %rax

information_battle_entry_unwind_before_add:
    addq $0x1e0, %rsp
.seh_endproc

.def information_battle_entry_restore_flags; .scl 2; .type 32; .endef
.seh_proc information_battle_entry_restore_flags
information_battle_entry_unwind_after_add:
    .seh_stackalloc 8
    .seh_endprologue
    popfq
.seh_endproc

.def information_battle_entry_tail; .scl 2; .type 32; .endef
.seh_proc information_battle_entry_tail
information_battle_entry_unwind_after_popfq:
    .seh_endprologue
    jmp *information_battle_entry_original(%rip)
.seh_endproc

#ifdef INFORMATION_BATTLE_TEMPLATE
// Message entry before its native prologue. Preserve the formatter's RBP
// anchor explicitly: a C++ wrapper may repurpose that nonvolatile register
// before a callback can inspect it. No native argument or return is changed.
.extern information_battle_message_capture
.extern information_battle_message_original
.globl information_battle_message_hook
.def information_battle_message_hook; .scl 2; .type 32; .endef
.seh_proc information_battle_message_hook
information_battle_message_hook:
    pushfq
    .seh_stackalloc 8
    subq $0x1e0, %rsp
    .seh_stackalloc 0x1e0
    .seh_endprologue
    movq %rax, 0xd8(%rsp)
    movq %rcx, 0x28(%rsp)
    movq %rdx, 0x30(%rsp)
    movq %r8,  0x38(%rsp)
    movq %r9,  0x40(%rsp)
    movq %r10, 0x48(%rsp)
    movq %r11, 0x50(%rsp)
    movdqu %xmm0, 0x60(%rsp)
    movdqu %xmm1, 0x70(%rsp)
    movdqu %xmm2, 0x80(%rsp)
    movdqu %xmm3, 0x90(%rsp)
    movdqu %xmm4, 0xa0(%rsp)
    movdqu %xmm5, 0xb0(%rsp)
    stmxcsr 0xc8(%rsp)
    fnstcw 0xcc(%rsp)
    call GetLastError
    movl %eax, 0xd0(%rsp)
    movq 0x30(%rsp), %rcx
    movq 0x40(%rsp), %rdx
    movq 0x1e8(%rsp), %r8
    movq %rbp, %r9
    call information_battle_message_capture
    movl 0xd0(%rsp), %ecx
    call SetLastError
    ldmxcsr 0xc8(%rsp)
    fldcw 0xcc(%rsp)
    movdqu 0x60(%rsp), %xmm0
    movdqu 0x70(%rsp), %xmm1
    movdqu 0x80(%rsp), %xmm2
    movdqu 0x90(%rsp), %xmm3
    movdqu 0xa0(%rsp), %xmm4
    movdqu 0xb0(%rsp), %xmm5
    movq 0x50(%rsp), %r11
    movq 0x48(%rsp), %r10
    movq 0x40(%rsp), %r9
    movq 0x38(%rsp), %r8
    movq 0x30(%rsp), %rdx
    movq 0x28(%rsp), %rcx
    movq 0xd8(%rsp), %rax
    addq $0x1e0, %rsp
.seh_endproc

.def information_battle_message_restore_flags; .scl 2; .type 32; .endef
.seh_proc information_battle_message_restore_flags
information_battle_message_restore_flags:
    .seh_stackalloc 8
    .seh_endprologue
    popfq
.seh_endproc

.def information_battle_message_tail; .scl 2; .type 32; .endef
.seh_proc information_battle_message_tail
information_battle_message_tail:
    .seh_endprologue
    jmp *information_battle_message_original(%rip)
.seh_endproc
#endif

#ifdef INFORMATION_BATTLE_CONTAINER
// Container cleanup entry before its native prologue. Preserve the formatter's RBP
// anchor explicitly: a C++ wrapper may repurpose that nonvolatile register
// before a callback can inspect it. No native argument or return is changed.
.extern information_battle_container_capture
.extern information_battle_container_original
.globl information_battle_container_hook
.def information_battle_container_hook; .scl 2; .type 32; .endef
.seh_proc information_battle_container_hook
information_battle_container_hook:
    pushfq
    .seh_stackalloc 8
    subq $0x1e0, %rsp
    .seh_stackalloc 0x1e0
    .seh_endprologue
    movq %rax, 0xd8(%rsp)
    movq %rcx, 0x28(%rsp)
    movq %rdx, 0x30(%rsp)
    movq %r8,  0x38(%rsp)
    movq %r9,  0x40(%rsp)
    movq %r10, 0x48(%rsp)
    movq %r11, 0x50(%rsp)
    movdqu %xmm0, 0x60(%rsp)
    movdqu %xmm1, 0x70(%rsp)
    movdqu %xmm2, 0x80(%rsp)
    movdqu %xmm3, 0x90(%rsp)
    movdqu %xmm4, 0xa0(%rsp)
    movdqu %xmm5, 0xb0(%rsp)
    stmxcsr 0xc8(%rsp)
    fnstcw 0xcc(%rsp)
    call GetLastError
    movl %eax, 0xd0(%rsp)
    movq 0x28(%rsp), %rcx
    movq 0x1e8(%rsp), %rdx
    movq %rbp, %r8
    call information_battle_container_capture
    movl 0xd0(%rsp), %ecx
    call SetLastError
    ldmxcsr 0xc8(%rsp)
    fldcw 0xcc(%rsp)
    movdqu 0x60(%rsp), %xmm0
    movdqu 0x70(%rsp), %xmm1
    movdqu 0x80(%rsp), %xmm2
    movdqu 0x90(%rsp), %xmm3
    movdqu 0xa0(%rsp), %xmm4
    movdqu 0xb0(%rsp), %xmm5
    movq 0x50(%rsp), %r11
    movq 0x48(%rsp), %r10
    movq 0x40(%rsp), %r9
    movq 0x38(%rsp), %r8
    movq 0x30(%rsp), %rdx
    movq 0x28(%rsp), %rcx
    movq 0xd8(%rsp), %rax
    addq $0x1e0, %rsp
.seh_endproc

.def information_battle_container_restore_flags; .scl 2; .type 32; .endef
.seh_proc information_battle_container_restore_flags
information_battle_container_restore_flags:
    .seh_stackalloc 8
    .seh_endprologue
    popfq
.seh_endproc

.def information_battle_container_tail; .scl 2; .type 32; .endef
.seh_proc information_battle_container_tail
information_battle_container_tail:
    .seh_endprologue
    jmp *information_battle_container_original(%rip)
.seh_endproc
#endif

#ifdef INFORMATION_BATTLE_GATE_TRACE
// Observe the existing post-gate callee entry without changing its arguments.
// The same owned Win64 entry-frame preservation as the message shim applies.
.extern information_battle_gate_marker_capture
.extern information_battle_gate_marker_original
.globl information_battle_gate_marker_hook
.def information_battle_gate_marker_hook; .scl 2; .type 32; .endef
.seh_proc information_battle_gate_marker_hook
information_battle_gate_marker_hook:
    pushfq
    .seh_stackalloc 8
    subq $0x1e0, %rsp
    .seh_stackalloc 0x1e0
    .seh_endprologue
    movq %rax, 0xd8(%rsp)
    movq %rcx, 0x28(%rsp)
    movq %rdx, 0x30(%rsp)
    movq %r8,  0x38(%rsp)
    movq %r9,  0x40(%rsp)
    movq %r10, 0x48(%rsp)
    movq %r11, 0x50(%rsp)
    movdqu %xmm0, 0x60(%rsp)
    movdqu %xmm1, 0x70(%rsp)
    movdqu %xmm2, 0x80(%rsp)
    movdqu %xmm3, 0x90(%rsp)
    movdqu %xmm4, 0xa0(%rsp)
    movdqu %xmm5, 0xb0(%rsp)
    stmxcsr 0xc8(%rsp)
    fnstcw 0xcc(%rsp)
    call GetLastError
    movl %eax, 0xd0(%rsp)
    movq 0x1e8(%rsp), %rcx
    movq %rbp, %rdx
    call information_battle_gate_marker_capture
    movl 0xd0(%rsp), %ecx
    call SetLastError
    ldmxcsr 0xc8(%rsp)
    fldcw 0xcc(%rsp)
    movdqu 0x60(%rsp), %xmm0
    movdqu 0x70(%rsp), %xmm1
    movdqu 0x80(%rsp), %xmm2
    movdqu 0x90(%rsp), %xmm3
    movdqu 0xa0(%rsp), %xmm4
    movdqu 0xb0(%rsp), %xmm5
    movq 0x50(%rsp), %r11
    movq 0x48(%rsp), %r10
    movq 0x40(%rsp), %r9
    movq 0x38(%rsp), %r8
    movq 0x30(%rsp), %rdx
    movq 0x28(%rsp), %rcx
    movq 0xd8(%rsp), %rax
    addq $0x1e0, %rsp
.seh_endproc

.def information_battle_gate_marker_restore_flags; .scl 2; .type 32; .endef
.seh_proc information_battle_gate_marker_restore_flags
information_battle_gate_marker_restore_flags:
    .seh_stackalloc 8
    .seh_endprologue
    popfq
.seh_endproc

.def information_battle_gate_marker_tail; .scl 2; .type 32; .endef
.seh_proc information_battle_gate_marker_tail
information_battle_gate_marker_tail:
    .seh_endprologue
    jmp *information_battle_gate_marker_original(%rip)
.seh_endproc
#endif
