.intel_syntax noprefix
.text

.extern GetLastError
.extern SetLastError
.extern g_line1_capture
.extern g_line1_trampoline
.extern g_line1_hook_restored_flags
.extern g_line1_native_widget
.extern g_line1_native_text
.extern g_line1_native_flag
.extern g_line1_native_hits

.globl line1_entry_hook
.p2align 4
line1_entry_hook:
    # Entry is reached by the fixed 20-byte patch with the original caller's
    # return address still at [RSP].  Preserve every register/state element
    # that the callback may clobber, while leaving the three original args
    # available for the later owned trampoline.
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0xd8

    # C is 16-byte aligned here.  [C+0x00..0x1f] is callback shadow space;
    # [C+0x20] is its fifth (original RBP) argument.
    movdqu xmmword ptr [rsp + 0x40], xmm0
    movdqu xmmword ptr [rsp + 0x50], xmm1
    movdqu xmmword ptr [rsp + 0x60], xmm2
    movdqu xmmword ptr [rsp + 0x70], xmm3
    movdqu xmmword ptr [rsp + 0x80], xmm4
    movdqu xmmword ptr [rsp + 0x90], xmm5
    stmxcsr dword ptr [rsp + 0xa0]
    fnstcw word ptr [rsp + 0xa4]
    call GetLastError
    mov dword ptr [rsp + 0xa8], eax

    # The sixteen pushes place the original return address at C+0x158 and
    # original RBP at C+0x108.  Save the two callback-only values locally.
    mov rax, qword ptr [rsp + 0x158]
    mov qword ptr [rsp + 0xb0], rax
    mov rax, qword ptr [rsp + 0x108]
    mov qword ptr [rsp + 0xb8], rax
    mov qword ptr [rsp + 0x20], rax

    # callback(widget, string32, flag, original_return, original_rbp)
    mov rcx, qword ptr [rsp + 0x140]
    mov rdx, qword ptr [rsp + 0x138]
    mov r8,  qword ptr [rsp + 0x130]
    mov r9,  qword ptr [rsp + 0xb0]
    mov rax, qword ptr [rip + g_line1_capture]
    test rax, rax
    jz .Lline1_no_capture
    call rax
.Lline1_no_capture:

    # Restore the process error state before restoring registers.  SetLastError
    # may itself clobber volatile registers and flags; all are still saved.
    mov ecx, dword ptr [rsp + 0xa8]
    call SetLastError
    ldmxcsr dword ptr [rsp + 0xa0]
    fldcw word ptr [rsp + 0xa4]
    movdqu xmm0, xmmword ptr [rsp + 0x40]
    movdqu xmm1, xmmword ptr [rsp + 0x50]
    movdqu xmm2, xmmword ptr [rsp + 0x60]
    movdqu xmm3, xmmword ptr [rsp + 0x70]
    movdqu xmm4, xmmword ptr [rsp + 0x80]
    movdqu xmm5, xmmword ptr [rsp + 0x90]

    # Record the saved caller flags rather than the flags left by
    # SetLastError/LD* state restoration.  The subsequent MOVs restore all
    # GPRs before the original RSP is reinstated.
    mov rax, qword ptr [rsp + 0x150]
    mov qword ptr [rip + g_line1_hook_restored_flags], rax
    mov rax, qword ptr [rsp + 0x148]
    mov rcx, qword ptr [rsp + 0x140]
    mov rdx, qword ptr [rsp + 0x138]
    mov r8,  qword ptr [rsp + 0x130]
    mov r9,  qword ptr [rsp + 0x128]
    mov r10, qword ptr [rsp + 0x120]
    mov r11, qword ptr [rsp + 0x118]
    mov rbx, qword ptr [rsp + 0x110]
    mov rbp, qword ptr [rsp + 0x108]
    mov rsi, qword ptr [rsp + 0x100]
    mov rdi, qword ptr [rsp + 0xf8]
    mov r12, qword ptr [rsp + 0xf0]
    mov r13, qword ptr [rsp + 0xe8]
    mov r14, qword ptr [rsp + 0xe0]
    mov r15, qword ptr [rsp + 0xd8]

    # Return to the untouched caller stack.  The saved flags are still at
    # [RSP-8]; push/pop restores them without using a scratch GPR, then the
    # memory-indirect jump preserves all original args and volatile state.
    add rsp, 0x158
    push qword ptr [rsp - 0x8]
    popfq
    jmp qword ptr [rip + g_line1_trampoline]

.globl line1_original_entry
.p2align 4
line1_original_entry:
    # Exact fixed-build prefix copied into the owned trampoline.
    mov qword ptr [rsp + 0x8], rbx
    mov qword ptr [rsp + 0x10], rbp
    mov qword ptr [rsp + 0x18], rsi
    push rdi
    sub rsp, 0x20

    # Synthetic continuation body for the offline fixture.  It records the
    # untouched three setter arguments without changing volatile registers,
    # then performs the matching epilogue for the copied prologue.
    mov qword ptr [rip + g_line1_native_widget], rcx
    mov qword ptr [rip + g_line1_native_text], rdx
    mov byte ptr [rip + g_line1_native_flag], r8b
    mov dword ptr [rip + g_line1_native_hits], 1
    mov rbx, qword ptr [rsp + 0x30]
    mov rbp, qword ptr [rsp + 0x38]
    mov rsi, qword ptr [rsp + 0x40]
    lea rsp, [rsp + 0x20]
    pop rdi
    ret
