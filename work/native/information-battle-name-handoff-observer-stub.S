.intel_syntax noprefix
.text

.extern GetLastError
.extern SetLastError
.extern information_battle_name_handoff_original
.extern information_battle_name_handoff_capture

.globl information_battle_name_handoff_hook
.def information_battle_name_handoff_hook; .scl 2; .type 32; .endef
.p2align 4
.seh_proc information_battle_name_handoff_hook
information_battle_name_handoff_hook:
    # Win64 entry before the native prologue.  RSP points at the untouched
    # caller return address and is 8 mod 16.  Preserve the full entry state
    # before calling the out-of-line observer.
    pushfq
    .seh_stackalloc 8
    push rax
    .seh_stackalloc 8
    push rcx
    .seh_stackalloc 8
    push rdx
    .seh_stackalloc 8
    push r8
    .seh_stackalloc 8
    push r9
    .seh_stackalloc 8
    push r10
    .seh_stackalloc 8
    push r11
    .seh_stackalloc 8
    push rbx
    .seh_pushreg %rbx
    push rbp
    .seh_pushreg %rbp
    push rsi
    .seh_pushreg %rsi
    push rdi
    .seh_pushreg %rdi
    push r12
    .seh_pushreg %r12
    push r13
    .seh_pushreg %r13
    push r14
    .seh_pushreg %r14
    push r15
    .seh_pushreg %r15
    sub rsp, 0xd8
    .seh_stackalloc 0xd8
    .seh_endprologue

.globl information_battle_name_handoff_body
information_battle_name_handoff_body:
    # C is 16-byte aligned.  It contains Win64 callback shadow space and
    # storage for volatile FP state.  No original caller home slot is touched.
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

    # Saved-register layout after the 0xd8 local allocation:
    # R15=d8, R14=e0, R13=e8, R12=f0, RDI=f8, RSI=100,
    # RBP=108, RBX=110, R11=118, R10=120, R9=128, R8=130,
    # RDX=138, RCX=140, RAX=148, RFLAGS=150.  The untouched original
    # return address is at C+158; original RSP is also C+158.
    # capture(dest, key, value, return_pc, original_rbp, original_rsp)
    mov rcx, qword ptr [rsp + 0x140]
    mov rdx, qword ptr [rsp + 0x138]
    mov r8,  qword ptr [rsp + 0x130]
    mov r9,  qword ptr [rsp + 0x158]
    mov rax, qword ptr [rsp + 0x108]
    mov qword ptr [rsp + 0x20], rax
    lea rax, [rsp + 0x158]
    mov qword ptr [rsp + 0x28], rax
    call information_battle_name_handoff_capture

    # Restore process error and floating-point control state after observer
    # code.  GPRs and saved flags are restored below.
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

    # Restore every GPR with C as the frame base.  The saved flags remain at
    # C+0x150 for the separate restore_flags unwind span.
    mov r15, qword ptr [rsp + 0xd8]
    mov r14, qword ptr [rsp + 0xe0]
    mov r13, qword ptr [rsp + 0xe8]
    mov r12, qword ptr [rsp + 0xf0]
    mov rdi, qword ptr [rsp + 0xf8]
    mov rsi, qword ptr [rsp + 0x100]
    mov rbp, qword ptr [rsp + 0x108]
    mov rbx, qword ptr [rsp + 0x110]
    mov r11, qword ptr [rsp + 0x118]
    mov r10, qword ptr [rsp + 0x120]
    mov r9,  qword ptr [rsp + 0x128]
    mov r8,  qword ptr [rsp + 0x130]
    mov rdx, qword ptr [rsp + 0x138]
    mov rcx, qword ptr [rsp + 0x140]
    mov rax, qword ptr [rsp + 0x148]
.globl information_battle_name_handoff_before_add
information_battle_name_handoff_before_add:
    add rsp, 0x150
.seh_endproc

.globl information_battle_name_handoff_restore_flags
.def information_battle_name_handoff_restore_flags; .scl 2; .type 32; .endef
.seh_proc information_battle_name_handoff_restore_flags
information_battle_name_handoff_restore_flags:
    # RSP names saved RFLAGS.  POPFQ leaves the untouched caller return slot.
    .seh_stackalloc 8
    .seh_endprologue
    popfq
.seh_endproc

.globl information_battle_name_handoff_tail
.def information_battle_name_handoff_tail; .scl 2; .type 32; .endef
.seh_proc information_battle_name_handoff_tail
information_battle_name_handoff_tail:
    # Zero-stack tail jump preserves every restored argument and return value.
    .seh_endprologue
    jmp qword ptr [rip + information_battle_name_handoff_original]
.seh_endproc
