.intel_syntax noprefix
.text

.extern GetLastError
.extern SetLastError
.extern observer_capture_widget
.extern observer_capture_text
.extern observer_capture_flag
.extern observer_capture_return
.extern observer_capture_rbp
.extern observer_capture_r13
.extern observer_native_widget
.extern observer_native_text
.extern observer_native_flag
.extern observer_native_hits
.extern observer_after_rax
.extern observer_after_rcx
.extern observer_after_rdx
.extern observer_after_r8
.extern observer_after_r9
.extern observer_after_r10
.extern observer_after_r11
.extern observer_after_rbp
.extern observer_after_flags
.extern observer_after_mxcsr
.extern observer_after_x87cw
.extern observer_after_last_error
.extern observer_after_xmm0
.extern observer_after_xmm1
.extern observer_after_xmm2
.extern observer_after_xmm3
.extern observer_after_xmm4
.extern observer_after_xmm5
.extern observer_expected_flags

.globl information_battle_line1_capture
.p2align 4
information_battle_line1_capture:
    # callback(widget, text, flag, return_pc, original_rbp, original_r13)
    mov qword ptr [rip + observer_capture_widget], rcx
    mov qword ptr [rip + observer_capture_text], rdx
    mov byte ptr [rip + observer_capture_flag], r8b
    mov qword ptr [rip + observer_capture_return], r9
    mov rax, qword ptr [rsp + 0x28]
    mov qword ptr [rip + observer_capture_rbp], rax
    mov rax, qword ptr [rsp + 0x30]
    mov qword ptr [rip + observer_capture_r13], rax

    # Deliberately destroy callback-clobberable state.  The production stub
    # must restore this state before tail-jumping its original trampoline.
    mov rax, 0x0a0b0c0d0e0f1011
    mov rcx, 0x1a1b1c1d1e1f2021
    mov rdx, 0x2a2b2c2d2e2f3031
    mov r8,  0x3a3b3c3d3e3f4041
    mov r9,  0x4a4b4c4d4e4f5051
    mov r10, 0x5a5b5c5d5e5f6061
    mov r11, 0x6a6b6c6d6e5f7071
    mov r13, 0x7a7b7c7d7e7f8081
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    sub rsp, 0x28
    mov dword ptr [rsp + 0x20], 0x00001f80
    ldmxcsr dword ptr [rsp + 0x20]
    mov word ptr [rsp + 0x22], 0x0f7f
    fldcw word ptr [rsp + 0x22]
    mov ecx, 0x5a5aa5a5
    call SetLastError
    add rsp, 0x28
    xor eax, eax
    ret

.globl observer_native_continuation
.p2align 4
observer_native_continuation:
    # The owned RX trampoline jumps here without changing GPRs or flags.
    # These stores are fixture-only observations; production stub has no such
    # globals or synthetic continuation.
    mov qword ptr [rip + observer_native_widget], rcx
    mov qword ptr [rip + observer_native_text], rdx
    mov byte ptr [rip + observer_native_flag], r8b
    mov dword ptr [rip + observer_native_hits], 1
    ret

.macro INVOKE_VARIANT name
.globl \name
.p2align 4
\name:
    # R1=target, R2=widget, R3=text, R4=flag in the Win64 ABI.
    sub rsp, 0x98
    mov qword ptr [rsp + 0x20], rcx
    mov qword ptr [rsp + 0x28], rdx
    mov qword ptr [rsp + 0x30], r8
    mov qword ptr [rsp + 0x38], r9
    stmxcsr dword ptr [rsp + 0x40]
    fnstcw word ptr [rsp + 0x44]
    pushfq
    pop rax
    mov qword ptr [rsp + 0x48], rax
    call GetLastError
    mov dword ptr [rsp + 0x50], eax
    mov qword ptr [rsp + 0x70], rbp
    mov qword ptr [rsp + 0x78], r13

    # Establish deterministic caller state and preserve it for post-call
    # assertions.  R9 intentionally differs from the three setter args.
    mov rbp, 0x7172737475767778
    mov r10, 0x2233445566778899
    mov r11, 0x33445566778899aa
    mov r9,  0x99aabbccddeeff00
    mov r13, 0x445566778899aabb
    mov rax, 0x1122334455667788

    mov rax, 0x0102030405060708
    movq xmm0, rax
    punpcklqdq xmm0, xmm0
    mov rax, 0x1112131415161718
    movq xmm1, rax
    punpcklqdq xmm1, xmm1
    mov rax, 0x2122232425262728
    movq xmm2, rax
    punpcklqdq xmm2, xmm2
    mov rax, 0x3132333435363738
    movq xmm3, rax
    punpcklqdq xmm3, xmm3
    mov rax, 0x4142434445464748
    movq xmm4, rax
    punpcklqdq xmm4, xmm4
    mov rax, 0x5152535455565758
    movq xmm5, rax
    punpcklqdq xmm5, xmm5

    mov dword ptr [rsp + 0x58], 0x00001f40
    ldmxcsr dword ptr [rsp + 0x58]
    mov word ptr [rsp + 0x5c], 0x037f
    fldcw word ptr [rsp + 0x5c]

    # ZF=1 and CF=1 form the expected pre-hook flags.
    xor eax, eax
    mov rax, 0x1122334455667788
    stc
    pushfq
    pop rax
    mov qword ptr [rip + observer_expected_flags], rax
    mov rax, 0x1122334455667788

    mov rdx, qword ptr [rsp + 0x30]
    mov rcx, qword ptr [rsp + 0x28]
    mov r8,  qword ptr [rsp + 0x38]
    call qword ptr [rsp + 0x20]

    mov qword ptr [rip + observer_after_rax], rax
    mov qword ptr [rip + observer_after_rcx], rcx
    mov qword ptr [rip + observer_after_rdx], rdx
    mov qword ptr [rip + observer_after_r8], r8
    mov qword ptr [rip + observer_after_r9], r9
    mov qword ptr [rip + observer_after_r10], r10
    mov qword ptr [rip + observer_after_r11], r11
    mov qword ptr [rip + observer_after_rbp], rbp
    mov qword ptr [rip + observer_after_r13], r13
    pushfq
    pop rax
    mov qword ptr [rip + observer_after_flags], rax
    movdqu xmmword ptr [rip + observer_after_xmm0], xmm0
    movdqu xmmword ptr [rip + observer_after_xmm1], xmm1
    movdqu xmmword ptr [rip + observer_after_xmm2], xmm2
    movdqu xmmword ptr [rip + observer_after_xmm3], xmm3
    movdqu xmmword ptr [rip + observer_after_xmm4], xmm4
    movdqu xmmword ptr [rip + observer_after_xmm5], xmm5
    stmxcsr dword ptr [rsp + 0x58]
    mov eax, dword ptr [rsp + 0x58]
    mov dword ptr [rip + observer_after_mxcsr], eax
    fnstcw word ptr [rsp + 0x5c]
    movzx eax, word ptr [rsp + 0x5c]
    mov dword ptr [rip + observer_after_x87cw], eax
    call GetLastError
    mov dword ptr [rip + observer_after_last_error], eax

    mov ecx, dword ptr [rsp + 0x50]
    call SetLastError
    ldmxcsr dword ptr [rsp + 0x40]
    fldcw word ptr [rsp + 0x44]
    mov rbp, qword ptr [rsp + 0x70]
    mov r13, qword ptr [rsp + 0x78]
    lea rsp, [rsp + 0x98]
    push qword ptr [rsp - 0x50]
    popfq
    ret
.endm

INVOKE_VARIANT observer_invoke_a
INVOKE_VARIANT observer_invoke_b
