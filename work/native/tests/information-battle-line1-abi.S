.intel_syntax noprefix
.text

.extern GetLastError
.extern SetLastError
.extern g_line1_capture_widget
.extern g_line1_capture_text
.extern g_line1_capture_flag
.extern g_line1_capture_return
.extern g_line1_capture_rbp
.extern g_line1_after_rax
.extern g_line1_after_rcx
.extern g_line1_after_rdx
.extern g_line1_after_r8
.extern g_line1_after_r9
.extern g_line1_after_r10
.extern g_line1_after_r11
.extern g_line1_after_rbp
.extern g_line1_after_flags
.extern g_line1_after_mxcsr
.extern g_line1_after_x87cw
.extern g_line1_after_last_error
.extern g_line1_after_xmm0
.extern g_line1_after_xmm1
.extern g_line1_after_xmm2
.extern g_line1_after_xmm3
.extern g_line1_after_xmm4
.extern g_line1_after_xmm5
.extern g_line1_expected_flags

.globl line1_capture_clobber
.p2align 4
line1_capture_clobber:
    # callback(widget, string32, flag, original_return, original_rbp)
    # Record all arguments before deliberately clobbering volatile state.
    mov qword ptr [rip + g_line1_capture_widget], rcx
    mov qword ptr [rip + g_line1_capture_text], rdx
    mov byte ptr [rip + g_line1_capture_flag], r8b
    mov qword ptr [rip + g_line1_capture_return], r9
    mov rax, qword ptr [rsp + 0x28]
    mov qword ptr [rip + g_line1_capture_rbp], rax

    # Volatile GPR/XMM state and both floating-point control words are changed
    # on purpose.  The hook must restore the caller state around this callback.
    mov rax, 0x0a0b0c0d0e0f1011
    mov rcx, 0x1a1b1c1d1e1f2021
    mov rdx, 0x2a2b2c2d2e2f3031
    mov r8,  0x3a3b3c3d3e3f4041
    mov r9,  0x4a4b4c4d4e4f5051
    mov r10, 0x5a5b5c5d5e5f6061
    mov r11, 0x6a6b6c6d6e6f7071
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

.macro INVOKE_VARIANT name
.globl \name
.p2align 4
\name:
    # R1=target, R2=widget, R3=string32, R4=flag in the Win64 ABI.
    # Reserve shadow space plus scratch and keep RSP 16-byte aligned before
    # every call.  The target call itself is memory-indirect so no volatile
    # register is consumed by the dispatch.
    sub rsp, 0x98
    mov qword ptr [rsp + 0x20], rcx
    mov qword ptr [rsp + 0x28], rdx
    mov qword ptr [rsp + 0x30], r8
    mov qword ptr [rsp + 0x38], r9
    mov dword ptr [rsp + 0x40], 0
    stmxcsr dword ptr [rsp + 0x40]
    fnstcw word ptr [rsp + 0x44]
    pushfq
    pop rax
    mov qword ptr [rsp + 0x48], rax
    call GetLastError
    mov dword ptr [rsp + 0x50], eax
    mov qword ptr [rsp + 0x70], rbp
    mov ecx, 0x13572468
    call SetLastError

    # Set a known callback-visible volatile state.  The flag itself remains
    # an original third setter argument in R8; R9 is intentionally unrelated.
    mov rbp, 0x7172737475767778
    mov r10, 0x2233445566778899
    mov r11, 0x33445566778899aa
    mov r9,  0x99aabbccddeeff00
    mov rax, 0x1122334455667788
    mov rdx, qword ptr [rsp + 0x30]
    mov rcx, qword ptr [rsp + 0x28]
    mov r8,  qword ptr [rsp + 0x38]

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

    # ZF=1 and CF=1 are the expected pre-hook flags.  MOVs below do not alter
    # them, and the hook records this value before entering its trampoline.
    xor eax, eax
    mov rax, 0x1122334455667788
    stc
    pushfq
    pop rax
    mov qword ptr [rip + g_line1_expected_flags], rax
    mov rax, 0x1122334455667788

    call qword ptr [rsp + 0x20]

    mov qword ptr [rip + g_line1_after_rax], rax
    mov qword ptr [rip + g_line1_after_rcx], rcx
    mov qword ptr [rip + g_line1_after_rdx], rdx
    mov qword ptr [rip + g_line1_after_r8], r8
    mov qword ptr [rip + g_line1_after_r9], r9
    mov qword ptr [rip + g_line1_after_r10], r10
    mov qword ptr [rip + g_line1_after_r11], r11
    mov qword ptr [rip + g_line1_after_rbp], rbp
    pushfq
    pop rax
    mov qword ptr [rip + g_line1_after_flags], rax
    movdqu xmmword ptr [rip + g_line1_after_xmm0], xmm0
    movdqu xmmword ptr [rip + g_line1_after_xmm1], xmm1
    movdqu xmmword ptr [rip + g_line1_after_xmm2], xmm2
    movdqu xmmword ptr [rip + g_line1_after_xmm3], xmm3
    movdqu xmmword ptr [rip + g_line1_after_xmm4], xmm4
    movdqu xmmword ptr [rip + g_line1_after_xmm5], xmm5
    stmxcsr dword ptr [rsp + 0x58]
    mov eax, dword ptr [rsp + 0x58]
    mov dword ptr [rip + g_line1_after_mxcsr], eax
    fnstcw word ptr [rsp + 0x5c]
    movzx eax, word ptr [rsp + 0x5c]
    mov dword ptr [rip + g_line1_after_x87cw], eax
    call GetLastError
    mov dword ptr [rip + g_line1_after_last_error], eax

    # Restore this helper's caller state; the target-state observations above
    # are already stored.  The outer flags are restored after the stack add.
    mov ecx, dword ptr [rsp + 0x50]
    call SetLastError
    ldmxcsr dword ptr [rsp + 0x40]
    fldcw word ptr [rsp + 0x44]
    mov rbp, qword ptr [rsp + 0x70]
    add rsp, 0x98
    push qword ptr [rsp - 0x50]
    popfq
    ret
.endm

INVOKE_VARIANT line1_invoke_hook_a
INVOKE_VARIANT line1_invoke_hook_b

