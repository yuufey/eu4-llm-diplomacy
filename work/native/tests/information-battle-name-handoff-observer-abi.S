.intel_syntax noprefix
.text

.extern GetLastError
.extern SetLastError

.extern observer_capture_dest
.extern observer_capture_key
.extern observer_capture_value
.extern observer_capture_return_pc
.extern observer_capture_rbp
.extern observer_capture_rsp
.extern observer_capture_rsp_value
.extern observer_capture_dest_word0
.extern observer_capture_dest_word1
.extern observer_capture_last_error
.extern observer_capture_hits

.extern observer_native_rcx
.extern observer_native_rdx
.extern observer_native_r8
.extern observer_native_r9
.extern observer_native_r10
.extern observer_native_r11
.extern observer_native_rax
.extern observer_native_rbp
.extern observer_native_rbx
.extern observer_native_rsi
.extern observer_native_rdi
.extern observer_native_r12
.extern observer_native_r13
.extern observer_native_r14
.extern observer_native_r15
.extern observer_native_flags
.extern observer_native_mxcsr
.extern observer_native_x87cw
.extern observer_native_last_error
.extern observer_native_xmm0
.extern observer_native_xmm1
.extern observer_native_xmm2
.extern observer_native_xmm3
.extern observer_native_xmm4
.extern observer_native_xmm5
.extern observer_native_entry_rsp
.extern observer_native_return_slot
.extern observer_native_home0
.extern observer_native_home1
.extern observer_native_home2
.extern observer_native_home3
.extern observer_expected_flags
.extern observer_expected_original_rsp
.extern observer_expected_return_pc
.extern observer_invoke_return_rax
.extern observer_invoke_home0
.extern observer_invoke_home1
.extern observer_invoke_home2
.extern observer_invoke_home3

.globl information_battle_name_handoff_capture
.p2align 4
information_battle_name_handoff_capture:
    # Six-argument Win64 callback:
    # RCX=dest, RDX=key, R8=value, R9=return_pc,
    # [RSP+0x28]=original_rbp, [RSP+0x30]=original entry RSP.
    mov qword ptr [rip + observer_capture_dest], rcx
    mov qword ptr [rip + observer_capture_key], rdx
    mov qword ptr [rip + observer_capture_value], r8
    mov qword ptr [rip + observer_capture_return_pc], r9
    mov rax, qword ptr [rsp + 0x28]
    mov qword ptr [rip + observer_capture_rbp], rax
    mov rax, qword ptr [rsp + 0x30]
    mov qword ptr [rip + observer_capture_rsp], rax
    mov r10, qword ptr [rax]
    mov qword ptr [rip + observer_capture_rsp_value], r10
    mov rax, qword ptr [rcx]
    mov qword ptr [rip + observer_capture_dest_word0], rax
    mov rax, qword ptr [rcx + 8]
    mov qword ptr [rip + observer_capture_dest_word1], rax
    mov dword ptr [rip + observer_capture_hits], 1

    # Deliberately damage volatile and saved GPRs plus volatile FP state.  The
    # observer stub must restore the exact hook-entry state before tail-jumping.
    mov rax, 0x0a0b0c0d0e0f1011
    mov rcx, 0x1a1b1c1d1e1f2021
    mov rdx, 0x2a2b2c2d2e2f3031
    mov r8,  0x3a3b3c3d3e3f4041
    mov r9,  0x4a4b4c4d4e4f5051
    mov r10, 0x5a5b5c5d5e5f6061
    mov r11, 0x6a6b6c6d6e5f7071
    mov rbx, 0x7a7b7c7d7e7f8081
    mov rbp, 0x8a8b8c8d8e8f9091
    mov rsi, 0x9a9b9c9d9e9fa0a1
    mov rdi, 0xaaabacadaeafb0b1
    mov r12, 0xbabbbcbdbebfc0c1
    mov r13, 0xcacbcccdcecfd0d1
    mov r14, 0xdadbdcdddedfe0e1
    mov r15, 0xeaebecedeeeff001
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
    call GetLastError
    mov dword ptr [rip + observer_capture_last_error], eax
    add rsp, 0x28
    xor eax, eax
    ret

.globl information_battle_name_handoff_fake_original
.p2align 4
information_battle_name_handoff_fake_original:
    # This is the owned fixture's fake native callee.  Record entry state
    # before any instruction that can change flags or invoke another function.
    mov qword ptr [rip + observer_native_rcx], rcx
    mov qword ptr [rip + observer_native_rdx], rdx
    mov qword ptr [rip + observer_native_r8], r8
    mov qword ptr [rip + observer_native_r9], r9
    mov qword ptr [rip + observer_native_r10], r10
    mov qword ptr [rip + observer_native_r11], r11
    mov qword ptr [rip + observer_native_rax], rax
    mov qword ptr [rip + observer_native_rbp], rbp
    mov qword ptr [rip + observer_native_rbx], rbx
    mov qword ptr [rip + observer_native_rsi], rsi
    mov qword ptr [rip + observer_native_rdi], rdi
    mov qword ptr [rip + observer_native_r12], r12
    mov qword ptr [rip + observer_native_r13], r13
    mov qword ptr [rip + observer_native_r14], r14
    mov qword ptr [rip + observer_native_r15], r15
    pushfq
    pop rax
    mov qword ptr [rip + observer_native_flags], rax
    movdqu xmmword ptr [rip + observer_native_xmm0], xmm0
    movdqu xmmword ptr [rip + observer_native_xmm1], xmm1
    movdqu xmmword ptr [rip + observer_native_xmm2], xmm2
    movdqu xmmword ptr [rip + observer_native_xmm3], xmm3
    movdqu xmmword ptr [rip + observer_native_xmm4], xmm4
    movdqu xmmword ptr [rip + observer_native_xmm5], xmm5
    stmxcsr dword ptr [rip + observer_native_mxcsr]
    fnstcw word ptr [rip + observer_native_x87cw]
    mov rax, rsp
    mov qword ptr [rip + observer_native_entry_rsp], rax
    mov rax, qword ptr [rsp]
    mov qword ptr [rip + observer_native_return_slot], rax
    mov rax, qword ptr [rsp + 0x08]
    mov qword ptr [rip + observer_native_home0], rax
    mov rax, qword ptr [rsp + 0x10]
    mov qword ptr [rip + observer_native_home1], rax
    mov rax, qword ptr [rsp + 0x18]
    mov qword ptr [rip + observer_native_home2], rax
    mov rax, qword ptr [rsp + 0x20]
    mov qword ptr [rip + observer_native_home3], rax

    sub rsp, 0x28
    call GetLastError
    mov dword ptr [rip + observer_native_last_error], eax
    add rsp, 0x28

    # Model the fixed native callee's post-hook construction of the destination.
    mov rcx, qword ptr [rip + observer_native_rcx]
    mov rdx, qword ptr [rip + observer_native_rdx]
    mov r8, qword ptr [rip + observer_native_r8]
    mov qword ptr [rcx], rdx
    mov qword ptr [rcx + 8], r8
    mov rax, rcx
    ret

.globl information_battle_name_handoff_invoke
.def information_battle_name_handoff_invoke; .scl 2; .type 32; .endef
.p2align 4
information_battle_name_handoff_invoke:
    # R1=target, R2=dest, R3=key, R4=value.  The first 32 bytes below RSP
    # become the target's caller-home area and are populated with sentinels.
    sub rsp, 0x98
    mov qword ptr [rsp + 0x20], rcx
    mov qword ptr [rsp + 0x28], rdx
    mov qword ptr [rsp + 0x30], r8
    mov qword ptr [rsp + 0x38], r9
    mov qword ptr [rsp + 0x40], rbx
    mov qword ptr [rsp + 0x48], rbp
    mov qword ptr [rsp + 0x50], rsi
    mov qword ptr [rsp + 0x58], rdi
    mov qword ptr [rsp + 0x60], r12
    mov qword ptr [rsp + 0x68], r13
    mov qword ptr [rsp + 0x70], r14
    mov qword ptr [rsp + 0x78], r15
    stmxcsr dword ptr [rsp + 0x88]
    fnstcw word ptr [rsp + 0x8c]
    mov rax, 0x1111111111111111
    mov qword ptr [rsp + 0x00], rax
    mov rax, 0x2222222222222222
    mov qword ptr [rsp + 0x08], rax
    mov rax, 0x3333333333333333
    mov qword ptr [rsp + 0x10], rax
    mov rax, 0x4444444444444444
    mov qword ptr [rsp + 0x18], rax

    mov rbx, 0x0102030405060708
    mov rbp, 0x7172737475767778
    mov rsi, 0x1112131415161718
    mov rdi, 0x2122232425262728
    mov r12, 0x3132333435363738
    mov r13, 0x4142434445464748
    mov r14, 0x5152535455565758
    mov r15, 0x6162636465666768
    mov r10, 0x2233445566778899
    mov r11, 0x33445566778899aa

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
    mov dword ptr [rsp + 0x80], 0x00001f40
    ldmxcsr dword ptr [rsp + 0x80]
    mov word ptr [rsp + 0x84], 0x037f
    fldcw word ptr [rsp + 0x84]

    lea rax, [rsp - 8]
    mov qword ptr [rip + observer_expected_original_rsp], rax
    lea rax, [rip + information_battle_name_handoff_after_call]
    mov qword ptr [rip + observer_expected_return_pc], rax

    # Establish ZF=1/CF=1 last.  MOV/LEA/CALL below leave flags unchanged.
    xor eax, eax
    stc
    pushfq
    pop qword ptr [rip + observer_expected_flags]
    mov rax, 0x1122334455667788
    mov rcx, qword ptr [rsp + 0x28]
    mov rdx, qword ptr [rsp + 0x30]
    mov r8, qword ptr [rsp + 0x38]
    mov r9, 0x99aabbccddeeff00
    call qword ptr [rsp + 0x20]
.globl information_battle_name_handoff_after_call
information_battle_name_handoff_after_call:
    mov qword ptr [rip + observer_invoke_return_rax], rax
    mov rax, qword ptr [rsp + 0x00]
    mov qword ptr [rip + observer_invoke_home0], rax
    mov rax, qword ptr [rsp + 0x08]
    mov qword ptr [rip + observer_invoke_home1], rax
    mov rax, qword ptr [rsp + 0x10]
    mov qword ptr [rip + observer_invoke_home2], rax
    mov rax, qword ptr [rsp + 0x18]
    mov qword ptr [rip + observer_invoke_home3], rax

    ldmxcsr dword ptr [rsp + 0x88]
    fldcw word ptr [rsp + 0x8c]
    mov rbx, qword ptr [rsp + 0x40]
    mov rbp, qword ptr [rsp + 0x48]
    mov rsi, qword ptr [rsp + 0x50]
    mov rdi, qword ptr [rsp + 0x58]
    mov r12, qword ptr [rsp + 0x60]
    mov r13, qword ptr [rsp + 0x68]
    mov r14, qword ptr [rsp + 0x70]
    mov r15, qword ptr [rsp + 0x78]
    add rsp, 0x98
    ret
