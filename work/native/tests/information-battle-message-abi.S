.section .rdata,"dr"
.align 16
.L_message_volatile_xmm0:
    .quad 0x8081828384858688, 0x0807060504030201
.L_message_volatile_xmm1:
    .quad 0x9091929394959698, 0x1817161514131211
.L_message_volatile_xmm2:
    .quad 0xa0a1a2a3a4a5a6a7, 0x2827262524232211
.L_message_volatile_xmm3:
    .quad 0xb0b1b2b3b4b5b6b7, 0x3837363534333221
.L_message_volatile_xmm4:
    .quad 0xc0c1c2c3c4c5c6c7, 0x4847464544434231
.L_message_volatile_xmm5:
    .quad 0xd0d1d2d3d4d5d6d7, 0x5857565554535241
.L_message_nonvolatile_xmm6:
    .quad 0xe0e1e2e3e4e5e6e7, 0xe8e7e6e5e4e3e2e1
.L_message_nonvolatile_xmm7:
    .quad 0xf0f1f2f3f4f5f6f7, 0xf8f7f6f5f4f3f2f1
.L_message_nonvolatile_xmm8:
    .quad 0x0123456789abcdef, 0x1122334455667788
.L_message_nonvolatile_xmm9:
    .quad 0x1021324354657687, 0x8877665544332211
.L_message_nonvolatile_xmm10:
    .quad 0x8899aabbccddeeff, 0x1020304050607080
.L_message_nonvolatile_xmm11:
    .quad 0x0f1e2d3c4b5a6978, 0x9080706050403020
.L_message_nonvolatile_xmm12:
    .quad 0x8877665544332211, 0x123456789abcdef0
.L_message_nonvolatile_xmm13:
    .quad 0x7766554433221100, 0x0fedcba987654321
.L_message_nonvolatile_xmm14:
    .quad 0xdeadbeefcafebabe, 0x13579bdf2468ace0
.L_message_nonvolatile_xmm15:
    .quad 0xfeedface12345678, 0x2468ace013579bdf
.L_message_return_xmm0:
    .quad 0x1234abcd5678ef90, 0xfedcba9876543210
.L_message_initial_mxcsr:
    .long 0x1f80
.L_message_initial_x87:
    .short 0x037f
.L_message_mutated_mxcsr:
    .long 0x9fc0
.L_message_mutated_x87:
    .short 0x0f7f

.text

.extern GetLastError
.extern information_battle_message_hook
.extern fixture_message_capture_mutate
.extern fixture_msg_original_call_count
.extern fixture_msg_original_manager
.extern fixture_msg_original_message
.extern fixture_msg_original_context
.extern fixture_msg_original_callback
.extern fixture_msg_original_rax
.extern fixture_msg_original_r10
.extern fixture_msg_original_r11
.extern fixture_msg_original_rbp
.extern fixture_msg_original_return
.extern fixture_msg_original_rsp
.extern fixture_msg_original_rsp_mod16
.extern fixture_msg_original_stack5
.extern fixture_msg_original_stack6
.extern fixture_msg_original_flags
.extern fixture_msg_original_mxcsr
.extern fixture_msg_original_x87
.extern fixture_msg_original_xmm0
.extern fixture_msg_original_xmm1
.extern fixture_msg_original_xmm2
.extern fixture_msg_original_xmm3
.extern fixture_msg_original_xmm4
.extern fixture_msg_original_xmm5
.extern fixture_msg_original_last_error
.extern fixture_msg_return_rax
.extern fixture_msg_return_xmm0
.extern fixture_msg_after_rbx
.extern fixture_msg_after_rbp
.extern fixture_msg_after_rsi
.extern fixture_msg_after_rdi
.extern fixture_msg_after_r12
.extern fixture_msg_after_r13
.extern fixture_msg_after_r14
.extern fixture_msg_after_r15
.extern fixture_msg_after_xmm6
.extern fixture_msg_after_xmm7
.extern fixture_msg_after_xmm8
.extern fixture_msg_after_xmm9
.extern fixture_msg_after_xmm10
.extern fixture_msg_after_xmm11
.extern fixture_msg_after_xmm12
.extern fixture_msg_after_xmm13
.extern fixture_msg_after_xmm14
.extern fixture_msg_after_xmm15
.extern fixture_msg_after_stack5
.extern fixture_msg_after_stack6
.extern fixture_msg_expected_flags

.macro STORE_XMM reg, symbol
    movdqu \reg, \symbol(%rip)
.endm

.macro LOAD_XMM reg, symbol
    movdqu \symbol(%rip), \reg
.endm

// The callback deliberately changes volatile registers, vector state, flags,
// and both floating-point control words.  The production message shim must
// restore all of this before it tail-jumps to the native original.
.globl fixture_message_capture_mutate
.def fixture_message_capture_mutate; .scl 2; .type 32; .endef
.seh_proc fixture_message_capture_mutate
fixture_message_capture_mutate:
    subq $0x28, %rsp
    .seh_stackalloc 0x28
    .seh_endprologue
    movabs $0xdead000000000001, %rax
    movabs $0xdead000000000002, %rcx
    movabs $0xdead000000000003, %rdx
    movabs $0xdead000000000004, %r8
    movabs $0xdead000000000005, %r9
    movabs $0xdead000000000006, %r10
    movabs $0xdead000000000007, %r11
    LOAD_XMM %xmm0, .L_message_volatile_xmm0
    LOAD_XMM %xmm1, .L_message_volatile_xmm1
    LOAD_XMM %xmm2, .L_message_volatile_xmm2
    LOAD_XMM %xmm3, .L_message_volatile_xmm3
    LOAD_XMM %xmm4, .L_message_volatile_xmm4
    LOAD_XMM %xmm5, .L_message_volatile_xmm5
    ldmxcsr .L_message_mutated_mxcsr(%rip)
    fldcw .L_message_mutated_x87(%rip)
    movabs $1, %rax
    cmpq $2, %rax
    addq $0x28, %rsp
    ret
.seh_endproc

// The native original is reached by the production shim's tail jump.  It
// records every original argument before returning a deterministic value.
.globl fixture_message_original
.def fixture_message_original; .scl 2; .type 32; .endef
.seh_proc fixture_message_original
fixture_message_original:
    movq %rax, fixture_msg_original_rax(%rip)
    movq %rcx, fixture_msg_original_manager(%rip)
    movq %rdx, fixture_msg_original_message(%rip)
    movq %r8, fixture_msg_original_context(%rip)
    movq %r9, fixture_msg_original_callback(%rip)
    movq %r10, fixture_msg_original_r10(%rip)
    movq %r11, fixture_msg_original_r11(%rip)
    movq %rbp, fixture_msg_original_rbp(%rip)
    movq (%rsp), %rax
    movq %rax, fixture_msg_original_return(%rip)
    movq %rsp, fixture_msg_original_rsp(%rip)
    pushfq
    popq %rax
    movq %rax, fixture_msg_original_flags(%rip)
    movq %rsp, %rax
    movq %rax, fixture_msg_original_rsp_mod16(%rip)
    andq $0xf, fixture_msg_original_rsp_mod16(%rip)
    movq 0x28(%rsp), %rax
    movq %rax, fixture_msg_original_stack5(%rip)
    movq 0x30(%rsp), %rax
    movq %rax, fixture_msg_original_stack6(%rip)
    stmxcsr fixture_msg_original_mxcsr(%rip)
    fnstcw fixture_msg_original_x87(%rip)
    STORE_XMM %xmm0, fixture_msg_original_xmm0
    STORE_XMM %xmm1, fixture_msg_original_xmm1
    STORE_XMM %xmm2, fixture_msg_original_xmm2
    STORE_XMM %xmm3, fixture_msg_original_xmm3
    STORE_XMM %xmm4, fixture_msg_original_xmm4
    STORE_XMM %xmm5, fixture_msg_original_xmm5
    subq $0x28, %rsp
    call GetLastError
    addq $0x28, %rsp
    movl %eax, fixture_msg_original_last_error(%rip)
    movl fixture_msg_original_call_count(%rip), %eax
    incl %eax
    movl %eax, fixture_msg_original_call_count(%rip)
    movabs $0x7f6e5d4c3b2a1908, %rax
    LOAD_XMM %xmm0, .L_message_return_xmm0
    ret
.seh_endproc

// Caller fixture: preserve all nonvolatile state, install the four native
// message arguments plus two stack arguments, and call the actual production
// message hook.  The original is tail-called, so its return address and stack
// canaries must remain those of this call site.
.globl fixture_message_call
.globl fixture_message_call_after
.def fixture_message_call; .scl 2; .type 32; .endef
.seh_proc fixture_message_call
fixture_message_call:
    pushq %r15
    .seh_pushreg %r15
    pushq %r14
    .seh_pushreg %r14
    pushq %r13
    .seh_pushreg %r13
    pushq %r12
    .seh_pushreg %r12
    pushq %rdi
    .seh_pushreg %rdi
    pushq %rsi
    .seh_pushreg %rsi
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rbp
    .seh_pushreg %rbp
    subq $0x208, %rsp
    .seh_stackalloc 0x208
    .seh_endprologue
    movdqu %xmm6, 0x100(%rsp)
    movdqu %xmm7, 0x110(%rsp)
    movdqu %xmm8, 0x120(%rsp)
    movdqu %xmm9, 0x130(%rsp)
    movdqu %xmm10, 0x140(%rsp)
    movdqu %xmm11, 0x150(%rsp)
    movdqu %xmm12, 0x160(%rsp)
    movdqu %xmm13, 0x170(%rsp)
    movdqu %xmm14, 0x180(%rsp)
    movdqu %xmm15, 0x190(%rsp)
    movabs $0x0102030405060708, %rbx
    movabs $0x1112131415161718, %rbp
    movabs $0x2122232425262728, %rsi
    movabs $0x3132333435363738, %rdi
    movabs $0x4142434445464748, %r12
    movabs $0x5152535455565758, %r13
    movabs $0x6162636465666768, %r14
    movabs $0x7172737475767878, %r15
    LOAD_XMM %xmm6, .L_message_nonvolatile_xmm6
    LOAD_XMM %xmm7, .L_message_nonvolatile_xmm7
    LOAD_XMM %xmm8, .L_message_nonvolatile_xmm8
    LOAD_XMM %xmm9, .L_message_nonvolatile_xmm9
    LOAD_XMM %xmm10, .L_message_nonvolatile_xmm10
    LOAD_XMM %xmm11, .L_message_nonvolatile_xmm11
    LOAD_XMM %xmm12, .L_message_nonvolatile_xmm12
    LOAD_XMM %xmm13, .L_message_nonvolatile_xmm13
    LOAD_XMM %xmm14, .L_message_nonvolatile_xmm14
    LOAD_XMM %xmm15, .L_message_nonvolatile_xmm15
    movabs $0x1011121314151617, %r10
    movabs $0x18191a1b1c1d1e1f, %r11
    movabs $0x1111222233334444, %rcx
    movabs $0x2222333344445555, %rdx
    movabs $0x3333444455556666, %r8
    movabs $0x4444555566667777, %r9
    LOAD_XMM %xmm0, .L_message_volatile_xmm0
    LOAD_XMM %xmm1, .L_message_volatile_xmm1
    LOAD_XMM %xmm2, .L_message_volatile_xmm2
    LOAD_XMM %xmm3, .L_message_volatile_xmm3
    LOAD_XMM %xmm4, .L_message_volatile_xmm4
    LOAD_XMM %xmm5, .L_message_volatile_xmm5
    movabs $0x5555666677778888, %rax
    movq %rax, 0x20(%rsp)
    movabs $0x6666777788889999, %rax
    movq %rax, 0x28(%rsp)
    ldmxcsr .L_message_initial_mxcsr(%rip)
    fldcw .L_message_initial_x87(%rip)
    movabs $0xaaaabbbbccccdddd, %rax
    cmpq $2, %rax
    pushfq
    popq fixture_msg_expected_flags(%rip)
    movabs $0xaaaabbbbccccdddd, %rax
    call information_battle_message_hook
fixture_message_call_after:
    movq %rax, fixture_msg_return_rax(%rip)
    STORE_XMM %xmm0, fixture_msg_return_xmm0
    movq 0x20(%rsp), %rax
    movq %rax, fixture_msg_after_stack5(%rip)
    movq 0x28(%rsp), %rax
    movq %rax, fixture_msg_after_stack6(%rip)
    movq %rbx, fixture_msg_after_rbx(%rip)
    movq %rbp, fixture_msg_after_rbp(%rip)
    movq %rsi, fixture_msg_after_rsi(%rip)
    movq %rdi, fixture_msg_after_rdi(%rip)
    movq %r12, fixture_msg_after_r12(%rip)
    movq %r13, fixture_msg_after_r13(%rip)
    movq %r14, fixture_msg_after_r14(%rip)
    movq %r15, fixture_msg_after_r15(%rip)
    STORE_XMM %xmm6, fixture_msg_after_xmm6
    STORE_XMM %xmm7, fixture_msg_after_xmm7
    STORE_XMM %xmm8, fixture_msg_after_xmm8
    STORE_XMM %xmm9, fixture_msg_after_xmm9
    STORE_XMM %xmm10, fixture_msg_after_xmm10
    STORE_XMM %xmm11, fixture_msg_after_xmm11
    STORE_XMM %xmm12, fixture_msg_after_xmm12
    STORE_XMM %xmm13, fixture_msg_after_xmm13
    STORE_XMM %xmm14, fixture_msg_after_xmm14
    STORE_XMM %xmm15, fixture_msg_after_xmm15
    movdqu 0x100(%rsp), %xmm6
    movdqu 0x110(%rsp), %xmm7
    movdqu 0x120(%rsp), %xmm8
    movdqu 0x130(%rsp), %xmm9
    movdqu 0x140(%rsp), %xmm10
    movdqu 0x150(%rsp), %xmm11
    movdqu 0x160(%rsp), %xmm12
    movdqu 0x170(%rsp), %xmm13
    movdqu 0x180(%rsp), %xmm14
    movdqu 0x190(%rsp), %xmm15
    addq $0x208, %rsp
    popq %rbp
    popq %rbx
    popq %rsi
    popq %rdi
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    ret
.seh_endproc
