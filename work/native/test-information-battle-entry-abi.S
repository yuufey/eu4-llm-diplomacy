.section .rdata,"dr"
.align 4
.L_fixture_initial_mxcsr:
    .long 0x1f80
.L_fixture_initial_x87:
    .short 0x037f
.L_fixture_mutated_mxcsr:
    .long 0x9fc0
.L_fixture_mutated_x87:
    .short 0x0f7f

.align 16
.L_fixture_volatile_xmm0:
    .quad 0x8081828384858688, 0x0807060504030201
.L_fixture_volatile_xmm1:
    .quad 0x9091929394959698, 0x1817161514131211
.L_fixture_volatile_xmm2:
    .quad 0xa0a1a2a3a4a5a6a7, 0x2827262524232211
.L_fixture_volatile_xmm3:
    .quad 0xb0b1b2b3b4b5b6b7, 0x3837363534333221
.L_fixture_volatile_xmm4:
    .quad 0xc0c1c2c3c4c5c6c7, 0x4847464544434231
.L_fixture_volatile_xmm5:
    .quad 0xd0d1d2d3d4d5d6d7, 0x5857565554535241
.L_fixture_nonvolatile_xmm6:
    .quad 0xe0e1e2e3e4e5e6e7, 0xe8e7e6e5e4e3e2e1
.L_fixture_nonvolatile_xmm7:
    .quad 0xf0f1f2f3f4f5f6f7, 0xf8f7f6f5f4f3f2f1
.L_fixture_nonvolatile_xmm8:
    .quad 0x0123456789abcdef, 0x1122334455667788
.L_fixture_nonvolatile_xmm9:
    .quad 0x1021324354657687, 0x8877665544332211
.L_fixture_nonvolatile_xmm10:
    .quad 0x8899aabbccddeeff, 0x1020304050607080
.L_fixture_nonvolatile_xmm11:
    .quad 0x0f1e2d3c4b5a6978, 0x9080706050403020
.L_fixture_nonvolatile_xmm12:
    .quad 0x8877665544332211, 0x123456789abcdef0
.L_fixture_nonvolatile_xmm13:
    .quad 0x7766554433221100, 0x0fedcba987654321
.L_fixture_nonvolatile_xmm14:
    .quad 0xdeadbeefcafebabe, 0x13579bdf2468ace0
.L_fixture_nonvolatile_xmm15:
    .quad 0xfeedface12345678, 0x2468ace013579bdf

.text

.extern information_battle_entry_stub
.extern information_battle_entry_stub_pointer
.extern fixture_original_entry_flags
.extern fixture_target_call_count
.extern fixture_seen_rax
.extern fixture_seen_rcx
.extern fixture_seen_rdx
.extern fixture_seen_r8
.extern fixture_seen_r9
.extern fixture_seen_rbx
.extern fixture_seen_r10
.extern fixture_seen_r11
.extern fixture_seen_return_address
.extern fixture_seen_rsp
.extern fixture_seen_rsp_mod16
.extern fixture_seen_stack5
.extern fixture_seen_stack6
.extern fixture_seen_flags
.extern fixture_seen_mxcsr
.extern fixture_seen_x87_control
.extern fixture_seen_xmm0
.extern fixture_seen_xmm0_hi
.extern fixture_seen_xmm1
.extern fixture_seen_xmm1_hi
.extern fixture_seen_xmm2
.extern fixture_seen_xmm2_hi
.extern fixture_seen_xmm3
.extern fixture_seen_xmm3_hi
.extern fixture_seen_xmm4
.extern fixture_seen_xmm4_hi
.extern fixture_seen_xmm5
.extern fixture_seen_xmm5_hi
.extern fixture_seen_xmm6
.extern fixture_seen_xmm6_hi
.extern fixture_seen_xmm7
.extern fixture_seen_xmm7_hi
.extern fixture_seen_xmm8
.extern fixture_seen_xmm8_hi
.extern fixture_seen_xmm9
.extern fixture_seen_xmm9_hi
.extern fixture_seen_xmm10
.extern fixture_seen_xmm10_hi
.extern fixture_seen_xmm11
.extern fixture_seen_xmm11_hi
.extern fixture_seen_xmm12
.extern fixture_seen_xmm12_hi
.extern fixture_seen_xmm13
.extern fixture_seen_xmm13_hi
.extern fixture_seen_xmm14
.extern fixture_seen_xmm14_hi
.extern fixture_seen_xmm15
.extern fixture_seen_xmm15_hi
.extern fixture_expected_flags
.extern fixture_callback_mutated_flags
.extern fixture_after_rbx
.extern fixture_after_rbp
.extern fixture_after_rsi
.extern fixture_after_rdi
.extern fixture_after_r12
.extern fixture_after_r13
.extern fixture_after_r14
.extern fixture_after_r15
.extern fixture_after_xmm6
.extern fixture_after_xmm7
.extern fixture_after_xmm8
.extern fixture_after_xmm9
.extern fixture_after_xmm10
.extern fixture_after_xmm11
.extern fixture_after_xmm12
.extern fixture_after_xmm13
.extern fixture_after_xmm14
.extern fixture_after_xmm15
.extern fixture_last_return_xmm

.macro RECORD_XMM reg, low, high
    movdqu \reg, 0x40(%rsp)
    movq 0x40(%rsp), %r11
    leaq \low(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x48(%rsp), %r11
    leaq \high(%rip), %r10
    movq %r11, (%r10,%rax,8)
.endm

// The callback deliberately changes volatile GPR/XMM state, flags, MXCSR, the
// x87 control word, and LastError (the latter in C++).  The shim under test
// must restore the caller state before tail-jumping to the original.
.globl fixture_callback_mutate_volatile
.def fixture_callback_mutate_volatile; .scl 2; .type 32; .endef
.seh_proc fixture_callback_mutate_volatile
fixture_callback_mutate_volatile:
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
    movq %rax, %xmm0
    movq %rcx, %xmm1
    movq %rdx, %xmm2
    movq %r8, %xmm3
    movq %r9, %xmm4
    movq %r10, %xmm5
    ldmxcsr .L_fixture_mutated_mxcsr(%rip)
    fldcw .L_fixture_mutated_x87(%rip)
    movabs $1, %rax
    cmpq $2, %rax
    pushfq
    popq %rax
    movq %rax, fixture_callback_mutated_flags(%rip)
    addq $0x28, %rsp
    ret
.seh_endproc

// The original target records the exact entry surface after the shim's
// callback.  The fixed local frame makes the saved return address/stack args
// explicit while preserving the caller's original stack image.
.globl fixture_original_target
.def fixture_original_target; .scl 2; .type 32; .endef
.seh_proc fixture_original_target
fixture_original_target:
    pushfq
    popq fixture_original_entry_flags(%rip)
    subq $0x58, %rsp
    .seh_stackalloc 0x58
    .seh_endprologue
    movq %rax, 0x00(%rsp)
    movq %rcx, 0x08(%rsp)
    movq %rdx, 0x10(%rsp)
    movq %r8,  0x18(%rsp)
    movq %r9,  0x20(%rsp)
    movq %r10, 0x28(%rsp)
    movq %r11, 0x30(%rsp)
    movq %rbx, 0x38(%rsp)

    movl fixture_target_call_count(%rip), %eax
    cmpl $8, %eax
    jae .L_fixture_target_return

    movq 0x00(%rsp), %r11
    leaq fixture_seen_rax(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x08(%rsp), %r11
    leaq fixture_seen_rcx(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x10(%rsp), %r11
    leaq fixture_seen_rdx(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x18(%rsp), %r11
    leaq fixture_seen_r8(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x20(%rsp), %r11
    leaq fixture_seen_r9(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x28(%rsp), %r11
    leaq fixture_seen_r10(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x30(%rsp), %r11
    leaq fixture_seen_r11(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x38(%rsp), %r11
    leaq fixture_seen_rbx(%rip), %r10
    movq %r11, (%r10,%rax,8)

    movq 0x58(%rsp), %r11
    leaq fixture_seen_return_address(%rip), %r10
    movq %r11, (%r10,%rax,8)
    leaq 0x58(%rsp), %r11
    leaq fixture_seen_rsp(%rip), %r10
    movq %r11, (%r10,%rax,8)
    andq $0xf, %r11
    leaq fixture_seen_rsp_mod16(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x80(%rsp), %r11
    leaq fixture_seen_stack5(%rip), %r10
    movq %r11, (%r10,%rax,8)
    movq 0x88(%rsp), %r11
    leaq fixture_seen_stack6(%rip), %r10
    movq %r11, (%r10,%rax,8)

    movq fixture_original_entry_flags(%rip), %r11
    leaq fixture_seen_flags(%rip), %r10
    movq %r11, (%r10,%rax,8)
    leaq fixture_seen_mxcsr(%rip), %r10
    stmxcsr (%r10,%rax,4)
    leaq fixture_seen_x87_control(%rip), %r10
    fnstcw (%r10,%rax,2)

    RECORD_XMM %xmm0, fixture_seen_xmm0, fixture_seen_xmm0_hi
    RECORD_XMM %xmm1, fixture_seen_xmm1, fixture_seen_xmm1_hi
    RECORD_XMM %xmm2, fixture_seen_xmm2, fixture_seen_xmm2_hi
    RECORD_XMM %xmm3, fixture_seen_xmm3, fixture_seen_xmm3_hi
    RECORD_XMM %xmm4, fixture_seen_xmm4, fixture_seen_xmm4_hi
    RECORD_XMM %xmm5, fixture_seen_xmm5, fixture_seen_xmm5_hi
    RECORD_XMM %xmm6, fixture_seen_xmm6, fixture_seen_xmm6_hi
    RECORD_XMM %xmm7, fixture_seen_xmm7, fixture_seen_xmm7_hi
    RECORD_XMM %xmm8, fixture_seen_xmm8, fixture_seen_xmm8_hi
    RECORD_XMM %xmm9, fixture_seen_xmm9, fixture_seen_xmm9_hi
    RECORD_XMM %xmm10, fixture_seen_xmm10, fixture_seen_xmm10_hi
    RECORD_XMM %xmm11, fixture_seen_xmm11, fixture_seen_xmm11_hi
    RECORD_XMM %xmm12, fixture_seen_xmm12, fixture_seen_xmm12_hi
    RECORD_XMM %xmm13, fixture_seen_xmm13, fixture_seen_xmm13_hi
    RECORD_XMM %xmm14, fixture_seen_xmm14, fixture_seen_xmm14_hi
    RECORD_XMM %xmm15, fixture_seen_xmm15, fixture_seen_xmm15_hi
    incl %eax
    movl %eax, fixture_target_call_count(%rip)

.L_fixture_target_return:
    movabs $0x7f6e5d4c3b2a1908, %rax
    movabs $0x1234abcd5678ef90, %r11
    movq %r11, %xmm0
    addq $0x58, %rsp
    ret
.seh_endproc

// The two callers save all nonvolatile GPR/XMM state, install deterministic
// volatile markers and six/fifth stack arguments, then exercise direct versus
// indirect entry.  XMM6-XMM15 are restored before returning to the C++ test.
.macro FIXTURE_CALL_PROLOGUE name
.globl \name
.def \name; .scl 2; .type 32; .endef
.seh_proc \name
\name:
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
    movdqu .L_fixture_nonvolatile_xmm6(%rip), %xmm6
    movdqu .L_fixture_nonvolatile_xmm7(%rip), %xmm7
    movdqu .L_fixture_nonvolatile_xmm8(%rip), %xmm8
    movdqu .L_fixture_nonvolatile_xmm9(%rip), %xmm9
    movdqu .L_fixture_nonvolatile_xmm10(%rip), %xmm10
    movdqu .L_fixture_nonvolatile_xmm11(%rip), %xmm11
    movdqu .L_fixture_nonvolatile_xmm12(%rip), %xmm12
    movdqu .L_fixture_nonvolatile_xmm13(%rip), %xmm13
    movdqu .L_fixture_nonvolatile_xmm14(%rip), %xmm14
    movdqu .L_fixture_nonvolatile_xmm15(%rip), %xmm15
    movabs $0x1011121314151617, %r10
    movabs $0x18191a1b1c1d1e1f, %r11
    movabs $0x1111222233334444, %rcx
    movabs $0x2222333344445555, %rdx
    movabs $0x3333444455556666, %r8
    movabs $0x4444555566667777, %r9
    movdqu .L_fixture_volatile_xmm0(%rip), %xmm0
    movdqu .L_fixture_volatile_xmm1(%rip), %xmm1
    movdqu .L_fixture_volatile_xmm2(%rip), %xmm2
    movdqu .L_fixture_volatile_xmm3(%rip), %xmm3
    movdqu .L_fixture_volatile_xmm4(%rip), %xmm4
    movdqu .L_fixture_volatile_xmm5(%rip), %xmm5
    movabs $0x5555666677778888, %rax
    movq %rax, 0x20(%rsp)
    movabs $0x6666777788889999, %rax
    movq %rax, 0x28(%rsp)
    ldmxcsr .L_fixture_initial_mxcsr(%rip)
    fldcw .L_fixture_initial_x87(%rip)
    movabs $0xaaaabbbbccccdddd, %rax
    cmpq $2, %rax
    pushfq
    popq %rax
    movq %rax, fixture_expected_flags(%rip)
    movabs $0xaaaabbbbccccdddd, %rax
.endm

.macro FIXTURE_CALL_EPILOGUE
    movq %xmm0, %r10
    movq %r10, fixture_last_return_xmm(%rip)
    movq %rbx, fixture_after_rbx(%rip)
    movq %rbp, fixture_after_rbp(%rip)
    movq %rsi, fixture_after_rsi(%rip)
    movq %rdi, fixture_after_rdi(%rip)
    movq %r12, fixture_after_r12(%rip)
    movq %r13, fixture_after_r13(%rip)
    movq %r14, fixture_after_r14(%rip)
    movq %r15, fixture_after_r15(%rip)
    movq %xmm6, %r10
    movq %r10, fixture_after_xmm6(%rip)
    movq %xmm7, %r10
    movq %r10, fixture_after_xmm7(%rip)
    movq %xmm8, %r10
    movq %r10, fixture_after_xmm8(%rip)
    movq %xmm9, %r10
    movq %r10, fixture_after_xmm9(%rip)
    movq %xmm10, %r10
    movq %r10, fixture_after_xmm10(%rip)
    movq %xmm11, %r10
    movq %r10, fixture_after_xmm11(%rip)
    movq %xmm12, %r10
    movq %r10, fixture_after_xmm12(%rip)
    movq %xmm13, %r10
    movq %r10, fixture_after_xmm13(%rip)
    movq %xmm14, %r10
    movq %r10, fixture_after_xmm14(%rip)
    movq %xmm15, %r10
    movq %r10, fixture_after_xmm15(%rip)
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
.endm

FIXTURE_CALL_PROLOGUE fixture_call_direct
    call information_battle_entry_stub
    FIXTURE_CALL_EPILOGUE
.seh_endproc

FIXTURE_CALL_PROLOGUE fixture_call_indirect
    call *information_battle_entry_stub_pointer(%rip)
    FIXTURE_CALL_EPILOGUE
.seh_endproc
