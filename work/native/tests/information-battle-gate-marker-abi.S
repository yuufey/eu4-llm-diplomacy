.section .rdata,"dr"
.align 16
.L_gate_xmm0:
    .quad 0x0102030405060708, 0x1112131415161718
.L_gate_xmm1:
    .quad 0x2122232425262728, 0x3132333435363738
.L_gate_xmm2:
    .quad 0x4142434445464748, 0x5152535455565758
.L_gate_xmm3:
    .quad 0x6162636465666768, 0x7172737475767878
.L_gate_xmm4:
    .quad 0x8182838485868788, 0x9192939495969798
.L_gate_xmm5:
    .quad 0xa1a2a3a4a5a6a7a8, 0xb1b2b3b4b5b6b7b8
.L_gate_mutated_xmm0:
    .quad 0xd0d1d2d3d4d5d6d7, 0x0807060504030201
.L_gate_mutated_xmm1:
    .quad 0xc0c1c2c3c4c5c6c7, 0x1817161514131211
.L_gate_mutated_xmm2:
    .quad 0xb0b1b2b3b4b5b6b7, 0x2827262524232221
.L_gate_mutated_xmm3:
    .quad 0xa0a1a2a3a4a5a6a7, 0x3837363534333221
.L_gate_mutated_xmm4:
    .quad 0x9091929394959698, 0x4847464544434231
.L_gate_mutated_xmm5:
    .quad 0x8081828384858688, 0x5857565554535241
.L_gate_return_xmm0:
    .quad 0x1234abcd5678ef90, 0xfedcba9876543210
.L_gate_initial_mxcsr:
    .long 0x1f80
.L_gate_initial_x87:
    .short 0x037f
.L_gate_mutated_mxcsr:
    .long 0x9fc0
.L_gate_mutated_x87:
    .short 0x0f7f

.text
.extern GetLastError
.extern information_battle_gate_marker_hook
.extern fixture_gate_callback_expected_flags
.extern fixture_gate_marker_expected_rsp
.extern fixture_gate_mutation_calls
.extern fixture_gate_marker_original_calls
.extern fixture_gate_original_rax
.extern fixture_gate_original_rbx
.extern fixture_gate_original_rcx
.extern fixture_gate_original_rdx
.extern fixture_gate_original_rsi
.extern fixture_gate_original_rdi
.extern fixture_gate_original_rbp
.extern fixture_gate_original_r8
.extern fixture_gate_original_r9
.extern fixture_gate_original_r10
.extern fixture_gate_original_r11
.extern fixture_gate_original_r12
.extern fixture_gate_original_r13
.extern fixture_gate_original_r14
.extern fixture_gate_original_r15
.extern fixture_gate_original_rsp
.extern fixture_gate_original_return_pc
.extern fixture_gate_original_rflags
.extern fixture_gate_original_mxcsr
.extern fixture_gate_original_x87
.extern fixture_gate_original_last_error
.extern fixture_gate_original_xmm0
.extern fixture_gate_original_xmm1
.extern fixture_gate_original_xmm2
.extern fixture_gate_original_xmm3
.extern fixture_gate_original_xmm4
.extern fixture_gate_original_xmm5
.extern fixture_gate_marker_return_rax
.extern fixture_gate_marker_return_xmm0
.extern fixture_gate_marker_after_rbp

.macro STORE_XMM reg, symbol
    movdqu \reg, \symbol(%rip)
.endm

.macro LOAD_XMM reg, symbol
    movdqu \symbol(%rip), \reg
.endm

// The helper only damages volatile state, as a Win64 callback is allowed to.
.globl fixture_gate_marker_mutate
.def fixture_gate_marker_mutate; .scl 2; .type 32; .endef
.seh_proc fixture_gate_marker_mutate
fixture_gate_marker_mutate:
    .seh_endprologue
    movabs $0xdead000000000001, %rax
    movabs $0xdead000000000002, %rcx
    movabs $0xdead000000000003, %rdx
    movabs $0xdead000000000004, %r8
    movabs $0xdead000000000005, %r9
    movabs $0xdead000000000006, %r10
    movabs $0xdead000000000007, %r11
    LOAD_XMM %xmm0, .L_gate_mutated_xmm0
    LOAD_XMM %xmm1, .L_gate_mutated_xmm1
    LOAD_XMM %xmm2, .L_gate_mutated_xmm2
    LOAD_XMM %xmm3, .L_gate_mutated_xmm3
    LOAD_XMM %xmm4, .L_gate_mutated_xmm4
    LOAD_XMM %xmm5, .L_gate_mutated_xmm5
    ldmxcsr .L_gate_mutated_mxcsr(%rip)
    fldcw .L_gate_mutated_x87(%rip)
    movabs $1, %rax
    cmpq $2, %rax
    ret
.seh_endproc

// Set distinctive incoming state and call the actual production marker hook.
.globl fixture_gate_marker_call
.globl fixture_gate_marker_call_after
.def fixture_gate_marker_call; .scl 2; .type 32; .endef
.seh_proc fixture_gate_marker_call
fixture_gate_marker_call:
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
    subq $0x28, %rsp
    .seh_stackalloc 0x28
    .seh_endprologue

    movabs $0x2222333344445555, %rbx
    movabs $0x1112131415161718, %rbp
    movabs $0x2122232425262728, %rsi
    movabs $0x3132333435363738, %rdi
    movabs $0x4142434445464748, %r12
    movabs $0x5152535455565758, %r13
    movabs $0x6162636465666768, %r14
    movabs $0x7172737475767878, %r15

    movabs $0x1011121314151617, %r10
    movabs $0x18191a1b1c1d1e1f, %r11
    movabs $0xaaaabbbbccccdddd, %rcx
    movabs $0x9999888877776666, %rdx
    movabs $0x8888777766665555, %r8
    movabs $0x7777666655554444, %r9
    LOAD_XMM %xmm0, .L_gate_xmm0
    LOAD_XMM %xmm1, .L_gate_xmm1
    LOAD_XMM %xmm2, .L_gate_xmm2
    LOAD_XMM %xmm3, .L_gate_xmm3
    LOAD_XMM %xmm4, .L_gate_xmm4
    LOAD_XMM %xmm5, .L_gate_xmm5
    ldmxcsr .L_gate_initial_mxcsr(%rip)
    fldcw .L_gate_initial_x87(%rip)
    movabs $0x1111222233334444, %rax
    cmpq %rbx, %rax
    pushfq
    popq fixture_gate_callback_expected_flags(%rip)
    movq %rsp, fixture_gate_marker_expected_rsp(%rip)
    call information_battle_gate_marker_hook
fixture_gate_marker_call_after:
    movq %rax, fixture_gate_marker_return_rax(%rip)
    STORE_XMM %xmm0, fixture_gate_marker_return_xmm0
    movq %rbp, fixture_gate_marker_after_rbp(%rip)

    addq $0x28, %rsp
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

// The hook tail-jumps here, so this function sees the original call frame.
.globl fixture_gate_marker_original
.def fixture_gate_marker_original; .scl 2; .type 32; .endef
.seh_proc fixture_gate_marker_original
fixture_gate_marker_original:
    movq %rax, fixture_gate_original_rax(%rip)
    movq %rbx, fixture_gate_original_rbx(%rip)
    movq %rcx, fixture_gate_original_rcx(%rip)
    movq %rdx, fixture_gate_original_rdx(%rip)
    movq %rsi, fixture_gate_original_rsi(%rip)
    movq %rdi, fixture_gate_original_rdi(%rip)
    movq %rbp, fixture_gate_original_rbp(%rip)
    movq %r8, fixture_gate_original_r8(%rip)
    movq %r9, fixture_gate_original_r9(%rip)
    movq %r10, fixture_gate_original_r10(%rip)
    movq %r11, fixture_gate_original_r11(%rip)
    movq %r12, fixture_gate_original_r12(%rip)
    movq %r13, fixture_gate_original_r13(%rip)
    movq %r14, fixture_gate_original_r14(%rip)
    movq %r15, fixture_gate_original_r15(%rip)
    movq %rsp, fixture_gate_original_rsp(%rip)
    movq (%rsp), %rax
    movq %rax, fixture_gate_original_return_pc(%rip)
    pushfq
    popq %rax
    movq %rax, fixture_gate_original_rflags(%rip)
    stmxcsr fixture_gate_original_mxcsr(%rip)
    fnstcw fixture_gate_original_x87(%rip)
    STORE_XMM %xmm0, fixture_gate_original_xmm0
    STORE_XMM %xmm1, fixture_gate_original_xmm1
    STORE_XMM %xmm2, fixture_gate_original_xmm2
    STORE_XMM %xmm3, fixture_gate_original_xmm3
    STORE_XMM %xmm4, fixture_gate_original_xmm4
    STORE_XMM %xmm5, fixture_gate_original_xmm5

    subq $0x28, %rsp
    .seh_stackalloc 0x28
    .seh_endprologue
    call GetLastError
    addq $0x28, %rsp
    movl %eax, fixture_gate_original_last_error(%rip)
    movl fixture_gate_marker_original_calls(%rip), %eax
    incl %eax
    movl %eax, fixture_gate_marker_original_calls(%rip)
    movabs $0x7f6e5d4c3b2a1908, %rax
    LOAD_XMM %xmm0, .L_gate_return_xmm0
    ret
.seh_endproc
