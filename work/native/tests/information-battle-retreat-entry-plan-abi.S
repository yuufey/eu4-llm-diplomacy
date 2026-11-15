.text

.globl fixture_retreat_removal_call
.def fixture_retreat_removal_call; .scl 2; .type 32; .endef
.seh_proc fixture_retreat_removal_call
fixture_retreat_removal_call:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rbp
    .seh_pushreg %rbp
    pushq %rsi
    .seh_pushreg %rsi
    pushq %rdi
    .seh_pushreg %rdi
    pushq %r12
    .seh_pushreg %r12
    pushq %r13
    .seh_pushreg %r13
    pushq %r14
    .seh_pushreg %r14
    pushq %r15
    .seh_pushreg %r15
    subq $0x38, %rsp
    .seh_stackalloc 0x38
    .seh_endprologue

    movq %rcx, %r10
    movabsq $0x0102030405060708, %rcx
    movabsq $0x1112131415161718, %rdx
    movabsq $0x2122232425262728, %r8
    movabsq $0x3132333435363738, %r9
    movabsq $0x4142434445464748, %rax
    movq %rax, 0x20(%rsp)
    movabsq $0x5152535455565758, %rax
    movq %rax, 0x28(%rsp)

    movabsq $0x6162636465666768, %rbx
    movabsq $0x7172737475767778, %rbp
    movabsq $0x8182838485868788, %rsi
    movabsq $0x9192939495969798, %rdi
    movabsq $0xa1a2a3a4a5a6a7a8, %r12
    movabsq $0xb1b2b3b4b5b6b7b8, %r13
    movabsq $0xc1c2c3c4c5c6c7c8, %r14
    movabsq $0xd1d2d3d4d5d6d7d8, %r15
    movq %rsp, fixture_retreat_call_rsp(%rip)
    call *%r10
.Lretreat_removal_after_call:
    movq %rsp, fixture_retreat_after_rsp(%rip)
    movq %rax, fixture_retreat_return_value(%rip)
    movq %rbx, fixture_retreat_after_rbx(%rip)
    movq %rbp, fixture_retreat_after_rbp(%rip)
    movq %rsi, fixture_retreat_after_rsi(%rip)
    movq %rdi, fixture_retreat_after_rdi(%rip)
    movq %r12, fixture_retreat_after_r12(%rip)
    movq %r13, fixture_retreat_after_r13(%rip)
    movq %r14, fixture_retreat_after_r14(%rip)
    movq %r15, fixture_retreat_after_r15(%rip)

    addq $0x38, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    ret
.seh_endproc

.globl fixture_retreat_removal_continuation
.def fixture_retreat_removal_continuation; .scl 2; .type 32; .endef
fixture_retreat_removal_continuation:
    incq fixture_retreat_continuation_calls(%rip)
    movq %rcx, fixture_retreat_continuation_rcx(%rip)
    movq %rdx, fixture_retreat_continuation_rdx(%rip)
    movq %r8, fixture_retreat_continuation_r8(%rip)
    movq %r9, fixture_retreat_continuation_r9(%rip)
    movq %rsp, fixture_retreat_continuation_rsp(%rip)
    movq 0x50(%rsp), %r10
    movq %r10, fixture_retreat_continuation_stack5(%rip)
    movq 0x58(%rsp), %r10
    movq %r10, fixture_retreat_continuation_stack6(%rip)

    addq $0x20, %rsp
    popq %rdi
    movq 0x08(%rsp), %rbx
    movq 0x10(%rsp), %rbp
    movq 0x20(%rsp), %rsi
    movabsq $0x0fedcba987654321, %rax
    ret
