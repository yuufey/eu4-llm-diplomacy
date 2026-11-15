.text
.p2align 4

.extern information_country_modifier_expiry_abi_entry_rsp
.extern information_country_modifier_expiry_abi_entry_r13
.extern information_country_modifier_expiry_abi_pre_call_rsp
.extern information_country_modifier_expiry_abi_post_call_rsp
.extern information_country_modifier_expiry_abi_post_call_r13
.extern information_country_modifier_expiry_abi_outgoing_r13
.extern information_country_modifier_expiry_abi_post_restore_rsp
.extern information_country_modifier_expiry_abi_observer_rcx
.extern information_country_modifier_expiry_abi_observer_rdx
.extern information_country_modifier_expiry_abi_observer_r8
.extern information_country_modifier_expiry_abi_observer_r13
.extern information_country_modifier_expiry_abi_observer_rsp
.extern information_country_modifier_expiry_abi_observer_return_pc

.globl information_country_modifier_expiry_abi_invoke
.def information_country_modifier_expiry_abi_invoke; .scl 2; .type 32; .endef
.seh_proc information_country_modifier_expiry_abi_invoke
information_country_modifier_expiry_abi_invoke:
    movq %rsp, information_country_modifier_expiry_abi_entry_rsp(%rip)
    movq %r13, information_country_modifier_expiry_abi_entry_r13(%rip)
    pushq %r13
    .seh_pushreg %r13
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    movq %r8, %r13
    movq %rsp, information_country_modifier_expiry_abi_pre_call_rsp(%rip)
    call bridge_country_modifier_remove_expiry_entry
.globl information_country_modifier_expiry_abi_after_call
information_country_modifier_expiry_abi_after_call:
    movq %rsp, information_country_modifier_expiry_abi_post_call_rsp(%rip)
    movq %r13, information_country_modifier_expiry_abi_post_call_r13(%rip)
    addq $32, %rsp
    popq %r13
    movq %r13, information_country_modifier_expiry_abi_outgoing_r13(%rip)
    movq %rsp, information_country_modifier_expiry_abi_post_restore_rsp(%rip)
    ret
.seh_endproc

.globl country_modifier_remove_observe
.def country_modifier_remove_observe; .scl 2; .type 32; .endef
.p2align 4
country_modifier_remove_observe:
    movq %rcx, information_country_modifier_expiry_abi_observer_rcx(%rip)
    movq %rdx, information_country_modifier_expiry_abi_observer_rdx(%rip)
    movq %r8, information_country_modifier_expiry_abi_observer_r8(%rip)
    movq %r13, information_country_modifier_expiry_abi_observer_r13(%rip)
    movq %rsp, information_country_modifier_expiry_abi_observer_rsp(%rip)
    movq (%rsp), %rax
    movq %rax, information_country_modifier_expiry_abi_observer_return_pc(%rip)
    ret

