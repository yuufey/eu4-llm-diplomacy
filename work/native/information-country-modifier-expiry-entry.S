.text
.p2align 4
.globl bridge_country_modifier_remove_expiry_entry
.def bridge_country_modifier_remove_expiry_entry; .scl 2; .type 32; .endef
.seh_proc bridge_country_modifier_remove_expiry_entry
bridge_country_modifier_remove_expiry_entry:
    .seh_endprologue
    movq %r13, %r8
    jmp country_modifier_remove_observe
.seh_endproc
