.intel_syntax noprefix
.text
.globl subsidy_entry_registers
subsidy_entry_registers:
    push rbx
    sub rsp, 0x30
    mov [rsp+0x20], rdx
    mov r10, rcx
    movabs rbx, 0x1111111122222222
    movabs rax, 0x3333333344444444
    mov [rsp], rax
    mov rcx, r8
    call r10
    mov r10, [rsp+0x20]
    mov [r10], rax
    mov [r10+8], rbx
    add rsp, 0x30
    pop rbx
    ret
