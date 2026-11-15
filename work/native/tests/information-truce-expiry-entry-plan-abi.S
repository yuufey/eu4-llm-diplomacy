.intel_syntax noprefix
.text
.globl truce_entry_registers
truce_entry_registers:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x38
    mov [rsp+0x20], rdx
    mov r10, rcx
    mov rcx, r8
    movabs rbx, 0x1111111122222222
    movabs rbp, 0x3333333344444444
    movabs rsi, 0x5555555566666666
    movabs rdi, 0x7777777788888888
    movabs r12, 0x99999999aaaaaaaa
    movabs r13, 0xbbbbbbbbcccccccc
    movabs r14, 0xddddddddeeeeeeee
    movabs r15, 0x123456789abcdef0
    call r10
    mov r10, [rsp+0x20]
    mov [r10], rax
    mov [r10+8], rbx
    mov [r10+16], rbp
    mov [r10+24], rsi
    mov [r10+32], rdi
    mov [r10+40], r12
    mov [r10+48], r13
    mov [r10+56], r14
    mov [r10+64], r15
    add rsp, 0x38
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
