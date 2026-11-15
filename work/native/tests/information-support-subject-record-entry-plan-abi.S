.intel_syntax noprefix
.text
.globl support_subject_entry_registers
support_subject_entry_registers:
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x48
    mov [rsp+0x20], rdx
    mov [rsp+0x28], rcx
    mov [rsp+0x30], r8
    movabs rbx, 0x1111111122222222
    movabs rsi, 0x3333333344444444
    movabs rdi, 0x5555555566666666
    movabs rbp, 0x7777777788888888
    movabs r12, 0xbbbbbbbbcccccccc
    movabs r13, 0xddddddddeeeeeeee
    movabs r14, 0x99999999aaaaaaaa
    movabs r15, 0xffff000011112222
    mov rcx, [rsp+0x30]
    movabs rdx, 0x1200000100415246
    movabs r8, 0x9876543210123456
    movabs r9, 0x8877665544332211
    call [rsp+0x28]
    mov r10, [rsp+0x20]
    mov [r10], rax
    mov [r10+8], rbx
    mov [r10+16], rsi
    mov [r10+24], rdi
    mov [r10+32], rbp
    mov [r10+40], r12
    mov [r10+48], r13
    mov [r10+56], r14
    mov [r10+64], r15
    add rsp, 0x48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret
