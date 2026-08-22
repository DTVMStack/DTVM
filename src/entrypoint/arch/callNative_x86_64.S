/*
 * Copyright (C) 2019 Intel Corporation.
 * Copyright (C) 2021-2023 the DTVM authors.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

    .text
    .align 2

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _rollbackWasmVirtualStack
_rollbackWasmVirtualStack:
#else
    .globl rollbackWasmVirtualStack
    .type  rollbackWasmVirtualStack, @function
rollbackWasmVirtualStack:
#endif
    // virtualstack return address
    movq (%rsp), %rax
    // put ret address to old sp(rsi as old rsp)
    movq %rax, (%rsi)
    // put OldRsp(second param) to rsp
    movq %rsi, %rsp
    // JmpBuf(third param) as return
    mov %rdx, %rax
    ret

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _startWasmFuncStack
_startWasmFuncStack:
#else
    .globl startWasmFuncStack
    .type  startWasmFuncStack, @function
startWasmFuncStack:
#endif
    // old return address
    movq (%rsp), %rax
    // put ret address to new sp(rsi as new rsp)
    movq %rax, (%rsi)
    push %rbp
    mov %rsp, %rbp

    // put old rsp to OldRspPtr(third param)
    movq %rsp, (%rdx)

    // put NewRsp(second param) to rsp
    movq %rsi, %rsp
    // StackInfo still first param(rdi)
    // call InVirtualStackFuncPtr(5th param, r8)
    call *%r8
    // not run again(InVirtualStackFuncPtr will call longjmp)
    int $3
    ret

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _callNative
_callNative:
#else
    .globl callNative
    .type  callNative, @function
callNative:
#endif
    /* rdi - function ptr */
    /* rsi - argv */
    /* rdx - n_stacks */
    /* cl  - skip_instance_processing */

    push %rbp
    mov %rsp, %rbp

    mov %rdx, %r10
    mov %rsp, %r11      /* Check that stack is aligned on */
    and $8, %r11        /* 16 bytes. This code may be removed */
    je check_stack_succ /* when we are sure that compiler always */
    int3                /* calls us with aligned stack */

check_stack_succ:
    mov %r10, %r11      /* Align stack on 16 bytes before pushing */
    and $1, %r11        /* stack arguments in case we have an odd */
    shl $3, %r11        /* number of stack arguments */
    sub %r11, %rsp

    /* save registers clobbered by JIT */
    sub $48, %rsp           /* allocate 6*8 to save r12~r15, rbx, aligned */
    movq %r12, -0x08(%rbp)  /* save %r12 */
    movq %r13, -0x10(%rbp)  /* save %r13 */
    movq %r14, -0x18(%rbp)  /* save %r14 */
    movq %r15, -0x20(%rbp)  /* save %r15 */
    movq %rbx, -0x28(%rbp)  /* save %rbx */

    /* save has_instance into al */
    movb %cl, %al

    /* store memory args */
    movq %rdi, %r11     /* func ptr */
    movq %r10, %rcx     /* counter */
    lea 128+48-8(%rsi,%rcx,8), %r10 /* move cursor to last the stack argument */
    sub %rsp, %r10
    cmpq $0, %rcx
    je push_args_end

push_args:
    push 0(%rsp,%r10)
    loop push_args

push_args_end:
    /* fill all fp args */
    movdqu 0x00(%rsi), %xmm0
    movdqu 0x10(%rsi), %xmm1
    movdqu 0x20(%rsi), %xmm2
    movdqu 0x30(%rsi), %xmm3
    movdqu 0x40(%rsi), %xmm4
    movdqu 0x50(%rsi), %xmm5
    movdqu 0x60(%rsi), %xmm6
    movdqu 0x70(%rsi), %xmm7

    /* fill all int args */
    movq 0x80(%rsi), %rdi
    movq 0x90(%rsi), %rdx
    movq 0x98(%rsi), %rcx
    movq 0xa0(%rsi), %r8
    movq 0xa8(%rsi), %r9
    movq 0x88(%rsi), %rsi

#ifdef ZEN_ENABLE_JIT
    /* skip instance related processing */
    cmpb $0, %al
    jne call_function

#ifdef ZEN_ENABLE_SINGLEPASS_JIT
    /* prepare `instance` for singlepass JIT */
    movq %rdi, %r15         /* instance */
    movq 0x40(%r15), %r14   /* offsetof(Instance, _global_var_data) == 0x40 */
    movq 0x50(%r15), %r13   /* offsetof(Instance, _memories) == 0x50 */
    movq 0x08(%r13), %r12   /* offsetof(Instance::MemoryInstance, _memory_size) == 0x08 */
    movq 0x10(%r13), %r13   /* offsetof(Instance::MemoryInstance, _memory_base) == 0x10 */
#endif // ZEN_ENABLE_SINGLEPASS_JIT

    /* calculate stack boundary */
    movq %rsp, %rax
    subq 0x68(%rdi), %rax   /* offsetof(Instance, _jit_stack_size) == 0x68 */
    movq %rax, 0x70(%rdi)   /* offsetof(Instance, _jit_stack_boundary) == 0x70 */
#endif // ZEN_ENABLE_JIT

call_function:
    call *%r11

    /* restore %r12-%r15, rbx */
    movq -0x08(%rbp), %r12
    movq -0x10(%rbp), %r13
    movq -0x18(%rbp), %r14
    movq -0x20(%rbp), %r15
    movq -0x28(%rbp), %rbx

    leave
    ret

/* mark end of the function */
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _callNative_end
_callNative_end:
#else
    .globl callNative_end
callNative_end:
#endif

#ifndef ZEN_BUILD_PLATFORM_DARWIN
    .section .note.GNU-stack,"",@progbits
#endif
