// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

    .text
    .align 2

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubResolver
_stubResolver:
#else
    .globl stubResolver
    .type  stubResolver, @function
stubResolver:
#endif
    /* can't add breakpoints in assembly templates,
     * otherwise the breakpoint postions will be changed
     * to 0xcc(int3) by debugger */
    /* save registers */
    push %rbp
    mov %rsp, %rbp
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rdi
    push %rsi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    push %rsp
    /* and %rsp, -128 */ /* make rsp 128bytes aligned */
    /* allocate 560(at least 256 and rsp need 128 aligned) bytes to save all registers */
    sub $560, %rsp
    /* fxsave64 arg address must 128-aligned, XMM-s saved in +128 positions, MXCSR saved in +256 postions */
    /* save registers */
    fxsave64 (%rsp)
    /* get trampolineAddr as compileOnRequestTrampoline second argument */
    /* when trampoline call resolver, the trampoline rip will saved in stack */
    movq 0x08(%rbp), %rsi
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubResolverPatchPoint
_stubResolverPatchPoint:
#else
    .globl stubResolverPatchPoint
stubResolverPatchPoint:
#endif
    /* moveabsq instructions has 10bytes(last 8bytes is i64 value) */
    movabsq $0, %rax /* this target address need updated to compileOnRequestTrampoline */
    /* first argument register not changed, the first still WASMInstance* */
    /* compileOnRequestTrampoline pointer should call by abosulte because trampoline codo generated dynamic */
    call *%rax
    /* change stack to override the next instruction after ret. this works like re-entry */
    mov %rax, 8(%rbp)
    /* restore registers from memory */
    fxrstor64 (%rsp)
    add $560, %rsp
    pop %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rsi
    pop %rdi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    mov %rbp, %rsp
    pop %rbp
    ret

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubResolverEnd
_stubResolverEnd:
#else
    .globl stubResolverEnd
stubResolverEnd:
#endif

#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubTemplate
_stubTemplate:
#else
    .globl stubTemplate
    .type  stubTemplate, @function
stubTemplate:
#endif
    /* stub. first will jmp to trampoline, then jmp to target wasm func */
    jmp 0x7fffffff
    /* stub trampoline */
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubTemplatePatchPoint
_stubTemplatePatchPoint:
    call _stubResolver
#else
    .globl stubTemplatePatchPoint
stubTemplatePatchPoint:
    callq stubResolver /* must use callq */
#endif

/* mark end of the function */
#ifdef ZEN_BUILD_PLATFORM_DARWIN
    .globl _stubTemplateEnd
_stubTemplateEnd:
#else
    .globl stubTemplateEnd
stubTemplateEnd:
#endif


    .text
    .align 4
#ifdef ZEN_BUILD_PLATFORM_DARWIN
#define PRIVATE_SYM(x) _##x
#else
#define PRIVATE_SYM(x) x
#endif
    .globl PRIVATE_SYM(privateLoopCold)
PRIVATE_SYM(privateLoopCold):
    // Called at a regular aligned call site: entry RSP % 16 == 8.
    push %rbp
    mov %rsp, %rbp
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rdi
    push %rsi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    sub $512, %rsp
    fxsave64 (%rsp)
    .globl PRIVATE_SYM(privateLoopColdCookie)
PRIVATE_SYM(privateLoopColdCookie):
    movabsq $0, %rdi
    .globl PRIVATE_SYM(privateLoopColdCallback)
PRIVATE_SYM(privateLoopColdCallback):
    movabsq $0, %rax
    call *%rax
    fxrstor64 (%rsp)
    add $512, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rsi
    pop %rdi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    pop %rbp
    ret
    .globl PRIVATE_SYM(privateLoopColdEnd)
PRIVATE_SYM(privateLoopColdEnd):
#undef PRIVATE_SYM

#ifndef ZEN_BUILD_PLATFORM_DARWIN
    .section .note.GNU-stack,"",@progbits
#endif
