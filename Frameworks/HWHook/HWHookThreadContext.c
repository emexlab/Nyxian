/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

#include "CFRuntime.h"
#include "HWHookThreadContext.h"
#include <pthread.h>
#include <mach/mach.h>

static CFTypeID gHWHookThreadContextTypeID = _kCFRuntimeNotATypeID;

struct __HWHookThreadContext {
    CFRuntimeBase _base;
    CFMutableArrayRef symbols;
};

static void __HWHookThreadContextFinalize(CFTypeRef cf)
{
    HWHookThreadContextRef context = (HWHookThreadContextRef)cf;
    if(context->symbols != NULL)
    {
        CFRelease(context->symbols);
    }
}

static const CFRuntimeClass gHWHookThreadContext = {
    0,                              /* version */
    "HWHookThreadContext",          /* class name */
    NULL,                           /* init */
    NULL,                           /* copy */
    __HWHookThreadContextFinalize,  /* finalize */
    NULL,                           /* equal */
    NULL,                           /* hash */
    NULL,                           /* copyFormattingDesc */
    NULL,                           /* copyDebugDesc */
    NULL,
    NULL,
    0
};

CFTypeID HWHookThreadContextGetTypeID(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gHWHookThreadContextTypeID = _CFRuntimeRegisterClass(&gHWHookThreadContext);
    });
    return gHWHookThreadContextTypeID;
}

typedef struct {
    thread_t target;
    arm_debug_state64_t state;
    
    uint64_t original_lr;
    
    mach_port_t exceptionPort;
    
    /* old exception port configurations */
    mach_msg_type_number_t old_count;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_ports[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    
    HWHookThreadContextRef context;
} hwhook_server_ctx_t;

typedef struct {
    union {
        __Request__exception_raise_state_identity_t v;
        uint8_t pad[1024];
    };
} __Request__exception_raise_large_t;

_Thread_local HWHookThreadContextRef tCurrentContext = NULL; /* retained */
_Thread_local hwhook_server_ctx_t tCurrentServerContext;

static Boolean gHWHookSelfStateRefused = false;

static Boolean __HWHookApplyDebugStateSelf(const arm_debug_state64_t *state)
{
    if(gHWHookSelfStateRefused || tCurrentServerContext.target == MACH_PORT_NULL)
    {
        return false;
    }
    arm_debug_state64_t copy = *state;
    if(thread_set_state(tCurrentServerContext.target, ARM_DEBUG_STATE64, (thread_state_t)&copy, ARM_DEBUG_STATE64_COUNT) != KERN_SUCCESS)
    {
        gHWHookSelfStateRefused = true;
        return false;
    }
    return true;
}

static void __HWHookFillDebugState(HWHookThreadContextRef context, arm_debug_state64_t *state)
{
    memset(state, 0, sizeof(*state));
    CFIndex hookCount = CFArrayGetCount(context->symbols);
    for(CFIndex index = 0; index < hookCount && index < 16; index++)
    {
        HWHookRef hook = (HWHookRef)CFArrayGetValueAtIndex(context->symbols, index);
        state->__bvr[index] = (uint64_t)HWHookGetSymbolPtr(hook);
        state->__bcr[index] = (0xFu << 5) | (0b10u << 1) | 1u;
    }
}

static int __HWHookBrkImmediateAt(uint64_t pc)
{
#if __has_feature(ptrauth_calls)
    pc = (uint64_t)__builtin_ptrauth_strip((void *)pc, 0);
#endif
    uint32_t insn = *(const uint32_t *)(uintptr_t)pc;
    if((insn & 0xFFE0001Fu) != 0xD4200000u)
    {
        return -1;
    }
    return (int)((insn >> 5) & 0xFFFFu);
}

__attribute__((used)) static void __HWHookReenableImpl(void)
{
    HWHookThreadContextEnableHooks(HWHookThreadContextGetCurrent());
}

__attribute__((naked))
static void __HWHookThreadContextClientTrampolineReenableHooks(void)
{
    __asm__ volatile(
        "stp q0, q1, [sp, #-32]!\n"
        "stp x0, x1, [sp, #-16]!\n"
        "bl  ___HWHookReenableImpl\n"
        "ldp x0, x1, [sp], #16\n"
        "ldp q0, q1, [sp], #32\n"
        "ldr lr, [sp], #16\n"
        "ret\n"
    );
}

static void __HWHookThreadContextServerTrampolineReenableHooks(arm_thread_state64_t *state,
                                                               uint64_t addr)
{
    state->__sp -= 16;
    *(uint64_t*)(state->__sp) = state->__lr;
    state->__lr = (uint64_t)&__HWHookThreadContextClientTrampolineReenableHooks;
    state->__pc = addr;
}

static void *__HWHookThreadContextServer(void *ctxp)
{
    hwhook_server_ctx_t *ctx = ctxp;
    
    mach_port_t port = ctx->exceptionPort;
    
    /* will carry request buffer */
    __Request__exception_raise_large_t request;
    
    /* reply of the previous exception, sent together with the next receive */
    __Reply__exception_raise_state_identity_t reply;
    Boolean replyPending = false;
    
    for(;;)
    {
        /* receiving pseudo exception (and answering the previous one in the same trap) */
        request.v.Head.msgh_local_port = port;
        request.v.Head.msgh_size = (mach_msg_size_t)sizeof(request);
        mach_msg_return_t mr;
        if(replyPending)
        {
            replyPending = false;
            mr = mach_msg_overwrite(&reply.Head, MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_LARGE, reply.Head.msgh_size, sizeof(request), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL, &(request.v.Head), 0);
            if(mr >= MACH_SEND_IN_PROGRESS && mr < MACH_RCV_IN_PROGRESS)
            {
                fprintf(stderr, "[!] failed to send reply to the kernel\n");
                return NULL;
            }
        }
        else
        {
            mr = mach_msg(&(request.v.Head), MACH_RCV_MSG | MACH_RCV_LARGE, 0, sizeof(request), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        }
        if(mr != MACH_MSG_SUCCESS ||
           request.v.codeCnt != 2 ||
           request.v.flavor != ARM_THREAD_STATE64 ||
           request.v.old_stateCnt != ARM_THREAD_STATE64_COUNT ||
           request.v.exception != EXC_BREAKPOINT)   /* impossible not to be EXC_BREAKPOINT */
        {
            printf("[!] failed to receive exception\n");
            continue;
        }
        
        arm_thread_state64_t state;
        memcpy(&state, request.v.old_state, sizeof(state));
        
        /*
         * No thread_get_state(ARM_EXCEPTION_STATE64) round-trip for the ESR: a BRK we
         * raised ourselves is recognisable by the instruction at pc, anything else on
         * this port is one of our hardware breakpoints.
         */
        int brkImmediate = __HWHookBrkImmediateAt(state.__pc);
        uint16_t imm;
        uint32_t ec = brkImmediate >= 0 ? 0x3C : 0x30;
        
        kern_return_t handled_ret = KERN_SUCCESS;
        
        switch(ec)
        {
            case 0x3C:  /* software breakpoint, thread want's something from us */
            {
                imm = (uint16_t)brkImmediate;
                switch(imm)
                {
                    case 1111:  /* set hooks */
                    {
                        /* setting debug state */
                        kern_return_t kr = thread_set_state(request.v.thread.name, ARM_DEBUG_STATE64, (thread_state_t)&ctx->state, ARM_DEBUG_STATE64_COUNT);
                        if(kr != KERN_SUCCESS)
                        {
                            fprintf(stderr, "[!] failed to set debug thread state\n");
                            handled_ret = KERN_FAILURE;
                            goto reply_fastpath;
                        }
                        
                        /* skipping over __builtin_trap */
                        state.__pc += 4;
                        
                        break;
                    }
                    case 2222:  /* teardown */
                    {
                        /* clear hooks */
                        arm_debug_state64_t clear;
                        memset(&clear, 0, sizeof(clear));
                        kern_return_t kr = thread_set_state(request.v.thread.name, ARM_DEBUG_STATE64, (thread_state_t)&clear, ARM_DEBUG_STATE64_COUNT);
                        if(kr != KERN_SUCCESS)
                        {
                            fprintf(stderr, "[!] failed to clear debug state\n");
                            handled_ret = KERN_FAILURE;
                            goto reply_fastpath;
                        }
                        
                        state.__pc += 4;
                        
                        if(ctx->old_count > 0)
                        {
                            for(mach_msg_type_number_t i = 0; i < ctx->old_count; i++)
                            {
                                thread_set_exception_ports(request.v.thread.name, ctx->old_masks[i], ctx->old_ports[i], ctx->old_behaviors[i], ctx->old_flavors[i]);
                            }
                        }
                        else
                        {
                            thread_set_exception_ports(request.v.thread.name, EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_STATE_IDENTITY, THREAD_STATE_NONE);
                        }
                        
                        mach_port_mod_refs(mach_task_self(), ctx->exceptionPort, MACH_PORT_RIGHT_RECEIVE, -1);
                        mach_port_deallocate(mach_task_self(), ctx->exceptionPort);
                        
                        __Reply__exception_raise_state_identity_t reply;
                        memset(&reply, 0, sizeof(reply));
                        reply.flavor = ARM_THREAD_STATE64;
                        memcpy(reply.new_state, &state, sizeof(state));
                        reply.new_stateCnt = ARM_THREAD_STATE64_COUNT;
                        reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request.v.Head.msgh_bits), 0);
                        reply.Head.msgh_id = request.v.Head.msgh_id + 100;
                        reply.Head.msgh_local_port = MACH_PORT_NULL;
                        reply.Head.msgh_remote_port = request.v.Head.msgh_remote_port;
                        reply.Head.msgh_size = (mach_msg_size_t)(offsetof(__Reply__exception_raise_state_identity_t, new_state) + reply.new_stateCnt * sizeof(reply.new_state[0]));
                        reply.NDR = NDR_record;
                        reply.RetCode = handled_ret;
                        mr = mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                        mach_msg_destroy(&(request.v.Head));
                        if(mr != KERN_SUCCESS)
                        {
                            fprintf(stderr, "[!] failed to send reply to the kernel\n");
                            handled_ret = KERN_FAILURE;
                            goto reply_fastpath;
                        }
                        return NULL;
                    }
                    default:
                        handled_ret = KERN_FAILURE;
                        break;
                }
                break;
            }
            case 0x30:  /* this is a hardware breakpoint hook */
            case 0x31:
            {
                /* matching hook */
                HWHookRef matchingHook = NULL;
                CFIndex hookCount = CFArrayGetCount(ctx->context->symbols);
                for(CFIndex index = 0; index < hookCount; index++)
                {
                    HWHookRef hook = (HWHookRef)CFArrayGetValueAtIndex(ctx->context->symbols, index);
                    if(state.__pc == (uint64_t)HWHookGetSymbolPtr(hook))
                    {
                        matchingHook = hook;
                        break;
                    }
                }
                
                if(matchingHook == NULL)
                {
                    fprintf(stderr, "[!] failed to match the hook\n");
                    handled_ret = KERN_FAILURE;
                    goto reply_fastpath;
                }
                
                /* now call the replacement */
                if(HWHookGetDisableContextHooksInFrame(matchingHook))
                {
                    arm_debug_state64_t clear;
                    memset(&clear, 0, sizeof(clear));
                    kern_return_t kr = thread_set_state(request.v.thread.name, ARM_DEBUG_STATE64, (thread_state_t)&clear, ARM_DEBUG_STATE64_COUNT);
                    if(kr != KERN_SUCCESS)
                    {
                        fprintf(stderr, "[!] failed to clear debug state\n");
                        handled_ret = KERN_FAILURE;
                        goto reply_fastpath;
                    }
                    
                    __HWHookThreadContextServerTrampolineReenableHooks(&state, (uint64_t)HWHookGetReplacementPtr(matchingHook));
                }
                else
                {
                    state.__pc = (uint64_t)HWHookGetReplacementPtr(matchingHook);
                }
                break;
            }
            case 0x32:  /* step or something else */
            case 0x33:
            default:
                handled_ret = KERN_FAILURE;
                break;
        }
        
    reply_fastpath:
        {
            memset(&reply, 0, sizeof(reply));
            reply.flavor = ARM_THREAD_STATE64;
            memcpy(reply.new_state, &state, sizeof(state));
            reply.new_stateCnt = ARM_THREAD_STATE64_COUNT;
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request.v.Head.msgh_bits), 0);
            reply.Head.msgh_id = request.v.Head.msgh_id + 100;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_remote_port = request.v.Head.msgh_remote_port;
            reply.Head.msgh_size = (mach_msg_size_t)(offsetof(__Reply__exception_raise_state_identity_t, new_state) + reply.new_stateCnt * sizeof(reply.new_state[0]));
            reply.NDR = NDR_record;
            reply.RetCode = handled_ret;
            
            request.v.Head.msgh_remote_port = MACH_PORT_NULL;
            request.v.Head.msgh_bits &= ~MACH_MSGH_BITS_REMOTE_MASK;
            mach_msg_destroy(&(request.v.Head));
            replyPending = true;
        }
    }
    
    return NULL;
}

HWHookThreadContextRef HWHookThreadContextGetCurrent(void)
{
    return tCurrentContext;
}

HWHookThreadContextRef HWHookThreadContextCreate(CFAllocatorRef allocator)
{
    HWHookThreadContextRef context = (HWHookThreadContextRef)_CFRuntimeCreateInstance(allocator, HWHookThreadContextGetTypeID(), sizeof(struct __HWHookThreadContext) - sizeof(CFRuntimeBase), NULL);
    if(context == NULL)
    {
        return NULL;
    }
    
    context->symbols = CFArrayCreateMutable(allocator, 0, &kCFTypeArrayCallBacks);
    if(context->symbols == NULL)
    {
        CFRelease(context);
        return NULL;
    }
    
    return context;
}

Boolean HWHookThreadContextEnter(HWHookThreadContextRef context)
{
    if(context == NULL || tCurrentContext != NULL)
    {
        return false;
    }
    bzero(&tCurrentServerContext, sizeof(tCurrentServerContext));
    
    /* backing up current exception ports */
    thread_t currentThread = mach_thread_self();
    thread_get_exception_ports(currentThread, EXC_MASK_BREAKPOINT, tCurrentServerContext.old_masks, &tCurrentServerContext.old_count, tCurrentServerContext.old_ports, tCurrentServerContext.old_behaviors, tCurrentServerContext.old_flavors);
    
    /* creating thread port exception port */
    mach_port_options_t opt = { .flags =  MPO_INSERT_SEND_RIGHT };
    mach_port_t exceptionPort = MACH_PORT_NULL;
    kern_return_t kr = mach_port_construct(mach_task_self(), &opt, 0, &exceptionPort);
    if(kr != KERN_SUCCESS)
    {
        goto out_recover_thread_exception_ports;
    }
    tCurrentServerContext.exceptionPort = exceptionPort;
    
    kr = thread_set_exception_ports(currentThread, EXC_MASK_BREAKPOINT, exceptionPort, EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64);
    if(kr != KERN_SUCCESS)
    {
        goto out_destroy_exception_port;
    }
    
    /* creating detached HWHookThreadContextServer */
    __HWHookFillDebugState(context, &tCurrentServerContext.state);
    tCurrentServerContext.target = currentThread;
    tCurrentContext = context;
    tCurrentServerContext.context = context;
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    int rc = pthread_create(&thread, &attr, __HWHookThreadContextServer, &tCurrentServerContext);
    pthread_attr_destroy(&attr);
    if(rc != 0)
    {
        goto out_destroy_exception_port;
    }
    if(!__HWHookApplyDebugStateSelf(&tCurrentServerContext.state))
    {
        __asm__ volatile ("brk #1111" ::: "memory");
    }
    
    return true;
    
out_stop_server:
out_destroy_exception_port:
    mach_port_deallocate(mach_task_self(), exceptionPort);
    mach_port_mod_refs(mach_task_self(), exceptionPort, MACH_PORT_RIGHT_RECEIVE, -1);
out_recover_thread_exception_ports:
    if(tCurrentServerContext.old_count > 0)
    {
        thread_set_exception_ports(tCurrentServerContext.target, tCurrentServerContext.old_masks[0], tCurrentServerContext.old_ports[0], tCurrentServerContext.old_behaviors[0], tCurrentServerContext.old_flavors[0]);
    }
    else
    {
        thread_set_exception_ports(tCurrentServerContext.target, EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_STATE_IDENTITY, THREAD_STATE_NONE);
    }
    return false;
}

Boolean HWHookThreadContextExit(HWHookThreadContextRef context)
{
    if(context == NULL || tCurrentContext != context)
    {
        return false;
    }
    
    /* safe cause this thread is not causing a exception in here xD */
    __asm__ volatile ("brk #2222" ::: "memory");
    tCurrentContext = NULL;
    mach_port_deallocate(mach_task_self(), tCurrentServerContext.target);
    
    return true;
}

Boolean HWHookThreadContextEnableHooks(HWHookThreadContextRef context)
{
    if(context == NULL || tCurrentContext != context)
    {
        return false;
    }
    
    __HWHookFillDebugState(context, &tCurrentServerContext.state);
    if(!__HWHookApplyDebugStateSelf(&tCurrentServerContext.state))
    {
        __asm__ volatile ("brk #1111" ::: "memory");
    }
    
    return true;
}

Boolean HWHookThreadContextDisableHooks(HWHookThreadContextRef context)
{
    if(context == NULL || tCurrentContext != context)
    {
        return false;
    }
    
    memset(&tCurrentServerContext.state, 0, sizeof(tCurrentServerContext.state));
    if(!__HWHookApplyDebugStateSelf(&tCurrentServerContext.state))
    {
        __asm__ volatile ("brk #1111" ::: "memory");
    }
    
    return true;
}

Boolean HWHookThreadContextAppendHook(HWHookThreadContextRef context,
                                      HWHookRef hook)
{
    if(context == NULL)
    {
        return false;
    }
    
    CFArrayAppendValue(context->symbols, hook);
    return true;
}

CFArrayRef HWHookThreadContextGetHooks(HWHookThreadContextRef context)
{
    if(context == NULL)
    {
        return NULL;
    }
    
    return context->symbols;
}
