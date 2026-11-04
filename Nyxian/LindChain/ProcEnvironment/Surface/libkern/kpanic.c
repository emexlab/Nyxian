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

#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#include <LindChain/ProcEnvironment/Surface/libkern/version.h>
#include <stdio.h>
#include <stdarg.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/ldsyms.h>
#include <unistd.h>

static const char *xnu_version_string(void)
{
    static char buf[256];
    size_t len = sizeof(buf);
    if(sysctlbyname("kern.version", buf, &len, NULL, 0) != 0)
    {
        buf[0] = '\0';
    }
    return buf;
}

static struct ksurface_panic_header g_kpanic_header;

void kpanic_append(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_kpanic_header.body + g_kpanic_header.len, sizeof(g_kpanic_header.body) - g_kpanic_header.len, fmt, ap);
    va_end(ap);
    if(n > 0)
    {
        g_kpanic_header.len += n;
    }
}

static void kpanic_emit_backtrace(task_t task,
                                  thread_t thread,
                                  uint64_t tid)
{
    arm_thread_state64_t ts;
    mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
    if(thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts, &cnt) != KERN_SUCCESS)
    {
        return;
    }
    
    uint64_t pc = arm_thread_state64_get_pc(ts);
    uint64_t fp = arm_thread_state64_get_fp(ts);
    
    kpanic_append("Panicked thread: 0x%llx, backtrace: 0x%016llx, tid: %llu\n", (uint64_t)thread, fp, tid);
    kpanic_append("\t\t  lr: 0x%016llx fp: 0x%016llx\n", pc, fp);
    
    const int MAX_FRAMES = 64;
    for(int i = 0; i < MAX_FRAMES && fp != 0; i++)
    {
        struct {
            uint64_t saved_fp;
            uint64_t saved_lr;
        } frame;
        vm_size_t got = 0;
        
        if(vm_read_overwrite(task, (vm_address_t)fp, sizeof(frame), (vm_address_t)&frame, &got) != KERN_SUCCESS || got != sizeof(frame))
        {
            break;
        }
        
        if(frame.saved_lr == 0)
        {
            break;
        }
        
        kpanic_append("\t\t  lr: 0x%016llx fp: 0x%016llx\n", frame.saved_lr, frame.saved_fp);
        
        if(frame.saved_fp <= fp)
        {
            break;
        }
        fp = frame.saved_fp;
    }
}

static int kpanic_thread_index(task_t task, thread_t target)
{
    thread_act_array_t list;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &list, &count) != KERN_SUCCESS)
        return -1;

    int index = -1;
    for (mach_msg_type_number_t i = 0; i < count; i++)
    {
        if (list[i] == target)
            index = (int)i;
    }

    /* release the port rights task_threads handed you */
    for (mach_msg_type_number_t i = 0; i < count; i++)
        mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)list, count * sizeof(thread_t));

    return index;
}

__attribute__((noreturn))
void kpanic(const char *fmt, ...)
{
    g_kpanic_header.magic = 'KSPN';
    g_kpanic_header.version = 1;
    g_kpanic_header.len = 0;
    
    uint64_t faulting_tid = 0;
    thread_identifier_info_data_t tid;
    mach_msg_type_number_t tcnt = THREAD_IDENTIFIER_INFO_COUNT;
    thread_t thread = mach_thread_self();
    if(thread_info(thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&tid, &tcnt) == KERN_SUCCESS)
    {
        faulting_tid = tid.thread_id;
    }
    
    /* ksurface is seeing XNU as the hardware as the chip, so our CPU is the Thread */
    kpanic_append("panic(cpu %d caller 0x%016llx): ", kpanic_thread_index(mach_task_self(), thread), (uint64_t)__builtin_return_address(0));
    va_list ap; va_start(ap, fmt);
    g_kpanic_header.len += vsnprintf(g_kpanic_header.body + g_kpanic_header.len, sizeof(g_kpanic_header.body) - g_kpanic_header.len, fmt, ap);
    va_end(ap);
    kpanic_append("\n");
    
    /* structured block */
    kpanic_append("Debugger message: panic\n");
    kpanic_append("Kernel version: %s + ksurface %s\n", xnu_version_string(), ksurface_version_get_string());
    kpanic_append("Paniclog version: %u\n", g_kpanic_header.version);
    kpanic_append("Kernel slide: 0x%016llx\n", (uint64_t)_dyld_get_image_vmaddr_slide(0));
    kpanic_append("Kernel text base: 0x%016llx\n", (uint64_t)_dyld_get_image_header(0));
    
    /* now a backtrace */
    kpanic_emit_backtrace(mach_task_self(), thread, faulting_tid);
    mach_port_deallocate(mach_task_self(), thread);
    
    /* first dump panic string into kernel log */
    extern int kfd;
    int pkfd = dup(kfd);
    close(kfd);
    kfd = -1;
    fsync(pkfd);
    write(pkfd, g_kpanic_header.body, g_kpanic_header.len);  /* shouldnt be obfuscated */
    fsync(pkfd);    /* log done */
    close(pkfd);
    pkfd = -1;
    
    __builtin_unreachable();
}

const struct ksurface_panic_header *kpanic_log_get(void)
{
    return &g_kpanic_header;
}
