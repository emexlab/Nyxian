/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2023 - 2026 LiveContainer
 Copyright (C) 2026 emexlab

 This file is part of LiveContainer.

 LiveContainer is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 LiveContainer is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <LindChain/ProcEnvironment/LiveContainer/Tweaks/DyldHook.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <assert.h>
#include <LindChain/ProcEnvironment/LiveContainer/utils.h>
#include <LindChain/ProcEnvironment/litehook/litehook.h>
#include <LiveProcessLegacy/LPLLSPatchcache.h>
#include <mach/mach.h>

bool performHookDyldApi(const char* functionName,
                        uint32_t adrpOffset,
                        void** origFunction,
                        void* hookFunction)
{
    void *handle = dlopen("/usr/lib/system/libdyld.dylib", RTLD_NOW | RTLD_NOLOAD);
    uint32_t *baseAddr = dlsym(handle, functionName);
    assert(baseAddr != 0);
    uint32_t* adrpInstPtr = baseAddr + adrpOffset;

    // find the following instruction pattern: 1 adrp + 2 ldr
    // adrp    x8, 0x1e6cf0000
    // ldr     x0, [x8, #0x30]  {dyld4::gAPIs}
    // ldr     x16, [x0]
    
    static long adrpExtraOffset = -1;
    if(adrpExtraOffset == -1)
    {
        // let't hope the function is not longer than 200 instructions
        uint32_t* end = baseAddr + 200;
        for(uint32_t* cur = adrpInstPtr;cur < end;++cur)
        {
            if((*cur & 0x9f000000) != 0x90000000)
            {
                continue;
            }
            if((*(cur+1) & 0xFFC00000) != 0xF9400000)
            {
                continue;
            }
            if((*(cur+2) & 0xFFC00000) != 0xF9400000)
            {
                continue;
            }
            adrpExtraOffset = cur - adrpInstPtr;
            break;
        }
        assert(adrpExtraOffset != -1);
    }
    
    adrpInstPtr += adrpExtraOffset;

    void* gdyldPtr = (void*)aarch64_emulate_adrp_ldr(*adrpInstPtr, *(adrpInstPtr + 1), (uint64_t)adrpInstPtr);
    
    assert(gdyldPtr != 0);
    assert(*(void**)gdyldPtr != 0);
    void* vtablePtr = **(void***)gdyldPtr;
    
    void* vtableFunctionPtr = 0;
    uint32_t* movInstPtr = adrpInstPtr + 6;

    if((*movInstPtr & 0x7F800000) == 0x52800000)
    {
        // arm64e, mov imm + add + ldr
        uint32_t imm16 = (*movInstPtr & 0x1FFFE0) >> 5;
        vtableFunctionPtr = vtablePtr + imm16;
    }
    else if ((*movInstPtr & 0xFFE00C00) == 0xF8400C00)
    {
        // arm64e, ldr immediate Pre-index 64bit
        uint32_t imm9 = (*movInstPtr & 0x1FF000) >> 12;
        vtableFunctionPtr = vtablePtr + imm9;
    }
    else
    {
        // arm64
        uint32_t* ldrInstPtr2 = adrpInstPtr + 3;
        assert((*ldrInstPtr2 & 0xBFC00000) == 0xB9400000);
        uint32_t size2 = (*ldrInstPtr2 & 0xC0000000) >> 30;
        uint32_t imm12_2 = (*ldrInstPtr2 & 0x3FFC00) >> 10;
        vtableFunctionPtr = vtablePtr + (imm12_2 << size2);
    }
    
    kern_return_t ret = builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if(ret != KERN_SUCCESS)
    {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_rw();
    }
    
    if(origFunction != NULL)
    {
        *origFunction = (void*)*(void**)vtableFunctionPtr;
    }
    
    *(uint64_t*)vtableFunctionPtr = (uint64_t)hookFunction;
    builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ);
    if(ret != KERN_SUCCESS)
    {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_ro();
    }
    return true;
}

bool performHookDyldApiFast(int ptrcacheIndex,
                            void** origFunction,
                            void* hookFunction)
{
    if(!ksurface_user_patchcache_load())
    {
        return false;
    }
    
    void* vtableFunctionPtr = (void*)patchcache[ptrcacheIndex];
    
    kern_return_t ret = builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if(ret != KERN_SUCCESS)
    {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_rw();
    }
    
    if(origFunction != NULL)
    {
        *origFunction = (void*)*(void**)vtableFunctionPtr;
    }
    
    *(uint64_t*)vtableFunctionPtr = (uint64_t)hookFunction;
    builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ);
    if(ret != KERN_SUCCESS)
    {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_ro();
    }
    return true;
}
