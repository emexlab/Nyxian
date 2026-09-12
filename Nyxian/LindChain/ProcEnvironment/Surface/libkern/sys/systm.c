/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 semvis123

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#include <LindChain/ProcEnvironment/Surface/libkern/sys/systm.h>
#include <LindChain/Private/mach/mach_vm.h>
#include <assert.h>

kern_return_t syscall_payload_create(void *ptr,
                                     size_t size,
                                     mach_vm_address_t *mach_vm_address)
{
    kern_return_t kr = mach_vm_allocate(mach_task_self(), mach_vm_address, size, VM_FLAGS_ANYWHERE);
    if(kr == KERN_SUCCESS && ptr != NULL)
    {
        /* you belong into here buffer pointed to by ptr ^^ */
        memcpy((void*)(*mach_vm_address), ptr, size);
    }
    
    /* returning the kernels opinion of all this :/ (mom, i didnt broke the vase) */
    return kr;
}

bool syscall_copy_in(task_t task,
                     size_t size,
                     kernelspace_pointer_t kptr,
                     userspace_pointer_t src)
{
    assert(kptr != NULL);
    
    if(src == NULL)
    {
        return false;
    }
    
    /*
     * reading userspace buffer into virtual kernel
     * space.
     */
    mach_vm_size_t reply = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (vm_address_t)src, size, (vm_address_t)kptr, &reply);
    if(kr != KERN_SUCCESS || reply < size)
    {
        return false;
    }
    
    return true;
}

kernelspace_pointer_t syscall_alloc_in(task_t task,
                                       size_t size,
                                       userspace_pointer_t src)
{
    if(src == NULL)
    {
        return NULL;
    }
    
    /*
     * allocate zeroed out kernelspace buffer,
     * so this doesnt become a attack vector some day
     */
    kernelspace_pointer_t kptr = calloc(1, size);
    if(kptr == NULL)
    {
        return NULL;
    }
    
    if(!syscall_copy_in(task, size, kptr, src))
    {
        free(kptr);
        return NULL;
    }
    
    return kptr;
}

bool syscall_copy_out(task_t task,
                      size_t size,
                      kernelspace_pointer_t kptr,
                      userspace_pointer_t dst)
{
    assert(kptr != NULL);
    
    if(dst == NULL)
    {
        return false;
    }
    
    /*
     * copy kernel buffer into virtualised userspace
     * dont worry tho we dont need to know how much
     * was written, because thats not our buisness.
     */
    kern_return_t kr = mach_vm_write(task, (mach_vm_address_t)dst, (mach_vm_offset_t)kptr, (mach_msg_type_number_t)size);
    if(kr != KERN_SUCCESS)
    {
        
        return false;
    }
    
    return true;
}

char *syscall_copy_str_in(task_t task,
                          userspace_pointer_t src,
                          size_t len)
{
    if(len == SIZE_MAX)
    {
        return NULL;
    }
    
    size_t cap = (len < 1024 ? len : 1024) + 1;
    char *buf = malloc(cap);
    if(!buf)
    {
        return NULL;
    }
    
    size_t off = 0;
    while(off < len)
    {
        mach_vm_address_t addr = (mach_vm_address_t)src + off;
        mach_vm_size_t want = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
        
        if(want > len - off)
        {
            want = len - off;
        }
        
        if(want > cap - 1 - off)
        {
            size_t ncap = cap * 2;
            if(ncap < off + want + 1)
            {
                ncap = off + want + 1;
            }
            char *nbuf = realloc(buf, ncap);
            if(!nbuf)
            {
                free(buf);
                return NULL;
            }
            buf = nbuf;
            cap = ncap;
        }
        
        mach_vm_size_t rlen = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, addr, want, (mach_vm_address_t)(buf + off), &rlen);
        if(kr != KERN_SUCCESS || rlen != want)
        {
            free(buf);
            return NULL;
        }
        
        char *nul = memchr(buf + off, '\0', want);
        if(nul)
        {
            size_t total = (size_t)(nul - buf);
            char *shrunk = realloc(buf, total + 1);
            return shrunk ? shrunk : buf;
        }
        
        off += want;
    }
    
    buf[off] = '\0';
    return buf;
}
