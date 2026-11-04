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

#include <LindChain/Utils/NXBootLockdown.h>
#include <mach/mach.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <stdatomic.h>
#include <stdio.h>

static atomic_bool NXBootLocked;

NX_BOOT_ONLY static int NXBootLockdownProbe(void)
{
    return 0x4E58;
}

bool NXBootLockdownActive(void)
{
    return atomic_load(&NXBootLocked);
}

bool NXBootLockdown(void)
{
    if(atomic_load(&NXBootLocked))
    {
        return true;
    }
    
    /* checking if necessary __BOOTONLY region exists */
    unsigned long length = 0;
    extern const struct mach_header_64 __dso_handle;
    uint8_t *start = getsegmentdata(&__dso_handle, "__BOOTONLY", &length);
    if(start == NULL || length == 0 || NXBootLockdownProbe() != 0x4E58)
    {
        return false;
    }
    
    /* now we validate that the region is kosher */
    vm_address_t address = (vm_address_t)start;
    if(address % vm_page_size != 0 || length % vm_page_size != 0 ||
       (vm_address_t)&NXBootLockdownProbe < address || (vm_address_t)&NXBootLockdownProbe >= address + length)
    {
        return false;
    }
    
    /* literally "removing" the mapping's of code */
    kern_return_t kr = vm_protect(mach_task_self(), address, length, TRUE, VM_PROT_NONE);
    if(kr == KERN_SUCCESS)
    {
        atomic_store(&NXBootLocked, true);
        kr = vm_protect(mach_task_self(), address, length, FALSE, VM_PROT_NONE);    /* just making sure */
    }
    if(kr != KERN_SUCCESS)
    {
        return false;
    }
    
    /* checking precisely if the __BOOTONLY protection actually worked */
    for(vm_address_t cursor = address; cursor < address + length;)
    {
        vm_address_t region = cursor;
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kr = vm_region_64(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        if(object != MACH_PORT_NULL)
        {
            mach_port_deallocate(mach_task_self(), object);
        }
        if(kr != KERN_SUCCESS || region > cursor || info.protection != VM_PROT_NONE || info.max_protection != VM_PROT_NONE)
        {
            return false;
        }
        cursor = region + size;
    }
    return true;
}
