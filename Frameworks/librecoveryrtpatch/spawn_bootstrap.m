/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2026 emexlab
 Copyright (C) 2026 roothider

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

#include "spawn_bootstrap.h"
#include "ksurface_abi.h"
#include <LiveProcessLegacy/LPLSyscall.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <stdlib.h>

typedef struct {
    int32_t kind;
    uint32_t mask;
    mach_port_t port;
    int32_t behavior, flavor, which;
} pe_spawn_port_action_t;

typedef struct { int32_t allocated, count; } pe_spawn_port_actions_t;
_Static_assert(sizeof(pe_spawn_port_action_t) == 24, "Darwin port-action stride");
_Static_assert(sizeof(pe_spawn_port_actions_t) == 8, "Darwin port-action header");

extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
static size_t port_actions_offset = SIZE_MAX;
static mach_port_t initial_bootstrap;
static bool initialized;

static bool read_memory(uintptr_t address,
                        void *destination,
                        size_t size)
{
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), address, size, (mach_vm_address_t)destination, &copied) == KERN_SUCCESS && copied == size;
}

static bool bootstrap_action(const pe_spawn_port_action_t *action)
{
    return action->kind == 0 && action->which == TASK_BOOTSTRAP_PORT && action->mask == 0 && action->behavior == 0 && action->flavor == 0;
}

static void discover_port_actions(void)
{
    posix_spawnattr_t probe;
    if(posix_spawnattr_init(&probe) != 0)
    {
        return;
    }
    size_t size = malloc_size(probe);
    unsigned char *before = size <= 4096 ? malloc(size) : NULL;
    if(before != NULL)
    {
        memcpy(before, probe, size);
        if(posix_spawnattr_setspecialport_np(&probe, mach_task_self(), TASK_BOOTSTRAP_PORT) == 0)
        {
            for(size_t offset = 0; offset + sizeof(uintptr_t) <= size; offset += sizeof(uintptr_t))
            {
                uintptr_t original, candidate;
                memcpy(&original, before + offset, sizeof(original));
                memcpy(&candidate, (char *)probe + offset, sizeof(candidate));
                if(original != 0 || candidate == 0)
                {
                    continue;
                }
                
                struct {
                    pe_spawn_port_actions_t header;
                    pe_spawn_port_action_t action;
                } record;
                
                if(!read_memory(candidate, &record, sizeof(record)))
                {
                    continue;
                }
                if(record.header.count != 1 || record.header.allocated < 1 || !bootstrap_action(&record.action) || record.action.port != mach_task_self())
                {
                    continue;
                }
                if(port_actions_offset != SIZE_MAX)
                {
                    port_actions_offset = SIZE_MAX;
                    break;
                }
                port_actions_offset = offset;
            }
        }
        free(before);
    }
    posix_spawnattr_destroy(&probe);
}

int pe_spawn_bootstrap_copy(const posix_spawnattr_t *attr,
                            bool *present,
                            mach_port_t *port)
{
    *present = false;
    *port = MACH_PORT_NULL;
    if(attr != NULL)
    {
        static pthread_once_t discovery = PTHREAD_ONCE_INIT;
        pthread_once(&discovery, discover_port_actions);
        
        if(port_actions_offset == SIZE_MAX)
        {
            return ENOTSUP;
        }
        
        uintptr_t base, list;
        if(!read_memory((uintptr_t)attr, &base, sizeof(base)) || base == 0 || !read_memory(base + port_actions_offset, &list, sizeof(list)))
        {
            return EINVAL;
        }
        
        if(list != 0)
        {
            pe_spawn_port_actions_t header;
            if(!read_memory(list, &header, sizeof(header)) || header.count < 0 || header.allocated < header.count || header.count > 1024)
            {
                return EINVAL;
            }
            
            size_t bytes = (size_t)header.count * sizeof(pe_spawn_port_action_t);
            pe_spawn_port_action_t *actions = bytes ? malloc(bytes) : NULL;
            if(bytes && actions == NULL)
            {
                return ENOMEM;
            }
            
            if(bytes && !read_memory(list + sizeof(header), actions, bytes))
            {
                free(actions);
                return EINVAL;
            }
            
            for(int32_t i = 0; i < header.count; i++)
            {
                if(actions[i].kind != 0 || actions[i].which != TASK_BOOTSTRAP_PORT)
                {
                    continue;
                }
                if(!bootstrap_action(&actions[i]))
                {
                    free(actions);
                    return EINVAL;
                }
                *present = true;
                *port = actions[i].port;
            }
            
            free(actions);
            if(*present)
            {
                if(*port == MACH_PORT_NULL)
                {
                    return 0;
                }
                if(*port == MACH_PORT_DEAD || mach_port_mod_refs(mach_task_self(), *port, MACH_PORT_RIGHT_SEND, 1) != KERN_SUCCESS)
                {
                    *port = MACH_PORT_NULL;
                    return EINVAL;
                }
                return 0;
            }
        }
    }
    
    if(!initialized)
    {
        return 0;
    }
    
    mach_port_t current = MACH_PORT_NULL;
    if(task_get_bootstrap_port(mach_task_self(), &current) != KERN_SUCCESS) return EINVAL;
    if(current == initial_bootstrap)
    {
        if(MACH_PORT_VALID(current)) mach_port_deallocate(mach_task_self(), current);
        return 0;
    }
    
    *present = true;
    *port = current;
    return 0;
}

int pe_spawn_bootstrap_initialize(void)
{
    if(task_get_bootstrap_port(mach_task_self(), &initial_bootstrap) != KERN_SUCCESS)
    {
        return EINVAL;
    }
    
    initialized = true;
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t *output[] = { &port };
    int64_t args[6] = {0};
    int64_t result = liveshim_syscall_invoke(syscallProxy, SYS_spawn_bootstrap, args, NULL, 0, MACH_MSG_TYPE_COPY_SEND, output, 1);
    if(result < 0)
    {
        int error = errno;
        if(MACH_PORT_VALID(port))
        {
            mach_port_deallocate(mach_task_self(), port);
        }
        return error == ENOSYS ? 0 : (error ? error : EIO);
    }
    
    if(result == 0 && port == MACH_PORT_NULL)
    {
        return 0;
    }
    
    if((result != KSURFACE_BOOTSTRAP_SET && result != KSURFACE_BOOTSTRAP_CLEAR) || ((result == KSURFACE_BOOTSTRAP_SET) != MACH_PORT_VALID(port)))
    {
        if(MACH_PORT_VALID(port))
        {
            mach_port_deallocate(mach_task_self(), port);
        }
        return EPROTO;
    }
    
    if(task_set_bootstrap_port(mach_task_self(), port) != KERN_SUCCESS)
    {
        if(MACH_PORT_VALID(port))
        {
            mach_port_deallocate(mach_task_self(), port);
        }
        return EPERM;
    }
    
    mach_port_t previous = bootstrap_port;
    bootstrap_port = port;
    if(MACH_PORT_VALID(previous))
    {
        mach_port_deallocate(mach_task_self(), previous);
    }
    
    return 0;
}
