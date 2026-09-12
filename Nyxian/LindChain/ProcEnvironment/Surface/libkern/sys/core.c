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

#include <LindChain/ProcEnvironment/Surface/libkern/sys/core.h>
#include <os/lock.h>

syscall_server_t* syscall_server_create(void)
{
    syscall_server_t *server = calloc(1, sizeof(syscall_server_t));
    if(server == NULL)
    {
        return NULL;
    }
    server->lock = OS_UNFAIR_LOCK_INIT;
    return server;
}

int syscall_server_start(syscall_server_t *server)
{
    assert(server != NULL);
    
    if(atomic_flag_test_and_set(&server->init_once))
    {
        ksurface_panic("syscall server was already initialized");
    }
    
    /*
     * we need a very special secure port that is
     * guarded, because this receive right shall never
     * be snatched by a attacker.
     */
    mach_port_options_t options = {
        .flags = MPO_PORT | MPO_IMMOVABLE_RECEIVE | MPO_INSERT_SEND_RIGHT | MPO_QLIMIT | MPO_STRICT | MPO_CONTEXT_AS_GUARD,
        .mpl = SYSCALL_QUEUE_LIMIT,
    };
    
    uint64_t guard_value;
    arc4random_buf(&guard_value, sizeof(guard_value));  /* random guard value because this secures the MPO_PORT even more */
    kern_return_t kr = mach_port_construct(mach_task_self(), &options, guard_value, &server->port);
    guard_value = 0;    /* from now on, not even ksurface can unguard it */
    if(kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), server->port);
        return -1;
    }
    
    /* now we spin the workers up (not AI lol) */
    extern int CCGetMaximumPerformanceCores(void);
    server->threads_cnt = (int)CCGetMaximumPerformanceCores();
    if(server->threads_cnt == 0)
    {
        ksurface_panic("got 0 return from CCGetMaximumPerformanceCores()");
    }
    server->threads = calloc(server->threads_cnt, sizeof(pthread_t));
    
    for(int i = 0; i < server->threads_cnt; i++)
    {
        pthread_create(&server->threads[i], NULL, syscall_worker, server);
    }
    
    return 0;
}

void syscall_server_register(syscall_server_t *server,
                             uint32_t syscall_num,
                             syscall_handler_t handler)
{
    assert(server != NULL && syscall_num < SYSCALL_HANDLERS_LIMIT && handler != NULL);
    
    os_unfair_lock_lock(&server->lock);
    server->handlers[syscall_num] = handler;
    os_unfair_lock_unlock(&server->lock);
}

syscall_handler_t syscall_server_get_handler(syscall_server_t *server,
                                             uint32_t syscall_num)
{
    os_unfair_lock_lock(&server->lock);
    syscall_handler_t handler = server->handlers[syscall_num];
    os_unfair_lock_unlock(&server->lock);
    return handler;
}

mach_port_t syscall_server_get_port(syscall_server_t *server)
{
    return server->port;
}
