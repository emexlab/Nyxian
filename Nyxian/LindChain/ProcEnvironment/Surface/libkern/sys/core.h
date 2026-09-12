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

#ifndef SYS_CORE_H
#define SYS_CORE_H

#include <LindChain/ProcEnvironment/Surface/libkern/sys/worker.h>
#include <os/lock.h>
#include <stdint.h>

#define SYSCALL_QUEUE_LIMIT     32
#define SYSCALL_HANDLERS_LIMIT  UINT16_MAX

struct syscall_server {
    mach_port_t port;
    pthread_t *threads;
    int threads_cnt;
    atomic_flag init_once;
    os_unfair_lock lock;
    syscall_handler_t handlers[SYSCALL_HANDLERS_LIMIT]; /* for performance reasons this array has to stay flat */
};

syscall_server_t *syscall_server_create(void);
int syscall_server_start(syscall_server_t *server);

void syscall_server_register(syscall_server_t *server, uint32_t syscall_num, syscall_handler_t handler);
syscall_handler_t syscall_server_get_handler(syscall_server_t *server, uint32_t syscall_num);

mach_port_t syscall_server_get_port(syscall_server_t *server);

#endif /* SYS_CORE_H */
