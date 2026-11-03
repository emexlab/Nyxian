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

#ifndef LIVESHIMPREFS_H
#define LIVESHIMPREFS_H

#include <stdint.h>
#include <mach/mach.h>
#include <sys/syscall.h>

typedef struct syscall_client syscall_client_t;

extern syscall_client_t *syscallProxy;

syscall_client_t *liveshim_syscall_client_create(mach_port_t port);
int64_t liveshim_syscall_invoke(syscall_client_t *client, uint32_t syscall_num, int64_t *args, mach_port_t *in_ports, uint32_t in_ports_cnt, mach_msg_type_name_t in_type, mach_port_t **out_ports, uint32_t out_ports_cnt);

int64_t liveshim_syscall(uint32_t syscall_num, ...);

#endif /* LIVESHIMPREFS_H */
