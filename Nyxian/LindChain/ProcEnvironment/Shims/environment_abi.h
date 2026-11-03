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

#ifndef PROCENVIRONMENT_ENVIRONMENT_ABI_H
#define PROCENVIRONMENT_ENVIRONMENT_ABI_H

#include <mach/mach.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void environment_connect_syscall_proxy_c(mach_port_t port, bool sendOnce);
int environment_init_c(long exec, const char *path, int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* PROCENVIRONMENT_ENVIRONMENT_ABI_H */
