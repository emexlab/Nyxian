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

#ifndef RECOVERY_KSURFACE_H
#define RECOVERY_KSURFACE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RKS_ABI_VERSION         1

#define RKS_LAYOUT_VROOT        "Library/TWRP"
#define RKS_LAYOUT_JBROOT       "opt/procursus"
#define RKS_LAYOUT_ROOTFS       "rootfs"
#define RKS_LAYOUT_SKIP         "SystemData"
#define RKS_LAYOUT_RTPATCH      "boot/rtpatch"
#define RKS_LAYOUT_BOOTLOADER   "boot/bootloader"

#define RKS_LIBRARY_NAME        "librecoveryksurface.dylib"
#define RKS_RTPATCH_NAME        "librecoveryrtpatch.dylib"

#define RKS_SYS_spawn           766
#define RKS_SYS_spawn_bootstrap 767
#define RKS_SYS_exitstatus      1100

#ifndef SYS_sign2
#define SYS_sign2               1000
#endif

typedef struct rks_boot_args {
    uint32_t version;
    uint32_t size;
    const char *root;
    const char *bundle;
    int (*sign)(const char *path);
    void (*log)(const char *message);
} rks_boot_args_t;

typedef void (*rks_exit_handler_t)(pid_t pid, int status, void *context);

typedef int  (*rks_boot_fn)(const rks_boot_args_t *args);
typedef int  (*rks_spawn_terminal_fn)(const char *path, char *const argv[], char *const envp[], const char *cwd,
                                      unsigned short rows, unsigned short cols, int *master_fd, pid_t *pid);
typedef int  (*rks_tty_set_winsize_fn)(int master_fd, unsigned short rows, unsigned short cols);
typedef int  (*rks_signal_fn)(pid_t pid, int sig);
typedef void (*rks_set_exit_handler_fn)(rks_exit_handler_t handler, void *context);

int rks_boot(const rks_boot_args_t *args);
int rks_spawn_terminal(const char *path, char *const argv[], char *const envp[], const char *cwd, unsigned short rows, unsigned short cols, int *master_fd, pid_t *pid);
int rks_tty_set_winsize(int master_fd, unsigned short rows, unsigned short cols);
int rks_signal(pid_t pid, int sig);
void rks_set_exit_handler(rks_exit_handler_t handler, void *context);

#ifdef __cplusplus
}
#endif

#endif /* RECOVERY_KSURFACE_H */
