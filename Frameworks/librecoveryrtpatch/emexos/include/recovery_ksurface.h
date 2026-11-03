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

/*
 * librecoveryksurface: the mini KSurface the recovery (TWRP) loads on demand.
 *
 * It speaks the same syscall wire format as KSurface NXT2 (LiveShim's
 * liveshim_syscall), so the unmodified LiveProcess guest runtime runs on it,
 * but it only implements what a recovery shell needs: processes, sessions,
 * process groups, wait4, signals, the TTY layer, the vroot and signing on
 * demand (SYS_sign / SYS_sign2). There is no entitlement system: every check
 * a ROM kernel would make is dropped, because this is a recovery.
 *
 * The bootloader never links it. NXRecoveryTerminal dlopen()s it from the
 * bundle's Frameworks directory and resolves the entry points below by name.
 */

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RKS_ABI_VERSION         1

/*
 * Layout of the recovery root (~/Library/TWRP), relative to it. The root is
 * the vroot (SYS_vroot). The binpack is the roothide jbroot ("/" and HOME of
 * the shell) and libroothide only accepts a jbroot named "procursus", hence
 * the same opt/procursus as emexOS's $vroot/opt/procursus.
 *
 * roothide's ROOTFS (/rootfs in the shell) is rootfs/ in the vroot: the
 * bootloader's container as guests can reach it. ROOTFS has to be a directory
 * guests hold a sandbox extension for (libroothide stat()s it on every path it
 * translates) and the sandbox issues none for the container root or ~/Library,
 * only for the directories in them. So rootfs/ links every top-level directory
 * of the container (SystemData excluded) and, in a real rootfs/Library/, every
 * entry of ~/Library; guests get an extension per link target, and rootfs/dev/
 * is the /dev the binpack's dev -> /dev resolves to.
 */
#define RKS_LAYOUT_VROOT        "Library/TWRP"      /* relative to the bootloader's container */
#define RKS_LAYOUT_JBROOT       "opt/procursus"
#define RKS_LAYOUT_ROOTFS       "rootfs"
#define RKS_LAYOUT_SKIP         "SystemData"        /* not accessible to the app: never linked or granted */
#define RKS_LAYOUT_RTPATCH      "boot/rtpatch"
#define RKS_LAYOUT_BOOTLOADER   "boot/bootloader"

/* file names inside the bundle's Frameworks directory */
#define RKS_LIBRARY_NAME        "librecoveryksurface.dylib"
#define RKS_RTPATCH_NAME        "librecoveryrtpatch.dylib"

/*
 * Recovery-only syscalls. They sit far above KSurface NXT2's numbers and the
 * procursus jailed SYS_sign2 (1000), a ROM kernel answers them with ENOSYS.
 */
/* KSurface's posix_spawn without NSXPC (emexOS ksurface_abi.h), used by the vendored fork emulation */
#define RKS_SYS_spawn           766
#define RKS_SYS_spawn_bootstrap 767     /* not served: the guest treats ENOSYS as "no override" */
#define RKS_SYS_exitstatus      1100    /* args[0]: status the guest passed to exit(), sent by librecoveryrtpatch */

/* procursus jailed: resign a path on demand, emexOS's number (Nyxian's ksurface_abi.h predates it) */
#ifndef SYS_sign2
#define SYS_sign2               1000
#endif

typedef struct rks_boot_args {
    uint32_t version;                       /* RKS_ABI_VERSION */
    uint32_t size;                          /* sizeof(rks_boot_args_t) */
    const char *root;                       /* ~/Library/TWRP */
    const char *bundle;                     /* the bootloader bundle */
    int (*sign)(const char *path);          /* resign a Mach-O in place (no-op when already valid), 0 or an errno */
    void (*log)(const char *message);       /* optional */
} rks_boot_args_t;

/* called on an arbitrary thread when a process the recovery itself spawned exits, status is a wait(2) status */
typedef void (*rks_exit_handler_t)(pid_t pid, int status, void *context);

/* entry points, resolved with dlsym() under these names */
typedef int  (*rks_boot_fn)(const rks_boot_args_t *args);
typedef int  (*rks_spawn_terminal_fn)(const char *path, char *const argv[], char *const envp[], const char *cwd,
                                      unsigned short rows, unsigned short cols, int *master_fd, pid_t *pid);
typedef int  (*rks_tty_set_winsize_fn)(int master_fd, unsigned short rows, unsigned short cols);
typedef int  (*rks_signal_fn)(pid_t pid, int sig);
typedef void (*rks_set_exit_handler_fn)(rks_exit_handler_t handler, void *context);

/* starts the syscall server and the spawn server; idempotent, 0 or an errno */
int rks_boot(const rks_boot_args_t *args);

/*
 * spawns path as a session leader with a fresh TTY as its controlling
 * terminal on fds 0-2. *master_fd is the terminal's end (read output, write
 * input), owned by the caller.
 */
int rks_spawn_terminal(const char *path, char *const argv[], char *const envp[], const char *cwd,
                       unsigned short rows, unsigned short cols, int *master_fd, pid_t *pid);

/* TIOCSWINSZ from the terminal's side, SIGWINCH to the foreground job when it changed */
int rks_tty_set_winsize(int master_fd, unsigned short rows, unsigned short cols);

/* signal a recovery process (job control semantics like kill(2) from the kernel) */
int rks_signal(pid_t pid, int sig);

void rks_set_exit_handler(rks_exit_handler_t handler, void *context);

#ifdef __cplusplus
}
#endif

#endif /* RECOVERY_KSURFACE_H */
