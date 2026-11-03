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

/*
 * librecoveryrtpatch: the runtime patch of the recovery, its roothideinit.
 *
 * Laid out like emexOS: the guest runtime dlopen()s $vroot/boot/rtpatch before
 * the guest program, and that is the binpack's libroothide. libroothide links
 * @loader_path/.jbroot/usr/lib/roothideinit.dylib, a symlink to this library in
 * the bootloader bundle (NXRecoveryTerminal refreshes it on every start). So
 * this library is loaded exactly once per process, as libroothide's dependency,
 * and its initializers run before libroothide's. The binpack's libroothide and
 * libvroot (built by emexOS) import exactly the three __roothideinit_* globals.
 *
 * What it does:
 *   - roothide's roots: ROOTFS = vroot/rootfs (/rootfs in the shell, the
 *     bootloader's container through links), JBROOT = vroot/opt/procursus
 *     (the binpack, "/" of the shell)
 *   - signing on demand like emexOS: the guest runtime's dlopen hardware
 *     breakpoint context has a hook on dyld's stat64, every Mach-O dyld is
 *     about to load is checked and resigned with SYS_sign2 when it is not
 *     signed for us (the binpack ships unsigned)
 *   - reports the status a process passes to exit() (RKS_SYS_exitstatus),
 *     for when the mini kernel cannot learn it from FrontBoard
 *   - emexOS's fork emulation (emexos/: vfork.m, posix_spawn.m and
 *     spawn_bootstrap.c, vendored unmodified). Their constructors install it on
 *     top of the guest runtime's own fork emulation, exactly like emexOS's
 *     roothideinit: the fake child's setpgid/setsid/tcsetpgrp go to the
 *     spawned process instead of the shell, fds are journaled and restored.
 *
 * No tweak injection, no launchd namespace, no patchcache-only dyld hooks:
 * the binpack's per-directory .jbroot symlinks resolve @loader_path/.jbroot
 * without patching dyld. The guest runtime's symbols are bound at load time
 * (-undefined dynamic_lookup, like emexOS) or looked up with dlsym.
 */

#include <Recovery/include/recovery_ksurface.h>
#include <Broadpatch/Broadpatch.h>    /* emexos/include */
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <os/lock.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXPORT __attribute__((visibility("default"))) __attribute__((used))

/* roothideinit ABI */
EXPORT const char *__roothideinit_JBRAND = NULL;
EXPORT const char *__roothideinit_JBROOT = NULL;
EXPORT const char *__roothideinit_ROOTFS = NULL;

/* nonzero once the hooks are installed in this process (by whichever copy dyld loaded first) */
EXPORT int rks_rtpatch_state = 0;

/* guest runtime (LiveShim / libLiveProcessLegacy) */
typedef int64_t (*liveshim_syscall_fn)(uint32_t num, ...);
typedef const char *(*liveshim_vroot_fn)(void);
typedef void *(*lc_map_fn)(const char *path, bool readOnly);
typedef bool (*lc_check_fn)(void *macho);
typedef void (*lc_unmap_fn)(void *macho);
typedef void *(*hwhook_context_fn)(void);
typedef CFArrayRef (*hwhook_get_hooks_fn)(void *context);
typedef void *(*hwhook_get_replacement_fn)(void *hook);
typedef void (*hwhook_set_replacement_fn)(void *hook, void *replacement);

static liveshim_syscall_fn g_syscall;
static lc_map_fn g_map;
static lc_check_fn g_check;
static lc_unmap_fn g_unmap;

static void rtpatch_log(const char *message)
{
    fprintf(stderr, "librecoveryrtpatch: %s\n", message);
}

/* ----------------------------------------------------------------------
 *  signing on demand (emexOS roothideinit's dlopen stat64 hook)
 * -------------------------------------------------------------------- */

typedef struct {
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtime;
} rtpatch_checked_t;

#define RTPATCH_CHECKED_MAX 256
static rtpatch_checked_t g_checked[RTPATCH_CHECKED_MAX];
static size_t g_checked_next, g_checked_count;
static os_unfair_lock g_checked_lock = OS_UNFAIR_LOCK_INIT;

static bool rtpatch_checked_lookup(const struct stat *st)
{
    bool found = false;
    os_unfair_lock_lock(&g_checked_lock);
    for(size_t i = 0; i < g_checked_count; i++)
    {
        rtpatch_checked_t *e = &g_checked[i];
        if(e->ino == st->st_ino && e->dev == st->st_dev && e->size == st->st_size &&
           e->mtime.tv_sec == st->st_mtimespec.tv_sec && e->mtime.tv_nsec == st->st_mtimespec.tv_nsec)
        {
            found = true;
            break;
        }
    }
    os_unfair_lock_unlock(&g_checked_lock);
    return found;
}

static void rtpatch_checked_insert(const struct stat *st)
{
    os_unfair_lock_lock(&g_checked_lock);
    rtpatch_checked_t *e = &g_checked[g_checked_next];
    e->dev = st->st_dev;
    e->ino = st->st_ino;
    e->size = st->st_size;
    e->mtime = st->st_mtimespec;
    g_checked_next = (g_checked_next + 1) % RTPATCH_CHECKED_MAX;
    if(g_checked_count < RTPATCH_CHECKED_MAX)
    {
        g_checked_count++;
    }
    os_unfair_lock_unlock(&g_checked_lock);
}

static int (*g_stat_next)(const char *path, struct stat *buf);

static int rtpatch_dyld_stat64(const char *path, struct stat *buf)
{
    int ret = g_stat_next(path, buf);
    if(ret != 0 || !S_ISREG(buf->st_mode) || rtpatch_checked_lookup(buf))
    {
        return ret;
    }

    void *macho = g_map(path, true);
    if(macho == NULL)
    {
        /* not a Mach-O (or unreadable): let dyld produce its own error */
        return ret;
    }
    bool valid = g_check(macho);
    g_unmap(macho);

    if(!valid)
    {
        /* resign, the file changed so stat it again */
        g_syscall(SYS_sign2, path);
        return g_stat_next(path, buf);
    }

    rtpatch_checked_insert(buf);
    return ret;
}

static bool rtpatch_install_sign_hook(void)
{
    hwhook_context_fn context_fn = (hwhook_context_fn)dlsym(RTLD_DEFAULT, "HWHookDlopenThreadContext");
    hwhook_get_hooks_fn get_hooks = (hwhook_get_hooks_fn)dlsym(RTLD_DEFAULT, "HWHookThreadContextGetHooks");
    hwhook_get_replacement_fn get_replacement = (hwhook_get_replacement_fn)dlsym(RTLD_DEFAULT, "HWHookGetReplacementPtr");
    hwhook_set_replacement_fn set_replacement = (hwhook_set_replacement_fn)dlsym(RTLD_DEFAULT, "HWHookSetReplacementPtr");
    g_map = (lc_map_fn)dlsym(RTLD_DEFAULT, "LCMapMachO");
    g_check = (lc_check_fn)dlsym(RTLD_DEFAULT, "LCCheckCodeSignature");
    g_unmap = (lc_unmap_fn)dlsym(RTLD_DEFAULT, "LCUnmapMachO");
    if(context_fn == NULL || get_hooks == NULL || get_replacement == NULL || set_replacement == NULL ||
       g_map == NULL || g_check == NULL || g_unmap == NULL)
    {
        rtpatch_log("guest runtime lacks the dlopen hook context, dependencies are not resigned on demand");
        return false;
    }

    void *context = context_fn();
    CFArrayRef hooks = context ? get_hooks(context) : NULL;
    /* LiveShim's dlopen context: fcntl, open, fstat64, stat64, openat */
    if(hooks == NULL || CFArrayGetCount(hooks) < 4)
    {
        rtpatch_log("no dlopen hook context (patchcache missing?), dependencies are not resigned on demand");
        return false;
    }
    void *stat_hook = (void *)CFArrayGetValueAtIndex(hooks, 3);
    g_stat_next = (int (*)(const char *, struct stat *))get_replacement(stat_hook);
    if(g_stat_next == NULL)
    {
        return false;
    }
    set_replacement(stat_hook, (void *)rtpatch_dyld_stat64);
    return true;
}

/* ----------------------------------------------------------------------
 *  exit status
 * -------------------------------------------------------------------- */

static void (*g_exit_next)(int status);
static int g_exit_status;
static bool g_exit_called;

static void rtpatch_exit(int status)
{
    /* the fork emulation's fake children call exit() too, the last call before the real exit wins */
    g_exit_status = status;
    g_exit_called = true;
    g_exit_next(status);
    __builtin_unreachable();
}

static void rtpatch_report_exit(void)
{
    if(g_exit_called)
    {
        g_syscall(RKS_SYS_exitstatus, (int64_t)g_exit_status);
    }
}

static void rtpatch_install_exit_report(void)
{
    /* Broadpatch's interpose-patchable exit from the guest runtime */
    void **exit_ptr = (void **)dlsym(RTLD_DEFAULT, "exit__ptr");
    if(exit_ptr == NULL || *exit_ptr == NULL)
    {
        return;
    }
    g_exit_next = (void (*)(int))*exit_ptr;
    *exit_ptr = (void *)rtpatch_exit;
    /* registered before the guest program loads, so it runs after the program's own handlers */
    atexit(rtpatch_report_exit);
}

/* ----------------------------------------------------------------------
 *  init
 * -------------------------------------------------------------------- */

/* ----------------------------------------------------------------------
 *  DyldHooksInit (like emexOS's roothideinit)
 * -------------------------------------------------------------------- */

/*
 * LCBootstrapMain runs the guest runtime's DyldHooksInit for every guest. Like
 * emexOS's roothideinit, keep everything it sets up except its dlopen_hook
 * patch (an in-process signature check and SYS_sign on every dlopen): signing
 * on demand is this library's stat64 hook, and emexOS guests, whose fork
 * emulation this library carries, never run with that patch installed.
 */
extern void *dlopen_hook__ptr;

LIBKERN_PATCH(void, DyldHooksInit, (void),
{
    void *dlopen_hook_backup = dlopen_hook__ptr;
    LIBKERN_ORIG(DyldHooksInit)();
    dlopen_hook__ptr = dlopen_hook_backup;
});

/* emexos/spawn_bootstrap.c */
int pe_spawn_bootstrap_initialize(void);

/*
 * Runs before every other initializer of this library (priority 101): the exit
 * report hooks exit() first, so emexOS's fork emulation (installed after it,
 * by emexos/vfork.m's constructor) sits on top and a fake child's exit() goes
 * back to its parent without ever reaching the report.
 */
__attribute__((constructor(101)))
static void rtpatch_init(void)
{
    g_syscall = (liveshim_syscall_fn)dlsym(RTLD_DEFAULT, "liveshim_syscall");
    liveshim_vroot_fn vroot_fn = (liveshim_vroot_fn)dlsym(RTLD_DEFAULT, "liveshim_vroot");
    const char *vroot = vroot_fn ? vroot_fn() : NULL;
    if(g_syscall == NULL || vroot == NULL || vroot[0] != '/')
    {
        rtpatch_log("not running inside a recovery guest (no syscall proxy / vroot)");
        return;
    }

    /* ROOTFS (/rootfs) is the container as vroot/rootfs links it, the jbroot lives in the vroot */
    char *jbroot = NULL;
    char *rootfs = NULL;
    if(asprintf(&jbroot, "%s/%s", vroot, RKS_LAYOUT_JBROOT) < 0 ||
       asprintf(&rootfs, "%s/%s", vroot, RKS_LAYOUT_ROOTFS) < 0)
    {
        return;
    }
    __roothideinit_ROOTFS = rootfs;
    __roothideinit_JBROOT = jbroot;
    __roothideinit_JBRAND = "";

    /* but only the first one hooks */
    int *first = (int *)dlsym(RTLD_DEFAULT, "rks_rtpatch_state");
    if(first != NULL && first != &rks_rtpatch_state && *first != 0)
    {
        return;
    }
    rks_rtpatch_state = 1;

    rtpatch_install_sign_hook();
    rtpatch_install_exit_report();
    LIBKERN_INSTALL_PATCH(DyldHooksInit);

    /* like emexOS's roothideinit, before any guest code: the recovery kernel answers ENOSYS, which is fine */
    int err = pe_spawn_bootstrap_initialize();
    if(err != 0)
    {
        fprintf(stderr, "librecoveryrtpatch: spawn bootstrap: %s\n", strerror(err));
    }
}
