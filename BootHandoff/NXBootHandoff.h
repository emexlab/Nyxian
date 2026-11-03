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

#ifndef NXBOOTHANDOFF_H
#define NXBOOTHANDOFF_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NX_BOOT_HANDOFF_VERSION 1

/* Who draws the verbose log. Can be changed at any time while the claim is live (NXBootHandoffSetConsoleModeV1). */
typedef uint32_t NXBootConsoleMode;
enum {
    NX_BOOT_CONSOLE_AUTO   = 0, /* follow the user's Verbose Boot flag, host draws it (exactly 0.11.6.1) */
    NX_BOOT_CONSOLE_HOST   = 1, /* host console shown, whatever the flag says */
    NX_BOOT_CONSOLE_HIDDEN = 2, /* nothing drawn; the log is still recorded so recovery can replay it */
    NX_BOOT_CONSOLE_ROM    = 3, /* host draws nothing, every line goes to the client's consoleLine() */
};

/* NXBootHandoffClientV1.flags */
enum {
    NX_BOOT_HANDOFF_HIDE_HOST_LOGO  = 1u << 0, /* the host's splash logo stays hidden for the whole handoff */
    NX_BOOT_HANDOFF_NO_VERBOSE_HOLD = 1u << 1, /* skip the 1.5 s console hold before the host transition */
};
#define NX_BOOT_HANDOFF_KNOWN_FLAGS_V1 (NX_BOOT_HANDOFF_HIDE_HOST_LOGO | NX_BOOT_HANDOFF_NO_VERBOSE_HOLD)

/* revoke() reasons */
enum {
    NX_BOOT_HANDOFF_REVOKE_BOOT_FAILED = 1, /* slot failed after the claim (no NXSlotMain, nil root, ...) */
    NX_BOOT_HANDOFF_REVOKE_RECOVERY    = 2, /* the bootloader is putting the recovery on screen */
    NX_BOOT_HANDOFF_REVOKE_TIMEOUT     = 3, /* transition() didn't call complete() in time, the host finished it */
};

/* Given to attach(), main thread. Pointers are valid until revoke() or until the transition completes. */
typedef struct NXBootHandoffSurfaceV1 {
    uint32_t version, size;
    void *windowScene;          /* UIWindowScene * */
    void *hostWindow;           /* UIWindow *, the bootloader's window */
    void *splashView;           /* UIView *, full screen boot splash. Add subviews / sublayers freely */
    void *logoView;             /* UIImageView *, the host's splash logo inside splashView */
    uint32_t verboseRequested;  /* -v in the boot arguments (NXBootArgs.h), on 0.11.6.1 the Verbose Boot flag */
    int32_t logFD;              /* the boot log fd (27); write lines here to have them shown / recorded */
} NXBootHandoffSurfaceV1;

typedef struct NXBootHandoffTransitionV1 {
    uint32_t version, size;
    void *hostWindow;           /* UIWindow * */
    void *splashView;           /* UIView * */
    void *logoView;             /* UIImageView * */
    void *slotWindow;           /* UIWindow * from NXSlotCreateWindow: root installed, key + visible, alpha 0.
                                   NULL when the ROM has no NXSlotCreateWindow, see rootViewController */
    void *rootViewController;   /* UIViewController * from NXSlotMain. Without a slotWindow it is already a child of
                                   the boot view controller, laid out full screen *below* splashView, alpha 1 */
    uint32_t consoleVisible;    /* the host console is on screen right now */
    uint32_t reduceMotion;      /* UIAccessibility.isReduceMotionEnabled */
    void (*complete)(void *token);
    void *token;
} NXBootHandoffTransitionV1;

/* Handed to NXBootHandoffClaimV1(). The host copies it, it doesn't have to outlive the call. */
typedef struct NXBootHandoffClientV1 {
    uint32_t version, size;     /* NX_BOOT_HANDOFF_VERSION, sizeof(NXBootHandoffClientV1) */
    uint32_t flags;             /* NX_BOOT_HANDOFF_* */
    NXBootConsoleMode consoleMode;
    void *context;              /* passed back to every callback */

    /* main thread, once, before transition() and (when claimed from a constructor) before NXSlotMain. Optional */
    void (*attach)(void *context, const NXBootHandoffSurfaceV1 *surface);
    /* the host's log drain thread, only in NX_BOOT_CONSOLE_ROM. Switching into ROM mode first replays what was
       logged so far. line has no newline and is only valid during the call. Must not block. Optional */
    void (*consoleLine)(void *context, const char *line, uint32_t isError);
    /* main thread. NULL: the host does its own transition (0.11.6.1 zoom) */
    void (*transition)(void *context, const NXBootHandoffTransitionV1 *transition);
    /* main thread. The host took the screen back, stop touching every surface object. Optional */
    void (*revoke)(void *context, uint32_t reason);
} NXBootHandoffClientV1;

uint32_t NXBootHandoffGetHostVersion(void);
int NXBootHandoffClaimV1(const NXBootHandoffClientV1 *client);
int NXBootHandoffSetConsoleModeV1(NXBootConsoleMode mode);

typedef struct NXBootHandoffAPI {
    uint32_t hostVersion;       /* 0: no handoff host (0.11.6.1 bootloader, or not running under one) */
    int (*claimV1)(const NXBootHandoffClientV1 *client);
    int (*setConsoleModeV1)(NXBootConsoleMode mode);
} NXBootHandoffAPI;

/* fills api, returns true when a v1 capable host is present */
static inline bool NXBootHandoffResolve(NXBootHandoffAPI *api)
{
    memset(api, 0, sizeof(*api));
    uint32_t (*version)(void) = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "NXBootHandoffGetHostVersion");
    if(version == NULL)
    {
        return false;
    }
    api->claimV1 = (int (*)(const NXBootHandoffClientV1 *))dlsym(RTLD_DEFAULT, "NXBootHandoffClaimV1");
    api->setConsoleModeV1 = (int (*)(NXBootConsoleMode))dlsym(RTLD_DEFAULT, "NXBootHandoffSetConsoleModeV1");
    if(api->claimV1 == NULL || api->setConsoleModeV1 == NULL)
    {
        memset(api, 0, sizeof(*api));
        return false;
    }
    api->hostVersion = version();
    return api->hostVersion >= 1;
}

#ifdef __cplusplus
}
#endif

#if defined(__LP64__)
#if defined(__cplusplus)
static_assert(sizeof(NXBootHandoffClientV1) == 56 && sizeof(NXBootHandoffSurfaceV1) == 48 && sizeof(NXBootHandoffTransitionV1) == 72, "boot handoff v1 layout changed");
#else
_Static_assert(sizeof(NXBootHandoffClientV1) == 56 && sizeof(NXBootHandoffSurfaceV1) == 48 && sizeof(NXBootHandoffTransitionV1) == 72, "boot handoff v1 layout changed");
#endif
#endif

#endif /* NXBOOTHANDOFF_H */
