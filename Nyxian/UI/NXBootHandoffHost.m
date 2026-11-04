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

#import "NXBootHandoffHost.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef NS_ENUM(NSInteger, NXBootHandoffState) {
    NXBootHandoffStateClosed,
    NXBootHandoffStateOpen,
    NXBootHandoffStateClaimed,
    NXBootHandoffStateTransitioning,
    NXBootHandoffStateDone,
    NXBootHandoffStateRevoked,
};

static const NSUInteger NXBootHandoffBacklogLimit = 512;
static const int64_t NXBootHandoffTransitionTimeout = 10;
static const int NXBootHandoffLogFD = 27;

@interface NXBootHandoffLine : NSObject
@property (nonatomic, copy) NSString *text;
@property (nonatomic) BOOL isError;
@end

@implementation NXBootHandoffLine
@end

static BOOL NXBootHandoffLive(NXBootHandoffState state)
{
    return state == NXBootHandoffStateClaimed || state == NXBootHandoffStateTransitioning;
}

static BOOL NXBootHandoffConsoleVisible(NXBootConsoleMode mode, BOOL verbose)
{
    return NO;
}

static BOOL NXBootHandoffNeedsCapture(NXBootConsoleMode mode, BOOL verbose)
{
    return mode != NX_BOOT_CONSOLE_AUTO;
}

static const char *NXBootHandoffConsoleName(NXBootConsoleMode mode)
{
    switch(mode)
    {
        case NX_BOOT_CONSOLE_AUTO: return "auto";
        case NX_BOOT_CONSOLE_HOST: return "host";
        case NX_BOOT_CONSOLE_HIDDEN: return "hidden";
        case NX_BOOT_CONSOLE_ROM: return "rom";
        default: return "?";
    }
}

static void NXBootHandoffComplete(void *token);

@interface NXBootHandoffHost ()
- (int)claim:(const NXBootHandoffClientV1 *)client;
- (int)setConsoleMode:(NXBootConsoleMode)mode;
- (void)finishTransition:(uint64_t)generation timedOut:(BOOL)timedOut;
@end

@implementation NXBootHandoffHost {
    NSRecursiveLock *_lock;
    NXBootHandoffState _state;
    BOOL _verbose;
    NXBootHandoffClientV1 _client;
    NXBootConsoleMode _mode;
    NSMutableArray<NXBootHandoffLine *> *_backlog;
    uint64_t _generation;
    void (^_pendingCompletion)(void);
    BOOL _attachDelivered;
}

+ (NXBootHandoffHost *)shared
{
    static NXBootHandoffHost *shared;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        shared = [NXBootHandoffHost new];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        _lock = [NSRecursiveLock new];
        _backlog = [NSMutableArray array];
        _state = NXBootHandoffStateClosed;
    }
    return self;
}

- (void)openWithVerboseRequested:(BOOL)verbose
{
    [_lock lock];
    if(_state == NXBootHandoffStateClosed || _state == NXBootHandoffStateRevoked)
    {
        memset(&_client, 0, sizeof(_client));
        _mode = NX_BOOT_CONSOLE_AUTO;
        _verbose = verbose;
        _pendingCompletion = nil;
        _attachDelivered = NO;
        _state = NXBootHandoffStateOpen;
    }
    [_lock unlock];
}

- (BOOL)isClaimed
{
    [_lock lock];
    BOOL claimed = NXBootHandoffLive(_state);
    [_lock unlock];
    return claimed;
}

- (BOOL)wantsVerboseHold
{
    [_lock lock];
    /* a ROM that transitions itself does its own pacing */
    BOOL hold = NXBootHandoffLive(_state) &&
                _client.transition == NULL &&
                !(_client.flags & NX_BOOT_HANDOFF_NO_VERBOSE_HOLD) &&
                NXBootHandoffConsoleVisible(_mode, _verbose);
    [_lock unlock];
    return hold;
}

/* _lock held: everything recorded so far, oldest first */
- (void)replayBacklogLocked
{
    if(_client.consoleLine == NULL)
    {
        return;
    }
    for(NXBootHandoffLine *line in [_backlog copy])
    {
        _client.consoleLine(_client.context, line.text.UTF8String ?: "", line.isError);
    }
}

- (void)recordLogLine:(NSString *)text
              isError:(BOOL)isError
{
    NXBootHandoffLine *line = [NXBootHandoffLine new];
    line.text = text;
    line.isError = isError;

    [_lock lock];
    [_backlog addObject:line];
    if(_backlog.count > NXBootHandoffBacklogLimit)
    {
        [_backlog removeObjectsInRange:NSMakeRange(0, _backlog.count - NXBootHandoffBacklogLimit)];
    }
    if(NXBootHandoffLive(_state) && _mode == NX_BOOT_CONSOLE_ROM && _client.consoleLine != NULL)
    {
        _client.consoleLine(_client.context, text.UTF8String ?: "", isError);
    }
    [_lock unlock];
}

/* main thread */
- (void)applyConsole
{
    [_lock lock];
    if(!NXBootHandoffLive(_state))
    {
        [_lock unlock];
        return;
    }
    BOOL visible = NXBootHandoffConsoleVisible(_mode, _verbose);
    BOOL logoHidden = visible || (_client.flags & NX_BOOT_HANDOFF_HIDE_HOST_LOGO);
    [_lock unlock];

    [self.delegate bootHandoffSetConsoleVisible:visible logoHidden:logoHidden];
}

- (void)applyConsoleOnMain
{
    if(NSThread.isMainThread)
    {
        [self applyConsole];
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self applyConsole];
        });
    }
}

/* main thread */
- (void)deliverAttach
{
    [_lock lock];
    if(_state != NXBootHandoffStateClaimed || _attachDelivered)
    {
        [_lock unlock];
        return;
    }
    _attachDelivered = YES;
    NXBootHandoffClientV1 client = _client;
    BOOL verbose = _verbose;
    [_lock unlock];

    [self applyConsole];

    id<NXBootHandoffHostDelegate> delegate = self.delegate;
    if(delegate == nil || client.attach == NULL)
    {
        return;
    }

    NXBootHandoffSurfaceV1 surface = {
        .version = NX_BOOT_HANDOFF_VERSION,
        .size = sizeof(NXBootHandoffSurfaceV1),
        .windowScene = (__bridge void *)delegate.bootHandoffWindowScene,
        .hostWindow = (__bridge void *)delegate.bootHandoffHostWindow,
        .splashView = (__bridge void *)delegate.bootHandoffSplashView,
        .logoView = (__bridge void *)delegate.bootHandoffLogoView,
        .verboseRequested = verbose,
        .logFD = NXBootHandoffLogFD,
    };
    client.attach(client.context, &surface);
}

- (int)claim:(const NXBootHandoffClientV1 *)client
{
    [_lock lock];
    if(NXBootHandoffLive(_state))
    {
        [_lock unlock];
        return EBUSY;
    }
    if(_state != NXBootHandoffStateOpen)
    {
        [_lock unlock];
        return EPERM;
    }

    /* v1 prefix only, a bigger (newer) descriptor is fine */
    memcpy(&_client, client, sizeof(NXBootHandoffClientV1));
    _client.size = sizeof(NXBootHandoffClientV1);
    _mode = client->consoleMode;
    _state = NXBootHandoffStateClaimed;
    BOOL verbose = _verbose;
    NXBootConsoleMode mode = _mode;
    if(mode == NX_BOOT_CONSOLE_ROM)
    {
        [self replayBacklogLocked];
    }
    [_lock unlock];

    if(NXBootHandoffNeedsCapture(mode, verbose))
    {
        [self.delegate bootHandoffEnsureLogCapture];
    }
    dprintf(NXBootHandoffLogFD, "bootloader: ROM took over the boot screen (console: %s)\n", NXBootHandoffConsoleName(mode));

    /* the main queue is FIFO, so this lands before the bootloader's NXSlotMain block when claimed from a constructor */
    if(NSThread.isMainThread)
    {
        [self deliverAttach];
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self deliverAttach];
        });
    }
    return 0;
}

- (int)setConsoleMode:(NXBootConsoleMode)mode
{
    [_lock lock];
    if(!NXBootHandoffLive(_state))
    {
        [_lock unlock];
        return ENOTCONN;
    }
    NXBootConsoleMode previous = _mode;
    _mode = mode;
    if(mode == NX_BOOT_CONSOLE_ROM && previous != NX_BOOT_CONSOLE_ROM)
    {
        [self replayBacklogLocked];
    }
    BOOL verbose = _verbose;
    [_lock unlock];

    if(NXBootHandoffNeedsCapture(mode, verbose))
    {
        [self.delegate bootHandoffEnsureLogCapture];
    }
    [self applyConsoleOnMain];
    return 0;
}

- (BOOL)beginTransitionWithHostWindow:(UIWindow *)hostWindow
                               splash:(UIView *)splash
                                 logo:(UIImageView *)logo
                           slotWindow:(UIWindow *)slotWindow
                                 root:(UIViewController *)root
                              prepare:(void (NS_NOESCAPE ^)(void))prepare
                           completion:(void (^)(void))completion
{
    [_lock lock];
    if(_state == NXBootHandoffStateClaimed && !_attachDelivered)
    {
        /* claimed late from another thread, its attach is still queued: attach always comes before transition.
           Only main leaves CLAIMED, so the state holds across the unlock */
        [_lock unlock];
        [self deliverAttach];
        [_lock lock];
    }
    if(_state != NXBootHandoffStateClaimed || _client.transition == NULL)
    {
        /* the host transitions, no claims past this point */
        if(_state == NXBootHandoffStateOpen || _state == NXBootHandoffStateClaimed)
        {
            _state = NXBootHandoffStateDone;
        }
        [_lock unlock];
        return NO;
    }
    _state = NXBootHandoffStateTransitioning;
    uint64_t generation = ++_generation;
    _pendingCompletion = [completion copy];
    NXBootHandoffClientV1 client = _client;
    BOOL consoleVisible = NXBootHandoffConsoleVisible(_mode, _verbose);
    [_lock unlock];

    prepare();

    NXBootHandoffTransitionV1 transition = {
        .version = NX_BOOT_HANDOFF_VERSION,
        .size = sizeof(NXBootHandoffTransitionV1),
        .hostWindow = (__bridge void *)hostWindow,
        .splashView = (__bridge void *)splash,
        .logoView = (__bridge void *)logo,
        .slotWindow = (__bridge void *)slotWindow,
        .rootViewController = (__bridge void *)root,
        .consoleVisible = consoleVisible,
        .reduceMotion = UIAccessibilityIsReduceMotionEnabled(),
        .complete = NXBootHandoffComplete,
        .token = (void *)(uintptr_t)generation,
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NXBootHandoffTransitionTimeout * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self finishTransition:generation timedOut:YES];
    });

    client.transition(client.context, &transition);
    return YES;
}

/* main thread */
- (void)finishTransition:(uint64_t)generation
                timedOut:(BOOL)timedOut
{
    [_lock lock];
    if(_state != NXBootHandoffStateTransitioning || generation != _generation)
    {
        [_lock unlock];
        return;
    }
    _state = NXBootHandoffStateDone;
    void (^completion)(void) = _pendingCompletion;
    _pendingCompletion = nil;
    NXBootHandoffClientV1 client = _client;
    [_lock unlock];

    if(timedOut)
    {
        NSLog(@"bootloader: ROM transition didn't complete within %llds, finishing it", (long long)NXBootHandoffTransitionTimeout);
        if(client.revoke != NULL)
        {
            client.revoke(client.context, NX_BOOT_HANDOFF_REVOKE_TIMEOUT);
        }
    }
    if(completion != nil)
    {
        completion();
    }
}

- (void)revokeWithReason:(uint32_t)reason
{
    [_lock lock];
    if(_state != NXBootHandoffStateOpen && !NXBootHandoffLive(_state))
    {
        [_lock unlock];
        return;
    }
    BOOL hadClient = NXBootHandoffLive(_state);
    NXBootHandoffClientV1 client = _client;
    _state = NXBootHandoffStateRevoked;
    _pendingCompletion = nil;
    [_lock unlock];

    if(hadClient && client.revoke != NULL)
    {
        client.revoke(client.context, reason);
    }
}

@end

static void NXBootHandoffComplete(void *token)
{
    uint64_t generation = (uint64_t)(uintptr_t)token;
    if(NSThread.isMainThread)
    {
        [NXBootHandoffHost.shared finishTransition:generation timedOut:NO];
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [NXBootHandoffHost.shared finishTransition:generation timedOut:NO];
        });
    }
}

/* Host exports, ROMs resolve them with NXBootHandoffResolve() (dlsym(RTLD_DEFAULT, ...)). */

__attribute__((used, visibility("default"))) uint32_t NXBootHandoffGetHostVersion(void)
{
    return NX_BOOT_HANDOFF_VERSION;
}

__attribute__((used, visibility("default"))) int NXBootHandoffClaimV1(const NXBootHandoffClientV1 *client)
{
    if(client == NULL || client->version != NX_BOOT_HANDOFF_VERSION || client->size < sizeof(NXBootHandoffClientV1))
    {
        return EINVAL;
    }
    if(client->flags & ~NX_BOOT_HANDOFF_KNOWN_FLAGS_V1)
    {
        return ENOTSUP;
    }
    if(client->consoleMode > NX_BOOT_CONSOLE_ROM)
    {
        return EINVAL;
    }
    return [NXBootHandoffHost.shared claim:client];
}

__attribute__((used, visibility("default"))) int NXBootHandoffSetConsoleModeV1(NXBootConsoleMode mode)
{
    if(mode > NX_BOOT_CONSOLE_ROM)
    {
        return EINVAL;
    }
    return [NXBootHandoffHost.shared setConsoleMode:mode];
}
