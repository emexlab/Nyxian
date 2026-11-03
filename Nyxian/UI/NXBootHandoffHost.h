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

#ifndef NXBOOTHANDOFFHOST_H
#define NXBOOTHANDOFFHOST_H

#import <UIKit/UIKit.h>
#include "../../BootHandoff/NXBootHandoff.h"

NS_ASSUME_NONNULL_BEGIN

/* the bootloader side of BootHandoff/README.md, implemented by BootViewController */
@protocol NXBootHandoffHostDelegate <NSObject>
/* any thread, synchronous: fd 27 must be captured when this returns (unless capturing is over for this boot) */
- (void)bootHandoffEnsureLogCapture;
/* main thread */
- (void)bootHandoffSetConsoleVisible:(BOOL)visible logoHidden:(BOOL)logoHidden NS_SWIFT_NAME(bootHandoffSetConsole(visible:logoHidden:));
@property (nonatomic, readonly, nullable) UIWindowScene *bootHandoffWindowScene;
@property (nonatomic, readonly, nullable) UIWindow *bootHandoffHostWindow;
@property (nonatomic, readonly) UIView *bootHandoffSplashView;
@property (nonatomic, readonly) UIImageView *bootHandoffLogoView;
@end

@interface NXBootHandoffHost : NSObject

@property (class, nonatomic, readonly) NXBootHandoffHost *shared;
@property (nonatomic, weak, nullable) id<NXBootHandoffHostDelegate> delegate;

/* any thread, right before the slot is dlopen'd: claims are accepted from here on */
- (void)openWithVerboseRequested:(BOOL)verbose NS_SWIFT_NAME(open(verboseRequested:));

/* a ROM holds the boot screen */
@property (nonatomic, readonly, getter=isClaimed) BOOL claimed;
/* only meaningful while claimed: the 1.5 s console hold before the host transition (never with a ROM transition) */
@property (nonatomic, readonly) BOOL wantsVerboseHold;

/* the capture drain thread, every captured line, claimed or not */
- (void)recordLogLine:(NSString *)line isError:(BOOL)isError NS_SWIFT_NAME(record(line:isError:));

/*
 * Main thread. YES: the ROM transitions; prepare ran synchronously before the ROM was called and completion runs once
 * the ROM (or the 10 s watchdog) finished. NO: nothing ran, the host transitions itself. Either way claims are closed.
 */
- (BOOL)beginTransitionWithHostWindow:(nullable UIWindow *)hostWindow
                               splash:(UIView *)splash
                                 logo:(UIImageView *)logo
                           slotWindow:(nullable UIWindow *)slotWindow
                                 root:(UIViewController *)root
                              prepare:(void (NS_NOESCAPE ^)(void))prepare
                           completion:(void (^)(void))completion
    NS_SWIFT_NAME(beginTransition(hostWindow:splash:logo:slotWindow:root:prepare:completion:));

/* main thread: the bootloader takes the screen back (NX_BOOT_HANDOFF_REVOKE_*), no-op without a live handoff */
- (void)revokeWithReason:(uint32_t)reason NS_SWIFT_NAME(revoke(reason:));

@end

NS_ASSUME_NONNULL_END

#endif /* NXBOOTHANDOFFHOST_H */
