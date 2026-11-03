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

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <LindChain/ProcEnvironment/Shims/application.h>
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/Utils/Swizzle.h>
#import <LindChain/ProcEnvironment/Shims/proxy.h>
#import <LindChain/ProcEnvironment/Surface/sys/syscall.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#include <ksurface_config.h>
#include <ksurface_abi.h>

#pragma mark - Initilizer

static dispatch_source_t global_signal_source = nil;


@implementation UIApplication (ProcEnvironment)

- (void)hook_run
{
    /* tell host app to let our process appear as a window */
    liveshim_syscall(SYS_pectl, kPECTLCategoryUserInterface, kPECTLUserInterfaceInit, NULL, NULL, MACH_PORT_NULL);
    
    while(errno == EAGAIN)
    {
        usleep(500);
        liveshim_syscall(SYS_pectl, kPECTLCategoryUserInterface, kPECTLUserInterfaceInit, NULL, NULL, MACH_PORT_NULL);
    }
    
    [self hook_run];
}

@end

void environment_application_init(void)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
    SwizzleObjCMethod(@selector(_run), [UIApplication class], @selector(hook_run), nil, kSwizzleMethodTypeInstance);
#pragma clang diagnostic pop
    
    signal(SIGUSR1, SIG_IGN);
    global_signal_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
    if(global_signal_source)
    {
        dispatch_source_set_event_handler(global_signal_source, ^{
            UIApplication *sharedApplication = [PrivClass(UIApplication) sharedApplication];
            
            if(sharedApplication)
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    // TODO: Shall be done by the runLoop and not by the handler, this could lead to some strange behaviour
                    
                    /* finding active scene */
                    UIWindowScene *activeScene = nil;
                    for(UIWindowScene *scene in sharedApplication.connectedScenes)
                    {
                        if(scene.activationState == UISceneActivationStateForegroundActive)
                        {
                            activeScene = scene;
                            break;
                        }
                    }
                    
                    /* null pointer check */
                    if(!activeScene)
                    {
                        return;
                    }
                    
                    /* getting view we wanna capture with our own eyes ^^ */
                    UIWindow *rootWindow = activeScene.keyWindow;
                    UIViewController *topVC = rootWindow.rootViewController;
                    UIView *viewToCapture = topVC.view ?: rootWindow;
                    
                    /* preparing format for renderer */
                    CGFloat scale = [UIScreen mainScreen].scale;
                    UIGraphicsImageRendererFormat *format = [UIGraphicsImageRendererFormat defaultFormat];
                    format.scale = scale;
                    format.opaque = viewToCapture.isOpaque;
                    
                    /* creating renderer */
                    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:viewToCapture.bounds.size format:format];
                    
                    /* and snapshotting... */
                    UIImage *snapshot = [renderer imageWithActions:^(UIGraphicsImageRendererContext * _Nonnull rendererContext) {
                        /* crafting screenshot */
                        [viewToCapture drawViewHierarchyInRect:viewToCapture.bounds afterScreenUpdates:YES];
                    }];
                    
                    /* sending to host */
                    environment_proxy_set_snapshot(snapshot);
                });
                return;
            }
        });
        
        dispatch_resume(global_signal_source);
    }
}
