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

#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>
#import <LindChain/ProcEnvironment/Surface/proc/proc.h>
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/ProcEnvironment/PEExtension.h>
#import <LindChain/Utils/Swizzle.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <objc/runtime.h>
#import <os/lock.h>
#import <objc/message.h>

static NSMutableDictionary<NSString*,NSValue*> *g_window_rects;
static os_unfair_lock g_window_rects_lock = OS_UNFAIR_LOCK_INIT;

@implementation NXWindowSessionApplication {
    UIView *_contentView;
    FBScene *_scene;
    
    NSArray<NSLayoutConstraint*> *_contentViewConstraints;
    CGSize _resizeFrozenSize;
    BOOL _isInteractivelyResizing;
}

@dynamic contentView;
@dynamic scene;

- (instancetype)initWithProcess:(PEProcess*)process;
{
    if(process == nil)
    {
        return nil;
    }
    
    self = [super init];
    if(self)
    {
        _process = process;
        [_process addObserver:self];
    }
    return self;
}

- (UIView*)contentView
{
    assert([NSThread isMainThread]);
    return _contentView;
}

- (void)setContentView:(UIView *)contentView
{
    assert([NSThread isMainThread]);
    if(_contentView != nil)
    {
        contentView.alpha = 0.0;
    }
    [self.view addSubview:contentView];
    
    contentView.translatesAutoresizingMaskIntoConstraints = NO;
    
    /* keep a reference so the resize path can drop/restore pinning */
    _contentViewConstraints = @[
        [contentView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor],
        [contentView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor],
        [contentView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [contentView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
    ];
    [NSLayoutConstraint activateConstraints:_contentViewConstraints];
    
    if(_contentView != nil)
    {
        UIView *currentContentView = _contentView;
        [UIView animateWithDuration:0.125 animations:^{
            currentContentView.alpha = 0.0;
            contentView.alpha = 1.0;
        } completion:^(BOOL finished){
            if(finished) [currentContentView removeFromSuperview];
        }];
    }
    
    _contentView = contentView;
}

- (void)setScene:(FBScene *)scene
{
    _scene = scene;
    
    [scene updateSettingsWithBlock:^(UIMutableApplicationSceneSettings *settings) {
        UIEdgeInsets insets = (self.isFullscreen) ? NXWindowServer.shared.safeAreaInsets : UIEdgeInsetsZero;
        
        insets.top = 10;
        
        switch(settings.interfaceOrientation)
        {
            case UIInterfaceOrientationPortrait:
                settings.safeAreaInsetsPortrait = insets;
                break;
            case UIInterfaceOrientationPortraitUpsideDown:
                settings.safeAreaInsetsPortraitUpsideDown = insets;
                break;
            case UIInterfaceOrientationLandscapeLeft:
                settings.safeAreaInsetsLandscapeLeft = insets;
                break;
            case UIInterfaceOrientationLandscapeRight:
                settings.safeAreaInsetsLandscapeRight = insets;
            case UIInterfaceOrientationUnknown:
                break;
        }
    }];
}

- (FBScene*)scene
{
    return _scene;
}

+ (void)bringSessionToFrontWithBundleIdentifier:(NSString*)bundleIdentifier
{
    assert([NSThread isMainThread]);
    if(UIDevice.currentDevice.userInterfaceIdiom != UIUserInterfaceIdiomPad) return;
    NXWindowServer *windowServer = [NXWindowServer shared];
    assert(windowServer != nil);
    
    for(NSNumber *key in windowServer.windows)
    {
        NXWindow *window = windowServer.windows[key];
        
        if(window != nil &&
           [window.session isKindOfClass:[NXWindowSessionApplication class]] &&
           [((NXWindowSessionApplication*)(window.session)).process.bundleIdentifier isEqualToString:bundleIdentifier])
        {
            [window.view.superview bringSubviewToFront:window.view];
            [window focusWindow];
            break;
        }
    }
}

- (BOOL)bindInApplicationWindow
{
    assert([NSThread isMainThread]);
    
    /* create a new window using the new lifecycle */
    void (^updateSceneSettings)(id) = ^void(UIMutableApplicationSceneSettings *settings) {
        settings.canShowAlerts = YES;
        settings.cornerRadiusConfiguration = [[PrivClass(BSCornerRadiusConfiguration) alloc] initWithTopLeft:self.view.layer.cornerRadius bottomLeft:self.view.layer.cornerRadius bottomRight:self.view.layer.cornerRadius topRight:self.view.layer.cornerRadius];
        settings.displayConfiguration = UIScreen.mainScreen.displayConfiguration;
        settings.foreground = NO;
        settings.level = 1;
        settings.persistenceIdentifier = [NSString stringWithFormat:@"sceneID:%@-%@", @"LiveProcess", [NSUUID.UUID UUIDString]];
        settings.statusBarDisabled = true;
        settings.frame = self.view.frame;
        if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPhone)
        {
            UIEdgeInsets insets = settings.safeAreaInsetsPortrait;
            insets.bottom = NXWindowServer.shared.safeAreaInsets.bottom;
            settings.safeAreaInsetsPortrait = insets;
        }
    };
    void (^updateSceneClientSettings)(id) = ^void(UIMutableApplicationSceneClientSettings *clientSettings) {
        clientSettings.interfaceOrientation = UIInterfaceOrientationPortrait;
        clientSettings.statusBarStyle = 0;
    };
    
    _UISceneHostingControllerAdvancedConfiguration *config = [[_UISceneHostingControllerAdvancedConfiguration alloc] initWithProcessIdentity:self.process.process.identity];
    config.sceneSpecification = [UIApplicationSceneSpecification specification];
    if(!@available(iOS 27.0, *))
    {
        /* on 27 manually adding this is not need, also setAdditionalExtensions: doesn't exist for some reason */
        config.additionalExtensions = [NSOrderedSet orderedSetWithArray:@[
            PrivClass(_UISceneHostingEventDeferringExtension),
        ]];
    }
    else
    {
        SEL settingsSelector = NSSelectorFromString(@"setInitialSettingsUpdater:");
        if([config respondsToSelector:settingsSelector])
        {
            void (*sendSettings)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
            sendSettings(config, settingsSelector, updateSceneSettings);
        }
        
        SEL clientSettingsSelector = NSSelectorFromString(@"setInitialClientSettingsUpdater:");
        if([config respondsToSelector:clientSettingsSelector])
        {
            void (*sendClientSettings)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
            sendClientSettings(config, clientSettingsSelector, updateSceneClientSettings);
        }
    }
    
    self.sceneHostingController = [[_UISceneHostingController alloc] initWithAdvancedConfiguration:config];
    
    if(@available(iOS 27.0, *))
    {
        Class deferringExtensionClass = NSClassFromString(@"_UISceneEventDeferringExtension"); // Or equivalent internal extension class
        if(deferringExtensionClass)
        {
            /* need to add extension, otherwise the instance can make caboom */
            [self.sceneHostingController addExtension:deferringExtensionClass];
        }
        [self.sceneHostingController configureScene];
        
        _UISceneEventDeferringHostComponent *deferringComponent = [self.sceneHostingController performSelector:@selector(_eventDeferringComponent)];
        if(deferringComponent)
        {
            [deferringComponent setValue:self forKey:@"_firstResponderTrackingSelectionPath"];
            [deferringComponent setGrantBehavior:2];
            [deferringComponent setSelectionRequestBehavior:2];
        }
        else
        {
            klog_log("NXWindowSessionApplication", "Unexpectedly nil _UISceneEventDeferringHostComponent");
        }
    }
    
    self.contentView = self.sceneHostingController.sceneViewController.view;
    self.contentView.clipsToBounds = YES;
    self.scenePresenter = [self.contentView valueForKey:@"_scenePresenter"];
    self.scene = self.scenePresenter.scene;
    
    /* gosh apple changed the behaviour of this API to death ;w; */
    if(!@available(iOS 27.0, *))
    {
        [self.scene updateSettingsWithBlock:updateSceneSettings];
    }
    
    /* FIXME: no way to update client settings so far */
    
    return YES;
}

- (BOOL)openWindow
{
    if(![super openWindow])
    {
        return NO;
    }
    
    os_unfair_lock_lock(&g_window_rects_lock);
    if(self.process && self.process.applicationObject && self.process.applicationObject.bundleIdentifier &&
       ![self.process.applicationObject.bundleIdentifier isEqual:@""] &&
       g_window_rects)
    {
        NSValue *rect = [g_window_rects objectForKey:self.process.applicationObject.bundleIdentifier];
        if(rect)
        {
            self.startWindowRect = [rect CGRectValue];
        }
    }
    os_unfair_lock_unlock(&g_window_rects_lock);
    
    if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad &&
       self.process.applicationObject != nil && self.process.applicationObject.isFullscreenRequired)
    {
        CGRect screenRect = UIScreen.mainScreen.bounds;
        UIInterfaceOrientationMask mask = self.process.applicationObject.supportedInterfaceOrientations;
        
        BOOL supportsPortrait = (mask & (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskPortraitUpsideDown)) != 0;
        BOOL supportsLandscape = (mask & UIInterfaceOrientationMaskLandscape) != 0;
        BOOL isLandscapeOnly = supportsLandscape && !supportsPortrait;
        BOOL isCurrentlyLandscape = (NXWindowServer.shared.rootViewController.interfaceOrientation == UIInterfaceOrientationLandscapeLeft || NXWindowServer.shared.rootViewController.interfaceOrientation == UIInterfaceOrientationLandscapeRight);
        BOOL needsFlip = NO;
        
        if(isLandscapeOnly)
        {
            if(!isCurrentlyLandscape)
            {
                needsFlip = YES;
            }
        }
        else
        {
            if(isCurrentlyLandscape)
            {
                needsFlip = YES;
            }
        }
        
        if(needsFlip)
        {
            CGFloat height = screenRect.size.height;
            screenRect.size.height = screenRect.size.width;
            screenRect.size.width = height;
        }
        
        screenRect.size.width = screenRect.size.width / 2;
        screenRect.size.height = screenRect.size.height / 2;
        screenRect.origin.x = 50;
        screenRect.origin.y = 50;
        self.startWindowRect = screenRect;
    }
    
    return [self bindInApplicationWindow];
}

- (BOOL)closeWindow
{
    [super closeWindow];
    
    if(self.scene != nil)
    {
        /* bye bye presenter */
        [_scenePresenter invalidate];
    }
    [_process forceTerminate];
    
    return YES;
}

- (BOOL)needRatioLocked
{
    if(self.process.applicationObject == nil)
    {
        return NO;
    }
    return self.process.applicationObject.isFullscreenRequired;
}

- (UIImage*)snapshotWindow
{
    if(_process == nil) return nil;
    return _process.snapshot;
}

- (BOOL)activateWindow
{
    assert([NSThread isMainThread]);
    
    /* set presenter to foreground */
    [_scene updateSettingsWithBlock:^(UIMutableApplicationSceneSettings *settings) {
        settings.foreground = YES;
    }];
    
    /* re-activate presenter */
    [_scenePresenter activate];
    
    return YES;
}

- (BOOL)deactivateWindow
{
    assert([NSThread isMainThread]);
    
    /* set presenter to background */
    [_scene updateSettingsWithBlock:^(UIMutableApplicationSceneSettings *settings) {
        settings.foreground = NO;
    }];
    
    [_process sendSignal:SIGUSR1];
    
    /* deactivate the presenter */
    [_scenePresenter deactivate];
    
    return YES;
}

- (BOOL)shouldUpdateFocusInContext:(nonnull UIFocusUpdateContext *)context
{
    return YES;
}

- (NSString*)windowName
{
    return self.process.displayName;
}

- (NSString*)getWindowName
{
    NSString *windowName = [super getWindowName];
    return windowName ?: self.process.displayName;
}

- (void)windowBeganResizing
{
    assert([NSThread isMainThread]);
    if(_isInteractivelyResizing || _contentView == nil)
    {
        return;
    }
    
    [self.view layoutIfNeeded];
    CGSize frozen = _contentView.bounds.size;
    if(frozen.width < 1.0 || frozen.height < 1.0)
    {
        return;
    }
    
    _isInteractivelyResizing = YES;
    _resizeFrozenSize = frozen;
    if(_contentViewConstraints)
    {
        [NSLayoutConstraint deactivateConstraints:_contentViewConstraints];
    }
    _contentView.translatesAutoresizingMaskIntoConstraints = YES;
    _contentView.bounds = (CGRect){CGPointZero, frozen};
    _contentView.userInteractionEnabled = NO;
    
    [self updateInteractiveResizeTransform];
}

- (void)updateInteractiveResizeTransform
{
    if(!_isInteractivelyResizing || _contentView == nil)
    {
        return;
    }
    
    CGSize target = self.view.bounds.size;
    if(target.width < 1.0 || target.height < 1.0)
    {
        return;
    }
    
    [CATransaction begin];
    [CATransaction setDisableActions:YES];  /* otherwise every frame gets an implicit 0.25s animation */
    CALayer *layer = _contentView.layer;
    layer.transform = CATransform3DMakeScale(target.width  / _resizeFrozenSize.width, target.height / _resizeFrozenSize.height, 1.0);
    layer.position = CGPointMake(CGRectGetMidX(self.view.bounds), CGRectGetMidY(self.view.bounds));
    [CATransaction commit];
}

- (void)viewDidLayoutSubviews
{
    [super viewDidLayoutSubviews];
    if(_isInteractivelyResizing)
    {
        [self updateInteractiveResizeTransform];
    }
}

- (void)windowEndedResizing
{
    assert([NSThread isMainThread]);
    if(!_isInteractivelyResizing)
    {
        return;
    }
    _isInteractivelyResizing = NO;
    
    _contentView.translatesAutoresizingMaskIntoConstraints = NO;
    if(_contentViewConstraints)
    {
        [NSLayoutConstraint activateConstraints:_contentViewConstraints];
    }
    
    UIMutableApplicationSceneSettings *settings = [_scene.settings mutableCopy];
    settings.frame = self.view.frame;
    
    __weak typeof(self) weakSelf = self;
    __block BOOL settled = NO;
    void (^unstretch)(void) = ^{
        if(settled)
        {
            return;
        }
        settled = YES;
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if(strongSelf == nil || strongSelf->_contentView == nil)
        {
            return;
        }
        
        [CATransaction begin];
        [CATransaction setDisableActions:YES];
        strongSelf->_contentView.layer.transform = CATransform3DIdentity;
        strongSelf->_contentView.translatesAutoresizingMaskIntoConstraints = NO;
        if(strongSelf->_contentViewConstraints)
        {
            [NSLayoutConstraint activateConstraints:strongSelf->_contentViewConstraints];
        }
        [strongSelf.view layoutIfNeeded];
        [CATransaction commit];
        
        strongSelf->_contentView.userInteractionEnabled = YES;
    };
    
    [_scene updateSettings:settings withTransitionContext:nil completion:^{
        dispatch_async(dispatch_get_main_queue(), unstretch);
    }];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), unstretch);
    
    os_unfair_lock_lock(&g_window_rects_lock);
    if(self.process && self.process.applicationObject && self.process.applicationObject.bundleIdentifier &&
       ![self.process.applicationObject.bundleIdentifier isEqual:@""])
    {
        if(!g_window_rects)
        {
            g_window_rects = [NSMutableDictionary dictionary];
        }
        
        [g_window_rects setObject:[NSValue valueWithCGRect:self.window.view.frame] forKey:self.process.applicationObject.bundleIdentifier];
    }
    os_unfair_lock_unlock(&g_window_rects_lock);
}

- (void)windowDidMove
{
    os_unfair_lock_lock(&g_window_rects_lock);
    if(self.process && self.process.applicationObject && self.process.applicationObject.bundleIdentifier &&
       ![self.process.applicationObject.bundleIdentifier isEqual:@""])
    {
        if(!g_window_rects)
        {
            g_window_rects = [NSMutableDictionary dictionary];
        }
        
        [g_window_rects setObject:[NSValue valueWithCGRect:self.window.view.frame] forKey:self.process.applicationObject.bundleIdentifier];
    }
    os_unfair_lock_unlock(&g_window_rects_lock);
}

- (void)process:(PEProcess *)process didExitWithWait4Code:(int)code
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NXWindowServer shared] closeWindowWithIdentifier:self.windowIdentifier withCompletion:nil];
    });
}

- (void)dealloc
{
    [self.process removeObserver:self];
#if DEBUG
    NSLog(@"deallocated %@", self);
#endif /* DEBUG */
}

@end
