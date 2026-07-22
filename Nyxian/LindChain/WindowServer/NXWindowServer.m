/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/WindowServer/NXAppTile.h>
#import <LindChain/ProcEnvironment/Process/PEProcessManager.h>

@interface NXWindowLayerView : UIView
@end

@implementation NXWindowLayerView

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event
{
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self) ? nil : hit;
}

@end

@implementation NXWindowServer {
    UIStackView *_stackView;
    UIStackView *_placeholderStack;
    NXWindow *_activeWindow;
    id_t _activeWindowIdentifier;
    UIScrollView *_runningAppsScrollView;
    
    NXWindowLayerView *_windowLayer;
}

- (instancetype)initWithWindowScene:(UIWindowScene *)windowScene
{
    [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
    static BOOL hasInitialized = NO;
    if(hasInitialized)
    {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"This class may only be initialized once." userInfo:nil];
    }
    
    self = [super initWithWindowScene:windowScene];
    if(self)
    {
        _windows = [[NSMutableDictionary alloc] init];
        _windowOrder = [[NSMutableArray alloc] init];
        _activeWindowIdentifier = (id_t)-1;
        _appSwitcherView = nil;
        
        //if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad)
        if(YES)
        {
            [[UIDevice currentDevice] beginGeneratingDeviceOrientationNotifications];
            [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(orientationChanged:) name:UIDeviceOrientationDidChangeNotification object:nil];
        }
        
        hasInitialized = YES;
    }
    
    _windowLayer = [[NXWindowLayerView alloc] init];
    _windowLayer.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    
    return self;
}

- (void)layoutSubviews
{
    [super layoutSubviews];
    _windowLayer.frame = self.bounds;
}

+ (instancetype)sharedWithWindowScene:(UIWindowScene*)windowScene
{
    static NXWindowServer *multitaskManagerSingleton = nil;
    if(windowScene == nil && multitaskManagerSingleton == nil)
    {
        return nil;
    }
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        multitaskManagerSingleton = [[NXWindowServer alloc] initWithWindowScene:windowScene];
    });
    return multitaskManagerSingleton;
}

+ (instancetype)shared
{
    return [self sharedWithWindowScene:nil];
}

- (void)moveWindowToFrontWithNumber:(NSNumber *)number
{
    if(!number || !self.windows[number]) return;

    [self.windowOrder removeObject:number];
    [self.windowOrder insertObject:number atIndex:0];
}

- (void)activateWindowForIdentifier:(id_t)identifier
                           animated:(BOOL)animated
                     withCompletion:(void (^)(void))completion
{
    assert([NSThread isMainThread]);
    
    NXWindow *window = self.windows[@(identifier)];
    if(!window) return;
    
    if(window.view.superview != _windowLayer)
    {
        _activeWindowIdentifier = identifier;
        [self moveWindowToFrontWithNumber:@(identifier)];
        [window.session activateWindow];
        [_windowLayer addSubview:window.view];
        [window openWindow];
        [window focusWindow];
    }
    
    if(self.appSwitcherView)
    {
        [self hideAppSwitcher];
    }
    
    if(completion)
    {
        completion();
    }
}

- (void)deactivateWindowByPullDown:(BOOL)pullDown
                    withIdentifier:(id_t)identifier
                    withCompletion:(void (^)(void))completion
{
    assert([NSThread isMainThread]);
    
    NXWindow *window = self.windows[@(identifier)];
    if(!window || window.view.hidden)
    {
        if(completion)
        {
            completion();
        }
        return;
    }

    [window.view.layer removeAllAnimations];
    
    [UIView animateWithDuration:0.3 animations:^{
        window.view.alpha = 0.0;
    } completion:^(BOOL finished) {
        window.view.hidden = YES;
        window.view.alpha = 1.0;
        window.view.transform = CGAffineTransformIdentity;
        [window.session deactivateWindow];
        if (completion) completion();
    }];
}

- (void)focusWindowForIdentifier:(id_t)identifier
{
    assert([NSThread isMainThread]);
    NXWindow *window = self.windows[@(identifier)];
    if (!window) return;
    [window focusWindow];
}

- (NXWindowSession*)windowSessionForIdentifier:(id_t)identifier
{
    assert([NSThread isMainThread]);
    NXWindow *window = self.windows[@(identifier)];
    if(window != nil)
    {
        return window.session;
    }
    return nil;
}

- (void)unfocusFocusedWindow
{
    assert([NSThread isMainThread]);
    if(_activeWindow != nil)
    {
        [_activeWindow unfocusWindow];
    }
}

- (void)windowsGetOutOfMyWay
{
    //if(UIDevice.currentDevice.userInterfaceIdiom != UIUserInterfaceIdiomPad)
    if(YES)
    {
        return;
    }
    
    [UIView animateWithDuration:0.3 delay:0 options:UIViewAnimationOptionBeginFromCurrentState | UIViewAnimationOptionCurveEaseOut | UIViewAnimationOptionAllowUserInteraction animations:^{
        self->_windowLayer.alpha = 0.25;
    } completion:nil];
}

- (void)windowsGetInMyWay
{
    //if(UIDevice.currentDevice.userInterfaceIdiom != UIUserInterfaceIdiomPad)
    if(YES)
    {
        return;
    }
    
    [UIView animateWithDuration:0.3 delay:0 options:UIViewAnimationOptionBeginFromCurrentState | UIViewAnimationOptionCurveEaseOut | UIViewAnimationOptionAllowUserInteraction animations:^{
        self->_windowLayer.alpha = 1.0;
    } completion:nil];
}

- (void)openWindowWithSession:(NXWindowSession*)session
               withCompletion:(void (^)(BOOL))completion
{
    assert([NSThread isMainThread]);
    
    __block id_t windowIdentifier = (id_t)-1;
    __block BOOL windowOpened = YES;
    
    void (^openAct)(void) = ^{
        /* getting next window identifier */
        static id_t nextWindowIdentifier = 0;
        windowIdentifier = nextWindowIdentifier++;
        
        [session movedWindowToScene:self.windowScene withIdentifier:windowIdentifier];
        
        if(![session openWindow])
        {
            windowOpened = NO;
            return;
        }
        
        NXWindow *window = [[NXWindow alloc] initWithSession:session withDelegate:self];
        window.identifier = windowIdentifier;
        if(window)
        {
            self.windows[@(windowIdentifier)] = window;
            [self windowWantsToFocus:window];
            [self.windowOrder insertObject:@(windowIdentifier) atIndex:0];
            [self activateWindowForIdentifier:windowIdentifier animated:YES withCompletion:nil];
        }
        else
        {
            return;
        }
    };
    
    NXWindow *window = self.windows[@(_activeWindowIdentifier)];
    if(window != nil &&
       _activeWindowIdentifier != window.identifier)
       /&&
       //[[UIDevice currentDevice] userInterfaceIdiom] != UIUserInterfaceIdiomPad)
    {
        // close first the old one and wait
        [self deactivateWindowByPullDown:YES withIdentifier:_activeWindowIdentifier withCompletion:^{
            openAct();
            if(completion) completion(windowOpened);
        }];
    }
    else
    {
        openAct();
        if(completion) completion(windowOpened);
    }
}

- (void)closeWindowWithIdentifier:(id_t)identifier
                   withCompletion:(void (^)(BOOL))completion
{
    assert([NSThread isMainThread]);
    
    if(_activeWindowIdentifier == identifier)
    {
        _activeWindowIdentifier = (id_t)-1;
    }
    
    NXWindow *window = self.windows[@(identifier)];
    if(window != nil)
    {
        [window closeWindowWithCompletion:^(BOOL closedWindow){
            if(closedWindow)
            {
                [self.windows removeObjectForKey:@(identifier)];
                [self.windowOrder removeObject:@(identifier)];
            }
            
            if(completion) completion(closedWindow);
        }];
    }
    else
    {
        if(completion) completion(NO);
    }
}

- (void)makeKeyAndVisible
{
    [super makeKeyAndVisible];
    
    /* attaching the window layer */
    [self addSubview:_windowLayer];
    [self bringSubviewToFront:_windowLayer];
    [_windowLayer setUserInteractionEnabled:YES];

    //if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPhone)
    //{
        /* iOS 26 and above uses the tabbar button instead of gesture */
        //if(@available(iOS 26.0, *))
        //{
            //return;
        //}
            
        /* add the gesture */
        //UILongPressGestureRecognizer *gestureRecognizer = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
        //[self addGestureRecognizer:gestureRecognizer];
    //}
}

// TODO: FRIDA! PLS MAKE LDEWINDOWSERVERTILEVIEW!!!! IM SO LAZY ONG
- (void)handleLongPress:(UILongPressGestureRecognizer *)recognizer
{
    if(_activeWindowIdentifier == (id_t)-1 &&
       (recognizer.state == UIGestureRecognizerStateBegan || recognizer == nil))
    {
        if(!self.appSwitcherView)
        {
            [self buildAppSwitcherView];
        }

        [self showAppSwitcher];
    }
}

- (void)buildAppSwitcherView
{
    UIView *container = [[UIView alloc] init];
    container.translatesAutoresizingMaskIntoConstraints = NO;
    container.layer.shadowColor = [UIColor blackColor].CGColor;
    container.layer.shadowOpacity = 0.25;
    container.layer.shadowRadius = 12;
    container.layer.shadowOffset = CGSizeMake(0, -4);
    
    UIVisualEffectView *effectView = [self createBlurEffectView];
    effectView.translatesAutoresizingMaskIntoConstraints = NO;
    effectView.layer.cornerRadius = 20;
    effectView.layer.masksToBounds = YES;
    [container addSubview:effectView];
    
    [NSLayoutConstraint activateConstraints:@[
        [effectView.topAnchor constraintEqualToAnchor:container.topAnchor],
        [effectView.bottomAnchor constraintEqualToAnchor:container.bottomAnchor],
        [effectView.leadingAnchor constraintEqualToAnchor:container.leadingAnchor],
        [effectView.trailingAnchor constraintEqualToAnchor:container.trailingAnchor]
    ]];
    
    _runningAppsScrollView = [[UIScrollView alloc] init];
    _runningAppsScrollView.translatesAutoresizingMaskIntoConstraints = NO;
    _runningAppsScrollView.showsHorizontalScrollIndicator = NO;
    _runningAppsScrollView.clipsToBounds = NO;
    [effectView.contentView addSubview:_runningAppsScrollView];
    
    _stackView = [[UIStackView alloc] init];
    _stackView.axis = UILayoutConstraintAxisHorizontal;
    _stackView.alignment = UIStackViewAlignmentCenter;
    _stackView.spacing = 20;
    _stackView.translatesAutoresizingMaskIntoConstraints = NO;
    _stackView.clipsToBounds = NO;
    [_runningAppsScrollView addSubview:_stackView];
    
    [self buildPlaceholderStackInView:effectView.contentView];
    
    [NSLayoutConstraint activateConstraints:@[
        [_runningAppsScrollView.topAnchor constraintEqualToAnchor:effectView.topAnchor constant:20],
        [_runningAppsScrollView.bottomAnchor constraintEqualToAnchor:effectView.contentView.bottomAnchor constant:-20],
        [_runningAppsScrollView.leadingAnchor constraintEqualToAnchor:effectView.contentView.leadingAnchor],
        [_runningAppsScrollView.trailingAnchor constraintEqualToAnchor:effectView.contentView.trailingAnchor],
        
        [_stackView.topAnchor constraintEqualToAnchor:_runningAppsScrollView.topAnchor],
        [_stackView.bottomAnchor constraintEqualToAnchor:_runningAppsScrollView.bottomAnchor],
        [_stackView.leadingAnchor constraintEqualToAnchor:_runningAppsScrollView.leadingAnchor constant:20],
        [_stackView.trailingAnchor constraintEqualToAnchor:_runningAppsScrollView.trailingAnchor constant:-20],
        [_stackView.heightAnchor constraintEqualToAnchor:_runningAppsScrollView.heightAnchor],
    ]];
    
    _placeholderStack.hidden = (self.windows.count > 0);
    
    [self populateRunningAppTiles];
    
    self.appSwitcherView = container;
    [self.rootViewController.view addSubview:self.appSwitcherView];
    
    [NSLayoutConstraint activateConstraints:@[
        [self.appSwitcherView.leadingAnchor constraintEqualToAnchor:self.rootViewController.view.leadingAnchor],
        [self.appSwitcherView.trailingAnchor constraintEqualToAnchor:self.rootViewController.view.trailingAnchor],
        [self.appSwitcherView.heightAnchor constraintEqualToAnchor:self.rootViewController.view.heightAnchor multiplier:0.55]
    ]];
    
    self.appSwitcherTopConstraint = [self.appSwitcherView.topAnchor constraintEqualToAnchor:self.rootViewController.view.bottomAnchor];
    self.appSwitcherTopConstraint.active = YES;
    [self.rootViewController.view layoutIfNeeded];
    
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    pan.delegate = self;
    [self.appSwitcherView addGestureRecognizer:pan];
    
    self.impactGenerator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
    [self.impactGenerator prepare];
}

- (UIVisualEffectView *)createBlurEffectView
{
    if(@available(iOS 26.0, *))
    {
        UIGlassEffect *glassEffect = [[UIGlassEffect alloc] init];
        return [[UIVisualEffectView alloc] initWithEffect:glassEffect];
    }
    else
    {
        UIBlurEffect *blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
        return [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    }
}

- (void)buildPlaceholderStackInView:(UIView *)parentView
{
    UIImageSymbolConfiguration *config = [UIImageSymbolConfiguration configurationWithPointSize:48 weight:UIImageSymbolWeightRegular];
    UIImage *symbol = [UIImage systemImageNamed:@"app.dashed" withConfiguration:config];
    UIImageView *symbolView = [[UIImageView alloc] initWithImage:symbol];
    symbolView.tintColor = [UIColor secondaryLabelColor];
    
    UILabel *placeholderLabel = [[UILabel alloc] init];
    placeholderLabel.text = @"No Apps Running";
    placeholderLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    placeholderLabel.textColor = [UIColor secondaryLabelColor];
    
    _placeholderStack = [[UIStackView alloc] initWithArrangedSubviews:@[symbolView, placeholderLabel]];
    _placeholderStack.axis = UILayoutConstraintAxisVertical;
    _placeholderStack.alignment = UIStackViewAlignmentCenter;
    _placeholderStack.spacing = 12;
    _placeholderStack.translatesAutoresizingMaskIntoConstraints = NO;
    
    [parentView addSubview:_placeholderStack];
    
    [NSLayoutConstraint activateConstraints:@[
        [_placeholderStack.centerXAnchor constraintEqualToAnchor:_runningAppsScrollView.centerXAnchor],
        [_placeholderStack.centerYAnchor constraintEqualToAnchor:_runningAppsScrollView.centerYAnchor constant:-20]
    ]];
}

- (void)populateRunningAppTiles
{
    if(self.windows.count == 0)
    {
        /* lets placeholder appear instead */
        return;
    }
    
    /* populate tile by identifier */
    for(NSNumber *identifier in self.windowOrder)
    {
        NXWindow *window = self.windows[identifier];
        UIView *tileContainer = [self createTileContainerForWindow:window];
        [_stackView addArrangedSubview:tileContainer];
    }
}

- (UIView *)createTileContainerForWindow:(NXWindow *)window
{
    NXAppTile *appTile = [[NXAppTile alloc] initWithWindow:window];
    
    appTile.tag = (NSInteger)window.identifier;
    
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTileTap:)];
    [appTile addGestureRecognizer:tap];
    
    UIPanGestureRecognizer *verticalPan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleTileVerticalSwipe:)];
    verticalPan.delegate = self;
    [appTile addGestureRecognizer:verticalPan];
    
    return appTile;
}

- (void)handleTileTap:(UITapGestureRecognizer*)recognizer
{
    UIView *tileWrapper = recognizer.view;
    if(tileWrapper == NULL)
    {
        return;
    }
    
    id_t identifier = (id_t)tileWrapper.tag;
    [self activateWindowForIdentifier:identifier animated:YES withCompletion:nil];
}

- (void)handleTileVerticalSwipe:(UIPanGestureRecognizer *)pan
{
    NXAppTile *tile = (NXAppTile *)pan.view;
    if(!tile)
    {
        return;
    }

    CGPoint translation = [pan translationInView:tile];
    CGPoint velocity = [pan velocityInView:tile];

    if(pan.state == UIGestureRecognizerStateChanged)
    {
        [self handleTileSwipeChanged:translation velocity:velocity tileWrapper:tile.tileWrapper tileMaterial:tile.tileMaterial title:tile.titleLabel reflection:tile.reflection];
    }
    else if(pan.state == UIGestureRecognizerStateEnded || pan.state == UIGestureRecognizerStateCancelled)
    {
        [self handleTileSwipeEnded:translation velocity:velocity tileWrapper:tile.tileWrapper tileMaterial:tile.tileMaterial title:tile.titleLabel reflection:tile.reflection tileContainer:tile];
    }
}

- (void)handleTileSwipeChanged:(CGPoint)translation
                      velocity:(CGPoint)velocity
                   tileWrapper:(UIView*)tileWrapper
                  tileMaterial:(UIVisualEffectView*)tileMaterial
                         title:(UILabel*)title
                    reflection:(UIImageView*)reflection
{
    if(translation.y >= 0)
    {
        return;
    }
    
    CGFloat lift = fabs(translation.y);
    CGFloat maxLift = 250.0;
    CGFloat progress = MIN(1.0, lift / maxLift);
    
    CATransform3D transform = CATransform3DIdentity;
    transform.m34 = -1.0 / 800.0;
    transform = CATransform3DTranslate(transform, 0, translation.y, 0);
    
    CGFloat tiltAngle = progress * 0.4;
    transform = CATransform3DRotate(transform, tiltAngle, 1, 0, 0);
    
    CGFloat maxYRotation = 0.15;
    CGFloat yRotation = (velocity.x / 2000.0) * maxYRotation;
    yRotation = MAX(-maxYRotation, MIN(maxYRotation, yRotation));
    transform = CATransform3DRotate(transform, yRotation, 0, 1, 0);
    
    CGFloat scale = 1.0 - (progress * 0.1);
    transform = CATransform3DScale(transform, scale, scale, scale);
    
    CGFloat zTranslate = -progress * 50;
    transform = CATransform3DTranslate(transform, 0, 0, zTranslate);
    
    CGFloat horizontalDrift = (velocity.x / 1500.0) * 15.0;
    horizontalDrift = MAX(-20, MIN(20, horizontalDrift));
    transform = CATransform3DTranslate(transform, horizontalDrift, 0, 0);
    
    tileWrapper.layer.transform = transform;
    tileWrapper.alpha = 1.0 - (progress * 0.5);
    
    tileMaterial.layer.shadowOpacity = 0.25 + (progress * 0.15);
    tileMaterial.layer.shadowRadius = 12 + (progress * 6);
    tileMaterial.layer.shadowOffset = CGSizeMake(horizontalDrift * 0.2, 6 + (progress * 15));
    
    title.alpha = 1.0 - (progress * 20);
    CATransform3D titleTransform = CATransform3DIdentity;
    titleTransform.m34 = -1.0 / 800.0;
    titleTransform = CATransform3DTranslate(titleTransform, horizontalDrift * 0.3, translation.y * 0.25, 0);
    titleTransform = CATransform3DScale(titleTransform, 1.0 - (progress * 0.15), 1.0 - (progress * 0.15), 1);
    title.layer.transform = titleTransform;
    
    CGFloat scaleY = 1.0 + (progress * 0.8);
    reflection.transform = CGAffineTransformConcat(
        CGAffineTransformMakeScale(1, -scaleY),
        CGAffineTransformMakeTranslation(0, lift)
    );
    reflection.alpha = 0.35 * (1.0 - (progress * 0.6));
}

- (void)handleTileSwipeEnded:(CGPoint)translation
                    velocity:(CGPoint)velocity
                 tileWrapper:(UIView*)tileWrapper
                tileMaterial:(UIVisualEffectView *)tileMaterial
                       title:(UILabel*)title
                  reflection:(UIImageView*)reflection
               tileContainer:(UIView *)tileContainer
{
    CGFloat velocityY = velocity.y;
    CGFloat velocityX = velocity.x;
    CGFloat offsetY = translation.y;
    
    BOOL shouldDismiss = (offsetY < -100) || (velocityY < -500);
    
    if(shouldDismiss)
    {
        [self dismissTile:tileWrapper tileMaterial:tileMaterial title:title reflection:reflection tileContainer:tileContainer velocityX:velocityX offsetY:offsetY];
    }
    else
    {
        [self resetTile:tileWrapper tileMaterial:tileMaterial title:title reflection:reflection];
    }
}

- (void)dismissTile:(UIView*)tileWrapper
       tileMaterial:(UIVisualEffectView*)tileMaterial
              title:(UILabel*)title
         reflection:(UIImageView*)reflection
      tileContainer:(UIView*)tileContainer
          velocityX:(CGFloat)velocityX
            offsetY:(CGFloat)offsetY
{
    CGFloat lift = fabs(offsetY);
    CGFloat progress = MIN(1.0, lift / 250.0);
    CGFloat currentScale = 1.0 + (progress * 0.8);
    
    CGFloat exitYRotation = (velocityX / 800.0) * 0.5;
    exitYRotation = MAX(-0.6, MIN(0.6, exitYRotation));
    CGFloat exitDriftX = (velocityX / 800.0) * 100;
    exitDriftX = MAX(-150, MIN(150, exitDriftX));
    
    UIStackView *stack = _stackView;
    
    [UIView animateWithDuration:0.25 delay:0 options:UIViewAnimationOptionCurveEaseIn animations:^{
        CATransform3D exitTransform = CATransform3DIdentity;
        exitTransform.m34 = -1.0 / 600.0;
        exitTransform = CATransform3DTranslate(exitTransform, exitDriftX, -tileContainer.bounds.size.height * 0.8, -200);
        exitTransform = CATransform3DRotate(exitTransform, 0.7, 1, 0, 0);
        exitTransform = CATransform3DRotate(exitTransform, exitYRotation, 0, 1, 0);
        exitTransform = CATransform3DScale(exitTransform, 0.5, 0.5, 0.5);
        tileWrapper.layer.transform = exitTransform;
        tileWrapper.alpha = 0;
        
        tileMaterial.layer.shadowOpacity = 0;
        
        title.alpha = 0;
        CATransform3D titleExit = CATransform3DIdentity;
        titleExit.m34 = -1.0 / 800.0;
        titleExit = CATransform3DTranslate(titleExit, exitDriftX * 0.3, -100, -50);
        titleExit = CATransform3DScale(titleExit, 0.7, 0.7, 1);
        title.layer.transform = titleExit;
        
        reflection.transform = CGAffineTransformConcat(
            CGAffineTransformMakeScale(1, -(currentScale + 0.5)),
            CGAffineTransformMakeTranslation(0, lift + 100)
        );
        reflection.alpha = 0;
    } completion:^(BOOL finished) {
        id_t identifier = (id_t)tileContainer.tag;
        NXWindow *window = self.windows[@(identifier)];
        
        if(window)
        {
            [window.session closeWindow];
        }
        
        tileContainer.hidden = YES;
        
        [UIView animateWithDuration:0.35 delay:0 usingSpringWithDamping:0.8 initialSpringVelocity:0.5 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            [stack removeArrangedSubview:tileContainer];
            [tileContainer removeFromSuperview];
            [stack layoutIfNeeded];
            [stack.superview layoutIfNeeded];
        } completion:^(BOOL finished) {
            if(self.windows.count == 0 && self->_placeholderStack)
            {
                self->_placeholderStack.alpha = 0;
                self->_placeholderStack.hidden = NO;
                [UIView animateWithDuration:0.3 animations:^{
                    self->_placeholderStack.alpha = 1;
                }];
            }
        }];
    }];
}

- (void)resetTile:(UIView*)tileWrapper
     tileMaterial:(UIVisualEffectView*)tileMaterial
            title:(UILabel*)title
       reflection:(UIImageView*)reflection
{
    [UIView animateWithDuration:0.7 delay:0 usingSpringWithDamping:0.55 initialSpringVelocity:0.9 options:UIViewAnimationOptionBeginFromCurrentState animations:^{
        tileWrapper.layer.transform = CATransform3DIdentity;
        tileWrapper.alpha = 1.0;
        tileMaterial.layer.shadowOpacity = 0.25;
        tileMaterial.layer.shadowRadius = 12;
        tileMaterial.layer.shadowOffset = CGSizeMake(0, 6);
        
        title.alpha = 1.0;
        title.layer.transform = CATransform3DIdentity;
        
        reflection.transform = CGAffineTransformMakeScale(1, -1);
        reflection.alpha = 0.35;
    } completion:nil];
}

- (void)showAppSwitcher
{
    self.appSwitcherTopConstraint.active = NO;
    self.appSwitcherTopConstraint = [self.appSwitcherView.topAnchor constraintEqualToAnchor:self.centerYAnchor];
    self.appSwitcherTopConstraint.active = YES;

    [UIView animateWithDuration:0.6 delay:0 usingSpringWithDamping:0.85 initialSpringVelocity:0.6 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        [self layoutIfNeeded];
    } completion:nil];

    [self.impactGenerator impactOccurred];
}

- (void)showAppSwitcherExternal
{
    [self handleLongPress:nil];
}

- (void)hideAppSwitcher
{
    self.appSwitcherTopConstraint.active = NO;
    self.appSwitcherTopConstraint = [self.appSwitcherView.topAnchor constraintEqualToAnchor:self.bottomAnchor];
    self.appSwitcherTopConstraint.active = YES;
    
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1.0 initialSpringVelocity:1.0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        [self layoutIfNeeded];
    } completion:^(BOOL finished) {
        [self.appSwitcherView removeFromSuperview];
        self.appSwitcherView = nil;
        self.appSwitcherTopConstraint = nil;
        self->_placeholderStack = nil;
        self->_stackView = nil;
        self->_runningAppsScrollView = nil;
    }];
    
    UIImpactFeedbackGenerator *dismissHaptic = [[UIImpactFeedbackGenerator alloc]
        initWithStyle:UIImpactFeedbackStyleLight];
    [dismissHaptic impactOccurred];
    
    [[NSNotificationCenter defaultCenter] removeObserver:self name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:UIKeyboardWillHideNotification object:nil];
}

- (void)handlePan:(UIPanGestureRecognizer*)pan
{
    CGPoint translation = [pan translationInView:self];
    
    switch(pan.state)
    {
        case UIGestureRecognizerStateBegan:
        case UIGestureRecognizerStateChanged:
        {
            CGFloat offset = MAX(0, translation.y);
            self.appSwitcherTopConstraint.constant = offset;
            [self layoutIfNeeded];
            break;
        }
        case UIGestureRecognizerStateEnded:
        case UIGestureRecognizerStateCancelled:
        {
            CGFloat velocityY = [pan velocityInView:self].y;
            CGFloat offset = self.appSwitcherTopConstraint.constant;
            
            if(offset > 100 || velocityY > 500)
            {
                [self hideAppSwitcher];
            }
            else
            {
                self.appSwitcherTopConstraint.constant = 0;
                [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.8 initialSpringVelocity:0.7 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                    [self layoutIfNeeded];
                } completion:nil];
            }
            break;
        }
        default:
            break;
    }
}

- (BOOL)gestureRecognizerShouldBegin:(UIGestureRecognizer *)gestureRecognizer
{
    if([gestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]])
    {
        UIPanGestureRecognizer *pan = (UIPanGestureRecognizer *)gestureRecognizer;
        UIView *view = gestureRecognizer.view;
        
        BOOL isTilePan = [view isKindOfClass:[NXAppTile class]];
        
        if(isTilePan)
        {
            CGPoint velocity = [pan velocityInView:self];
            return (fabs(velocity.y) > fabs(velocity.x)) && (velocity.y < 0);
        }
    }

    return YES;
}

- (BOOL)windowWantsToFocus:(NXWindow *)window
{
    if(_presentationState == NXWindowServerPresentationStateDefault)
    {
        if(_activeWindow != nil &&
           _activeWindow != window)
        {
            [_activeWindow unfocusWindow];
        }
        _activeWindow = window;
        return YES;
    }
    else
    {
        return NO;
    }
}

- (void)windowWantsToClose:(NXWindow *)window
{
    if(_activeWindow == window)
    {
        _activeWindow = nil;
    }
    [window deinit];
    [self.windows removeObjectForKey:@(window.identifier)];
    [self.windowOrder removeObject:@(window.identifier)];
}

- (void)windowWantsToMinimize:(NXWindow *)window
{
    if(_fullScreenWindow == window)
    {
        _fullScreenWindow = nil;
    }
    _activeWindowIdentifier = (id_t)-1;
}

- (void)windowWantsToMaximize:(NXWindow*)window
{
    if(window == nil)
    {
        if(_fullScreenWindow != nil)
        {
            [_fullScreenWindow.view removeFromSuperview];
            [_windowLayer addSubview:_fullScreenWindow.view];
            [_fullScreenWindow.view layoutSubviews];
        }
        
        _fullScreenWindow = nil;
        _presentationState = NXWindowServerPresentationStateDefault;
    }
    else
    {
        if(_fullScreenWindow != nil)
        {
            [_fullScreenWindow.view removeFromSuperview];
            [_windowLayer addSubview:_fullScreenWindow.view];
        }
        
        [window.view removeFromSuperview];
        [self addSubview:window.view];
        [self bringSubviewToFront:window.view];
        [window.view layoutSubviews];
        
        [self windowWantsToFocus:window];
        _fullScreenWindow = window;
        _presentationState = NXWindowServerPresentationStateFullScreen;
    }
}

- (CGRect)window:(NXWindow*)window wantsToChangeToRect:(CGRect)rect
{
    /* getting parameters */
    UIEdgeInsets insets = self.safeAreaInsets;
    CGRect bounds = self.bounds;
    
    /* calculating fullscreen rectangle */
    CGRect allowed = UIEdgeInsetsInsetRect(bounds, insets);
    CGRect boundsInset = allowed;
    allowed.size.height += insets.bottom;
    
    /* checking if maximised */
    if(window.isMaximized)
    {
        //if([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
        if(YES)
        {
            return self.bounds;
        }
        else
        {
            return allowed;
        }
    }
    else
    {
        /* fixing non maximised constraints */
        allowed.origin.x -= (rect.size.width - 50);
        allowed.size.width += ((rect.size.width * 2) - 100);
        allowed.size.height += (rect.size.height - 50);
    }
    
    /* a lot of math */
    if(rect.size.height > boundsInset.size.height)
    {
        rect.size.height = boundsInset.size.height;
    }

    if(rect.origin.x < allowed.origin.x)
    {
        rect.origin.x = allowed.origin.x;
    }
    
    if(CGRectGetMaxX(rect) > CGRectGetMaxX(allowed))
    {
        rect.origin.x = CGRectGetMaxX(allowed) - rect.size.width;
    }
    
    if(rect.origin.y < allowed.origin.y)
    {
        rect.origin.y = allowed.origin.y;
    }
    
    if(CGRectGetMaxY(rect) > CGRectGetMaxY(allowed))
    {
        rect.origin.y = CGRectGetMaxY(allowed) - rect.size.height;
    }
    
    return rect;
}

- (void)orientationChanged:(NSNotification*)notification
{
    dispatch_async(dispatch_get_main_queue(), ^{
        for(NSNumber *key in self.windows)
        {
            NXWindow *window = self.windows[key];
            if(window != nil)
            {
                [window changeWindowToRect:[self window:window wantsToChangeToRect:window.view.frame] completion:nil];
            }
        }
    });
}

- (UIModalPresentationStyle)styleForTransitionView:(id)view
{
    if(![view isKindOfClass:NSClassFromString(@"UITransitionView")])
    {
        return UIModalPresentationNone;
    }
    
    __strong id delegate = nil;
    if([view respondsToSelector:@selector(delegate)])
    {
        delegate = [view performSelector:@selector(delegate)];
    }
    
    if(delegate == nil)
    {
        return UIModalPresentationNone;
    }
    
    if([delegate isKindOfClass:NSClassFromString(@"_UIFullscreenPresentationController")])
    {
        return UIModalPresentationFullScreen;
    }
    
    return UIModalPresentationNone;
}

- (void)addSubview:(UIView *)view
{
    [super addSubview:view];
    
    if([view isKindOfClass:NSClassFromString(@"UITransitionView")])
    {
        UIModalPresentationStyle presentationStyle = [self styleForTransitionView:view];
        if(presentationStyle == UIModalPresentationFullScreen)
        {
            [super bringSubviewToFront:view];
            [super bringSubviewToFront:_windowLayer];
            if(_fullScreenWindow != nil)
            {
                [super bringSubviewToFront:_fullScreenWindow.view];
            }
        }
        return;
    }
}

@end
