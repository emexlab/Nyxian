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

#import <LindChain/WindowServer/Window/NXWindow.h>
#import <LindChain/WindowServer/Window/NXResizeHandle.h>
#import <LindChain/WindowServer/Window/NXWindowBar.h>
#import <LindChain/Private/UIKitPrivate.h>
#import <LindChain/WindowServer/NXWindowServer.h>
@implementation NXWindow {
    UIStackView *_contentStack;
    NXResizeHandle *_resizeHandle;
    NXWindowBar *_windowBar;
    UIView *_focusHitView;
    dispatch_once_t _viewDidAppearOnceDispatch;
    dispatch_once_t _closeOnce;
    int _resizeEndDebounceRefCnt;
}

- (instancetype)initWithSession:(NXWindowSession*)session
                   withDelegate:(id<NXWindowDelegate>)delegate;
{
    self = [super initWithNibName:nil bundle:nil];
    /* TODO: sanitize all nil classes in all objc apis of Nyxian please */
    
    _session = session;
    _session.isFullscreen = NO;
    _delegate = delegate;
    
    self.view = [[UIStackView alloc] initWithFrame:[_session startWindowRect]];
    self.view.backgroundColor = UIColor.clearColor;
    self.view.autoresizingMask = UIViewAutoresizingNone;
    
    if(UITraitCollection.currentTraitCollection.userInterfaceStyle == UIUserInterfaceStyleDark)
    {
        self.view.layer.shadowColor = UIColor.blackColor.CGColor;
        self.view.layer.shadowOpacity = 0.8;
        self.view.layer.shadowRadius = 20;
        self.view.layer.shadowOffset = CGSizeMake(0, 0);
    }
    else
    {
        self.view.layer.shadowColor = UIColor.blackColor.CGColor;
        self.view.layer.shadowOpacity = 0.4;
        self.view.layer.shadowRadius = 10;
        self.view.layer.shadowOffset = CGSizeMake(0, 0);
    }
    
    _contentStack = [UIStackView new];
    _contentStack.frame = self.view.bounds;
    _contentStack.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    
    _contentStack.axis = UILayoutConstraintAxisVertical;
    _contentStack.backgroundColor = UIColor.systemBackgroundColor;
    
    _contentStack.layer.cornerRadius = 20;
    //if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPhone)
    //{
        //_contentStack.layer.maskedCorners = kCALayerMinXMinYCorner | kCALayerMaxXMinYCorner;
    //}
    _contentStack.layer.masksToBounds = YES;
    [self.view addSubview:_contentStack];
    
    __weak typeof(self) weakSelf = self;
    _windowBar = [[NXWindowBar alloc] initWithTitle:self.session.windowName withCloseCallback:^{
        [weakSelf closeWindowWithCompletion:nil];
    } withMaximizeCallback:^{
        [weakSelf maximizeWindow:YES];
    }];
    self.session.window = self;
    
    [_contentStack addArrangedSubview:_windowBar];
    
    [NSLayoutConstraint activateConstraints:@[
        [_windowBar.topAnchor constraintEqualToAnchor:_contentStack.topAnchor],
        [_windowBar.leadingAnchor constraintEqualToAnchor:_contentStack.leadingAnchor],
        [_windowBar.trailingAnchor constraintEqualToAnchor:_contentStack.trailingAnchor],
    ]];
    
    [self addChildViewController:_session];
    _session.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [_contentStack addArrangedSubview:_session.view];
    [_contentStack sendSubviewToBack:_session.view];
    [_session didMoveToParentViewController:self];
    
    //if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad)
    if([NXWindowServer isMultitaskingEnabled])
    {
        /* this is to move the window obviously */
        UIPanGestureRecognizer *moveGesture =
        [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(moveWindow:)];
        moveGesture.minimumNumberOfTouches = 1;
        moveGesture.maximumNumberOfTouches = 1;
        [_windowBar addGestureRecognizer:moveGesture];
        
        /* this is to full screen the window by double tap */
        UITapGestureRecognizer *fullScreenGesture =
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(maximizeButtonPressed)];
        fullScreenGesture.numberOfTapsRequired = 2;
        fullScreenGesture.numberOfTouchesRequired = 1;
        fullScreenGesture.delaysTouchesBegan = NO;
        fullScreenGesture.delaysTouchesEnded = NO;
        fullScreenGesture.cancelsTouchesInView = NO;
        [_windowBar addGestureRecognizer:fullScreenGesture];
        
        moveGesture.delegate = self;
        fullScreenGesture.delegate = self;
        
        /* and this is to resize a window lol */
        UIPanGestureRecognizer *resizeGesture =
        [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(resizeWindow:)];
        resizeGesture.minimumNumberOfTouches = 1;
        resizeGesture.maximumNumberOfTouches = 1;
        
        _resizeHandle = [[NXResizeHandle alloc] initWithFrame:CGRectMake(_contentStack.frame.size.width - 44, _contentStack.frame.size.height - 44, 44, 44)];
        [_resizeHandle addGestureRecognizer:resizeGesture];
        [_contentStack addSubview:_resizeHandle];
    }
    else
    {
        /* this is to close the app on iPhone lol */
        UIPanGestureRecognizer *pullDownGesture = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(minimizeWindow:)];
        [_windowBar addGestureRecognizer:pullDownGesture];
    }
    
    _contentStack.layer.borderWidth = 0.5;
    _contentStack.layer.borderColor = UIColor.systemGray3Color.CGColor;
    
    [self updateOriginalFrame];
    self.view.alpha = 0.0;
    
    return self;
}

- (void)closeWindowWithCompletion:(void (^)(BOOL))completion
{
    dispatch_once(&_closeOnce, ^{
        [UIView animateKeyframesWithDuration:0.25 delay:0 options:UIViewKeyframeAnimationOptionCalculationModeCubic animations:^{
            [UIView addKeyframeWithRelativeStartTime:0.0 relativeDuration:0.25 animations:^{
                self.view.alpha = 0.8;
                self.view.transform = CGAffineTransformMakeScale(1.05, 1.05);
            }];
            [UIView addKeyframeWithRelativeStartTime:0.25 relativeDuration:0.75 animations:^{
                self.view.alpha = 0.0;
                self.view.transform = CGAffineTransformMakeScale(0.6, 0.6);
            }];
        } completion:^(BOOL finished) {
            self.view.transform = CGAffineTransformIdentity;
            BOOL closeWindow = [self.session closeWindow];
            
            if(closeWindow)
            {
                [self.delegate windowWantsToClose:self];
            }
            else
            {
                if(completion) completion(closeWindow);
            }
        }];
    });
}

- (void)openWindow
{
    self.view.alpha = 0.0;
    self.view.transform = CGAffineTransformMakeScale(0.6, 0.6);
    [UIView animateKeyframesWithDuration:0.28 delay:0 options:UIViewKeyframeAnimationOptionCalculationModeCubic animations:^{
        [UIView addKeyframeWithRelativeStartTime:0.0 relativeDuration:0.5 animations:^{
            self.view.alpha = 1.0;
            self.view.transform = CGAffineTransformMakeScale(1.05, 1.05);
        }];
        [UIView addKeyframeWithRelativeStartTime:0.5 relativeDuration:0.5 animations:^{
            self.view.transform = CGAffineTransformIdentity;
        }];
    } completion:nil];
}

- (void)focusWindow
{
    assert([NSThread isMainThread]);
    
    if(!_focusHitView) return;
    if(![self.delegate windowWantsToFocus:self]) return;
    self.session.isFocused = YES;
    
    [self.view.superview bringSubviewToFront:self.view];
    
    [_windowBar changeFocus:true];
    
    [UIView animateWithDuration:0.11 delay:0 options:UIViewAnimationOptionCurveEaseIn animations:^{
        self->_focusHitView.alpha = 0.0;
        self->_focusHitView.transform = CGAffineTransformMakeScale(1.02, 1.02);
    } completion:^(BOOL finished) {
        [self->_focusHitView removeFromSuperview];
        self->_focusHitView = nil;
    }];
}

- (void)unfocusWindow
{
    assert([NSThread isMainThread]);
    
    if (_focusHitView != nil) return;
    self.session.isFocused = NO;
    
    [_windowBar changeFocus:false];
    
    _focusHitView = [[UIView alloc] init];
    _focusHitView.backgroundColor = UIColor.secondarySystemFillColor;
    _focusHitView.alpha = 0.0;
    _focusHitView.translatesAutoresizingMaskIntoConstraints = NO;
    [_contentStack insertSubview:_focusHitView aboveSubview:self.session.view];
    
    [NSLayoutConstraint activateConstraints:@[
        [_focusHitView.topAnchor constraintEqualToAnchor:_windowBar.bottomAnchor],
        [_focusHitView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [_focusHitView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_focusHitView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor]
    ]];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_focusHitView.transform = CGAffineTransformMakeScale(1.02, 1.02);
        
        [UIView animateWithDuration:0.11 delay:0 options:UIViewAnimationOptionCurveEaseOut animations:^{
            self->_focusHitView.alpha = 0.12;
            self->_focusHitView.transform = CGAffineTransformIdentity;
        } completion:nil];
    });
}

- (void)maximizeWindow:(BOOL)animated
{
    [self focusWindow];
    
    void (^changes)(void);
    void (^completion)(void);
    
    if(self.isMaximized)
    {
        [self.delegate windowWantsToMaximize:nil];
        [_windowBar setFullscreen:NO animated:YES];
        
        self.isMaximized = NO;
        self.session.isFullscreen = NO;
        CGRect newFrame = [self.delegate window:self wantsToChangeToRect:self.originalFrame];
        
        changes = ^{
            self.view.frame = newFrame;
            [self.view layoutIfNeeded];
            
            if(UIDevice.currentDevice.userInterfaceIdiom != UIUserInterfaceIdiomPhone)
            {
                self->_contentStack.layer.cornerRadius = 20;
            }
            self->_contentStack.layer.borderWidth = 0.5;
            [self refreshEffects];
            self->_resizeHandle.hidden = NO;
        };
        
        completion = ^{
            self->_windowBar.maximizeButton.imageView.image = [UIImage systemImageNamed:@"arrow.up.left.and.arrow.down.right.circle.fill"];
        };
    }
    else
    {
        [self.delegate windowWantsToMaximize:self];
        [_windowBar setFullscreen:YES animated:YES];
        
        self.isMaximized = YES;
        self.session.isFullscreen = YES;
        CGRect newFrame = [self.delegate window:self wantsToChangeToRect:CGRectZero];
        
        changes = ^{
            self.view.frame = newFrame;
            [self.view layoutIfNeeded];
            
            //if(UIDevice.currentDevice.userInterfaceIdiom != UIUserInterfaceIdiomPhone)
            //{
                //self->_contentStack.layer.cornerRadius = 0;
            //}
            self->_contentStack.layer.borderWidth = 0;
            self.view.layer.shadowOpacity = 0;
            self->_resizeHandle.hidden = YES;
        };
        
        completion = ^{
            self->_windowBar.maximizeButton.imageView.image = [UIImage systemImageNamed:@"arrow.down.right.and.arrow.up.left.circle.fill"];
        };
    }
    
    if(animated)
    {
        [UIView animateWithDuration:0.35 delay:0 options:UIViewAnimationOptionCurveEaseInOut animations:changes completion:^(BOOL finished) {
            if(finished)
            {
                completion();
            }
        }];
    }
    else
    {
        changes();
        completion();
    }
}

- (void)maximizeButtonPressed
{
    [self maximizeWindow:YES];
}

- (void)moveWindow:(UIPanGestureRecognizer*)gesture
{
    if(_isMaximized) return;
    
    switch(gesture.state)
    {
        case UIGestureRecognizerStateBegan:
            [self focusWindow];
            [gesture setTranslation:CGPointZero inView:self.view.superview];
            break;
        case UIGestureRecognizerStateChanged:
        {
            CGPoint delta = [gesture translationInView:self.view.superview];
            CGRect frame = self.originalFrame;
            frame.origin.x += delta.x;
            frame.origin.y += delta.y;
            frame = [self.delegate window:self wantsToChangeToRect:frame];
            self.view.frame = frame;
            break;
        }
        case UIGestureRecognizerStateEnded:
        case UIGestureRecognizerStateCancelled:
        case UIGestureRecognizerStateFailed:
            [self updateOriginalFrame];
        default:
            break;
    }
}

- (void)resizeWindow:(UIPanGestureRecognizer*)gesture
{
    if(_isMaximized) return;
    
    switch(gesture.state)
    {
        case UIGestureRecognizerStateBegan:
            [self focusWindow];
            [gesture setTranslation:CGPointZero inView:self.view.superview];
            break;
        case UIGestureRecognizerStateChanged:
        {
            CGPoint delta = [gesture translationInView:self.view.superview];
            CGRect oldFrame = self.view.frame;
            CGRect proposed = oldFrame;
            proposed.size.width  = MAX(300, self.originalFrame.size.width  + delta.x);
            proposed.size.height = MAX(200, self.originalFrame.size.height + delta.y);
            
            CGRect corrected = [self.delegate window:self wantsToChangeToRect:proposed];
            BOOL widthBlocked  = (corrected.origin.x != proposed.origin.x);
            BOOL heightBlocked = (corrected.origin.y != proposed.origin.y);
            
            if(widthBlocked)
            {
                corrected.size.width = oldFrame.size.width;
                corrected.origin.x = oldFrame.origin.x;
            }
            
            if(heightBlocked)
            {
                corrected.size.height = oldFrame.size.height;
                corrected.origin.y = oldFrame.origin.y;
            }
            
            self.view.frame = corrected;
            break;
        }
        case UIGestureRecognizerStateEnded:
        case UIGestureRecognizerStateCancelled:
        case UIGestureRecognizerStateFailed:
            [self updateOriginalFrame];
            break;
        default:
            break;
    }
}

- (void)minimizeWindow:(UIPanGestureRecognizer *)gesture
{
    UIView *windowView = self.view;
    
    switch(gesture.state)
    {
        case UIGestureRecognizerStateBegan:
            [windowView.layer removeAllAnimations];
            break;
        case UIGestureRecognizerStateChanged:
        {
            CGPoint translation = [gesture translationInView:windowView.superview];
            CGFloat offsetY = MAX(translation.y, 0);
            windowView.transform = CGAffineTransformMakeTranslation(0, offsetY);
            break;
        }
        case UIGestureRecognizerStateEnded:
        case UIGestureRecognizerStateCancelled:
        {
            CGPoint translation = [gesture translationInView:windowView.superview];
            CGFloat offsetY = MAX(translation.y, 0);
            CGFloat velocityY = [gesture velocityInView:windowView.superview].y;
            BOOL shouldDismiss = (offsetY > 150 || velocityY > 600);
            if(shouldDismiss)
            {
                [UIView animateWithDuration:0.3 delay:0 options:UIViewAnimationOptionCurveEaseInOut | UIViewAnimationOptionBeginFromCurrentState animations:^{
                    windowView.transform = CGAffineTransformMakeTranslation(0, windowView.bounds.size.height + 100);
                    windowView.alpha = 0;
                } completion:^(BOOL finished) {
                    windowView.transform = CGAffineTransformIdentity;
                    windowView.alpha = 1.0;
                    [windowView removeFromSuperview];
                    [self.session deactivateWindow];
                    [self.delegate windowWantsToMinimize:self];
                }];
            }
            else
            {
                [UIView animateWithDuration:0.6 delay:0 usingSpringWithDamping:0.8 initialSpringVelocity:velocityY / 1000.0 options:UIViewAnimationOptionBeginFromCurrentState animations:^{
                    windowView.transform = CGAffineTransformIdentity;
                } completion:nil];
            }
            break;
        }
        default:
            break;
    }
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
    
    dispatch_once(&_viewDidAppearOnceDispatch, ^{
        // MARK: Suppose to only run on phones
        //if([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone)
        if(![NXWindowServer isMultitaskingEnabled])
        {
            [self maximizeWindow:NO];
        }
    });
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [super touchesBegan:touches withEvent:event];
    [self focusWindow];
}

- (void)updateOriginalFrame
{
    self.originalFrame = self.view.frame;
}

- (void)changeWindowToRect:(CGRect)rect
                completion:(void (^)(BOOL))completion
{
    [UIView animateWithDuration:0.35 delay:0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.view.frame = rect;
    } completion:^(BOOL finished){
        if(finished)
        {
            if(completion != nil)
            {
                completion(finished);
            }
        }
    }];
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer
        shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    return YES;
}

- (void)traitCollectionDidChange:(UITraitCollection *)previousTraitCollection
{
    [super traitCollectionDidChange:previousTraitCollection];
    [self refreshEffects];
}

- (void)refreshEffects
{
    _contentStack.layer.borderColor = UIColor.systemGray3Color.CGColor;
    if(!self.isMaximized)
    {
        if(UITraitCollection.currentTraitCollection.userInterfaceStyle == UIUserInterfaceStyleDark)
        {
            self.view.layer.shadowColor = UIColor.blackColor.CGColor;
            self.view.layer.shadowOpacity = 0.8;
            self.view.layer.shadowRadius = 20;
            self.view.layer.shadowOffset = CGSizeMake(0, 0);
        }
        else
        {
            self.view.layer.shadowColor = UIColor.blackColor.CGColor;
            self.view.layer.shadowOpacity = 0.4;
            self.view.layer.shadowRadius = 10;
            self.view.layer.shadowOffset = CGSizeMake(0, 0);
        }
    }
}

- (NSString*)getWindowName
{
    return _windowBar.title;
}

- (void)setWindowName:(NSString *)windowName
{
    _windowBar.title = windowName;
}

- (void)deinit
{
    dispatch_async(dispatch_get_main_queue(), ^{
        /* destroying focus view */
        if(self->_focusHitView != nil)
        {
            [self->_focusHitView removeFromSuperview];
            self->_focusHitView = nil;
        }
    });
}

- (void)dealloc
{
    NSLog(@"deallocated %@", self);
}

@end

