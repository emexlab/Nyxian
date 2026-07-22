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

#import <LindChain/WindowServer/Window/NXWindowBar.h>

@implementation NXWindowBar {
    UIView *_bottomBorder;

    UIView *_dotContainer;
    UIStackView *_buttonStack;

    NSLayoutConstraint *_islandWidthConstraint;
    NSLayoutConstraint *_islandHeightConstraint;
    NSLayoutConstraint *_windowBarHeightConstraint;

    BOOL _islandExpanded;
    NSTimer *_collapseTimer;
    
    UIView *_closeDot;
    UIView *_maxDot;
    UIView *_safeAreaFill;
    
    UILabel *_titleLabel;
}

- (instancetype)initWithTitle:(NSString *)title
            withCloseCallback:(void (^)(void))closeCallback
         withMaximizeCallback:(void (^)(void))maximizeCallback
{
    self = [super init];
    if (!self) return nil;

    self.translatesAutoresizingMaskIntoConstraints = NO;
    self.clipsToBounds = NO;

    BOOL isiPad  = (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad);
    CGFloat barH = isiPad ? 44.0 : 44.0;
    
    _safeAreaFill = [[UIView alloc] init];
    _safeAreaFill.translatesAutoresizingMaskIntoConstraints = NO;
    _safeAreaFill.backgroundColor = UIColor.quaternarySystemFillColor;
    [self addSubview:_safeAreaFill];

    [NSLayoutConstraint activateConstraints:@[
        [_safeAreaFill.topAnchor constraintEqualToAnchor:self.topAnchor],
        [_safeAreaFill.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
        [_safeAreaFill.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        [_safeAreaFill.heightAnchor constraintEqualToConstant:0],
    ]];
    
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
    UIVisualEffectView *blurView = [[UIVisualEffectView alloc] initWithEffect:blur];
    blurView.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:blurView];
    [NSLayoutConstraint activateConstraints:@[
        [blurView.topAnchor constraintEqualToAnchor:self.topAnchor],
        [blurView.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
        [blurView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
        [blurView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
    ]];

    _titleLabel = [[UILabel alloc] init];
    _titleLabel.text = title;
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _titleLabel.textAlignment = NSTextAlignmentCenter;
    _titleLabel.font = [UIFont systemFontOfSize:isiPad ? 17 : 17 weight:UIFontWeightSemibold];
    [self addSubview:_titleLabel];

    UIView *border = [[UIView alloc] init];
    border.translatesAutoresizingMaskIntoConstraints = NO;
    border.backgroundColor = UIColor.systemGray3Color;
    [self addSubview:border];
    _bottomBorder = border;
    
    _windowBarHeightConstraint = [self.heightAnchor constraintEqualToConstant:barH];
    _windowBarHeightConstraint.active = YES;

    //if([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    if(YES)
    {
        [_titleLabel.centerYAnchor constraintEqualToAnchor:self.bottomAnchor constant:-19.0].active = YES;
    }
    else
    {
        [_titleLabel.centerYAnchor constraintEqualToAnchor:self.centerYAnchor].active = YES;
    }
    
    [NSLayoutConstraint activateConstraints:@[
        [_titleLabel.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
        [border.heightAnchor constraintEqualToConstant:0.5],
        [border.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
        [border.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        [border.bottomAnchor constraintEqualToAnchor:self.bottomAnchor],
    ]];

    //if(isiPad)
    if(YES)
    {
        _islandExpanded = NO;
        
        UIVisualEffect *effect;
        
        if(@available(iOS 26.0, *))
        {
            effect = [UIGlassEffect effectWithStyle:UIGlassEffectStyleClear];
        }
        else
        {
            effect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
        }
        
        UIVisualEffectView *island = [[UIVisualEffectView alloc] initWithEffect:effect];
        island.translatesAutoresizingMaskIntoConstraints = NO;
        island.clipsToBounds = YES;
        
        /* FIXME: weird liquid glass artifacts get rendered... */
        island.layer.cornerRadius = 13.0;
        island.layer.cornerCurve = kCACornerCurveContinuous;

        [self addSubview:island];
        _buttonIsland = island;

        UIView *dotContainer = [[UIView alloc] init];
        dotContainer.translatesAutoresizingMaskIntoConstraints = NO;
        [island.contentView addSubview:dotContainer];
        _dotContainer = dotContainer;

        _closeDot = [self _dotWithColor:UIColor.systemRedColor];
        _maxDot = [self _dotWithColor:UIColor.systemGreenColor];
        [dotContainer addSubview:_closeDot];
        [dotContainer addSubview:_maxDot];

        [NSLayoutConstraint activateConstraints:@[
            [_closeDot.leadingAnchor constraintEqualToAnchor:dotContainer.leadingAnchor],
            [_closeDot.centerYAnchor constraintEqualToAnchor:dotContainer.centerYAnchor],
            [_closeDot.widthAnchor constraintEqualToConstant:9.0],
            [_closeDot.heightAnchor constraintEqualToConstant:9.0],
            [_maxDot.leadingAnchor constraintEqualToAnchor:_closeDot.trailingAnchor constant:6.0],
            [_maxDot.trailingAnchor constraintEqualToAnchor:dotContainer.trailingAnchor],
            [_maxDot.centerYAnchor constraintEqualToAnchor:dotContainer.centerYAnchor],
            [_maxDot.widthAnchor constraintEqualToConstant:9.0],
            [_maxDot.heightAnchor constraintEqualToConstant:9.0],
            [dotContainer.centerXAnchor constraintEqualToAnchor:island.centerXAnchor],
            [dotContainer.centerYAnchor constraintEqualToAnchor:island.centerYAnchor],
        ]];

        _closeButton = [self _islandButtonWithImage:@"xmark.circle.fill" withBackgroundColor:UIColor.systemRedColor callback:closeCallback];
        
        __weak typeof(self) weakSelf = self;
        _maximizeButton = [self _islandButtonWithImage:@"arrow.up.left.and.arrow.down.right.circle.fill" withBackgroundColor:UIColor.systemGreenColor callback:^{
            maximizeCallback();
            
            __strong typeof(self) strongSelf = weakSelf;
            if(strongSelf != nil)
            {
                [strongSelf collapseIsland];
            }
        }];

        UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[_closeButton, _maximizeButton]];
        stack.axis = UILayoutConstraintAxisHorizontal;
        stack.spacing = 8;
        stack.alignment = UIStackViewAlignmentCenter;
        stack.translatesAutoresizingMaskIntoConstraints = NO;
        stack.alpha = 0.0;
        stack.transform = CGAffineTransformMakeScale(0.5, 0.5);
        [island.contentView addSubview:stack];
        _buttonStack = stack;

        [NSLayoutConstraint activateConstraints:@[
            [stack.centerXAnchor constraintEqualToAnchor:island.centerXAnchor],
            [stack.centerYAnchor constraintEqualToAnchor:island.centerYAnchor],
            [_closeButton.widthAnchor constraintEqualToConstant:30.0],
            [_closeButton.heightAnchor constraintEqualToConstant:30.0],
            [_maximizeButton.widthAnchor constraintEqualToConstant:30.0],
            [_maximizeButton.heightAnchor constraintEqualToConstant:30.0],
        ]];

        _islandWidthConstraint = [island.widthAnchor  constraintEqualToConstant:48.0];
        _islandHeightConstraint = [island.heightAnchor constraintEqualToConstant:26.0];
        [NSLayoutConstraint activateConstraints:@[
            [island.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:7],
            [island.topAnchor constraintEqualToAnchor:_titleLabel.centerYAnchor constant:-13.0],
            _islandWidthConstraint,
            _islandHeightConstraint,
        ]];

        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTap:)];
        [island.contentView addGestureRecognizer:tap];
        
        UITapGestureRecognizer *bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleBackgroundTap:)];
        bgTap.cancelsTouchesInView = NO;
        [self addGestureRecognizer:bgTap];
    }
    
    UIBlurEffect *barBlur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemThickMaterial];
    UIVisualEffectView *barBackground = [[UIVisualEffectView alloc] initWithEffect:barBlur];
    barBackground.frame = self.bounds;
    barBackground.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self insertSubview:barBackground atIndex:0];

    return self;
}

- (void)handleTap:(UILongPressGestureRecognizer *)gr
{
    if(gr.state == UIGestureRecognizerStateRecognized)
    {
        [self expandIsland];
    }
}

- (void)handleBackgroundTap:(UITapGestureRecognizer *)gr
{
    if(!_islandExpanded)
    {
        return;
    }
    
    CGPoint pt = [gr locationInView:self];
    BOOL insideIsland = [_buttonIsland pointInside:[self convertPoint:pt toView:_buttonIsland] withEvent:nil];
    
    if(!insideIsland)
    {
        [self collapseIsland];
    }
}

- (void)expandIsland
{
    if(_islandExpanded)
    {
        [self resetCollapseTimer];
        return;
    }
    _islandExpanded = YES;
    
    UIView *layoutRoot = _buttonIsland.superview ?: self;

    [layoutRoot layoutIfNeeded];
    [UIView animateWithDuration:0.44 delay:0 usingSpringWithDamping:0.60 initialSpringVelocity:0.6 options:UIViewAnimationOptionBeginFromCurrentState animations:^{
        [self layoutIfNeeded];
        
        self->_dotContainer.alpha = 0.0;
        self->_dotContainer.transform = CGAffineTransformMakeScale(0.3, 0.3);
        self->_buttonStack.alpha = 1.0;
        self->_buttonStack.transform = CGAffineTransformIdentity;
        
        self->_islandWidthConstraint.constant  = 120.0;
        self->_islandHeightConstraint.constant = 58.0;
        
        [layoutRoot layoutIfNeeded];
    } completion:nil];

    [self resetCollapseTimer];
}

- (void)collapseIsland
{
    if(!_islandExpanded)
    {
        return;
    }
    
    _islandExpanded = NO;

    [_collapseTimer invalidate];
    _collapseTimer = nil;
    
    UIView *layoutRoot = _buttonIsland.superview ?: self;

    [layoutRoot layoutIfNeeded];
    [UIView animateWithDuration:0.34 delay:0 usingSpringWithDamping:0.78 initialSpringVelocity:0.2 options:UIViewAnimationOptionBeginFromCurrentState animations:^{
        [self layoutIfNeeded];
        
        self->_buttonIsland.layer.cornerRadius = 13.0;
        self->_dotContainer.alpha = 1.0;
        self->_dotContainer.transform = CGAffineTransformIdentity;
        self->_buttonStack.alpha = 0.0;
        self->_buttonStack.transform = CGAffineTransformMakeScale(0.5, 0.5);
        
        self->_islandWidthConstraint.constant = 48.0;
        self->_islandHeightConstraint.constant = 26.0;
        
        [layoutRoot layoutIfNeeded];
    } completion:nil];
}

- (void)resetCollapseTimer
{
    [_collapseTimer invalidate];
    _collapseTimer = [NSTimer scheduledTimerWithTimeInterval:3.0 target:self selector:@selector(collapseTimerFired) userInfo:nil repeats:NO];
}

- (void)collapseTimerFired
{
    [self collapseIsland];
}

- (UIView *)_dotWithColor:(UIColor *)color
{
    UIView *dot = [[UIView alloc] init];
    dot.translatesAutoresizingMaskIntoConstraints = NO;
    dot.backgroundColor = color;
    dot.layer.cornerRadius = 9.0 / 2.0;
    return dot;
}

- (UIButton *)_islandButtonWithImage:(NSString *)name
                 withBackgroundColor:(UIColor*)backgroundColor
                            callback:(void (^)(void))callback
{
    UIButtonConfiguration *cfg = [UIButtonConfiguration plainButtonConfiguration];
    cfg.preferredSymbolConfigurationForImage = [UIImageSymbolConfiguration configurationWithPointSize:16 weight:UIImageSymbolWeightSemibold];
    cfg.image = [UIImage systemImageNamed:name];
    cfg.baseForegroundColor = backgroundColor;

    UIButton *btn = [UIButton buttonWithConfiguration:cfg primaryAction:nil];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    
    if(callback)
    {
        [btn addAction:[UIAction actionWithHandler:^(__kindof UIAction *a) {
            [self resetCollapseTimer];
            callback();
        }] forControlEvents:UIControlEventTouchUpInside];
    }
    return btn;
}

- (void)changeFocus:(BOOL)focusState
{
    if(focusState)
    {
        [UIView animateWithDuration:0.11 delay:0 options:UIViewAnimationOptionCurveEaseIn animations:^{
            self->_closeDot.backgroundColor = UIColor.systemRedColor;
            self->_maxDot.backgroundColor = UIColor.systemGreenColor;
        } completion:nil];
    }
    else
    {
        [self collapseIsland];
        [UIView animateWithDuration:0.11 delay:0 options:UIViewAnimationOptionCurveEaseOut animations:^{
            self->_closeDot.backgroundColor = UIColor.systemGrayColor;
            self->_maxDot.backgroundColor = UIColor.systemGrayColor;
        } completion:nil];
    }
}

- (void)setFullscreen:(BOOL)fullscreen animated:(BOOL)animated
{
    //if([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    if(YES)
    {
        //CGFloat safeTop = self.window.safeAreaInsets.top;
        CGFloat baseHeight = 44.0;
        
        CGFloat newHeight = baseHeight
        
        void (^changes)(void) = ^{
            self->_windowBarHeightConstraint.constant = newHeight;
            [self layoutIfNeeded];
        };
        
        if(animated)
        {
            [UIView animateWithDuration:0.3 animations:changes];
        }
        else
        {
            changes();
        }
    }
}

- (NSString*)getTitle
{
    return _titleLabel.text;
}

- (void)setTitle:(NSString *)title
{
    _titleLabel.text = title;
}

- (void)dealloc
{
    [_collapseTimer invalidate];
    NSLog(@"deallocated %@", self);
}

- (UIView *)hitTest:(CGPoint)point
          withEvent:(UIEvent *)event
{
    if(_buttonIsland && !_buttonIsland.hidden)
    {
        CGPoint islandPoint = [self convertPoint:point toView:_buttonIsland];
        if([_buttonIsland pointInside:islandPoint withEvent:event])
        {
            return [_buttonIsland hitTest:islandPoint withEvent:event];
        }
    }
    return [super hitTest:point withEvent:event];
}

@end
