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

#ifndef NXWINDOWSERVER_H
#define NXWINDOWSERVER_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <LindChain/WindowServer/Window/NXWindow.h>

typedef UInt64 NXWindowServerPresentationState NS_TYPED_ENUM;
static NXWindowServerPresentationState const NXWindowServerPresentationStateDefault = 0;
static NXWindowServerPresentationState const NXWindowServerPresentationStateFullScreen = 1;
static NXWindowServerPresentationState const NXWindowServerPresentationStateOutOfMyWay = 2;

@interface NXWindowServer : UIWindow <UIGestureRecognizerDelegate,NXWindowDelegate>

@property (nonatomic, readonly) NXWindowServerPresentationState presentationState;
@property (nonatomic, weak, readonly) NXWindow *fullScreenWindow;

@property (nonatomic, strong,readonly) NSMutableDictionary<NSNumber*,NXWindow*> *windows;
@property (nonatomic, strong) NSMutableArray<NSNumber *> *windowOrder;

@property (nonatomic, strong) UIView *appSwitcherView;
@property (nonatomic, strong) NSLayoutConstraint *appSwitcherTopConstraint;
@property (nonatomic, strong) UIImpactFeedbackGenerator *impactGenerator;

- (instancetype)initWithWindowScene:(UIWindowScene *)windowScene;
+ (instancetype)sharedWithWindowScene:(UIWindowScene*)windowScene;
+ (instancetype)shared;

- (void)openWindowWithSession:(NXWindowSession*)session withCompletion:(void (^)(BOOL))completion;
- (void)closeWindowWithIdentifier:(id_t)identifier  withCompletion:(void (^)(BOOL))completion;

- (void)activateWindowForIdentifier:(id_t)identifier animated:(BOOL)animated withCompletion:(void (^)(void))completion;

- (void)focusWindowForIdentifier:(id_t)identifier;
- (NXWindowSession*)windowSessionForIdentifier:(id_t)identifier;
- (void)unfocusFocusedWindow;
- (void)windowsGetOutOfMyWay;
- (void)windowsGetInMyWay;

- (void)showAppSwitcherExternal;
+ (BOOL)isMultitaskingEnabled;
+ (void)setMultitaskingEnabled:(BOOL)enabled;
@end

#endif /* NXWINDOWSERVER_H */
