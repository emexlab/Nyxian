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

#import <LindChain/WindowServer/Window/NXWindowSession.h>
#import <LindChain/WindowServer/Window/NXWindow.h>

@implementation NXWindowSession

- (BOOL)openWindow
{
    _startWindowRect = CGRectMake(50, 50, 375, 667);
    return (self.windowScene != nil);
}

- (BOOL)closeWindow
{
    return YES;
}

- (BOOL)activateWindow
{
    return YES;
}

- (BOOL)deactivateWindow
{
    return YES;
}

- (BOOL)focusWindow
{
    return YES;
}

- (BOOL)unfocusWindow
{
    return YES;
}

- (UIImage*)snapshotWindow
{
    UIGraphicsBeginImageContextWithOptions(self.view.bounds.size, NO, 0.0);
    CGContextRef context = UIGraphicsGetCurrentContext();
    [self.view.layer renderInContext:context];
    UIImage *snapshot = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return snapshot;
}

- (NSString*)getWindowName
{
    __strong NXWindow *window = self.window;
    return (window == nil) ? window.windowName : @"Unknown";
}

- (void)setWindowName:(NSString *)windowName
{
    __strong NXWindow *window = self.window;
    if(window != nil)
    {
        window.windowName = windowName;
    }
}

- (void)movedWindowToScene:(UIWindowScene*)windowScene
            withIdentifier:(id_t)identifier
{
    self.windowIdentifier = identifier;
    
    /*
     * not changing the windowScene doesnt mean strictly
     * that changing the windowIdentifier shall be
     * prohibited.
     */
    if(windowScene == nil)
    {
        return;
    }
    
    self.windowScene = windowScene;
    
    return;
}



@end
