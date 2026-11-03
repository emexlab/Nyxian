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

#ifndef LDEAPPLICATIONOBJECT_H
#define LDEAPPLICATIONOBJECT_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface LDEApplicationObject : NSObject <NSSecureCoding>

@property (nonatomic) NSString *bundleIdentifier;
@property (nonatomic) NSString *localizedName;

@property (nonatomic) NSString *bundlePath;
@property (nonatomic) NSString *containerPath;
@property (nonatomic) NSString *executablePath;
@property (nonatomic) NSDictionary *iconDictionary;
@property (nonatomic) NSString *bundleVersion;
@property (nonatomic) NSString *shortVersionString;
@property (nonatomic) NSString *sdkVersion;
@property (nonatomic) NSString *minimumSystemVersion;
@property (nonatomic) NSDictionary *entitlements;

@property (nonatomic) BOOL isLaunchAllowed;
@property (nonatomic) BOOL isFullscreenRequired;
@property (nonatomic) UIInterfaceOrientationMask supportedInterfaceOrientations;

@property (nonatomic) UIImage *icon;
@property (nonatomic) UIImage *darkIcon;

- (instancetype)initWithNSBundle:(NSBundle*)nsBundle;

@end

#endif /* LDEAPPLICATIONOBJECT_H */
