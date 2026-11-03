/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2023 - 2026 LiveContainer
 Copyright (C) 2026 emexlab

 This file is part of LiveContainer.

 LiveContainer is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 LiveContainer is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIVECONTAINER_LCUTILS_H
#define LIVECONTAINER_LCUTILS_H

#import <Foundation/Foundation.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>

int dyld_get_program_sdk_version(void);

#if defined(BOOT)
__attribute__((objc_runtime_name("NXBootLCUtils")))
#endif
@interface LCUtils : NSObject

@property (class, nonatomic, readwrite, strong) NSData *certificateData;
@property (class, nonatomic, readwrite, strong) NSString *certificatePassword;
@property (class, nonatomic, readonly, strong) NSData *profileData;

+ (NSProgress *)signAppBundleWithZSign:(NSURL *)path completionHandler:(void (^)(BOOL success, NSError *error))completionHandler;
+ (BOOL)signMachOAtURL:(NSURL *)url;
+ (BOOL)signMachOWithoutPatchAtURL:(NSURL *)url;
+ (int)validateCertificateWithCompletionHandler:(void(^)(int status, NSString *error))completionHandler;
+ (int)validateCertificateWithCertificateData:(NSData*)data withPassword:(NSString*)password WithCompletionHandler:(void(^)(int status, NSString *error))completionHandler;

@end

BOOL NXSignMachOAuto(NSURL *url);

#endif /* LIVECONTAINER_LCUTILS_H */

BOOL NXSignMachOWithIdentity(NSURL *url, NSData *profile, NSData *certificate, NSString *password);
