/* SPDX-License-Identifier: GPL-3.0-or-later */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT NSNotificationName const NXTWRPThemeDidChangeNotification;

@interface NXTWRPThemeStore : NSObject

+ (nullable NSString *)activeDirectory;
+ (NSString *)activeName;
+ (nullable NSURL *)prepareArchive:(NSURL *)archive error:(NSError **)error;
+ (BOOL)activatePreparedTheme:(NSURL *)directory name:(NSString *)name error:(NSError **)error;
+ (void)useStockTheme;

@end

NS_ASSUME_NONNULL_END
