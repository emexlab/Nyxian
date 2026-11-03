/* SPDX-License-Identifier: LicenseRef-EPSL-1.1 */
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN
/* Presentation only. No filesystem, signing, wipe or boot operations belong here. */
@interface NXRecoverySurface : UIView
@property (nonatomic, copy, nullable) void (^onSelect)(NSInteger index);
@property (nonatomic, copy, nullable) dispatch_block_t onBack;
@property (nonatomic, copy, nullable) dispatch_block_t onHome;
@property (nonatomic, copy, nullable) dispatch_block_t onComplete;
- (void)showHeader:(NSString *)header instructions:(NSString *)instructions
           titles:(NSArray<NSString *> *)titles enabled:(NSArray<NSNumber *> *)enabled
         checks:(NSArray<NSNumber *> *)checks browserPath:(nullable NSString *)browserPath filePaths:(NSArray<NSString *> *)filePaths selected:(NSInteger)selected home:(BOOL)home confirmation:(BOOL)confirmation canGoBack:(BOOL)canGoBack;
- (NSInteger)browserIndexAfterMoving:(NSInteger)delta current:(NSInteger)current;
- (void)showCertificatePassword:(NSString *)password;
- (void)focusCertificatePassword;
- (BOOL)formatDataConfirmed;
/* TWRP's file manager name/permissions inputs: the text the next input page starts with, and what was typed */
- (void)prepareTextInput:(NSString *)text;
- (NSString *)textInputValue;
@property (nonatomic, copy, nullable) void (^onPasswordChanged)(NSString *password);
- (void)setSelectedIndex:(NSInteger)index;
- (BOOL)settingsDetailActive;
- (void)setLog:(NSAttributedString *)log;
- (void)setOperationProgress:(double)fraction status:(NSString *)status;
- (void)clearOperationProgress;
- (void)setConsole:(BOOL)console completionEnabled:(BOOL)enabled;
/* a finished console's button and subtitle, "Continue"/"Complete" unless set */
- (void)setConsoleCompletionTitle:(NSString *)title status:(NSString *)status;
/* the TWRP terminal page (session in TWRP/NXTWRPTerminal), takes hardware keyboard input while shown */
- (void)setTerminal:(BOOL)terminal;
@end
NS_ASSUME_NONNULL_END
