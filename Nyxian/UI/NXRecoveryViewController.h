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

#ifndef NXRECOVERYVIEWCONTROLLER_H
#define NXRECOVERYVIEWCONTROLLER_H

#import <UIKit/UIKit.h>

typedef NS_ENUM(NSInteger, NXRecoveryLogLevel) {
    NXRecoveryLogLevelInfo = 0,
    NXRecoveryLogLevelError = 1,
};

@class NXRecoveryViewController;
@class NXRecoveryItem;

typedef void (^NXRecoveryAction)(NXRecoveryViewController *controller);
typedef void (^NXRecoveryIndexHandler)(NXRecoveryViewController *controller, NSInteger index, NXRecoveryItem *item);
typedef void (^NXRecoveryFileHandler)(NSString *path, NSString *name, NXRecoveryViewController *controller);

extern const CGFloat NXRecoveryFontSize;

@interface NXRecoveryItem : NSObject

@property (nonatomic, copy) NSString *title;
@property (nonatomic) BOOL enabled;
@property (nonatomic) BOOL toggle;
@property (nonatomic) BOOL checked;
/* a toggle that is one choice of a radio group (drawn with TWRP's radio buttons) */
@property (nonatomic) BOOL radio;
@property (nonatomic, copy, nullable) NSString *filePath;
@property (nonatomic, copy) NXRecoveryAction action;

- (instancetype)initWithTitle:(NSString *)title action:(NXRecoveryAction)action;

+ (instancetype)itemWithTitle:(NSString *)title;
+ (instancetype)itemWithTitle:(NSString *)title action:(NXRecoveryAction)action;

@end

@interface NXRecoveryViewController : UIViewController

@property (nonatomic, copy) NSArray<NXRecoveryItem *> *recoveryItems;
@property (nonatomic) NSInteger recoveryIndex;
@property (nonatomic, readonly) NXRecoveryItem *currentRecoveryItem;
@property (nonatomic, readonly, getter=isRecoveryActive) BOOL recoveryActive;
@property (nonatomic) NSInteger recoveryLogMax;
@property (nonatomic, readonly, getter=isConsoleActive) BOOL consoleActive;
@property (nonatomic, readonly, getter=isTerminalActive) BOOL terminalActive;

+ (UIColor *)recoveryBackgroundColor;
+ (UIColor *)recoveryHeaderColor;
+ (UIColor *)recoveryInfoColor;
+ (UIColor *)recoveryItemColor;
+ (UIColor *)recoveryHighlightColor;
+ (UIColor *)recoveryHighlightTextColor;
+ (UIColor *)recoveryFooterColor;
+ (UIColor *)recoveryLogInfoColor;
+ (UIColor *)recoveryLogErrorColor;

- (void)attachToViewController:(UIViewController *)parent;
- (void)createRecoveryView;

- (void)setRecoveryHeader:(NSString *)text;
- (void)setRecoveryInstructions:(NSString *)text;
- (void)setRecoveryFooter:(NSString *)text;
- (void)setRecoveryItems:(NSArray<NXRecoveryItem *> *)items;

- (void)showRecovery:(BOOL)visible;

- (void)enterRecoveryWithHeader:(NSString *)header instructions:(NSString *)instructions footer:(NSString *)footer items:(NSArray<NXRecoveryItem *> *)items onSelect:(NXRecoveryIndexHandler)onSelect onMove:(NXRecoveryIndexHandler)onMove;
- (void)exitRecovery;


- (void)recoveryLog:(NSString *)line;
- (void)recoveryLog:(NSString *)line level:(NXRecoveryLogLevel)level;
- (void)recoveryLogError:(NSString *)line;
- (void)clearRecoveryLog;

- (void)browsePath:(NSString *)path root:(NSString *)root header:(NSString *)header onBack:(NXRecoveryAction)onBack onFile:(NXRecoveryFileHandler)onFile;
- (void)browsePath:(NSString *)path;
- (void)enterFileBrowserAtPath:(NSString *)path root:(NSString *)root header:(NSString *)header onBack:(NXRecoveryAction)onBack onFile:(NXRecoveryFileHandler)onFile;
/* TWRP's file manager: a file or the select-folder button opens "Choose Action" (Edit File in the terminal, Open Terminal Here, Copy, Move, chmod, Delete, Rename) */
- (void)enterFileManagerAtPath:(NSString *)path root:(NSString *)root onBack:(NXRecoveryAction)onBack;

/* Settings > General > Boot Arguments: a TWRP text input page with the keyboard. Cancel / Back return to the page it
   was opened from; Save does too and then hands over what was typed */
- (void)enterBootArgumentsInput:(NSString *)text help:(NSString *)help onSave:(void (^)(NXRecoveryViewController *controller, NSString *text))onSave;

- (void)importRecoveryTheme;
- (void)useStockRecoveryTheme;
- (void)reloadRecoveryTheme;
- (void)restoreRecoverySettings;
- (void)focusWipeConfirmation;

- (void)setOperationProgress:(double)fraction status:(NSString *)status;
- (void)clearOperationProgress;
- (void)enterConsole;
- (void)finishConsoleWithSelectAction:(nullable NXRecoveryAction)action;
/* the same with another button and subtitle than "Continue"/"Complete" (a failed locked-down boot: "Reboot") */
- (void)finishConsoleWithSelectAction:(nullable NXRecoveryAction)action title:(NSString *)title status:(NSString *)status;
- (void)exitConsole;

/* the TWRP terminal (NXRecoveryTerminal starts its session), shown over the current page; Back/Home leave it */
- (void)enterTerminal;
- (void)exitTerminal;

@end

#endif /* NXRECOVERYVIEWCONTROLLER_H */
