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

#ifndef NXRECOVERYTERMINAL_H
#define NXRECOVERYTERMINAL_H

#import <Foundation/Foundation.h>

@class NXRecoveryViewController;

NS_ASSUME_NONNULL_BEGIN

/*
 * The recovery's terminal: unpacks the binpack (Shared/Recovery/binpack.zip)
 * into ~/Library/TWRP/opt/procursus, lays out ~/Library/TWRP like emexOS's
 * vroot (boot/rtpatch -> the binpack's libroothide, whose roothideinit.dylib is
 * librecoveryrtpatch; boot/patchfinder.bin), loads the mini kernel
 * (librecoveryksurface) and runs a login bash on a TTY of its own, shown by
 * the TWRP terminal page.
 */
@interface NXRecoveryTerminal : NSObject

@property (class, nonatomic, readonly) NXRecoveryTerminal *shared;

/* ~/Library/TWRP: the recovery's vroot, rootfs and HOME */
@property (nonatomic, readonly) NSString *rootPath;

/* shows the terminal, preparing the recovery root and starting a shell first when needed */
- (void)presentInRecovery:(NXRecoveryViewController *)controller;

/*
 * The path a file of the bootloader's container has in the shell: the binpack
 * is "/", the container is /rootfs (its directories and ~/Library's are
 * linked there). nil when the shell cannot see the file.
 */
- (nullable NSString *)shellPathForPath:(NSString *)path;

/* TWRP's file manager: "Edit File" (nano, vi while the binpack has no nano) and "Open Terminal Here" */
- (void)editFile:(NSString *)path inRecovery:(NXRecoveryViewController *)controller;
- (void)openTerminalAt:(NSString *)directory inRecovery:(NXRecoveryViewController *)controller;

@end

NS_ASSUME_NONNULL_END

#endif /* NXRECOVERYTERMINAL_H */
