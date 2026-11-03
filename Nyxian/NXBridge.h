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

#ifndef NXBRIDGE_H
#define NXBRIDGE_H

/* Objective-C UI Headers */
#import <UI/XCodeButton.h>
#import <UI/UIInit/NXUIViewController.h>
#import <UI/UIInit/NXUITableViewController.h>
#import <UI/UIInit/NXUITabBarController.h>
#import <UI/UIInit/NXUISwitch.h>
#import <UI/Settings/NXSettingsTableViewController.h>

/* Apple Private API Headers */
#import <LindChain/Private/UIKitPrivate.h>

/* IDE Headers */
#import <LindChain/IDEFoundation/NXUser.h>
#import <LindChain/IDEFoundation/NXCodeTemplate.h>
#import <LindChain/IDEFoundation/NXPlist.h>
#import <LindChain/IDEFoundation/NXProject.h>
#import <LindChain/IDEFoundation/NXDocumentManager.h>
#import <LindChain/IDEFoundation/NXUtils.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <LindChain/IDEFoundation/NXRemoteCompiler.h>
#import <LindChain/IDEFoundation/NXAlertDiagnosticPresenter.h>
#import <LindChain/IDEBuilder/LDEFilesFinder.h>
#import <LindChain/IDEBuilder/NXPhaseEngine.h>
#import <LindChain/IDEBuilder/NXPhaseRunner.h>
#import <LindChain/IDELanguageServer/NXLanguageServer.h>
#import <LindChain/IDEConsole/NXConsoleView.h>

/* LindChain Core Headers */
#import <LindChain/Downloader/fdownload.h>
#import <LindChain/Utils/Zip.h>
#import <LindChain/Utils/LDEDebouncer.h>
#import <LindChain/Utils/IconUtils.h>

/* WindowServer headers */
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>
#import <LindChain/WindowServer/Session/NXWindowSessionTerminal.h>

/* Micro Kernel Headers */
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/PELaunchServiceManager.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#import <LindChain/ProcEnvironment/PEExtension.h>
#import <LindChain/ProcEnvironment/PEUserspaceManager.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/ZSign/zsigner.h>
#import <LindChain/ProcEnvironment/Surface/trust/trust.h>
#import <LindChain/ProcEnvironment/Surface/fs/fs.h>
#import <LindChain/ProcEnvironment/KextLoader/PEKext.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <LindChain/ProcEnvironment/Utils/misc.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>

/* Daemon Interfaces Headers */
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>

void refreshFile(const char* path);

#endif /* NXBRIDGE_H */
