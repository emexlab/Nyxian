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

#ifndef BOOTBRIDGE_H
#define BOOTBRIDGE_H

#import <UI/NXVolumeButtonMonitor.h>
#import <UI/NXRecoveryViewController.h>
#import <UI/NXRecoverySurface.h>
#import <UI/NXRecoveryTerminal.h>
#import <UI/TWRP/NXTWRPSplash.h>

#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/PEExtension.h>
#import <LindChain/ProcEnvironment/Surface/trust/trust.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <LindChain/ProcEnvironment/Utils/misc.h>

#import <LindChain/Utils/Zip.h>
#import <LindChain/Utils/NXBootCertificate.h>
#import <LindChain/Utils/NXROMTrust.h>
#import <LindChain/Utils/NXROMDeviceTrust.h>
#import <LindChain/Utils/NXBootLockdown.h>
#import <LindChain/Utils/NXTrustStore.h>

#import <LindChain/ProcEnvironment/Surface/trust/signing.h>

#include "../LiveProcess/NXLiveProcessABI.h"
#include "../BootHandoff/NXBootHandoff.h"
#import <UI/NXBootHandoffHost.h>
#import <UI/NXBootArgumentsHost.h>

#endif /* BOOTBRIDGE_H */
