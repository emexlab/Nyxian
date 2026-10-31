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

#ifndef PROCENVIRONMENT_SURFACE_H
#define PROCENVIRONMENT_SURFACE_H

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif /* __OBJC__ */

#import <LindChain/ProcEnvironment/Surface/limits.h>
#import <LindChain/ProcEnvironment/Surface/mapping.h>
#include <mach/kern_return.h>
#include <assert.h>
#include <errno.h>

extern ksurface_mapping_t *ksurface;

#ifdef __OBJC__
int ksurface_sethostname(NSString *hostname);
#endif /* __OBJC__ */

void ksurface_kinit_get_keys(void);
void ksurface_kinit(void);

#endif /* PROCENVIRONMENT_SURFACE_H */
