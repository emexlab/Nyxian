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

#ifndef TTY_LOOKUP_H
#define TTY_LOOKUP_H

#include <LindChain/ProcEnvironment/Surface/tty/def.h>
#include <LindChain/Private/mach/fileport.h>

kern_return_t tty_for_port(fileport_t port, ksurface_tty_t **tty);

#endif /* TTY_LOOKUP_H */
